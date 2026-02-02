## What we are building in this session

- A **deterministic, step-driven simulation harness** for `src/scheduler/executor.rs` that can run **multi-worker work-stealing** without OS threads, and explore interleavings like TigerBeetle (bounded exhaustive + long seeded stress).
- A **task bytecode VM** whose programs perform only scheduler-relevant operations: spawn (local/global/external), yield, wait on IO/timers, and acquire/release abstract “permits/budgets”.
- A **trace + replay + shrink** pipeline: any failure produces a single repro artifact `{seed, program, external event schedule, driver choices, version stamp}`, plus a readable summary, and then a deterministic minimizer shrinks it into a stable regression case.
- A precise set of **step-wise oracles** for determinism, safety (lost wakeups/double-runs/permit underflow/overflow), liveness, and the executor’s intended fairness knobs (wake-on-hoard + round-robin unpark + FIFO stealing).

---

## Seams and required refactors

### Production modules/types we must touch

**Primary target**: `src/scheduler/executor.rs`
We will not couple to pipeline logic (`task_graph`, scanning), but we _will_ reuse the executor’s actual scheduling policy:

- Local deque is **LIFO** (`Worker::new_lifo()`).
- Global injector is used for external/global spawns.
- Stealing: **random victim selection** via per-worker `XorShift64`, with **FIFO steal** semantics (steal oldest from victim).
- Fairness knobs:
  - `WAKE_ON_HOARD_THRESHOLD: u32 = 32`
  - `unpark_one()` uses `next_unpark: AtomicUsize` (approx round-robin)

**Also referenced**:

- `src/scheduler/rng.rs` (`XorShift64`)
- `src/scheduler/contract.rs` (limits, used to cap generation so we never overflow the executor’s 32-bit in-flight counter packing)

### Minimal refactor seam (surgical, “no hot-path tax”)

Right now, `Executor` is inherently threadful. For deterministic simulation we need a **non-threaded stepping interface** and **instrumentation hooks**, without impacting production performance.

I recommend extracting a small “core” submodule that contains the _policy_ and _state machine transitions_, and then reusing it from both:

- production thread runner (today’s behavior)
- deterministic simulator (new harness)

Concretely:

#### 1) Extract core scheduling functions and state into `executor_core.rs`

New file: `src/scheduler/executor_core.rs` (internal, `pub(crate)`).

Move / refactor from `executor.rs`:

- `SharedState` bitpacking helpers (`is_accepting`, `in_flight`, `close_gate`, `increment_count`)
- `pop_task`, `try_steal` logic (policy)
- constants (`ACCEPTING_BIT`, `COUNT_MASK`, `COUNT_UNIT`, `WAKE_ON_HOARD_THRESHOLD`)

This does **not** require changing the external `Executor` API.

#### 2) Add a step-capable worker engine (no blocking)

Add a small internal state machine:

```rust
// src/scheduler/executor_core.rs
pub(crate) enum WorkerStepResult<T> {
    RanTask { task: T, source: PopSource, victim: Option<usize> },
    NoWork,
    ShouldPark { timeout_ticks: u64 }, // simulator interprets
    ExitDone,
    ExitPanicked,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PopSource { Local, Injector, Steal }
```

And a function:

```rust
pub(crate) fn worker_step<T, S, RunnerFn>(
    cfg: &ExecutorConfig,
    runner: &RunnerFn,
    ctx: &mut WorkerCtxLike<T, S>,    // see below
    idle: &mut dyn IdleHooks,         // simulator vs production
    trace: &mut dyn TraceHooks<T>,    // optional hooks
) -> WorkerStepResult<T>
where
    T: Send + 'static,
    RunnerFn: Fn(T, &mut WorkerCtxLike<T, S>) + 'static;
```

#### 3) Introduce a minimal “context” trait for the core

We don’t want generics explosion. We just need the core to access:

- local deque ops
- shared injector + stealers
- unpark/park semantics via hooks
- scratch space

Add:

```rust
pub(crate) trait WorkerCtxLike<T, S> {
    fn worker_id(&self) -> usize;
    fn scratch_mut(&mut self) -> &mut S;

    fn pop_local(&self) -> Option<T>;
    fn push_local(&self, task: T);

    fn push_injector(&self, task: T);
    fn steal_from_injector(&self) -> Option<T>;
    fn steal_from_victim(&self, victim: usize) -> Option<T>;

    fn shared_state_load(&self) -> u64;
    fn shared_state_fetch_sub(&self, delta: u64) -> u64;
    fn shared_state_close_gate(&self) -> u64;
    fn shared_state_increment(&self) -> Result<(), ()>; // fail if !accepting for external

    fn initiate_done(&self);
    fn done_flag(&self) -> bool;

    fn unpark_one(&self);
    fn unpark_all(&self);

    fn record_panic(&self, payload: Box<dyn std::any::Any + Send>);
}
```

Production `WorkerCtx` can implement this via thin wrappers with `#[inline]` and no dynamic dispatch in hot path by having `worker_step` generic over the concrete ctx type in production. The simulator uses a separate ctx implementation.

#### 4) Instrumentation hooks (feature-gated, zero overhead when off)

Add:

```rust
pub(crate) trait TraceHooks<T> {
    fn on_event(&mut self, e: ExecTraceEvent<T>);
}

pub(crate) enum ExecTraceEvent<T> {
    Pop { wid: usize, source: PopSource, victim: Option<usize> },
    SpawnLocal { wid: usize },
    SpawnGlobal { wid: usize },
    SpawnExternal,
    UnparkOne { target: usize },
    InitiateDone,
    PanicRecorded,
}
```

Provide a no-op implementation in production. In simulation, we implement it to emit the structured trace.

**Why this seam is minimal:** no public API changes; production still uses threads; simulation is a parallel internal consumer of the same policy/state machine.

---

## Correctness definition

The harness must not say “no issues found.” It must check falsifiable properties. Here are the oracles, with **when checked** and **what data required**.

### A) Determinism oracle

**Property:** For a fixed `{seed, case, driver_choices}`, simulation produces the **same trace bytes** step-for-step.

- **Checked:** end of run (also optionally rolling-hash per step).
- **Data:** `ReproArtifact` (seed + case + driver choices) and the emitted `Trace`.

Implementation:

- Run `run(case, seed, choices)` twice and assert `trace1 == trace2`.
- Also assert final state digests match (queues empty, resources balanced).

### B) Safety oracles

1. **No lost tasks / no double-run**

- Each logical task-run token is executed exactly once.
- No task id appears in two places simultaneously (local queues, injector, blocked lists, running).

**Checked:** every step.
**Data:** executor queues, per-task state (runnable/blocked/running/completed), in-flight counter.

Concrete invariants:

- `in_flight == runnable_count + running_count` (for the executor’s “run tokens”; see below)
- Every `TaskId` is in exactly one of:
  - runnable (in some queue)
  - blocked (timer/io/resource wait)
  - running
  - completed/cancelled

Note: the simulator does not yet track explicit run-token IDs, so the
double-run check is not enforced in the current oracles. The `DoubleRun`
violation kind is reserved until we instrument tokens directly.

2. **Gate semantics (spawn vs join)**

- After `join()` closes the gate, `spawn_external()` must return `Err(task)`.
- Every successful spawn before/at the instant of gate closure must execute exactly once.

**Checked:** per step and end-state.
**Data:** model state (below), plus actual state transitions.

3. **No permit/budget underflow/overflow**

- Resource counters never go negative; never exceed totals on release.
- No double-release.

**Checked:** every step.
**Data:** resource totals/avail, per-task held permits.

4. **No panics escaping the harness driver**

- Any panic inside the scheduler or task VM is caught, recorded as failure, and turned into a repro artifact.

**Checked:** immediate.
**Data:** `catch_unwind` around `worker_step` + instruction execution.

5. **No lost wakeups / no “sleeping while work exists” deadlock**
   This is the classic: all workers “parked” but runnable tasks exist and no future external event can wake anyone.

**Checked:** every step once the system is quiescent.
**Data:** parked flags, unpark tokens, runnable queues, pending external events.

Invariant:

- If `runnable_count > 0` then **exists** an enabled action that runs work:
  - some worker is not parked, or
  - some parked worker has an unpark token set, or
  - unpark events are pending to be delivered (e.g., external spawn)

If none, that’s a lost-wakeup style bug.

### C) Liveness oracles (under stated assumptions)

We can’t demand “everything finishes” if programs can block forever. So we define assumptions:

**Assumptions for liveness checks:**

- Timer/IO events scheduled in the case _will_ be delivered by the driver (deterministically).
- Task programs are _bounded_ (generator ensures eventual `Complete` unless explicitly generating “hang” cases).

**Properties:**

1. **Runnable tasks eventually run** (bounded starvation)

- If a task remains runnable continuously for `K` scheduler steps, it must be executed at least once within that window.

**Checked:** per step (track runnable-age).
**Data:** per-task runnable age, scheduling trace.

`K` should be a small bound derived from policy, e.g.:

- `K = workers * (steal_tries + 2) * C` for some small `C` (like 4), since a worker checks local→injector→steal.

2. **Blocked tasks only unblock due to defined events**

- Tasks in `BlockedOnIo(token)` only become runnable on `IoComplete(token)`.
- Tasks in `Sleeping(until)` only become runnable when `now >= until`.

**Checked:** per unblock transition.
**Data:** task blocked reason + delivered events.

### D) Fairness oracles (match intended policy in _this_ codebase)

This executor does not promise strict fairness; it promises specific mechanisms:

1. **Wake-on-hoard**
   From `WorkerCtx::spawn_local` in `executor.rs`:

- After `WAKE_ON_HOARD_THRESHOLD = 32` local spawns since last wake, call `unpark_one()` and reset the counter.

**Checked:** per local spawn instruction.
**Data:** local spawn counter, trace of `unpark_one()` invocations.

2. **Round-robin unpark selection**
   From `Shared::unpark_one`:

- Target index is `(next_unpark.fetch_add(1) % unparkers.len())`. This gives approximate fairness.

**Checked:** per unpark event.
**Data:** `next_unpark` value + chosen index.

3. **FIFO stealing**
   Because locals are created by `Worker::new_lifo()`, _victim steals from the opposite end_ → older tasks get stolen first.

**Checked:** per steal.
**Data:** per-worker local queue ordering + which task got stolen.

We explicitly do _not_ claim “fair per-task CPU distribution” because LIFO locals can starve older local tasks if a task keeps pushing onto its own stack; that’s an intentional locality tradeoff.

---

## Simulation design

### Responsibilities and boundaries

- **SimExecutorCore**: deterministic model of the executor policy (local LIFO, injector, random victim steal, gate/count, park/unpark).
- **TaskVM**: executes one bytecode instruction per run-token; emits effects (spawn, yield, wait, acquire/release).
- **ExternalEvents**: deterministic IO completions and timer wakeups.
- **Driver**: chooses the next enabled action (exhaustive enumeration for small bounds; seeded RNG for stress).
- **TraceRecorder**: structured trace events + state digests.
- **OracleChecker**: step-wise invariants.

### Core loop pseudocode

```text
state = init_from_case(seed, case)

for step in 0..max_steps:
  enabled = compute_enabled_actions(state)
  if enabled.is_empty():
      return Ok(TerminatedOrDeadlocked)

  choice = driver.choose(enabled)     // deterministic: exhaustive or RNG+seed
  trace.push(ActionChosen(step, choice))

  apply(choice):
    - StepWorker(wid):
        res = executor.worker_step(wid)
        trace.push(res events)
        if res ran task:
            effects = task_vm.exec_one(task_id, wid)
            apply_effects(effects)    // spawn, waits, resource ops
    - DeliverIo(token):
        wake waiting tasks -> executor.spawn_external(...)
    - AdvanceTimeTo(t):
        now = t; wake sleepers -> executor.spawn_external(...)
    - CloseGateJoin:
        executor.close_gate_and_maybe_done()

  oracle.check_step(state, trace, step)?
end

return Failure(Timeout) // also a liveness failure, with artifact
```

### Key modeling choice: “run-tokens” vs “logical tasks”

The production executor’s `in_flight` counts **enqueued task values**, not “async tasks.”
In the harness we model this cleanly:

- A **logical task** is a persistent VM state: `(program, pc, held permits, blocked status)`.
- A **run-token** is “this logical task is runnable once,” represented by enqueuing its `TaskId` into executor queues.
- When a worker executes a `TaskId`, that consumes one run-token (decrement `in_flight`).
- If the instruction yields/reschedules, it produces a new run-token (increment `in_flight` and enqueue).

This lets us test the executor’s count/gate correctness faithfully.

### Trace format (designed for replay + shrinking)

Keep it structured, stable, and small:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trace {
    pub header: TraceHeader,
    pub events: Vec<TraceEvent>,
    pub final_digest: StateDigest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TraceEvent {
    Step { n: u64, action: DriverAction },

    ExecPop { wid: u8, src: PopSource, victim: Option<u8>, tid: u32 },
    ExecPark { wid: u8 },
    ExecUnpark { target: u8 },

    TaskInstr { tid: u32, pc: u16, instr: Instruction },

    Resource { op: ResourceOp, tid: u32 },
    Blocked { tid: u32, reason: BlockReason },
    Unblocked { tid: u32, reason: BlockReason },

    GateClosed,
    DoneSet,
    Panic { message: String },
    InvariantViolation { kind: ViolationKind },
}
```

Replay uses:

- the case + seed
- optionally driver choices to force an identical interleaving

---

## Failure artifact and debugging workflow

### Machine-readable repro artifact schema

Use `serde_json` (already in dev-deps) with only `Vec`/scalars (no maps), so it’s deterministic.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReproArtifact {
    pub schema_version: u32,
    pub build: BuildStamp,
    pub seed: u64,

    pub case: SimCase,

    // EXACT interleaving: chosen action indices or explicit actions.
    pub driver_choices: Vec<DriverChoice>,

    // For fast sanity: hash of expected trace.
    pub expected_trace_hash: u64,

    pub failure: FailureInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildStamp {
    pub pkg_version: &'static str, // env!("CARGO_PKG_VERSION")
    pub git_sha: Option<&'static str>, // option_env!("GIT_SHA")
    pub rustc: Option<&'static str>,   // option_env!("RUSTC_VERSION")
}
```

### Human-readable summary (must be sufficient without rerun)

On failure, print:

- failure kind + step number
- last ~200 trace events
- executor snapshot: gate/count/done, per-worker queues lengths, parked flags, next_unpark
- the minimized case summary: programs, resources, pending events

### Debug/replay workflow

- Failure path:
  1. Immediately serialize the full repro JSON (or base64-embed it in panic message if file writes disabled).
  2. Run minimizer → write minimized repro JSON.
  3. Panic with a message that includes the minimized artifact path (or base64).

- Replay:
  - A dedicated test reads each artifact and calls `replay(artifact)`, asserting:
    - determinism (trace matches hash)
    - invariants
    - same failure kind at same step

### Turning failures into stable regression tests

- Keep a corpus directory:
  - `tests/simulation/corpus/*.json`

- Add a normal `#[test]` that iterates corpus files and replays each, so every PR runs the regression bank.

---

## Minimization plan

Goal: shrink `{workers, programs, steps, external events, resources}` while preserving:

- same failure kind
- same determinism (replayable trace)

### Deterministic reducer pipeline (no heuristics that depend on timing)

Use a fixed reducer order, and a fixed candidate enumeration order:

1. **Reduce workers**

- Try `workers = 1..orig_workers`, keeping the same programs/events.
- Update `ExecutorConfig.workers` and remap any worker ids in driver choices.

2. **Reduce external events**

- Delta-debug the event list:
  - remove half, check failure, keep if still fails
  - then smaller chunks (classic ddmin)

- Then reduce event parameters:
  - earlier delivery times (move toward 0)
  - remove redundant duplicates

3. **Reduce number of initial runnable tasks**

- Remove tasks not reachable from spawns.
- Drop initial runnable set members (stable order).

4. **Shrink programs**
   For each program:

- Remove instructions (try delete ranges, then single instructions).
- Replace complex instructions with `Yield` or `Complete`.
- Reduce numeric operands (ticks, permit amounts) via monotone halving toward 0/1.

5. **Shrink driver choices**

- If using explicit driver choices, shrink the prefix length:
  - keep shortest prefix that still reproduces.

### Minimizer interface

```rust
pub fn minimize(
    artifact: &ReproArtifact,
    cfg: MinimizeConfig,
    check: impl Fn(&ReproArtifact) -> Result<(), FailureInfo>,
) -> ReproArtifact;
```

The minimizer must be bounded:

- `max_iters`, `max_checks`
- deterministic stop condition

Output:

- minimized repro JSON
- readable summary

---

## Implementation plan

### File/module layout

- `src/scheduler/executor_core.rs` _(new)_: extracted policy/state machine helpers, step function.
- `src/scheduler/executor.rs` _(small edit)_: production uses core; no behavior changes.
- `src/scheduler/sim_executor_harness.rs` _(new, `#[cfg(test)]` or `feature = "scheduler-sim"`)_:
  - bytecode, generator, sim driver, trace, oracles, minimizer, replay.

- `tests/scheduler_sim.rs` _(new integration test)_:
  - fast-tier bounded exploration
  - corpus replay tests
  - soak tests behind `--features scheduler-sim`

### Rust code skeletons

#### Task program + instruction set

```rust
// src/scheduler/sim_executor_harness.rs
#![cfg(any(test, feature = "scheduler-sim"))]

use serde::{Deserialize, Serialize};

pub type ProgramId = u32;
pub type TaskId = u32;
pub type ResourceId = u16;
pub type IoToken = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgram {
    pub name: String,
    pub code: Vec<Instruction>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpawnPlacement {
    Local,    // equivalent to WorkerCtx::spawn_local
    Global,   // equivalent to WorkerCtx::spawn_global
    External, // equivalent to ExecutorHandle::spawn
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Instruction {
    // Scheduling
    Yield { placement: SpawnPlacement },
    Spawn { program: ProgramId, placement: SpawnPlacement },

    // Blocking primitives (modeled as “no run-token until event”)
    Sleep { ticks: u32 },
    WaitIo { token: IoToken },

    // Resources
    TryAcquire { res: ResourceId, units: u32, ok: u16, fail: u16 },
    Release { res: ResourceId, units: u32 },

    // Control flow
    Jump { target: u16 },

    // Termination
    Complete,

    // Optional: negative testing
    Panic,
}
```

#### Simulation case + external events

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimCase {
    pub exec_cfg: SimExecCfg,
    pub resources: Vec<ResourceSpec>,
    pub programs: Vec<TaskProgram>,

    // initial logical tasks (persistent VM states)
    pub tasks: Vec<LogicalTaskInit>,

    // initial runnable tokens (TaskIds enqueued before start)
    pub initial_runnable: Vec<TaskId>,

    // deterministic external events: IO completes, join gate close, etc
    pub external_events: Vec<ScheduledEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimExecCfg {
    pub workers: u8,
    pub steal_tries: u8,
    pub wake_on_hoard_threshold: u32, // default 32 to match prod
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogicalTaskInit {
    pub tid: TaskId,
    pub program: ProgramId,
    pub pc: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub id: ResourceId,
    pub total: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduledEvent {
    pub at_step: u64, // simulated time (monotone step counter)
    pub event: ExternalEvent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExternalEvent {
    IoComplete { token: IoToken },
    CloseGateJoin,
}
```

#### Deterministic generator (seeded)

```rust
use crate::scheduler::XorShift64;

pub struct CaseGen {
    rng: XorShift64,
    next_tid: TaskId,
}

impl CaseGen {
    pub fn new(seed: u64) -> Self {
        Self { rng: XorShift64::new(seed), next_tid: 0 }
    }

    pub fn gen_case(&mut self, bounds: GenBounds) -> SimCase {
        // 1) generate resources (small totals)
        // 2) generate programs (bounded code len)
        // 3) generate logical tasks + initial runnable tokens
        // 4) generate external events (IO completions, join)
        // All deterministic from self.rng.
        unimplemented!()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GenBounds {
    pub workers_max: u8,
    pub tasks_max: u8,
    pub prog_len_max: u8,
    pub resources_max: u8,
    pub events_max: u8,
}
```

#### Sim executor model (step function)

```rust
use std::collections::VecDeque;

#[derive(Clone, Debug)]
struct SimWorker {
    local: VecDeque<TaskId>, // back = LIFO pop, front = FIFO steal
    parked: bool,
    unpark_token: bool,
    local_spawns_since_wake: u32,
    rng: XorShift64,
}

#[derive(Clone, Debug)]
struct SimShared {
    accepting: bool,
    in_flight: u32,      // mirror of prod low 32 bits
    done: bool,
    next_unpark: usize,  // round-robin counter
}

#[derive(Clone, Debug)]
struct SimExecutor {
    injector: VecDeque<TaskId>,
    workers: Vec<SimWorker>,
    shared: SimShared,
    steal_tries: u8,
    wake_on_hoard_threshold: u32,
}

impl SimExecutor {
    fn spawn_external(&mut self, tid: TaskId, trace: &mut Trace) -> Result<(), ()> {
        if !self.shared.accepting { return Err(()); }
        self.shared.in_flight = self.shared.in_flight.checked_add(1).ok_or(())?;
        self.injector.push_back(tid);
        self.unpark_one(trace);
        Ok(())
    }

    fn spawn_global(&mut self, tid: TaskId, trace: &mut Trace) {
        self.shared.in_flight += 1;
        self.injector.push_back(tid);
        self.unpark_one(trace);
    }

    fn spawn_local(&mut self, wid: usize, tid: TaskId, trace: &mut Trace) {
        self.shared.in_flight += 1;
        self.workers[wid].local.push_back(tid);

        let w = &mut self.workers[wid];
        w.local_spawns_since_wake += 1;
        if w.local_spawns_since_wake >= self.wake_on_hoard_threshold {
            w.local_spawns_since_wake = 0;
            self.unpark_one(trace);
        }
    }

    fn unpark_one(&mut self, trace: &mut Trace) {
        let n = self.workers.len();
        if n == 0 { return; }
        let idx = self.shared.next_unpark % n;
        self.shared.next_unpark += 1;

        let w = &mut self.workers[idx];
        w.unpark_token = true;
        w.parked = false;

        trace.events.push(TraceEvent::ExecUnpark { target: idx as u8 });
    }

    fn close_gate_join(&mut self, trace: &mut Trace) {
        self.shared.accepting = false;
        trace.events.push(TraceEvent::GateClosed);
        if self.shared.in_flight == 0 {
            self.shared.done = true;
            trace.events.push(TraceEvent::DoneSet);
            // unpark_all in prod; here: clear parked on all
            for (i, w) in self.workers.iter_mut().enumerate() {
                w.unpark_token = true;
                w.parked = false;
                trace.events.push(TraceEvent::ExecUnpark { target: i as u8 });
            }
        }
    }

    fn pop_task(&mut self, wid: usize) -> Option<(TaskId, PopSource, Option<usize>)> {
        // 1) local pop (LIFO)
        if let Some(tid) = self.workers[wid].local.pop_back() {
            return Some((tid, PopSource::Local, None));
        }

        // 2) injector pop (approx “steal_batch_and_pop”)
        if let Some(tid) = self.injector.pop_front() {
            return Some((tid, PopSource::Injector, None));
        }

        // 3) steal tries: choose victim via rng, skip self
        let n = self.workers.len();
        for _ in 0..self.steal_tries {
            if n <= 1 { break; }
            let mut v = self.workers[wid].rng.next_usize(n);
            if v == wid { v = (v + 1) % n; }

            // FIFO steal from victim (oldest at front)
            if let Some(tid) = self.workers[v].local.pop_front() {
                return Some((tid, PopSource::Steal, Some(v)));
            }
        }
        None
    }

    fn step_worker(
        &mut self,
        wid: usize,
        trace: &mut Trace,
        task_vm: &mut TaskVm,
        resources: &mut ResourceModel,
        now: u64,
    ) -> StepOutcome {
        if self.shared.done { return StepOutcome::ExitDone; }

        // simulate park token behavior
        let w = &mut self.workers[wid];
        if w.parked && !w.unpark_token {
            return StepOutcome::NoProgress;
        }
        if w.unpark_token {
            w.unpark_token = false; // consume token
            w.parked = false;
        }

        let Some((tid, src, victim)) = self.pop_task(wid) else {
            // done check: if in_flight==0 and !accepting => done
            if self.shared.in_flight == 0 && !self.shared.accepting {
                self.shared.done = true;
                trace.events.push(TraceEvent::DoneSet);
                return StepOutcome::ExitDone;
            }
            // park
            self.workers[wid].parked = true;
            trace.events.push(TraceEvent::ExecPark { wid: wid as u8 });
            return StepOutcome::Parked;
        };

        trace.events.push(TraceEvent::ExecPop { wid: wid as u8, src, victim: victim.map(|v| v as u8), tid });

        // execute one instruction for this logical task
        // any panic must be caught and converted
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            task_vm.exec_one(tid, wid, now, self, resources, trace)
        }));

        // decrement in_flight like prod worker_loop does after task execution
        self.shared.in_flight = self.shared.in_flight.saturating_sub(1);

        if let Err(p) = res {
            trace.events.push(TraceEvent::Panic { message: panic_payload_to_string(p) });
            self.shared.done = true;
            return StepOutcome::ExitPanicked;
        }

        // if count hit 0 and gate closed -> done
        if self.shared.in_flight == 0 && !self.shared.accepting {
            self.shared.done = true;
            trace.events.push(TraceEvent::DoneSet);
            return StepOutcome::ExitDone;
        }

        StepOutcome::Progress
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepOutcome { Progress, NoProgress, Parked, ExitDone, ExitPanicked }

fn panic_payload_to_string(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() { (*s).to_string() }
    else if let Some(s) = p.downcast_ref::<String>() { s.clone() }
    else { "<non-string panic payload>".to_string() }
}
```

#### Task VM + resource model skeleton

```rust
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub enum BlockReason {
    SleepUntil(u64),
    Io(IoToken),
    Resource(ResourceId),
}

#[derive(Clone, Debug)]
struct LogicalTask {
    program: ProgramId,
    pc: u16,
    blocked: Option<BlockReason>,
    held: BTreeMap<ResourceId, u32>,
    completed: bool,
}

pub struct TaskVm {
    programs: Vec<TaskProgram>,
    tasks: BTreeMap<TaskId, LogicalTask>,
    io_waiters: BTreeMap<IoToken, BTreeSet<TaskId>>, // deterministic
    sleepers: BTreeMap<u64, Vec<TaskId>>,            // key = wake step, stable order
}

impl TaskVm {
    pub fn new(programs: Vec<TaskProgram>, tasks: Vec<LogicalTaskInit>) -> Self {
        let mut map = BTreeMap::new();
        for t in tasks {
            map.insert(t.tid, LogicalTask {
                program: t.program,
                pc: t.pc,
                blocked: None,
                held: BTreeMap::new(),
                completed: false,
            });
        }
        Self {
            programs,
            tasks: map,
            io_waiters: BTreeMap::new(),
            sleepers: BTreeMap::new(),
        }
    }

    pub fn exec_one(
        &mut self,
        tid: TaskId,
        wid: usize,
        now: u64,
        ex: &mut SimExecutor,
        res: &mut ResourceModel,
        trace: &mut Trace,
    ) {
        let t = self.tasks.get_mut(&tid).expect("valid tid");
        if t.completed { return; }
        if t.blocked.is_some() { return; }

        let prog = &self.programs[t.program as usize];
        let pc = t.pc as usize;
        let instr = prog.code.get(pc).cloned().unwrap_or(Instruction::Complete);

        trace.events.push(TraceEvent::TaskInstr { tid, pc: t.pc, instr: instr.clone() });

        match instr {
            Instruction::Yield { placement } => {
                // re-enqueue this task as a new run-token
                t.pc = t.pc.saturating_add(1);
                self.enqueue_run_token(ex, wid, tid, placement, trace);
            }
            Instruction::Spawn { program, placement } => {
                let child_tid = self.allocate_task(program);
                self.enqueue_run_token(ex, wid, child_tid, placement, trace);
                t.pc = t.pc.saturating_add(1);
            }
            Instruction::Sleep { ticks } => {
                let wake = now + ticks as u64;
                t.blocked = Some(BlockReason::SleepUntil(wake));
                self.sleepers.entry(wake).or_default().push(tid);
                t.pc = t.pc.saturating_add(1);
            }
            Instruction::WaitIo { token } => {
                t.blocked = Some(BlockReason::Io(token));
                self.io_waiters.entry(token).or_default().insert(tid);
                t.pc = t.pc.saturating_add(1);
            }
            Instruction::TryAcquire { res: rid, units, ok, fail } => {
                if res.try_acquire(rid, units, tid, trace) {
                    *t.held.entry(rid).or_insert(0) += units;
                    t.pc = ok;
                } else {
                    t.pc = fail;
                }
            }
            Instruction::Release { res: rid, units } => {
                let held = t.held.get_mut(&rid).unwrap_or_else(|| panic!("release without hold"));
                assert!(*held >= units, "release underflow");
                *held -= units;
                if *held == 0 { t.held.remove(&rid); }
                res.release(rid, units, tid, trace);
                t.pc = t.pc.saturating_add(1);
            }
            Instruction::Jump { target } => t.pc = target,
            Instruction::Complete => t.completed = true,
            Instruction::Panic => panic!("task panic requested"),
        }
    }

    fn enqueue_run_token(
        &self,
        ex: &mut SimExecutor,
        wid: usize,
        tid: TaskId,
        placement: SpawnPlacement,
        trace: &mut Trace,
    ) {
        match placement {
            SpawnPlacement::Local => ex.spawn_local(wid, tid, trace),
            SpawnPlacement::Global => ex.spawn_global(tid, trace),
            SpawnPlacement::External => { let _ = ex.spawn_external(tid, trace); }
        }
    }

    fn allocate_task(&mut self, program: ProgramId) -> TaskId {
        let tid = self.tasks.len() as u32 + 1;
        self.tasks.insert(tid, LogicalTask {
            program,
            pc: 0,
            blocked: None,
            held: BTreeMap::new(),
            completed: false,
        });
        tid
    }

    pub fn deliver_io(&mut self, token: IoToken, ex: &mut SimExecutor, trace: &mut Trace) {
        let Some(waiters) = self.io_waiters.remove(&token) else { return; };
        for tid in waiters {
            if let Some(t) = self.tasks.get_mut(&tid) {
                t.blocked = None;
                // IO completion behaves like “external spawn”: injector + unpark_one
                let _ = ex.spawn_external(tid, trace);
                trace.events.push(TraceEvent::Unblocked { tid, reason: BlockReason::Io(token) });
            }
        }
    }

    pub fn wake_sleepers(&mut self, now: u64, ex: &mut SimExecutor, trace: &mut Trace) {
        let keys: Vec<u64> = self.sleepers
            .range(..=now)
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            if let Some(tids) = self.sleepers.remove(&k) {
                for tid in tids {
                    if let Some(t) = self.tasks.get_mut(&tid) {
                        t.blocked = None;
                        let _ = ex.spawn_external(tid, trace);
                        trace.events.push(TraceEvent::Unblocked { tid, reason: BlockReason::SleepUntil(k) });
                    }
                }
            }
        }
    }
}

pub struct ResourceModel {
    totals: BTreeMap<ResourceId, u32>,
    avail: BTreeMap<ResourceId, u32>,
}

impl ResourceModel {
    pub fn new(specs: &[ResourceSpec]) -> Self {
        let mut totals = BTreeMap::new();
        let mut avail = BTreeMap::new();
        for s in specs {
            totals.insert(s.id, s.total);
            avail.insert(s.id, s.total);
        }
        Self { totals, avail }
    }

    pub fn try_acquire(&mut self, rid: ResourceId, units: u32, tid: TaskId, trace: &mut Trace) -> bool {
        let a = *self.avail.get(&rid).unwrap_or(&0);
        if a < units { return false; }
        self.avail.insert(rid, a - units);
        trace.events.push(TraceEvent::Resource { op: ResourceOp::Acquire { rid, units }, tid });
        true
    }

    pub fn release(&mut self, rid: ResourceId, units: u32, tid: TaskId, trace: &mut Trace) {
        let a = *self.avail.get(&rid).unwrap_or(&0);
        let t = *self.totals.get(&rid).unwrap_or(&0);
        let new = a + units;
        assert!(new <= t, "resource over-release");
        self.avail.insert(rid, new);
        trace.events.push(TraceEvent::Resource { op: ResourceOp::Release { rid, units }, tid });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceOp {
    Acquire { rid: ResourceId, units: u32 },
    Release { rid: ResourceId, units: u32 },
}
```

#### Driver + replay + oracles skeleton

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriverAction {
    StepWorker { wid: u8 },
    DeliverIo { token: IoToken },
    CloseGateJoin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DriverChoice {
    // choose Nth enabled action at each step (compact + stable)
    pub idx: u16,
}

pub struct OracleChecker {
    // internal counters for runnable-age, invariants, etc
}

impl OracleChecker {
    pub fn check_step(&mut self, st: &SimState, trace: &Trace, step: u64) -> Result<(), FailureInfo> {
        // implement invariants here
        Ok(())
    }
}

pub struct SimState {
    pub now: u64,
    pub ex: SimExecutor,
    pub vm: TaskVm,
    pub res: ResourceModel,
}

pub fn run_with_choices(
    artifact: &ReproArtifact,
) -> Result<Trace, FailureInfo> {
    // build state from artifact.case + artifact.seed
    // loop steps using artifact.driver_choices
    unimplemented!()
}

pub fn replay(artifact: &ReproArtifact) {
    let t1 = run_with_choices(artifact).unwrap_err(); // should fail
    let t2 = run_with_choices(artifact).unwrap_err();
    assert_eq!(t1.kind, t2.kind);
}
```

#### Minimizer skeleton

```rust
pub struct MinimizeConfig {
    pub max_checks: usize,
}

pub fn minimize(mut art: ReproArtifact, cfg: MinimizeConfig) -> ReproArtifact {
    let mut checks = 0usize;

    // reducer list in fixed order
    let reducers: Vec<Box<dyn Reducer>> = vec![
        Box::new(ReduceWorkers),
        Box::new(ReduceEventsDdmin),
        Box::new(ReducePrograms),
        Box::new(ReduceChoices),
    ];

    'outer: loop {
        let mut changed = false;
        for r in &reducers {
            for cand in r.candidates(&art) {
                if checks >= cfg.max_checks { return art; }
                checks += 1;
                if reproduces_failure(&cand) {
                    art = cand;
                    changed = true;
                    break;
                }
            }
        }
        if !changed { break 'outer; }
    }
    art
}

trait Reducer {
    fn candidates(&self, art: &ReproArtifact) -> Vec<ReproArtifact>;
}

fn reproduces_failure(art: &ReproArtifact) -> bool {
    // run replay and match failure kind
    unimplemented!()
}
```

---

## CI plan

### PR tier (fast, deterministic, bounded)

Runs on every PR:

1. **Corpus replay**

- `tests/scheduler_corpus/*.json` replays.
- Guarantees old bugs stay dead.

2. **Exhaustive-ish exploration for tiny bounds**

- Fixed small cases generated deterministically:
  - workers: 1..=3
  - tasks: 1..=4
  - prog_len: 1..=8
  - max_steps: 200

- Explore interleavings by enumerating enabled actions in a stable order; cap branching by bounds.

3. **A small fixed-seed stress set**

- e.g. 50 seeds, medium bounds, max_steps 5k.

### Soak tier (nightly/weekly, longer random runs)

Behind `--features scheduler-sim`:

- 1k–10k seeds
- workers up to 8–16
- prog_len up to 64–256
- max_steps 100k+
- On first failure:
  - write full artifact
  - run minimizer
  - write minimized artifact
  - fail the job with the minimized summary printed

### Optional Loom (explicit scope + limitations)

You can add a **separate** `loom` feature for the atomic gate/count state machine only:

- Model `SharedState` operations (`spawn_external` CAS loop, `close_gate`, `fetch_sub`) with Loom atomics.
- This covers memory-ordering/racy interleavings that the deterministic simulator (which is sequential) does not.
- Limitations:
  - Crossbeam deques and parkers are not Loom-friendly.
  - Loom state explosion; keep workers <= 2 and operations <= ~20.

The deterministic simulator remains the primary harness.

---

## What this harness proves vs what remains out of scope

**Proves (falsifiable):**

- Replay determinism for `{seed, case, driver_choices}`.
- Gate/count safety (no lost tasks) across systematically explored interleavings.
- No “all parked while work exists” deadlocks in the simulated park/unpark model.
- Wake-on-hoard and round-robin unpark behavior match the code’s intended fairness knobs.
- FIFO stealing (oldest first) and local LIFO behavior.
- Resource accounting invariants (no underflow/overflow/leaks) in the simulated resource layer.

**Out of scope (explicit):**

- The internal correctness of crossbeam’s lock-free deque under true parallelism (unless you add targeted loom-like tests or black-box stress, which are nondeterministic).
- OS scheduler, preemption, and timing behavior (by design).

---

This design is deliberately “state machine first”: every step has an enabled-action set, a chosen action, a trace event, and invariants checked immediately. That’s the TigerBeetle vibe: make bugs cheap to reproduce, cheap to shrink, and impossible to hand-wave away.

---

## Harness flow, errors, and debugging

This section is the operational guide for anyone new to the harness.

### Harness flow (what runs each step)

1. **Inputs**: a `SimCase` (programs, tasks, initial runnable list, resources, external event schedule) and a driver policy.
2. **Enabled actions**: `enabled_actions()` enumerates the action set in a stable order: deliverable events, worker steps (if not fully parked), then time advance.
3. **Driver choice**: replay uses recorded `driver_choices` (index into the enabled list). Stress uses a fair driver (deliver events first, then round-robin workers) to avoid driver-induced starvation.
4. **Worker step**: `worker_step` executes the real scheduler policy (local LIFO, injector, randomized steals, fairness knobs). `TaskVm` executes exactly one instruction for the popped task and may enqueue new run-tokens (yield/spawn).
5. **Oracles**: step-wise invariants are checked immediately after each driver step. Any violation is recorded as `TraceEvent::InvariantViolation` and fails the test.
6. **Trace**: each step emits `TraceEvent::Step`, plus `Exec`, `TaskInstr`, and `External` events. A final `StateDigest` captures queue sizes and gate/done state.

### What the harness is testing

- **Policy correctness**: local LIFO, global injector behavior, FIFO stealing, and randomized victim selection.
- **Gate semantics**: `spawn_external` rejects after `close_gate` and `done` transitions are correct.
- **Park/unpark semantics**: no “all parked while work exists” deadlocks in the simulated parker.
- **Resource accounting**: no underflow/overflow or double-release in the resource model.
- **Determinism**: fixed `{seed, case, driver_choices}` yields identical traces and digests.
- **Bounded fairness**: runnable tasks must be scheduled within a bounded number of steps, under a fair driver, with the bound scaled by the runnable backlog when the task became runnable.

### What an error looks like

Errors surface in one of three ways:

- **Invariant violation**: `TraceEvent::InvariantViolation { kind, message }`.
- **Replay hash mismatch**: `expected_trace_hash` does not match the replayed trace hash.
- **Panic**: `ExecTraceEvent::PanicRecorded` in the trace and early exit of the run.

In stress runs, the harness writes a repro artifact to `tests/simulation/failures/seed_<seed>.json` before failing.

### Debugging playbook

1. **Locate the artifact** in `tests/simulation/failures/` and inspect `case`, `driver_choices`, and `failure` (kind, step, message).
2. **Reproduce with a focused run** by setting `SCHEDULER_SIM_STRESS_SEEDS=1` and `SCHEDULER_SIM_STRESS_SEED_BASE=<seed>` when running the `scheduler_sim` test.
3. **Replay deterministically**: the replay path uses `run_with_choices` and recorded `driver_choices`. Artifacts under `tests/scheduler_corpus/` are automatically replayed in `scheduler_sim_replay_corpus`.
4. **Interpret the action stream**: each `DriverChoice` index points into the enabled-action list at that step. `enabled_actions()` orders deliverable events, then worker steps, then time advance.
5. **Classify the failure**: if the fair driver still produces starvation, it is likely a scheduler bug. If the case violates harness assumptions (for example, programs that never terminate), it is a harness bug.

### Stress configuration

The stress test reads environment variables so CI can scale it without changing code:

- `SCHEDULER_SIM_STRESS_SEEDS`
- `SCHEDULER_SIM_STRESS_MAX_STEPS`
- `SCHEDULER_SIM_STRESS_MAX_PROGRAMS`
- `SCHEDULER_SIM_STRESS_MAX_TASKS`
- `SCHEDULER_SIM_STRESS_SEED_BASE`

These are intentionally small by default to keep per-push CI fast; cron jobs can increase them substantially.
