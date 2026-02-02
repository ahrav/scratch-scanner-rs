//! Executor core policy/state helpers shared by production and simulation.
//!
//! This module centralizes the combined state bitpacking and hot-path atomics
//! so the threaded executor and deterministic harness stay in lockstep.

use std::any::Any;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::executor::ExecutorConfig;

/// LSB in the combined state: 1 when accepting external spawns.
pub(crate) const ACCEPTING_BIT: usize = 1;
/// Count unit for the combined state (count stored in bits 1+).
pub(crate) const COUNT_UNIT: usize = 2;

/// Threshold for local spawns before waking a sibling.
///
/// # Problem: Work Hoarding
///
/// Without this heuristic, a worker that rapidly spawns local tasks might
/// accumulate thousands of tasks while siblings sleep. By the time siblings
/// wake (on next steal attempt), tail latency spikes.
///
/// # Solution: Wake-on-Hoard
///
/// After `N` consecutive local spawns, wake one sibling proactively.
/// This bounds the "hoarding window" to ~N tasks.
///
/// # Why 32?
///
/// | Threshold | Wakeup Rate | Overhead | Tail Latency |
/// |-----------|-------------|----------|--------------|
/// | 8 | High | ~12.5% of spawns trigger syscall | Low |
/// | 32 | Medium | ~3% of spawns trigger syscall | Medium |
/// | 128 | Low | ~0.8% of spawns trigger syscall | Higher |
///
/// 32 balances responsiveness with syscall overhead. For workloads with
/// very short tasks (<1µs), consider lowering. For long tasks (>100µs),
/// stealing latency is less critical.
///
/// # Tuning
///
/// Measure `steal_attempts` vs `steal_successes` in
/// [`super::metrics::MetricsSnapshot`].
/// If success rate is low and tail latency is high, lower this threshold.
pub(crate) const WAKE_ON_HOARD_THRESHOLD: u32 = 32;

/// Source queue for a popped task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PopSource {
    Local,
    Injector,
    Steal,
}

/// Outcome of a single worker step.
///
/// The `tag` is a lightweight identifier derived from the task before it is
/// executed. Production uses `()`; simulation can use a task id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WorkerStepResult<Tag> {
    RanTask {
        tag: Tag,
        source: PopSource,
        victim: Option<usize>,
    },
    NoWork,
    ShouldPark {
        timeout: Duration,
    },
    ExitDone,
    ExitPanicked,
}

/// Structured trace events emitted by the step engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExecTraceEvent<Tag> {
    Pop {
        wid: usize,
        source: PopSource,
        victim: Option<usize>,
        tag: Tag,
    },
    SpawnLocal {
        wid: usize,
    },
    SpawnGlobal {
        wid: usize,
    },
    SpawnExternal,
    UnparkOne {
        target: usize,
    },
    InitiateDone,
    PanicRecorded,
}

/// Optional trace hooks for the step engine.
///
/// Implementations should keep `tag_task` cheap and avoid allocation.
pub(crate) trait TraceHooks<T> {
    type TaskTag: Copy;

    #[inline(always)]
    fn is_enabled(&self) -> bool {
        false
    }

    fn tag_task(&mut self, task: &T) -> Self::TaskTag;

    #[inline(always)]
    fn on_event(&mut self, _event: ExecTraceEvent<Self::TaskTag>) {}
}

/// No-op tracing (production default).
#[derive(Default)]
pub(crate) struct NoopTrace;

impl<T> TraceHooks<T> for NoopTrace {
    type TaskTag = ();

    #[inline(always)]
    fn tag_task(&mut self, _task: &T) -> Self::TaskTag {}
}

/// Idle decision returned by [`IdleHooks`].
pub(crate) enum IdleAction {
    Continue,
    Park { timeout: Duration },
}

/// Idle policy hook for step-driven execution.
///
/// `on_idle` should perform any spin/yield side effects and return whether the
/// caller should park. `on_work` resets idle state on progress.
pub(crate) trait IdleHooks {
    fn on_work(&mut self);
    fn on_idle(&mut self, cfg: &ExecutorConfig) -> IdleAction;
}

/// Minimal worker context needed by the core step engine.
///
/// Implementations must preserve executor invariants:
/// - `shared_state_*` operations follow the combined `(count<<1)|accepting` layout.
/// - `pop_local` is LIFO; `steal_from_victim` is FIFO for stolen tasks.
/// - `record_panic` must signal shutdown and wake sleeping workers.
pub(crate) trait WorkerCtxLike<T, S> {
    fn worker_id(&self) -> usize;
    fn worker_count(&self) -> usize;
    fn scratch_mut(&mut self) -> &mut S;

    fn pop_local(&mut self) -> Option<T>;
    fn push_local(&mut self, task: T);

    fn push_injector(&mut self, task: T);
    fn steal_from_injector(&mut self) -> Option<T>;
    fn steal_from_victim(&mut self, victim: usize) -> Option<T>;

    fn shared_state_load(&self) -> usize;
    fn shared_state_fetch_sub(&mut self, delta: usize) -> usize;
    fn shared_state_close_gate(&mut self) -> usize;
    /// Increment in-flight count if accepting; return `Err(())` if gate closed.
    fn shared_state_increment(&mut self) -> Result<(), ()>;

    fn initiate_done(&mut self);
    fn done_flag(&self) -> bool;

    fn unpark_one(&mut self);
    fn unpark_all(&mut self);

    fn record_panic(&mut self, payload: Box<dyn Any + Send + 'static>);

    fn rng_next_usize(&mut self, upper: usize) -> usize;

    fn record_steal_attempt(&mut self) {}
    fn record_steal_success(&mut self) {}
}

/// Extract the in-flight count from the combined state word.
#[inline(always)]
pub(crate) fn in_flight(state: usize) -> usize {
    state >> 1
}

/// Check whether the executor is accepting external spawns.
#[inline(always)]
pub(crate) fn is_accepting(state: usize) -> bool {
    (state & ACCEPTING_BIT) != 0
}

/// Clear the accepting bit and return the previous state word.
#[inline(always)]
pub(crate) fn close_gate(state: &AtomicUsize) -> usize {
    state.fetch_and(!ACCEPTING_BIT, Ordering::AcqRel)
}

/// Increment the in-flight count in the combined state word.
#[inline(always)]
pub(crate) fn increment_count(state: &AtomicUsize) -> usize {
    state.fetch_add(COUNT_UNIT, Ordering::AcqRel)
}

/// Decrement the in-flight count in the combined state word.
#[inline(always)]
pub(crate) fn decrement_count(state: &AtomicUsize) -> usize {
    state.fetch_sub(COUNT_UNIT, Ordering::AcqRel)
}

/// Try to pop a task: local first, then injector, then steal.
///
/// # Priority Order
///
/// ```text
///  ┌─────────────────────────────────────────────────────────────────┐
///  │                        pop_task()                               │
///  │                                                                 │
///  │   ┌──────────────┐                                              │
///  │   │ 1. Local pop │  ◄── LIFO, best cache locality              │
///  │   │    O(1)      │      Same core, hot L1/L2 cache             │
///  │   └──────┬───────┘                                              │
///  │          │ empty                                                │
///  │          ▼                                                      │
///  │   ┌──────────────────────┐                                      │
///  │   │ 2. Injector batch    │  ◄── MPMC, moderate contention      │
///  │   │    steal_batch_and_pop│      Batch amortizes lock cost      │
///  │   │    O(batch_size)     │                                      │
///  │   └──────┬───────────────┘                                      │
///  │          │ empty                                                │
///  │          ▼                                                      │
///  │   ┌──────────────────────┐                                      │
///  │   │ 3. Victim stealing   │  ◄── Randomized to avoid hot spots  │
///  │   │    O(steal_tries)    │      FIFO steal preserves fairness   │
///  │   │    random victim     │                                      │
///  │   └──────────────────────┘                                      │
///  │                                                                 │
///  └─────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Why This Order?
///
/// 1. **Local pop**: Zero contention (single-threaded fast path), best locality.
///    Tasks spawned locally likely operate on data still in L1/L2 cache.
///
/// 2. **Injector**: External work needs distribution. Batch steal moves multiple
///    tasks to the local deque, amortizing the cost of global queue access.
///
/// 3. **Stealing**: Last resort when both local and injector are empty.
///    Randomized victim selection prevents "thundering herd" on a single hot worker.
///
/// # Randomized Victim Selection
///
/// Instead of round-robin (which causes correlated stealing when all workers
/// are idle), we pick random victims. This distributes steal attempts uniformly,
/// reducing contention spikes.
///
/// The formula `victim = rng.next_usize(n-1); if victim >= self { victim += 1 }`
/// ensures we never steal from ourselves while maintaining uniform distribution
/// over the remaining N-1 workers.
#[inline(always)]
pub(crate) fn pop_task<T, S, C>(
    steal_tries: u32,
    ctx: &mut C,
) -> Option<(T, PopSource, Option<usize>)>
where
    C: WorkerCtxLike<T, S>,
{
    // 1) Local fast path (LIFO, best cache locality)
    if let Some(t) = ctx.pop_local() {
        return Some((t, PopSource::Local, None));
    }

    // 2) Global injector (batch steal reduces contention)
    if let Some(t) = ctx.steal_from_injector() {
        return Some((t, PopSource::Injector, None));
    }

    // 3) Randomized victim stealing
    let n = ctx.worker_count();
    if n <= 1 {
        return None;
    }

    for _ in 0..steal_tries {
        // Pick random victim, excluding self
        // Formula: [0, n-1) → [0, n) \ {self}
        let mut victim = ctx.rng_next_usize(n - 1);
        if victim >= ctx.worker_id() {
            victim += 1;
        }

        if let Some(t) = ctx.steal_from_victim(victim) {
            ctx.record_steal_success();
            return Some((t, PopSource::Steal, Some(victim)));
        }

        ctx.record_steal_attempt();
    }

    None
}

/// Execute a single deterministic worker step.
///
/// This mirrors the production worker loop but avoids blocking. The caller
/// is responsible for handling `ShouldPark` (e.g., by parking or recording
/// a park intent in simulation).
pub(crate) fn worker_step<T, S, C, RunnerFn, Idle, Trace>(
    cfg: &ExecutorConfig,
    runner: &RunnerFn,
    ctx: &mut C,
    idle: &mut Idle,
    trace: &mut Trace,
) -> WorkerStepResult<Trace::TaskTag>
where
    T: Send + 'static,
    C: WorkerCtxLike<T, S>,
    RunnerFn: Fn(T, &mut C) + 'static,
    Idle: IdleHooks,
    Trace: TraceHooks<T>,
{
    if ctx.done_flag() {
        return WorkerStepResult::ExitDone;
    }

    if let Some((task, source, victim)) = pop_task(cfg.steal_tries, ctx) {
        idle.on_work();

        let tag = trace.tag_task(&task);
        if trace.is_enabled() {
            trace.on_event(ExecTraceEvent::Pop {
                wid: ctx.worker_id(),
                source,
                victim,
                tag,
            });
        }

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            (runner)(task, ctx);
        }));

        if let Err(p) = res {
            ctx.shared_state_fetch_sub(COUNT_UNIT);
            ctx.record_panic(p);
            if trace.is_enabled() {
                trace.on_event(ExecTraceEvent::PanicRecorded);
            }
            return WorkerStepResult::ExitPanicked;
        }

        let prev_state = ctx.shared_state_fetch_sub(COUNT_UNIT);
        let prev_count = in_flight(prev_state);
        debug_assert!(prev_count > 0, "in_flight underflow");

        if prev_count == 1 && !is_accepting(prev_state) {
            ctx.initiate_done();
            if trace.is_enabled() {
                trace.on_event(ExecTraceEvent::InitiateDone);
            }
        }

        return WorkerStepResult::RanTask {
            tag,
            source,
            victim,
        };
    }

    let state = ctx.shared_state_load();
    if in_flight(state) == 0 && !is_accepting(state) {
        ctx.initiate_done();
        if trace.is_enabled() {
            trace.on_event(ExecTraceEvent::InitiateDone);
        }
        return WorkerStepResult::ExitDone;
    }

    match idle.on_idle(cfg) {
        IdleAction::Continue => WorkerStepResult::NoWork,
        IdleAction::Park { timeout } => WorkerStepResult::ShouldPark { timeout },
    }
}
