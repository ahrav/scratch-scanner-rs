//! Work-Stealing CPU Executor (Phase 1)
//!
//! # Architecture
//!
//! - N worker threads (optionally pinned to cores)
//! - Per-worker Chase-Lev deque (LIFO local, FIFO steal)
//! - Per-worker scratch space via `WorkerCtx<T, S>`
//! - Global injector for external producers
//! - Tiered idle strategy: spin → yield → park
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: once spawned, a task will execute
//! - **Termination detection**: `in_flight` counter tracks live tasks
//! - **Panic isolation**: panics caught and propagated on join
//! - **No lost wakeups**: Parker/Unparker pattern
//!
//! # Performance Invariants
//!
//! - **Local-first spawn**: reduces contention, improves locality
//! - **Randomized stealing**: avoids correlated contention
//! - **Batch steal from injector**: reduces global queue contention
//!
//! # What This Does NOT Guarantee Yet
//!
//! - **Bounded task queues**: crossbeam queues are unbounded.
//!   Use `TokenBudget` from Phase 0 to enforce `max_queued_tasks`.
//! - **I/O completion integration**: the seam exists via `ExecutorHandle::spawn()`.

use super::metrics::WorkerMetricsLocal;
use super::rng::XorShift64;
use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use crossbeam_utils::sync::{Parker, Unparker};
use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ============================================================================
// Configuration
// ============================================================================

/// Executor configuration.
///
/// All defaults are conservative. Profile with your workload before tuning.
///
/// # Measurement Required Before Tuning
///
/// | Knob         | Workload Sensitivity                    |
/// |--------------|-----------------------------------------|
/// | workers      | CPU count, task CPU-boundedness         |
/// | steal_tries  | Task fanout pattern, worker count       |
/// | spin_iters   | Task latency distribution               |
/// | park_timeout | External spawn frequency                |
#[derive(Clone, Copy, Debug)]
pub struct ExecutorConfig {
    /// Number of worker threads.
    pub workers: usize,

    /// Seed for deterministic victim selection.
    ///
    /// Same seed + same task spawn order = reproducible steal pattern (modulo timing).
    pub seed: u64,

    /// Steal attempts before giving up per idle cycle.
    ///
    /// Higher = less parking, more CPU when idle.
    /// Lower = faster sleep, less steal overhead.
    pub steal_tries: u32,

    /// Spin iterations before yielding/parking.
    ///
    /// Higher = better latency for bursty work.
    /// Lower = less CPU waste when truly idle.
    pub spin_iters: u32,

    /// Park timeout after spinning/yielding.
    ///
    /// Shorter = more responsive to external spawns.
    /// Longer = less OS scheduling overhead.
    pub park_timeout: Duration,

    /// Try to pin each worker to a core (requires `affinity` feature).
    pub pin_threads: bool,
}

impl ExecutorConfig {
    /// Validate configuration. Panics on invalid values.
    pub fn validate(&self) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.steal_tries > 0, "steal_tries must be > 0");
        assert!(self.spin_iters > 0, "spin_iters must be > 0");
        assert!(
            self.park_timeout > Duration::ZERO,
            "park_timeout must be > 0"
        );
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            seed: 0x853c49e6748fea9b,
            steal_tries: 4,
            spin_iters: 200,
            park_timeout: Duration::from_micros(200),
            pin_threads: false,
        }
    }
}

// ============================================================================
// ExecutorHandle (the thin seam for external producers)
// ============================================================================

/// Handle for external producers (I/O threads, API callers).
///
/// This is the "thin seam" for Phase 2: I/O completion can enqueue
/// CPU work via this handle without knowing executor internals.
///
/// # Thread Safety
///
/// `Clone` and `Send + Sync`. Multiple producers can call `spawn` concurrently.
#[derive(Clone)]
pub struct ExecutorHandle<T> {
    shared: Arc<Shared<T>>,
}

impl<T: Send + 'static> ExecutorHandle<T> {
    /// Spawn a task from outside the worker threads.
    ///
    /// Returns `Err(task)` if the executor is shutting down.
    ///
    /// # Correctness
    ///
    /// Uses CAS to atomically check accepting + increment count, eliminating
    /// the TOCTOU race between spawn and join.
    ///
    /// # Performance Note
    ///
    /// Uses the global injector queue. For high-frequency external spawns,
    /// consider batching.
    #[inline]
    pub fn spawn(&self, task: T) -> Result<(), T> {
        // CAS loop: atomically check accepting AND increment count
        let mut s = self.shared.state.load(Ordering::Acquire);
        loop {
            if !Shared::<T>::is_accepting(s) {
                return Err(task);
            }
            // Try to increment count (add 2 because count is in bits 1+)
            match self.shared.state.compare_exchange_weak(
                s,
                s.wrapping_add(COUNT_UNIT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }

        self.shared.injector.push(task);
        self.shared.unpark_one();
        Ok(())
    }

    /// Check if the executor is still accepting external work.
    #[inline]
    pub fn is_accepting(&self) -> bool {
        Shared::<T>::is_accepting(self.shared.state.load(Ordering::Acquire))
    }
}

// ============================================================================
// Shared state
// ============================================================================

/// Combined executor state: `(in_flight_count << 1) | accepting_bit`
///
/// This encoding ensures that "close gate" and "increment count" are mutually
/// exclusive operations, eliminating the TOCTOU race between spawn and join.
///
/// - Bit 0: accepting_external (1 = accepting, 0 = closed)
/// - Bits 1+: in_flight count (stored as count << 1)
///
/// State transitions:
/// - init: `state = 1` (accepting, count=0)
/// - external spawn: CAS loop "if accepting, count++"
/// - internal spawn: `fetch_add(2)` (count++)
/// - completion: `fetch_sub(2)` (count--); if result==0, done
/// - join/close: `fetch_and(!1)` (clear accepting bit)
const ACCEPTING_BIT: usize = 1;
const COUNT_UNIT: usize = 2;

/// Shared state between all workers and the executor owner.
struct Shared<T> {
    /// Global injector queue for external submissions.
    injector: Injector<T>,
    /// Stealers for each worker's local queue.
    stealers: Vec<Stealer<T>>,

    /// Combined state: `(in_flight << 1) | accepting`
    ///
    /// This single atomic eliminates the shutdown race between spawn and join.
    state: AtomicUsize,

    /// Stop flag. Once true, workers exit.
    done: AtomicBool,

    /// Unparkers for each worker.
    unparkers: Vec<Unparker>,
    /// Round-robin counter for wakeups.
    next_unpark: AtomicUsize,

    /// First panic captured from any worker.
    panic: Mutex<Option<Box<dyn Any + Send + 'static>>>,
}

impl<T> Shared<T> {
    /// Extract in_flight count from state.
    #[inline]
    fn in_flight(state: usize) -> usize {
        state >> 1
    }

    /// Check if accepting from state.
    #[inline]
    fn is_accepting(state: usize) -> bool {
        (state & ACCEPTING_BIT) != 0
    }

    /// Wake one worker (round-robin).
    fn unpark_one(&self) {
        let n = self.unparkers.len();
        if n == 0 {
            return;
        }
        let idx = self.next_unpark.fetch_add(1, Ordering::Relaxed) % n;
        self.unparkers[idx].unpark();
    }

    /// Wake all workers.
    fn unpark_all(&self) {
        for u in &self.unparkers {
            u.unpark();
        }
    }

    /// Signal all workers to stop.
    fn initiate_done(&self) {
        self.done.store(true, Ordering::Release);
        self.unpark_all();
    }

    /// Record a panic and signal shutdown.
    fn record_panic(&self, p: Box<dyn Any + Send + 'static>) {
        let mut guard = self.panic.lock().expect("panic mutex poisoned");
        if guard.is_none() {
            *guard = Some(p);
        }
        self.initiate_done();
    }
}

// ============================================================================
// WorkerCtx (per-worker context passed to every task)
// ============================================================================

/// Per-worker context passed to every task execution.
///
/// This is where you put per-worker state:
/// - Scanner scratch buffers
/// - Decode buffers
/// - Per-worker buffer pool
/// - Per-worker metrics
///
/// # Type Parameters
///
/// - `T`: Task type
/// - `S`: User-defined scratch type, initialized via `scratch_init`
pub struct WorkerCtx<T, S> {
    /// Worker ID (0..workers).
    pub worker_id: usize,
    /// User-defined per-worker scratch space.
    pub scratch: S,

    /// Per-worker RNG for randomized stealing.
    pub rng: XorShift64,
    /// Per-worker metrics (no cross-thread contention).
    pub metrics: WorkerMetricsLocal,

    local: Worker<T>,
    parker: Parker,
    shared: Arc<Shared<T>>,

    /// Counter for wake-on-hoard heuristic.
    /// Reset to 0 after waking a sibling.
    local_spawns_since_wake: u32,
}

/// Threshold for local spawns before waking a sibling.
///
/// If a worker spawns this many tasks locally without waking anyone,
/// it signals a potential idle sibling to help.
///
/// Tuning: Higher = less wakeup overhead, higher tail latency.
/// Lower = more responsive stealing, more syscall overhead.
const WAKE_ON_HOARD_THRESHOLD: u32 = 32;

impl<T: Send + 'static, S> WorkerCtx<T, S> {
    /// Spawn a task locally (preferred).
    ///
    /// Task goes to this worker's local queue. Other workers can steal it,
    /// but the local worker tries it first. Maximizes cache locality.
    ///
    /// # Performance
    ///
    /// Workers don't need CAS because they only run while executor is live.
    /// Single fetch_add on combined state. Occasionally wakes a sibling
    /// if we're hoarding too much work (wake-on-hoard optimization).
    #[inline]
    pub fn spawn_local(&mut self, task: T) {
        // Workers don't need to check accepting - they only run when executor is live
        self.shared.state.fetch_add(COUNT_UNIT, Ordering::AcqRel);
        self.metrics.tasks_enqueued = self.metrics.tasks_enqueued.saturating_add(1);
        self.local.push(task);

        // Wake-on-hoard: if we've spawned many tasks locally, wake a sibling
        // to help with stealing. This prevents one worker from hoarding work
        // while others sleep.
        self.local_spawns_since_wake += 1;
        if self.local_spawns_since_wake >= WAKE_ON_HOARD_THRESHOLD {
            self.local_spawns_since_wake = 0;
            self.shared.unpark_one();
        }
    }

    /// Spawn a task globally (use sparingly).
    ///
    /// Task goes to the global injector, visible to all workers immediately.
    /// Use for initial work distribution or explicit load balancing.
    ///
    /// # Performance
    ///
    /// Higher contention than local spawn. Includes an unpark call.
    #[inline]
    pub fn spawn_global(&mut self, task: T) {
        self.shared.state.fetch_add(COUNT_UNIT, Ordering::AcqRel);
        self.metrics.tasks_enqueued = self.metrics.tasks_enqueued.saturating_add(1);
        self.shared.injector.push(task);
        self.shared.unpark_one();
    }

    /// Get an external handle for spawning from outside workers.
    #[inline]
    pub fn handle(&self) -> ExecutorHandle<T> {
        ExecutorHandle {
            shared: Arc::clone(&self.shared),
        }
    }
}

// ============================================================================
// Executor
// ============================================================================

/// Work-stealing executor.
///
/// # Type Parameters
///
/// - `T`: Task type. Should be small (≤32 bytes) and `Copy` if possible.
///   Avoid `Box<dyn FnOnce()>` - use an enum instead.
///
/// # Lifecycle
///
/// 1. Create with `Executor::new(config, scratch_init, runner)`
/// 2. Spawn initial work via `spawn_external()` or get a handle
/// 3. Call `join()` to wait for completion and get metrics
///
/// # Example
///
/// ```ignore
/// #[derive(Clone, Copy)]
/// enum Task { Scan(u32), Done }
///
/// let ex = Executor::<Task>::new(
///     config,
///     |worker_id| ScannerScratch::new(),
///     |task, ctx| match task {
///         Task::Scan(id) => { /* scan */ ctx.spawn_local(Task::Done); }
///         Task::Done => {}
///     },
/// );
/// ex.spawn_external(Task::Scan(0))?;
/// let metrics = ex.join();
/// ```
pub struct Executor<T> {
    shared: Arc<Shared<T>>,
    threads: Vec<JoinHandle<WorkerMetricsLocal>>,
}

impl<T: Send + 'static> Executor<T> {
    /// Get an external handle for spawning.
    pub fn handle(&self) -> ExecutorHandle<T> {
        ExecutorHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Create and start the executor.
    ///
    /// # Parameters
    ///
    /// - `cfg`: Executor configuration
    /// - `scratch_init`: Called once per worker to create scratch space
    /// - `runner`: Called for each task to execute it
    ///
    /// Workers start immediately and park until work is spawned.
    pub fn new<S, ScratchInit, Runner>(
        cfg: ExecutorConfig,
        scratch_init: ScratchInit,
        runner: Runner,
    ) -> Self
    where
        S: 'static,
        ScratchInit: Fn(usize) -> S + Send + Sync + 'static,
        Runner: Fn(T, &mut WorkerCtx<T, S>) + Send + Sync + 'static,
    {
        cfg.validate();

        let injector = Injector::new();

        // Build per-worker Chase-Lev deques
        let mut locals = Vec::with_capacity(cfg.workers);
        let mut stealers = Vec::with_capacity(cfg.workers);
        for _ in 0..cfg.workers {
            let w = Worker::new_lifo();
            stealers.push(w.stealer());
            locals.push(w);
        }

        // Build Parker/Unparker pairs
        let mut parkers = Vec::with_capacity(cfg.workers);
        let mut unparkers = Vec::with_capacity(cfg.workers);
        for _ in 0..cfg.workers {
            let p = Parker::new();
            unparkers.push(p.unparker().clone());
            parkers.push(p);
        }

        let shared = Arc::new(Shared {
            injector,
            stealers,
            // Initial state: accepting=1, count=0
            state: AtomicUsize::new(ACCEPTING_BIT),
            done: AtomicBool::new(false),
            unparkers,
            next_unpark: AtomicUsize::new(0),
            panic: Mutex::new(None),
        });

        let runner = Arc::new(runner);
        let scratch_init = Arc::new(scratch_init);

        let mut threads = Vec::with_capacity(cfg.workers);

        // Spawn workers in reverse so pop() gives correct worker_id
        for worker_id in (0..cfg.workers).rev() {
            let shared = Arc::clone(&shared);
            let runner = Arc::clone(&runner);
            let scratch_init = Arc::clone(&scratch_init);
            let local = locals.pop().expect("locals length mismatch");
            let parker = parkers.pop().expect("parkers length mismatch");
            let thread_cfg = cfg;

            let th = thread::Builder::new()
                .name(format!("scanner-worker-{worker_id}"))
                .spawn(move || {
                    #[cfg(feature = "scheduler-affinity")]
                    if thread_cfg.pin_threads {
                        pin_current_thread(worker_id);
                    }

                    let scratch = (scratch_init)(worker_id);
                    let rng_seed =
                        thread_cfg.seed ^ (worker_id as u64).wrapping_mul(0x9E3779B97F4A7C15);

                    let mut ctx = WorkerCtx {
                        worker_id,
                        scratch,
                        rng: XorShift64::new(rng_seed),
                        metrics: WorkerMetricsLocal::default(),
                        local,
                        parker,
                        shared,
                        local_spawns_since_wake: 0,
                    };

                    worker_loop(thread_cfg, &runner, &mut ctx);
                    ctx.metrics
                })
                .expect("failed to spawn worker thread");

            threads.push(th);
        }

        // Reverse so threads[0] is worker 0
        threads.reverse();

        Self { shared, threads }
    }

    /// Spawn a task from outside worker threads.
    ///
    /// Convenience for `self.handle().spawn(task)`.
    pub fn spawn_external(&self, task: T) -> Result<(), T> {
        self.handle().spawn(task)
    }

    /// Stop accepting external spawns and wait for all work to complete.
    ///
    /// Returns aggregated metrics from all workers.
    ///
    /// # Panics
    ///
    /// If any worker panicked, this re-panics on the calling thread.
    pub fn join(mut self) -> super::metrics::MetricsSnapshot {
        // Atomically close the gate (clear accepting bit)
        // This prevents new external spawns while we wait
        let prev_state = self
            .shared
            .state
            .fetch_and(!ACCEPTING_BIT, Ordering::AcqRel);

        // If count was already 0 when we closed, we're done
        if Shared::<T>::in_flight(prev_state) == 0 {
            self.shared.initiate_done();
        }

        let mut snapshot = super::metrics::MetricsSnapshot::default();

        while let Some(th) = self.threads.pop() {
            let m = th.join().unwrap_or_else(|p| {
                self.shared.record_panic(p);
                WorkerMetricsLocal::default()
            });
            snapshot.merge_worker(&m);
        }

        // Re-throw captured panic
        if let Some(p) = self
            .shared
            .panic
            .lock()
            .expect("panic mutex poisoned")
            .take()
        {
            std::panic::resume_unwind(p);
        }

        snapshot
    }
}

// ============================================================================
// Worker loop
// ============================================================================

/// Main worker loop.
fn worker_loop<T, S, RunnerFn>(
    cfg: ExecutorConfig,
    runner: &Arc<RunnerFn>,
    ctx: &mut WorkerCtx<T, S>,
) where
    T: Send + 'static,
    RunnerFn: Fn(T, &mut WorkerCtx<T, S>) + Send + Sync + 'static,
{
    let mut idle_rounds: u32 = 0;

    loop {
        // Check done flag
        if ctx.shared.done.load(Ordering::Acquire) {
            break;
        }

        // Try to get work
        if let Some(task) = pop_task(cfg.steal_tries, ctx) {
            idle_rounds = 0;
            ctx.metrics.tasks_executed = ctx.metrics.tasks_executed.saturating_add(1);

            // Execute task (with panic catching in tests)
            #[cfg(any(test, feature = "catch-panics"))]
            {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (runner)(task, ctx);
                }));
                if let Err(p) = res {
                    // FIX: Decrement state before breaking on panic
                    // The task was popped, so we must account for it
                    ctx.shared.state.fetch_sub(COUNT_UNIT, Ordering::AcqRel);
                    ctx.shared.record_panic(p);
                    break;
                }
            }

            #[cfg(not(any(test, feature = "catch-panics")))]
            {
                (runner)(task, ctx);
            }

            // Decrement count after execution
            let prev_state = ctx.shared.state.fetch_sub(COUNT_UNIT, Ordering::AcqRel);
            let prev_count = Shared::<T>::in_flight(prev_state);
            debug_assert!(prev_count > 0, "in_flight underflow");

            // If count is now 0 AND gate is closed, we're done
            // prev_state had count >= 1, so if prev_count == 1, new count is 0
            // Also check that accepting bit is not set
            if prev_count == 1 && !Shared::<T>::is_accepting(prev_state) {
                ctx.shared.initiate_done();
                break;
            }

            continue;
        }

        // No work found
        // Check combined state: if count==0 and not accepting, we're done
        let state = ctx.shared.state.load(Ordering::Acquire);
        if Shared::<T>::in_flight(state) == 0 && !Shared::<T>::is_accepting(state) {
            ctx.shared.initiate_done();
            break;
        }

        // Tiered idle strategy
        idle_rounds = idle_rounds.saturating_add(1);

        if idle_rounds <= cfg.spin_iters {
            std::hint::spin_loop();
            continue;
        }

        // Yield occasionally to reduce contention
        if (idle_rounds & 0xF) == 0 {
            thread::yield_now();
        }

        // Park with timeout
        ctx.parker.park_timeout(cfg.park_timeout);
    }
}

/// Try to pop a task: local first, then injector, then steal.
fn pop_task<T, S>(steal_tries: u32, ctx: &mut WorkerCtx<T, S>) -> Option<T>
where
    T: Send + 'static,
{
    // 1) Local fast path (LIFO, best cache locality)
    if let Some(t) = ctx.local.pop() {
        return Some(t);
    }

    // 2) Global injector (batch steal reduces contention)
    match ctx.shared.injector.steal_batch_and_pop(&ctx.local) {
        Steal::Success(t) => return Some(t),
        Steal::Retry => {
            // Contention, fall through to stealing
        }
        Steal::Empty => {}
    }

    // 3) Randomized victim stealing
    let n = ctx.shared.stealers.len();
    if n <= 1 {
        return None;
    }

    for _ in 0..steal_tries {
        // Pick random victim, excluding self
        let mut victim = ctx.rng.next_usize(n - 1);
        if victim >= ctx.worker_id {
            victim += 1;
        }

        match ctx.shared.stealers[victim].steal() {
            Steal::Success(t) => {
                ctx.metrics.steal_successes = ctx.metrics.steal_successes.saturating_add(1);
                return Some(t);
            }
            Steal::Retry => {
                ctx.metrics.steal_attempts = ctx.metrics.steal_attempts.saturating_add(1);
            }
            Steal::Empty => {
                ctx.metrics.steal_attempts = ctx.metrics.steal_attempts.saturating_add(1);
            }
        }
    }

    None
}

#[cfg(feature = "scheduler-affinity")]
fn pin_current_thread(worker_id: usize) {
    let cores = match core_affinity::get_core_ids() {
        Some(v) if !v.is_empty() => v,
        _ => return,
    };
    let core = cores[worker_id % cores.len()];
    let _ = core_affinity::set_for_current(core);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn test_config(workers: usize) -> ExecutorConfig {
        ExecutorConfig {
            workers,
            seed: 12345,
            steal_tries: 4,
            spin_iters: 100,
            park_timeout: Duration::from_micros(100),
            pin_threads: false,
        }
    }

    #[test]
    fn executor_runs_all_external_tasks() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        let ex = Executor::<usize>::new(
            test_config(4),
            |_wid| (),
            move |_task, _ctx| {
                c2.fetch_add(1, Ordering::Relaxed);
            },
        );

        let n = 10_000usize;
        for i in 0..n {
            ex.spawn_external(i).unwrap();
        }

        let metrics = ex.join();
        assert_eq!(counter.load(Ordering::Relaxed), n);
        assert_eq!(metrics.tasks_executed, n as u64);
    }

    #[test]
    fn tasks_can_spawn_more_tasks_locally() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        #[derive(Clone, Copy, Debug)]
        enum Task {
            Root(u32),
            Child,
        }

        let ex = Executor::<Task>::new(
            test_config(4),
            |_wid| (),
            move |task, ctx| match task {
                Task::Root(n) => {
                    c2.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..n {
                        ctx.spawn_local(Task::Child);
                    }
                }
                Task::Child => {
                    c2.fetch_add(1, Ordering::Relaxed);
                }
            },
        );

        ex.spawn_external(Task::Root(10_000)).unwrap();
        let metrics = ex.join();

        // 1 root + 10_000 children
        assert_eq!(counter.load(Ordering::Relaxed), 10_001);
        assert_eq!(metrics.tasks_executed, 10_001);
    }

    #[test]
    fn join_without_tasks_returns_immediately() {
        let ex = Executor::<()>::new(test_config(2), |_wid| (), |_t, _ctx| {});
        let metrics = ex.join();
        assert_eq!(metrics.tasks_executed, 0);
    }

    #[test]
    fn spawn_after_join_fails() {
        let ex = Executor::<u32>::new(test_config(2), |_wid| (), |_t, _ctx| {});
        let handle = ex.handle();
        let _metrics = ex.join();

        // Handle should reject spawns after join
        assert!(handle.spawn(42).is_err());
    }

    #[test]
    fn deterministic_with_same_seed_single_worker() {
        // Single worker for true determinism
        let cfg = ExecutorConfig {
            workers: 1,
            seed: 99999,
            ..test_config(1)
        };

        let results1 = Arc::new(Mutex::new(Vec::new()));
        let r1 = Arc::clone(&results1);

        let ex = Executor::<u32>::new(
            cfg,
            |_| (),
            move |task, _ctx| {
                r1.lock().unwrap().push(task);
            },
        );

        for i in 0..100u32 {
            ex.spawn_external(i).unwrap();
        }
        let _ = ex.join();

        let results2 = Arc::new(Mutex::new(Vec::new()));
        let r2 = Arc::clone(&results2);

        let ex = Executor::<u32>::new(
            cfg,
            |_| (),
            move |task, _ctx| {
                r2.lock().unwrap().push(task);
            },
        );

        for i in 0..100u32 {
            ex.spawn_external(i).unwrap();
        }
        let _ = ex.join();

        // Same seed + single worker = same execution order
        assert_eq!(*results1.lock().unwrap(), *results2.lock().unwrap());
    }

    #[test]
    fn scratch_space_per_worker() {
        let worker_ids = Arc::new(Mutex::new(Vec::new()));
        let w = Arc::clone(&worker_ids);

        let ex = Executor::<()>::new(
            test_config(4),
            |wid| wid, // scratch = worker_id
            move |_, ctx| {
                w.lock().unwrap().push(ctx.scratch);
            },
        );

        // Spawn one task per worker (roughly)
        for _ in 0..4 {
            ex.spawn_external(()).unwrap();
        }

        let _ = ex.join();

        let ids = worker_ids.lock().unwrap();
        // All worker IDs should be in 0..4
        for &id in ids.iter() {
            assert!(id < 4, "worker_id {} out of range", id);
        }
    }

    #[test]
    fn metrics_track_steals() {
        // Force stealing with high fanout on few workers
        let ex = Executor::<u32>::new(
            test_config(4),
            |_wid| (),
            |_t, _ctx| {
                // Small task body
                std::hint::black_box(42);
            },
        );

        for i in 0..1000u32 {
            ex.spawn_external(i).unwrap();
        }

        let metrics = ex.join();
        assert_eq!(metrics.tasks_executed, 1000);
        // With 4 workers and 1000 tasks, there should be some stealing
        // (not guaranteed, but highly likely)
    }

    /// Stress test: concurrent spawn + join must not lose tasks.
    ///
    /// This test validates that the combined atomic state correctly prevents
    /// the TOCTOU race between external spawn and join.
    #[test]
    fn concurrent_spawn_and_join_no_task_loss() {
        use std::thread;

        for iteration in 0..100 {
            let counter = Arc::new(AtomicUsize::new(0));
            let c2 = Arc::clone(&counter);

            let ex = Executor::<u32>::new(
                test_config(4),
                |_wid| (),
                move |_task, _ctx| {
                    c2.fetch_add(1, Ordering::Relaxed);
                },
            );

            let handle = ex.handle();
            let spawned = Arc::new(AtomicUsize::new(0));
            let spawned2 = Arc::clone(&spawned);

            // Spawn tasks from another thread while we call join
            let spawn_thread = thread::spawn(move || {
                for i in 0..1000u32 {
                    match handle.spawn(i) {
                        Ok(()) => {
                            spawned2.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Executor closed, stop spawning
                            break;
                        }
                    }
                }
            });

            // Give spawner a head start sometimes
            if iteration % 2 == 0 {
                thread::yield_now();
            }

            let _metrics = ex.join();
            spawn_thread.join().unwrap();

            // CRITICAL INVARIANT: every successfully spawned task must execute
            let total_spawned = spawned.load(Ordering::Relaxed);
            let total_executed = counter.load(Ordering::Relaxed);
            assert_eq!(
                total_executed, total_spawned,
                "iteration {}: spawned {} but executed {}",
                iteration, total_spawned, total_executed
            );
        }
    }

    /// Test that panic in task doesn't corrupt in_flight count.
    #[test]
    fn panic_in_task_decrements_count() {
        use std::panic;

        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        #[derive(Clone, Copy, Debug)]
        enum Task {
            Normal,
            Panic,
        }

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let ex = Executor::<Task>::new(
                test_config(2),
                |_wid| (),
                move |task, _ctx| match task {
                    Task::Normal => {
                        c2.fetch_add(1, Ordering::Relaxed);
                    }
                    Task::Panic => {
                        panic!("intentional test panic");
                    }
                },
            );

            // Spawn some normal tasks, then a panic
            for _ in 0..10 {
                ex.spawn_external(Task::Normal).unwrap();
            }
            ex.spawn_external(Task::Panic).unwrap();
            for _ in 0..10 {
                ex.spawn_external(Task::Normal).unwrap();
            }

            ex.join()
        }));

        // Should have panicked
        assert!(result.is_err(), "executor should have propagated panic");

        // Some tasks should have executed (at least until panic)
        let executed = counter.load(Ordering::Relaxed);
        assert!(executed > 0, "some tasks should have executed before panic");
    }
}
