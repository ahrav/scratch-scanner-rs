//! Deterministic, step-driven executor model for the scheduler harness.
//!
//! This module mirrors the production scheduling policy (LIFO locals, FIFO
//! injector, FIFO steals, wake-on-hoard, round-robin unpark) without using
//! OS threads. It is intended for exhaustive and seeded simulation runs.
//!
//! # Invariants
//!
//! - `state` stores the combined `(in_flight << 1) | accepting` word.
//! - Local queues are LIFO for the owning worker; steals are FIFO.
//! - `unpark_one` uses round-robin selection to match production fairness.
//! - `done` is monotonic: once set, it remains true for the run.
//!
//! # Design Notes
//!
//! - `SimExecutor` implements [`WorkerCtxLike`] directly so the core
//!   [`worker_step`] logic runs unchanged.
//! - Park/unpark is modeled with a single boolean token per worker, mirroring
//!   the production parker semantics closely enough for scheduling validation.
//! - The harness intentionally avoids OS sleep; the driver chooses the next
//!   enabled action when a worker reports `ShouldPark`.

#![cfg(any(test, feature = "scheduler-sim"))]
#![allow(dead_code)]

use std::any::Any;
use std::collections::VecDeque;
use std::time::Duration;

use super::executor::ExecutorConfig;
use super::executor_core::{
    in_flight, is_accepting, worker_step, IdleAction, IdleHooks, NoopTrace, TraceHooks,
    WorkerCtxLike, WorkerStepResult, ACCEPTING_BIT, COUNT_UNIT, WAKE_ON_HOARD_THRESHOLD,
};
use super::rng::XorShift64;

/// Simulation configuration for the executor policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SimExecCfg {
    /// Number of simulated workers.
    pub workers: usize,
    /// Steal attempts per idle cycle.
    pub steal_tries: u32,
    /// Seed for deterministic victim selection.
    pub seed: u64,
    /// Wake-on-hoard threshold (defaults to the production constant).
    pub wake_on_hoard_threshold: u32,
}

impl SimExecCfg {
    pub(crate) fn new(workers: usize, seed: u64) -> Self {
        Self {
            workers,
            steal_tries: 4,
            seed,
            wake_on_hoard_threshold: WAKE_ON_HOARD_THRESHOLD,
        }
    }

    pub(crate) fn to_executor_config(self) -> ExecutorConfig {
        // Spin/park values are placeholders: simulation does not sleep,
        // but the shared `worker_step` requires a config.
        ExecutorConfig {
            workers: self.workers,
            seed: self.seed,
            steal_tries: self.steal_tries,
            spin_iters: 1,
            park_timeout: Duration::from_micros(1),
            pin_threads: false,
        }
    }

    pub(crate) fn validate(self) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.steal_tries > 0, "steal_tries must be > 0");
    }
}

/// Per-worker simulation state.
#[derive(Debug)]
pub(crate) struct SimWorker<T, S> {
    /// Local deque: LIFO pop for owner, FIFO steal for victims.
    pub(crate) local: VecDeque<T>,
    /// True once the worker has parked (until unpark token is consumed).
    pub(crate) parked: bool,
    /// Park token that allows one wake-up to proceed.
    pub(crate) unpark_token: bool,
    /// Wake-on-hoard counter for local spawns.
    pub(crate) local_spawns_since_wake: u32,
    /// Per-worker RNG for victim selection.
    pub(crate) rng: XorShift64,
    /// Per-worker scratch used by the task runner.
    pub(crate) scratch: S,
}

impl<T, S> SimWorker<T, S> {
    fn new(worker_id: usize, seed: u64, scratch: S) -> Self {
        let rng_seed = seed ^ (worker_id as u64).wrapping_mul(0x9E3779B97F4A7C15);
        Self {
            local: VecDeque::new(),
            parked: false,
            unpark_token: false,
            local_spawns_since_wake: 0,
            rng: XorShift64::new(rng_seed),
            scratch,
        }
    }
}

/// Deterministic executor model used by the scheduler harness.
#[derive(Debug)]
pub(crate) struct SimExecutor<T, S> {
    /// Global injector queue (FIFO).
    pub(crate) injector: VecDeque<T>,
    /// Per-worker state (locals, RNG, park tokens).
    pub(crate) workers: Vec<SimWorker<T, S>>,
    /// Combined `(in_flight << 1) | accepting` state word.
    pub(crate) state: usize,
    /// Shutdown flag mirroring the production executor.
    pub(crate) done: bool,
    /// Round-robin counter for unpark selection.
    pub(crate) next_unpark: usize,
    /// First panic captured by the harness.
    pub(crate) panic: Option<Box<dyn Any + Send + 'static>>,

    exec_cfg: ExecutorConfig,
    wake_on_hoard_threshold: u32,
    /// Active worker index for context-sensitive operations (spawn_local, RNG).
    current_worker: usize,
}

impl<T: Send + 'static, S> SimExecutor<T, S> {
    /// Construct a new simulator from config and per-worker scratch factory.
    ///
    /// # Panics
    ///
    /// Panics if the config is invalid.
    pub(crate) fn new(cfg: SimExecCfg, scratch_init: impl Fn(usize) -> S) -> Self {
        cfg.validate();
        let exec_cfg = cfg.to_executor_config();

        let mut workers = Vec::with_capacity(cfg.workers);
        for worker_id in 0..cfg.workers {
            workers.push(SimWorker::new(worker_id, cfg.seed, scratch_init(worker_id)));
        }

        Self {
            injector: VecDeque::new(),
            workers,
            state: ACCEPTING_BIT,
            done: false,
            next_unpark: 0,
            panic: None,
            exec_cfg,
            wake_on_hoard_threshold: cfg.wake_on_hoard_threshold,
            current_worker: 0,
        }
    }

    pub(crate) fn spawn_local(&mut self, task: T) {
        let wid = self.current_worker;
        self.spawn_local_for(wid, task);
    }

    /// Spawn a task into a specific worker's local queue.
    pub(crate) fn spawn_local_for(&mut self, wid: usize, task: T) {
        // Internal spawns always increment in-flight count.
        self.state = self.state.wrapping_add(COUNT_UNIT);
        let worker = &mut self.workers[wid];
        worker.local.push_back(task);

        worker.local_spawns_since_wake = worker.local_spawns_since_wake.saturating_add(1);
        if worker.local_spawns_since_wake >= self.wake_on_hoard_threshold {
            worker.local_spawns_since_wake = 0;
            self.unpark_one();
        }
    }

    pub(crate) fn spawn_global(&mut self, task: T) {
        // Global spawns always wake a sibling to reduce hoarding.
        self.state = self.state.wrapping_add(COUNT_UNIT);
        self.injector.push_back(task);
        self.unpark_one();
    }

    pub(crate) fn spawn_external(&mut self, task: T) -> Result<(), T> {
        // External spawns must respect the accepting gate.
        if !is_accepting(self.state) {
            return Err(task);
        }
        self.state = self.state.wrapping_add(COUNT_UNIT);
        self.injector.push_back(task);
        self.unpark_one();
        Ok(())
    }

    pub(crate) fn close_gate(&mut self) -> usize {
        let prev = self.state;
        self.state &= !ACCEPTING_BIT;
        prev
    }

    pub(crate) fn in_flight(&self) -> usize {
        in_flight(self.state)
    }

    /// Execute a single step for one worker.
    ///
    /// The caller must handle `ShouldPark` by choosing another enabled action.
    pub(crate) fn step_worker<Runner, Idle, Trace>(
        &mut self,
        wid: usize,
        runner: &Runner,
        idle: &mut Idle,
        trace: &mut Trace,
    ) -> WorkerStepResult<Trace::TaskTag>
    where
        Runner: Fn(T, &mut SimExecutor<T, S>) + 'static,
        Idle: IdleHooks,
        Trace: TraceHooks<T>,
    {
        // Simulate park token semantics: a parked worker only proceeds if it
        // has an unpark token available.
        let worker = &mut self.workers[wid];
        if worker.parked {
            if !worker.unpark_token {
                return WorkerStepResult::NoWork;
            }
            worker.unpark_token = false;
            worker.parked = false;
        }

        self.current_worker = wid;
        let exec_cfg = self.exec_cfg;
        let res = worker_step(&exec_cfg, runner, self, idle, trace);

        if matches!(res, WorkerStepResult::ShouldPark { .. }) {
            self.workers[wid].parked = true;
        }

        res
    }

    pub(crate) fn step_worker_no_trace<Runner>(
        &mut self,
        wid: usize,
        runner: &Runner,
    ) -> WorkerStepResult<<NoopTrace as TraceHooks<T>>::TaskTag>
    where
        Runner: Fn(T, &mut SimExecutor<T, S>) + 'static,
    {
        let mut idle = SimIdle;
        let mut trace = NoopTrace;
        self.step_worker(wid, runner, &mut idle, &mut trace)
    }
}

impl<T: Send + 'static, S> WorkerCtxLike<T, S> for SimExecutor<T, S> {
    fn worker_id(&self) -> usize {
        self.current_worker
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    fn scratch_mut(&mut self) -> &mut S {
        &mut self.workers[self.current_worker].scratch
    }

    fn pop_local(&mut self) -> Option<T> {
        self.workers[self.current_worker].local.pop_back()
    }

    fn push_local(&mut self, task: T) {
        self.workers[self.current_worker].local.push_back(task);
    }

    fn push_injector(&mut self, task: T) {
        self.injector.push_back(task);
    }

    fn steal_from_injector(&mut self) -> Option<T> {
        self.injector.pop_front()
    }

    fn steal_from_victim(&mut self, victim: usize) -> Option<T> {
        self.workers[victim].local.pop_front()
    }

    fn shared_state_load(&self) -> usize {
        self.state
    }

    fn shared_state_fetch_sub(&mut self, delta: usize) -> usize {
        let prev = self.state;
        self.state = self.state.wrapping_sub(delta);
        prev
    }

    fn shared_state_close_gate(&mut self) -> usize {
        self.close_gate()
    }

    fn shared_state_increment(&mut self) -> Result<(), ()> {
        if !is_accepting(self.state) {
            return Err(());
        }
        self.state = self.state.wrapping_add(COUNT_UNIT);
        Ok(())
    }

    fn initiate_done(&mut self) {
        self.done = true;
        self.unpark_all();
    }

    fn done_flag(&self) -> bool {
        self.done
    }

    fn unpark_one(&mut self) {
        let n = self.workers.len();
        if n == 0 {
            return;
        }

        let idx = self.next_unpark % n;
        self.next_unpark = self.next_unpark.wrapping_add(1);

        let worker = &mut self.workers[idx];
        worker.unpark_token = true;
        worker.parked = false;
    }

    fn unpark_all(&mut self) {
        for worker in &mut self.workers {
            worker.unpark_token = true;
            worker.parked = false;
        }
    }

    fn record_panic(&mut self, payload: Box<dyn Any + Send + 'static>) {
        if self.panic.is_none() {
            self.panic = Some(payload);
        }
        self.done = true;
        self.unpark_all();
    }

    fn rng_next_usize(&mut self, upper: usize) -> usize {
        self.workers[self.current_worker].rng.next_usize(upper)
    }
}

struct SimIdle;

impl IdleHooks for SimIdle {
    fn on_work(&mut self) {}

    fn on_idle(&mut self, _cfg: &ExecutorConfig) -> IdleAction {
        // Simulation never sleeps; a "park" means the driver must pick
        // another enabled action to make progress.
        IdleAction::Park {
            timeout: Duration::from_micros(1),
        }
    }
}
