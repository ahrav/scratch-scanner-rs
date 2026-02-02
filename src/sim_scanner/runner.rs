//! Deterministic scanner simulation runner.
//!
//! The baseline runner executes a discover task and a set of file scan tasks
//! over a single-threaded simulated executor. Each file scan task processes
//! one chunk per step, applying overlap-based deduplication and collecting
//! findings in a deterministic order.

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::{Deserialize, Serialize};

use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, SimTaskState, StepResult};
use crate::sim::fs::{SimFs, SimPath};
use crate::sim_scanner::scenario::{RunConfig, Scenario};
use crate::{Engine, FileId, FindingRec, ScanScratch};

/// Result of a simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    Ok { findings: Vec<FindingRec> },
    Failed(FailureReport),
}

/// Structured failure report captured in artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub kind: FailureKind,
    pub message: String,
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    Panic,
    Hang,
    InvariantViolation { code: u32 },
    OracleMismatch,
    StabilityMismatch,
    Unimplemented,
}

/// Deterministic scanner simulation runner.
pub struct ScannerSimRunner {
    cfg: RunConfig,
    schedule_seed: u64,
}

impl ScannerSimRunner {
    pub fn new(cfg: RunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed.
    pub fn run(&self, scenario: &Scenario, engine: &Engine) -> RunOutcome {
        let res = catch_unwind(AssertUnwindSafe(|| self.run_inner(scenario, engine)));
        match res {
            Ok(outcome) => outcome,
            Err(payload) => RunOutcome::Failed(FailureReport {
                kind: FailureKind::Panic,
                message: panic_message(payload),
                step: 0,
            }),
        }
    }

    fn run_inner(&self, scenario: &Scenario, engine: &Engine) -> RunOutcome {
        if self.cfg.workers == 0 {
            return self.fail(
                FailureKind::InvariantViolation { code: 1 },
                "workers must be > 0",
                0,
            );
        }
        if self.cfg.chunk_size == 0 {
            return self.fail(
                FailureKind::InvariantViolation { code: 2 },
                "chunk_size must be > 0",
                0,
            );
        }

        let overlap = self.cfg.overlap as usize;
        debug_assert!(overlap >= engine.required_overlap());

        let fs = SimFs::from_spec(&scenario.fs);
        let mut executor = SimExecutor::new(self.cfg.workers, self.schedule_seed);
        let mut tasks: Vec<ScannerTask> = Vec::new();
        let mut output = OutputCollector::new();

        let discover = DiscoverState::new(fs.file_paths());
        let discover_id = executor.spawn_external(SimTask {
            kind: TaskKind::Discover as u16,
        });
        insert_task(&mut tasks, discover_id, ScannerTask::Discover(discover));

        for step in 0..self.cfg.max_steps {
            if !executor.has_queued_tasks() {
                if all_tasks_completed(&executor, &tasks) {
                    return RunOutcome::Ok {
                        findings: output.finish(),
                    };
                }
                return self.fail(
                    FailureKind::Hang,
                    "no runnable tasks but incomplete work",
                    step,
                );
            }

            let (worker, task_id) = match executor.step() {
                StepResult::Idle => {
                    return self.fail(FailureKind::Hang, "executor idle with queued tasks", step)
                }
                StepResult::Ran {
                    worker, task_id, ..
                } => (worker, task_id),
            };

            if executor.state(task_id) != SimTaskState::Runnable {
                return self.fail(
                    FailureKind::InvariantViolation { code: 3 },
                    "scheduled non-runnable task",
                    step,
                );
            }

            let task_idx = task_id.index();
            let mut files_to_spawn = None;
            if let Some(task_state) = tasks.get_mut(task_idx) {
                match task_state {
                    ScannerTask::Discover(state) => {
                        files_to_spawn = Some(std::mem::take(&mut state.files));
                    }
                    ScannerTask::FileScan(state) => {
                        let done = state.scan_next_chunk(
                            engine,
                            overlap,
                            self.cfg.chunk_size as usize,
                            &mut output,
                        );
                        if done {
                            executor.mark_completed(task_id);
                        } else {
                            executor.mark_runnable(task_id);
                            executor.enqueue_local(worker, task_id);
                        }
                    }
                }
            } else {
                return self.fail(
                    FailureKind::InvariantViolation { code: 4 },
                    "task state missing",
                    step,
                );
            }

            if let Some(files) = files_to_spawn {
                for (idx, path) in files.iter().enumerate() {
                    let file_id = FileId(idx as u32);
                    let state =
                        match FileScanState::new(&fs, path.clone(), file_id, engine, overlap) {
                            Ok(state) => state,
                            Err(msg) => {
                                return RunOutcome::Failed(FailureReport {
                                    kind: FailureKind::InvariantViolation { code: 10 },
                                    message: msg,
                                    step,
                                })
                            }
                        };

                    let spawned_id = executor.spawn_local(
                        worker,
                        SimTask {
                            kind: TaskKind::FileScan as u16,
                        },
                    );
                    insert_task(
                        &mut tasks,
                        spawned_id,
                        ScannerTask::FileScan(Box::new(state)),
                    );
                }

                executor.mark_completed(task_id);
                executor.remove_from_queues(task_id);
            }
        }

        self.fail(FailureKind::Hang, "max steps exceeded", self.cfg.max_steps)
    }

    fn fail(&self, kind: FailureKind, message: &str, step: u64) -> RunOutcome {
        RunOutcome::Failed(FailureReport {
            kind,
            message: message.to_string(),
            step,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskKind {
    Discover = 1,
    FileScan = 2,
}

struct OutputCollector {
    findings: Vec<FindingRec>,
}

impl OutputCollector {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    fn append(&mut self, batch: &mut Vec<FindingRec>) {
        self.findings.append(batch);
    }

    fn finish(self) -> Vec<FindingRec> {
        self.findings
    }
}

enum ScannerTask {
    Discover(DiscoverState),
    FileScan(Box<FileScanState>),
}

struct DiscoverState {
    files: Vec<SimPath>,
}

impl DiscoverState {
    fn new(mut files: Vec<SimPath>) -> Self {
        files.sort_by(|a, b| a.bytes.cmp(&b.bytes));
        Self { files }
    }
}

struct FileScanState {
    file_id: FileId,
    path: SimPath,
    buf: Vec<u8>,
    offset: usize,
    tail: Vec<u8>,
    tail_len: usize,
    scratch: ScanScratch,
    batch: Vec<FindingRec>,
}

impl FileScanState {
    fn new(
        fs: &SimFs,
        path: SimPath,
        file_id: FileId,
        engine: &Engine,
        overlap: usize,
    ) -> Result<Self, String> {
        let handle = fs
            .open_file(&path)
            .map_err(|e| format!("open {:?}: {e}", path.bytes))?;
        let len =
            usize::try_from(handle.len).map_err(|_| format!("file too large: {:?}", path.bytes))?;
        let data = fs
            .read_at(&handle, 0, len)
            .map_err(|e| format!("read {:?}: {e}", path.bytes))?;

        Ok(Self {
            file_id,
            path,
            buf: data.to_vec(),
            offset: 0,
            tail: vec![0u8; overlap],
            tail_len: 0,
            scratch: engine.new_scratch(),
            batch: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
        })
    }

    fn scan_next_chunk(
        &mut self,
        engine: &Engine,
        overlap: usize,
        chunk_size: usize,
        output: &mut OutputCollector,
    ) -> bool {
        if self.offset >= self.buf.len() {
            return true;
        }

        let remaining = self.buf.len() - self.offset;
        let payload_len = chunk_size.min(remaining);
        let payload = &self.buf[self.offset..self.offset + payload_len];

        let mut chunk = Vec::with_capacity(self.tail_len + payload.len());
        chunk.extend_from_slice(&self.tail[..self.tail_len]);
        chunk.extend_from_slice(payload);

        let base_offset = self.offset.saturating_sub(self.tail_len) as u64;
        engine.scan_chunk_into(&chunk, self.file_id, base_offset, &mut self.scratch);
        self.scratch.drop_prefix_findings(self.offset as u64);
        self.scratch.drain_findings_into(&mut self.batch);
        output.append(&mut self.batch);

        let total_len = chunk.len();
        let keep = overlap.min(total_len);
        if keep > 0 {
            self.tail[..keep].copy_from_slice(&chunk[total_len - keep..]);
        }
        self.tail_len = keep;
        self.offset += payload_len;

        self.offset >= self.buf.len()
    }
}

fn insert_task(tasks: &mut Vec<ScannerTask>, task_id: SimTaskId, task: ScannerTask) {
    if task_id.index() == tasks.len() {
        tasks.push(task);
    } else if task_id.index() < tasks.len() {
        tasks[task_id.index()] = task;
    }
}

fn all_tasks_completed(executor: &SimExecutor, tasks: &[ScannerTask]) -> bool {
    tasks
        .iter()
        .enumerate()
        .all(|(idx, _)| executor.state(SimTaskId::from_u32(idx as u32)) == SimTaskState::Completed)
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload".to_string()
    }
}
