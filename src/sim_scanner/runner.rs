//! Deterministic scanner simulation runner.
//!
//! Scope:
//! - Deterministic, single-threaded scheduling of discover + scan tasks.
//! - Chunked scanning with overlap deduplication using the real `Engine`.
//! - No fault injection, timeouts, or IO latency (those are layered on later).
//!
//! Determinism:
//! - File discovery order is lexicographic by raw path bytes.
//! - Schedule decisions are driven by a seedable RNG in `SimExecutor`.
//! - Output ordering is emission order; a stability oracle compares sets.
//!
//! Oracles implemented here:
//! - Termination: enforce a max-steps bound to catch hangs.
//! - Monotonic progress: chunk offsets and prefix boundaries never move backward.
//! - Overlap dedupe: no finding may be entirely contained in the overlap prefix.
//! - Duplicate suppression: emitted findings are unique under a normalized key.
//! - Ground-truth: expected secrets are found, and no unexpected findings appear.
//! - Differential: chunked results match a single-chunk reference scan.
//! - Stability: repeated runs with different schedule seeds yield the same set.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::{Deserialize, Serialize};

use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, SimTaskState, StepResult};
use crate::sim::fs::{SimFs, SimPath};
use crate::sim_scanner::scenario::{RunConfig, Scenario, SecretRepr, SpanU32};
use crate::{Engine, FileId, FindingRec, ScanScratch};

/// Result of a simulation run.
///
/// `Ok` returns raw `FindingRec` entries in emission order (not sorted).
#[derive(Clone, Debug)]
pub enum RunOutcome {
    Ok { findings: Vec<FindingRec> },
    Failed(FailureReport),
}

/// Structured failure report captured in artifacts.
///
/// `step` is the simulation step index where the failure was detected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub kind: FailureKind,
    pub message: String,
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    /// A panic escaped from engine or harness logic.
    Panic,
    /// The simulation failed to reach a terminal state within the step budget.
    Hang,
    /// An invariant about ordering, offsets, or dedupe was violated.
    InvariantViolation { code: u32 },
    /// A correctness oracle failed (reserved for later phases).
    OracleMismatch,
    /// The same scenario produced different final findings across schedules.
    StabilityMismatch,
    /// Placeholder for unimplemented phases.
    Unimplemented,
}

/// Deterministic scanner simulation runner.
///
/// Preconditions:
/// - `cfg.overlap >= engine.required_overlap()`.
/// - `cfg.chunk_size > 0` and `cfg.workers > 0`.
pub struct ScannerSimRunner {
    cfg: RunConfig,
    schedule_seed: u64,
}

impl ScannerSimRunner {
    /// Create a new runner with a fixed schedule seed.
    pub fn new(cfg: RunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed.
    ///
    /// If `cfg.stability_runs > 1`, replays the same scenario under additional
    /// schedule seeds and compares the normalized finding sets.
    pub fn run(&self, scenario: &Scenario, engine: &Engine) -> RunOutcome {
        let base = match self.run_once_catch(scenario, engine, self.schedule_seed) {
            RunOutcome::Ok { findings } => findings,
            fail => return fail,
        };

        if self.cfg.stability_runs <= 1 {
            return RunOutcome::Ok { findings: base };
        }

        let baseline = normalize_findings(&base);
        for i in 1..self.cfg.stability_runs {
            let seed = self.schedule_seed.wrapping_add(i as u64);
            match self.run_once_catch(scenario, engine, seed) {
                RunOutcome::Ok { findings } => {
                    let candidate = normalize_findings(&findings);
                    if candidate != baseline {
                        return RunOutcome::Failed(FailureReport {
                            kind: FailureKind::StabilityMismatch,
                            message: format!(
                                "stability mismatch between seeds {} and {}",
                                self.schedule_seed, seed
                            ),
                            step: 0,
                        });
                    }
                }
                fail => return fail,
            }
        }

        RunOutcome::Ok { findings: base }
    }

    // Wrap a single run to convert panics into a structured failure.
    fn run_once_catch(&self, scenario: &Scenario, engine: &Engine, seed: u64) -> RunOutcome {
        let res = catch_unwind(AssertUnwindSafe(|| self.run_once(scenario, engine, seed)));
        match res {
            Ok(outcome) => outcome,
            Err(payload) => RunOutcome::Failed(FailureReport {
                kind: FailureKind::Panic,
                message: panic_message(payload),
                step: 0,
            }),
        }
    }

    /// Execute a single schedule with no stability replay.
    fn run_once(&self, scenario: &Scenario, engine: &Engine, seed: u64) -> RunOutcome {
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
        if overlap < engine.required_overlap() {
            return self.fail(
                FailureKind::InvariantViolation { code: 10 },
                "overlap smaller than engine.required_overlap()",
                0,
            );
        }

        let fs = SimFs::from_spec(&scenario.fs);
        let files = sorted_file_paths(&fs);
        let total_bytes = total_file_bytes(&fs, &files);
        let max_steps = resolve_max_steps(&self.cfg, files.len() as u64, total_bytes);

        let mut executor = SimExecutor::new(self.cfg.workers, seed);
        let mut tasks: Vec<ScannerTask> = Vec::new();
        let mut output = OutputCollector::new();

        let discover = DiscoverState::new(files.clone());
        let discover_id = executor.spawn_external(SimTask {
            kind: TaskKind::Discover as u16,
        });
        insert_task(&mut tasks, discover_id, ScannerTask::Discover(discover));

        for step in 0..max_steps {
            if !executor.has_queued_tasks() {
                if all_tasks_completed(&executor, &tasks) {
                    let findings = output.finish();
                    if let Err(fail) =
                        self.run_oracles(scenario, engine, &fs, &files, &findings, step)
                    {
                        return RunOutcome::Failed(fail);
                    }
                    return RunOutcome::Ok { findings };
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
                        let done = match state.scan_next_chunk(
                            engine,
                            overlap,
                            self.cfg.chunk_size as usize,
                            &mut output,
                            step,
                        ) {
                            Ok(done) => done,
                            Err(fail) => return RunOutcome::Failed(fail),
                        };
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
                // Spawn file scan tasks deterministically in discovered order.
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

        self.fail(FailureKind::Hang, "max steps exceeded", max_steps)
    }

    fn fail(&self, kind: FailureKind, message: &str, step: u64) -> RunOutcome {
        RunOutcome::Failed(FailureReport {
            kind,
            message: message.to_string(),
            step,
        })
    }

    fn run_oracles(
        &self,
        scenario: &Scenario,
        engine: &Engine,
        fs: &SimFs,
        files: &[SimPath],
        findings: &[FindingRec],
        step: u64,
    ) -> Result<(), FailureReport> {
        oracle_ground_truth(scenario, files, findings, step)?;
        oracle_differential(engine, fs, files, findings, step)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Task classification for the executor (used for tracing/debugging).
enum TaskKind {
    Discover = 1,
    FileScan = 2,
}

/// Normalized finding identity used for dedupe and stability checks.
///
/// Note: `step_id` is intentionally excluded because it is scratch-local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FindingKey {
    file_id: u32,
    rule_id: u32,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
}

impl From<&FindingRec> for FindingKey {
    fn from(rec: &FindingRec) -> Self {
        Self {
            file_id: rec.file_id.0,
            rule_id: rec.rule_id,
            span_start: rec.span_start,
            span_end: rec.span_end,
            root_hint_start: rec.root_hint_start,
            root_hint_end: rec.root_hint_end,
        }
    }
}

/// Output collector that enforces a no-duplicates invariant.
struct OutputCollector {
    findings: Vec<FindingRec>,
    seen: BTreeSet<FindingKey>,
}

impl OutputCollector {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen: BTreeSet::new(),
        }
    }

    /// Append a batch of findings, rejecting duplicates by normalized key.
    fn append(&mut self, batch: &mut Vec<FindingRec>, step: u64) -> Result<(), FailureReport> {
        for rec in batch.drain(..) {
            let key = FindingKey::from(&rec);
            if !self.seen.insert(key) {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 20 },
                    message: "duplicate finding emitted".to_string(),
                    step,
                });
            }
            self.findings.push(rec);
        }
        Ok(())
    }

    /// Finish and return findings in emission order.
    fn finish(self) -> Vec<FindingRec> {
        self.findings
    }
}

enum ScannerTask {
    Discover(DiscoverState),
    FileScan(Box<FileScanState>),
}

/// Discover task state (pre-sorted file list).
struct DiscoverState {
    files: Vec<SimPath>,
}

impl DiscoverState {
    fn new(mut files: Vec<SimPath>) -> Self {
        files.sort_by(|a, b| a.bytes.cmp(&b.bytes));
        Self { files }
    }
}

/// Per-file scanning state for deterministic chunked scans.
///
/// Invariants:
/// - `offset` is the next payload byte index in `buf`.
/// - `tail_len <= overlap` and `tail` stores the last `overlap` bytes of the
///   previous chunk buffer.
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
    /// Load the entire file into memory for deterministic chunking.
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

    /// Scan the next chunk and advance the cursor.
    ///
    /// Returns `Ok(true)` when the file is fully processed.
    fn scan_next_chunk(
        &mut self,
        engine: &Engine,
        overlap: usize,
        chunk_size: usize,
        output: &mut OutputCollector,
        step: u64,
    ) -> Result<bool, FailureReport> {
        if self.offset > self.buf.len() {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 11 },
                message: "offset exceeds file length".to_string(),
                step,
            });
        }
        if self.offset >= self.buf.len() {
            return Ok(true);
        }
        if self.tail_len > overlap {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 12 },
                message: "tail_len exceeds overlap".to_string(),
                step,
            });
        }
        if self.tail_len > self.offset {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 13 },
                message: "tail_len exceeds offset".to_string(),
                step,
            });
        }

        let remaining = self.buf.len() - self.offset;
        let payload_len = chunk_size.min(remaining);
        if payload_len == 0 {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 14 },
                message: "zero-length payload".to_string(),
                step,
            });
        }
        let payload = &self.buf[self.offset..self.offset + payload_len];

        let mut chunk = Vec::with_capacity(self.tail_len + payload.len());
        chunk.extend_from_slice(&self.tail[..self.tail_len]);
        chunk.extend_from_slice(payload);

        let base_offset = self.offset.saturating_sub(self.tail_len) as u64;
        let new_bytes_start = self.offset as u64;
        if base_offset.saturating_add(self.tail_len as u64) != new_bytes_start {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 15 },
                message: "prefix boundary mismatch".to_string(),
                step,
            });
        }
        engine.scan_chunk_into(&chunk, self.file_id, base_offset, &mut self.scratch);
        self.scratch.drop_prefix_findings(new_bytes_start);
        // Invariant: no finding may end at or before the prefix boundary.
        for rec in self.scratch.findings() {
            if rec.root_hint_end <= new_bytes_start {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 16 },
                    message: "prefix dedupe failed".to_string(),
                    step,
                });
            }
        }
        self.scratch.drain_findings_into(&mut self.batch);
        output.append(&mut self.batch, step)?;

        let total_len = chunk.len();
        let keep = overlap.min(total_len);
        if keep > 0 {
            self.tail[..keep].copy_from_slice(&chunk[total_len - keep..]);
        }
        self.tail_len = keep;
        let prev_offset = self.offset;
        self.offset = self.offset.saturating_add(payload_len);
        if self.offset <= prev_offset {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 17 },
                message: "offset did not advance".to_string(),
                step,
            });
        }
        let expected_next = base_offset.saturating_add(chunk.len() as u64);
        if expected_next != self.offset as u64 {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 18 },
                message: "base_offset + chunk_len mismatch".to_string(),
                step,
            });
        }

        Ok(self.offset >= self.buf.len())
    }
}

/// Insert a task into the slot indexed by its task id.
fn insert_task(tasks: &mut Vec<ScannerTask>, task_id: SimTaskId, task: ScannerTask) {
    if task_id.index() == tasks.len() {
        tasks.push(task);
    } else if task_id.index() < tasks.len() {
        tasks[task_id.index()] = task;
    }
}

/// Return whether every known task has reached the completed state.
fn all_tasks_completed(executor: &SimExecutor, tasks: &[ScannerTask]) -> bool {
    tasks
        .iter()
        .enumerate()
        .all(|(idx, _)| executor.state(SimTaskId::from_u32(idx as u32)) == SimTaskState::Completed)
}

#[derive(Clone, Debug)]
struct ExpectedEntry {
    path: SimPath,
    file_id: FileId,
    rule_id: u32,
    span: SpanU32,
    repr: SecretRepr,
    matched: bool,
}

/// Normalize findings into a stable, ordered key set.
fn normalize_findings(findings: &[FindingRec]) -> BTreeSet<FindingKey> {
    findings.iter().map(FindingKey::from).collect()
}

/// Return file paths in deterministic order.
fn sorted_file_paths(fs: &SimFs) -> Vec<SimPath> {
    let mut files = fs.file_paths();
    files.sort_by(|a, b| a.bytes.cmp(&b.bytes));
    files
}

/// Check that observed findings match the scenario's expected secrets.
///
/// Matches require the same `(file_id, rule_id)` and containment of the expected
/// root span within the finding's `root_hint` range. Any extra finding is a
/// ground-truth failure.
fn oracle_ground_truth(
    scenario: &Scenario,
    files: &[SimPath],
    findings: &[FindingRec],
    step: u64,
) -> Result<(), FailureReport> {
    let file_ids = build_file_id_map(files);
    let mut expected = Vec::with_capacity(scenario.expected.len());
    let mut index: BTreeMap<(u32, u32), Vec<usize>> = BTreeMap::new();

    for exp in &scenario.expected {
        let file_id = match file_ids.get(&exp.path.bytes) {
            Some(id) => *id,
            None => {
                return Err(FailureReport {
                    kind: FailureKind::OracleMismatch,
                    message: format!(
                        "expected secret references missing path {:?}",
                        exp.path.bytes
                    ),
                    step,
                })
            }
        };
        let idx = expected.len();
        expected.push(ExpectedEntry {
            path: exp.path.clone(),
            file_id,
            rule_id: exp.rule_id,
            span: exp.root_span,
            repr: exp.repr.clone(),
            matched: false,
        });
        index.entry((file_id.0, exp.rule_id)).or_default().push(idx);
    }

    for rec in findings {
        let Some(candidates) = index.get(&(rec.file_id.0, rec.rule_id)) else {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "unexpected finding in {:?} (rule_id {}, root_hint {}..{})",
                    path_for_file_id(files, rec.file_id)
                        .map(|p| p.bytes.clone())
                        .unwrap_or_default(),
                    rec.rule_id,
                    rec.root_hint_start,
                    rec.root_hint_end
                ),
                step,
            });
        };
        let mut matched = false;
        for &idx in candidates {
            let entry = &mut expected[idx];
            if span_contained(entry.span, rec.root_hint_start, rec.root_hint_end) {
                entry.matched = true;
                matched = true;
            }
        }
        if !matched {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "unexpected finding in {:?} (rule_id {}, root_hint {}..{})",
                    path_for_file_id(files, rec.file_id)
                        .map(|p| p.bytes.clone())
                        .unwrap_or_default(),
                    rec.rule_id,
                    rec.root_hint_start,
                    rec.root_hint_end
                ),
                step,
            });
        }
    }

    if let Some(miss) = expected.iter().find(|e| !e.matched) {
        return Err(FailureReport {
            kind: FailureKind::OracleMismatch,
            message: format!(
                "missing expected secret in {:?} (rule_id {}, span {}..{}, repr {:?})",
                miss.path.bytes, miss.rule_id, miss.span.start, miss.span.end, miss.repr
            ),
            step,
        });
    }

    Ok(())
}

/// Compare chunked findings against a single-chunk reference scan.
fn oracle_differential(
    engine: &Engine,
    fs: &SimFs,
    files: &[SimPath],
    findings: &[FindingRec],
    step: u64,
) -> Result<(), FailureReport> {
    let reference = reference_findings(engine, fs, files).map_err(|msg| FailureReport {
        kind: FailureKind::OracleMismatch,
        message: msg,
        step,
    })?;

    let observed = normalize_findings(findings);
    let expected = normalize_findings(&reference);
    if observed != expected {
        let mut message = format!(
            "differential mismatch (sim {}, reference {})",
            observed.len(),
            expected.len()
        );
        if let Some(miss) = expected.difference(&observed).next() {
            message.push_str(&format!(", missing {:?}", miss));
        }
        if let Some(extra) = observed.difference(&expected).next() {
            message.push_str(&format!(", extra {:?}", extra));
        }
        return Err(FailureReport {
            kind: FailureKind::OracleMismatch,
            message,
            step,
        });
    }

    Ok(())
}

fn reference_findings(
    engine: &Engine,
    fs: &SimFs,
    files: &[SimPath],
) -> Result<Vec<FindingRec>, String> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();

    for (idx, path) in files.iter().enumerate() {
        let file_id = FileId(idx as u32);
        let handle = fs
            .open_file(path)
            .map_err(|e| format!("open {:?}: {e}", path.bytes))?;
        let len =
            usize::try_from(handle.len).map_err(|_| format!("file too large: {:?}", path.bytes))?;
        if len > u32::MAX as usize {
            return Err(format!(
                "reference scan requires <= u32::MAX bytes: {:?}",
                path.bytes
            ));
        }
        let data = fs
            .read_at(&handle, 0, len)
            .map_err(|e| format!("read {:?}: {e}", path.bytes))?;

        engine.scan_chunk_into(data, file_id, 0, &mut scratch);
        scratch.drain_findings_into(&mut out);
    }

    Ok(out)
}

fn build_file_id_map(files: &[SimPath]) -> BTreeMap<Vec<u8>, FileId> {
    let mut map = BTreeMap::new();
    for (idx, path) in files.iter().enumerate() {
        map.insert(path.bytes.clone(), FileId(idx as u32));
    }
    map
}

fn path_for_file_id(files: &[SimPath], file_id: FileId) -> Option<&SimPath> {
    files.get(file_id.0 as usize)
}

fn span_contained(span: SpanU32, start: u64, end: u64) -> bool {
    let span_start = span.start as u64;
    let span_end = span.end as u64;
    span_start >= start && span_end <= end
}

/// Sum file lengths for a scenario (missing paths contribute 0).
fn total_file_bytes(fs: &SimFs, files: &[SimPath]) -> u64 {
    let mut total = 0u64;
    for path in files {
        if let Ok(handle) = fs.open_file(path) {
            total = total.saturating_add(handle.len);
        }
    }
    total
}

/// Resolve the max steps bound. If `cfg.max_steps > 0`, honor it; otherwise
/// derive a conservative bound from file count and byte count.
fn resolve_max_steps(cfg: &RunConfig, file_count: u64, total_bytes: u64) -> u64 {
    if cfg.max_steps > 0 {
        return cfg.max_steps;
    }
    let chunk = (cfg.chunk_size as u64).max(1);
    let chunks = total_bytes.saturating_add(chunk - 1) / chunk;
    let base = 32u64;
    let alpha = 8u64;
    base.saturating_add(alpha.saturating_mul(file_count.saturating_add(chunks)))
}

/// Format panic payloads into a stable message.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload".to_string()
    }
}
