//! Deterministic Git simulation runner.
//!
//! The runner executes stage tasks under a deterministic scheduler and
//! records a bounded trace for replay. End-of-run oracles validate output
//! shape (sorted/disjoint sets), watermark gating, and stability across
//! schedule seeds.
//!
use std::panic::{catch_unwind, AssertUnwindSafe};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::git_scan::{
    build_pack_plans, ByteArena, BytesView, CandidateBuffer, CommitPlanIter, CommitWalkLimits,
    FinalizeOutcome, OidBytes, PackCache, PackDecodeLimits, PackExecError, PackExecReport,
    PackPlanConfig, PackReadError, PackReader, PlannedCommit, StartSetRef, TreeDiffLimits,
    TreeDiffWalker,
};
use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, StepResult};

use super::commit_graph::SimCommitGraph;
use super::convert::{to_object_format, to_oid_bytes};
use super::fault::{
    corruption_kind_code, fault_kind_code, GitFaultInjector, GitFaultPlan, GitIoFault,
    GitResourceId,
};
use super::pack_bytes::SimPackBytes;
use super::pack_io::SimPackIo;
use super::scenario::{GitRunConfig, GitScenario};
use super::start_set::SimStartSet;
use super::trace::{GitTraceEvent, GitTraceRing};
use super::tree_source::SimTreeSource;

/// Result of a Git simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    /// Run completed without detected failures.
    Ok { report: RunReport },
    /// Run failed with a structured report.
    Failed(FailureReport),
}

/// Outcome of finalize in simulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SimFinalizeOutcome {
    Complete,
    Partial { skipped_count: usize },
}

impl From<FinalizeOutcome> for SimFinalizeOutcome {
    fn from(outcome: FinalizeOutcome) -> Self {
        match outcome {
            FinalizeOutcome::Complete => Self::Complete,
            FinalizeOutcome::Partial { skipped_count } => Self::Partial { skipped_count },
        }
    }
}

/// Summary report for a successful run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunReport {
    /// Total steps executed.
    pub steps: u64,
    /// Commit count emitted by the commit walk.
    pub commit_count: u32,
    /// Candidate count emitted by tree diff.
    pub candidate_count: u32,
    /// Skipped candidate count.
    pub skipped_count: usize,
    /// Finalize outcome.
    pub outcome: SimFinalizeOutcome,
    /// Hash of scanned OIDs (sorted, unique).
    pub scanned_hash: [u8; 32],
    /// Hash of skipped OIDs (sorted, unique).
    pub skipped_hash: [u8; 32],
    /// Hash of trace events (order-sensitive, bounded to the trace ring).
    pub trace_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunOutput {
    commit_count: u32,
    candidate_count: u32,
    outcome: SimFinalizeOutcome,
    scanned_hash: [u8; 32],
    skipped_hash: [u8; 32],
}

impl From<&RunReport> for RunOutput {
    fn from(report: &RunReport) -> Self {
        Self {
            commit_count: report.commit_count,
            candidate_count: report.candidate_count,
            outcome: report.outcome,
            scanned_hash: report.scanned_hash,
            skipped_hash: report.skipped_hash,
        }
    }
}

/// Structured failure report captured in artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    /// Failure classification.
    pub kind: FailureKind,
    /// Human-readable message for logs and artifacts.
    pub message: String,
    /// Monotonic step counter at the time of failure.
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    /// A panic escaped from harness logic.
    Panic,
    /// The simulation failed to reach a terminal state within the step budget.
    Hang,
    /// An invariant about ordering or gating was violated.
    InvariantViolation { code: u32 },
    /// A correctness oracle failed.
    OracleMismatch,
    /// The same scenario produced different outputs across schedules.
    StabilityMismatch,
}

/// Deterministic Git simulation runner.
///
/// The schedule seed drives the scheduler RNG; deterministic behavior is
/// expected given identical scenario, fault plan, and configuration.
pub struct GitSimRunner {
    cfg: GitRunConfig,
    schedule_seed: u64,
}

impl GitSimRunner {
    /// Create a new runner with a fixed schedule seed.
    pub fn new(cfg: GitRunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed and fault plan.
    pub fn run(&self, scenario: &GitScenario, fault_plan: &GitFaultPlan) -> RunOutcome {
        let base = match self.run_once_catch(scenario, fault_plan, self.schedule_seed) {
            RunOutcome::Ok { report } => report,
            fail => return fail,
        };

        if self.cfg.stability_runs <= 1 {
            return RunOutcome::Ok { report: base };
        }

        let baseline = RunOutput::from(&base);
        for i in 1..self.cfg.stability_runs {
            let seed = self.schedule_seed.wrapping_add(i as u64);
            match self.run_once_catch(scenario, fault_plan, seed) {
                RunOutcome::Ok { report } => {
                    let candidate = RunOutput::from(&report);
                    if candidate != baseline {
                        return RunOutcome::Failed(FailureReport {
                            kind: FailureKind::StabilityMismatch,
                            message: format!(
                                "stability mismatch between seeds {} and {}",
                                self.schedule_seed, seed
                            ),
                            step: report.steps,
                        });
                    }
                }
                fail => return fail,
            }
        }

        RunOutcome::Ok { report: base }
    }

    /// Returns the configured run settings.
    #[must_use]
    pub fn config(&self) -> &GitRunConfig {
        &self.cfg
    }

    /// Returns the base schedule seed.
    #[must_use]
    pub fn schedule_seed(&self) -> u64 {
        self.schedule_seed
    }

    fn run_once_catch(
        &self,
        scenario: &GitScenario,
        fault_plan: &GitFaultPlan,
        seed: u64,
    ) -> RunOutcome {
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.run_once(scenario, fault_plan, seed)
        }));
        match result {
            Ok(outcome) => outcome,
            Err(_) => RunOutcome::Failed(FailureReport {
                kind: FailureKind::Panic,
                message: "panic in git sim runner".to_string(),
                step: 0,
            }),
        }
    }

    fn run_once(&self, scenario: &GitScenario, fault_plan: &GitFaultPlan, seed: u64) -> RunOutcome {
        let mut executor = SimExecutor::new(self.cfg.workers, seed);
        let mut tasks: Vec<StageKind> = Vec::new();

        let mut state = RunState::new(scenario, self.cfg.trace_capacity, fault_plan.clone());
        spawn_stage(&mut executor, &mut tasks, StageKind::RepoOpen);

        let max_steps = derive_max_steps(self.cfg.max_steps, scenario);
        let mut done = false;
        let mut steps = 0u64;

        for step in 1..=max_steps {
            if done {
                break;
            }

            match executor.step() {
                StepResult::Idle => {
                    return RunOutcome::Failed(FailureReport {
                        kind: FailureKind::Hang,
                        message: "no runnable tasks".to_string(),
                        step,
                    });
                }
                StepResult::Ran {
                    worker: _,
                    task_id,
                    decision,
                } => {
                    steps = step;
                    state.trace.push(GitTraceEvent::Decision {
                        code: (decision.choices << 16) | decision.chosen,
                    });
                    let stage = tasks[task_id.index()];
                    let stage_id = stage as u16;
                    state.trace.push(GitTraceEvent::StageEnter { stage_id });

                    let stage_result = match stage {
                        StageKind::RepoOpen => stage_repo_open(&mut state),
                        StageKind::CommitWalk => stage_commit_walk(&mut state),
                        StageKind::TreeDiff => stage_tree_diff(&mut state),
                        StageKind::PackExec => stage_pack_exec(&mut state),
                        StageKind::Finalize => stage_finalize(&mut state),
                    };

                    match stage_result {
                        Ok(items) => {
                            state
                                .trace
                                .push(GitTraceEvent::StageExit { stage_id, items });
                            executor.mark_completed(task_id);
                            executor.remove_from_queues(task_id);

                            match stage {
                                StageKind::RepoOpen => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::CommitWalk);
                                }
                                StageKind::CommitWalk => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::TreeDiff);
                                }
                                StageKind::TreeDiff => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::PackExec);
                                }
                                StageKind::PackExec => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::Finalize);
                                }
                                StageKind::Finalize => {
                                    done = true;
                                }
                            }
                        }
                        Err(mut failure) => {
                            failure.step = step;
                            return RunOutcome::Failed(failure);
                        }
                    }
                }
            }
        }

        if !done {
            return RunOutcome::Failed(FailureReport {
                kind: FailureKind::Hang,
                message: "max steps exceeded".to_string(),
                step: steps,
            });
        }

        let report = match build_report(&state, steps) {
            Ok(report) => report,
            Err(mut failure) => {
                failure.step = steps;
                return RunOutcome::Failed(failure);
            }
        };
        RunOutcome::Ok { report }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageKind {
    RepoOpen = 1,
    CommitWalk = 2,
    TreeDiff = 3,
    PackExec = 4,
    Finalize = 5,
}

struct RunState<'a> {
    scenario: &'a GitScenario,
    trace: GitTraceRing,
    faults: GitFaultInjector,
    ref_arena: Option<ByteArena>,
    refs: Vec<StartSetRef>,
    commit_graph: Option<SimCommitGraph>,
    tree_source: Option<SimTreeSource>,
    plan: Vec<PlannedCommit>,
    candidates: Option<CandidateBuffer>,
    scanned: Vec<OidBytes>,
    skipped: Vec<OidBytes>,
    outcome: Option<FinalizeOutcome>,
}

impl<'a> RunState<'a> {
    fn new(scenario: &'a GitScenario, trace_capacity: u32, fault_plan: GitFaultPlan) -> Self {
        Self {
            scenario,
            trace: GitTraceRing::new(trace_capacity as usize),
            faults: GitFaultInjector::new(fault_plan),
            ref_arena: None,
            refs: Vec::new(),
            commit_graph: None,
            tree_source: None,
            plan: Vec::new(),
            candidates: None,
            scanned: Vec::new(),
            skipped: Vec::new(),
            outcome: None,
        }
    }
}

fn spawn_stage(
    executor: &mut SimExecutor,
    tasks: &mut Vec<StageKind>,
    stage: StageKind,
) -> SimTaskId {
    let task = SimTask { kind: stage as u16 };
    let id = executor.spawn_external(task);
    if id.index() >= tasks.len() {
        tasks.resize(id.index() + 1, stage);
    }
    tasks[id.index()] = stage;
    id
}

fn derive_max_steps(max_steps: u64, scenario: &GitScenario) -> u64 {
    if max_steps != 0 {
        return max_steps;
    }
    // Heuristic to prevent hangs while allowing small scenarios to complete.
    let commits = scenario.repo.commits.len() as u64;
    let refs = scenario.repo.refs.len() as u64;
    let trees = scenario.repo.trees.len() as u64;
    1000 + commits.saturating_mul(8) + refs.saturating_mul(4) + trees.saturating_mul(2)
}

fn stage_repo_open(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let repo = &state.scenario.repo;
    if let Some(artifacts) = &state.scenario.artifacts {
        if let Some(bytes) = &artifacts.commit_graph {
            let _ = apply_fault_to_bytes(
                &mut state.faults,
                &mut state.trace,
                &GitResourceId::CommitGraph,
                bytes,
            )?;
        }
    }
    let _start_set = SimStartSet::from_repo(repo).map_err(|err| failure_inv(1, err))?;
    let commit_graph = SimCommitGraph::from_repo(repo).map_err(|err| failure_inv(2, err))?;
    let tree_source = SimTreeSource::from_repo(repo).map_err(|err| failure_inv(3, err))?;

    let object_format = to_object_format(repo.object_format);

    let mut refs = repo.refs.clone();
    refs.sort_by(|a, b| a.name.cmp(&b.name));

    // Size the arena from total ref name bytes to avoid growth churn.
    let total_bytes: usize = refs.iter().map(|r| r.name.len()).sum();
    let mut arena = ByteArena::with_capacity(total_bytes as u32 + 1);
    let mut start_set_refs = Vec::with_capacity(refs.len());

    for r in refs {
        let name = arena
            .intern(&r.name)
            .ok_or_else(|| failure_inv(4, "ref name too long"))?;
        let tip = to_oid_bytes(&r.tip, object_format).map_err(|err| failure_inv(5, err))?;
        let watermark = match &r.watermark {
            Some(oid) => Some(to_oid_bytes(oid, object_format).map_err(|err| failure_inv(6, err))?),
            None => None,
        };
        start_set_refs.push(StartSetRef {
            name,
            tip,
            watermark,
        });
    }

    state.ref_arena = Some(arena);
    state.refs = start_set_refs;
    state.commit_graph = Some(commit_graph);
    state.tree_source = Some(tree_source);

    Ok(state.refs.len() as u32)
}

fn stage_commit_walk(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let commit_graph = state
        .commit_graph
        .as_ref()
        .ok_or_else(|| failure_inv(10, "commit graph missing"))?;

    let limits = CommitWalkLimits::default();
    let iter = CommitPlanIter::new_from_refs(&state.refs, commit_graph, limits)
        .map_err(|err| failure_inv(11, err))?;

    let mut plan = Vec::new();
    for item in iter {
        match item {
            Ok(commit) => plan.push(commit),
            Err(err) => return Err(failure_inv(12, err)),
        }
    }

    state.plan = plan;
    Ok(state.plan.len() as u32)
}

fn stage_tree_diff(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let commit_graph = state
        .commit_graph
        .as_ref()
        .ok_or_else(|| failure_inv(20, "commit graph missing"))?;
    let tree_source = state
        .tree_source
        .as_mut()
        .ok_or_else(|| failure_inv(21, "tree source missing"))?;

    let limits = TreeDiffLimits::default();
    let oid_len = to_object_format(state.scenario.repo.object_format).oid_len();
    let mut walker = TreeDiffWalker::new(&limits, oid_len);
    let mut candidates = CandidateBuffer::new(&limits, oid_len);

    for planned in &state.plan {
        let new_tree = commit_graph
            .root_tree_oid(planned.pos)
            .map_err(|err| failure_inv(22, err))?;
        let parents = commit_graph.parents(planned.pos);

        if planned.snapshot_root || parents.is_empty() {
            walker
                .diff_trees(
                    tree_source,
                    &mut candidates,
                    Some(&new_tree),
                    None,
                    planned.pos.0,
                    0,
                )
                .map_err(|err| failure_inv(23, err))?;
        } else {
            for (idx, parent) in parents.iter().enumerate() {
                let old_tree = commit_graph
                    .root_tree_oid(*parent)
                    .map_err(|err| failure_inv(24, err))?;
                let parent_idx = u8::try_from(idx).map_err(|_| failure_inv(25, "parent idx"))?;
                walker
                    .diff_trees(
                        tree_source,
                        &mut candidates,
                        Some(&new_tree),
                        Some(&old_tree),
                        planned.pos.0,
                        parent_idx,
                    )
                    .map_err(|err| failure_inv(26, err))?;
            }
        }
    }

    let count = candidates.len() as u32;
    state.candidates = Some(candidates);
    Ok(count)
}

fn stage_pack_exec(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let Some(candidates) = state.candidates.as_ref() else {
        return Err(failure_inv(30, "candidates missing"));
    };

    let mut scanned: Vec<OidBytes> = Vec::new();
    let mut skipped: Vec<OidBytes> = Vec::new();

    // If there are no byte-level artifacts, treat the semantic candidates as scanned.
    let Some(artifacts) = &state.scenario.artifacts else {
        collect_semantic_scan(candidates, &mut scanned);
        state.scanned = dedupe_sorted(scanned);
        state.skipped = Vec::new();
        return Ok(state.scanned.len() as u32);
    };

    // If artifacts are present but incomplete, treat all candidates as skipped.
    if artifacts.midx.is_none() || artifacts.packs.is_empty() {
        collect_semantic_skip(candidates, &mut skipped);
        state.scanned = Vec::new();
        state.skipped = dedupe_sorted(skipped);
        return Ok(0);
    }

    let midx_bytes = artifacts.midx.clone().unwrap_or_default();
    let object_format = to_object_format(state.scenario.repo.object_format);

    let midx_faulted = apply_fault_to_bytes(
        &mut state.faults,
        &mut state.trace,
        &GitResourceId::Midx,
        &midx_bytes,
    )?;

    let midx_view = crate::git_scan::MidxView::parse(&midx_faulted, object_format)
        .map_err(|err| failure_inv(31, err))?;

    let pack_bytes = SimPackBytes::from_repo(&state.scenario.repo, artifacts)
        .map_err(|err| failure_inv(32, err))?;

    let mut pack_candidates = Vec::new();
    let mut path_arena = ByteArena::with_capacity(4 * 1024 * 1024);

    for cand in candidates.iter_resolved() {
        match midx_view.find_oid(&cand.oid) {
            Ok(Some(idx)) => {
                let (pack_id, offset) = midx_view
                    .offset_at(idx)
                    .map_err(|err| failure_inv(33, err))?;
                let path_ref = path_arena
                    .intern(cand.path)
                    .ok_or_else(|| failure_inv(34, "path arena full"))?;
                let ctx = crate::git_scan::CandidateContext {
                    commit_id: cand.commit_id,
                    parent_idx: cand.parent_idx,
                    change_kind: cand.change_kind,
                    ctx_flags: cand.ctx_flags,
                    cand_flags: cand.cand_flags,
                    path_ref,
                };
                pack_candidates.push(crate::git_scan::PackCandidate {
                    oid: cand.oid,
                    ctx,
                    pack_id,
                    offset,
                });
            }
            Ok(None) => skipped.push(cand.oid),
            Err(err) => return Err(failure_inv(35, err)),
        }
    }

    if pack_candidates.is_empty() {
        state.scanned = Vec::new();
        state.skipped = dedupe_sorted(skipped);
        return Ok(0);
    }

    let pack_views = pack_bytes
        .pack_views()
        .map_err(|err| failure_inv(36, err))?;
    let pack_views = pack_views.into_iter().map(Some).collect::<Vec<_>>();
    let plans = build_pack_plans(
        pack_candidates,
        &pack_views,
        &midx_view,
        &PackPlanConfig::default(),
    )
    .map_err(|err| failure_inv(37, err))?;

    let mut cache = PackCache::new(64 * 1024);
    let limits = PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024);
    let mut pack_list = Vec::with_capacity(pack_bytes.pack_count());
    for id in 0..pack_bytes.pack_count() {
        pack_list.push(
            pack_bytes
                .pack_bytes(id as u16)
                .map_err(|err| failure_inv(38, err))?,
        );
    }
    let mut external = SimPackIo::new(
        object_format,
        crate::git_scan::BytesView::from_vec(midx_faulted),
        pack_list,
        crate::git_scan::PackIoLimits::new(limits, 32),
    )
    .map_err(|err| failure_inv(39, err))?;

    let mut sink = CollectingSink::default();

    for plan in &plans {
        let reader_bytes = pack_bytes
            .pack_bytes(plan.pack_id)
            .map_err(|err| failure_inv(41, err))?;
        let mut reader = FaultyPackReader::new(
            GitResourceId::Pack {
                pack_id: plan.pack_id,
            },
            reader_bytes,
            &mut state.faults,
            &mut state.trace,
        );

        let report = crate::git_scan::execute_pack_plan_with_reader(
            plan,
            &mut reader,
            &path_arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        )
        .map_err(|err| failure_inv(40, err))?;

        collect_skipped_from_report(plan, &report, &mut skipped);
    }

    scanned.extend(sink.scanned);

    state.scanned = dedupe_sorted(scanned);
    state.skipped = dedupe_sorted(skipped);

    Ok(state.scanned.len() as u32)
}

fn stage_finalize(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let skipped_count = state.skipped.len();
    let outcome = if skipped_count == 0 {
        FinalizeOutcome::Complete
    } else {
        FinalizeOutcome::Partial { skipped_count }
    };

    if matches!(outcome, FinalizeOutcome::Complete) && skipped_count != 0 {
        return Err(failure_inv(50, "complete with skips"));
    }

    state.outcome = Some(outcome);
    Ok(skipped_count as u32)
}

#[derive(Default)]
struct CollectingSink {
    scanned: Vec<OidBytes>,
}

impl crate::git_scan::PackObjectSink for CollectingSink {
    fn emit(
        &mut self,
        candidate: &crate::git_scan::PackCandidate,
        _path: &[u8],
        _bytes: &[u8],
    ) -> Result<(), PackExecError> {
        self.scanned.push(candidate.oid);
        Ok(())
    }
}

fn collect_skipped_from_report(
    plan: &crate::git_scan::PackPlan,
    report: &PackExecReport,
    out: &mut Vec<OidBytes>,
) {
    if report.skips.is_empty() {
        return;
    }
    let offsets = &plan.candidate_offsets;
    for skip in &report.skips {
        let start = offsets.partition_point(|c| c.offset < skip.offset);
        let end = offsets.partition_point(|c| c.offset <= skip.offset);
        for cand in &offsets[start..end] {
            let idx = cand.cand_idx as usize;
            if let Some(entry) = plan.candidates.get(idx) {
                out.push(entry.oid);
            }
        }
    }
}

fn collect_semantic_scan(candidates: &CandidateBuffer, out: &mut Vec<OidBytes>) {
    for cand in candidates.iter_resolved() {
        out.push(cand.oid);
    }
}

fn collect_semantic_skip(candidates: &CandidateBuffer, out: &mut Vec<OidBytes>) {
    for cand in candidates.iter_resolved() {
        out.push(cand.oid);
    }
}

fn dedupe_sorted(mut oids: Vec<OidBytes>) -> Vec<OidBytes> {
    oids.sort();
    oids.dedup();
    oids
}

fn build_report(state: &RunState<'_>, steps: u64) -> Result<RunReport, FailureReport> {
    let commit_count = state.plan.len() as u32;
    let candidate_count = state
        .candidates
        .as_ref()
        .map(|c| c.len() as u32)
        .unwrap_or(0);
    let outcome = validate_outputs(state)?;

    let scanned_hash = hash_oids(&state.scanned);
    let skipped_hash = hash_oids(&state.skipped);
    let trace_hash = hash_trace(&state.trace.dump());
    let skipped_count = state.skipped.len();

    Ok(RunReport {
        steps,
        commit_count,
        candidate_count,
        skipped_count,
        outcome: SimFinalizeOutcome::from(outcome),
        scanned_hash,
        skipped_hash,
        trace_hash,
    })
}

fn hash_oids(oids: &[OidBytes]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for oid in oids {
        hasher.update(oid.as_slice());
    }
    *hasher.finalize().as_bytes()
}

fn hash_trace(events: &[GitTraceEvent]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for ev in events {
        hash_event(&mut hasher, ev);
    }
    *hasher.finalize().as_bytes()
}

fn hash_event(hasher: &mut Hasher, ev: &GitTraceEvent) {
    match ev {
        GitTraceEvent::StageEnter { stage_id } => {
            hasher.update(&[1]);
            hasher.update(&stage_id.to_le_bytes());
        }
        GitTraceEvent::StageExit { stage_id, items } => {
            hasher.update(&[2]);
            hasher.update(&stage_id.to_le_bytes());
            hasher.update(&items.to_le_bytes());
        }
        GitTraceEvent::Decision { code } => {
            hasher.update(&[3]);
            hasher.update(&code.to_le_bytes());
        }
        GitTraceEvent::FaultInjected {
            resource_id,
            op,
            kind,
        } => {
            hasher.update(&[4]);
            hasher.update(&resource_id.to_le_bytes());
            hasher.update(&op.to_le_bytes());
            hasher.update(&kind.to_le_bytes());
        }
    }
}

fn apply_fault_to_bytes(
    faults: &mut GitFaultInjector,
    trace: &mut GitTraceRing,
    resource: &GitResourceId,
    bytes: &[u8],
) -> Result<Vec<u8>, FailureReport> {
    let (fault, op) = faults.next_read(resource);
    record_fault_events(trace, resource, op, &fault);

    let mut out = bytes.to_vec();
    if let Some(io_fault) = &fault.fault {
        match io_fault {
            GitIoFault::ErrKind { kind } => {
                return Err(failure_inv(70, format!("fault err kind {kind}")));
            }
            GitIoFault::EIntrOnce => {
                return Err(failure_inv(71, "fault interrupted"));
            }
            GitIoFault::PartialRead { max_len } => {
                let max_len = (*max_len as usize).min(out.len());
                out.truncate(max_len);
            }
        }
    }

    if let Some(corruption) = &fault.corruption {
        apply_corruption_vec(&mut out, corruption);
    }

    Ok(out)
}

fn record_fault_events(
    trace: &mut GitTraceRing,
    resource: &GitResourceId,
    op: u32,
    fault: &super::fault::GitReadFault,
) {
    if let Some(io_fault) = &fault.fault {
        trace.push(GitTraceEvent::FaultInjected {
            resource_id: resource.stable_id(),
            op,
            kind: fault_kind_code(io_fault),
        });
    }
    if let Some(corruption) = &fault.corruption {
        trace.push(GitTraceEvent::FaultInjected {
            resource_id: resource.stable_id(),
            op,
            kind: corruption_kind_code(corruption),
        });
    }
}

fn apply_corruption_vec(buf: &mut Vec<u8>, corruption: &super::fault::GitCorruption) {
    match corruption {
        super::fault::GitCorruption::TruncateTo { new_len } => {
            let new_len = (*new_len as usize).min(buf.len());
            buf.truncate(new_len);
        }
        super::fault::GitCorruption::FlipBit { offset, mask } => {
            let idx = *offset as usize;
            if idx < buf.len() {
                buf[idx] ^= *mask;
            }
        }
        super::fault::GitCorruption::Overwrite { offset, bytes } => {
            let start = *offset as usize;
            if start >= buf.len() {
                return;
            }
            let len = (buf.len() - start).min(bytes.len());
            buf[start..start + len].copy_from_slice(&bytes[..len]);
        }
    }
}

struct FaultyPackReader<'a> {
    resource: GitResourceId,
    bytes: BytesView,
    faults: &'a mut GitFaultInjector,
    trace: &'a mut GitTraceRing,
}

impl<'a> FaultyPackReader<'a> {
    fn new(
        resource: GitResourceId,
        bytes: BytesView,
        faults: &'a mut GitFaultInjector,
        trace: &'a mut GitTraceRing,
    ) -> Self {
        Self {
            resource,
            bytes,
            faults,
            trace,
        }
    }
}

impl PackReader for FaultyPackReader<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, PackReadError> {
        let offset_usize = offset as usize;
        let bytes = self.bytes.as_slice();
        if offset_usize > bytes.len() {
            return Err(PackReadError::OutOfRange {
                offset,
                len: dst.len(),
            });
        }

        let (fault, op) = self.faults.next_read(&self.resource);
        record_fault_events(self.trace, &self.resource, op, &fault);

        if let Some(io_fault) = &fault.fault {
            match io_fault {
                GitIoFault::ErrKind { kind } => {
                    return Err(PackReadError::Io(format!("fault err kind {kind}")));
                }
                GitIoFault::EIntrOnce => {
                    return Err(PackReadError::Io("fault interrupted".to_string()));
                }
                GitIoFault::PartialRead { .. } => {}
            }
        }

        let available = &bytes[offset_usize..];
        let mut n = available.len().min(dst.len());

        if let Some(GitIoFault::PartialRead { max_len }) = &fault.fault {
            n = n.min(*max_len as usize);
        }

        dst[..n].copy_from_slice(&available[..n]);

        if let Some(corruption) = &fault.corruption {
            n = apply_corruption_read(dst, n, corruption);
        }

        Ok(n)
    }
}

fn apply_corruption_read(
    buf: &mut [u8],
    mut len: usize,
    corruption: &super::fault::GitCorruption,
) -> usize {
    match corruption {
        super::fault::GitCorruption::TruncateTo { new_len } => {
            let new_len = (*new_len as usize).min(len);
            len = new_len;
        }
        super::fault::GitCorruption::FlipBit { offset, mask } => {
            let idx = *offset as usize;
            if idx < len {
                buf[idx] ^= *mask;
            }
        }
        super::fault::GitCorruption::Overwrite { offset, bytes } => {
            let start = *offset as usize;
            if start < len {
                let copy_len = (len - start).min(bytes.len());
                buf[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
            }
        }
    }
    len
}

/// Validate end-of-run invariants and correctness oracles.
fn validate_outputs(state: &RunState<'_>) -> Result<FinalizeOutcome, FailureReport> {
    let outcome = state
        .outcome
        .ok_or_else(|| failure_inv(60, "missing finalize outcome"))?;

    // Enforce set semantics: sorted, unique, and disjoint.
    if !is_sorted_unique(&state.scanned) {
        return Err(failure_inv(61, "scanned OIDs not sorted/unique"));
    }
    if !is_sorted_unique(&state.skipped) {
        return Err(failure_inv(62, "skipped OIDs not sorted/unique"));
    }
    if has_overlap(&state.scanned, &state.skipped) {
        return Err(failure_oracle("scanned and skipped sets overlap"));
    }

    let skipped_count = state.skipped.len();
    match outcome {
        FinalizeOutcome::Complete => {
            if skipped_count != 0 {
                return Err(failure_inv(63, "complete outcome with skips"));
            }
        }
        FinalizeOutcome::Partial {
            skipped_count: expected,
        } => {
            if expected != skipped_count {
                return Err(failure_oracle(format!(
                    "partial skipped_count mismatch: expected {expected}, got {skipped_count}"
                )));
            }
            if skipped_count == 0 {
                return Err(failure_oracle("partial outcome with zero skips"));
            }
        }
    }

    Ok(outcome)
}

fn is_sorted_unique(oids: &[OidBytes]) -> bool {
    oids.windows(2).all(|pair| pair[0] < pair[1])
}

fn has_overlap(left: &[OidBytes], right: &[OidBytes]) -> bool {
    let mut i = 0usize;
    let mut j = 0usize;
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn failure_inv<T: std::fmt::Display>(code: u32, err: T) -> FailureReport {
    FailureReport {
        kind: FailureKind::InvariantViolation { code },
        message: err.to_string(),
        step: 0,
    }
}

fn failure_oracle<T: std::fmt::Display>(err: T) -> FailureReport {
    FailureReport {
        kind: FailureKind::OracleMismatch,
        message: err.to_string(),
        step: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_git_scan::scenario::{
        GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel, GitScenario,
        GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec,
    };

    fn oid(val: u8) -> GitOid {
        GitOid {
            bytes: vec![val; 20],
        }
    }

    fn simple_scenario() -> GitScenario {
        GitScenario {
            schema_version: super::super::scenario::GIT_SCENARIO_SCHEMA_VERSION,
            repo: GitRepoModel {
                object_format: GitObjectFormat::Sha1,
                refs: vec![GitRefSpec {
                    name: b"refs/heads/main".to_vec(),
                    tip: oid(1),
                    watermark: None,
                }],
                commits: vec![GitCommitSpec {
                    oid: oid(1),
                    parents: Vec::new(),
                    tree: oid(2),
                    generation: 1,
                }],
                trees: vec![GitTreeSpec {
                    oid: oid(2),
                    entries: vec![GitTreeEntrySpec {
                        name: b"file.txt".to_vec(),
                        mode: 0o100644,
                        oid: oid(3),
                        kind: GitTreeEntryKind::Blob,
                    }],
                }],
                blobs: vec![GitBlobSpec {
                    oid: oid(3),
                    bytes: b"hello".to_vec(),
                }],
            },
            artifacts: None,
        }
    }

    #[test]
    fn trace_hash_matches_expected_stage_order() {
        let scenario = simple_scenario();
        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 0,
            stability_runs: 1,
            trace_capacity: 64,
        };
        let runner = GitSimRunner::new(cfg, 7);
        let outcome = runner.run(&scenario, &GitFaultPlan::default());
        let report = match outcome {
            RunOutcome::Ok { report } => report,
            RunOutcome::Failed(fail) => panic!("unexpected failure: {fail:?}"),
        };

        let decision = GitTraceEvent::Decision { code: 1 << 16 };
        let expected = vec![
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::RepoOpen as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::RepoOpen as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::CommitWalk as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::CommitWalk as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::TreeDiff as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::TreeDiff as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::PackExec as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::PackExec as u16,
                items: 1,
            },
            decision,
            GitTraceEvent::StageEnter {
                stage_id: StageKind::Finalize as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::Finalize as u16,
                items: 0,
            },
        ];

        let expected_hash = hash_trace(&expected);
        assert_eq!(report.trace_hash, expected_hash);
        assert_eq!(report.commit_count, 1);
        assert_eq!(report.candidate_count, 1);
        assert_eq!(report.skipped_count, 0);
        assert_eq!(report.outcome, SimFinalizeOutcome::Complete);
    }

    #[test]
    fn run_halts_when_step_budget_exceeded() {
        let scenario = simple_scenario();
        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 2,
            stability_runs: 1,
            trace_capacity: 32,
        };
        let runner = GitSimRunner::new(cfg, 1);
        let outcome = runner.run(&scenario, &GitFaultPlan::default());
        let failure = match outcome {
            RunOutcome::Failed(fail) => fail,
            RunOutcome::Ok { .. } => panic!("expected hang failure"),
        };

        assert!(matches!(failure.kind, FailureKind::Hang));
        assert_eq!(failure.message, "max steps exceeded");
    }

    #[test]
    fn corrupt_midx_bytes_fail_parse() {
        let midx_bytes = build_minimal_midx();
        let plan = GitFaultPlan {
            resources: vec![super::super::fault::GitResourceFaults {
                resource: GitResourceId::Midx,
                reads: vec![super::super::fault::GitReadFault {
                    fault: None,
                    latency_ticks: 0,
                    corruption: Some(super::super::fault::GitCorruption::TruncateTo { new_len: 8 }),
                }],
            }],
        };

        let mut injector = GitFaultInjector::new(plan);
        let mut trace = GitTraceRing::new(16);
        let faulted =
            apply_fault_to_bytes(&mut injector, &mut trace, &GitResourceId::Midx, &midx_bytes)
                .expect("faulted bytes");

        let parsed =
            crate::git_scan::MidxView::parse(&faulted, crate::git_scan::ObjectFormat::Sha1);
        assert!(parsed.is_err(), "corrupt midx should fail parse");
    }

    #[test]
    fn pack_reader_partial_read_returns_error() {
        use crate::git_scan::pack_inflate::ObjectKind;
        use crate::git_scan::pack_plan_model::CandidateAtOffset;
        use crate::git_scan::{
            execute_pack_plan_with_reader, ByteArena, CandidateContext, ChangeKind, PackCache,
            PackCandidate, PackDecodeLimits, PackExecError, PackPlan, PackPlanStats,
        };
        use crate::git_scan::{ExternalBase, ExternalBaseProvider, PackObjectSink};
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        struct NoExternal;

        impl ExternalBaseProvider for NoExternal {
            fn load_base(
                &mut self,
                _oid: &crate::git_scan::OidBytes,
            ) -> Result<Option<ExternalBase>, PackExecError> {
                Ok(None)
            }
        }

        #[derive(Default)]
        struct CollectingSink {
            scanned: Vec<crate::git_scan::OidBytes>,
        }

        impl PackObjectSink for CollectingSink {
            fn emit(
                &mut self,
                candidate: &PackCandidate,
                _path: &[u8],
                _bytes: &[u8],
            ) -> Result<(), PackExecError> {
                self.scanned.push(candidate.oid);
                Ok(())
            }
        }

        fn encode_entry_header(kind: ObjectKind, size: usize) -> Vec<u8> {
            let obj_type = match kind {
                ObjectKind::Commit => 1u8,
                ObjectKind::Tree => 2u8,
                ObjectKind::Blob => 3u8,
                ObjectKind::Tag => 4u8,
            };
            let mut out = Vec::new();
            let mut remaining = size as u64;
            let mut first = ((obj_type & 0x07) << 4) | ((remaining & 0x0f) as u8);
            remaining >>= 4;
            if remaining != 0 {
                first |= 0x80;
            }
            out.push(first);
            while remaining != 0 {
                let mut byte = (remaining & 0x7f) as u8;
                remaining >>= 7;
                if remaining != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
            }
            out
        }

        fn compress(data: &[u8]) -> Vec<u8> {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        }

        fn build_pack(entries: &[(ObjectKind, &[u8])]) -> (Vec<u8>, Vec<u64>) {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"PACK");
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());

            let mut offsets = Vec::with_capacity(entries.len());
            for (kind, data) in entries {
                offsets.push(bytes.len() as u64);
                bytes.extend_from_slice(&encode_entry_header(*kind, data.len()));
                bytes.extend_from_slice(&compress(data));
            }

            bytes.extend_from_slice(&[0u8; 20]);
            (bytes, offsets)
        }

        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 0,
            candidates: vec![PackCandidate {
                oid: crate::git_scan::OidBytes::sha1([0x11; 20]),
                ctx: CandidateContext {
                    commit_id: 1,
                    parent_idx: 0,
                    change_kind: ChangeKind::Add,
                    ctx_flags: 0,
                    cand_flags: 0,
                    path_ref: crate::git_scan::ByteRef::new(0, 0),
                },
                pack_id: 0,
                offset: offsets[0],
            }],
            candidate_offsets: vec![CandidateAtOffset {
                offset: offsets[0],
                cand_idx: 0,
            }],
            need_offsets: vec![offsets[0]],
            delta_deps: Vec::new(),
            delta_dep_index: Vec::new(),
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: 0,
            },
        };

        let plan_fault = GitFaultPlan {
            resources: vec![super::super::fault::GitResourceFaults {
                resource: GitResourceId::Pack { pack_id: 0 },
                reads: vec![super::super::fault::GitReadFault {
                    fault: Some(GitIoFault::PartialRead { max_len: 8 }),
                    latency_ticks: 0,
                    corruption: None,
                }],
            }],
        };

        let mut injector = GitFaultInjector::new(plan_fault);
        let mut trace = GitTraceRing::new(16);
        let mut reader = FaultyPackReader::new(
            GitResourceId::Pack { pack_id: 0 },
            BytesView::from_vec(pack),
            &mut injector,
            &mut trace,
        );

        let arena = ByteArena::with_capacity(32);
        let mut cache = PackCache::new(64 * 1024);
        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let mut sink = CollectingSink::default();
        let mut external = NoExternal;

        let err = execute_pack_plan_with_reader(
            &plan,
            &mut reader,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        )
        .expect_err("expected pack read error");
        assert!(matches!(err, PackExecError::PackRead(_)));
    }

    fn build_minimal_midx() -> Vec<u8> {
        const MIDX_MAGIC: [u8; 4] = *b"MIDX";
        const MIDX_VERSION: u8 = 1;
        const MIDX_HEADER_SIZE: usize = 12;
        const CHUNK_ENTRY_SIZE: usize = 12;
        const CHUNK_PNAM: [u8; 4] = *b"PNAM";
        const CHUNK_OIDF: [u8; 4] = *b"OIDF";
        const CHUNK_OIDL: [u8; 4] = *b"OIDL";
        const CHUNK_OOFF: [u8; 4] = *b"OOFF";
        const FANOUT_SIZE: usize = 256 * 4;

        let pack_names = vec![b"pack-test".to_vec()];
        let objects = vec![([0x11; 20], 0u16, 100u64)];

        let mut pnam = Vec::new();
        for name in &pack_names {
            pnam.extend_from_slice(name);
            pnam.push(0);
        }

        let mut oidf = vec![0u8; FANOUT_SIZE];
        let mut counts = [0u32; 256];
        for (oid, _, _) in &objects {
            counts[oid[0] as usize] += 1;
        }
        let mut running = 0u32;
        for (i, count) in counts.iter().enumerate() {
            running += count;
            let off = i * 4;
            oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
        }

        let mut oidl = Vec::with_capacity(objects.len() * 20);
        let mut ooff = Vec::with_capacity(objects.len() * 8);
        for (oid, pack_id, offset) in &objects {
            oidl.extend_from_slice(oid);
            ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
            ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        let chunk_count = 4u8;
        let header_size = MIDX_HEADER_SIZE;
        let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;

        let pnam_off = (header_size + chunk_table_size) as u64;
        let oidf_off = pnam_off + pnam.len() as u64;
        let oidl_off = oidf_off + oidf.len() as u64;
        let ooff_off = oidl_off + oidl.len() as u64;
        let end_off = ooff_off + ooff.len() as u64;

        let mut out = Vec::new();
        out.extend_from_slice(&MIDX_MAGIC);
        out.push(MIDX_VERSION);
        out.push(1); // SHA-1
        out.push(chunk_count);
        out.push(0); // base count
        out.extend_from_slice(&(pack_names.len() as u32).to_be_bytes());

        let mut push_chunk = |id: [u8; 4], off: u64| {
            out.extend_from_slice(&id);
            out.extend_from_slice(&off.to_be_bytes());
        };

        push_chunk(CHUNK_PNAM, pnam_off);
        push_chunk(CHUNK_OIDF, oidf_off);
        push_chunk(CHUNK_OIDL, oidl_off);
        push_chunk(CHUNK_OOFF, ooff_off);
        push_chunk([0, 0, 0, 0], end_off);

        out.extend_from_slice(&pnam);
        out.extend_from_slice(&oidf);
        out.extend_from_slice(&oidl);
        out.extend_from_slice(&ooff);
        out
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "runner_tests.rs"]
mod runner_tests;
