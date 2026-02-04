//! Deterministic Git simulation runner.
//!
//! The runner executes stage tasks under a deterministic scheduler and
//! records a bounded trace for replay. End-of-run oracles validate output
//! shape (sorted/disjoint sets), watermark gating, and stability across
//! schedule seeds.
//!
//! Phase 0 does not yet apply the `fault_plan`; the API reserves it for
//! later injection points.

use std::panic::{catch_unwind, AssertUnwindSafe};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::git_scan::{
    build_pack_plans, ByteArena, CandidateBuffer, CommitPlanIter, CommitWalkLimits,
    FinalizeOutcome, OidBytes, PackCache, PackDecodeLimits, PackExecError, PackExecReport,
    PackPlanConfig, PlannedCommit, StartSetRef, TreeDiffLimits, TreeDiffWalker,
};
use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, StepResult};

use super::commit_graph::SimCommitGraph;
use super::convert::{to_object_format, to_oid_bytes};
use super::fault::GitFaultPlan;
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

    fn run_once(
        &self,
        scenario: &GitScenario,
        _fault_plan: &GitFaultPlan,
        seed: u64,
    ) -> RunOutcome {
        let mut executor = SimExecutor::new(self.cfg.workers, seed);
        let mut tasks: Vec<StageKind> = Vec::new();

        // Phase 0 schedules exactly one task per stage in a fixed order.
        // Scheduling decisions are still recorded for determinism checks.
        let mut state = RunState::new(scenario, self.cfg.trace_capacity);
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
    fn new(scenario: &'a GitScenario, trace_capacity: u32) -> Self {
        Self {
            scenario,
            trace: GitTraceRing::new(trace_capacity as usize),
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

    let midx_view = crate::git_scan::MidxView::parse(&midx_bytes, object_format)
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
    let plans = build_pack_plans(
        &pack_candidates,
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
        crate::git_scan::BytesView::from_vec(midx_bytes),
        pack_list,
        crate::git_scan::PackIoLimits::new(limits, 32),
    )
    .map_err(|err| failure_inv(39, err))?;

    let mut sink = CollectingSink::default();

    for plan in &plans {
        let mut reader = pack_bytes
            .pack_bytes(plan.pack_id)
            .map_err(|err| failure_inv(39, err))?;

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
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "runner_tests.rs"]
mod runner_tests;
