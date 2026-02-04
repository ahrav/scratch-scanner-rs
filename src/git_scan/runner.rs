//! End-to-end Git scan runner.
//!
//! Orchestrates preflight, repo open, commit walk, tree diff, spill/dedupe,
//! pack planning, pack decode + scan, finalize, and persistence.
//!
//! # Pipeline
//! 1. Preflight repository metadata and artifact readiness.
//! 2. Open the repo (start set resolution, watermarks, and artifact status).
//! 3. Plan commits, diff trees, and collect candidate blobs.
//! 4. Spill/dedupe candidates and map them to pack entries.
//! 5. Plan packs, decode + scan, then finalize and optionally persist.
//!
//! # Invariants
//! - If preflight or repo open detects missing artifacts, the run returns
//!   `GitScanResult::NeedsMaintenance` and skips the scan pipeline.
//! - MIDX completeness is verified before pack execution.
//! - Pack cache sizing must fit in `u32` (checked before execution).
//!
//! # Notes
//! - Loose objects are decoded via `PackIo::load_loose_object`; failures are
//!   recorded as skipped candidates.
//! - Persistence is optional; callers can run the pipeline without a store.

use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use crate::Engine;

use super::byte_arena::ByteArena;
use super::commit_walk::{
    introduced_by_plan, CommitGraph, CommitGraphView, ParentScratch, PlannedCommit,
};
use super::commit_walk_limits::CommitWalkLimits;
use super::engine_adapter::{EngineAdapter, EngineAdapterConfig};
use super::errors::{CommitPlanError, PersistError, RepoOpenError, SpillError, TreeDiffError};
use super::finalize::{build_finalize_ops, FinalizeInput, FinalizeOutput, RefEntry};
use super::limits::RepoOpenLimits;
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::{ObjectFormat, OidBytes};
use super::object_store::ObjectStore;
use super::pack_cache::PackCache;
use super::pack_candidates::{CappedPackCandidateSink, LooseCandidate};
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{execute_pack_plan, PackExecError, PackExecReport, SkipReason, SkipRecord};
use super::pack_inflate::ObjectKind;
use super::pack_io::{PackIo, PackIoError, PackIoLimits};
use super::pack_plan::{build_pack_plans, PackPlanConfig, PackPlanError, PackView};
use super::pack_plan_model::{PackPlan, PackPlanStats};
use super::persist::{persist_finalize_output, PersistenceStore};
use super::policy_hash::MergeDiffMode;
use super::preflight::{preflight, PreflightReport};
use super::preflight_error::PreflightError;
use super::preflight_limits::PreflightLimits;
use super::repo::GitRepoPaths;
use super::repo_open::{repo_open, RefWatermarkStore, RepoJobState, StartSetResolver};
use super::seen_store::SeenBlobStore;
use super::spill_limits::SpillLimits;
use super::spiller::{SpillStats, Spiller};
use super::start_set::StartSetConfig;
use super::tree_candidate::CandidateSink;
use super::tree_diff::{TreeDiffStats, TreeDiffWalker};
use super::tree_diff_limits::TreeDiffLimits;

/// Limits for pack file mmapping during scan execution.
#[derive(Clone, Copy, Debug)]
pub struct PackMmapLimits {
    /// Maximum number of pack files to mmap.
    ///
    /// Counted from MIDX-resolved pack paths.
    pub max_open_packs: u16,
    /// Maximum total bytes to mmap across all packs.
    ///
    /// Computed from file sizes; this caps address space usage, not RSS.
    pub max_total_bytes: u64,
}

impl PackMmapLimits {
    /// Safe defaults suitable for large monorepos.
    pub const DEFAULT: Self = Self {
        max_open_packs: 128,
        max_total_bytes: 8 * 1024 * 1024 * 1024,
    };

    /// Restrictive limits for testing or constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_open_packs: 8,
        max_total_bytes: 512 * 1024 * 1024,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_open_packs > 0, "must allow at least 1 pack");
        assert!(self.max_total_bytes > 0, "pack mmap budget must be > 0");
    }
}

/// Candidate sink that forwards tree-diff output to the spill/dedupe stage.
struct SpillCandidateSink<'a> {
    spiller: &'a mut Spiller,
}

impl<'a> SpillCandidateSink<'a> {
    fn new(spiller: &'a mut Spiller) -> Self {
        Self { spiller }
    }
}

impl CandidateSink for SpillCandidateSink<'_> {
    fn emit(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: super::tree_candidate::ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        self.spiller
            .push(
                oid,
                path,
                commit_id,
                parent_idx,
                change_kind,
                ctx_flags,
                cand_flags,
            )
            .map_err(|err| TreeDiffError::CandidateSinkError {
                detail: err.to_string(),
            })
    }
}

/// Git scan runner configuration.
///
/// The defaults mirror the Git scanning limits and are intended for
/// production usage. Callers should set `repo_id` and `policy_hash` to
/// stable identifiers for their environment to ensure consistent
/// persistence keys and scan identity.
#[derive(Clone, Debug)]
pub struct GitScanConfig {
    /// Stable repository identifier used to namespace persisted keys.
    pub repo_id: u64,
    /// Stable policy hash that identifies the scan configuration.
    pub policy_hash: [u8; 32],
    /// Start set selection (default branch, explicit refs, etc.).
    pub start_set: StartSetConfig,
    /// Merge diff strategy for merge commits.
    pub merge_diff_mode: MergeDiffMode,
    /// Path-policy version for scan configuration hashing.
    pub path_policy_version: u32,
    pub preflight: PreflightLimits,
    pub repo_open: RepoOpenLimits,
    pub commit_walk: CommitWalkLimits,
    pub tree_diff: TreeDiffLimits,
    pub spill: SpillLimits,
    pub mapping: MappingBridgeConfig,
    pub pack_plan: PackPlanConfig,
    pub pack_decode: PackDecodeLimits,
    pub pack_io: PackIoLimits,
    pub engine_adapter: EngineAdapterConfig,
    /// Pack mmap limits during pack execution (count + total bytes).
    pub pack_mmap: PackMmapLimits,
    /// Pack cache size in bytes (must fit in `u32`).
    pub pack_cache_bytes: usize,
    /// Optional spill directory override. When `None`, a temp directory is used.
    pub spill_dir: Option<PathBuf>,
}

impl Default for GitScanConfig {
    fn default() -> Self {
        let pack_decode = PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024);
        Self {
            repo_id: 1,
            policy_hash: [0u8; 32],
            start_set: StartSetConfig::DefaultBranchOnly,
            merge_diff_mode: MergeDiffMode::AllParents,
            path_policy_version: 1,
            preflight: PreflightLimits::DEFAULT,
            repo_open: RepoOpenLimits::DEFAULT,
            commit_walk: CommitWalkLimits::DEFAULT,
            tree_diff: TreeDiffLimits::DEFAULT,
            spill: SpillLimits::DEFAULT,
            mapping: MappingBridgeConfig::default(),
            pack_plan: PackPlanConfig::default(),
            pack_decode,
            pack_io: PackIoLimits::new(pack_decode, PackPlanConfig::default().max_delta_depth),
            engine_adapter: EngineAdapterConfig::default(),
            pack_mmap: PackMmapLimits::DEFAULT,
            pack_cache_bytes: 64 * 1024 * 1024,
            spill_dir: None,
        }
    }
}

/// Result of a Git scan run.
#[derive(Debug)]
pub enum GitScanResult {
    /// The repo is missing required maintenance artifacts (commit-graph, MIDX, etc.).
    NeedsMaintenance { preflight: PreflightReport },
    /// Scan completed; consult `finalize.outcome` and `skipped_candidates` for partial runs.
    Completed(GitScanReport),
}

/// Reason a candidate blob was skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSkipReason {
    /// Loose object was missing on disk.
    LooseMissing,
    /// Loose object failed to decode.
    LooseDecode,
    /// Loose object was not a blob.
    LooseNotBlob,
    /// Pack entry was not a blob.
    PackNotBlob,
    /// Pack entry failed to decode.
    PackDecode,
    /// Delta application failed.
    PackDelta,
    /// Delta base offset was missing from the cache.
    PackBaseMissing,
    /// External base OID could not be resolved.
    PackExternalBaseMissing,
    /// External base provider failed.
    PackExternalBaseError,
    /// Pack parse error surfaced as a skip.
    PackParse,
}

impl CandidateSkipReason {
    fn from_pack_skip(reason: &SkipReason) -> Self {
        match reason {
            SkipReason::PackParse(_) => Self::PackParse,
            SkipReason::Decode(_) => Self::PackDecode,
            SkipReason::Delta(_) => Self::PackDelta,
            SkipReason::BaseMissing { .. } => Self::PackBaseMissing,
            SkipReason::ExternalBaseMissing { .. } => Self::PackExternalBaseMissing,
            SkipReason::ExternalBaseError => Self::PackExternalBaseError,
            SkipReason::NotBlob => Self::PackNotBlob,
        }
    }
}

/// Candidate blob skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedCandidate {
    pub oid: OidBytes,
    pub reason: CandidateSkipReason,
}

/// Summary report for a completed scan.
#[derive(Debug)]
pub struct GitScanReport {
    /// Number of commits processed in the plan.
    pub commit_count: usize,
    /// Tree diff stage statistics.
    pub tree_diff_stats: TreeDiffStats,
    /// Spill/dedupe stage statistics.
    pub spill_stats: SpillStats,
    /// Pack mapping statistics.
    pub mapping_stats: MappingStats,
    /// Per-pack-plan statistics.
    pub pack_plan_stats: Vec<PackPlanStats>,
    /// Pack decode + scan reports.
    pub pack_exec_reports: Vec<PackExecReport>,
    /// Candidates skipped with explicit reasons.
    pub skipped_candidates: Vec<SkippedCandidate>,
    /// Finalize output and persistence stats.
    pub finalize: FinalizeOutput,
}

/// Git scan error taxonomy.
#[derive(Debug)]
pub enum GitScanError {
    Preflight(PreflightError),
    RepoOpen(RepoOpenError),
    CommitPlan(CommitPlanError),
    TreeDiff(TreeDiffError),
    Spill(SpillError),
    Midx(MidxError),
    PackPlan(PackPlanError),
    PackExec(PackExecError),
    PackIo(PackIoError),
    Persist(PersistError),
    Io(io::Error),
    /// Resource limit exceeded (pack mmap counts or bytes).
    ResourceLimit(String),
}

impl std::fmt::Display for GitScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preflight(err) => write!(f, "{err}"),
            Self::RepoOpen(err) => write!(f, "{err}"),
            Self::CommitPlan(err) => write!(f, "{err}"),
            Self::TreeDiff(err) => write!(f, "{err}"),
            Self::Spill(err) => write!(f, "{err}"),
            Self::Midx(err) => write!(f, "{err}"),
            Self::PackPlan(err) => write!(f, "{err}"),
            Self::PackExec(err) => write!(f, "{err}"),
            Self::PackIo(err) => write!(f, "{err}"),
            Self::Persist(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::ResourceLimit(msg) => write!(f, "resource limit exceeded: {msg}"),
        }
    }
}

impl std::error::Error for GitScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(err) => Some(err),
            Self::RepoOpen(err) => Some(err),
            Self::CommitPlan(err) => Some(err),
            Self::TreeDiff(err) => Some(err),
            Self::Spill(err) => Some(err),
            Self::Midx(err) => Some(err),
            Self::PackPlan(err) => Some(err),
            Self::PackExec(err) => Some(err),
            Self::PackIo(err) => Some(err),
            Self::Persist(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::ResourceLimit(_) => None,
        }
    }
}

impl From<PreflightError> for GitScanError {
    fn from(err: PreflightError) -> Self {
        Self::Preflight(err)
    }
}
impl From<RepoOpenError> for GitScanError {
    fn from(err: RepoOpenError) -> Self {
        Self::RepoOpen(err)
    }
}
impl From<CommitPlanError> for GitScanError {
    fn from(err: CommitPlanError) -> Self {
        Self::CommitPlan(err)
    }
}
impl From<TreeDiffError> for GitScanError {
    fn from(err: TreeDiffError) -> Self {
        Self::TreeDiff(err)
    }
}
impl From<SpillError> for GitScanError {
    fn from(err: SpillError) -> Self {
        Self::Spill(err)
    }
}
impl From<MidxError> for GitScanError {
    fn from(err: MidxError) -> Self {
        Self::Midx(err)
    }
}
impl From<PackPlanError> for GitScanError {
    fn from(err: PackPlanError) -> Self {
        Self::PackPlan(err)
    }
}
impl From<PackExecError> for GitScanError {
    fn from(err: PackExecError) -> Self {
        Self::PackExec(err)
    }
}
impl From<PackIoError> for GitScanError {
    fn from(err: PackIoError) -> Self {
        Self::PackIo(err)
    }
}
impl From<PersistError> for GitScanError {
    fn from(err: PersistError) -> Self {
        Self::Persist(err)
    }
}
impl From<io::Error> for GitScanError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Runs a full Git scan with the provided configuration and stores.
///
/// The pipeline short-circuits with `NeedsMaintenance` if preflight or repo
/// open indicates missing artifacts (MIDX, commit graph, etc.). On success,
/// the scan is finalized and optionally persisted.
///
/// # Inputs
/// - `repo_root` must reference a Git repository with readable metadata.
/// - `resolver` controls how the start set is chosen (default branch, refs, etc.).
/// - `seen_store` is used to dedupe candidates across runs.
/// - `watermark_store` records ref watermarks when finalize succeeds.
/// - `persist_store` is optional; when `None`, finalize output is returned only.
///
/// # Returns
/// - `NeedsMaintenance` when repo artifacts are missing or out of date.
/// - `Completed` with a `GitScanReport` when the scan finishes.
///
/// # Maintenance
/// Preflight pack-count recommendations are advisory only; the scan proceeds
/// as long as required artifacts are present.
///
/// # Errors
/// Pack mmap limits and cache sizing may surface as `GitScanError::ResourceLimit`.
///
/// # Caveats
/// - Loose object decode failures are recorded as skipped candidates and may
///   yield a `FinalizeOutcome::Partial`, suppressing watermark writes.
#[allow(clippy::too_many_arguments)]
pub fn run_git_scan(
    repo_root: &Path,
    engine: &Engine,
    resolver: &dyn StartSetResolver,
    seen_store: &dyn SeenBlobStore,
    watermark_store: &dyn RefWatermarkStore,
    persist_store: Option<&dyn PersistenceStore>,
    config: &GitScanConfig,
) -> Result<GitScanResult, GitScanError> {
    // Preflight (metadata-only readiness). Pack count recommendations are advisory.
    let preflight = preflight(repo_root, config.preflight)?;
    if !preflight.status.is_ready() {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    let start_set_id = config.start_set.id();
    let repo = repo_open(
        repo_root,
        config.repo_id,
        config.policy_hash,
        start_set_id,
        resolver,
        watermark_store,
        config.repo_open,
    )?;
    if !repo.artifact_status.is_ready() {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    // Commit walk plan.
    let cg = CommitGraphView::open_repo(&repo)?;
    let plan = introduced_by_plan(&repo, &cg, config.commit_walk)?;

    // Spill + dedupe (stream candidates during tree diff).
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
    let mut object_store = ObjectStore::open(&repo, &config.tree_diff)?;
    let mut walker = TreeDiffWalker::new(&config.tree_diff, repo.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    {
        let mut sink = SpillCandidateSink::new(&mut spiller);
        for PlannedCommit { pos, snapshot_root } in &plan {
            let commit_id = pos.0;
            let new_tree = cg.root_tree_oid(*pos)?;

            if *snapshot_root {
                walker.diff_trees(
                    &mut object_store,
                    &mut sink,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                )?;
                continue;
            }

            parent_scratch.clear();
            cg.collect_parents(
                *pos,
                config.commit_walk.max_parents_per_commit,
                &mut parent_scratch,
            )?;
            let parents = parent_scratch.as_slice();

            if parents.is_empty() {
                walker.diff_trees(
                    &mut object_store,
                    &mut sink,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                )?;
                continue;
            }

            match config.merge_diff_mode {
                MergeDiffMode::AllParents => {
                    for (idx, parent_pos) in parents.iter().enumerate() {
                        let old_tree = cg.root_tree_oid(*parent_pos)?;
                        walker.diff_trees(
                            &mut object_store,
                            &mut sink,
                            Some(&new_tree),
                            Some(&old_tree),
                            commit_id,
                            idx as u8,
                        )?;
                    }
                }
                MergeDiffMode::FirstParentOnly => {
                    let old_tree = cg.root_tree_oid(parents[0])?;
                    walker.diff_trees(
                        &mut object_store,
                        &mut sink,
                        Some(&new_tree),
                        Some(&old_tree),
                        commit_id,
                        0,
                    )?;
                }
            }
        }
    }

    let midx = load_midx(&repo)?;
    let mut bridge = MappingBridge::new(
        &midx,
        CappedPackCandidateSink::new(
            config.mapping.max_packed_candidates,
            config.mapping.max_loose_candidates,
        ),
        config.mapping,
    );
    let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
    let (mapping_stats, sink, mapping_arena) = bridge.finish()?;

    // Pack planning.
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    // Enforce pack mmap limits before decoding to cap address space usage.
    let pack_mmaps = mmap_pack_files(&pack_paths, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    if !sink.packed.is_empty() {
        let mut pack_plans = build_pack_plans(&sink.packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }

    // Validate artifacts before decoding packs to avoid scanning during maintenance.
    if !repo.artifacts_unchanged()? {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    // Execute pack plans + scan.
    let pack_cache_bytes: u32 = config
        .pack_cache_bytes
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut cache = PackCache::new(pack_cache_bytes);
    let mut external = PackIo::open(&repo, config.pack_io)?;
    let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
    adapter.reserve_results(sink.packed.len().saturating_add(sink.loose.len()));
    let mut pack_exec_reports = Vec::with_capacity(plans.len());
    let mut skipped_candidates = Vec::new();

    for plan in &plans {
        let pack_id = plan.pack_id as usize;
        let pack_bytes = pack_mmaps
            .get(pack_id)
            .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                pack_id: plan.pack_id,
                pack_count: pack_mmaps.len(),
            }))?
            .as_ref();

        let report = execute_pack_plan(
            plan,
            pack_bytes,
            &mapping_arena,
            &config.pack_decode,
            &mut cache,
            &mut external,
            &mut adapter,
        )?;
        collect_skipped_candidates(plan, &report.skips, &mut skipped_candidates);
        pack_exec_reports.push(report);
    }

    if !sink.loose.is_empty() {
        scan_loose_candidates(
            &sink.loose,
            &mapping_arena,
            &mut adapter,
            &mut external,
            &mut skipped_candidates,
        )?;
    }

    let scanned = adapter.take_results();
    let path_arena = adapter.path_arena();

    // Finalize ops.
    let refs = build_ref_entries(&repo);
    let skipped_candidate_oids = skipped_candidates.iter().map(|entry| entry.oid).collect();

    let finalize = build_finalize_ops(FinalizeInput {
        repo_id: config.repo_id,
        policy_hash: config.policy_hash,
        start_set_id,
        refs,
        scanned_blobs: scanned.blobs,
        finding_arena: &scanned.finding_arena,
        skipped_candidate_oids,
        path_arena,
    });

    if let Some(store) = persist_store {
        persist_finalize_output(store, &finalize)?;
    }

    Ok(GitScanResult::Completed(GitScanReport {
        commit_count: plan.len(),
        tree_diff_stats: walker.stats().clone(),
        spill_stats,
        mapping_stats,
        pack_plan_stats,
        pack_exec_reports,
        skipped_candidates,
        finalize,
    }))
}

/// Create a unique spill directory under the OS temp directory.
///
/// The directory name is derived from the PID and a nanosecond timestamp.
fn make_spill_dir() -> Result<PathBuf, io::Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "git_scan_spill_{}_{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Load the MIDX view for the repository.
///
/// # Errors
/// Returns `GitScanError::Midx` if the MIDX mmap is missing or corrupted.
fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_mmap = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx mmap missing")))?;
    Ok(MidxView::parse(midx_mmap.as_ref(), repo.object_format)?)
}

/// Convert the repo start set into finalize `RefEntry` values.
///
/// The ref names are taken from the repo's shared name table.
fn build_ref_entries(repo: &RepoJobState) -> Vec<RefEntry> {
    let mut refs = Vec::with_capacity(repo.start_set.len());
    for r in &repo.start_set {
        refs.push(RefEntry {
            ref_name: repo.ref_names.get(r.name).to_vec(),
            tip_oid: r.tip,
        });
    }
    refs
}

/// Collect pack directories, including alternates.
///
/// Alternates that resolve to the main objects dir are ignored.
fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

/// List pack file names from the provided pack directories.
///
/// Returns raw file names (as bytes) for `.pack` files. Missing pack
/// directories are ignored; other IO errors are returned.
fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, GitScanError> {
    let mut names = Vec::new();
    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(GitScanError::Io(err)),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }
    Ok(names)
}

/// Resolve pack file paths referenced by the MIDX.
///
/// The MIDX stores pack basenames; we add the `.pack` suffix and search
/// each pack directory until a match is found.
fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, GitScanError> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);
    for name in midx.pack_names() {
        let mut base = strip_pack_suffix(name);
        base.extend_from_slice(b".pack");
        let file_name = String::from_utf8_lossy(&base).into_owned();

        let mut found = None;
        for dir in pack_dirs {
            let candidate = dir.join(&file_name);
            if is_file(&candidate) {
                found = Some(candidate);
                break;
            }
        }
        match found {
            Some(path) => paths.push(path),
            None => {
                return Err(GitScanError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("pack file not found for {}", String::from_utf8_lossy(name)),
                )))
            }
        }
    }
    Ok(paths)
}

/// Strip a `.pack` or `.idx` suffix from a pack-related file name.
fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") {
        name[..name.len() - 5].to_vec()
    } else if name.ends_with(b".idx") {
        name[..name.len() - 4].to_vec()
    } else {
        name.to_vec()
    }
}

/// Memory-map pack files for zero-copy decoding.
///
/// The mappings are read-only and may outlive the file handles.
/// Returns `GitScanError::ResourceLimit` if pack counts or total bytes exceed
/// the configured mmap limits.
fn mmap_pack_files(
    pack_paths: &[PathBuf],
    limits: PackMmapLimits,
) -> Result<Vec<Mmap>, GitScanError> {
    limits.validate();
    if pack_paths.len() > limits.max_open_packs as usize {
        return Err(GitScanError::ResourceLimit(format!(
            "pack count {} exceeds limit {}",
            pack_paths.len(),
            limits.max_open_packs
        )));
    }

    let mut out = Vec::with_capacity(pack_paths.len());
    let mut total_bytes = 0_u64;
    for path in pack_paths {
        let metadata = fs::metadata(path)?;
        total_bytes = total_bytes.saturating_add(metadata.len());
        if total_bytes > limits.max_total_bytes {
            return Err(GitScanError::ResourceLimit(format!(
                "mapped pack bytes {} exceed limit {}",
                total_bytes, limits.max_total_bytes
            )));
        }
        let file = File::open(path)?;
        // SAFETY: mapping read-only pack files; the OS keeps the mapping valid
        // even after `file` is dropped.
        let mmap = unsafe { Mmap::map(&file)? };
        out.push(mmap);
    }
    Ok(out)
}

/// Parse pack headers into `PackView`s used for planning.
///
/// Each pack view validates header structure and captures offsets needed by
/// the planning stage.
fn build_pack_views<'a>(
    pack_mmaps: &'a [Mmap],
    format: ObjectFormat,
) -> Result<Vec<PackView<'a>>, GitScanError> {
    let mut views = Vec::with_capacity(pack_mmaps.len());
    for mmap in pack_mmaps {
        let view = PackView::parse(mmap.as_ref(), format.oid_len())
            .map_err(|err| GitScanError::PackPlan(PackPlanError::PackParse(err)))?;
        views.push(view);
    }
    Ok(views)
}

/// Loads loose candidates and scans blob payloads.
///
/// Missing or undecodable loose objects are recorded as skips so the run can
/// complete with partial results. Paths are re-interned into the adapter's
/// arena via `emit_loose`.
/// Scan loose candidates and record explicit skip reasons for failures.
///
/// Missing objects, decode errors, and non-blob kinds are recorded as skips.
/// Unexpected pack I/O errors are returned as fatal scan errors.
fn scan_loose_candidates(
    candidates: &[LooseCandidate],
    paths: &ByteArena,
    adapter: &mut EngineAdapter,
    pack_io: &mut PackIo<'_>,
    skipped: &mut Vec<SkippedCandidate>,
) -> Result<(), GitScanError> {
    for candidate in candidates {
        let path = paths.get(candidate.ctx.path_ref);
        match pack_io.load_loose_object(&candidate.oid) {
            Ok(Some((ObjectKind::Blob, bytes))) => {
                adapter.emit_loose(candidate, path, &bytes)?;
            }
            Ok(Some((_kind, _bytes))) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseNotBlob,
                });
            }
            Ok(None) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseMissing,
                });
            }
            Err(PackIoError::LooseObject { .. }) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseDecode,
                });
            }
            Err(err) => return Err(GitScanError::PackIo(err)),
        }
    }
    Ok(())
}

/// Collect candidates that were skipped during pack execution.
///
/// The skip records are offsets into the pack stream; we map them back to
/// candidate offsets and record the corresponding OIDs with a reason.
fn collect_skipped_candidates(
    plan: &PackPlan,
    skips: &[SkipRecord],
    out: &mut Vec<SkippedCandidate>,
) {
    if skips.is_empty() {
        return;
    }
    // `candidate_offsets` are sorted by pack offset, enabling binary partitioning.
    let offsets = &plan.candidate_offsets;
    for skip in skips {
        let reason = CandidateSkipReason::from_pack_skip(&skip.reason);
        let start = offsets.partition_point(|c| c.offset < skip.offset);
        let end = offsets.partition_point(|c| c.offset <= skip.offset);
        for cand in &offsets[start..end] {
            let idx = cand.cand_idx as usize;
            if let Some(entry) = plan.candidates.get(idx) {
                out.push(SkippedCandidate {
                    oid: entry.oid,
                    reason,
                });
            }
        }
    }
}

fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::{ByteRef, CandidateContext, ChangeKind};
    use crate::{
        demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId,
        TransformMode, ValidatorKind,
    };
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use regex::bytes::Regex;
    use std::io::Write;
    use tempfile::tempdir;

    /// Helper for constructing a minimal SHA-1 MIDX buffer.
    ///
    /// Only the chunks needed by `MidxView` lookups are populated.
    #[derive(Default)]
    struct MidxBuilder {
        pack_names: Vec<Vec<u8>>,
        objects: Vec<([u8; 20], u16, u64)>,
    }

    impl MidxBuilder {
        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn build(&self) -> Vec<u8> {
            const MIDX_MAGIC: [u8; 4] = *b"MIDX";
            const VERSION: u8 = 1;
            const HEADER_SIZE: usize = 12;
            const CHUNK_ENTRY_SIZE: usize = 12;
            const CHUNK_PNAM: [u8; 4] = *b"PNAM";
            const CHUNK_OIDF: [u8; 4] = *b"OIDF";
            const CHUNK_OIDL: [u8; 4] = *b"OIDL";
            const CHUNK_OOFF: [u8; 4] = *b"OOFF";

            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let pack_count = self.pack_names.len() as u32;

            let mut pnam = Vec::new();
            for name in &self.pack_names {
                pnam.extend_from_slice(name);
                pnam.push(0);
            }

            let mut oidf = vec![0u8; 256 * 4];
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
            for (oid, _, _) in &objects {
                oidl.extend_from_slice(oid);
            }

            let mut ooff = Vec::with_capacity(objects.len() * 8);
            for (_, pack_id, offset) in &objects {
                ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
                ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
            }

            let chunk_count = 4u8;
            let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
            let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
            let oidf_off = pnam_off + pnam.len() as u64;
            let oidl_off = oidf_off + oidf.len() as u64;
            let ooff_off = oidl_off + oidl.len() as u64;
            let end_off = ooff_off + ooff.len() as u64;

            let mut out = Vec::new();
            out.extend_from_slice(&MIDX_MAGIC);
            out.push(VERSION);
            out.push(1); // SHA-1
            out.push(chunk_count);
            out.push(0); // base count
            out.extend_from_slice(&pack_count.to_be_bytes());

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

    fn test_engine() -> Engine {
        let rule = RuleSpec {
            name: "tok",
            anchors: &[b"TOK_"],
            radius: 16,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            secret_group: Some(1),
            re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
        };

        let transforms = vec![TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 4,
            max_encoded_len: 1024,
            max_decoded_bytes: 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }];

        Engine::new_with_anchor_policy(
            vec![rule],
            transforms,
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        )
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn oid_to_hex(oid: &OidBytes) -> String {
        let mut out = String::with_capacity(oid.len() as usize * 2);
        for &b in oid.as_slice() {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }

    fn write_loose_blob(objects_dir: &Path, oid: OidBytes, payload: &[u8]) {
        let mut header = Vec::new();
        header.extend_from_slice(b"blob ");
        header.extend_from_slice(payload.len().to_string().as_bytes());
        header.push(0);
        header.extend_from_slice(payload);

        let compressed = compress(&header);
        let hex = oid_to_hex(&oid);
        let (dir, file) = hex.split_at(2);
        let dir_path = objects_dir.join(dir);
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join(file), &compressed).unwrap();
    }

    fn build_pack_io(objects_dir: &Path) -> PackIo<'static> {
        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-test");
        let midx_bytes = builder.build();
        // Leak the bytes for the duration of the test to satisfy `MidxView` lifetimes.
        let midx_bytes: &'static [u8] = Box::leak(midx_bytes.into_boxed_slice());
        let midx = MidxView::parse(midx_bytes, ObjectFormat::Sha1).unwrap();

        let pack_paths = vec![objects_dir.join("pack-test.pack")];
        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024), 2);
        PackIo::from_parts(midx, pack_paths, vec![objects_dir.to_path_buf()], limits).unwrap()
    }

    fn loose_candidate(path_ref: ByteRef, oid: OidBytes) -> LooseCandidate {
        LooseCandidate {
            oid,
            ctx: CandidateContext {
                commit_id: 1,
                parent_idx: 0,
                change_kind: ChangeKind::Add,
                ctx_flags: 0,
                cand_flags: 0,
                path_ref,
            },
        }
    }

    #[test]
    fn loose_blob_with_secret_is_scanned() {
        let engine = test_engine();
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");

        let oid = OidBytes::sha1([0xAB; 20]);
        write_loose_blob(&objects_dir, oid, b"hello TOK_ABCDEFGH");

        let mut pack_io = build_pack_io(&objects_dir);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        adapter.reserve_results(1);
        adapter.reserve_findings(4);
        adapter.reserve_findings_buf(4);

        let mut paths = ByteArena::with_capacity(64);
        let path_ref = paths.intern(b"src/lib.rs").unwrap();
        let candidate = loose_candidate(path_ref, oid);
        let mut skipped = Vec::new();

        scan_loose_candidates(
            &[candidate],
            &paths,
            &mut adapter,
            &mut pack_io,
            &mut skipped,
        )
        .unwrap();

        assert!(skipped.is_empty());
        let scanned = adapter.take_results();
        assert_eq!(scanned.blobs.len(), 1);
        assert!(!scanned.finding_arena.is_empty());
    }

    #[test]
    fn missing_loose_object_is_skipped() {
        let engine = test_engine();
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");

        let oid = OidBytes::sha1([0xCD; 20]);
        let mut pack_io = build_pack_io(&objects_dir);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        let mut paths = ByteArena::with_capacity(64);
        let path_ref = paths.intern(b"src/lib.rs").unwrap();
        let candidate = loose_candidate(path_ref, oid);
        let mut skipped = Vec::new();

        scan_loose_candidates(
            &[candidate],
            &paths,
            &mut adapter,
            &mut pack_io,
            &mut skipped,
        )
        .unwrap();

        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].oid, oid);
        assert_eq!(skipped[0].reason, CandidateSkipReason::LooseMissing);
        let scanned = adapter.take_results();
        assert!(scanned.blobs.is_empty());
    }
}
