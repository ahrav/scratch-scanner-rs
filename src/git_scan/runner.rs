//! End-to-end Git scan runner.
//!
//! Orchestrates preflight, repo open, commit walk, tree diff, spill/dedupe,
//! pack planning, pack decode + scan, finalize, and persistence.
//!
//! # Notes
//! - Loose objects are currently treated as skipped candidates.
//! - Persistence is optional; callers can run the pipeline without a store.

use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Engine;

use super::bytes::BytesView;
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
use super::pack_candidates::CollectingPackCandidateSink;
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{execute_pack_plan, PackExecError, PackExecReport, SkipRecord};
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
use super::tree_candidate::CandidateBuffer;
use super::tree_diff::{TreeDiffStats, TreeDiffWalker};
use super::tree_diff_limits::TreeDiffLimits;

/// Git scan runner configuration.
///
/// The defaults mirror the Git scanning limits and are intended for
/// production usage. Callers should set `repo_id` and `policy_hash` to
/// stable identifiers for their environment.
///
/// `pack_cache_bytes` is an in-memory cache cap; oversized values are rejected
/// at runtime when converting to `u32`.
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
    /// Scan completed (data ops may still be partial if candidates were skipped).
    Completed(GitScanReport),
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
/// # Caveats
/// - Loose objects are currently treated as skipped candidates. This yields
///   a `FinalizeOutcome::Partial` and suppresses watermark writes.
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
    // Preflight (metadata-only readiness).
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

    // Tree diff and candidate collection.
    let mut object_store = ObjectStore::open(&repo, &config.tree_diff)?;
    let mut walker = TreeDiffWalker::new(&config.tree_diff, repo.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&config.tree_diff, repo.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    for PlannedCommit { pos, snapshot_root } in &plan {
        let commit_id = pos.0;
        let new_tree = cg.root_tree_oid(*pos)?;

        if *snapshot_root {
            walker.diff_trees(
                &mut object_store,
                &mut candidates,
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
                &mut candidates,
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
                        &mut candidates,
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
                    &mut candidates,
                    Some(&new_tree),
                    Some(&old_tree),
                    commit_id,
                    0,
                )?;
            }
        }
    }

    // Spill + dedupe.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
    for cand in candidates.iter_resolved() {
        spiller.push(
            cand.oid,
            cand.path,
            cand.commit_id,
            cand.parent_idx,
            cand.change_kind,
            cand.ctx_flags,
            cand.cand_flags,
        )?;
    }

    let midx = load_midx(&repo)?;
    let mut bridge = MappingBridge::new(
        &midx,
        CollectingPackCandidateSink::default(),
        config.mapping,
    );
    let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
    let (mapping_stats, sink, mapping_arena) = bridge.finish()?;

    // Pack planning.
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    let pack_mmaps = mmap_pack_files(&pack_paths)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    if !sink.packed.is_empty() {
        let mut pack_plans = build_pack_plans(&sink.packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }

    // Execute pack plans + scan.
    let pack_cache_bytes: u32 = config
        .pack_cache_bytes
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut cache = PackCache::new(pack_cache_bytes);
    let mut external = PackIo::open(&repo, config.pack_io)?;
    let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
    let mut pack_exec_reports = Vec::with_capacity(plans.len());
    let mut skipped_candidate_oids = Vec::new();

    // Record loose candidates as skipped (not yet decoded).
    for cand in &sink.loose {
        skipped_candidate_oids.push(cand.oid);
    }

    for plan in &plans {
        let pack_id = plan.pack_id as usize;
        let pack_bytes = pack_mmaps
            .get(pack_id)
            .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                pack_id: plan.pack_id,
                pack_count: pack_mmaps.len(),
            }))?
            .as_slice();

        let report = execute_pack_plan(
            plan,
            pack_bytes,
            &mapping_arena,
            &config.pack_decode,
            &mut cache,
            &mut external,
            &mut adapter,
        )?;
        collect_skipped_candidate_oids(plan, &report.skips, &mut skipped_candidate_oids);
        pack_exec_reports.push(report);
    }

    let scanned_blobs = adapter.take_results();
    let path_arena = adapter.path_arena();

    // Finalize ops.
    let refs = build_ref_entries(&repo);
    let finalize = build_finalize_ops(FinalizeInput {
        repo_id: config.repo_id,
        policy_hash: config.policy_hash,
        start_set_id,
        refs,
        scanned_blobs,
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
        finalize,
    }))
}

/// Create a unique spill directory under the OS temp directory.
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
fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_bytes = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx bytes missing")))?;
    Ok(MidxView::parse(midx_bytes.as_slice(), repo.object_format)?)
}

/// Convert the repo start set into finalize `RefEntry` values.
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
fn mmap_pack_files(pack_paths: &[PathBuf]) -> Result<Vec<BytesView>, GitScanError> {
    let mut out = Vec::with_capacity(pack_paths.len());
    for path in pack_paths {
        let file = File::open(path)?;
        // SAFETY: mapping read-only pack files; the OS keeps the mapping valid
        // even after `file` is dropped.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        out.push(BytesView::from_mmap(mmap));
    }
    Ok(out)
}

/// Parse pack headers into `PackView`s used for planning.
fn build_pack_views<'a>(
    pack_mmaps: &'a [BytesView],
    format: ObjectFormat,
) -> Result<Vec<PackView<'a>>, GitScanError> {
    let mut views = Vec::with_capacity(pack_mmaps.len());
    for mmap in pack_mmaps {
        let view = PackView::parse(mmap.as_slice(), format.oid_len())
            .map_err(|err| GitScanError::PackPlan(PackPlanError::PackParse(err)))?;
        views.push(view);
    }
    Ok(views)
}

/// Collect candidate OIDs that were skipped during pack execution.
///
/// The skip records are offsets into the pack stream; we map them back to
/// candidate offsets and record the corresponding OIDs.
/// Duplicate OIDs may be emitted when multiple candidates share an offset.
fn collect_skipped_candidate_oids(plan: &PackPlan, skips: &[SkipRecord], out: &mut Vec<OidBytes>) {
    if skips.is_empty() {
        return;
    }
    let offsets = &plan.candidate_offsets;
    for skip in skips {
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

fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
