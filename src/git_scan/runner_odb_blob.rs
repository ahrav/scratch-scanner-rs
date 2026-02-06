//! ODB-blob fast-path scan pipeline.
//!
//! Computes first-introduced blobs from the commit graph and scans them in
//! pack order. If candidate caps or path arena limits are exceeded during
//! blob introduction, retries via the spill/dedupe pipeline.
//!
//! # Pipeline Stages
//!
//! 1. **Blob introduction** -- walks the commit graph and emits
//!    (oid, pack_id, path) candidates for blobs first introduced by each
//!    commit.  On success the candidates land directly in the
//!    `PackCandidateCollector`; on overflow (`CandidateLimitExceeded` /
//!    `PathArenaFull`) the introducer's seen-set is reset and the walk is
//!    re-run through a `Spiller` → `MappingBridge` dedupe pipeline.
//!
//! 2. **Pack planning** -- candidates are bucketed by pack id, then a
//!    per-pack plan (topologically sorted decode order including delta base
//!    dependencies) is built on the runner thread.
//!
//! 3. **Pack execution** -- plans are dispatched as scheduler tasks via
//!    `scheduler::Executor`. The strategy selector chooses the scheduler
//!    worker width (`1` for serial, `pack_exec_workers` for parallel).
//!
//! 4. **Loose scan** -- loose object candidates that did not map to any
//!    pack are scanned after all pack plans complete.
//!
//! All outputs are merged deterministically regardless of worker count so
//! that the same input always produces the same `ScanModeOutput`.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use crate::scheduler::{alloc_stats, AllocStats};
use crate::Engine;

use super::blob_introducer::BlobIntroducer;
use super::commit_graph::CommitGraphIndex;
use super::commit_walk::PlannedCommit;
use super::engine_adapter::{EngineAdapter, ScannedBlobs};
use super::errors::TreeDiffError;
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
use super::object_store::ObjectStore;
use super::oid_index::OidIndex;
use super::pack_candidates::{CappedPackCandidateSink, PackCandidateCollector};
use super::pack_io::PackIo;
use super::pack_plan::{bucket_pack_candidates, build_pack_plan_for_pack, PackPlanError};
use super::runner::{
    GitScanAllocStats, GitScanConfig, GitScanError, GitScanStageNanos, ScanModeOutput,
};
use super::seen_store::SeenBlobStore;
use super::spiller::{SpillStats, Spiller};
use super::tree_delta_cache::TreeDeltaCache;
use super::tree_diff::TreeDiffStats;

use super::runner_exec::{
    append_scanned_blobs, auto_tree_delta_cache_bytes, build_pack_views, collect_loose_dirs,
    collect_pack_dirs, estimate_path_arena_capacity, execute_pack_plans_with_scheduler,
    list_pack_files, load_midx, make_spill_dir, mmap_pack_files, per_worker_cache_bytes,
    resolve_pack_paths, scan_loose_candidates, select_pack_exec_strategy, PackExecStrategy,
    SpillCandidateSink,
};

use super::repo_open::RepoJobState;

/// Runs the ODB-blob fast-path scan pipeline.
///
/// Walks the commit graph to identify first-introduced blobs, maps them to
/// pack offsets via the MIDX, builds per-pack decode plans, then decodes
/// and scans blob contents through the detection engine.  See the module
/// docs for the full stage breakdown and parallelism strategies.
///
/// # Spill / retry
///
/// If the in-memory candidate collector exceeds its capacity or path-arena
/// budget during blob introduction, the fast-path aborts and the function
/// retries the entire introduction through the spill/dedupe pipeline
/// (`Spiller` → `MappingBridge`).  The introducer's seen-set is reset
/// before the retry so every candidate is re-emitted.
///
/// # Determinism
///
/// Regardless of worker count, outputs are reassembled in pack-plan order
/// so that the same input always produces identical `ScanModeOutput`.
///
/// # Parameters
/// - `repo`: opened repository job state (paths, object format, artifacts).
/// - `engine`: detection engine instance for scanning blob contents.
/// - `seen_store`: seen-blob store for deduplication during spill retry.
/// - `cg_index`: commit graph index built from the commit graph.
/// - `plan`: commit plan (planned commits from `introduced_by_plan`).
/// - `config`: scan configuration (limits, worker counts, etc.).
///
/// # Errors
/// Returns `GitScanError` on MIDX, pack plan, pack exec, or I/O failures.
/// Returns `GitScanError::ConcurrentMaintenance` if artifacts change
/// between planning start and execution start.
pub(super) fn run_odb_blob(
    repo: &RepoJobState,
    engine: Arc<Engine>,
    seen_store: &dyn SeenBlobStore,
    cg_index: &CommitGraphIndex,
    plan: &[PlannedCommit],
    config: &GitScanConfig,
    event_sink: std::sync::Arc<dyn crate::unified::events::EventSink>,
) -> Result<ScanModeOutput, GitScanError> {
    let mut stage_nanos = GitScanStageNanos::default();
    let mut alloc_deltas = GitScanAllocStats::default();

    // Shared spill directory for tree payloads and pack-exec large blobs.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let midx = load_midx(repo)?;
    let mut mapping_cfg = config.mapping;
    let default_mapping_cfg = MappingBridgeConfig::default();
    if mapping_cfg.max_packed_candidates >= default_mapping_cfg.max_packed_candidates {
        // Default-or-higher caps are treated as soft budgets; scale to the
        // repository object count so mapping does not fail on large repos.
        mapping_cfg.max_packed_candidates =
            mapping_cfg.max_packed_candidates.max(midx.object_count());
    }
    mapping_cfg.path_arena_capacity = estimate_path_arena_capacity(
        mapping_cfg.path_arena_capacity,
        mapping_cfg.max_packed_candidates,
        mapping_cfg.max_loose_candidates,
    );
    let oid_index = OidIndex::from_midx(&midx);
    // Scale tree delta-cache to repo size to reduce base re-inflate churn on
    // large histories while respecting the configured upper bound.
    let auto_cache_bytes = auto_tree_delta_cache_bytes(
        midx.object_count(),
        config.tree_diff.max_tree_delta_cache_bytes,
    );
    let tree_delta_cache = TreeDeltaCache::new(auto_cache_bytes);
    let mut object_store = ObjectStore::open_with_tree_delta_cache(
        repo,
        &config.tree_diff,
        &spill_dir,
        tree_delta_cache,
    )?;

    let mut introducer = BlobIntroducer::new(
        &config.tree_diff,
        repo.object_format.oid_len(),
        midx.object_count(),
        config.path_policy_version,
        mapping_cfg.max_loose_candidates,
    );

    // ── Stage 1: blob introduction ───────────────────────────────────
    // Attempt the fast path first (in-memory collector).  On capacity
    // overflow, fall back to the spill/dedupe pipeline which writes
    // candidates to disk, deduplicates via `seen_store`, then maps back
    // through a `MappingBridge`.
    let intro_start = Instant::now();
    let (intro_stats, mut packed, loose, path_arena, spill_stats, mapping_stats) = {
        let mut collector = PackCandidateCollector::new(
            &midx,
            &oid_index,
            mapping_cfg.path_arena_capacity,
            mapping_cfg.max_packed_candidates,
            mapping_cfg.max_loose_candidates,
        );

        match introducer.introduce(
            &mut object_store,
            cg_index,
            plan,
            &oid_index,
            &mut collector,
        ) {
            Ok(stats) => {
                stage_nanos.blob_intro = intro_start.elapsed().as_nanos() as u64;
                let collect_start = Instant::now();
                let (packed, loose, path_arena) = collector.finish();
                stage_nanos.pack_collect = collect_start.elapsed().as_nanos() as u64;
                let mapping_stats = MappingStats {
                    unique_blobs_in: packed.len().saturating_add(loose.len()) as u64,
                    packed_matched: packed.len() as u64,
                    loose_unmatched: loose.len() as u64,
                };
                (
                    stats,
                    packed,
                    loose,
                    path_arena,
                    SpillStats::default(),
                    mapping_stats,
                )
            }
            Err(TreeDiffError::CandidateLimitExceeded { .. } | TreeDiffError::PathArenaFull) => {
                let first_elapsed = intro_start.elapsed().as_nanos() as u64;
                // The fast path may have recorded a partial seen-set; reset
                // so the spill/dedupe retry can re-emit every candidate.
                introducer.reset_seen();

                let retry_start = Instant::now();
                let mut spiller =
                    Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
                let mut sink = SpillCandidateSink::new(&mut spiller);
                let stats = introducer.introduce(
                    &mut object_store,
                    cg_index,
                    plan,
                    &oid_index,
                    &mut sink,
                )?;
                let retry_elapsed = retry_start.elapsed().as_nanos() as u64;
                stage_nanos.blob_intro = first_elapsed.saturating_add(retry_elapsed);

                let spill_start = Instant::now();
                let mut bridge = MappingBridge::new(
                    &midx,
                    CappedPackCandidateSink::new(
                        mapping_cfg.max_packed_candidates,
                        mapping_cfg.max_loose_candidates,
                    ),
                    mapping_cfg,
                );
                let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
                stage_nanos.spill = spill_start.elapsed().as_nanos() as u64;
                let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;
                let packed = std::mem::take(&mut sink.packed);
                let loose = std::mem::take(&mut sink.loose);
                (
                    stats,
                    packed,
                    loose,
                    mapping_arena,
                    spill_stats,
                    mapping_stats,
                )
            }
            Err(err) => return Err(err.into()),
        }
    };

    // ── Stage 2 + 3: pack planning + execution ──────────────────────
    let pack_plan_start = Instant::now();
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = Arc::new(resolve_pack_paths(&midx, &pack_dirs)?);
    let loose_dirs = Arc::new(collect_loose_dirs(&repo.paths));
    let mut used_pack_ids: Vec<u16> = packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    let pack_mmaps = Arc::new(mmap_pack_files(
        pack_paths.as_ref(),
        &used_pack_ids,
        config.pack_mmap,
    )?);
    let pack_views = build_pack_views(pack_mmaps.as_ref(), repo.object_format)?;

    let packed_len = packed.len();
    let loose_len = loose.len();
    let mut pack_plan_stats = Vec::with_capacity(used_pack_ids.len());
    let mut pack_plan_cfg = config.pack_plan;
    let mut pack_plan_delta_deps_total: u64 = 0;
    let mut pack_plan_delta_deps_max: u32 = 0;

    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    let pack_exec_workers = config.pack_exec_workers.max(1);
    let pack_cache_target = per_worker_cache_bytes(
        config.pack_cache_bytes,
        pack_mmaps.as_ref(),
        &used_pack_ids,
        config.pack_exec_workers,
    );
    let pack_cache_bytes: u32 = pack_cache_target
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut pack_exec_reports = Vec::with_capacity(used_pack_ids.len());
    let mut skipped_candidates = Vec::new();
    let mut scanned = ScannedBlobs {
        blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
        finding_arena: Vec::new(),
    };
    let path_arena = Arc::new(path_arena);
    let spill_dir = Arc::new(spill_dir);

    let mut pack_exec_started = false;
    let mut pack_exec_start = Instant::now();
    let mut pack_exec_alloc_before = AllocStats::default();
    let mut start_pack_exec = || {
        if !pack_exec_started {
            pack_exec_started = true;
            pack_exec_start = Instant::now();
            pack_exec_alloc_before = alloc_stats();
        }
    };

    if packed_len > 0 {
        let scaled = packed_len.saturating_mul(2);
        pack_plan_cfg.max_worklist_entries = pack_plan_cfg.max_worklist_entries.max(scaled);
        pack_plan_cfg.max_base_lookups = pack_plan_cfg.max_base_lookups.max(scaled);

        let (mut buckets, pack_ids) = bucket_pack_candidates(packed.drain(..), pack_views.len())?;
        let mut plans = Vec::with_capacity(pack_ids.len());
        for pack_id in pack_ids {
            let pack_idx = pack_id as usize;
            let pack = pack_views
                .get(pack_idx)
                .and_then(|pack| pack.as_ref())
                .ok_or(PackPlanError::PackIdOutOfRange {
                    pack_id,
                    pack_count: pack_views.len(),
                })?;
            let pack_candidates = std::mem::take(&mut buckets[pack_idx]);
            let plan =
                build_pack_plan_for_pack(pack_id, pack, pack_candidates, &midx, &pack_plan_cfg)?;
            pack_plan_stats.push(plan.stats);
            let deps_len = plan.delta_deps.len() as u32;
            pack_plan_delta_deps_total = pack_plan_delta_deps_total.saturating_add(deps_len as u64);
            pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);
            plans.push(plan);
        }
        stage_nanos.pack_plan = pack_plan_start.elapsed().as_nanos() as u64;

        if !plans.is_empty() {
            start_pack_exec();
            let strategy = select_pack_exec_strategy(pack_exec_workers, &plans);
            let scheduler_workers = match strategy {
                PackExecStrategy::Serial => 1,
                PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => {
                    pack_exec_workers
                }
            };
            let midx_bytes = repo
                .mmaps
                .midx
                .clone()
                .ok_or_else(|| GitScanError::Io(io::Error::other("midx bytes missing")))?;
            let outputs = execute_pack_plans_with_scheduler(
                Arc::clone(&engine),
                event_sink.clone(),
                midx_bytes,
                repo.object_format,
                Arc::clone(&pack_paths),
                Arc::clone(&loose_dirs),
                Arc::clone(&pack_mmaps),
                Arc::clone(&path_arena),
                Arc::clone(&spill_dir),
                plans,
                config.pack_decode,
                config.pack_io,
                config.engine_adapter,
                pack_cache_bytes,
                scheduler_workers,
            )?;
            for output in outputs {
                pack_exec_reports.push(output.report);
                skipped_candidates.extend(output.skipped);
                append_scanned_blobs(&mut scanned, output.scanned);
            }
        }

        if !loose.is_empty() {
            start_pack_exec();
            let mut adapter = EngineAdapter::new_with_event_sink(
                engine.as_ref(),
                config.engine_adapter,
                event_sink.clone(),
            );
            adapter.reserve_results(loose.len());
            let mut external = PackIo::from_parts(
                midx,
                (*pack_paths).clone(),
                (*loose_dirs).clone(),
                config.pack_io,
            )
            .map_err(GitScanError::PackIo)?;
            let loose_start = Instant::now();
            scan_loose_candidates(
                &loose,
                path_arena.as_ref(),
                &mut adapter,
                &mut external,
                &mut skipped_candidates,
            )?;
            stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
            append_scanned_blobs(&mut scanned, adapter.take_results());
        }
    } else {
        stage_nanos.pack_plan = pack_plan_start.elapsed().as_nanos() as u64;
        if !loose.is_empty() {
            start_pack_exec();
            let mut adapter = EngineAdapter::new_with_event_sink(
                engine.as_ref(),
                config.engine_adapter,
                event_sink.clone(),
            );
            adapter.reserve_results(loose.len());
            let mut external = PackIo::from_parts(
                midx,
                (*pack_paths).clone(),
                (*loose_dirs).clone(),
                config.pack_io,
            )
            .map_err(GitScanError::PackIo)?;
            let loose_start = Instant::now();
            scan_loose_candidates(
                &loose,
                path_arena.as_ref(),
                &mut adapter,
                &mut external,
                &mut skipped_candidates,
            )?;
            stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
            append_scanned_blobs(&mut scanned, adapter.take_results());
        }
    }

    if pack_exec_started {
        stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
        let pack_exec_alloc_after = alloc_stats();
        alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);
    }

    Ok(ScanModeOutput {
        scanned,
        path_arena: Arc::try_unwrap(path_arena)
            .map_err(|_| GitScanError::Io(io::Error::other("path arena still shared")))?,
        skipped_candidates,
        pack_exec_reports,
        pack_plan_stats,
        pack_plan_config: pack_plan_cfg,
        pack_plan_delta_deps_total,
        pack_plan_delta_deps_max,
        tree_diff_stats: TreeDiffStats::from(intro_stats),
        spill_stats,
        mapping_stats,
        stage_nanos,
        alloc_stats: alloc_deltas,
        pack_cache_per_worker_bytes: pack_cache_target,
    })
}
