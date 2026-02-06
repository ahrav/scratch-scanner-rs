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
//!    dependencies) is built on a **background thread** and streamed to the
//!    execution loop via a bounded channel (`sync_channel(1)`), overlapping
//!    planning I/O with decode + scan.
//!
//! 3. **Pack execution** -- one of three strategies is selected at runtime:
//!    - *Single-threaded* (`pack_exec_workers == 1`): plans are consumed
//!      serially with a single cache and engine adapter.
//!    - *Per-pack parallel* (`pack_count >= workers`): each worker pulls
//!      whole pack plans from a shared work queue; results carry a sequence
//!      number and are reassembled in plan order for determinism.
//!    - *Underfilled worker pool* (`pack_count < workers`): the small plan
//!      set is buffered, then a shared stats-free selector chooses serial
//!      execution for tiny work or adaptive intra-pack sharding otherwise.
//!
//! 4. **Loose scan** -- loose object candidates that did not map to any
//!    pack are scanned after all pack plans complete.
//!
//! All outputs are merged deterministically regardless of worker count so
//! that the same input always produces the same `ScanModeOutput`.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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
use super::pack_cache::PackCache;
use super::pack_candidates::{CappedPackCandidateSink, PackCandidateCollector};
use super::pack_exec::{
    build_candidate_ranges, execute_pack_plan_with_scratch, execute_pack_plan_with_scratch_indices,
    merge_pack_exec_reports, PackExecError, PackExecReport, PackExecScratch,
};
use super::pack_io::PackIo;
use super::pack_plan::{bucket_pack_candidates, build_pack_plan_for_pack, PackPlanError};
use super::pack_plan_model::PackPlan;
use super::runner::{
    GitScanAllocStats, GitScanConfig, GitScanError, GitScanStageNanos, ScanModeOutput,
    SkippedCandidate,
};
use super::seen_store::SeenBlobStore;
use super::spiller::{SpillStats, Spiller};
use super::tree_diff::TreeDiffStats;

use super::runner_exec::{
    append_scanned_blobs, build_exec_indices, build_pack_views, collect_loose_dirs,
    collect_pack_dirs, collect_skipped_candidates, estimate_path_arena_capacity, list_pack_files,
    load_midx, make_spill_dir, merge_scanned_blobs, mmap_pack_files, per_worker_cache_bytes,
    resolve_pack_paths, scan_loose_candidates, select_pack_exec_strategy, select_plan_shard_count,
    shard_count_for_pack, shard_ranges, PackExecStrategy, SpillCandidateSink,
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
/// (and, for intra-pack sharding, in shard order) so that the same input
/// always produces identical `ScanModeOutput`.
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
    engine: &Engine,
    seen_store: &dyn SeenBlobStore,
    cg_index: &CommitGraphIndex,
    plan: &[PlannedCommit],
    config: &GitScanConfig,
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
    let mut object_store = ObjectStore::open(repo, &config.tree_diff, &spill_dir)?;

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
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    let loose_dirs = collect_loose_dirs(&repo.paths);
    let mut used_pack_ids: Vec<u16> = packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let packed_len = packed.len();
    let loose_len = loose.len();
    let mut pack_plan_stats = Vec::with_capacity(used_pack_ids.len());
    let mut pack_plan_cfg = config.pack_plan;
    let mut pack_plan_delta_deps_total: u64 = 0;
    let mut pack_plan_delta_deps_max: u32 = 0;

    // Artifact fingerprints must remain stable; we check before planning and
    // again after exec because planning now overlaps execution.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // Planning prelude remains serial; the plan builder runs on a worker
    // thread and is tracked separately for metrics.
    let pack_plan_prelude_nanos = pack_plan_start.elapsed().as_nanos() as u64;
    let pack_plan_thread_nanos = AtomicU64::new(0);

    // Execute pack plans + scan.
    let pack_exec_workers = config.pack_exec_workers.max(1);
    let pack_cache_target = per_worker_cache_bytes(
        config.pack_cache_bytes,
        &pack_mmaps,
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

    // Lazy timing gate: we only start the pack-exec stopwatch the first
    // time work is actually dispatched.  This avoids charging planning or
    // setup time to the pack-exec stage metric.
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
        // ODB-blob mode may produce very large candidate sets (one per
        // first-introduced blob); scale the plan builder's internal
        // worklist/lookup caps to at least 2x the candidate count so it
        // doesn't hit artificial limits.
        let scaled = packed_len.saturating_mul(2);
        pack_plan_cfg.max_worklist_entries = pack_plan_cfg.max_worklist_entries.max(scaled);
        pack_plan_cfg.max_base_lookups = pack_plan_cfg.max_base_lookups.max(scaled);

        let (mut buckets, pack_ids) = bucket_pack_candidates(packed.drain(..), pack_views.len())?;
        let pack_plan_count = pack_ids.len();

        // Strategy preselection: decided *before* plans are built so we know
        // whether to stream plans to workers (pack-parallel) or buffer them
        // for the stats-free selector (underfilled pool). This heuristic
        // uses only the plan count (= number of distinct used packs), which
        // is available before planning starts.
        //   - `pack_exec_workers == 1` → single-threaded execution.
        //   - `pack_plan_count >= workers` → one plan per worker, preserving
        //     planning/execution overlap via the work queue.
        //   - otherwise → collect the small plan set and run the shared
        //     stats-free selector before execution.
        let prefer_pack_parallelism = pack_exec_workers > 1 && pack_plan_count >= pack_exec_workers;

        // Bounded(1) channel: the planner blocks after producing one plan
        // until the executor consumes it, bounding memory to at most two
        // plans in flight (one being built, one being executed).
        let (tx, rx) = mpsc::sync_channel::<Result<PackPlan, PackPlanError>>(1);

        std::thread::scope(|scope| -> Result<(), GitScanError> {
            let pack_plan_thread_nanos = &pack_plan_thread_nanos;
            let pack_views = &pack_views;
            let midx = &midx;
            let pack_plan_cfg = pack_plan_cfg;

            scope.spawn(move || {
                let plan_start = Instant::now();
                let result = (|| -> Result<(), PackPlanError> {
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

                        let plan = build_pack_plan_for_pack(
                            pack_id,
                            pack,
                            pack_candidates,
                            midx,
                            &pack_plan_cfg,
                        )?;
                        if tx.send(Ok(plan)).is_err() {
                            return Ok(());
                        }
                    }
                    Ok(())
                })();

                pack_plan_thread_nanos
                    .store(plan_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

                if let Err(err) = result {
                    let _ = tx.send(Err(err));
                }
            });

            // Pre-allocate cache and scratch before the strategy branch so
            // no allocation happens inside worker closures (Tiger Style).
            let prealloc_cache = PackCache::new(pack_cache_bytes);
            let prealloc_scratch = PackExecScratch::default();

            // ── Strategy A: single-threaded execution ──────────────
            if pack_exec_workers == 1 {
                let mut cache = prealloc_cache;
                let mut external = PackIo::from_parts(
                    *midx,
                    pack_paths.clone(),
                    loose_dirs.clone(),
                    config.pack_io,
                )
                .map_err(GitScanError::PackIo)?;
                let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                adapter.reserve_results(packed_len.saturating_add(loose_len));
                let mut exec_scratch = prealloc_scratch;
                for plan in rx {
                    let plan = plan?;
                    pack_plan_stats.push(plan.stats);
                    let deps_len = plan.delta_deps.len() as u32;
                    pack_plan_delta_deps_total =
                        pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                    pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);

                    start_pack_exec();

                    let pack_id = plan.pack_id as usize;
                    let pack_bytes = pack_mmaps
                        .get(pack_id)
                        .and_then(|mmap| mmap.as_ref())
                        .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                            pack_id: plan.pack_id,
                            pack_count: pack_mmaps.len(),
                        }))?
                        .as_ref();

                    let report = execute_pack_plan_with_scratch(
                        &plan,
                        pack_bytes,
                        &path_arena,
                        &config.pack_decode,
                        &mut cache,
                        &mut external,
                        &mut adapter,
                        &spill_dir,
                        &mut exec_scratch,
                    )?;
                    collect_skipped_candidates(&plan, &report.skips, &mut skipped_candidates);
                    pack_exec_reports.push(report);
                }

                if !loose.is_empty() {
                    start_pack_exec();
                    let loose_start = Instant::now();
                    scan_loose_candidates(
                        &loose,
                        &path_arena,
                        &mut adapter,
                        &mut external,
                        &mut skipped_candidates,
                    )?;
                    stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
                }

                scanned = adapter.take_results();
            // ── Strategy B: per-pack parallel execution ────────────
            // Workers pull whole pack plans from a shared queue.
            // Each (seq, plan) pair carries a sequence number assigned
            // by the dispatcher so results can be slotted back in plan
            // order during reassembly.
            } else if prefer_pack_parallelism {
                // Pre-allocate cache and scratch pools before spawning
                // workers (Tiger Style: allocate at startup, not in closures).
                let mut cache_pool: Vec<PackCache> = (0..pack_exec_workers)
                    .map(|_| PackCache::new(pack_cache_bytes))
                    .collect();
                let mut scratch_pool: Vec<PackExecScratch> = (0..pack_exec_workers)
                    .map(|_| PackExecScratch::default())
                    .collect();

                let (work_tx, work_rx) = mpsc::sync_channel::<(usize, PackPlan)>(pack_exec_workers);
                let work_rx = Arc::new(Mutex::new(work_rx));
                let (result_tx, result_rx) = mpsc::channel::<
                    Result<
                        (usize, PackExecReport, ScannedBlobs, Vec<SkippedCandidate>),
                        PackExecError,
                    >,
                >();
                let mut handles = Vec::with_capacity(pack_exec_workers);

                for (mut cache, mut scratch) in cache_pool.drain(..).zip(scratch_pool.drain(..)) {
                    let work_rx = Arc::clone(&work_rx);
                    let result_tx = result_tx.clone();
                    let pack_paths = pack_paths.clone();
                    let loose_dirs = loose_dirs.clone();
                    let pack_decode = config.pack_decode;
                    let pack_io_limits = config.pack_io;
                    let adapter_cfg = config.engine_adapter;
                    let paths = &path_arena;
                    let spill_dir = &spill_dir;
                    let pack_mmaps = &pack_mmaps;

                    handles.push(scope.spawn(move || {
                        let mut external =
                            match PackIo::from_parts(*midx, pack_paths, loose_dirs, pack_io_limits)
                            {
                                Ok(external) => external,
                                Err(err) => {
                                    let _ = result_tx
                                        .send(Err(PackExecError::ExternalBase(err.to_string())));
                                    return;
                                }
                            };
                        let mut adapter = EngineAdapter::new(engine, adapter_cfg);

                        loop {
                            let work = {
                                let rx = work_rx.lock().expect("pack exec work queue poisoned");
                                rx.recv()
                            };
                            let (seq, plan) = match work {
                                Ok(work) => work,
                                Err(_) => break,
                            };

                            let work_result = (|| {
                                let pack_id = plan.pack_id as usize;
                                let pack_bytes = pack_mmaps
                                    .get(pack_id)
                                    .and_then(|mmap| mmap.as_ref())
                                    .ok_or_else(|| {
                                        PackExecError::PackRead(format!(
                                            "pack id {} out of range (pack count {})",
                                            plan.pack_id,
                                            pack_mmaps.len()
                                        ))
                                    })?
                                    .as_ref();

                                adapter.reserve_results(plan.candidate_offsets.len());
                                adapter.reserve_findings(plan.candidate_offsets.len());
                                let report = execute_pack_plan_with_scratch(
                                    &plan,
                                    pack_bytes,
                                    paths,
                                    &pack_decode,
                                    &mut cache,
                                    &mut external,
                                    &mut adapter,
                                    spill_dir,
                                    &mut scratch,
                                )?;

                                let scanned = adapter.take_results();
                                let mut skipped = Vec::new();
                                collect_skipped_candidates(&plan, &report.skips, &mut skipped);

                                Ok((seq, report, scanned, skipped))
                            })();

                            let should_break = work_result.is_err();
                            if result_tx.send(work_result).is_err() || should_break {
                                break;
                            }
                        }
                    }));
                }

                // Drop the sender half owned by the dispatcher thread so
                // workers see channel closure once all plans are consumed.
                drop(result_tx);

                // Dispatch plans to the work queue, tagging each with a
                // monotonic sequence number for deterministic reassembly.
                let mut plan_count = 0usize;
                for plan in rx {
                    let plan = plan?;
                    pack_plan_stats.push(plan.stats);
                    let deps_len = plan.delta_deps.len() as u32;
                    pack_plan_delta_deps_total =
                        pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                    pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);

                    start_pack_exec();

                    let pack_id = plan.pack_id as usize;
                    pack_mmaps
                        .get(pack_id)
                        .and_then(|mmap| mmap.as_ref())
                        .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                            pack_id: plan.pack_id,
                            pack_count: pack_mmaps.len(),
                        }))?;

                    // Use plan_count as the deterministic sequence for reassembly.
                    if work_tx.send((plan_count, plan)).is_err() {
                        return Err(GitScanError::PackExec(PackExecError::PackRead(
                            "pack exec work queue closed".to_string(),
                        )));
                    }
                    plan_count += 1;
                }
                drop(work_tx);

                // Reassemble outputs by pack order for deterministic merges.
                let mut outputs: Vec<
                    Option<(PackExecReport, ScannedBlobs, Vec<SkippedCandidate>)>,
                > = (0..plan_count).map(|_| None).collect();
                for _ in 0..plan_count {
                    let output = result_rx.recv().map_err(|_| {
                        GitScanError::PackExec(PackExecError::PackRead(
                            "pack exec worker channel closed".to_string(),
                        ))
                    })?;
                    let (seq, report, scanned_pack, skipped) = output?;
                    outputs[seq] = Some((report, scanned_pack, skipped));
                }

                for handle in handles {
                    handle.join().expect("pack exec worker panicked");
                }

                for output in outputs.into_iter() {
                    let (report, scanned_pack, skipped) = output.expect("missing pack exec output");
                    pack_exec_reports.push(report);
                    skipped_candidates.extend(skipped);
                    append_scanned_blobs(&mut scanned, scanned_pack);
                }
            // ── Strategy C: underfilled worker pool ────────────────
            // Fewer plans than workers. Buffer this small plan set, run the
            // shared stats-free selector, then execute either serially (tiny
            // work) or with adaptive per-plan sharding.
            } else {
                let mut queued_plans = Vec::with_capacity(pack_plan_count);
                for plan in rx {
                    let plan = plan?;
                    pack_plan_stats.push(plan.stats);
                    let deps_len = plan.delta_deps.len() as u32;
                    pack_plan_delta_deps_total =
                        pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                    pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);
                    queued_plans.push(plan);
                }

                // Pre-allocate shard caches + scratches for the sharded
                // branch. For Serial/PackParallel the first entry is used
                // directly; extras are harmless (zero-cost default).
                let mut shard_caches: Vec<PackCache> = (0..pack_exec_workers)
                    .map(|_| PackCache::new(pack_cache_bytes))
                    .collect();
                let mut shard_scratches: Vec<PackExecScratch> = (0..pack_exec_workers)
                    .map(|_| PackExecScratch::default())
                    .collect();
                let mut shard_adapters: Vec<EngineAdapter<'_>> = (0..pack_exec_workers)
                    .map(|_| EngineAdapter::new(engine, config.engine_adapter))
                    .collect();
                let mut shard_externals: Vec<PackIo<'_>> = (0..pack_exec_workers)
                    .map(|_| {
                        PackIo::from_parts(
                            *midx,
                            pack_paths.clone(),
                            loose_dirs.clone(),
                            config.pack_io,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(GitScanError::PackIo)?;

                match select_pack_exec_strategy(pack_exec_workers, &queued_plans) {
                    PackExecStrategy::Serial | PackExecStrategy::PackParallel => {
                        if !queued_plans.is_empty() {
                            start_pack_exec();
                        }
                        // Reuse first pre-allocated cache, scratch, adapter,
                        // and PackIo from the pools.
                        let mut cache = shard_caches.swap_remove(0);
                        let external = &mut shard_externals[0];
                        let adapter = &mut shard_adapters[0];
                        adapter.clear_results();
                        adapter.reserve_results(packed_len.saturating_add(loose_len));
                        let mut exec_scratch = shard_scratches.swap_remove(0);
                        for plan in &queued_plans {
                            let pack_id = plan.pack_id as usize;
                            let pack_bytes = pack_mmaps
                                .get(pack_id)
                                .and_then(|mmap| mmap.as_ref())
                                .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                                    pack_id: plan.pack_id,
                                    pack_count: pack_mmaps.len(),
                                }))?
                                .as_ref();

                            let report = execute_pack_plan_with_scratch(
                                plan,
                                pack_bytes,
                                &path_arena,
                                &config.pack_decode,
                                &mut cache,
                                external,
                                adapter,
                                &spill_dir,
                                &mut exec_scratch,
                            )?;
                            collect_skipped_candidates(
                                plan,
                                &report.skips,
                                &mut skipped_candidates,
                            );
                            pack_exec_reports.push(report);
                        }
                        append_scanned_blobs(&mut scanned, adapter.take_results());
                    }
                    PackExecStrategy::IntraPackSharded { shard_counts } => {
                        // ── Pre-compute per-plan work on the main thread ──
                        // Resolves pack bytes, exec indices, candidate ranges,
                        // and shard assignments before spawning any workers.
                        struct PlanWork<'a> {
                            plan: &'a PackPlan,
                            pack_bytes: &'a [u8],
                            exec_indices: Vec<usize>,
                            candidate_ranges: Vec<Option<(usize, usize)>>,
                            shard_ranges: Vec<(usize, usize)>,
                        }
                        let mut candidate_ranges_buf = Vec::new();
                        let plan_work: Vec<PlanWork<'_>> = queued_plans
                            .iter()
                            .filter_map(|plan| {
                                let pack_id = plan.pack_id as usize;
                                let pack_bytes = pack_mmaps
                                    .get(pack_id)
                                    .and_then(|mmap| mmap.as_ref())?
                                    .as_ref();
                                let exec_indices = build_exec_indices(plan);
                                if exec_indices.is_empty() {
                                    return None;
                                }
                                build_candidate_ranges(plan, &mut candidate_ranges_buf);
                                let candidate_ranges = candidate_ranges_buf.clone();
                                let assigned_shards = {
                                    let assigned =
                                        shard_count_for_pack(&shard_counts, plan.pack_id);
                                    if assigned == 1 {
                                        select_plan_shard_count(pack_exec_workers, plan)
                                    } else {
                                        assigned
                                    }
                                };
                                let sr = shard_ranges(exec_indices.len(), assigned_shards);
                                Some(PlanWork {
                                    plan,
                                    pack_bytes,
                                    exec_indices,
                                    candidate_ranges,
                                    shard_ranges: sr,
                                })
                            })
                            .collect();

                        // Clamp actual worker count to the max shards any
                        // single plan needs — no point spawning idle threads.
                        let max_shards = plan_work
                            .iter()
                            .map(|pw| pw.shard_ranges.len())
                            .max()
                            .unwrap_or(0);
                        let actual_workers = pack_exec_workers.min(max_shards);

                        if actual_workers > 0 {
                            start_pack_exec();

                            struct ShardOutput {
                                plan_idx: usize,
                                report: PackExecReport,
                                scanned: ScannedBlobs,
                                skipped: Vec<SkippedCandidate>,
                            }

                            // ── Single scope: spawn workers once ─────────
                            let plan_work = &plan_work;
                            let shard_outputs = std::thread::scope(
                                |scope| -> Result<Vec<Vec<ShardOutput>>, PackExecError> {
                                    let cache_slice = &mut shard_caches[..actual_workers];
                                    let scratch_slice = &mut shard_scratches[..actual_workers];
                                    let adapter_slice = &mut shard_adapters[..actual_workers];
                                    let external_slice = &mut shard_externals[..actual_workers];

                                    let handles: Vec<_> = cache_slice
                                        .iter_mut()
                                        .zip(scratch_slice.iter_mut())
                                        .zip(adapter_slice.iter_mut())
                                        .zip(external_slice.iter_mut())
                                        .enumerate()
                                        .map(
                                            |(
                                                worker_idx,
                                                (((cache, scratch), adapter), external),
                                            )| {
                                                let paths = &path_arena;
                                                let spill_dir = &spill_dir;
                                                let pack_decode = config.pack_decode;

                                                scope.spawn(move || {
                                                    let mut outputs = Vec::new();
                                                    for (plan_idx, pw) in
                                                        plan_work.iter().enumerate()
                                                    {
                                                        if worker_idx >= pw.shard_ranges.len() {
                                                            continue;
                                                        }
                                                        let (start, end) =
                                                            pw.shard_ranges[worker_idx];
                                                        let exec_slice =
                                                            &pw.exec_indices[start..end];

                                                        let shard_candidates: usize = exec_slice
                                                            .iter()
                                                            .filter_map(|idx| {
                                                                pw.candidate_ranges[*idx]
                                                                    .map(|(s, e)| e - s)
                                                            })
                                                            .sum();
                                                        adapter.clear_results();
                                                        adapter.reserve_results(shard_candidates);

                                                        cache.ensure_capacity(pack_cache_bytes);

                                                        let report =
                                                            execute_pack_plan_with_scratch_indices(
                                                                pw.plan,
                                                                pw.pack_bytes,
                                                                paths,
                                                                &pack_decode,
                                                                cache,
                                                                external,
                                                                adapter,
                                                                spill_dir,
                                                                scratch,
                                                                exec_slice,
                                                                &pw.candidate_ranges,
                                                            )?;

                                                        let mut skipped = Vec::new();
                                                        collect_skipped_candidates(
                                                            pw.plan,
                                                            &report.skips,
                                                            &mut skipped,
                                                        );

                                                        outputs.push(ShardOutput {
                                                            plan_idx,
                                                            report,
                                                            scanned: adapter.take_results(),
                                                            skipped,
                                                        });
                                                    }
                                                    Ok(outputs)
                                                })
                                            },
                                        )
                                        .collect();

                                    handles
                                        .into_iter()
                                        .map(|h| h.join().expect("pack exec worker panicked"))
                                        .collect()
                                },
                            )?;

                            // ── Merge in plan-order then shard-order ─────
                            // Workers are iterated in worker_idx order and
                            // worker_idx == shard_idx for any given plan, so
                            // pushing preserves deterministic shard order.
                            let num_plans = plan_work.len();
                            let mut per_plan_reports: Vec<Vec<PackExecReport>> =
                                (0..num_plans).map(|_| Vec::new()).collect();
                            let mut per_plan_shards: Vec<Vec<ScannedBlobs>> =
                                (0..num_plans).map(|_| Vec::new()).collect();

                            for worker_outputs in shard_outputs {
                                for output in worker_outputs {
                                    skipped_candidates.extend(output.skipped);
                                    per_plan_reports[output.plan_idx].push(output.report);
                                    per_plan_shards[output.plan_idx].push(output.scanned);
                                }
                            }

                            for plan_idx in 0..num_plans {
                                let reports = std::mem::take(&mut per_plan_reports[plan_idx]);
                                let shards = std::mem::take(&mut per_plan_shards[plan_idx]);
                                pack_exec_reports.push(merge_pack_exec_reports(reports));
                                append_scanned_blobs(&mut scanned, merge_scanned_blobs(shards));
                            }
                        }
                    }
                }

                // ── Loose scan: reuse pooled PackIo ──────────────────
                if !loose.is_empty() {
                    start_pack_exec();
                    let loose_adapter = &mut shard_adapters[0];
                    loose_adapter.clear_results();
                    loose_adapter.reserve_results(loose.len());
                    let external = &mut shard_externals[0];
                    let loose_start = Instant::now();
                    scan_loose_candidates(
                        &loose,
                        &path_arena,
                        loose_adapter,
                        external,
                        &mut skipped_candidates,
                    )?;
                    stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
                    append_scanned_blobs(&mut scanned, loose_adapter.take_results());
                }
            }

            Ok(())
        })?;
    // ── Stage 4: loose-only fallback ────────────────────────────────
    // No packed candidates at all; scan only loose objects.
    } else if !loose.is_empty() {
        start_pack_exec();
        let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
        adapter.reserve_results(loose.len());
        let mut external =
            PackIo::from_parts(midx, pack_paths.clone(), loose_dirs.clone(), config.pack_io)
                .map_err(GitScanError::PackIo)?;
        let loose_start = Instant::now();
        scan_loose_candidates(
            &loose,
            &path_arena,
            &mut adapter,
            &mut external,
            &mut skipped_candidates,
        )?;
        stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
        append_scanned_blobs(&mut scanned, adapter.take_results());
    }

    // ── Metrics assembly ────────────────────────────────────────────
    // pack_plan time = serial prelude (MIDX verify, mmap, etc.) + the
    // wall-clock time the background planner thread spent building plans.
    stage_nanos.pack_plan =
        pack_plan_prelude_nanos.saturating_add(pack_plan_thread_nanos.load(Ordering::Relaxed));

    if pack_exec_started {
        stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
        let pack_exec_alloc_after = alloc_stats();
        alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);
    }

    Ok(ScanModeOutput {
        scanned,
        path_arena,
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
