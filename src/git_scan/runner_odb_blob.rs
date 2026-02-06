//! ODB-blob fast-path scan pipeline.
//!
//! Computes first-introduced blobs from the commit graph and scans them in
//! pack order. If candidate caps or path arena limits are exceeded during
//! blob introduction, retries via the spill/dedupe pipeline.
//!
//! # Streaming Plan Generation
//! Pack plans are generated on a background thread and streamed to the
//! execution loop via a bounded channel, overlapping planning with
//! pack decode + scan.

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
use super::mapping_bridge::{MappingBridge, MappingStats};
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
    collect_pack_dirs, collect_skipped_candidates, estimate_pack_cache_bytes,
    estimate_path_arena_capacity, list_pack_files, load_midx, make_spill_dir, merge_scanned_blobs,
    mmap_pack_files, resolve_pack_paths, scan_loose_candidates, shard_ranges, SpillCandidateSink,
};

use super::repo_open::RepoJobState;

/// Runs the ODB-blob fast-path scan pipeline.
///
/// Computes first-introduced blobs from the commit graph and scans them in
/// pack order. If candidate caps or path arena limits are exceeded during
/// blob introduction, retries via the spill/dedupe pipeline.
///
/// Returns a `ScanModeOutput` containing scanned blobs, path arena, skip
/// records, pack execution reports, and stage timing data. The caller
/// (dispatcher) is responsible for finalize, persist, and perf snapshot.
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
/// Returns `GitScanError::ConcurrentMaintenance` if artifacts change during
/// planning (pre-execution check).
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

    // Pack planning + execution.
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
    let pack_cache_target =
        estimate_pack_cache_bytes(config.pack_cache_bytes, &pack_mmaps, &used_pack_ids);
    let pack_cache_bytes: u32 = pack_cache_target
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut pack_exec_reports = Vec::with_capacity(used_pack_ids.len());
    let mut skipped_candidates = Vec::new();

    let mut scanned = ScannedBlobs {
        blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
        finding_arena: Vec::new(),
    };

    let mut pack_exec_started = false;
    let mut pack_exec_start = Instant::now();
    let mut pack_exec_alloc_before = AllocStats::default();
    let mut start_pack_exec = || {
        if !pack_exec_started {
            // Start timing/alloc counters only if we actually execute work.
            pack_exec_started = true;
            pack_exec_start = Instant::now();
            pack_exec_alloc_before = alloc_stats();
        }
    };

    if packed_len > 0 {
        // Scale plan caps for large candidate sets in ODB-blob mode.
        let scaled = packed_len.saturating_mul(2);
        pack_plan_cfg.max_worklist_entries = pack_plan_cfg.max_worklist_entries.max(scaled);
        pack_plan_cfg.max_base_lookups = pack_plan_cfg.max_base_lookups.max(scaled);

        let (mut buckets, pack_ids) = bucket_pack_candidates(packed.drain(..), pack_views.len())?;
        let pack_plan_count = pack_ids.len();
        // Prefer one worker per pack when enough packs are available to
        // preserve sequential access and avoid intra-pack sharding.
        let prefer_pack_parallelism = pack_exec_workers > 1 && pack_plan_count >= pack_exec_workers;
        // Stream per-pack plans to overlap planning with execution while
        // keeping deterministic pack order.
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

            if pack_exec_workers == 1 {
                let mut cache = PackCache::new(pack_cache_bytes);
                let mut external = PackIo::from_parts(
                    *midx,
                    pack_paths.clone(),
                    loose_dirs.clone(),
                    config.pack_io,
                )
                .map_err(GitScanError::PackIo)?;
                let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                adapter.reserve_results(packed_len.saturating_add(loose_len));
                let mut exec_scratch = PackExecScratch::default();
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
            } else if prefer_pack_parallelism {
                let (work_tx, work_rx) = mpsc::sync_channel::<(usize, PackPlan)>(pack_exec_workers);
                let work_rx = Arc::new(Mutex::new(work_rx));
                let (result_tx, result_rx) = mpsc::channel::<
                    Result<
                        (usize, PackExecReport, ScannedBlobs, Vec<SkippedCandidate>),
                        PackExecError,
                    >,
                >();
                let mut handles = Vec::with_capacity(pack_exec_workers);

                for _ in 0..pack_exec_workers {
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
                        let mut cache = PackCache::new(pack_cache_bytes);
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
                        let mut scratch = PackExecScratch::default();

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

                                adapter.reserve_results(plan.stats.candidate_count as usize);
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

                drop(result_tx);

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
            } else {
                // Not enough packs to keep workers busy: shard within a
                // single pack while preserving deterministic shard order.
                for plan in rx {
                    let plan = plan?;
                    pack_plan_stats.push(plan.stats);
                    let deps_len = plan.delta_deps.len() as u32;
                    pack_plan_delta_deps_total =
                        pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                    pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);

                    start_pack_exec();

                    let plan_ref = &plan;
                    let pack_id = plan_ref.pack_id as usize;
                    let pack_bytes = pack_mmaps
                        .get(pack_id)
                        .and_then(|mmap| mmap.as_ref())
                        .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                            pack_id: plan_ref.pack_id,
                            pack_count: pack_mmaps.len(),
                        }))?
                        .as_ref();

                    let exec_indices = build_exec_indices(plan_ref);
                    if exec_indices.is_empty() {
                        continue;
                    }

                    let mut candidate_ranges = Vec::new();
                    build_candidate_ranges(plan_ref, &mut candidate_ranges);

                    let ranges = shard_ranges(exec_indices.len(), pack_exec_workers);
                    let shard_outputs =
                        std::thread::scope(
                            |scope| -> Result<
                                Vec<(usize, PackExecReport, ScannedBlobs)>,
                                PackExecError,
                            > {
                                let mut handles = Vec::with_capacity(ranges.len());
                                for (shard_idx, (start, end)) in ranges.iter().enumerate() {
                                    let exec_slice = &exec_indices[*start..*end];
                                    let candidate_ranges = &candidate_ranges;
                                    let pack_paths = pack_paths.clone();
                                    let loose_dirs = loose_dirs.clone();
                                    let pack_decode = config.pack_decode;
                                    let pack_io_limits = config.pack_io;
                                    let adapter_cfg = config.engine_adapter;
                                    let paths = &path_arena;
                                    let spill_dir = &spill_dir;

                                    handles.push(scope.spawn(move || {
                                        let mut cache = PackCache::new(pack_cache_bytes);
                                        let mut external = PackIo::from_parts(
                                            *midx,
                                            pack_paths,
                                            loose_dirs,
                                            pack_io_limits,
                                        )
                                        .map_err(|err| {
                                            PackExecError::ExternalBase(err.to_string())
                                        })?;
                                        let mut adapter = EngineAdapter::new(engine, adapter_cfg);
                                        let shard_candidates: usize = exec_slice
                                            .iter()
                                            .filter_map(|idx| {
                                                candidate_ranges[*idx].map(|(s, e)| e - s)
                                            })
                                            .sum();
                                        adapter.reserve_results(shard_candidates);
                                        let mut scratch = PackExecScratch::default();
                                        let report = execute_pack_plan_with_scratch_indices(
                                            plan_ref,
                                            pack_bytes,
                                            paths,
                                            &pack_decode,
                                            &mut cache,
                                            &mut external,
                                            &mut adapter,
                                            spill_dir,
                                            &mut scratch,
                                            exec_slice,
                                            candidate_ranges,
                                        )?;
                                        Ok::<_, PackExecError>((
                                            shard_idx,
                                            report,
                                            adapter.take_results(),
                                        ))
                                    }));
                                }

                                let mut outputs = Vec::with_capacity(handles.len());
                                for handle in handles {
                                    let joined =
                                        handle.join().expect("pack exec worker panicked")?;
                                    outputs.push(joined);
                                }
                                Ok(outputs)
                            },
                        )?;

                    let mut outputs: Vec<Option<(PackExecReport, ScannedBlobs)>> =
                        (0..ranges.len()).map(|_| None).collect();
                    for (shard_idx, report, scanned_shard) in shard_outputs {
                        outputs[shard_idx] = Some((report, scanned_shard));
                    }

                    let mut reports = Vec::with_capacity(outputs.len());
                    let mut scanned_shards = Vec::with_capacity(outputs.len());
                    for output in outputs.into_iter() {
                        let (report, scanned_shard) =
                            output.expect("missing pack exec shard output");
                        reports.push(report);
                        scanned_shards.push(scanned_shard);
                    }

                    let merged_report = merge_pack_exec_reports(reports);
                    collect_skipped_candidates(
                        plan_ref,
                        &merged_report.skips,
                        &mut skipped_candidates,
                    );
                    pack_exec_reports.push(merged_report);

                    let merged_scanned = merge_scanned_blobs(scanned_shards);
                    append_scanned_blobs(&mut scanned, merged_scanned);
                }

                if !loose.is_empty() {
                    start_pack_exec();
                    let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                    adapter.reserve_results(loose.len());
                    let mut external = PackIo::from_parts(
                        *midx,
                        pack_paths.clone(),
                        loose_dirs.clone(),
                        config.pack_io,
                    )
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
            }

            Ok(())
        })?;
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
    })
}
