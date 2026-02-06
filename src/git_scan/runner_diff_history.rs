//! Diff-history scan pipeline.
//!
//! Walks commits in topological order, diffs trees to discover changed blobs,
//! spills and deduplicates candidates, then batch-plans and executes pack
//! decode + scan.
//!
//! # Batch Planning
//! Unlike the ODB-blob path, all pack plans are built before execution begins.
//! The `PackExecStrategy` enum selects serial, pack-parallel, or intra-pack
//! sharded execution based on worker count and plan volume.

use std::io;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use crate::scheduler::{alloc_stats, AllocStats};
use crate::Engine;

use super::commit_walk::{CommitGraph, ParentScratch, PlannedCommit};
use super::engine_adapter::{EngineAdapter, ScannedBlobs};
use super::mapping_bridge::MappingBridge;
use super::object_store::ObjectStore;
use super::pack_cache::PackCache;
use super::pack_candidates::CappedPackCandidateSink;
use super::pack_exec::{
    build_candidate_ranges, execute_pack_plan_with_scratch, execute_pack_plan_with_scratch_indices,
    merge_pack_exec_reports, PackExecError, PackExecReport, PackExecScratch,
};
use super::pack_io::PackIo;
use super::pack_plan::{build_pack_plans, PackPlanError};
use super::pack_plan_model::PackPlan;
use super::policy_hash::MergeDiffMode;
use super::repo_open::RepoJobState;
use super::runner::{
    GitScanAllocStats, GitScanConfig, GitScanError, GitScanStageNanos, ScanModeOutput,
    SkippedCandidate,
};
use super::seen_store::SeenBlobStore;
use super::spiller::Spiller;
use super::tree_diff::TreeDiffWalker;

use super::runner_exec::{
    append_scanned_blobs, build_exec_indices, build_pack_views, collect_loose_dirs,
    collect_pack_dirs, collect_skipped_candidates, list_pack_files, load_midx, make_spill_dir,
    merge_scanned_blobs, mmap_pack_files, resolve_pack_paths, scan_loose_candidates,
    select_pack_exec_strategy, shard_ranges, summarize_pack_plan_deps, PackExecStrategy,
    SpillCandidateSink,
};

/// Runs the diff-history scan pipeline.
///
/// Walks planned commits, diffs trees to discover changed blobs, streams
/// candidates through the spill/dedupe pipeline, then batch-plans and
/// executes pack decode + scan.
///
/// Returns a `ScanModeOutput` containing scanned blobs, path arena, skip
/// records, pack execution reports, and stage timing data. The caller
/// (dispatcher) is responsible for finalize, persist, and perf snapshot.
///
/// # Parameters
/// - `repo`: opened repository job state (paths, object format, artifacts).
/// - `engine`: detection engine instance for scanning blob contents.
/// - `seen_store`: seen-blob store for deduplication during spill/dedupe.
/// - `cg`: commit graph for tree root lookups and parent traversal.
/// - `plan`: commit plan (planned commits from `introduced_by_plan`).
/// - `config`: scan configuration (limits, worker counts, etc.).
///
/// # Errors
/// Returns `GitScanError` on MIDX, pack plan, pack exec, or I/O failures.
/// Returns `GitScanError::ConcurrentMaintenance` if artifacts change between
/// planning and execution (pre-execution check).
pub(super) fn run_diff_history(
    repo: &RepoJobState,
    engine: &Engine,
    seen_store: &dyn SeenBlobStore,
    cg: &dyn CommitGraph,
    plan: &[PlannedCommit],
    config: &GitScanConfig,
) -> Result<ScanModeOutput, GitScanError> {
    let mut stage_nanos = GitScanStageNanos::default();
    let mut alloc_deltas = GitScanAllocStats::default();

    // Spill + dedupe (stream candidates during tree diff).
    // Shared spill directory for tree payloads and pack-exec large blobs.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
    let mut object_store = ObjectStore::open(repo, &config.tree_diff, &spill_dir)?;
    let mut walker = TreeDiffWalker::new(&config.tree_diff, repo.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    {
        let diff_start = Instant::now();
        let mut sink = SpillCandidateSink::new(&mut spiller);
        for PlannedCommit { pos, snapshot_root } in plan {
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
        stage_nanos.tree_diff = diff_start.elapsed().as_nanos() as u64;
    }

    let spill_start = Instant::now();
    let midx = load_midx(repo)?;
    let mut bridge = MappingBridge::new(
        &midx,
        CappedPackCandidateSink::new(
            config.mapping.max_packed_candidates,
            config.mapping.max_loose_candidates,
        ),
        config.mapping,
    );
    let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
    stage_nanos.spill = spill_start.elapsed().as_nanos() as u64;
    let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;

    // Pack planning.
    let pack_plan_start = Instant::now();
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    let mut used_pack_ids: Vec<u16> = sink.packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    // Enforce pack mmap limits before decoding to cap address space usage.
    let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    let packed_len = sink.packed.len();
    let loose_len = sink.loose.len();
    if !sink.packed.is_empty() {
        let packed = std::mem::take(&mut sink.packed);
        let mut pack_plans = build_pack_plans(packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }
    let (pack_plan_delta_deps_total, pack_plan_delta_deps_max) = summarize_pack_plan_deps(&plans);
    stage_nanos.pack_plan = pack_plan_start.elapsed().as_nanos() as u64;

    // Validate artifacts before decoding packs to avoid scanning during maintenance.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // Execute pack plans + scan.
    let pack_cache_bytes: u32 = config
        .pack_cache_bytes
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let pack_exec_workers = config.pack_exec_workers.max(1);
    let pack_exec_strategy = select_pack_exec_strategy(pack_exec_workers, plans.len());
    let plan_count = plans.len();
    let loose_dirs = collect_loose_dirs(&repo.paths);
    let mut pack_exec_reports = Vec::with_capacity(plan_count);
    let mut skipped_candidates = Vec::new();
    let mut scanned = ScannedBlobs {
        blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
        finding_arena: Vec::new(),
    };

    let pack_exec_start = Instant::now();
    let pack_exec_alloc_before: AllocStats = alloc_stats();
    // Keep result assembly deterministic across all execution strategies so
    // finalize output is stable regardless of worker count.
    match pack_exec_strategy {
        PackExecStrategy::Serial => {
            let mut cache = PackCache::new(pack_cache_bytes);
            let mut external = PackIo::open(repo, config.pack_io)?;
            let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
            adapter.reserve_results(packed_len.saturating_add(loose_len));
            let mut exec_scratch = PackExecScratch::default();
            for plan in &plans {
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
                    &mapping_arena,
                    &config.pack_decode,
                    &mut cache,
                    &mut external,
                    &mut adapter,
                    &spill_dir,
                    &mut exec_scratch,
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

            scanned = adapter.take_results();
        }
        PackExecStrategy::PackParallel => {
            std::thread::scope(|scope| -> Result<(), GitScanError> {
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
                    let paths = &mapping_arena;
                    let spill_dir = &spill_dir;
                    let pack_mmaps = &pack_mmaps;

                    handles.push(scope.spawn(move || {
                        let mut cache = PackCache::new(pack_cache_bytes);
                        let mut external = match PackIo::from_parts(
                            midx,
                            pack_paths,
                            loose_dirs,
                            pack_io_limits,
                        ) {
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

                for (seq, plan) in plans.into_iter().enumerate() {
                    let pack_id = plan.pack_id as usize;
                    pack_mmaps
                        .get(pack_id)
                        .and_then(|mmap| mmap.as_ref())
                        .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                            pack_id: plan.pack_id,
                            pack_count: pack_mmaps.len(),
                        }))?;

                    if work_tx.send((seq, plan)).is_err() {
                        return Err(GitScanError::PackExec(PackExecError::PackRead(
                            "pack exec work queue closed".to_string(),
                        )));
                    }
                }
                drop(work_tx);

                // Reassemble worker outputs by planned sequence.
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

                Ok(())
            })?;

            if !sink.loose.is_empty() {
                let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                adapter.reserve_results(sink.loose.len());
                let mut external = PackIo::from_parts(
                    midx,
                    pack_paths.clone(),
                    loose_dirs.clone(),
                    config.pack_io,
                )
                .map_err(GitScanError::PackIo)?;
                scan_loose_candidates(
                    &sink.loose,
                    &mapping_arena,
                    &mut adapter,
                    &mut external,
                    &mut skipped_candidates,
                )?;
                append_scanned_blobs(&mut scanned, adapter.take_results());
            }
        }
        PackExecStrategy::IntraPackSharded => {
            for plan in &plans {
                let plan_ref = plan;
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
                let shard_outputs = std::thread::scope(
                    |scope| -> Result<Vec<(usize, PackExecReport, ScannedBlobs)>, PackExecError> {
                        let mut handles = Vec::with_capacity(ranges.len());
                        for (shard_idx, (start, end)) in ranges.iter().enumerate() {
                            let exec_slice = &exec_indices[*start..*end];
                            let candidate_ranges = &candidate_ranges;
                            let pack_paths = pack_paths.clone();
                            let loose_dirs = loose_dirs.clone();
                            let pack_decode = config.pack_decode;
                            let pack_io_limits = config.pack_io;
                            let adapter_cfg = config.engine_adapter;
                            let paths = &mapping_arena;
                            let spill_dir = &spill_dir;

                            handles.push(scope.spawn(move || {
                                let mut cache = PackCache::new(pack_cache_bytes);
                                let mut external = PackIo::from_parts(
                                    midx,
                                    pack_paths,
                                    loose_dirs,
                                    pack_io_limits,
                                )
                                .map_err(|err| PackExecError::ExternalBase(err.to_string()))?;
                                let mut adapter = EngineAdapter::new(engine, adapter_cfg);
                                let shard_candidates: usize = exec_slice
                                    .iter()
                                    .filter_map(|idx| candidate_ranges[*idx].map(|(s, e)| e - s))
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
                                Ok::<_, PackExecError>((shard_idx, report, adapter.take_results()))
                            }));
                        }

                        let mut outputs = Vec::with_capacity(handles.len());
                        for handle in handles {
                            let joined = handle.join().expect("pack exec worker panicked")?;
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
                    let (report, scanned_shard) = output.expect("missing pack exec shard output");
                    reports.push(report);
                    scanned_shards.push(scanned_shard);
                }

                let merged_report = merge_pack_exec_reports(reports);
                collect_skipped_candidates(plan_ref, &merged_report.skips, &mut skipped_candidates);
                pack_exec_reports.push(merged_report);

                let merged_scanned = merge_scanned_blobs(scanned_shards);
                append_scanned_blobs(&mut scanned, merged_scanned);
            }

            if !sink.loose.is_empty() {
                let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                adapter.reserve_results(sink.loose.len());
                let mut external = PackIo::from_parts(
                    midx,
                    pack_paths.clone(),
                    loose_dirs.clone(),
                    config.pack_io,
                )
                .map_err(GitScanError::PackIo)?;
                scan_loose_candidates(
                    &sink.loose,
                    &mapping_arena,
                    &mut adapter,
                    &mut external,
                    &mut skipped_candidates,
                )?;
                append_scanned_blobs(&mut scanned, adapter.take_results());
            }
        }
    }
    stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
    let pack_exec_alloc_after = alloc_stats();
    alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);

    Ok(ScanModeOutput {
        scanned,
        path_arena: mapping_arena,
        skipped_candidates,
        pack_exec_reports,
        pack_plan_stats,
        pack_plan_config: config.pack_plan,
        pack_plan_delta_deps_total,
        pack_plan_delta_deps_max,
        tree_diff_stats: walker.stats().clone(),
        spill_stats,
        mapping_stats,
        stage_nanos,
        alloc_stats: alloc_deltas,
    })
}
