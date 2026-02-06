//! Diff-history scan pipeline.
//!
//! Walks commits in topological order, diffs trees to discover changed blobs,
//! spills and deduplicates candidates, then batch-plans and executes pack
//! decode + scan.
//!
//! # Pipeline stages
//!
//! ```text
//! PlannedCommits ──► TreeDiff ──► Spill/Dedupe ──► MappingBridge ──► PackPlan ──► PackExec
//!   (topo order)    (blob OIDs)   (seen filter)    (OID→pack loc)   (per-pack)   (decode+scan)
//! ```
//!
//! 1. **Tree diff** – walks each planned commit, diffs its tree against parent
//!    trees (or the empty tree for snapshot roots) to discover changed blob
//!    OIDs. Candidates stream directly into the spiller to bound memory.
//! 2. **Spill / dedupe** – the spiller externalizes candidates to disk when the
//!    in-memory budget is exceeded, then replays them through the seen-blob
//!    store to drop already-scanned OIDs.
//! 3. **Mapping bridge** – maps surviving OIDs to pack locations via the MIDX,
//!    partitioning into packed and loose candidate sets. Produces a `ByteArena`
//!    of file paths that pack-exec and loose-scan reference by `ByteRef`.
//! 4. **Pack planning** – groups packed candidates by pack file and builds a
//!    topologically-sorted decode plan that respects delta chains.
//! 5. **Pack execution** – decodes pack entries, resolves deltas, and feeds
//!    reconstructed blobs to the detection engine for scanning.
//!
//! # Batch planning
//!
//! Unlike the ODB-blob path, all pack plans are built before execution begins.
//! This enables a pre-execution artifact staleness check: if `git gc` or
//! `git repack` ran between planning and execution, the function bails with
//! `ConcurrentMaintenance` rather than reading corrupt pack offsets.
//!
//! # Execution strategies
//!
//! The `PackExecStrategy` enum selects one of three modes based on worker
//! count and plan structure:
//!
//! | Strategy | Condition | Parallelism |
//! |---|---|---|
//! | `Serial` | 1 worker, 0 plans, or tiny total decode work | Single-threaded, minimal overhead |
//! | `PackParallel` | enough plans to saturate workers | One plan per worker, work-stealing via shared channel |
//! | `IntraPackSharded` | fewer plans than workers, non-trivial decode work | Shard each plan with adaptive shard counts |
//!
//! All three strategies produce **deterministic output order** by reassembling
//! results in planned sequence, regardless of worker completion order.

use std::io;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use crate::scheduler::{alloc_stats, AllocStats};
use crate::Engine;

use super::commit_walk::{CommitGraph, ParentScratch, PlannedCommit};
use super::engine_adapter::{EngineAdapter, ScannedBlobs};
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig};
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
    merge_scanned_blobs, mmap_pack_files, per_worker_cache_bytes, resolve_pack_paths,
    scan_loose_candidates, select_pack_exec_strategy, shard_count_for_pack, shard_ranges,
    summarize_pack_plan_deps, PackExecStrategy, SpillCandidateSink,
};

/// Runs the diff-history scan pipeline.
///
/// Walks planned commits, diffs trees to discover changed blobs, streams
/// candidates through the spill/dedupe pipeline, then batch-plans and
/// executes pack decode + scan. See the [module docs](self) for the full
/// pipeline diagram and execution strategy selection.
///
/// The caller (dispatcher) is responsible for finalize, persist, and perf
/// snapshot on the returned output.
///
/// # Determinism
///
/// Output order is deterministic for identical inputs regardless of worker
/// count. Parallel strategies reassemble results by planned sequence index,
/// and loose candidates are always appended after all packed results.
///
/// # Lifetime of the returned path arena
///
/// The `path_arena` in the returned [`ScanModeOutput`] owns all file-path
/// bytes referenced by `ByteRef` handles in the scanned blobs and skipped
/// candidates. It must outlive any downstream consumer that dereferences
/// those handles.
///
/// # Errors
///
/// - MIDX load, completeness, or OID resolution failures.
/// - Pack plan errors (out-of-range pack IDs, corrupt headers).
/// - Pack exec errors (decode failures, delta resolution, I/O).
/// - `GitScanError::ConcurrentMaintenance` if repository artifacts (pack
///   files, indices) changed between pack planning and pack execution,
///   indicating a concurrent `git gc` or `git repack`.
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
    // Reused across commits to avoid per-commit allocation for parent position lists.
    let mut parent_scratch = ParentScratch::new();

    // ── Stage 1: Tree diff ──────────────────────────────────────────────
    // Walk each planned commit and diff its tree against parent trees to
    // discover changed blob OIDs. The SpillCandidateSink streams candidates
    // directly into the spiller, bounding memory even for repositories with
    // millions of changed blobs.
    {
        let diff_start = Instant::now();
        let mut sink = SpillCandidateSink::new(&mut spiller);
        for PlannedCommit { pos, snapshot_root } in plan {
            let commit_id = pos.0;
            let new_tree = cg.root_tree_oid(*pos)?;

            // Snapshot roots are diffed against the empty tree (old_tree=None),
            // treating every blob in the tree as a new addition. This is used
            // for orphan commits and forced snapshot points in the commit plan.
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

            // Parentless commits (e.g. grafted roots) use the same empty-tree
            // diff as snapshot roots—every blob is considered introduced.
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

    // ── Stages 2–3: Spill/dedupe → mapping bridge ──────────────────────
    // Finalize the spiller: flush any on-disk runs, merge-sort, and replay
    // unique (unseen) OIDs through the mapping bridge. The bridge resolves
    // each OID to a pack location via the MIDX, splitting candidates into
    // packed (with pack_id + offset) and loose (fan-out directory lookup).
    // The returned path arena owns all file-path bytes for the rest of the
    // pipeline.
    let spill_start = Instant::now();
    let midx = load_midx(repo)?;
    let mut mapping_cfg = config.mapping;
    let default_mapping_cfg = MappingBridgeConfig::default();
    if mapping_cfg.max_packed_candidates >= default_mapping_cfg.max_packed_candidates {
        // Keep explicit low caps as hard limits; only scale default-or-higher
        // caps to handle very large repositories.
        mapping_cfg.max_packed_candidates =
            mapping_cfg.max_packed_candidates.max(midx.object_count());
    }
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

    // ── Stage 4: Pack planning ───────────────────────────────────────────
    let pack_plan_start = Instant::now();
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    // Only mmap packs that contain at least one candidate. This avoids
    // wasting address space on multi-pack repos where most packs are idle.
    let mut used_pack_ids: Vec<u16> = sink.packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    let packed_len = sink.packed.len();
    let loose_len = sink.loose.len();
    if !sink.packed.is_empty() {
        // Move candidates out of the sink to avoid cloning the potentially
        // large candidate vec; the sink's packed field is left empty.
        let packed = std::mem::take(&mut sink.packed);
        let mut pack_plans = build_pack_plans(packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }
    let (pack_plan_delta_deps_total, pack_plan_delta_deps_max) = summarize_pack_plan_deps(&plans);
    stage_nanos.pack_plan = pack_plan_start.elapsed().as_nanos() as u64;

    // Gate between planning and execution: if pack files or indices were
    // rewritten by a concurrent `git gc` / `git repack`, the offsets in our
    // plans are stale. Bail early rather than reading garbage.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // ── Stage 5: Pack execution + scan ───────────────────────────────────
    let pack_cache_target = per_worker_cache_bytes(
        config.pack_cache_bytes,
        &pack_mmaps,
        &used_pack_ids,
        config.pack_exec_workers,
    );
    let pack_cache_bytes: u32 = pack_cache_target
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let pack_exec_workers = config.pack_exec_workers.max(1);
    let pack_exec_strategy = select_pack_exec_strategy(pack_exec_workers, &plans);
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
    // All three branches below produce identical output for identical inputs.
    // Parallel branches reassemble results in plan-sequence order to preserve
    // determinism. Loose candidates are always scanned after packed plans,
    // outside the parallel scope, because loose reads go through the object
    // fan-out directory and are not contention-free across threads.
    // Pre-allocate cache and scratch pools before strategy dispatch so no
    // allocation happens inside worker closures (Tiger Style).
    let mut prealloc_caches: Vec<PackCache> = (0..pack_exec_workers)
        .map(|_| PackCache::new(pack_cache_bytes))
        .collect();
    let mut prealloc_scratches: Vec<PackExecScratch> = (0..pack_exec_workers)
        .map(|_| PackExecScratch::default())
        .collect();

    match pack_exec_strategy {
        PackExecStrategy::Serial => {
            let mut cache = prealloc_caches.swap_remove(0);
            let mut external = PackIo::open(repo, config.pack_io)?;
            let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
            adapter.reserve_results(packed_len.saturating_add(loose_len));
            let mut exec_scratch = prealloc_scratches.swap_remove(0);
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
            // Work-stealing: a bounded sync_channel acts as a shared queue.
            // Workers pull the next plan when idle, naturally balancing load
            // when pack sizes vary. The channel bound (= worker count) caps
            // the number of in-flight plans to avoid over-committing memory.
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

                for (mut cache, mut scratch) in
                    prealloc_caches.drain(..).zip(prealloc_scratches.drain(..))
                {
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

                // Drop the producer's clone of result_tx so the result channel
                // closes once all workers finish, allowing the recv loop below
                // to terminate.
                drop(result_tx);

                // Eagerly validate pack IDs before sending to workers so the
                // producer thread surfaces the error, not a worker.
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

                // Reassemble worker outputs by planned sequence index to
                // guarantee deterministic result order.
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
        PackExecStrategy::IntraPackSharded { shard_counts } => {
            // When there are fewer plans than workers, we shard each plan's
            // offset indices across workers so all cores stay busy. Each
            // shard decodes a disjoint slice of the plan's need_offsets and
            // the per-shard reports are merged back into a single report.
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

                let shard_count = shard_count_for_pack(&shard_counts, plan_ref.pack_id);
                let ranges = shard_ranges(exec_indices.len(), shard_count);

                // Reset pre-allocated shard caches for this plan.
                for sc in prealloc_caches.iter_mut().take(ranges.len()) {
                    sc.ensure_capacity(pack_cache_bytes);
                }

                let shard_outputs = std::thread::scope(
                    |scope| -> Result<Vec<(usize, PackExecReport, ScannedBlobs)>, PackExecError> {
                        let mut handles = Vec::with_capacity(ranges.len());
                        let cache_slice = &mut prealloc_caches[..ranges.len()];
                        let scratch_slice = &mut prealloc_scratches[..ranges.len()];
                        for ((shard_idx, (start, end)), (cache, scratch)) in ranges
                            .iter()
                            .enumerate()
                            .zip(cache_slice.iter_mut().zip(scratch_slice.iter_mut()))
                        {
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
                                let report = execute_pack_plan_with_scratch_indices(
                                    plan_ref,
                                    pack_bytes,
                                    paths,
                                    &pack_decode,
                                    cache,
                                    &mut external,
                                    &mut adapter,
                                    spill_dir,
                                    scratch,
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
        pack_cache_per_worker_bytes: pack_cache_target,
    })
}
