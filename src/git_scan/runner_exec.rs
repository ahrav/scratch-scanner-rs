//! Shared pack execution helpers for the Git scan runner.
//!
//! Contains standalone building-block functions used by both scan mode
//! pipelines ([`runner_odb_blob`](super::runner_odb_blob) and
//! [`runner_diff_history`](super::runner_diff_history)). Each mode file
//! owns its execution loop; this module provides the pieces they call:
//!
//! - **Directory discovery** — pack dirs, loose dirs, pack file listing.
//! - **Mmap management** — map pack files, apply sequential access hints.
//! - **Pack view parsing** — validate headers, build `PackView`s for planning.
//! - **Pack cache sizing** — layered heuristic (`estimate_pack_cache_bytes` →
//!   [`per_worker_cache_bytes`]) that balances hit-rate against aggregate memory.
//! - **Loose scanning** — decode loose objects and feed them to the engine.
//! - **Threading utilities** — stats-free strategy selection, index sharding, result merging.
//! - **Spill adapter** — [`SpillCandidateSink`] bridges [`CandidateSink`] to [`Spiller`].
//!
//! # Design note
//!
//! Functions here are intentionally stateless: they accept explicit inputs and
//! return values rather than mutating shared runner state. This keeps the
//! mode-specific pipelines testable in isolation and makes threading boundaries
//! explicit (e.g. `merge_scanned_blobs` expects shards produced by independent
//! workers).

use std::fs;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use super::byte_arena::ByteArena;
use super::engine_adapter::{EngineAdapter, ScannedBlobs};
use super::errors::TreeDiffError;
use super::finalize::RefEntry;
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::ObjectFormat;
use super::pack_candidates::LooseCandidate;
use super::pack_exec::SkipRecord;
use super::pack_inflate::ObjectKind;
use super::pack_io::{PackIo, PackIoError};
use super::pack_plan::{PackPlanError, PackView};
use super::pack_plan_model::{BaseLoc, PackPlan};
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;
use super::runner::{CandidateSkipReason, GitScanError, PackMmapLimits, SkippedCandidate};
use super::spiller::Spiller;
use super::tree_candidate::CandidateSink;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Pack cache sizing forms a layered hierarchy applied by `per_worker_cache_bytes`:
//
//   raw estimate  = total_pack_bytes / PACK_CACHE_FRACTION_DENOM  (~6.25 %)
//   per-worker cap = PACK_CACHE_TOTAL_MAX_BYTES / workers         (aggregate bound)
//   per-worker min = PACK_CACHE_PER_WORKER_MIN                    (functional floor)
//   hard ceiling   = PACK_CACHE_MAX_BYTES                         (per-worker cap)
//
// The min-floor can exceed the per-worker cap, which is intentional: a
// worker with too little cache is worse than slightly exceeding the
// aggregate target.

/// Heuristic bytes-per-candidate for path arena sizing.
///
/// Average git path length is ~40 bytes; 64 adds headroom for longer paths
/// without over-allocating for small repos. The estimate is multiplied by
/// candidate count and clamped to `u32::MAX` in [`estimate_path_arena_capacity`].
pub(super) const PATH_BYTES_PER_CANDIDATE_ESTIMATE: u64 = 64;

/// Denominator for the pack cache sizing fraction.
///
/// The pack cache receives `total_mapped_bytes / 16` (~6.25 % of pack data).
/// This fraction provides sufficient working-set coverage for large repos
/// while remaining bounded by [`PACK_CACHE_TOTAL_MAX_BYTES`] so aggregate memory stays
/// controlled.
pub(super) const PACK_CACHE_FRACTION_DENOM: u64 = 16;

/// Hard upper bound per worker for the pack cache (2 GiB).
///
/// Prevents runaway allocation on repos with many large packs.
pub(super) const PACK_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Aggregate memory cap across all workers (16 GiB).
///
/// With N workers each sizing caches independently, the per-worker estimate
/// could sum to excessive totals (e.g. 24 × 800 MiB = 19.2 GiB on a 50 GiB
/// repo). This cap divides evenly across workers so total cache memory stays
/// bounded regardless of pack size or worker count. With 20 workers each
/// gets up to 819 MiB — enough for large repos without starving small ones.
pub(super) const PACK_CACHE_TOTAL_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Minimum per-worker cache budget (32 MiB).
///
/// Ensures each worker has a functional cache even when the total cap is
/// divided among many workers. Below this threshold, cache sets are too few
/// to maintain reasonable hit rates.
pub(super) const PACK_CACHE_PER_WORKER_MIN: u64 = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SpillCandidateSink
// ---------------------------------------------------------------------------

/// Candidate sink that forwards tree-diff output to the spill/dedupe stage.
///
/// Bridges [`CandidateSink`] (the trait consumed by tree-diff walkers) to
/// [`Spiller::push`], translating spill I/O errors into [`TreeDiffError`].
/// This lets the diff-history pipeline emit candidates directly into the
/// spiller without an intermediate buffer.
pub(super) struct SpillCandidateSink<'a> {
    spiller: &'a mut Spiller,
}

impl<'a> SpillCandidateSink<'a> {
    pub(super) fn new(spiller: &'a mut Spiller) -> Self {
        Self { spiller }
    }
}

impl CandidateSink for SpillCandidateSink<'_> {
    fn emit(
        &mut self,
        oid: super::object_id::OidBytes,
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

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create a unique spill directory under the OS temp directory.
///
/// The directory name is derived from the PID and a nanosecond timestamp
/// to avoid collisions between concurrent scans. The caller owns the
/// directory and is responsible for cleanup (typically via [`Spiller`] drop).
pub(super) fn make_spill_dir() -> Result<PathBuf, io::Error> {
    // unwrap: SystemTime::now() is always ≥ UNIX_EPOCH on any supported platform.
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

/// Estimate a path arena capacity based on candidate volume.
///
/// Returns `max(base, (packed + loose) * PATH_BYTES_PER_CANDIDATE_ESTIMATE)`,
/// clamped to `u32::MAX`. The heuristic avoids arena overflow when candidate
/// counts greatly exceed the default `base` capacity.
pub(super) fn estimate_path_arena_capacity(base: u32, packed: u32, loose: u32) -> u32 {
    let total = packed as u64 + loose as u64;
    let est = total
        .saturating_mul(PATH_BYTES_PER_CANDIDATE_ESTIMATE)
        .min(u32::MAX as u64) as u32;
    base.max(est)
}

/// Estimate a raw pack cache size from mapped pack bytes.
///
/// Returns `clamp(total_used_bytes / PACK_CACHE_FRACTION_DENOM, base, PACK_CACHE_MAX_BYTES)`.
/// Only packs referenced by `used_pack_ids` contribute to `total_used_bytes`.
/// Returns `base` unchanged when no used packs are mapped (e.g. loose-only
/// repos).
///
/// This is the *raw* estimate before per-worker and total-memory capping.
/// Prefer [`per_worker_cache_bytes`] in pipeline code to respect aggregate
/// memory limits.
pub(super) fn estimate_pack_cache_bytes(
    base: usize,
    pack_mmaps: &[Option<Mmap>],
    used_pack_ids: &[u16],
) -> usize {
    let total_bytes: u64 = used_pack_ids
        .iter()
        .filter_map(|id| pack_mmaps.get(*id as usize).and_then(|m| m.as_ref()))
        .map(|m| m.len() as u64)
        .sum();

    if total_bytes == 0 {
        return base;
    }

    let target = total_bytes / PACK_CACHE_FRACTION_DENOM;
    let target = target.min(PACK_CACHE_MAX_BYTES).max(base as u64);
    target as usize
}

/// Compute bounded per-worker pack cache bytes.
///
/// 1. Starts from the raw estimate ([`estimate_pack_cache_bytes`]).
/// 2. Caps at `PACK_CACHE_TOTAL_MAX_BYTES / workers` so aggregate memory
///    across all workers stays bounded (16 GiB by default).
/// 3. Floors at `PACK_CACHE_PER_WORKER_MIN` (32 MiB) so each worker
///    retains a functional cache.
/// 4. Clamps to `PACK_CACHE_MAX_BYTES` (2 GiB per-worker hard cap).
///
/// Step 3 can exceed the per-worker cap from step 2 — this is intentional:
/// a worker with too little cache degrades hit-rate more than marginally
/// exceeding the aggregate target.
///
/// Both scan pipelines should call this instead of
/// `estimate_pack_cache_bytes` directly.
pub(super) fn per_worker_cache_bytes(
    base: usize,
    pack_mmaps: &[Option<Mmap>],
    used_pack_ids: &[u16],
    workers: usize,
) -> usize {
    let raw = estimate_pack_cache_bytes(base, pack_mmaps, used_pack_ids);
    let workers = workers.max(1) as u64;

    // Cap: total memory across all workers must not exceed PACK_CACHE_TOTAL_MAX_BYTES.
    let per_worker_cap = PACK_CACHE_TOTAL_MAX_BYTES / workers;
    let target = (raw as u64).min(per_worker_cap);

    // Floor: each worker needs at least a minimal functional cache.
    let target = target.max(PACK_CACHE_PER_WORKER_MIN);

    // Hard per-worker ceiling.
    let target = target.min(PACK_CACHE_MAX_BYTES);

    target as usize
}

/// Load the MIDX view for the repository.
///
/// The parser uses the repo's object format to validate OID lengths.
///
/// # Preconditions
///
/// `acquire_midx` must have been called to populate `repo.mmaps.midx`.
///
/// # Errors
///
/// Returns `GitScanError::Midx` if the MIDX bytes are missing or corrupted.
pub(super) fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_bytes = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx bytes missing")))?;
    Ok(MidxView::parse(midx_bytes.as_slice(), repo.object_format)?)
}

/// Convert the repo start set into finalize [`RefEntry`] values.
///
/// The "start set" is the set of branch/tag tips that the walk begins from
/// (populated during repo discovery). Each entry's ref name is resolved
/// through the repo's shared name table so the resulting `RefEntry` vector
/// carries owned byte names suitable for the finalize stage.
pub(super) fn build_ref_entries(repo: &RepoJobState) -> Vec<RefEntry> {
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
/// The primary `pack_dir` is returned first, followed by `<alternate>/pack`
/// for each alternate objects directory. Alternates equal to the main objects
/// dir are skipped to avoid duplicate scanning.
pub(super) fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
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

/// Collect loose object directories, including alternates.
///
/// The primary objects dir is returned first, followed by each alternate.
/// Alternates equal to the main objects dir are skipped to avoid duplicate
/// scanning.
pub(super) fn collect_loose_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.objects_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.clone());
    }
    dirs
}

/// List pack file names from the provided pack directories.
///
/// Returns raw file names (as bytes) for `.pack` files. Names are converted
/// through [`OsStr::to_string_lossy`], so non-UTF-8 bytes are replaced with
/// U+FFFD — acceptable because git pack file names are always ASCII hex.
/// Missing pack directories are ignored; other IO errors are returned.
pub(super) fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, GitScanError> {
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
/// The MIDX stores pack basenames (with `.idx` suffix); this function strips
/// the suffix, appends `.pack`, and searches `pack_dirs` in order. The first
/// match wins, so `pack_dirs` order is significant (primary before alternates).
///
/// # Errors
///
/// Returns `GitScanError::Io(NotFound)` if any MIDX-referenced pack cannot be
/// located in the provided directories.
pub(super) fn resolve_pack_paths(
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
///
/// Returns the input unchanged (as a new `Vec`) if neither suffix matches.
pub(super) fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
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
/// Only packs whose IDs appear in `used_pack_ids` are mapped; the returned
/// vector has the same length as `pack_paths` with `None` for unmapped slots,
/// preserving pack-ID-to-index correspondence.
///
/// # Preconditions
///
/// `used_pack_ids` must be de-duplicated. Duplicates would double-count
/// mapped bytes against `limits.max_total_bytes` and re-map the same file.
///
/// # Errors
///
/// - `GitScanError::ResourceLimit` — pack count or cumulative file size
///   exceeds `limits`.
/// - `GitScanError::PackPlan(PackIdOutOfRange)` — a pack ID falls outside
///   `pack_paths`.
/// - `GitScanError::Io` — file metadata or mmap syscall failure.
pub(super) fn mmap_pack_files(
    pack_paths: &[PathBuf],
    used_pack_ids: &[u16],
    limits: PackMmapLimits,
) -> Result<Vec<Option<Mmap>>, GitScanError> {
    limits.validate();
    if used_pack_ids.len() > limits.max_open_packs as usize {
        return Err(GitScanError::ResourceLimit(format!(
            "pack count {} exceeds limit {}",
            used_pack_ids.len(),
            limits.max_open_packs
        )));
    }

    let mut out = Vec::with_capacity(pack_paths.len());
    out.resize_with(pack_paths.len(), || None);
    let mut total_bytes = 0_u64;
    for &pack_id in used_pack_ids {
        let idx = pack_id as usize;
        let path =
            pack_paths
                .get(idx)
                .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                    pack_id,
                    pack_count: pack_paths.len(),
                }))?;
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
        advise_sequential(&file, &mmap);
        out[idx] = Some(mmap);
    }
    Ok(out)
}

/// Hint to the OS that the pack mmap will be read sequentially.
///
/// Issues `POSIX_FADV_SEQUENTIAL` (Linux only) on the file descriptor and
/// `MADV_SEQUENTIAL` on the mapped region. Both are advisory; failures are
/// silently ignored since they only affect readahead heuristics.
#[cfg(unix)]
pub(super) fn advise_sequential(file: &File, reader: &Mmap) {
    unsafe {
        // SAFETY: The file descriptor and mmap are valid for the duration of
        // these advisory calls; failures are ignored because they are hints.
        #[cfg(target_os = "linux")]
        let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        #[cfg(not(target_os = "linux"))]
        let _ = file;
        let _ = libc::madvise(
            reader.as_ptr() as *mut libc::c_void,
            reader.len(),
            libc::MADV_SEQUENTIAL,
        );
    }
}

#[cfg(not(unix))]
pub(super) fn advise_sequential(_file: &File, _reader: &Mmap) {}

/// Parse pack headers into `PackView`s used for planning.
///
/// Each pack view validates header structure and captures offsets needed by
/// the planning stage.
///
/// `pack_mmaps` may include `None` for unused packs; the output preserves that
/// indexing so pack IDs remain stable.
pub(super) fn build_pack_views<'a>(
    pack_mmaps: &'a [Option<Mmap>],
    format: ObjectFormat,
) -> Result<Vec<Option<PackView<'a>>>, GitScanError> {
    let mut views = Vec::with_capacity(pack_mmaps.len());
    for mmap in pack_mmaps {
        if let Some(mmap) = mmap {
            let view = PackView::parse(mmap.as_ref(), format.oid_len())
                .map_err(|err| GitScanError::PackPlan(PackPlanError::PackParse(err)))?;
            views.push(Some(view));
        } else {
            views.push(None);
        }
    }
    Ok(views)
}

/// Returns `(total_delta_deps, max_deps_in_single_plan)` across all plans.
///
/// Delta deps are pack entries that require decoding another object first
/// (the "base"). High dependency counts penalize sharding because shard
/// boundaries can separate a delta from its base, forcing cross-shard
/// resolution. The pipeline uses these numbers for logging and to inform
/// the strategy chosen by [`select_pack_exec_strategy`].
pub(super) fn summarize_pack_plan_deps(plans: &[PackPlan]) -> (u64, u32) {
    let mut total = 0u64;
    let mut max = 0u32;
    for plan in plans {
        let len = plan.delta_deps.len() as u32;
        total = total.saturating_add(len as u64);
        if len > max {
            max = len;
        }
    }
    (total, max)
}

// Sharding heuristic thresholds — these parameterize `select_plan_shard_count`
// and `select_pack_exec_strategy`. Each constant represents one independent
// cap; the shard count is the *minimum* across all of them.

/// Minimum decoded offsets before multi-threaded pack exec is considered.
const MIN_TOTAL_NEED_FOR_PARALLEL: usize = 512;
/// Minimum decoded offsets per shard to avoid oversharding tiny plans.
const MIN_NEED_PER_SHARD: usize = 1_024;
/// Minimum offset span per shard to avoid over-partitioning narrow ranges.
const MIN_SPAN_PER_SHARD: u64 = 4 * 1024 * 1024;
/// Cap shard fan-out when dependency pressure is high.
const MAX_SHARDS_WITH_DEP_PRESSURE: usize = 2;

/// Stats-free cost hint derived from core `PackPlan` structure.
///
/// This intentionally avoids `plan.stats` so strategy selection remains
/// independent of optional perf/debug instrumentation surfaces. The hint
/// captures only structural properties visible from `need_offsets` and
/// `delta_deps`, which are sufficient for shard-count and strategy decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanCostHint {
    /// Pack index this plan targets.
    pack_id: u16,
    /// Number of offsets that need decoding (`plan.need_offsets.len()`).
    need_count: usize,
    /// Byte span from first to last need offset; drives minimum-span-per-shard.
    span_bytes: u64,
    /// Delta deps where the base offset is *after* the dependent offset.
    /// Forward deps penalize sharding because a shard boundary could place
    /// a base in a different shard from its dependent.
    forward_deps: usize,
    /// Delta deps resolved via external OID lookup (not by offset).
    external_deps: usize,
}

/// Diff-history pack execution strategy for a planned pack set.
///
/// Selected by [`select_pack_exec_strategy`] from worker count and per-plan
/// structural hints derived from `PackPlan` internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PackExecStrategy {
    /// Single-threaded execution. Used when `workers <= 1` or no plans exist.
    Serial,
    /// One plan per worker with deterministic sequence reassembly.
    /// Chosen when `plan_count >= workers`.
    PackParallel,
    /// Intra-pack index sharding with per-pack shard count assignments.
    IntraPackSharded {
        /// `(pack_id, shard_count)` assignments for plans selected for sharding.
        shard_counts: Vec<(u16, usize)>,
    },
}

/// Extract a [`PlanCostHint`] from a plan's structural fields.
///
/// Counts forward delta dependencies (base offset > dependent offset) and
/// external dependencies (resolved by OID, not offset). These counts feed
/// the shard-count heuristic: high dependency pressure caps the number of
/// shards to avoid cross-shard decode ordering issues.
fn build_plan_cost_hint(plan: &PackPlan) -> PlanCostHint {
    let mut forward_deps = 0usize;
    let mut external_deps = 0usize;
    for dep in &plan.delta_deps {
        match dep.base {
            BaseLoc::Offset(base_offset) => {
                if base_offset > dep.offset {
                    forward_deps = forward_deps.saturating_add(1);
                }
            }
            BaseLoc::External { .. } => {
                external_deps = external_deps.saturating_add(1);
            }
        }
    }

    let span_bytes = plan
        .need_offsets
        .first()
        .zip(plan.need_offsets.last())
        .map_or(0, |(start, end)| end.saturating_sub(*start));

    PlanCostHint {
        pack_id: plan.pack_id,
        need_count: plan.need_offsets.len(),
        span_bytes,
        forward_deps,
        external_deps,
    }
}

/// Select the shard count for one pack plan based on structural heuristics.
///
/// The shard count is the minimum of several independent caps:
/// 1. **Worker count** — never more shards than available workers.
/// 2. **`need_count / MIN_NEED_PER_SHARD`** — avoids oversharding tiny plans.
/// 3. **`span_bytes / MIN_SPAN_PER_SHARD`** — avoids splitting narrow byte ranges.
/// 4. **Dependency pressure** — if more than half the need offsets have forward
///    or external deps, the shard count is capped to [`MAX_SHARDS_WITH_DEP_PRESSURE`]
///    to reduce cross-shard ordering hazards.
///
/// Returns 1 for single-worker execution or degenerate plans (≤ 1 offset).
#[inline(always)]
pub(super) fn select_plan_shard_count(workers: usize, plan: &PackPlan) -> usize {
    let workers = workers.max(1);
    if workers == 1 {
        return 1;
    }

    let hint = build_plan_cost_hint(plan);
    if hint.need_count <= 1 {
        return 1;
    }

    let mut shard_cap = workers.min(hint.need_count);
    let by_need = hint.need_count / MIN_NEED_PER_SHARD;
    shard_cap = if by_need == 0 {
        1
    } else {
        shard_cap.min(by_need.max(1))
    };

    if hint.span_bytes > 0 {
        let by_span = (hint.span_bytes / MIN_SPAN_PER_SHARD) as usize;
        shard_cap = if by_span == 0 {
            1
        } else {
            shard_cap.min(by_span.max(1))
        };
    }

    let dep_pressure = hint.forward_deps.saturating_add(hint.external_deps);
    if dep_pressure > (hint.need_count / 2) {
        shard_cap = shard_cap.min(MAX_SHARDS_WITH_DEP_PRESSURE);
    }

    shard_cap.max(1).min(hint.need_count)
}

/// Returns assigned shard count for `pack_id` or `1` if not present.
#[inline(always)]
pub(super) fn shard_count_for_pack(shard_counts: &[(u16, usize)], pack_id: u16) -> usize {
    shard_counts
        .iter()
        .find_map(|(id, shards)| (*id == pack_id).then_some(*shards))
        .unwrap_or(1)
        .max(1)
}

/// Select diff-history pack execution strategy from workers and plan structure.
///
/// Decision boundaries:
/// - `workers <= 1` or `plans == 0` → [`PackExecStrategy::Serial`]
/// - tiny total decode work → [`PackExecStrategy::Serial`]
/// - `plans >= workers` → [`PackExecStrategy::PackParallel`]
/// - otherwise → [`PackExecStrategy::IntraPackSharded`] with adaptive shards
#[inline(always)]
pub(super) fn select_pack_exec_strategy(workers: usize, plans: &[PackPlan]) -> PackExecStrategy {
    let workers = workers.max(1);
    if workers == 1 || plans.is_empty() {
        return PackExecStrategy::Serial;
    } else {
        let total_need: usize = plans
            .iter()
            .map(|plan| build_plan_cost_hint(plan).need_count)
            .sum();
        if total_need < MIN_TOTAL_NEED_FOR_PARALLEL {
            return PackExecStrategy::Serial;
        }
    }

    if plans.len() >= workers {
        PackExecStrategy::PackParallel
    } else {
        let mut shard_counts = Vec::with_capacity(plans.len());
        for plan in plans {
            shard_counts.push((plan.pack_id, select_plan_shard_count(workers, plan)));
        }
        PackExecStrategy::IntraPackSharded { shard_counts }
    }
}

/// Returns execution indices in deterministic order for a plan.
///
/// When `exec_order` is present (set by the planner when forward delta
/// dependencies exist) it is used to decode bases before their dependents.
/// Otherwise offsets are visited in natural `need_offsets` order, which is
/// correct when all bases precede their deltas in the pack file.
pub(super) fn build_exec_indices(plan: &PackPlan) -> Vec<usize> {
    if let Some(order) = plan.exec_order.as_ref() {
        order.iter().map(|&idx| idx as usize).collect()
    } else {
        (0..plan.need_offsets.len()).collect()
    }
}

/// Split `[0, len)` into `shards` contiguous `(start, end)` ranges.
///
/// The first `len % shards` ranges receive one extra element to distribute
/// remainder evenly. Returns an empty vec when `len == 0`.
/// `shards` is clamped to `[1, len]`.
///
/// Example: `shard_ranges(10, 3)` → `[(0,4), (4,7), (7,10)]`.
pub(super) fn shard_ranges(len: usize, shards: usize) -> Vec<(usize, usize)> {
    if len == 0 {
        return Vec::new();
    }
    let shards = shards.max(1).min(len);
    let base = len / shards;
    let extra = len % shards;
    let mut out = Vec::with_capacity(shards);
    let mut start = 0usize;
    for idx in 0..shards {
        let mut end = start + base;
        if idx < extra {
            end += 1;
        }
        out.push((start, end));
        start = end;
    }
    out
}

/// Merge per-shard scan results into a single [`ScannedBlobs`].
///
/// Each blob stores its findings as a `Range<u32>` into a flat
/// `finding_arena`. When arenas are concatenated the range start indices
/// become stale, so every blob's `findings.start` is shifted ("rebased")
/// by the arena length at the time its shard is appended.
///
/// Shards must be in deterministic order (e.g. by pack id) to produce
/// reproducible output.
pub(super) fn merge_scanned_blobs(mut shards: Vec<ScannedBlobs>) -> ScannedBlobs {
    let total_blobs: usize = shards.iter().map(|s| s.blobs.len()).sum();
    let total_findings: usize = shards.iter().map(|s| s.finding_arena.len()).sum();

    let mut merged = ScannedBlobs {
        blobs: Vec::with_capacity(total_blobs),
        finding_arena: Vec::with_capacity(total_findings),
    };

    for shard in shards.drain(..) {
        let base = merged.finding_arena.len() as u32;
        merged.finding_arena.extend_from_slice(&shard.finding_arena);
        for mut blob in shard.blobs {
            blob.findings.start = blob.findings.start.saturating_add(base);
            merged.blobs.push(blob);
        }
    }

    merged
}

/// Append `src` blobs into `dst`, rebasing finding spans into `dst`'s arena.
///
/// Same rebasing logic as [`merge_scanned_blobs`] but operates in-place.
pub(super) fn append_scanned_blobs(dst: &mut ScannedBlobs, mut src: ScannedBlobs) {
    let base = dst.finding_arena.len() as u32;
    dst.finding_arena.extend_from_slice(&src.finding_arena);
    for mut blob in src.blobs.drain(..) {
        blob.findings.start = blob.findings.start.saturating_add(base);
        dst.blobs.push(blob);
    }
}

/// Load loose candidate objects and scan their blob payloads.
///
/// For each candidate the loose object is decoded via `pack_io`. Blobs are
/// forwarded to `adapter.emit_loose`; non-blobs, missing objects, and decode
/// failures are recorded in `skipped` so the run can complete with partial
/// results.
///
/// # Errors
///
/// Returns `GitScanError::PackIo` only for unexpected I/O errors (e.g. a
/// permission failure on the objects directory). Recoverable per-object
/// problems are captured in `skipped` instead.
pub(super) fn scan_loose_candidates(
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

/// Map pack-level skip records back to candidate-level skip entries.
///
/// [`SkipRecord`]s carry raw pack offsets; this function binary-searches
/// `plan.candidate_offsets` (which are sorted by offset) to find every
/// candidate at each skipped offset. Multiple candidates can share an
/// offset (e.g. identical blobs referenced by different paths), and each
/// one produces a separate [`SkippedCandidate`] entry in `out`.
///
/// Complexity: O(S × log N) where S = `skips.len()` and N =
/// `candidate_offsets.len()` (two `partition_point` calls per skip).
pub(super) fn collect_skipped_candidates(
    plan: &PackPlan,
    skips: &[SkipRecord],
    out: &mut Vec<SkippedCandidate>,
) {
    if skips.is_empty() {
        return;
    }
    let offsets = &plan.candidate_offsets;
    for skip in skips {
        let reason = CandidateSkipReason::from_pack_skip(&skip.reason);
        // Two partition_points carve out the equal-range [start..end) of
        // candidates at this offset (sorted invariant of candidate_offsets).
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

/// Returns `true` if the file name has a `.pack` extension.
pub(super) fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

/// Returns `true` if `path` exists and is a regular file.
pub(super) fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::object_id::OidBytes;
    use crate::git_scan::pack_decode::PackDecodeLimits;
    use crate::git_scan::pack_plan_model::{BaseLoc, DeltaDep, DeltaKind, PackPlanStats, NONE_U32};
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

    use crate::git_scan::engine_adapter::{EngineAdapter, EngineAdapterConfig};
    use crate::git_scan::midx::MidxView;
    use crate::git_scan::object_id::ObjectFormat;
    use crate::git_scan::pack_candidates::PackCandidate;
    use crate::git_scan::pack_io::{PackIo, PackIoLimits};

    fn synthetic_plan(
        pack_id: u16,
        need_count: usize,
        span_bytes: u64,
        forward_deps: usize,
        external_deps: usize,
    ) -> PackPlan {
        let effective_span = span_bytes.max(need_count.saturating_sub(1) as u64);
        let step = if need_count <= 1 {
            0
        } else {
            (effective_span / (need_count as u64 - 1)).max(1)
        };
        let need_offsets: Vec<u64> = (0..need_count)
            .map(|idx| (idx as u64).saturating_mul(step))
            .collect();

        let mut delta_deps = Vec::with_capacity(forward_deps.saturating_add(external_deps));
        for idx in 0..forward_deps {
            let offset = idx as u64;
            delta_deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(offset.saturating_add(1)),
            });
        }
        for idx in 0..external_deps {
            let offset = forward_deps.saturating_add(idx) as u64;
            delta_deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ref,
                base: BaseLoc::External {
                    oid: OidBytes::default(),
                },
            });
        }
        delta_deps.sort_by_key(|dep| dep.offset);

        PackPlan {
            pack_id,
            oid_len: 20,
            max_delta_depth: 64,
            candidates: Vec::<PackCandidate>::new(),
            candidate_offsets: Vec::new(),
            need_offsets,
            delta_deps,
            delta_dep_index: vec![NONE_U32; need_count],
            exec_order: None,
            stats: PackPlanStats::empty(),
        }
    }

    #[test]
    fn select_pack_exec_strategy_handles_serial_boundaries() {
        let empty: Vec<PackPlan> = Vec::new();
        assert_eq!(
            select_pack_exec_strategy(0, &empty),
            PackExecStrategy::Serial,
            "empty plans should remain serial",
        );

        let single = vec![synthetic_plan(0, 2_048, 64 * 1024 * 1024, 0, 0)];
        assert_eq!(
            select_pack_exec_strategy(1, &single),
            PackExecStrategy::Serial,
            "worker=1 must remain serial",
        );
        assert_eq!(
            select_pack_exec_strategy(8, &[synthetic_plan(0, 100, 4 * 1024 * 1024, 0, 0)]),
            PackExecStrategy::Serial,
            "tiny total work should stay serial",
        );
    }

    #[test]
    fn select_pack_exec_strategy_prefers_pack_parallel_with_enough_plans() {
        let plans = vec![
            synthetic_plan(0, 1_500, 64 * 1024 * 1024, 0, 0),
            synthetic_plan(1, 1_500, 64 * 1024 * 1024, 0, 0),
            synthetic_plan(2, 1_500, 64 * 1024 * 1024, 0, 0),
        ];
        assert_eq!(
            select_pack_exec_strategy(3, &plans),
            PackExecStrategy::PackParallel,
            "plans>=workers should use pack-parallel",
        );
    }

    #[test]
    fn select_pack_exec_strategy_assigns_adaptive_shards() {
        let plans = vec![
            synthetic_plan(7, 8_192, 256 * 1024 * 1024, 0, 0),
            synthetic_plan(8, 200, 512 * 1024, 0, 0),
        ];
        match select_pack_exec_strategy(8, &plans) {
            PackExecStrategy::IntraPackSharded { shard_counts } => {
                assert_eq!(shard_count_for_pack(&shard_counts, 7), 8);
                assert_eq!(shard_count_for_pack(&shard_counts, 8), 1);
            }
            other => panic!("expected IntraPackSharded, got {other:?}"),
        }
    }

    #[test]
    fn select_plan_shard_count_caps_dependency_heavy_plans() {
        let dependency_heavy = synthetic_plan(0, 4_096, 64 * 1024 * 1024, 2_200, 0);
        assert_eq!(
            select_plan_shard_count(8, &dependency_heavy),
            2,
            "dependency pressure should cap shard fan-out",
        );
    }

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
            local_context: None,
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
