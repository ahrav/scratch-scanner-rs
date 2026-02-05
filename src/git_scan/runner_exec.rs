//! Shared helper functions for Git scan execution.
//!
//! Contains standalone utilities used by both scan modes (diff-history and
//! ODB-blob). These were extracted from `runner.rs` to keep the main
//! orchestrator focused on the pipeline dispatch.

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
use super::pack_plan_model::PackPlan;
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;
use super::runner::{CandidateSkipReason, GitScanError, PackMmapLimits, SkippedCandidate};
use super::spiller::Spiller;
use super::tree_candidate::CandidateSink;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Heuristic bytes-per-candidate for path arena sizing in ODB-blob mode.
///
/// This is a safety cushion to keep path arenas from overflowing when
/// candidates greatly exceed default caps, while still bounding capacity
/// to `u32::MAX`.
pub(super) const PATH_BYTES_PER_CANDIDATE_ESTIMATE: u64 = 64;
/// Denominator for pack cache sizing heuristic (total_bytes / denom).
pub(super) const PACK_CACHE_FRACTION_DENOM: u64 = 64;
/// Upper bound for pack cache sizing in ODB-blob mode (2 GiB).
pub(super) const PACK_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SpillCandidateSink
// ---------------------------------------------------------------------------

/// Candidate sink that forwards tree-diff output to the spill/dedupe stage.
///
/// Adapts `CandidateSink` to `Spiller::push`, translating tree-diff errors
/// into the common `TreeDiffError` type.
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
/// The directory name is derived from the PID and a nanosecond timestamp.
pub(super) fn make_spill_dir() -> Result<PathBuf, io::Error> {
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
/// Uses a bytes-per-candidate heuristic and returns at least `base`,
/// clamped to `u32::MAX`.
pub(super) fn estimate_path_arena_capacity(base: u32, packed: u32, loose: u32) -> u32 {
    let total = packed as u64 + loose as u64;
    let est = total
        .saturating_mul(PATH_BYTES_PER_CANDIDATE_ESTIMATE)
        .min(u32::MAX as u64) as u32;
    base.max(est)
}

/// Estimate a pack cache size from mapped pack bytes.
///
/// Uses a fixed fraction of total mapped pack size, clamped to the configured
/// minimum and an upper safety bound. Only packs referenced by `used_pack_ids`
/// contribute to the estimate.
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

/// Load the MIDX view for the repository.
///
/// The parser uses the repo's object format to validate OID lengths.
/// `acquire_midx` must have been called to populate `repo.mmaps.midx`.
///
/// # Errors
/// Returns `GitScanError::Midx` if the MIDX bytes are missing or corrupted.
pub(super) fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_bytes = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx bytes missing")))?;
    Ok(MidxView::parse(midx_bytes.as_slice(), repo.object_format)?)
}

/// Convert the repo start set into finalize `RefEntry` values.
///
/// The ref names are taken from the repo's shared name table.
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
/// Alternates that resolve to the main objects dir are ignored.
/// The primary pack dir is returned first.
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
/// Alternates that resolve to the main objects dir are ignored.
/// The primary objects dir is returned first.
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
/// Returns raw file names (as bytes) for `.pack` files. Missing pack
/// directories are ignored; other IO errors are returned.
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
/// The MIDX stores pack basenames; we add the `.pack` suffix and search
/// each pack directory until a match is found. The first match wins, so
/// `pack_dirs` order is significant.
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
/// The mappings are read-only and may outlive the file handles.
/// Returns `GitScanError::ResourceLimit` if pack counts or total bytes exceed
/// the configured mmap limits.
///
/// Callers must pass de-duplicated `used_pack_ids`; duplicates would
/// double-count bytes and re-map the same pack.
///
/// The returned vector matches `pack_paths` length so pack IDs remain stable.
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

/// Returns total delta dependency count and the maximum deps in any plan.
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

/// Diff-history pack execution strategy for a planned pack set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PackExecStrategy {
    /// Single-threaded execution (default and worker fallback).
    Serial,
    /// One plan per worker with deterministic sequence reassembly.
    PackParallel,
    /// Intra-pack index sharding when plan count is below worker count.
    IntraPackSharded,
}

/// Selects diff-history pack execution strategy from worker and plan counts.
#[inline(always)]
pub(super) fn select_pack_exec_strategy(workers: usize, plan_count: usize) -> PackExecStrategy {
    let workers = workers.max(1);
    if workers == 1 || plan_count == 0 {
        PackExecStrategy::Serial
    } else if plan_count >= workers {
        PackExecStrategy::PackParallel
    } else {
        PackExecStrategy::IntraPackSharded
    }
}

/// Returns execution indices in deterministic order for a plan.
///
/// When `exec_order` is present, it is used to handle forward delta
/// dependencies. Otherwise the offsets are executed sequentially.
pub(super) fn build_exec_indices(plan: &PackPlan) -> Vec<usize> {
    if let Some(order) = plan.exec_order.as_ref() {
        order.iter().map(|&idx| idx as usize).collect()
    } else {
        (0..plan.need_offsets.len()).collect()
    }
}

/// Splits a range into `shards` contiguous ranges covering `[0, len)`.
///
/// The first `len % shards` ranges receive one extra element.
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

/// Merge per-shard results in shard order, rebasing finding spans.
///
/// Shards should already be ordered deterministically (for example by pack id).
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

/// Append scanned blobs while rebasing finding spans.
pub(super) fn append_scanned_blobs(dst: &mut ScannedBlobs, mut src: ScannedBlobs) {
    let base = dst.finding_arena.len() as u32;
    dst.finding_arena.extend_from_slice(&src.finding_arena);
    for mut blob in src.blobs.drain(..) {
        blob.findings.start = blob.findings.start.saturating_add(base);
        dst.blobs.push(blob);
    }
}

/// Load loose candidates and scan blob payloads.
///
/// Missing or undecodable loose objects are recorded as skips so the run can
/// complete with partial results. Paths are re-interned into the adapter's
/// arena via `emit_loose`.
///
/// Missing objects, decode errors, and non-blob kinds are recorded as skips.
/// Unexpected pack I/O errors are returned as fatal scan errors.
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

/// Collect candidates that were skipped during pack execution.
///
/// The skip records are offsets into the pack stream; we map them back to
/// candidate offsets and record the corresponding OIDs with a reason.
/// If multiple candidates share an offset, each one is recorded.
pub(super) fn collect_skipped_candidates(
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

pub(super) fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

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
    use crate::git_scan::pack_io::{PackIo, PackIoLimits};

    #[test]
    fn diff_history_pack_exec_strategy_honors_worker_setting() {
        assert_eq!(
            select_pack_exec_strategy(0, 4),
            PackExecStrategy::Serial,
            "worker=0 should fallback to serial",
        );
        assert_eq!(
            select_pack_exec_strategy(1, 4),
            PackExecStrategy::Serial,
            "worker=1 must remain serial",
        );
        assert_eq!(
            select_pack_exec_strategy(4, 0),
            PackExecStrategy::Serial,
            "no plans should remain serial",
        );
        assert_eq!(
            select_pack_exec_strategy(2, 1),
            PackExecStrategy::IntraPackSharded,
            "workers>plans should shard within pack",
        );
        assert_eq!(
            select_pack_exec_strategy(2, 2),
            PackExecStrategy::PackParallel,
            "matching workers/plans should use pack-parallel",
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
