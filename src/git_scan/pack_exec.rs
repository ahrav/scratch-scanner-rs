//! Pack plan executor.
//!
//! Decodes pack objects in plan order, applies deltas with bounded buffers,
//! and emits decoded blob bytes to a caller-provided sink. All skips are
//! recorded with explicit reasons.
//!
//! # Execution model
//! - Offsets are decoded at most once during the planned pass; delta base
//!   cache misses may trigger on-demand re-decodes into scratch buffers.
//! - `inflate_buf`, `result_buf`, and `base_buf` are reused across offsets
//!   to avoid repeated allocations on the hot path.
//! - Oversized objects are decoded into spill-backed mmaps under the
//!   caller-provided `spill_dir`, keeping RAM bounded while still scanning.
//! - When the allocation guard is enabled, per-offset decoding and sink
//!   emission must not allocate.
//! - Oversized blobs and delta outputs may be spilled to mmap-backed files
//!   under a caller-provided spill directory.
//!
//! Execution order is driven by `PackPlan.exec_order`: when absent, offsets
//! are processed in ascending order and candidate gating uses a single
//! forward-only merge cursor over `candidate_offsets`. When present, the
//! executor precomputes exact per-offset candidate ranges to preserve
//! gating under out-of-order execution.
//!
//! # Invariants
//! - `plan.need_offsets` and `plan.candidate_offsets` are sorted by pack offset.
//! - `exec_order`, when present, is a permutation of `need_offsets` indices.
//! - The sink must not retain `bytes` slices beyond `emit` calls.
//! - Skip records are appended in execution order.
//!
//! The executor treats decode failures as per-offset skips and only returns
//! fatal errors for pack parsing or sink failures. External base provider
//! errors are recorded as skips for the affected offsets.
//!
//! # Plan assumptions
//! - `need_offsets` is sorted ascending.
//! - `candidate_offsets` is sorted ascending by offset and grouped per offset.
//! - `exec_order`, when present, indexes into `need_offsets`.
//!
//! # Buffer ownership
//! - `PackCache` stores decoded bytes when space permits.
//! - Otherwise, bytes live in a scratch buffer that is overwritten per offset.
//! - Sinks must consume `bytes` within the `emit` call.

use std::fmt;
use std::path::Path;

use crate::scheduler::AllocGuard;

use super::alloc_guard;
use super::blob_spill::BlobSpill;
use super::byte_arena::ByteArena;
use super::object_id::OidBytes;
use super::pack_cache::PackCache;
use super::pack_candidates::PackCandidate;
use super::pack_decode::{inflate_entry_payload, PackDecodeError, PackDecodeLimits};
use super::pack_delta::apply_delta;
use super::pack_inflate::{
    apply_delta_into, delta_sizes, inflate_limited, inflate_stream, DeltaError, EntryHeader,
    EntryKind, ObjectKind, PackFile, PackParseError,
};
use super::pack_plan_model::{BaseLoc, DeltaDep, PackPlan, NONE_U32};
use super::pack_reader::PackReader;
use super::perf;

/// External base object for REF deltas.
///
/// The bytes must contain the fully inflated base object and will be used as
/// the delta application base.
#[derive(Debug)]
pub struct ExternalBase {
    pub kind: ObjectKind,
    pub bytes: Vec<u8>,
}

/// Provider for external REF delta bases.
///
/// Implementations may source bases from loose objects or other packs.
pub trait ExternalBaseProvider {
    /// Returns the base object for a given OID, or `None` if missing.
    ///
    /// Any error is recorded as `SkipReason::ExternalBaseError` for the
    /// affected offset; execution continues.
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError>;
}

/// Sink for decoded pack blobs.
///
/// The sink is invoked only for blob objects. Non-blob objects are recorded
/// as skips with `SkipReason::NotBlob`.
pub trait PackObjectSink {
    /// Receives a decoded blob candidate.
    ///
    /// The `bytes` slice is only valid for the duration of the call and may
    /// be backed by either a cache entry or a scratch buffer. Implementations
    /// must copy if they need to retain the bytes.
    /// `path` points into the caller-owned arena.
    ///
    /// When the allocation guard is enabled, `emit` must avoid heap
    /// allocation to preserve hot-path guarantees.
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError>;

    /// Called after all candidates for a pack are processed.
    fn finish(&mut self) -> Result<(), PackExecError> {
        Ok(())
    }
}

/// Pack executor error taxonomy (fatal only).
///
/// Decode errors do not appear here; they are tracked as `SkipReason`s.
#[derive(Debug)]
pub enum PackExecError {
    /// Pack header or index parsing failed.
    PackParse(PackParseError),
    /// Pack bytes could not be read.
    PackRead(String),
    /// The sink rejected an emitted blob.
    Sink(String),
    /// External base provider returned a fatal error.
    ExternalBase(String),
    /// Spill file creation or write failed.
    Spill(String),
}

impl fmt::Display for PackExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::PackRead(msg) => write!(f, "pack read error: {msg}"),
            Self::Sink(msg) => write!(f, "sink error: {msg}"),
            Self::ExternalBase(msg) => write!(f, "external base error: {msg}"),
            Self::Spill(msg) => write!(f, "spill error: {msg}"),
        }
    }
}

impl std::error::Error for PackExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PackParseError> for PackExecError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

/// Skip reason for a candidate offset.
///
/// These are non-fatal and recorded in the execution report.
#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Pack parsing failed for this offset.
    PackParse(PackParseError),
    /// Inflating or decoding this entry failed.
    Decode(PackDecodeError),
    /// Delta application failed after a successful decode.
    Delta(DeltaError),
    /// An OFS/REF delta base was expected in-pack but missing from cache.
    BaseMissing { base_offset: u64 },
    /// External base provider returned `None` for a REF delta.
    ExternalBaseMissing { oid: OidBytes },
    /// External base provider returned an error.
    ExternalBaseError,
    /// Entry decoded successfully but is not a blob.
    NotBlob,
}

/// Record of a skipped offset.
///
/// A single offset may appear multiple times if multiple candidates map to
/// the same offset and are all skipped.
#[derive(Debug)]
pub struct SkipRecord {
    pub offset: u64,
    pub reason: SkipReason,
}

/// Execution statistics.
#[derive(Debug, Default)]
pub struct PackExecStats {
    /// Offsets successfully decoded (including bases and non-blob kinds).
    pub decoded_offsets: u32,
    /// Candidates emitted to the sink.
    pub emitted_candidates: u32,
    /// Skip records emitted (may exceed unique offsets).
    pub skipped_offsets: u32,
    /// Cache hits when looking up delta base offsets.
    pub base_cache_hits: u32,
    /// Cache misses when looking up delta base offsets.
    pub base_cache_misses: u32,
    /// External base provider calls for REF deltas.
    pub external_base_calls: u32,
    /// On-demand base decode attempts triggered by cache misses.
    pub fallback_base_decodes: u32,
    /// Sum of delta-chain lengths walked during fallback decode attempts.
    pub fallback_chain_len_sum: u32,
    /// Maximum delta-chain length observed in fallback decode attempts.
    pub fallback_chain_len_max: u32,
    /// Cache insert attempts rejected (oversize entry or cache disabled).
    pub cache_insert_rejects: u32,
    /// Total rejected bytes across cache insert attempts.
    pub cache_reject_bytes_total: u64,
    /// Maximum rejected entry size.
    pub cache_reject_bytes_max: u32,
    /// Size histogram buckets (log2 sizes) for rejected cache inserts.
    pub cache_reject_size_buckets: [u64; CACHE_REJECT_BUCKETS],
    /// Large blobs streamed without full in-memory decode.
    pub large_blob_streamed_count: u32,
    /// Large blobs spilled to disk for scanning.
    pub large_blob_spilled_count: u32,
    /// Total bytes across large blob handling (stream + spill).
    pub large_blob_bytes: u64,
    // Timing fields (nanoseconds) - populated when git-perf feature enabled
    /// Wall-clock nanoseconds spent in cache.get() lookups.
    pub cache_lookup_nanos: u64,
    /// Wall-clock nanoseconds spent in fallback base resolution.
    pub fallback_resolve_nanos: u64,
    /// Wall-clock nanoseconds spent in sink.emit() calls.
    pub sink_emit_nanos: u64,
}

/// Pack execution report.
#[derive(Debug, Default)]
pub struct PackExecReport {
    /// Aggregate stats for this pack execution.
    pub stats: PackExecStats,
    /// Per-offset skip records (may include repeated offsets), in execution order.
    pub skips: Vec<SkipRecord>,
}

/// Number of cache reject size buckets (log2 of byte size).
pub const CACHE_REJECT_BUCKETS: usize = 32;

/// Aggregate cache reject histogram across pack-exec reports.
#[derive(Debug, Default, Clone)]
pub struct CacheRejectHistogram {
    pub rejects: u64,
    pub bytes_total: u64,
    pub bytes_max: u32,
    pub buckets: [u64; CACHE_REJECT_BUCKETS],
}

impl CacheRejectHistogram {
    /// Formats the top-N buckets by count.
    #[must_use]
    pub fn format_top(&self, top_n: usize) -> String {
        let mut entries: Vec<(usize, u64)> = self
            .buckets
            .iter()
            .enumerate()
            .filter_map(|(idx, &count)| (count > 0).then_some((idx, count)))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut out = String::from("[");
        for (pos, (idx, count)) in entries.into_iter().take(top_n).enumerate() {
            if pos > 0 {
                out.push_str(", ");
            }
            let (start, end) = cache_reject_bucket_range(idx);
            out.push_str(&format!("{start}-{end}:{count}"));
        }
        out.push(']');
        out
    }
}

impl PackExecStats {
    #[inline]
    fn record_cache_reject(&mut self, size: usize) {
        self.cache_insert_rejects = self.cache_insert_rejects.saturating_add(1);
        self.cache_reject_bytes_total = self.cache_reject_bytes_total.saturating_add(size as u64);
        let size_u32 = size.min(u32::MAX as usize) as u32;
        self.cache_reject_bytes_max = self.cache_reject_bytes_max.max(size_u32);
        let bucket = cache_reject_bucket_index(size_u32);
        self.cache_reject_size_buckets[bucket] =
            self.cache_reject_size_buckets[bucket].saturating_add(1);
    }

    #[inline]
    fn merge_from(&mut self, other: &PackExecStats) {
        self.decoded_offsets = self.decoded_offsets.saturating_add(other.decoded_offsets);
        self.emitted_candidates = self
            .emitted_candidates
            .saturating_add(other.emitted_candidates);
        self.skipped_offsets = self.skipped_offsets.saturating_add(other.skipped_offsets);
        self.base_cache_hits = self.base_cache_hits.saturating_add(other.base_cache_hits);
        self.base_cache_misses = self
            .base_cache_misses
            .saturating_add(other.base_cache_misses);
        self.external_base_calls = self
            .external_base_calls
            .saturating_add(other.external_base_calls);
        self.fallback_base_decodes = self
            .fallback_base_decodes
            .saturating_add(other.fallback_base_decodes);
        self.fallback_chain_len_sum = self
            .fallback_chain_len_sum
            .saturating_add(other.fallback_chain_len_sum);
        self.fallback_chain_len_max = self
            .fallback_chain_len_max
            .max(other.fallback_chain_len_max);
        self.cache_insert_rejects = self
            .cache_insert_rejects
            .saturating_add(other.cache_insert_rejects);
        self.cache_reject_bytes_total = self
            .cache_reject_bytes_total
            .saturating_add(other.cache_reject_bytes_total);
        self.cache_reject_bytes_max = self
            .cache_reject_bytes_max
            .max(other.cache_reject_bytes_max);
        for (idx, count) in other.cache_reject_size_buckets.iter().enumerate() {
            self.cache_reject_size_buckets[idx] =
                self.cache_reject_size_buckets[idx].saturating_add(*count);
        }
        self.large_blob_streamed_count = self
            .large_blob_streamed_count
            .saturating_add(other.large_blob_streamed_count);
        self.large_blob_spilled_count = self
            .large_blob_spilled_count
            .saturating_add(other.large_blob_spilled_count);
        self.large_blob_bytes = self.large_blob_bytes.saturating_add(other.large_blob_bytes);
        self.cache_lookup_nanos = self
            .cache_lookup_nanos
            .saturating_add(other.cache_lookup_nanos);
        self.fallback_resolve_nanos = self
            .fallback_resolve_nanos
            .saturating_add(other.fallback_resolve_nanos);
        self.sink_emit_nanos = self.sink_emit_nanos.saturating_add(other.sink_emit_nanos);
    }
}

/// Accumulate timing into stats field (no-op when git-perf disabled).
#[inline(always)]
fn record_timing(field: &mut u64, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        *field = field.saturating_add(nanos);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (field, nanos);
    }
}

#[inline]
fn cache_reject_bucket_index(size: u32) -> usize {
    if size == 0 {
        return 0;
    }
    (31 - size.leading_zeros()) as usize
}

fn cache_reject_bucket_range(idx: usize) -> (u32, u32) {
    if idx == 0 {
        return (0, 1);
    }
    let start = 1u32 << idx;
    let end = if idx >= 31 {
        u32::MAX
    } else {
        (1u32 << (idx + 1)) - 1
    };
    (start, end)
}

#[inline]
fn record_fallback_chain(stats: &mut PackExecStats, chain_len: usize) {
    let chain_len = chain_len.min(u32::MAX as usize) as u32;
    stats.fallback_chain_len_sum = stats.fallback_chain_len_sum.saturating_add(chain_len);
    stats.fallback_chain_len_max = stats.fallback_chain_len_max.max(chain_len);
}

/// Aggregate cache reject histogram across pack-exec reports.
#[must_use]
pub fn aggregate_cache_reject_histogram(reports: &[PackExecReport]) -> CacheRejectHistogram {
    let mut out = CacheRejectHistogram::default();
    for report in reports {
        let stats = &report.stats;
        out.rejects = out
            .rejects
            .saturating_add(stats.cache_insert_rejects as u64);
        out.bytes_total = out
            .bytes_total
            .saturating_add(stats.cache_reject_bytes_total);
        out.bytes_max = out.bytes_max.max(stats.cache_reject_bytes_max);
        for (idx, count) in stats.cache_reject_size_buckets.iter().enumerate() {
            out.buckets[idx] = out.buckets[idx].saturating_add(*count);
        }
    }
    out
}

/// Merge per-shard reports in order into a single report.
#[must_use]
pub fn merge_pack_exec_reports(mut reports: Vec<PackExecReport>) -> PackExecReport {
    let mut merged = PackExecReport::default();
    for report in reports.drain(..) {
        merged.stats.merge_from(&report.stats);
        merged.skips.extend(report.skips);
    }
    merged
}

/// Reusable scratch buffers for pack execution.
#[derive(Debug, Default)]
pub struct PackExecScratch {
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    base_buf: Vec<u8>,
    delta_stack: Vec<DeltaFrame>,
    candidate_ranges: Vec<Option<(usize, usize)>>,
}

impl PackExecScratch {
    /// Prepares scratch buffers for the given plan and decode limits.
    ///
    /// This only reserves capacity; it does not prefill contents. Callers
    /// rely on this to avoid per-offset allocations on the hot path.
    fn prepare(&mut self, plan: &PackPlan, limits: &PackDecodeLimits) {
        let inflate_target = limits.max_delta_bytes.max(1024);
        if self.inflate_buf.capacity() < inflate_target {
            self.inflate_buf
                .reserve(inflate_target - self.inflate_buf.capacity());
        }
        self.inflate_buf.clear();

        let result_target = limits.max_object_bytes.max(1024);
        if self.result_buf.capacity() < result_target {
            self.result_buf
                .reserve(result_target - self.result_buf.capacity());
        }
        self.result_buf.clear();

        let base_target = limits.max_object_bytes.max(1024);
        if self.base_buf.capacity() < base_target {
            self.base_buf
                .reserve(base_target - self.base_buf.capacity());
        }
        self.base_buf.clear();

        let depth_target = plan.max_delta_depth as usize + 1;
        if self.delta_stack.capacity() < depth_target {
            self.delta_stack
                .reserve(depth_target - self.delta_stack.capacity());
        }
        self.delta_stack.clear();
        self.candidate_ranges.clear();
    }
}

/// Where the decoded bytes live after `decode_offset`.
#[derive(Debug)]
enum DecodedStorage {
    /// Bytes are stored in the `PackCache`.
    Cache,
    /// Bytes are stored in the scratch buffer passed to the decoder.
    Scratch,
    /// Bytes are stored in a spill-backed mmap.
    ///
    /// The spill must outlive any use of the returned slice.
    Spill(BlobSpill),
}

/// Metadata for a decoded offset (kind + storage location).
#[derive(Debug)]
struct DecodedObject {
    kind: ObjectKind,
    storage: DecodedStorage,
}

/// Base byte storage for delta application.
enum BaseStorage<'a> {
    Slice(&'a [u8]),
    /// Spill-backed bytes; the spill must remain alive while referenced.
    Spill(BlobSpill),
}

impl BaseStorage<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Spill(spill) => spill.as_slice(),
        }
    }
}

/// Resolved base bytes for delta application.
struct BaseBytes<'a> {
    kind: ObjectKind,
    storage: BaseStorage<'a>,
}

impl BaseBytes<'_> {
    fn bytes(&self) -> &[u8] {
        self.storage.as_slice()
    }
}

#[derive(Clone, Copy, Debug)]
struct DeltaFrame {
    offset: u64,
    header: EntryHeader,
}

/// Executes a pack plan against a `PackReader`.
///
/// The reader is used to materialize a contiguous pack byte buffer. This
/// enables deterministic fault injection for simulation without changing
/// the core decode logic.
///
/// Note: this reads the entire pack into memory; very large packs may exceed
/// addressable memory on 32-bit platforms. Spill-backed decoding uses the
/// process temp directory.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_reader<S: PackObjectSink, B: ExternalBaseProvider, R: PackReader>(
    plan: &PackPlan,
    reader: &mut R,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
) -> Result<PackExecReport, PackExecError> {
    let mut pack_bytes = Vec::new();
    read_pack_bytes(reader, &mut pack_bytes)?;
    let spill_dir = std::env::temp_dir();
    execute_pack_plan(
        plan,
        &pack_bytes,
        paths,
        limits,
        cache,
        external,
        sink,
        &spill_dir,
    )
}

/// Executes a pack plan against pack bytes.
///
/// The plan's `exec_order` is respected when present to satisfy forward
/// delta dependencies. Pack bytes must contain the full pack file.
///
/// `paths` must contain all path refs referenced by plan candidates.
/// `cache` is updated with decoded objects when capacity allows.
/// `spill_dir` is used for oversized blob spill files.
/// `spill_dir` is used for spill-backed large blob or delta outputs.
///
/// The returned report includes both successful decode stats and per-offset
/// skip reasons for non-fatal failures (decode errors, missing bases, and
/// external base provider errors).
///
/// For offsets with multiple candidates, `emit` is invoked once per candidate.
/// Non-blob objects record `SkipReason::NotBlob` for each candidate at the
/// offset.
///
/// # Errors
/// - `PackExecError::PackParse` for invalid pack headers.
/// - `PackExecError::Sink` for sink failures.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
) -> Result<PackExecReport, PackExecError> {
    let mut scratch = PackExecScratch::default();
    execute_pack_plan_with_scratch(
        plan,
        pack_bytes,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        &mut scratch,
    )
}

/// Executes a pack plan using reusable scratch buffers.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
) -> Result<PackExecReport, PackExecError> {
    let pack = PackFile::parse(pack_bytes, plan.oid_len as usize)?;
    let mut report = PackExecReport::default();
    report
        .skips
        .reserve(plan.candidate_offsets.len().min(u32::MAX as usize));

    let alloc_guard_enabled = alloc_guard::enabled();

    scratch.prepare(plan, limits);
    let inflate_buf = &mut scratch.inflate_buf;
    let result_buf = &mut scratch.result_buf;

    let mut handle_idx = |idx: usize, range: Option<(usize, usize)>| -> Result<(), PackExecError> {
        let guard = if alloc_guard_enabled {
            Some(AllocGuard::new())
        } else {
            None
        };
        let offset = plan.need_offsets[idx];

        let (cache_result, lookup_nanos) = perf::time(|| cache.get(offset));
        record_timing(&mut report.stats.cache_lookup_nanos, lookup_nanos);
        let (obj_kind, storage) = if let Some(hit) = cache_result {
            perf::record_cache_hit();
            (hit.kind, DecodedStorage::Cache)
        } else {
            perf::record_cache_miss();
            let decoded = decode_offset(
                &pack,
                offset,
                idx,
                &plan.need_offsets,
                limits,
                plan.max_delta_depth,
                cache,
                external,
                &plan.delta_deps,
                &plan.delta_dep_index,
                &mut report,
                inflate_buf,
                result_buf,
                &mut scratch.base_buf,
                &mut scratch.delta_stack,
                spill_dir,
            )?;

            let Some(obj) = decoded else {
                return Ok(());
            };

            (obj.kind, obj.storage)
        };

        let bytes = match &storage {
            DecodedStorage::Cache => cache
                .get(offset)
                .map(|hit| hit.bytes)
                .unwrap_or(result_buf.as_slice()),
            DecodedStorage::Scratch => result_buf.as_slice(),
            DecodedStorage::Spill(spill) => spill.as_slice(),
        };

        if let Some((start, end)) = range {
            // Candidate range is precomputed (out-of-order) or merged (monotone).
            for cand_idx in start..end {
                let candidate =
                    &plan.candidates[plan.candidate_offsets[cand_idx].cand_idx as usize];
                if obj_kind != ObjectKind::Blob {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::NotBlob,
                    });
                    report.stats.skipped_offsets += 1;
                    continue;
                }
                let path = paths.get(candidate.ctx.path_ref);
                let (emit_result, emit_nanos) = perf::time(|| sink.emit(candidate, path, bytes));
                emit_result?;
                record_timing(&mut report.stats.sink_emit_nanos, emit_nanos);
                report.stats.emitted_candidates += 1;
            }
        }

        if let Some(guard) = guard {
            guard.assert_no_alloc();
        }

        Ok(())
    };

    if let Some(order) = plan.exec_order.as_ref() {
        // Out-of-order execution: precompute exact candidate ranges by need index.
        build_candidate_ranges(plan, &mut scratch.candidate_ranges);
        for &idx in order {
            let idx = idx as usize;
            handle_idx(idx, scratch.candidate_ranges[idx])?;
        }
    } else {
        // Monotone execution: merge candidate offsets with need offsets.
        let cand = &plan.candidate_offsets;
        let mut cand_idx = 0usize;
        for (idx, &offset) in plan.need_offsets.iter().enumerate() {
            while cand_idx < cand.len() && cand[cand_idx].offset < offset {
                cand_idx += 1;
            }
            let range = if cand_idx < cand.len() && cand[cand_idx].offset == offset {
                let start = cand_idx;
                while cand_idx < cand.len() && cand[cand_idx].offset == offset {
                    cand_idx += 1;
                }
                Some((start, cand_idx))
            } else {
                None
            };
            handle_idx(idx, range)?;
        }
    }

    sink.finish()?;
    Ok(report)
}

/// Executes a pack plan for a subset of offsets in `exec_indices`.
///
/// The `candidate_ranges` slice must be indexed by `need_offsets` index and
/// is used to map offsets to candidate ranges deterministically.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_indices<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    exec_indices: &[usize],
    candidate_ranges: &[Option<(usize, usize)>],
) -> Result<PackExecReport, PackExecError> {
    debug_assert_eq!(candidate_ranges.len(), plan.need_offsets.len());
    let pack = PackFile::parse(pack_bytes, plan.oid_len as usize)?;
    let mut report = PackExecReport::default();
    let mut expected = exec_indices.len();
    for &idx in exec_indices {
        if let Some((start, end)) = candidate_ranges[idx] {
            expected = expected.saturating_add(end - start);
        }
    }
    report.skips.reserve(expected.min(u32::MAX as usize));

    let alloc_guard_enabled = alloc_guard::enabled();

    scratch.prepare(plan, limits);
    let inflate_buf = &mut scratch.inflate_buf;
    let result_buf = &mut scratch.result_buf;

    let mut handle_idx = |idx: usize| -> Result<(), PackExecError> {
        let guard = if alloc_guard_enabled {
            Some(AllocGuard::new())
        } else {
            None
        };
        let offset = plan.need_offsets[idx];
        let range = candidate_ranges[idx];

        let (cache_result, lookup_nanos) = perf::time(|| cache.get(offset));
        record_timing(&mut report.stats.cache_lookup_nanos, lookup_nanos);
        let (obj_kind, storage) = if let Some(hit) = cache_result {
            perf::record_cache_hit();
            (hit.kind, DecodedStorage::Cache)
        } else {
            perf::record_cache_miss();
            let decoded = decode_offset(
                &pack,
                offset,
                idx,
                &plan.need_offsets,
                limits,
                plan.max_delta_depth,
                cache,
                external,
                &plan.delta_deps,
                &plan.delta_dep_index,
                &mut report,
                inflate_buf,
                result_buf,
                &mut scratch.base_buf,
                &mut scratch.delta_stack,
                spill_dir,
            )?;

            let Some(obj) = decoded else {
                return Ok(());
            };

            (obj.kind, obj.storage)
        };

        let bytes: &[u8] = match &storage {
            DecodedStorage::Cache => cache
                .get(offset)
                .map(|hit| hit.bytes)
                .unwrap_or(result_buf.as_slice()),
            DecodedStorage::Scratch => result_buf.as_slice(),
            DecodedStorage::Spill(spill) => spill.as_slice(),
        };

        if let Some((start, end)) = range {
            for cand_idx in start..end {
                let candidate =
                    &plan.candidates[plan.candidate_offsets[cand_idx].cand_idx as usize];
                if obj_kind != ObjectKind::Blob {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::NotBlob,
                    });
                    report.stats.skipped_offsets += 1;
                    continue;
                }
                let path = paths.get(candidate.ctx.path_ref);
                let (emit_result, emit_nanos) = perf::time(|| sink.emit(candidate, path, bytes));
                emit_result?;
                record_timing(&mut report.stats.sink_emit_nanos, emit_nanos);
                report.stats.emitted_candidates += 1;
            }
        }

        if let Some(guard) = guard {
            guard.assert_no_alloc();
        }

        Ok(())
    };

    for &idx in exec_indices {
        handle_idx(idx)?;
    }

    sink.finish()?;
    Ok(report)
}

/// Read the entire pack into `out`, returning a fatal error on short reads.
fn read_pack_bytes<R: PackReader>(reader: &mut R, out: &mut Vec<u8>) -> Result<(), PackExecError> {
    let len_u64 = reader.len();
    let len = usize::try_from(len_u64).map_err(|_| {
        PackExecError::PackRead(format!("pack length {len_u64} exceeds addressable memory"))
    })?;
    out.clear();
    out.resize(len, 0);
    if len == 0 {
        return Ok(());
    }
    reader
        .read_exact_at(0, out)
        .map_err(|err| PackExecError::PackRead(err.to_string()))
}

/// Build candidate index ranges for each `need_offsets` entry.
///
/// This is used only when `exec_order` reorders offsets; it avoids repeated
/// scans of the candidate list by leveraging sorted candidate offsets.
///
/// Assumes `candidate_offsets` is sorted ascending by offset.
pub fn build_candidate_ranges(plan: &PackPlan, ranges: &mut Vec<Option<(usize, usize)>>) {
    // Single pass over sorted offsets; each need offset maps to a contiguous
    // range in `candidate_offsets` (if any). Requires plan invariants:
    // `need_offsets` sorted unique and `candidate_offsets` sorted by offset.
    ranges.clear();
    ranges.resize(plan.need_offsets.len(), None);
    let mut cand_idx = 0usize;
    for (need_idx, &offset) in plan.need_offsets.iter().enumerate() {
        let start = cand_idx;
        while cand_idx < plan.candidate_offsets.len()
            && plan.candidate_offsets[cand_idx].offset == offset
        {
            cand_idx += 1;
        }
        if cand_idx > start {
            ranges[need_idx] = Some((start, cand_idx));
        }
    }
}

#[inline]
fn read_entry_header(
    pack: &PackFile<'_>,
    offset: u64,
    max_header_bytes: usize,
) -> Result<EntryHeader, PackDecodeError> {
    pack.entry_header_at(offset, max_header_bytes)
        .map_err(PackDecodeError::PackParse)
}

#[inline]
fn size_to_usize(size: u64, kind: EntryKind) -> Result<usize, PackDecodeError> {
    usize::try_from(size).map_err(|_| match kind {
        EntryKind::NonDelta { .. } => PackDecodeError::ObjectTooLarge {
            size,
            max: usize::MAX,
        },
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => PackDecodeError::DeltaTooLarge {
            size,
            max: usize::MAX,
        },
    })
}

enum DeltaPayload<'a> {
    Slice(&'a [u8]),
    Spill(BlobSpill),
}

impl DeltaPayload<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Spill(spill) => spill.as_slice(),
        }
    }
}

fn inflate_delta_payload<'a>(
    pack: &PackFile<'_>,
    header: &EntryHeader,
    limits: &PackDecodeLimits,
    spill_dir: &Path,
    inflate_buf: &'a mut Vec<u8>,
) -> Result<DeltaPayload<'a>, PackDecodeError> {
    let delta_size = size_to_usize(header.size, header.kind)?;
    if delta_size <= limits.max_delta_bytes {
        let consumed = inflate_limited(
            pack.slice_from(header.data_start),
            inflate_buf,
            limits.max_delta_bytes,
        )
        .map_err(PackDecodeError::Inflate)?;
        let _ = consumed;
        Ok(DeltaPayload::Slice(inflate_buf.as_slice()))
    } else {
        let mut spill = BlobSpill::new(spill_dir, delta_size)
            .map_err(|_| PackDecodeError::Inflate(super::pack_inflate::InflateError::Backend))?;
        let mut writer = spill.writer();
        inflate_stream(pack.slice_from(header.data_start), delta_size, |chunk| {
            writer
                .write(chunk)
                .map_err(|_| super::pack_inflate::InflateError::Backend)
        })
        .map_err(PackDecodeError::Inflate)?;
        writer
            .finish()
            .map_err(|_| PackDecodeError::Inflate(super::pack_inflate::InflateError::Backend))?;
        Ok(DeltaPayload::Spill(spill))
    }
}

/// Decodes a single offset, using the cache for bases and for storing results.
///
/// Returns `Ok(None)` for non-fatal issues (decode errors, missing bases, or
/// external base provider errors), with the skip recorded in the report.
/// Successful decodes return metadata describing where the bytes reside
/// (cache vs scratch).
#[allow(clippy::too_many_arguments)]
fn decode_offset<'a, B: ExternalBaseProvider>(
    pack: &'a PackFile<'a>,
    offset: u64,
    need_idx: usize,
    need_offsets: &'a [u64],
    limits: &'a PackDecodeLimits,
    max_delta_depth: u8,
    cache: &'a mut PackCache,
    external: &'a mut B,
    delta_deps: &'a [DeltaDep],
    delta_dep_index: &'a [u32],
    report: &'a mut PackExecReport,
    inflate_buf: &'a mut Vec<u8>,
    result_buf: &'a mut Vec<u8>,
    base_buf: &'a mut Vec<u8>,
    delta_stack: &'a mut Vec<DeltaFrame>,
    spill_dir: &'a Path,
) -> Result<Option<DecodedObject>, PackExecError> {
    let header = match read_entry_header(pack, offset, limits.max_header_bytes) {
        Ok(header) => header,
        Err(err) => {
            report.skips.push(SkipRecord {
                offset,
                reason: SkipReason::Decode(err),
            });
            report.stats.skipped_offsets += 1;
            return Ok(None);
        }
    };

    match header.kind {
        EntryKind::NonDelta { kind } => {
            let size = match size_to_usize(header.size, header.kind) {
                Ok(size) => size,
                Err(err) => {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::Decode(err),
                    });
                    report.stats.skipped_offsets += 1;
                    return Ok(None);
                }
            };

            if size <= limits.max_object_bytes {
                result_buf.clear();
                if result_buf.capacity() < size {
                    result_buf.reserve(size - result_buf.capacity());
                }
                let (inflate_res, nanos) =
                    perf::time(|| inflate_entry_payload(pack, &header, result_buf, limits));
                if let Err(err) = inflate_res {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::Decode(err),
                    });
                    report.stats.skipped_offsets += 1;
                    return Ok(None);
                }
                perf::record_pack_inflate(result_buf.len(), nanos);
                report.stats.decoded_offsets += 1;

                if cache.insert(offset, kind, result_buf) {
                    Ok(Some(DecodedObject {
                        kind,
                        storage: DecodedStorage::Cache,
                    }))
                } else {
                    report.stats.record_cache_reject(result_buf.len());
                    Ok(Some(DecodedObject {
                        kind,
                        storage: DecodedStorage::Scratch,
                    }))
                }
            } else {
                let mut spill = BlobSpill::new(spill_dir, size)
                    .map_err(|err| PackExecError::Spill(err.to_string()))?;
                let mut writer = spill.writer();
                let (inflate_res, nanos) = perf::time(|| {
                    inflate_stream(pack.slice_from(header.data_start), size, |chunk| {
                        writer
                            .write(chunk)
                            .map_err(|_| super::pack_inflate::InflateError::Backend)
                    })
                });
                if let Err(err) = inflate_res {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::Decode(PackDecodeError::Inflate(err)),
                    });
                    report.stats.skipped_offsets += 1;
                    return Ok(None);
                }
                writer
                    .finish()
                    .map_err(|err| PackExecError::Spill(err.to_string()))?;
                perf::record_pack_inflate(size, nanos);
                report.stats.decoded_offsets += 1;
                report.stats.record_cache_reject(size);
                report.stats.large_blob_spilled_count =
                    report.stats.large_blob_spilled_count.saturating_add(1);
                report.stats.large_blob_bytes =
                    report.stats.large_blob_bytes.saturating_add(size as u64);

                Ok(Some(DecodedObject {
                    kind,
                    storage: DecodedStorage::Spill(spill),
                }))
            }
        }
        EntryKind::OfsDelta { base_offset } => {
            let (base_kind, storage, out_len) = {
                let base = match cache.get(base_offset) {
                    Some(base) => {
                        report.stats.base_cache_hits += 1;
                        BaseBytes {
                            kind: base.kind,
                            storage: BaseStorage::Slice(base.bytes),
                        }
                    }
                    None => {
                        report.stats.base_cache_misses += 1;
                        let (result, resolve_nanos) = perf::time(|| {
                            decode_base_from_pack(
                                pack,
                                base_offset,
                                need_offsets,
                                limits,
                                max_delta_depth,
                                cache,
                                external,
                                delta_deps,
                                delta_dep_index,
                                report,
                                inflate_buf,
                                result_buf,
                                base_buf,
                                delta_stack,
                                spill_dir,
                            )
                        });
                        record_timing(&mut report.stats.fallback_resolve_nanos, resolve_nanos);
                        match result {
                            Ok(base) => base,
                            Err(reason) => {
                                report.skips.push(SkipRecord { offset, reason });
                                report.stats.skipped_offsets += 1;
                                return Ok(None);
                            }
                        }
                    }
                };

                let (storage, out_len) = match decode_delta_output(
                    pack,
                    &header,
                    base.bytes(),
                    limits,
                    inflate_buf,
                    result_buf,
                    spill_dir,
                ) {
                    Ok(out) => out,
                    Err(err) => {
                        match err {
                            DeltaDecodeError::Decode(err) => {
                                report.skips.push(SkipRecord {
                                    offset,
                                    reason: SkipReason::Decode(err),
                                });
                            }
                            DeltaDecodeError::Delta(err) => {
                                report.skips.push(SkipRecord {
                                    offset,
                                    reason: SkipReason::Delta(err),
                                });
                            }
                        }
                        report.stats.skipped_offsets += 1;
                        return Ok(None);
                    }
                };

                (base.kind, storage, out_len)
            };

            report.stats.decoded_offsets += 1;
            if matches!(&storage, DecodedStorage::Spill(_)) {
                report.stats.large_blob_spilled_count =
                    report.stats.large_blob_spilled_count.saturating_add(1);
                report.stats.large_blob_bytes =
                    report.stats.large_blob_bytes.saturating_add(out_len as u64);
            }
            match storage {
                DecodedStorage::Cache | DecodedStorage::Scratch => {
                    if cache.insert(offset, base_kind, result_buf) {
                        Ok(Some(DecodedObject {
                            kind: base_kind,
                            storage: DecodedStorage::Cache,
                        }))
                    } else {
                        report.stats.record_cache_reject(out_len);
                        Ok(Some(DecodedObject {
                            kind: base_kind,
                            storage: DecodedStorage::Scratch,
                        }))
                    }
                }
                DecodedStorage::Spill(spill) => {
                    report.stats.record_cache_reject(out_len);
                    Ok(Some(DecodedObject {
                        kind: base_kind,
                        storage: DecodedStorage::Spill(spill),
                    }))
                }
            }
        }
        EntryKind::RefDelta { base_oid } => {
            let dep = delta_dep_at_index(delta_deps, delta_dep_index, need_idx);
            match dep.map(|d| d.base) {
                Some(BaseLoc::Offset(base_offset)) => {
                    let (base_kind, storage, out_len) = {
                        let base = match cache.get(base_offset) {
                            Some(base) => {
                                report.stats.base_cache_hits += 1;
                                BaseBytes {
                                    kind: base.kind,
                                    storage: BaseStorage::Slice(base.bytes),
                                }
                            }
                            None => {
                                report.stats.base_cache_misses += 1;
                                let (result, resolve_nanos) = perf::time(|| {
                                    decode_base_from_pack(
                                        pack,
                                        base_offset,
                                        need_offsets,
                                        limits,
                                        max_delta_depth,
                                        cache,
                                        external,
                                        delta_deps,
                                        delta_dep_index,
                                        report,
                                        inflate_buf,
                                        result_buf,
                                        base_buf,
                                        delta_stack,
                                        spill_dir,
                                    )
                                });
                                record_timing(
                                    &mut report.stats.fallback_resolve_nanos,
                                    resolve_nanos,
                                );
                                match result {
                                    Ok(base) => base,
                                    Err(reason) => {
                                        report.skips.push(SkipRecord { offset, reason });
                                        report.stats.skipped_offsets += 1;
                                        return Ok(None);
                                    }
                                }
                            }
                        };

                        let (storage, out_len) = match decode_delta_output(
                            pack,
                            &header,
                            base.bytes(),
                            limits,
                            inflate_buf,
                            result_buf,
                            spill_dir,
                        ) {
                            Ok(out) => out,
                            Err(err) => {
                                match err {
                                    DeltaDecodeError::Decode(err) => {
                                        report.skips.push(SkipRecord {
                                            offset,
                                            reason: SkipReason::Decode(err),
                                        });
                                    }
                                    DeltaDecodeError::Delta(err) => {
                                        report.skips.push(SkipRecord {
                                            offset,
                                            reason: SkipReason::Delta(err),
                                        });
                                    }
                                }
                                report.stats.skipped_offsets += 1;
                                return Ok(None);
                            }
                        };

                        (base.kind, storage, out_len)
                    };

                    report.stats.decoded_offsets += 1;
                    if matches!(&storage, DecodedStorage::Spill(_)) {
                        report.stats.large_blob_spilled_count =
                            report.stats.large_blob_spilled_count.saturating_add(1);
                        report.stats.large_blob_bytes =
                            report.stats.large_blob_bytes.saturating_add(out_len as u64);
                    }
                    match storage {
                        DecodedStorage::Cache | DecodedStorage::Scratch => {
                            if cache.insert(offset, base_kind, result_buf) {
                                Ok(Some(DecodedObject {
                                    kind: base_kind,
                                    storage: DecodedStorage::Cache,
                                }))
                            } else {
                                report.stats.record_cache_reject(out_len);
                                Ok(Some(DecodedObject {
                                    kind: base_kind,
                                    storage: DecodedStorage::Scratch,
                                }))
                            }
                        }
                        DecodedStorage::Spill(spill) => {
                            report.stats.record_cache_reject(out_len);
                            Ok(Some(DecodedObject {
                                kind: base_kind,
                                storage: DecodedStorage::Spill(spill),
                            }))
                        }
                    }
                }
                Some(BaseLoc::External { .. }) | None => {
                    let base_oid = oid_or_base(base_oid, dep.as_ref());
                    report.stats.external_base_calls += 1;
                    match external.load_base(&base_oid) {
                        Ok(Some(base)) => {
                            let base_bytes = BaseBytes {
                                kind: base.kind,
                                storage: BaseStorage::Slice(&base.bytes),
                            };
                            let (storage, out_len) = match decode_delta_output(
                                pack,
                                &header,
                                base_bytes.bytes(),
                                limits,
                                inflate_buf,
                                result_buf,
                                spill_dir,
                            ) {
                                Ok(out) => out,
                                Err(err) => {
                                    match err {
                                        DeltaDecodeError::Decode(err) => {
                                            report.skips.push(SkipRecord {
                                                offset,
                                                reason: SkipReason::Decode(err),
                                            });
                                        }
                                        DeltaDecodeError::Delta(err) => {
                                            report.skips.push(SkipRecord {
                                                offset,
                                                reason: SkipReason::Delta(err),
                                            });
                                        }
                                    }
                                    report.stats.skipped_offsets += 1;
                                    return Ok(None);
                                }
                            };

                            report.stats.decoded_offsets += 1;
                            if matches!(&storage, DecodedStorage::Spill(_)) {
                                report.stats.large_blob_spilled_count =
                                    report.stats.large_blob_spilled_count.saturating_add(1);
                                report.stats.large_blob_bytes =
                                    report.stats.large_blob_bytes.saturating_add(out_len as u64);
                            }
                            match storage {
                                DecodedStorage::Cache | DecodedStorage::Scratch => {
                                    if cache.insert(offset, base.kind, result_buf) {
                                        Ok(Some(DecodedObject {
                                            kind: base.kind,
                                            storage: DecodedStorage::Cache,
                                        }))
                                    } else {
                                        report.stats.record_cache_reject(out_len);
                                        Ok(Some(DecodedObject {
                                            kind: base.kind,
                                            storage: DecodedStorage::Scratch,
                                        }))
                                    }
                                }
                                DecodedStorage::Spill(spill) => {
                                    report.stats.record_cache_reject(out_len);
                                    Ok(Some(DecodedObject {
                                        kind: base.kind,
                                        storage: DecodedStorage::Spill(spill),
                                    }))
                                }
                            }
                        }
                        Ok(None) => {
                            report.skips.push(SkipRecord {
                                offset,
                                reason: SkipReason::ExternalBaseMissing { oid: base_oid },
                            });
                            report.stats.skipped_offsets += 1;
                            Ok(None)
                        }
                        Err(_) => {
                            report.skips.push(SkipRecord {
                                offset,
                                reason: SkipReason::ExternalBaseError,
                            });
                            report.stats.skipped_offsets += 1;
                            Ok(None)
                        }
                    }
                }
            }
        }
    }
}

fn decode_delta_output(
    pack: &PackFile<'_>,
    header: &EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    spill_dir: &Path,
) -> Result<(DecodedStorage, usize), DeltaDecodeError> {
    let (payload_res, inflate_nanos) =
        perf::time(|| inflate_delta_payload(pack, header, limits, spill_dir, inflate_buf));
    let payload = payload_res.map_err(DeltaDecodeError::Decode)?;
    let delta_bytes = payload.as_slice();
    perf::record_pack_inflate(delta_bytes.len(), inflate_nanos);

    let (_, result_size) = delta_sizes(delta_bytes).map_err(DeltaDecodeError::Delta)?;
    if result_size <= limits.max_object_bytes {
        let (apply_res, apply_nanos) = perf::time(|| {
            apply_delta(base_bytes, delta_bytes, result_buf, limits.max_object_bytes)
        });
        if let Err(err) = apply_res {
            return Err(DeltaDecodeError::Delta(err));
        }
        perf::record_delta_apply(result_buf.len(), apply_nanos);
        Ok((DecodedStorage::Scratch, result_buf.len()))
    } else {
        let mut spill = BlobSpill::new(spill_dir, result_size)
            .map_err(|_| DeltaDecodeError::Delta(DeltaError::OutputOverrun))?;
        let mut writer = spill.writer();
        let (apply_res, apply_nanos) = perf::time(|| {
            apply_delta_into(base_bytes, delta_bytes, result_size, |chunk| {
                writer.write(chunk).map_err(|_| DeltaError::OutputOverrun)
            })
        });
        if let Err(err) = apply_res {
            return Err(DeltaDecodeError::Delta(err));
        }
        writer
            .finish()
            .map_err(|_| DeltaDecodeError::Delta(DeltaError::OutputOverrun))?;
        perf::record_delta_apply(result_size, apply_nanos);
        Ok((DecodedStorage::Spill(spill), result_size))
    }
}

/// Resolve the base location for a REF delta at the given offset.
fn resolve_ref_base(
    offset: u64,
    base_oid: OidBytes,
    need_offsets: &[u64],
    delta_deps: &[DeltaDep],
    delta_dep_index: &[u32],
) -> BaseLoc {
    if let Ok(need_idx) = need_offsets.binary_search(&offset) {
        if let Some(dep) = delta_dep_at_index(delta_deps, delta_dep_index, need_idx) {
            return dep.base;
        }
    }
    BaseLoc::External { oid: base_oid }
}

/// Lookup the delta dependency by `need_offsets` index using the dense index.
#[inline]
fn delta_dep_at_index(
    delta_deps: &[DeltaDep],
    delta_dep_index: &[u32],
    need_idx: usize,
) -> Option<DeltaDep> {
    if delta_dep_index.is_empty() {
        return None;
    }
    let idx = *delta_dep_index.get(need_idx)?;
    if idx == NONE_U32 {
        return None;
    }
    delta_deps.get(idx as usize).copied()
}

/// Decode a base object on demand into `base_buf`, following delta chains as needed.
///
/// Returns `SkipReason` for non-fatal failures; callers should record skips
/// on the original offset.
#[allow(clippy::too_many_arguments)]
fn decode_base_from_pack<'a, 'b, B: ExternalBaseProvider>(
    pack: &'a PackFile<'a>,
    offset: u64,
    need_offsets: &'a [u64],
    limits: &'a PackDecodeLimits,
    max_delta_depth: u8,
    cache: &'a mut PackCache,
    external: &'a mut B,
    delta_deps: &'a [DeltaDep],
    delta_dep_index: &'a [u32],
    report: &'a mut PackExecReport,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    base_buf: &'b mut Vec<u8>,
    delta_stack: &mut Vec<DeltaFrame>,
    spill_dir: &Path,
) -> Result<BaseBytes<'b>, SkipReason> {
    if max_delta_depth == 0 {
        return Err(SkipReason::BaseMissing {
            base_offset: offset,
        });
    }

    delta_stack.clear();
    let mut current_offset = offset;
    report.stats.fallback_base_decodes = report.stats.fallback_base_decodes.saturating_add(1);

    loop {
        if delta_stack.len() >= max_delta_depth as usize {
            record_fallback_chain(&mut report.stats, delta_stack.len());
            return Err(SkipReason::BaseMissing {
                base_offset: current_offset,
            });
        }

        let header = match read_entry_header(pack, current_offset, limits.max_header_bytes) {
            Ok(header) => header,
            Err(err) => {
                record_fallback_chain(&mut report.stats, delta_stack.len());
                return Err(SkipReason::Decode(err));
            }
        };

        match header.kind {
            EntryKind::NonDelta { kind } => {
                let size = match size_to_usize(header.size, header.kind) {
                    Ok(size) => size,
                    Err(err) => {
                        record_fallback_chain(&mut report.stats, delta_stack.len());
                        return Err(SkipReason::Decode(err));
                    }
                };

                // Keep oversized bases in a spill-backed mmap instead of RAM.
                let mut base_spill: Option<BlobSpill> = None;
                if size <= limits.max_object_bytes {
                    base_buf.clear();
                    if base_buf.capacity() < size {
                        base_buf.reserve(size - base_buf.capacity());
                    }
                    let (inflate_res, nanos) =
                        perf::time(|| inflate_entry_payload(pack, &header, base_buf, limits));
                    if let Err(err) = inflate_res {
                        record_fallback_chain(&mut report.stats, delta_stack.len());
                        return Err(SkipReason::Decode(err));
                    }
                    perf::record_pack_inflate(base_buf.len(), nanos);
                    report.stats.decoded_offsets += 1;
                    if !cache.insert(current_offset, kind, base_buf) {
                        report.stats.record_cache_reject(base_buf.len());
                    }
                } else {
                    let mut spill = match BlobSpill::new(spill_dir, size) {
                        Ok(spill) => spill,
                        Err(_) => {
                            record_fallback_chain(&mut report.stats, delta_stack.len());
                            return Err(SkipReason::Decode(PackDecodeError::Inflate(
                                super::pack_inflate::InflateError::Backend,
                            )));
                        }
                    };
                    let mut writer = spill.writer();
                    let (inflate_res, nanos) = perf::time(|| {
                        inflate_stream(pack.slice_from(header.data_start), size, |chunk| {
                            writer
                                .write(chunk)
                                .map_err(|_| super::pack_inflate::InflateError::Backend)
                        })
                    });
                    if let Err(err) = inflate_res {
                        record_fallback_chain(&mut report.stats, delta_stack.len());
                        return Err(SkipReason::Decode(PackDecodeError::Inflate(err)));
                    }
                    if writer.finish().is_err() {
                        record_fallback_chain(&mut report.stats, delta_stack.len());
                        return Err(SkipReason::Decode(PackDecodeError::Inflate(
                            super::pack_inflate::InflateError::Backend,
                        )));
                    }
                    perf::record_pack_inflate(size, nanos);
                    report.stats.decoded_offsets += 1;
                    report.stats.record_cache_reject(size);
                    base_spill = Some(spill);
                }

                let base_kind = kind;
                for frame in delta_stack.iter().rev() {
                    let base_bytes = base_spill
                        .as_ref()
                        .map(|spill| spill.as_slice())
                        .unwrap_or_else(|| base_buf.as_slice());
                    let (storage, out_len) = decode_delta_output(
                        pack,
                        &frame.header,
                        base_bytes,
                        limits,
                        inflate_buf,
                        result_buf,
                        spill_dir,
                    )
                    .map_err(|err| {
                        record_fallback_chain(&mut report.stats, delta_stack.len());
                        match err {
                            DeltaDecodeError::Decode(err) => SkipReason::Decode(err),
                            DeltaDecodeError::Delta(err) => SkipReason::Delta(err),
                        }
                    })?;

                    report.stats.decoded_offsets += 1;
                    match storage {
                        DecodedStorage::Cache | DecodedStorage::Scratch => {
                            std::mem::swap(base_buf, result_buf);
                            base_spill = None;
                            if !cache.insert(frame.offset, base_kind, base_buf) {
                                report.stats.record_cache_reject(base_buf.len());
                            }
                        }
                        DecodedStorage::Spill(spill) => {
                            report.stats.record_cache_reject(out_len);
                            base_spill = Some(spill);
                        }
                    }
                }

                record_fallback_chain(&mut report.stats, delta_stack.len());
                let storage = match base_spill {
                    Some(spill) => BaseStorage::Spill(spill),
                    None => BaseStorage::Slice(base_buf.as_slice()),
                };
                return Ok(BaseBytes {
                    kind: base_kind,
                    storage,
                });
            }
            EntryKind::OfsDelta { base_offset } => {
                if base_offset == current_offset {
                    return Err(SkipReason::BaseMissing { base_offset });
                }
                delta_stack.push(DeltaFrame {
                    offset: current_offset,
                    header,
                });
                current_offset = base_offset;
            }
            EntryKind::RefDelta { base_oid } => {
                match resolve_ref_base(
                    current_offset,
                    base_oid,
                    need_offsets,
                    delta_deps,
                    delta_dep_index,
                ) {
                    BaseLoc::Offset(base_offset) => {
                        delta_stack.push(DeltaFrame {
                            offset: current_offset,
                            header,
                        });
                        current_offset = base_offset;
                    }
                    BaseLoc::External { oid } => {
                        delta_stack.push(DeltaFrame {
                            offset: current_offset,
                            header,
                        });
                        report.stats.external_base_calls += 1;
                        match external.load_base(&oid) {
                            Ok(Some(base)) => {
                                let base_len = base.bytes.len();
                                let mut base_spill: Option<BlobSpill> = None;
                                if base_len <= limits.max_object_bytes {
                                    base_buf.clear();
                                    if base_buf.capacity() < base_len {
                                        base_buf.reserve(base_len - base_buf.capacity());
                                    }
                                    base_buf.extend_from_slice(&base.bytes);
                                    report.stats.decoded_offsets += 1;
                                } else {
                                    let mut spill = match BlobSpill::new(spill_dir, base_len) {
                                        Ok(spill) => spill,
                                        Err(_) => {
                                            record_fallback_chain(
                                                &mut report.stats,
                                                delta_stack.len(),
                                            );
                                            return Err(SkipReason::Decode(
                                                PackDecodeError::Inflate(
                                                    super::pack_inflate::InflateError::Backend,
                                                ),
                                            ));
                                        }
                                    };
                                    let mut writer = spill.writer();
                                    if writer.write(&base.bytes).is_err() {
                                        record_fallback_chain(&mut report.stats, delta_stack.len());
                                        return Err(SkipReason::Decode(PackDecodeError::Inflate(
                                            super::pack_inflate::InflateError::Backend,
                                        )));
                                    }
                                    if writer.finish().is_err() {
                                        record_fallback_chain(&mut report.stats, delta_stack.len());
                                        return Err(SkipReason::Decode(PackDecodeError::Inflate(
                                            super::pack_inflate::InflateError::Backend,
                                        )));
                                    }
                                    report.stats.decoded_offsets += 1;
                                    report.stats.record_cache_reject(base_len);
                                    base_spill = Some(spill);
                                };

                                let base_kind = base.kind;
                                for frame in delta_stack.iter().rev() {
                                    let base_bytes = base_spill
                                        .as_ref()
                                        .map(|spill| spill.as_slice())
                                        .unwrap_or_else(|| base_buf.as_slice());
                                    let (storage, out_len) = decode_delta_output(
                                        pack,
                                        &frame.header,
                                        base_bytes,
                                        limits,
                                        inflate_buf,
                                        result_buf,
                                        spill_dir,
                                    )
                                    .map_err(|err| {
                                        record_fallback_chain(&mut report.stats, delta_stack.len());
                                        match err {
                                            DeltaDecodeError::Decode(err) => {
                                                SkipReason::Decode(err)
                                            }
                                            DeltaDecodeError::Delta(err) => SkipReason::Delta(err),
                                        }
                                    })?;

                                    report.stats.decoded_offsets += 1;
                                    match storage {
                                        DecodedStorage::Cache | DecodedStorage::Scratch => {
                                            std::mem::swap(base_buf, result_buf);
                                            base_spill = None;
                                            if !cache.insert(frame.offset, base_kind, base_buf) {
                                                report.stats.record_cache_reject(base_buf.len());
                                            }
                                        }
                                        DecodedStorage::Spill(spill) => {
                                            report.stats.record_cache_reject(out_len);
                                            base_spill = Some(spill);
                                        }
                                    }
                                }

                                record_fallback_chain(&mut report.stats, delta_stack.len());
                                let storage = match base_spill {
                                    Some(spill) => BaseStorage::Spill(spill),
                                    None => BaseStorage::Slice(base_buf.as_slice()),
                                };
                                return Ok(BaseBytes {
                                    kind: base_kind,
                                    storage,
                                });
                            }
                            Ok(None) => {
                                record_fallback_chain(&mut report.stats, delta_stack.len());
                                return Err(SkipReason::ExternalBaseMissing { oid });
                            }
                            Err(_) => {
                                record_fallback_chain(&mut report.stats, delta_stack.len());
                                return Err(SkipReason::ExternalBaseError);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum DeltaDecodeError {
    Decode(PackDecodeError),
    Delta(DeltaError),
}

/// Returns the best OID to query for external bases.
///
/// If the planner resolved a specific external base OID, prefer it over the
/// base OID encoded in the REF delta header.
fn oid_or_base(base_oid: OidBytes, dep: Option<&DeltaDep>) -> OidBytes {
    match dep {
        Some(DeltaDep {
            base: BaseLoc::External { oid },
            ..
        }) => *oid,
        _ => base_oid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::byte_arena::{ByteArena, ByteRef};
    use crate::git_scan::pack_plan_model::{CandidateAtOffset, DeltaKind, PackPlanStats};
    use crate::git_scan::tree_candidate::{CandidateContext, ChangeKind};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::collections::HashMap;
    use std::io::Write;

    #[derive(Default)]
    struct TestSink {
        emitted: Vec<OidBytes>,
    }

    impl PackObjectSink for TestSink {
        fn emit(
            &mut self,
            candidate: &PackCandidate,
            _path: &[u8],
            _bytes: &[u8],
        ) -> Result<(), PackExecError> {
            self.emitted.push(candidate.oid);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CollectingSink {
        blobs: HashMap<OidBytes, Vec<u8>>,
    }

    impl PackObjectSink for CollectingSink {
        fn emit(
            &mut self,
            candidate: &PackCandidate,
            _path: &[u8],
            bytes: &[u8],
        ) -> Result<(), PackExecError> {
            self.blobs.insert(candidate.oid, bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct NoExternal;

    impl ExternalBaseProvider for NoExternal {
        fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
            panic!("unexpected external base lookup in test");
        }
    }

    fn ctx(path_ref: ByteRef) -> CandidateContext {
        CandidateContext {
            commit_id: 1,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        }
    }

    fn encode_entry_header(kind: ObjectKind, size: usize) -> Vec<u8> {
        let obj_type = match kind {
            ObjectKind::Commit => 1u8,
            ObjectKind::Tree => 2u8,
            ObjectKind::Blob => 3u8,
            ObjectKind::Tag => 4u8,
        };
        encode_header_bytes(obj_type, size)
    }

    fn encode_delta_header(obj_type: u8, size: usize) -> Vec<u8> {
        encode_header_bytes(obj_type, size)
    }

    fn encode_header_bytes(obj_type: u8, size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut remaining = size as u64;
        let mut first = ((obj_type & 0x07) << 4) | ((remaining & 0x0f) as u8);
        remaining >>= 4;
        if remaining != 0 {
            first |= 0x80;
        }
        out.push(first);
        while remaining != 0 {
            let mut byte = (remaining & 0x7f) as u8;
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    #[test]
    fn cache_reject_bucket_index_maps_log2() {
        assert_eq!(cache_reject_bucket_index(0), 0);
        assert_eq!(cache_reject_bucket_index(1), 0);
        assert_eq!(cache_reject_bucket_index(2), 1);
        assert_eq!(cache_reject_bucket_index(3), 1);
        assert_eq!(cache_reject_bucket_index(4), 2);
        assert_eq!(cache_reject_bucket_index(7), 2);
        assert_eq!(cache_reject_bucket_index(8), 3);
    }

    fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
        assert!(dist > 0);
        let mut bytes = Vec::new();
        bytes.push((dist & 0x7f) as u8);
        dist >>= 7;
        while dist > 0 {
            dist -= 1;
            bytes.push(((dist & 0x7f) as u8) | 0x80);
            dist >>= 7;
        }
        bytes.reverse();
        bytes
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn build_insert_delta(result: &[u8], base_len: usize) -> Vec<u8> {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(base_len as u64));
        delta.extend_from_slice(&encode_varint(result.len() as u64));

        let mut remaining = result;
        while !remaining.is_empty() {
            let chunk = remaining.len().min(0x7f);
            delta.push(chunk as u8);
            delta.extend_from_slice(&remaining[..chunk]);
            remaining = &remaining[chunk..];
        }

        delta
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn exec_plan<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_indices<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        exec_indices: &[usize],
        candidate_ranges: &[Option<(usize, usize)>],
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_indices(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            exec_indices,
            candidate_ranges,
        )
        .unwrap()
    }

    fn build_pack(entries: &[(ObjectKind, &[u8])]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        let mut offsets = Vec::with_capacity(entries.len());
        for (kind, data) in entries {
            offsets.push(bytes.len() as u64);
            bytes.extend_from_slice(&encode_entry_header(*kind, data.len()));
            bytes.extend_from_slice(&compress(data));
        }

        bytes.extend_from_slice(&[0u8; 20]);
        (bytes, offsets)
    }

    fn candidate_span(offsets: &[CandidateAtOffset]) -> u64 {
        if offsets.is_empty() {
            0
        } else {
            let first = offsets.first().unwrap().offset;
            let last = offsets.last().unwrap().offset;
            last.saturating_sub(first)
        }
    }

    fn build_delta_dep_index(need_offsets: &[u64], delta_deps: &[DeltaDep]) -> Vec<u32> {
        let mut index = vec![NONE_U32; need_offsets.len()];
        if delta_deps.is_empty() {
            return index;
        }
        let mut dep_idx = 0usize;
        for (need_idx, &offset) in need_offsets.iter().enumerate() {
            while dep_idx < delta_deps.len() && delta_deps[dep_idx].offset < offset {
                dep_idx += 1;
            }
            if dep_idx < delta_deps.len() && delta_deps[dep_idx].offset == offset {
                index[need_idx] = dep_idx as u32;
                dep_idx += 1;
            }
        }
        index
    }

    fn build_plan(
        need_offsets: Vec<u64>,
        candidates: Vec<PackCandidate>,
        candidate_offsets: Vec<CandidateAtOffset>,
        exec_order: Option<Vec<u32>>,
    ) -> PackPlan {
        let stats = PackPlanStats {
            candidate_count: candidates.len() as u32,
            need_count: need_offsets.len() as u32,
            external_bases: 0,
            forward_deps: exec_order.as_ref().map_or(0, |_| 1),
            candidate_span: candidate_span(&candidate_offsets),
        };

        PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates,
            candidate_offsets,
            need_offsets,
            delta_deps: Vec::new(),
            delta_dep_index: vec![NONE_U32; stats.need_count as usize],
            exec_order,
            stats,
        }
    }

    #[test]
    fn merge_fast_path_emits_single_candidate() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x11; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(sink.emitted.len(), 1);
    }

    #[test]
    fn large_non_delta_blob_spills_and_scans() {
        let data = vec![b'a'; 64];
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, data.as_slice())]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x12; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();
        let limits = PackDecodeLimits::new(64, 16, 1024);

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(report.stats.large_blob_spilled_count, 1);
        assert_eq!(report.stats.large_blob_bytes, data.len() as u64);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(data.as_slice())
        );
    }

    #[test]
    fn large_delta_blob_spills_and_scans() {
        let base_bytes = b"base";
        let result_bytes = vec![b'Z'; 64];
        let delta_payload = build_insert_delta(&result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, base_bytes.len()));
        pack.extend_from_slice(&compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x13; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
            },
        };

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();
        let limits = PackDecodeLimits::new(64, 16, 1024);

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(report.stats.large_blob_spilled_count, 1);
        assert_eq!(report.stats.large_blob_bytes, result_bytes.len() as u64);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn merge_fast_path_emits_multiple_candidates_at_same_offset() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset,
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset,
            },
        ];

        let plan = build_plan(
            vec![offset],
            candidates,
            vec![
                CandidateAtOffset {
                    offset,
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset,
                    cand_idx: 1,
                },
            ],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 2);
        assert_eq!(sink.emitted.len(), 2);
    }

    #[test]
    fn merge_fast_path_skips_non_blob_candidates() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Tree, b"tree")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x33; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 0);
        assert_eq!(report.skips.len(), 1);
        assert!(matches!(report.skips[0].reason, SkipReason::NotBlob));
    }

    #[test]
    fn out_of_order_exec_uses_candidate_ranges() {
        let (pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            Some(vec![1, 0]),
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 2);
        assert_eq!(
            sink.emitted,
            vec![OidBytes::sha1([0x22; 20]), OidBytes::sha1([0x11; 20])]
        );
    }

    #[test]
    fn shard_exec_matches_sequential_order() {
        let (pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report_seq = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );
        let emitted_seq = sink.emitted.clone();

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [0usize, 1usize];

        let mut shard_reports = Vec::new();
        let mut shard_emitted = Vec::new();
        for shard in exec_indices.chunks(1) {
            let mut cache = PackCache::new(0);
            let mut external = NoExternal;
            let mut sink = TestSink::default();
            let mut scratch = PackExecScratch::default();
            let report = exec_plan_indices(
                &plan,
                &pack,
                &arena,
                &PackDecodeLimits::new(64, 1024, 1024),
                &mut cache,
                &mut external,
                &mut sink,
                &mut scratch,
                shard,
                &candidate_ranges,
            );
            shard_reports.push(report);
            shard_emitted.extend(sink.emitted);
        }

        let merged = merge_pack_exec_reports(shard_reports);
        assert_eq!(
            merged.stats.emitted_candidates,
            report_seq.stats.emitted_candidates
        );
        assert_eq!(shard_emitted, emitted_seq);
    }

    #[test]
    fn shard_exec_decodes_delta_without_base_cached() {
        let base_bytes = b"";
        let result_bytes = b"TOK_ABCDEFGH";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, base_bytes.len()));
        pack.extend_from_slice(&compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x66; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
            },
        };

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [1usize];

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();
        let mut scratch = PackExecScratch::default();
        let report = exec_plan_indices(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
            &mut scratch,
            &exec_indices,
            &candidate_ranges,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(sink.emitted, vec![OidBytes::sha1([0x66; 20])]);
    }

    #[test]
    fn delta_inflate_error_skips_without_emitting() {
        let base_bytes = b"BASE";

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, base_bytes.len()));
        pack.extend_from_slice(&compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(6, 4);
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&[0x78]); // truncated zlib stream
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x44; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
            },
        };

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 0);
        assert!(report.skips.iter().any(|skip| {
            matches!(skip.reason, SkipReason::Decode(PackDecodeError::Inflate(_)))
        }));
        assert!(cache.get(delta_offset).is_none());
    }

    #[test]
    fn ofs_delta_chain_decodes_within_limit() {
        let base_bytes = b"";
        let result_bytes = b"TOK_ABCDEFGH";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, base_bytes.len()));
        pack.extend_from_slice(&compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x55; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
            },
        };

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn ofs_delta_fallback_decodes_without_cache() {
        let base_bytes = b"base";
        let result_bytes = b"TOK_FALLBACK1";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, base_bytes.len()));
        pack.extend_from_slice(&compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x58; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
            },
        };

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn ref_delta_external_base_decodes_within_limit() {
        let base_bytes = b"";
        let result_bytes = b"TOK_QWERTY12";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let base_oid = OidBytes::sha1([0x33; 20]);

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_delta_header(7, delta_payload.len());
        delta_entry.extend_from_slice(base_oid.as_slice());
        delta_entry.extend_from_slice(&compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x66; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::External { oid: base_oid },
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 1,
                forward_deps: 0,
                candidate_span: 0,
            },
        };

        struct ExternalBaseProviderImpl {
            base_oid: OidBytes,
            base_bytes: Vec<u8>,
        }

        impl ExternalBaseProvider for ExternalBaseProviderImpl {
            fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
                if *oid == self.base_oid {
                    Ok(Some(ExternalBase {
                        kind: ObjectKind::Blob,
                        bytes: self.base_bytes.clone(),
                    }))
                } else {
                    Ok(None)
                }
            }
        }

        let mut cache = PackCache::new(64 * 1024);
        let mut external = ExternalBaseProviderImpl {
            base_oid,
            base_bytes: base_bytes.to_vec(),
        };
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn truncated_non_delta_stream_is_skipped() {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header(ObjectKind::Blob, 4));
        pack.extend_from_slice(&[0x78]); // truncated zlib stream
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x77; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 0);
        assert!(matches!(
            report.skips[0].reason,
            SkipReason::Decode(PackDecodeError::Inflate(_))
        ));
    }

    #[test]
    fn corrupt_pack_header_is_skipped() {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let offset = pack.len() as u64;
        pack.push(0x80); // header continuation without following bytes
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x88; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_eq!(report.stats.emitted_candidates, 0);
        assert!(matches!(
            report.skips[0].reason,
            SkipReason::Decode(PackDecodeError::PackParse(_))
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn alloc_guard_no_alloc_after_warmup() {
        use crate::git_scan::alloc_guard;
        use crate::git_scan::{EngineAdapter, EngineAdapterConfig};
        use crate::{
            demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId,
            TransformMode, ValidatorKind,
        };
        use regex::bytes::Regex;

        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                alloc_guard::set_enabled(false);
            }
        }

        if std::env::var("SCANNER_RS_ALLOC_GUARD").ok().as_deref() != Some("1") {
            eprintln!(
                "alloc guard test skipped; set SCANNER_RS_ALLOC_GUARD=1 and \
run with --test-threads=1 to enable"
            );
            return;
        }

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

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            transforms,
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"TOK_ABCDEFGH")]);
        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x55; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: offsets[0],
        };

        let plan = build_plan(
            vec![offsets[0]],
            vec![candidate],
            vec![CandidateAtOffset {
                offset: offsets[0],
                cand_idx: 0,
            }],
            None,
        );

        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        adapter.reserve_results(1);
        adapter.reserve_findings(8);
        adapter.reserve_findings_buf(8);

        alloc_guard::set_enabled(false);
        let mut warm_cache = PackCache::new(64 * 1024);
        let mut warm_external = NoExternal;
        let _warm = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut warm_cache,
            &mut warm_external,
            &mut adapter,
        );
        adapter.clear_results();

        alloc_guard::set_enabled(true);
        let _reset = Reset;

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut adapter,
        );

        assert_eq!(report.stats.emitted_candidates, 1);
        let scanned = adapter.take_results();
        assert_eq!(scanned.blobs.len(), 1);
        assert!(!scanned.finding_arena.is_empty());
    }
}
