//! Pack plan executor.
//!
//! Decodes pack objects in plan order, applies deltas with bounded buffers,
//! and emits decoded blob bytes to a caller-provided sink. All skips are
//! recorded with explicit reasons.
//!
//! # Execution model
//! - Offsets are decoded at most once and may be cached for reuse.
//! - `inflate_buf` and `result_buf` are reused across offsets to avoid
//!   repeated allocations on the hot path.
//! - When the allocation guard is enabled, per-offset decoding and sink
//!   emission must not allocate.
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

use std::collections::HashMap;
use std::fmt;

use crate::scheduler::AllocGuard;

use super::alloc_guard;
use super::byte_arena::ByteArena;
use super::object_id::OidBytes;
use super::pack_cache::PackCache;
use super::pack_candidates::PackCandidate;
use super::pack_decode::{
    entry_header_at, inflate_entry_payload, PackDecodeError, PackDecodeLimits,
};
use super::pack_delta::apply_delta;
use super::pack_inflate::{DeltaError, EntryKind, ObjectKind, PackFile, PackParseError};
use super::pack_plan_model::{BaseLoc, DeltaDep, PackPlan};
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
    /// The sink rejected an emitted blob.
    Sink(String),
    /// External base provider returned a fatal error.
    ExternalBase(String),
}

impl fmt::Display for PackExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::Sink(msg) => write!(f, "sink error: {msg}"),
            Self::ExternalBase(msg) => write!(f, "external base error: {msg}"),
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
    /// Cache hits on pack offsets.
    pub cache_hits: u32,
    /// Cache misses on pack offsets.
    pub cache_misses: u32,
    /// External base provider calls for REF deltas.
    pub external_base_calls: u32,
}

/// Pack execution report.
#[derive(Debug, Default)]
pub struct PackExecReport {
    /// Aggregate stats for this pack execution.
    pub stats: PackExecStats,
    /// Per-offset skip records (may include repeated offsets), in execution order.
    pub skips: Vec<SkipRecord>,
}

/// Reusable scratch buffers for pack execution.
#[derive(Debug, Default)]
pub struct PackExecScratch {
    delta_map: HashMap<u64, DeltaDep>,
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    candidate_ranges: Vec<Option<(usize, usize)>>,
}

impl PackExecScratch {
    /// Prepares scratch buffers for the given plan and decode limits.
    fn prepare(&mut self, plan: &PackPlan, limits: &PackDecodeLimits) {
        self.delta_map.clear();
        self.delta_map.reserve(plan.delta_deps.len());
        for dep in &plan.delta_deps {
            self.delta_map.insert(dep.offset, *dep);
        }

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
        self.candidate_ranges.clear();
    }
}

/// Where the decoded bytes live after `decode_offset`.
#[derive(Clone, Copy, Debug)]
enum DecodedStorage {
    /// Bytes are stored in the `PackCache`.
    Cache,
    /// Bytes are stored in the scratch buffer passed to the decoder.
    Scratch,
}

/// Metadata for a decoded offset (kind + storage location).
#[derive(Clone, Copy, Debug)]
struct DecodedObject {
    kind: ObjectKind,
    storage: DecodedStorage,
}

/// Executes a pack plan against pack bytes.
///
/// The plan's `exec_order` is respected when present to satisfy forward
/// delta dependencies. Pack bytes must contain the full pack file.
///
/// `paths` must contain all path refs referenced by plan candidates.
/// `cache` is updated with decoded objects when capacity allows.
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
    scratch: &mut PackExecScratch,
) -> Result<PackExecReport, PackExecError> {
    let pack = PackFile::parse(pack_bytes, plan.oid_len as usize)?;
    let mut report = PackExecReport::default();
    report
        .skips
        .reserve(plan.candidate_offsets.len().min(u32::MAX as usize));

    let alloc_guard_enabled = alloc_guard::enabled();

    scratch.prepare(plan, limits);
    let delta_map = &scratch.delta_map;
    let inflate_buf = &mut scratch.inflate_buf;
    let result_buf = &mut scratch.result_buf;

    let mut handle_idx = |idx: usize, range: Option<(usize, usize)>| -> Result<(), PackExecError> {
        let guard = if alloc_guard_enabled {
            Some(AllocGuard::new())
        } else {
            None
        };
        let offset = plan.need_offsets[idx];

        let (obj_kind, bytes) = if let Some(hit) = cache.get(offset) {
            report.stats.cache_hits += 1;
            perf::record_cache_hit();
            (hit.kind, hit.bytes)
        } else {
            report.stats.cache_misses += 1;
            perf::record_cache_miss();
            let decoded = decode_offset(
                &pack,
                offset,
                limits,
                cache,
                external,
                delta_map,
                &mut report,
                inflate_buf,
                result_buf,
            )?;

            let Some(obj) = decoded else {
                return Ok(());
            };

            let bytes = match obj.storage {
                DecodedStorage::Cache => cache
                    .get(offset)
                    .map(|hit| hit.bytes)
                    .unwrap_or(result_buf.as_slice()),
                DecodedStorage::Scratch => result_buf.as_slice(),
            };

            (obj.kind, bytes)
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
                sink.emit(candidate, path, bytes)?;
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

/// Build candidate index ranges for each `need_offsets` entry.
///
/// This is used only when `exec_order` reorders offsets; it avoids repeated
/// scans of the candidate list by leveraging sorted candidate offsets.
fn build_candidate_ranges(plan: &PackPlan, ranges: &mut Vec<Option<(usize, usize)>>) {
    // Single pass over sorted offsets; each need offset maps to a contiguous
    // range in `candidate_offsets` (if any).
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
    limits: &'a PackDecodeLimits,
    cache: &'a mut PackCache,
    external: &'a mut B,
    delta_map: &'a HashMap<u64, DeltaDep>,
    report: &'a mut PackExecReport,
    inflate_buf: &'a mut Vec<u8>,
    result_buf: &'a mut Vec<u8>,
) -> Result<Option<DecodedObject>, PackExecError> {
    let header = match entry_header_at(pack, offset, limits) {
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
            result_buf.clear();
            if result_buf.capacity() < header.size as usize {
                result_buf.reserve(header.size as usize - result_buf.capacity());
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
                // Cache refused the insert; bytes remain in `result_buf`.
                Ok(Some(DecodedObject {
                    kind,
                    storage: DecodedStorage::Scratch,
                }))
            }
        }
        EntryKind::OfsDelta { base_offset } => {
            let base_kind = {
                let base = match cache.get(base_offset) {
                    Some(base) => base,
                    None => {
                        report.skips.push(SkipRecord {
                            offset,
                            reason: SkipReason::BaseMissing { base_offset },
                        });
                        report.stats.skipped_offsets += 1;
                        return Ok(None);
                    }
                };

                if let Err(err) = decode_delta_entry(
                    pack,
                    offset,
                    header,
                    base.bytes,
                    limits,
                    inflate_buf,
                    result_buf,
                ) {
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
                base.kind
            };

            report.stats.decoded_offsets += 1;
            if cache.insert(offset, base_kind, result_buf) {
                Ok(Some(DecodedObject {
                    kind: base_kind,
                    storage: DecodedStorage::Cache,
                }))
            } else {
                // Cache refused the insert; bytes remain in `result_buf`.
                Ok(Some(DecodedObject {
                    kind: base_kind,
                    storage: DecodedStorage::Scratch,
                }))
            }
        }
        EntryKind::RefDelta { base_oid } => {
            let dep = delta_map.get(&offset);
            match dep.map(|d| d.base) {
                Some(BaseLoc::Offset(base_offset)) => {
                    let base_kind = {
                        let base = match cache.get(base_offset) {
                            Some(base) => base,
                            None => {
                                report.skips.push(SkipRecord {
                                    offset,
                                    reason: SkipReason::BaseMissing { base_offset },
                                });
                                report.stats.skipped_offsets += 1;
                                return Ok(None);
                            }
                        };
                        if let Err(err) = decode_delta_entry(
                            pack,
                            offset,
                            header,
                            base.bytes,
                            limits,
                            inflate_buf,
                            result_buf,
                        ) {
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
                        base.kind
                    };

                    report.stats.decoded_offsets += 1;
                    if cache.insert(offset, base_kind, result_buf) {
                        Ok(Some(DecodedObject {
                            kind: base_kind,
                            storage: DecodedStorage::Cache,
                        }))
                    } else {
                        Ok(Some(DecodedObject {
                            kind: base_kind,
                            storage: DecodedStorage::Scratch,
                        }))
                    }
                }
                Some(BaseLoc::External { .. }) | None => {
                    let base_oid = oid_or_base(base_oid, dep);
                    report.stats.external_base_calls += 1;
                    match external.load_base(&base_oid) {
                        Ok(Some(base)) => {
                            if let Err(err) = decode_delta_entry(
                                pack,
                                offset,
                                header,
                                &base.bytes,
                                limits,
                                inflate_buf,
                                result_buf,
                            ) {
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

                            report.stats.decoded_offsets += 1;
                            if cache.insert(offset, base.kind, result_buf) {
                                Ok(Some(DecodedObject {
                                    kind: base.kind,
                                    storage: DecodedStorage::Cache,
                                }))
                            } else {
                                // Cache refused the insert; bytes remain in `result_buf`.
                                Ok(Some(DecodedObject {
                                    kind: base.kind,
                                    storage: DecodedStorage::Scratch,
                                }))
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

/// Inflates a delta payload and applies it to the provided base.
///
/// Decode errors are returned to the caller for skip tracking; delta
/// application errors surface as `DeltaError`.
#[allow(clippy::too_many_arguments)]
fn decode_delta_entry(
    pack: &PackFile<'_>,
    _offset: u64,
    header: super::pack_inflate::EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
) -> Result<(), DeltaDecodeError> {
    inflate_buf.clear();
    if inflate_buf.capacity() < limits.max_delta_bytes {
        inflate_buf.reserve(limits.max_delta_bytes - inflate_buf.capacity());
    }
    let (inflate_res, inflate_nanos) =
        perf::time(|| inflate_entry_payload(pack, &header, inflate_buf, limits));
    if let Err(err) = inflate_res {
        return Err(DeltaDecodeError::Decode(err));
    }
    perf::record_pack_inflate(inflate_buf.len(), inflate_nanos);

    result_buf.clear();
    let (apply_res, apply_nanos) =
        perf::time(|| apply_delta(base_bytes, inflate_buf, result_buf, limits.max_object_bytes));
    match apply_res {
        Ok(()) => {
            perf::record_delta_apply(result_buf.len(), apply_nanos);
            Ok(())
        }
        Err(err) => Err(DeltaDecodeError::Delta(err)),
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
            candidates,
            candidate_offsets,
            need_offsets,
            delta_deps: Vec::new(),
            exec_order,
            clusters: Vec::new(),
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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

        assert_eq!(report.stats.emitted_candidates, 1);
        assert_eq!(sink.emitted.len(), 1);
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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

        assert_eq!(report.stats.emitted_candidates, 2);
        assert_eq!(
            sink.emitted,
            vec![OidBytes::sha1([0x22; 20]), OidBytes::sha1([0x11; 20])]
        );
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

        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets: vec![base_offset, delta_offset],
            delta_deps: vec![DeltaDep {
                offset: delta_offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(base_offset),
            }],
            exec_order: None,
            clusters: Vec::new(),
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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets: vec![base_offset, delta_offset],
            delta_deps: vec![DeltaDep {
                offset: delta_offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(base_offset),
            }],
            exec_order: None,
            clusters: Vec::new(),
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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets: vec![delta_offset],
            delta_deps: vec![DeltaDep {
                offset: delta_offset,
                kind: DeltaKind::Ref,
                base: BaseLoc::External { oid: base_oid },
            }],
            exec_order: None,
            clusters: Vec::new(),
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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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

        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        )
        .unwrap();

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
        let _warm = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut warm_cache,
            &mut warm_external,
            &mut adapter,
        )
        .unwrap();
        adapter.clear_results();

        alloc_guard::set_enabled(true);
        let _reset = Reset;

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let report = execute_pack_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut adapter,
        )
        .unwrap();

        assert_eq!(report.stats.emitted_candidates, 1);
        let scanned = adapter.take_results();
        assert_eq!(scanned.blobs.len(), 1);
        assert!(!scanned.finding_arena.is_empty());
    }
}
