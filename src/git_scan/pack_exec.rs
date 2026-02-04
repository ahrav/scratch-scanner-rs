//! Pack plan executor.
//!
//! Decodes pack objects in plan order, applies deltas with bounded buffers,
//! and emits decoded blob bytes to a caller-provided sink. All skips are
//! recorded with explicit reasons.
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
    PackParse(PackParseError),
    Sink(String),
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
    PackParse(PackParseError),
    Decode(PackDecodeError),
    Delta(DeltaError),
    BaseMissing { base_offset: u64 },
    ExternalBaseMissing { oid: OidBytes },
    ExternalBaseError,
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
    /// Offsets successfully decoded (including bases).
    pub decoded_offsets: u32,
    /// Candidates emitted to the sink.
    pub emitted_candidates: u32,
    /// Offsets skipped for any reason.
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
    pub stats: PackExecStats,
    /// Per-offset skip records (may include repeated offsets).
    pub skips: Vec<SkipRecord>,
}

/// Where the decoded bytes live after `decode_offset`.
#[derive(Clone, Copy, Debug)]
enum DecodedStorage {
    Cache,
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
/// The returned report includes both successful decode stats and per-offset
/// skip reasons for non-fatal failures (decode errors, missing bases, and
/// external base provider errors).
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
    let pack = PackFile::parse(pack_bytes, plan.oid_len as usize)?;
    let mut report = PackExecReport::default();
    report
        .skips
        .reserve(plan.candidate_offsets.len().min(u32::MAX as usize));

    let alloc_guard_enabled = alloc_guard::enabled();

    let mut delta_map: HashMap<u64, DeltaDep> = HashMap::with_capacity(plan.delta_deps.len());
    for dep in &plan.delta_deps {
        delta_map.insert(dep.offset, *dep);
    }

    let mut inflate_buf: Vec<u8> = Vec::with_capacity(limits.max_delta_bytes.max(1024));
    let mut result_buf: Vec<u8> = Vec::with_capacity(limits.max_object_bytes.max(1024));

    let mut handle_idx = |idx: usize, range: Option<(usize, usize)>| -> Result<(), PackExecError> {
        let guard = if alloc_guard_enabled {
            Some(AllocGuard::new())
        } else {
            None
        };
        let offset = plan.need_offsets[idx];

        let decoded = if cache.get(offset).is_some() {
            report.stats.cache_hits += 1;
            Some(DecodedObject {
                kind: cache.get(offset).expect("cache hit").kind,
                storage: DecodedStorage::Cache,
            })
        } else {
            report.stats.cache_misses += 1;
            decode_offset(
                &pack,
                offset,
                limits,
                cache,
                external,
                &delta_map,
                &mut report,
                &mut inflate_buf,
                &mut result_buf,
            )?
        };

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

        if let Some((start, end)) = range {
            for cand_idx in start..end {
                let candidate =
                    &plan.candidates[plan.candidate_offsets[cand_idx].cand_idx as usize];
                if obj.kind != ObjectKind::Blob {
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
        let candidate_ranges = build_candidate_ranges(plan);
        for &idx in order {
            let idx = idx as usize;
            handle_idx(idx, candidate_ranges[idx])?;
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
fn build_candidate_ranges(plan: &PackPlan) -> Vec<Option<(usize, usize)>> {
    let mut ranges = vec![None; plan.need_offsets.len()];
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
    ranges
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
            if let Err(err) = inflate_entry_payload(pack, &header, result_buf, limits) {
                report.skips.push(SkipRecord {
                    offset,
                    reason: SkipReason::Decode(err),
                });
                report.stats.skipped_offsets += 1;
                return Ok(None);
            }
            report.stats.decoded_offsets += 1;

            if cache.insert(offset, kind, result_buf) {
                Ok(Some(DecodedObject {
                    kind,
                    storage: DecodedStorage::Cache,
                }))
            } else {
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
    if let Err(err) = inflate_entry_payload(pack, &header, inflate_buf, limits) {
        return Err(DeltaDecodeError::Decode(err));
    }

    result_buf.clear();
    if result_buf.capacity() < header.size as usize {
        result_buf.reserve(header.size as usize - result_buf.capacity());
    }

    apply_delta(
        base_bytes,
        inflate_buf,
        result_buf,
        header.size as usize,
        limits.max_object_bytes,
    )
    .map_err(DeltaDecodeError::Delta)
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
}
