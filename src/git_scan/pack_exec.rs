//! Pack plan executor.
//!
//! Decodes pack objects in plan order, applies deltas with bounded buffers,
//! and emits decoded blob bytes to a caller-provided sink. All skips are
//! recorded with explicit reasons.
//!
//! The executor treats decode failures as per-offset skips and only returns
//! fatal errors for pack parsing, sink failures, or external base loading
//! errors.

use std::collections::HashMap;
use std::fmt;

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
use super::pack_strategy::PackStrategy;

/// External base object for REF deltas.
///
/// The bytes should contain the fully inflated base object.
#[derive(Debug)]
pub struct ExternalBase {
    pub kind: ObjectKind,
    pub bytes: Vec<u8>,
}

/// Provider for external REF delta bases.
pub trait ExternalBaseProvider {
    /// Returns the base object for a given OID, or `None` if missing.
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError>;
}

/// Sink for decoded pack blobs.
pub trait PackObjectSink {
    /// Receives a decoded blob candidate.
    ///
    /// The `bytes` slice is only valid for the duration of the call.
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
    pub skips: Vec<SkipRecord>,
}

#[derive(Clone, Copy, Debug)]
/// Where the decoded bytes live after `decode_offset`.
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
/// # Errors
/// - `PackExecError::PackParse` for invalid pack headers.
/// - `PackExecError::ExternalBase` for external base loader failures.
/// - `PackExecError::Sink` for sink failures.
pub fn execute_pack_plan<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
) -> Result<PackExecReport, PackExecError> {
    execute_pack_plan_with_strategy(
        plan,
        pack_bytes,
        paths,
        limits,
        cache,
        external,
        sink,
        PackStrategy::Sparse,
    )
}

/// Executes a pack plan with an explicit strategy.
///
/// `PackStrategy::Sparse` respects `plan.exec_order` when present. Linear
/// mode enforces pack-order execution and should only be used when the plan
/// has no forward dependencies.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_strategy<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    strategy: PackStrategy,
) -> Result<PackExecReport, PackExecError> {
    let pack = PackFile::parse(pack_bytes, plan.oid_len as usize)?;
    let mut report = PackExecReport::default();

    let mut delta_map: HashMap<u64, DeltaDep> = HashMap::with_capacity(plan.delta_deps.len());
    for dep in &plan.delta_deps {
        delta_map.insert(dep.offset, *dep);
    }

    // Map each need_offset index to the candidate indices that share it.
    let mut candidate_ranges = vec![None; plan.need_offsets.len()];
    let mut cand_idx = 0usize;
    for (need_idx, &offset) in plan.need_offsets.iter().enumerate() {
        let start = cand_idx;
        while cand_idx < plan.candidate_offsets.len()
            && plan.candidate_offsets[cand_idx].offset == offset
        {
            cand_idx += 1;
        }
        if cand_idx > start {
            candidate_ranges[need_idx] = Some((start, cand_idx));
        }
    }

    let indices = execution_indices(plan, strategy);

    let mut inflate_buf: Vec<u8> = Vec::with_capacity(limits.max_delta_bytes.max(1024));
    let mut result_buf: Vec<u8> = Vec::with_capacity(limits.max_object_bytes.max(1024));

    for idx in indices {
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
            continue;
        };

        let bytes = match obj.storage {
            DecodedStorage::Cache => cache
                .get(offset)
                .map(|hit| hit.bytes)
                .unwrap_or(result_buf.as_slice()),
            DecodedStorage::Scratch => result_buf.as_slice(),
        };

        if let Some((start, end)) = candidate_ranges[idx] {
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
    }

    sink.finish()?;
    Ok(report)
}

fn execution_indices(plan: &PackPlan, strategy: PackStrategy) -> Vec<usize> {
    match strategy {
        PackStrategy::Sparse => plan
            .exec_order
            .as_ref()
            .map(|order| order.iter().map(|&idx| idx as usize).collect())
            .unwrap_or_else(|| (0..plan.need_offsets.len()).collect()),
        PackStrategy::Linear => (0..plan.need_offsets.len()).collect(),
    }
}

/// Decodes a single offset, using the cache for bases and for storing results.
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
                    report,
                    inflate_buf,
                    result_buf,
                ) {
                    report.skips.push(SkipRecord {
                        offset,
                        reason: SkipReason::Delta(err),
                    });
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
                            report,
                            inflate_buf,
                            result_buf,
                        ) {
                            report.skips.push(SkipRecord {
                                offset,
                                reason: SkipReason::Delta(err),
                            });
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
                                report,
                                inflate_buf,
                                result_buf,
                            ) {
                                report.skips.push(SkipRecord {
                                    offset,
                                    reason: SkipReason::Delta(err),
                                });
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
#[allow(clippy::too_many_arguments)]
fn decode_delta_entry(
    pack: &PackFile<'_>,
    offset: u64,
    header: super::pack_inflate::EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
    report: &mut PackExecReport,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
) -> Result<(), DeltaError> {
    inflate_buf.clear();
    if inflate_buf.capacity() < limits.max_delta_bytes {
        inflate_buf.reserve(limits.max_delta_bytes - inflate_buf.capacity());
    }
    if let Err(err) = inflate_entry_payload(pack, &header, inflate_buf, limits) {
        report.skips.push(SkipRecord {
            offset,
            reason: SkipReason::Decode(err),
        });
        report.stats.skipped_offsets += 1;
        return Ok(());
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
    )?;

    Ok(())
}

/// Returns the best OID to query for external bases.
fn oid_or_base(base_oid: OidBytes, dep: Option<&DeltaDep>) -> OidBytes {
    match dep {
        Some(DeltaDep {
            base: BaseLoc::External { oid },
            ..
        }) => *oid,
        _ => base_oid,
    }
}
