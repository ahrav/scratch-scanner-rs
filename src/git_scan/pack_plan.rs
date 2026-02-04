//! Pack planning for pack decode.
//!
//! Builds per-pack plans that describe which offsets must be decoded to
//! satisfy candidate blobs, including pack-local delta bases up to a
//! configured depth. The plan also records delta dependencies and basic
//! clustering hints for later execution strategies.
//!
//! REF deltas whose base is missing from the current pack are treated as
//! external dependencies and are not expanded further.
//!
//! # Algorithm
//! 1. Group candidates by `pack_id`.
//! 2. Parse entry headers for candidate offsets and resolve REF deltas.
//! 3. Expand a pack-local base closure up to `max_delta_depth`.
//! 4. Materialize sorted `need_offsets`, delta dependencies, exec order,
//!    and (optionally) offset clusters.
//!
//! # Invariants
//! - `need_offsets` is sorted and unique.
//! - `candidate_offsets` is sorted by offset (ties by candidate index).
//! - `exec_order` indices refer to `need_offsets`.
//! - `clusters` are contiguous ranges within `need_offsets` split by
//!   `CLUSTER_GAP_BYTES` when clustering is enabled.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_candidates::PackCandidate;
use super::pack_inflate::{EntryKind, PackFile, PackParseError};
use super::pack_plan_model::{
    BaseLoc, CandidateAtOffset, Cluster, DeltaDep, DeltaKind, PackPlan, PackPlanStats,
    CLUSTER_GAP_BYTES,
};

/// Default safety bound for pack entry headers.
const DEFAULT_MAX_HEADER_BYTES: usize = 64;
/// Default maximum delta chain depth.
const DEFAULT_MAX_DELTA_DEPTH: u8 = 16;
/// Default maximum offsets tracked during planning.
const DEFAULT_MAX_WORKLIST_ENTRIES: usize = 1_000_000;
/// Default maximum REF base lookups during planning.
const DEFAULT_MAX_BASE_LOOKUPS: usize = 1_000_000;

/// Config for pack planning.
///
/// `max_delta_depth` counts delta edges from a candidate to its base.
/// A depth of 0 disables base expansion entirely.
#[derive(Clone, Copy, Debug)]
pub struct PackPlanConfig {
    /// Maximum delta chain depth to traverse (0 disables base expansion).
    pub max_delta_depth: u8,
    /// Safety bound for header parsing.
    pub max_header_bytes: usize,
    /// Maximum number of unique offsets tracked during planning.
    pub max_worklist_entries: usize,
    /// Maximum REF base lookups during planning.
    pub max_base_lookups: usize,
}

impl Default for PackPlanConfig {
    fn default() -> Self {
        Self {
            max_delta_depth: DEFAULT_MAX_DELTA_DEPTH,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_worklist_entries: DEFAULT_MAX_WORKLIST_ENTRIES,
            max_base_lookups: DEFAULT_MAX_BASE_LOOKUPS,
        }
    }
}

/// Errors from pack planning.
///
/// Planning failures are fatal for the pack: no partial plan is emitted.
#[derive(Debug)]
pub enum PackPlanError {
    /// Pack parsing failed.
    PackParse(PackParseError),
    /// A candidate offset points outside the pack.
    CandidateOffsetOutOfRange { pack_id: u16, offset: u64 },
    /// `pack_id` does not exist in the provided pack list.
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Unique offsets exceeded the configured worklist limit.
    WorklistLimitExceeded { limit: usize, observed: usize },
    /// REF base lookups exceeded the configured limit.
    BaseLookupLimitExceeded { limit: usize, observed: usize },
    /// Delta dependency graph contains a cycle.
    DeltaCycleDetected { pack_id: u16, offset: u64 },
    /// MIDX lookup or ordering error.
    MidxError(MidxError),
}

impl fmt::Display for PackPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::CandidateOffsetOutOfRange { pack_id, offset } => {
                write!(
                    f,
                    "candidate offset {offset} out of range for pack {pack_id}"
                )
            }
            Self::PackIdOutOfRange {
                pack_id,
                pack_count,
            } => {
                write!(
                    f,
                    "pack id {pack_id} out of range (pack count {pack_count})"
                )
            }
            Self::WorklistLimitExceeded { limit, observed } => {
                write!(
                    f,
                    "pack plan worklist exceeded limit {limit} (saw {observed})"
                )
            }
            Self::BaseLookupLimitExceeded { limit, observed } => {
                write!(
                    f,
                    "pack plan base lookups exceeded limit {limit} (saw {observed})"
                )
            }
            Self::DeltaCycleDetected { pack_id, offset } => {
                write!(
                    f,
                    "delta cycle detected in pack {pack_id} at offset {offset}"
                )
            }
            Self::MidxError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PackPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            Self::MidxError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PackParseError> for PackPlanError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<MidxError> for PackPlanError {
    fn from(err: MidxError) -> Self {
        Self::MidxError(err)
    }
}

/// Resolves OIDs to pack offsets.
///
/// Implementations should return `Ok(None)` for missing OIDs rather than
/// treating them as errors; missing bases are tracked as external.
pub trait OidResolver {
    /// Returns `(pack_id, offset)` for the given OID if present.
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError>;
}

impl<'a> OidResolver for MidxView<'a> {
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        let Some(idx) = self.find_oid(oid)? else {
            return Ok(None);
        };
        let (pack_id, offset) = self.offset_at(idx)?;
        Ok(Some((pack_id, offset)))
    }
}

/// Header-only pack view for planning.
///
/// Expects the full pack bytes including the trailing hash. The view
/// only parses headers and does not verify checksums.
#[derive(Debug)]
pub struct PackView<'a> {
    file: PackFile<'a>,
    object_count: u32,
    oid_len: u8,
}

impl<'a> PackView<'a> {
    /// Parse a pack view from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `PackParseError` if the pack header is invalid.
    pub fn parse(bytes: &'a [u8], oid_len: u8) -> Result<Self, PackParseError> {
        let file = PackFile::parse(bytes, oid_len as usize)?;
        let object_count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok(Self {
            file,
            object_count,
            oid_len,
        })
    }

    /// Parse the entry header at the given offset.
    ///
    /// The offset must point at an entry header (typically from MIDX/IDX).
    pub fn entry_header_at(
        &self,
        offset: u64,
        max_header_bytes: usize,
    ) -> Result<super::pack_inflate::EntryHeader, PackParseError> {
        self.file.entry_header_at(offset, max_header_bytes)
    }

    /// Returns the pack object count from the header.
    #[inline]
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Returns the configured OID length for this pack.
    #[inline]
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }
}

/// Parsed entry metadata cached during planning.
#[derive(Clone, Copy, Debug)]
enum ParsedEntry {
    NonDelta,
    Ofs {
        base_offset: u64,
    },
    Ref {
        base_oid: OidBytes,
        base: Option<(u16, u64)>,
    },
}

/// Worklist entry for delta-base expansion.
#[derive(Clone, Copy, Debug)]
struct WorkItem {
    offset: u64,
    depth: u8,
}

/// Build pack plans for the given candidates.
///
/// Plans are deterministic for identical inputs. Candidates may share the
/// same pack offset; they are preserved as distinct entries in
/// `PackPlan.candidates` while `need_offsets` is deduplicated.
///
/// `packs` must be indexed by `pack_id` (PNAM order). Unused pack slots may
/// be `None`; referenced pack IDs must be `Some`, otherwise
/// `PackIdOutOfRange` is returned.
///
/// # Errors
///
/// Returns `PackPlanError` for invalid pack headers, out-of-range offsets,
/// or resolver failures.
pub fn build_pack_plans<'a, R: OidResolver>(
    mut candidates: Vec<PackCandidate>,
    packs: &[Option<PackView<'a>>],
    resolver: &R,
    config: &PackPlanConfig,
) -> Result<Vec<PackPlan>, PackPlanError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut buckets: Vec<Vec<PackCandidate>> = vec![Vec::new(); packs.len()];
    let mut pack_ids: Vec<u16> = Vec::new();
    for cand in candidates.drain(..) {
        let pack_idx = cand.pack_id as usize;
        if pack_idx >= packs.len() {
            return Err(PackPlanError::PackIdOutOfRange {
                pack_id: cand.pack_id,
                pack_count: packs.len(),
            });
        }
        if buckets[pack_idx].is_empty() {
            pack_ids.push(cand.pack_id);
        }
        buckets[pack_idx].push(cand);
    }

    pack_ids.sort_unstable();

    let mut plans = Vec::with_capacity(pack_ids.len());
    for pack_id in pack_ids {
        let pack_idx = pack_id as usize;
        let pack = packs.get(pack_idx).and_then(|pack| pack.as_ref()).ok_or(
            PackPlanError::PackIdOutOfRange {
                pack_id,
                pack_count: packs.len(),
            },
        )?;
        let pack_candidates = std::mem::take(&mut buckets[pack_idx]);

        let plan = build_pack_plan_for_pack(pack_id, pack, pack_candidates, resolver, config)?;
        plans.push(plan);
    }

    Ok(plans)
}

fn build_pack_plan_for_pack<'a, R: OidResolver>(
    pack_id: u16,
    pack: &PackView<'a>,
    candidates: Vec<PackCandidate>,
    resolver: &R,
    config: &PackPlanConfig,
) -> Result<PackPlan, PackPlanError> {
    let mut candidate_offsets = Vec::with_capacity(candidates.len());
    for (idx, cand) in candidates.iter().enumerate() {
        candidate_offsets.push(CandidateAtOffset {
            offset: cand.offset,
            cand_idx: idx as u32,
        });
    }
    candidate_offsets.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.cand_idx.cmp(&b.cand_idx)));
    debug_assert!(
        candidate_offsets.windows(2).all(|pair| {
            pair[0].offset < pair[1].offset
                || (pair[0].offset == pair[1].offset && pair[0].cand_idx < pair[1].cand_idx)
        }),
        "candidate_offsets must be sorted by offset then cand_idx"
    );

    let mut unique_candidate_offsets: Vec<u64> =
        candidate_offsets.iter().map(|c| c.offset).collect();
    unique_candidate_offsets.sort_unstable();
    unique_candidate_offsets.dedup();
    debug_assert!(is_sorted_unique(&unique_candidate_offsets));

    let candidate_span = span_from_sorted(&unique_candidate_offsets);

    let mut entry_cache: HashMap<u64, ParsedEntry> =
        HashMap::with_capacity(unique_candidate_offsets.len());

    let mut base_lookup_count = 0usize;
    for &offset in &unique_candidate_offsets {
        // Candidate offsets must be in range; base offsets are validated later.
        parse_entry(
            offset,
            pack,
            resolver,
            &mut entry_cache,
            config,
            pack_id,
            true,
            &mut base_lookup_count,
        )?;
    }

    let mut need_set: HashSet<u64> = HashSet::with_capacity(unique_candidate_offsets.len());
    for &offset in &unique_candidate_offsets {
        need_set.insert(offset);
    }
    if need_set.len() > config.max_worklist_entries {
        return Err(PackPlanError::WorklistLimitExceeded {
            limit: config.max_worklist_entries,
            observed: need_set.len(),
        });
    }

    let mut worklist: VecDeque<WorkItem> = unique_candidate_offsets
        .iter()
        .map(|&offset| WorkItem { offset, depth: 0 })
        .collect();

    while let Some(item) = worklist.pop_front() {
        let entry = parse_entry(
            item.offset,
            pack,
            resolver,
            &mut entry_cache,
            config,
            pack_id,
            false,
            &mut base_lookup_count,
        )?;

        let next_depth = item.depth.saturating_add(1);
        let can_expand = item.depth < config.max_delta_depth;

        match entry {
            ParsedEntry::NonDelta => {}
            ParsedEntry::Ofs { base_offset } => {
                if base_offset == item.offset {
                    return Err(PackPlanError::DeltaCycleDetected {
                        pack_id,
                        offset: base_offset,
                    });
                }
                if can_expand && need_set.insert(base_offset) {
                    if need_set.len() > config.max_worklist_entries {
                        return Err(PackPlanError::WorklistLimitExceeded {
                            limit: config.max_worklist_entries,
                            observed: need_set.len(),
                        });
                    }
                    worklist.push_back(WorkItem {
                        offset: base_offset,
                        depth: next_depth,
                    });
                }
            }
            ParsedEntry::Ref { base, .. } => {
                if let Some((base_pack, base_offset)) = base {
                    if base_pack == pack_id && can_expand && need_set.insert(base_offset) {
                        if need_set.len() > config.max_worklist_entries {
                            return Err(PackPlanError::WorklistLimitExceeded {
                                limit: config.max_worklist_entries,
                                observed: need_set.len(),
                            });
                        }
                        worklist.push_back(WorkItem {
                            offset: base_offset,
                            depth: next_depth,
                        });
                    }
                }
            }
        }
    }

    let mut need_offsets: Vec<u64> = need_set.into_iter().collect();
    need_offsets.sort_unstable();
    debug_assert!(is_sorted_unique(&need_offsets));
    debug_assert!(
        candidate_offsets
            .iter()
            .all(|cand| need_offsets.binary_search(&cand.offset).is_ok()),
        "candidate offset missing from need_offsets"
    );

    let delta_deps = build_delta_deps(&need_offsets, &entry_cache, pack_id);
    let exec_order = build_exec_order(&need_offsets, &delta_deps, pack_id)?;
    // Pack exec does not currently consume clustering hints; skip computation.
    let clusters = Vec::new();

    let external_bases = delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::External { .. }))
        .count() as u32;
    let forward_deps = delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::Offset(base) if base > dep.offset))
        .count() as u32;

    let stats = PackPlanStats {
        candidate_count: candidates.len() as u32,
        need_count: need_offsets.len() as u32,
        external_bases,
        forward_deps,
        candidate_span,
    };

    Ok(PackPlan {
        pack_id,
        oid_len: pack.oid_len(),
        candidates,
        candidate_offsets,
        need_offsets,
        delta_deps,
        exec_order,
        clusters,
        stats,
    })
}

/// Parse an entry header at `offset` and cache the result.
///
/// Candidate offsets that are out of range return a dedicated error; base
/// offsets that are out of range are treated as pack corruption.
#[allow(clippy::too_many_arguments)]
fn parse_entry<R: OidResolver>(
    offset: u64,
    pack: &PackView<'_>,
    resolver: &R,
    cache: &mut HashMap<u64, ParsedEntry>,
    config: &PackPlanConfig,
    pack_id: u16,
    is_candidate: bool,
    base_lookup_count: &mut usize,
) -> Result<ParsedEntry, PackPlanError> {
    if let Some(entry) = cache.get(&offset) {
        return Ok(*entry);
    }

    let header = match pack.entry_header_at(offset, config.max_header_bytes) {
        Ok(header) => header,
        Err(PackParseError::OffsetOutOfRange(_)) if is_candidate => {
            return Err(PackPlanError::CandidateOffsetOutOfRange { pack_id, offset })
        }
        // Base offsets outside the pack are treated as pack corruption.
        Err(err) => return Err(PackPlanError::PackParse(err)),
    };

    let parsed = match header.kind {
        EntryKind::NonDelta { .. } => ParsedEntry::NonDelta,
        EntryKind::OfsDelta { base_offset } => ParsedEntry::Ofs { base_offset },
        EntryKind::RefDelta { base_oid } => {
            if *base_lookup_count >= config.max_base_lookups {
                return Err(PackPlanError::BaseLookupLimitExceeded {
                    limit: config.max_base_lookups,
                    observed: base_lookup_count.saturating_add(1),
                });
            }
            *base_lookup_count += 1;
            let base = resolver.resolve(&base_oid)?;
            ParsedEntry::Ref { base_oid, base }
        }
    };

    cache.insert(offset, parsed);
    Ok(parsed)
}

/// Build delta dependency descriptors for the current pack.
///
/// External bases are recorded as `BaseLoc::External`.
fn build_delta_deps(
    need_offsets: &[u64],
    cache: &HashMap<u64, ParsedEntry>,
    pack_id: u16,
) -> Vec<DeltaDep> {
    let mut deps = Vec::new();
    for &offset in need_offsets {
        let Some(entry) = cache.get(&offset) else {
            continue;
        };
        match *entry {
            ParsedEntry::NonDelta => {}
            ParsedEntry::Ofs { base_offset } => deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(base_offset),
            }),
            ParsedEntry::Ref { base_oid, base } => {
                let base_loc = match base {
                    Some((base_pack, base_offset)) if base_pack == pack_id => {
                        BaseLoc::Offset(base_offset)
                    }
                    _ => BaseLoc::External { oid: base_oid },
                };
                deps.push(DeltaDep {
                    offset,
                    kind: DeltaKind::Ref,
                    base: base_loc,
                });
            }
        }
    }
    deps
}

/// Build an execution order that respects forward delta dependencies.
///
/// Returns `None` when natural `need_offsets` order already satisfies all
/// dependencies.
fn build_exec_order(
    need_offsets: &[u64],
    delta_deps: &[DeltaDep],
    pack_id: u16,
) -> Result<Option<Vec<u32>>, PackPlanError> {
    // If all delta bases are at offsets <= their dependents, natural
    // `need_offsets` order already respects dependencies.
    if need_offsets.is_empty() {
        return Ok(None);
    }

    let mut offset_to_idx: HashMap<u64, usize> = HashMap::with_capacity(need_offsets.len());
    for (idx, &offset) in need_offsets.iter().enumerate() {
        offset_to_idx.insert(offset, idx);
    }

    let mut indegree = vec![0u32; need_offsets.len()];
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); need_offsets.len()];
    let mut has_forward = false;

    for dep in delta_deps {
        let BaseLoc::Offset(base_offset) = dep.base else {
            continue;
        };
        let Some(&base_idx) = offset_to_idx.get(&base_offset) else {
            continue;
        };
        let Some(&dep_idx) = offset_to_idx.get(&dep.offset) else {
            continue;
        };
        if base_offset > dep.offset {
            has_forward = true;
        }
        edges[base_idx].push(dep_idx);
        indegree[dep_idx] = indegree[dep_idx].saturating_add(1);
    }

    if !has_forward {
        return Ok(None);
    }

    let mut ready: BTreeSet<usize> = BTreeSet::new();
    for (idx, &deg) in indegree.iter().enumerate() {
        if deg == 0 {
            ready.insert(idx);
        }
    }

    let mut order = Vec::with_capacity(need_offsets.len());
    while let Some(&idx) = ready.iter().next() {
        ready.remove(&idx);
        order.push(idx as u32);
        for &next in &edges[idx] {
            let next_deg = indegree[next].saturating_sub(1);
            indegree[next] = next_deg;
            if next_deg == 0 {
                ready.insert(next);
            }
        }
    }

    if order.len() != need_offsets.len() {
        let mut offset = 0u64;
        for (idx, &deg) in indegree.iter().enumerate() {
            if deg != 0 {
                offset = need_offsets[idx];
                break;
            }
        }
        return Err(PackPlanError::DeltaCycleDetected { pack_id, offset });
    }

    Ok(Some(order))
}

/// Cluster nearby offsets to reduce large seek gaps during execution.
fn cluster_offsets(need_offsets: &[u64]) -> Vec<Cluster> {
    // Split into clusters to limit seek gaps during pack reads.
    if need_offsets.is_empty() {
        return Vec::new();
    }

    let mut clusters = Vec::new();
    let mut start_idx = 0usize;
    let mut start_offset = need_offsets[0];
    let mut last_offset = need_offsets[0];

    for (idx, &offset) in need_offsets.iter().enumerate().skip(1) {
        debug_assert!(offset >= last_offset, "need_offsets must be sorted");
        if offset - last_offset > CLUSTER_GAP_BYTES {
            clusters.push(Cluster {
                start_idx: start_idx as u32,
                end_idx: idx as u32,
                start_offset,
                end_offset: last_offset,
            });
            start_idx = idx;
            start_offset = offset;
        }
        last_offset = offset;
    }

    clusters.push(Cluster {
        start_idx: start_idx as u32,
        end_idx: need_offsets.len() as u32,
        start_offset,
        end_offset: last_offset,
    });

    clusters
}

/// Span (last - first) for a sorted offset list.
fn span_from_sorted(offsets: &[u64]) -> u64 {
    if offsets.is_empty() {
        0
    } else {
        offsets[offsets.len() - 1].saturating_sub(offsets[0])
    }
}

/// Returns true if the slice is strictly increasing.
fn is_sorted_unique(offsets: &[u64]) -> bool {
    offsets.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_offsets_splits_on_gap() {
        let offsets = vec![10, 20, 30, 1_048_700, 1_048_900, 3_200_000];
        let clusters = cluster_offsets(&offsets);
        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters[0].start_idx, 0);
        assert_eq!(clusters[0].end_idx, 3);
        assert_eq!(clusters[1].start_idx, 3);
        assert_eq!(clusters[1].end_idx, 5);
        assert_eq!(clusters[2].start_idx, 5);
        assert_eq!(clusters[2].end_idx, 6);
    }

    #[test]
    fn exec_order_emits_only_with_forward_deps() {
        let need_offsets = vec![10, 50, 70];
        let deps = vec![DeltaDep {
            offset: 50,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(10),
        }];
        let order = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(order.is_none());
    }

    #[test]
    fn exec_order_respects_forward_dep() {
        let need_offsets = vec![10, 50, 70];
        let deps = vec![DeltaDep {
            offset: 10,
            kind: DeltaKind::Ref,
            base: BaseLoc::Offset(50),
        }];
        let order = build_exec_order(&need_offsets, &deps, 0)
            .unwrap()
            .expect("exec order");
        let pos = |offset| {
            let idx = need_offsets.iter().position(|&o| o == offset).unwrap();
            order.iter().position(|&o| o == idx as u32).unwrap()
        };
        assert!(pos(50) < pos(10));
    }
}
