//! Pack plan model types.
//!
//! Pack plans group candidates by pack and describe which offsets must be
//! decoded (candidates plus pack-local bases), along with delta dependency
//! metadata for later execution strategies.
//!
//! Execution order is optional: it is only required when forward delta
//! dependencies exist (a base offset greater than its dependent offset).
//!
//! # Invariants
//! - `need_offsets` is sorted and unique.
//! - `candidate_offsets` is sorted by offset (ties by candidate index).
//! - `exec_order` indices refer to `need_offsets`.
//! - `delta_deps` is sorted by offset (subset of `need_offsets`).
//! - `delta_dep_index` maps `need_offsets` index -> `delta_deps` index or NONE_U32.

use super::object_id::OidBytes;
use super::pack_candidates::PackCandidate;

/// Sentinel for missing `u32` indices.
pub const NONE_U32: u32 = u32::MAX;

/// Delta encoding kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaKind {
    /// OFS_DELTA (base offset within same pack).
    Ofs,
    /// REF_DELTA (base object ID reference).
    Ref,
}

/// Delta base location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseLoc {
    /// Base stored at the given pack offset.
    Offset(u64),
    /// Base stored outside this pack (or unresolved).
    External { oid: OidBytes },
}

/// Delta dependency for a pack entry.
///
/// For REF deltas whose base is not in the same pack, `base` is external.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaDep {
    /// Offset of the delta entry.
    pub offset: u64,
    /// Delta encoding kind.
    pub kind: DeltaKind,
    /// Base location (internal offset or external OID).
    pub base: BaseLoc,
}

/// Candidate index paired with its pack offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateAtOffset {
    /// Offset within the pack.
    pub offset: u64,
    /// Index into `PackPlan.candidates`.
    pub cand_idx: u32,
}

/// Pack plan summary statistics.
///
/// `candidate_span` is the span of unique candidate offsets (0 if empty).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackPlanStats {
    /// Number of candidate entries in the plan.
    pub candidate_count: u32,
    /// Number of unique offsets that must be decoded.
    pub need_count: u32,
    /// Number of REF deltas whose base is outside the pack.
    pub external_bases: u32,
    /// Number of dependencies where base offset > dependent offset.
    pub forward_deps: u32,
    /// Span between first and last candidate offsets.
    pub candidate_span: u64,
}

impl PackPlanStats {
    /// Returns a zeroed stats struct for empty plans.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            candidate_count: 0,
            need_count: 0,
            external_bases: 0,
            forward_deps: 0,
            candidate_span: 0,
        }
    }
}

/// Pack plan for a single pack file.
///
/// The plan contains both the candidate list and the expanded set of
/// offsets required to decode them (including pack-local delta bases).
/// `exec_order` is present only when forward dependencies exist.
#[derive(Clone, Debug)]
pub struct PackPlan {
    /// Pack id (PNAM order).
    pub pack_id: u16,
    /// OID length for this repository (20 or 32).
    pub oid_len: u8,
    /// Maximum delta chain depth expanded in planning.
    pub max_delta_depth: u8,
    /// Pack candidates for this pack.
    pub candidates: Vec<PackCandidate>,
    /// Candidate offsets sorted by offset (ties by candidate index).
    pub candidate_offsets: Vec<CandidateAtOffset>,
    /// Offsets to decode (candidates + pack-local bases), sorted unique.
    pub need_offsets: Vec<u64>,
    /// Delta dependencies for offsets in `need_offsets`.
    pub delta_deps: Vec<DeltaDep>,
    /// Dense index mapping `need_offsets` index to `delta_deps` index.
    pub delta_dep_index: Vec<u32>,
    /// Optional execution order (indices into `need_offsets`).
    pub exec_order: Option<Vec<u32>>,
    /// Summary statistics for strategy selection.
    pub stats: PackPlanStats,
}
