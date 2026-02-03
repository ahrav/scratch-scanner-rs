//! Pack and loose candidate output types.
//!
//! Pack candidates include the pack id and offset for sequential decoding.
//! Loose candidates capture blobs not present in the MIDX. Both variants
//! carry a `CandidateContext` whose `path_ref` points into the path arena
//! owned by the mapping bridge.

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::tree_candidate::CandidateContext;

/// Candidate mapped to a pack offset.
///
/// The `ctx.path_ref` points into the mapping bridge arena that produced
/// this candidate; consumers must keep that arena alive while using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context with path reference.
    pub ctx: CandidateContext,
    /// Pack id (PNAM order).
    pub pack_id: u16,
    /// Offset within the pack.
    pub offset: u64,
}

/// Candidate that must be loaded from loose objects.
///
/// The `ctx.path_ref` points into the mapping bridge arena that produced
/// this candidate; consumers must keep that arena alive while using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LooseCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context with path reference.
    pub ctx: CandidateContext,
}

/// Sink for pack and loose candidates.
///
/// # Contract
/// - `emit_packed`/`emit_loose` preserve input order.
/// - Candidates borrow their path bytes; implementations must not outlive
///   the arena that owns the paths.
pub trait PackCandidateSink {
    /// Receives a packed candidate.
    fn emit_packed(&mut self, candidate: &PackCandidate) -> Result<(), SpillError>;
    /// Receives a loose candidate.
    fn emit_loose(&mut self, candidate: &LooseCandidate) -> Result<(), SpillError>;
    /// Called when all candidates have been emitted.
    fn finish(&mut self) -> Result<(), SpillError> {
        Ok(())
    }
}

/// Collecting sink for tests and diagnostics.
///
/// Stores candidates by value; callers still own the path arena.
#[derive(Debug, Default)]
pub struct CollectingPackCandidateSink {
    pub packed: Vec<PackCandidate>,
    pub loose: Vec<LooseCandidate>,
}

impl PackCandidateSink for CollectingPackCandidateSink {
    fn emit_packed(&mut self, candidate: &PackCandidate) -> Result<(), SpillError> {
        self.packed.push(*candidate);
        Ok(())
    }

    fn emit_loose(&mut self, candidate: &LooseCandidate) -> Result<(), SpillError> {
        self.loose.push(*candidate);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::byte_arena::ByteRef;
    use super::super::tree_candidate::ChangeKind;
    use super::*;

    fn ctx(commit_id: u32, path_ref: ByteRef) -> CandidateContext {
        CandidateContext {
            commit_id,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        }
    }

    #[test]
    fn collecting_sink_preserves_order() {
        let mut sink = CollectingPackCandidateSink::default();
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);

        let packed = PackCandidate {
            oid: oid_a,
            ctx: ctx(1, ByteRef::new(0, 0)),
            pack_id: 1,
            offset: 100,
        };
        let loose = LooseCandidate {
            oid: oid_b,
            ctx: ctx(2, ByteRef::new(4, 2)),
        };

        sink.emit_packed(&packed).unwrap();
        sink.emit_loose(&loose).unwrap();

        assert_eq!(sink.packed, vec![packed]);
        assert_eq!(sink.loose, vec![loose]);
    }

    #[test]
    fn candidate_layout_sizes() {
        assert!(std::mem::size_of::<PackCandidate>() <= 64);
        assert!(std::mem::size_of::<LooseCandidate>() <= 48);
    }
}
