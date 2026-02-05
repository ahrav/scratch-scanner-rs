//! Pack and loose candidate output types.
//!
//! Pack candidates include the pack id and offset for sequential decoding.
//! Loose candidates capture blobs not present in the MIDX. Both variants
//! carry a `CandidateContext` whose `path_ref` points into the path arena
//! owned by the mapping bridge.
//!
//! # Invariants
//! - Candidates borrow path bytes from the mapping bridge arena.
//! - Pack IDs are in MIDX PNAM order; offsets are pack-relative.

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::{MappingCandidateKind, SpillError, TreeDiffError};
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::oid_index::OidIndex;
use super::tree_candidate::CandidateContext;
use super::tree_candidate::CandidateSink;

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
/// - The sink may be called with a mix of packed and loose candidates.
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

/// Candidate collector that maps blob introductions directly to pack/loose candidates.
///
/// This is the fast path for ODB-blob mode: it interns paths into a local arena,
/// resolves each blob OID to a pack/offset via the MIDX, and stores candidates in
/// bounded vectors.
#[derive(Debug)]
pub struct PackCandidateCollector<'midx> {
    midx: &'midx MidxView<'midx>,
    oid_index: &'midx OidIndex,
    path_arena: ByteArena,
    packed: Vec<PackCandidate>,
    loose: Vec<LooseCandidate>,
    max_packed: u32,
    max_loose: u32,
}

impl<'midx> PackCandidateCollector<'midx> {
    /// Creates a new collector with explicit caps and path arena capacity.
    #[must_use]
    pub fn new(
        midx: &'midx MidxView<'midx>,
        oid_index: &'midx OidIndex,
        path_arena_capacity: u32,
        max_packed: u32,
        max_loose: u32,
    ) -> Self {
        Self {
            midx,
            oid_index,
            path_arena: ByteArena::with_capacity(path_arena_capacity),
            packed: Vec::new(),
            loose: Vec::new(),
            max_packed,
            max_loose,
        }
    }

    /// Returns the collected candidates and path arena.
    pub fn finish(self) -> (Vec<PackCandidate>, Vec<LooseCandidate>, ByteArena) {
        (self.packed, self.loose, self.path_arena)
    }

    fn exceed_error(&self, kind: MappingCandidateKind, observed: usize, max: u32) -> TreeDiffError {
        TreeDiffError::CandidateLimitExceeded {
            kind,
            max,
            observed: observed.min(u32::MAX as usize) as u32,
        }
    }

    fn intern_path(&mut self, path: &[u8]) -> Result<ByteRef, TreeDiffError> {
        if path.is_empty() {
            return Ok(ByteRef::new(0, 0));
        }
        if path.len() > ByteRef::MAX_LEN as usize {
            return Err(TreeDiffError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN as usize,
            });
        }
        self.path_arena
            .intern(path)
            .ok_or(TreeDiffError::PathArenaFull)
    }
}

impl CandidateSink for PackCandidateCollector<'_> {
    fn emit(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: super::tree_candidate::ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        let path_ref = self.intern_path(path)?;
        let ctx = CandidateContext {
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
            path_ref,
        };

        if let Some(idx) = self.oid_index.get(&oid) {
            if self.packed.len() as u32 >= self.max_packed {
                return Err(self.exceed_error(
                    MappingCandidateKind::Packed,
                    self.packed.len().saturating_add(1),
                    self.max_packed,
                ));
            }
            let (pack_id, offset) =
                self.midx
                    .offset_at(idx)
                    .map_err(|err| TreeDiffError::ObjectStoreError {
                        detail: err.to_string(),
                    })?;
            self.packed.push(PackCandidate {
                oid,
                ctx,
                pack_id,
                offset,
            });
        } else {
            if self.loose.len() as u32 >= self.max_loose {
                return Err(self.exceed_error(
                    MappingCandidateKind::Loose,
                    self.loose.len().saturating_add(1),
                    self.max_loose,
                ));
            }
            self.loose.push(LooseCandidate { oid, ctx });
        }

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

/// Collecting sink with explicit candidate caps.
///
/// Exceeding a cap returns `SpillError::MappingCandidateLimitExceeded`.
#[derive(Debug)]
pub struct CappedPackCandidateSink {
    pub packed: Vec<PackCandidate>,
    pub loose: Vec<LooseCandidate>,
    max_packed: u32,
    max_loose: u32,
}

impl CappedPackCandidateSink {
    /// Creates a capped collecting sink.
    #[must_use]
    pub fn new(max_packed: u32, max_loose: u32) -> Self {
        Self {
            packed: Vec::new(),
            loose: Vec::new(),
            max_packed,
            max_loose,
        }
    }

    fn exceed_error(&self, kind: MappingCandidateKind, observed: usize, max: u32) -> SpillError {
        SpillError::MappingCandidateLimitExceeded {
            kind,
            max,
            observed: observed.min(u32::MAX as usize) as u32,
        }
    }
}

impl PackCandidateSink for CappedPackCandidateSink {
    fn emit_packed(&mut self, candidate: &PackCandidate) -> Result<(), SpillError> {
        if self.packed.len() as u32 >= self.max_packed {
            return Err(self.exceed_error(
                MappingCandidateKind::Packed,
                self.packed.len().saturating_add(1),
                self.max_packed,
            ));
        }
        self.packed.push(*candidate);
        Ok(())
    }

    fn emit_loose(&mut self, candidate: &LooseCandidate) -> Result<(), SpillError> {
        if self.loose.len() as u32 >= self.max_loose {
            return Err(self.exceed_error(
                MappingCandidateKind::Loose,
                self.loose.len().saturating_add(1),
                self.max_loose,
            ));
        }
        self.loose.push(*candidate);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::byte_arena::ByteRef;
    use super::super::tree_candidate::CandidateSink as _;
    use super::super::tree_candidate::ChangeKind;
    use super::super::{midx::MidxView, object_id::ObjectFormat, oid_index::OidIndex};
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
        assert!(std::mem::size_of::<LooseCandidate>() <= 64);
    }

    #[test]
    fn capped_sink_enforces_packed_limit() {
        let mut sink = CappedPackCandidateSink::new(1, 10);
        let oid = OidBytes::sha1([0x11; 20]);
        let cand = PackCandidate {
            oid,
            ctx: ctx(1, ByteRef::new(0, 0)),
            pack_id: 1,
            offset: 42,
        };

        sink.emit_packed(&cand).unwrap();
        let err = sink.emit_packed(&cand).unwrap_err();
        assert!(matches!(
            err,
            SpillError::MappingCandidateLimitExceeded {
                kind: MappingCandidateKind::Packed,
                max: 1,
                observed: 2
            }
        ));
    }

    struct MidxBuilder {
        objects: Vec<([u8; 20], u16, u64)>,
        pack_names: Vec<Vec<u8>>,
    }

    impl MidxBuilder {
        fn new() -> Self {
            Self {
                objects: Vec::new(),
                pack_names: Vec::new(),
            }
        }

        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
            self.objects.push((oid, pack_id, offset));
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

    #[test]
    fn pack_candidate_collector_maps_packed_and_loose() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-0.pack");
        let packed_oid = [0x11; 20];
        builder.add_object(packed_oid, 0, 100);
        let bytes = builder.build();
        let midx = MidxView::parse(&bytes, ObjectFormat::Sha1).unwrap();
        let oid_index = OidIndex::from_midx(&midx);

        let mut collector = PackCandidateCollector::new(&midx, &oid_index, 1024, 8, 8);

        let packed = OidBytes::sha1(packed_oid);
        collector
            .emit(packed, b"packed.txt", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();

        let loose = OidBytes::sha1([0x22; 20]);
        collector
            .emit(loose, b"loose.txt", 2, 0, ChangeKind::Add, 0, 0)
            .unwrap();

        let (packed_out, loose_out, arena) = collector.finish();
        assert_eq!(packed_out.len(), 1);
        assert_eq!(loose_out.len(), 1);
        assert_eq!(arena.get(packed_out[0].ctx.path_ref), b"packed.txt");
    }
}
