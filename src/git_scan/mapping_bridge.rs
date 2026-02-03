//! Mapping bridge from unique blobs to pack/loose candidates.
//!
//! The bridge re-interns path bytes into a long-lived `ByteArena`, enforces
//! sorted unique input, and maps each blob to a pack offset via the MIDX
//! or emits it as a loose candidate.

use std::cmp::Ordering;

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::SpillError;
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate, PackCandidateSink};
use super::tree_candidate::CandidateContext;
use super::unique_blob::{UniqueBlob, UniqueBlobSink};

/// Configuration for the mapping bridge.
#[derive(Clone, Copy, Debug)]
pub struct MappingBridgeConfig {
    /// Maximum path arena capacity in bytes.
    ///
    /// Default: 64 MiB.
    pub path_arena_capacity: u32,
}

impl Default for MappingBridgeConfig {
    fn default() -> Self {
        Self {
            path_arena_capacity: 64 * 1024 * 1024,
        }
    }
}

/// Mapping statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappingStats {
    /// Total unique blobs processed.
    pub unique_blobs_in: u64,
    /// Blobs found in the MIDX.
    pub packed_matched: u64,
    /// Blobs missing from the MIDX (loose fallback).
    pub loose_unmatched: u64,
}

/// Adapter that maps unique blobs to pack/loose candidates.
///
/// Paths are re-interned into the bridge's arena so downstream stages can
/// hold stable `ByteRef` values. The input stream must be strictly sorted
/// by OID and contain no duplicates.
pub struct MappingBridge<'midx, S: PackCandidateSink> {
    midx: &'midx MidxView<'midx>,
    sink: S,
    path_arena: ByteArena,
    stats: MappingStats,
    last_oid: Option<OidBytes>,
}

impl<'midx, S: PackCandidateSink> MappingBridge<'midx, S> {
    /// Creates a new mapping bridge.
    #[must_use]
    pub fn new(midx: &'midx MidxView<'midx>, sink: S, config: MappingBridgeConfig) -> Self {
        Self {
            midx,
            sink,
            path_arena: ByteArena::with_capacity(config.path_arena_capacity),
            stats: MappingStats::default(),
            last_oid: None,
        }
    }

    /// Returns current mapping statistics.
    #[must_use]
    pub const fn stats(&self) -> MappingStats {
        self.stats
    }

    /// Returns a reference to the bridge's path arena.
    #[must_use]
    pub fn path_arena(&self) -> &ByteArena {
        &self.path_arena
    }

    /// Finishes the bridge and returns stats, sink, and path arena.
    ///
    /// This does not call `sink.finish()`. Callers should invoke the sink
    /// finish via the `UniqueBlobSink` trait before consuming the bridge.
    pub fn finish(self) -> Result<(MappingStats, S, ByteArena), SpillError> {
        let total = self.stats.packed_matched + self.stats.loose_unmatched;
        if total != self.stats.unique_blobs_in {
            return Err(SpillError::from(MidxError::corrupt(
                "mapping stats mismatch",
            )));
        }
        Ok((self.stats, self.sink, self.path_arena))
    }

    fn ensure_sorted(&mut self, oid: OidBytes) -> Result<(), SpillError> {
        if let Some(last) = self.last_oid {
            match oid.cmp(&last) {
                Ordering::Less => return Err(SpillError::from(MidxError::InputNotSorted)),
                Ordering::Equal => return Err(SpillError::from(MidxError::DuplicateInputOid)),
                Ordering::Greater => {}
            }
        }
        self.last_oid = Some(oid);
        Ok(())
    }

    fn intern_path(&mut self, paths: &ByteArena, path_ref: ByteRef) -> Result<ByteRef, SpillError> {
        let path = paths.get(path_ref);
        if path.is_empty() {
            return Ok(ByteRef::new(0, 0));
        }
        if path.len() > ByteRef::MAX_LEN as usize {
            return Err(SpillError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN as usize,
            });
        }
        self.path_arena
            .intern(path)
            .ok_or(SpillError::ArenaOverflow)
    }
}

impl<S: PackCandidateSink> UniqueBlobSink for MappingBridge<'_, S> {
    fn emit(&mut self, blob: &UniqueBlob, paths: &ByteArena) -> Result<(), SpillError> {
        self.ensure_sorted(blob.oid)?;

        let path_ref = self.intern_path(paths, blob.ctx.path_ref)?;
        let ctx = CandidateContext {
            path_ref,
            ..blob.ctx
        };

        self.stats.unique_blobs_in += 1;

        match self.midx.find_oid(&blob.oid)? {
            Some(idx) => {
                let (pack_id, offset) = self.midx.offset_at(idx)?;
                let candidate = PackCandidate {
                    oid: blob.oid,
                    ctx,
                    pack_id,
                    offset,
                };
                self.sink.emit_packed(&candidate)?;
                self.stats.packed_matched += 1;
            }
            None => {
                let candidate = LooseCandidate { oid: blob.oid, ctx };
                self.sink.emit_loose(&candidate)?;
                self.stats.loose_unmatched += 1;
            }
        }

        Ok(())
    }

    fn finish(&mut self) -> Result<(), SpillError> {
        self.sink.finish()
    }
}
