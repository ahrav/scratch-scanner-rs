//! Bridge from unique-blob output to downstream mapping stages.
//!
//! This adapter re-interns path bytes into a long-lived `ByteArena` so
//! downstream stages can hold stable `ByteRef` values. It translates the
//! short-lived arena passed to `UniqueBlobSink::emit` into a stable arena
//! owned by the bridge.

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::SpillError;
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

/// Adapter that re-interns paths for downstream consumers.
///
/// The internal arena accumulates paths for the lifetime of the bridge.
/// Callers must keep the returned arena alive for as long as downstream
/// users retain `ByteRef` values.
pub struct MappingBridge<S: UniqueBlobSink> {
    sink: S,
    path_arena: ByteArena,
}

impl<S: UniqueBlobSink> MappingBridge<S> {
    /// Creates a new mapping bridge.
    #[must_use]
    pub fn new(sink: S, config: MappingBridgeConfig) -> Self {
        Self {
            sink,
            path_arena: ByteArena::with_capacity(config.path_arena_capacity),
        }
    }

    /// Returns a reference to the bridge's path arena.
    ///
    /// All path references emitted by the bridge point into this arena.
    #[must_use]
    pub fn path_arena(&self) -> &ByteArena {
        &self.path_arena
    }

    /// Finishes the bridge and returns the sink plus the path arena.
    ///
    /// The caller is responsible for keeping the arena alive while any
    /// downstream `ByteRef` values are still in use.
    #[must_use]
    pub fn finish(self) -> (S, ByteArena) {
        (self.sink, self.path_arena)
    }
}

impl<S: UniqueBlobSink> UniqueBlobSink for MappingBridge<S> {
    fn emit(&mut self, blob: &UniqueBlob, paths: &ByteArena) -> Result<(), SpillError> {
        let path = paths.get(blob.ctx.path_ref);

        let path_ref = if path.is_empty() {
            // Avoid interning empty paths; treat as a zero-length ref.
            ByteRef::new(0, 0)
        } else if path.len() > ByteRef::MAX_LEN as usize {
            return Err(SpillError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN as usize,
            });
        } else {
            self.path_arena
                .intern(path)
                .ok_or(SpillError::ArenaOverflow)?
        };

        let ctx = CandidateContext {
            path_ref,
            ..blob.ctx
        };
        let mapped = UniqueBlob { oid: blob.oid, ctx };
        self.sink.emit(&mapped, &self.path_arena)
    }

    fn finish(&mut self) -> Result<(), SpillError> {
        self.sink.finish()
    }
}
