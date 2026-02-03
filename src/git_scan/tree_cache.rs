//! Set-associative cache for tree object bytes.
//!
//! TODO: Port the arena-backed cache implementation and wire into
//! the object store. This stub exists to define the API surface.
//!
//! # Intended behavior
//! A real cache should:
//! - Evict by set/way with a bounded byte budget.
//! - Store *decompressed* tree payloads (no object header).
//! - Allow zero-copy access via borrowed slices while the cache entry lives.

use super::object_id::OidBytes;

/// Stub tree cache.
///
/// The current implementation never stores data; `get` always returns `None`
/// and `insert` always returns `false`.
#[derive(Debug, Default)]
pub struct TreeCache {
    capacity_bytes: u32,
}

impl TreeCache {
    /// Creates a new stub cache with a byte capacity.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        Self { capacity_bytes }
    }

    /// Returns the configured capacity.
    #[must_use]
    pub const fn capacity_bytes(&self) -> u32 {
        self.capacity_bytes
    }

    /// Looks up cached tree bytes by OID.
    #[allow(unused_variables)]
    pub fn get(&self, oid: &OidBytes) -> Option<&[u8]> {
        None
    }

    /// Inserts tree bytes into the cache.
    ///
    /// Returns true if the entry was cached.
    #[allow(unused_variables)]
    pub fn insert(&mut self, oid: OidBytes, bytes: &[u8]) -> bool {
        false
    }
}
