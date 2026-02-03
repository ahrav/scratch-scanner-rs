//! RocksDB-backed persistence adapters (placeholder).
//!
//! This module defines a `SeenBlobStore` implementation intended for a
//! RocksDB backend. The current implementation is a stub that returns
//! an explicit error until the RocksDB integration is wired up.
//!
//! # Intended behavior (future)
//! - `open` should initialize or open a RocksDB database at the path.
//! - `batch_check_seen` should perform ordered point lookups and return
//!   one boolean per input OID.
//! - The implementation should honor the `SeenBlobStore` contract:
//!   output order must match input order.

use std::io;
use std::path::Path;

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::seen_store::SeenBlobStore;

/// Placeholder RocksDB-backed seen store.
///
/// This type currently does not hold any state and always returns an
/// explicit I/O error indicating RocksDB support is unavailable.
#[derive(Debug, Default)]
pub struct RocksDbSeenStore;

impl RocksDbSeenStore {
    /// Opens the seen-store database at the given path.
    ///
    /// # Errors
    /// Always returns `SpillError::Io` until RocksDB support is enabled.
    pub fn open(_path: impl AsRef<Path>) -> Result<Self, SpillError> {
        Err(SpillError::Io(io::Error::other(
            "rocksdb support not enabled",
        )))
    }
}

impl SeenBlobStore for RocksDbSeenStore {
    fn batch_check_seen(&self, _oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        // Placeholder until the RocksDB backend is implemented.
        Err(SpillError::Io(io::Error::other(
            "rocksdb support not enabled",
        )))
    }
}
