//! Object store abstraction for tree loading.
//!
//! This module will host the shared pack/loose object reader used by
//! tree diffing. For now it defines the `TreeSource` trait and a stub
//! implementation to unblock compilation while the pack loader is ported.
//!
//! # Contract
//! Implementations must return the raw, decompressed tree payload (no
//! `tree <size>\\0` header). Callers assume the returned buffer contains
//! a sequence of tree entries in Git tree order.

use super::errors::TreeDiffError;
use super::object_id::OidBytes;

/// Trait for loading tree object bytes.
///
/// Implement this with your object store (packed or loose).
/// The returned bytes must be the decompressed tree payload (no header).
pub trait TreeSource {
    /// Loads a tree object by OID.
    ///
    /// Implementations may allocate per call; higher-level caches can wrap
    /// the source to avoid repeated inflations of hot subtrees.
    ///
    /// # Errors
    /// - `TreeNotFound` if the object doesn't exist
    /// - `NotATree` if the object exists but isn't a tree
    fn load_tree(&mut self, oid: &OidBytes) -> Result<Vec<u8>, TreeDiffError>;
}

/// Stub object store implementation.
///
/// This placeholder is wired so the tree diff API can be exercised while
/// the pack/loose loader is ported. It always returns `TreeNotFound`.
///
/// TODO: Replace with pack/loose-backed loader and tree cache.
#[derive(Debug, Default)]
pub struct ObjectStore {
    oid_len: u8,
}

impl ObjectStore {
    /// Creates a new stub object store for the given OID length.
    #[must_use]
    pub fn new(oid_len: u8) -> Self {
        Self { oid_len }
    }

    /// Returns the configured OID length.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }
}

impl TreeSource for ObjectStore {
    fn load_tree(&mut self, _oid: &OidBytes) -> Result<Vec<u8>, TreeDiffError> {
        Err(TreeDiffError::TreeNotFound)
    }
}
