//! Commit-graph indexing helpers for attribution-first ODB scans.
//!
//! This module provides a cache-friendly view over commit-graph data. It
//! precomputes commit OIDs, root tree OIDs, and committer timestamps into
//! flat arrays so hot-path lookups avoid per-commit graph access.
//!
//! # Invariants
//! - Arrays are sized to `CommitGraphView::num_commits()` and never grow.
//! - Positions are used as direct indices into the arrays.
//! - OID lengths always match the repo's object format.
//! - The index is immutable after construction; all reads are O(1).

use gix_commitgraph::Position;

use super::commit_walk::{CommitGraph, CommitGraphView};
use super::errors::CommitPlanError;
use super::object_id::OidBytes;

/// Cache-friendly commit-graph index.
///
/// Owns copies of commit/tree OIDs so the backing commit-graph view can be
/// dropped after construction.
#[derive(Debug)]
pub struct CommitGraphIndex {
    commit_oids: Vec<OidBytes>,
    root_trees: Vec<OidBytes>,
    committer_timestamps: Vec<u64>,
}

impl CommitGraphIndex {
    /// Builds a commit-graph index from the given view.
    ///
    /// # Costs
    /// - Time: O(N) over commit-graph entries
    /// - Memory: O(N * oid_len) for commit and tree OIDs plus timestamps
    pub fn build(view: &CommitGraphView) -> Result<Self, CommitPlanError> {
        let count = view.num_commits() as usize;
        let mut commit_oids = Vec::with_capacity(count);
        let mut root_trees = Vec::with_capacity(count);
        let mut committer_timestamps = Vec::with_capacity(count);

        for idx in 0..count {
            let pos = Position(idx as u32);
            commit_oids.push(view.commit_oid(pos)?);
            root_trees.push(view.root_tree_oid(pos)?);
            committer_timestamps.push(view.committer_timestamp(pos));
        }

        Ok(Self {
            commit_oids,
            root_trees,
            committer_timestamps,
        })
    }

    /// Returns the number of commits indexed.
    #[inline]
    pub fn len(&self) -> usize {
        self.commit_oids.len()
    }

    /// Returns true if the index is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.commit_oids.is_empty()
    }

    /// Returns the commit OID for `pos`.
    #[inline]
    pub fn commit_oid(&self, pos: Position) -> OidBytes {
        self.commit_oids[pos.0 as usize]
    }

    /// Returns the root tree OID for `pos`.
    #[inline]
    pub fn root_tree_oid(&self, pos: Position) -> OidBytes {
        self.root_trees[pos.0 as usize]
    }

    /// Returns the committer timestamp for `pos` (seconds since epoch).
    #[inline]
    pub fn committer_timestamp(&self, pos: Position) -> u64 {
        self.committer_timestamps[pos.0 as usize]
    }
}

// Tests live in `tests/integration/git_commit_walk.rs` to reuse git helpers.
