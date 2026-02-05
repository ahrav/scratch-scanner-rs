//! In-memory commit graph for use when file-based commit-graph is unavailable.
//!
//! This module provides `CommitGraphMem`, an in-memory commit graph built from
//! loaded commit objects. It implements the same `CommitGraph` trait as
//! `CommitGraphView`, enabling transparent substitution when disk artifacts
//! are missing.
//!
//! # Layout
//! Uses Struct-of-Arrays (SoA) for cache-friendly access:
//! - `commit_oids`: N * oid_len bytes (sorted by position)
//! - `root_trees`: N * oid_len bytes
//! - `timestamps`: N * u64
//! - `generations`: N * u32
//! - `parent_start`: N+1 * u32 (CSR-style prefix sums)
//! - `parents`: flattened parent positions
//!
//! # Generation Numbers
//! Computed as `gen(commit) = 1 + max(gen(parent))` with roots having gen=1.
//! This matches Git's commit-graph generation semantics.
//! Parents outside the loaded set are treated as generation 0 and are
//! not stored in the parent list.
//!
//! # Invalid Input
//! Cycles are not expected in valid Git history. If a cycle (or unresolved
//! parent chain) is detected during generation computation, remaining commits
//! are force-assigned generation 1 to keep the graph usable.
//!
//! # Deterministic Ordering
//! Commits are sorted by `(generation ASC, commit_oid ASC)` to assign
//! deterministic positions. This ensures stable traversal order.
//! Parent order is preserved from the loaded commit list when stored.

use std::collections::HashMap;

use gix_commitgraph::Position;

use super::commit_loader::LoadedCommit;
use super::commit_walk::{CommitGraph, ParentScratch};
use super::errors::CommitPlanError;
use super::object_id::{ObjectFormat, OidBytes};

/// In-memory commit graph built from loaded commits.
///
/// Provides equivalent functionality to `CommitGraphView` for repos without
/// pre-built commit-graph files.
#[derive(Debug)]
pub struct CommitGraphMem {
    format: ObjectFormat,
    num_commits: u32,

    // Per-commit data (SoA layout, indexed by Position)
    commit_oids: Vec<u8>,  // N * oid_len bytes
    root_trees: Vec<u8>,   // N * oid_len bytes
    timestamps: Vec<u64>,  // N entries
    generations: Vec<u32>, // N entries

    // Parent storage (CSR-style: prefix sums + flattened positions)
    parent_start: Vec<u32>, // N+1 entries
    parents: Vec<u32>,      // flattened parent positions

    // Lookup table
    oid_to_pos: HashMap<OidBytes, u32>,
}

impl CommitGraphMem {
    /// Builds an in-memory commit graph from loaded commits.
    ///
    /// Commits are sorted deterministically by `(generation, oid)` to assign
    /// stable positions. Generation numbers are computed from parent links.
    ///
    /// # Arguments
    /// * `commits` - Loaded commits from `load_commits_from_tips`
    /// * `format` - Object format (SHA-1 or SHA-256)
    ///
    /// # Errors
    /// Currently infallible; the error type is reserved for future validation.
    /// Parents that are missing from the loaded set are dropped and treated
    /// as external roots for generation computation.
    pub fn build(
        commits: Vec<LoadedCommit>,
        format: ObjectFormat,
    ) -> Result<Self, CommitPlanError> {
        if commits.is_empty() {
            return Ok(Self::empty(format));
        }

        let oid_len = format.oid_len() as usize;
        let n = commits.len();

        // Build OID -> index mapping (for parent resolution)
        let mut oid_to_idx: HashMap<OidBytes, usize> = HashMap::with_capacity(n);
        for (idx, commit) in commits.iter().enumerate() {
            oid_to_idx.insert(commit.oid, idx);
        }

        // Compute generation numbers
        let mut generations = vec![0u32; n];
        let mut pending: Vec<usize> = (0..n).collect();
        let mut resolved = vec![false; n];

        // Iterate until all generations are computed
        // This handles DAG ordering naturally
        let mut made_progress = true;
        while made_progress {
            made_progress = false;
            let mut next_pending = Vec::new();

            for idx in pending {
                if resolved[idx] {
                    continue;
                }

                let commit = &commits[idx];

                // Check if all parents are resolved
                let mut all_parents_resolved = true;
                let mut max_parent_gen = 0u32;

                for parent_oid in &commit.parents {
                    if let Some(&parent_idx) = oid_to_idx.get(parent_oid) {
                        if resolved[parent_idx] {
                            max_parent_gen = max_parent_gen.max(generations[parent_idx]);
                        } else {
                            all_parents_resolved = false;
                            break;
                        }
                    }
                    // Parents not in our set are treated as having gen=0
                    // (they're outside the traversed commit set)
                }

                if all_parents_resolved {
                    generations[idx] = max_parent_gen.saturating_add(1);
                    resolved[idx] = true;
                    made_progress = true;
                } else {
                    next_pending.push(idx);
                }
            }

            pending = next_pending;
        }

        // Check for unresolved commits (cycle or missing parents)
        if !pending.is_empty() {
            // Force-resolve remaining with gen=1 (shouldn't happen in valid repos)
            for idx in pending {
                if !resolved[idx] {
                    generations[idx] = 1;
                }
            }
        }

        // Sort commits by (generation, oid) for deterministic positions
        let mut sorted_indices: Vec<usize> = (0..n).collect();
        sorted_indices.sort_by(|&a, &b| match generations[a].cmp(&generations[b]) {
            std::cmp::Ordering::Equal => commits[a].oid.cmp(&commits[b].oid),
            ord => ord,
        });

        // Build position mapping
        let mut idx_to_pos = vec![0u32; n];
        for (pos, &idx) in sorted_indices.iter().enumerate() {
            idx_to_pos[idx] = pos as u32;
        }

        // Build SoA arrays
        let mut commit_oids = Vec::with_capacity(n * oid_len);
        let mut root_trees = Vec::with_capacity(n * oid_len);
        let mut timestamps = Vec::with_capacity(n);
        let mut final_generations = Vec::with_capacity(n);
        let mut parent_start = Vec::with_capacity(n + 1);
        let mut parents_flat = Vec::new();
        let mut oid_to_pos = HashMap::with_capacity(n);

        parent_start.push(0);

        for &idx in &sorted_indices {
            let commit = &commits[idx];
            let pos = idx_to_pos[idx];

            // Store commit data
            commit_oids.extend_from_slice(commit.oid.as_slice());
            root_trees.extend_from_slice(commit.tree_oid.as_slice());
            timestamps.push(commit.timestamp);
            final_generations.push(generations[idx]);
            oid_to_pos.insert(commit.oid, pos);

            // Store parent positions
            for parent_oid in &commit.parents {
                if let Some(&parent_idx) = oid_to_idx.get(parent_oid) {
                    parents_flat.push(idx_to_pos[parent_idx]);
                }
                // Parents outside our set are dropped (they're unreachable)
            }
            parent_start.push(parents_flat.len() as u32);
        }

        Ok(Self {
            format,
            num_commits: n as u32,
            commit_oids,
            root_trees,
            timestamps,
            generations: final_generations,
            parent_start,
            parents: parents_flat,
            oid_to_pos,
        })
    }

    /// Creates an empty commit graph.
    fn empty(format: ObjectFormat) -> Self {
        Self {
            format,
            num_commits: 0,
            commit_oids: Vec::new(),
            root_trees: Vec::new(),
            timestamps: Vec::new(),
            generations: Vec::new(),
            parent_start: vec![0],
            parents: Vec::new(),
            oid_to_pos: HashMap::new(),
        }
    }

    /// Returns the root tree OID for the commit at `pos`.
    pub fn root_tree_oid(&self, pos: Position) -> OidBytes {
        let oid_len = self.format.oid_len() as usize;
        let start = pos.0 as usize * oid_len;
        OidBytes::from_slice(&self.root_trees[start..start + oid_len])
    }

    /// Returns the commit OID for the commit at `pos`.
    pub fn commit_oid(&self, pos: Position) -> OidBytes {
        let oid_len = self.format.oid_len() as usize;
        let start = pos.0 as usize * oid_len;
        OidBytes::from_slice(&self.commit_oids[start..start + oid_len])
    }

    /// Returns the committer timestamp for the commit at `pos`.
    #[inline]
    pub fn committer_timestamp(&self, pos: Position) -> u64 {
        self.timestamps[pos.0 as usize]
    }
}

impl CommitGraph for CommitGraphMem {
    #[inline]
    fn num_commits(&self) -> u32 {
        self.num_commits
    }

    fn lookup(&self, oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        let expected = self.format.oid_len() as usize;
        let len = oid.len() as usize;
        if len != expected {
            return Err(CommitPlanError::InvalidOidLength { len, expected });
        }

        Ok(self.oid_to_pos.get(oid).map(|&pos| Position(pos)))
    }

    #[inline]
    fn generation(&self, pos: Position) -> u32 {
        self.generations[pos.0 as usize]
    }

    fn collect_parents(
        &self,
        pos: Position,
        max_parents: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();

        let idx = pos.0 as usize;
        let start = self.parent_start[idx] as usize;
        let end = self.parent_start[idx + 1] as usize;

        let parent_count = end - start;
        if parent_count > max_parents as usize {
            return Err(CommitPlanError::TooManyParents {
                count: parent_count,
                max: max_parents as usize,
            });
        }

        for &parent_pos in &self.parents[start..end] {
            scratch.push(Position(parent_pos), max_parents)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(oid: [u8; 20], tree: [u8; 20], parents: &[[u8; 20]], ts: u64) -> LoadedCommit {
        LoadedCommit {
            oid: OidBytes::sha1(oid),
            tree_oid: OidBytes::sha1(tree),
            parents: parents.iter().map(|p| OidBytes::sha1(*p)).collect(),
            timestamp: ts,
        }
    }

    #[test]
    fn empty_graph() {
        let graph = CommitGraphMem::build(vec![], ObjectFormat::Sha1).unwrap();
        assert_eq!(graph.num_commits(), 0);
    }

    #[test]
    fn single_root_commit() {
        let commit = make_commit([1; 20], [2; 20], &[], 1000);
        let graph = CommitGraphMem::build(vec![commit], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 1);

        let pos = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        assert_eq!(graph.generation(pos), 1);
        assert_eq!(graph.committer_timestamp(pos), 1000);
        assert_eq!(graph.commit_oid(pos), OidBytes::sha1([1; 20]));
        assert_eq!(graph.root_tree_oid(pos), OidBytes::sha1([2; 20]));
    }

    #[test]
    fn linear_chain() {
        // c3 -> c2 -> c1 (root)
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[[1; 20]], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[2; 20]], 3000);

        let graph = CommitGraphMem::build(vec![c3, c2, c1], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 3);

        let pos1 = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos2 = graph.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        let pos3 = graph.lookup(&OidBytes::sha1([3; 20])).unwrap().unwrap();

        assert_eq!(graph.generation(pos1), 1);
        assert_eq!(graph.generation(pos2), 2);
        assert_eq!(graph.generation(pos3), 3);
    }

    #[test]
    fn merge_commit() {
        // c3 (merge) -> c1, c2 (both roots)
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[1; 20], [2; 20]], 3000);

        let graph = CommitGraphMem::build(vec![c1, c2, c3], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 3);

        let pos3 = graph.lookup(&OidBytes::sha1([3; 20])).unwrap().unwrap();
        // Generation should be 1 + max(gen(c1), gen(c2)) = 1 + max(1, 1) = 2
        assert_eq!(graph.generation(pos3), 2);

        // Check parents
        let mut scratch = ParentScratch::new();
        graph.collect_parents(pos3, 10, &mut scratch).unwrap();
        assert_eq!(scratch.as_slice().len(), 2);
    }

    #[test]
    fn lookup_missing_oid() {
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let graph = CommitGraphMem::build(vec![c1], ObjectFormat::Sha1).unwrap();

        let result = graph.lookup(&OidBytes::sha1([99; 20])).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn deterministic_positions() {
        // Build graph twice with same commits in different order
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[[1; 20]], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[2; 20]], 3000);

        let graph1 =
            CommitGraphMem::build(vec![c1.clone(), c2.clone(), c3.clone()], ObjectFormat::Sha1)
                .unwrap();
        let graph2 = CommitGraphMem::build(vec![c3, c1, c2], ObjectFormat::Sha1).unwrap();

        // Positions should be identical due to deterministic sorting
        let pos1_a = graph1.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos1_b = graph2.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        assert_eq!(pos1_a, pos1_b);

        let pos2_a = graph1.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        let pos2_b = graph2.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        assert_eq!(pos2_a, pos2_b);
    }

    #[test]
    fn memory_layout_efficient() {
        // Verify SoA layout is reasonably sized
        let size = std::mem::size_of::<CommitGraphMem>();
        // Should be ~200 bytes for the struct (vecs are pointers + len + cap)
        assert!(size < 300, "CommitGraphMem struct too large: {size}");
    }
}
