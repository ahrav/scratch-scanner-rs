//! Candidate buffer for tree diff output.
//!
//! Stores OID-only candidates with canonical context and interned paths.
//! The buffer enforces hard caps on candidate count and path arena usage.
//!
//! # Canonical context
//! Each candidate carries enough context to be stable across spill/merge:
//! commit id, parent index, change kind, file mode, and path classification
//! bits. Paths are interned into a shared arena to avoid per-candidate copies.

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::TreeDiffError;
use super::object_id::OidBytes;
use super::tree_diff_limits::TreeDiffLimits;

/// Change kind for a tree diff candidate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// New blob introduced at this path.
    Add = 1,
    /// Existing blob modified at this path.
    Modify = 2,
}

impl ChangeKind {
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Canonical context for a blob candidate.
///
/// This structure is designed to be stable across spill/merge boundaries:
/// the same blob candidate in the same commit/parent context should yield
/// identical serialized context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateContext {
    /// Commit-graph position identifying which commit introduced this blob.
    pub commit_id: u32,
    /// Index of the parent in the commit's parent list.
    pub parent_idx: u8,
    /// Type of change: Add or Modify.
    pub change_kind: ChangeKind,
    /// Context flags (file mode in low bits).
    pub ctx_flags: u16,
    /// Candidate flags (path classification, etc.).
    pub cand_flags: u16,
    /// Path reference into the shared `ByteArena`.
    pub path_ref: ByteRef,
}

/// Tree diff candidate (OID + context).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context for the candidate.
    pub ctx: CandidateContext,
}

/// Resolved candidate with its path bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedCandidate<'a> {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Full path bytes.
    pub path: &'a [u8],
    /// Commit-graph position identifying the introducing commit.
    pub commit_id: u32,
    /// Parent index in the commit's parent list.
    pub parent_idx: u8,
    /// Change kind.
    pub change_kind: ChangeKind,
    /// Context flags.
    pub ctx_flags: u16,
    /// Candidate flags.
    pub cand_flags: u16,
}

/// In-memory candidate buffer for tree diff output.
///
/// # Invariants
/// - `oid_len` is 20 or 32
/// - `candidates.len() <= max_candidates`
/// - All `path_ref` values refer into `path_arena`
///
/// # Ordering
/// Candidates are stored in the order they are emitted by the tree diff
/// walker (Git tree order), with no additional sorting.
pub struct CandidateBuffer {
    candidates: Vec<TreeCandidate>,
    path_arena: ByteArena,
    max_candidates: u32,
    oid_len: u8,
}

impl CandidateBuffer {
    /// Creates a new candidate buffer.
    #[must_use]
    pub fn new(limits: &TreeDiffLimits, oid_len: u8) -> Self {
        assert!(oid_len == 20 || oid_len == 32, "oid_len must be 20 or 32");
        Self {
            candidates: Vec::with_capacity(limits.max_candidates as usize),
            path_arena: ByteArena::with_capacity(limits.max_path_arena_bytes),
            max_candidates: limits.max_candidates,
            oid_len,
        }
    }

    /// Returns the number of candidates in the buffer.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Clears the buffer contents (retains capacity).
    ///
    /// This resets the path arena, invalidating any previously returned
    /// `ByteRef` values and resolved path slices.
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.path_arena = ByteArena::with_capacity(self.path_arena.capacity());
    }

    /// Pushes a new candidate.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `CandidateBufferFull` if the candidate cap is exceeded
    /// - `PathArenaFull` if path arena capacity is exceeded
    /// - `InvalidOidLength` if OID length mismatches the configured length
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        if self.candidates.len() as u32 >= self.max_candidates {
            return Err(TreeDiffError::CandidateBufferFull);
        }
        if oid.len() != self.oid_len {
            return Err(TreeDiffError::InvalidOidLength {
                len: oid.len() as usize,
                expected: self.oid_len as usize,
            });
        }

        let path_ref = self
            .path_arena
            .intern(path)
            .ok_or(TreeDiffError::PathArenaFull)?;

        let ctx = CandidateContext {
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
            path_ref,
        };

        self.candidates.push(TreeCandidate { oid, ctx });
        Ok(())
    }

    /// Iterates over resolved candidates (with path bytes).
    #[must_use]
    pub fn iter_resolved(&self) -> ResolvedIter<'_> {
        ResolvedIter { buf: self, idx: 0 }
    }
}

/// Iterator over resolved candidates.
///
/// The returned paths borrow from the candidate buffer's arena and remain
/// valid only as long as the buffer is not cleared or dropped.
pub struct ResolvedIter<'a> {
    buf: &'a CandidateBuffer,
    idx: usize,
}

impl<'a> Iterator for ResolvedIter<'a> {
    type Item = ResolvedCandidate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.buf.candidates.len() {
            return None;
        }
        let cand = self.buf.candidates[self.idx];
        self.idx += 1;

        let path = self.buf.path_arena.get(cand.ctx.path_ref);
        Some(ResolvedCandidate {
            oid: cand.oid,
            path,
            commit_id: cand.ctx.commit_id,
            parent_idx: cand.ctx.parent_idx,
            change_kind: cand.ctx.change_kind,
            ctx_flags: cand.ctx.ctx_flags,
            cand_flags: cand.ctx.cand_flags,
        })
    }
}
