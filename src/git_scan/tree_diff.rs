//! Tree diff walker for Git scanning.
//!
//! Performs OID-only tree diffs between two trees, emitting candidates
//! for changed blob-like entries. Uses explicit stack (no recursion) and
//! enforces depth limits.
//!
//! # Algorithm
//!
//! Merge-walk both trees in Git tree order (see `tree_order` module).
//! For each pair of entries:
//!
//! - new < old: Entry added in new tree -> emit candidate (if blob-like)
//! - new > old: Entry deleted -> skip (nothing to scan)
//! - new == old:
//!   - If tree: recurse only if subtree OIDs differ
//!   - If blob-like: emit candidate only if OIDs differ (modify)
//!   - If gitlink: skip (submodule commits not scanned)
//!
//! # Kind Changes (File <-> Directory)
//!
//! When an entry changes kind (e.g., file "foo" becomes dir "foo/"):
//! - Git tree ordering treats them as different entries (different terminators)
//! - file "foo" terminates with NUL (0x00)
//! - dir "foo/" terminates with '/' (0x2F)
//! - So file < dir when names match exactly
//! - Result: file deleted (skip) + dir added (recurse into new dir)
//!
//! # Kind Changes (Blob <-> Gitlink)
//!
//! When both entries are non-directories (same ordering):
//! - blob -> gitlink: skip (gitlinks not scanned)
//! - gitlink -> blob: emit candidate with ChangeKind::Add
//!
//! # Performance
//!
//! - O(n) where n is the number of changed entries
//! - Skips unchanged subtrees entirely (no recursion)
//! - No blob reads (OID comparison only)
//! - Fixed-size stack allocation (bounded depth)
//! - Stack is reused across diff_trees calls (no per-call allocation)
//! - Large or spill-backed trees are parsed with a streaming buffer
//!   to keep the working set bounded
//!
//! # Invariants
//! - `TreeSource` returns raw tree payload bytes (no object header) in
//!   canonical Git tree order.
//! - The configured `oid_len` is authoritative; mismatches are errors.
//! - `reset_stats()` must be called only when the diff stack is empty.
//!
//! # Output Ordering
//! Candidates are emitted in Git tree order for each diff. For merge commits,
//! the caller should invoke `diff_trees` once per parent; `parent_idx` tags
//! the candidate with which parent diff produced it.
//!
//! # Budgeting
//! The tree-bytes budget is enforced on in-flight bytes retained by the
//! walker. Call `reset_stats()` when starting a new repo job; the in-flight
//! tracker is reset and the diff stack must be empty.

use std::cmp::Ordering;

use super::errors::TreeDiffError;
use super::object_id::OidBytes;
use super::object_store::{TreeBytes, TreeSource};
use super::tree_candidate::{CandidateSink, ChangeKind};
use super::tree_diff_limits::TreeDiffLimits;
use super::tree_entry::{parse_entry, EntryKind, ParseOutcome, ParsedTreeEntry, TreeEntry};
use super::tree_order::git_tree_name_cmp;
use super::tree_stream::{TreeBytesReader, TreeStream};

/// Maximum path length in bytes.
///
/// This matches common filesystem limits (PATH_MAX on Linux/macOS).
/// Paths exceeding this are rejected to prevent DoS via deeply nested trees.
const MAX_PATH_LEN: usize = 4096;
/// Streaming tree entry buffer size (bytes).
const TREE_STREAM_BUF_BYTES: usize = 16 * 1024;

/// Counters for tree diff operations.
///
/// Statistics are cumulative until `reset_stats()` is called. The
/// `tree_bytes_loaded` counter is informational; the in-flight budget
/// is enforced separately via the walker.
#[derive(Clone, Debug, Default)]
pub struct TreeDiffStats {
    /// Number of trees loaded.
    pub trees_loaded: u64,
    /// Total bytes loaded from trees.
    pub tree_bytes_loaded: u64,
    /// Peak in-flight tree bytes retained by the walker.
    pub tree_bytes_in_flight_peak: u64,
    /// Number of candidates emitted.
    pub candidates_emitted: u64,
    /// Number of subtrees skipped (same OID).
    pub subtrees_skipped: u64,
    /// Maximum stack depth reached.
    pub max_depth_reached: u16,
}

/// Stack frame for iterative tree diff.
struct DiffFrame {
    /// Cursor over the new tree.
    new_cursor: TreeCursor,
    /// Cursor over the old tree.
    old_cursor: TreeCursor,
    /// Path prefix length (where to truncate path_buf).
    prefix_len: usize,
}

/// Action to take after processing a pair of entries.
///
/// Using an enum avoids mutable borrow conflicts: we collect all the
/// information needed while holding an immutable reference to the frame,
/// then execute the action afterwards.
enum Action {
    /// Pop the current frame (both trees exhausted).
    Pop,
    /// Entry only in new tree: advance new cursor and process.
    AddedEntry {
        oid: OidBytes,
        kind: EntryKind,
        mode: u32,
    },
    /// Entry only in old tree (deletion, skip).
    DeletedEntry,
    /// Entries match (same name+type in ordering), names lexically equal.
    MatchedEntries {
        new_oid: OidBytes,
        old_oid: OidBytes,
        new_kind: EntryKind,
        old_kind: EntryKind,
        new_mode: u32,
    },
    /// new < old in tree ordering: entry added in new tree.
    NewBeforeOld {
        oid: OidBytes,
        kind: EntryKind,
        mode: u32,
    },
    /// new > old in tree ordering: entry deleted from old tree.
    OldBeforeNew,
}

/// Buffered tree cursor (slice-backed).
struct BufferedCursor {
    bytes: TreeBytes,
    pos: usize,
    cached: Option<ParsedTreeEntry>,
    oid_len: u8,
}

impl BufferedCursor {
    fn new(bytes: TreeBytes, oid_len: u8) -> Self {
        Self {
            bytes,
            pos: 0,
            cached: None,
            oid_len,
        }
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        if let Some(parsed) = self.cached {
            return Ok(Some(
                parsed.materialize(self.bytes.as_slice(), self.oid_len),
            ));
        }

        if self.pos >= self.bytes.len() {
            return Ok(None);
        }

        let remaining = &self.bytes.as_slice()[self.pos..];
        match parse_entry(remaining, self.oid_len)? {
            ParseOutcome::Complete(mut parsed) => {
                parsed.offset_by(self.pos);
                self.cached = Some(parsed);
                Ok(Some(
                    parsed.materialize(self.bytes.as_slice(), self.oid_len),
                ))
            }
            ParseOutcome::Incomplete(stage) => Err(TreeDiffError::CorruptTree {
                detail: stage.error_detail(),
            }),
        }
    }

    fn advance(&mut self) -> Result<(), TreeDiffError> {
        if self.cached.is_none() {
            let _ = self.peek_entry()?;
        }
        if let Some(parsed) = self.cached.take() {
            self.pos = self.pos.saturating_add(parsed.entry_len);
        }
        Ok(())
    }

    fn in_flight_len(&self) -> u64 {
        self.bytes.in_flight_len() as u64
    }
}

/// Tree cursor selecting buffered vs streaming parsing.
enum TreeCursor {
    Buffered(BufferedCursor),
    Stream(TreeStream<TreeBytesReader>),
}

impl TreeCursor {
    /// Builds a cursor, selecting streaming for large or spill-backed trees.
    fn new(bytes: TreeBytes, oid_len: u8, stream_threshold: usize) -> Self {
        let use_stream = bytes.len() >= stream_threshold || matches!(bytes, TreeBytes::Spilled(_));
        if use_stream {
            let reader = TreeBytesReader::new(bytes);
            let stream = TreeStream::new(reader, oid_len, TREE_STREAM_BUF_BYTES);
            Self::Stream(stream)
        } else {
            Self::Buffered(BufferedCursor::new(bytes, oid_len))
        }
    }

    /// Returns an empty cursor with the configured OID length.
    fn empty(oid_len: u8) -> Self {
        Self::Buffered(BufferedCursor::new(TreeBytes::empty(), oid_len))
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        match self {
            Self::Buffered(cursor) => cursor.peek_entry(),
            Self::Stream(stream) => stream.peek_entry(),
        }
    }

    fn advance(&mut self) -> Result<(), TreeDiffError> {
        match self {
            Self::Buffered(cursor) => cursor.advance(),
            Self::Stream(stream) => stream.advance(),
        }
    }

    fn in_flight_len(&self) -> u64 {
        match self {
            Self::Buffered(cursor) => cursor.in_flight_len(),
            Self::Stream(stream) => stream.in_flight_len() as u64,
        }
    }
}

/// Tree diff walker configuration and state.
///
/// The walker maintains internal state (stack, path buffer, name scratch)
/// that is reused across multiple `diff_trees` calls for efficiency.
/// Candidate paths are assembled in a reusable buffer; sinks must copy
/// the provided path if they need to retain it.
///
/// # Invariants
/// - `stack.len() <= max_depth`
/// - `path_buf` holds the current path prefix for the top stack frame
pub struct TreeDiffWalker {
    /// Maximum recursion depth.
    max_depth: u16,
    /// OID length (20 or 32).
    oid_len: u8,
    /// Path buffer (reused across entries).
    path_buf: Vec<u8>,
    /// Reused entry-name scratch to avoid per-diff allocations.
    name_scratch: Vec<u8>,
    /// Diff stack (reused across calls).
    stack: Vec<DiffFrame>,
    /// Statistics.
    stats: TreeDiffStats,
    /// In-flight tree bytes budget.
    tree_bytes_in_flight_limit: u64,
    /// Current in-flight tree bytes retained by stack frames.
    tree_bytes_in_flight: u64,
    /// Threshold for switching to streaming parsing.
    stream_threshold: usize,
}

impl TreeDiffWalker {
    /// Creates a new tree diff walker.
    #[must_use]
    pub fn new(limits: &TreeDiffLimits, oid_len: u8) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );

        Self {
            max_depth: limits.max_tree_depth,
            oid_len,
            path_buf: Vec::with_capacity(4096),
            name_scratch: Vec::with_capacity(256),
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: TreeDiffStats::default(),
            tree_bytes_in_flight_limit: limits.max_tree_bytes_in_flight,
            tree_bytes_in_flight: 0,
            stream_threshold: limits.max_tree_cache_bytes.max(1) as usize,
        }
    }

    /// Returns the current statistics.
    #[must_use]
    pub fn stats(&self) -> &TreeDiffStats {
        &self.stats
    }

    /// Resets statistics for a new repo job.
    ///
    /// Call this when starting a new repository scan to get fresh stats.
    /// The internal buffers (stack, path_buf) are retained for reuse.
    /// The tree-bytes budget is enforced on in-flight bytes across calls.
    pub fn reset_stats(&mut self) {
        debug_assert!(
            self.stack.is_empty(),
            "reset_stats must be called with an empty diff stack"
        );
        self.stats = TreeDiffStats::default();
        self.tree_bytes_in_flight = 0;
    }

    /// Diffs two trees, emitting candidates for changed blobs.
    ///
    /// # Arguments
    ///
    /// * `source` - Tree object loader
    /// * `candidates` - Output sink for candidates
    /// * `new_tree` - OID of the new (child) tree, or None for empty tree
    /// * `old_tree` - OID of the old (parent) tree, or None for empty tree
    /// * `commit_id` - Commit identifier for attribution
    /// * `parent_idx` - Which parent this diff is against (for merge commits)
    ///
    /// # Errors
    ///
    /// - `CandidateBufferFull` if the candidate buffer is exhausted
    /// - `MaxTreeDepthExceeded` if recursion depth exceeds limit
    /// - `TreeBytesBudgetExceeded` if total tree bytes exceed budget
    /// - `PathTooLong` if a path exceeds MAX_PATH_LEN
    /// - Tree loading errors from the source
    ///
    /// # Notes
    ///
    /// - If `new_tree == old_tree`, this is a no-op.
    /// - `parent_idx` is preserved in candidate context for later merge/dedupe.
    /// - The candidate sink is appended to; it is not cleared by this call.
    /// - Candidate paths are borrowed from an internal buffer and are only
    ///   valid until the next emission.
    /// - Stats are cumulative across calls; `reset_stats()` clears counters.
    /// - The tree-bytes budget is enforced on in-flight bytes across calls until reset.
    pub fn diff_trees<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        new_tree: Option<&OidBytes>,
        old_tree: Option<&OidBytes>,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        if new_tree == old_tree {
            return Ok(());
        }

        self.path_buf.clear();
        self.stack.clear();
        let mut name_scratch = std::mem::take(&mut self.name_scratch);
        name_scratch.clear();
        debug_assert!(
            name_scratch.is_empty(),
            "name_scratch must be cleared before diff_trees"
        );

        let result = (|| {
            let new_cursor = self.load_tree_cursor(source, new_tree)?;
            let old_cursor = self.load_tree_cursor(source, old_tree)?;

            self.stack.push(DiffFrame {
                new_cursor,
                old_cursor,
                prefix_len: 0,
            });

            while !self.stack.is_empty() {
                let depth = self.stack.len() as u16;
                self.stats.max_depth_reached = self.stats.max_depth_reached.max(depth);

                let action = {
                    let frame = self.stack.last_mut().expect("frame exists");
                    let new_entry = frame.new_cursor.peek_entry()?;
                    let old_entry = frame.old_cursor.peek_entry()?;

                    let action = compute_action(new_entry, old_entry, self.oid_len)?;
                    if matches!(
                        action,
                        Action::AddedEntry { .. }
                            | Action::MatchedEntries { .. }
                            | Action::NewBeforeOld { .. }
                    ) {
                        let entry = new_entry.expect("name requires new entry");
                        name_scratch.clear();
                        name_scratch.extend_from_slice(entry.name);
                    }
                    action
                };

                match action {
                    Action::Pop => {
                        let frame = self.stack.pop().expect("frame exists");
                        self.release_tree_bytes(frame.new_cursor.in_flight_len());
                        self.release_tree_bytes(frame.old_cursor.in_flight_len());
                        self.path_buf.truncate(frame.prefix_len);
                    }
                    Action::AddedEntry { oid, kind, mode } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        self.handle_new_entry(
                            source,
                            candidates,
                            &oid,
                            &name_scratch,
                            kind,
                            mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::DeletedEntry => {
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.old_cursor.advance()?;
                    }
                    Action::MatchedEntries {
                        new_oid,
                        old_oid,
                        new_kind,
                        old_kind,
                        new_mode,
                    } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        frame.old_cursor.advance()?;
                        self.handle_matched_entries(
                            source,
                            candidates,
                            &new_oid,
                            &old_oid,
                            &name_scratch,
                            new_kind,
                            old_kind,
                            new_mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::NewBeforeOld { oid, kind, mode } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        self.handle_new_entry(
                            source,
                            candidates,
                            &oid,
                            &name_scratch,
                            kind,
                            mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::OldBeforeNew => {
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.old_cursor.advance()?;
                    }
                }
            }

            Ok(())
        })();

        self.name_scratch = name_scratch;

        result
    }

    /// Loads tree data and updates cumulative stats and in-flight budget.
    ///
    /// `None` yields an empty tree without incrementing counters.
    fn load_tree_cursor<S: TreeSource>(
        &mut self,
        source: &mut S,
        oid: Option<&OidBytes>,
    ) -> Result<TreeCursor, TreeDiffError> {
        // Loading a tree increments stats and enforces the in-flight budget.
        if let Some(oid) = oid {
            let bytes = source.load_tree(oid)?;
            let bytes_len = bytes.len() as u64;
            let in_flight_len = bytes.in_flight_len() as u64;
            let new_in_flight = self.tree_bytes_in_flight.saturating_add(in_flight_len);
            self.stats.trees_loaded += 1;
            self.stats.tree_bytes_loaded = self.stats.tree_bytes_loaded.saturating_add(bytes_len);

            if new_in_flight > self.tree_bytes_in_flight_limit {
                return Err(TreeDiffError::TreeBytesBudgetExceeded {
                    loaded: new_in_flight,
                    budget: self.tree_bytes_in_flight_limit,
                });
            }
            self.tree_bytes_in_flight = new_in_flight;
            self.stats.tree_bytes_in_flight_peak = self
                .stats
                .tree_bytes_in_flight_peak
                .max(self.tree_bytes_in_flight);

            Ok(TreeCursor::new(bytes, self.oid_len, self.stream_threshold))
        } else {
            Ok(TreeCursor::empty(self.oid_len))
        }
    }

    fn release_tree_bytes(&mut self, len: u64) {
        self.tree_bytes_in_flight = self.tree_bytes_in_flight.saturating_sub(len);
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_new_entry<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        oid: &OidBytes,
        name: &[u8],
        kind: EntryKind,
        mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        if kind.is_tree() {
            self.push_subtree_frame(source, oid, None, name)?;
        } else if kind.is_blob_like() {
            self.emit_candidate(
                candidates,
                oid,
                name,
                ChangeKind::Add,
                mode,
                commit_id,
                parent_idx,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_matched_entries<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        new_oid: &OidBytes,
        old_oid: &OidBytes,
        name: &[u8],
        new_kind: EntryKind,
        old_kind: EntryKind,
        new_mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        if new_oid == old_oid && new_kind.is_tree() && old_kind.is_tree() {
            self.stats.subtrees_skipped += 1;
            return Ok(());
        }

        match (new_kind.is_tree(), old_kind.is_tree()) {
            (true, true) => {
                self.push_subtree_frame(source, new_oid, Some(old_oid), name)?;
            }
            (true, false) => {
                // Old was non-tree, new is tree; treat as new tree added.
                self.push_subtree_frame(source, new_oid, None, name)?;
            }
            (false, true) => {
                // Old was tree, new is non-tree.
                if new_kind.is_blob_like() {
                    self.emit_candidate(
                        candidates,
                        new_oid,
                        name,
                        ChangeKind::Add,
                        new_mode,
                        commit_id,
                        parent_idx,
                    )?;
                }
            }
            (false, false) => {
                if new_kind.is_blob_like() {
                    if old_kind.is_blob_like() {
                        if new_oid != old_oid {
                            self.emit_candidate(
                                candidates,
                                new_oid,
                                name,
                                ChangeKind::Modify,
                                new_mode,
                                commit_id,
                                parent_idx,
                            )?;
                        }
                    } else {
                        self.emit_candidate(
                            candidates,
                            new_oid,
                            name,
                            ChangeKind::Add,
                            new_mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Pushes a subtree frame, extending `path_buf` with `name/`.
    fn push_subtree_frame<S: TreeSource>(
        &mut self,
        source: &mut S,
        new_oid: &OidBytes,
        old_oid: Option<&OidBytes>,
        name: &[u8],
    ) -> Result<(), TreeDiffError> {
        // Extend the path buffer with "name/" for the subtree frame.
        if self.stack.len() >= self.max_depth as usize {
            return Err(TreeDiffError::MaxTreeDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        let new_len = self.path_buf.len() + name.len() + 1;
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }

        let prefix_len = self.path_buf.len();
        self.path_buf.extend_from_slice(name);
        self.path_buf.push(b'/');

        let new_cursor = self.load_tree_cursor(source, Some(new_oid))?;
        let old_cursor = self.load_tree_cursor(source, old_oid)?;

        self.stack.push(DiffFrame {
            new_cursor,
            old_cursor,
            prefix_len,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    /// Emits a candidate using the current path prefix plus `name`.
    ///
    /// The path slice is backed by an internal buffer that is reused on the
    /// next emission; sinks must copy the path if they need to retain it.
    fn emit_candidate<C: CandidateSink>(
        &mut self,
        candidates: &mut C,
        oid: &OidBytes,
        name: &[u8],
        change_kind: ChangeKind,
        mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        // Temporarily append the leaf name to the current path prefix.
        let full_len = self.path_buf.len() + name.len();
        if full_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: full_len,
                max: MAX_PATH_LEN,
            });
        }

        let path_start = self.path_buf.len();
        self.path_buf.extend_from_slice(name);

        let mode_u16 = mode as u16;
        // Path classification is deferred until post-dedupe to avoid per-candidate work.
        let cand_flags = 0;

        candidates.emit(
            *oid,
            &self.path_buf,
            commit_id,
            parent_idx,
            change_kind,
            mode_u16,
            cand_flags,
        )?;

        self.stats.candidates_emitted += 1;

        self.path_buf.truncate(path_start);

        Ok(())
    }
}

/// Computes the next action by comparing tree entries in Git tree order.
fn compute_action(
    new_entry: Option<TreeEntry<'_>>,
    old_entry: Option<TreeEntry<'_>>,
    oid_len: u8,
) -> Result<Action, TreeDiffError> {
    match (new_entry, old_entry) {
        (None, None) => Ok(Action::Pop),

        (Some(new_ent), None) => {
            let oid = convert_oid(new_ent.oid_bytes, oid_len)?;
            Ok(Action::AddedEntry {
                oid,
                kind: new_ent.kind,
                mode: new_ent.mode,
            })
        }

        (None, Some(_)) => Ok(Action::DeletedEntry),

        (Some(new_ent), Some(old_ent)) => {
            let cmp = git_tree_name_cmp(
                new_ent.name,
                new_ent.kind.is_tree(),
                old_ent.name,
                old_ent.kind.is_tree(),
            );

            match cmp {
                Ordering::Less => {
                    let oid = convert_oid(new_ent.oid_bytes, oid_len)?;
                    Ok(Action::NewBeforeOld {
                        oid,
                        kind: new_ent.kind,
                        mode: new_ent.mode,
                    })
                }
                Ordering::Greater => Ok(Action::OldBeforeNew),
                Ordering::Equal => {
                    let new_oid = convert_oid(new_ent.oid_bytes, oid_len)?;
                    let old_oid = convert_oid(old_ent.oid_bytes, oid_len)?;
                    Ok(Action::MatchedEntries {
                        new_oid,
                        old_oid,
                        new_kind: new_ent.kind,
                        old_kind: old_ent.kind,
                        new_mode: new_ent.mode,
                    })
                }
            }
        }
    }
}

/// Converts raw OID bytes into `OidBytes`, enforcing the configured length.
fn convert_oid(bytes: &[u8], oid_len: u8) -> Result<OidBytes, TreeDiffError> {
    OidBytes::try_from_slice(bytes).ok_or(TreeDiffError::InvalidOidLength {
        len: bytes.len(),
        expected: oid_len as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::CandidateBuffer;

    use std::collections::HashMap;

    struct MockTreeSource {
        trees: HashMap<OidBytes, Vec<u8>>,
    }

    impl MockTreeSource {
        fn new() -> Self {
            Self {
                trees: HashMap::new(),
            }
        }

        fn add_tree(&mut self, oid: OidBytes, data: Vec<u8>) {
            self.trees.insert(oid, data);
        }
    }

    impl TreeSource for MockTreeSource {
        fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
            self.trees
                .get(oid)
                .cloned()
                .map(TreeBytes::Owned)
                .ok_or(TreeDiffError::TreeNotFound)
        }
    }

    fn make_entry(mode: &[u8], name: &[u8], oid: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(mode);
        entry.push(b' ');
        entry.extend_from_slice(name);
        entry.push(0);
        entry.extend_from_slice(oid);
        entry
    }

    fn test_oid(val: u8) -> OidBytes {
        OidBytes::sha1([val; 20])
    }

    fn test_limits() -> TreeDiffLimits {
        TreeDiffLimits {
            max_candidates: 1000,
            max_tree_depth: 64,
            max_tree_bytes_in_flight: 1024 * 1024,
            ..TreeDiffLimits::RESTRICTIVE
        }
    }

    #[test]
    fn diff_identical_trees() {
        let mut source = MockTreeSource::new();
        let oid = test_oid(1);
        let data = make_entry(b"100644", b"file.txt", &[0xab; 20]);
        source.add_tree(oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&oid), Some(&oid), 1, 0)
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn diff_add_single_file() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let blob_oid = [0xab; 20];
        let data = make_entry(b"100644", b"file.txt", &blob_oid);
        source.add_tree(new_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&new_oid), None, 1, 0)
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"file.txt");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn diff_delete_single_file() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        let data = make_entry(b"100644", b"file.txt", &[0xab; 20]);
        source.add_tree(old_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, None, Some(&old_oid), 1, 0)
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn diff_modify_single_file() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        let old_blob = [0xaa; 20];
        source.add_tree(old_oid, make_entry(b"100644", b"file.txt", &old_blob));

        let new_oid = test_oid(2);
        let new_blob = [0xbb; 20];
        source.add_tree(new_oid, make_entry(b"100644", b"file.txt", &new_blob));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].change_kind, ChangeKind::Modify);
        assert_eq!(resolved[0].oid.as_slice(), &new_blob);
    }

    #[test]
    fn diff_unchanged_file_skipped() {
        let mut source = MockTreeSource::new();

        let blob_oid = [0xab; 20];

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"100644", b"file.txt", &blob_oid));

        let new_oid = test_oid(2);
        source.add_tree(new_oid, make_entry(b"100644", b"file.txt", &blob_oid));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn diff_with_subdirectory() {
        let mut source = MockTreeSource::new();

        let subdir_oid = test_oid(10);
        let blob_oid = [0xab; 20];
        source.add_tree(subdir_oid, make_entry(b"100644", b"nested.txt", &blob_oid));

        let root_oid = test_oid(1);
        let mut root_data = make_entry(b"40000", b"subdir", subdir_oid.as_slice());
        root_data.extend(make_entry(b"100644", b"root.txt", &[0xcc; 20]));
        source.add_tree(root_oid, root_data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&root_oid), None, 1, 0)
            .unwrap();

        assert_eq!(candidates.len(), 2);

        let paths: Vec<_> = candidates
            .iter_resolved()
            .map(|c| c.path.to_vec())
            .collect();
        assert!(paths.contains(&b"root.txt".to_vec()));
        assert!(paths.contains(&b"subdir/nested.txt".to_vec()));
    }

    #[test]
    fn subtree_skipped_when_unchanged() {
        let mut source = MockTreeSource::new();

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"file.txt", &[0xab; 20]));

        let old_root = test_oid(1);
        source.add_tree(
            old_root,
            make_entry(b"40000", b"subdir", subdir_oid.as_slice()),
        );

        let new_root = test_oid(2);
        source.add_tree(
            new_root,
            make_entry(b"40000", b"subdir", subdir_oid.as_slice()),
        );

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_root),
                Some(&old_root),
                1,
                0,
            )
            .unwrap();

        assert!(candidates.is_empty());
        assert_eq!(walker.stats().subtrees_skipped, 1);
    }

    #[test]
    fn depth_limit_enforced() {
        let mut source = MockTreeSource::new();

        let file_oid = [0xab; 20];

        let c_tree = test_oid(13);
        source.add_tree(c_tree, make_entry(b"100644", b"file.txt", &file_oid));

        let b_tree = test_oid(12);
        source.add_tree(b_tree, make_entry(b"40000", b"c", c_tree.as_slice()));

        let a_tree = test_oid(11);
        source.add_tree(a_tree, make_entry(b"40000", b"b", b_tree.as_slice()));

        let root = test_oid(1);
        source.add_tree(root, make_entry(b"40000", b"a", a_tree.as_slice()));

        let limits = TreeDiffLimits {
            max_tree_depth: 2,
            ..test_limits()
        };
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        let result = walker.diff_trees(&mut source, &mut candidates, Some(&root), None, 1, 0);

        assert!(matches!(
            result,
            Err(TreeDiffError::MaxTreeDepthExceeded { max_depth: 2 })
        ));
    }

    #[test]
    fn gitlink_skipped() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let data = make_entry(b"160000", b"submodule", &[0xab; 20]);
        source.add_tree(new_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&new_oid), None, 1, 0)
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn gitlink_to_blob_emits_candidate() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"160000", b"module", &[0xaa; 20]));

        let new_oid = test_oid(2);
        let blob_oid = [0xbb; 20];
        source.add_tree(new_oid, make_entry(b"100644", b"module", &blob_oid));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"module");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn blob_to_gitlink_skipped() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"100644", b"module", &[0xaa; 20]));

        let new_oid = test_oid(2);
        source.add_tree(new_oid, make_entry(b"160000", b"module", &[0xbb; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn file_becomes_directory() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"100644", b"foo", &[0xaa; 20]));

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"bar.txt", &[0xbb; 20]));

        let new_oid = test_oid(2);
        source.add_tree(new_oid, make_entry(b"40000", b"foo", subdir_oid.as_slice()));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"foo/bar.txt");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn directory_becomes_file() {
        let mut source = MockTreeSource::new();

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"bar.txt", &[0xaa; 20]));

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"40000", b"foo", subdir_oid.as_slice()));

        let new_oid = test_oid(2);
        let blob_oid = [0xbb; 20];
        source.add_tree(new_oid, make_entry(b"100644", b"foo", &blob_oid));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"foo");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn path_too_long_rejected() {
        let mut source = MockTreeSource::new();

        let long_name = vec![b'a'; 2000];
        let file_oid = [0xab; 20];

        let l3_oid = test_oid(13);
        source.add_tree(l3_oid, make_entry(b"100644", b"f.txt", &file_oid));

        let l2_oid = test_oid(12);
        source.add_tree(l2_oid, make_entry(b"40000", &long_name, l3_oid.as_slice()));

        let l1_oid = test_oid(11);
        source.add_tree(l1_oid, make_entry(b"40000", &long_name, l2_oid.as_slice()));

        let root = test_oid(1);
        source.add_tree(root, make_entry(b"40000", &long_name, l1_oid.as_slice()));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        let result = walker.diff_trees(&mut source, &mut candidates, Some(&root), None, 1, 0);

        assert!(matches!(result, Err(TreeDiffError::PathTooLong { .. })));
    }

    #[test]
    fn stats_tracking() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let data = make_entry(b"100644", b"file.txt", &[0xab; 20]);
        source.add_tree(new_oid, data.clone());

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&new_oid), None, 1, 0)
            .unwrap();

        let stats = walker.stats();
        assert_eq!(stats.trees_loaded, 1);
        assert_eq!(stats.tree_bytes_loaded as usize, data.len());
        assert_eq!(stats.candidates_emitted, 1);
    }

    #[test]
    fn stats_reset() {
        let mut source = MockTreeSource::new();
        let oid = test_oid(1);
        source.add_tree(oid, make_entry(b"100644", b"file.txt", &[0xab; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&oid), None, 1, 0)
            .unwrap();
        assert_eq!(walker.stats().candidates_emitted, 1);

        walker.reset_stats();
        assert_eq!(walker.stats().candidates_emitted, 0);
        assert_eq!(walker.stats().trees_loaded, 0);
    }

    #[test]
    fn stack_reused_across_calls() {
        let mut source = MockTreeSource::new();

        let oid1 = test_oid(1);
        source.add_tree(oid1, make_entry(b"100644", b"a.txt", &[0xaa; 20]));

        let oid2 = test_oid(2);
        source.add_tree(oid2, make_entry(b"100644", b"b.txt", &[0xbb; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&oid1), None, 1, 0)
            .unwrap();
        walker
            .diff_trees(&mut source, &mut candidates, Some(&oid2), None, 2, 0)
            .unwrap();

        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn symlink_emits_candidate() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let link_target_oid = [0xab; 20];
        let data = make_entry(b"120000", b"link", &link_target_oid);
        source.add_tree(new_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(&mut source, &mut candidates, Some(&new_oid), None, 1, 0)
            .unwrap();

        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn multiple_changes_in_one_diff() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        let mut old_data = make_entry(b"100644", b"file1.txt", &[0x11; 20]);
        old_data.extend(make_entry(b"100644", b"file2.txt", &[0x22; 20]));
        old_data.extend(make_entry(b"100644", b"file3.txt", &[0x33; 20]));
        source.add_tree(old_oid, old_data);

        let new_oid = test_oid(2);
        let mut new_data = make_entry(b"100644", b"file1.txt", &[0xaa; 20]);
        new_data.extend(make_entry(b"100644", b"file3.txt", &[0x33; 20]));
        new_data.extend(make_entry(b"100644", b"file4.txt", &[0x44; 20]));
        source.add_tree(new_oid, new_data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
            )
            .unwrap();

        assert_eq!(candidates.len(), 2);

        let resolved: Vec<_> = candidates.iter_resolved().collect();
        let paths: Vec<&[u8]> = resolved.iter().map(|c| c.path).collect();
        assert!(paths.contains(&b"file1.txt".as_slice()));
        assert!(paths.contains(&b"file4.txt".as_slice()));
    }
}
