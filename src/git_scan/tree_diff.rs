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
//!
//! # Output Ordering
//! Candidates are emitted in Git tree order for each diff. For merge commits,
//! the caller should invoke `diff_trees` once per parent; `parent_idx` tags
//! the candidate with which parent diff produced it.
//!
//! # Budgeting
//! The tree-bytes budget is enforced cumulatively via `TreeDiffStats`. Call
//! `reset_stats()` when starting a new repo job to reset the budget counter.

use std::cmp::Ordering;

use super::errors::TreeDiffError;
use super::object_id::OidBytes;
use super::object_store::TreeSource;
use super::path_policy::classify_path;
use super::tree_candidate::{CandidateBuffer, ChangeKind};
use super::tree_diff_limits::TreeDiffLimits;
use super::tree_entry::{EntryKind, TreeEntry, TreeEntryIter};
use super::tree_order::git_tree_name_cmp;

/// Maximum path length in bytes.
///
/// This matches common filesystem limits (PATH_MAX on Linux/macOS).
/// Paths exceeding this are rejected to prevent DoS via deeply nested trees.
const MAX_PATH_LEN: usize = 8192;

/// Counters for tree diff operations.
///
/// Statistics are cumulative until `reset_stats()` is called.
#[derive(Clone, Debug, Default)]
pub struct TreeDiffStats {
    /// Number of trees loaded.
    pub trees_loaded: u64,
    /// Total bytes loaded from trees.
    pub tree_bytes_loaded: u64,
    /// Number of candidates emitted.
    pub candidates_emitted: u64,
    /// Number of subtrees skipped (same OID).
    pub subtrees_skipped: u64,
    /// Maximum stack depth reached.
    pub max_depth_reached: u16,
}

/// Stack frame for iterative tree diff.
struct DiffFrame {
    /// New tree bytes (owned to avoid lifetime issues).
    new_bytes: Vec<u8>,
    /// Old tree bytes (owned).
    old_bytes: Vec<u8>,
    /// Position in new_bytes.
    new_pos: usize,
    /// Position in old_bytes.
    old_pos: usize,
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
    /// Entry only in new tree: advance new_pos and process.
    AddedEntry {
        new_end: usize,
        oid: OidBytes,
        name_copy: Vec<u8>,
        kind: EntryKind,
        mode: u32,
    },
    /// Entry only in old tree: advance old_pos (deletion, skip).
    DeletedEntry { old_end: usize },
    /// Entries match (same name+type in ordering), names lexically equal.
    MatchedEntries {
        new_end: usize,
        old_end: usize,
        new_oid: OidBytes,
        old_oid: OidBytes,
        new_kind: EntryKind,
        old_kind: EntryKind,
        name_copy: Vec<u8>,
        new_mode: u32,
    },
    /// new < old in tree ordering: entry added in new tree.
    NewBeforeOld {
        new_end: usize,
        oid: OidBytes,
        name_copy: Vec<u8>,
        kind: EntryKind,
        mode: u32,
    },
    /// new > old in tree ordering: entry deleted from old tree.
    OldBeforeNew { old_end: usize },
}

/// Tree diff walker configuration and state.
///
/// The walker maintains internal state (stack, path buffer) that is reused
/// across multiple `diff_trees` calls for efficiency.
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
    /// Diff stack (reused across calls).
    stack: Vec<DiffFrame>,
    /// Statistics.
    stats: TreeDiffStats,
    /// Total tree bytes budget.
    tree_bytes_budget: u64,
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
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: TreeDiffStats::default(),
            tree_bytes_budget: limits.max_tree_bytes_per_job,
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
    pub fn reset_stats(&mut self) {
        self.stats = TreeDiffStats::default();
    }

    /// Diffs two trees, emitting candidates for changed blobs.
    ///
    /// # Arguments
    ///
    /// * `source` - Tree object loader
    /// * `candidates` - Output buffer for candidates
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
    /// - The candidate buffer is appended to; it is not cleared by this call.
    pub fn diff_trees<S: TreeSource>(
        &mut self,
        source: &mut S,
        candidates: &mut CandidateBuffer,
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

        let new_bytes = self.load_tree_bytes(source, new_tree)?;
        let old_bytes = self.load_tree_bytes(source, old_tree)?;

        self.stack.push(DiffFrame {
            new_bytes,
            old_bytes,
            new_pos: 0,
            old_pos: 0,
            prefix_len: 0,
        });

        while !self.stack.is_empty() {
            let depth = self.stack.len() as u16;
            self.stats.max_depth_reached = self.stats.max_depth_reached.max(depth);

            let frame = self.stack.last_mut().expect("frame exists");

            let new_entry = next_entry(&frame.new_bytes, frame.new_pos, self.oid_len)?;
            let old_entry = next_entry(&frame.old_bytes, frame.old_pos, self.oid_len)?;

            let action = compute_action(new_entry, old_entry, self.oid_len)?;

            match action {
                Action::Pop => {
                    let frame = self.stack.pop().expect("frame exists");
                    self.path_buf.truncate(frame.prefix_len);
                }
                Action::AddedEntry {
                    new_end,
                    oid,
                    name_copy,
                    kind,
                    mode,
                } => {
                    frame.new_pos = new_end;
                    self.handle_new_entry(
                        source, candidates, &oid, &name_copy, kind, mode, commit_id, parent_idx,
                    )?;
                }
                Action::DeletedEntry { old_end } => {
                    frame.old_pos = old_end;
                }
                Action::MatchedEntries {
                    new_end,
                    old_end,
                    new_oid,
                    old_oid,
                    new_kind,
                    old_kind,
                    name_copy,
                    new_mode,
                } => {
                    frame.new_pos = new_end;
                    frame.old_pos = old_end;
                    self.handle_matched_entries(
                        source, candidates, &new_oid, &old_oid, &name_copy, new_kind, old_kind,
                        new_mode, commit_id, parent_idx,
                    )?;
                }
                Action::NewBeforeOld {
                    new_end,
                    oid,
                    name_copy,
                    kind,
                    mode,
                } => {
                    frame.new_pos = new_end;
                    self.handle_new_entry(
                        source, candidates, &oid, &name_copy, kind, mode, commit_id, parent_idx,
                    )?;
                }
                Action::OldBeforeNew { old_end } => {
                    frame.old_pos = old_end;
                }
            }
        }

        Ok(())
    }

    fn load_tree_bytes<S: TreeSource>(
        &mut self,
        source: &mut S,
        oid: Option<&OidBytes>,
    ) -> Result<Vec<u8>, TreeDiffError> {
        // Loading a tree increments stats and enforces the cumulative budget.
        if let Some(oid) = oid {
            let bytes = source.load_tree(oid)?;
            self.stats.trees_loaded += 1;
            self.stats.tree_bytes_loaded += bytes.len() as u64;

            if self.stats.tree_bytes_loaded > self.tree_bytes_budget {
                return Err(TreeDiffError::TreeBytesBudgetExceeded {
                    loaded: self.stats.tree_bytes_loaded,
                    budget: self.tree_bytes_budget,
                });
            }

            Ok(bytes)
        } else {
            Ok(Vec::new())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_new_entry<S: TreeSource>(
        &mut self,
        source: &mut S,
        candidates: &mut CandidateBuffer,
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
    fn handle_matched_entries<S: TreeSource>(
        &mut self,
        source: &mut S,
        candidates: &mut CandidateBuffer,
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
                    let change_kind = if old_kind.is_blob_like() {
                        ChangeKind::Modify
                    } else {
                        ChangeKind::Add
                    };
                    self.emit_candidate(
                        candidates,
                        new_oid,
                        name,
                        change_kind,
                        new_mode,
                        commit_id,
                        parent_idx,
                    )?;
                }
            }
        }

        Ok(())
    }

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

        self.path_buf.extend_from_slice(name);
        self.path_buf.push(b'/');

        let new_bytes = self.load_tree_bytes(source, Some(new_oid))?;
        let old_bytes = self.load_tree_bytes(source, old_oid)?;

        self.stack.push(DiffFrame {
            new_bytes,
            old_bytes,
            new_pos: 0,
            old_pos: 0,
            prefix_len: self.path_buf.len(),
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_candidate(
        &mut self,
        candidates: &mut CandidateBuffer,
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
        let cand_flags = classify_path(&self.path_buf).bits();

        candidates.push(
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

fn compute_action(
    new_entry: Option<(TreeEntry<'_>, usize)>,
    old_entry: Option<(TreeEntry<'_>, usize)>,
    oid_len: u8,
) -> Result<Action, TreeDiffError> {
    match (new_entry, old_entry) {
        (None, None) => Ok(Action::Pop),

        (Some((new_ent, new_end)), None) => {
            let oid = convert_oid(new_ent.oid_bytes, oid_len)?;
            Ok(Action::AddedEntry {
                new_end,
                oid,
                name_copy: new_ent.name.to_vec(),
                kind: new_ent.kind,
                mode: new_ent.mode,
            })
        }

        (None, Some((_, old_end))) => Ok(Action::DeletedEntry { old_end }),

        (Some((new_ent, new_end)), Some((old_ent, old_end))) => {
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
                        new_end,
                        oid,
                        name_copy: new_ent.name.to_vec(),
                        kind: new_ent.kind,
                        mode: new_ent.mode,
                    })
                }
                Ordering::Greater => Ok(Action::OldBeforeNew { old_end }),
                Ordering::Equal => {
                    let new_oid = convert_oid(new_ent.oid_bytes, oid_len)?;
                    let old_oid = convert_oid(old_ent.oid_bytes, oid_len)?;
                    Ok(Action::MatchedEntries {
                        new_end,
                        old_end,
                        new_oid,
                        old_oid,
                        new_kind: new_ent.kind,
                        old_kind: old_ent.kind,
                        name_copy: new_ent.name.to_vec(),
                        new_mode: new_ent.mode,
                    })
                }
            }
        }
    }
}

fn next_entry(
    bytes: &[u8],
    pos: usize,
    oid_len: u8,
) -> Result<Option<(TreeEntry<'_>, usize)>, TreeDiffError> {
    if pos >= bytes.len() {
        return Ok(None);
    }

    let mut iter = TreeEntryIter::new(&bytes[pos..], oid_len as usize);
    let entry = iter.next_entry()?;
    if let Some(entry) = entry {
        let end = pos + iter.position();
        Ok(Some((entry, end)))
    } else {
        Ok(None)
    }
}

fn convert_oid(bytes: &[u8], oid_len: u8) -> Result<OidBytes, TreeDiffError> {
    OidBytes::try_from_slice(bytes).ok_or(TreeDiffError::InvalidOidLength {
        len: bytes.len(),
        expected: oid_len as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        fn load_tree(&mut self, oid: &OidBytes) -> Result<Vec<u8>, TreeDiffError> {
            self.trees
                .get(oid)
                .cloned()
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
            max_tree_bytes_per_job: 1024 * 1024,
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
