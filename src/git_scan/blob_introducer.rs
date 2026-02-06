//! First-introduced blob walk for ODB-blob scan mode.
//!
//! This module traverses commits in topological order and discovers each
//! unique blob exactly once. It maintains seen-set bitmaps keyed by MIDX
//! indices so repeated trees/blobs are skipped without re-parsing.
//!
//! # Invariants
//! - Seen sets are sized to `midx.object_count` and never grow.
//! - OID indices must be validated before use (caller responsibility).
//! - Tree and blob indices share the same index space but are tracked
//!   independently to avoid false positives.
//! - Paths are assembled in a reusable buffer and must not exceed
//!   `MAX_PATH_LEN`.

use crate::perf_stats;
use crate::stdx::bitset::DynamicBitSet;

use super::errors::{MappingCandidateKind, TreeDiffError};
use super::object_id::OidBytes;
use super::object_store::TreeBytes;
use super::oid_index::OidIndex;
use super::path_policy::{classify_path, is_excluded_path};
use super::tree_candidate::{CandidateSink, ChangeKind};
use super::tree_diff::TreeDiffStats;
use super::tree_diff_limits::TreeDiffLimits;
use super::tree_entry::{parse_entry, EntryKind, ParseOutcome, ParsedTreeEntry, TreeEntry};
use super::tree_stream::{TreeBytesReader, TreeStream};
use super::{CommitGraphIndex, PlannedCommit, TreeSource};

const TREE_STREAM_BUF_BYTES: usize = 16 * 1024;
const MAX_PATH_LEN: usize = 4096;

/// Seen-set bitmaps for trees and blobs keyed by MIDX index.
#[derive(Debug)]
pub struct SeenSets {
    trees: DynamicBitSet,
    blobs: DynamicBitSet,
    blobs_excluded: DynamicBitSet,
}

impl SeenSets {
    /// Creates empty seen sets sized to the MIDX object count.
    pub fn new(object_count: u32) -> Self {
        let bits = object_count as usize;
        Self {
            trees: DynamicBitSet::empty(bits),
            blobs: DynamicBitSet::empty(bits),
            blobs_excluded: DynamicBitSet::empty(bits),
        }
    }

    /// Clears all seen bits.
    pub fn clear(&mut self) {
        self.trees.clear();
        self.blobs.clear();
        self.blobs_excluded.clear();
    }

    /// Marks a tree index as seen, returning true if it was newly set.
    #[inline]
    pub fn mark_tree(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.trees.is_set(idx) {
            false
        } else {
            self.trees.set(idx);
            true
        }
    }

    /// Marks a blob index as seen, returning true if it was newly set.
    #[inline]
    pub fn mark_blob(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.blobs.is_set(idx) {
            false
        } else {
            self.blobs.set(idx);
            true
        }
    }

    /// Marks a blob index as excluded, returning true if it was newly set.
    #[inline]
    pub fn mark_blob_excluded(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.blobs_excluded.is_set(idx) {
            false
        } else {
            self.blobs_excluded.set(idx);
            true
        }
    }

    /// Returns true if the tree index is already seen.
    #[inline]
    pub fn is_tree_seen(&self, idx: u32) -> bool {
        self.trees.is_set(idx as usize)
    }

    /// Returns true if the blob index is already seen.
    #[inline]
    pub fn is_blob_seen(&self, idx: u32) -> bool {
        self.blobs.is_set(idx as usize)
    }

    /// Returns true if the blob index is already marked excluded.
    #[inline]
    pub fn is_blob_excluded(&self, idx: u32) -> bool {
        self.blobs_excluded.is_set(idx as usize)
    }
}

#[derive(Clone, Copy, Debug)]
struct LooseEntry {
    key: OidBytes,
    tag: u8,
    occupied: bool,
}

impl LooseEntry {
    #[inline]
    fn empty() -> Self {
        Self {
            key: OidBytes::default(),
            tag: 0,
            occupied: false,
        }
    }
}

/// Fixed-capacity open addressing set for loose OIDs.
#[derive(Debug)]
struct LooseOidSet {
    entries: Vec<LooseEntry>,
    mask: usize,
    len: u32,
    oid_len: u8,
    max_items: u32,
    kind: MappingCandidateKind,
}

impl LooseOidSet {
    fn new(max_items: u32, oid_len: u8, kind: MappingCandidateKind) -> Self {
        let max_items = max_items.max(1);
        let capacity = table_size_for_count(max_items as usize);
        Self {
            entries: vec![LooseEntry::empty(); capacity],
            mask: capacity - 1,
            len: 0,
            oid_len,
            max_items,
            kind,
        }
    }

    fn clear(&mut self) {
        self.entries.fill(LooseEntry::empty());
        self.len = 0;
    }

    fn contains(&self, oid: &OidBytes) -> bool {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &self.entries[slot];
            if !entry.occupied {
                return false;
            }
            if entry.tag == tag && entry.key == *oid {
                return true;
            }
            slot = (slot + 1) & self.mask;
        }

        false
    }

    fn insert(&mut self, oid: &OidBytes) -> Result<bool, TreeDiffError> {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        if self.len >= self.max_items {
            return Err(TreeDiffError::CandidateLimitExceeded {
                kind: self.kind,
                max: self.max_items,
                observed: self.len.saturating_add(1),
            });
        }

        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &mut self.entries[slot];
            if !entry.occupied {
                entry.key = *oid;
                entry.tag = tag;
                entry.occupied = true;
                self.len += 1;
                return Ok(true);
            }
            if entry.tag == tag && entry.key == *oid {
                return Ok(false);
            }
            slot = (slot + 1) & self.mask;
        }

        Err(TreeDiffError::CandidateLimitExceeded {
            kind: self.kind,
            max: self.max_items,
            observed: self.len.saturating_add(1),
        })
    }
}

/// Statistics for the blob introducer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlobIntroStats {
    /// Number of commits visited.
    pub commits_visited: u64,
    /// Number of trees loaded.
    pub trees_loaded: u64,
    /// Total bytes loaded from trees.
    pub tree_bytes_loaded: u64,
    /// Peak in-flight tree bytes retained by the stack.
    pub tree_bytes_in_flight_peak: u64,
    /// Number of blobs emitted.
    pub blobs_emitted: u64,
    /// Number of subtrees skipped because the tree OID was already seen.
    pub subtrees_skipped: u64,
    /// Maximum stack depth reached.
    pub max_depth_reached: u16,
}

impl From<BlobIntroStats> for TreeDiffStats {
    fn from(stats: BlobIntroStats) -> Self {
        Self {
            trees_loaded: stats.trees_loaded,
            tree_bytes_loaded: stats.tree_bytes_loaded,
            tree_bytes_in_flight_peak: stats.tree_bytes_in_flight_peak,
            candidates_emitted: stats.blobs_emitted,
            subtrees_skipped: stats.subtrees_skipped,
            max_depth_reached: stats.max_depth_reached,
        }
    }
}

/// Reusable path builder for tree traversal.
#[derive(Debug)]
struct PathBuilder {
    buf: Vec<u8>,
    stack: Vec<usize>,
}

impl PathBuilder {
    fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            stack: Vec::with_capacity(64),
        }
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.stack.clear();
    }

    fn push_dir(&mut self, name: &[u8]) -> Result<(), TreeDiffError> {
        let new_len = self.buf.len() + name.len() + 1;
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }
        self.stack.push(self.buf.len());
        self.buf.extend_from_slice(name);
        self.buf.push(b'/');
        Ok(())
    }

    fn pop_dir(&mut self) {
        if let Some(len) = self.stack.pop() {
            self.buf.truncate(len);
        }
    }

    fn push_leaf(&mut self, name: &[u8]) -> Result<usize, TreeDiffError> {
        let new_len = self.buf.len() + name.len();
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(name);
        Ok(start)
    }

    fn pop_leaf(&mut self, start: usize) {
        self.buf.truncate(start);
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Buffered tree cursor with cached parsing, used for small trees.
struct BufferedCursor {
    bytes: TreeBytes,
    pos: usize,
    oid_len: u8,
    cached: Option<ParsedTreeEntry>,
}

impl BufferedCursor {
    fn new(bytes: TreeBytes, oid_len: u8) -> Self {
        Self {
            bytes,
            pos: 0,
            oid_len,
            cached: None,
        }
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        if let Some(parsed) = self.cached {
            return Ok(Some(
                parsed.materialize(self.bytes.as_slice(), self.oid_len),
            ));
        }

        let data = self.bytes.as_slice();
        if self.pos >= data.len() {
            return Ok(None);
        }

        match parse_entry(&data[self.pos..], self.oid_len)? {
            ParseOutcome::Complete(mut parsed) => {
                parsed.offset_by(self.pos);
                self.cached = Some(parsed);
                Ok(Some(parsed.materialize(data, self.oid_len)))
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

    fn in_flight_len(&self) -> usize {
        self.bytes.in_flight_len()
    }
}

/// Tree cursor selecting buffered vs streaming parsing.
enum TreeCursor {
    Buffered(BufferedCursor),
    Stream(TreeStream<TreeBytesReader>),
}

impl TreeCursor {
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
            Self::Buffered(cursor) => cursor.in_flight_len() as u64,
            Self::Stream(stream) => stream.in_flight_len() as u64,
        }
    }
}

struct TreeFrame {
    cursor: TreeCursor,
    in_flight_len: u64,
}

/// Blob introducer state.
pub struct BlobIntroducer {
    max_depth: u16,
    oid_len: u8,
    path_builder: PathBuilder,
    name_scratch: Vec<u8>,
    stack: Vec<TreeFrame>,
    stats: BlobIntroStats,
    tree_bytes_in_flight_limit: u64,
    tree_bytes_in_flight: u64,
    stream_threshold: usize,
    seen: SeenSets,
    loose_seen: LooseOidSet,
    loose_excluded: LooseOidSet,
    path_policy_version: u32,
}

impl BlobIntroducer {
    /// Creates a new blob introducer sized to the MIDX object count.
    pub fn new(
        limits: &TreeDiffLimits,
        oid_len: u8,
        object_count: u32,
        path_policy_version: u32,
        max_loose_oids: u32,
    ) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );
        Self {
            max_depth: limits.max_tree_depth,
            oid_len,
            path_builder: PathBuilder::new(4096),
            name_scratch: Vec::with_capacity(256),
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: BlobIntroStats::default(),
            tree_bytes_in_flight_limit: limits.max_tree_bytes_in_flight,
            tree_bytes_in_flight: 0,
            stream_threshold: limits.max_tree_cache_bytes.max(1) as usize,
            seen: SeenSets::new(object_count),
            loose_seen: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            loose_excluded: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            path_policy_version,
        }
    }

    /// Returns the current stats.
    #[inline]
    pub fn stats(&self) -> &BlobIntroStats {
        &self.stats
    }

    /// Resets stats and in-flight accounting for a new run.
    ///
    /// Requires no in-flight traversal state; `introduce` clears that state
    /// before returning an error.
    pub fn reset_stats(&mut self) {
        debug_assert!(self.stack.is_empty(), "reset requires empty stack");
        self.stats = BlobIntroStats::default();
        self.tree_bytes_in_flight = 0;
    }

    /// Clears seen sets so the introducer can be re-run.
    pub fn reset_seen(&mut self) {
        self.seen.clear();
        self.loose_seen.clear();
        self.loose_excluded.clear();
    }

    /// Walks the commit plan and emits first-introduced blob candidates.
    ///
    /// On error, clears traversal state so the introducer can be reused after
    /// handling the failure. Seen sets are preserved; call `reset_seen` if needed.
    pub fn introduce<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        cg: &CommitGraphIndex,
        plan: &[PlannedCommit],
        oid_index: &OidIndex,
        sink: &mut S,
    ) -> Result<BlobIntroStats, TreeDiffError> {
        self.reset_stats();

        let result = (|| {
            for PlannedCommit { pos, .. } in plan {
                perf_stats::sat_add_u64(&mut self.stats.commits_visited, 1);
                let commit_id = pos.0;
                let root_oid = cg.root_tree_oid(*pos);

                if let Some(idx) = oid_index.get(&root_oid) {
                    if !self.seen.mark_tree(idx) {
                        perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                        continue;
                    }
                }

                self.push_tree(source, &root_oid)?;
                self.walk_stack(source, oid_index, sink, commit_id)?;
            }

            Ok(self.stats)
        })();

        if result.is_err() {
            self.reset_run_state();
        }

        result
    }

    /// Clears transient traversal state so a subsequent run can start cleanly.
    fn reset_run_state(&mut self) {
        self.stack.clear();
        self.path_builder.clear();
        self.tree_bytes_in_flight = 0;
    }

    fn push_tree(
        &mut self,
        source: &mut impl TreeSource,
        oid: &OidBytes,
    ) -> Result<(), TreeDiffError> {
        if self.stack.len() >= self.max_depth as usize {
            return Err(TreeDiffError::MaxTreeDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        let bytes = source.load_tree(oid)?;
        perf_stats::sat_add_u64(&mut self.stats.trees_loaded, 1);
        perf_stats::sat_add_u64(&mut self.stats.tree_bytes_loaded, bytes.len() as u64);

        let cursor = TreeCursor::new(bytes, self.oid_len, self.stream_threshold);
        let in_flight_len = cursor.in_flight_len();
        let new_in_flight = self.tree_bytes_in_flight.saturating_add(in_flight_len);
        if new_in_flight > self.tree_bytes_in_flight_limit {
            return Err(TreeDiffError::TreeBytesBudgetExceeded {
                loaded: new_in_flight,
                budget: self.tree_bytes_in_flight_limit,
            });
        }
        self.tree_bytes_in_flight = new_in_flight;
        perf_stats::max_u64(
            &mut self.stats.tree_bytes_in_flight_peak,
            self.tree_bytes_in_flight,
        );

        self.stack.push(TreeFrame {
            cursor,
            in_flight_len,
        });
        self.stats.max_depth_reached = self.stats.max_depth_reached.max(self.stack.len() as u16);
        Ok(())
    }

    fn pop_tree(&mut self) {
        if let Some(frame) = self.stack.pop() {
            self.tree_bytes_in_flight = self
                .tree_bytes_in_flight
                .saturating_sub(frame.in_flight_len);
        }
        self.path_builder.pop_dir();
    }

    fn walk_stack<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        oid_index: &OidIndex,
        sink: &mut S,
        commit_id: u32,
    ) -> Result<(), TreeDiffError> {
        while let Some(frame) = self.stack.last_mut() {
            let entry = match frame.cursor.peek_entry()? {
                Some(entry) => entry,
                None => {
                    self.pop_tree();
                    continue;
                }
            };

            self.name_scratch.clear();
            self.name_scratch.extend_from_slice(entry.name);
            let kind = entry.kind;
            let mode = entry.mode;
            let oid = entry.oid()?;

            frame.cursor.advance()?;

            match kind {
                EntryKind::Tree => {
                    if let Some(idx) = oid_index.get(&oid) {
                        if !self.seen.mark_tree(idx) {
                            perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                            continue;
                        }
                    }

                    self.path_builder.push_dir(&self.name_scratch)?;
                    if let Err(err) = self.push_tree(source, &oid) {
                        self.path_builder.pop_dir();
                        return Err(err);
                    }
                }
                EntryKind::RegularFile | EntryKind::ExecutableFile | EntryKind::Symlink => {
                    let leaf_start = self.path_builder.push_leaf(&self.name_scratch)?;
                    let path = self.path_builder.as_slice();
                    let excluded = is_excluded_path(path, self.path_policy_version);
                    let idx = oid_index.get(&oid);

                    if excluded {
                        if let Some(idx) = idx {
                            if self.seen.is_blob_excluded(idx) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                            self.seen.mark_blob_excluded(idx);
                        } else {
                            if self.loose_excluded.contains(&oid) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                            self.loose_excluded.insert(&oid)?;
                        }
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }

                    if let Some(idx) = idx {
                        if !self.seen.mark_blob(idx) {
                            self.path_builder.pop_leaf(leaf_start);
                            continue;
                        }
                    } else if !self.loose_seen.insert(&oid)? {
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }
                    let cand_flags = classify_path(path).bits();
                    let mode_u16 = mode as u16;
                    sink.emit(
                        oid,
                        path,
                        commit_id,
                        0,
                        ChangeKind::Add,
                        mode_u16,
                        cand_flags,
                    )?;
                    perf_stats::sat_add_u64(&mut self.stats.blobs_emitted, 1);
                    self.path_builder.pop_leaf(leaf_start);
                }
                EntryKind::Gitlink | EntryKind::Unknown => {}
            }
        }

        Ok(())
    }
}

fn table_size_for_count(count: usize) -> usize {
    const LOAD_FACTOR_NUM: usize = 7;
    const LOAD_FACTOR_DEN: usize = 10;
    let min_capacity = count
        .saturating_mul(LOAD_FACTOR_DEN)
        .div_ceil(LOAD_FACTOR_NUM);
    min_capacity.max(1).next_power_of_two()
}

#[inline]
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let head = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut h = head ^ tail.rotate_left(32);
    h ^= (bytes.len() as u64) << 56;
    mix64(h)
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::SeenSets;

    #[test]
    fn seen_sets_mark_and_query() {
        let mut seen = SeenSets::new(8);
        assert!(!seen.is_tree_seen(2));
        assert!(seen.mark_tree(2));
        assert!(seen.is_tree_seen(2));
        assert!(!seen.mark_tree(2));

        assert!(!seen.is_blob_seen(3));
        assert!(seen.mark_blob(3));
        assert!(seen.is_blob_seen(3));
        assert!(!seen.mark_blob(3));
    }
}
