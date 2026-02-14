//! Object store abstraction for tree loading.
//!
//! Provides a pack/loose-backed object loader that returns raw tree
//! payload bytes (no `tree <size>\0` header). This is used by the
//! tree diff walker to avoid blob reads while traversing trees.
//! Tree payloads are cached in a fixed-size, set-associative tree cache
//! to avoid repeated inflations of hot subtrees. A separate delta base
//! cache keyed by `(pack_id, offset)` reuses decompressed tree bases when
//! resolving pack delta chains.
//!
//! # Contract
//! Implementations must return the raw, decompressed tree payload (no
//! header). Callers assume the returned buffer contains a sequence of
//! tree entries in Git tree order.
//!
//! # Lookup Order
//! - MIDX lookup into pack files (including delta resolution)
//! - Loose objects in `objects/` and alternates (if present)
//!
//! # Invariants
//! - `max_object_bytes` caps all inflated payloads and delta buffers
//! - Delta chains are bounded by `MAX_DELTA_DEPTH`
//! - Repo artifacts must be `Ready` (commit-graph + MIDX present)
//! - Tree cache is best-effort: oversize payloads are not cached
//! - Tree delta cache is best-effort: oversize bases are not cached
//! - Spill arena stores large tree payloads in a fixed-size mmapped file;
//!   spill indexing is best-effort and may disable itself when full
//!
//! # Load Pipeline
//! - Validate OID length
//! - Check tree cache for a pinned payload
//! - Check spill index for spilled payloads
//! - Load the object from pack or loose storage
//! - Verify the object kind is `tree`
//! - Spill large payloads (best-effort), otherwise insert into cache
//!
//! When the `git-perf` feature is enabled, tree-load cache/spill hit rates and
//! decode timings are recorded via the global perf counters.
//!
//! # Spill/Cache Behavior
//! Small payloads stay in RAM. Large payloads can be written to the spill arena
//! and optionally indexed for fast lookup. The spill index is open-addressed
//! and never deletes entries; once full, it is disabled and lookups fall back
//! to pack/loose reads.
//!
//! # Error semantics
//! - Missing objects surface as `TreeDiffError::TreeNotFound`.
//! - Non-tree objects surface as `TreeDiffError::NotATree`.
//! - Corrupt loose objects surface as `TreeDiffError::CorruptTree`.
//!
//! # Ordering
//! Pack lookup is attempted before loose objects. This mirrors typical Git
//! layouts where packs are the primary store and loose objects are a fallback.

use super::bytes::BytesView;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::errors::TreeDiffError;
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::pack_inflate::{
    apply_delta, inflate_exact_with, inflate_limited, inflate_limited_with, EntryKind, ObjectKind,
    PackFile, PackHeader,
};
use super::perf;
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;
use super::spill_arena::{SpillArena, SpillArenaError, SpillSlice};
use super::tree_cache::{TreeCache, TreeCacheHandle};
use super::tree_delta_cache::TreeDeltaCache;
use super::tree_diff_limits::TreeDiffLimits;

/// Maximum entry header bytes to parse in pack files.
const MAX_ENTRY_HEADER_BYTES: usize = 64;
/// Maximum depth for delta chains.
const MAX_DELTA_DEPTH: u8 = 64;
/// Safety allowance for loose object headers (`"tree <size>\0"`).
const LOOSE_HEADER_MAX_BYTES: usize = 64;
/// Minimum number of spill-index slots (power of two).
const MIN_SPILL_INDEX_ENTRIES: usize = 64;
/// Maximum number of spill-index slots (power of two).
const MAX_SPILL_INDEX_ENTRIES: usize = 1_048_576;

/// Fixed spill-index slot storing an OID key and spill offset/length.
///
/// `key_len == 0` denotes an empty slot. Entries are never deleted.
/// `key_bytes` is sized for the maximum supported OID (SHA-256); `key_len`
/// records the actual length (SHA-1 or SHA-256).
#[derive(Clone, Copy, Debug)]
struct SpillIndexEntry {
    key_len: u8,
    key_bytes: [u8; 32],
    offset: u64,
    len: u64,
}

impl SpillIndexEntry {
    const EMPTY: Self = Self {
        key_len: 0,
        key_bytes: [0u8; 32],
        offset: 0,
        len: 0,
    };

    fn is_empty(&self) -> bool {
        self.key_len == 0
    }

    fn matches(&self, oid: &OidBytes) -> bool {
        self.key_len == oid.len() && &self.key_bytes[..self.key_len as usize] == oid.as_slice()
    }

    fn set(&mut self, oid: &OidBytes, offset: u64, len: u64) {
        self.key_len = oid.len();
        self.key_bytes.fill(0);
        self.key_bytes[..oid.len() as usize].copy_from_slice(oid.as_slice());
        self.offset = offset;
        self.len = len;
    }
}

/// Fixed-size open-addressed hash table for spilled tree payloads.
///
/// Uses linear probing with OID-derived hashing (first 8 bytes of the OID
/// read as a little-endian u64). There are no tombstones; once all slots are
/// occupied, inserts fail and callers may disable indexing. This keeps lookup
/// and insert logic simple and deterministic at the cost of best-effort
/// behavior under high spill pressure.
///
/// Invariants:
/// - `slots.len()` is power-of-two so masking is cheap.
/// - `key_len == 0` marks an empty slot; no deletions are performed.
/// - An empty `slots` disables indexing (lookups return `None`).
/// - Inserts are best-effort; once full, callers can disable indexing.
#[derive(Debug)]
struct SpillIndex {
    mask: usize,
    slots: Vec<SpillIndexEntry>,
}

impl SpillIndex {
    fn new(entries: usize) -> Self {
        if entries == 0 {
            return Self {
                mask: 0,
                slots: Vec::new(),
            };
        }

        let entries = entries.clamp(MIN_SPILL_INDEX_ENTRIES, MAX_SPILL_INDEX_ENTRIES);
        let entries = entries.next_power_of_two();
        let slots = vec![SpillIndexEntry::EMPTY; entries];
        Self {
            mask: entries - 1,
            slots,
        }
    }

    fn lookup(&self, oid: &OidBytes) -> Option<(u64, u64)> {
        if self.slots.is_empty() {
            return None;
        }

        let mut idx = (hash_oid(oid) as usize) & self.mask;
        for _ in 0..self.slots.len() {
            let entry = &self.slots[idx];
            if entry.is_empty() {
                return None;
            }
            if entry.matches(oid) {
                return Some((entry.offset, entry.len));
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    fn insert(&mut self, oid: &OidBytes, offset: u64, len: u64) -> bool {
        if self.slots.is_empty() {
            return false;
        }

        let mut idx = (hash_oid(oid) as usize) & self.mask;
        for _ in 0..self.slots.len() {
            let entry = &mut self.slots[idx];
            if entry.is_empty() || entry.matches(oid) {
                entry.set(oid, offset, len);
                return true;
            }
            idx = (idx + 1) & self.mask;
        }
        false
    }
}

/// Abstraction for loading raw tree payloads by OID.
///
/// Implementations resolve a Git tree object and return its decompressed
/// payload (without the `tree <size>\0` header). The `ObjectStore` in this
/// module is the primary implementation, backed by MIDX pack lookups, loose
/// objects, and a tree cache.
pub trait TreeSource {
    /// Loads a tree object by OID.
    ///
    /// Implementations may allocate per call; higher-level caches can lend
    /// pinned payloads to avoid repeated inflations of hot subtrees.
    /// Returned bytes are treated as read-only and are not retained by the
    /// caller beyond the `TreeBytes` value.
    ///
    /// # Contract
    /// - The returned bytes are the tree payload only (no loose header).
    /// - Missing objects should map to `TreeDiffError::TreeNotFound`.
    /// - Objects that are not trees should map to `TreeDiffError::NotATree`.
    ///
    /// # Errors
    /// - `TreeNotFound` if the object doesn't exist
    /// - `NotATree` if the object exists but isn't a tree
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError>;
}

/// Tree payload bytes returned by a `TreeSource`.
#[derive(Debug)]
pub enum TreeBytes {
    /// Borrowed bytes pinned in the tree cache.
    ///
    /// Dropping the handle releases the pin and may allow eviction.
    Cached(TreeCacheHandle),
    /// Owned bytes (e.g., from pack/loose reads).
    Owned(Vec<u8>),
    /// Bytes stored in the spill arena.
    ///
    /// The underlying spill arena must outlive the returned `TreeBytes` for
    /// the slice to remain valid.
    Spilled(SpillSlice),
}

impl TreeBytes {
    /// Returns an empty tree payload.
    #[must_use]
    pub fn empty() -> Self {
        Self::Owned(Vec::new())
    }

    /// Returns the tree payload as a byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Cached(handle) => handle.as_slice(),
            Self::Owned(buf) => buf.as_slice(),
            Self::Spilled(slice) => slice.as_slice(),
        }
    }

    /// Returns the payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns the RAM-resident byte count of this payload.
    ///
    /// Spilled payloads return 0 because their bytes live in the memory-mapped
    /// spill arena and do not count against the in-flight memory budget.
    /// Cached and owned payloads return their full length.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        match self {
            Self::Cached(handle) => handle.as_slice().len(),
            Self::Owned(buf) => buf.len(),
            Self::Spilled(_) => 0,
        }
    }

    /// Returns true if the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

/// Scratch buffers reused across delta resolution hops.
///
/// Eliminates per-hop `Vec::new()` / `Vec::with_capacity()` allocations
/// in [`ObjectStore::read_pack_object`]. The decompressor is reset before
/// each inflate call so no stale state leaks between objects.
///
/// # Buffer ping-pong protocol
///
/// During the unwind phase of delta resolution, `base_buf` and `result_buf`
/// alternate roles via `std::mem::swap`:
///
/// 1. Delta payload is inflated into `inflate_buf`.
/// 2. `apply_delta(base_buf, inflate_buf, result_buf, …)` produces output.
/// 3. `swap(&mut base_buf, &mut result_buf)` — the result becomes the base
///    for the next frame.
///
/// After the final unwind step, the resolved object is in `base_buf`.
struct TreeDecodeBufs {
    de: flate2::Decompress,
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    base_buf: Vec<u8>,
}

impl std::fmt::Debug for TreeDecodeBufs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeDecodeBufs")
            .field("inflate_buf.cap", &self.inflate_buf.capacity())
            .field("result_buf.cap", &self.result_buf.capacity())
            .field("base_buf.cap", &self.base_buf.capacity())
            .finish()
    }
}

impl TreeDecodeBufs {
    fn new() -> Self {
        Self {
            de: flate2::Decompress::new(true),
            inflate_buf: Vec::new(),
            result_buf: Vec::new(),
            base_buf: Vec::new(),
        }
    }
}

/// One frame of a pending delta chain collected during the walk-forward
/// phase of iterative delta resolution.
#[derive(Clone, Copy, Debug)]
struct TreeDeltaFrame {
    /// Pack offset of this delta entry (used as cache key during unwind).
    offset: u64,
    /// Byte offset where the compressed delta payload begins in the pack.
    data_start: usize,
    /// Expected decompressed delta size (from the entry header).
    delta_size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectSource {
    Pack,
    Loose,
}

#[derive(Debug)]
struct DecodedTreeObject {
    kind: ObjectKind,
    bytes: Vec<u8>,
    chain_len: u8,
}

#[derive(Debug)]
struct LoadedObject {
    kind: ObjectKind,
    bytes: Vec<u8>,
    source: ObjectSource,
    chain_len: u8,
}

/// Immutable repository layout shared by object store instances.
///
/// This contains repo-level metadata that is expensive to recompute and does
/// not change per worker: parsed MIDX view, resolved pack paths, and loose
/// object directories. Callers can build one layout and open multiple
/// per-worker [`ObjectStore`] instances from it.
#[derive(Debug, Clone)]
pub(super) struct ObjectStoreLayout<'a> {
    oid_len: u8,
    midx: MidxView<'a>,
    pack_paths: Arc<[PathBuf]>,
    loose_dirs: Arc<[PathBuf]>,
}

impl<'a> ObjectStoreLayout<'a> {
    /// Builds shared object-store layout from repository artifacts.
    ///
    /// This performs MIDX parse/validation plus pack/loose directory
    /// resolution once so worker-local stores can skip repeating it.
    pub(super) fn from_repo(repo: &'a RepoJobState) -> Result<Self, TreeDiffError> {
        let midx_bytes =
            repo.mmaps
                .midx
                .as_ref()
                .ok_or_else(|| TreeDiffError::ObjectStoreError {
                    detail: "midx bytes missing".to_string(),
                })?;
        let midx =
            MidxView::parse(midx_bytes.as_slice(), repo.object_format).map_err(store_error)?;
        Self::from_midx(repo, midx)
    }

    /// Builds shared object-store layout using a pre-parsed MIDX view.
    pub(super) fn from_midx(
        repo: &RepoJobState,
        midx: MidxView<'a>,
    ) -> Result<Self, TreeDiffError> {
        let pack_dirs = collect_pack_dirs(&repo.paths);
        let pack_names = list_pack_files(&pack_dirs)?;
        // Ensure every on-disk pack file is represented in the MIDX so
        // pack lookups are complete across alternates.
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))
            .map_err(store_error)?;

        let pack_paths = Arc::<[PathBuf]>::from(resolve_pack_paths(&midx, &pack_dirs)?);
        let loose_dirs = Arc::<[PathBuf]>::from(collect_loose_dirs(&repo.paths));

        Ok(Self {
            oid_len: repo.object_format.oid_len(),
            midx,
            pack_paths,
            loose_dirs,
        })
    }
}

/// Pack/loose object store for tree loading.
///
/// Holds a borrowed MIDX view (tied to the repo job's bytes view lifetime) and
/// lazily maps pack files on demand. Pack bytes are cached so iterative delta
/// resolution can borrow pack data without aliasing `self`.
///
/// The tree cache stores decompressed payloads; cache hits return pinned
/// handles so callers can borrow the bytes without copying.
///
/// Delta resolution uses iterative walk-forward + unwind phases with
/// reusable scratch buffers (`decode_bufs`) to eliminate per-hop allocations.
#[derive(Debug)]
pub struct ObjectStore<'a> {
    oid_len: u8,
    max_object_bytes: usize,
    midx: MidxView<'a>,
    pack_paths: Arc<[PathBuf]>,
    pack_cache: Vec<Option<(BytesView, PackHeader)>>,
    loose_dirs: Arc<[PathBuf]>,
    tree_cache: TreeCache,
    tree_delta_cache: TreeDeltaCache,
    /// Reusable scratch buffers for iterative delta resolution.
    decode_bufs: TreeDecodeBufs,
    spill: Option<SpillArena>,
    /// Minimum payload size to consider spilling (smaller payloads stay in RAM).
    spill_min_bytes: usize,
    /// Set when the spill arena is out of space; disables further spills.
    spill_exhausted: bool,
    /// Best-effort index for spilled payloads (OID -> offset/len).
    spill_index: SpillIndex,
    /// Set when the index fills; subsequent spills are not indexed.
    spill_index_exhausted: bool,
}

impl<'a> ObjectStore<'a> {
    /// Opens an object store for the given repository job.
    ///
    /// The store resolves pack paths from the MIDX and uses a best-effort
    /// tree cache sized by `TreeDiffLimits`.
    ///
    /// Verifies that the MIDX covers all pack files found in pack directories,
    /// including alternates, so pack lookups are complete.
    ///
    /// `spill_dir` must be an existing directory used for the spill arena
    /// backing file. It should be on a fast local filesystem (e.g., tmpfs or
    /// local SSD) to keep large-tree reads predictable.
    ///
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if the MIDX is malformed
    /// or pack files cannot be resolved. `acquire_midx` must have been
    /// called to populate `repo.mmaps.midx`.
    pub fn open(
        repo: &'a RepoJobState,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
    ) -> Result<Self, TreeDiffError> {
        let tree_delta_cache = TreeDeltaCache::new(limits.max_tree_delta_cache_bytes);
        Self::open_with_tree_delta_cache(repo, limits, spill_dir, tree_delta_cache)
    }

    /// Opens an object store with a caller-provided tree delta cache.
    ///
    /// This allows runners to auto-size the cache based on repository
    /// metadata while preserving the default behavior of [`Self::open`].
    ///
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if the MIDX is malformed
    /// or pack files cannot be resolved. `acquire_midx` must have been
    /// called to populate `repo.mmaps.midx`.
    pub fn open_with_tree_delta_cache(
        repo: &'a RepoJobState,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
        tree_delta_cache: TreeDeltaCache,
    ) -> Result<Self, TreeDiffError> {
        let layout = ObjectStoreLayout::from_repo(repo)?;
        Self::open_with_layout(&layout, limits, spill_dir, tree_delta_cache)
    }

    /// Opens an object store from a shared immutable layout.
    ///
    /// This avoids recomputing repo/pack discovery work for each store.
    pub(super) fn open_with_layout(
        layout: &ObjectStoreLayout<'a>,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
        tree_delta_cache: TreeDeltaCache,
    ) -> Result<Self, TreeDiffError> {
        let pack_cache = vec![None; layout.pack_paths.len()];
        let tree_cache = TreeCache::new(limits.max_tree_cache_bytes);
        let max_object_bytes = limits.max_tree_bytes_in_flight.min(usize::MAX as u64) as usize;
        let spill = SpillArena::new(spill_dir, limits.max_tree_spill_bytes).map_err(store_error)?;
        let spill_min_bytes = limits.max_tree_cache_bytes.max(1) as usize;
        let spill_index_entries = spill_index_entries(limits.max_tree_spill_bytes, spill_min_bytes);
        let spill_index = SpillIndex::new(spill_index_entries);

        Ok(Self {
            oid_len: layout.oid_len,
            max_object_bytes,
            midx: layout.midx,
            pack_paths: Arc::clone(&layout.pack_paths),
            pack_cache,
            loose_dirs: Arc::clone(&layout.loose_dirs),
            tree_cache,
            tree_delta_cache,
            decode_bufs: TreeDecodeBufs::new(),
            spill: Some(spill),
            spill_min_bytes,
            spill_exhausted: false,
            spill_index,
            spill_index_exhausted: false,
        })
    }

    /// Returns the configured OID length.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Loads an object by OID, resolving deltas up to `MAX_DELTA_DEPTH`.
    ///
    /// This prefers pack files over loose objects.
    fn load_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<(ObjectKind, Vec<u8>, ObjectSource), TreeDiffError> {
        let loaded = self.load_object_with_depth(oid, MAX_DELTA_DEPTH)?;
        Ok((loaded.kind, loaded.bytes, loaded.source))
    }

    /// Loads an object with an explicit remaining delta depth.
    ///
    /// `depth` counts remaining delta edges; when it reaches 0, delta
    /// resolution stops and the call fails with a depth error.
    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<LoadedObject, TreeDiffError> {
        // Depth is decremented per delta hop to bound recursion.
        if let Some(obj) = self.load_object_from_pack(oid, depth)? {
            return Ok(LoadedObject {
                kind: obj.kind,
                bytes: obj.bytes,
                source: ObjectSource::Pack,
                chain_len: obj.chain_len,
            });
        }
        if let Some(obj) = self.load_object_from_loose(oid)? {
            return Ok(LoadedObject {
                kind: obj.0,
                bytes: obj.1,
                source: ObjectSource::Loose,
                chain_len: 0,
            });
        }
        Err(TreeDiffError::TreeNotFound)
    }

    fn load_object_from_pack(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<DecodedTreeObject>, TreeDiffError> {
        // MIDX lookups are O(log N) on the OID list and return pack offsets.
        let idx = match self.midx.find_oid(oid).map_err(store_error)? {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let (pack_id, offset) = self.midx.offset_at(idx).map_err(store_error)?;
        let (pack, pack_header) = self.pack_data(pack_id)?;
        let obj = self.read_pack_object(
            pack_id,
            pack.as_ref(),
            pack_header,
            offset,
            depth,
            Some(*oid),
        )?;
        Ok(Some(obj))
    }

    /// Resolves a pack object at `offset`, iteratively unwinding any delta
    /// chain.
    ///
    /// **Phase 1 — Walk forward**: follows OFS delta base offsets (and delta
    /// cache hits) without recursion, pushing one `TreeDeltaFrame` per hop.
    /// The walk terminates when a non-delta root is reached, a delta cache
    /// hit supplies the base bytes, or a REF delta requires a cross-pack
    /// base loaded via [`Self::load_object_with_depth`].
    ///
    /// **Phase 2 — Unwind backward**: iterates the frame stack in reverse,
    /// inflating each delta payload and applying it against the current base
    /// in `decode_bufs`, swapping `base_buf`/`result_buf` after each step.
    ///
    /// Scratch buffers in `decode_bufs` are reused across calls, eliminating
    /// per-hop `Vec::new()` / `Vec::with_capacity()` allocations that the
    /// previous recursive implementation performed.
    #[allow(unused_assignments)] // base_kind/base_chain_len initializers
    fn read_pack_object(
        &mut self,
        pack_id: u16,
        pack_bytes: &[u8],
        pack_header: PackHeader,
        offset: u64,
        depth: u8,
        root_oid: Option<OidBytes>,
    ) -> Result<DecodedTreeObject, TreeDiffError> {
        let pack = PackFile::from_header(pack_bytes, pack_header);
        let max_object_bytes = self.max_object_bytes;

        // -- Phase 1: Walk forward through the delta chain -----------------
        //
        // delta_stack is intentionally local (not in TreeDecodeBufs) because
        // the REF delta path below may re-enter read_pack_object via
        // load_object_with_depth. A shared delta_stack would be clobbered
        // by the inner call. The per-call Vec::new() cost is acceptable
        // since delta chains are bounded by MAX_DELTA_DEPTH (64 frames).
        let mut delta_stack: Vec<TreeDeltaFrame> = Vec::new();
        let mut current_offset = offset;
        let mut remaining_depth = depth;
        let mut base_kind: ObjectKind = ObjectKind::Tree; // set below
        let mut base_chain_len: u8 = 0; // set below

        loop {
            let header = pack
                .entry_header_at(current_offset, MAX_ENTRY_HEADER_BYTES)
                .map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: {err}{}",
                        format_root_oid(root_oid)
                    ),
                })?;

            let payload_size =
                usize::try_from(header.size).map_err(|_| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: object size overflow{}",
                        format_root_oid(root_oid)
                    ),
                })?;

            if payload_size > max_object_bytes {
                let label = if delta_stack.is_empty() {
                    "object size"
                } else {
                    "delta payload size"
                };
                return Err(TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: {label} {payload_size} exceeds cap {max_object_bytes}{}",
                        format_root_oid(root_oid)
                    ),
                });
            }

            match header.kind {
                EntryKind::NonDelta { kind } => {
                    // Root of the chain: inflate directly into base_buf.
                    let (inflate_result, inflate_nanos) = perf::time(|| {
                        inflate_exact_with(
                            &mut self.decode_bufs.de,
                            pack.slice_from(header.data_start),
                            &mut self.decode_bufs.base_buf,
                            payload_size,
                        )
                    });
                    inflate_result.map_err(|err| TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {current_offset}: {err}{}",
                            format_root_oid(root_oid)
                        ),
                    })?;
                    perf::record_tree_inflate(self.decode_bufs.base_buf.len(), inflate_nanos);
                    base_kind = kind;
                    base_chain_len = 0;
                    break;
                }

                EntryKind::OfsDelta { base_offset } => {
                    if remaining_depth == 0 {
                        return Err(TreeDiffError::ObjectStoreError {
                            detail: format!(
                                "pack {pack_id} offset {current_offset}: delta chain too deep{}",
                                format_root_oid(root_oid)
                            ),
                        });
                    }

                    // Check delta cache for the base.
                    let (cache_handle, cache_nanos) =
                        perf::time(|| self.tree_delta_cache.get_handle(pack_id, base_offset));

                    if let Some(handle) = cache_handle {
                        perf::record_tree_delta_cache_hit(handle.len());
                        perf::record_tree_delta_cache_hit_nanos(cache_nanos);

                        // Copy cached base into base_buf, then drop the pin.
                        self.decode_bufs.base_buf.clear();
                        self.decode_bufs
                            .base_buf
                            .extend_from_slice(handle.as_slice());
                        base_kind = handle.kind();
                        base_chain_len = handle.chain_len();
                        drop(handle);

                        // Push this delta frame for unwind.
                        delta_stack.push(TreeDeltaFrame {
                            offset: current_offset,
                            data_start: header.data_start,
                            delta_size: payload_size,
                        });
                        break;
                    }

                    perf::record_tree_delta_cache_miss();
                    perf::record_tree_delta_cache_miss_nanos(cache_nanos);

                    // Push frame and follow the base offset.
                    delta_stack.push(TreeDeltaFrame {
                        offset: current_offset,
                        data_start: header.data_start,
                        delta_size: payload_size,
                    });
                    current_offset = base_offset;
                    remaining_depth -= 1;
                }

                EntryKind::RefDelta { base_oid } => {
                    if remaining_depth == 0 {
                        return Err(TreeDiffError::ObjectStoreError {
                            detail: format!(
                                "pack {pack_id} offset {current_offset}: delta chain too deep{}",
                                format_root_oid(root_oid)
                            ),
                        });
                    }

                    // Push this delta frame.
                    delta_stack.push(TreeDeltaFrame {
                        offset: current_offset,
                        data_start: header.data_start,
                        delta_size: payload_size,
                    });

                    // INVARIANT: Phase 1 must NOT use decode_bufs (inflate_buf,
                    // result_buf, base_buf) for any inflate operations before
                    // this point. The inner load_object_with_depth call
                    // re-enters read_pack_object and freely overwrites
                    // decode_bufs. Its returned Vec is independent (owned),
                    // so copying into base_buf after the call is safe.
                    // Violating this invariant would silently corrupt the
                    // outer call's partially-inflated buffers.
                    let loaded = self.load_object_with_depth(&base_oid, remaining_depth - 1)?;
                    base_kind = loaded.kind;
                    base_chain_len = loaded.chain_len;

                    // Copy loaded bytes into base_buf (inner call is done).
                    // NOTE: The inner call may mem::take decode_bufs.base_buf,
                    // losing its capacity. The extend_from_slice below will
                    // re-allocate. This is acceptable for REF deltas
                    // (cross-pack, relatively rare).
                    self.decode_bufs.base_buf.clear();
                    self.decode_bufs.base_buf.extend_from_slice(&loaded.bytes);
                    break;
                }
            }
        }

        // -- Fast path: non-delta object (no frames pushed) ----------------
        if delta_stack.is_empty() {
            perf::record_tree_delta_chain(0);
            if base_kind == ObjectKind::Tree {
                self.tree_delta_cache.insert(
                    pack_id,
                    offset,
                    base_kind,
                    0,
                    &self.decode_bufs.base_buf,
                );
            }
            // NOTE: mem::take drains base_buf's capacity (replaces with
            // Vec::new()). A swap-based approach was evaluated but does not
            // help: the returned Vec is consumed by the caller, so there is
            // no way to reclaim its allocation. Re-growing base_buf on the
            // next call is cheap for typical tree sizes (< 8 KB) and dwarfed
            // by inflate/delta-apply costs.
            let bytes = std::mem::take(&mut self.decode_bufs.base_buf);
            return Ok(DecodedTreeObject {
                kind: base_kind,
                bytes,
                chain_len: 0,
            });
        }

        // -- Phase 2: Unwind the delta stack in reverse --------------------
        for frame in delta_stack.iter().rev() {
            // Inflate the delta payload into inflate_buf.
            let (inflate_result, inflate_nanos) = perf::time(|| {
                inflate_limited_with(
                    &mut self.decode_bufs.de,
                    pack.slice_from(frame.data_start),
                    &mut self.decode_bufs.inflate_buf,
                    frame.delta_size,
                )
            });
            inflate_result.map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {}: delta inflate failed: {err}{}",
                    frame.offset,
                    format_root_oid(root_oid)
                ),
            })?;
            perf::record_tree_inflate(self.decode_bufs.inflate_buf.len(), inflate_nanos);

            // Apply delta: base_buf × inflate_buf → result_buf.
            // Split borrow decode_bufs fields to satisfy the borrow checker.
            let (apply_result, apply_nanos) = perf::time(|| {
                let TreeDecodeBufs {
                    ref base_buf,
                    ref inflate_buf,
                    ref mut result_buf,
                    ..
                } = self.decode_bufs;
                apply_delta(base_buf, inflate_buf, result_buf, max_object_bytes)
            });
            apply_result.map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {}: delta apply failed: {err}{}",
                    frame.offset,
                    format_root_oid(root_oid)
                ),
            })?;
            perf::record_tree_delta_apply(self.decode_bufs.result_buf.len(), apply_nanos);

            // Rotate: output becomes the next base.
            std::mem::swap(
                &mut self.decode_bufs.base_buf,
                &mut self.decode_bufs.result_buf,
            );

            base_chain_len = base_chain_len.saturating_add(1);

            // Offer intermediate result to the delta cache.
            if base_kind == ObjectKind::Tree {
                self.tree_delta_cache.insert(
                    pack_id,
                    frame.offset,
                    base_kind,
                    base_chain_len,
                    &self.decode_bufs.base_buf,
                );
            }
        }

        perf::record_tree_delta_chain(base_chain_len);
        // NOTE: same capacity-loss tradeoff as the fast path above.
        // inflate_buf and result_buf retain their capacity (only swapped,
        // never taken), so the main per-call cost is re-growing base_buf.
        let bytes = std::mem::take(&mut self.decode_bufs.base_buf);
        Ok(DecodedTreeObject {
            kind: base_kind,
            bytes,
            chain_len: base_chain_len,
        })
    }

    fn load_object_from_loose(
        &self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, TreeDiffError> {
        // Loose objects are stored by hex fanout: <objects>/<2-hex>/<38-hex>.
        let hex = oid_to_hex(oid);
        let (dir, file) = hex.split_at(2);
        let dir_name = String::from_utf8_lossy(dir);
        let file_name = String::from_utf8_lossy(file);

        for base in self.loose_dirs.iter() {
            let path = base.join(dir_name.as_ref()).join(file_name.as_ref());
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!("loose object read failed: {err}"),
                    });
                }
            };

            let max_out = self.max_object_bytes.saturating_add(LOOSE_HEADER_MAX_BYTES);
            let mut out = Vec::with_capacity(max_out);
            inflate_limited(&data, &mut out, max_out).map_err(store_error)?;

            // Parse and validate the loose header before returning the payload.
            let (kind, payload) = parse_loose_object(&out, self.max_object_bytes)?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    /// Returns cached pack bytes and pre-parsed header for the given pack id,
    /// mapping and validating the header if needed.
    ///
    /// Caching the `PackHeader` alongside the bytes avoids re-validating the
    /// "PACK" signature, version, and recomputing `data_end` on every call to
    /// `read_pack_object` — including recursive delta chain resolution where
    /// the same pack is parsed N times for a chain of depth N.
    fn pack_data(&mut self, pack_id: u16) -> Result<(BytesView, PackHeader), TreeDiffError> {
        // Pack files are immutable during the scan. Cache their bytes so
        // recursive delta resolution can reuse pack data cheaply.
        let idx = pack_id as usize;
        let path = self
            .pack_paths
            .get(idx)
            .ok_or_else(|| TreeDiffError::ObjectStoreError {
                detail: format!("pack id {pack_id} out of bounds"),
            })?;

        if self.pack_cache.get(idx).is_none() {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "pack cache index out of bounds".to_string(),
            });
        }

        if self.pack_cache[idx].is_none() {
            let file = File::open(path).map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!("failed to open pack {}: {err}", path.display()),
            })?;
            // SAFETY: `Mmap::map` requires that the file is not concurrently
            // truncated or modified while mapped. Pack files are immutable in
            // a well-formed Git repository (writes create new packs). We also
            // detect concurrent maintenance via lock-file and fingerprint checks
            // in `artifacts_unchanged`. The mapping is read-only; we never
            // mutate through it.
            let mmap = unsafe {
                memmap2::Mmap::map(&file).map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!("failed to mmap pack {}: {err}", path.display()),
                })?
            };
            let bv = BytesView::from_mmap(mmap);
            let header =
                PackFile::parse_header(bv.as_ref(), self.oid_len as usize).map_err(|err| {
                    TreeDiffError::ObjectStoreError {
                        detail: format!("pack {} header: {err}", path.display()),
                    }
                })?;
            self.pack_cache[idx] = Some((bv, header));
        }

        let (bv, header) = self.pack_cache[idx].as_ref().expect("pack bytes present");
        Ok((bv.clone(), *header))
    }

    fn try_spill(
        &mut self,
        oid: &OidBytes,
        bytes: &[u8],
    ) -> Result<Option<SpillSlice>, TreeDiffError> {
        // Spilling is best-effort: we only spill large payloads and stop once
        // the arena reports out-of-space. Indexing is optional and can be
        // disabled if the table fills to avoid unbounded probe costs.
        if self.spill_exhausted || bytes.len() < self.spill_min_bytes {
            return Ok(None);
        }

        let Some(spill) = self.spill.as_mut() else {
            return Ok(None);
        };

        match spill.append(bytes) {
            Ok(slice) => {
                if !self.spill_index_exhausted {
                    let inserted = self.spill_index.insert(oid, slice.offset(), slice.len());
                    if !inserted {
                        // Index is full: keep spilling but stop indexing to avoid costly probes.
                        self.spill_index_exhausted = true;
                    }
                }
                Ok(Some(slice))
            }
            Err(SpillArenaError::OutOfSpace { .. }) => {
                self.spill_exhausted = true;
                Ok(None)
            }
            Err(err) => Err(TreeDiffError::ObjectStoreError {
                detail: err.to_string(),
            }),
        }
    }
}

impl TreeSource for ObjectStore<'_> {
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
        let (result, nanos) = perf::time(|| {
            if oid.len() != self.oid_len {
                return Err(TreeDiffError::InvalidOidLength {
                    len: oid.len() as usize,
                    expected: self.oid_len as usize,
                });
            }

            if let Some(handle) = self.tree_cache.get_handle(oid) {
                perf::record_tree_cache_hit();
                return Ok(TreeBytes::Cached(handle));
            }

            if let Some((offset, len)) = self.spill_index.lookup(oid) {
                if let Some(spill) = self.spill.as_ref() {
                    perf::record_tree_spill_hit();
                    return Ok(TreeBytes::Spilled(spill.slice(offset, len)));
                }
            }

            let (obj_res, load_nanos) = perf::time(|| self.load_object(oid));
            let (kind, data, source) = obj_res?;
            perf::record_tree_object(data.len(), load_nanos, source == ObjectSource::Pack);

            if kind != ObjectKind::Tree {
                return Err(TreeDiffError::NotATree);
            }

            if let Some(slice) = self.try_spill(oid, &data)? {
                return Ok(TreeBytes::Spilled(slice));
            }

            // Cache is best-effort; failures are ignored.
            self.tree_cache.insert(*oid, &data);
            Ok(TreeBytes::Owned(data))
        });

        let bytes = result.as_ref().map(|payload| payload.len()).unwrap_or(0);
        perf::record_tree_load(bytes, nanos);
        result
    }
}

/// Computes the spill index capacity from spill size and spill threshold.
///
/// The result is clamped to a power-of-two range to bound RAM usage while
/// still allowing O(1) indexing for the largest spilled trees.
fn spill_index_entries(max_spill_bytes: u64, spill_min_bytes: usize) -> usize {
    if max_spill_bytes == 0 {
        return 0;
    }

    let min_bytes = spill_min_bytes.max(1) as u64;
    let mut entries = max_spill_bytes / min_bytes;
    if entries == 0 {
        entries = 1;
    }
    if entries > MAX_SPILL_INDEX_ENTRIES as u64 {
        entries = MAX_SPILL_INDEX_ENTRIES as u64;
    }
    let entries = entries as usize;
    let entries = entries.max(MIN_SPILL_INDEX_ENTRIES);
    entries.next_power_of_two()
}

/// Hashes an OID for spill-index probing.
///
/// OIDs are already cryptographic hashes with excellent byte distribution,
/// so the first 8 bytes provide sufficient entropy for power-of-two table
/// indexing. This replaces FNV-1a which created a 60-cycle serial multiply
/// dependency chain on ARM (20 bytes × 3-cycle MUL latency).
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

fn store_error<E: std::fmt::Display>(err: E) -> TreeDiffError {
    TreeDiffError::ObjectStoreError {
        detail: err.to_string(),
    }
}

fn format_root_oid(root_oid: Option<OidBytes>) -> String {
    match root_oid {
        Some(oid) => format!(" (root oid {oid})"),
        None => String::new(),
    }
}

fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

fn collect_loose_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.objects_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.clone());
    }
    dirs
}

fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, TreeDiffError> {
    // Collect pack *names* (not full paths) so we can compare them to MIDX PNAM.
    let mut names = Vec::new();

    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(TreeDiffError::ObjectStoreError {
                    detail: format!("failed to read pack dir {}: {err}", dir.display()),
                });
            }
        };

        for entry in entries {
            let entry = entry.map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!("failed to read pack dir entry: {err}"),
            })?;
            let file_type = entry
                .file_type()
                .map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!("failed to read pack dir entry type: {err}"),
                })?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }

    Ok(names)
}

fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, TreeDiffError> {
    // Resolve pack names from PNAM to full paths, searching pack dirs in order.
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);

    for name in midx.pack_names() {
        let mut base = strip_pack_suffix(name);
        base.extend_from_slice(b".pack");
        let file_name = String::from_utf8_lossy(&base).into_owned();

        let mut found = None;
        for dir in pack_dirs {
            let candidate = dir.join(&file_name);
            if is_file(&candidate) {
                found = Some(candidate);
                break;
            }
        }

        match found {
            Some(path) => paths.push(path),
            None => {
                return Err(TreeDiffError::ObjectStoreError {
                    detail: format!("pack file not found for {}", String::from_utf8_lossy(name)),
                })
            }
        }
    }

    Ok(paths)
}

fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") || name.ends_with(b".idx") {
        let mut base = name.to_vec();
        if let Some(idx) = base.iter().rposition(|&b| b == b'.') {
            base.truncate(idx);
        }
        base
    } else {
        name.to_vec()
    }
}

/// Parses an inflated loose object into kind + payload.
///
/// Expects the loose format `<type> <size>\0<payload>` and verifies that the
/// payload size matches the header. Returns an error if the header is
/// malformed, the size mismatches the payload, or the object kind is unknown.
/// Payloads larger than `max_payload` are rejected.
fn parse_loose_object(
    bytes: &[u8],
    max_payload: usize,
) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
    // Loose object format: "<type> <size>\\0<payload>".
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(TreeDiffError::CorruptTree {
            detail: "missing object header terminator",
        })?;

    let header = &bytes[..nul];
    let mut parts = header.split(|&b| b == b' ');
    let kind_bytes = parts.next().ok_or(TreeDiffError::CorruptTree {
        detail: "missing object kind",
    })?;
    let size_bytes = parts.next().ok_or(TreeDiffError::CorruptTree {
        detail: "missing object size",
    })?;
    if parts.next().is_some() {
        return Err(TreeDiffError::CorruptTree {
            detail: "invalid object header",
        });
    }

    let size = parse_decimal(size_bytes).ok_or(TreeDiffError::CorruptTree {
        detail: "invalid object size",
    })? as usize;
    if size > max_payload {
        return Err(TreeDiffError::ObjectStoreError {
            detail: format!("object size {size} exceeds cap {max_payload}"),
        });
    }

    let payload = &bytes[nul + 1..];
    if payload.len() != size {
        return Err(TreeDiffError::CorruptTree {
            detail: "object size mismatch",
        });
    }

    let kind = match kind_bytes {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "unknown loose object type".to_string(),
            })
        }
    };

    Ok((kind, payload.to_vec()))
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(value)
}

fn oid_to_hex(oid: &OidBytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() as usize * 2);
    for &b in oid.as_slice() {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

fn hex_digit(val: u8) -> u8 {
    match val {
        0..=9 => b'0' + val,
        10..=15 => b'a' + (val - 10),
        _ => b'?',
    }
}

fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
