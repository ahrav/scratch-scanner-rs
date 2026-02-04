//! Object store abstraction for tree loading.
//!
//! Provides a pack/loose-backed object loader that returns raw tree
//! payload bytes (no `tree <size>\0` header). This is used by the
//! tree diff walker to avoid blob reads while traversing trees.
//! Tree payloads are cached in a fixed-size, set-associative tree cache
//! to avoid repeated inflations of hot subtrees.
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
//! - Spill arena stores large tree payloads in a fixed-size mmapped file;
//!   spill indexing is best-effort and may disable itself when full
//!
//! # Ordering
//! Pack lookup is attempted before loose objects. This mirrors typical Git
//! layouts where packs are the primary store and loose objects are a fallback.

use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use memmap2::Mmap;

use super::errors::TreeDiffError;
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::pack_inflate::{
    apply_delta, inflate_exact, inflate_limited, EntryKind, ObjectKind, PackFile,
};
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;
use super::spill_arena::{SpillArena, SpillArenaError, SpillSlice};
use super::tree_cache::{TreeCache, TreeCacheHandle};
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
/// FNV-1a offset basis for spill index hashing.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
/// FNV-1a prime for spill index hashing.
const FNV_PRIME: u64 = 0x00000100000001b3;

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

/// Trait for loading tree object bytes.
///
/// Implement this with your object store (packed or loose).
/// The returned bytes must be the decompressed tree payload (no header).
pub trait TreeSource {
    /// Loads a tree object by OID.
    ///
    /// Implementations may allocate per call; higher-level caches can lend
    /// pinned payloads to avoid repeated inflations of hot subtrees.
    /// Returned bytes are treated as read-only and are not retained by the
    /// caller beyond the `TreeBytes` value.
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

    /// Returns the in-flight length (RAM-resident bytes).
    ///
    /// Spilled bytes are treated as 0 in-flight because they live in the
    /// spill arena, not in RAM.
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

/// Pack/loose object store for tree loading.
///
/// Holds a borrowed MIDX view (tied to the repo job's mmap lifetime) and
/// lazily mmaps pack files on demand. Pack mmaps are cached in `Arc` so
/// recursive delta resolution can borrow pack bytes without aliasing `self`.
///
/// The tree cache stores decompressed payloads; cache hits return pinned
/// handles so callers can borrow the bytes without copying.
#[derive(Debug)]
pub struct ObjectStore<'a> {
    oid_len: u8,
    max_object_bytes: usize,
    midx: MidxView<'a>,
    pack_paths: Vec<PathBuf>,
    pack_cache: Vec<Option<Arc<Mmap>>>,
    loose_dirs: Vec<PathBuf>,
    tree_cache: TreeCache,
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
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if artifacts are missing,
    /// the MIDX is malformed, or pack files cannot be resolved.
    pub fn open(
        repo: &'a RepoJobState,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
    ) -> Result<Self, TreeDiffError> {
        if !repo.artifact_status.is_ready() {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "repo artifacts not ready".to_string(),
            });
        }

        let midx_mmap =
            repo.mmaps
                .midx
                .as_ref()
                .ok_or_else(|| TreeDiffError::ObjectStoreError {
                    detail: "midx mmap missing".to_string(),
                })?;

        let midx = MidxView::parse(midx_mmap.as_ref(), repo.object_format).map_err(store_error)?;

        let pack_dirs = collect_pack_dirs(&repo.paths);
        let pack_names = list_pack_files(&pack_dirs)?;
        // Ensure every on-disk pack file is represented in the MIDX so
        // pack lookups are complete across alternates.
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))
            .map_err(store_error)?;

        let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
        let pack_cache = vec![None; pack_paths.len()];

        let loose_dirs = collect_loose_dirs(&repo.paths);
        let tree_cache = TreeCache::new(limits.max_tree_cache_bytes);
        let max_object_bytes = limits.max_tree_bytes_in_flight.min(usize::MAX as u64) as usize;
        let spill = SpillArena::new(spill_dir, limits.max_tree_spill_bytes).map_err(store_error)?;
        let spill_min_bytes = limits.max_tree_cache_bytes.max(1) as usize;
        let spill_index_entries = spill_index_entries(limits.max_tree_spill_bytes, spill_min_bytes);
        let spill_index = SpillIndex::new(spill_index_entries);

        Ok(Self {
            oid_len: repo.object_format.oid_len(),
            max_object_bytes,
            midx,
            pack_paths,
            pack_cache,
            loose_dirs,
            tree_cache,
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
    fn load_object(&mut self, oid: &OidBytes) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
        self.load_object_with_depth(oid, MAX_DELTA_DEPTH)
    }

    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
        // Depth is decremented per delta hop to bound recursion.
        if let Some(obj) = self.load_object_from_pack(oid, depth)? {
            return Ok(obj);
        }
        if let Some(obj) = self.load_object_from_loose(oid)? {
            return Ok(obj);
        }
        Err(TreeDiffError::TreeNotFound)
    }

    fn load_object_from_pack(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, TreeDiffError> {
        // MIDX lookups are O(log N) on the OID list and return pack offsets.
        let idx = match self.midx.find_oid(oid).map_err(store_error)? {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let (pack_id, offset) = self.midx.offset_at(idx).map_err(store_error)?;
        let pack = self.pack_data(pack_id)?;
        let obj = self.read_pack_object(pack_id, pack.as_ref(), offset, depth, Some(*oid))?;
        Ok(Some(obj))
    }

    fn read_pack_object(
        &mut self,
        pack_id: u16,
        pack_bytes: &[u8],
        offset: u64,
        depth: u8,
        root_oid: Option<OidBytes>,
    ) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
        // Pack objects can be delta chains; bound recursion by depth.
        let pack = PackFile::parse(pack_bytes, self.oid_len as usize).map_err(|err| {
            TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {offset}: {err}{}",
                    format_root_oid(root_oid)
                ),
            }
        })?;
        let header = pack
            .entry_header_at(offset, MAX_ENTRY_HEADER_BYTES)
            .map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {offset}: {err}{}",
                    format_root_oid(root_oid)
                ),
            })?;

        let payload_size =
            usize::try_from(header.size).map_err(|_| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {offset}: object size overflow{}",
                    format_root_oid(root_oid)
                ),
            })?;

        match header.kind {
            EntryKind::NonDelta { kind } => {
                if payload_size > self.max_object_bytes {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: object size {payload_size} exceeds cap {}{}",
                            self.max_object_bytes,
                            format_root_oid(root_oid)
                        ),
                    });
                }

                let mut out = Vec::with_capacity(payload_size);
                inflate_exact(pack.slice_from(header.data_start), &mut out, payload_size).map_err(
                    |err| TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: {err}{}",
                            format_root_oid(root_oid)
                        ),
                    },
                )?;
                Ok((kind, out))
            }
            EntryKind::OfsDelta { base_offset } => {
                if payload_size > self.max_object_bytes {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta payload size {payload_size} exceeds cap {}{}",
                            self.max_object_bytes,
                            format_root_oid(root_oid)
                        ),
                    });
                }
                if depth == 0 {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta chain too deep{}",
                            format_root_oid(root_oid)
                        ),
                    });
                }
                let (base_kind, base_bytes) =
                    self.read_pack_object(pack_id, pack_bytes, base_offset, depth - 1, root_oid)?;

                let mut delta = Vec::with_capacity(payload_size.min(self.max_object_bytes));
                inflate_limited(
                    pack.slice_from(header.data_start),
                    &mut delta,
                    self.max_object_bytes,
                )
                .map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {offset}: delta inflate failed: {err} (base offset {base_offset}){}",
                        format_root_oid(root_oid)
                    ),
                })?;

                let mut out = Vec::new();
                apply_delta(&base_bytes, &delta, &mut out, self.max_object_bytes)
                    .map_err(|err| TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta apply failed: {err} (base offset {base_offset}){}",
                            format_root_oid(root_oid)
                        ),
                    })?;

                Ok((base_kind, out))
            }
            EntryKind::RefDelta { base_oid } => {
                if payload_size > self.max_object_bytes {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta payload size {payload_size} exceeds cap {}{}",
                            self.max_object_bytes,
                            format_root_oid(root_oid)
                        ),
                    });
                }
                if depth == 0 {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta chain too deep{}",
                            format_root_oid(root_oid)
                        ),
                    });
                }
                let (base_kind, base_bytes) = self.load_object_with_depth(&base_oid, depth - 1)?;

                let mut delta = Vec::with_capacity(payload_size.min(self.max_object_bytes));
                inflate_limited(
                    pack.slice_from(header.data_start),
                    &mut delta,
                    self.max_object_bytes,
                )
                .map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {offset}: delta inflate failed: {err} (base oid {base_oid}){}",
                        format_root_oid(root_oid)
                    ),
                })?;

                let mut out = Vec::new();
                apply_delta(&base_bytes, &delta, &mut out, self.max_object_bytes)
                    .map_err(|err| TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {offset}: delta apply failed: {err} (base oid {base_oid}){}",
                            format_root_oid(root_oid)
                        ),
                    })?;

                Ok((base_kind, out))
            }
        }
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

        for base in &self.loose_dirs {
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

            let (kind, payload) = parse_loose_object(&out, self.max_object_bytes)?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    fn pack_data(&mut self, pack_id: u16) -> Result<Arc<Mmap>, TreeDiffError> {
        // Pack files are immutable during the scan. Cache their mmaps so
        // recursive delta resolution can reuse pack bytes cheaply.
        let idx = pack_id as usize;
        let path = self
            .pack_paths
            .get(idx)
            .ok_or_else(|| TreeDiffError::ObjectStoreError {
                detail: format!("pack id {pack_id} out of bounds"),
            })?
            .clone();

        if self.pack_cache.get(idx).is_none() {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "pack cache index out of bounds".to_string(),
            });
        }

        if self.pack_cache[idx].is_none() {
            let file = File::open(&path).map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!("failed to open pack {}: {err}", path.display()),
            })?;
            // SAFETY: The pack file is immutable for the duration of a repo
            // job. We map it read-only and never mutate through the mapping.
            let mmap = unsafe {
                Mmap::map(&file).map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!("failed to mmap pack {}: {err}", path.display()),
                })?
            };
            self.pack_cache[idx] = Some(Arc::new(mmap));
        }

        Ok(self.pack_cache[idx]
            .as_ref()
            .expect("pack mmap present")
            .clone())
    }

    fn try_spill(
        &mut self,
        oid: &OidBytes,
        bytes: &[u8],
    ) -> Result<Option<SpillSlice>, TreeDiffError> {
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
        if oid.len() != self.oid_len {
            return Err(TreeDiffError::InvalidOidLength {
                len: oid.len() as usize,
                expected: self.oid_len as usize,
            });
        }

        if let Some(handle) = self.tree_cache.get_handle(oid) {
            return Ok(TreeBytes::Cached(handle));
        }

        if let Some((offset, len)) = self.spill_index.lookup(oid) {
            if let Some(spill) = self.spill.as_ref() {
                return Ok(TreeBytes::Spilled(spill.slice(offset, len)));
            }
        }

        let (kind, data) = self.load_object(oid)?;
        if kind != ObjectKind::Tree {
            return Err(TreeDiffError::NotATree);
        }

        if let Some(slice) = self.try_spill(oid, &data)? {
            return Ok(TreeBytes::Spilled(slice));
        }

        // Cache is best-effort; failures are ignored.
        self.tree_cache.insert(*oid, &data);
        Ok(TreeBytes::Owned(data))
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

/// Hashes an OID for spill-index probing (FNV-1a).
fn hash_oid(oid: &OidBytes) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in oid.as_slice() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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
