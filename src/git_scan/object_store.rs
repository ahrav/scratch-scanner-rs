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

use super::errors::TreeDiffError;
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::pack_inflate::{
    apply_delta, inflate_exact, inflate_limited, EntryKind, ObjectKind, PackFile,
};
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;
use super::tree_cache::TreeCache;
use super::tree_diff_limits::TreeDiffLimits;

/// Maximum entry header bytes to parse in pack files.
const MAX_ENTRY_HEADER_BYTES: usize = 64;
/// Maximum depth for delta chains.
const MAX_DELTA_DEPTH: u8 = 64;
/// Safety allowance for loose object headers (`"tree <size>\0"`).
const LOOSE_HEADER_MAX_BYTES: usize = 64;

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
    /// # Contract
    /// - The returned bytes are the tree payload only (no loose header).
    /// - Missing objects should map to `TreeDiffError::TreeNotFound`.
    /// - Objects that are not trees should map to `TreeDiffError::NotATree`.
    ///
    /// # Errors
    /// - `TreeNotFound` if the object doesn't exist
    /// - `NotATree` if the object exists but isn't a tree
    fn load_tree(&mut self, oid: &OidBytes) -> Result<Vec<u8>, TreeDiffError>;
}

/// Pack/loose object store for tree loading.
///
/// Holds a borrowed MIDX view (tied to the repo job's bytes view lifetime) and
/// lazily maps pack files on demand. Pack bytes are cached so recursive delta
/// resolution can borrow pack data without aliasing `self`.
///
/// The tree cache stores decompressed payloads, but cache hits are still
/// returned as owned `Vec<u8>` to keep `TreeSource` ownership semantics
/// simple for callers.
#[derive(Debug)]
pub struct ObjectStore<'a> {
    oid_len: u8,
    max_object_bytes: usize,
    midx: MidxView<'a>,
    pack_paths: Vec<PathBuf>,
    pack_cache: Vec<Option<BytesView>>,
    loose_dirs: Vec<PathBuf>,
    tree_cache: TreeCache,
}

impl<'a> ObjectStore<'a> {
    /// Opens an object store for the given repository job.
    ///
    /// Verifies that the MIDX covers all pack files found in pack directories,
    /// including alternates, so pack lookups are complete.
    ///
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if artifacts are missing,
    /// the MIDX is malformed, or pack files cannot be resolved.
    pub fn open(repo: &'a RepoJobState, limits: &TreeDiffLimits) -> Result<Self, TreeDiffError> {
        if !repo.artifact_status.is_ready() {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "repo artifacts not ready".to_string(),
            });
        }

        let midx_bytes =
            repo.mmaps
                .midx
                .as_ref()
                .ok_or_else(|| TreeDiffError::ObjectStoreError {
                    detail: "midx bytes missing".to_string(),
                })?;

        let midx =
            MidxView::parse(midx_bytes.as_slice(), repo.object_format).map_err(store_error)?;

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
        let max_object_bytes = limits.max_tree_bytes_per_job.min(usize::MAX as u64) as usize;

        Ok(Self {
            oid_len: repo.object_format.oid_len(),
            max_object_bytes,
            midx,
            pack_paths,
            pack_cache,
            loose_dirs,
            tree_cache,
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

    /// Loads an object with an explicit remaining delta depth.
    ///
    /// `depth` counts remaining delta edges; when it reaches 0, delta
    /// resolution stops and the call fails with a depth error.
    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
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
        let obj = self.read_pack_object(pack.as_ref(), offset, depth)?;
        Ok(Some(obj))
    }

    fn read_pack_object(
        &mut self,
        pack_bytes: &[u8],
        offset: u64,
        depth: u8,
    ) -> Result<(ObjectKind, Vec<u8>), TreeDiffError> {
        // Pack objects can be delta chains; bound recursion by depth.
        let pack = PackFile::parse(pack_bytes, self.oid_len as usize).map_err(store_error)?;
        let header = pack
            .entry_header_at(offset, MAX_ENTRY_HEADER_BYTES)
            .map_err(store_error)?;

        let size = usize::try_from(header.size).map_err(|_| store_error("object size overflow"))?;
        if size > self.max_object_bytes {
            return Err(TreeDiffError::ObjectStoreError {
                detail: format!("object size {size} exceeds cap {}", self.max_object_bytes),
            });
        }

        match header.kind {
            EntryKind::NonDelta { kind } => {
                let mut out = Vec::with_capacity(size);
                inflate_exact(pack.slice_from(header.data_start), &mut out, size)
                    .map_err(store_error)?;
                Ok((kind, out))
            }
            EntryKind::OfsDelta { base_offset } => {
                if depth == 0 {
                    return Err(store_error("delta chain too deep"));
                }
                let (base_kind, base_bytes) =
                    self.read_pack_object(pack_bytes, base_offset, depth - 1)?;

                let mut delta = Vec::with_capacity(size.min(self.max_object_bytes));
                inflate_limited(
                    pack.slice_from(header.data_start),
                    &mut delta,
                    self.max_object_bytes,
                )
                .map_err(store_error)?;

                let mut out = Vec::with_capacity(size);
                apply_delta(&base_bytes, &delta, &mut out, size, self.max_object_bytes)
                    .map_err(store_error)?;

                Ok((base_kind, out))
            }
            EntryKind::RefDelta { base_oid } => {
                if depth == 0 {
                    return Err(store_error("delta chain too deep"));
                }
                let (base_kind, base_bytes) = self.load_object_with_depth(&base_oid, depth - 1)?;

                let mut delta = Vec::with_capacity(size.min(self.max_object_bytes));
                inflate_limited(
                    pack.slice_from(header.data_start),
                    &mut delta,
                    self.max_object_bytes,
                )
                .map_err(store_error)?;

                let mut out = Vec::with_capacity(size);
                apply_delta(&base_bytes, &delta, &mut out, size, self.max_object_bytes)
                    .map_err(store_error)?;

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

            // Parse and validate the loose header before returning the payload.
            let (kind, payload) = parse_loose_object(&out, self.max_object_bytes)?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    /// Returns cached pack bytes for the given pack id, mapping if needed.
    fn pack_data(&mut self, pack_id: u16) -> Result<BytesView, TreeDiffError> {
        // Pack files are immutable during the scan. Cache their bytes so
        // recursive delta resolution can reuse pack data cheaply.
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
                memmap2::Mmap::map(&file).map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!("failed to mmap pack {}: {err}", path.display()),
                })?
            };
            self.pack_cache[idx] = Some(BytesView::from_mmap(mmap));
        }

        Ok(self.pack_cache[idx]
            .as_ref()
            .expect("pack bytes present")
            .clone())
    }
}

impl TreeSource for ObjectStore<'_> {
    fn load_tree(&mut self, oid: &OidBytes) -> Result<Vec<u8>, TreeDiffError> {
        if oid.len() != self.oid_len {
            return Err(TreeDiffError::InvalidOidLength {
                len: oid.len() as usize,
                expected: self.oid_len as usize,
            });
        }

        if let Some(bytes) = self.tree_cache.get(oid) {
            return Ok(bytes.to_vec());
        }

        let (kind, data) = self.load_object(oid)?;
        if kind != ObjectKind::Tree {
            return Err(TreeDiffError::NotATree);
        }

        // Cache is best-effort; failures are ignored.
        self.tree_cache.insert(*oid, &data);
        Ok(data)
    }
}

fn store_error<E: std::fmt::Display>(err: E) -> TreeDiffError {
    TreeDiffError::ObjectStoreError {
        detail: err.to_string(),
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
/// Returns an error if the header is malformed, the size mismatches the
/// payload, or the object kind is unknown.
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
