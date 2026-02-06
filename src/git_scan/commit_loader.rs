//! BFS commit loader for in-memory commit graph construction.
//!
//! Loads commit objects starting from tip OIDs, traversing parent links
//! until the frontier is exhausted. Uses MIDX for pack lookups and
//! falls back to loose-object lookup when an OID is missing from MIDX.
//!
//! # Algorithm
//! 1. Start with tip OIDs in a frontier queue
//! 2. Pop OID from frontier
//! 3. Locate in MIDX → get (pack_id, offset), or fall back to loose object
//! 4. Decode commit object (pack mmap + inflate or loose inflate)
//! 5. Parse commit, collect parents
//! 6. Add parents to frontier only if neither visited nor already queued
//! 7. Repeat until frontier empty or limits exceeded
//!
//! # Limits
//! - `max_commits`: Stop loading after this many commits
//! - `max_commit_object_bytes`: Reject commits exceeding this size
//! - `max_parents`: Reject commits with too many parents
//! - `max_delta_depth`: Abort overly deep delta chains
//!
//! # Determinism
//! BFS order is deterministic given:
//! - The input `tips` order
//! - Stable parent ordering within commit objects
//! - Stable pack contents (MIDX + pack files)
//!
//! # Frontier Management
//! The traversal tracks two sets:
//! - `visited`: commits already popped and decoded
//! - `queued`: commits currently present in the BFS queue
//!
//! This avoids duplicate frontier entries in merge-heavy DAGs while preserving
//! first-seen BFS ordering.
//!
//! # Pack Access
//! Pack files are memory-mapped lazily on first access and cached per pack id.
//! The `pack_paths` slice must align with MIDX pack ids.

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

use memmap2::Mmap;

use super::commit_parse::{parse_commit, CommitParseLimits};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::{ObjectFormat, OidBytes};
use super::pack_inflate::{
    apply_delta, inflate_limited, EntryKind, InflateError, ObjectKind, PackFile, PackHeader,
    PackParseError,
};
use super::repo::GitRepoPaths;

/// Safety allowance for loose object headers (`"commit <size>\0"`).
const LOOSE_HEADER_MAX_BYTES: usize = 64;

/// Errors from commit loading.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommitLoadError {
    /// I/O error during pack access.
    Io(io::Error),
    /// MIDX lookup failed.
    MidxError(MidxError),
    /// Pack parsing failed.
    PackError {
        pack_id: u16,
        source: PackParseError,
    },
    /// Object inflate failed.
    InflateError {
        pack_id: u16,
        offset: u64,
        source: InflateError,
    },
    /// Delta resolution failed.
    DeltaError { pack_id: u16, detail: String },
    /// Commit parsing failed.
    ParseError { oid: OidBytes, detail: String },
    /// Object is not a commit.
    NotACommit { oid: OidBytes, kind: ObjectKind },
    /// Loose object decode/validation failed.
    LooseObjectError { oid: OidBytes, detail: String },
    /// Commit not found in packs or loose-object directories.
    CommitNotFound { oid: OidBytes },
    /// Too many commits.
    TooManyCommits { count: u32, limit: u32 },
    /// Delta chain too deep.
    DeltaChainTooDeep {
        pack_id: u16,
        offset: u64,
        depth: u8,
    },
}

impl std::fmt::Display for CommitLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "commit load I/O error: {err}"),
            Self::MidxError(err) => write!(f, "MIDX error: {err}"),
            Self::PackError { pack_id, source } => {
                write!(f, "pack {pack_id} error: {source}")
            }
            Self::InflateError {
                pack_id,
                offset,
                source,
            } => {
                write!(f, "pack {pack_id} offset {offset} inflate: {source}")
            }
            Self::DeltaError { pack_id, detail } => {
                write!(f, "pack {pack_id} delta error: {detail}")
            }
            Self::ParseError { oid, detail } => {
                write!(f, "commit {oid} parse error: {detail}")
            }
            Self::NotACommit { oid, kind } => {
                write!(f, "object {oid} is {kind:?}, not a commit")
            }
            Self::LooseObjectError { oid, detail } => {
                write!(f, "loose object {oid} error: {detail}")
            }
            Self::CommitNotFound { oid } => {
                write!(f, "commit {oid} not found in MIDX packs or loose objects")
            }
            Self::TooManyCommits { count, limit } => {
                write!(f, "too many commits: {count} (limit: {limit})")
            }
            Self::DeltaChainTooDeep {
                pack_id,
                offset,
                depth,
            } => {
                write!(
                    f,
                    "pack {pack_id} offset {offset}: delta chain depth {depth} exceeded"
                )
            }
        }
    }
}

impl std::error::Error for CommitLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::MidxError(err) => Some(err),
            Self::PackError { source, .. } => Some(source),
            Self::InflateError { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for CommitLoadError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<MidxError> for CommitLoadError {
    fn from(err: MidxError) -> Self {
        Self::MidxError(err)
    }
}

/// Loaded commit with all fields needed for graph construction.
#[derive(Debug, Clone)]
pub struct LoadedCommit {
    /// Commit OID.
    pub oid: OidBytes,
    /// Tree OID this commit points to.
    pub tree_oid: OidBytes,
    /// Parent commit OIDs.
    pub parents: Vec<OidBytes>,
    /// Committer timestamp (Unix epoch seconds).
    pub timestamp: u64,
}

/// Limits for commit loading.
#[derive(Debug, Clone, Copy)]
pub struct CommitLoadLimits {
    /// Maximum number of commits to load.
    pub max_commits: u32,
    /// Maximum commit object bytes before inflation.
    pub max_commit_object_bytes: u32,
    /// Maximum parents per commit.
    pub max_parents: usize,
    /// Maximum delta chain depth.
    pub max_delta_depth: u8,
}

impl Default for CommitLoadLimits {
    fn default() -> Self {
        Self {
            max_commits: 10_000_000,              // 10M commits
            max_commit_object_bytes: 1024 * 1024, // 1 MiB
            max_parents: 256,
            max_delta_depth: 64,
        }
    }
}

/// Progress callback for commit loading.
pub type ProgressFn = dyn Fn(u32);

/// Enqueues `oid` for BFS if it is neither visited nor already queued.
///
/// Returns `true` when the OID is appended to `frontier`.
#[inline(always)]
fn enqueue_frontier_oid(
    oid: OidBytes,
    visited: &HashSet<OidBytes>,
    queued: &mut HashSet<OidBytes>,
    frontier: &mut VecDeque<OidBytes>,
) -> bool {
    if visited.contains(&oid) {
        return false;
    }

    if queued.insert(oid) {
        frontier.push_back(oid);
        return true;
    }

    false
}

/// Loads commits starting from tip OIDs using BFS.
///
/// Returns all reachable commits in discovery order (BFS). The order is
/// deterministic given the same tip OIDs (including order) and pack contents.
///
/// # Arguments
/// * `tips` - Starting commit OIDs (branch tips, tags, etc.)
/// * `midx` - MIDX view for pack lookups
/// * `pack_paths` - Resolved pack file paths (in MIDX order)
/// * `format` - Object format (SHA-1 or SHA-256)
/// * `limits` - Loading limits
/// * `progress` - Optional progress callback (called every 1000 commits)
///
/// # Errors
/// Returns `CommitLoadError` if:
/// - A commit cannot be found or decoded
/// - Limits are exceeded
/// - Pack files cannot be read
pub fn load_commits_from_tips(
    tips: &[OidBytes],
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    format: ObjectFormat,
    limits: &CommitLoadLimits,
    progress: Option<&ProgressFn>,
) -> Result<Vec<LoadedCommit>, CommitLoadError> {
    let loose_dirs = derive_loose_dirs_from_pack_paths(pack_paths);
    load_commits_from_tips_with_loose_dirs(
        tips,
        midx,
        pack_paths,
        &loose_dirs,
        format,
        limits,
        progress,
    )
}

/// Loads commits starting from tip OIDs using BFS with explicit loose lookup dirs.
///
/// The loader first resolves commits from MIDX-backed packs. If an OID is
/// absent from MIDX, it attempts the same OID in `loose_dirs`.
pub fn load_commits_from_tips_with_loose_dirs(
    tips: &[OidBytes],
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    loose_dirs: &[PathBuf],
    format: ObjectFormat,
    limits: &CommitLoadLimits,
    progress: Option<&ProgressFn>,
) -> Result<Vec<LoadedCommit>, CommitLoadError> {
    let mut loader = CommitLoader::new(midx, pack_paths, loose_dirs, format, limits)?;
    loader.load_from_tips(tips, progress)
}

/// Resolves pack paths from MIDX pack names.
///
/// Returns paths in MIDX pack order (by pack_id).
/// The first matching directory in `pack_dirs` wins.
pub fn resolve_pack_paths_from_midx(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, CommitLoadError> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);

    for pack_name in midx.pack_names() {
        let path = find_pack_file(pack_name, pack_dirs)?;
        paths.push(path);
    }

    Ok(paths)
}

/// Collects pack directories from repo paths.
pub fn collect_pack_dirs(repo: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    dirs.push(repo.pack_dir.clone());

    for alternate in &repo.alternate_object_dirs {
        if alternate != &repo.objects_dir {
            dirs.push(alternate.join("pack"));
        }
    }

    dirs
}

/// Collects loose object directories from repo paths.
pub fn collect_loose_dirs(repo: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    dirs.push(repo.objects_dir.clone());

    for alternate in &repo.alternate_object_dirs {
        if alternate != &repo.objects_dir {
            dirs.push(alternate.clone());
        }
    }

    dirs
}

/// Finds a pack file by name across pack directories.
///
/// MIDX stores pack names with `.idx` extension (e.g., `pack-xxx.idx`).
/// This function converts the name to `.pack` extension to find the actual
/// pack data file.
fn find_pack_file(name: &[u8], pack_dirs: &[PathBuf]) -> Result<PathBuf, CommitLoadError> {
    let name_str = std::str::from_utf8(name).unwrap_or("<invalid>");

    // Convert .idx to .pack extension if needed (MIDX stores .idx names)
    let pack_name = if name_str.ends_with(".idx") {
        name_str.replace(".idx", ".pack")
    } else if name_str.ends_with(".pack") {
        name_str.to_string()
    } else {
        // No extension; try adding .pack
        format!("{name_str}.pack")
    };

    for dir in pack_dirs {
        let path = dir.join(&pack_name);
        if path.is_file() {
            return Ok(path);
        }
    }

    Err(CommitLoadError::Io(io::Error::new(
        io::ErrorKind::NotFound,
        format!("pack file not found: {pack_name}"),
    )))
}

fn derive_loose_dirs_from_pack_paths(pack_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for pack_path in pack_paths {
        let Some(pack_dir) = pack_path.parent() else {
            continue;
        };
        let Some(objects_dir) = pack_dir.parent() else {
            continue;
        };
        let objects_dir = objects_dir.to_path_buf();
        if !dirs.iter().any(|existing| existing == &objects_dir) {
            dirs.push(objects_dir);
        }
    }
    dirs
}

/// Internal commit loader state.
struct CommitLoader<'m, 'p, 'l> {
    /// MIDX used for OID → (pack_id, offset) resolution.
    midx: &'m MidxView<'m>,
    /// Pack paths aligned to MIDX pack ids.
    pack_paths: &'p [PathBuf],
    /// Loose object directories (primary objects dir + alternates).
    loose_dirs: &'l [PathBuf],
    format: ObjectFormat,
    limits: CommitLoadLimits,
    parse_limits: CommitParseLimits,
    /// Lazy cache of memory-mapped pack files (indexed by pack id).
    pack_cache: Vec<Option<Mmap>>,
    /// Cached pack header metadata (indexed by pack id).
    pack_parse_cache: Vec<Option<PackHeader>>,
}

impl<'m, 'p, 'l> CommitLoader<'m, 'p, 'l> {
    fn new(
        midx: &'m MidxView<'m>,
        pack_paths: &'p [PathBuf],
        loose_dirs: &'l [PathBuf],
        format: ObjectFormat,
        limits: &CommitLoadLimits,
    ) -> Result<Self, CommitLoadError> {
        let mut pack_cache = Vec::with_capacity(pack_paths.len());
        pack_cache.resize_with(pack_paths.len(), || None);
        let mut pack_parse_cache = Vec::with_capacity(pack_paths.len());
        pack_parse_cache.resize_with(pack_paths.len(), || None);
        let parse_limits = CommitParseLimits {
            max_commit_bytes: limits.max_commit_object_bytes as usize,
            max_parents: limits.max_parents,
        };

        Ok(Self {
            midx,
            pack_paths,
            loose_dirs,
            format,
            limits: *limits,
            parse_limits,
            pack_cache,
            pack_parse_cache,
        })
    }

    fn load_from_tips(
        &mut self,
        tips: &[OidBytes],
        progress: Option<&ProgressFn>,
    ) -> Result<Vec<LoadedCommit>, CommitLoadError> {
        let mut commits = Vec::new();
        let mut visited = HashSet::new();
        let mut queued = HashSet::with_capacity(tips.len());
        let mut frontier = VecDeque::with_capacity(tips.len());

        for tip in tips {
            let _ = enqueue_frontier_oid(*tip, &visited, &mut queued, &mut frontier);
        }

        while let Some(oid) = frontier.pop_front() {
            queued.remove(&oid);

            if !visited.insert(oid) {
                continue;
            }

            if commits.len() >= self.limits.max_commits as usize {
                return Err(CommitLoadError::TooManyCommits {
                    count: commits.len() as u32,
                    limit: self.limits.max_commits,
                });
            }

            let commit = self.load_commit(&oid)?;

            // Add unseen parents to frontier.
            for parent in &commit.parents {
                let _ = enqueue_frontier_oid(*parent, &visited, &mut queued, &mut frontier);
            }

            commits.push(commit);

            if let Some(cb) = progress {
                if commits.len() % 1000 == 0 {
                    cb(commits.len() as u32);
                }
            }
        }

        Ok(commits)
    }

    fn load_commit(&mut self, oid: &OidBytes) -> Result<LoadedCommit, CommitLoadError> {
        // Prefer MIDX-backed packs. Fall back to loose object lookup on miss.
        let (kind, data) = match self.midx.find_oid(oid)? {
            Some(idx) => {
                let (pack_id, offset) = self.midx.offset_at(idx)?;
                self.load_object(pack_id, offset)?
            }
            None => self
                .load_loose_object(oid)?
                .ok_or(CommitLoadError::CommitNotFound { oid: *oid })?,
        };

        if kind != ObjectKind::Commit {
            return Err(CommitLoadError::NotACommit { oid: *oid, kind });
        }

        // Parse commit
        let parsed = parse_commit(&data, self.format, &self.parse_limits).map_err(|e| {
            CommitLoadError::ParseError {
                oid: *oid,
                detail: e.to_string(),
            }
        })?;

        Ok(LoadedCommit {
            oid: *oid,
            tree_oid: parsed.tree_oid,
            parents: parsed.parents,
            timestamp: parsed.committer_timestamp,
        })
    }

    fn load_loose_object(
        &self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, CommitLoadError> {
        if oid.len() != self.format.oid_len() {
            return Err(CommitLoadError::ParseError {
                oid: *oid,
                detail: format!(
                    "OID length {} does not match object format length {}",
                    oid.len(),
                    self.format.oid_len()
                ),
            });
        }

        let hex = oid_to_hex(oid);
        let (dir_name, file_name) = hex.split_at(2);

        for base in self.loose_dirs {
            let path = base.join(dir_name).join(file_name);
            let compressed = match fs::read(&path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(CommitLoadError::LooseObjectError {
                        oid: *oid,
                        detail: format!("read failed for {}: {err}", path.display()),
                    })
                }
            };

            let max_payload = self.limits.max_commit_object_bytes as usize;
            let max_out = max_payload.saturating_add(LOOSE_HEADER_MAX_BYTES);
            let mut out = Vec::with_capacity(max_out);
            inflate_limited(&compressed, &mut out, max_out).map_err(|err| {
                CommitLoadError::LooseObjectError {
                    oid: *oid,
                    detail: format!("inflate failed for {}: {err}", path.display()),
                }
            })?;

            let (kind, payload) = parse_loose_object(&out, max_payload)
                .map_err(|detail| CommitLoadError::LooseObjectError { oid: *oid, detail })?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    fn load_object(
        &mut self,
        pack_id: u16,
        offset: u64,
    ) -> Result<(ObjectKind, Vec<u8>), CommitLoadError> {
        let max_depth = self.limits.max_delta_depth;
        self.load_object_with_depth(pack_id, offset, max_depth)
    }

    fn load_object_with_depth(
        &mut self,
        pack_id: u16,
        offset: u64,
        depth: u8,
    ) -> Result<(ObjectKind, Vec<u8>), CommitLoadError> {
        let max_depth = self.limits.max_delta_depth;
        let max_bytes = self.limits.max_commit_object_bytes as usize;
        if depth == 0 {
            return Err(CommitLoadError::DeltaChainTooDeep {
                pack_id,
                offset,
                depth: max_depth,
            });
        }

        // Ensure pack is loaded
        self.ensure_pack_loaded(pack_id)?;

        // Parse entry header (extract info, then release borrow)
        let (kind, data_start, size) = {
            let pack_idx = pack_id as usize;
            let pack_bytes = self.pack_cache[pack_idx].as_ref().unwrap().as_ref();
            let header = self.pack_parse_cache[pack_idx]
                .expect("pack header cached after ensure_pack_loaded");
            let pack = PackFile::from_header(pack_bytes, header);

            let header = pack
                .entry_header_at(offset, 64)
                .map_err(|e| CommitLoadError::PackError { pack_id, source: e })?;

            (header.kind, header.data_start, header.size as usize)
        };

        // Non-delta payloads should not exceed their declared entry size.
        // Delta payload streams can legitimately be larger than the decoded
        // object size, so delta inflate uses `max_bytes` below.
        let non_delta_inflate_limit = size.min(max_bytes);

        match kind {
            EntryKind::NonDelta { kind } => {
                let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
                let mut data = Vec::with_capacity(non_delta_inflate_limit);
                inflate_limited(
                    &pack_bytes[data_start..],
                    &mut data,
                    non_delta_inflate_limit,
                )
                .map_err(|e| CommitLoadError::InflateError {
                    pack_id,
                    offset,
                    source: e,
                })?;
                Ok((kind, data))
            }
            EntryKind::OfsDelta { base_offset } => {
                // Recursively load base first (releases borrow)
                let (base_kind, base_data) =
                    self.load_object_with_depth(pack_id, base_offset, depth - 1)?;

                // Re-borrow pack to inflate delta
                let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
                let mut delta = Vec::with_capacity(max_bytes);
                inflate_limited(&pack_bytes[data_start..], &mut delta, max_bytes).map_err(|e| {
                    CommitLoadError::InflateError {
                        pack_id,
                        offset,
                        source: e,
                    }
                })?;

                let mut result = Vec::new();
                apply_delta(&base_data, &delta, &mut result, max_bytes).map_err(|e| {
                    CommitLoadError::DeltaError {
                        pack_id,
                        detail: e.to_string(),
                    }
                })?;

                Ok((base_kind, result))
            }
            EntryKind::RefDelta { base_oid } => {
                // Look up base by OID
                let base_idx =
                    self.midx
                        .find_oid(&base_oid)?
                        .ok_or_else(|| CommitLoadError::DeltaError {
                            pack_id,
                            detail: format!("REF_DELTA base {base_oid} not found"),
                        })?;

                let (base_pack_id, base_offset) = self.midx.offset_at(base_idx)?;

                // Recursively load base first
                let (base_kind, base_data) =
                    self.load_object_with_depth(base_pack_id, base_offset, depth - 1)?;

                // Re-borrow pack to inflate delta
                let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
                let mut delta = Vec::with_capacity(max_bytes);
                inflate_limited(&pack_bytes[data_start..], &mut delta, max_bytes).map_err(|e| {
                    CommitLoadError::InflateError {
                        pack_id,
                        offset,
                        source: e,
                    }
                })?;

                let mut result = Vec::new();
                apply_delta(&base_data, &delta, &mut result, max_bytes).map_err(|e| {
                    CommitLoadError::DeltaError {
                        pack_id,
                        detail: e.to_string(),
                    }
                })?;

                Ok((base_kind, result))
            }
        }
    }

    fn ensure_pack_loaded(&mut self, pack_id: u16) -> Result<(), CommitLoadError> {
        let idx = pack_id as usize;
        if idx >= self.pack_cache.len() {
            return Err(CommitLoadError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("pack_id {pack_id} out of range"),
            )));
        }

        if self.pack_cache[idx].is_none() {
            let path = &self.pack_paths[idx];
            let file = File::open(path)?;
            // SAFETY: map read-only pack data; loader assumes packs are stable
            // for the duration of the scan.
            let mmap = unsafe { Mmap::map(&file)? };
            let oid_len = self.format.oid_len() as usize;
            let header = PackFile::parse_header(mmap.as_ref(), oid_len)
                .map_err(|e| CommitLoadError::PackError { pack_id, source: e })?;
            self.pack_cache[idx] = Some(mmap);
            self.pack_parse_cache[idx] = Some(header);
        }

        Ok(())
    }
}

fn parse_loose_object(bytes: &[u8], max_payload: usize) -> Result<(ObjectKind, Vec<u8>), String> {
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "missing object header terminator".to_string())?;

    let header = &bytes[..nul];
    let mut parts = header.split(|&b| b == b' ');
    let kind_bytes = parts
        .next()
        .ok_or_else(|| "missing object kind".to_string())?;
    let size_bytes = parts
        .next()
        .ok_or_else(|| "missing object size".to_string())?;
    if parts.next().is_some() {
        return Err("invalid object header".to_string());
    }

    let size = parse_decimal(size_bytes)
        .ok_or_else(|| "invalid object size in loose header".to_string())? as usize;
    if size > max_payload {
        return Err(format!("object size {size} exceeds cap {max_payload}"));
    }

    let payload = &bytes[nul + 1..];
    if payload.len() != size {
        return Err(format!(
            "object size mismatch: header={size}, payload={}",
            payload.len()
        ));
    }

    let kind = match kind_bytes {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => return Err("unknown loose object type".to_string()),
    };

    Ok((kind, payload.to_vec()))
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }

    let mut out = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(out)
}

fn oid_to_hex(oid: &OidBytes) -> String {
    let mut out = String::with_capacity(oid.len() as usize * 2);
    for &byte in oid.as_slice() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tempfile::tempdir;

    #[derive(Default)]
    struct MidxBuilder {
        pack_names: Vec<Vec<u8>>,
        objects: Vec<([u8; 20], u16, u64)>,
    }

    impl MidxBuilder {
        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
            self.objects.push((oid, pack_id, offset));
        }

        fn build(&self) -> Vec<u8> {
            let oid_len = 20;
            let pack_count = self.pack_names.len() as u32;
            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let mut pnam = Vec::new();
            for name in &self.pack_names {
                pnam.extend_from_slice(name);
                pnam.push(0);
            }

            let mut oidf = vec![0u8; 256 * 4];
            let mut counts = [0u32; 256];
            for (oid, _, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            let mut oidl = Vec::with_capacity(objects.len() * oid_len);
            for (oid, _, _) in &objects {
                oidl.extend_from_slice(oid);
            }

            let mut ooff = Vec::with_capacity(objects.len() * 8);
            for (_, pack_id, offset) in &objects {
                ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
                ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
            }

            let chunk_count = 4u8;
            let header_size = 12usize;
            let chunk_table_size = (chunk_count as usize + 1) * 12;

            let pnam_off = (header_size + chunk_table_size) as u64;
            let oidf_off = pnam_off + pnam.len() as u64;
            let oidl_off = oidf_off + oidf.len() as u64;
            let ooff_off = oidl_off + oidl.len() as u64;
            let end_off = ooff_off + ooff.len() as u64;

            let mut out = Vec::new();
            out.extend_from_slice(b"MIDX");
            out.push(1);
            out.push(1); // SHA-1
            out.push(chunk_count);
            out.push(0); // base count
            out.extend_from_slice(&pack_count.to_be_bytes());

            let mut push_chunk = |id: [u8; 4], off: u64| {
                out.extend_from_slice(&id);
                out.extend_from_slice(&off.to_be_bytes());
            };

            push_chunk(*b"PNAM", pnam_off);
            push_chunk(*b"OIDF", oidf_off);
            push_chunk(*b"OIDL", oidl_off);
            push_chunk(*b"OOFF", ooff_off);
            push_chunk([0, 0, 0, 0], end_off);

            out.extend_from_slice(&pnam);
            out.extend_from_slice(&oidf);
            out.extend_from_slice(&oidl);
            out.extend_from_slice(&ooff);
            out
        }
    }

    fn encode_entry_header(obj_type: u8, mut size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = (obj_type & 0x07) << 4;
        first |= (size & 0x0f) as u8;
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        out.push(first);
        while size != 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
        assert!(dist > 0);
        let mut bytes = Vec::new();
        bytes.push((dist & 0x7f) as u8);
        dist >>= 7;
        while dist > 0 {
            dist -= 1;
            bytes.push(((dist & 0x7f) as u8) | 0x80);
            dist >>= 7;
        }
        bytes.reverse();
        bytes
    }

    fn build_pack_with_large_ofs_delta(base: &[u8], result: &[u8]) -> (Vec<u8>, u64, usize) {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(base.len() as u64));
        delta.extend_from_slice(&encode_varint(result.len() as u64));

        // Encode as a sequence of literal insert opcodes (1..=127 bytes each).
        // This produces a valid delta stream with deterministic size overhead.
        let mut pos = 0usize;
        while pos < result.len() {
            let chunk = (result.len() - pos).min(127);
            delta.push(chunk as u8);
            delta.extend_from_slice(&result[pos..pos + chunk]);
            pos += chunk;
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = out.len() as u64;
        out.extend_from_slice(&encode_entry_header(3, base.len() as u64));
        out.extend_from_slice(&compress(base));

        let delta_offset = out.len() as u64;
        out.extend_from_slice(&encode_entry_header(6, result.len() as u64));
        out.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        out.extend_from_slice(&compress(&delta));
        out.extend_from_slice(&[0u8; 20]);

        (out, delta_offset, delta.len())
    }

    fn test_oid(byte: u8) -> OidBytes {
        let mut oid = [0u8; 20];
        oid[0] = byte;
        oid[19] = byte ^ 0x5a;
        OidBytes::sha1(oid)
    }

    #[test]
    fn limits_default_reasonable() {
        let limits = CommitLoadLimits::default();
        assert!(limits.max_commits >= 1_000_000);
        assert!(limits.max_commit_object_bytes >= 64 * 1024);
        assert!(limits.max_parents >= 16);
        assert!(limits.max_delta_depth >= 32);
    }

    #[test]
    fn loaded_commit_size() {
        // LoadedCommit should be reasonably sized
        let size = std::mem::size_of::<LoadedCommit>();
        // OidBytes(33) + OidBytes(33) + Vec(24) + u64(8) = ~98 bytes
        assert!(size < 150, "LoadedCommit too large: {size}");
    }

    #[test]
    fn enqueue_frontier_oid_skips_visited() {
        let oid = test_oid(0x11);
        let mut visited = HashSet::new();
        visited.insert(oid);
        let mut queued = HashSet::new();
        let mut frontier = VecDeque::new();

        assert!(!enqueue_frontier_oid(
            oid,
            &visited,
            &mut queued,
            &mut frontier
        ));
        assert!(frontier.is_empty());
        assert!(queued.is_empty());
    }

    #[test]
    fn enqueue_frontier_oid_dedupes_queued_entries() {
        let oid = test_oid(0x22);
        let visited = HashSet::new();
        let mut queued = HashSet::new();
        let mut frontier = VecDeque::new();

        assert!(enqueue_frontier_oid(
            oid,
            &visited,
            &mut queued,
            &mut frontier
        ));
        assert!(!enqueue_frontier_oid(
            oid,
            &visited,
            &mut queued,
            &mut frontier
        ));
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier.front(), Some(&oid));
    }

    #[test]
    fn enqueue_frontier_oid_preserves_first_seen_tip_order() {
        let a = test_oid(0x01);
        let b = test_oid(0x02);
        let c = test_oid(0x03);
        let tips = [a, b, a, c, b];

        let visited = HashSet::new();
        let mut queued = HashSet::new();
        let mut frontier = VecDeque::new();

        for oid in tips {
            let _ = enqueue_frontier_oid(oid, &visited, &mut queued, &mut frontier);
        }

        assert_eq!(frontier.len(), 3);
        assert_eq!(frontier.pop_front(), Some(a));
        assert_eq!(frontier.pop_front(), Some(b));
        assert_eq!(frontier.pop_front(), Some(c));
        assert!(frontier.is_empty());
    }

    #[test]
    fn large_valid_delta_stream_within_limit_does_not_raise_inflate_error() {
        let base = Vec::new();
        let result = vec![b'Z'; 192 * 1024];
        let (pack, delta_offset, delta_stream_len) =
            build_pack_with_large_ofs_delta(&base, &result);
        assert!(delta_stream_len > result.len());

        let max_commit_object_bytes = delta_stream_len + 512;
        assert!(delta_stream_len <= max_commit_object_bytes);

        let temp = tempdir().unwrap();
        let pack_path = temp.path().join("pack-large-delta.pack");
        fs::write(&pack_path, &pack).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-large-delta");
        builder.add_object([0x10; 20], 0, 12);
        builder.add_object([0x20; 20], 0, delta_offset);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let limits = CommitLoadLimits {
            max_commit_object_bytes: max_commit_object_bytes as u32,
            ..CommitLoadLimits::default()
        };

        let pack_paths = vec![pack_path];
        let loose_dirs = Vec::new();
        let mut loader =
            CommitLoader::new(&midx, &pack_paths, &loose_dirs, ObjectFormat::Sha1, &limits)
                .unwrap();

        let loaded = loader
            .load_object_with_depth(0, delta_offset, limits.max_delta_depth)
            .unwrap();
        assert_eq!(loaded.0, ObjectKind::Blob);
        assert_eq!(loaded.1, result);
    }
}
