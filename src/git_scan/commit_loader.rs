//! BFS commit loader for in-memory commit graph construction.
//!
//! Loads commit objects starting from tip OIDs, traversing parent links
//! until the frontier is exhausted. Uses MIDX for pack lookups and
//! lazy-maps pack files on demand.
//!
//! # Algorithm
//! 1. Start with tip OIDs in a frontier queue
//! 2. Pop OID from frontier
//! 3. Locate in MIDX → get (pack_id, offset)
//! 4. Mmap pack if needed, decode commit object
//! 5. Parse commit, collect parents
//! 6. Add unvisited parents to frontier
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
//! # Pack Access
//! Pack files are memory-mapped lazily on first access and cached per pack id.
//! The `pack_paths` slice must align with MIDX pack ids.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::path::PathBuf;

use memmap2::Mmap;

use super::commit_parse::{parse_commit, CommitParseLimits};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::{ObjectFormat, OidBytes};
use super::pack_inflate::{
    apply_delta, inflate_limited, EntryKind, InflateError, ObjectKind, PackFile, PackParseError,
};
use super::repo::GitRepoPaths;

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
    /// Commit not found in packs.
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
            Self::CommitNotFound { oid } => {
                write!(f, "commit {oid} not found in packs")
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
    let mut loader = CommitLoader::new(midx, pack_paths, format, limits)?;
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

/// Internal commit loader state.
struct CommitLoader<'a> {
    /// MIDX used for OID → (pack_id, offset) resolution.
    midx: &'a MidxView<'a>,
    /// Pack paths aligned to MIDX pack ids.
    pack_paths: &'a [PathBuf],
    format: ObjectFormat,
    limits: CommitLoadLimits,
    parse_limits: CommitParseLimits,
    /// Lazy cache of memory-mapped pack files (indexed by pack id).
    pack_cache: Vec<Option<Mmap>>,
}

impl<'a> CommitLoader<'a> {
    fn new(
        midx: &'a MidxView<'a>,
        pack_paths: &'a [PathBuf],
        format: ObjectFormat,
        limits: &CommitLoadLimits,
    ) -> Result<Self, CommitLoadError> {
        let mut pack_cache = Vec::with_capacity(pack_paths.len());
        pack_cache.resize_with(pack_paths.len(), || None);
        let parse_limits = CommitParseLimits {
            max_commit_bytes: limits.max_commit_object_bytes as usize,
            max_parents: limits.max_parents,
        };

        Ok(Self {
            midx,
            pack_paths,
            format,
            limits: *limits,
            parse_limits,
            pack_cache,
        })
    }

    fn load_from_tips(
        &mut self,
        tips: &[OidBytes],
        progress: Option<&ProgressFn>,
    ) -> Result<Vec<LoadedCommit>, CommitLoadError> {
        let mut commits = Vec::new();
        let mut visited = HashSet::new();
        let mut frontier: VecDeque<OidBytes> = tips.iter().copied().collect();

        while let Some(oid) = frontier.pop_front() {
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

            // Add unvisited parents to frontier
            for parent in &commit.parents {
                if !visited.contains(parent) {
                    frontier.push_back(*parent);
                }
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
        // Look up in MIDX
        let idx = self
            .midx
            .find_oid(oid)?
            .ok_or(CommitLoadError::CommitNotFound { oid: *oid })?;

        let (pack_id, offset) = self.midx.offset_at(idx)?;

        // Load and decode object
        let (kind, data) = self.load_object(pack_id, offset)?;

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
        let oid_len = self.format.oid_len() as usize;

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
            let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
            let pack = PackFile::parse(pack_bytes, oid_len)
                .map_err(|e| CommitLoadError::PackError { pack_id, source: e })?;

            let header = pack
                .entry_header_at(offset, 64)
                .map_err(|e| CommitLoadError::PackError { pack_id, source: e })?;

            (header.kind, header.data_start, header.size as usize)
        };

        // Use the minimum of the entry size and max_bytes as the inflate limit.
        // This ensures the Vec capacity matches the inflate limit for debug assertions.
        let inflate_limit = size.min(max_bytes);

        match kind {
            EntryKind::NonDelta { kind } => {
                let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
                let mut data = Vec::with_capacity(inflate_limit);
                inflate_limited(&pack_bytes[data_start..], &mut data, inflate_limit).map_err(
                    |e| CommitLoadError::InflateError {
                        pack_id,
                        offset,
                        source: e,
                    },
                )?;
                Ok((kind, data))
            }
            EntryKind::OfsDelta { base_offset } => {
                // Recursively load base first (releases borrow)
                let (base_kind, base_data) =
                    self.load_object_with_depth(pack_id, base_offset, depth - 1)?;

                // Re-borrow pack to inflate delta
                let pack_bytes = self.pack_cache[pack_id as usize].as_ref().unwrap().as_ref();
                let mut delta = Vec::with_capacity(inflate_limit);
                inflate_limited(&pack_bytes[data_start..], &mut delta, inflate_limit).map_err(
                    |e| CommitLoadError::InflateError {
                        pack_id,
                        offset,
                        source: e,
                    },
                )?;

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
                let mut delta = Vec::with_capacity(inflate_limit);
                inflate_limited(&pack_bytes[data_start..], &mut delta, inflate_limit).map_err(
                    |e| CommitLoadError::InflateError {
                        pack_id,
                        offset,
                        source: e,
                    },
                )?;

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
            self.pack_cache[idx] = Some(mmap);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
