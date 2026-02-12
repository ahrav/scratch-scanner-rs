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
//!    (except commits listed in `shallow`, which are treated as traversal roots)
//! 7. Repeat until frontier empty or limits exceeded
//!
//! # Limits
//! - `max_commits`: Stop loading after this many commits
//! - `max_commit_object_bytes`: Reject commits exceeding this size
//! - `max_parents`: Reject commits with too many parents
//! - `max_delta_depth`: Abort overly deep delta chains
//! - `max_shallow_file_bytes`: Reject oversized `.git/shallow` files
//! - `max_shallow_roots`: Reject excessive unique shallow roots (also clamped
//!   by the preallocated shallow-root capacity)
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
//!
//! # Shallow Boundaries
//! Commits listed in `.git/shallow` are loaded as normal commit nodes, but BFS
//! intentionally does not enqueue their parents. This preserves first-class
//! graph nodes for local history while preventing traversal into known-missing
//! remote ancestry.

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

use memmap2::Mmap;

use super::byte_arena::ByteRef;
use super::commit_parse::{parse_commit, CommitParseLimits};
use super::identity_intern::{CommitIdentityIds, IdentityInterner, SENTINEL_ID};
use super::identity_parse::{parse_author_identity, parse_committer_identity};
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
    /// Shallow file exceeds configured byte cap.
    ShallowFileTooLarge {
        path: PathBuf,
        size: u64,
        limit: u32,
    },
    /// Too many unique shallow roots were ingested.
    TooManyShallowRoots {
        path: PathBuf,
        line: u32,
        count: u32,
        limit: u32,
    },
    /// Delta chain too deep.
    DeltaChainTooDeep {
        pack_id: u16,
        offset: u64,
        depth: u8,
    },
    /// Identity parsed successfully but could not be interned.
    IdentityInternError {
        oid: OidBytes,
        field: &'static str,
        reason: &'static str,
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
            Self::ShallowFileTooLarge { path, size, limit } => {
                write!(
                    f,
                    "shallow file too large: {} (size: {size}, limit: {limit})",
                    path.display()
                )
            }
            Self::TooManyShallowRoots {
                path,
                line,
                count,
                limit,
            } => {
                write!(
                    f,
                    "too many shallow roots in {} at line {line}: {count} (limit: {limit})",
                    path.display()
                )
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
            Self::IdentityInternError { oid, field, reason } => {
                write!(
                    f,
                    "commit {oid} identity interning failed for {field}: {reason}"
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
///
/// Parent OIDs preserve the order from the commit object, which matters
/// for first-parent semantics and deterministic traversal.
#[derive(Debug, Clone)]
pub struct LoadedCommit {
    /// Commit OID.
    pub oid: OidBytes,
    /// Tree OID this commit points to.
    pub tree_oid: OidBytes,
    /// Parent commit OIDs (in commit-object order).
    pub parents: Vec<OidBytes>,
    /// Committer timestamp (Unix epoch seconds).
    pub timestamp: u64,
}

/// Limits for commit loading.
///
/// These bounds are guardrails against malicious or pathological object graphs
/// (oversized commit payloads, extreme merge fan-in, and deep delta chains).
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
    /// Maximum bytes accepted from a single shallow file.
    pub max_shallow_file_bytes: u32,
    /// Maximum unique shallow roots accepted across all shallow files.
    ///
    /// Effective limit is additionally capped by
    /// [`ShallowBoundaryRoots::PREALLOC_CAPACITY`].
    pub max_shallow_roots: u32,
}

impl Default for CommitLoadLimits {
    fn default() -> Self {
        Self {
            max_commits: 10_000_000,              // 10M commits
            max_commit_object_bytes: 1024 * 1024, // 1 MiB
            max_parents: 256,
            max_delta_depth: 64,
            max_shallow_file_bytes: 8 * 1024 * 1024, // 8 MiB
            max_shallow_roots: ShallowBoundaryRoots::PREALLOC_CAPACITY as u32,
        }
    }
}

/// Compact shallow-boundary root set used by commit traversal.
///
/// Layout is optimized for expected shallow-root cardinalities:
/// - `Empty`: no lookup work in the BFS hot path
/// - `One`: single equality check
/// - `ManySorted`: sorted contiguous OID storage + binary search
///
/// `ManySorted` is populated from a preallocated vector to avoid additional
/// heap growth in common cases.
#[derive(Debug, Clone)]
pub enum ShallowBoundaryRoots {
    Empty,
    One(OidBytes),
    ManySorted(Vec<OidBytes>),
}

impl ShallowBoundaryRoots {
    /// Preallocated shallow-root capacity (OID count).
    pub const PREALLOC_CAPACITY: usize = 256;

    #[inline(always)]
    fn contains(&self, oid: &OidBytes) -> bool {
        match self {
            Self::Empty => false,
            Self::One(root) => root == oid,
            Self::ManySorted(roots) => roots.binary_search(oid).is_ok(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::One(_) => 1,
            Self::ManySorted(roots) => roots.len(),
        }
    }

    fn from_deduped(mut roots: Vec<OidBytes>) -> Self {
        if roots.is_empty() {
            return Self::Empty;
        }
        roots.sort_unstable();
        roots.dedup();
        match roots.len() {
            0 => Self::Empty,
            1 => Self::One(roots[0]),
            _ => Self::ManySorted(roots),
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
/// The loader first resolves commits from MIDX-backed packs. If an OID is
/// absent from MIDX, it attempts the same OID in `loose_dirs`. Commits listed
/// in `.git/shallow` are treated as traversal roots: their parent links are
/// retained in the loaded commit but not enqueued for loading.
///
/// This is the canonical commit-loading entrypoint: callers must explicitly
/// provide loose-object lookup directories and shallow-boundary roots from the
/// same repository snapshot used to build `midx` and `pack_paths`.
///
/// # Preconditions
/// - `pack_paths` must be indexed by MIDX `pack_id`.
/// - `shallow_boundary_roots` should come from the same repository graph as
///   `tips`/`midx` to avoid unintentionally truncating traversal.
#[allow(clippy::too_many_arguments)]
pub fn load_commits_from_tips(
    tips: &[OidBytes],
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    loose_dirs: &[PathBuf],
    shallow_boundary_roots: &ShallowBoundaryRoots,
    format: ObjectFormat,
    limits: &CommitLoadLimits,
    progress: Option<&ProgressFn>,
) -> Result<Vec<LoadedCommit>, CommitLoadError> {
    let mut loader = CommitLoader::new(
        midx,
        pack_paths,
        loose_dirs,
        shallow_boundary_roots,
        format,
        limits,
    )?;
    loader.load_from_tips(tips, progress)
}

/// Loads commits with identity enrichment from tip OIDs using BFS.
///
/// Same BFS traversal as [`load_commits_from_tips`], but also
/// extracts author/committer identity from each commit's raw bytes and interns
/// the strings into `interner`. Returns both the loaded commits and a parallel
/// `Vec<CommitIdentityIds>` aligned 1:1 with the commit list.
///
/// When identity parsing fails for a commit (malformed header), the identity
/// IDs are set to [`SENTINEL_ID`]. If parsing succeeds but interning fails,
/// loading returns `CommitLoadError`.
#[allow(clippy::too_many_arguments)]
pub fn load_commits_with_identities(
    tips: &[OidBytes],
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    loose_dirs: &[PathBuf],
    shallow_boundary_roots: &ShallowBoundaryRoots,
    format: ObjectFormat,
    limits: &CommitLoadLimits,
    interner: &mut IdentityInterner,
    progress: Option<&ProgressFn>,
) -> Result<(Vec<LoadedCommit>, Vec<CommitIdentityIds>), CommitLoadError> {
    let mut loader = CommitLoader::new(
        midx,
        pack_paths,
        loose_dirs,
        shallow_boundary_roots,
        format,
        limits,
    )?;
    loader.load_from_tips_with_identities(tips, interner, progress)
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
///
/// Includes the primary objects pack dir and alternate object pack dirs,
/// skipping alternates that resolve to the primary objects directory.
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
///
/// Returns directories in precedence order: primary objects dir first, then
/// unique alternates.
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

/// Loads shallow-boundary commit OIDs from `shallow` files.
///
/// Git stores shallow-cut commits in `<gitdir>/shallow` (and, for linked
/// worktrees, potentially `<commondir>/shallow`). These commits are real local
/// objects whose parent links may reference non-local history. The commit
/// loader uses this set to stop BFS traversal at those boundaries.
///
/// Missing `shallow` files are treated as an empty set.
///
/// # Errors
/// Returns `CommitLoadError::Io(InvalidData)` when a `shallow` entry is not a
/// valid full-length OID for the repository object format. Returns dedicated
/// limit errors when shallow file size or root count bounds are exceeded. The
/// root-count bound is clamped by [`ShallowBoundaryRoots::PREALLOC_CAPACITY`].
pub fn load_shallow_boundary_roots(
    repo: &GitRepoPaths,
    format: ObjectFormat,
    limits: &CommitLoadLimits,
) -> Result<ShallowBoundaryRoots, CommitLoadError> {
    let mut shallow_files = Vec::with_capacity(2);
    shallow_files.push(repo.git_dir.join("shallow"));
    if repo.common_dir != repo.git_dir {
        shallow_files.push(repo.common_dir.join("shallow"));
    }

    let mut out = Vec::with_capacity(ShallowBoundaryRoots::PREALLOC_CAPACITY);
    let max_unique_roots = limits
        .max_shallow_roots
        .min(limits.max_commits)
        .min(ShallowBoundaryRoots::PREALLOC_CAPACITY as u32);
    let mut line_buf = String::new();

    for shallow_path in shallow_files {
        let file = match File::open(&shallow_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(CommitLoadError::Io(err)),
        };
        let file_size = file.metadata().map_err(CommitLoadError::Io)?.len();
        if file_size > limits.max_shallow_file_bytes as u64 {
            return Err(CommitLoadError::ShallowFileTooLarge {
                path: shallow_path,
                size: file_size,
                limit: limits.max_shallow_file_bytes,
            });
        }

        let mut reader = BufReader::new(file);
        let mut line_idx = 0u32;
        loop {
            line_buf.clear();
            if reader
                .read_line(&mut line_buf)
                .map_err(CommitLoadError::Io)?
                == 0
            {
                break;
            }
            line_idx = line_idx.saturating_add(1);
            let trimmed = line_buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some(oid) = parse_hex_oid_for_format(trimmed.as_bytes(), format) else {
                return Err(CommitLoadError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid shallow OID in {} at line {}",
                        shallow_path.display(),
                        line_idx
                    ),
                )));
            };

            if out.contains(&oid) {
                continue;
            }
            if out.len() >= max_unique_roots as usize {
                return Err(CommitLoadError::TooManyShallowRoots {
                    path: shallow_path.clone(),
                    line: line_idx,
                    count: u32::try_from(out.len().saturating_add(1)).unwrap_or(u32::MAX),
                    limit: max_unique_roots,
                });
            }
            out.push(oid);
        }
    }

    Ok(ShallowBoundaryRoots::from_deduped(out))
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
///
/// Owns a lazy mmap cache for pack files: each pack is mapped on first
/// access and reused for all subsequent lookups within the same load call.
/// Delta resolution is recursive (bounded by `max_delta_depth`); each
/// recursive call releases the pack borrow before recursing so the mmap
/// cache can be extended if the base lives in a different pack.
struct CommitLoader<'m, 'p, 'l, 's> {
    /// MIDX used for OID → (pack_id, offset) resolution.
    midx: &'m MidxView<'m>,
    /// Pack paths aligned to MIDX pack ids.
    pack_paths: &'p [PathBuf],
    /// Loose object directories (primary objects dir + alternates).
    loose_dirs: &'l [PathBuf],
    /// Commit OIDs at shallow boundaries (`.git/shallow`).
    shallow_boundary_roots: &'s ShallowBoundaryRoots,
    format: ObjectFormat,
    limits: CommitLoadLimits,
    parse_limits: CommitParseLimits,
    /// Lazy cache of memory-mapped pack files (indexed by pack id).
    pack_cache: Vec<Option<Mmap>>,
    /// Cached pack header metadata (indexed by pack id).
    pack_parse_cache: Vec<Option<PackHeader>>,
}

impl<'m, 'p, 'l, 's> CommitLoader<'m, 'p, 'l, 's> {
    fn new(
        midx: &'m MidxView<'m>,
        pack_paths: &'p [PathBuf],
        loose_dirs: &'l [PathBuf],
        shallow_boundary_roots: &'s ShallowBoundaryRoots,
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
            shallow_boundary_roots,
            format,
            limits: *limits,
            parse_limits,
            pack_cache,
            pack_parse_cache,
        })
    }

    /// Runs the BFS traversal from `tips`, returning loaded commits in
    /// discovery order. See module docs for the full algorithm.
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

            // Shallow-boundary commits intentionally reference unavailable
            // ancestors. Keep parent links for graph semantics, but stop BFS.
            if !self.shallow_boundary_roots.contains(&oid) {
                for parent in &commit.parents {
                    let _ = enqueue_frontier_oid(*parent, &visited, &mut queued, &mut frontier);
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

    /// BFS traversal with identity enrichment. Returns commits and a
    /// parallel `Vec<CommitIdentityIds>` aligned 1:1 with the commit list.
    ///
    /// Alignment invariant: `identity_ids[i]` always corresponds to
    /// `commits[i]` for every loaded commit.
    fn load_from_tips_with_identities(
        &mut self,
        tips: &[OidBytes],
        interner: &mut IdentityInterner,
        progress: Option<&ProgressFn>,
    ) -> Result<(Vec<LoadedCommit>, Vec<CommitIdentityIds>), CommitLoadError> {
        let mut commits = Vec::new();
        let mut identity_ids = Vec::new();
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

            let (commit, ids) = self.load_commit_with_identity(&oid, interner)?;

            if !self.shallow_boundary_roots.contains(&oid) {
                for parent in &commit.parents {
                    let _ = enqueue_frontier_oid(*parent, &visited, &mut queued, &mut frontier);
                }
            }

            commits.push(commit);
            identity_ids.push(ids);

            if let Some(cb) = progress {
                if commits.len() % 1000 == 0 {
                    cb(commits.len() as u32);
                }
            }
        }

        Ok((commits, identity_ids))
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

    /// Loads a commit and extracts identity data from the raw bytes.
    ///
    /// Performs the same object loading and parsing as [`load_commit`](Self::load_commit),
    /// then makes a second pass over the raw header bytes (~200 B) to extract
    /// author/committer identity via [`parse_author_identity`] and
    /// [`parse_committer_identity`]. The identity strings are interned into
    /// `interner`; on parse failure, fields default to [`SENTINEL_ID`].
    /// Interner failures return `CommitLoadError::IdentityInternError`.
    fn load_commit_with_identity(
        &mut self,
        oid: &OidBytes,
        interner: &mut IdentityInterner,
    ) -> Result<(LoadedCommit, CommitIdentityIds), CommitLoadError> {
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

        // Extract identity from raw commit bytes before parsing consumes structure.
        let ids = intern_commit_identities(&data, interner, *oid)?;

        let parsed = parse_commit(&data, self.format, &self.parse_limits).map_err(|e| {
            CommitLoadError::ParseError {
                oid: *oid,
                detail: e.to_string(),
            }
        })?;

        let commit = LoadedCommit {
            oid: *oid,
            tree_oid: parsed.tree_oid,
            parents: parsed.parents,
            timestamp: parsed.committer_timestamp,
        };

        Ok((commit, ids))
    }

    /// Attempts to load `oid` from loose-object directories.
    ///
    /// Returns `Ok(None)` when the object is not present in any loose dir. Any
    /// read/inflate/header-parse failure for a discovered loose object returns
    /// `CommitLoadError::LooseObjectError`.
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

    /// Loads one object from pack storage, resolving deltas recursively.
    ///
    /// Starts recursion at the configured maximum delta depth.
    fn load_object(
        &mut self,
        pack_id: u16,
        offset: u64,
    ) -> Result<(ObjectKind, Vec<u8>), CommitLoadError> {
        let max_depth = self.limits.max_delta_depth;
        self.load_object_with_depth(pack_id, offset, max_depth)
    }

    /// Resolves a pack entry, recursing through delta chains up to `depth`.
    ///
    /// For delta entries (OFS_DELTA / REF_DELTA), the method extracts the
    /// entry header, drops the pack borrow, recurses to resolve the base,
    /// then re-borrows the pack to inflate the delta payload. This
    /// borrow-release-reborrow pattern is necessary because `ensure_pack_loaded`
    /// may mutate `pack_cache` when the base lives in a different pack.
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

    /// Memory-maps and caches the pack file for `pack_id` if not already
    /// loaded. Subsequent calls for the same `pack_id` are no-ops.
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

/// Parses a decompressed loose object.
///
/// Git loose objects have the wire format `<type> <decimal-size>\0<payload>`
/// after zlib decompression. The caller is responsible for decompression
/// before calling this function.
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

/// Parses ASCII decimal digits into `u64` with overflow checks.
///
/// Returns `None` for empty, non-digit, or overflowing inputs.
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

/// Parses a full-length hex OID string for the repository object format.
///
/// Returns `None` on length mismatch or invalid hex characters.
fn parse_hex_oid_for_format(hex: &[u8], format: ObjectFormat) -> Option<OidBytes> {
    let expected_hex_len = format.hex_len() as usize;
    if hex.len() != expected_hex_len {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, pair) in hex.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[idx] = (hi << 4) | lo;
    }

    match format {
        ObjectFormat::Sha1 => {
            let mut sha1 = [0u8; 20];
            sha1.copy_from_slice(&out[..20]);
            Some(OidBytes::sha1(sha1))
        }
        ObjectFormat::Sha256 => Some(OidBytes::sha256(out)),
    }
}

#[inline(always)]
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Extracts and interns author/committer identity from raw commit bytes.
///
/// Makes a single pass over the commit header (~200 bytes) to locate the
/// `author` and `committer` lines, then interns the name/email strings.
/// On parse failure (malformed header), the corresponding fields are set
/// to [`SENTINEL_ID`]. If parsing succeeds but interning fails, returns
/// `CommitLoadError::IdentityInternError`.
fn intern_commit_identities(
    data: &[u8],
    interner: &mut IdentityInterner,
    oid: OidBytes,
) -> Result<CommitIdentityIds, CommitLoadError> {
    #[inline]
    fn intern_field(
        interner: &mut IdentityInterner,
        bytes: &[u8],
        oid: OidBytes,
        field: &'static str,
    ) -> Result<u32, CommitLoadError> {
        if let Some(id) = interner.intern(bytes) {
            return Ok(id);
        }

        // `IdentityInterner::intern` only fails for oversized fields or arena
        // exhaustion. Treat both as hard errors so parse-failure sentinel use
        // remains unambiguous.
        let reason = if bytes.len() > ByteRef::MAX_LEN as usize {
            "too_long"
        } else {
            "arena_full"
        };

        Err(CommitLoadError::IdentityInternError { oid, field, reason })
    }

    let (author_name, author_email) = match parse_author_identity(data) {
        Some(raw) => (
            intern_field(interner, raw.name, oid, "author_name")?,
            intern_field(interner, raw.email, oid, "author_email")?,
        ),
        None => (SENTINEL_ID, SENTINEL_ID),
    };

    let (committer_name, committer_email) = match parse_committer_identity(data) {
        Some(raw) => (
            intern_field(interner, raw.name, oid, "committer_name")?,
            intern_field(interner, raw.email, oid, "committer_email")?,
        ),
        None => (SENTINEL_ID, SENTINEL_ID),
    };

    Ok(CommitIdentityIds {
        author_name,
        author_email,
        committer_name,
        committer_email,
    })
}

/// Converts an OID to its lowercase hex representation for loose-object
/// path construction (`ab/cdef…`).
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
    use crate::git_scan::RepoKind;
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

    fn test_repo_paths(base: &std::path::Path) -> GitRepoPaths {
        let git_dir = base.join(".git");
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(base.to_path_buf()),
            git_dir: git_dir.clone(),
            common_dir: git_dir,
            objects_dir,
            pack_dir,
            alternate_object_dirs: Vec::new(),
        }
    }

    fn sha1_hex(seed: u8) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(40);
        for idx in 0..20u8 {
            let _ = write!(&mut out, "{:02x}", seed.wrapping_add(idx));
        }
        out
    }

    fn make_commit_bytes(
        author_name: &[u8],
        author_email: &[u8],
        committer_name: &[u8],
        committer_email: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"tree ");
        buf.extend_from_slice(&[b'a'; 40]);
        buf.push(b'\n');
        buf.extend_from_slice(b"author ");
        buf.extend_from_slice(author_name);
        buf.extend_from_slice(b" <");
        buf.extend_from_slice(author_email);
        buf.extend_from_slice(b"> 1700000000 +0000\n");
        buf.extend_from_slice(b"committer ");
        buf.extend_from_slice(committer_name);
        buf.extend_from_slice(b" <");
        buf.extend_from_slice(committer_email);
        buf.extend_from_slice(b"> 1700000000 +0000\n");
        buf.push(b'\n');
        buf.extend_from_slice(b"commit message\n");
        buf
    }

    #[test]
    fn intern_commit_identities_interner_failure_is_error_parse_failure_is_sentinel() {
        let valid = make_commit_bytes(b"Alice", b"alice@example.com", b"Bob", b"bob@example.com");
        assert!(parse_author_identity(&valid).is_some());
        assert!(parse_committer_identity(&valid).is_some());

        // With no interner capacity, this must be an error (never sentinel).
        let oid = test_oid(0xA1);
        let mut exhausted = IdentityInterner::with_capacity(0, 0);
        let err = intern_commit_identities(&valid, &mut exhausted, oid)
            .expect_err("interner failure must be a hard error");
        match err {
            CommitLoadError::IdentityInternError {
                oid: err_oid,
                field,
                reason,
            } => {
                assert_eq!(err_oid, oid);
                assert_eq!(field, "author_name");
                assert_eq!(reason, "arena_full");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Parse failures still map to sentinel IDs even with zero interner
        // capacity, so ambiguity is impossible.
        let malformed = b"tree aaaa\n\ncommit body\n";
        let mut tiny = IdentityInterner::with_capacity(0, 0);
        let ids = intern_commit_identities(malformed, &mut tiny, test_oid(0xA2)).unwrap();
        assert_eq!(ids.author_name, SENTINEL_ID);
        assert_eq!(ids.author_email, SENTINEL_ID);
        assert_eq!(ids.committer_name, SENTINEL_ID);
        assert_eq!(ids.committer_email, SENTINEL_ID);
    }

    #[test]
    fn limits_default_reasonable() {
        let limits = CommitLoadLimits::default();
        assert!(limits.max_commits >= 1_000_000);
        assert!(limits.max_commit_object_bytes >= 64 * 1024);
        assert!(limits.max_parents >= 16);
        assert!(limits.max_delta_depth >= 32);
        assert!(limits.max_shallow_file_bytes >= 1024 * 1024);
        assert_eq!(
            limits.max_shallow_roots as usize,
            ShallowBoundaryRoots::PREALLOC_CAPACITY
        );
    }

    #[test]
    fn load_shallow_boundary_roots_missing_files_returns_empty() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        let roots =
            load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &CommitLoadLimits::default())
                .unwrap();
        assert!(roots.is_empty());
    }

    #[test]
    fn load_shallow_boundary_roots_invalid_oid_is_invalid_data() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        fs::write(repo.git_dir.join("shallow"), "not-an-oid\n").unwrap();

        let err =
            load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &CommitLoadLimits::default())
                .unwrap_err();
        match err {
            CommitLoadError::Io(err) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn load_shallow_boundary_roots_rejects_oversized_file() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        let payload = format!("{}\n", sha1_hex(0x11));
        fs::write(repo.git_dir.join("shallow"), payload).unwrap();

        let limits = CommitLoadLimits {
            max_shallow_file_bytes: 8,
            ..CommitLoadLimits::default()
        };
        let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
        match err {
            CommitLoadError::ShallowFileTooLarge { path, size, limit } => {
                assert_eq!(path, repo.git_dir.join("shallow"));
                assert!(size > u64::from(limit));
                assert_eq!(limit, 8);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn load_shallow_boundary_roots_rejects_too_many_unique_roots() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        let shallow = format!("{}\n{}\n", sha1_hex(0x22), sha1_hex(0x33));
        fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

        let limits = CommitLoadLimits {
            max_shallow_roots: 1,
            max_commits: 10,
            ..CommitLoadLimits::default()
        };
        let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
        match err {
            CommitLoadError::TooManyShallowRoots {
                path,
                line,
                count,
                limit,
            } => {
                assert_eq!(path, repo.git_dir.join("shallow"));
                assert_eq!(line, 2);
                assert_eq!(count, 2);
                assert_eq!(limit, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn load_shallow_boundary_roots_duplicates_do_not_trip_unique_limit() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        let oid = sha1_hex(0x44);
        let shallow = format!("{oid}\n{oid}\n{oid}\n");
        fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

        let limits = CommitLoadLimits {
            max_shallow_roots: 1,
            max_commits: 10,
            ..CommitLoadLimits::default()
        };
        let roots = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn load_shallow_boundary_roots_clamps_limit_to_max_commits() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());
        let shallow = format!("{}\n{}\n", sha1_hex(0x55), sha1_hex(0x66));
        fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

        let limits = CommitLoadLimits {
            max_shallow_roots: 10,
            max_commits: 1,
            ..CommitLoadLimits::default()
        };
        let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
        match err {
            CommitLoadError::TooManyShallowRoots { limit, .. } => {
                assert_eq!(limit, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn load_shallow_boundary_roots_clamps_limit_to_preallocated_capacity() {
        let temp = tempdir().unwrap();
        let repo = test_repo_paths(temp.path());

        let mut shallow = String::new();
        for idx in 0..=ShallowBoundaryRoots::PREALLOC_CAPACITY {
            // 40-hex-digit SHA-1 OIDs; all unique across this range.
            shallow.push_str(&format!("{:040x}\n", idx + 1));
        }
        fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

        let limits = CommitLoadLimits {
            max_shallow_roots: 10_000,
            max_commits: 10_000,
            ..CommitLoadLimits::default()
        };
        let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
        match err {
            CommitLoadError::TooManyShallowRoots {
                line, count, limit, ..
            } => {
                assert_eq!(line as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY + 1);
                assert_eq!(count as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY + 1);
                assert_eq!(limit as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn load_shallow_boundary_roots_reads_common_dir_for_linked_worktree() {
        let temp = tempdir().unwrap();
        let worktree_root = temp.path().join("worktree");
        let git_dir = worktree_root.join(".git");
        let common_dir = temp.path().join("common.git");
        fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        fs::create_dir_all(common_dir.join("objects/pack")).unwrap();

        fs::write(git_dir.join("shallow"), format!("{}\n", sha1_hex(0x77))).unwrap();
        fs::write(common_dir.join("shallow"), format!("{}\n", sha1_hex(0x88))).unwrap();

        let repo = GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(worktree_root),
            git_dir: git_dir.clone(),
            common_dir: common_dir.clone(),
            objects_dir: common_dir.join("objects"),
            pack_dir: common_dir.join("objects/pack"),
            alternate_object_dirs: Vec::new(),
        };
        let limits = CommitLoadLimits {
            max_shallow_roots: 2,
            ..CommitLoadLimits::default()
        };

        let roots = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(roots.len(), 2);
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
        let shallow_boundary_roots = ShallowBoundaryRoots::Empty;
        let mut loader = CommitLoader::new(
            &midx,
            &pack_paths,
            &loose_dirs,
            &shallow_boundary_roots,
            ObjectFormat::Sha1,
            &limits,
        )
        .unwrap();

        let loaded = loader
            .load_object_with_depth(0, delta_offset, limits.max_delta_depth)
            .unwrap();
        assert_eq!(loaded.0, ObjectKind::Blob);
        assert_eq!(loaded.1, result);
    }
}
