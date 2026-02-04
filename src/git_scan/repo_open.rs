//! Repository discovery and open for Git scanning.
//!
//! This stage prepares a repository for scanning by:
//! - Resolving repository paths (worktree, bare, linked worktree)
//! - Checking artifact readiness (commit-graph, MIDX)
//! - Detecting maintenance lock files and recording artifact fingerprints
//! - Memory-mapping metadata files (commit-graph, MIDX only - not packs)
//! - Resolving start set tips (refs to scan)
//! - Loading persisted watermarks for incremental scanning
//!
//! Packs are not mmapped here. They are opened on demand in later phases
//! per pack plan to avoid unnecessary FD and VMA pressure.
//! # Invariants
//! - Missing artifacts yield `NeedsMaintenance` with empty `mmaps` and `start_set`.
//! - When artifacts are ready, fingerprints are captured for maintenance checks.
//! - Start set refs are sorted deterministically by name.
//!
//! This stage performs minimal validation of metadata files: it checks for
//! presence and mmaps commit-graph and MIDX, but parsing and structural
//! validation are done by later phases.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use memmap2::Mmap;

use super::byte_arena::{ByteArena, ByteRef};
use super::bytes::BytesView;
use super::errors::RepoOpenError;
use super::limits::RepoOpenLimits;
use super::object_id::{ObjectFormat, OidBytes};
use super::repo::GitRepoPaths;
use super::start_set::StartSetId;

/// Status of required artifacts (commit-graph, MIDX).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoArtifactStatus {
    /// All required artifacts are present and can be mmapped.
    Ready,
    /// One or more artifacts are missing; repo needs maintenance.
    NeedsMaintenance {
        /// True if commit-graph is missing.
        missing_commit_graph: bool,
        /// True if multi-pack-index is missing.
        missing_midx: bool,
        /// True if a Git maintenance lock file is present.
        lock_present: bool,
    },
}

impl RepoArtifactStatus {
    /// Returns true if all artifacts are ready.
    #[inline]
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Paths to required artifact files.
#[derive(Clone, Debug)]
pub struct RepoArtifactPaths {
    /// Path to the commit-graph file.
    pub commit_graph: PathBuf,
    /// Path to the multi-pack-index file.
    pub midx: PathBuf,
}

/// Artifact bytes for required metadata files.
///
/// Only populated when `RepoArtifactStatus::Ready`.
/// Views are read-only and expected to remain valid for the duration of
/// a repo job (maintenance must not run concurrently).
#[derive(Debug, Default)]
pub struct RepoArtifactMmaps {
    /// Commit-graph bytes (mmap or in-memory).
    pub commit_graph: Option<BytesView>,
    /// Multi-pack-index bytes (mmap or in-memory).
    pub midx: Option<BytesView>,
}

/// Fingerprint of an artifact file.
///
/// This is a lightweight change detector (length + mtime), not a content hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactFingerprint {
    /// File length in bytes.
    pub len: u64,
    /// Last modification time.
    pub modified: SystemTime,
}

/// Fingerprints for commit-graph and MIDX.
///
/// Used to detect concurrent maintenance between repo open and later phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepoArtifactFingerprint {
    pub commit_graph: ArtifactFingerprint,
    pub midx: ArtifactFingerprint,
}

/// A ref in the start set with its resolved tip and optional watermark.
#[derive(Clone, Debug)]
pub struct StartSetRef {
    /// Interned ref name (e.g., `refs/heads/main`).
    pub name: ByteRef,
    /// Resolved commit OID at tip.
    pub tip: OidBytes,
    /// Last scanned tip OID for this ref (if previously scanned).
    pub watermark: Option<OidBytes>,
}

/// Complete state for a repository job after repo open.
///
/// This struct contains everything needed for later Git phases without
/// additional file opens (except pack files in pack processing phases). It
/// also records artifact fingerprints used to detect concurrent maintenance.
/// When artifacts are missing, `start_set` is empty and `mmaps` is unset.
#[derive(Debug)]
pub struct RepoJobState {
    /// Resolved repository paths.
    pub paths: GitRepoPaths,

    /// Object ID format (SHA-1 or SHA-256).
    pub object_format: ObjectFormat,

    /// Paths to artifact files.
    pub artifact_paths: RepoArtifactPaths,

    /// Artifact readiness status.
    pub artifact_status: RepoArtifactStatus,

    /// Artifact bytes (only if `artifact_status.is_ready()`).
    pub mmaps: RepoArtifactMmaps,

    /// Artifact fingerprints captured at repo open (only if artifacts were ready).
    pub artifact_fingerprint: Option<RepoArtifactFingerprint>,

    /// Arena for ref name storage.
    pub ref_names: ByteArena,

    /// Start set refs, sorted deterministically by name.
    ///
    /// Invariant: sorted by `ref_names.get(r.name)` lexicographically.
    /// Empty when `artifact_status` is `NeedsMaintenance`.
    pub start_set: Vec<StartSetRef>,
}

impl RepoJobState {
    /// Returns true if artifacts remain unchanged and no lock files are present.
    ///
    /// Returns `false` if no baseline fingerprint was captured (artifacts not ready).
    pub fn artifacts_unchanged(&self) -> Result<bool, RepoOpenError> {
        let Some(expected) = self.artifact_fingerprint else {
            return Ok(false);
        };

        if has_lock_files(&self.paths, &self.artifact_paths)? {
            return Ok(false);
        }

        let current = RepoArtifactFingerprint::from_paths(&self.artifact_paths)?;
        Ok(current == expected)
    }
}

impl RepoArtifactFingerprint {
    fn from_paths(paths: &RepoArtifactPaths) -> Result<Self, RepoOpenError> {
        Ok(Self {
            commit_graph: fingerprint_path(&paths.commit_graph)?,
            midx: fingerprint_path(&paths.midx)?,
        })
    }
}

/// Trait for resolving start set refs.
///
/// Implement this with gix plumbing to enumerate refs per your start set
/// configuration (default branch only, all remotes, branches + tags, etc).
pub trait StartSetResolver {
    /// Resolves refs in the start set.
    ///
    /// # Requirements
    ///
    /// - Ref names must be fully qualified (e.g., `refs/heads/main`)
    /// - Tips must be commit OIDs (peel tags to commits)
    /// - Order does not matter (repo open sorts deterministically)
    ///
    /// # Errors
    ///
    /// Return an error if ref resolution fails.
    fn resolve(&self, paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError>;
}

/// Trait for loading persisted ref watermarks.
///
/// Implement this with your database layer. The watermark store is keyed by
/// `(repo_id, policy_hash, start_set_id, ref_name)`.
pub trait RefWatermarkStore {
    /// Loads watermarks for the given refs.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - Repository identifier
    /// * `policy_hash` - Policy identity (rules + merge semantics)
    /// * `start_set_id` - Start set configuration identity
    /// * `ref_names` - Ref names to load watermarks for (in order)
    ///
    /// # Returns
    ///
    /// A vector of `Option<OidBytes>` aligned with `ref_names`.
    /// Length must equal `ref_names.len()`.
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError>;
}

/// Executes repo discovery and open.
///
/// # Arguments
///
/// * `repo_root` - Path to repository (worktree or bare root)
/// * `repo_id` - Repository identifier (for watermark keys)
/// * `policy_hash` - Policy identity hash
/// * `start_set_id` - Start set configuration identity
/// * `resolver` - Start set resolver implementation
/// * `watermark_store` - Watermark store implementation
/// * `limits` - Hard caps for repo open
///
/// # Returns
///
/// A `RepoJobState` ready for later Git phases.
///
/// # Errors
///
/// Returns an error if:
/// - Repository paths cannot be resolved
/// - Start set exceeds limits
/// - Watermark store returns wrong count
///
/// Note: Missing artifacts is not an error. Check `artifact_status` and
/// run maintenance if needed before proceeding to later phases. When
/// artifacts are missing, `mmaps` and `start_set` are empty; rerun
/// `repo_open` after maintenance to populate them.
pub fn repo_open(
    repo_root: &Path,
    repo_id: u64,
    policy_hash: [u8; 32],
    start_set_id: StartSetId,
    resolver: &dyn StartSetResolver,
    watermark_store: &dyn RefWatermarkStore,
    limits: RepoOpenLimits,
) -> Result<RepoJobState, RepoOpenError> {
    limits.validate();

    let paths = GitRepoPaths::resolve(repo_root, &limits)?;
    let object_format = detect_object_format(&paths, &limits)?;

    let artifact_paths = RepoArtifactPaths {
        commit_graph: paths.objects_dir.join("info").join("commit-graph"),
        midx: paths.pack_dir.join("multi-pack-index"),
    };

    let lock_present = has_lock_files(&paths, &artifact_paths)?;
    let artifact_status = check_artifact_status(&artifact_paths, lock_present);

    if !artifact_status.is_ready() {
        return Ok(RepoJobState {
            paths,
            object_format,
            artifact_paths,
            artifact_status,
            mmaps: RepoArtifactMmaps::default(),
            artifact_fingerprint: None,
            ref_names: ByteArena::with_capacity(0),
            start_set: Vec::new(),
        });
    }

    let (mmaps, artifact_fingerprint) = mmap_artifacts(&artifact_paths)?;

    let (ref_names, start_set) = resolve_start_set_with_watermarks(
        repo_id,
        policy_hash,
        start_set_id,
        &paths,
        resolver,
        watermark_store,
        &limits,
    )?;

    Ok(RepoJobState {
        paths,
        object_format,
        artifact_paths,
        artifact_status,
        mmaps,
        artifact_fingerprint: Some(artifact_fingerprint),
        ref_names,
        start_set,
    })
}

/// Checks for the presence of required artifact files.
///
/// This is a fast existence check only; file contents are not validated here.
/// Any detected maintenance lock forces `NeedsMaintenance`.
fn check_artifact_status(
    artifact_paths: &RepoArtifactPaths,
    lock_present: bool,
) -> RepoArtifactStatus {
    let missing_commit_graph = !is_file(&artifact_paths.commit_graph);
    let missing_midx = !is_file(&artifact_paths.midx);

    if missing_commit_graph || missing_midx || lock_present {
        RepoArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            lock_present,
        }
    } else {
        RepoArtifactStatus::Ready
    }
}

/// Memory-maps the artifact files for later read-only access.
///
/// Assumes `check_artifact_status` returned `Ready`. The returned fingerprint
/// is captured from the file metadata used for the mapping.
fn mmap_artifacts(
    artifact_paths: &RepoArtifactPaths,
) -> Result<(RepoArtifactMmaps, RepoArtifactFingerprint), RepoOpenError> {
    let (commit_graph, commit_graph_fp) = mmap_file(&artifact_paths.commit_graph)?;
    let (midx, midx_fp) = mmap_file(&artifact_paths.midx)?;

    Ok((
        RepoArtifactMmaps {
            commit_graph: Some(commit_graph),
            midx: Some(midx),
        },
        RepoArtifactFingerprint {
            commit_graph: commit_graph_fp,
            midx: midx_fp,
        },
    ))
}

/// Maps a file read-only and returns a byte view plus a metadata fingerprint.
fn mmap_file(path: &Path) -> Result<(BytesView, ArtifactFingerprint), RepoOpenError> {
    let file = File::open(path).map_err(RepoOpenError::io)?;
    let metadata = file.metadata().map_err(RepoOpenError::io)?;
    let fingerprint = fingerprint_metadata(&metadata)?;

    #[allow(unsafe_code)]
    unsafe {
        // SAFETY: We map the file read-only and treat it as immutable during the scan.
        // Repo maintenance is expected to be quiescent; if the file is truncated
        // or replaced while mapped, the OS may signal a fault. That risk is accepted.
        let mmap = Mmap::map(&file).map_err(RepoOpenError::io)?;
        Ok((BytesView::from_mmap(mmap), fingerprint))
    }
}

/// Resolves the start set, interns ref names, and loads watermarks.
///
/// The resolver output is sorted lexicographically by ref name to ensure a
/// deterministic order. Watermarks are fetched in that same order and then
/// paired back with their refs.
///
/// # Errors
/// Returns an error if limits are exceeded, ref names cannot be interned,
/// or the watermark store returns a mismatched count.
fn resolve_start_set_with_watermarks(
    repo_id: u64,
    policy_hash: [u8; 32],
    start_set_id: StartSetId,
    paths: &GitRepoPaths,
    resolver: &dyn StartSetResolver,
    watermark_store: &dyn RefWatermarkStore,
    limits: &RepoOpenLimits,
) -> Result<(ByteArena, Vec<StartSetRef>), RepoOpenError> {
    let mut refs = resolver.resolve(paths)?;

    if refs.len() > limits.max_refs_in_start_set as usize {
        return Err(RepoOpenError::StartSetTooLarge {
            count: refs.len(),
            max: limits.max_refs_in_start_set as usize,
        });
    }

    refs.sort_by(|(a, _), (b, _)| a.as_slice().cmp(b.as_slice()));

    let mut ref_names = ByteArena::with_capacity(limits.max_refname_arena_bytes);
    let mut interned_refs = Vec::with_capacity(refs.len());

    for (name_bytes, tip) in &refs {
        if name_bytes.len() > limits.max_refname_bytes as usize {
            return Err(RepoOpenError::RefNameTooLong {
                len: name_bytes.len(),
                max: limits.max_refname_bytes as usize,
            });
        }

        let name_ref = ref_names
            .intern(name_bytes)
            .ok_or(RepoOpenError::ArenaOverflow)?;

        interned_refs.push((name_ref, *tip));
    }

    let name_slices: Vec<&[u8]> = interned_refs
        .iter()
        .map(|(name_ref, _)| ref_names.get(*name_ref))
        .collect();

    let watermarks =
        watermark_store.load_watermarks(repo_id, policy_hash, start_set_id, &name_slices)?;

    if watermarks.len() != interned_refs.len() {
        return Err(RepoOpenError::WatermarkCountMismatch {
            got: watermarks.len(),
            expected: interned_refs.len(),
        });
    }

    let start_set: Vec<StartSetRef> = interned_refs
        .into_iter()
        .zip(watermarks)
        .map(|((name, tip), watermark)| StartSetRef {
            name,
            tip,
            watermark,
        })
        .collect();

    Ok((ref_names, start_set))
}

fn fingerprint_path(path: &Path) -> Result<ArtifactFingerprint, RepoOpenError> {
    let metadata = fs::metadata(path).map_err(RepoOpenError::io)?;
    fingerprint_metadata(&metadata)
}

fn fingerprint_metadata(metadata: &Metadata) -> Result<ArtifactFingerprint, RepoOpenError> {
    let modified = metadata.modified().map_err(RepoOpenError::io)?;
    Ok(ArtifactFingerprint {
        len: metadata.len(),
        modified,
    })
}

fn has_lock_files(
    paths: &GitRepoPaths,
    artifact_paths: &RepoArtifactPaths,
) -> Result<bool, RepoOpenError> {
    // Only artifact and pack directory locks are considered here.
    if is_file(&lock_path(&artifact_paths.commit_graph))
        || is_file(&lock_path(&artifact_paths.midx))
    {
        return Ok(true);
    }

    let mut pack_dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    pack_dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        pack_dirs.push(alternate.join("pack"));
    }

    for pack_dir in pack_dirs {
        if has_lock_files_in_dir(&pack_dir)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn has_lock_files_in_dir(pack_dir: &Path) -> Result<bool, RepoOpenError> {
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RepoOpenError::io(err)),
    };

    for entry in entries {
        let entry = entry.map_err(RepoOpenError::io)?;
        let file_type = entry.file_type().map_err(RepoOpenError::io)?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if Path::new(&file_name)
            .extension()
            .is_some_and(|ext| ext == "lock")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[inline]
fn lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

/// Detects the repository object format via config.
///
/// This is a lightweight scan, not a full Git config parser. It:
/// - Reads the first existing config path
/// - Ignores comments/blank lines
/// - Treats any line containing both "objectformat" and "sha256"
///   (case-insensitive) as a SHA-256 repo
///
/// Anything else defaults to SHA-1.
fn detect_object_format(
    paths: &GitRepoPaths,
    limits: &RepoOpenLimits,
) -> Result<ObjectFormat, RepoOpenError> {
    for config_path in paths.config_paths() {
        if !config_path.is_file() {
            continue;
        }

        let bytes = read_bounded_file(&config_path, limits.max_config_file_bytes)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RepoOpenError::InvalidUtf8Config)?;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }

            let lower = line.to_ascii_lowercase();
            if lower.contains("objectformat") && lower.contains("sha256") {
                return Ok(ObjectFormat::Sha256);
            }
        }

        return Ok(ObjectFormat::Sha1);
    }

    Ok(ObjectFormat::Sha1)
}

/// Reads a file with a maximum byte limit.
///
/// The size check is done via metadata first; the read itself is bounded via
/// `take()` to guard against concurrent file growth.
fn read_bounded_file(path: &Path, max_bytes: u32) -> Result<Vec<u8>, RepoOpenError> {
    let file = File::open(path).map_err(RepoOpenError::io)?;
    let metadata = file.metadata().map_err(RepoOpenError::io)?;

    if metadata.len() > max_bytes as u64 {
        return Err(RepoOpenError::FileTooLarge {
            size: metadata.len(),
            limit: max_bytes,
        });
    }

    let size = metadata.len() as usize;
    let mut buffer = Vec::with_capacity(size);
    let mut take = file.take(max_bytes as u64);
    take.read_to_end(&mut buffer).map_err(RepoOpenError::io)?;

    Ok(buffer)
}

#[inline]
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
