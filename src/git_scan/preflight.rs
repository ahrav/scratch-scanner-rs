//! Maintenance preflight for Git repository scanning.
//!
//! Performs a deterministic readiness check without reading blobs:
//! - Resolve repository paths
//! - Verify commit-graph and MIDX presence
//! - Enforce pack count limits
//!
//! # Invariants
//! - No blob reads (metadata only).
//! - File reads are bounded by explicit limits.
//! - Outputs are deterministic for identical repo state.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::preflight_error::PreflightError;
use super::preflight_limits::PreflightLimits;
use super::repo::GitRepoPaths;

/// Paths to required artifact files.
///
/// These are derived from the resolved repository layout and do not imply
/// existence; `ArtifactStatus` reports whether they are present.
#[derive(Clone, Debug)]
pub struct ArtifactPaths {
    /// Path to the commit-graph file.
    pub commit_graph: PathBuf,
    /// Path to the multi-pack-index file.
    pub midx: PathBuf,
    /// Path to the pack directory.
    pub pack_dir: PathBuf,
}

/// Status of required artifacts (commit-graph, MIDX, pack count).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactStatus {
    /// All required artifacts are present and pack count is within limits.
    Ready { pack_count: u32 },
    /// One or more artifacts are missing or pack count exceeded.
    NeedsMaintenance {
        /// `true` if `info/commit-graph` is missing.
        missing_commit_graph: bool,
        /// `true` if `multi-pack-index` is missing.
        missing_midx: bool,
        /// Total number of `*.pack` files observed.
        ///
        /// This count is capped at `max_pack_count + 1` to allow early exit
        /// when the limit is exceeded.
        pack_count: u32,
        /// Pack count limit that was checked.
        max_pack_count: u16,
    },
}

impl ArtifactStatus {
    /// Returns true if all artifacts are ready.
    #[inline]
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Result of the preflight check.
///
/// The report is fully derived from repository metadata; no blob objects are
/// read during preflight.
#[derive(Debug)]
pub struct PreflightReport {
    /// Resolved repository paths.
    pub repo: GitRepoPaths,
    /// Artifact paths derived from repository layout.
    pub artifact_paths: ArtifactPaths,
    /// Artifact readiness status.
    pub status: ArtifactStatus,
}

/// Executes the maintenance preflight.
///
/// # Arguments
/// * `repo_root` - Path to repository (worktree or bare root)
/// * `limits` - Hard caps for preflight
///
/// # Returns
/// A `PreflightReport` containing artifact paths and readiness status.
///
/// # Errors
/// Returns `PreflightError` for repository discovery failures, malformed
/// metadata files, size limit violations, or I/O failures.
pub fn preflight(
    repo_root: &Path,
    limits: PreflightLimits,
) -> Result<PreflightReport, PreflightError> {
    limits.validate();

    let repo = GitRepoPaths::resolve(repo_root, &limits)?;

    let artifact_paths = ArtifactPaths {
        commit_graph: repo.objects_dir.join("info").join("commit-graph"),
        midx: repo.pack_dir.join("multi-pack-index"),
        pack_dir: repo.pack_dir.clone(),
    };

    let missing_commit_graph = !is_file(&artifact_paths.commit_graph);
    let missing_midx = !is_file(&artifact_paths.midx);
    let pack_count = count_pack_files(&repo, limits.max_pack_count)?;
    let pack_limit_exceeded = pack_count > limits.max_pack_count as u32;

    let status = if missing_commit_graph || missing_midx || pack_limit_exceeded {
        ArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            pack_count,
            max_pack_count: limits.max_pack_count,
        }
    } else {
        ArtifactStatus::Ready { pack_count }
    };

    Ok(PreflightReport {
        repo,
        artifact_paths,
        status,
    })
}

/// Counts pack files across the repository and alternates.
///
/// The returned count is capped at `max_pack_count + 1` to allow callers to
/// detect limit violations without scanning every directory.
fn count_pack_files(repo: &GitRepoPaths, max_pack_count: u16) -> Result<u32, PreflightError> {
    let cap = max_pack_count as u32 + 1;
    let mut total = 0_u32;

    let mut pack_dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    pack_dirs.push(repo.pack_dir.clone());
    for alternate in &repo.alternate_object_dirs {
        if alternate == &repo.objects_dir {
            continue;
        }
        pack_dirs.push(alternate.join("pack"));
    }

    for pack_dir in pack_dirs {
        if total >= cap {
            break;
        }
        let remaining = cap - total;
        total += count_pack_files_in_dir(&pack_dir, remaining)?;
    }

    Ok(total)
}

/// Counts pack files in a single `objects/pack` directory.
///
/// Only `*.pack` files are counted; `.idx` and other entries are ignored.
/// The count stops once `limit` is reached.
fn count_pack_files_in_dir(pack_dir: &Path, limit: u32) -> Result<u32, PreflightError> {
    if limit == 0 {
        return Ok(0);
    }

    let mut count = 0_u32;
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(PreflightError::io(err)),
    };

    for entry in entries {
        let entry = entry.map_err(PreflightError::io)?;
        let file_type = entry.file_type().map_err(PreflightError::io)?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if is_pack_file(&file_name) {
            count += 1;
            if count >= limit {
                break;
            }
        }
    }

    Ok(count)
}

/// Returns true if the filename ends with `.pack`.
fn is_pack_file(name: &OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

/// Checks if a path is a file (follows symlinks).
#[inline]
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
