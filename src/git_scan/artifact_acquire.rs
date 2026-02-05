//! Artifact construction for Git scanning.
//!
//! This module builds in-memory MIDX and commit-graph artifacts from pack
//! index files and commit data. It does not attempt to reuse on-disk artifacts;
//! disk-backed paths are handled by `repo_open`.
//!
//! # Construction Flow
//!
//! 1. `acquire_midx()`: Builds MIDX from `.idx` files via k-way merge
//! 2. `acquire_commit_graph()`: Loads commits and builds `CommitGraphMem`
//!
//! # Memory Limits
//!
//! The `ArtifactBuildLimits` struct provides hard caps on artifact
//! construction to prevent runaway memory usage on large repositories.
//!
//! # Consistency
//! When artifacts are built, `RepoJobState` is mutated to store the new bytes
//! and to set fingerprints to the `PackSet` variant. Callers should re-check
//! `artifacts_unchanged` before starting any pack scans.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::bytes::BytesView;
use super::commit_graph_mem::CommitGraphMem;
use super::commit_loader::{
    collect_pack_dirs, load_commits_from_tips, resolve_pack_paths_from_midx, CommitLoadError,
    CommitLoadLimits,
};
use super::errors::{CommitPlanError, RepoOpenError};
use super::midx::MidxView;
use super::midx_build::{build_midx_bytes, MidxBuildError, MidxBuildLimits};
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::repo_open::{RepoArtifactFingerprint, RepoJobState};

/// Limits for in-memory artifact construction.
///
/// These limits are enforced only when building artifacts in memory; they do
/// not apply to disk-backed artifact access in `repo_open`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactBuildLimits {
    /// MIDX build limits.
    pub midx: MidxBuildLimits,
    /// Commit loading limits.
    pub commit_load: CommitLoadLimits,
}

/// Errors from artifact acquisition.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactAcquireError {
    /// I/O error during artifact access.
    Io(io::Error),
    /// MIDX build failed.
    MidxBuild(MidxBuildError),
    /// MIDX parsing failed.
    MidxParse(MidxError),
    /// Commit loading failed during in-memory graph build.
    CommitLoad(CommitLoadError),
    /// In-memory commit graph construction failed.
    CommitGraphBuild(CommitPlanError),
    /// Repo open error (e.g., fingerprint computation).
    RepoOpen(RepoOpenError),
    /// Concurrent maintenance detected.
    ConcurrentMaintenance,
}

impl fmt::Display for ArtifactAcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "artifact I/O error: {err}"),
            Self::MidxBuild(err) => write!(f, "MIDX build failed: {err}"),
            Self::MidxParse(err) => write!(f, "MIDX parse failed: {err}"),
            Self::CommitLoad(err) => write!(f, "commit loading failed: {err}"),
            Self::CommitGraphBuild(err) => write!(f, "commit graph build failed: {err}"),
            Self::RepoOpen(err) => write!(f, "repo open error: {err}"),
            Self::ConcurrentMaintenance => write!(f, "concurrent maintenance detected"),
        }
    }
}

impl std::error::Error for ArtifactAcquireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::MidxBuild(err) => Some(err),
            Self::MidxParse(err) => Some(err),
            Self::CommitLoad(err) => Some(err),
            Self::CommitGraphBuild(err) => Some(err),
            Self::RepoOpen(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ArtifactAcquireError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<MidxBuildError> for ArtifactAcquireError {
    fn from(err: MidxBuildError) -> Self {
        Self::MidxBuild(err)
    }
}

impl From<MidxError> for ArtifactAcquireError {
    fn from(err: MidxError) -> Self {
        Self::MidxParse(err)
    }
}

impl From<CommitLoadError> for ArtifactAcquireError {
    fn from(err: CommitLoadError) -> Self {
        Self::CommitLoad(err)
    }
}

impl From<RepoOpenError> for ArtifactAcquireError {
    fn from(err: RepoOpenError) -> Self {
        Self::RepoOpen(err)
    }
}

/// Output of MIDX acquisition, carrying the MIDX bytes and resolved
/// pack file paths needed for subsequent pack planning and execution.
pub struct MidxAcquireResult {
    /// The acquired MIDX bytes (either mmapped or built in-memory).
    pub bytes: BytesView,
    /// Whether the MIDX was built in-memory (vs. loaded from disk).
    pub built_in_memory: bool,
    /// Pack file paths in MIDX order.
    ///
    /// These paths align with `pack_id` values in the MIDX.
    pub pack_paths: Vec<PathBuf>,
}

/// Acquires MIDX data by building it in memory.
///
/// # Arguments
/// * `repo` - Repository state from `repo_open`
/// * `limits` - Build limits for artifact construction
///
/// # Returns
/// A `MidxAcquireResult` containing the MIDX bytes and metadata.
///
/// # Behavior
/// Builds the MIDX from `.idx` files via k-way merge; existing on-disk MIDX
/// files are not consulted.
///
/// # Side Effects
/// This function updates `repo.mmaps.midx` with the built bytes and sets
/// the fingerprint to `PackSet` variant.
pub fn acquire_midx(
    repo: &mut RepoJobState,
    limits: &ArtifactBuildLimits,
) -> Result<MidxAcquireResult, ArtifactAcquireError> {
    let midx_bytes = build_midx_bytes(&repo.paths, repo.object_format, &limits.midx)?;
    MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;
    let pack_paths = resolve_pack_paths(repo, &midx_bytes)?;

    let packset_fingerprint = RepoArtifactFingerprint::from_pack_dirs(&repo.paths)?;
    repo.artifact_fingerprint = Some(packset_fingerprint);

    repo.mmaps.midx = Some(midx_bytes.clone());

    Ok(MidxAcquireResult {
        bytes: midx_bytes,
        built_in_memory: true,
        pack_paths,
    })
}

/// Builds the commit-graph from commit data.
///
/// # Arguments
/// * `repo` - Repository state from `repo_open`
/// * `midx` - Parsed MIDX view (needed for commit loading)
/// * `pack_paths` - Pack file paths in MIDX order
/// * `limits` - Build limits for artifact construction
///
/// # Returns
/// A `CommitGraphMem` that can be used for commit traversal.
///
/// # Behavior
/// Loads commits via BFS from the start set tips and builds `CommitGraphMem`.
/// The graph contains only commits reachable from `repo.start_set` tips.
/// Parents outside that set are treated as external roots.
///
/// Bounded by `limits.commit_load`.
pub fn acquire_commit_graph(
    repo: &RepoJobState,
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    limits: &ArtifactBuildLimits,
) -> Result<CommitGraphMem, ArtifactAcquireError> {
    let tips: Vec<OidBytes> = repo.start_set.iter().map(|r| r.tip).collect();

    if tips.is_empty() {
        // No tips to traverse; return empty graph
        return CommitGraphMem::build(vec![], repo.object_format)
            .map_err(ArtifactAcquireError::CommitGraphBuild);
    }

    let commits = load_commits_from_tips(
        &tips,
        midx,
        pack_paths,
        repo.object_format,
        &limits.commit_load,
        None, // No progress callback for now
    )?;

    CommitGraphMem::build(commits, repo.object_format)
        .map_err(ArtifactAcquireError::CommitGraphBuild)
}

/// Resolves pack paths from MIDX data.
fn resolve_pack_paths(
    repo: &RepoJobState,
    midx_bytes: &BytesView,
) -> Result<Vec<PathBuf>, ArtifactAcquireError> {
    let midx = MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;
    let pack_dirs = collect_pack_dirs(&repo.paths);
    resolve_pack_paths_from_midx(&midx, &pack_dirs).map_err(ArtifactAcquireError::CommitLoad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::commit_walk::CommitGraph;

    #[test]
    fn artifact_build_limits_default() {
        let limits = ArtifactBuildLimits::default();
        assert!(limits.midx.max_packs > 0);
        assert!(limits.commit_load.max_commits > 0);
    }

    #[test]
    fn commit_graph_mem_builds_empty() {
        let mem =
            CommitGraphMem::build(vec![], super::super::object_id::ObjectFormat::Sha1).unwrap();
        assert_eq!(mem.num_commits(), 0);
    }
}
