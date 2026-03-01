//! Git source driver and CLI helper types.
//!
//! Contains the `GitCliResolver`, `EmptyWatermarkStore`, and execution-mode
//! dispatcher used by the unified CLI for git scanning.
//!
//! ## Current state
//!
//! The git source delegates to [`crate::git_scan::run_git_scan()`].
//! `run_git_scan_with_execution_mode()` provides the migration seam:
//! - `direct` mode calls the direct runner;
//! - `connector` mode calls a dedicated adapter path that currently
//!   reuses the same shared-core runner for strict parity.
//!
//! Pack execution is dispatched through `scheduler::Executor` via
//! `runner_exec::execute_pack_plans_with_scheduler`. An
//! `Arc<dyn EventSink>` is threaded through to `EngineAdapter` so
//! findings are streamed as structured `ScanEvent::Finding` events
//! during pack and loose scanning.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use crate::git_scan::{
    run_git_scan, GitScanConfig, GitScanError, GitScanResult, OidBytes, RefWatermarkStore,
    RepoOpenError, SeenBlobStore, StartSetConfig, StartSetResolver,
};
use crate::unified::events::EventSink;
use crate::unified::ExecutionMode;
use crate::Engine;

/// Resolves the start set by invoking `git` in the target repository.
///
/// Supported configs: `DefaultBranchOnly` and `ExplicitRefs`. All other
/// start-set modes return an error to keep the CLI lightweight.
///
/// Requires `git` on PATH; command failures surface as `RepoOpenError::Io`.
pub struct GitCliResolver {
    repo: PathBuf,
    start_set: StartSetConfig,
}

impl GitCliResolver {
    pub fn new(repo: PathBuf, start_set: StartSetConfig) -> Self {
        Self { repo, start_set }
    }
}

impl StartSetResolver for GitCliResolver {
    fn resolve(
        &self,
        _paths: &crate::git_scan::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        match &self.start_set {
            StartSetConfig::DefaultBranchOnly => resolve_default_branch(&self.repo),
            StartSetConfig::ExplicitRefs { refs } => resolve_explicit_refs(&self.repo, refs),
            _ => Err(RepoOpenError::io(io::Error::other(
                "start set config not supported by git_scan CLI",
            ))),
        }
    }
}

/// Watermark store that always returns `None`.
///
/// Forces the runner to treat all refs as unwatermarked and scan
/// full history every run.
pub struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

/// Run the Git scanner via the selected execution mode.
///
/// `ExecutionMode::Direct` uses the current direct scanner path.
/// `ExecutionMode::Connector` uses a dedicated adapter seam that currently
/// delegates to the same shared-core runner to preserve parity while exposing
/// a distinct orchestration path.
#[allow(clippy::too_many_arguments)]
pub fn run_git_scan_with_execution_mode(
    execution_mode: ExecutionMode,
    repo_root: &std::path::Path,
    engine: std::sync::Arc<Engine>,
    resolver: &dyn StartSetResolver,
    seen_store: &dyn SeenBlobStore,
    watermark_store: &dyn RefWatermarkStore,
    persist_store: Option<&dyn crate::git_scan::PersistenceStore>,
    config: &GitScanConfig,
    event_sink: std::sync::Arc<dyn EventSink>,
) -> Result<GitScanResult, GitScanError> {
    dispatch_by_execution_mode(
        execution_mode,
        || {
            run_git_scan(
                repo_root,
                std::sync::Arc::clone(&engine),
                resolver,
                seen_store,
                watermark_store,
                persist_store,
                config,
                std::sync::Arc::clone(&event_sink),
            )
        },
        || {
            run_git_scan_via_connector_adapter(
                repo_root,
                std::sync::Arc::clone(&engine),
                resolver,
                seen_store,
                watermark_store,
                persist_store,
                config,
                std::sync::Arc::clone(&event_sink),
            )
        },
    )
}

/// Connector-mode adapter seam for Git scanning.
///
/// This adapter currently reuses `run_git_scan` so direct and connector modes
/// stay behavior-identical while migration parity gates remain strict.
#[allow(clippy::too_many_arguments)]
fn run_git_scan_via_connector_adapter(
    repo_root: &std::path::Path,
    engine: std::sync::Arc<Engine>,
    resolver: &dyn StartSetResolver,
    seen_store: &dyn SeenBlobStore,
    watermark_store: &dyn RefWatermarkStore,
    persist_store: Option<&dyn crate::git_scan::PersistenceStore>,
    config: &GitScanConfig,
    event_sink: std::sync::Arc<dyn EventSink>,
) -> Result<GitScanResult, GitScanError> {
    run_git_scan(
        repo_root,
        engine,
        resolver,
        seen_store,
        watermark_store,
        persist_store,
        config,
        event_sink,
    )
}

fn dispatch_by_execution_mode<T>(
    execution_mode: ExecutionMode,
    run_direct: impl FnOnce() -> T,
    run_connector: impl FnOnce() -> T,
) -> T {
    match execution_mode {
        ExecutionMode::Direct => run_direct(),
        ExecutionMode::Connector => run_connector(),
    }
}

/// Run `git` in `repo` and return trimmed UTF-8 stdout.
///
/// Output is lossy UTF-8 with leading and trailing whitespace removed.
/// Both stdout and stderr are captured; only stdout is used.
fn run_git(repo: &PathBuf, args: &[&str]) -> io::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("git command failed: {:?}", args)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Resolve the default-branch tip, falling back to detached `HEAD`.
///
/// Uses `symbolic-ref --quiet HEAD` to find the default branch; if that
/// fails, falls back to `HEAD`.
fn resolve_default_branch(repo: &PathBuf) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let head_ref = run_git(repo, &["symbolic-ref", "--quiet", "HEAD"]).ok();
    if let Some(ref_name) = head_ref {
        let tip_hex = run_git(repo, &["rev-parse", &ref_name]).map_err(RepoOpenError::io)?;
        let oid = oid_from_hex(&tip_hex)?;
        return Ok(vec![(ref_name.into_bytes(), oid)]);
    }

    // Detached HEAD fallback.
    let tip_hex = run_git(repo, &["rev-parse", "HEAD"]).map_err(RepoOpenError::io)?;
    let oid = oid_from_hex(&tip_hex)?;
    Ok(vec![(b"HEAD".to_vec(), oid)])
}

/// Resolve the tip OIDs for explicitly provided ref names.
///
/// Each ref is passed to `git rev-parse`; missing refs surface as errors.
fn resolve_explicit_refs(
    repo: &PathBuf,
    refs: &[Vec<u8>],
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        let name = String::from_utf8_lossy(r);
        let tip_hex = run_git(repo, &["rev-parse", name.as_ref()]).map_err(RepoOpenError::io)?;
        let oid = oid_from_hex(&tip_hex)?;
        out.push((r.clone(), oid));
    }
    Ok(out)
}

/// Decode a hex-encoded OID into raw bytes.
///
/// The input must have an even number of hex digits.
fn oid_from_hex(hex: &str) -> Result<OidBytes, RepoOpenError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(RepoOpenError::io(io::Error::other(
            "invalid OID hex length",
        )));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| RepoOpenError::io(io::Error::other("invalid OID hex")))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| RepoOpenError::io(io::Error::other("invalid OID hex")))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(OidBytes::from_slice(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_mode_dispatch_prefers_direct_runner() {
        let selected =
            dispatch_by_execution_mode(ExecutionMode::Direct, || "direct", || "connector");
        assert_eq!(selected, "direct");
    }

    #[test]
    fn execution_mode_dispatch_prefers_connector_runner() {
        let selected =
            dispatch_by_execution_mode(ExecutionMode::Connector, || "direct", || "connector");
        assert_eq!(selected, "connector");
    }
}
