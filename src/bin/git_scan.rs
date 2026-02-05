//! Git scanning CLI entrypoint.
//!
//! Minimal wrapper around the git_scan runner with demo rules.
//! Intended for local smoke tests and debugging, not production usage.
//! The start-set resolver shells out to `git` and only supports default-branch
//! or explicit-ref modes. Watermarks are disabled, so each run scans full
//! history for the selected refs.

use std::env;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use scanner_rs::git_scan::policy_hash;
use scanner_rs::git_scan::InMemoryPersistenceStore;
use scanner_rs::git_scan::OidBytes;
use scanner_rs::git_scan::{
    run_git_scan, GitScanConfig, GitScanResult, MergeDiffMode, NeverSeenStore, RefWatermarkStore,
    RepoOpenError, StartSetConfig, StartSetResolver,
};
use scanner_rs::{demo_rules, demo_transforms, demo_tuning, AnchorMode, AnchorPolicy, Engine};

/// Resolves the start set by invoking `git` in the target repository.
///
/// Supported configs: `DefaultBranchOnly` and `ExplicitRefs`. All other
/// start-set modes return an error to keep the CLI lightweight.
struct GitCliResolver {
    repo: PathBuf,
    start_set: StartSetConfig,
}

impl StartSetResolver for GitCliResolver {
    fn resolve(
        &self,
        _paths: &scanner_rs::git_scan::GitRepoPaths,
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
/// This forces the runner to treat all refs as unwatermarked and scan
/// full history every run.
struct EmptyWatermarkStore;

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

/// Print usage and flag summary to stderr.
fn print_usage(exe: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} [OPTIONS] <repo>

OPTIONS:
    --repo-id=<N>           Repository id (default: 1)
    --merge=all|first-parent  Merge diff mode (default: all)
    --anchors=manual|derived  Anchor mode (default: manual)
    --max-transform-depth=<N> Maximum decode depth (default: demo tuning)
    --debug                 Emit stage statistics to stderr
    --help, -h              Show this help message",
        exe.to_string_lossy()
    );
}

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "git_scan".into());

    let mut repo: Option<PathBuf> = None;
    let mut repo_id: u64 = 1;
    let mut merge_mode = MergeDiffMode::AllParents;
    let mut anchor_mode = AnchorMode::Manual;
    let mut max_transform_depth: Option<usize> = None;
    let mut debug = false;

    for arg in args {
        if let Some(flag) = arg.to_str() {
            if let Some(value) = flag.strip_prefix("--repo-id=") {
                repo_id = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --repo-id value: {}", value);
                    std::process::exit(2);
                });
                continue;
            }
            if let Some(value) = flag.strip_prefix("--merge=") {
                merge_mode = match value {
                    "all" => MergeDiffMode::AllParents,
                    "first-parent" => MergeDiffMode::FirstParentOnly,
                    _ => {
                        eprintln!("invalid --merge value: {}", value);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(value) = flag.strip_prefix("--max-transform-depth=") {
                max_transform_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-transform-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            match flag {
                "--anchors=manual" => {
                    anchor_mode = AnchorMode::Manual;
                    continue;
                }
                "--anchors=derived" | "--derive-anchors" => {
                    anchor_mode = AnchorMode::Derived;
                    continue;
                }
                "--debug" => {
                    debug = true;
                    continue;
                }
                "--help" | "-h" => {
                    print_usage(&exe);
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    print_usage(&exe);
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        if repo.is_some() {
            print_usage(&exe);
            std::process::exit(2);
        }
        repo = Some(PathBuf::from(arg));
    }

    let Some(repo) = repo else {
        print_usage(&exe);
        std::process::exit(2);
    };

    let rules = demo_rules();
    let transforms = demo_transforms();
    let mut tuning = demo_tuning();
    if let Some(depth) = max_transform_depth {
        tuning.max_transform_depth = depth;
    }

    let base_config = GitScanConfig::default();

    let policy = policy_hash(
        &rules,
        &transforms,
        &tuning,
        merge_mode,
        base_config.path_policy_version,
    );

    let engine = match anchor_mode {
        AnchorMode::Manual => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::ManualOnly)
        }
        AnchorMode::Derived => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::DerivedOnly)
        }
    };

    let start_set = StartSetConfig::DefaultBranchOnly;
    let resolver = GitCliResolver {
        repo: repo.clone(),
        start_set: start_set.clone(),
    };
    let seen_store = NeverSeenStore;
    let watermark_store = EmptyWatermarkStore;
    let persist_store = InMemoryPersistenceStore::default();

    let config = GitScanConfig {
        repo_id,
        merge_diff_mode: merge_mode,
        start_set: start_set.clone(),
        policy_hash: policy,
        ..base_config
    };

    match run_git_scan(
        &repo,
        &engine,
        &resolver,
        &seen_store,
        &watermark_store,
        Some(&persist_store),
        &config,
    ) {
        Ok(GitScanResult::NeedsMaintenance { preflight }) => {
            eprintln!("needs_maintenance status={:?}", preflight.status);
            std::process::exit(3);
        }
        Ok(GitScanResult::Completed(report)) => {
            let (status, skipped) = match report.finalize.outcome {
                scanner_rs::git_scan::FinalizeOutcome::Complete => ("complete", 0),
                scanner_rs::git_scan::FinalizeOutcome::Partial { skipped_count } => {
                    ("partial", skipped_count)
                }
            };
            println!(
                "status={} findings={} blobs={} data_ops={} watermarks={} skipped={}",
                status,
                report.finalize.stats.total_findings,
                report.finalize.stats.unique_blobs,
                report.finalize.stats.data_ops_count,
                report.finalize.stats.watermark_ops_count,
                skipped
            );
            if debug {
                eprintln!("commits={}", report.commit_count);
                eprintln!("tree_diff_stats={:?}", report.tree_diff_stats);
                eprintln!("spill_stats={:?}", report.spill_stats);
                eprintln!("mapping_stats={:?}", report.mapping_stats);
                eprintln!("pack_plan_stats={:?}", report.pack_plan_stats);
                eprintln!("pack_exec_reports={:?}", report.pack_exec_reports);
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("git_scan failed: {err}");
            std::process::exit(2);
        }
    }
}

/// Run `git` in `repo` and return trimmed UTF-8 stdout.
///
/// # Errors
/// Returns an I/O error if the command fails or exits non-zero.
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
