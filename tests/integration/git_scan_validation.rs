//! Integration tests covering Git scan validation matrix scenarios.
//!
//! These tests exercise combinations of packed vs loose objects, watermark
//! presence, and missing objects. They rely on the `git` CLI to create repos,
//! generate commit-graph/MIDX artifacts, and mutate the object store.

use std::fs;
use std::path::Path;
use std::process::Command;

use regex::bytes::Regex;
use tempfile::TempDir;

use scanner_rs::git_scan::{
    run_git_scan, CandidateSkipReason, FinalizeOutcome, GitScanConfig, GitScanError, GitScanMode,
    GitScanResult, InMemoryPersistenceStore, MappingCandidateKind, NeverSeenStore, OidBytes,
    RefWatermarkStore, RepoOpenError, SpillError, StartSetConfig, StartSetResolver,
};
use scanner_rs::{demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId};
use scanner_rs::{TransformMode, ValidatorKind};

/// Returns true when the `git` CLI is available on the host.
fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// Runs a git command inside `repo` and asserts success.
fn run_git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git command failed: {args:?}");
}

/// Runs a git command and returns UTF-8 stdout, asserting success.
fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(out.status.success(), "git command failed: {args:?}");
    String::from_utf8(out.stdout).expect("git output not utf8")
}

/// Decode a hex string into bytes (expects even length and valid hex digits).
fn decode_hex(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

/// Parse a Git object ID from hex output.
fn oid_from_hex(hex: &str) -> OidBytes {
    let bytes = decode_hex(hex.trim());
    OidBytes::from_slice(&bytes)
}

/// Initialize a new repo with a deterministic user identity.
fn init_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);
    tmp
}

/// Write a file and commit it to the repo.
fn commit_file(repo: &Path, name: &str, contents: &str, msg: &str) {
    let path = repo.join(name);
    fs::write(&path, contents).unwrap();
    run_git(repo, &["add", name]);
    run_git(repo, &["commit", "-m", msg]);
}

/// Ensure commit-graph and multi-pack-index artifacts exist.
fn ensure_artifacts(repo: &Path) {
    run_git(repo, &["gc"]);
    run_git(repo, &["multi-pack-index", "write"]);
    run_git(repo, &["commit-graph", "write", "--reachable"]);
}

/// Update the commit-graph after new commits without repacking objects.
fn update_commit_graph(repo: &Path) {
    run_git(repo, &["commit-graph", "write", "--reachable"]);
}

/// Build a tiny engine that detects TOK_ secrets (and Base64 variants).
fn test_engine() -> Engine {
    let rule = RuleSpec {
        name: "tok",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        local_context: None,
        secret_group: Some(1),
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

/// Start set resolver pinned to the current `main` tip.
struct TestResolver {
    tip: OidBytes,
}

impl StartSetResolver for TestResolver {
    fn resolve(
        &self,
        _paths: &scanner_rs::git_scan::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(vec![(b"refs/heads/main".to_vec(), self.tip)])
    }
}

/// Watermark store that returns a fixed optional watermark for all refs.
struct TestWatermarkStore {
    watermark: Option<OidBytes>,
}

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(ref_names.iter().map(|_| self.watermark).collect())
    }
}

/// Run a Git scan for the repo with an optional watermark.
///
/// The config pins `repo_id`, `policy_hash`, and `start_set` to keep the
/// test inputs deterministic. Persistence is routed to an in-memory store.
fn run_scan(repo: &Path, watermark: Option<OidBytes>) -> GitScanResult {
    run_scan_with_config(repo, watermark, base_config()).unwrap()
}

fn base_config() -> GitScanConfig {
    GitScanConfig {
        repo_id: 42,
        policy_hash: [0x11; 32],
        start_set: StartSetConfig::DefaultBranchOnly,
        ..Default::default()
    }
}

fn run_scan_with_config(
    repo: &Path,
    watermark: Option<OidBytes>,
    config: GitScanConfig,
) -> Result<GitScanResult, GitScanError> {
    let engine = test_engine();
    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark };
    let persist_store = InMemoryPersistenceStore::default();

    run_git_scan(
        repo,
        &engine,
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
    )
}

#[test]
fn loose_only_candidate_scans_complete() {
    if !git_available() {
        eprintln!("git not available; skipping git scan validation test");
        return;
    }

    let tmp = init_repo();
    commit_file(tmp.path(), "base.txt", "base\n", "base");
    ensure_artifacts(tmp.path());
    // Commit after artifacts so the new blob remains loose.
    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");
    update_commit_graph(tmp.path());

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    let result = run_scan(tmp.path(), Some(watermark));

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    assert!(report.finalize.stats.total_findings >= 1);
}

#[test]
fn odb_blob_respects_packed_candidate_cap() {
    if !git_available() {
        eprintln!("git not available; skipping packed candidate cap test");
        return;
    }

    let tmp = init_repo();
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP", "c2");
    ensure_artifacts(tmp.path());

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.mapping.max_packed_candidates = 1;

    let err = run_scan_with_config(tmp.path(), None, config)
        .expect_err("expected packed candidate cap error");
    match err {
        GitScanError::Spill(SpillError::MappingCandidateLimitExceeded {
            kind,
            max,
            observed,
        }) => {
            assert_eq!(kind, MappingCandidateKind::Packed);
            assert_eq!(max, 1);
            assert!(observed >= 2);
        }
        other => panic!("expected mapping cap error, got {other:?}"),
    }
}

#[test]
fn packed_and_loose_candidates_scan_complete() {
    if !git_available() {
        eprintln!("git not available; skipping git scan validation test");
        return;
    }

    let tmp = init_repo();
    commit_file(tmp.path(), "base.txt", "TOK_BASE1234\n", "base");
    ensure_artifacts(tmp.path());
    // Base blob is packed; secret blob remains loose.
    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");
    update_commit_graph(tmp.path());

    let result = run_scan(tmp.path(), None);

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    assert!(report.finalize.stats.total_findings >= 2);
}

#[test]
fn missing_loose_object_yields_partial() {
    if !git_available() {
        eprintln!("git not available; skipping git scan validation test");
        return;
    }

    let tmp = init_repo();
    commit_file(tmp.path(), "base.txt", "base\n", "base");
    ensure_artifacts(tmp.path());

    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");
    update_commit_graph(tmp.path());
    let blob_hex = git_output(tmp.path(), &["rev-parse", "HEAD:secret.txt"]);
    let blob_oid = oid_from_hex(&blob_hex);

    let hex = blob_hex.trim();
    let (dir, file) = hex.split_at(2);
    let obj_path = tmp.path().join(".git/objects").join(dir).join(file);
    // Delete the loose object to force a missing-blob partial outcome.
    fs::remove_file(obj_path).unwrap();

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    let result = run_scan(tmp.path(), Some(watermark));

    let GitScanResult(report) = result;
    assert!(matches!(
        report.finalize.outcome,
        FinalizeOutcome::Partial { .. }
    ));
    assert!(report
        .skipped_candidates
        .iter()
        .any(|skip| { skip.oid == blob_oid && skip.reason == CandidateSkipReason::LooseMissing }));
}
