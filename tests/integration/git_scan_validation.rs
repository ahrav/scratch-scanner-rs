//! Integration tests covering Git scan validation matrix scenarios.

use std::fs;
use std::path::Path;
use std::process::Command;

use regex::bytes::Regex;
use tempfile::TempDir;

use scanner_rs::git_scan::{
    run_git_scan, CandidateSkipReason, FinalizeOutcome, GitScanConfig, GitScanResult,
    InMemoryPersistenceStore, NeverSeenStore, OidBytes, RefWatermarkStore, RepoOpenError,
    StartSetConfig, StartSetResolver,
};
use scanner_rs::{demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId};
use scanner_rs::{TransformMode, ValidatorKind};

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn run_git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git command failed: {args:?}");
}

fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(out.status.success(), "git command failed: {args:?}");
    String::from_utf8(out.stdout).expect("git output not utf8")
}

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

fn oid_from_hex(hex: &str) -> OidBytes {
    let bytes = decode_hex(hex.trim());
    OidBytes::from_slice(&bytes)
}

fn init_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);
    tmp
}

fn commit_file(repo: &Path, name: &str, contents: &str, msg: &str) {
    let path = repo.join(name);
    fs::write(&path, contents).unwrap();
    run_git(repo, &["add", name]);
    run_git(repo, &["commit", "-m", msg]);
}

fn ensure_artifacts(repo: &Path) {
    run_git(repo, &["gc"]);
    run_git(repo, &["multi-pack-index", "write"]);
    run_git(repo, &["commit-graph", "write", "--reachable"]);
}

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

fn run_scan(repo: &Path, watermark: Option<OidBytes>) -> GitScanResult {
    let engine = test_engine();
    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark };
    let persist_store = InMemoryPersistenceStore::default();
    let mut config = GitScanConfig::default();
    config.repo_id = 42;
    config.policy_hash = [0x11; 32];
    config.start_set = StartSetConfig::DefaultBranchOnly;

    run_git_scan(
        repo,
        &engine,
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
    )
    .unwrap()
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

    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    let result = run_scan(tmp.path(), Some(watermark));

    match result {
        GitScanResult::Completed(report) => {
            assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
            assert!(report.skipped_candidates.is_empty());
            assert!(report.finalize.stats.total_findings >= 1);
        }
        GitScanResult::NeedsMaintenance { .. } => panic!("expected completed scan"),
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
    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");

    let result = run_scan(tmp.path(), None);

    match result {
        GitScanResult::Completed(report) => {
            assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
            assert!(report.skipped_candidates.is_empty());
            assert!(report.finalize.stats.total_findings >= 2);
        }
        GitScanResult::NeedsMaintenance { .. } => panic!("expected completed scan"),
    }
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
    let blob_hex = git_output(tmp.path(), &["rev-parse", "HEAD:secret.txt"]);
    let blob_oid = oid_from_hex(&blob_hex);

    let hex = blob_hex.trim();
    let (dir, file) = hex.split_at(2);
    let obj_path = tmp.path().join(".git/objects").join(dir).join(file);
    fs::remove_file(obj_path).unwrap();

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    let result = run_scan(tmp.path(), Some(watermark));

    match result {
        GitScanResult::Completed(report) => {
            assert!(matches!(
                report.finalize.outcome,
                FinalizeOutcome::Partial { .. }
            ));
            assert!(report.skipped_candidates.iter().any(|skip| {
                skip.oid == blob_oid && skip.reason == CandidateSkipReason::LooseMissing
            }));
        }
        GitScanResult::NeedsMaintenance { .. } => panic!("expected completed scan"),
    }
}
