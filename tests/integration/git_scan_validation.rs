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
    run_git_scan, FinalizeOutcome, GitScanConfig, GitScanError, GitScanMode, GitScanReport,
    GitScanResult, InMemoryPersistenceStore, MappingCandidateKind, NeverSeenStore, OidBytes,
    RefWatermarkStore, RepoOpenError, SpillError, StartSetConfig, StartSetResolver, WriteOp,
};
use scanner_rs::unified::events::NullEventSink;
use scanner_rs::{demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId};
use scanner_rs::{TransformMode, ValidatorKind};

const NS_BLOB_CTX: [u8; 3] = *b"bc\0";
const NS_FINDING: [u8; 3] = *b"fn\0";
const NS_SEEN_BLOB: [u8; 3] = *b"sb\0";

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

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

/// Ensure all objects are packed and indexed.
fn ensure_artifacts(repo: &Path) {
    run_git(repo, &["gc"]);
}

/// Repack after new commits so in-memory artifact builders can find them.
fn repack_all(repo: &Path) {
    run_git(repo, &["repack", "-ad"]);
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
        std::sync::Arc::new(engine),
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
        std::sync::Arc::new(NullEventSink),
    )
}

fn assert_write_ops_equal(left: &[WriteOp], right: &[WriteOp]) {
    assert_eq!(left.len(), right.len(), "write op length mismatch");
    for (idx, (lhs, rhs)) in left.iter().zip(right.iter()).enumerate() {
        assert_eq!(lhs.key, rhs.key, "write op key mismatch at index {idx}");
        assert_eq!(
            lhs.value, rhs.value,
            "write op value mismatch at index {idx}"
        );
    }
}

fn assert_scan_outputs_equal(left: &GitScanReport, right: &GitScanReport) {
    assert_eq!(left.skipped_candidates, right.skipped_candidates);
    assert_eq!(left.finalize.outcome, right.finalize.outcome);
    assert_eq!(
        left.finalize.stats.unique_blobs,
        right.finalize.stats.unique_blobs
    );
    assert_eq!(
        left.finalize.stats.total_findings,
        right.finalize.stats.total_findings
    );
    assert_eq!(
        left.finalize.stats.findings_deduped,
        right.finalize.stats.findings_deduped
    );
    assert_write_ops_equal(&left.finalize.data_ops, &right.finalize.data_ops);
    assert_write_ops_equal(&left.finalize.watermark_ops, &right.finalize.watermark_ops);
}

fn select_ops_with_ns(ops: &[WriteOp], ns: &[u8; 3]) -> Vec<WriteOp> {
    ops.iter()
        .filter(|op| op.key.starts_with(ns))
        .cloned()
        .collect()
}

fn assert_odb_parallel_contract(left: &GitScanReport, right: &GitScanReport) {
    assert_eq!(left.skipped_candidates, right.skipped_candidates);
    assert_eq!(left.finalize.outcome, right.finalize.outcome);
    assert_eq!(
        left.finalize.stats.unique_blobs,
        right.finalize.stats.unique_blobs
    );
    assert_eq!(
        left.finalize.stats.total_findings,
        right.finalize.stats.total_findings
    );
    assert_eq!(
        left.finalize.stats.findings_deduped,
        right.finalize.stats.findings_deduped
    );

    let left_blob_ctx = select_ops_with_ns(&left.finalize.data_ops, &NS_BLOB_CTX);
    let right_blob_ctx = select_ops_with_ns(&right.finalize.data_ops, &NS_BLOB_CTX);
    assert_eq!(
        left_blob_ctx.len(),
        right_blob_ctx.len(),
        "blob_ctx cardinality mismatch"
    );
    for (idx, (lhs, rhs)) in left_blob_ctx.iter().zip(right_blob_ctx.iter()).enumerate() {
        assert_eq!(lhs.key, rhs.key, "blob_ctx key mismatch at index {idx}");
    }

    let left_findings = select_ops_with_ns(&left.finalize.data_ops, &NS_FINDING);
    let right_findings = select_ops_with_ns(&right.finalize.data_ops, &NS_FINDING);
    assert_write_ops_equal(&left_findings, &right_findings);

    let left_seen = select_ops_with_ns(&left.finalize.data_ops, &NS_SEEN_BLOB);
    let right_seen = select_ops_with_ns(&right.finalize.data_ops, &NS_SEEN_BLOB);
    assert_write_ops_equal(&left_seen, &right_seen);

    assert_write_ops_equal(&left.finalize.watermark_ops, &right.finalize.watermark_ops);
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
    repack_all(tmp.path());

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    let result = run_scan(tmp.path(), Some(watermark));

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    if perf_stats_enabled() {
        assert!(report.finalize.stats.total_findings >= 1);
    } else {
        assert_eq!(report.finalize.stats.total_findings, 0);
    }
}

#[test]
fn odb_blob_parallel_intro_handles_empty_midx_without_panic() {
    if !git_available() {
        eprintln!("git not available; skipping empty-midx parallel intro test");
        return;
    }

    let tmp = init_repo();
    // Keep all objects loose (no gc/repack), with >1 commits so parallel intro
    // is selected when blob_intro_workers > 1.
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH\n", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP\n", "c2");

    let pack_dir = tmp.path().join(".git").join("objects").join("pack");
    let has_pack = fs::read_dir(&pack_dir)
        .expect("pack directory should exist")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".pack"));
    assert!(
        !has_pack,
        "fixture requires no pack files so MIDX object_count is zero"
    );

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.blob_intro_workers = 4;

    let GitScanResult(report) = run_scan_with_config(tmp.path(), None, config)
        .expect("parallel ODB blob intro should not panic with empty MIDX");
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(
        report.pack_exec_reports.is_empty(),
        "empty MIDX should produce no packed candidates"
    );
    assert!(report.skipped_candidates.is_empty());
}

#[test]
fn odb_blob_parallel_intro_handles_low_delta_cache_budget() {
    if !git_available() {
        eprintln!("git not available; skipping low delta-cache budget test");
        return;
    }

    let tmp = init_repo();
    // Keep all objects loose (no gc/repack), with >1 commits so parallel intro
    // is selected when blob_intro_workers > 1.
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH\n", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP\n", "c2");

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.blob_intro_workers = 4;
    config.tree_diff.max_tree_delta_cache_bytes = 8 * 1024 * 1024;

    let GitScanResult(report) = run_scan_with_config(tmp.path(), None, config)
        .expect("parallel ODB blob intro should not fail with 8MiB total delta cache");
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
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
    repack_all(tmp.path());

    let result = run_scan(tmp.path(), None);

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    if perf_stats_enabled() {
        assert!(report.finalize.stats.total_findings >= 2);
    } else {
        assert_eq!(report.finalize.stats.total_findings, 0);
    }
}

#[test]
fn diff_history_pack_exec_workers_preserve_deterministic_output() {
    if !git_available() {
        eprintln!("git not available; skipping diff-history worker test");
        return;
    }

    let tmp = init_repo();
    let payloads = [
        "TOK_ABCDEFGH\n",
        "TOK_IJKLMNOP\n",
        "TOK_QRSTUVWX\n",
        "TOK_YZABCDEF\n",
        "TOK_GHIJKLMN\n",
        "TOK_OPQRSTUV\n",
        "TOK_WXYZ1234\n",
        "TOK_5678ABCD\n",
    ];
    for (idx, payload) in payloads.iter().enumerate() {
        let name = format!("secret-{idx}.txt");
        let msg = format!("c{idx}");
        commit_file(tmp.path(), &name, payload, &msg);
    }
    ensure_artifacts(tmp.path());

    let mut serial_cfg = base_config();
    serial_cfg.scan_mode = GitScanMode::DiffHistory;
    serial_cfg.pack_exec_workers = 1;

    let mut parallel_cfg = serial_cfg.clone();
    parallel_cfg.pack_exec_workers = 4;

    let GitScanResult(serial_report) = run_scan_with_config(tmp.path(), None, serial_cfg).unwrap();
    let GitScanResult(parallel_report) =
        run_scan_with_config(tmp.path(), None, parallel_cfg).unwrap();

    assert_eq!(serial_report.finalize.outcome, FinalizeOutcome::Complete);
    assert_eq!(parallel_report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(
        !serial_report.pack_exec_reports.is_empty(),
        "expected packed candidates in diff-history test fixture"
    );

    assert_scan_outputs_equal(&serial_report, &parallel_report);
}

#[test]
fn odb_blob_parallel_intro_keeps_persistence_contract_without_blob_ctx_determinism() {
    if !git_available() {
        eprintln!("git not available; skipping odb-blob parallel intro contract test");
        return;
    }

    let tmp = init_repo();
    commit_file(tmp.path(), "base.txt", "base\n", "base");

    // Emit the same blob across many commit/path contexts to exercise
    // race-winner attribution in parallel ODB introduction.
    for idx in 0..16 {
        let file = format!("shared-{idx}.txt");
        let msg = format!("shared-{idx}");
        commit_file(tmp.path(), &file, "TOK_SHARED00\n", &msg);
    }
    ensure_artifacts(tmp.path());

    let mut serial_cfg = base_config();
    serial_cfg.scan_mode = GitScanMode::OdbBlobFast;
    serial_cfg.blob_intro_workers = 1;

    let mut parallel_cfg = serial_cfg.clone();
    parallel_cfg.blob_intro_workers = 4;

    let GitScanResult(serial_report) = run_scan_with_config(tmp.path(), None, serial_cfg).unwrap();
    let GitScanResult(parallel_report) =
        run_scan_with_config(tmp.path(), None, parallel_cfg).unwrap();

    assert_eq!(serial_report.finalize.outcome, FinalizeOutcome::Complete);
    assert_eq!(parallel_report.finalize.outcome, FinalizeOutcome::Complete);

    let serial_blob_ctx = select_ops_with_ns(&serial_report.finalize.data_ops, &NS_BLOB_CTX);
    let parallel_blob_ctx = select_ops_with_ns(&parallel_report.finalize.data_ops, &NS_BLOB_CTX);
    assert!(
        !serial_blob_ctx.is_empty(),
        "expected blob_ctx ops in serial output"
    );
    assert!(
        !parallel_blob_ctx.is_empty(),
        "expected blob_ctx ops in parallel output"
    );

    assert_odb_parallel_contract(&serial_report, &parallel_report);
}

// NOTE: `missing_loose_object_yields_partial` was removed because the
// in-memory artifact builder requires all commits to be in packs (`repack
// -ad`), which also packs every blob. There is no reliable way to create a
// loose-only blob whose commit is still in a pack using normal Git
// operations. The `LooseMissing` code path is covered by the unit test in
// `runner.rs` (see `scan_loose_candidates_missing_object_skipped`).
