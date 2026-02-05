//! Integration test for commit-graph range walking against a real `git` repo.

use std::fs;
use std::path::Path;
use std::process::Command;

use scanner_rs::git_scan::{
    repo_open, CommitGraph, CommitGraphView, CommitPlanIter, CommitWalkLimits, RefWatermarkStore,
    RepoOpenError, RepoOpenLimits, StartSetConfig, StartSetResolver,
};
use scanner_rs::git_scan::{OidBytes, RepoArtifactStatus};
use tempfile::TempDir;

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

fn rev_list(repo: &Path, rev: &str) -> Vec<OidBytes> {
    let out = git_output(repo, &["rev-list", rev]);
    out.lines().map(oid_from_hex).collect()
}

fn init_repo_with_commits(count: usize) -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    for i in 0..count {
        let msg = format!("c{i}");
        run_git(tmp.path(), &["commit", "--allow-empty", "-m", &msg]);
    }

    run_git(tmp.path(), &["commit-graph", "write", "--reachable"]);

    let pack_dir = tmp.path().join(".git/objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    // Stub MIDX file so preflight treats artifacts as present.
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();

    tmp
}

fn init_repo_with_branches() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("base.txt"), "base\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "base"]);

    run_git(tmp.path(), &["checkout", "-b", "other"]);
    fs::write(tmp.path().join("other.txt"), "other\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "other"]);

    run_git(tmp.path(), &["checkout", "main"]);
    fs::write(tmp.path().join("main.txt"), "main\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "main"]);

    run_git(tmp.path(), &["commit-graph", "write", "--reachable"]);

    let pack_dir = tmp.path().join(".git/objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();

    tmp
}

struct TestResolver {
    refs: Vec<(Vec<u8>, OidBytes)>,
}

impl StartSetResolver for TestResolver {
    fn resolve(
        &self,
        _paths: &scanner_rs::git_scan::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(self.refs.clone())
    }
}

struct TestWatermarkStore {
    watermarks: Vec<(Vec<u8>, Option<OidBytes>)>,
}

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        let mut out = Vec::with_capacity(ref_names.len());
        for name in ref_names {
            let mut found = None;
            for (n, wm) in &self.watermarks {
                if n.as_slice() == *name {
                    found = *wm;
                    break;
                }
            }
            out.push(found);
        }
        Ok(out)
    }
}

#[test]
fn commit_walk_linear_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(4);

    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let head_parent = git_output(tmp.path(), &["rev-parse", "HEAD~1"]);
    let watermark = git_output(tmp.path(), &["rev-parse", "HEAD~2"]);

    let tip_oid = oid_from_hex(&head);
    let parent_oid = oid_from_hex(&head_parent);
    let watermark_oid = oid_from_hex(&watermark);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore {
        watermarks: vec![(b"refs/heads/main".to_vec(), Some(watermark_oid))],
    };

    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        42,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(matches!(state.artifact_status, RepoArtifactStatus::Ready));

    let cg = CommitGraphView::open_repo(&state).unwrap();

    let iter = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();
    let mut out = Vec::new();
    for item in iter {
        out.push(item.unwrap().pos.0);
    }

    let tip_pos = cg.lookup(&tip_oid).unwrap().unwrap().0;
    let parent_pos = cg.lookup(&parent_oid).unwrap().unwrap().0;

    assert_eq!(out, vec![tip_pos, parent_pos]);
}

#[test]
fn commit_walk_missing_watermark_scans_full_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(3);
    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let tip_oid = oid_from_hex(&head);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore { watermarks: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let cg = CommitGraphView::open_repo(&state).unwrap();
    let mut actual: Vec<u32> = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE)
        .unwrap()
        .map(|item| item.unwrap().pos.0)
        .collect();
    actual.sort_unstable();

    let expected_oids = rev_list(tmp.path(), "HEAD");
    let mut expected: Vec<u32> = expected_oids
        .iter()
        .map(|oid| cg.lookup(oid).unwrap().unwrap().0)
        .collect();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

#[test]
fn commit_walk_watermark_not_ancestor_scans_full_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_branches();
    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let other = git_output(tmp.path(), &["rev-parse", "other"]);
    let tip_oid = oid_from_hex(&head);
    let other_oid = oid_from_hex(&other);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore {
        watermarks: vec![(b"refs/heads/main".to_vec(), Some(other_oid))],
    };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        8,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let cg = CommitGraphView::open_repo(&state).unwrap();
    let mut actual: Vec<u32> = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE)
        .unwrap()
        .map(|item| item.unwrap().pos.0)
        .collect();
    actual.sort_unstable();

    let expected_oids = rev_list(tmp.path(), "main");
    let mut expected: Vec<u32> = expected_oids
        .iter()
        .map(|oid| cg.lookup(oid).unwrap().unwrap().0)
        .collect();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}
