//! Integration tests for tree diff and object store against a real Git repo.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use scanner_rs::git_scan::{
    repo_open, CandidateBuffer, ChangeKind, MergeDiffMode, ObjectStore, RefWatermarkStore,
    RepoArtifactStatus, RepoOpenError, RepoOpenLimits, StartSetConfig, StartSetResolver,
    TreeDiffError, TreeDiffLimits, TreeDiffWalker,
};
use scanner_rs::git_scan::{OidBytes, RepoJobState};
use tempfile::TempDir;

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn git_supports_midx() -> bool {
    Command::new("git")
        .args(["multi-pack-index", "--help"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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
    while i + 1 < bytes.len() {
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

fn prepare_repo_with_commits() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("a.txt"), "one\n").unwrap();
    fs::create_dir_all(tmp.path().join("dir")).unwrap();
    fs::write(tmp.path().join("dir/b.txt"), "two\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c1"]);

    fs::write(tmp.path().join("a.txt"), "one\nchanged\n").unwrap();
    fs::write(tmp.path().join("dir/c.txt"), "three\n").unwrap();
    fs::remove_file(tmp.path().join("dir/b.txt")).unwrap();
    run_git(tmp.path(), &["add", "-A"]);
    run_git(tmp.path(), &["commit", "-m", "c2"]);

    run_git(tmp.path(), &["commit-graph", "write", "--reachable"]);
    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

fn prepare_repo_with_merge() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("a.txt"), "base\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "base"]);

    run_git(tmp.path(), &["checkout", "-b", "feature"]);
    fs::write(tmp.path().join("feature.txt"), "feature\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "feature"]);

    run_git(tmp.path(), &["checkout", "main"]);
    fs::write(tmp.path().join("a.txt"), "base\nmain\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "main change"]);

    run_git(
        tmp.path(),
        &["merge", "--no-ff", "feature", "-m", "merge feature"],
    );

    run_git(tmp.path(), &["commit-graph", "write", "--reachable"]);
    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

fn open_repo_state(repo: &Path) -> RepoJobState {
    let head = git_output(repo, &["rev-parse", "HEAD"]);
    let head_oid = oid_from_hex(&head);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), head_oid)],
    };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        repo,
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &EmptyWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(matches!(state.artifact_status, RepoArtifactStatus::Ready));
    state
}

fn diff_paths(
    store: &mut ObjectStore,
    limits: &TreeDiffLimits,
    new_tree: &OidBytes,
    old_tree: &OidBytes,
    parent_idx: u8,
) -> BTreeMap<String, ChangeKind> {
    let mut walker = TreeDiffWalker::new(limits, store.oid_len());
    let mut candidates = CandidateBuffer::new(limits, store.oid_len());

    walker
        .diff_trees(
            store,
            &mut candidates,
            Some(new_tree),
            Some(old_tree),
            0,
            parent_idx,
        )
        .unwrap();

    let mut out = BTreeMap::new();
    for cand in candidates.iter_resolved() {
        let path = String::from_utf8_lossy(cand.path).into_owned();
        out.insert(path, cand.change_kind);
    }
    out
}

#[test]
fn tree_diff_matches_git_diff_tree() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping tree diff test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let mut store = ObjectStore::open(&state, &limits).unwrap();
    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());

    let new_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD"],
    ));
    let old_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD~1"],
    ));

    walker
        .diff_trees(
            &mut store,
            &mut candidates,
            Some(&new_tree),
            Some(&old_tree),
            0,
            0,
        )
        .unwrap();

    let diff = git_output(
        tmp.path(),
        &[
            "diff-tree",
            "-r",
            "--name-status",
            "--no-commit-id",
            "--no-renames",
            "HEAD~1",
            "HEAD",
        ],
    );

    let mut expected: BTreeMap<String, ChangeKind> = BTreeMap::new();
    for line in diff.lines() {
        let mut parts = line.splitn(2, '\t');
        let status = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        let kind = match status {
            "A" => ChangeKind::Add,
            "M" => ChangeKind::Modify,
            _ => continue,
        };
        expected.insert(path.to_string(), kind);
    }

    let mut actual: BTreeMap<String, ChangeKind> = BTreeMap::new();
    for cand in candidates.iter_resolved() {
        let path = String::from_utf8_lossy(cand.path).into_owned();
        actual.insert(path, cand.change_kind);
    }

    assert_eq!(actual, expected);
}

#[test]
fn corrupt_tree_is_reported() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping corrupt tree test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let mut store = ObjectStore::open(&state, &limits).unwrap();
    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());

    let corrupt_oid = OidBytes::sha1([0x11; 20]);
    write_corrupt_tree(&state.paths.objects_dir, &corrupt_oid);

    let result = walker.diff_trees(&mut store, &mut candidates, Some(&corrupt_oid), None, 0, 0);

    assert!(matches!(result, Err(TreeDiffError::CorruptTree { .. })));
}

#[test]
fn merge_diff_modes_emit_expected_candidates() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping merge diff test");
        return;
    }

    let tmp = prepare_repo_with_merge();
    let state = open_repo_state(tmp.path());

    let merge_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^{tree}"]));
    let parent1_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^1^{tree}"]));
    let parent2_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^2^{tree}"]));

    let limits = TreeDiffLimits::RESTRICTIVE;
    let mut store = ObjectStore::open(&state, &limits).unwrap();

    let first_parent = diff_paths(&mut store, &limits, &merge_tree, &parent1_tree, 0);
    let second_parent = diff_paths(&mut store, &limits, &merge_tree, &parent2_tree, 1);

    assert!(first_parent.contains_key("feature.txt"));
    assert!(!first_parent.contains_key("a.txt"));
    assert!(second_parent.contains_key("a.txt"));
    assert!(!second_parent.contains_key("feature.txt"));

    let all_parents =
        collect_merge_candidates(MergeDiffMode::AllParents, &first_parent, &second_parent);
    let first_only = collect_merge_candidates(
        MergeDiffMode::FirstParentOnly,
        &first_parent,
        &second_parent,
    );

    assert!(all_parents.contains_key("feature.txt"));
    assert!(all_parents.contains_key("a.txt"));
    assert_eq!(first_only.len(), 1);
    assert!(first_only.contains_key("feature.txt"));
}

fn collect_merge_candidates(
    mode: MergeDiffMode,
    first_parent: &BTreeMap<String, ChangeKind>,
    second_parent: &BTreeMap<String, ChangeKind>,
) -> BTreeMap<String, ChangeKind> {
    match mode {
        MergeDiffMode::AllParents => {
            let mut out = first_parent.clone();
            out.extend(second_parent.iter().map(|(k, v)| (k.clone(), *v)));
            out
        }
        MergeDiffMode::FirstParentOnly => first_parent.clone(),
    }
}

fn write_corrupt_tree(objects_dir: &Path, oid: &OidBytes) {
    let payload = b"100644 file\0";
    let mut data = format!("tree {}\0", payload.len()).into_bytes();
    data.extend_from_slice(payload);

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let hex = oid.to_string();
    let (dir, file) = hex.split_at(2);

    let obj_dir = objects_dir.join(dir);
    fs::create_dir_all(&obj_dir).unwrap();
    fs::write(obj_dir.join(file), compressed).unwrap();
}
