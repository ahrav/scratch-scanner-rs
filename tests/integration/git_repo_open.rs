//! Integration tests for repo_open's filesystem discovery and artifact handling.
//!
//! The commit-graph and MIDX files contain placeholder bytes; repo_open only
//! checks for presence and mmaps them during these tests.
use std::fs;
use std::path::{Path, PathBuf};

use scanner_rs::git_scan::{
    repo_open, RefWatermarkStore, RepoOpenError, RepoOpenLimits, StartSetConfig, StartSetResolver,
};
use scanner_rs::git_scan::{OidBytes, RepoArtifactStatus};
use tempfile::TempDir;

// Writes a minimal commit-graph marker file (not a valid commit-graph).
fn write_commit_graph(objects_dir: &Path) {
    let info_dir = objects_dir.join("info");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("commit-graph"), b"CGPH").unwrap();
}

// Writes a minimal multi-pack-index marker file (not a valid MIDX).
fn write_midx(pack_dir: &Path) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();
}

// Creates a minimal worktree .git layout with HEAD, objects, and refs dirs.
fn create_main_repo(root: &Path) -> PathBuf {
    let git_dir = root.join(".git");
    fs::create_dir_all(git_dir.join("objects").join("pack")).unwrap();
    fs::create_dir_all(git_dir.join("refs")).unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    git_dir
}

// Creates a linked worktree with a .git file pointing at worktrees/<name>.
fn create_linked_worktree(worktree_root: &Path, main_git_dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(worktree_root).unwrap();

    let wt_git_dir = main_git_dir.join("worktrees").join(name);
    fs::create_dir_all(&wt_git_dir).unwrap();
    fs::write(wt_git_dir.join("commondir"), "../..\n").unwrap();

    let gitdir_line = format!("gitdir: {}\n", wt_git_dir.to_string_lossy());
    fs::write(worktree_root.join(".git"), gitdir_line).unwrap();

    wt_git_dir
}

// Writes an info/alternates file with one path per line.
fn write_alternates(objects_dir: &Path, alternates: &[PathBuf]) {
    let alternates_path = objects_dir.join("info").join("alternates");
    fs::create_dir_all(alternates_path.parent().unwrap()).unwrap();

    let mut content = Vec::new();
    for path in alternates {
        content.extend_from_slice(path.to_string_lossy().as_bytes());
        content.push(b'\n');
    }
    fs::write(alternates_path, content).unwrap();
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

struct TestWatermarkStore;

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(ref_names
            .iter()
            .map(|name| {
                if *name == b"refs/heads/a" {
                    Some(OidBytes::sha1([0x0a; 20]))
                } else {
                    None
                }
            })
            .collect())
    }
}

#[test]
fn repo_open_linked_worktree_and_alternates() {
    let tmp = TempDir::new().unwrap();

    let main_repo = tmp.path().join("main");
    let main_git_dir = create_main_repo(&main_repo);

    let worktree_root = tmp.path().join("worktree");
    create_linked_worktree(&worktree_root, &main_git_dir, "wt1");

    let objects_dir = main_git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let alt_objects = tmp.path().join("alt-objects");
    fs::create_dir_all(&alt_objects).unwrap();
    write_alternates(&objects_dir, std::slice::from_ref(&alt_objects));

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        &worktree_root,
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(state.paths.is_linked_worktree());
    assert_eq!(state.paths.alternate_object_dirs.len(), 1);
    assert!(state.paths.alternate_object_dirs[0].ends_with("alt-objects"));

    assert!(state.artifact_status.is_ready());
    assert!(matches!(state.artifact_status, RepoArtifactStatus::Ready));
    assert!(state.mmaps.commit_graph.is_some());
    assert!(state.mmaps.midx.is_some());
    assert!(state.artifact_fingerprint.is_some());
}

#[test]
fn repo_open_sorts_refs_and_loads_watermarks() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_main_repo(tmp.path());

    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let resolver = TestResolver {
        refs: vec![
            (b"refs/heads/z".to_vec(), OidBytes::sha1([0x03; 20])),
            (b"refs/heads/a".to_vec(), OidBytes::sha1([0x01; 20])),
            (b"refs/heads/m".to_vec(), OidBytes::sha1([0x02; 20])),
        ],
    };

    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        9,
        [1u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(matches!(state.artifact_status, RepoArtifactStatus::Ready));
    assert_eq!(state.start_set.len(), 3);

    let names: Vec<&[u8]> = state
        .start_set
        .iter()
        .map(|r| state.ref_names.get(r.name))
        .collect();
    assert_eq!(names[0], b"refs/heads/a");
    assert_eq!(names[1], b"refs/heads/m");
    assert_eq!(names[2], b"refs/heads/z");

    assert!(state.start_set[0].watermark.is_some());
    assert!(state.start_set[1].watermark.is_none());
    assert!(state.start_set[2].watermark.is_none());
}

#[test]
fn repo_open_detects_lock_files() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_main_repo(tmp.path());

    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let lock_path = objects_dir.join("info").join("commit-graph.lock");
    fs::write(lock_path, b"").unwrap();

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        1,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    match state.artifact_status {
        RepoArtifactStatus::NeedsMaintenance { lock_present, .. } => {
            assert!(lock_present, "lock should be detected");
        }
        RepoArtifactStatus::Ready => panic!("expected NeedsMaintenance"),
    }
    assert!(state.mmaps.commit_graph.is_none());
    assert!(state.mmaps.midx.is_none());
    assert!(state.artifact_fingerprint.is_none());
}

#[test]
fn repo_open_detects_artifact_changes() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_main_repo(tmp.path());

    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        1,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(state.artifacts_unchanged().unwrap());

    let commit_graph_path = objects_dir.join("info").join("commit-graph");
    fs::write(commit_graph_path, b"CGPH2").unwrap();

    assert!(!state.artifacts_unchanged().unwrap());
}
