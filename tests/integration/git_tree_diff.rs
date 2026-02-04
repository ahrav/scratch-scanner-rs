//! Integration tests for tree diff and object store against a real Git repo.
//!
//! These tests build small repos, write commit-graph/MIDX artifacts, and then
//! compare tree-diff behavior against `git diff-tree` output or explicit
//! expectations. They also exercise spill partitioning and corrupt-tree
//! error reporting.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use scanner_rs::git_scan::{
    introduced_by_plan, repo_open, CandidateBuffer, CandidateSink, ChangeKind, CollectedUniqueBlob,
    CollectingUniqueBlobSink, CommitGraph, CommitGraphView, CommitWalkLimits, MergeDiffMode,
    NeverSeenStore, ObjectStore, ParentScratch, RefWatermarkStore, RepoArtifactStatus,
    RepoOpenError, RepoOpenLimits, SpillLimits, Spiller, StartSetConfig, StartSetResolver,
    TreeDiffError, TreeDiffLimits, TreeDiffWalker,
};
use scanner_rs::git_scan::{OidBytes, PlannedCommit, RepoJobState};
use tempfile::TempDir;

/// Returns true when the `git` CLI is available on the host.
fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// Returns true when this git build supports the MIDX command.
fn git_supports_midx() -> bool {
    Command::new("git")
        .args(["multi-pack-index", "--help"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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
    while i + 1 < bytes.len() {
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

/// Start set resolver that returns fixed refs.
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

/// Watermark store that returns no watermarks for all refs.
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

/// Create a repo with a simple two-commit history.
///
/// The second commit modifies, adds, and deletes paths to exercise tree diff.
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

/// Create a repo with a two-parent merge commit for merge diff tests.
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

/// Open repo state with commit-graph and MIDX artifacts ready.
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

/// Collect tree diff change kinds into a map keyed by UTF-8 path.
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

    // Baseline expected changes from git itself.
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

/// Collect unique blobs via spill with the supplied limits.
fn collect_unique_blobs(state: &RepoJobState, limits: SpillLimits) -> Vec<CollectedUniqueBlob> {
    let cg = CommitGraphView::open_repo(state).unwrap();
    let plan = introduced_by_plan(state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();

    let tree_limits = TreeDiffLimits::RESTRICTIVE;
    let mut store = ObjectStore::open(state, &tree_limits).unwrap();
    let mut walker = TreeDiffWalker::new(&tree_limits, state.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, state.object_format.oid_len(), tmp.path()).unwrap();

    struct SpillSink<'a> {
        spiller: &'a mut Spiller,
    }

    impl CandidateSink for SpillSink<'_> {
        fn emit(
            &mut self,
            oid: OidBytes,
            path: &[u8],
            commit_id: u32,
            parent_idx: u8,
            change_kind: ChangeKind,
            ctx_flags: u16,
            cand_flags: u16,
        ) -> Result<(), TreeDiffError> {
            self.spiller
                .push(
                    oid,
                    path,
                    commit_id,
                    parent_idx,
                    change_kind,
                    ctx_flags,
                    cand_flags,
                )
                .map_err(|err| TreeDiffError::CandidateSinkError {
                    detail: err.to_string(),
                })
        }
    }

    {
        let mut sink = SpillSink {
            spiller: &mut spiller,
        };
        for PlannedCommit { pos, snapshot_root } in &plan {
            let commit_id = pos.0;
            let new_tree = cg.root_tree_oid(*pos).unwrap();

            if *snapshot_root {
                walker
                    .diff_trees(&mut store, &mut sink, Some(&new_tree), None, commit_id, 0)
                    .unwrap();
                continue;
            }

            parent_scratch.clear();
            cg.collect_parents(
                *pos,
                CommitWalkLimits::RESTRICTIVE.max_parents_per_commit,
                &mut parent_scratch,
            )
            .unwrap();
            let parents = parent_scratch.as_slice();

            if parents.is_empty() {
                walker
                    .diff_trees(&mut store, &mut sink, Some(&new_tree), None, commit_id, 0)
                    .unwrap();
                continue;
            }

            let merge_mode = MergeDiffMode::AllParents;
            match merge_mode {
                MergeDiffMode::AllParents => {
                    for (idx, parent_pos) in parents.iter().enumerate() {
                        let old_tree = cg.root_tree_oid(*parent_pos).unwrap();
                        walker
                            .diff_trees(
                                &mut store,
                                &mut sink,
                                Some(&new_tree),
                                Some(&old_tree),
                                commit_id,
                                idx as u8,
                            )
                            .unwrap();
                    }
                }
                MergeDiffMode::FirstParentOnly => {
                    let old_tree = cg.root_tree_oid(parents[0]).unwrap();
                    walker
                        .diff_trees(
                            &mut store,
                            &mut sink,
                            Some(&new_tree),
                            Some(&old_tree),
                            commit_id,
                            0,
                        )
                        .unwrap();
                }
            }
        }
    }

    let store = NeverSeenStore;
    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&store, &mut sink).unwrap();
    sink.blobs
}

/// Collect unique blobs using a buffered candidate path before spilling.
fn collect_unique_blobs_buffered(
    state: &RepoJobState,
    limits: SpillLimits,
) -> Vec<CollectedUniqueBlob> {
    let cg = CommitGraphView::open_repo(state).unwrap();
    let plan = introduced_by_plan(state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();

    let tree_limits = TreeDiffLimits::RESTRICTIVE;
    let mut store = ObjectStore::open(state, &tree_limits).unwrap();
    let mut walker = TreeDiffWalker::new(&tree_limits, state.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();
    let mut buffer = CandidateBuffer::new(&tree_limits, state.object_format.oid_len());

    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, state.object_format.oid_len(), tmp.path()).unwrap();

    for PlannedCommit { pos, snapshot_root } in &plan {
        let commit_id = pos.0;
        let new_tree = cg.root_tree_oid(*pos).unwrap();

        if *snapshot_root {
            walker
                .diff_trees(&mut store, &mut buffer, Some(&new_tree), None, commit_id, 0)
                .unwrap();
            continue;
        }

        parent_scratch.clear();
        cg.collect_parents(
            *pos,
            CommitWalkLimits::RESTRICTIVE.max_parents_per_commit,
            &mut parent_scratch,
        )
        .unwrap();
        let parents = parent_scratch.as_slice();

        if parents.is_empty() {
            walker
                .diff_trees(&mut store, &mut buffer, Some(&new_tree), None, commit_id, 0)
                .unwrap();
            continue;
        }

        for (idx, parent_pos) in parents.iter().enumerate() {
            let old_tree = cg.root_tree_oid(*parent_pos).unwrap();
            walker
                .diff_trees(
                    &mut store,
                    &mut buffer,
                    Some(&new_tree),
                    Some(&old_tree),
                    commit_id,
                    idx as u8,
                )
                .unwrap();
        }
    }

    for cand in buffer.iter_resolved() {
        spiller
            .push(
                cand.oid,
                cand.path,
                cand.commit_id,
                cand.parent_idx,
                cand.change_kind,
                cand.ctx_flags,
                cand.cand_flags,
            )
            .unwrap();
    }

    let store = NeverSeenStore;
    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&store, &mut sink).unwrap();
    sink.blobs
}

fn sort_unique_blobs(blobs: &mut [CollectedUniqueBlob]) {
    blobs.sort_by(|a, b| {
        (
            a.oid,
            a.ctx.commit_id,
            a.ctx.parent_idx,
            a.ctx.change_kind.as_u8(),
            a.ctx.ctx_flags,
            a.ctx.cand_flags,
            &a.path,
        )
            .cmp(&(
                b.oid,
                b.ctx.commit_id,
                b.ctx.parent_idx,
                b.ctx.change_kind.as_u8(),
                b.ctx.ctx_flags,
                b.ctx.cand_flags,
                &b.path,
            ))
    });
}

#[test]
fn spill_limits_streaming_is_partition_invariant() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping spill limits test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let mut limits_small = SpillLimits::RESTRICTIVE;
    limits_small.max_chunk_candidates = 2;
    limits_small.max_chunk_path_bytes = 64;
    limits_small.seen_batch_max_oids = 2;
    limits_small.seen_batch_max_path_bytes = 64;
    limits_small.max_path_len = 64;

    let mut limits_large = limits_small;
    limits_large.max_chunk_candidates = 1024;
    limits_large.max_chunk_path_bytes = 4096;

    let mut out_small = collect_unique_blobs(&state, limits_small);
    let mut out_large = collect_unique_blobs(&state, limits_large);

    sort_unique_blobs(&mut out_small);
    sort_unique_blobs(&mut out_large);

    assert_eq!(out_small, out_large);
}

#[test]
fn buffered_vs_streaming_candidates_match() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping buffered vs streaming test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = SpillLimits::RESTRICTIVE;
    let mut out_stream = collect_unique_blobs(&state, limits);
    let mut out_buffered = collect_unique_blobs_buffered(&state, limits);

    sort_unique_blobs(&mut out_stream);
    sort_unique_blobs(&mut out_buffered);

    assert_eq!(out_stream, out_buffered);
}

/// Write a corrupt tree object into the object database.
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
