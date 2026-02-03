use std::fs;
use std::path::{Path, PathBuf};

use scanner_rs::git_scan::{preflight, ArtifactStatus, PreflightLimits};
use tempfile::TempDir;

fn create_worktree_repo(root: &Path) -> PathBuf {
    let git_dir = root.join(".git");
    fs::create_dir_all(git_dir.join("objects").join("pack")).unwrap();
    fs::create_dir_all(git_dir.join("refs")).unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    git_dir
}

fn write_commit_graph(objects_dir: &Path) {
    let info_dir = objects_dir.join("info");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("commit-graph"), b"CGPH").unwrap();
}

fn write_midx(pack_dir: &Path) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();
}

fn write_pack(pack_dir: &Path, name: &str) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join(name), b"").unwrap();
}

#[test]
fn preflight_missing_artifacts() {
    let tmp = TempDir::new().unwrap();
    create_worktree_repo(tmp.path());

    let report = preflight(tmp.path(), PreflightLimits::DEFAULT).unwrap();

    match report.status {
        ArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            ..
        } => {
            assert!(missing_commit_graph, "commit-graph should be missing");
            assert!(missing_midx, "midx should be missing");
        }
        ArtifactStatus::Ready { .. } => panic!("expected NeedsMaintenance"),
    }
}

#[test]
fn preflight_pack_count_threshold() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_worktree_repo(tmp.path());
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");

    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);
    write_pack(&pack_dir, "pack-1.pack");
    write_pack(&pack_dir, "pack-2.pack");

    let limits = PreflightLimits {
        max_pack_count: 1,
        ..PreflightLimits::DEFAULT
    };
    let report = preflight(tmp.path(), limits).unwrap();

    match report.status {
        ArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            pack_count,
            max_pack_count,
        } => {
            assert!(!missing_commit_graph, "commit-graph should be present");
            assert!(!missing_midx, "midx should be present");
            assert!(
                pack_count > max_pack_count as u32,
                "pack count should exceed limit"
            );
        }
        ArtifactStatus::Ready { .. } => panic!("expected NeedsMaintenance"),
    }
}

#[test]
fn preflight_alternates_in_pack_count() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_worktree_repo(tmp.path());
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");

    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);
    write_pack(&pack_dir, "pack-main.pack");

    let alt_objects = tmp.path().join("alt-objects");
    let alt_pack_dir = alt_objects.join("pack");
    fs::create_dir_all(&alt_pack_dir).unwrap();
    write_pack(&alt_pack_dir, "pack-alt.pack");

    let alternates_path = objects_dir.join("info").join("alternates");
    fs::create_dir_all(alternates_path.parent().unwrap()).unwrap();
    let mut alternates_line = alt_objects.to_string_lossy().to_string();
    alternates_line.push('\n');
    fs::write(alternates_path, alternates_line.as_bytes()).unwrap();

    let limits = PreflightLimits {
        max_pack_count: 1,
        ..PreflightLimits::DEFAULT
    };
    let report = preflight(tmp.path(), limits).unwrap();

    assert_eq!(report.repo.alternate_object_dirs.len(), 1);

    match report.status {
        ArtifactStatus::NeedsMaintenance { pack_count, .. } => {
            assert!(pack_count > 1, "alternate pack should count toward total");
        }
        ArtifactStatus::Ready { .. } => panic!("expected NeedsMaintenance"),
    }
}
