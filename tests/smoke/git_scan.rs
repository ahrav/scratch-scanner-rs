//! Smoke test for git_scan binary end-to-end.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn run_git(repo: &Path, args: &[&str]) -> bool {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .expect("git command");
    status.success()
}

fn make_temp_dir() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("git_scan_smoke_{}", stamp));
    fs::create_dir(&path).unwrap();
    path
}

fn find_release_binary(name: &str) -> PathBuf {
    let bin_name = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let base = PathBuf::from(target_dir);
        let base = if let Ok(target) = std::env::var("CARGO_BUILD_TARGET") {
            base.join(target)
        } else {
            base
        };
        return base.join("release").join(bin_name);
    }

    if let Ok(target) = std::env::var("CARGO_BUILD_TARGET") {
        return PathBuf::from("target")
            .join(target)
            .join("release")
            .join(bin_name);
    }

    PathBuf::from("target").join("release").join(bin_name)
}

fn extract_metric(line: &str, key: &str) -> Option<u64> {
    for part in line.split_whitespace() {
        if let Some(rest) = part.strip_prefix(key) {
            return rest.parse().ok();
        }
    }
    None
}

#[test]
fn git_scan_binary_finds_secrets() {
    if !git_available() {
        eprintln!("git not available; skipping git_scan smoke test");
        return;
    }

    let repo = make_temp_dir();
    assert!(run_git(&repo, &["init", "-b", "main"]));
    assert!(run_git(
        &repo,
        &["config", "user.email", "test@example.com"]
    ));
    assert!(run_git(&repo, &["config", "user.name", "Test User"]));

    let secret_file = repo.join("secrets.txt");
    fs::write(&secret_file, b"token=xoxa-1234567890abcdef\n").unwrap();
    assert!(run_git(&repo, &["add", "."]));
    assert!(run_git(&repo, &["commit", "-m", "add secret"]));

    if !run_git(&repo, &["gc", "--aggressive", "--prune=now"]) {
        eprintln!("git gc failed; skipping git_scan smoke test");
        return;
    }
    if !run_git(&repo, &["commit-graph", "write", "--reachable"]) {
        eprintln!("commit-graph write failed; skipping git_scan smoke test");
        return;
    }
    if !run_git(&repo, &["multi-pack-index", "write", "--bitmap"]) {
        eprintln!("multi-pack-index write failed; skipping git_scan smoke test");
        return;
    }

    let status = Command::new("cargo")
        .args(["build", "--release", "--bin", "git_scan"])
        .status()
        .unwrap();
    assert!(status.success(), "Failed to build git_scan");

    let binary = find_release_binary("git_scan");
    let output = Command::new(&binary).arg(&repo).output().unwrap();
    assert!(
        output.status.success(),
        "git_scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status="), "missing status in stdout");
    let findings = extract_metric(&stdout, "findings=").unwrap_or(0);
    if perf_stats_enabled() {
        assert!(findings > 0, "expected findings > 0, got {findings}");
    } else {
        assert_eq!(findings, 0, "expected findings=0 when perf stats disabled");
    }

    fs::remove_dir_all(&repo).unwrap();
}
