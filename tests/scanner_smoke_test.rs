//! Smoke test that exercises the scanner end-to-end.
//!
//! This runs on every `cargo test` to catch regressions in real scanning.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn make_temp_dir() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("scanner_smoke_{}", stamp));
    fs::create_dir(&path).unwrap();
    path
}

/// Find the release binary, respecting CARGO_TARGET_DIR and cross-compilation.
///
/// Checks in order:
/// 1. CARGO_TARGET_DIR environment variable
/// 2. CARGO_BUILD_TARGET for cross-compilation
/// 3. Default ./target/release/ location
fn find_release_binary() -> PathBuf {
    #[cfg(windows)]
    const BINARY_NAME: &str = "scanner-rs.exe";
    #[cfg(not(windows))]
    const BINARY_NAME: &str = "scanner-rs";

    // Check CARGO_TARGET_DIR first
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target_dir).join("release").join(BINARY_NAME);
    }

    // Check for cross-compilation target
    if let Ok(target) = std::env::var("CARGO_BUILD_TARGET") {
        return PathBuf::from("target")
            .join(target)
            .join("release")
            .join(BINARY_NAME);
    }

    // Default location
    PathBuf::from("target").join("release").join(BINARY_NAME)
}

#[test]
fn scanner_binary_finds_secrets() {
    let tmp = make_temp_dir();

    // Create file with known secret pattern (Slack legacy workspace token)
    let secret_file = tmp.join("secrets.txt");
    fs::write(&secret_file, b"token=xoxa-1234567890abcdef\n").unwrap();

    // Build release binary
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .status()
        .unwrap();
    assert!(status.success(), "Failed to build scanner");

    // Use dynamic binary path instead of hardcoded path.
    // This respects CARGO_TARGET_DIR and cross-compilation settings.
    let binary = find_release_binary();

    let output = Command::new(&binary).arg(&tmp).output().unwrap();

    assert!(
        output.status.success(),
        "Scanner failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("findings="), "No stats output in stderr");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("slack"),
        "Expected slack token finding in stdout, got: {}",
        stdout
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
