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

    let output = Command::new("./target/release/scanner-rs")
        .arg(&tmp)
        .output()
        .unwrap();

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
