//! Integration tests for binary-aware content policy.
//!
//! # Scope
//!
//! These tests exercise the FS scanning path's binary file skipping,
//! binary text extraction, and the `--scan-binary` override behavior.
//!
//! Run with: `cargo test --test integration --features binary-extract`

use scanner_rs::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_rs::scheduler::local_fs_owner::{scan_local, LocalConfig, LocalFile, VecFileSource};
use scanner_rs::unified::events::VecEventSink;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

/// Extract a JSON string value for a given key from a single JSON line.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        if bytes[end] == b'\\' {
            end += 2;
        } else if bytes[end] == b'"' {
            break;
        } else {
            end += 1;
        }
    }
    Some(rest[..end].to_string())
}

fn finding_paths(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.contains("\"type\":\"finding\""))
        .filter_map(|l| extract_json_string(l, "path"))
        .collect()
}

fn lf(path: PathBuf, size: u64) -> LocalFile {
    LocalFile { path, size }
}

fn run_scan_with_config(
    files: Vec<LocalFile>,
    mut cfg: LocalConfig,
) -> (String, scanner_rs::scheduler::local_fs_owner::LocalReport) {
    let engine = Arc::new(MockEngine::new(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        16,
    ));
    let sink = Arc::new(VecEventSink::new());
    cfg.event_sink = Arc::clone(&sink) as Arc<dyn scanner_rs::unified::events::EventSink>;
    let report = scan_local(engine, VecFileSource::new(files), cfg);
    let out = String::from_utf8_lossy(&sink.take()).to_string();
    (out, report)
}

fn default_cfg() -> LocalConfig {
    LocalConfig {
        workers: 1,
        chunk_size: 64,
        ..LocalConfig::default()
    }
}

/// Binary files (containing NUL bytes) should be skipped by default.
#[test]
fn fs_scan_skips_binary_files() {
    let dir = TempDir::new().unwrap();

    // Binary file with NUL bytes.
    let bin_path = dir.path().join("image.png");
    let mut f = std::fs::File::create(&bin_path).unwrap();
    f.write_all(b"\x89PNG\r\n\x1a\n\x00SECRET").unwrap();
    let bin_size = std::fs::metadata(&bin_path).unwrap().len();

    // Text file with the secret.
    let txt_path = dir.path().join("config.txt");
    std::fs::write(&txt_path, b"password=SECRET\n").unwrap();
    let txt_size = std::fs::metadata(&txt_path).unwrap().len();

    let files = vec![lf(bin_path, bin_size), lf(txt_path, txt_size)];

    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    // Secret should be found in text file, not in binary file.
    assert!(
        paths.iter().any(|p| p.contains("config.txt")),
        "expected finding in config.txt: {output}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("image.png")),
        "binary file should be skipped: {output}"
    );

    // Binary skip counter should be incremented.
    assert!(
        report.metrics.binary_skipped > 0,
        "expected binary_skipped > 0, got {}",
        report.metrics.binary_skipped
    );
}

/// With `skip_binary = false`, binary files should be scanned.
#[test]
fn fs_scan_binary_flag_overrides_skip() {
    let dir = TempDir::new().unwrap();

    // Binary file with NUL bytes but also contains the secret pattern.
    let bin_path = dir.path().join("data.bin");
    let mut f = std::fs::File::create(&bin_path).unwrap();
    f.write_all(b"\x00\x00SECRET\x00\x00").unwrap();
    let size = std::fs::metadata(&bin_path).unwrap().len();

    let files = vec![lf(bin_path, size)];

    let mut cfg = default_cfg();
    cfg.skip_binary = false;

    let (output, _report) = run_scan_with_config(files, cfg);
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("data.bin")),
        "with skip_binary=false, binary file should be scanned: {output}"
    );
}

/// Text files should always be scanned (not incorrectly classified as binary).
#[test]
fn fs_scan_text_files_not_skipped() {
    let dir = TempDir::new().unwrap();

    let txt_path = dir.path().join("app.py");
    std::fs::write(&txt_path, b"api_key = 'SECRET'\n").unwrap();
    let size = std::fs::metadata(&txt_path).unwrap().len();

    let files = vec![lf(txt_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("app.py")),
        "text file should be scanned: {output}"
    );
    assert_eq!(
        report.metrics.binary_skipped, 0,
        "no binary files should be skipped"
    );
}

/// .ipynb files should be detected as extractable and have their code cells scanned.
#[cfg(feature = "binary-extract")]
#[test]
fn fs_scan_ipynb_extraction() {
    let dir = TempDir::new().unwrap();

    let nb_path = dir.path().join("notebook.ipynb");
    let notebook_json = r##"{
        "cells": [
            {
                "cell_type": "code",
                "source": ["api_key = 'SECRET'\n"]
            }
        ]
    }"##;
    std::fs::write(&nb_path, notebook_json).unwrap();
    let size = std::fs::metadata(&nb_path).unwrap().len();

    let files = vec![lf(nb_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("notebook.ipynb")),
        "ipynb extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// Stats should report correct binary skip counts.
#[test]
fn binary_skip_stats_correct() {
    let dir = TempDir::new().unwrap();

    // Create 3 binary files and 2 text files.
    for i in 0..3 {
        let path = dir.path().join(format!("bin{i}.dat"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
    }
    for i in 0..2 {
        let path = dir.path().join(format!("text{i}.txt"));
        std::fs::write(&path, b"hello world\n").unwrap();
    }

    let files: Vec<LocalFile> = (0..3)
        .map(|i| {
            let p = dir.path().join(format!("bin{i}.dat"));
            let s = std::fs::metadata(&p).unwrap().len();
            lf(p, s)
        })
        .chain((0..2).map(|i| {
            let p = dir.path().join(format!("text{i}.txt"));
            let s = std::fs::metadata(&p).unwrap().len();
            lf(p, s)
        }))
        .collect();

    let (_, report) = run_scan_with_config(files, default_cfg());

    assert_eq!(
        report.metrics.binary_skipped, 3,
        "expected 3 binary files skipped, got {}",
        report.metrics.binary_skipped
    );
}
