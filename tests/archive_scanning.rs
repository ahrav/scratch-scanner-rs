//! Archive scanning tests for the local scheduler path.
//!
//! # Scope
//! These tests exercise archive expansion (gzip, tar, tar.gz), virtual path
//! attribution, boundary overlap, and budget enforcement when using the
//! `scheduler::local` execution path.
//!
//! # Assumptions
//! - Findings are emitted in the `VecSink` format: `<path>:<start>-<end> <rule>`.
//! - Virtual paths are displayed as `parent::entry`.
//! - Archive bytes are synthesized with minimal headers (no ZIP here).

use flate2::write::GzEncoder;
use flate2::Compression;
use scanner_rs::archive::PartialReason;
use scanner_rs::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_rs::scheduler::local::{
    scan_local, LocalConfig, LocalFile, LocalReport, VecFileSource,
};
use scanner_rs::scheduler::output_sink::VecSink;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

#[derive(Debug)]
struct FindingLine {
    path: String,
    start: u64,
}

/// Parse the sink output into `(path, start)` pairs.
///
/// This is intentionally lossy: end offsets and rule names are ignored because
/// the tests only assert path attribution and the start position.
fn parse_findings(output: &str) -> Vec<FindingLine> {
    let mut out = Vec::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Format: <path>:<start>-<end> <rule>
        let mut parts = line.splitn(2, ' ');
        let left = parts.next().unwrap_or("");
        let mut left_parts = left.rsplitn(2, ':');
        let range = left_parts.next().unwrap_or("0-0");
        let path = left_parts.next().unwrap_or("");
        let mut range_parts = range.splitn(2, '-');
        let start = range_parts
            .next()
            .unwrap_or("0")
            .parse::<u64>()
            .unwrap_or(0);
        out.push(FindingLine {
            path: path.to_string(),
            start,
        });
    }
    out
}

/// Build a payload with `SECRET` starting exactly at `offset`.
fn payload_with_secret_at(offset: usize) -> Vec<u8> {
    let mut payload = vec![b'A'; offset];
    payload.extend_from_slice(b"SECRET");
    payload
}

/// Write a gzip file to `path` with the provided payload bytes.
fn write_gz(path: &Path, payload: &[u8]) -> io::Result<()> {
    let f = File::create(path)?;
    let mut enc = GzEncoder::new(f, Compression::default());
    enc.write_all(payload)?;
    enc.finish()?;
    Ok(())
}

const TAR_BLOCK_LEN: usize = 512;

/// Write a minimal ustar header for a regular file.
///
/// This is "just enough" for the tar reader in this repo; it does not attempt
/// to be a full tar writer.
fn tar_write_header(buf: &mut [u8; TAR_BLOCK_LEN], name: &str, size: u64, typeflag: u8) {
    buf.fill(0);
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    buf[0..name_len].copy_from_slice(&name_bytes[..name_len]);
    buf[100..108].copy_from_slice(b"0000777\0");
    buf[108..116].copy_from_slice(b"0000000\0");
    buf[116..124].copy_from_slice(b"0000000\0");
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    buf[124..135].copy_from_slice(&size_field);
    buf[135] = 0;
    buf[136..148].copy_from_slice(b"00000000000\0");
    for b in &mut buf[148..156] {
        *b = b' ';
    }
    buf[156] = typeflag;
    buf[257..263].copy_from_slice(b"ustar\0");
    buf[263..265].copy_from_slice(b"00");
    let sum: u32 = buf.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    buf[148..156].copy_from_slice(chk.as_bytes());
}

fn tar_pad(size: usize) -> usize {
    let rem = size % TAR_BLOCK_LEN;
    if rem == 0 {
        0
    } else {
        TAR_BLOCK_LEN - rem
    }
}

/// Build a single-entry tar archive terminated by two zero blocks.
fn build_simple_tar(entry_name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hdr = [0u8; TAR_BLOCK_LEN];
    tar_write_header(&mut hdr, entry_name, payload.len() as u64, b'0');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

/// Build a multi-entry tar archive terminated by two zero blocks.
fn build_multi_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, payload) in entries {
        let mut hdr = [0u8; TAR_BLOCK_LEN];
        tar_write_header(&mut hdr, name, payload.len() as u64, b'0');
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    }
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

/// Create a `LocalFile` with a size snapshot based on filesystem metadata.
fn file_from_path(path: &Path) -> LocalFile {
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    LocalFile {
        path: path.to_path_buf(),
        size,
    }
}

/// Archive-enabled config with generous budgets for tests.
///
/// Individual tests override specific limits to exercise budget behavior.
fn cfg_archives_enabled() -> LocalConfig {
    let mut cfg = LocalConfig {
        workers: 1,
        chunk_size: 64,
        ..LocalConfig::default()
    };
    cfg.archive.enabled = true;
    cfg.archive.max_entries_per_archive = 256;
    cfg.archive.max_archive_metadata_bytes = 1 << 20;
    cfg.archive.max_total_uncompressed_bytes_per_archive = 8 << 20;
    cfg.archive.max_total_uncompressed_bytes_per_root = 8 << 20;
    cfg.archive.max_uncompressed_bytes_per_entry = 2 << 20;
    cfg.archive.max_virtual_path_len_per_entry = 256;
    cfg.archive.max_virtual_path_bytes_per_archive = 64 << 10;
    cfg
}

/// Run a local scan with a single "SECRET" rule and return sink output + report.
fn run_scan(files: Vec<LocalFile>, cfg: LocalConfig) -> (String, LocalReport) {
    let engine = Arc::new(MockEngine::new(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        16,
    ));
    let sink = Arc::new(VecSink::new());
    let report = scan_local(engine, VecFileSource::new(files), cfg, sink.clone());
    let out = String::from_utf8_lossy(&sink.take()).to_string();
    (out, report)
}

#[test]
fn finds_secret_in_gzip_with_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let gz = tmp.path().join("payload.txt.gz");

    let payload = payload_with_secret_at(12);
    write_gz(&gz, &payload).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&gz)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    assert!(!findings.is_empty(), "expected finding; output: {out}");

    let f = &findings[0];
    assert!(f.path.contains("payload.txt.gz"));
    assert!(f.path.contains("::"));
    assert_eq!(f.start, 12);
}

#[test]
fn gzip_entry_byte_cap_prevents_unbounded_work_and_is_reported() {
    let tmp = TempDir::new().unwrap();
    let gz = tmp.path().join("big.txt.gz");

    let mut payload = Vec::new();
    payload.extend(std::iter::repeat_n(b'A', 64));
    payload.extend_from_slice(b"SECRET\n");
    payload.extend_from_slice(b"tail\n");

    write_gz(&gz, &payload).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_uncompressed_bytes_per_entry = 32;

    let (out, report) = run_scan(vec![file_from_path(&gz)], cfg);
    assert!(
        out.trim().is_empty(),
        "expected no findings due to cap; got: {out}"
    );

    assert!(
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            > 0,
        "expected entry output budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn scans_tar_entry_and_emits_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let tar_bytes = build_simple_tar("a/b.txt", b"hello SECRET world\n");
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    assert!(out.contains("secret"), "output: {out}");
    assert!(out.contains("::"), "output: {out}");
    assert!(out.contains("a/b.txt"), "output: {out}");
}

#[test]
fn tar_boundary_spanning_secret_once() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let payload = {
        let mut v = Vec::new();
        v.extend_from_slice(b"AAAAA");
        v.extend_from_slice(b"SECRET");
        v.extend_from_slice(b"BBBBBBBBBBBB");
        v
    };
    let tar_bytes = build_simple_tar("x.txt", &payload);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.chunk_size = 6;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert!(report.metrics.chunks_scanned >= 2);
    let count = out.matches("secret").count();
    assert_eq!(count, 1, "output: {out}");
}

#[test]
fn scans_targz_entry_and_emits_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let tgz = tmp.path().join("payload.tar.gz");

    let tar_bytes = build_simple_tar("inner.txt", b"xxSECRETyy");
    {
        let f = File::create(&tgz).unwrap();
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();
    }

    let (out, _report) = run_scan(vec![file_from_path(&tgz)], cfg_archives_enabled());
    assert!(out.contains("secret"), "output: {out}");
    assert!(out.contains("::inner.txt"), "output: {out}");
}

#[test]
fn tar_path_budget_exceeded_is_reported() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let payload = b"hello SECRET world\n";
    let tar_bytes = build_multi_tar(&[("first.txt", payload), ("second.txt", payload)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 8;
    cfg.archive.max_virtual_path_bytes_per_archive = 8;

    let (_out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert!(
        report.metrics.archive.partial_reasons[PartialReason::PathBudgetExceeded.as_usize()] > 0,
        "expected path budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}
