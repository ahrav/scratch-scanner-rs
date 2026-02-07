use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use std::process::Command;

#[test]
fn fs_scan_expands_gzip_archives_by_default() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let gz_path = tmp.path().join("payload.txt.gz");

    // Reuse the known-good smoke fixture token so the default demo rules match.
    let payload = b"token=xoxa-1234567890abcdef\n";
    let gz_file = fs::File::create(&gz_path).expect("create gzip");
    let mut gz = GzEncoder::new(gz_file, Compression::default());
    gz.write_all(payload).expect("write gzip payload");
    gz.finish().expect("finish gzip");

    let binary = env!("CARGO_BIN_EXE_scanner-rs");
    let output = Command::new(binary)
        .args(["scan", "fs"])
        .arg(tmp.path())
        .output()
        .expect("run scanner-rs");

    assert!(
        output.status.success(),
        "scanner failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"type\":\"finding\""),
        "expected at least one finding event, got: {stdout}"
    );
    assert!(
        stdout.contains(".gz::"),
        "expected finding path to include archive virtual path marker, got: {stdout}"
    );
}
