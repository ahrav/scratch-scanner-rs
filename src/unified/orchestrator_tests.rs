use super::*;
use crate::api::{TransformConfig, TransformId};

fn touch_default_rules_file(path: &Path) {
    std::fs::write(path, "rules: []\n").expect("write default_rules.yaml");
}

fn test_transforms() -> Vec<TransformConfig> {
    crate::demo_transforms()
}

fn ids(ts: &[TransformConfig]) -> Vec<TransformId> {
    ts.iter().map(|t| t.id).collect()
}

#[test]
fn rules_hash_is_stable_and_hex_sized() {
    let h1 = crate::rules::rules_content_hash64(b"rules: []\n");
    let h2 = crate::rules::rules_content_hash64(b"rules: []\n");
    let h3 = crate::rules::rules_content_hash64(b"rules:\n- name: x\n");
    assert_eq!(h1, h2, "same bytes should hash identically");
    assert_ne!(h1, h3, "different bytes should generally hash differently");
    let h1_hex = format!("{h1:016x}");
    assert_eq!(
        h1_hex.len(),
        16,
        "u64 fingerprint should format as 16 hex chars"
    );
    assert!(h1_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn resolve_rule_source_prefers_explicit_path_over_default() {
    let dir = tempfile::tempdir().unwrap();
    let explicit = dir.path().join("custom_rules.yaml");
    let candidate = dir.path().join("exe_default_rules.yaml");
    touch_default_rules_file(&explicit);
    touch_default_rules_file(&candidate);

    let source = resolve_rule_source(Some(&explicit), Some(candidate.as_path()));
    assert_eq!(source, RuleSource::Explicit(explicit));
}

#[test]
fn resolve_rule_source_uses_existing_default() {
    let dir = tempfile::tempdir().unwrap();
    let candidate = dir.path().join("default_rules.yaml");
    touch_default_rules_file(&candidate);

    let source = resolve_rule_source(None, Some(candidate.as_path()));
    assert_eq!(source, RuleSource::DefaultCandidate(candidate));
}

#[test]
fn resolve_rule_source_falls_back_to_builtin_when_default_missing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nonexistent.yaml");

    let source = resolve_rule_source(None, Some(missing.as_path()));
    assert_eq!(source, RuleSource::BuiltInFallback);
}

#[test]
fn resolve_rule_source_falls_back_to_builtin_when_no_default_given() {
    let source = resolve_rule_source(None, None);
    assert_eq!(source, RuleSource::BuiltInFallback);
}

#[cfg(unix)]
#[test]
fn load_rules_from_path_hash_tracks_loaded_content() {
    use std::ffi::CString;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let fifo_path = dir.path().join("rules.fifo");
    let fifo_cstr = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo_cstr` is a valid NUL-terminated C string and lives for the duration of
    // this call. The directory exists (created by `tempdir`) so `mkfifo` will not write OOB.
    let mkfifo_rc = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o600) };
    assert_eq!(
        mkfifo_rc,
        0,
        "mkfifo failed: {}",
        std::io::Error::last_os_error()
    );

    let first_yaml = r#"rules:
  - name: "fifo-first"
    regex: "sk_live_[a-z0-9]{24}"
    anchors: ["sk_live_"]
    radius: 64
"#;
    let second_yaml = r#"rules:
  - name: "fifo-second"
    regex: "ghp_[A-Za-z0-9]{36}"
    anchors: ["ghp_"]
    radius: 64
"#;
    let first_hash = crate::rules::rules_content_hash64(first_yaml.as_bytes());
    let second_hash = crate::rules::rules_content_hash64(second_yaml.as_bytes());

    let writer_fifo = fifo_path.clone();
    let first_payload = first_yaml.to_owned();
    let second_payload = second_yaml.to_owned();
    let writer = thread::spawn(move || -> bool {
        {
            let mut stream = OpenOptions::new().write(true).open(&writer_fifo).unwrap();
            stream.write_all(first_payload.as_bytes()).unwrap();
        }
        // Ensure reader #1 can observe EOF before probing reader #2.
        thread::sleep(Duration::from_millis(20));
        let writer_cstr = CString::new(writer_fifo.as_os_str().as_bytes()).unwrap();
        for _ in 0..100 {
            // SAFETY: `writer_cstr` is a valid NUL-terminated C string that outlives this call.
            let fd = unsafe { libc::open(writer_cstr.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            if fd >= 0 {
                // SAFETY: `fd` is a valid open file descriptor (checked `fd >= 0` above) and
                // ownership is transferred to the `File`, which will close it on drop.
                let mut stream = unsafe { File::from_raw_fd(fd) };
                stream.write_all(second_payload.as_bytes()).unwrap();
                return true;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENXIO) {
                panic!("unexpected second-write open error: {err}");
            }
            thread::sleep(Duration::from_millis(2));
        }
        false
    });

    let source = RuleSource::Explicit(fifo_path.clone());
    let (rules, observed_hash) = load_rules_from_path(&fifo_path, &source);
    let second_write_consumed = writer.join().unwrap();

    assert_eq!(rules.len(), 1, "test YAML contains exactly one rule");
    let expected_hash = match rules[0].name {
        "fifo-first" => first_hash,
        "fifo-second" => second_hash,
        other => panic!("unexpected loaded rule name: {other}"),
    };
    assert_eq!(
        observed_hash, expected_hash,
        "rule_hash must represent the bytes that were actually parsed"
    );
    assert_eq!(
        second_write_consumed,
        rules[0].name == "fifo-second",
        "second payload should only be consumed when a second read occurs"
    );
}

#[test]
fn filter_all_keeps_both() {
    let result = apply_transform_filter(test_transforms(), &TransformFilter::All);
    assert_eq!(
        ids(&result),
        vec![TransformId::UrlPercent, TransformId::Base64]
    );
}

#[test]
fn filter_none_returns_empty() {
    let result = apply_transform_filter(test_transforms(), &TransformFilter::None);
    assert!(result.is_empty());
}

#[test]
fn filter_only_base64() {
    let filter = TransformFilter::Only(vec![TransformId::Base64]);
    let result = apply_transform_filter(test_transforms(), &filter);
    assert_eq!(ids(&result), vec![TransformId::Base64]);
}

#[test]
fn filter_only_url() {
    let filter = TransformFilter::Only(vec![TransformId::UrlPercent]);
    let result = apply_transform_filter(test_transforms(), &filter);
    assert_eq!(ids(&result), vec![TransformId::UrlPercent]);
}

#[test]
fn filter_both_preserves_order() {
    let filter = TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64]);
    let result = apply_transform_filter(test_transforms(), &filter);
    assert_eq!(
        ids(&result),
        vec![TransformId::UrlPercent, TransformId::Base64]
    );
}

#[test]
fn filter_none_on_empty_input() {
    let result = apply_transform_filter(vec![], &TransformFilter::All);
    assert!(result.is_empty());
}

#[cfg(feature = "connector-pipeline")]
#[test]
fn run_fs_connector_rejects_persistence_until_wired() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.txt"), b"alpha").unwrap();
    let cfg = FsScanConfig {
        root: temp.path().to_path_buf(),
        workers: 2,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: true,
    };
    let err = run_fs_connector(
        Arc::new(crate::demo_engine()),
        &cfg,
        Arc::new(crate::unified::events::NullEventSink),
    )
    .expect_err("persist_findings should be rejected");
    assert!(err.to_string().contains("not yet supported"));
}

#[cfg(feature = "connector-pipeline")]
#[test]
fn run_fs_connector_scans_files_through_connector_pipeline() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.txt"), b"alpha").unwrap();
    std::fs::write(temp.path().join("b.txt"), b"beta").unwrap();
    let cfg = FsScanConfig {
        root: temp.path().to_path_buf(),
        workers: 2,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: false,
    };
    let report = run_fs_connector(
        Arc::new(crate::demo_engine()),
        &cfg,
        Arc::new(crate::unified::events::NullEventSink),
    )
    .expect("connector scan should succeed");
    assert_eq!(report.stats.files_enqueued, 2);
    assert!(report.metrics.bytes_scanned >= 9);
}

/// Verify that FS scans work regardless of whether the `connector-pipeline`
/// feature is enabled.  Without the feature the orchestrator must fall back
/// to `parallel_scan_dir` instead of returning an unconditional error.
#[cfg(not(feature = "connector-pipeline"))]
#[test]
fn run_fs_connector_fallback_scans_files_without_connector_feature() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.txt"), b"alpha").unwrap();
    std::fs::write(temp.path().join("b.txt"), b"beta").unwrap();
    let cfg = FsScanConfig {
        root: temp.path().to_path_buf(),
        workers: 2,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: false,
    };
    let report = run_fs_connector(
        Arc::new(crate::demo_engine()),
        &cfg,
        Arc::new(crate::unified::events::NullEventSink),
    )
    .expect("FS scan fallback should succeed without connector-pipeline feature");
    assert_eq!(report.stats.files_enqueued, 2);
    assert!(report.metrics.bytes_scanned >= 9);
}

#[test]
fn format_human_bytes_binary_units() {
    assert_eq!(format_human_bytes(0), "0B");
    assert_eq!(format_human_bytes(1023), "1023B");
    assert_eq!(format_human_bytes(1024), "1.00KiB");
    assert_eq!(format_human_bytes(1536), "1.50KiB");
    assert_eq!(format_human_bytes(1024 * 1024), "1.00MiB");
    assert_eq!(format_human_bytes(1024 * 1024 * 1024), "1.00GiB");
}

#[test]
fn parse_in_pack_object_count_extracts_value() {
    let text = "count: 0\nsize: 0\nin-pack: 11278814\npacks: 241\n";
    assert_eq!(parse_in_pack_object_count(text), Some(11_278_814));
}

#[test]
fn parse_in_pack_object_count_handles_missing_or_invalid_value() {
    assert_eq!(parse_in_pack_object_count("count: 0\npacks: 1\n"), None);
    assert_eq!(parse_in_pack_object_count("in-pack: not-a-number\n"), None);
}
