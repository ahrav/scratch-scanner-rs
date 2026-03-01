//! Tests for the filesystem connector factory.
//!
//! Covers `build_connector` dispatch, `enumerate_page` pagination/budget/shard
//! logic, `ReadConnector::open` roundtrips, pure helper functions, and
//! `map_io_error` permanent-vs-retryable classification.

use super::*;

use std::io::Read;

use gossip_contracts::connector::ErrorClass;
use rstest::rstest;

use crate::git_scan::{GitScanMode, MergeDiffMode};
use crate::unified::{DebugLevel, GitSourceConfig, OutputFormat, StoreCommand};
use crate::AnchorMode;

// -- Helper: build a FilesystemConnector over a temp directory ---------------

/// Create a temp directory with the given filenames and contents, returning
/// both the `tempfile::TempDir` (kept alive for RAII) and the connector.
fn connector_with_files(files: &[(&str, &[u8])]) -> (tempfile::TempDir, FilesystemConnector) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    for (name, data) in files {
        // Support nested paths.
        if let Some(parent) = Path::new(name).parent() {
            std::fs::create_dir_all(root.join(parent)).unwrap();
        }
        std::fs::write(root.join(name), data).unwrap();
    }
    let cfg = FsScanConfig {
        root,
        workers: 1,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: false,
    };
    let connector = FilesystemConnector::new(&cfg).unwrap();
    (tmp, connector)
}

// ===========================================================================
// build_connector dispatch
// ===========================================================================

#[test]
fn build_connector_fs_enumerates_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    std::fs::write(root.join("b.txt"), b"beta").unwrap();

    let cfg = SourceConfig::Fs(FsScanConfig {
        root: root.clone(),
        workers: 2,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: false,
    });

    let mut connector = build_connector(&cfg).expect("build fs connector");
    let page = connector
        .enumerate_page(
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            Budgets::try_new(100, u64::MAX, None).unwrap(),
        )
        .expect("enumerate first page");
    assert_eq!(page.items().len(), 2);
}

#[test]
fn build_connector_git_returns_explicit_error() {
    let cfg = SourceConfig::Git(GitSourceConfig {
        repo_root: PathBuf::from("."),
        repo_id: 1,
        scan_mode: GitScanMode::DiffHistory,
        merge_mode: MergeDiffMode::AllParents,
        anchor_mode: AnchorMode::Manual,
        decode_depth: None,
        pack_exec_workers: None,
        tree_delta_cache_mb: None,
        engine_chunk_mb: None,
        debug: DebugLevel::Off,
        scan_binary: false,
        enrich_identities: false,
    });

    let err = match build_connector(&cfg) {
        Ok(_) => panic!("git should be unsupported"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("not implemented"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_connector_store_returns_explicit_error() {
    let cfg = SourceConfig::Store(StoreCommand::ListRuns {
        store_dir: PathBuf::from("."),
        status: None,
        limit: 10,
        format: OutputFormat::Text,
    });
    let err = match build_connector(&cfg) {
        Ok(_) => panic!("store should be unsupported"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("not connector-backed"),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// rstest: map_io_error — permanent vs retryable classification
// ===========================================================================

#[rstest]
#[case::not_found(io::ErrorKind::NotFound, ErrorClass::Permanent)]
#[case::permission_denied(io::ErrorKind::PermissionDenied, ErrorClass::Permanent)]
#[case::invalid_input(io::ErrorKind::InvalidInput, ErrorClass::Permanent)]
#[case::invalid_data(io::ErrorKind::InvalidData, ErrorClass::Permanent)]
#[case::unsupported(io::ErrorKind::Unsupported, ErrorClass::Permanent)]
#[case::timed_out(io::ErrorKind::TimedOut, ErrorClass::Retryable)]
#[case::connection_reset(io::ErrorKind::ConnectionReset, ErrorClass::Retryable)]
#[case::interrupted(io::ErrorKind::Interrupted, ErrorClass::Retryable)]
#[case::would_block(io::ErrorKind::WouldBlock, ErrorClass::Retryable)]
fn io_error_classification(#[case] kind: io::ErrorKind, #[case] expected_class: ErrorClass) {
    let read_err = map_io_error(io::Error::new(kind, "test"));
    assert_eq!(
        read_err.class(),
        expected_class,
        "ErrorKind::{kind:?} should map to {expected_class:?}",
    );
}

// ===========================================================================
// rstest: display_path — path normalization
// ===========================================================================

#[rstest]
#[case::relative_child("/a/b", "/a/b/c.txt", "c.txt")]
#[case::nested_relative("/a/b", "/a/b/d/e.rs", "d/e.rs")]
#[case::unrelated_path("/a/b", "/x/y.txt", "/x/y.txt")]
#[case::path_equals_root("/a/b", "/a/b", "/a/b")]
fn display_path_cases(#[case] root: &str, #[case] path: &str, #[case] expected: &str) {
    assert_eq!(display_path(Path::new(root), Path::new(path)), expected);
}

// ===========================================================================
// rstest: key_for_display — short path vs blake3 hash fallback
// ===========================================================================

#[rstest]
#[case::short_path("hello.txt", false)]
#[case::at_limit(&"x".repeat(MAX_ITEM_KEY_SIZE), false)]
#[case::over_limit(&"x".repeat(MAX_ITEM_KEY_SIZE + 1), true)]
fn key_for_display_fallback(#[case] display: &str, #[case] expect_hash_prefix: bool) {
    let key = key_for_display(display).unwrap();
    let text = std::str::from_utf8(key.as_bytes()).expect("key should be valid UTF-8");
    assert_eq!(
        text.starts_with("fs-hash:"),
        expect_hash_prefix,
        "display len={}, key={text}",
        display.len(),
    );
}

#[test]
fn key_for_display_empty_string_uses_hash() {
    // Empty string fails the `!display.is_empty()` check, so it falls
    // through to the blake3 hash branch.
    let key = key_for_display("").unwrap();
    let text = std::str::from_utf8(key.as_bytes()).unwrap();
    assert!(
        text.starts_with("fs-hash:"),
        "empty display should use hash fallback, got: {text}",
    );
}

#[test]
fn key_for_display_deterministic() {
    let display = "some/path/to/file.rs";
    let k1 = key_for_display(display).unwrap();
    let k2 = key_for_display(display).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

// ===========================================================================
// enumerate_page edge cases
// ===========================================================================

#[test]
fn enumerate_page_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("empty");
    std::fs::create_dir_all(&root).unwrap();

    let cfg = FsScanConfig {
        root,
        workers: 1,
        decode_depth: None,
        skip_archives: false,
        anchor_mode: AnchorMode::Manual,
        scan_binary: false,
        persist_findings: false,
    };
    let mut conn = FilesystemConnector::new(&cfg).unwrap();
    let page = conn
        .enumerate_page(
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            Budgets::try_new(100, u64::MAX, None).unwrap(),
        )
        .unwrap();
    assert!(page.items().is_empty());
}

#[test]
fn enumerate_page_expired_budget_returns_empty() {
    let (_tmp, mut conn) = connector_with_files(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);

    // Deadline already in the past.
    let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let budgets = Budgets::try_new(100, u64::MAX, Some(expired)).unwrap();
    let page = conn
        .enumerate_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets)
        .unwrap();
    assert!(
        page.items().is_empty(),
        "expired budget should yield empty page",
    );
}

#[test]
fn enumerate_page_max_items_budget() {
    let (_tmp, mut conn) =
        connector_with_files(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);

    // Request at most 1 item per page.
    let page = conn
        .enumerate_page(
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            Budgets::try_new(1, u64::MAX, None).unwrap(),
        )
        .unwrap();
    assert_eq!(page.items().len(), 1, "should respect max_items=1");

    // The cursor should allow resumption.
    assert!(
        page.next_cursor().last_key().is_some(),
        "non-empty page must produce a cursor with last_key",
    );
}

#[test]
fn enumerate_page_cursor_resume_skips_prior_items() {
    let (_tmp, mut conn) =
        connector_with_files(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);

    let shard = ShardSpec::unbounded();
    let budget = Budgets::try_new(1, u64::MAX, None).unwrap();

    // Page 1.
    let p1 = conn
        .enumerate_page(&shard, &Cursor::initial(), budget)
        .unwrap();
    assert_eq!(p1.items().len(), 1);

    // Page 2: resume from cursor of page 1.
    let budget = Budgets::try_new(1, u64::MAX, None).unwrap();
    let p2 = conn
        .enumerate_page(&shard, p1.next_cursor(), budget)
        .unwrap();
    assert_eq!(p2.items().len(), 1);

    // The two pages must return different keys.
    assert_ne!(
        p1.items()[0].item_key().as_bytes(),
        p2.items()[0].item_key().as_bytes(),
        "cursor resume should advance past previously returned items",
    );
}

#[test]
fn enumerate_page_multi_page_exhaust() {
    let (_tmp, mut conn) =
        connector_with_files(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);

    let shard = ShardSpec::unbounded();
    let mut cursor = Cursor::initial();
    let mut all_keys = Vec::new();

    // Drain one item at a time until we get an empty page.
    for _ in 0..10 {
        let budget = Budgets::try_new(1, u64::MAX, None).unwrap();
        let page = conn.enumerate_page(&shard, &cursor, budget).unwrap();
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            all_keys.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    assert_eq!(all_keys.len(), 3, "should have enumerated all 3 files");

    // Keys must be sorted (connector sorts by key on construction).
    let mut sorted = all_keys.clone();
    sorted.sort();
    assert_eq!(all_keys, sorted, "keys should be yielded in sorted order");

    // No duplicates.
    sorted.dedup();
    assert_eq!(sorted.len(), 3, "must not return duplicate keys");
}

#[test]
fn enumerate_page_max_bytes_budget_stops_early() {
    // Create one small file and one large file.
    let small_data = b"tiny";
    let large_data = vec![0xAA; 8192];
    let (_tmp, mut conn) =
        connector_with_files(&[("a.txt", small_data), ("z_big.txt", &large_data)]);

    // Budget: enough for the small file but not the large one after it.
    // The first item is always emitted regardless of bytes, but the second
    // should be skipped if its size_hint exceeds the remaining budget.
    let budget = Budgets::try_new(100, 100, None).unwrap();
    let page = conn
        .enumerate_page(&ShardSpec::unbounded(), &Cursor::initial(), budget)
        .unwrap();

    // Should get only the first item (the small file), because the large
    // file's size_hint exceeds remaining bytes.
    assert_eq!(
        page.items().len(),
        1,
        "should stop before the second item when bytes budget is exhausted",
    );
}

#[test]
fn enumerate_page_shard_bounds_filter_entries() {
    let (_tmp, mut conn) = connector_with_files(&[
        ("a.txt", b"aaa"),
        ("b.txt", b"bbb"),
        ("c.txt", b"ccc"),
        ("d.txt", b"ddd"),
    ]);

    // Create a shard that only includes keys starting with "b" or "c".
    // Since entries are keyed by relative path, we use the path strings.
    let shard = ShardSpec::with_range(b"b", b"d");
    let page = conn
        .enumerate_page(
            &shard,
            &Cursor::initial(),
            Budgets::try_new(100, u64::MAX, None).unwrap(),
        )
        .unwrap();

    let keys: Vec<String> = page
        .items()
        .iter()
        .map(|item| String::from_utf8_lossy(item.item_key().as_bytes()).into_owned())
        .collect();

    // The half-open range [b, d) should include "b.txt" and "c.txt" but
    // exclude "a.txt" and "d.txt".
    assert_eq!(keys.len(), 2, "shard [b, d) should yield 2 items: {keys:?}");
    assert!(
        keys.iter().all(|k| k.as_str() >= "b" && k.as_str() < "d"),
        "all keys should be in [b, d): {keys:?}",
    );
}

// ===========================================================================
// ReadConnector::open
// ===========================================================================

#[test]
fn open_roundtrip_reads_file_contents() {
    let (_tmp, mut conn) = connector_with_files(&[("hello.txt", b"world")]);

    // Enumerate to get the item_ref.
    let page = conn
        .enumerate_page(
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            Budgets::try_new(10, u64::MAX, None).unwrap(),
        )
        .unwrap();
    assert_eq!(page.items().len(), 1);

    let item = &page.items()[0];
    let item_ref = item.item_ref();
    let budget = Budgets::try_new(10, u64::MAX, None).unwrap();

    let mut reader = conn.open(item_ref, budget).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"world");
}

#[test]
fn open_budget_exceeded_returns_permanent_error() {
    let (_tmp, mut conn) = connector_with_files(&[("big.txt", &[0u8; 1024])]);

    let page = conn
        .enumerate_page(
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            Budgets::try_new(10, u64::MAX, None).unwrap(),
        )
        .unwrap();
    assert_eq!(page.items().len(), 1);

    let item_ref_bytes = page.items()[0].item_ref().as_bytes().to_vec();
    let item_ref = ItemRef::try_from_slice(&item_ref_bytes).unwrap();

    // Budget smaller than the file size.
    let budget = Budgets::try_new(10, 100, None).unwrap();
    let err = match conn.open(&item_ref, budget) {
        Ok(_) => panic!("open should fail when budget is exceeded"),
        Err(e) => e,
    };
    assert!(
        !err.is_retryable(),
        "budget exceeded should be a permanent error",
    );
    assert!(
        err.message().contains("exceeds max_bytes"),
        "unexpected error message: {}",
        err.message(),
    );
}

#[test]
fn open_invalid_item_ref_returns_permanent_error() {
    let (_tmp, mut conn) = connector_with_files(&[("a.txt", b"data")]);

    // Forge an item_ref with garbage bytes (wrong length for u64 decode).
    let bad_ref = ItemRef::try_from_slice(b"bad").unwrap();
    let budget = Budgets::try_new(10, u64::MAX, None).unwrap();

    let err = match conn.open(&bad_ref, budget) {
        Ok(_) => panic!("open should fail with invalid item_ref"),
        Err(e) => e,
    };
    assert!(
        !err.is_retryable(),
        "invalid item_ref should be a permanent error",
    );
}

// ===========================================================================
// version_material determinism
// ===========================================================================

#[test]
fn version_material_deterministic_without_metadata() {
    let key = ItemKey::try_from_slice(b"test/path.rs").unwrap();
    let v1 = version_material(&key, None);
    let v2 = version_material(&key, None);
    assert_eq!(v1, v2, "version_material must be deterministic");
}

#[test]
fn version_material_includes_key_bytes() {
    let key = ItemKey::try_from_slice(b"my/file.txt").unwrap();
    let mat = version_material(&key, None);
    assert!(
        mat.starts_with(b"my/file.txt"),
        "version material should start with the key bytes",
    );
}

// ===========================================================================
// Property tests — key_for_display invariants over the full input domain
// ===========================================================================

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Output is always a valid `ItemKey` (non-empty, within size limit)
        /// regardless of input length.
        #[test]
        fn key_for_display_always_valid(display in "[a-zA-Z0-9/_.-]{1,8200}") {
            let key = key_for_display(&display).unwrap();
            prop_assert!(!key.as_bytes().is_empty(), "key must be non-empty");
            prop_assert!(
                key.as_bytes().len() <= MAX_ITEM_KEY_SIZE,
                "key len {} exceeds MAX_ITEM_KEY_SIZE {MAX_ITEM_KEY_SIZE}",
                key.as_bytes().len(),
            );
        }

        /// Same input always produces the same key.
        #[test]
        fn key_for_display_is_deterministic(display in "[a-zA-Z0-9/_.-]{1,500}") {
            let k1 = key_for_display(&display).unwrap();
            let k2 = key_for_display(&display).unwrap();
            prop_assert_eq!(k1.as_bytes(), k2.as_bytes());
        }

        /// The hash-fallback branch always produces keys starting with "fs-hash:".
        #[test]
        fn key_for_display_long_paths_use_hash_prefix(
            display in "[a-zA-Z0-9/_.-]{4097,8200}"
        ) {
            let key = key_for_display(&display).unwrap();
            let text = std::str::from_utf8(key.as_bytes()).unwrap();
            prop_assert!(
                text.starts_with("fs-hash:"),
                "long path (len={}) should use hash fallback, got: {text}",
                display.len(),
            );
        }

        /// version_material is deterministic for a given key (without metadata).
        #[test]
        fn version_material_deterministic(key_str in "[a-zA-Z0-9/_.-]{1,200}") {
            let key = ItemKey::try_from_slice(key_str.as_bytes()).unwrap();
            let v1 = version_material(&key, None);
            let v2 = version_material(&key, None);
            prop_assert_eq!(v1, v2);
        }

        /// version_material output starts with the key bytes.
        #[test]
        fn version_material_starts_with_key(key_str in "[a-zA-Z0-9/_.-]{1,200}") {
            let key = ItemKey::try_from_slice(key_str.as_bytes()).unwrap();
            let mat = version_material(&key, None);
            prop_assert!(
                mat.starts_with(key.as_bytes()),
                "material should start with key bytes",
            );
        }
    }
}
