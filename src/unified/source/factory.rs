//! Source-to-connector factory for unified orchestration.
//!
//! The orchestrator calls [`build_connector`] as the single source wiring
//! entrypoint. Source-specific connector construction lives here so scheduler
//! orchestration stays source-agnostic.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use gossip_contracts::connector::{
    Budgets, ConnectorCapabilities, ConnectorInstance, Cursor, EnumerateError,
    EnumerationConnector, EnumerationPage, ItemKey, ItemRef, Location, ReadConnector, ReadError,
    ScanItem, VersionId, MAX_ITEM_KEY_SIZE,
};
use gossip_contracts::coordination::ShardSpec;
use gossip_contracts::identity::{ConnectorTag, ItemIdentityKey, ObjectVersionId, StableItemId};

use crate::unified::{FsScanConfig, SourceConfig};

const FS_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"localfs");

/// Build a connector instance for a unified source configuration.
///
/// This function is the single source-wiring entrypoint used by unified
/// orchestration. Unsupported source variants return explicit actionable
/// errors rather than falling back to legacy scheduler-specific paths.
pub fn build_connector(cfg: &SourceConfig) -> io::Result<Box<dyn ConnectorInstance>> {
    match cfg {
        SourceConfig::Fs(fs_cfg) => {
            let connector = FilesystemConnector::new(fs_cfg)?;
            Ok(Box::new(connector))
        }
        SourceConfig::Git(_) => Err(io::Error::other(
            "git source connector is not implemented yet (follow-up: scratch-g7dk.12)",
        )),
        SourceConfig::Store(_) => Err(io::Error::other(
            "store commands are not connector-backed scan sources",
        )),
    }
}

#[derive(Clone, Debug)]
struct FsEntry {
    path: PathBuf,
    key: ItemKey,
    stable_item_id: StableItemId,
    version: VersionId,
    size_hint: Option<u64>,
    location: Option<Location>,
}

#[derive(Debug)]
struct FilesystemConnector {
    entries: Vec<FsEntry>,
}

impl FilesystemConnector {
    fn new(cfg: &FsScanConfig) -> io::Result<Self> {
        let mut entries = collect_filesystem_entries(&cfg.root)?;
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(Self { entries })
    }

    #[inline]
    fn lower_bound(&self, key: &[u8]) -> usize {
        self.entries
            .partition_point(|entry| entry.key.as_bytes() < key)
    }

    #[inline]
    fn upper_bound(&self, key: &[u8]) -> usize {
        self.entries
            .partition_point(|entry| entry.key.as_bytes() <= key)
    }

    fn shard_bound(bound: &[u8], label: &'static str) -> Result<Option<ItemKey>, EnumerateError> {
        if bound.is_empty() {
            return Ok(None);
        }
        ItemKey::try_from_slice(bound)
            .map(Some)
            .map_err(|err| EnumerateError::permanent(format!("invalid shard {label} bound: {err}")))
    }

    fn scan_item_for_index(&self, idx: usize) -> Result<ScanItem, EnumerateError> {
        let entry = self
            .entries
            .get(idx)
            .ok_or_else(|| EnumerateError::permanent("item index out of bounds"))?;

        let idx_u64 = u64::try_from(idx)
            .map_err(|_| EnumerateError::permanent("item index exceeds u64 capacity"))?;
        let item_ref = ItemRef::try_from_slice(&idx_u64.to_be_bytes())
            .map_err(|err| EnumerateError::permanent(format!("invalid item_ref: {err}")))?;

        let mut item = ScanItem::new(
            entry.key.clone(),
            item_ref,
            entry.stable_item_id,
            entry.version,
        );
        if let Some(size_hint) = entry.size_hint {
            item = item.with_size_hint(size_hint);
        }
        if let Some(location) = entry.location.clone() {
            item = item.with_location(location);
        }
        Ok(item)
    }

    fn item_index(item_ref: &ItemRef) -> Result<usize, ReadError> {
        let array: [u8; 8] = item_ref
            .as_bytes()
            .try_into()
            .map_err(|_| ReadError::permanent("invalid item_ref encoding"))?;
        let idx_u64 = u64::from_be_bytes(array);
        usize::try_from(idx_u64).map_err(|_| ReadError::permanent("item_ref index too large"))
    }
}

impl EnumerationConnector for FilesystemConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: false,
            range_read: false,
            split_hints: false,
        }
    }

    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        if budgets.is_expired_at(std::time::Instant::now()) {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let start = Self::shard_bound(shard.key_range_start(), "start")?;
        let end = Self::shard_bound(shard.key_range_end(), "end")?;

        let range_start = start
            .as_ref()
            .map_or(0usize, |bound| self.lower_bound(bound.as_bytes()));
        let range_end = end.as_ref().map_or(self.entries.len(), |bound| {
            self.lower_bound(bound.as_bytes())
        });

        let mut start_idx = range_start;
        if let Some(last_key) = cursor.last_key() {
            start_idx = start_idx.max(self.upper_bound(last_key.as_bytes()));
        }

        if start_idx >= range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let mut out = Vec::new();
        let mut idx = start_idx;
        let max_items = budgets.max_items();
        let mut bytes_remaining = budgets.max_bytes();
        while idx < range_end && out.len() < max_items {
            let entry = self
                .entries
                .get(idx)
                .ok_or_else(|| EnumerateError::permanent("item index out of bounds"))?;

            let hint = entry.size_hint.unwrap_or(0);
            if !out.is_empty() && hint > bytes_remaining {
                break;
            }
            bytes_remaining = bytes_remaining.saturating_sub(hint);
            out.push(self.scan_item_for_index(idx)?);
            idx += 1;
        }

        if out.is_empty() {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let last_key = out
            .last()
            .expect("non-empty page must have a final item")
            .item_key()
            .clone();
        Ok(EnumerationPage::new(out, Cursor::with_last_key(last_key)))
    }
}

impl ReadConnector for FilesystemConnector {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let idx = Self::item_index(item_ref)?;
        let entry = self
            .entries
            .get(idx)
            .ok_or_else(|| ReadError::permanent("item_ref out of bounds"))?;

        if let Some(size_hint) = entry.size_hint {
            if size_hint > budgets.max_bytes() {
                return Err(ReadError::permanent("item exceeds max_bytes budget"));
            }
        }

        let file = File::open(&entry.path).map_err(map_io_error)?;
        Ok(Box::new(file))
    }
}

fn collect_filesystem_entries(root: &Path) -> io::Result<Vec<FsEntry>> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);

    let mut entries = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("warn: filesystem connector discovery error: {err}");
                continue;
            }
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        let path = entry.into_path();
        let display = display_path(root, &path);
        let key = key_for_display(&display)?;
        let stable_item_id = ItemIdentityKey::new(FS_CONNECTOR_TAG, key.as_bytes()).stable_id();
        let metadata = std::fs::metadata(&path).ok();
        let version = VersionId::Weak(ObjectVersionId::from_version_bytes(&version_material(
            &key,
            metadata.as_ref(),
        )));
        let size_hint = metadata.as_ref().map(std::fs::Metadata::len);
        let location = Location::try_new(display, None).ok();

        entries.push(FsEntry {
            path,
            key,
            stable_item_id,
            version,
            size_hint,
            location,
        });
    }

    Ok(entries)
}

fn key_for_display(display: &str) -> io::Result<ItemKey> {
    if !display.is_empty() && display.len() <= MAX_ITEM_KEY_SIZE {
        return ItemKey::try_from_slice(display.as_bytes())
            .map_err(|err| io::Error::other(format!("failed to encode item key: {err}")));
    }

    let digest = blake3::hash(display.as_bytes());
    let fallback = format!("fs-hash:{}", digest.to_hex());
    ItemKey::try_from_slice(fallback.as_bytes())
        .map_err(|err| io::Error::other(format!("failed to encode fallback item key: {err}")))
}

fn display_path(root: &Path, path: &Path) -> String {
    let preferred = path
        .strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path);
    preferred.to_string_lossy().replace('\\', "/")
}

fn version_material(key: &ItemKey, metadata: Option<&std::fs::Metadata>) -> Vec<u8> {
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(key.as_bytes());
    if let Some(metadata) = metadata {
        material.extend_from_slice(&metadata.len().to_le_bytes());
        if let Ok(modified) = metadata.modified() {
            if let Ok(since_epoch) = modified.duration_since(UNIX_EPOCH) {
                material.extend_from_slice(&since_epoch.as_nanos().to_le_bytes());
            }
        }
    }
    material
}

fn map_io_error(err: io::Error) -> ReadError {
    match err.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::Unsupported => {
            ReadError::permanent(format!("filesystem read failed: {err}"))
        }
        _ => ReadError::retryable(format!("filesystem read failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;

    use gossip_contracts::connector::ErrorClass;
    use rstest::rstest;

    use crate::git_scan::{GitScanMode, MergeDiffMode};
    use crate::unified::{DebugLevel, GitSourceConfig, OutputFormat, StoreCommand};
    use crate::AnchorMode;

    // -- Helper: build a FilesystemConnector over a temp directory -----------

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

    // =====================================================================
    // Existing build_connector tests
    // =====================================================================

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

    // =====================================================================
    // rstest: map_io_error — permanent vs retryable classification
    // =====================================================================

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

    // =====================================================================
    // rstest: display_path — path normalization
    // =====================================================================

    #[rstest]
    #[case::relative_child("/a/b", "/a/b/c.txt", "c.txt")]
    #[case::nested_relative("/a/b", "/a/b/d/e.rs", "d/e.rs")]
    #[case::unrelated_path("/a/b", "/x/y.txt", "/x/y.txt")]
    #[case::path_equals_root("/a/b", "/a/b", "/a/b")]
    fn display_path_cases(#[case] root: &str, #[case] path: &str, #[case] expected: &str) {
        assert_eq!(display_path(Path::new(root), Path::new(path)), expected);
    }

    // =====================================================================
    // rstest: key_for_display — short path vs blake3 hash fallback
    // =====================================================================

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

    // =====================================================================
    // enumerate_page edge cases
    // =====================================================================

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

    // =====================================================================
    // ReadConnector::open
    // =====================================================================

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

    // =====================================================================
    // version_material determinism
    // =====================================================================

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
}
