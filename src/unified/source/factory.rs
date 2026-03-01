//! Source-to-connector factory for unified orchestration.
//!
//! The orchestrator calls [`build_connector`] as the single source wiring
//! entrypoint. Source-specific connector construction lives here so scheduler
//! orchestration stays source-agnostic.
//!
//! The filesystem connector eagerly walks the directory tree into a sorted
//! in-memory entry list, then serves `enumerate_page` via binary search for
//! O(log N) cursor resume. Each entry carries a weak version derived from
//! `(key, size, mtime)` and a stable item ID keyed by connector tag + item key.

#[cfg(not(unix))]
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

/// Hard safety cap to prevent OOM on extremely large directory trees.
const MAX_FS_ENTRIES: usize = 10_000_000;

/// Build a connector instance for a unified source configuration.
///
/// This function is the single source-wiring entrypoint used by unified
/// orchestration. Unsupported source variants return explicit actionable
/// errors rather than falling back to scheduler-specific paths.
pub fn build_connector(cfg: &SourceConfig) -> io::Result<Box<dyn ConnectorInstance>> {
    match cfg {
        SourceConfig::Fs(fs_cfg) => {
            let connector = FilesystemConnector::new(fs_cfg)?;
            Ok(Box::new(connector))
        }
        SourceConfig::Git(_) => Err(io::Error::other(
            "git source connector is not implemented yet",
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
    entries: Box<[FsEntry]>,
}

impl FilesystemConnector {
    /// Build a connector by eagerly walking the directory tree into memory.
    ///
    /// The full walk happens upfront so that `enumerate_page` can binary-search
    /// the sorted entry list for O(log N) cursor resume. For very large trees
    /// (millions of files), the upfront walk creates a memory spike — the
    /// connector contract supports lazy/streaming enumeration as a future
    /// optimization path.
    fn new(cfg: &FsScanConfig) -> io::Result<Self> {
        let mut entries = collect_filesystem_entries(&cfg.root)?;
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
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
            eprintln!("warn: filesystem connector: budget expired, returning empty page");
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
            let entry = &self.entries[idx];

            let hint = entry.size_hint.unwrap_or(0);
            if !out.is_empty() && hint > bytes_remaining {
                break;
            }
            bytes_remaining = bytes_remaining.saturating_sub(hint);

            let idx_u64 = u64::try_from(idx)
                .map_err(|_| EnumerateError::permanent("item index exceeds u64 capacity"))?;
            let item_ref = ItemRef::try_from_slice(&idx_u64.to_be_bytes())
                .map_err(|e| EnumerateError::permanent(format!("invalid item_ref: {e}")))?;
            let mut item = ScanItem::new(
                entry.key.clone(),
                item_ref,
                entry.stable_item_id,
                entry.version,
            );
            if let Some(sz) = entry.size_hint {
                item = item.with_size_hint(sz);
            }
            if let Some(loc) = entry.location.clone() {
                item = item.with_location(loc);
            }
            out.push(item);
            idx += 1;
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

        // Re-check file type to guard against TOCTOU races where the path
        // was replaced between enumerate and open.
        let meta = std::fs::symlink_metadata(&entry.path).map_err(map_io_error)?;
        if !meta.file_type().is_file() {
            return Err(ReadError::permanent("path is no longer a regular file"));
        }

        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&entry.path)
                .map_err(map_io_error)?
        };
        #[cfg(not(unix))]
        let file = File::open(&entry.path).map_err(map_io_error)?;
        Ok(Box::new(file))
    }
}

/// Discover every regular file under `root`.
///
/// Intentionally scans hidden files and ignores `.gitignore` rules:
/// a secret scanner must examine files like `.env`, `.aws/credentials`,
/// and `.npmrc` that are commonly gitignored or hidden.
fn collect_filesystem_entries(root: &Path) -> io::Result<Vec<FsEntry>> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);

    let mut entries = Vec::new();
    let mut version_buf = Vec::with_capacity(128);
    let mut walk_errors: u64 = 0;
    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                walk_errors += 1;
                eprintln!("warn: filesystem connector: skipped entry during discovery: {err}");
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
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => Some(m),
            Err(err) => {
                eprintln!(
                    "warn: filesystem connector: metadata failed for {}: {err}",
                    path.display()
                );
                None
            }
        };
        version_material(&mut version_buf, &key, metadata.as_ref());
        let version = VersionId::Weak(ObjectVersionId::from_version_bytes(&version_buf));
        let size_hint = metadata.as_ref().map(std::fs::Metadata::len);
        let location = match Location::try_new(display, None) {
            Ok(loc) => Some(loc),
            Err(err) => {
                eprintln!(
                    "warn: filesystem connector: location construction failed for {}: {err}",
                    path.display()
                );
                None
            }
        };

        entries.push(FsEntry {
            path,
            key,
            stable_item_id,
            version,
            size_hint,
            location,
        });
        if entries.len() >= MAX_FS_ENTRIES {
            return Err(io::Error::other(format!(
                "filesystem entry limit exceeded ({MAX_FS_ENTRIES}); \
                 narrow the scan root to a smaller directory tree",
            )));
        }
    }

    if walk_errors > 0 {
        eprintln!("warn: filesystem connector: {walk_errors} entries skipped due to walk errors");
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

/// Compose a weak version fingerprint from `(key, size, mtime)`.
///
/// The resulting bytes are hashed by [`ObjectVersionId::from_version_bytes`] to
/// produce a deterministic version token. When metadata is unavailable the
/// fingerprint degrades to key-only, so the item is still trackable but
/// version changes won't be detected until metadata becomes readable.
fn version_material(buf: &mut Vec<u8>, key: &ItemKey, metadata: Option<&std::fs::Metadata>) {
    buf.clear();
    buf.extend_from_slice(key.as_bytes());
    if let Some(metadata) = metadata {
        buf.extend_from_slice(&metadata.len().to_le_bytes());
        if let Ok(modified) = metadata.modified() {
            if let Ok(since_epoch) = modified.duration_since(UNIX_EPOCH) {
                buf.extend_from_slice(&since_epoch.as_nanos().to_le_bytes());
            }
        }
    }
}

/// Thin wrapper around the shared classifier in [`crate::scheduler::failure`]
/// with a filesystem-specific context string.
fn map_io_error(err: io::Error) -> ReadError {
    crate::scheduler::failure::classify_io_read_error(err, "filesystem read failed")
}

#[cfg(test)]
#[path = "factory_tests.rs"]
mod tests;
