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
#[path = "factory_tests.rs"]
mod tests;
