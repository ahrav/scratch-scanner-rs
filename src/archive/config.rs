//! Archive scanning policy and hard limits.
//!
//! # Invariants
//! - All limits are hard bounds and must be internally consistent.
//! - Archives are treated as hostile input: sizes, counts, and paths are untrusted.
//!
//! # Design Notes
//! - Defaults are safety-first: archive scanning is enabled by default.
//! - Limits are shared across execution modes to keep behavior consistent.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Policy for how to treat encrypted archives or encrypted entries.
///
/// Policy choices are enforced in archive scanning paths (pipeline + scheduler).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum EncryptedPolicy {
    /// Skip encrypted content and increment telemetry counters.
    #[default]
    SkipWithTelemetry = 0,
    /// Treat the current archive as failed and continue scanning other roots.
    FailArchive = 1,
    /// Abort the entire scan.
    FailRun = 2,
}

/// Policy for how to treat unsupported archive formats or unsupported features.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum UnsupportedPolicy {
    /// Skip unsupported content and increment telemetry counters.
    #[default]
    SkipWithTelemetry = 0,
    /// Treat the current archive as failed and continue scanning other roots.
    FailArchive = 1,
    /// Abort the entire scan.
    FailRun = 2,
}

/// Shared archive scanning configuration (pipeline + scheduler).
///
/// All limits are hard bounds. Archive code must treat archive metadata and
/// payload as hostile: sizes, counts, paths, and offsets are untrusted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Master enable switch.
    ///
    /// When disabled, the scanner must behave exactly as before.
    pub enabled: bool,

    /// Maximum nested archive depth.
    pub max_archive_depth: u8,
    /// Maximum number of entries processed per archive.
    pub max_entries_per_archive: u32,
    /// Maximum decompressed bytes scanned for a single entry.
    pub max_uncompressed_bytes_per_entry: u64,
    /// Maximum total decompressed bytes scanned for a single archive.
    pub max_total_uncompressed_bytes_per_archive: u64,
    /// Maximum total decompressed bytes scanned for a root scan.
    pub max_total_uncompressed_bytes_per_root: u64,

    /// Maximum bytes of archive metadata parsed per archive.
    pub max_archive_metadata_bytes: u64,
    /// Maximum tolerated inflation ratio (best-effort).
    pub max_inflation_ratio: u32,

    /// Maximum virtual path length (bytes) per entry.
    pub max_virtual_path_len_per_entry: usize,
    /// Maximum total virtual path bytes stored per archive (pipeline path arena protection).
    pub max_virtual_path_bytes_per_archive: usize,

    /// Policy for encrypted content.
    pub encrypted_policy: EncryptedPolicy,
    /// Policy for unsupported content.
    pub unsupported_policy: UnsupportedPolicy,
}

/// Validation error returned by `ArchiveConfig::validate`.
///
/// Each variant corresponds to a violated invariant or ordering constraint.
/// Callers should treat this as a configuration bug (not hostile input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveConfigError {
    MaxArchiveDepthZero,
    MaxEntriesPerArchiveZero,
    MaxUncompressedBytesPerEntryZero,
    MaxTotalUncompressedBytesPerArchiveZero,
    MaxTotalUncompressedBytesPerRootZero,
    ArchiveBytesCapTooSmall {
        per_entry: u64,
        per_archive: u64,
    },
    RootBytesCapTooSmall {
        per_archive: u64,
        per_root: u64,
    },
    MaxArchiveMetadataBytesZero,
    MaxInflationRatioZero,
    MaxVirtualPathLenPerEntryZero,
    MaxVirtualPathBytesPerArchiveZero,
    PathBudgetTooSmall {
        per_entry: usize,
        per_archive: usize,
    },
}

impl fmt::Display for ArchiveConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveConfigError::MaxArchiveDepthZero => {
                write!(f, "max_archive_depth must be > 0")
            }
            ArchiveConfigError::MaxEntriesPerArchiveZero => {
                write!(f, "max_entries_per_archive must be > 0")
            }
            ArchiveConfigError::MaxUncompressedBytesPerEntryZero => {
                write!(f, "max_uncompressed_bytes_per_entry must be > 0")
            }
            ArchiveConfigError::MaxTotalUncompressedBytesPerArchiveZero => {
                write!(f, "max_total_uncompressed_bytes_per_archive must be > 0")
            }
            ArchiveConfigError::MaxTotalUncompressedBytesPerRootZero => {
                write!(f, "max_total_uncompressed_bytes_per_root must be > 0")
            }
            ArchiveConfigError::ArchiveBytesCapTooSmall {
                per_entry,
                per_archive,
            } => write!(
                f,
                "per-archive byte cap must be >= per-entry byte cap (entry={per_entry}, archive={per_archive})"
            ),
            ArchiveConfigError::RootBytesCapTooSmall {
                per_archive,
                per_root,
            } => write!(
                f,
                "per-root byte cap must be >= per-archive byte cap (archive={per_archive}, root={per_root})"
            ),
            ArchiveConfigError::MaxArchiveMetadataBytesZero => {
                write!(f, "max_archive_metadata_bytes must be > 0")
            }
            ArchiveConfigError::MaxInflationRatioZero => {
                write!(f, "max_inflation_ratio must be > 0")
            }
            ArchiveConfigError::MaxVirtualPathLenPerEntryZero => {
                write!(f, "max_virtual_path_len_per_entry must be > 0")
            }
            ArchiveConfigError::MaxVirtualPathBytesPerArchiveZero => {
                write!(f, "max_virtual_path_bytes_per_archive must be > 0")
            }
            ArchiveConfigError::PathBudgetTooSmall {
                per_entry,
                per_archive,
            } => write!(
                f,
                "per-archive path budget must be >= per-entry max length (entry={per_entry}, archive={per_archive})"
            ),
        }
    }
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,

            max_archive_depth: 3,
            max_entries_per_archive: 4096,
            max_uncompressed_bytes_per_entry: 64 * 1024 * 1024, // 64 MiB
            max_total_uncompressed_bytes_per_archive: 256 * 1024 * 1024, // 256 MiB
            max_total_uncompressed_bytes_per_root: 512 * 1024 * 1024, // 512 MiB

            max_archive_metadata_bytes: 16 * 1024 * 1024, // 16 MiB
            max_inflation_ratio: 128,

            max_virtual_path_len_per_entry: 1024,
            max_virtual_path_bytes_per_archive: 1024 * 1024, // 1 MiB

            encrypted_policy: EncryptedPolicy::SkipWithTelemetry,
            unsupported_policy: UnsupportedPolicy::SkipWithTelemetry,
        }
    }
}

impl ArchiveConfig {
    /// Validate cross-field invariants.
    ///
    /// This is intended to catch configuration mistakes early. It is cheap and
    /// should be called once at startup.
    ///
    pub fn validate(&self) -> Result<(), ArchiveConfigError> {
        // Always validate even when disabled, so configs can be checked in
        // tests without enabling the feature.
        if self.max_archive_depth == 0 {
            return Err(ArchiveConfigError::MaxArchiveDepthZero);
        }
        if self.max_entries_per_archive == 0 {
            return Err(ArchiveConfigError::MaxEntriesPerArchiveZero);
        }
        if self.max_uncompressed_bytes_per_entry == 0 {
            return Err(ArchiveConfigError::MaxUncompressedBytesPerEntryZero);
        }
        if self.max_total_uncompressed_bytes_per_archive == 0 {
            return Err(ArchiveConfigError::MaxTotalUncompressedBytesPerArchiveZero);
        }
        if self.max_total_uncompressed_bytes_per_root == 0 {
            return Err(ArchiveConfigError::MaxTotalUncompressedBytesPerRootZero);
        }
        if self.max_total_uncompressed_bytes_per_archive < self.max_uncompressed_bytes_per_entry {
            return Err(ArchiveConfigError::ArchiveBytesCapTooSmall {
                per_entry: self.max_uncompressed_bytes_per_entry,
                per_archive: self.max_total_uncompressed_bytes_per_archive,
            });
        }
        if self.max_total_uncompressed_bytes_per_root
            < self.max_total_uncompressed_bytes_per_archive
        {
            return Err(ArchiveConfigError::RootBytesCapTooSmall {
                per_archive: self.max_total_uncompressed_bytes_per_archive,
                per_root: self.max_total_uncompressed_bytes_per_root,
            });
        }
        if self.max_archive_metadata_bytes == 0 {
            return Err(ArchiveConfigError::MaxArchiveMetadataBytesZero);
        }
        if self.max_inflation_ratio == 0 {
            return Err(ArchiveConfigError::MaxInflationRatioZero);
        }
        if self.max_virtual_path_len_per_entry == 0 {
            return Err(ArchiveConfigError::MaxVirtualPathLenPerEntryZero);
        }
        if self.max_virtual_path_bytes_per_archive == 0 {
            return Err(ArchiveConfigError::MaxVirtualPathBytesPerArchiveZero);
        }
        if self.max_virtual_path_bytes_per_archive < self.max_virtual_path_len_per_entry {
            return Err(ArchiveConfigError::PathBudgetTooSmall {
                per_entry: self.max_virtual_path_len_per_entry,
                per_archive: self.max_virtual_path_bytes_per_archive,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_sane() {
        let cfg = ArchiveConfig::default();
        assert!(cfg.enabled);
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_inconsistent_byte_caps() {
        let cfg = ArchiveConfig {
            max_total_uncompressed_bytes_per_archive: 1,
            max_uncompressed_bytes_per_entry: 2,
            ..ArchiveConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            ArchiveConfigError::ArchiveBytesCapTooSmall { .. }
        ));
    }
}
