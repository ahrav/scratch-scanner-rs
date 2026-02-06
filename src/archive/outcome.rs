//! Stable, explicit outcome codes for archive scanning.
//!
//! # Invariants
//! - Enums are `#[repr(u8)]` with stable discriminants; new variants must be appended.
//! - `COUNT` constants must match the last variant + 1.
//! - Counters are fixed arrays indexed by the enum discriminant.
//! - Samples are bounded and store only a path prefix (never unbounded strings).
//!
//! # Design Notes
//! - This module is intentionally allocation-free on hot paths.
//! - Bounded samples make skip/partial behavior observable without log spam.
//! - Reasons are part of the public surface; changing them is a semver-ish event.

#![allow(dead_code)]

use core::fmt;

// -----------------------------
// Reasons (stable taxonomy)
// -----------------------------

/// Why an entire archive was skipped.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveSkipReason {
    /// Archive scanning disabled by configuration.
    Disabled = 0,
    /// Format not supported (e.g., 7z) or could not be detected.
    UnsupportedFormat = 1,
    /// Archive indicates encryption in a way that prevents scanning.
    EncryptedArchive = 2,
    /// Nested archive depth exceeded `ArchiveConfig::max_archive_depth`.
    DepthExceeded = 3,
    /// Entry count exceeded `ArchiveConfig::max_entries_per_archive`.
    EntryCountExceeded = 4,
    /// Metadata budget exceeded `ArchiveConfig::max_archive_metadata_bytes`.
    MetadataBudgetExceeded = 5,
    /// Pipeline path budget exceeded while creating virtual entry paths.
    PathBudgetExceeded = 6,
    /// Total decompressed output exceeded `max_total_uncompressed_bytes_per_archive`.
    ArchiveOutputBudgetExceeded = 7,
    /// Root decompressed output exceeded `max_total_uncompressed_bytes_per_root`.
    RootOutputBudgetExceeded = 8,
    /// Inflation ratio exceeded `max_inflation_ratio` (best-effort).
    InflationRatioExceeded = 9,
    /// Nested archive requires random access but spill/materialization is not available.
    NeedsRandomAccessNoSpill = 10,
    /// I/O error while reading archive bytes.
    IoError = 11,
    /// Corrupt/malformed archive container.
    Corrupt = 12,
    /// Unsupported container feature (e.g., Zip64 without support).
    UnsupportedFeature = 13,
}

impl ArchiveSkipReason {
    pub const COUNT: usize = 14;

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UnsupportedFormat => "unsupported_format",
            Self::EncryptedArchive => "encrypted_archive",
            Self::DepthExceeded => "depth_exceeded",
            Self::EntryCountExceeded => "entry_count_exceeded",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::PathBudgetExceeded => "path_budget_exceeded",
            Self::ArchiveOutputBudgetExceeded => "archive_output_budget_exceeded",
            Self::RootOutputBudgetExceeded => "root_output_budget_exceeded",
            Self::InflationRatioExceeded => "inflation_ratio_exceeded",
            Self::NeedsRandomAccessNoSpill => "needs_random_access_no_spill",
            Self::IoError => "io_error",
            Self::Corrupt => "corrupt",
            Self::UnsupportedFeature => "unsupported_feature",
        }
    }
}

/// Why a specific archive entry was skipped.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntrySkipReason {
    /// The entry is not a regular file (dir, symlink, device, etc.).
    NonRegular = 0,
    /// Entry path metadata is malformed or exceeds configured component/length caps.
    MalformedPath = 1,
    /// Entry is encrypted.
    EncryptedEntry = 2,
    /// Entry uses an unsupported compression method.
    UnsupportedCompression = 3,
    /// Entry's uncompressed size exceeds `max_uncompressed_bytes_per_entry`.
    EntryOutputBudgetExceeded = 4,
    /// Entry payload is corrupt (e.g., CRC mismatch, invalid stream).
    CorruptPayload = 5,
    /// Entry metadata is corrupt or points outside archive bounds.
    CorruptEntry = 6,
    /// I/O error while reading entry payload bytes.
    IoError = 7,
    /// Unsupported entry feature (e.g., data descriptor without streaming support).
    UnsupportedFeature = 8,
}

impl EntrySkipReason {
    pub const COUNT: usize = 9;

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::NonRegular => "non_regular",
            Self::MalformedPath => "malformed_path",
            Self::EncryptedEntry => "encrypted_entry",
            Self::UnsupportedCompression => "unsupported_compression",
            Self::EntryOutputBudgetExceeded => "entry_output_budget_exceeded",
            Self::CorruptPayload => "corrupt_payload",
            Self::CorruptEntry => "corrupt_entry",
            Self::IoError => "io_error",
            Self::UnsupportedFeature => "unsupported_feature",
        }
    }
}

/// Why an archive was only partially scanned.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartialReason {
    /// Metadata parsing hit budget cap.
    MetadataBudgetExceeded = 0,
    /// Path storage hit budget cap.
    PathBudgetExceeded = 1,
    /// Per-entry output budget hit (some bytes in entry may have been scanned).
    EntryOutputBudgetExceeded = 2,
    /// Per-archive output budget hit.
    ArchiveOutputBudgetExceeded = 3,
    /// Per-root output budget hit.
    RootOutputBudgetExceeded = 4,
    /// Inflation ratio exceeded (best-effort).
    InflationRatioExceeded = 5,
    /// gzip stream corrupted mid-stream (bytes already produced were scanned).
    GzipCorrupt = 6,
    /// tar container malformed mid-stream.
    MalformedTar = 7,
    /// zip container malformed mid-scan.
    MalformedZip = 8,
    /// Entry count cap hit after scanning began (stop expanding further entries).
    EntryCountExceeded = 9,
    /// Unsupported container feature (e.g., Zip64 sentinel in CDFH).
    UnsupportedFeature = 10,
}

impl PartialReason {
    pub const COUNT: usize = 11;

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::PathBudgetExceeded => "path_budget_exceeded",
            Self::EntryOutputBudgetExceeded => "entry_output_budget_exceeded",
            Self::ArchiveOutputBudgetExceeded => "archive_output_budget_exceeded",
            Self::RootOutputBudgetExceeded => "root_output_budget_exceeded",
            Self::InflationRatioExceeded => "inflation_ratio_exceeded",
            Self::GzipCorrupt => "gzip_corrupt",
            Self::MalformedTar => "malformed_tar",
            Self::MalformedZip => "malformed_zip",
            Self::EntryCountExceeded => "entry_count_exceeded",
            Self::UnsupportedFeature => "unsupported_feature",
        }
    }
}

// Keep these arrays aligned with discriminant order; merge/formatting iterate
// reasons explicitly and tests assert the alignment.
const ARCHIVE_SKIP_REASONS: [ArchiveSkipReason; ArchiveSkipReason::COUNT] = [
    ArchiveSkipReason::Disabled,
    ArchiveSkipReason::UnsupportedFormat,
    ArchiveSkipReason::EncryptedArchive,
    ArchiveSkipReason::DepthExceeded,
    ArchiveSkipReason::EntryCountExceeded,
    ArchiveSkipReason::MetadataBudgetExceeded,
    ArchiveSkipReason::PathBudgetExceeded,
    ArchiveSkipReason::ArchiveOutputBudgetExceeded,
    ArchiveSkipReason::RootOutputBudgetExceeded,
    ArchiveSkipReason::InflationRatioExceeded,
    ArchiveSkipReason::NeedsRandomAccessNoSpill,
    ArchiveSkipReason::IoError,
    ArchiveSkipReason::Corrupt,
    ArchiveSkipReason::UnsupportedFeature,
];

const ENTRY_SKIP_REASONS: [EntrySkipReason; EntrySkipReason::COUNT] = [
    EntrySkipReason::NonRegular,
    EntrySkipReason::MalformedPath,
    EntrySkipReason::EncryptedEntry,
    EntrySkipReason::UnsupportedCompression,
    EntrySkipReason::EntryOutputBudgetExceeded,
    EntrySkipReason::CorruptPayload,
    EntrySkipReason::CorruptEntry,
    EntrySkipReason::IoError,
    EntrySkipReason::UnsupportedFeature,
];

const PARTIAL_REASONS: [PartialReason; PartialReason::COUNT] = [
    PartialReason::MetadataBudgetExceeded,
    PartialReason::PathBudgetExceeded,
    PartialReason::EntryOutputBudgetExceeded,
    PartialReason::ArchiveOutputBudgetExceeded,
    PartialReason::RootOutputBudgetExceeded,
    PartialReason::InflationRatioExceeded,
    PartialReason::GzipCorrupt,
    PartialReason::MalformedTar,
    PartialReason::MalformedZip,
    PartialReason::EntryCountExceeded,
    PartialReason::UnsupportedFeature,
];

// -----------------------------
// Bounded samples (optional)
// -----------------------------

/// Classifies a bounded sample by granularity (archive vs entry) and
/// outcome (skipped vs partial).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleKind {
    ArchiveSkipped = 0,
    ArchivePartial = 1,
    EntrySkipped = 2,
    EntryPartial = 3,
}

impl SampleKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArchiveSkipped => "archive_skipped",
            Self::ArchivePartial => "archive_partial",
            Self::EntrySkipped => "entry_skipped",
            Self::EntryPartial => "entry_partial",
        }
    }
}

/// Maximum samples retained in an [`ArchiveSampleRing`].
pub const ARCHIVE_SAMPLE_MAX: usize = 32;
/// Maximum path prefix bytes stored per sample (truncated beyond this).
pub const ARCHIVE_SAMPLE_PATH_PREFIX_MAX: usize = 192;

/// Bounded sample of a skip/partial outcome with a path prefix.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveSample {
    pub kind: SampleKind,
    /// Reason enum discriminant (ArchiveSkipReason/EntrySkipReason/PartialReason).
    pub reason: u8,
    pub path_len: u16,
    pub path_prefix: [u8; ARCHIVE_SAMPLE_PATH_PREFIX_MAX],
}

impl ArchiveSample {
    pub const EMPTY: Self = Self {
        kind: SampleKind::ArchiveSkipped,
        reason: 0,
        path_len: 0,
        path_prefix: [0u8; ARCHIVE_SAMPLE_PATH_PREFIX_MAX],
    };

    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        &self.path_prefix[..self.path_len as usize]
    }
}

/// Fixed-size sample buffer for skipped/partial outcomes.
///
/// # Guarantees
/// - Stores at most `ARCHIVE_SAMPLE_MAX` samples.
/// - Never allocates; path bytes are truncated to `ARCHIVE_SAMPLE_PATH_PREFIX_MAX`.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveSampleRing {
    pub len: u8,
    pub dropped: u64,
    pub items: [ArchiveSample; ARCHIVE_SAMPLE_MAX],
}

impl Default for ArchiveSampleRing {
    fn default() -> Self {
        Self {
            len: 0,
            dropped: 0,
            items: [ArchiveSample::EMPTY; ARCHIVE_SAMPLE_MAX],
        }
    }
}

impl ArchiveSampleRing {
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, ArchiveSample> {
        self.items[..self.len as usize].iter()
    }

    /// Insert a sample if capacity remains; otherwise increments `dropped`.
    #[inline]
    pub fn push(&mut self, kind: SampleKind, reason: u8, path: &[u8]) {
        let idx = self.len as usize;
        if idx >= ARCHIVE_SAMPLE_MAX {
            self.dropped = self.dropped.wrapping_add(1);
            return;
        }

        let mut s = ArchiveSample::EMPTY;
        s.kind = kind;
        s.reason = reason;

        let n = path.len().min(ARCHIVE_SAMPLE_PATH_PREFIX_MAX);
        s.path_prefix[..n].copy_from_slice(&path[..n]);
        s.path_len = n as u16;

        self.items[idx] = s;
        self.len = self.len.wrapping_add(1);
    }

    /// Merge samples from another ring, preserving the local capacity cap.
    pub fn merge_from(&mut self, other: &ArchiveSampleRing) {
        for s in other.iter() {
            self.push(s.kind, s.reason, s.path_bytes());
        }
        self.dropped = self.dropped.wrapping_add(other.dropped);
    }
}

// -----------------------------
// Aggregate stats
// -----------------------------

/// Aggregate archive outcomes + bounded samples.
///
/// # Guarantees
/// - Counters are monotonic (wrapping on overflow).
/// - Arrays are indexed by the stable reason discriminants.
/// - Recording/merge operations mutate counters only when
///   `all(feature = "perf-stats", debug_assertions)` is enabled.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveStats {
    pub archives_seen: u64,
    pub archives_scanned: u64,
    pub archives_skipped: u64,
    pub archives_partial: u64,
    pub entries_scanned: u64,
    pub entries_skipped: u64,
    pub paths_truncated: u64,
    pub paths_had_traversal: u64,
    pub paths_component_cap_exceeded: u64,

    pub archive_skip_reasons: [u64; ArchiveSkipReason::COUNT],
    pub entry_skip_reasons: [u64; EntrySkipReason::COUNT],
    pub partial_reasons: [u64; PartialReason::COUNT],

    pub samples: ArchiveSampleRing,
}

impl Default for ArchiveStats {
    fn default() -> Self {
        Self {
            archives_seen: 0,
            archives_scanned: 0,
            archives_skipped: 0,
            archives_partial: 0,
            entries_scanned: 0,
            entries_skipped: 0,
            paths_truncated: 0,
            paths_had_traversal: 0,
            paths_component_cap_exceeded: 0,
            archive_skip_reasons: [0; ArchiveSkipReason::COUNT],
            entry_skip_reasons: [0; EntrySkipReason::COUNT],
            partial_reasons: [0; PartialReason::COUNT],
            samples: ArchiveSampleRing::default(),
        }
    }
}

impl ArchiveStats {
    #[inline(always)]
    fn recording_enabled() -> bool {
        cfg!(all(feature = "perf-stats", debug_assertions))
    }

    #[inline]
    pub fn has_activity(&self) -> bool {
        self.archives_seen != 0
            || self.archives_scanned != 0
            || self.archives_skipped != 0
            || self.archives_partial != 0
            || self.entries_scanned != 0
            || self.entries_skipped != 0
            || self.paths_truncated != 0
            || self.paths_had_traversal != 0
            || self.paths_component_cap_exceeded != 0
    }

    #[inline]
    pub fn record_archive_seen(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.archives_seen = self.archives_seen.wrapping_add(1);
    }

    #[inline]
    pub fn record_archive_scanned(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.archives_scanned = self.archives_scanned.wrapping_add(1);
    }

    #[inline]
    pub fn record_archive_skipped(
        &mut self,
        reason: ArchiveSkipReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.archives_skipped = self.archives_skipped.wrapping_add(1);
        let idx = reason.as_usize();
        self.archive_skip_reasons[idx] = self.archive_skip_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::ArchiveSkipped, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_archive_partial(
        &mut self,
        reason: PartialReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.archives_partial = self.archives_partial.wrapping_add(1);
        let idx = reason.as_usize();
        self.partial_reasons[idx] = self.partial_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::ArchivePartial, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_entry_scanned(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.entries_scanned = self.entries_scanned.wrapping_add(1);
    }

    #[inline]
    pub fn record_entry_skipped(
        &mut self,
        reason: EntrySkipReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.entries_skipped = self.entries_skipped.wrapping_add(1);
        let idx = reason.as_usize();
        self.entry_skip_reasons[idx] = self.entry_skip_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::EntrySkipped, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_entry_partial(
        &mut self,
        reason: PartialReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        let idx = reason.as_usize();
        self.partial_reasons[idx] = self.partial_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::EntryPartial, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_path_truncated(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_truncated = self.paths_truncated.wrapping_add(1);
    }

    #[inline]
    pub fn record_path_had_traversal(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_had_traversal = self.paths_had_traversal.wrapping_add(1);
    }

    #[inline]
    pub fn record_component_cap_exceeded(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_component_cap_exceeded = self.paths_component_cap_exceeded.wrapping_add(1);
    }

    /// Merge counters and bounded samples from another stats instance.
    ///
    /// All counters are merged via wrapping addition; samples respect the
    /// local `ARCHIVE_SAMPLE_MAX` capacity.
    pub fn merge_from(&mut self, other: &ArchiveStats) {
        if !Self::recording_enabled() {
            let _ = other;
            return;
        }
        self.archives_seen = self.archives_seen.wrapping_add(other.archives_seen);
        self.archives_scanned = self.archives_scanned.wrapping_add(other.archives_scanned);
        self.archives_skipped = self.archives_skipped.wrapping_add(other.archives_skipped);
        self.archives_partial = self.archives_partial.wrapping_add(other.archives_partial);
        self.entries_scanned = self.entries_scanned.wrapping_add(other.entries_scanned);
        self.entries_skipped = self.entries_skipped.wrapping_add(other.entries_skipped);
        self.paths_truncated = self.paths_truncated.wrapping_add(other.paths_truncated);
        self.paths_had_traversal = self
            .paths_had_traversal
            .wrapping_add(other.paths_had_traversal);
        self.paths_component_cap_exceeded = self
            .paths_component_cap_exceeded
            .wrapping_add(other.paths_component_cap_exceeded);

        for r in ARCHIVE_SKIP_REASONS.iter() {
            let idx = r.as_usize();
            self.archive_skip_reasons[idx] =
                self.archive_skip_reasons[idx].wrapping_add(other.archive_skip_reasons[idx]);
        }
        for r in ENTRY_SKIP_REASONS.iter() {
            let idx = r.as_usize();
            self.entry_skip_reasons[idx] =
                self.entry_skip_reasons[idx].wrapping_add(other.entry_skip_reasons[idx]);
        }
        for r in PARTIAL_REASONS.iter() {
            let idx = r.as_usize();
            self.partial_reasons[idx] =
                self.partial_reasons[idx].wrapping_add(other.partial_reasons[idx]);
        }

        self.samples.merge_from(&other.samples);
    }

    /// Render a compact reason table for diagnostics/debug output.
    pub fn fmt_reason_table(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "archive_skip_reasons:")?;
        for r in ARCHIVE_SKIP_REASONS.iter() {
            let n = self.archive_skip_reasons[r.as_usize()];
            if n != 0 {
                writeln!(f, "  {}={}", r.name(), n)?;
            }
        }

        writeln!(f, "entry_skip_reasons:")?;
        for r in ENTRY_SKIP_REASONS.iter() {
            let n = self.entry_skip_reasons[r.as_usize()];
            if n != 0 {
                writeln!(f, "  {}={}", r.name(), n)?;
            }
        }

        writeln!(f, "partial_reasons:")?;
        for r in PARTIAL_REASONS.iter() {
            let n = self.partial_reasons[r.as_usize()];
            if n != 0 {
                writeln!(f, "  {}={}", r.name(), n)?;
            }
        }
        if self.paths_truncated != 0 {
            writeln!(f, "path_truncated={}", self.paths_truncated)?;
        }
        if self.paths_had_traversal != 0 {
            writeln!(f, "had_traversal={}", self.paths_had_traversal)?;
        }
        if self.paths_component_cap_exceeded != 0 {
            writeln!(
                f,
                "component_cap_exceeded={}",
                self.paths_component_cap_exceeded
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_match_variant_space() {
        assert_eq!(
            ArchiveSkipReason::COUNT,
            ArchiveSkipReason::UnsupportedFeature as usize + 1
        );
        assert_eq!(
            EntrySkipReason::COUNT,
            EntrySkipReason::UnsupportedFeature as usize + 1
        );
        assert_eq!(
            PartialReason::COUNT,
            PartialReason::UnsupportedFeature as usize + 1
        );
    }

    #[test]
    fn reason_arrays_match_discriminants() {
        for r in ARCHIVE_SKIP_REASONS.iter() {
            assert_eq!(ARCHIVE_SKIP_REASONS[r.as_usize()], *r);
        }
        for r in ENTRY_SKIP_REASONS.iter() {
            assert_eq!(ENTRY_SKIP_REASONS[r.as_usize()], *r);
        }
        for r in PARTIAL_REASONS.iter() {
            assert_eq!(PARTIAL_REASONS[r.as_usize()], *r);
        }
    }
}
