//! Unified source-driven scanner architecture.
//!
//! Consolidates filesystem and git scanning behind a single CLI with
//! explicit source selection (`scanner-rs scan fs|git ...`), structured
//! event output, and a shared scheduler.
//!
//! # Module layout
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`cli`] | Subcommand argument parsing |
//! | [`events`] | `ScanEvent`, `EventSink`, JSONL encoder |
//! | [`orchestrator`] | Top-level dispatch (`run()`) |
//! | [`source`] | Source drivers (FS, Git) |

pub mod cli;
pub mod events;
pub mod orchestrator;
pub mod source;

use std::path::PathBuf;

use crate::AnchorMode;

pub use cli::ScanConfig;

/// Identifies which source produced a scan event.
///
/// Appears in every [`ScanEvent`](events::ScanEvent) so consumers can
/// route findings and metrics by origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Filesystem scan (directory walk or single file).
    Fs,
    /// Git repository history scan (pack or loose objects).
    Git,
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fs => f.write_str("fs"),
            Self::Git => f.write_str("git"),
        }
    }
}

/// Source-specific scan configuration parsed from the CLI.
///
/// Exactly one variant is populated per invocation; the orchestrator
/// dispatches on this to select the appropriate scan driver.
pub enum SourceConfig {
    /// Filesystem path scan (directory or single file).
    Fs(FsScanConfig),
    /// Git repository history scan.
    Git(GitSourceConfig),
}

/// Filesystem scan configuration.
pub struct FsScanConfig {
    /// Directory or file path to scan.
    pub root: PathBuf,
    /// Number of worker threads (defaults to CPU count).
    pub workers: usize,
    /// Max transform decode depth (`None` → engine default of 2).
    pub decode_depth: Option<usize>,
    /// Disable archive (zip/tar/gz) expansion.
    pub no_archives: bool,
    /// Anchor extraction mode for rule matching.
    pub anchor_mode: AnchorMode,
    /// Use a no-op event sink (drops all findings). For measuring scan overhead
    /// without JSON encoding + stdout I/O.
    pub null_sink: bool,
}

/// Git repository scan configuration.
pub struct GitSourceConfig {
    /// Path to the repository root (bare or worktree).
    pub repo_root: PathBuf,
    /// Numeric identifier used for persistence and watermarking.
    pub repo_id: u64,
    /// Object enumeration strategy (diff-history vs odb-blob).
    pub scan_mode: crate::git_scan::GitScanMode,
    /// How merge commits are diffed (all parents vs first parent).
    pub merge_mode: crate::git_scan::MergeDiffMode,
    /// Anchor extraction mode for rule matching.
    pub anchor_mode: AnchorMode,
    /// Max transform decode depth (`None` → engine default of 2).
    pub decode_depth: Option<usize>,
    /// Pack execution worker count (`None` → config default).
    pub pack_exec_workers: Option<usize>,
    /// Tree delta cache size in MiB (`None` → config default of 128).
    pub tree_delta_cache_mb: Option<u32>,
    /// Engine chunk size in MiB (`None` → config default of 1).
    pub engine_chunk_mb: Option<u32>,
    /// Emit verbose stage stats to stderr.
    pub debug: bool,
    /// Emit pack execution timing breakdown to stderr.
    pub perf_breakdown: bool,
}

/// Output event format selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventFormat {
    /// One JSON object per line (default).
    #[default]
    Jsonl,
}
