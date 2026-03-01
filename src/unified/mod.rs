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
//! | [`cli`] | Subcommand argument parsing (hand-rolled, no clap) |
//! | [`events`] | `ScanEvent` types, `EventSink` trait, JSONL encoder + sink |
//! | [`json_write`] | Shared JSON primitives (escaping, numbers, byte-paths) — no serde |
//! | [`json_sink`] | Streaming JSON array (`[{...},{...}]`) event sink |
//! | [`sarif_sink`] | SARIF 2.1.0 event sink (findings only) |
//! | [`text_sink`] | Human-readable text sink (compact / verbose) |
//! | [`orchestrator`] | Top-level dispatch: engine build → source driver → event sink |
//! | [`source`] | Source driver helpers (currently Git-only; FS scan uses `crate::scheduler` directly) |

pub mod cli;
pub mod events;
#[cfg(any(feature = "bench", feature = "tiger-harness"))]
#[doc(hidden)]
pub mod harness_api;
pub mod json_sink;
pub mod json_write;
pub mod orchestrator;
pub mod parity;
pub mod sarif_sink;
#[cfg(test)]
mod sink_stress_tests;
pub mod source;
pub mod text_sink;

use std::path::PathBuf;

use crate::AnchorMode;

pub use cli::ScanConfig;

/// Identifies which source produced a scan event.
///
/// Appears in [`Finding`](events::FindingEvent), [`Progress`](events::ProgressEvent),
/// and [`Summary`](events::SummaryEvent) events so consumers can route findings
/// and metrics by origin. Git-specific events (`CommitMeta`, `IdentityDictionary`)
/// and diagnostics omit it.
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
    /// Store query command (not a scan).
    Store(StoreCommand),
}

/// Store subcommand for querying the findings database.
pub enum StoreCommand {
    /// List completed runs.
    ListRuns {
        store_dir: PathBuf,
        status: Option<i32>,
        limit: usize,
        format: OutputFormat,
    },
    /// List findings for a specific run.
    ListFindings {
        store_dir: PathBuf,
        run: String,
        rule: Option<String>,
        path: Option<String>,
        limit: usize,
        format: OutputFormat,
    },
    /// Diff two runs.
    Diff {
        store_dir: PathBuf,
        run_a: String,
        run_b: String,
        format: OutputFormat,
    },
    /// List unique secrets.
    ListSecrets {
        store_dir: PathBuf,
        status: Option<i32>,
        limit: usize,
        format: OutputFormat,
    },
}

/// Output format for store queries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// JSON output.
    Json,
}

/// Execution path selector for scan orchestration.
///
/// `Direct` is the current default scanner path. `Connector` reserves the
/// connector-oriented execution path used by migration parity gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Run the current direct scanner path (default).
    #[default]
    Direct,
    /// Run the connector-oriented scanner path.
    Connector,
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Connector => f.write_str("connector"),
        }
    }
}

/// Filesystem scan configuration.
pub struct FsScanConfig {
    /// Directory or file path to scan.
    pub root: PathBuf,
    /// Number of worker threads (defaults to CPU count).
    pub workers: usize,
    /// Max transform decode depth (`None` → engine default of 3).
    pub decode_depth: Option<usize>,
    /// When `true`, skip archive (zip/tar/gz) expansion (default: `false`, archives are expanded).
    pub skip_archives: bool,
    /// Anchor extraction mode for rule matching.
    pub anchor_mode: AnchorMode,
    /// When `true`, scan binary files instead of skipping them
    /// (default: `false`, binary files are skipped). A file is classified as
    /// binary by [`content_policy::classify_content`](crate::content_policy::classify_content),
    /// which checks for NUL bytes in the first 8 KiB — matching Git's own
    /// `buffer_is_binary` heuristic.
    pub scan_binary: bool,
    /// When `true`, wire a [`StoreProducer`](crate::store::StoreProducer) into
    /// the parallel scan so post-dedupe findings are emitted to the persistence
    /// backend. The default backend writes to a SQLite database under the
    /// configured store root.
    pub persist_findings: bool,
    /// Execution mode selector (`direct` default, `connector` for parity runs).
    pub execution_mode: ExecutionMode,
}

/// Controls which debug output is emitted to stderr after a git scan.
///
/// Variants form a hierarchy: `Perf` is a strict superset of `Stats`
/// (stage stats are always included when perf breakdown is requested).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DebugLevel {
    /// No debug output (default).
    #[default]
    Off,
    /// Emit verbose stage stats (`--debug`).
    Stats,
    /// Emit stage stats **and** pack execution timing breakdown (`--debug=perf`).
    Perf,
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
    /// Max transform decode depth (`None` → engine default of 3).
    pub decode_depth: Option<usize>,
    /// Pack execution worker count (`None` → config default).
    pub pack_exec_workers: Option<usize>,
    /// Tree delta cache size in MiB (`None` → config default of 128).
    pub tree_delta_cache_mb: Option<u32>,
    /// Engine chunk size in MiB (`None` → config default of 1).
    pub engine_chunk_mb: Option<u32>,
    /// Debug output level for stderr diagnostics.
    pub debug: DebugLevel,
    /// When `true`, scan binary blobs instead of skipping them
    /// (default: `false`, binary blobs are skipped). Classification uses
    /// NUL-byte detection in the first 8 KiB via
    /// [`content_policy::classify_content`](crate::content_policy::classify_content).
    pub scan_binary: bool,
    /// When `true`, extract and emit author/committer identity data.
    pub enrich_identities: bool,
    /// Execution mode selector (`direct` default, `connector` for parity runs).
    pub execution_mode: ExecutionMode,
}

/// Output event format selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventFormat {
    /// One JSON object per line (default).
    #[default]
    Jsonl,
    /// Human-readable text output.
    Text,
    /// Single JSON array document.
    Json,
    /// SARIF 2.1.0 for GitHub Code Scanning and security tools.
    Sarif,
}
