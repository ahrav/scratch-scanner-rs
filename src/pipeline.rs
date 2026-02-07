//! Configuration and statistics types for file-scanning pipelines.
//!
//! These types are shared across different scanning backends (runtime,
//! scheduler, etc.) to provide a common configuration surface and
//! uniform stats reporting.

use crate::archive::{ArchiveConfig, ArchiveStats};

/// Default chunk size used by the pipeline (bytes).
///
/// A value of 0 means "auto", resolved to the maximum buffer size minus overlap
/// (aligned down to `BUFFER_ALIGN`).
pub const DEFAULT_CHUNK_SIZE: usize = 0;

/// Default file ring capacity.
pub const PIPE_FILE_RING_CAP: usize = 1024;
/// Default chunk ring capacity.
pub const PIPE_CHUNK_RING_CAP: usize = 128;
/// Default output ring capacity.
pub const PIPE_OUT_RING_CAP: usize = 8192;
/// Target aggregate bytes for the pipeline buffer pool.
///
/// Pool capacity is derived from this budget and `BUFFER_LEN_MAX`, so larger
/// buffers automatically reduce the number of pooled slots.
pub const PIPE_POOL_TARGET_BYTES: usize = 256 * 1024 * 1024;
/// Minimum buffer pool capacity for the pipeline.
pub const PIPE_POOL_MIN: usize = 16;

/// Default maximum number of files to scan.
///
/// This bounds the `FileTable` allocation. Increase for very large scans;
/// decrease if memory is constrained.
pub const PIPE_MAX_FILES: usize = 100_000;
/// Default per-file path byte budget for the pipeline.
pub const PIPE_PATH_BYTES_PER_FILE: usize = 256;

/// Configuration for the high-level pipeline scanner.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Bytes read per chunk (excluding overlap). Use 0 for the maximum size.
    ///
    /// A value of 0 is resolved to the largest aligned chunk that fits within
    /// `BUFFER_LEN_MAX` after accounting for overlap.
    pub chunk_size: usize,
    /// Maximum number of files to queue.
    pub max_files: usize,
    /// Total byte capacity reserved for path storage (0 = auto).
    ///
    /// On Unix this is the fixed-size path arena budget; on non-Unix it is
    /// ignored. Exceeding the arena is treated as a configuration bug and will
    /// fail fast rather than allocate.
    pub path_bytes_cap: usize,
    /// Archive scanning configuration.
    pub archive: ArchiveConfig,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let max_files = PIPE_MAX_FILES;
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_files,
            path_bytes_cap: max_files.saturating_mul(PIPE_PATH_BYTES_PER_FILE),
            archive: ArchiveConfig::default(),
        }
    }
}

/// Summary counters for a pipeline run.
///
/// All counters are always populated (unconditional arithmetic).
/// `errors` is an aggregate that includes `walk_errors` and `open_errors`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PipelineStats {
    /// Number of files enqueued.
    pub files: u64,
    /// Number of chunks scanned.
    pub chunks: u64,
    /// Total bytes scanned (excludes overlap).
    pub bytes_scanned: u64,
    /// Total number of findings emitted.
    pub findings: u64,
    /// Errors encountered while walking directories.
    pub walk_errors: u64,
    /// Errors encountered while opening files.
    pub open_errors: u64,
    /// Errors encountered while reading files.
    pub errors: u64,
    /// Optional Base64 decode/gate instrumentation (feature: `b64-stats`).
    #[cfg(feature = "b64-stats")]
    pub base64: crate::Base64DecodeStats,
    /// Archive scanning outcomes (when enabled).
    pub archive: ArchiveStats,
}
