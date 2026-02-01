//! High-Level Parallel Filesystem Scanning API
//!
//! This module provides a batteries-included entry point for parallel filesystem
//! scanning. It wraps the lower-level [`local`](super::local) scheduler with
//! directory walking, gitignore support, and sensible defaults.
//!
//! # Architecture
//!
//! ```text
//!                          ┌─────────────────────────────────────────────────────┐
//!                          │               parallel_scan_dir()                   │
//!                          └───────────────────────┬─────────────────────────────┘
//!                                                  │
//!                    ┌─────────────────────────────┴─────────────────────────────┐
//!                    ▼                                                           ▼
//!          ┌─────────────────────┐                                    ┌──────────────────┐
//!          │  collect_files()    │                                    │  LocalConfig     │
//!          │  (ignore crate)     │                                    │  (from config)   │
//!          └─────────┬───────────┘                                    └────────┬─────────┘
//!                    │                                                         │
//!                    │ Vec<LocalFile>                                          │
//!                    └────────────────────┬────────────────────────────────────┘
//!                                         │
//!                                         ▼
//!                          ┌──────────────────────────────┐
//!                          │       scan_local()           │
//!                          │   (executor + workers)       │
//!                          └──────────────────────────────┘
//! ```
//!
//! # When to Use This vs `scan_local`
//!
//! | Use case | Recommended API |
//! |----------|-----------------|
//! | Scan a directory tree | `parallel_scan_dir` |
//! | Scan a pre-collected file list | `parallel_scan_files` or `scan_local` |
//! | Custom file discovery (e.g., git diff) | `scan_local` with custom `FileSource` |
//! | Need streaming discovery | `scan_local` with `DirWalker` (future) |
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use scanner_rs::engine::Engine;
//! use scanner_rs::scheduler::parallel_scan::{parallel_scan_dir, ParallelScanConfig};
//! use scanner_rs::scheduler::output_sink::StdoutSink;
//!
//! let engine = Arc::new(Engine::new(rules, transforms, tuning));
//! let config = ParallelScanConfig::default();
//! let sink = Arc::new(StdoutSink::new());
//!
//! let report = parallel_scan_dir(
//!     "/path/to/scan",
//!     engine,
//!     config,
//!     sink,
//! )?;
//!
//! println!("Scanned {} files, {} bytes", report.stats.files_enqueued, report.metrics.bytes_scanned);
//! ```
//!
//! # Features
//!
//! - **Directory walking**: Recursive traversal with symlink control
//! - **Gitignore support**: Respects `.gitignore`, `.git/info/exclude`, global gitignore
//! - **Hidden file filtering**: Optionally skip dotfiles and dot-directories
//! - **Size filtering**: Skip files above `max_file_size` to avoid memory pressure
//! - **Parallel scanning**: Work-stealing scheduler with chunked I/O
//! - **Overlap handling**: Automatic chunk overlap for boundary-crossing secrets
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: Every file matching filters is scanned (no silent drops)
//! - **Consistent snapshots**: File size captured at open time, not discovery time
//! - **Deduplication**: Findings in chunk overlap regions are deduplicated
//! - **Fail-soft**: I/O errors on individual files don't abort the scan
//!
//! # Performance
//!
//! For best performance:
//! - Use an SSD for I/O-bound workloads
//! - Set `workers` to match CPU core count (default: `num_cpus::get()`)
//! - Tune `chunk_size` based on file sizes (64-256 KiB typical)
//! - Ensure `pool_buffers >= workers` to avoid buffer starvation
//!
//! # Memory Budget
//!
//! Peak memory ≈ `pool_buffers × (chunk_size + overlap)` + file metadata overhead.
//! With defaults (workers=N, pool=4N, chunk=256K, overlap≈256): ~1 MiB per worker.

use super::local::{scan_local, FileSource, LocalConfig, LocalFile, LocalReport};
use super::output_sink::OutputSink;
use crate::engine::Engine;

use std::io;
use std::path::Path;
use std::sync::Arc;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for parallel directory scanning.
///
/// This struct combines directory walking options (gitignore, symlinks, etc.)
/// with scheduler tuning parameters. Internally, scheduler parameters are
/// converted to [`LocalConfig`](super::local::LocalConfig) for the executor.
///
/// # Defaults
///
/// | Parameter | Default | Rationale |
/// |-----------|---------|-----------|
/// | `workers` | `num_cpus::get()` | Match hardware parallelism |
/// | `chunk_size` | 256 KiB | Balance syscall overhead vs memory |
/// | `pool_buffers` | 4 × workers | Avoid buffer starvation under load |
/// | `max_in_flight_objects` | 1024 | Bound discovery queue memory |
/// | `max_file_size` | 100 MiB | Skip large binaries that rarely contain secrets |
///
/// # Memory Planning
///
/// Peak buffer memory = `pool_buffers × (chunk_size + engine.required_overlap())`.
///
/// Example with 8 workers, 256 KiB chunks, 256-byte overlap:
/// - Pool buffers: 32
/// - Buffer size: ~256 KiB each
/// - Peak: ~8 MiB for buffers
///
/// Additional memory for file metadata: ~200 bytes per in-flight file.
#[derive(Clone, Debug)]
pub struct ParallelScanConfig {
    /// Number of worker threads for parallel scanning.
    ///
    /// Workers perform both I/O (blocking reads) and CPU work (scanning).
    /// Setting this higher than CPU count may help if I/O latency is high
    /// (e.g., network filesystems), but typically `num_cpus::get()` is optimal.
    pub workers: usize,

    /// Payload bytes per chunk (excluding overlap).
    ///
    /// Each chunk is `chunk_size + engine.required_overlap()` bytes.
    /// Larger chunks reduce syscall overhead but increase memory per file.
    /// Typical values: 64-256 KiB.
    pub chunk_size: usize,

    /// Total buffers in the shared pool.
    ///
    /// Bounds peak memory: `pool_buffers × (chunk_size + overlap)`.
    /// Should be ≥ `workers` to avoid starvation; 4× workers is typical.
    pub pool_buffers: usize,

    /// Max discovered-but-not-complete files (discovery backpressure).
    ///
    /// When this limit is reached, the file walker blocks until workers
    /// complete files. Higher values allow more discovery-ahead but use
    /// more memory for file path metadata.
    pub max_in_flight_objects: usize,

    /// Per-worker local queue capacity in the buffer pool.
    ///
    /// Higher values reduce contention on the global pool but may cause
    /// uneven buffer distribution. Typically 2-8.
    pub local_queue_cap: usize,

    /// Random seed for deterministic executor behavior (work stealing).
    ///
    /// Set to a fixed value for reproducible scheduling in tests.
    pub seed: u64,

    /// Follow symbolic links when walking directories.
    ///
    /// **Warning**: Enabling this can cause infinite loops if symlinks
    /// form cycles. The `ignore` crate detects some cycles but not all.
    pub follow_symlinks: bool,

    /// Skip hidden files and directories (names starting with `.`).
    ///
    /// When `true`, dotfiles like `.env` and directories like `.git`
    /// are excluded from scanning. Set to `false` to scan everything.
    pub skip_hidden: bool,

    /// Respect `.gitignore` files when walking directories.
    ///
    /// When `true`, honors:
    /// - `.gitignore` in each directory
    /// - `.git/info/exclude`
    /// - Global gitignore (`~/.config/git/ignore`)
    ///
    /// This is useful for skipping `node_modules`, `target/`, etc.
    pub respect_gitignore: bool,

    /// Maximum file size to scan in bytes.
    ///
    /// Files larger than this are silently skipped. Useful for avoiding
    /// large binaries, media files, or database dumps that are unlikely
    /// to contain secrets but would consume significant scan time.
    pub max_file_size: u64,
}

impl Default for ParallelScanConfig {
    fn default() -> Self {
        let workers = num_cpus::get().max(1);
        Self {
            workers,
            chunk_size: 256 * 1024, // 256 KiB
            pool_buffers: workers * 4,
            max_in_flight_objects: 1024,
            local_queue_cap: 4,
            seed: 0x853c49e6748fea9b,
            follow_symlinks: false,
            skip_hidden: true,
            respect_gitignore: true,
            max_file_size: 100 * 1024 * 1024, // 100 MiB
        }
    }
}

impl ParallelScanConfig {
    /// Convert to [`LocalConfig`](super::local::LocalConfig) for the scheduler.
    ///
    /// This extracts only the scheduler-relevant parameters; directory walking
    /// options (`follow_symlinks`, `skip_hidden`, `respect_gitignore`, `max_file_size`)
    /// are handled during file collection, not during scanning.
    fn to_local_config(&self) -> LocalConfig {
        LocalConfig {
            workers: self.workers,
            chunk_size: self.chunk_size,
            pool_buffers: self.pool_buffers,
            local_queue_cap: self.local_queue_cap,
            max_in_flight_objects: self.max_in_flight_objects,
            seed: self.seed,
            dedupe_within_chunk: true,
        }
    }
}

// ============================================================================
// Report
// ============================================================================

/// Report from a parallel directory scan.
pub type ParallelScanReport = LocalReport;

// ============================================================================
// Directory Walker File Source
// ============================================================================

/// File source that walks a directory tree using parallel discovery.
///
/// # Design
///
/// Uses `ignore::WalkParallel` for multi-threaded directory traversal, sending
/// discovered files through a bounded channel. This allows discovery to run
/// ahead of scanning (up to `max_in_flight_objects` files).
///
/// # Current Status
///
/// **Not currently used.** The `parallel_scan_dir` function uses `collect_files`
/// instead, which collects all files upfront before scanning. This struct is
/// retained for future streaming implementation.
///
/// # Why Streaming Matters
///
/// For very large directory trees (millions of files), collecting upfront:
/// - Delays scan start until discovery completes
/// - Uses memory for all file paths simultaneously
///
/// Streaming discovery would allow scanning to begin immediately and bound
/// path metadata memory to `max_in_flight_objects`.
#[allow(dead_code)]
struct DirWalker {
    /// Unused but retained for type compatibility.
    /// The actual parallel walker is spawned in `new()` and communicates via `receiver`.
    walker: ignore::WalkParallel,
    /// Channel receiving discovered files from the walker thread.
    receiver: crossbeam_channel::Receiver<LocalFile>,
    /// Files larger than this are filtered out during discovery.
    max_file_size: u64,
}

impl DirWalker {
    /// Create a new directory walker.
    ///
    /// Spawns a background thread that walks the directory tree and sends
    /// files through a bounded channel. The channel capacity matches
    /// `config.max_in_flight_objects` to provide backpressure.
    ///
    /// # Thread Lifecycle
    ///
    /// The walker thread runs until:
    /// - Discovery completes (all files enumerated)
    /// - The receiver is dropped (scanner finished or errored)
    ///
    /// The thread is detached (not joined), so it will be terminated when
    /// the process exits even if discovery is incomplete.
    #[allow(dead_code)]
    fn new(root: &Path, config: &ParallelScanConfig) -> io::Result<Self> {
        let mut builder = ignore::WalkBuilder::new(root);

        builder
            .follow_links(config.follow_symlinks)
            .hidden(config.skip_hidden)
            .git_ignore(config.respect_gitignore)
            .git_global(config.respect_gitignore)
            .git_exclude(config.respect_gitignore);

        // Use parallel walker for faster discovery
        let walker = builder.build_parallel();

        let (sender, receiver) = crossbeam_channel::bounded(config.max_in_flight_objects);
        let max_file_size = config.max_file_size;

        // Spawn walker thread
        std::thread::spawn(move || {
            walker.run(|| {
                let sender = sender.clone();
                Box::new(move |result| {
                    if let Ok(entry) = result {
                        if let Some(ft) = entry.file_type() {
                            if ft.is_file() {
                                if let Ok(meta) = entry.metadata() {
                                    let size = meta.len();
                                    if size <= max_file_size && size > 0 {
                                        let file = LocalFile {
                                            path: entry.into_path(),
                                            size,
                                        };
                                        // Ignore send errors (receiver dropped)
                                        let _ = sender.send(file);
                                    }
                                }
                            }
                        }
                    }
                    ignore::WalkState::Continue
                })
            });
        });

        Ok(Self {
            walker: ignore::WalkBuilder::new(root).build_parallel(), // Unused but kept for type
            receiver,
            max_file_size,
        })
    }
}

impl FileSource for DirWalker {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.receiver.recv().ok()
    }
}

/// Simple file source that iterates over a pre-collected list.
///
/// Used by `parallel_scan_dir` after `collect_files` gathers all files upfront.
/// This is simpler than streaming but uses more memory for large directories.
struct VecSource {
    files: std::vec::IntoIter<LocalFile>,
}

impl FileSource for VecSource {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.files.next()
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan a directory tree in parallel using the real detection engine.
///
/// This is the main entry point for filesystem scanning. It:
/// 1. Validates the root path exists
/// 2. Collects all matching files (respecting gitignore, size limits, etc.)
/// 3. Scans files in parallel using the work-stealing executor
/// 4. Returns statistics and metrics
///
/// # Arguments
///
/// - `root`: Root directory to scan (must exist)
/// - `engine`: The detection engine (determines overlap, provides scan logic)
/// - `config`: Scan configuration (workers, chunk size, filtering options)
/// - `output`: Sink for findings (stdout, file, or custom)
///
/// # Returns
///
/// `Ok(report)` with scan statistics, or `Err` if:
/// - Root path does not exist
/// - Root path is not accessible
///
/// Individual file I/O errors do not cause the function to return `Err`;
/// they are counted in `report.stats.io_errors` and scanning continues.
///
/// # Complexity
///
/// - File discovery: O(files + directories) with gitignore overhead
/// - Scanning: O(total_bytes / chunk_size) chunks processed in parallel
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use scanner_rs::engine::Engine;
/// use scanner_rs::scheduler::parallel_scan::{parallel_scan_dir, ParallelScanConfig};
/// use scanner_rs::scheduler::output_sink::VecSink;
///
/// let engine = Arc::new(Engine::new(rules, transforms, tuning));
/// let sink = Arc::new(VecSink::new());
///
/// let report = parallel_scan_dir(
///     "/path/to/scan",
///     engine,
///     ParallelScanConfig::default(),
///     sink,
/// )?;
///
/// println!("Files: {}, Bytes: {}, I/O errors: {}",
///     report.stats.files_enqueued,
///     report.metrics.bytes_scanned,
///     report.stats.io_errors);
/// ```
pub fn parallel_scan_dir(
    root: impl AsRef<Path>,
    engine: Arc<Engine>,
    config: ParallelScanConfig,
    output: Arc<dyn OutputSink>,
) -> io::Result<ParallelScanReport> {
    let root = root.as_ref();

    // Verify root exists and is accessible
    if !root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Root path does not exist: {}", root.display()),
        ));
    }

    // Collect files first for simpler implementation
    // Future optimization: streaming with DirWalker
    let collect_result = collect_files(root, &config)?;

    let source = VecSource {
        files: collect_result.files.into_iter(),
    };

    let local_config = config.to_local_config();

    let mut report = scan_local(engine, source, local_config, output);

    // Include discovery errors from the file collection phase
    report.stats.discovery_errors = collect_result.discovery_errors;

    Ok(report)
}

/// Collect all files from a directory tree.
///
/// Walks the directory using `ignore::WalkBuilder`, applying filters:
/// - Skip hidden files/directories if `config.skip_hidden`
/// - Skip gitignored files if `config.respect_gitignore`
/// - Skip files > `config.max_file_size`
/// - Skip empty files (size == 0)
/// - Follow symlinks if `config.follow_symlinks`
///
/// # Trade-off: Upfront vs Streaming
///
/// This collects all files before returning, which:
/// - **Pro**: Simple implementation, predictable memory after collection
/// - **Con**: Delays scan start, peak memory holds all file paths
///
/// For very large trees (millions of files), consider `DirWalker` streaming.
///
/// # Errors
///
/// Returns `Err` if:
/// - Root directory cannot be read (permission denied, I/O error)
///
/// Individual entry errors during traversal (broken symlinks, permission
/// denied on subdirectories) are counted in `discovery_errors` but don't
/// cause the function to fail.
/// Result of file collection including discovered files and error counts.
struct CollectResult {
    files: Vec<LocalFile>,
    /// Errors during directory traversal (permission denied, broken symlink, etc.)
    discovery_errors: u64,
}

fn collect_files(root: &Path, config: &ParallelScanConfig) -> io::Result<CollectResult> {
    // Verify root is accessible (readable) before walking.
    // This catches permission denied early rather than silently returning
    // an empty file list. The exists() check in parallel_scan_dir only
    // verifies the inode exists, not that we can read the directory.
    std::fs::read_dir(root).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Cannot read root directory '{}': {}", root.display(), e),
        )
    })?;

    let mut builder = ignore::WalkBuilder::new(root);

    builder
        .follow_links(config.follow_symlinks)
        .hidden(config.skip_hidden)
        .git_ignore(config.respect_gitignore)
        .git_global(config.respect_gitignore)
        .git_exclude(config.respect_gitignore);

    let mut files = Vec::new();
    let mut discovery_errors: u64 = 0;

    for entry in builder.build() {
        // Skip individual entry errors (permission denied, broken symlink, etc.)
        // rather than aborting the entire scan. This matches the documented
        // fail-soft behavior. We count these errors for observability.
        let entry = match entry {
            Ok(e) => e,
            Err(_e) => {
                discovery_errors = discovery_errors.saturating_add(1);
                #[cfg(debug_assertions)]
                eprintln!("[collect_files] Discovery error: {}", _e);
                continue;
            }
        };

        if let Some(ft) = entry.file_type() {
            if ft.is_file() {
                match entry.metadata() {
                    Ok(meta) => {
                        let size = meta.len();
                        if size <= config.max_file_size && size > 0 {
                            files.push(LocalFile {
                                path: entry.into_path(),
                                size,
                            });
                        }
                    }
                    Err(_e) => {
                        discovery_errors = discovery_errors.saturating_add(1);
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "[collect_files] Metadata error for {:?}: {}",
                            entry.path(),
                            _e
                        );
                    }
                }
            }
        }
    }

    Ok(CollectResult {
        files,
        discovery_errors,
    })
}

/// Scan a list of files in parallel using the real detection engine.
///
/// This is a lower-level API for when you have a pre-determined file list
/// (e.g., from `git diff`, a manifest, or custom filtering logic).
///
/// # When to Use
///
/// - You've already collected files through some other mechanism
/// - You want to scan a subset of files (e.g., changed files only)
/// - You need custom filtering not supported by `ParallelScanConfig`
///
/// For directory scanning with standard filters, use [`parallel_scan_dir`] instead.
///
/// # Arguments
///
/// - `files`: List of files to scan (with sizes for progress tracking)
/// - `engine`: The detection engine
/// - `config`: Scan configuration (directory walking options are ignored)
/// - `output`: Sink for findings
///
/// # Note
///
/// Unlike `parallel_scan_dir`, this function:
/// - Does not validate that files exist (errors handled per-file)
/// - Does not apply `max_file_size` filtering (caller's responsibility)
/// - Cannot fail at the function level (all errors are per-file)
pub fn parallel_scan_files(
    files: Vec<LocalFile>,
    engine: Arc<Engine>,
    config: ParallelScanConfig,
    output: Arc<dyn OutputSink>,
) -> ParallelScanReport {
    let source = VecSource {
        files: files.into_iter(),
    };

    let local_config = config.to_local_config();

    scan_local(engine, source, local_config, output)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{RuleSpec, TransformConfig, Tuning, ValidatorKind};
    use crate::scheduler::output_sink::VecSink;
    use regex::bytes::Regex;
    use std::fs;
    use tempfile::TempDir;

    fn test_tuning() -> Tuning {
        Tuning {
            merge_gap: 64,
            max_windows_per_rule_variant: 64,
            pressure_gap_start: 128,
            max_anchor_hits_per_rule_variant: 256,
            max_utf16_decoded_bytes_per_window: 4096,
            max_transform_depth: 2,
            max_total_decode_output_bytes: 1024 * 1024,
            max_work_items: 64,
            max_findings_per_chunk: 4096,
            scan_utf16_variants: true,
        }
    }

    fn simple_rule() -> RuleSpec {
        RuleSpec {
            name: "test-secret",
            anchors: &[b"SECRET"],
            radius: 32,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
        }
    }

    fn small_config() -> ParallelScanConfig {
        ParallelScanConfig {
            workers: 2,
            chunk_size: 64 * 1024,
            pool_buffers: 8,
            max_in_flight_objects: 64,
            local_queue_cap: 2,
            seed: 12345,
            follow_symlinks: false,
            skip_hidden: true,
            respect_gitignore: false,
            max_file_size: 10 * 1024 * 1024,
        }
    }

    #[test]
    fn scans_directory_with_files() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        // Create temp directory with files
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("test1.txt");
        let file2 = dir.path().join("test2.txt");

        fs::write(&file1, "contains SECRETABCD1234 here").unwrap();
        fs::write(&file2, "another SECRETEFGH5678 secret").unwrap();

        let report = parallel_scan_dir(dir.path(), engine, small_config(), sink.clone()).unwrap();

        assert_eq!(report.stats.files_enqueued, 2);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);

        // Should find both secrets
        assert!(output_str.contains("test-secret"));
    }

    #[test]
    fn handles_empty_directory() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();

        let report = parallel_scan_dir(dir.path(), engine, small_config(), sink.clone()).unwrap();

        assert_eq!(report.stats.files_enqueued, 0);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn respects_max_file_size() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let small_file = dir.path().join("small.txt");
        let large_file = dir.path().join("large.txt");

        fs::write(&small_file, "SECRETABCD1234").unwrap();

        // Create a file larger than max_file_size
        let mut config = small_config();
        config.max_file_size = 100;

        let large_content = vec![b'x'; 1000];
        fs::write(&large_file, &large_content).unwrap();

        let report = parallel_scan_dir(dir.path(), engine, config, sink.clone()).unwrap();

        // Only the small file should be scanned
        assert_eq!(report.stats.files_enqueued, 1);
    }

    #[test]
    fn errors_on_nonexistent_path() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let result = parallel_scan_dir("/nonexistent/path", engine, small_config(), sink);

        assert!(result.is_err());
    }

    #[test]
    fn scan_files_directly() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "SECRETABCD1234").unwrap();

        let files = vec![LocalFile {
            path: file,
            size: 14,
        }];

        let report = parallel_scan_files(files, engine, small_config(), sink.clone());

        assert_eq!(report.stats.files_enqueued, 1);
    }

    #[test]
    #[cfg(unix)] // chmod requires Unix
    fn errors_on_unreadable_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let unreadable = dir.path().join("unreadable");
        fs::create_dir(&unreadable).unwrap();

        // Remove read permission
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let result = parallel_scan_dir(&unreadable, engine, small_config(), sink);

        // Restore permissions before assertions (for cleanup)
        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    #[cfg(unix)]
    fn continues_on_unreadable_subdir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();

        // Readable file at root level
        let file = dir.path().join("readable.txt");
        fs::write(&file, "SECRETABCD1234").unwrap();

        // Unreadable subdirectory
        let subdir = dir.path().join("blocked");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("hidden.txt"), "SECRETEFGH5678").unwrap();
        fs::set_permissions(&subdir, fs::Permissions::from_mode(0o000)).unwrap();

        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let result = parallel_scan_dir(dir.path(), engine, small_config(), sink.clone());

        // Restore permissions before assertions
        let _ = fs::set_permissions(&subdir, fs::Permissions::from_mode(0o755));

        // Should succeed - only the root-level file is scanned
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.stats.files_enqueued, 1);
        assert!(report.stats.discovery_errors >= 1); // Subdirectory error counted
    }
}
