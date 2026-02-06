//! High-Level Parallel Filesystem Scanning API
//!
//! This module provides a batteries-included entry point for parallel filesystem
//! scanning. It wraps the lower-level [`local`](super::local) scheduler with
//! streaming directory walking, gitignore support, and sensible defaults.
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
//!          │     DirWalker       │                                    │  LocalConfig     │
//!          │ (streaming via      │                                    │  (from config)   │
//!          │  bounded channel)   │                                    └────────┬─────────┘
//!          └─────────┬───────────┘                                             │
//!                    │                                                         │
//!                    │ LocalFile (streamed)                                    │
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
//! | Scan a pre-collected file list | `scan_local` with `VecFileSource` |
//! | Custom file discovery (e.g., git diff) | `scan_local` with custom `FileSource` |
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
//! - **Size filtering**: Enforced at open time; discovery avoids per-file metadata
//! - **Parallel scanning**: Work-stealing scheduler with chunked I/O
//! - **Overlap handling**: Automatic chunk overlap for boundary-crossing secrets
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: Every file matching filters is scanned (no silent drops)
//! - **Type-hint safety**: Missing `file_type()` hints fall back to metadata
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
use crate::archive::ArchiveConfig;
use crate::engine::Engine;

use std::io;
use std::path::Path;
use std::sync::Arc;

/// Minimal entry adapter so discovery classification can be unit-tested.
///
/// This keeps the DirWalker logic centralized while letting tests inject
/// `file_type()`-missing cases without depending on platform-specific behavior.
trait EntryLike {
    fn file_type(&self) -> Option<std::fs::FileType>;
    fn metadata(&self) -> io::Result<std::fs::Metadata>;
    fn path(&self) -> &Path;
    fn into_path(self) -> std::path::PathBuf
    where
        Self: Sized;
}

impl EntryLike for ignore::DirEntry {
    #[inline(always)]
    fn file_type(&self) -> Option<std::fs::FileType> {
        ignore::DirEntry::file_type(self)
    }

    #[inline(always)]
    fn metadata(&self) -> io::Result<std::fs::Metadata> {
        ignore::DirEntry::metadata(self).map_err(io::Error::other)
    }

    #[inline(always)]
    fn path(&self) -> &Path {
        ignore::DirEntry::path(self)
    }

    #[inline(always)]
    fn into_path(self) -> std::path::PathBuf {
        ignore::DirEntry::into_path(self)
    }
}

/// Classify a directory entry into a `LocalFile`, if eligible.
///
/// The algorithm uses `file_type()` as a fast hint when available, but must
/// fall back to `metadata()` if the hint is missing. This prevents silent drops
/// on platforms that do not supply file type in directory entries.
///
/// Discovery avoids per-file metadata when a type hint is available. Size caps
/// are enforced at open time in `local.rs`.
///
/// When the fast type hint path is used, the file size is set to 0; open-time
/// metadata determines the actual size and enforcement.
///
/// Returns `None` on:
/// - Non-file entries
/// - Metadata errors when the type hint is missing
#[inline(always)]
fn local_file_from_entry<E: EntryLike>(entry: E) -> Option<LocalFile> {
    if let Some(ft) = entry.file_type() {
        if !ft.is_file() {
            return None;
        }
        return Some(LocalFile {
            path: entry.into_path(),
            size: 0,
        });
    }

    let meta = match entry.metadata() {
        Ok(meta) => meta,
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[DirWalker] Metadata error for {:?}: {}", entry.path(), _e);
            return None;
        }
    };

    if !meta.file_type().is_file() {
        return None;
    }

    Some(LocalFile {
        path: entry.into_path(),
        size: meta.len(),
    })
}

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

    /// Archive scanning configuration.
    pub archive: ArchiveConfig,
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
            archive: ArchiveConfig::default(),
        }
    }
}

impl ParallelScanConfig {
    /// Convert to [`LocalConfig`](super::local::LocalConfig) for the scheduler.
    ///
    /// This extracts only the scheduler-relevant parameters; directory walking
    /// options (`follow_symlinks`, `skip_hidden`, `respect_gitignore`) are handled
    /// during file collection. `max_file_size` is enforced both at discovery and
    /// open time.
    fn to_local_config(&self) -> LocalConfig {
        LocalConfig {
            workers: self.workers,
            chunk_size: self.chunk_size,
            pool_buffers: self.pool_buffers,
            local_queue_cap: self.local_queue_cap,
            max_in_flight_objects: self.max_in_flight_objects,
            max_file_size: self.max_file_size,
            seed: self.seed,
            dedupe_within_chunk: true,
            archive: self.archive.clone(),
        }
    }
}

// ============================================================================
// Report
// ============================================================================

/// Report from a parallel directory scan.
///
/// This is currently identical to `LocalReport` (stats + metrics snapshot).
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
/// # Why Streaming Matters
///
/// For very large directory trees (millions of files), collecting upfront:
/// - Delays scan start until discovery completes
/// - Uses memory for all file paths simultaneously
///
/// Streaming discovery allows scanning to begin immediately and bounds
/// path metadata memory to `max_in_flight_objects`.
///
/// # Thread Lifecycle
///
/// The walker thread runs until:
/// - Discovery completes (all files enumerated)
/// - The receiver is dropped (scanner finished or errored) - walker quits early
struct DirWalker {
    /// Channel receiving discovered files from the walker thread.
    receiver: crossbeam_channel::Receiver<LocalFile>,
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
    /// - The receiver is dropped (scanner finished or errored) - sends fail, walker quits
    ///
    /// The thread is detached (not joined), so it will be terminated when
    /// the process exits even if discovery is incomplete.
    fn new(root: &Path, config: &ParallelScanConfig) -> Self {
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
        // Spawn walker thread
        std::thread::spawn(move || {
            walker.run(|| {
                let sender = sender.clone();
                Box::new(move |result| {
                    match result {
                        Ok(entry) => {
                            if let Some(file) = local_file_from_entry(entry) {
                                // Stop walking if receiver dropped (scanner finished)
                                if sender.send(file).is_err() {
                                    return ignore::WalkState::Quit;
                                }
                            }
                        }
                        Err(_e) => {
                            #[cfg(debug_assertions)]
                            eprintln!("[DirWalker] Discovery error: {}", _e);
                        }
                    }
                    ignore::WalkState::Continue
                })
            });
        });

        Self { receiver }
    }
}

impl FileSource for DirWalker {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.receiver.recv().ok()
    }
}

/// File source for a single file.
///
/// Used when `parallel_scan_dir` is called with a file path instead of a directory.
/// Returns the file once, then `None` on subsequent calls.
struct SingleFileSource(Option<LocalFile>);

impl FileSource for SingleFileSource {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.0.take()
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan a directory tree in parallel using the real detection engine.
///
/// This is the main entry point for filesystem scanning. It:
/// 1. Validates the root path exists and is accessible
/// 2. Streams files via `DirWalker` (respecting gitignore, size limits, etc.)
/// 3. Scans files in parallel using the work-stealing executor
/// 4. Returns statistics and metrics
///
/// # Streaming Discovery
///
/// Unlike implementations that collect all files upfront, this uses streaming
/// discovery via `DirWalker`. Benefits:
/// - Scanning starts immediately (doesn't wait for full directory enumeration)
/// - Bounded memory: only `max_in_flight_objects` file paths in memory at once
/// - ~1000x memory reduction for large scans (1M files: 200KB vs 200MB)
///
/// # Arguments
///
/// - `root`: Root directory or file to scan (must exist)
/// - `engine`: The detection engine (determines overlap, provides scan logic)
/// - `config`: Scan configuration (workers, chunk size, filtering options)
/// - `output`: Sink for findings (stdout, file, or custom)
///
/// # Returns
///
/// `Ok(report)` with scan statistics, or `Err` if:
/// - Root path does not exist
/// - Root path is not accessible (permission denied)
///
/// Individual file I/O errors do not cause the function to return `Err`;
/// they are counted in `report.stats.io_errors` and scanning continues.
/// Discovery errors (permission denied on subdirs, broken symlinks) are
/// logged in debug builds but not tracked in metrics to keep the design simple.
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

    // Verify root exists
    if !root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Root path does not exist: {}", root.display()),
        ));
    }

    // Handle single-file case: don't use DirWalker for one file
    if root.is_file() {
        return scan_single_file(root, engine, &config, output);
    }

    // Verify directory is readable (early permission check)
    std::fs::read_dir(root).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Cannot read root directory '{}': {}", root.display(), e),
        )
    })?;

    // Create streaming walker (returns immediately, spawns background thread)
    let walker = DirWalker::new(root, &config);

    let local_config = config.to_local_config();
    Ok(scan_local(engine, walker, local_config, output))
}

/// Scan a single file.
///
/// Helper for when `parallel_scan_dir` is called with a file path instead of directory.
fn scan_single_file(
    path: &Path,
    engine: Arc<Engine>,
    config: &ParallelScanConfig,
    output: Arc<dyn OutputSink>,
) -> io::Result<ParallelScanReport> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();

    // Size is only a discovery hint here; open-time enforcement happens in local.rs.
    let file = LocalFile {
        path: path.to_path_buf(),
        size,
    };
    let source = SingleFileSource(Some(file));
    let local_config = config.to_local_config();
    Ok(scan_local(engine, source, local_config, output))
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

    struct StubEntry {
        path: std::path::PathBuf,
    }

    impl EntryLike for StubEntry {
        fn file_type(&self) -> Option<std::fs::FileType> {
            None
        }

        fn metadata(&self) -> io::Result<std::fs::Metadata> {
            fs::metadata(&self.path)
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn into_path(self) -> std::path::PathBuf {
            self.path
        }
    }

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
            local_context: None,
            secret_group: None,
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
            archive: ArchiveConfig::default(),
        }
    }

    fn assert_perf_u64(actual: u64, expected: u64) {
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(actual, expected);
        } else {
            assert_eq!(actual, 0);
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

        assert_perf_u64(report.stats.files_enqueued, 2);

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

        assert_perf_u64(report.stats.files_enqueued, 0);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn file_type_none_falls_back_to_metadata() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("unknown_type.txt");
        fs::write(&file, "SECRETABCD1234").unwrap();

        let entry = StubEntry { path: file.clone() };
        let file_opt = local_file_from_entry(entry);

        assert!(file_opt.is_some());
        let local = file_opt.unwrap();
        assert_eq!(local.path, file);
        assert!(local.size > 0);
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

        // Discovery enqueues both; open-time enforcement skips the large file.
        assert_perf_u64(report.stats.files_enqueued, 2);
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert!(report.metrics.bytes_scanned < large_content.len() as u64);
        } else {
            assert_eq!(report.metrics.bytes_scanned, 0);
        }
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
        // Discovery errors (unreadable subdir) are logged in debug builds
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_perf_u64(report.stats.files_enqueued, 1);
    }

    #[test]
    fn scans_single_file() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("single.txt");
        fs::write(&file, "SECRETABCD1234").unwrap();

        // Pass file path directly (not directory)
        let result = parallel_scan_dir(&file, engine, small_config(), sink.clone());

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_perf_u64(report.stats.files_enqueued, 1);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("test-secret"));
    }

    #[test]
    fn single_file_respects_max_size() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("large.txt");
        let content = vec![b'x'; 1000];
        fs::write(&file, &content).unwrap();

        let mut config = small_config();
        config.max_file_size = 100; // Smaller than file

        // Pass file path directly
        let result = parallel_scan_dir(&file, engine, config, sink.clone());

        assert!(result.is_ok());
        let report = result.unwrap();
        // File is too large, should be skipped at open time.
        assert_perf_u64(report.stats.files_enqueued, 1);
        assert_perf_u64(report.metrics.bytes_scanned, 0);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn single_file_skips_empty() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Arc::new(Engine::new(rules, transforms, test_tuning()));
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("empty.txt");
        fs::write(&file, "").unwrap();

        // Pass empty file path directly
        let result = parallel_scan_dir(&file, engine, small_config(), sink.clone());

        assert!(result.is_ok());
        let report = result.unwrap();
        // Empty file should be skipped at open time.
        assert_perf_u64(report.stats.files_enqueued, 1);
        assert_perf_u64(report.metrics.bytes_scanned, 0);
        assert!(sink.take().is_empty());
    }
}
