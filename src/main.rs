//! Secret Scanner CLI
//!
//! A high-performance secret detection tool that scans filesystem paths for
//! sensitive credentials, API keys, and other secrets using pattern matching
//! with optional Base64/URL decoding.
//!
//! # Execution Modes
//!
//! - **Parallel (default)**: Work-stealing scheduler with N workers doing
//!   concurrent file I/O and scanning. Best for multi-core machines and SSDs.
//!
//! - **Single-threaded** (`--workers=1` or `--single-threaded`): Legacy pipeline
//!   mode that processes files sequentially. Useful for debugging or when
//!   parallelism overhead exceeds benefit (very small scans).
//!
//! # Output Format
//!
//! Findings are written to stdout as: `<path>:<start>-<end> <rule_name>`
//!
//! Statistics are written to stderr upon completion:
//! `files=N chunks=N bytes=N findings=N errors=N elapsed_ms=N throughput_mib_s=N workers=N`
//!
//! # Exit Codes
//!
//! - `0`: Success (regardless of findings count)
//! - `2`: Invalid arguments or configuration error

use scanner_rs::pipeline::scan_path_default;
use scanner_rs::scheduler::{parallel_scan_dir, ParallelScanConfig, StdoutSink};
use scanner_rs::{
    demo_engine_with_anchor_mode, demo_engine_with_anchor_mode_and_max_transform_depth, AnchorMode,
};
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Worker configuration determining parallelism strategy.
///
/// The scanner supports two fundamentally different execution paths:
/// - Parallel: Work-stealing scheduler (any `workers >= 2`)
/// - Single-threaded: Legacy sequential pipeline (forces `workers == 1`)
///
/// The distinction matters because single-threaded mode uses a different
/// code path (the pipeline module) which may behave differently in edge cases.
enum WorkerConfig {
    /// Auto-detect based on CPU count (parallel mode).
    ///
    /// Uses `num_cpus::get()` to determine worker count, falling back to at
    /// least 1. On most systems this equals the number of logical cores.
    Auto,
    /// Use explicit worker count (parallel mode if N >= 2).
    ///
    /// Setting `Explicit(1)` is semantically equivalent to `SingleThreaded`.
    Explicit(usize),
    /// Force single-threaded mode using the legacy pipeline.
    ///
    /// This bypasses the work-stealing scheduler entirely, using the older
    /// sequential pipeline from `scanner_rs::pipeline`. Useful for:
    /// - Debugging scheduler vs engine issues
    /// - Baseline comparison benchmarks
    /// - Environments where threading is problematic
    SingleThreaded,
}

fn print_usage(exe: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} [OPTIONS] <path>

OPTIONS:
    --workers=<N>           Use N parallel workers (default: auto-detect CPU count)
    --workers=1             Force single-threaded mode (same as --single-threaded)
    --single-threaded       Force single-threaded mode (legacy pipeline)
    --anchors=manual|derived  Anchor extraction mode (default: manual)
    --max-transform-depth=<N> Maximum decode depth (default: 2)
    --help, -h              Show this help message",
        exe.to_string_lossy()
    );
}

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "scanner-rs".into());
    let mut anchor_mode = AnchorMode::Manual;
    let mut path: Option<PathBuf> = None;
    let mut worker_config = WorkerConfig::Auto;
    let mut max_transform_depth: Option<usize> = None;

    for arg in args {
        if let Some(flag) = arg.to_str() {
            if let Some(value) = flag.strip_prefix("--workers=") {
                let n: usize = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --workers value: {}", value);
                    std::process::exit(2);
                });
                if n == 0 {
                    eprintln!("--workers must be >= 1");
                    std::process::exit(2);
                }
                worker_config = if n == 1 {
                    WorkerConfig::SingleThreaded
                } else {
                    WorkerConfig::Explicit(n)
                };
                continue;
            }
            if let Some(value) = flag.strip_prefix("--max-transform-depth=") {
                max_transform_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-transform-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            if let Some(value) = flag.strip_prefix("--decode-depth=") {
                max_transform_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --decode-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            if let Some(value) = flag.strip_prefix("--max-decode-depth=") {
                max_transform_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-decode-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            match flag {
                "--single-threaded" => {
                    worker_config = WorkerConfig::SingleThreaded;
                    continue;
                }
                "--anchors=manual" => {
                    anchor_mode = AnchorMode::Manual;
                    continue;
                }
                "--anchors=derived" | "--derive-anchors" => {
                    anchor_mode = AnchorMode::Derived;
                    continue;
                }
                "--help" | "-h" => {
                    print_usage(&exe);
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    print_usage(&exe);
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        if path.is_some() {
            print_usage(&exe);
            std::process::exit(2);
        }
        path = Some(PathBuf::from(arg));
    }

    let Some(path) = path else {
        print_usage(&exe);
        std::process::exit(2);
    };

    let engine = Arc::new(match max_transform_depth {
        Some(depth) => demo_engine_with_anchor_mode_and_max_transform_depth(anchor_mode, depth),
        None => demo_engine_with_anchor_mode(anchor_mode),
    });
    let start = Instant::now();

    // Determine number of workers
    let workers = match worker_config {
        WorkerConfig::Auto => num_cpus::get().max(1),
        WorkerConfig::Explicit(n) => n,
        WorkerConfig::SingleThreaded => 1, // Will use legacy pipeline below
    };

    // Unified statistics structure to normalize output between execution modes.
    //
    // The parallel scheduler and legacy pipeline return different stat types,
    // so we map both into this common representation for consistent output.
    struct ScanStats {
        /// Total files processed (or enqueued for parallel mode).
        files: u64,
        /// Total chunks scanned across all files.
        chunks: u64,
        /// Total payload bytes scanned (excluding overlap re-scans).
        bytes_scanned: u64,
        /// Number of secret findings emitted.
        findings: u64,
        /// I/O and processing errors encountered during scanning.
        io_errors: u64,
        /// Errors encountered during file discovery (directory walking).
        discovery_errors: u64,
    }

    let stats = if matches!(worker_config, WorkerConfig::SingleThreaded) {
        // Legacy single-threaded mode
        let pipeline_stats = scan_path_default(&path, Arc::clone(&engine))?;
        ScanStats {
            files: pipeline_stats.files,
            chunks: pipeline_stats.chunks,
            bytes_scanned: pipeline_stats.bytes_scanned,
            findings: pipeline_stats.findings,
            io_errors: pipeline_stats.errors,
            discovery_errors: 0, // Legacy pipeline doesn't track discovery errors
        }
    } else {
        // Parallel mode (default)
        let config = ParallelScanConfig {
            workers,
            skip_hidden: false,       // Scan all files including hidden
            respect_gitignore: false, // Don't skip gitignored files
            ..Default::default()
        };
        let sink = Arc::new(StdoutSink::new());
        let report = parallel_scan_dir(&path, Arc::clone(&engine), config, sink)?;

        // Map LocalReport to our unified stats
        ScanStats {
            files: report.stats.files_enqueued,
            chunks: report.metrics.chunks_scanned,
            bytes_scanned: report.metrics.bytes_scanned,
            findings: report.metrics.findings_emitted,
            io_errors: report.stats.io_errors,
            discovery_errors: report.stats.discovery_errors,
        }
    };
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let throughput_mib = if elapsed_secs > 0.0 {
        (stats.bytes_scanned as f64 / (1024.0 * 1024.0)) / elapsed_secs
    } else {
        0.0
    };

    eprintln!(
        "files={} chunks={} bytes={} findings={} io_errors={} discovery_errors={} elapsed_ms={} throughput_mib_s={:.2} workers={}",
        stats.files,
        stats.chunks,
        stats.bytes_scanned,
        stats.findings,
        stats.io_errors,
        stats.discovery_errors,
        elapsed.as_millis(),
        throughput_mib,
        workers
    );

    #[cfg(feature = "stats")]
    if std::env::var_os("SCANNER_VS_STATS").is_some() {
        let vs = engine.vectorscan_stats();
        eprintln!(
            "vectorscan db_built={} scans_attempted={} scans_ok={} scans_err={} utf16_db_built={} utf16_scans_attempted={} utf16_scans_ok={} utf16_scans_err={} anchor_only={} anchor_after_vs={} anchor_skipped={}",
            vs.db_built,
            vs.scans_attempted,
            vs.scans_ok,
            vs.scans_err,
            vs.utf16_db_built,
            vs.utf16_scans_attempted,
            vs.utf16_scans_ok,
            vs.utf16_scans_err,
            vs.anchor_only,
            vs.anchor_after_vs,
            vs.anchor_skipped
        );
    }

    // Note: b64-stats feature is only available in single-threaded mode
    // For parallel mode, per-chunk stats would need to be aggregated across workers

    Ok(())
}
