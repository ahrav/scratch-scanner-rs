//! Secret Scanner CLI
//!
//! A high-performance secret detection tool that scans filesystem paths for
//! sensitive credentials, API keys, and other secrets using pattern matching
//! with optional Base64/URL decoding.
//!
//! Uses a work-stealing scheduler with N parallel workers for concurrent file
//! I/O and scanning. Best for multi-core machines and SSDs.
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

use scanner_rs::scheduler::{parallel_scan_dir, ParallelScanConfig, StdoutSink};
use scanner_rs::{
    demo_engine_with_anchor_mode, demo_engine_with_anchor_mode_and_max_transform_depth, AnchorMode,
};
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn print_usage(exe: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} [OPTIONS] <path>

OPTIONS:
    --workers=<N>           Number of parallel workers (default: auto-detect CPU count)
    --decode-depth=<N>      Maximum decode depth (default: 2)
    --no-archives           Disable archive scanning (zip, tar, gz, etc.)
    --help, -h              Show this help message",
        exe.to_string_lossy()
    );
}

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "scanner-rs".into());
    let mut path: Option<PathBuf> = None;
    let mut workers: Option<usize> = None;
    let mut decode_depth: Option<usize> = None;
    let mut no_archives = false;

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
                workers = Some(n);
                continue;
            }
            if let Some(value) = flag.strip_prefix("--decode-depth=") {
                decode_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --decode-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            match flag {
                "--no-archives" => {
                    no_archives = true;
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

    let workers = workers.unwrap_or_else(|| num_cpus::get().max(1));

    let engine = Arc::new(match decode_depth {
        Some(depth) => {
            demo_engine_with_anchor_mode_and_max_transform_depth(AnchorMode::Manual, depth)
        }
        None => demo_engine_with_anchor_mode(AnchorMode::Manual),
    });
    let start = Instant::now();

    let mut config = ParallelScanConfig {
        workers,
        skip_hidden: false,
        respect_gitignore: false,
        ..Default::default()
    };
    if no_archives {
        config.archive.enabled = false;
    }
    let sink = Arc::new(StdoutSink::new());
    let report = parallel_scan_dir(&path, Arc::clone(&engine), config, sink)?;

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let throughput_mib = if elapsed_secs > 0.0 {
        (report.metrics.bytes_scanned as f64 / (1024.0 * 1024.0)) / elapsed_secs
    } else {
        0.0
    };

    eprintln!(
        "files={} chunks={} bytes={} findings={} errors={} elapsed_ms={} throughput_mib_s={:.2} workers={}",
        report.stats.files_enqueued,
        report.metrics.chunks_scanned,
        report.metrics.bytes_scanned,
        report.metrics.findings_emitted,
        report.stats.io_errors,
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

    Ok(())
}
