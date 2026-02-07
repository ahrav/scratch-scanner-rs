//! Subcommand CLI parser for the unified scanner.
//!
//! Hand-rolled (no clap dependency) to keep binary size small and boot fast.
//!
//! # Grammar
//!
//! ```text
//! scanner-rs scan fs --path <dir|file> [FS_FLAGS]
//! scanner-rs scan git --repo <path>    [GIT_FLAGS]
//! scanner-rs --help | -h
//! ```

use std::env;
use std::io;
use std::path::PathBuf;

use crate::git_scan::{GitScanMode, MergeDiffMode};
use crate::AnchorMode;

use super::{EventFormat, FsScanConfig, GitSourceConfig, SourceConfig};

/// Top-level scan configuration produced by CLI parsing.
pub struct ScanConfig {
    pub source: SourceConfig,
    pub event_format: EventFormat,
}

/// Parse `std::env::args_os()` into a [`ScanConfig`].
///
/// Exits the process with code 2 on invalid arguments, printing a
/// diagnostic and usage summary to stderr.
pub fn parse_args() -> io::Result<ScanConfig> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "scanner-rs".into());

    let first = match args.next() {
        Some(a) => a,
        None => {
            print_top_usage(&exe);
            std::process::exit(2);
        }
    };

    let first_str = first.to_string_lossy();
    match first_str.as_ref() {
        "--help" | "-h" => {
            print_top_usage(&exe);
            std::process::exit(0);
        }
        "scan" => {}
        _ => {
            eprintln!("error: expected 'scan' subcommand, got '{}'", first_str);
            eprintln!();
            print_top_usage(&exe);
            std::process::exit(2);
        }
    }

    let sub = match args.next() {
        Some(a) => a,
        None => {
            eprintln!("error: 'scan' requires a source: fs or git");
            eprintln!();
            print_top_usage(&exe);
            std::process::exit(2);
        }
    };

    let sub_str = sub.to_string_lossy();
    match sub_str.as_ref() {
        "fs" => parse_fs_args(args),
        "git" => parse_git_args(args),
        "--help" | "-h" => {
            print_top_usage(&exe);
            std::process::exit(0);
        }
        _ => {
            eprintln!(
                "error: unknown scan source '{}'; expected 'fs' or 'git'",
                sub_str
            );
            eprintln!();
            print_top_usage(&exe);
            std::process::exit(2);
        }
    }
}

fn parse_fs_args(args: env::ArgsOs) -> io::Result<ScanConfig> {
    let mut path: Option<PathBuf> = None;
    let mut workers: Option<usize> = None;
    let mut decode_depth: Option<usize> = None;
    let mut no_archives = false;
    let mut anchor_mode = AnchorMode::Manual;
    let mut event_format = EventFormat::Jsonl;
    for arg in args {
        if let Some(flag) = arg.to_str() {
            if let Some(rest) = flag.strip_prefix("--path=") {
                path = Some(PathBuf::from(rest));
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--workers=") {
                let n: usize = parse_or_exit(rest, "--workers");
                if n == 0 {
                    eprintln!("--workers must be >= 1");
                    std::process::exit(2);
                }
                workers = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--decode-depth=") {
                decode_depth = Some(parse_or_exit(rest, "--decode-depth"));
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--anchors=") {
                anchor_mode = parse_anchor_mode(rest);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--event-format=") {
                event_format = parse_event_format(rest);
                continue;
            }
            match flag {
                "--no-archives" => {
                    no_archives = true;
                    continue;
                }
                "--help" | "-h" => {
                    print_fs_usage();
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    print_fs_usage();
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        // Positional: treat as --path if not yet set.
        if path.is_some() {
            eprintln!("error: multiple paths provided; use --path=<dir|file>");
            std::process::exit(2);
        }
        path = Some(PathBuf::from(arg));
    }

    let Some(root) = path else {
        eprintln!("error: --path is required for 'scan fs'");
        print_fs_usage();
        std::process::exit(2);
    };

    Ok(ScanConfig {
        source: SourceConfig::Fs(FsScanConfig {
            root,
            workers: workers.unwrap_or_else(|| num_cpus::get().max(1)),
            decode_depth,
            no_archives,
            anchor_mode,
        }),
        event_format,
    })
}

fn parse_git_args(args: env::ArgsOs) -> io::Result<ScanConfig> {
    let mut repo: Option<PathBuf> = None;
    let mut repo_id: u64 = 1;
    let mut scan_mode = GitScanMode::OdbBlobFast;
    let mut merge_mode = MergeDiffMode::AllParents;
    let mut anchor_mode = AnchorMode::Manual;
    let mut decode_depth: Option<usize> = None;
    let mut pack_exec_workers: Option<usize> = None;
    let mut tree_delta_cache_mb: Option<u32> = None;
    let mut engine_chunk_mb: Option<u32> = None;
    let mut debug = false;
    let mut perf_breakdown = false;
    let mut event_format = EventFormat::Jsonl;

    for arg in args {
        if let Some(flag) = arg.to_str() {
            if let Some(rest) = flag.strip_prefix("--repo=") {
                repo = Some(PathBuf::from(rest));
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--repo-id=") {
                repo_id = parse_or_exit(rest, "--repo-id");
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--mode=") {
                scan_mode = match rest {
                    "diff" | "diff-history" => GitScanMode::DiffHistory,
                    "odb-blob" | "odb-blob-fast" => GitScanMode::OdbBlobFast,
                    _ => {
                        eprintln!("invalid --mode value: {}", rest);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--merge=") {
                merge_mode = match rest {
                    "all" => MergeDiffMode::AllParents,
                    "first-parent" => MergeDiffMode::FirstParentOnly,
                    _ => {
                        eprintln!("invalid --merge value: {}", rest);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--anchors=") {
                anchor_mode = parse_anchor_mode(rest);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--decode-depth=") {
                decode_depth = Some(parse_or_exit(rest, "--decode-depth"));
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--pack-exec-workers=") {
                let n: usize = parse_or_exit(rest, "--pack-exec-workers");
                if n == 0 {
                    eprintln!("--pack-exec-workers must be >= 1");
                    std::process::exit(2);
                }
                pack_exec_workers = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--tree-delta-cache-mb=") {
                let n: u32 = parse_or_exit(rest, "--tree-delta-cache-mb");
                if n == 0 {
                    eprintln!("--tree-delta-cache-mb must be >= 1");
                    std::process::exit(2);
                }
                tree_delta_cache_mb = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--engine-chunk-mb=") {
                let n: u32 = parse_or_exit(rest, "--engine-chunk-mb");
                if n == 0 {
                    eprintln!("--engine-chunk-mb must be >= 1");
                    std::process::exit(2);
                }
                engine_chunk_mb = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--event-format=") {
                event_format = parse_event_format(rest);
                continue;
            }
            match flag {
                "--debug" => {
                    debug = true;
                    continue;
                }
                "--perf-breakdown" => {
                    perf_breakdown = true;
                    continue;
                }
                "--help" | "-h" => {
                    print_git_usage();
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    print_git_usage();
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        // Positional: treat as --repo if not yet set.
        if repo.is_some() {
            eprintln!("error: multiple repos provided; use --repo=<path>");
            std::process::exit(2);
        }
        repo = Some(PathBuf::from(arg));
    }

    let Some(repo_root) = repo else {
        eprintln!("error: --repo (or positional path) is required for 'scan git'");
        print_git_usage();
        std::process::exit(2);
    };

    Ok(ScanConfig {
        source: SourceConfig::Git(GitSourceConfig {
            repo_root,
            repo_id,
            scan_mode,
            merge_mode,
            anchor_mode,
            decode_depth,
            pack_exec_workers,
            tree_delta_cache_mb,
            engine_chunk_mb,
            debug,
            perf_breakdown,
        }),
        event_format,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_or_exit<T: std::str::FromStr>(s: &str, flag: &str) -> T {
    s.parse().unwrap_or_else(|_| {
        eprintln!("invalid {} value: {}", flag, s);
        std::process::exit(2);
    })
}

fn parse_anchor_mode(s: &str) -> AnchorMode {
    match s {
        "manual" => AnchorMode::Manual,
        "derived" => AnchorMode::Derived,
        _ => {
            eprintln!("invalid --anchors value: {} (expected manual|derived)", s);
            std::process::exit(2);
        }
    }
}

fn parse_event_format(s: &str) -> EventFormat {
    match s {
        "jsonl" => EventFormat::Jsonl,
        _ => {
            eprintln!("invalid --event-format value: {} (expected jsonl)", s);
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Usage text
// ---------------------------------------------------------------------------

fn print_top_usage(exe: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} scan <source> [OPTIONS]

SOURCES:
    fs    Scan filesystem path(s)
    git   Scan git repository history

EXAMPLES:
    {} scan fs --path /src
    {} scan git --repo /repos/myproject

Run '{} scan fs --help' or '{} scan git --help' for source-specific options.",
        exe.to_string_lossy(),
        exe.to_string_lossy(),
        exe.to_string_lossy(),
        exe.to_string_lossy(),
        exe.to_string_lossy(),
    );
}

fn print_fs_usage() {
    eprintln!(
        "usage: scanner-rs scan fs --path <dir|file> [OPTIONS]

OPTIONS:
    --path=<dir|file>             Path to scan (also accepted as positional arg)
    --workers=<N>                 Worker threads (default: CPU count)
    --decode-depth=<N>            Max decode depth (default: 2)
    --no-archives                 Disable archive scanning
    --anchors=manual|derived      Anchor mode (default: manual)
    --event-format=jsonl          Output format (default: jsonl)
    --help, -h                    Show this help"
    );
}

fn print_git_usage() {
    eprintln!(
        "usage: scanner-rs scan git --repo <path> [OPTIONS]

OPTIONS:
    --repo=<path>             Repository path (also accepted as positional arg)
    --repo-id=<N>             Repository id (default: 1)
    --mode=diff|odb-blob      Scan mode (default: odb-blob)
    --merge=all|first-parent  Merge diff mode (default: all)
    --pack-exec-workers=<N>   Pack exec workers
    --tree-delta-cache-mb=<N> Tree delta cache (default: 128)
    --engine-chunk-mb=<N>     Engine chunk size (default: 1)
    --decode-depth=<N>        Max decode depth (default: 2)
    --anchors=manual|derived  Anchor mode (default: manual)
    --debug                   Verbose stage stats to stderr
    --perf-breakdown          Pack execution timing breakdown
    --event-format=jsonl      Output format (default: jsonl)
    --help, -h                Show this help"
    );
}
