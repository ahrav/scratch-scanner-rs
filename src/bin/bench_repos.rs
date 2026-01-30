//! Benchmark comparison of prefilter modes (Regex vs Auto) across repositories.
//!
//! This tool scans sibling repositories using two different prefilter configurations
//! and reports throughput (MiB/s) for each, allowing direct performance comparison.
//!
//! # Usage
//!
//! ```bash
//! # Run from within a repo; scans siblings in parent directory
//! cargo run --release --bin bench_repos
//!
//! # Specify a custom root directory
//! cargo run --release --bin bench_repos -- --root /path/to/repos
//!
//! # Filter to repos containing "api" in their name
//! cargo run --release --bin bench_repos -- --filter api
//!
//! # Limit to first 5 repos
//! cargo run --release --bin bench_repos -- --max-repos 5
//!
//! # Control scan order (for cache warming fairness)
//! cargo run --release --bin bench_repos -- --order regex-first
//! cargo run --release --bin bench_repos -- --order auto-first
//! cargo run --release --bin bench_repos -- --order alternate  # default
//!
//! # Enable detailed stats (requires "stats" feature)
//! cargo run --release --bin bench_repos --features stats
//! ```
//!
//! # Output Format
//!
//! The output is a table with columns:
//! - `repo`: Repository name
//! - `MiB`: Total bytes attempted (not necessarily scanned, some files may error)
//! - `regex`: Throughput in MiB/s using `PrefilterMode::Regex`
//! - `auto`: Throughput in MiB/s using `PrefilterMode::Auto`
//! - `delta%`: Percentage difference (`(auto - regex) / regex * 100`)
//! - `errs`: Total I/O errors encountered across both runs
//!
//! Positive delta% means Auto mode is faster; negative means Regex mode is faster.

#[cfg(feature = "stats")]
use scanner_rs::VectorscanStats;
use scanner_rs::{
    demo_engine_with_anchor_mode_and_tuning, demo_tuning, AnchorMode, FileId, PrefilterMode,
    ScannerConfig, ScannerRuntime, BUFFER_LEN_MAX,
};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Controls which prefilter mode runs first for each repository.
///
/// Scan order matters for benchmark fairness because the first scan warms filesystem
/// caches, giving the second scan an advantage. Different orderings help identify
/// whether observed differences are due to prefilter performance or cache effects.
#[derive(Clone, Copy)]
enum Order {
    /// Always run Regex mode first (Auto benefits from warm cache).
    RegexFirst,
    /// Always run Auto mode first (Regex benefits from warm cache).
    AutoFirst,
    /// Alternate which runs first per repo (fairest for aggregate comparisons).
    Alternate,
}

impl Order {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "regex-first" => Some(Self::RegexFirst),
            "auto-first" | "anchor-first" => Some(Self::AutoFirst),
            "alternate" => Some(Self::Alternate),
            _ => None,
        }
    }
}

/// A discovered repository to benchmark.
struct Repo {
    /// Repository directory name (used for display in output table).
    name: String,
    /// Absolute path to the repository root.
    path: PathBuf,
}

/// Result of scanning a single repository with one prefilter mode.
struct RunResult {
    /// Total bytes *attempted* (sum of file sizes), not necessarily all successfully scanned.
    bytes: u64,
    /// Count of I/O errors encountered (directory reads, file reads, metadata access).
    errors: u64,
    /// Wall-clock time for the scan in seconds.
    elapsed_s: f64,
}

/// Checks if a directory is a git repository.
///
/// Returns `true` if the directory contains a `.git` entry, which may be either:
/// - A directory (standard git repos)
/// - A file (git worktrees and submodules store a pointer file instead)
fn is_repo_dir(path: &Path) -> bool {
    let git_dir = path.join(".git");
    if git_dir.is_dir() {
        return true;
    }
    // Worktrees and submodules use a .git *file* pointing to the actual git dir.
    if git_dir.is_file() {
        return true;
    }
    false
}

/// Discovers git repositories in the immediate children of `root`.
///
/// Only performs single-level discovery (does not recurse into subdirectories).
/// Results are sorted alphabetically by name for deterministic ordering.
///
/// # Arguments
/// - `filter`: If `Some`, only includes repos whose name *contains* this substring.
/// - `max_repos`: If `Some`, stops after discovering this many repos (before sorting).
fn discover_repos(
    root: &Path,
    filter: Option<&str>,
    max_repos: Option<usize>,
) -> io::Result<Vec<Repo>> {
    let mut repos = Vec::new();
    let entries = fs::read_dir(root)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(OsStr::to_str) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        if let Some(f) = filter {
            if !name.contains(f) {
                continue;
            }
        }
        if !is_repo_dir(&path) {
            continue;
        }
        repos.push(Repo { name, path });
        if let Some(max) = max_repos {
            if repos.len() >= max {
                break;
            }
        }
    }
    repos.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(repos)
}

/// Returns `true` for directories that should be skipped during scanning.
///
/// Skipped directories include:
/// - VCS internals (`.git`, `.hg`, `.svn`)
/// - Build artifacts (`target`, `dist`, `build`, `out`, `.next`)
/// - Dependencies (`node_modules`)
/// - Caches (`.cache`, `__pycache__`)
/// - Virtual environments (`.venv`, `venv`)
///
/// These directories typically contain generated/vendored content that inflates
/// scan time without providing meaningful benchmark signal.
fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "target"
            | "node_modules"
            | "dist"
            | "build"
            | "out"
            | ".next"
            | ".cache"
            | ".venv"
            | "venv"
            | "__pycache__"
    )
}

/// Scans all files in a repository using synchronous single-threaded I/O.
///
/// Uses a deliberately constrained configuration to isolate prefilter performance:
/// - Single-threaded scanning eliminates thread scheduling variance
/// - Synchronous I/O avoids async runtime overhead
/// - High findings limit prevents truncation from affecting timing
///
/// Errors (permission denied, broken symlinks, etc.) are counted but do not
/// abort the scan—we continue to get throughput numbers even for repos with
/// some inaccessible files.
fn scan_repo(engine: &Arc<scanner_rs::Engine>, path: &Path) -> io::Result<RunResult> {
    let start = Instant::now();
    let overlap = engine.required_overlap();
    let chunk_size = BUFFER_LEN_MAX.saturating_sub(overlap).max(1);
    let config = ScannerConfig {
        chunk_size,
        io_queue: 2,        // Minimal queue depth for sequential scanning.
        reader_threads: 1,  // Single-threaded to isolate prefilter performance.
        scan_threads: 1,    // Single-threaded to isolate prefilter performance.
        max_findings_per_file: 16_384, // High limit to avoid truncation affecting timing.
    };
    let mut runtime = ScannerRuntime::new(Arc::clone(engine), config);

    let mut bytes = 0u64;
    let mut errors = 0u64;
    let mut file_id = 0u32;
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                errors = errors.saturating_add(1);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    errors = errors.saturating_add(1);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => {
                    errors = errors.saturating_add(1);
                    continue;
                }
            };
            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or_default();

            if file_type.is_dir() {
                // Skip symlinked directories to avoid infinite loops and double-counting.
                if file_type.is_symlink() || should_skip_dir(name_str) {
                    continue;
                }
                stack.push(entry.path());
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    errors = errors.saturating_add(1);
                    continue;
                }
            };
            bytes = bytes.saturating_add(meta.len());
            let fid = FileId(file_id);
            file_id = file_id.saturating_add(1);
            if runtime.scan_file_sync(fid, &entry.path()).is_err() {
                errors = errors.saturating_add(1);
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    Ok(RunResult {
        bytes,
        errors,
        // Epsilon floor prevents division by zero in throughput calculations.
        elapsed_s: elapsed.max(0.000_000_1),
    })
}

/// Calculates throughput in MiB/s (mebibytes per second).
fn format_mib_s(bytes: u64, elapsed_s: f64) -> f64 {
    if elapsed_s <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed_s
}

/// Logs detailed Auto-mode statistics when performance is notably worse than Regex.
///
/// Only prints stats when `delta_pct < -5.0` (Auto is 5%+ slower than Regex).
/// This threshold filters out noise—small differences aren't actionable, but
/// significant regressions warrant investigation of the mode selection heuristics.
#[cfg(feature = "stats")]
fn maybe_log_auto_stats(before: VectorscanStats, after: VectorscanStats, delta_pct: f64) {
    // Only log when Auto is meaningfully slower (5%+ regression).
    if delta_pct >= -5.0 {
        return;
    }
    let auto_anchor = after
        .auto_anchor_scans
        .saturating_sub(before.auto_anchor_scans);
    let auto_regex = after
        .auto_regex_scans
        .saturating_sub(before.auto_regex_scans);
    let gate_allow = after.auto_gate_allow.saturating_sub(before.auto_gate_allow);
    let gate_reject = after
        .auto_gate_reject
        .saturating_sub(before.auto_gate_reject);
    let gate_missing = after
        .auto_gate_missing
        .saturating_sub(before.auto_gate_missing);
    let aborts = after
        .auto_anchor_aborts
        .saturating_sub(before.auto_anchor_aborts);
    let anchor_bytes = after
        .auto_anchor_bytes
        .saturating_sub(before.auto_anchor_bytes);
    let regex_bytes = after
        .auto_regex_bytes
        .saturating_sub(before.auto_regex_bytes);
    let total = auto_anchor.saturating_add(auto_regex);
    let anchor_pct = if total > 0 {
        (auto_anchor as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let total_bytes = anchor_bytes.saturating_add(regex_bytes);
    let anchor_bytes_pct = if total_bytes > 0 {
        (anchor_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };
    eprintln!(
        "  auto_scans: anchor={} regex={} (anchor%={:.1}, bytes%={:.1}) gate_allow={} gate_reject={} gate_missing={} aborts={}",
        auto_anchor,
        auto_regex,
        anchor_pct,
        anchor_bytes_pct,
        gate_allow,
        gate_reject,
        gate_missing,
        aborts
    );
}

fn print_usage(exe: &str) {
    eprintln!("Usage: {exe} [options]");
    eprintln!("Options:");
    eprintln!("  --root <path>          Root directory (default: parent of cwd)");
    eprintln!("  --anchors=manual|derived Anchor policy (default: manual)");
    eprintln!("  --filter <substr>      Only include repos with name containing substr");
    eprintln!("  --max-repos <n>         Limit number of repos scanned");
    eprintln!(
        "  --order <mode>          regex-first | auto-first | alternate (default: alternate)"
    );
    eprintln!("  --help, -h             Show this help");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let exe = args.first().map(|s| s.as_str()).unwrap_or("bench_repos");
    let mut root: Option<PathBuf> = None;
    let mut anchor_mode = AnchorMode::Manual;
    let mut filter: Option<String> = None;
    let mut max_repos: Option<usize> = None;
    let mut order = Order::Alternate;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --root requires a path");
                    print_usage(exe);
                    std::process::exit(2);
                }
                root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            s if s.starts_with("--anchors=") => {
                let v = s.trim_start_matches("--anchors=");
                anchor_mode = match v {
                    "manual" => AnchorMode::Manual,
                    "derived" => AnchorMode::Derived,
                    _ => {
                        eprintln!("invalid --anchors value: {v}");
                        std::process::exit(2);
                    }
                };
                i += 1;
            }
            "--filter" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --filter requires a value");
                    print_usage(exe);
                    std::process::exit(2);
                }
                filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--max-repos" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --max-repos requires a number");
                    print_usage(exe);
                    std::process::exit(2);
                }
                max_repos = args[i + 1].parse::<usize>().ok();
                i += 2;
            }
            "--order" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --order requires a value");
                    print_usage(exe);
                    std::process::exit(2);
                }
                order = Order::parse(&args[i + 1]).unwrap_or_else(|| {
                    eprintln!("invalid --order value: {}", args[i + 1]);
                    std::process::exit(2);
                });
                i += 2;
            }
            "--help" | "-h" => {
                print_usage(exe);
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage(exe);
                std::process::exit(2);
            }
        }
    }

    let root = match root {
        Some(p) => p,
        None => {
            let cwd = env::current_dir()?;
            cwd.parent().map(|p| p.to_path_buf()).unwrap_or(cwd)
        }
    };

    let repos = discover_repos(&root, filter.as_deref(), max_repos)?;
    if repos.is_empty() {
        eprintln!("No repos found under {}", root.display());
        return Ok(());
    }

    let mut tuning_regex = demo_tuning();
    tuning_regex.prefilter_mode = PrefilterMode::Regex;
    let mut tuning_auto = demo_tuning();
    tuning_auto.prefilter_mode = PrefilterMode::Auto;

    let engine_regex = Arc::new(demo_engine_with_anchor_mode_and_tuning(
        anchor_mode,
        tuning_regex,
    ));
    let engine_auto = Arc::new(demo_engine_with_anchor_mode_and_tuning(
        anchor_mode,
        tuning_auto,
    ));

    eprintln!("Scanning {} repos under {}", repos.len(), root.display());
    eprintln!(
        "anchor_mode={:?} order={:?}",
        anchor_mode,
        match order {
            Order::RegexFirst => "regex-first",
            Order::AutoFirst => "auto-first",
            Order::Alternate => "alternate",
        }
    );
    eprintln!(
        "{:<28} {:>8} {:>9} {:>9} {:>8} {:>6}",
        "repo", "MiB", "regex", "auto", "delta%", "errs"
    );

    let mut total_regex_bytes = 0u64;
    let mut total_auto_bytes = 0u64;
    let mut total_regex_time = 0.0;
    let mut total_auto_time = 0.0;

    for (idx, repo) in repos.iter().enumerate() {
        let regex_first = match order {
            Order::RegexFirst => true,
            Order::AutoFirst => false,
            Order::Alternate => idx % 2 == 0,
        };

        #[cfg(feature = "stats")]
        let (regex_res, auto_res, auto_stats) = if regex_first {
            let r = scan_repo(&engine_regex, &repo.path)?;
            let before = engine_auto.vectorscan_stats();
            let a = scan_repo(&engine_auto, &repo.path)?;
            let after = engine_auto.vectorscan_stats();
            (r, a, Some((before, after)))
        } else {
            let before = engine_auto.vectorscan_stats();
            let a = scan_repo(&engine_auto, &repo.path)?;
            let after = engine_auto.vectorscan_stats();
            let r = scan_repo(&engine_regex, &repo.path)?;
            (r, a, Some((before, after)))
        };
        #[cfg(not(feature = "stats"))]
        let (regex_res, auto_res) = if regex_first {
            let r = scan_repo(&engine_regex, &repo.path)?;
            let a = scan_repo(&engine_auto, &repo.path)?;
            (r, a)
        } else {
            let a = scan_repo(&engine_auto, &repo.path)?;
            let r = scan_repo(&engine_regex, &repo.path)?;
            (r, a)
        };

        let regex_mib_s = format_mib_s(regex_res.bytes, regex_res.elapsed_s);
        let auto_mib_s = format_mib_s(auto_res.bytes, auto_res.elapsed_s);
        let delta = if regex_mib_s > 0.0 {
            (auto_mib_s / regex_mib_s - 1.0) * 100.0
        } else {
            0.0
        };

        eprintln!(
            "{:<28} {:>8.0} {:>9.2} {:>9.2} {:>+7.1}% {:>6}",
            repo.name,
            (regex_res.bytes as f64 / (1024.0 * 1024.0)),
            regex_mib_s,
            auto_mib_s,
            delta,
            regex_res.errors + auto_res.errors
        );
        #[cfg(feature = "stats")]
        if let Some((before, after)) = auto_stats {
            maybe_log_auto_stats(before, after, delta);
        }

        total_regex_bytes = total_regex_bytes.saturating_add(regex_res.bytes);
        total_auto_bytes = total_auto_bytes.saturating_add(auto_res.bytes);
        total_regex_time += regex_res.elapsed_s;
        total_auto_time += auto_res.elapsed_s;
    }

    let total_regex_mib_s = format_mib_s(total_regex_bytes, total_regex_time);
    let total_auto_mib_s = format_mib_s(total_auto_bytes, total_auto_time);
    let total_delta = if total_regex_mib_s > 0.0 {
        (total_auto_mib_s / total_regex_mib_s - 1.0) * 100.0
    } else {
        0.0
    };

    eprintln!("---");
    eprintln!(
        "TOTAL {:>22} {:>9.2} {:>9.2} {:>+7.1}%",
        "", total_regex_mib_s, total_auto_mib_s, total_delta
    );

    Ok(())
}
