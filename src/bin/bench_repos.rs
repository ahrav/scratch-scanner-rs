//! Scan sibling repositories and report throughput.

use scanner_rs::{
    demo_engine_with_anchor_mode_and_tuning, demo_tuning, AnchorMode, FileId, ScannerConfig,
    ScannerRuntime, BUFFER_LEN_MAX,
};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

struct Repo {
    name: String,
    path: PathBuf,
}

struct RunResult {
    bytes: u64,
    errors: u64,
    elapsed_s: f64,
}

fn is_repo_dir(path: &Path) -> bool {
    let git_dir = path.join(".git");
    if git_dir.is_dir() {
        return true;
    }
    if git_dir.is_file() {
        return true; // Worktrees/submodules can store .git as a file.
    }
    false
}

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

fn scan_repo(engine: &Arc<scanner_rs::Engine>, path: &Path) -> io::Result<RunResult> {
    let start = Instant::now();
    let overlap = engine.required_overlap();
    let chunk_size = BUFFER_LEN_MAX.saturating_sub(overlap).max(1);
    let config = ScannerConfig {
        chunk_size,
        io_queue: 2,
        reader_threads: 1,
        scan_threads: 1,
        max_findings_per_file: 16_384,
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
            let path = entry.path();
            let name = match path.file_name().and_then(OsStr::to_str) {
                Some(n) => n,
                None => {
                    errors = errors.saturating_add(1);
                    continue;
                }
            };
            if path.is_dir() {
                if should_skip_dir(name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !path.is_file() {
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
        elapsed_s: elapsed.max(0.000_000_1),
    })
}

fn format_mib_s(bytes: u64, elapsed_s: f64) -> f64 {
    if elapsed_s <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed_s
}

fn print_usage(exe: &str) {
    eprintln!("Usage: {exe} [options]");
    eprintln!("Options:");
    eprintln!("  --root <path>          Root directory (default: parent of cwd)");
    eprintln!("  --anchors=manual|derived Anchor policy (default: manual)");
    eprintln!("  --filter <substr>      Only include repos with name containing substr");
    eprintln!("  --max-repos <n>         Limit number of repos scanned");
    eprintln!("  --help, -h             Show this help");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let exe = args.first().map(|s| s.as_str()).unwrap_or("bench_repos");
    let mut root: Option<PathBuf> = None;
    let mut anchor_mode = AnchorMode::Manual;
    let mut filter: Option<String> = None;
    let mut max_repos: Option<usize> = None;

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
                    eprintln!("Error: --filter requires a string");
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

    let tuning = demo_tuning();
    let engine = Arc::new(demo_engine_with_anchor_mode_and_tuning(anchor_mode, tuning));

    eprintln!("Scanning {} repos under {}", repos.len(), root.display());
    eprintln!("anchor_mode={:?}", anchor_mode);
    eprintln!("{:<28} {:>8} {:>9} {:>6}", "repo", "MiB", "MiB/s", "errs");

    let mut total_bytes = 0u64;
    let mut total_time = 0.0;
    let mut total_errs = 0u64;

    for repo in repos.iter() {
        let res = scan_repo(&engine, &repo.path)?;
        let mib_s = format_mib_s(res.bytes, res.elapsed_s);
        eprintln!(
            "{:<28} {:>8.0} {:>9.2} {:>6}",
            repo.name,
            (res.bytes as f64 / (1024.0 * 1024.0)),
            mib_s,
            res.errors
        );
        total_bytes = total_bytes.saturating_add(res.bytes);
        total_time += res.elapsed_s;
        total_errs = total_errs.saturating_add(res.errors);
    }

    let total_mib_s = format_mib_s(total_bytes, total_time);
    eprintln!("---");
    eprintln!("TOTAL {:>22} {:>9.2} {:>6}", "", total_mib_s, total_errs);

    Ok(())
}
