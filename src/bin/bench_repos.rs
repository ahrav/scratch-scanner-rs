//! Scan sibling repositories and report throughput + findings counts.
//!
//! Supports `ContextMode` toggles and optional TSV outputs for summary,
//! per-rule counts, and raw findings listings.

use scanner_rs::{
    demo_rules, demo_transforms, demo_tuning, AnchorMode, AnchorPolicy, ContextMode, Engine,
    FileId, ScannerConfig, ScannerRuntime, BUFFER_LEN_MAX,
};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use std::{collections::HashMap, fs::File};

struct Repo {
    name: String,
    path: PathBuf,
}

struct RunResult {
    bytes: u64,
    errors: u64,
    elapsed_s: f64,
    findings: u64,
    rule_counts: Vec<u64>,
}

/// Optional TSV outputs for summary, per-rule, and raw findings listings.
struct OutputWriters {
    summary: Option<BufWriter<File>>,
    per_rule: Option<BufWriter<File>>,
    findings: Option<BufWriter<File>>,
}

impl OutputWriters {
    fn write_summary_header(&mut self) -> io::Result<()> {
        if let Some(writer) = self.summary.as_mut() {
            writeln!(
                writer,
                "repo\tbytes\telapsed_s\tmib_s\tfindings\terrors\tcontext_mode"
            )?;
        }
        Ok(())
    }

    fn write_per_rule_header(&mut self) -> io::Result<()> {
        if let Some(writer) = self.per_rule.as_mut() {
            writeln!(writer, "repo\trule\tcount\tcontext_mode")?;
        }
        Ok(())
    }

    fn write_findings_header(&mut self) -> io::Result<()> {
        if let Some(writer) = self.findings.as_mut() {
            writeln!(
                writer,
                "repo\tpath\trule\troot_start\troot_end\tspan_start\tspan_end\tcontext_mode"
            )?;
        }
        Ok(())
    }
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

fn scan_repo(
    engine: &Arc<Engine>,
    path: &Path,
    repo_name: &str,
    context_mode: ContextMode,
    rule_index: &HashMap<&'static str, usize>,
    mut findings_out: Option<&mut BufWriter<File>>,
    max_findings_out: Option<usize>,
) -> io::Result<RunResult> {
    let start = Instant::now();
    let overlap = engine.required_overlap();
    let chunk_size = BUFFER_LEN_MAX.saturating_sub(overlap).max(1);
    let config = ScannerConfig {
        chunk_size,
        io_queue: 2,
        reader_threads: 1,
        scan_threads: 1,
        max_findings_per_file: 16_384,
        context_mode,
    };
    let mut runtime = ScannerRuntime::new(Arc::clone(engine), config);

    let mut bytes = 0u64;
    let mut errors = 0u64;
    let mut findings = 0u64;
    let mut rule_counts = vec![0u64; rule_index.len()];
    let mut written_findings = 0usize;
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
            let scan_path = entry.path();
            match runtime.scan_file_sync(fid, &scan_path) {
                Ok(findings_buf) => {
                    findings = findings.saturating_add(findings_buf.len() as u64);
                    for finding in findings_buf {
                        if let Some(idx) = rule_index.get(finding.rule) {
                            rule_counts[*idx] = rule_counts[*idx].saturating_add(1);
                        }
                        if let Some(writer) = findings_out.as_deref_mut() {
                            if let Some(limit) = max_findings_out {
                                if written_findings >= limit {
                                    continue;
                                }
                            }
                            let path = sanitize_field(&scan_path.to_string_lossy());
                            let rule = sanitize_field(finding.rule);
                            writeln!(
                                writer,
                                "{repo}\t{path}\t{rule}\t{}\t{}\t{}\t{}\t{}",
                                finding.root_span_hint.start,
                                finding.root_span_hint.end,
                                finding.span.start,
                                finding.span.end,
                                context_mode_label(context_mode),
                                repo = repo_name
                            )?;
                            written_findings = written_findings.saturating_add(1);
                        }
                    }
                }
                Err(_) => {
                    errors = errors.saturating_add(1);
                }
            };
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    Ok(RunResult {
        bytes,
        errors,
        elapsed_s: elapsed.max(0.000_000_1),
        findings,
        rule_counts,
    })
}

fn format_mib_s(bytes: u64, elapsed_s: f64) -> f64 {
    if elapsed_s <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed_s
}

fn context_mode_label(mode: ContextMode) -> &'static str {
    match mode {
        ContextMode::Off => "off",
        ContextMode::Filter => "filter",
        ContextMode::Score => "score",
    }
}

/// Replace control separators to keep TSV output parseable.
fn sanitize_field(input: &str) -> String {
    input.replace(['\t', '\n', '\r'], " ")
}

fn print_usage(exe: &str) {
    eprintln!("Usage: {exe} [options]");
    eprintln!("Options:");
    eprintln!("  --root <path>          Root directory (default: parent of cwd)");
    eprintln!("  --anchors=manual|derived Anchor policy (default: manual)");
    eprintln!("  --context=off|filter|score Context mode (default: off)");
    eprintln!("  --filter <substr>      Only include repos with name containing substr");
    eprintln!("  --max-repos <n>         Limit number of repos scanned");
    eprintln!("  --summary-out <path>    Write TSV summary to file");
    eprintln!("  --per-rule-out <path>   Write TSV per-rule counts to file");
    eprintln!("  --findings-out <path>   Write TSV findings list to file");
    eprintln!("  --max-findings-out <n>  Limit findings written per repo");
    eprintln!("  --quiet                Suppress stderr table output");
    eprintln!("  --help, -h             Show this help");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let exe = args.first().map(|s| s.as_str()).unwrap_or("bench_repos");
    let mut root: Option<PathBuf> = None;
    let mut anchor_mode = AnchorMode::Manual;
    let mut filter: Option<String> = None;
    let mut max_repos: Option<usize> = None;
    let mut context_mode = ContextMode::Off;
    let mut summary_out: Option<PathBuf> = None;
    let mut per_rule_out: Option<PathBuf> = None;
    let mut findings_out: Option<PathBuf> = None;
    let mut max_findings_out: Option<usize> = None;
    let mut quiet = false;

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
            s if s.starts_with("--context=") => {
                let v = s.trim_start_matches("--context=");
                context_mode = match v {
                    "off" => ContextMode::Off,
                    "filter" => ContextMode::Filter,
                    "score" => ContextMode::Score,
                    _ => {
                        eprintln!("invalid --context value: {v}");
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
            "--summary-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --summary-out requires a path");
                    print_usage(exe);
                    std::process::exit(2);
                }
                summary_out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--per-rule-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --per-rule-out requires a path");
                    print_usage(exe);
                    std::process::exit(2);
                }
                per_rule_out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--findings-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --findings-out requires a path");
                    print_usage(exe);
                    std::process::exit(2);
                }
                findings_out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--max-findings-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --max-findings-out requires a number");
                    print_usage(exe);
                    std::process::exit(2);
                }
                max_findings_out = args[i + 1].parse::<usize>().ok();
                i += 2;
            }
            "--quiet" => {
                quiet = true;
                i += 1;
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
    let policy = match anchor_mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    let rules = demo_rules();
    let rule_names: Vec<&'static str> = rules.iter().map(|r| r.name).collect();
    let mut rule_index = HashMap::with_capacity(rule_names.len());
    for (idx, name) in rule_names.iter().enumerate() {
        rule_index.insert(*name, idx);
    }
    let engine = Arc::new(Engine::new_with_anchor_policy(
        rules,
        demo_transforms(),
        tuning,
        policy,
    ));

    let mut writers = OutputWriters {
        summary: match summary_out {
            Some(path) => Some(BufWriter::new(File::create(path)?)),
            None => None,
        },
        per_rule: match per_rule_out {
            Some(path) => Some(BufWriter::new(File::create(path)?)),
            None => None,
        },
        findings: match findings_out {
            Some(path) => Some(BufWriter::new(File::create(path)?)),
            None => None,
        },
    };
    writers.write_summary_header()?;
    writers.write_per_rule_header()?;
    writers.write_findings_header()?;

    if !quiet {
        eprintln!("Scanning {} repos under {}", repos.len(), root.display());
        eprintln!(
            "anchor_mode={:?} context_mode={}",
            anchor_mode,
            context_mode_label(context_mode)
        );
        eprintln!(
            "{:<28} {:>8} {:>9} {:>9} {:>6}",
            "repo", "MiB", "MiB/s", "finds", "errs"
        );
    }

    let mut total_bytes = 0u64;
    let mut total_time = 0.0;
    let mut total_errs = 0u64;
    let mut total_findings = 0u64;

    for repo in repos.iter() {
        let res = scan_repo(
            &engine,
            &repo.path,
            &repo.name,
            context_mode,
            &rule_index,
            writers.findings.as_mut(),
            max_findings_out,
        )?;
        let mib_s = format_mib_s(res.bytes, res.elapsed_s);
        if !quiet {
            eprintln!(
                "{:<28} {:>8.0} {:>9.2} {:>9} {:>6}",
                repo.name,
                (res.bytes as f64 / (1024.0 * 1024.0)),
                mib_s,
                res.findings,
                res.errors
            );
        }
        if let Some(writer) = writers.summary.as_mut() {
            writeln!(
                writer,
                "{}\t{}\t{:.6}\t{:.3}\t{}\t{}\t{}",
                repo.name,
                res.bytes,
                res.elapsed_s,
                mib_s,
                res.findings,
                res.errors,
                context_mode_label(context_mode)
            )?;
        }
        if let Some(writer) = writers.per_rule.as_mut() {
            for (idx, name) in rule_names.iter().enumerate() {
                let count = res.rule_counts[idx];
                if count == 0 {
                    continue;
                }
                writeln!(
                    writer,
                    "{}\t{}\t{}\t{}",
                    repo.name,
                    name,
                    count,
                    context_mode_label(context_mode)
                )?;
            }
        }
        total_bytes = total_bytes.saturating_add(res.bytes);
        total_time += res.elapsed_s;
        total_errs = total_errs.saturating_add(res.errors);
        total_findings = total_findings.saturating_add(res.findings);
    }

    let total_mib_s = format_mib_s(total_bytes, total_time);
    if !quiet {
        eprintln!("---");
        eprintln!(
            "TOTAL {:>22} {:>9.2} {:>9} {:>6}",
            "", total_mib_s, total_findings, total_errs
        );
    }

    Ok(())
}
