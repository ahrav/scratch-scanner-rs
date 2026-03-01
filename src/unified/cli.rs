//! Subcommand CLI parser for the unified scanner.
//!
//! Hand-rolled (no clap dependency) to keep binary size small and boot fast.
//!
//! # Grammar
//!
//! ```text
//! scanner-rs scan fs --path <dir|file>  [FS_FLAGS]
//! scanner-rs scan git --repo <path>     [GIT_FLAGS]
//! scanner-rs store <command>            [STORE_FLAGS]
//! scanner-rs --help | -h
//! ```

use std::env;
use std::io;
use std::path::PathBuf;

use crate::api::TransformId;
use crate::git_scan::{GitScanMode, MergeDiffMode};
use crate::AnchorMode;

use super::{
    DebugLevel, EventFormat, ExecutionMode, FsScanConfig, GitSourceConfig, OutputFormat,
    SourceConfig, StoreCommand,
};

/// Controls which transform decoders are active during a scan.
///
/// The scanner supports multiple transform types (URL percent-decoding,
/// Base64 decoding) that produce derived buffers for secondary scanning.
/// This filter lets the user selectively enable/disable individual
/// transforms — e.g., to measure per-transform overhead, debug false
/// positives from a specific decoder, or skip transforms entirely for
/// raw-only scanning.
///
/// # Relationship to `--decode-depth`
///
/// `--decode-depth` controls how many *layers* of recursive decoding are
/// applied; `TransformFilter` controls *which* decoders participate at
/// every layer. The two are orthogonal: `--transforms=base64` with
/// `--decode-depth=3` still recurses up to 3 levels, but only using
/// the Base64 decoder.
///
/// # Mapping to engine types
///
/// CLI names are defined by [`TransformId::cli_name()`]:
///
/// | CLI name   | `TransformId` variant |
/// |------------|-----------------------|
/// | `"url"`    | `UrlPercent`          |
/// | `"base64"` | `Base64`              |
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransformFilter {
    /// Enable all available transforms (default).
    #[default]
    All,
    /// Disable all transforms — scan raw buffers only.
    None,
    /// Enable only the listed transforms (converted from CLI names at parse time).
    Only(Vec<TransformId>),
}

/// Top-level configuration produced by CLI parsing.
///
/// Combines the scan source (filesystem, git, or store query) with
/// cross-cutting options that apply regardless of source type. The
/// orchestrator consumes this directly — no further validation is needed
/// beyond what `parse_args` already enforces.
pub struct ScanConfig {
    /// What to scan (or query, in store mode).
    pub source: SourceConfig,
    /// Wire format for streaming scan events to stdout.
    pub event_format: EventFormat,
    /// Enable verbose output (used by text event format).
    pub verbose: bool,
    /// Optional path to a YAML rules file. When `None`, the orchestrator
    /// falls back to `default_rules.yaml` next to the binary, then the
    /// compiled-in demo rules.
    pub rules_file: Option<PathBuf>,
    /// Which transform decoders to enable. Applied as a pre-engine filter
    /// on [`demo_transforms()`](crate::demo_transforms) output. In git
    /// scans, the filtered list also feeds into the policy hash, so
    /// disabling a transform correctly invalidates cached scan results.
    pub transform_filter: TransformFilter,
    /// Use a no-op event sink (drops all findings). For measuring scan
    /// overhead without JSON encoding + stdout I/O.
    pub null_sink: bool,
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
        "store" => {
            let store_cmd = parse_store_subcommand(args);
            return Ok(ScanConfig {
                source: SourceConfig::Store(store_cmd),
                event_format: EventFormat::default(),
                verbose: false,
                rules_file: None,
                transform_filter: TransformFilter::default(),
                null_sink: false,
            });
        }
        _ => {
            eprintln!(
                "error: expected 'scan' or 'store' subcommand, got '{}'",
                first_str
            );
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

/// Parse `--path`, `--workers`, and other FS-specific flags from the
/// remaining argument iterator. Accepts `--path=<dir>` or a bare positional
/// path. Exits with code 2 on unrecognised flags or missing `--path`.
fn parse_fs_args(args: impl Iterator<Item = std::ffi::OsString>) -> io::Result<ScanConfig> {
    let mut path: Option<PathBuf> = None;
    let mut workers: Option<usize> = None;
    let mut decode_depth: Option<usize> = None;
    let mut skip_archives = false;
    let mut null_sink = false;
    let mut scan_binary = false;
    let mut persist_findings = false;
    let mut execution_mode = ExecutionMode::Direct;
    let mut verbose = false;
    let mut anchor_mode = AnchorMode::Manual;
    let mut event_format = EventFormat::Jsonl;
    let mut rules_file: Option<PathBuf> = None;
    let mut transform_filter = TransformFilter::All;

    for arg in args {
        // Handle --rules= before UTF-8 conversion since paths may be non-UTF8.
        if let Some(rest) = strip_os_prefix(&arg, "--rules=") {
            if rest.is_empty() {
                eprintln!("error: --rules requires a file path");
                std::process::exit(2);
            }
            rules_file = Some(PathBuf::from(rest));
            continue;
        }

        // Handle --transforms= before UTF-8 gate so non-UTF-8 args aren't
        // silently misinterpreted as positional paths.
        if let Some(rest) = strip_os_prefix(&arg, "--transforms=") {
            let value = rest.to_str().unwrap_or_else(|| {
                eprintln!("error: --transforms value must be valid UTF-8");
                std::process::exit(2);
            });
            transform_filter = parse_transforms(value);
            continue;
        }

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
            if let Some(rest) = flag.strip_prefix("--execution-mode=") {
                execution_mode = parse_execution_mode(rest);
                continue;
            }
            match flag {
                "--skip-archives" => {
                    skip_archives = true;
                    continue;
                }
                "--scan-archives" => {
                    skip_archives = false;
                    continue;
                }
                "--null-sink" => {
                    null_sink = true;
                    continue;
                }
                "--scan-binary" => {
                    scan_binary = true;
                    continue;
                }
                "--skip-binary" => {
                    scan_binary = false;
                    continue;
                }
                "--persist-findings" => {
                    persist_findings = true;
                    continue;
                }
                "--verbose" => {
                    verbose = true;
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
            skip_archives,
            anchor_mode,
            scan_binary,
            persist_findings,
            execution_mode,
        }),
        event_format,
        verbose,
        rules_file,
        transform_filter,
        null_sink,
    })
}

/// Parse git-specific flags from the remaining argument iterator.
/// Accepts `--repo=<path>` or a bare positional path. Exits with code 2
/// on unrecognised flags or missing `--repo`.
///
/// Public `--workers=<N>` is normalised to the git runner's
/// `pack_exec_workers` setting so caller-facing concurrency controls stay
/// aligned with `scan fs`.
fn parse_git_args(args: impl Iterator<Item = std::ffi::OsString>) -> io::Result<ScanConfig> {
    let mut repo: Option<PathBuf> = None;
    let mut repo_id: u64 = 1;
    let mut scan_mode = GitScanMode::OdbBlobFast;
    let mut merge_mode = MergeDiffMode::AllParents;
    let mut anchor_mode = AnchorMode::Manual;
    let mut decode_depth: Option<usize> = None;
    let mut pack_exec_workers: Option<usize> = None;
    let mut tree_delta_cache_mb: Option<u32> = None;
    let mut engine_chunk_mb: Option<u32> = None;
    let mut debug_level = DebugLevel::Off;
    let mut scan_binary = false;
    let mut enrich_identities = false;
    let mut execution_mode = ExecutionMode::Direct;
    let mut null_sink = false;
    let mut verbose = false;
    let mut event_format = EventFormat::Jsonl;
    let mut rules_file: Option<PathBuf> = None;
    let mut transform_filter = TransformFilter::All;

    for arg in args {
        // Handle --rules= before UTF-8 conversion since paths may be non-UTF8.
        if let Some(rest) = strip_os_prefix(&arg, "--rules=") {
            if rest.is_empty() {
                eprintln!("error: --rules requires a file path");
                std::process::exit(2);
            }
            rules_file = Some(PathBuf::from(rest));
            continue;
        }

        // Handle --transforms= before UTF-8 gate so non-UTF-8 args aren't
        // silently misinterpreted as positional paths.
        if let Some(rest) = strip_os_prefix(&arg, "--transforms=") {
            let value = rest.to_str().unwrap_or_else(|| {
                eprintln!("error: --transforms value must be valid UTF-8");
                std::process::exit(2);
            });
            transform_filter = parse_transforms(value);
            continue;
        }

        if let Some(flag) = arg.to_str() {
            if let Some(rest) = flag.strip_prefix("--repo=") {
                repo = Some(PathBuf::from(rest));
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--workers=") {
                // Keep source-agnostic worker semantics in the public CLI while
                // preserving the internal git runner field name.
                let n: usize = parse_or_exit(rest, "--workers");
                if n == 0 {
                    eprintln!("--workers must be >= 1");
                    std::process::exit(2);
                }
                pack_exec_workers = Some(n);
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
            if let Some(rest) = flag.strip_prefix("--event-format=") {
                event_format = parse_event_format(rest);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--execution-mode=") {
                execution_mode = parse_execution_mode(rest);
                continue;
            }
            // --- Hidden flags (--x-* prefix) -----------------------------------
            // These are unstable internal tuning knobs. They work but are
            // deliberately omitted from --help output so they don't become
            // part of the public API / semver surface.
            if let Some(rest) = flag.strip_prefix("--x-repo-id=") {
                repo_id = parse_or_exit(rest, "--x-repo-id");
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--x-mode=") {
                scan_mode = match rest {
                    "diff" | "diff-history" => GitScanMode::DiffHistory,
                    "odb-blob" | "odb-blob-fast" => GitScanMode::OdbBlobFast,
                    _ => {
                        eprintln!("invalid --x-mode value: {}", rest);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--x-merge=") {
                merge_mode = match rest {
                    "all" => MergeDiffMode::AllParents,
                    "first-parent" => MergeDiffMode::FirstParentOnly,
                    _ => {
                        eprintln!("invalid --x-merge value: {}", rest);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--x-pack-exec-workers=") {
                let n: usize = parse_or_exit(rest, "--x-pack-exec-workers");
                if n == 0 {
                    eprintln!("--x-pack-exec-workers must be >= 1");
                    std::process::exit(2);
                }
                pack_exec_workers = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--x-tree-delta-cache-mb=") {
                let n: u32 = parse_or_exit(rest, "--x-tree-delta-cache-mb");
                if n == 0 {
                    eprintln!("--x-tree-delta-cache-mb must be >= 1");
                    std::process::exit(2);
                }
                tree_delta_cache_mb = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--x-engine-chunk-mb=") {
                let n: u32 = parse_or_exit(rest, "--x-engine-chunk-mb");
                if n == 0 {
                    eprintln!("--x-engine-chunk-mb must be >= 1");
                    std::process::exit(2);
                }
                engine_chunk_mb = Some(n);
                continue;
            }
            if let Some(rest) = flag.strip_prefix("--debug=") {
                match rest {
                    "perf" => debug_level = DebugLevel::Perf,
                    _ => {
                        eprintln!(
                            "invalid --debug value: {} (expected: perf, or bare --debug for stats)",
                            rest
                        );
                        std::process::exit(2);
                    }
                }
                continue;
            }
            match flag {
                "--debug" => {
                    // Bare --debug: stage stats only (don't downgrade if
                    // --debug=perf was already seen).
                    if debug_level == DebugLevel::Off {
                        debug_level = DebugLevel::Stats;
                    }
                    continue;
                }
                "--scan-binary" => {
                    scan_binary = true;
                    continue;
                }
                "--skip-binary" => {
                    scan_binary = false;
                    continue;
                }
                "--enrich-identities" => {
                    enrich_identities = true;
                    continue;
                }
                "--null-sink" => {
                    null_sink = true;
                    continue;
                }
                "--verbose" => {
                    verbose = true;
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
            debug: debug_level,
            scan_binary,
            enrich_identities,
            execution_mode,
        }),
        event_format,
        verbose,
        rules_file,
        transform_filter,
        null_sink,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a string value into `T`, printing `"invalid {flag} value: {s}"` and
/// exiting with code 2 on parse failure. Used for numeric CLI flag values.
fn parse_or_exit<T: std::str::FromStr>(s: &str, flag: &str) -> T {
    s.parse().unwrap_or_else(|_| {
        eprintln!("invalid {} value: {}", flag, s);
        std::process::exit(2);
    })
}

/// Map a CLI string (`"manual"` | `"derived"`) to [`AnchorMode`].
/// Exits with code 2 on unrecognised values.
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

/// Map a CLI string to [`EventFormat`]. Exits with code 2 on unrecognised values.
fn parse_event_format(s: &str) -> EventFormat {
    match s {
        "jsonl" => EventFormat::Jsonl,
        "text" => EventFormat::Text,
        "json" => EventFormat::Json,
        "sarif" => EventFormat::Sarif,
        _ => {
            eprintln!(
                "invalid --event-format value: {} (expected jsonl|text|json|sarif)",
                s
            );
            std::process::exit(2);
        }
    }
}

/// Map a CLI string (`"direct"` | `"connector"`) to [`ExecutionMode`].
/// Exits with code 2 on unrecognised values.
fn parse_execution_mode(s: &str) -> ExecutionMode {
    match s {
        "direct" => ExecutionMode::Direct,
        "connector" => ExecutionMode::Connector,
        _ => {
            eprintln!(
                "invalid --execution-mode value: {} (expected direct|connector)",
                s
            );
            std::process::exit(2);
        }
    }
}

/// Parse the value of `--transforms=<value>` into a [`TransformFilter`].
///
/// Accepts `"all"`, `"none"`, or a comma-separated list of CLI names
/// defined by [`TransformId::cli_name()`]. Validation iterates
/// [`TransformId::ALL`], so adding a new variant there is sufficient
/// to accept it here.
///
/// Input is case-insensitive (including `all`/`none`) and whitespace
/// around commas is trimmed. Duplicate names are silently deduplicated
/// (first occurrence wins, preserving user-specified order). Exits with
/// code 2 on unrecognised names.
fn parse_transforms(s: &str) -> TransformFilter {
    let known_csv: String = TransformId::ALL
        .iter()
        .map(|id| id.cli_name())
        .collect::<Vec<_>>()
        .join(", ");

    let normalized = s.trim().to_lowercase();
    match normalized.as_str() {
        "" => {
            eprintln!(
                "error: --transforms requires a value (all, none, or comma-separated: {known_csv})"
            );
            std::process::exit(2);
        }
        "all" => TransformFilter::All,
        "none" => TransformFilter::None,
        _ => {
            let tokens: Vec<&str> = normalized
                .split(',')
                .map(|n| n.trim())
                .filter(|n| !n.is_empty())
                .collect();
            if tokens.is_empty() {
                eprintln!(
                    "error: --transforms requires at least one transform name (known: {known_csv})"
                );
                std::process::exit(2);
            }
            let mut ids = Vec::new();
            for tok in tokens {
                let id = TransformId::ALL
                    .iter()
                    .find(|id| id.cli_name() == tok)
                    .copied()
                    .unwrap_or_else(|| {
                        eprintln!("invalid --transforms value: '{}' (known: {known_csv})", tok);
                        std::process::exit(2);
                    });
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            TransformFilter::Only(ids)
        }
    }
}

// ---------------------------------------------------------------------------
// OsStr flag helpers
// ---------------------------------------------------------------------------

/// Extract the value from a `--flag=value` OsString without requiring UTF-8.
///
/// Returns the portion after `prefix` if the arg starts with it, or `None`.
fn strip_os_prefix<'a>(arg: &'a std::ffi::OsStr, prefix: &str) -> Option<&'a std::ffi::OsStr> {
    let bytes = arg.as_encoded_bytes();
    if bytes.starts_with(prefix.as_bytes()) {
        // SAFETY: `prefix` is pure ASCII, so splitting at its byte boundary
        // cannot break a valid platform OsStr encoding.
        Some(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&bytes[prefix.len()..]) })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Usage text
// ---------------------------------------------------------------------------

fn print_top_usage(exe: &std::ffi::OsStr) {
    let name = exe.to_string_lossy();
    eprintln!(
        "usage: {name} scan <source> [OPTIONS]
       {name} store <command> [OPTIONS]

COMMANDS:
    scan   Run a scan
    store  Query the findings database

SCAN SOURCES:
    fs    Scan filesystem path(s)
    git   Scan git repository history

STORE COMMANDS:
    list-runs       List completed scan runs
    list-findings   List findings for a specific run
    diff            Compare two runs
    list-secrets    List unique secrets

EXAMPLES:
    {name} scan fs --path /src
    {name} scan git --repo /repos/myproject
    {name} store list-runs --store-dir .scanner-store
    {name} store list-findings --store-dir .scanner-store --run <hex-id>
    {name} store diff --store-dir .scanner-store --run-a <hex-id> --run-b <hex-id>"
    );
}

fn print_fs_usage() {
    eprintln!(
        "usage: scanner-rs scan fs --path <dir|file> [OPTIONS]

OPTIONS:
    --path=<dir|file>       Path to scan (also accepted as positional arg)
    --rules=<path>          YAML rules file (default: default_rules.yaml next to binary)
    --workers=<N>           Worker threads (default: CPU count)
    --decode-depth=<N>      Max decode depth (default: 3)
    --transforms=all|none|<list>  Transforms to enable (default: all)
                            Comma-separated: base64, url (case-insensitive)
    --execution-mode=direct|connector  Execution path (default: direct)
    --null-sink             Drop all findings (measure scan overhead only)
    --persist-findings      Persist FS findings to append-log segment files

FILE TYPE OPTIONS:
    --skip-archives         Skip archive (zip/tar/gz) expansion  [default: scan]
    --scan-archives         Scan archives (undo --skip-archives) [default: scan]
    --scan-binary           Scan binary files instead of skipping [default: skip]
    --skip-binary           Skip binary files (undo --scan-binary) [default: skip]
OUTPUT OPTIONS:
    --anchors=manual|derived  Anchor mode (default: manual)
    --event-format=jsonl|text|json|sarif  Output format (default: jsonl)
    --verbose               Verbose output (text format only)
    --help, -h              Show this help"
    );
}

fn print_git_usage() {
    eprintln!(
        "usage: scanner-rs scan git --repo <path> [OPTIONS]

OPTIONS:
    --repo=<path>             Repository path (also accepted as positional arg)
    --rules=<path>            YAML rules file (default: default_rules.yaml next to binary)
    --workers=<N>             Worker threads (default: auto)
    --decode-depth=<N>        Max decode depth (default: 3)
    --transforms=all|none|<list>  Transforms to enable (default: all)
                              Comma-separated: base64, url (case-insensitive)
    --execution-mode=direct|connector  Execution path (default: direct)
    --anchors=manual|derived  Anchor mode (default: manual)
    --debug                   Verbose stage stats to stderr
    --debug=perf              Stage stats + pack execution timing breakdown
    --null-sink               Drop all findings (measure scan overhead only)
    --enrich-identities       Emit author/committer identity data

FILE TYPE OPTIONS:
    --scan-binary             Scan binary blobs instead of skipping [default: skip]
    --skip-binary             Skip binary blobs (undo --scan-binary) [default: skip]

OUTPUT OPTIONS:
    --event-format=jsonl|text|json|sarif  Output format (default: jsonl)
    --verbose                 Verbose output (text format only)
    --help, -h                Show this help"
    );
}

/// Dispatch `store <command>` to the appropriate flag parser.
///
/// The store subcommands are read-only queries against the findings database
/// and do not start a scan. Each variant collects its own `--store-dir`,
/// `--format`, and command-specific filters.
fn parse_store_subcommand(mut args: impl Iterator<Item = std::ffi::OsString>) -> StoreCommand {
    let sub = match args.next() {
        Some(a) => a,
        None => {
            eprintln!(
                "error: 'store' requires a command: list-runs, list-findings, diff, list-secrets"
            );
            std::process::exit(2);
        }
    };

    let sub_str = sub.to_string_lossy();
    match sub_str.as_ref() {
        "list-runs" => parse_store_list_runs(args),
        "list-findings" => parse_store_list_findings(args),
        "diff" => parse_store_diff(args),
        "list-secrets" => parse_store_list_secrets(args),
        "--help" | "-h" => {
            print_store_usage();
            std::process::exit(0);
        }
        _ => {
            eprintln!("error: unknown store command '{}'; expected list-runs, list-findings, diff, list-secrets", sub_str);
            std::process::exit(2);
        }
    }
}

/// Parse flags for `store list-runs` (`--store-dir`, `--status`, `--limit`, `--format`).
fn parse_store_list_runs(args: impl Iterator<Item = std::ffi::OsString>) -> StoreCommand {
    let mut store_dir = PathBuf::from(".scanner-store");
    let mut status: Option<i32> = None;
    let mut limit: usize = 50;
    let mut format = OutputFormat::Text;

    for arg in args {
        let s = arg.to_string_lossy();
        if let Some(v) = s.strip_prefix("--store-dir=") {
            store_dir = PathBuf::from(v);
        } else if let Some(v) = s.strip_prefix("--status=") {
            status = Some(parse_or_exit(v, "--status"));
        } else if let Some(v) = s.strip_prefix("--limit=") {
            limit = parse_or_exit(v, "--limit");
        } else if s == "--format=json" {
            format = OutputFormat::Json;
        } else if s == "--format=text" {
            format = OutputFormat::Text;
        } else if s == "--help" || s == "-h" {
            print_store_usage();
            std::process::exit(0);
        } else {
            eprintln!("error: unrecognized flag: {s}");
            std::process::exit(2);
        }
    }

    StoreCommand::ListRuns {
        store_dir,
        status,
        limit,
        format,
    }
}

/// Parse flags for `store list-findings`. Requires `--run=<hex-id>`.
fn parse_store_list_findings(args: impl Iterator<Item = std::ffi::OsString>) -> StoreCommand {
    let mut store_dir = PathBuf::from(".scanner-store");
    let mut run = String::new();
    let mut rule: Option<String> = None;
    let mut path: Option<String> = None;
    let mut limit: usize = 100;
    let mut format = OutputFormat::Text;

    for arg in args {
        let s = arg.to_string_lossy();
        if let Some(v) = s.strip_prefix("--store-dir=") {
            store_dir = PathBuf::from(v);
        } else if let Some(v) = s.strip_prefix("--run=") {
            run = v.to_string();
        } else if let Some(v) = s.strip_prefix("--rule=") {
            rule = Some(v.to_string());
        } else if let Some(v) = s.strip_prefix("--path=") {
            path = Some(v.to_string());
        } else if let Some(v) = s.strip_prefix("--limit=") {
            limit = parse_or_exit(v, "--limit");
        } else if s == "--format=json" {
            format = OutputFormat::Json;
        } else if s == "--format=text" {
            format = OutputFormat::Text;
        } else {
            eprintln!("error: unrecognized flag: {s}");
            std::process::exit(2);
        }
    }

    if run.is_empty() {
        eprintln!("error: --run=<hex-id> is required for list-findings");
        std::process::exit(2);
    }

    StoreCommand::ListFindings {
        store_dir,
        run,
        rule,
        path,
        limit,
        format,
    }
}

/// Parse flags for `store diff`. Requires `--run-a` and `--run-b`.
fn parse_store_diff(args: impl Iterator<Item = std::ffi::OsString>) -> StoreCommand {
    let mut store_dir = PathBuf::from(".scanner-store");
    let mut run_a = String::new();
    let mut run_b = String::new();
    let mut format = OutputFormat::Text;

    for arg in args {
        let s = arg.to_string_lossy();
        if let Some(v) = s.strip_prefix("--store-dir=") {
            store_dir = PathBuf::from(v);
        } else if let Some(v) = s.strip_prefix("--run-a=") {
            run_a = v.to_string();
        } else if let Some(v) = s.strip_prefix("--run-b=") {
            run_b = v.to_string();
        } else if s == "--format=json" {
            format = OutputFormat::Json;
        } else if s == "--format=text" {
            format = OutputFormat::Text;
        } else {
            eprintln!("error: unrecognized flag: {s}");
            std::process::exit(2);
        }
    }

    if run_a.is_empty() || run_b.is_empty() {
        eprintln!("error: --run-a=<hex-id> and --run-b=<hex-id> are required for diff");
        std::process::exit(2);
    }

    StoreCommand::Diff {
        store_dir,
        run_a,
        run_b,
        format,
    }
}

/// Parse flags for `store list-secrets` (`--store-dir`, `--status`, `--limit`, `--format`).
fn parse_store_list_secrets(args: impl Iterator<Item = std::ffi::OsString>) -> StoreCommand {
    let mut store_dir = PathBuf::from(".scanner-store");
    let mut status: Option<i32> = None;
    let mut limit: usize = 50;
    let mut format = OutputFormat::Text;

    for arg in args {
        let s = arg.to_string_lossy();
        if let Some(v) = s.strip_prefix("--store-dir=") {
            store_dir = PathBuf::from(v);
        } else if let Some(v) = s.strip_prefix("--status=") {
            status = Some(parse_or_exit(v, "--status"));
        } else if let Some(v) = s.strip_prefix("--limit=") {
            limit = parse_or_exit(v, "--limit");
        } else if s == "--format=json" {
            format = OutputFormat::Json;
        } else if s == "--format=text" {
            format = OutputFormat::Text;
        } else {
            eprintln!("error: unrecognized flag: {s}");
            std::process::exit(2);
        }
    }

    StoreCommand::ListSecrets {
        store_dir,
        status,
        limit,
        format,
    }
}

fn print_store_usage() {
    eprintln!(
        "usage: scanner-rs store <command> [OPTIONS]

COMMANDS:
    list-runs       List completed scan runs
    list-findings   List findings for a specific run
    diff            Compare two runs
    list-secrets    List unique secrets

COMMON OPTIONS:
    --store-dir=<path>   Path to store directory (default: .scanner-store)
    --format=text|json   Output format (default: text)
    --limit=<N>          Max results (default: 50)

EXAMPLES:
    scanner-rs store list-runs --store-dir .scanner-store
    scanner-rs store list-findings --store-dir .scanner-store --run <hex-id>
    scanner-rs store diff --store-dir .scanner-store --run-a <id1> --run-b <id2>
    scanner-rs store list-secrets --store-dir .scanner-store"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn fs_rules_utf8_path_parsed() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--rules=/tmp/rules.yaml"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(
            config.rules_file.as_deref(),
            Some(std::path::Path::new("/tmp/rules.yaml")),
        );
    }

    #[cfg(unix)]
    #[test]
    fn fs_rules_non_utf8_path_parsed() {
        use std::os::unix::ffi::OsStringExt;
        // --rules=/tmp/\xff/rules.yaml  (byte 0xFF is invalid UTF-8)
        let rules_arg = OsString::from_vec(b"--rules=/tmp/\xff/rules.yaml".to_vec());
        let args = vec![OsString::from("--path=/some/dir"), rules_arg];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert!(
            config.rules_file.is_some(),
            "non-UTF8 --rules= path must not be silently ignored"
        );
        let got = config.rules_file.unwrap();
        let expected =
            std::path::PathBuf::from(OsString::from_vec(b"/tmp/\xff/rules.yaml".to_vec()));
        assert_eq!(got, expected);
    }

    #[cfg(unix)]
    #[test]
    fn git_rules_non_utf8_path_parsed() {
        use std::os::unix::ffi::OsStringExt;
        let rules_arg = OsString::from_vec(b"--rules=/tmp/\xff/rules.yaml".to_vec());
        let args = vec![OsString::from("--repo=/some/repo"), rules_arg];
        let config = parse_git_args(args.into_iter()).unwrap();
        assert!(
            config.rules_file.is_some(),
            "non-UTF8 --rules= path must not be silently ignored"
        );
    }

    #[test]
    fn fs_transforms_default_is_all() {
        let args = vec![OsString::from("--path=/some/dir")];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::All);
    }

    #[test]
    fn fs_persist_findings_flag_enables_persistence() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--persist-findings"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        let SourceConfig::Fs(fs) = config.source else {
            panic!("expected fs source config");
        };
        assert!(fs.persist_findings);
    }

    #[test]
    fn fs_transforms_none() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=none"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::None);
    }

    #[test]
    fn fs_transforms_single() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=base64"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(
            config.transform_filter,
            TransformFilter::Only(vec![TransformId::Base64])
        );
    }

    #[test]
    fn fs_transforms_comma_list() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=url,base64"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(
            config.transform_filter,
            TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
        );
    }

    #[test]
    fn fs_transforms_all_explicit() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=all"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::All);
    }

    #[test]
    fn fs_transforms_all_case_insensitive() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=ALL"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::All);
    }

    #[test]
    fn git_transforms_none() {
        let args = vec![
            OsString::from("--repo=/some/repo"),
            OsString::from("--transforms=none"),
        ];
        let config = parse_git_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::None);
    }

    #[test]
    fn git_transforms_none_case_insensitive() {
        let args = vec![
            OsString::from("--repo=/some/repo"),
            OsString::from("--transforms=NoNe"),
        ];
        let config = parse_git_args(args.into_iter()).unwrap();
        assert_eq!(config.transform_filter, TransformFilter::None);
    }

    #[test]
    fn parse_transforms_helper() {
        assert_eq!(parse_transforms("all"), TransformFilter::All);
        assert_eq!(parse_transforms(" ALL "), TransformFilter::All);
        assert_eq!(parse_transforms("none"), TransformFilter::None);
        assert_eq!(parse_transforms("NoNe"), TransformFilter::None);
        assert_eq!(
            parse_transforms("base64"),
            TransformFilter::Only(vec![TransformId::Base64])
        );
        assert_eq!(
            parse_transforms("url,base64"),
            TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
        );
        assert_eq!(
            parse_transforms(" URL , Base64 "),
            TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
        );
        // Trailing comma: empty segments are filtered out.
        assert_eq!(
            parse_transforms("base64,"),
            TransformFilter::Only(vec![TransformId::Base64])
        );
        // Leading comma.
        assert_eq!(
            parse_transforms(",url"),
            TransformFilter::Only(vec![TransformId::UrlPercent])
        );
    }

    #[test]
    fn parse_transforms_deduplicates() {
        assert_eq!(
            parse_transforms("base64,base64"),
            TransformFilter::Only(vec![TransformId::Base64])
        );
        assert_eq!(
            parse_transforms("url,base64,url"),
            TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
        );
    }

    // Verify --transforms= is handled via strip_os_prefix (before the UTF-8
    // gate), so valid values still parse correctly through the new code path.
    // The non-UTF-8 case (e.g. --transforms=\xff) now calls process::exit(2)
    // with "error: --transforms value must be valid UTF-8" instead of being
    // silently misinterpreted as a positional path argument.
    #[test]
    fn fs_transforms_parsed_before_utf8_gate() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--transforms=base64"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert_eq!(
            config.transform_filter,
            TransformFilter::Only(vec![TransformId::Base64])
        );
    }

    #[test]
    fn strip_os_prefix_matches() {
        let arg = std::ffi::OsStr::new("--rules=/foo/bar");
        let val = strip_os_prefix(arg, "--rules=").unwrap();
        assert_eq!(val, "/foo/bar");
    }

    #[test]
    fn strip_os_prefix_no_match() {
        let arg = std::ffi::OsStr::new("--path=/foo");
        assert!(strip_os_prefix(arg, "--rules=").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn strip_os_prefix_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let arg = OsString::from_vec(b"--rules=/tmp/\xff/r.yaml".to_vec());
        let val = strip_os_prefix(&arg, "--rules=").unwrap();
        let expected = OsString::from_vec(b"/tmp/\xff/r.yaml".to_vec());
        assert_eq!(val, &*expected);
    }

    #[test]
    fn git_null_sink_flag_parsed() {
        let args = vec![OsString::from("--repo=/r"), OsString::from("--null-sink")];
        let config = parse_git_args(args.into_iter()).unwrap();
        assert!(config.null_sink);
    }

    #[test]
    fn fs_null_sink_flag_parsed() {
        let args = vec![
            OsString::from("--path=/some/dir"),
            OsString::from("--null-sink"),
        ];
        let config = parse_fs_args(args.into_iter()).unwrap();
        assert!(config.null_sink);
    }

    #[test]
    fn null_sink_defaults_false() {
        let fs_args = vec![OsString::from("--path=/some/dir")];
        let fs_config = parse_fs_args(fs_args.into_iter()).unwrap();
        assert!(!fs_config.null_sink);

        let git_args = vec![OsString::from("--repo=/r")];
        let git_config = parse_git_args(git_args.into_iter()).unwrap();
        assert!(!git_config.null_sink);
    }

    // -- Execution mode -------------------------------------------------------

    #[test]
    fn fs_execution_mode_defaults_direct() {
        let cfg = fs_config(&["--path=/d"]);
        assert_eq!(cfg.execution_mode, super::super::ExecutionMode::Direct);
    }

    #[test]
    fn fs_execution_mode_connector_parsed() {
        let cfg = fs_config(&["--path=/d", "--execution-mode=connector"]);
        assert_eq!(cfg.execution_mode, super::super::ExecutionMode::Connector);
    }

    #[test]
    fn git_execution_mode_defaults_direct() {
        let cfg = git_config(&["--repo=/r"]);
        assert_eq!(cfg.execution_mode, super::super::ExecutionMode::Direct);
    }

    #[test]
    fn git_execution_mode_connector_parsed() {
        let cfg = git_config(&["--repo=/r", "--execution-mode=connector"]);
        assert_eq!(cfg.execution_mode, super::super::ExecutionMode::Connector);
    }

    // -- DebugLevel / --debug / --debug=perf --------------------------------

    fn git_debug_level(args: &[&str]) -> super::super::DebugLevel {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let config = parse_git_args(os_args.into_iter()).unwrap();
        let SourceConfig::Git(git) = config.source else {
            panic!("expected git source config");
        };
        git.debug
    }

    #[test]
    fn git_debug_defaults_off() {
        assert_eq!(
            git_debug_level(&["--repo=/r"]),
            super::super::DebugLevel::Off
        );
    }

    #[test]
    fn git_debug_bare_sets_stats() {
        assert_eq!(
            git_debug_level(&["--repo=/r", "--debug"]),
            super::super::DebugLevel::Stats
        );
    }

    #[test]
    fn git_debug_perf_sets_perf() {
        assert_eq!(
            git_debug_level(&["--repo=/r", "--debug=perf"]),
            super::super::DebugLevel::Perf
        );
    }

    #[test]
    fn git_debug_perf_overrides_bare_debug() {
        // --debug then --debug=perf → Perf wins
        assert_eq!(
            git_debug_level(&["--repo=/r", "--debug", "--debug=perf"]),
            super::super::DebugLevel::Perf
        );
    }

    #[test]
    fn git_debug_bare_does_not_downgrade_perf() {
        // --debug=perf then --debug → Perf is preserved (bare doesn't downgrade)
        assert_eq!(
            git_debug_level(&["--repo=/r", "--debug=perf", "--debug"]),
            super::super::DebugLevel::Perf
        );
    }

    // -- Hidden --x-* flags -------------------------------------------------

    fn git_config(args: &[&str]) -> super::super::GitSourceConfig {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let config = parse_git_args(os_args.into_iter()).unwrap();
        let SourceConfig::Git(git) = config.source else {
            panic!("expected git source config");
        };
        git
    }

    #[test]
    fn git_hidden_repo_id_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-repo-id=42"]);
        assert_eq!(cfg.repo_id, 42);
    }

    #[test]
    fn git_hidden_mode_diff_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-mode=diff"]);
        assert_eq!(cfg.scan_mode, GitScanMode::DiffHistory);
    }

    #[test]
    fn git_hidden_mode_odb_blob_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-mode=odb-blob"]);
        assert_eq!(cfg.scan_mode, GitScanMode::OdbBlobFast);
    }

    #[test]
    fn git_workers_flag_parsed() {
        let cfg = git_config(&["--repo=/r", "--workers=4"]);
        assert_eq!(cfg.pack_exec_workers, Some(4));
    }

    #[test]
    fn git_hidden_merge_first_parent_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-merge=first-parent"]);
        assert_eq!(cfg.merge_mode, MergeDiffMode::FirstParentOnly);
    }

    #[test]
    fn git_hidden_pack_exec_workers_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-pack-exec-workers=4"]);
        assert_eq!(cfg.pack_exec_workers, Some(4));
    }

    #[test]
    fn git_hidden_tree_delta_cache_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-tree-delta-cache-mb=256"]);
        assert_eq!(cfg.tree_delta_cache_mb, Some(256));
    }

    #[test]
    fn git_hidden_engine_chunk_parsed() {
        let cfg = git_config(&["--repo=/r", "--x-engine-chunk-mb=4"]);
        assert_eq!(cfg.engine_chunk_mb, Some(4));
    }

    // -- File-type flag convention (--skip-X / --scan-X) ----------------------

    fn fs_config(args: &[&str]) -> super::super::FsScanConfig {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let config = parse_fs_args(os_args.into_iter()).unwrap();
        let SourceConfig::Fs(fs) = config.source else {
            panic!("expected fs source config");
        };
        fs
    }

    #[test]
    fn fs_skip_archives_flag_parsed() {
        let cfg = fs_config(&["--path=/d", "--skip-archives"]);
        assert!(cfg.skip_archives);
    }

    #[test]
    fn fs_scan_archives_accepted() {
        // --scan-archives is the default (no-op); verify it's accepted and
        // skip_archives stays false.
        let cfg = fs_config(&["--path=/d", "--scan-archives"]);
        assert!(!cfg.skip_archives);
    }

    #[test]
    fn fs_skip_binary_accepted() {
        // --skip-binary is the default (no-op); verify it's accepted and
        // scan_binary stays false.
        let cfg = fs_config(&["--path=/d", "--skip-binary"]);
        assert!(!cfg.scan_binary);
    }

    #[test]
    fn fs_scan_binary_flag_parsed() {
        let cfg = fs_config(&["--path=/d", "--scan-binary"]);
        assert!(cfg.scan_binary);
    }

    #[test]
    fn git_scan_binary_flag_parsed() {
        let cfg = git_config(&["--repo=/r", "--scan-binary"]);
        assert!(cfg.scan_binary);
    }

    #[test]
    fn git_skip_binary_accepted() {
        let cfg = git_config(&["--repo=/r", "--skip-binary"]);
        assert!(!cfg.scan_binary);
    }

    // -- Last-wins semantics: contradictory flags resolve to the last one -----

    #[test]
    fn fs_last_flag_wins_archives() {
        let cfg = fs_config(&["--path=/d", "--skip-archives", "--scan-archives"]);
        assert!(!cfg.skip_archives);
    }

    #[test]
    fn fs_last_flag_wins_binary() {
        let cfg = fs_config(&["--path=/d", "--scan-binary", "--skip-binary"]);
        assert!(!cfg.scan_binary);
    }

    // -- Defaults: file-type flags start at standard behavior -----------------

    #[test]
    fn file_type_flags_default_to_standard_behavior() {
        let fs = fs_config(&["--path=/d"]);
        assert!(!fs.skip_archives, "archives should be scanned by default");
        assert!(!fs.scan_binary, "binary should be skipped by default");

        let git = git_config(&["--repo=/r"]);
        assert!(!git.scan_binary, "binary should be skipped by default");
    }
}
