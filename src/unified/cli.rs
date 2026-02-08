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

use crate::api::TransformId;
use crate::git_scan::{GitScanMode, MergeDiffMode};
use crate::AnchorMode;

use super::{EventFormat, FsScanConfig, GitSourceConfig, SourceConfig};

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

/// Top-level scan configuration produced by CLI parsing.
pub struct ScanConfig {
    pub source: SourceConfig,
    pub event_format: EventFormat,
    /// Optional path to a YAML rules file. When `None`, the orchestrator
    /// falls back to `default_rules.yaml` next to the binary, then the
    /// compiled-in demo rules.
    pub rules_file: Option<PathBuf>,
    /// Which transform decoders to enable. Applied as a pre-engine filter
    /// on [`demo_transforms()`](crate::demo_transforms) output. In git
    /// scans, the filtered list also feeds into the policy hash, so
    /// disabling a transform correctly invalidates cached scan results.
    pub transform_filter: TransformFilter,
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

/// Parse `--path`, `--workers`, and other FS-specific flags from the
/// remaining argument iterator. Accepts `--path=<dir>` or a bare positional
/// path. Exits with code 2 on unrecognised flags or missing `--path`.
fn parse_fs_args(args: impl Iterator<Item = std::ffi::OsString>) -> io::Result<ScanConfig> {
    let mut path: Option<PathBuf> = None;
    let mut workers: Option<usize> = None;
    let mut decode_depth: Option<usize> = None;
    let mut no_archives = false;
    let mut null_sink = false;
    let mut scan_binary = false;
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
            match flag {
                "--no-archives" => {
                    no_archives = true;
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
            null_sink,
            scan_binary,
        }),
        event_format,
        rules_file,
        transform_filter,
    })
}

/// Parse `--repo`, `--mode`, and other git-specific flags from the
/// remaining argument iterator. Accepts `--repo=<path>` or a bare positional
/// path. Exits with code 2 on unrecognised flags or missing `--repo`.
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
    let mut debug = false;
    let mut perf_breakdown = false;
    let mut scan_binary = false;
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
                "--scan-binary" => {
                    scan_binary = true;
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
            scan_binary,
        }),
        event_format,
        rules_file,
        transform_filter,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a string value into `T`, or exit with code 2 on parse failure.
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
// Usage text
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
    --path=<dir|file>       Path to scan (also accepted as positional arg)
    --rules=<path>          YAML rules file (default: default_rules.yaml next to binary)
    --workers=<N>           Worker threads (default: CPU count)
    --decode-depth=<N>      Max decode depth (default: 2)
    --transforms=all|none|<list>  Transforms to enable (default: all)
                            Comma-separated: base64, url (case-insensitive)
    --no-archives           Disable archive scanning
    --null-sink             Drop all findings (measure scan overhead only)
    --scan-binary           Scan binary files instead of skipping them
    --anchors=manual|derived  Anchor mode (default: manual)
    --event-format=jsonl    Output format (default: jsonl)
    --help, -h              Show this help"
    );
}

fn print_git_usage() {
    eprintln!(
        "usage: scanner-rs scan git --repo <path> [OPTIONS]

OPTIONS:
    --repo=<path>             Repository path (also accepted as positional arg)
    --repo-id=<N>             Repository id (default: 1)
    --rules=<path>            YAML rules file (default: default_rules.yaml next to binary)
    --mode=diff|odb-blob      Scan mode (default: odb-blob)
    --merge=all|first-parent  Merge diff mode (default: all)
    --pack-exec-workers=<N>   Pack exec workers
    --tree-delta-cache-mb=<N> Tree delta cache (default: 128)
    --engine-chunk-mb=<N>     Engine chunk size (default: 1)
    --decode-depth=<N>        Max decode depth (default: 2)
    --transforms=all|none|<list>  Transforms to enable (default: all)
                              Comma-separated: base64, url (case-insensitive)
    --anchors=manual|derived  Anchor mode (default: manual)
    --debug                   Verbose stage stats to stderr
    --perf-breakdown          Pack execution timing breakdown
    --scan-binary             Scan binary blobs instead of skipping them
    --event-format=jsonl      Output format (default: jsonl)
    --help, -h                Show this help"
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
}
