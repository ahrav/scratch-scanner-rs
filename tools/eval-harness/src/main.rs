//! Eval-harness binary — measures scanner-rs accuracy against labeled corpora.
//!
//! Compares scanner findings (from a JSONL file or a live scan) against
//! ground-truth annotations from labeled corpora and computes precision,
//! recall, and PRC-AUC.
//!
//! # Pipelines
//!
//! Two evaluation pipelines exist, selected by subcommand:
//!
//! - **Position-based** (`creddata`, `synthetic`) — matches findings to truth
//!   items by file path and byte/line overlap, producing confidence-ranked
//!   classifications for PRC-AUC computation with bootstrap CIs.
//! - **Count-based** (`leaky-repo`) — compares per-file finding counts against
//!   expected counts. Coarser than position-based matching but sufficient for
//!   regression testing against corpora that lack position annotations.
//!
//! # Data flow
//!
//! Both pipelines follow a load-match-measure-report pattern. The
//! position-based pipeline has richer internals:
//!
//! ```text
//! Position-based (creddata / synthetic):
//!   truth loader ──► TruthItem[]
//!                                ├─► match_findings ──► ClassifiedFinding[]
//!   finding source ──► NormalizedFinding[]              ├─► compute_metrics ──► EvalMetrics
//!   corpus files ──► HashMap<path, bytes>               ├─► bootstrap_ap_ci ──► CI
//!                                                       ├─► check_regression ──► Verdict
//!                                                       └─► build_error_book ──► ErrorBook
//!                                                                   └─► EvalReport ──► JSON / table
//!
//! Count-based (leaky-repo):
//!   expectations CSV ──► FileExpectation[]
//!                                    ├─► compare_counts ──► per-file TP/FP/FN
//!   findings JSONL ──► NormalizedFinding[]                  └─► aggregate ──► EvalMetrics
//!                                                                └─► EvalReport ──► JSON / table
//! ```
//!
//! # Finding sources
//!
//! Position-based subcommands accept findings from two mutually exclusive
//! sources (enforced by clap argument groups):
//!
//! - `--findings <path>` — pre-computed JSONL from a previous scanner run.
//! - `--scan-corpus <dir>` — live-scan a directory using the embedded
//!   `scanner_rs::demo_engine()`, collecting findings via an in-memory
//!   event sink. Intended for quick iteration during rule development.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Pass or warn — metrics meet thresholds |
//! | 1    | Block — regression detected against a `--baseline` report |
//! | 2    | Argument or runtime error |

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use eval_harness::creddata::load_meta_dir;
use eval_harness::finding_parser::{
    JsonlParseResult, dedup_findings, parse_findings_file, parse_findings_jsonl,
};
use eval_harness::leaky_repo::{compare_counts, parse_leaky_repo_csv};
use eval_harness::matching::{MatchConfig, match_findings};
use eval_harness::metrics::{BootstrapConfig, EvalMetrics, bootstrap_ap_ci, compute_metrics};
use eval_harness::provenance::{build_provenance, collect_files_recursive};
use eval_harness::regression::{RegressionThresholds, check_regression};
use eval_harness::report::{
    ErrorBookConfig, EvalReport, build_error_book, render_json, render_table, write_json_file,
};
use eval_harness::synthetic::load_synthetic_manifest;
use eval_harness::types::{NormalizedFinding, TruthItem, normalize_path};

// ── CLI types ───────────────────────────────────────────────────────────

/// Top-level CLI dispatcher.
///
/// Each subcommand corresponds to a specific corpus format and evaluation
/// pipeline. The subcommand choice determines both how ground truth is
/// loaded and which matching strategy is applied.
#[derive(Parser)]
#[command(
    name = "eval-harness",
    about = "Measure scanner-rs accuracy against labeled corpora"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available evaluation subcommands, each targeting a different corpus format.
///
/// `Creddata` and `Synthetic` share the position-based pipeline via
/// [`run_position_pipeline`] but differ in how they load ground truth.
/// `LeakyRepo` uses a separate count-based pipeline because LeakyRepo
/// annotations lack positional information (only per-file secret counts).
#[derive(Subcommand)]
enum Command {
    /// Position-based accuracy against CredData CSV annotations.
    Creddata(CreddataArgs),
    /// Count-based accuracy against LeakyRepo secrets CSV.
    LeakyRepo(LeakyRepoArgs),
    /// Position-based accuracy against a synthetic JSON manifest.
    Synthetic(SyntheticArgs),
}

/// Shared arguments for position-based evaluation subcommands.
///
/// Both `creddata` and `synthetic` use the same finding-loading, matching,
/// metrics, and reporting pipeline — they differ only in how ground truth
/// is loaded. This struct captures the arguments common to both, flattened
/// into each subcommand via `#[command(flatten)]`.
///
/// Finding sources are mutually exclusive (enforced by clap argument group
/// `"input"`): either `--findings` (pre-computed JSONL) or `--scan-corpus`
/// (live scan) must be provided.
#[derive(clap::Args)]
struct PositionPipelineArgs {
    /// Pre-computed findings JSONL file.
    #[arg(long, group = "input")]
    findings: Option<PathBuf>,

    /// Directory to live-scan for findings.
    #[arg(long, group = "input")]
    scan_corpus: Option<PathBuf>,

    /// Path normalization root (stripped from finding and truth paths).
    #[arg(long)]
    corpus_root: PathBuf,

    /// Output format.
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Write JSON output to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Baseline JSON report for regression comparison.
    #[arg(long)]
    baseline: Option<PathBuf>,
}

/// Arguments for evaluating against the CredData corpus.
///
/// CredData organizes ground truth as one CSV file per category inside a
/// `meta/` directory. The harness loads all CSV files from `--meta-dir`,
/// normalizes paths relative to `--corpus-root`, and feeds the resulting
/// truth items into the position-based pipeline.
#[derive(clap::Args)]
struct CreddataArgs {
    /// CredData CSV directory containing ground-truth annotations.
    #[arg(long)]
    meta_dir: PathBuf,

    #[command(flatten)]
    common: PositionPipelineArgs,
}

/// Arguments for evaluating against the LeakyRepo corpus.
///
/// LeakyRepo provides only per-file expected secret counts (no byte/line
/// positions), so this subcommand uses the count-based pipeline rather
/// than position-based matching. Confidence-aware metrics (AP, bootstrap
/// CI) are not meaningful and are set to degenerate single-threshold
/// stand-ins.
#[derive(clap::Args)]
struct LeakyRepoArgs {
    /// Path to the LeakyRepo secrets CSV.
    #[arg(long)]
    secrets_csv: PathBuf,

    /// Pre-computed findings JSONL file.
    #[arg(long)]
    findings: PathBuf,

    /// Output format.
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Write JSON output to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for evaluating against a synthetic test corpus.
///
/// Synthetic corpora use a hand-written JSON manifest describing
/// expected findings with file paths, line ranges, and rule names.
/// Follows the same position-based pipeline as `creddata` but loads
/// truth via [`load_synthetic_manifest`] instead of CredData CSVs.
#[derive(clap::Args)]
struct SyntheticArgs {
    /// Synthetic JSON manifest file.
    #[arg(long)]
    manifest: PathBuf,

    #[command(flatten)]
    common: PositionPipelineArgs,
}

/// Report output format.
///
/// JSON is the default and supports `--output <file>` for CI artifact
/// storage and baseline comparison. Table is human-readable ASCII
/// intended for interactive terminal use and cannot be written to a file
/// (the `--output` + `Table` combination is rejected at validation time).
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Machine-readable JSON (pretty-printed).
    Json,
    /// Fixed-width ASCII table for terminal display.
    Table,
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Maps the return value of [`run`] to process exit codes.
///
/// Exit code 2 is reserved for argument or runtime errors (distinct from
/// exit code 1, which indicates a regression block verdict).
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("harness: {e}");
            std::process::exit(2);
        }
    }
}

/// Parse CLI arguments and dispatch to the appropriate subcommand handler.
///
/// Returns an exit code (0 for pass/warn, 1 for block) on success, or a
/// boxed error for argument and runtime failures.
fn run() -> Result<i32, Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Creddata(args) => run_creddata(args),
        Command::LeakyRepo(args) => run_leaky_repo(args),
        Command::Synthetic(args) => run_synthetic(args),
    }
}

// ── Subcommand handlers ─────────────────────────────────────────────────

/// Load CredData CSV annotations and evaluate via the position-based pipeline.
///
/// Loads all CSV files from `--meta-dir`, warns on per-file parse errors
/// (which are non-fatal to allow partial corpora), then delegates to
/// [`run_position_pipeline`] for matching, metrics, and reporting.
fn run_creddata(args: CreddataArgs) -> Result<i32, Box<dyn Error>> {
    let canonical_root = canonicalize_root(&args.common.corpus_root);

    let dir_result = load_meta_dir(&args.meta_dir, &canonical_root)?;
    if !dir_result.file_errors.is_empty() {
        for e in &dir_result.file_errors {
            eprintln!("warning: {e}");
        }
    }

    run_position_pipeline(dir_result.parsed.items, &args.common)
}

/// Load a synthetic JSON manifest and evaluate via the position-based pipeline.
///
/// Structurally identical to [`run_creddata`] except the truth loader:
/// [`load_synthetic_manifest`] reads a single JSON file rather than a
/// directory of CSVs.
fn run_synthetic(args: SyntheticArgs) -> Result<i32, Box<dyn Error>> {
    let canonical_root = canonicalize_root(&args.common.corpus_root);
    let truth = load_synthetic_manifest(&args.manifest, &canonical_root)?;

    run_position_pipeline(truth, &args.common)
}

/// Run the count-based evaluation pipeline for LeakyRepo.
///
/// Unlike the position-based pipeline, LeakyRepo annotations specify only
/// how many secrets exist per file, not where they are. The matching
/// strategy is therefore count-based: for each file, `compare_counts`
/// pairs the expected count against the actual finding count to derive
/// TP, FP, and FN tallies.
///
/// The per-file counts are then aggregated into corpus-wide totals and
/// packed into an [`EvalMetrics`] struct. Because there is no confidence
/// ranking (all findings are treated equally), confidence-aware metrics
/// like AP, P@R, R@P, and bootstrap CI are not meaningful. AP is set to
/// precision as a degenerate single-threshold approximation so the report
/// schema stays uniform across subcommands.
///
/// Regression checking is not supported for this subcommand (no
/// `--baseline` flag), so the exit code is always 0.
fn run_leaky_repo(args: LeakyRepoArgs) -> Result<i32, Box<dyn Error>> {
    validate_output_format(args.format, args.output.as_deref())?;

    let expectations = parse_leaky_repo_csv(&args.secrets_csv)?;
    let parse_result = parse_findings_file(&args.findings, "")?;
    print_parse_diagnostics(&parse_result);

    let comparisons = compare_counts(parse_result.findings, &expectations);

    // Collapse per-file results into corpus-wide totals.
    let (mut tp, mut fp, mut false_neg) = (0u64, 0u64, 0u64);
    for c in &comparisons {
        tp += u64::from(c.tp);
        fp += u64::from(c.fp);
        false_neg += u64::from(c.false_neg);
    }

    let metrics = EvalMetrics::from_counts(tp, fp, false_neg);

    let provenance = build_provenance(
        args.secrets_csv.parent().unwrap_or_else(|| Path::new(".")),
        None,
        None,
    )?;

    let report = EvalReport {
        metrics,
        provenance,
        regression: None,
        error_book: None,
    };

    output_report(&report, args.format, args.output.as_deref())?;
    Ok(0)
}

// ── Shared position-based pipeline ──────────────────────────────────────

/// Execute the full position-based evaluation pipeline.
///
/// This is the shared core of `creddata` and `synthetic` subcommands.
/// The caller provides truth items (already loaded and normalized);
/// this function handles everything from finding ingestion through
/// final report output.
///
/// # Pipeline steps
///
/// 1. **Validate** — reject invalid argument combinations (e.g.,
///    `--output` + `--format table`).
/// 2. **Load findings** — from pre-computed JSONL or a live scan.
/// 3. **Dedup** — sort + dedup findings, retaining highest confidence per
///    identity (path, byte_start, byte_end, rule).
/// 4. **Load corpus files** — read all files under `corpus_root` into
///    memory for byte-to-line conversion during matching.
/// 5. **Match** — classify each finding as TP, FP, or Unlabeled using
///    position-based overlap with truth items. Rule matching is disabled
///    (`require_rule_match: false`) so any finding overlapping a truth
///    region counts as a match regardless of rule name.
/// 6. **Compute metrics** — precision, recall, F1, F2, AP with tie
///    collapsing, P@R, R@P, per-rule breakdown, and bootstrap CI.
/// 7. **Regression check** — if a baseline report is provided, compare
///    current metrics against it using default thresholds (2pp block,
///    0.5pp warn) with CI overlap gating.
/// 8. **Report** — assemble all outputs into an [`EvalReport`] and
///    render to JSON or table format.
///
/// # Exit code
///
/// Returns the regression verdict's exit code (0 for pass/warn, 1 for
/// block). When no baseline is provided, always returns 0.
fn run_position_pipeline(
    truth: Vec<TruthItem>,
    args: &PositionPipelineArgs,
) -> Result<i32, Box<dyn Error>> {
    validate_output_format(args.format, args.output.as_deref())?;
    let canonical_root = canonicalize_root(&args.corpus_root);

    let mut findings =
        load_findings(args.findings.as_deref(), args.scan_corpus.as_deref(), &canonical_root)?;
    dedup_findings(&mut findings);

    let file_contents = load_corpus_files(&args.corpus_root)?;
    let config = MatchConfig {
        require_rule_match: false,
    };
    let match_result = match_findings(findings, truth, &file_contents, config);

    let total_positives = match_result.total_positives();
    let fn_count = match_result.fn_count();

    let metrics = compute_metrics(&match_result.classified, fn_count, total_positives);

    let ci = bootstrap_ap_ci(
        &match_result.classified,
        total_positives,
        &BootstrapConfig::default(),
    );
    let metrics = metrics.with_bootstrap_ci(ci);

    let provenance = build_provenance(&args.corpus_root, None, None)?;

    let regression = if let Some(bp) = args.baseline.as_deref() {
        let baseline_report = load_baseline(bp)?;
        let result = check_regression(
            &metrics,
            &baseline_report.metrics,
            &RegressionThresholds::default(),
        )?;
        Some(result)
    } else {
        None
    };

    let error_book = build_error_book(
        &match_result.classified,
        &match_result.false_negatives,
        &file_contents,
        &ErrorBookConfig::default(),
    );

    let exit_code = regression
        .as_ref()
        .map(|r| r.verdict.exit_code())
        .unwrap_or(0);

    let report = EvalReport {
        metrics,
        provenance,
        regression,
        error_book: Some(error_book),
    };

    output_report(&report, args.format, args.output.as_deref())?;
    Ok(exit_code)
}

// ── Finding loaders ─────────────────────────────────────────────────────

/// Load findings from exactly one of two mutually exclusive sources.
///
/// The clap `group = "input"` attribute on the CLI arguments enforces
/// mutual exclusivity at the argument-parsing level. This function
/// provides a runtime guard as a defense-in-depth check for the case
/// where both or neither source is provided (e.g., programmatic callers
/// that bypass clap).
///
/// Diagnostics (malformed lines, skipped findings) are emitted to stderr
/// regardless of the source to give visibility into data quality issues.
fn load_findings(
    findings_path: Option<&Path>,
    scan_corpus: Option<&Path>,
    canonical_root: &str,
) -> Result<Vec<NormalizedFinding>, Box<dyn Error>> {
    match (findings_path, scan_corpus) {
        (Some(path), None) => {
            let result = parse_findings_file(path, canonical_root)?;
            print_parse_diagnostics(&result);
            Ok(result.findings)
        }
        (None, Some(dir)) => run_live_scan(dir, canonical_root),
        (Some(_), Some(_)) | (None, None) => {
            Err("exactly one of --findings or --scan-corpus is required".into())
        }
    }
}

/// Run the scanner engine against a directory and collect findings in memory.
///
/// Uses the built-in `demo_engine()` (default ruleset) and the local
/// scheduler, collecting scanner events into a [`VecEventSink`]. Events
/// are serialized as JSONL, then re-parsed through the same
/// [`parse_findings_jsonl`] path as pre-computed findings to ensure both
/// sources produce identical `NormalizedFinding` representations.
///
/// The scan is synchronous: `scan_local` blocks until all files have been
/// processed. All corpus file bytes and scanner events are held in memory
/// simultaneously, so this path is intended for small-to-medium corpora
/// used in development iteration, not for multi-GB production benchmarks.
fn run_live_scan(
    scan_dir: &Path,
    canonical_root: &str,
) -> Result<Vec<NormalizedFinding>, Box<dyn Error>> {
    use scanner_rs::scheduler::{LocalConfig, LocalFile, VecFileSource, scan_local};
    use scanner_rs::unified::events::VecEventSink;

    let engine = Arc::new(scanner_rs::demo_engine());

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files_recursive(scan_dir, &mut files)?;
    let local_files: Vec<LocalFile> = files
        .into_iter()
        .map(|path| {
            let size = match path.metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    eprintln!(
                        "warning: could not read metadata for {}: {e}",
                        path.display(),
                    );
                    0
                }
            };
            LocalFile { path, size }
        })
        .collect();

    let sink = Arc::new(VecEventSink::new());
    let cfg = LocalConfig {
        event_sink: sink.clone(),
        ..LocalConfig::default()
    };

    scan_local(engine, VecFileSource::new(local_files), cfg);

    let bytes = sink.take();
    let jsonl = String::from_utf8_lossy(&bytes);
    let result = parse_findings_jsonl(&jsonl, canonical_root);
    print_parse_diagnostics(&result);

    Ok(result.findings)
}

// ── Corpus file loader ──────────────────────────────────────────────────

/// Read all files under `corpus_root` into a path-keyed map for matching.
///
/// The keys are normalized relative paths (forward slashes, no `.`/`..`)
/// that match the path format used by both [`NormalizedFinding`] and
/// [`TruthItem`]. This allows the matching layer to look up file contents
/// by exact string equality on the normalized path.
///
/// All file bytes are held in memory. For large corpora this can be
/// significant — the position-based pipeline requires file contents for
/// byte-to-line conversion via [`LineIndex`](eval_harness::line_index::LineIndex).
fn load_corpus_files(
    corpus_root: &Path,
) -> Result<HashMap<String, Vec<u8>>, Box<dyn Error>> {
    let mut paths: Vec<PathBuf> = Vec::new();
    collect_files_recursive(corpus_root, &mut paths)?;

    let mut contents = HashMap::with_capacity(paths.len());
    for path in paths {
        let rel = path.strip_prefix(corpus_root).unwrap_or(&path);
        // Empty root: corpus_root prefix is already stripped by
        // strip_prefix, so normalize_path only canonicalizes slashes.
        let key = normalize_path(&rel.to_string_lossy(), "");
        if key.is_empty() {
            continue;
        }
        let data = std::fs::read(&path)?;
        contents.insert(key, data);
    }
    Ok(contents)
}

// ── Baseline loader ─────────────────────────────────────────────────────

/// Deserialize a previously saved JSON report for regression comparison.
///
/// The baseline must have been produced by the same version of the
/// harness (or at least a schema-compatible one). Deserialization
/// failures surface as the returned error.
fn load_baseline(path: &Path) -> Result<EvalReport, Box<dyn Error>> {
    let contents = std::fs::read_to_string(path)?;
    let report: EvalReport = serde_json::from_str(&contents)?;
    Ok(report)
}

// ── Output ──────────────────────────────────────────────────────────────

/// Route the report to the requested output format and destination.
///
/// JSON output can go to either stdout (default) or a file (`--output`).
/// Table output always goes to stdout; the `--output` + `Table`
/// combination is rejected earlier by [`validate_output_format`].
fn output_report(
    report: &EvalReport,
    format: OutputFormat,
    output_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Json => {
            if let Some(path) = output_path {
                write_json_file(report, path)?;
            } else {
                let json = render_json(report)?;
                println!("{json}");
            }
        }
        OutputFormat::Table => {
            let table = render_table(report);
            print!("{table}");
        }
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert the corpus root path to a forward-slash string for use as
/// the `canonical_root` argument to [`normalize_path`].
///
/// This is a lightweight text transformation (backslash to forward slash),
/// not filesystem canonicalization — no symlink resolution or existence
/// checks. The result is suitable for prefix-stripping in path
/// normalization on any platform.
fn canonicalize_root(corpus_root: &Path) -> String {
    corpus_root.to_string_lossy().replace('\\', "/")
}

/// Reject the `--output` + `--format table` combination.
///
/// Table output is a fixed-width ASCII format designed for terminal
/// display and is not suitable for file persistence (it cannot be
/// deserialized for baseline comparison). This check runs before any
/// heavy computation to fail fast on invalid argument combinations.
fn validate_output_format(
    format: OutputFormat,
    output: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    if output.is_some() && matches!(format, OutputFormat::Table) {
        return Err("--output requires --format json".into());
    }
    Ok(())
}

/// Emit stderr warnings for any data quality issues found during JSONL parsing.
///
/// Non-fatal: malformed lines and skipped findings are counted and
/// reported, not treated as hard errors. This allows partial evaluation
/// when the findings input contains a small number of corrupt records.
/// Only the first error/reason is printed to avoid flooding the terminal
/// on heavily corrupt inputs.
fn print_parse_diagnostics(result: &JsonlParseResult) {
    if result.malformed_lines > 0 {
        eprintln!(
            "warning: {} malformed line(s) in findings input",
            result.malformed_lines,
        );
        if let Some(ref err) = result.first_malformed_error {
            eprintln!("  first error: {err}");
        }
    }
    if result.skipped_findings > 0 {
        eprintln!(
            "warning: {} finding(s) skipped during parse",
            result.skipped_findings,
        );
        if let Some(ref reason) = result.first_skip_reason {
            eprintln!("  first skip reason: {reason}");
        }
    }
}
