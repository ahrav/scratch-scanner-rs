//! Report output and error book generation.
//!
//! Produces the final eval report combining metrics, provenance, regression
//! verdict, and an error book of top FP/FN for debugging. This is the
//! terminal stage of the eval pipeline:
//!
//! ```text
//! EvalMetrics + Provenance + RegressionResult + ErrorBook ──► EvalReport ──► JSON / table
//! ```
//!
//! Two output formats are supported:
//!
//! - **JSON** ([`render_json`], [`write_json_file`]): machine-readable,
//!   suitable for CI artifact storage and baseline comparison. Optional fields
//!   (`regression`, `error_book`) are omitted from JSON when `None`.
//! - **Terminal table** ([`render_table`]): human-readable fixed-width ASCII
//!   summary for interactive use. Displays aggregate metrics, per-rule
//!   breakdown, and regression verdict.
//!
//! # Error book
//!
//! The error book extracts the top N false positives and false negatives
//! grouped by rule, sorted descending by frequency. When multiple findings
//! share a rule, the one with the highest confidence is selected as the
//! representative (its path and context appear in the entry). Each entry
//! includes an optional context window around the detection span, optionally
//! redacted via BLAKE3 keyed hash when the secret value should not appear in
//! reports.
//!
//! FN entries cannot include byte-level context because [`TruthItem`] carries
//! line-based coordinates, not byte offsets.
//!
//! # Determinism
//!
//! Error book output is deterministic for identical inputs: entries are sorted
//! by descending count with lexicographic rule-name tie-breaking, so the
//! ordering is independent of `HashMap` iteration order.
//!
//! # Performance
//!
//! - `HashMap<&str, _>` for counting borrows rule strings from input (zero
//!   allocation during the counting pass).
//! - `fmt::Write` to a pre-allocated `String` for table rendering avoids N
//!   intermediate `format!()` allocations.
//! - 64 KiB `BufWriter` for file output matches codebase convention.
//!
//! [`TruthItem`]: crate::types::TruthItem

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::metrics::EvalMetrics;
use crate::provenance::Provenance;
use crate::regression::RegressionResult;
use crate::types::{ClassifiedFinding, FindingClass, TruthItem};

// ── Public types ────────────────────────────────────────────────────────

/// Top-level eval report combining all pipeline outputs.
///
/// This is the single serializable artifact produced by an eval run.
/// Required fields (`metrics`, `provenance`) are always present; optional
/// fields are omitted from JSON when `None` via `skip_serializing_if`,
/// keeping the serialized output compact for minimal runs.
///
/// Callers construct this struct directly -- there is no builder. The
/// typical flow is:
///
/// 1. [`crate::metrics::compute_metrics`] produces `metrics`.
/// 2. [`crate::provenance::build_provenance`] produces `provenance`.
/// 3. [`crate::regression::check_regression`] produces `regression` (if a
///    baseline exists).
/// 4. [`build_error_book`] produces `error_book` (if requested).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    /// Aggregate evaluation metrics (precision, recall, AP, etc.).
    pub metrics: EvalMetrics,
    /// Reproducibility metadata (corpus hash, binary hash, etc.).
    pub provenance: Provenance,
    /// Regression check result. `None` when no baseline was provided.
    /// Omitted from serialized JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression: Option<RegressionResult>,
    /// Top FP/FN entries for debugging. `None` when error book generation
    /// was not requested. Omitted from serialized JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_book: Option<ErrorBook>,
}

/// Error classification for the error book.
///
/// Distinct from [`FindingClass`] because [`FindingClass`] has no
/// `FalseNegative` variant -- FN is truth-derived (an unmatched
/// [`TruthItem`]) rather than finding-derived, so it lives only in the
/// error book domain.
///
/// Serializes to `"FALSE_POSITIVE"` / `"FALSE_NEGATIVE"` in JSON.
/// The [`Display`](std::fmt::Display) impl produces short codes (`"FP"` / `"FN"`)
/// for terminal output.
///
/// [`TruthItem`]: crate::types::TruthItem
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorBookClass {
    /// Scanner produced a finding where no secret exists.
    FalsePositive,
    /// Scanner missed a secret that ground truth says is present.
    FalseNegative,
}

impl std::fmt::Display for ErrorBookClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FalsePositive => "FP",
            Self::FalseNegative => "FN",
        })
    }
}

/// Error book: top FP and FN entries for debugging.
///
/// FP and FN are tracked in separate lists because they come from different
/// sources (classified findings vs. unmatched truth items) and are bounded
/// independently by [`ErrorBookConfig::max_entries`]. Each list is sorted
/// by descending count with lexicographic rule-name tie-breaking for
/// determinism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBook {
    /// Top false positive rules sorted by descending count, then
    /// lexicographic rule name. Length is at most
    /// [`ErrorBookConfig::max_entries`].
    pub false_positives: Vec<ErrorBookEntry>,
    /// Top false negative rules sorted by descending count, then
    /// lexicographic rule name. Length is at most
    /// [`ErrorBookConfig::max_entries`].
    pub false_negatives: Vec<ErrorBookEntry>,
}

/// A single error book entry representing one rule's aggregated error pattern.
///
/// Each entry aggregates all errors of a given type for a single rule. The
/// `count` is the total number of errors; the remaining fields describe a
/// single *representative* instance chosen to give the reader a concrete
/// example.
///
/// For FP entries, the representative is the finding with the highest
/// confidence score (most confident mistake). For FN entries, the
/// representative is the first truth item encountered for that rule
/// (arbitrary but deterministic given stable input order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBookEntry {
    /// Rule name that produced this error.
    pub rule: String,
    /// Total number of occurrences of this error type for this rule.
    pub count: u64,
    /// Whether this is a false positive or false negative.
    pub classification: ErrorBookClass,
    /// Confidence score of the representative finding. For FP entries this
    /// is the highest confidence among all FP findings for this rule. For
    /// FN entries (no scanner finding exists), this is always 0.
    pub confidence: i8,
    /// File path of the representative finding (FP) or truth item (FN).
    pub path: String,
    /// Context window around the detection span, possibly redacted via
    /// BLAKE3 keyed hash. `None` when: the file is not in `file_contents`,
    /// the byte span exceeds file length, or this is an FN entry (truth
    /// items lack byte offsets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_context: Option<String>,
}

/// Configuration for error book generation.
///
/// Controls the size of the error book (how many entries per category),
/// the context window around each detection span, and whether secret
/// values are redacted in the output.
///
/// Default: 20 entries per category, no redaction, 64-byte context window.
#[derive(Debug, Clone)]
pub struct ErrorBookConfig {
    /// Maximum number of entries per category (FP and FN independently).
    /// The error book will contain at most `2 * max_entries` total entries.
    pub max_entries: usize,
    /// BLAKE3 keyed hash key for redaction. When `Some`, the detected
    /// secret bytes within the context window are replaced with
    /// `[REDACTED:<hex>]` where `<hex>` is the keyed hash of the secret.
    /// This allows correlating redacted entries across runs (same secret
    /// produces the same hash with the same key) without exposing the
    /// actual secret value. When `None`, the context is shown verbatim.
    pub redaction_key: Option<[u8; 32]>,
    /// Number of bytes before and after the detection span to include as
    /// context. The actual window may be shorter at file boundaries
    /// (clamped via `saturating_sub` and `min(data.len())`).
    pub context_window: usize,
}

impl Default for ErrorBookConfig {
    fn default() -> Self {
        Self {
            max_entries: 20,
            redaction_key: None,
            context_window: 64,
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Build the error book from classified findings and false negatives.
///
/// Produces a deterministic [`ErrorBook`] in two independent passes:
///
/// 1. **FP pass**: filters `classified` to [`FindingClass::FalsePositive`]
///    items, groups by rule name, selects the highest-confidence finding
///    as the representative, and extracts a context window from
///    `file_contents`.
/// 2. **FN pass**: groups `false_negatives` by rule name and selects the
///    first item as the representative. No context extraction (truth items
///    lack byte offsets).
///
/// Both passes sort by descending count with lexicographic rule-name
/// tie-breaking, then truncate to [`ErrorBookConfig::max_entries`].
///
/// # Parameters
///
/// - `classified`: all classified findings (TP, FP, and Unlabeled). Only
///   FP items are used; the rest are skipped in the counting pass.
/// - `false_negatives`: truth items that no finding matched.
/// - `file_contents`: corpus file contents keyed by path, used to extract
///   context windows for FP entries. Missing paths produce `None` context.
/// - `config`: controls entry count, context window size, and redaction.
pub fn build_error_book(
    classified: &[ClassifiedFinding],
    false_negatives: &[TruthItem],
    file_contents: &HashMap<String, Vec<u8>>,
    config: &ErrorBookConfig,
) -> ErrorBook {
    let false_positives = build_fp_entries(classified, file_contents, config);
    let false_negatives = build_fn_entries(false_negatives, config);

    ErrorBook {
        false_positives,
        false_negatives,
    }
}

/// Render the report as pretty-printed JSON.
///
/// Validates that all metric fields are finite (not NaN or Inf) before
/// serialization. NaN/Inf values cannot be represented in JSON and would
/// produce corrupt output that downstream consumers cannot parse.
///
/// # Errors
///
/// Returns `serde_json::Error` if any metric field is non-finite or if
/// serialization fails.
pub fn render_json(report: &EvalReport) -> Result<String, serde_json::Error> {
    validate_finite(report)?;
    serde_json::to_string_pretty(report)
}

/// Render a terminal-friendly summary table.
///
/// Produces an ASCII table with three sections:
///
/// 1. **Aggregate metrics**: AP (with CI if present), precision, recall,
///    F1, F2, and raw TP/FP/FN counts.
/// 2. **Per-rule breakdown** (omitted when empty): rule name (truncated
///    at byte offset 20, char-boundary-safe), TP, FP, and precision per rule.
/// 3. **Regression verdict**: PASS/WARN/BLOCK or "N/A (no baseline)".
///
/// Uses `fmt::Write` to a pre-allocated `String` sized to
/// `700 + rule_count * 80` bytes, avoiding per-row `format!()` heap
/// allocations. Plain ASCII box-drawing (`+`, `-`, `|`) for broad
/// terminal compatibility.
pub fn render_table(report: &EvalReport) -> String {
    let rule_count = report.metrics.per_rule.len();
    let mut out = String::with_capacity(700 + rule_count * 80);

    let _ = writeln!(out, "+{:-<55}+", "");
    let _ = writeln!(out, "| {:<53} |", "Eval Report");
    let _ = writeln!(out, "+{:-<55}+", "");

    // Aggregate metrics.
    write_metric_row(
        &mut out,
        "PRC-AUC (AP)",
        report.metrics.average_precision,
        report.metrics.ap_ci.as_ref(),
    );
    write_simple_row(&mut out, "Precision", report.metrics.precision);
    write_simple_row(&mut out, "Recall", report.metrics.recall);
    write_simple_row(&mut out, "F1", report.metrics.f1);
    write_simple_row(&mut out, "F2", report.metrics.f2);

    let _ = writeln!(
        out,
        "| {:<17} {:>8} / {:>8} / {:>14} |",
        "TP / FP / FN", report.metrics.tp, report.metrics.fp, report.metrics.false_neg,
    );

    // Per-rule breakdown.
    if !report.metrics.per_rule.is_empty() {
        let _ = writeln!(out, "+{:-<55}+", "");
        let _ = writeln!(out, "| {:<53} |", "Per-Rule Breakdown");
        let _ = writeln!(
            out,
            "| {:<20} {:>5} {:>5} {:>10}           |",
            "Rule", "TP", "FP", "Precision"
        );
        for (rule, rm) in &report.metrics.per_rule {
            // Truncate long rule names to fit the 20-byte fixed-width column,
            // snapping to the nearest char boundary to avoid splitting multi-byte chars.
            let max_bytes = rule.len().min(20);
            let display_rule = &rule[..rule.floor_char_boundary(max_bytes)];
            let _ = writeln!(
                out,
                "| {:<20} {:>5} {:>5} {:>10.4}           |",
                display_rule, rm.tp, rm.fp, rm.precision
            );
        }
    }

    // Regression verdict.
    let _ = writeln!(out, "+{:-<55}+", "");
    if let Some(ref reg) = report.regression {
        let _ = writeln!(out, "| Regression: {:<41} |", reg.verdict.to_string());
    } else {
        let _ = writeln!(out, "| {:<53} |", "Regression: N/A (no baseline)");
    }
    let _ = writeln!(out, "+{:-<55}+", "");

    out
}

/// Write a pretty-printed JSON report to a file.
///
/// Creates or truncates the file at `path`, writes through a 64 KiB
/// `BufWriter` (matching the codebase convention for file I/O), and
/// flushes before returning.
///
/// Validates that all metric fields are finite before serialization.
///
/// # Errors
///
/// Returns `io::Error` if any metric field is non-finite, file creation
/// fails, JSON serialization fails, or flush fails.
pub fn write_json_file(report: &EvalReport, path: &Path) -> io::Result<()> {
    validate_finite(report).map_err(io::Error::other)?;
    let file = std::fs::File::create(path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    serde_json::to_writer_pretty(&mut writer, report).map_err(io::Error::other)?;
    writer.flush()
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Build FP error book entries from classified findings.
///
/// Two-phase algorithm:
///
/// 1. **Counting pass** (O(n)): scan all classified findings, skip non-FP,
///    and accumulate per-rule `(count, best_confidence, best_index)` into
///    a `HashMap<&str, _>`. Keys borrow from the input to avoid
///    per-finding string allocation. The `best_confidence` / `best_index`
///    track the highest-confidence finding per rule for representative
///    selection.
///
/// 2. **Ranking pass**: sort by descending count, break ties
///    lexicographically by rule name for determinism, then truncate to
///    `max_entries`. Context extraction happens only for surviving entries,
///    so file I/O is bounded by `max_entries`, not by total FP count.
fn build_fp_entries(
    classified: &[ClassifiedFinding],
    file_contents: &HashMap<String, Vec<u8>>,
    config: &ErrorBookConfig,
) -> Vec<ErrorBookEntry> {
    // Counting pass: per-rule (count, best_confidence, best_index).
    // `i8::MIN` as initial confidence ensures any real finding wins the
    // first comparison without a separate "uninitialized" flag.
    let mut counts: HashMap<&str, (u64, i8, usize)> = HashMap::new();

    for (idx, cf) in classified.iter().enumerate() {
        if cf.class != FindingClass::FalsePositive {
            continue;
        }
        let entry = counts
            .entry(cf.finding.rule.as_str())
            .or_insert((0, i8::MIN, idx));
        entry.0 += 1;
        if cf.finding.confidence > entry.1 {
            entry.1 = cf.finding.confidence;
            entry.2 = idx;
        }
    }

    let mut ranked: Vec<(&str, u64, i8, usize)> = counts
        .into_iter()
        .map(|(rule, (count, conf, idx))| (rule, count, conf, idx))
        .collect();
    // Descending count, then ascending rule name for deterministic output.
    ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked.truncate(config.max_entries);

    ranked
        .into_iter()
        .map(|(rule, count, conf, idx)| {
            let finding = &classified[idx].finding;
            let context = extract_context(
                file_contents,
                &finding.path,
                finding.byte_start as usize,
                finding.byte_end as usize,
                config,
            );
            ErrorBookEntry {
                rule: rule.to_string(),
                count,
                classification: ErrorBookClass::FalsePositive,
                confidence: conf,
                path: finding.path.clone(),
                redacted_context: context,
            }
        })
        .collect()
}

/// Build FN error book entries from false negative truth items.
///
/// Follows the same two-phase (count, then rank) algorithm as
/// [`build_fp_entries`] but simpler: truth items have no confidence
/// score, so the representative is the first item encountered for each
/// rule (stable given consistent input ordering). Context extraction is
/// skipped entirely because [`TruthItem`](crate::types::TruthItem)
/// carries line-based coordinates, not byte offsets.
fn build_fn_entries(
    false_negatives: &[TruthItem],
    config: &ErrorBookConfig,
) -> Vec<ErrorBookEntry> {
    // Counting pass: per-rule (count, first_index).
    let mut counts: HashMap<&str, (u64, usize)> = HashMap::new();

    for (idx, item) in false_negatives.iter().enumerate() {
        let entry = counts.entry(item.rule.as_str()).or_insert((0, idx));
        entry.0 += 1;
    }

    let mut ranked: Vec<(&str, u64, usize)> = counts
        .into_iter()
        .map(|(rule, (count, idx))| (rule, count, idx))
        .collect();
    // Descending count, then ascending rule name for deterministic output.
    ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked.truncate(config.max_entries);

    ranked
        .into_iter()
        .map(|(rule, count, idx)| {
            let item = &false_negatives[idx];
            // FN entries come from unmatched truth items, not scanner
            // findings, so there is no confidence score or byte span to
            // extract context from.
            ErrorBookEntry {
                rule: rule.to_string(),
                count,
                classification: ErrorBookClass::FalseNegative,
                confidence: 0,
                path: item.path.clone(),
                redacted_context: None,
            }
        })
        .collect()
}

/// Extract a context window around a byte span, optionally redacting the
/// secret portion.
///
/// Returns `None` when:
/// - `path` is not present in `file_contents` (file was not loaded).
/// - `byte_start > byte_end` (inverted span -- indicates corrupt offsets).
/// - `byte_end` exceeds the file length (stale or corrupt byte offsets).
///
/// The context window is `[byte_start - context_window, byte_end + context_window]`
/// clamped to `[0, data.len()]`, so it is always safe even when the span
/// is near file boundaries. A zero-width span (`byte_start == byte_end`)
/// is valid and produces a context window centered on that byte position
/// with no secret portion; when redaction is enabled, the redaction
/// placeholder hashes an empty slice, yielding a deterministic
/// `[REDACTED:<hash_of_empty>]` token.
///
/// When redaction is enabled, the output has the structure:
/// `<prefix_bytes><[REDACTED:<keyed_hash_hex>]><suffix_bytes>`, where the
/// keyed hash is deterministic for a given (key, secret) pair. Non-UTF-8
/// bytes in prefix/suffix are replaced via `String::from_utf8_lossy`.
fn extract_context(
    file_contents: &HashMap<String, Vec<u8>>,
    path: &str,
    byte_start: usize,
    byte_end: usize,
    config: &ErrorBookConfig,
) -> Option<String> {
    let data = file_contents.get(path)?;
    if byte_start > byte_end || byte_end > data.len() {
        eprintln!(
            "warning: corrupt byte offsets for {path}: start={byte_start}, end={byte_end}, \
             file_len={}",
            data.len()
        );
        return None;
    }

    let ctx_start = byte_start.saturating_sub(config.context_window);
    let ctx_end = byte_end
        .saturating_add(config.context_window)
        .min(data.len());
    let span = &data[ctx_start..ctx_end];

    if let Some(key) = &config.redaction_key {
        // Reconstruct context as: prefix || [REDACTED:hash] || suffix,
        // where prefix and suffix are the non-secret portions of the
        // context window.
        let secret_slice = &data[byte_start..byte_end];
        let hash = blake3::keyed_hash(key, secret_slice);
        let prefix = &data[ctx_start..byte_start];
        let suffix = &data[byte_end..ctx_end];

        let mut result = String::with_capacity(prefix.len() + 64 + suffix.len());
        result.push_str(&String::from_utf8_lossy(prefix));
        result.push_str(&format!("[REDACTED:{}]", hash.to_hex()));
        result.push_str(&String::from_utf8_lossy(suffix));
        Some(result)
    } else {
        Some(String::from_utf8_lossy(span).into_owned())
    }
}

/// Write a metric row with optional bootstrap CI annotation.
///
/// When `ci` is `Some`, appends `[CI: lower, upper]` after the value.
/// When `None`, falls through to [`write_simple_row`].
fn write_metric_row(
    out: &mut String,
    label: &str,
    value: f64,
    ci: Option<&crate::metrics::ConfidenceInterval>,
) {
    if let Some(ci) = ci {
        let _ = writeln!(
            out,
            "| {:<17} {:<8.4}  [CI: {:.4}, {:.4}]      |",
            label, value, ci.lower, ci.upper,
        );
    } else {
        write_simple_row(out, label, value);
    }
}

/// Write a single `| label  value |` row to the table string.
fn write_simple_row(out: &mut String, label: &str, value: f64) {
    let _ = writeln!(out, "| {:<17} {:<36.4} |", label, value);
}

/// Validate that all core `f64` metric fields are finite (not NaN or Inf).
///
/// Serializing NaN or Infinity to JSON produces invalid output that
/// downstream consumers (CI parsers, baseline comparators) cannot handle.
/// This guard catches upstream computation bugs at the serialization
/// boundary rather than silently producing corrupt JSON.
///
/// Checks: `average_precision`, `precision`, `recall`, `f1`, `f2`,
/// `baseline_ap`, per-rule precision values, and CI bounds when present.
///
/// # Scope limitations
///
/// This function does **not** validate `precision_at_recall`,
/// `recall_at_precision`, or any fields inside
/// [`RegressionResult`]. Those values flow through from upstream
/// computations that use [`safe_div`](crate::metrics::safe_div) (which
/// returns 0.0 rather than NaN), so non-finite values there are unlikely
/// but not defensively guarded here.
fn validate_finite(report: &EvalReport) -> Result<(), serde_json::Error> {
    let m = &report.metrics;
    let fields = [
        ("average_precision", m.average_precision),
        ("precision", m.precision),
        ("recall", m.recall),
        ("f1", m.f1),
        ("f2", m.f2),
        ("baseline_ap", m.baseline_ap),
    ];
    for (name, v) in fields {
        if !v.is_finite() {
            return Err(serde::ser::Error::custom(format!(
                "metric field '{name}' is not finite: {v}"
            )));
        }
    }
    // Check per-rule precision values.
    for (rule, rm) in &m.per_rule {
        if !rm.precision.is_finite() {
            return Err(serde::ser::Error::custom(format!(
                "per-rule precision for '{rule}' is not finite: {}",
                rm.precision
            )));
        }
    }
    // Check CI bounds when present.
    if let Some(ci) = &m.ap_ci
        && (!ci.lower.is_finite() || !ci.upper.is_finite())
    {
        return Err(serde::ser::Error::custom(format!(
            "CI bounds are not finite: lower={}, upper={}",
            ci.lower, ci.upper
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::metrics::{ConfidenceInterval, RuleMetrics};
    use crate::regression::{RegressionThresholds, Verdict};
    use crate::types::NormalizedFinding;

    /// Build a minimal EvalReport for testing.
    fn sample_report(with_regression: bool, with_error_book: bool) -> EvalReport {
        let mut per_rule = BTreeMap::new();
        per_rule.insert(
            "aws-access-key".to_string(),
            RuleMetrics {
                tp: 45,
                fp: 2,
                precision: 45.0 / 47.0,
            },
        );
        per_rule.insert(
            "slack-bot-token".to_string(),
            RuleMetrics {
                tp: 12,
                fp: 8,
                precision: 12.0 / 20.0,
            },
        );

        let metrics = EvalMetrics {
            average_precision: 0.9234,
            precision: 0.8765,
            recall: 0.9345,
            f1: 0.9045,
            f2: 0.9221,
            tp: 234,
            fp: 32,
            false_neg: 16,
            unlabeled: 5,
            baseline_ap: 0.8765,
            precision_at_recall: vec![],
            recall_at_precision: vec![],
            ap_ci: Some(ConfidenceInterval {
                lower: 0.9012,
                upper: 0.9456,
            }),
            per_rule,
        };

        let provenance = Provenance {
            corpus_hash: "a".repeat(64),
            binary_hash: None,
            ruleset_hash: None,
            corpus_file_count: 100,
            corpus_total_bytes: 50000,
        };

        let regression = if with_regression {
            Some(crate::regression::RegressionResult {
                verdict: Verdict::Pass,
                checks: [
                    crate::regression::MetricCheck {
                        metric: crate::regression::MetricName::AveragePrecision,
                        current: 0.9234,
                        baseline: 0.8765,
                        delta: 0.0469,
                        verdict: Verdict::Pass,
                        ci_gate_applied: false,
                    },
                    crate::regression::MetricCheck {
                        metric: crate::regression::MetricName::Precision,
                        current: 0.8765,
                        baseline: 0.8765,
                        delta: 0.0,
                        verdict: Verdict::Pass,
                        ci_gate_applied: false,
                    },
                ],
                per_rule_deltas: vec![],
                thresholds: RegressionThresholds::default(),
            })
        } else {
            None
        };

        let error_book = if with_error_book {
            Some(ErrorBook {
                false_positives: vec![ErrorBookEntry {
                    rule: "test-rule".to_string(),
                    count: 5,
                    classification: ErrorBookClass::FalsePositive,
                    confidence: 10,
                    path: "test.txt".to_string(),
                    redacted_context: Some("...secret...".to_string()),
                }],
                false_negatives: vec![],
            })
        } else {
            None
        };

        EvalReport {
            metrics,
            provenance,
            regression,
            error_book,
        }
    }

    #[test]
    fn render_json_serialization() {
        // Round-trip: valid JSON object.
        let report = sample_report(true, true);
        let json = render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());

        // None fields are omitted from JSON output.
        let report = sample_report(false, false);
        let json = render_json(&report).unwrap();
        assert!(
            !json.contains("\"regression\""),
            "None regression should be skipped"
        );
        assert!(
            !json.contains("\"error_book\""),
            "None error_book should be skipped"
        );
    }

    #[test]
    fn render_json_rejects_nan_metrics() {
        let mut report = sample_report(false, false);
        report.metrics.average_precision = f64::NAN;
        let err = render_json(&report).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("average_precision") && msg.contains("not finite"),
            "error should name the offending field: {msg}"
        );
    }

    #[test]
    fn render_json_rejects_inf_per_rule_precision() {
        let mut report = sample_report(false, false);
        report
            .metrics
            .per_rule
            .values_mut()
            .next()
            .unwrap()
            .precision = f64::INFINITY;
        let err = render_json(&report).unwrap_err();
        assert!(
            err.to_string().contains("per-rule precision"),
            "error should mention per-rule precision: {}",
            err
        );
    }

    #[test]
    fn write_json_file_rejects_nan() {
        let mut report = sample_report(false, false);
        report.metrics.f1 = f64::NAN;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let err = write_json_file(&report, tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("f1"),
            "error should name the offending field: {}",
            err
        );
    }

    #[test]
    fn render_table_contains_expected_content() {
        // (with_regression, with_error_book, expected substrings)
        let cases: &[(bool, bool, &[&str])] = &[
            (true, false, &["PRC-AUC", "Precision", "Recall", "F1", "F2"]),
            (false, false, &["aws-access-key", "slack-bot-token"]),
            (true, false, &["Regression: PASS"]),
            (false, false, &["N/A (no baseline)"]),
        ];
        for &(with_reg, with_eb, expected) in cases {
            let report = sample_report(with_reg, with_eb);
            let table = render_table(&report);
            for exp in expected {
                assert!(
                    table.contains(exp),
                    "table missing '{exp}' (reg={with_reg}, eb={with_eb})"
                );
            }
        }
    }

    #[test]
    fn build_error_book_fp_sorted_desc() {
        let classified = vec![
            ClassifiedFinding {
                finding: NormalizedFinding::new("f.txt".into(), 0, 5, "rule_a".into(), 10),
                class: FindingClass::FalsePositive,
            },
            ClassifiedFinding {
                finding: NormalizedFinding::new("f.txt".into(), 10, 15, "rule_a".into(), 8),
                class: FindingClass::FalsePositive,
            },
            ClassifiedFinding {
                finding: NormalizedFinding::new("f.txt".into(), 20, 25, "rule_a".into(), 6),
                class: FindingClass::FalsePositive,
            },
            ClassifiedFinding {
                finding: NormalizedFinding::new("f.txt".into(), 30, 35, "rule_b".into(), 5),
                class: FindingClass::FalsePositive,
            },
            ClassifiedFinding {
                finding: NormalizedFinding::new("f.txt".into(), 40, 45, "rule_b".into(), 3),
                class: FindingClass::FalsePositive,
            },
        ];
        let fc: HashMap<String, Vec<u8>> = HashMap::new();
        let config = ErrorBookConfig::default();

        let book = build_error_book(&classified, &[], &fc, &config);
        assert_eq!(book.false_positives.len(), 2);
        assert_eq!(book.false_positives[0].rule, "rule_a");
        assert_eq!(book.false_positives[0].count, 3);
        assert_eq!(book.false_positives[1].rule, "rule_b");
        assert_eq!(book.false_positives[1].count, 2);
        // Representative has highest confidence for that rule.
        assert_eq!(
            book.false_positives[0].confidence, 10,
            "rule_a best confidence"
        );
        assert_eq!(
            book.false_positives[1].confidence, 5,
            "rule_b best confidence"
        );
    }

    #[test]
    fn build_error_book_redacted_context() {
        let classified = vec![ClassifiedFinding {
            finding: NormalizedFinding::new("f.txt".into(), 5, 10, "rule_a".into(), 10),
            class: FindingClass::FalsePositive,
        }];
        let mut fc = HashMap::new();
        fc.insert("f.txt".to_string(), b"prefix-SECRET-suffix".to_vec());

        let key = [0u8; 32];
        let config = ErrorBookConfig {
            max_entries: 20,
            redaction_key: Some(key),
            context_window: 64,
        };

        let book = build_error_book(&classified, &[], &fc, &config);
        let ctx = book.false_positives[0].redacted_context.as_ref().unwrap();
        assert!(
            ctx.contains("[REDACTED:"),
            "context should be redacted: {ctx}"
        );
        assert!(
            !ctx.contains("SECRE"),
            "redacted context must not contain secret"
        );
    }

    #[test]
    fn build_error_book_empty_file_contents() {
        let classified = vec![ClassifiedFinding {
            finding: NormalizedFinding::new("missing.txt".into(), 0, 5, "rule_a".into(), 10),
            class: FindingClass::FalsePositive,
        }];
        let fc: HashMap<String, Vec<u8>> = HashMap::new();
        let config = ErrorBookConfig::default();

        let book = build_error_book(&classified, &[], &fc, &config);
        assert_eq!(book.false_positives.len(), 1);
        assert!(book.false_positives[0].redacted_context.is_none());
    }

    #[test]
    fn build_error_book_fn_entries() {
        let fns = vec![
            TruthItem::new(
                "a.txt".into(),
                1,
                1,
                crate::types::TruthLabel::Positive,
                "rule_x".into(),
            ),
            TruthItem::new(
                "b.txt".into(),
                2,
                2,
                crate::types::TruthLabel::Positive,
                "rule_x".into(),
            ),
            TruthItem::new(
                "c.txt".into(),
                3,
                3,
                crate::types::TruthLabel::Positive,
                "rule_x".into(),
            ),
            TruthItem::new(
                "d.txt".into(),
                4,
                4,
                crate::types::TruthLabel::Positive,
                "rule_y".into(),
            ),
        ];
        let config = ErrorBookConfig::default();
        let book = build_error_book(&[], &fns, &HashMap::new(), &config);

        // FN entries sorted by descending count, then lexicographic rule name.
        assert_eq!(book.false_negatives.len(), 2);
        assert_eq!(book.false_negatives[0].rule, "rule_x");
        assert_eq!(book.false_negatives[0].count, 3);
        assert_eq!(book.false_negatives[1].rule, "rule_y");
        assert_eq!(book.false_negatives[1].count, 1);

        // FN entries always have confidence 0 and no context.
        for entry in &book.false_negatives {
            assert_eq!(
                entry.confidence, 0,
                "FN confidence must be 0 for {}",
                entry.rule
            );
            assert!(
                entry.redacted_context.is_none(),
                "FN context must be None for {}",
                entry.rule
            );
            assert_eq!(entry.classification, ErrorBookClass::FalseNegative);
        }

        // FP list is empty when no classified findings provided.
        assert!(book.false_positives.is_empty());
    }

    #[test]
    fn extract_context_inverted_span_returns_none() {
        let mut fc = HashMap::new();
        fc.insert("f.txt".to_string(), b"0123456789".to_vec());
        let config = ErrorBookConfig::default();

        // byte_start > byte_end is invalid — must return None.
        let ctx = extract_context(&fc, "f.txt", 8, 3, &config);
        assert!(ctx.is_none(), "inverted byte span must return None");
    }

    #[test]
    fn extract_context_span_exceeds_file_length() {
        let mut fc = HashMap::new();
        fc.insert("f.txt".to_string(), b"short".to_vec());
        let config = ErrorBookConfig::default();

        // byte_end exceeds file length — must return None.
        let ctx = extract_context(&fc, "f.txt", 0, 100, &config);
        assert!(ctx.is_none(), "span beyond file length must return None");
    }

    #[test]
    fn build_error_book_verbatim_context() {
        let classified = vec![ClassifiedFinding {
            finding: NormalizedFinding::new("f.txt".into(), 10, 16, "rule_a".into(), 10),
            class: FindingClass::FalsePositive,
        }];
        let mut fc = HashMap::new();
        // Controlled content: "SECRET" at bytes [10..16].
        let content = b"0123456789SECRETyz0123456789";
        fc.insert("f.txt".to_string(), content.to_vec());

        // Default config: no redaction key, small context window.
        let config = ErrorBookConfig {
            max_entries: 20,
            redaction_key: None,
            context_window: 5,
        };

        let book = build_error_book(&classified, &[], &fc, &config);
        let ctx = book.false_positives[0].redacted_context.as_ref().unwrap();
        // Context window: [10-5, 16+5] = [5, 21], so "56789SECRETyz012"
        assert!(
            ctx.contains("SECRET"),
            "verbatim context must contain the secret: {ctx}"
        );
        assert!(ctx.contains("56789"), "context prefix: {ctx}");
        assert!(ctx.contains("yz012"), "context suffix: {ctx}");
    }

    #[test]
    fn render_table_empty_per_rule() {
        let mut report = sample_report(true, false);
        report.metrics.per_rule = BTreeMap::new();
        let table = render_table(&report);

        assert!(
            !table.contains("Per-Rule Breakdown"),
            "empty per_rule should omit the per-rule section"
        );
        // Aggregate metrics and regression line must still be present.
        assert!(table.contains("PRC-AUC"), "missing aggregate metrics");
        assert!(
            table.contains("Regression: PASS"),
            "missing regression verdict"
        );
    }

    #[test]
    fn write_json_file_round_trip() {
        let report = sample_report(true, true);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_json_file(&report, tmp.path()).unwrap();

        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("metrics").is_some());
        assert!(parsed.get("provenance").is_some());
        assert!(parsed.get("regression").is_some());
        assert!(parsed.get("error_book").is_some());
    }

    // ── Proptest ─────────────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Error book FP entries are always bounded by max_entries.
            #[test]
            fn fp_bounded_by_max_entries(
                n_rules in 0usize..50,
                max_entries in 1usize..10,
            ) {
                let classified: Vec<ClassifiedFinding> = (0..n_rules)
                    .map(|i| ClassifiedFinding {
                        finding: NormalizedFinding::new(
                            "f.txt".into(),
                            i as u64 * 10,
                            i as u64 * 10 + 5,
                            format!("rule_{i}"),
                            10,
                        ),
                        class: FindingClass::FalsePositive,
                    })
                    .collect();
                let config = ErrorBookConfig {
                    max_entries,
                    ..Default::default()
                };
                let book = build_error_book(&classified, &[], &HashMap::new(), &config);
                prop_assert!(book.false_positives.len() <= max_entries);
            }

            /// FP entries are always sorted descending by count, with
            /// lexicographic rule-name tie-breaking.
            #[test]
            fn fp_sorted_desc_by_count(n_fp in 1usize..40) {
                let classified: Vec<ClassifiedFinding> = (0..n_fp)
                    .map(|i| ClassifiedFinding {
                        finding: NormalizedFinding::new(
                            "f.txt".into(),
                            i as u64 * 10,
                            i as u64 * 10 + 5,
                            format!("rule_{}", i % 7),
                            (i % 127) as i8,
                        ),
                        class: FindingClass::FalsePositive,
                    })
                    .collect();
                let config = ErrorBookConfig::default();
                let book = build_error_book(&classified, &[], &HashMap::new(), &config);
                for w in book.false_positives.windows(2) {
                    prop_assert!(
                        w[0].count > w[1].count
                            || (w[0].count == w[1].count && w[0].rule <= w[1].rule),
                        "FP entries not sorted: {:?} followed by {:?}",
                        (w[0].count, &w[0].rule),
                        (w[1].count, &w[1].rule),
                    );
                }
            }

            /// Same inputs always produce the same error book.
            #[test]
            fn error_book_deterministic(n_fp in 0usize..20, n_fn in 0usize..20) {
                let classified: Vec<ClassifiedFinding> = (0..n_fp)
                    .map(|i| ClassifiedFinding {
                        finding: NormalizedFinding::new(
                            "f.txt".into(),
                            i as u64 * 10,
                            i as u64 * 10 + 5,
                            format!("rule_{}", i % 5),
                            (i % 127) as i8,
                        ),
                        class: FindingClass::FalsePositive,
                    })
                    .collect();
                let fns: Vec<TruthItem> = (0..n_fn)
                    .map(|i| TruthItem::new(
                        "f.txt".into(),
                        (i as u32) + 1,
                        (i as u32) + 1,
                        crate::types::TruthLabel::Positive,
                        format!("rule_{}", i % 3),
                    ))
                    .collect();
                let config = ErrorBookConfig::default();
                let b1 = build_error_book(&classified, &fns, &HashMap::new(), &config);
                let b2 = build_error_book(&classified, &fns, &HashMap::new(), &config);
                prop_assert_eq!(b1.false_positives.len(), b2.false_positives.len());
                prop_assert_eq!(b1.false_negatives.len(), b2.false_negatives.len());
                // Verify content equality, not just length.
                for (a, b) in b1.false_positives.iter().zip(b2.false_positives.iter()) {
                    prop_assert_eq!(&a.rule, &b.rule);
                    prop_assert_eq!(a.count, b.count);
                    prop_assert_eq!(a.confidence, b.confidence);
                }
                for (a, b) in b1.false_negatives.iter().zip(b2.false_negatives.iter()) {
                    prop_assert_eq!(&a.rule, &b.rule);
                    prop_assert_eq!(a.count, b.count);
                }
            }
        }
    }
}
