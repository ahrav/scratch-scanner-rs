//! JSONL finding parser for scanner output.
//!
//! Reads JSONL produced by the scanner's [`JsonlEncoder`] and extracts
//! [`NormalizedFinding`] records for accuracy evaluation. Non-finding
//! event types (progress, summary, diagnostic, etc.) are silently skipped;
//! malformed lines are counted but do not halt parsing.
//!
//! The two entry points differ only in I/O:
//!
//! - [`parse_findings_jsonl`] — in-memory, infallible (errors become counters)
//! - [`parse_findings_file`] — reads from disk, returns `Result` for I/O errors
//!
//! After parsing, call [`dedup_findings`] to collapse duplicate detections at
//! the same `(path, byte_start, byte_end, rule)` identity, retaining the
//! highest confidence score.
//!
//! # Wire format
//!
//! Each JSONL line is a JSON object with a `"type"` discriminator. This
//! module only extracts `"finding"` events; all other types are counted
//! and skipped. A typical finding line:
//!
//! ```json
//! {"type":"finding","source":"fs","path":"src/main.rs","start":42,"end":80,"rule":"aws-access-key","rule_id":1,"confidence_score":5}
//! ```
//!
//! (Actual wire lines include additional fields such as `source`,
//! `commit_id`, `change_kind`, and `rule_id` — all intentionally
//! discarded here because the eval corpora are file-level, not
//! commit-level.)
//!
//! [`JsonlEncoder`]: scanner_rs::unified::events::JsonlEncoder

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::{NormalizedFinding, normalize_path};

// ── Wire format ──────────────────────────────────────────────────────────

/// Zero-copy borrowing view of one JSONL line for deserialization.
///
/// All fields except `event_type` are optional so that lines with
/// unrecognized or missing fields parse successfully instead of
/// producing a serde error. This makes the parser robust to new
/// event types and future wire-format additions.
///
/// Uses `&'a str` borrows rather than owned `String`s because most
/// lines are non-finding events that are counted and discarded. Paying
/// for allocation only on the ~5-10% of lines that produce
/// [`NormalizedFinding`] values keeps throughput high on large JSONL
/// streams.
#[derive(Deserialize)]
struct WireLine<'a> {
    /// The `"type"` discriminator from the wire format. Renamed because
    /// `type` is a Rust keyword.
    #[serde(rename = "type")]
    event_type: &'a str,
    path: Option<&'a str>,
    start: Option<u64>,
    end: Option<u64>,
    rule: Option<&'a str>,
    confidence_score: Option<i8>,
}

// ── Public types ─────────────────────────────────────────────────────────

/// Outcome of parsing a JSONL stream.
///
/// Separates successfully extracted findings from diagnostic counters so
/// callers can both consume results and report parse quality (e.g., warn
/// when `malformed_lines` is unexpectedly high, indicating a corrupt or
/// truncated file).
///
/// # Counting invariant
///
/// Every input line is classified into exactly one bucket:
///
/// ```text
/// total_lines == findings.len() + non_finding_lines + malformed_lines + skipped_findings
/// ```
///
/// This invariant is enforced by a property test (`line_count_invariant_always_holds`)
/// over arbitrary inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParseResult {
    /// Successfully parsed and validated findings.
    pub findings: Vec<NormalizedFinding>,
    /// Total lines processed (including empty, non-finding, malformed, and
    /// skipped).
    pub total_lines: u64,
    /// Lines that parsed as valid JSON but were not finding events (e.g.,
    /// progress, summary, diagnostic), plus empty lines (after `\r`
    /// trimming).
    pub non_finding_lines: u64,
    /// Lines that failed JSON deserialization entirely.
    pub malformed_lines: u64,
    /// Lines that deserialized as findings but were rejected during
    /// validation (inverted span, empty normalized path, missing required
    /// fields on a finding-typed line).
    pub skipped_findings: u64,
}

/// Errors that can occur when reading a JSONL file from disk.
///
/// Only I/O failures are represented here. Parse-level errors (malformed
/// JSON, invalid fields) are deliberately non-fatal — they are counted in
/// [`ParseResult`] instead. This two-tier design means callers only need
/// to handle `Result` for true I/O problems; parse corruption is surfaced
/// through counters that can be aggregated across many files.
#[derive(Debug)]
pub enum FindingParseError {
    /// Failed to read the file at `path`.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for FindingParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for FindingParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Parse JSONL text in memory.
///
/// Every line is processed independently — malformed lines increment
/// counters but never halt parsing. The returned [`ParseResult::findings`]
/// may contain duplicates; call [`dedup_findings`] afterward if needed.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from finding paths. Use `""` for no stripping.
pub fn parse_findings_jsonl(jsonl: &str, canonical_root: &str) -> ParseResult {
    let mut result = ParseResult {
        findings: Vec::new(),
        total_lines: 0,
        non_finding_lines: 0,
        malformed_lines: 0,
        skipped_findings: 0,
    };

    // split('\n') rather than lines(): str::lines() strips trailing
    // newlines and yields zero items for "", which would make total_lines
    // undershoot and violate the counting invariant. split('\n') always
    // yields at least one element, so even "" counts as one (empty) line.
    for line in jsonl.split('\n') {
        parse_line(line, canonical_root, &mut result);
    }

    result
}

/// Parse JSONL from a file on disk.
///
/// Reads the entire file into memory, then delegates to
/// [`parse_findings_jsonl`]. Only I/O failures produce errors; parse
/// failures are captured as counters in the returned [`ParseResult`].
pub fn parse_findings_file(
    path: &Path,
    canonical_root: &str,
) -> Result<ParseResult, FindingParseError> {
    let contents = std::fs::read_to_string(path).map_err(|e| FindingParseError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(parse_findings_jsonl(&contents, canonical_root))
}

/// Sort and deduplicate findings in place, retaining the highest
/// confidence per identity.
///
/// Identity is `(path, byte_start, byte_end, rule)` — confidence is
/// excluded from comparison (see [`NormalizedFinding`]'s `Eq` impl).
/// After dedup, findings are in sorted order (lexicographic over the
/// identity tuple).
///
/// # Algorithm
///
/// Uses sort-then-linear-dedup (O(n log n) time, O(n) auxiliary space from
/// the stable sort) rather than a `HashSet`-based approach. This is
/// preferable because:
///
/// 1. The sorted output is useful downstream for deterministic diffing
///    and binary-search lookups against truth items.
/// 2. Avoids heap allocation for a hash table that would be discarded
///    immediately.
/// 3. `dedup_by` gives access to both the retained and removed element,
///    letting us merge the max confidence in the same pass.
///
/// # Post-conditions
///
/// - No two elements share the same identity.
/// - `findings` is sorted by identity.
/// - Each surviving element carries the maximum confidence seen across
///   all duplicates at that identity.
/// - Idempotent: calling twice produces the same result as calling once.
pub fn dedup_findings(findings: &mut Vec<NormalizedFinding>) {
    findings.sort();
    findings.dedup_by(|a, b| {
        // dedup_by: `a` = candidate for removal, `b` = retained element.
        if a == b {
            b.confidence = b.confidence.max(a.confidence);
            true
        } else {
            false
        }
    });
}

// ── Internal ─────────────────────────────────────────────────────────────

/// Process a single JSONL line into `result`.
///
/// Categorizes the line into exactly one of four buckets, maintaining
/// the [`ParseResult`] counting invariant:
///
/// | Condition | Bucket | Action |
/// |---|---|---|
/// | Valid finding with all identity fields | `findings` | Push `NormalizedFinding` |
/// | Non-finding event type, or empty line (after `\r` trimming) | `non_finding_lines` | Count only |
/// | Unparseable JSON | `malformed_lines` | Count only |
/// | Finding-typed but invalid (inverted span, empty path, missing fields) | `skipped_findings` | Count only |
///
/// Handles Windows-style CRLF line endings by stripping trailing `\r`
/// before attempting JSON parse, so the caller can split on `\n` alone.
fn parse_line(line: &str, canonical_root: &str, result: &mut ParseResult) {
    result.total_lines += 1;

    // Trim trailing \r for Windows-style line endings.
    let line = line.trim_end_matches('\r');

    if line.is_empty() {
        result.non_finding_lines += 1;
        return;
    }

    let wire: WireLine<'_> = match serde_json::from_str(line) {
        Ok(w) => w,
        Err(_) => {
            result.malformed_lines += 1;
            return;
        }
    };

    if wire.event_type != "finding" {
        result.non_finding_lines += 1;
        return;
    }

    // All four identity fields must be present for a finding.
    let (Some(path), Some(start), Some(end), Some(rule)) =
        (wire.path, wire.start, wire.end, wire.rule)
    else {
        result.skipped_findings += 1;
        return;
    };

    // Reject inverted spans here rather than relying on
    // NormalizedFinding::new's debug_assert (which is compiled away in
    // release builds). An inverted span that slipped through would panic
    // downstream in LineIndex::line_range during truth-matching.
    if end < start {
        result.skipped_findings += 1;
        return;
    }

    // normalize_path can return "" for degenerate inputs (e.g., "..", ".")
    // where all path components are consumed by lexical resolution.
    let normalized = normalize_path(path, canonical_root);
    if normalized.is_empty() {
        result.skipped_findings += 1;
        return;
    }

    // Missing confidence defaults to 0 (neutral). This is a safe default
    // for PRC-AUC — a finding with confidence 0 will only survive at the
    // lowest threshold.
    let confidence = wire.confidence_score.unwrap_or(0);

    result.findings.push(NormalizedFinding::new(
        normalized,
        start,
        end,
        rule.to_owned(),
        confidence,
    ));
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit tests ──────────────────────────────────────────────

    #[test]
    fn parse_mixed_events() {
        let jsonl = [
            r#"{"type":"finding","path":"src/a.rs","start":0,"end":10,"rule":"key","confidence_score":5}"#,
            r#"{"type":"progress","stage":"scan","objects":100}"#,
            r#"{"type":"finding","path":"src/b.rs","start":20,"end":30,"rule":"token","confidence_score":3}"#,
        ]
        .join("\n");

        let result = parse_findings_jsonl(&jsonl, "");

        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.non_finding_lines, 1);
        assert_eq!(result.malformed_lines, 0);
        assert_eq!(result.skipped_findings, 0);
        assert_eq!(result.total_lines, 3);
    }

    #[test]
    fn malformed_json_counted() {
        let jsonl = "not json at all\n\
                     {\"type\":\"finding\",\"path\":\"a\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.malformed_lines, 1);
    }

    #[test]
    fn dedup_retains_max_confidence() {
        let jsonl = [
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":3}"#,
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":7}"#,
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":1}"#,
        ]
        .join("\n");

        let mut result = parse_findings_jsonl(&jsonl, "");
        assert_eq!(result.findings.len(), 3);

        dedup_findings(&mut result.findings);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].confidence, 7);
    }

    #[test]
    fn empty_input() {
        let result = parse_findings_jsonl("", "");

        assert!(result.findings.is_empty());
        assert_eq!(result.total_lines, 1);
        assert_eq!(result.non_finding_lines, 1);
    }

    #[test]
    fn inverted_span_skipped() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":50,"end":10,"rule":"r","confidence_score":0}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert!(result.findings.is_empty());
        assert_eq!(result.skipped_findings, 1);
    }

    #[test]
    fn missing_required_field_on_finding() {
        // "rule" is absent.
        let jsonl = r#"{"type":"finding","path":"a.rs","start":0,"end":10}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert!(result.findings.is_empty());
        assert_eq!(result.skipped_findings, 1);
    }

    #[test]
    fn path_normalization_with_root() {
        let jsonl = r#"{"type":"finding","path":"corpus/data/src/a.rs","start":0,"end":10,"rule":"r","confidence_score":0}"#;

        let result = parse_findings_jsonl(jsonl, "corpus/data");

        assert_eq!(result.findings[0].path, "src/a.rs");
    }

    #[test]
    fn blank_lines_counted_as_non_finding() {
        let jsonl = "\n\n{\"type\":\"finding\",\"path\":\"a\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\n\n";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.non_finding_lines, 4);
    }

    #[test]
    fn unknown_event_type_is_non_finding() {
        let jsonl = r#"{"type":"new_future_event","data":"stuff"}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert!(result.findings.is_empty());
        assert_eq!(result.non_finding_lines, 1);
        assert_eq!(result.malformed_lines, 0);
    }

    #[test]
    fn missing_confidence_defaults_to_zero() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r"}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].confidence, 0);
    }

    #[test]
    fn zero_length_finding_is_valid() {
        let jsonl =
            r#"{"type":"finding","path":"a.rs","start":5,"end":5,"rule":"r","confidence_score":0}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].byte_start, 5);
        assert_eq!(result.findings[0].byte_end, 5);
    }

    #[test]
    fn line_count_invariant() {
        let jsonl = [
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":0}"#,
            "bad json",
            r#"{"type":"progress"}"#,
            // Inverted span.
            r#"{"type":"finding","path":"a.rs","start":50,"end":10,"rule":"r","confidence_score":0}"#,
            "",
        ]
        .join("\n");

        let result = parse_findings_jsonl(&jsonl, "");

        assert_eq!(
            result.total_lines,
            result.findings.len() as u64
                + result.non_finding_lines
                + result.malformed_lines
                + result.skipped_findings,
        );
    }

    #[test]
    fn negative_confidence_preserved() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":-5}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings[0].confidence, -5);
    }

    #[test]
    fn extra_fields_ignored() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":0,"source":"git","commit_id":7,"change_kind":"add","rule_id":42}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].path, "a.rs");
    }

    #[test]
    fn windows_line_endings() {
        let jsonl = "{\"type\":\"finding\",\"path\":\"a.rs\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\r\n\
                     {\"type\":\"finding\",\"path\":\"b.rs\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\r\n";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn file_not_found_error() {
        let err = parse_findings_file(Path::new("/nonexistent/path.jsonl"), "").unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/path.jsonl"),
            "error should contain path: {msg}"
        );
    }

    #[test]
    fn dedup_distinct_findings_untouched() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 5),
            NormalizedFinding::new("a.rs".into(), 20, 30, "r1".into(), 3),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 7),
        ];

        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn dedup_empty_vec() {
        let mut findings: Vec<NormalizedFinding> = Vec::new();
        dedup_findings(&mut findings);
        assert!(findings.is_empty());
    }

    // ── Property tests ──────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Arbitrary input never panics.
            #[test]
            fn parse_never_panics(input in "\\PC*") {
                let _ = parse_findings_jsonl(&input, "");
            }

            /// The line-count invariant holds for all inputs.
            #[test]
            fn line_count_invariant_always_holds(input in "\\PC*") {
                let r = parse_findings_jsonl(&input, "");
                prop_assert_eq!(
                    r.total_lines,
                    r.findings.len() as u64
                        + r.non_finding_lines
                        + r.malformed_lines
                        + r.skipped_findings,
                );
            }

            /// Dedup is idempotent — running it twice yields the same result.
            #[test]
            fn dedup_idempotent(
                paths in proptest::collection::vec("[a-z]{1,5}", 1..10),
                starts in proptest::collection::vec(0u64..100, 1..10),
                ends in proptest::collection::vec(0u64..200, 1..10),
                rules in proptest::collection::vec("[a-z]{1,3}", 1..10),
                confs in proptest::collection::vec(-128i8..=127i8, 1..10),
            ) {
                let len = paths.len().min(starts.len()).min(ends.len()).min(rules.len()).min(confs.len());
                let mut findings: Vec<NormalizedFinding> = (0..len)
                    .map(|i| NormalizedFinding {
                        path: paths[i].clone(),
                        byte_start: starts[i],
                        byte_end: ends[i],
                        rule: rules[i].clone(),
                        confidence: confs[i],
                    })
                    .collect();

                dedup_findings(&mut findings);
                let snapshot = findings.clone();
                dedup_findings(&mut findings);
                prop_assert_eq!(findings, snapshot);
            }

            /// Dedup never increases the number of findings.
            #[test]
            fn dedup_never_grows(
                paths in proptest::collection::vec("[a-z]{1,3}", 1..20),
                confs in proptest::collection::vec(-128i8..=127i8, 1..20),
            ) {
                let len = paths.len().min(confs.len());
                let mut findings: Vec<NormalizedFinding> = (0..len)
                    .map(|i| NormalizedFinding {
                        path: paths[i].clone(),
                        byte_start: 0,
                        byte_end: 10,
                        rule: "r".into(),
                        confidence: confs[i],
                    })
                    .collect();
                let original_len = findings.len();

                dedup_findings(&mut findings);
                prop_assert!(findings.len() <= original_len);
            }

            /// Valid JSONL finding lines always parse into a finding with matching fields.
            #[test]
            fn valid_finding_roundtrips(
                path in "[a-z]{1,5}(/[a-z]{1,5}){0,3}\\.[a-z]{1,3}",
                start in 0u64..1000,
                span in 0u64..500,
                rule in "[a-z][a-z0-9_-]{0,9}",
                confidence in -128i8..=127i8,
            ) {
                let end = start + span;
                let line = format!(
                    r#"{{"type":"finding","path":"{path}","start":{start},"end":{end},"rule":"{rule}","confidence_score":{confidence}}}"#,
                );

                let result = parse_findings_jsonl(&line, "");

                prop_assert_eq!(result.findings.len(), 1, "should parse exactly one finding");
                prop_assert_eq!(result.malformed_lines, 0);
                prop_assert_eq!(result.skipped_findings, 0);

                let f = &result.findings[0];
                prop_assert_eq!(&f.path, &path);
                prop_assert_eq!(f.byte_start, start);
                prop_assert_eq!(f.byte_end, end);
                prop_assert_eq!(&f.rule, &rule);
                prop_assert_eq!(f.confidence, confidence);
            }

            /// Finding lines without confidence_score default to 0.
            #[test]
            fn missing_confidence_defaults_zero(
                path in "[a-z]{1,5}\\.[a-z]{1,3}",
                start in 0u64..1000,
                span in 0u64..500,
                rule in "[a-z][a-z0-9_-]{0,9}",
            ) {
                let end = start + span;
                let line = format!(
                    r#"{{"type":"finding","path":"{path}","start":{start},"end":{end},"rule":"{rule}"}}"#,
                );

                let result = parse_findings_jsonl(&line, "");

                prop_assert_eq!(result.findings.len(), 1);
                prop_assert_eq!(result.findings[0].confidence, 0);
            }
        }
    }
}
