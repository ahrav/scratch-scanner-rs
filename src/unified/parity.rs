//! Direct-vs-connector parity helpers for JSONL scan output.
//!
//! This module provides two core utilities used by parity harnesses:
//! - canonical finding normalization with commit metadata joins; and
//! - throughput delta and threshold enforcement.

use std::collections::HashMap;
use std::fmt;

/// Canonical finding identity used for deterministic mode-to-mode comparison.
///
/// This tuple intentionally excludes unstable fields (for example `commit_id`,
/// which is only a join key) and keeps the stable identity dimensions used by
/// parity gates: path, rule identity, span, and git commit metadata.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalFinding {
    /// Source-displayed path (JSON string form from finding events).
    pub path: String,
    /// Rule identity (`rule` field from finding events).
    pub rule: String,
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end: u64,
    /// Git-only change kind (`add` / `modify`), omitted for FS findings.
    pub change_kind: Option<String>,
    /// Git commit OID resolved from `commit_meta`, omitted for FS findings.
    pub commit_oid: Option<String>,
    /// Git commit timestamp resolved from `commit_meta`, omitted for FS findings.
    pub commit_timestamp: Option<u64>,
}

/// Canonicalized scan run payload.
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalRun {
    /// Sorted canonical finding identities.
    pub findings: Vec<CanonicalFinding>,
    /// Throughput emitted by the summary event (`throughput_mib_s`).
    pub throughput_mib_s: f64,
}

#[derive(Debug)]
struct PendingFinding {
    path: String,
    rule: String,
    start: u64,
    end: u64,
    change_kind: Option<String>,
    commit_id: Option<u32>,
}

/// Errors emitted while canonicalizing JSONL output into parity tuples.
#[derive(Debug)]
pub enum CanonicalizeError {
    Json {
        line: usize,
        source: serde_json::Error,
    },
    MissingField {
        line: usize,
        field: &'static str,
    },
    InvalidFieldType {
        line: usize,
        field: &'static str,
        expected: &'static str,
    },
    MissingCommitMeta {
        commit_id: u32,
    },
    MissingSummaryThroughput,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { line, source } => {
                write!(f, "failed to parse JSONL line {}: {}", line, source)
            }
            Self::MissingField { line, field } => {
                write!(f, "line {} is missing required field '{}'", line, field)
            }
            Self::InvalidFieldType {
                line,
                field,
                expected,
            } => write!(
                f,
                "line {} has invalid type for '{}'; expected {}",
                line, field, expected
            ),
            Self::MissingCommitMeta { commit_id } => {
                write!(
                    f,
                    "finding references commit_id {} but no commit_meta event was emitted",
                    commit_id
                )
            }
            Self::MissingSummaryThroughput => {
                write!(f, "scan output did not include a summary throughput value")
            }
        }
    }
}

impl std::error::Error for CanonicalizeError {}

/// Throughput threshold evaluation errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ThroughputError {
    EmptyInput,
    NonFinite {
        label: &'static str,
        value: f64,
    },
    NonPositiveBaseline {
        baseline: f64,
    },
    NonPositiveLimit {
        label: &'static str,
        value: f64,
    },
    ThresholdExceeded {
        scope: &'static str,
        observed_abs_pct: f64,
        limit_abs_pct: f64,
        index: Option<usize>,
    },
}

impl fmt::Display for ThroughputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one throughput sample is required"),
            Self::NonFinite { label, value } => {
                write!(f, "throughput value '{}' is non-finite: {}", label, value)
            }
            Self::NonPositiveBaseline { baseline } => {
                write!(f, "baseline throughput must be > 0, got {}", baseline)
            }
            Self::NonPositiveLimit { label, value } => {
                write!(f, "threshold limit '{}' must be > 0, got {}", label, value)
            }
            Self::ThresholdExceeded {
                scope,
                observed_abs_pct,
                limit_abs_pct,
                index,
            } => {
                if let Some(i) = index {
                    write!(
                        f,
                        "{} delta at index {} exceeded limit: {:.4}% > {:.4}%",
                        scope, i, observed_abs_pct, limit_abs_pct
                    )
                } else {
                    write!(
                        f,
                        "{} delta exceeded limit: {:.4}% > {:.4}%",
                        scope, observed_abs_pct, limit_abs_pct
                    )
                }
            }
        }
    }
}

impl std::error::Error for ThroughputError {}

fn required_str(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<String, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Err(CanonicalizeError::MissingField { line, field });
    };
    let Some(s) = raw.as_str() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "string",
        });
    };
    Ok(s.to_owned())
}

fn required_u64(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<u64, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Err(CanonicalizeError::MissingField { line, field });
    };
    let Some(n) = raw.as_u64() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "u64",
        });
    };
    Ok(n)
}

fn optional_u32(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<Option<u32>, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    let Some(n) = raw.as_u64() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "u32",
        });
    };
    let parsed = u32::try_from(n).map_err(|_| CanonicalizeError::InvalidFieldType {
        line,
        field,
        expected: "u32",
    })?;
    Ok(Some(parsed))
}

fn optional_string(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<Option<String>, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    let Some(s) = raw.as_str() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "string",
        });
    };
    Ok(Some(s.to_owned()))
}

/// Parse JSONL scan output into canonical finding identities and throughput.
///
/// Expected input is scanner event output (`--event-format=jsonl`) containing
/// finding, commit_meta, and summary events.
pub fn canonicalize_jsonl_events(bytes: &[u8]) -> Result<CanonicalRun, CanonicalizeError> {
    let mut commit_meta: HashMap<u32, (String, u64)> = HashMap::new();
    let mut pending_findings = Vec::new();
    let mut throughput_mib_s = None;

    for (line_idx, line) in bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let line_no = line_idx + 1;
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|source| CanonicalizeError::Json {
                line: line_no,
                source,
            })?;

        let event_type = required_str(&value, line_no, "type")?;
        match event_type.as_str() {
            "commit_meta" => {
                let commit_id_u64 = required_u64(&value, line_no, "commit_id")?;
                let commit_id = u32::try_from(commit_id_u64).map_err(|_| {
                    CanonicalizeError::InvalidFieldType {
                        line: line_no,
                        field: "commit_id",
                        expected: "u32",
                    }
                })?;
                let oid = required_str(&value, line_no, "oid")?;
                let timestamp = required_u64(&value, line_no, "timestamp")?;
                commit_meta.insert(commit_id, (oid, timestamp));
            }
            "finding" => {
                let path = required_str(&value, line_no, "path")?;
                let rule = required_str(&value, line_no, "rule")?;
                let start = required_u64(&value, line_no, "start")?;
                let end = required_u64(&value, line_no, "end")?;
                let change_kind = optional_string(&value, line_no, "change_kind")?;
                let commit_id = optional_u32(&value, line_no, "commit_id")?;
                pending_findings.push(PendingFinding {
                    path,
                    rule,
                    start,
                    end,
                    change_kind,
                    commit_id,
                });
            }
            "summary" => {
                let Some(raw) = value.get("throughput_mib_s") else {
                    return Err(CanonicalizeError::MissingField {
                        line: line_no,
                        field: "throughput_mib_s",
                    });
                };
                let Some(tp) = raw.as_f64() else {
                    return Err(CanonicalizeError::InvalidFieldType {
                        line: line_no,
                        field: "throughput_mib_s",
                        expected: "f64",
                    });
                };
                throughput_mib_s = Some(tp);
            }
            _ => {}
        }
    }

    let mut findings = Vec::with_capacity(pending_findings.len());
    for finding in pending_findings {
        let (commit_oid, commit_timestamp) = if let Some(commit_id) = finding.commit_id {
            let Some((oid, ts)) = commit_meta.get(&commit_id) else {
                return Err(CanonicalizeError::MissingCommitMeta { commit_id });
            };
            (Some(oid.clone()), Some(*ts))
        } else {
            (None, None)
        };
        findings.push(CanonicalFinding {
            path: finding.path,
            rule: finding.rule,
            start: finding.start,
            end: finding.end,
            change_kind: finding.change_kind,
            commit_oid,
            commit_timestamp,
        });
    }
    findings.sort();

    let Some(throughput_mib_s) = throughput_mib_s else {
        return Err(CanonicalizeError::MissingSummaryThroughput);
    };

    Ok(CanonicalRun {
        findings,
        throughput_mib_s,
    })
}

/// Compute signed throughput delta in percent.
///
/// `((candidate - baseline) / baseline) * 100`
pub fn throughput_delta_pct(baseline: f64, candidate: f64) -> Result<f64, ThroughputError> {
    if !baseline.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "baseline",
            value: baseline,
        });
    }
    if !candidate.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "candidate",
            value: candidate,
        });
    }
    if baseline == 0.0 {
        if candidate == 0.0 {
            return Ok(0.0);
        }
        return Err(ThroughputError::NonPositiveBaseline { baseline });
    }
    if baseline < 0.0 {
        return Err(ThroughputError::NonPositiveBaseline { baseline });
    }
    Ok(((candidate - baseline) / baseline) * 100.0)
}

/// Median of numeric values.
pub fn median(values: &[f64]) -> Result<f64, ThroughputError> {
    if values.is_empty() {
        return Err(ThroughputError::EmptyInput);
    }
    let mut sorted = values.to_vec();
    for v in &sorted {
        if !v.is_finite() {
            return Err(ThroughputError::NonFinite {
                label: "sample",
                value: *v,
            });
        }
    }
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Ok(sorted[mid])
    } else {
        Ok((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// Enforce absolute throughput delta thresholds.
///
/// - `median_limit_abs_pct`: median absolute delta across all cases (<= 2%)
/// - `per_case_limit_abs_pct`: per-case absolute delta bound (<= 5%)
///
/// Returns the computed median absolute delta on success.
pub fn enforce_throughput_thresholds(
    deltas_pct: &[f64],
    median_limit_abs_pct: f64,
    per_case_limit_abs_pct: f64,
) -> Result<f64, ThroughputError> {
    if deltas_pct.is_empty() {
        return Err(ThroughputError::EmptyInput);
    }
    if !median_limit_abs_pct.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "median_limit_abs_pct",
            value: median_limit_abs_pct,
        });
    }
    if median_limit_abs_pct <= 0.0 {
        return Err(ThroughputError::NonPositiveLimit {
            label: "median_limit_abs_pct",
            value: median_limit_abs_pct,
        });
    }
    if !per_case_limit_abs_pct.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "per_case_limit_abs_pct",
            value: per_case_limit_abs_pct,
        });
    }
    if per_case_limit_abs_pct <= 0.0 {
        return Err(ThroughputError::NonPositiveLimit {
            label: "per_case_limit_abs_pct",
            value: per_case_limit_abs_pct,
        });
    }

    let mut abs_deltas = Vec::with_capacity(deltas_pct.len());
    for (idx, delta) in deltas_pct.iter().copied().enumerate() {
        if !delta.is_finite() {
            return Err(ThroughputError::NonFinite {
                label: "delta_pct",
                value: delta,
            });
        }
        let abs = delta.abs();
        if abs > per_case_limit_abs_pct {
            return Err(ThroughputError::ThresholdExceeded {
                scope: "per-case",
                observed_abs_pct: abs,
                limit_abs_pct: per_case_limit_abs_pct,
                index: Some(idx),
            });
        }
        abs_deltas.push(abs);
    }

    let median_abs = median(&abs_deltas)?;
    if median_abs > median_limit_abs_pct {
        return Err(ThroughputError::ThresholdExceeded {
            scope: "median",
            observed_abs_pct: median_abs,
            limit_abs_pct: median_limit_abs_pct,
            index: None,
        });
    }

    Ok(median_abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_joins_commit_meta() {
        let jsonl = br#"{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":7,"change_kind":"add","confidence_score":0}
{"type":"commit_meta","commit_id":7,"oid":"0123","timestamp":100}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes":1,"findings":1,"errors":0,"throughput_mib_s":2.50}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].commit_oid.as_deref(), Some("0123"));
        assert_eq!(run.findings[0].commit_timestamp, Some(100));
        assert_eq!(run.throughput_mib_s, 2.5);
    }

    #[test]
    fn canonicalize_distinguishes_commit_attribution_for_same_span() {
        let jsonl = br#"{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":1,"change_kind":"add","confidence_score":0}
{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":2,"change_kind":"add","confidence_score":0}
{"type":"commit_meta","commit_id":1,"oid":"0001","timestamp":100}
{"type":"commit_meta","commit_id":2,"oid":"0002","timestamp":200}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes":1,"findings":2,"errors":0,"throughput_mib_s":2.50}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 2);
        assert_eq!(run.findings[0].commit_oid.as_deref(), Some("0001"));
        assert_eq!(run.findings[1].commit_oid.as_deref(), Some("0002"));
        assert_eq!(run.findings[0].commit_timestamp, Some(100));
        assert_eq!(run.findings[1].commit_timestamp, Some(200));
    }

    #[test]
    fn canonicalize_keeps_change_kind_in_identity() {
        let jsonl = br#"{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":7,"change_kind":"add","confidence_score":0}
{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":7,"change_kind":"modify","confidence_score":0}
{"type":"commit_meta","commit_id":7,"oid":"0123","timestamp":100}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes":1,"findings":2,"errors":0,"throughput_mib_s":2.50}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 2);
        assert_ne!(
            run.findings[0].change_kind, run.findings[1].change_kind,
            "change_kind must remain part of canonical identity"
        );
    }

    #[test]
    fn canonicalize_requires_commit_meta_for_git_findings() {
        let jsonl = br#"{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":9,"change_kind":"add","confidence_score":0}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes":1,"findings":1,"errors":0,"throughput_mib_s":2.50}
"#;
        let err = canonicalize_jsonl_events(jsonl).expect_err("missing commit_meta must error");
        match err {
            CanonicalizeError::MissingCommitMeta { commit_id } => assert_eq!(commit_id, 9),
            _ => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn median_handles_even_and_odd_lengths() {
        assert_eq!(median(&[1.0, 3.0, 2.0]).unwrap(), 2.0);
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]).unwrap(), 2.5);
    }

    #[test]
    fn threshold_enforcement_checks_per_case_and_median() {
        // Pass: abs deltas 1,2,3 => median 2.
        let passed = enforce_throughput_thresholds(&[1.0, -2.0, 3.0], 2.0, 5.0)
            .expect("thresholds should pass");
        assert_eq!(passed, 2.0);

        // Fail per-case.
        let per_case = enforce_throughput_thresholds(&[6.0], 2.0, 5.0).expect_err("must fail");
        assert!(matches!(
            per_case,
            ThroughputError::ThresholdExceeded {
                scope: "per-case",
                ..
            }
        ));

        // Fail median: abs deltas 2,3,4 => median 3.
        let median_err =
            enforce_throughput_thresholds(&[2.0, 3.0, 4.0], 2.5, 5.0).expect_err("must fail");
        assert!(matches!(
            median_err,
            ThroughputError::ThresholdExceeded {
                scope: "median",
                ..
            }
        ));
    }

    #[test]
    fn throughput_delta_allows_both_zero() {
        let delta = throughput_delta_pct(0.0, 0.0).expect("zero-vs-zero should be stable");
        assert_eq!(delta, 0.0);
    }

    // Verify-first test for claim: malformed summary throughput returns wrong error variant.
    // When summary event is present but throughput_mib_s is a string (not f64),
    // the error should be InvalidFieldType, not MissingField.
    #[test]
    fn canonicalize_returns_invalid_field_type_for_non_f64_throughput() {
        let jsonl = br#"{"type":"summary","source":"fs","status":"complete","elapsed_ms":1,"bytes":1,"findings":0,"errors":0,"throughput_mib_s":"not_a_number"}
"#;
        let err = canonicalize_jsonl_events(jsonl).expect_err("non-f64 throughput must error");
        match &err {
            CanonicalizeError::InvalidFieldType { field, .. } => {
                assert_eq!(*field, "throughput_mib_s");
            }
            other => panic!("expected InvalidFieldType for non-f64 throughput, got: {other}"),
        }
    }

    // Verify-first test for claim: negative threshold limits not rejected.
    // A negative limit should be rejected with a clear error, not silently
    // cause every case to fail.
    #[test]
    fn enforce_thresholds_rejects_negative_limits() {
        let result = enforce_throughput_thresholds(&[0.0], -2.0, 5.0);
        assert!(
            !matches!(result, Err(ThroughputError::ThresholdExceeded { .. })),
            "negative median limit should be rejected as invalid input, \
             not reported as a threshold exceedance"
        );

        let result2 = enforce_throughput_thresholds(&[0.0], 2.0, -5.0);
        assert!(
            !matches!(result2, Err(ThroughputError::ThresholdExceeded { .. })),
            "negative per-case limit should be rejected as invalid input, \
             not reported as a threshold exceedance"
        );
    }
}
