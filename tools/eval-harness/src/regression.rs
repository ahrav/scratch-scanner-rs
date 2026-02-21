//! Regression detection and CI gating.
//!
//! Compares current eval metrics against a stored baseline to produce a
//! [`Verdict`] (Pass / Warn / Block) suitable for CI gate decisions. This
//! module is pure computation — it does not load or persist baselines, nor
//! does it interact with the filesystem or network. Callers are responsible
//! for supplying the current and baseline [`EvalMetrics`] and interpreting
//! the returned [`RegressionResult`] (e.g., mapping [`Verdict::exit_code`]
//! to a process exit).
//!
//! # Algorithm
//!
//! 1. **AP check**: compute `current - baseline`, optionally apply the CI
//!    overlap gate (see below), classify as Pass/Warn/Block based on the
//!    absolute drop against [`RegressionThresholds`].
//! 2. **Precision check**: same threshold logic, no CI gate.
//! 3. **Per-rule diff**: merge the per-rule `BTreeMap`s with a peekable
//!    two-pointer scan to identify new, removed, and changed rules in
//!    O(r_curr + r_base). These deltas are informational — they do not
//!    influence the verdict.
//! 4. **Overall verdict** = `max(ap_verdict, precision_verdict)`. Because
//!    [`Verdict`] derives `Ord` with Pass < Warn < Block, `max` yields the
//!    worst verdict with no branching.
//!
//! # CI overlap gate
//!
//! When `use_ci` is true and the current run carries a bootstrap CI for AP
//! (see [`crate::metrics::EvalMetrics::ap_ci`]), the gate checks whether
//! the baseline AP falls at or below the CI upper bound. If it does, the
//! observed drop is attributable to sampling noise rather than a real
//! regression, and the metric check returns Pass regardless of the raw
//! delta.
//!
//! This is a **one-sided** test: only the upper bound matters because we
//! are asking "could the baseline plausibly come from the same distribution
//! as the current run?" The baseline is treated as a fixed point estimate
//! (no CI of its own), so overlap is checked in one direction only.
//!
//! # Threshold semantics
//!
//! All thresholds are **absolute** deltas in the same scale as the metric
//! (0.0–1.0 for precision and AP). A `block` threshold of 0.02 means a 2
//! percentage-point drop triggers Block. Relative (percentage) thresholds
//! are intentionally not supported: a 2pp drop from 0.98 to 0.96 is
//! operationally different from a 2pp drop from 0.52 to 0.50, but both
//! should block equally because the eval harness treats the absolute
//! quality floor as the gating criterion.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::metrics::{ConfidenceInterval, EvalMetrics, RuleMetrics};

#[cfg(test)]
use crate::metrics::safe_div;

// ── Public types ────────────────────────────────────────────────────────

/// Thresholds for regression gating (absolute deltas, not relative).
///
/// A drop exceeding the `block` threshold produces [`Verdict::Block`]; a drop
/// exceeding `warn` but not `block` produces [`Verdict::Warn`]; otherwise
/// [`Verdict::Pass`].
///
/// Thresholds are compared against the **absolute drop** (`baseline - current`),
/// so a value of 0.02 means "2 percentage points." The `warn` threshold must
/// be less than or equal to `block` for the tiered gating to make sense; if
/// inverted, the Warn band vanishes and every regression jumps straight from
/// Pass to Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionThresholds {
    /// AP drop (absolute) that triggers Block. Default: 0.02 (2 percentage points).
    pub ap_block: f64,
    /// AP drop (absolute) that triggers Warn. Default: 0.005 (0.5 percentage points).
    pub ap_warn: f64,
    /// Precision drop (absolute) that triggers Block. Default: 0.02 (2 percentage points).
    pub precision_block: f64,
    /// Precision drop (absolute) that triggers Warn. Default: 0.005 (0.5 percentage points).
    pub precision_warn: f64,
    /// Whether to apply the CI overlap gate for AP. When true and the current
    /// run has a bootstrap CI, a drop where the baseline falls within the CI
    /// is treated as noise and produces Pass. Default: true.
    pub use_ci: bool,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            ap_block: 0.02,
            ap_warn: 0.005,
            precision_block: 0.02,
            precision_warn: 0.005,
            use_ci: true,
        }
    }
}

/// Regression verdict for a CI gate decision.
///
/// **Variant order is load-bearing**: the derived `Ord` gives
/// Pass < Warn < Block, so `a.max(b)` yields the worst verdict. This
/// enables composing multiple metric checks into a single overall verdict
/// via `max` without any conditional logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// No regression detected.
    Pass,
    /// Minor regression, within tolerance but notable.
    Warn,
    /// Significant regression, should block CI.
    Block,
}

impl Verdict {
    /// Map to a process exit code suitable for CI scripts.
    ///
    /// Pass and Warn both map to 0 (success) because warnings are
    /// informational; only Block produces a non-zero exit (1) that fails
    /// the CI step.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Pass | Self::Warn => 0,
            Self::Block => 1,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        })
    }
}

/// Result of checking a single metric (AP or precision) against thresholds.
///
/// Each [`RegressionResult`] contains one `MetricCheck` per evaluated metric.
/// The `verdict` field reflects only this metric's contribution; the overall
/// verdict in [`RegressionResult`] is the `max` across all checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricCheck {
    /// Metric name (`"average_precision"` or `"precision"`).
    pub metric: String,
    /// Current run's value (0.0–1.0 as produced by [`EvalMetrics`]).
    pub current: f64,
    /// Baseline value (0.0–1.0 as produced by [`EvalMetrics`]).
    pub baseline: f64,
    /// `current - baseline`. Negative means regression (current is worse).
    pub delta: f64,
    /// Verdict for this metric alone.
    pub verdict: Verdict,
    /// Whether the CI overlap gate fired, overriding the raw threshold
    /// comparison and forcing the verdict to Pass. Only possible for AP
    /// when [`RegressionThresholds::use_ci`] is true and a bootstrap CI
    /// is available.
    pub ci_gate_applied: bool,
}

/// Per-rule TP/FP/precision delta between current and baseline runs.
///
/// These deltas are **informational only** — they do not influence the
/// overall [`Verdict`]. They exist so that CI reporters can surface
/// which specific rules improved or regressed, helping developers
/// pinpoint the cause of an aggregate metric shift.
///
/// For [`RuleDeltaStatus::New`] rules, the baseline fields are zero.
/// For [`RuleDeltaStatus::Removed`] rules, the current fields are zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDelta {
    /// Rule name (matches the key in [`EvalMetrics::per_rule`]).
    pub rule: String,
    /// Current TP count (0 for removed rules).
    pub current_tp: u64,
    /// Baseline TP count (0 for new rules).
    pub baseline_tp: u64,
    /// Current FP count (0 for removed rules).
    pub current_fp: u64,
    /// Baseline FP count (0 for new rules).
    pub baseline_fp: u64,
    /// Precision delta (`current_precision - baseline_precision`). Negative
    /// means the rule's precision regressed.
    pub precision_delta: f64,
    /// Whether this rule is new, removed, or present in both runs.
    pub status: RuleDeltaStatus,
}

/// Classification of a rule's lifecycle between two eval runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDeltaStatus {
    /// Rule exists in both runs. Counts may differ or be identical —
    /// "changed" means "present in both," not "values differ."
    Changed,
    /// Rule appears only in the current run (absent from baseline).
    New,
    /// Rule appears only in the baseline (absent from current).
    Removed,
}

/// Complete regression check result, suitable for serialization to JSON
/// and consumption by CI reporters.
///
/// Typical consumer flow:
/// 1. Check [`verdict`](Self::verdict) to decide pass/fail.
/// 2. If Warn or Block, iterate [`checks`](Self::checks) to identify which
///    metric(s) triggered the verdict.
/// 3. Optionally display [`per_rule_deltas`](Self::per_rule_deltas) to help
///    developers pinpoint which rules contributed to the regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionResult {
    /// Overall verdict — the worst (maximum) of all per-metric verdicts.
    pub verdict: Verdict,
    /// Per-metric checks. Always contains exactly two entries:
    /// `[average_precision, precision]`, in that order.
    pub checks: Vec<MetricCheck>,
    /// Per-rule deltas between current and baseline. Informational only;
    /// these do not affect the verdict.
    pub per_rule_deltas: Vec<RuleDelta>,
    /// The thresholds that were applied, echoed back for auditability.
    pub thresholds: RegressionThresholds,
}

// ── Public API ──────────────────────────────────────────────────────────

/// Run regression checks comparing current metrics against a baseline.
///
/// This is the sole entry point for regression detection. It is a pure
/// function: no IO, no side effects, deterministic output for the same
/// inputs.
///
/// The returned [`RegressionResult`] contains:
/// - An overall [`Verdict`] (the worst across all metrics).
/// - Two [`MetricCheck`] entries: one for AP, one for precision.
/// - A Vec of [`RuleDelta`] entries showing per-rule TP/FP/precision
///   changes (informational, does not affect the verdict).
///
/// # Verdict composition
///
/// `verdict = max(ap_check.verdict, precision_check.verdict)`.
/// Because [`Verdict`] orders Pass < Warn < Block, any single Block
/// metric is sufficient to block the overall result.
pub fn check_regression(
    current: &EvalMetrics,
    baseline: &EvalMetrics,
    thresholds: &RegressionThresholds,
) -> RegressionResult {
    let ap_check = check_metric(
        "average_precision",
        current.average_precision,
        baseline.average_precision,
        current.ap_ci.as_ref(),
        thresholds.ap_block,
        thresholds.ap_warn,
        thresholds.use_ci,
    );

    let precision_check = check_metric(
        "precision",
        current.precision,
        baseline.precision,
        None, // No CI gate for precision.
        thresholds.precision_block,
        thresholds.precision_warn,
        false,
    );

    let verdict = ap_check.verdict.max(precision_check.verdict);
    let per_rule_deltas = compute_per_rule_deltas(&current.per_rule, &baseline.per_rule);

    RegressionResult {
        verdict,
        checks: vec![ap_check, precision_check],
        per_rule_deltas,
        thresholds: thresholds.clone(),
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Check a single metric against thresholds, optionally applying the CI gate.
///
/// The CI gate is a **short-circuit**: when `use_ci` is true, a CI is
/// available, and the baseline falls at or below the CI upper bound, the
/// function returns Pass immediately without evaluating threshold logic.
/// The gate only checks the upper bound (one-sided) because we are asking
/// whether the baseline could plausibly be drawn from the same distribution
/// as the current run; a baseline above the CI upper bound is evidence of
/// a real regression.
///
/// When the CI gate does not fire, the raw absolute drop
/// (`baseline - current`) is compared against the warn and block thresholds.
/// Improvements (current > baseline) always produce Pass because the drop
/// is non-positive.
fn check_metric(
    metric_name: &str,
    current_val: f64,
    baseline_val: f64,
    ci: Option<&ConfidenceInterval>,
    block_threshold: f64,
    warn_threshold: f64,
    use_ci: bool,
) -> MetricCheck {
    let delta = current_val - baseline_val;

    // CI overlap gate: if baseline falls within the current CI, the observed
    // drop is noise, not a real regression. Only the upper bound matters —
    // see module-level "CI overlap gate" section for rationale.
    if use_ci
        && let Some(ci) = ci
        && baseline_val <= ci.upper
    {
        return MetricCheck {
            metric: metric_name.to_string(),
            current: current_val,
            baseline: baseline_val,
            delta,
            verdict: Verdict::Pass,
            ci_gate_applied: true,
        };
    }

    // Negate the delta so that a regression (current < baseline) yields a
    // positive `drop`, making the threshold comparison read naturally.
    let drop = -delta;
    let verdict = if drop >= block_threshold {
        Verdict::Block
    } else if drop >= warn_threshold {
        Verdict::Warn
    } else {
        Verdict::Pass
    };

    MetricCheck {
        metric: metric_name.to_string(),
        current: current_val,
        baseline: baseline_val,
        delta,
        verdict,
        ci_gate_applied: false,
    }
}

/// Compute per-rule deltas via a two-pointer merge of sorted `BTreeMap` iterators.
///
/// Because `BTreeMap` iterates in sorted key order, we can merge both maps
/// in a single pass without building a `HashMap`. The algorithm is identical
/// to the merge step of merge-sort: advance the iterator whose current key
/// is smaller, emitting New/Removed/Changed deltas as appropriate.
///
/// # Complexity
///
/// O(r_curr + r_base) time and space. The output Vec is pre-allocated to
/// `max(r_curr, r_base)` as a lower-bound hint, but may grow to
/// `r_curr + r_base` when the maps are disjoint.
///
/// # Output ordering
///
/// The returned Vec is sorted by rule name (lexicographic), inheriting the
/// BTreeMap iteration order.
fn compute_per_rule_deltas(
    current: &BTreeMap<String, RuleMetrics>,
    baseline: &BTreeMap<String, RuleMetrics>,
) -> Vec<RuleDelta> {
    let mut result = Vec::with_capacity(current.len().max(baseline.len()));

    let mut curr_iter = current.iter().peekable();
    let mut base_iter = baseline.iter().peekable();

    loop {
        match (curr_iter.peek(), base_iter.peek()) {
            (Some(&(ck, _)), Some(&(bk, _))) => match ck.cmp(bk) {
                std::cmp::Ordering::Equal => {
                    let (rule, cm) = curr_iter.next().unwrap();
                    let (_, bm) = base_iter.next().unwrap();
                    result.push(RuleDelta {
                        rule: rule.clone(),
                        current_tp: cm.tp,
                        baseline_tp: bm.tp,
                        current_fp: cm.fp,
                        baseline_fp: bm.fp,
                        precision_delta: cm.precision - bm.precision,
                        status: RuleDeltaStatus::Changed,
                    });
                }
                std::cmp::Ordering::Less => {
                    let (rule, cm) = curr_iter.next().unwrap();
                    result.push(RuleDelta {
                        rule: rule.clone(),
                        current_tp: cm.tp,
                        baseline_tp: 0,
                        current_fp: cm.fp,
                        baseline_fp: 0,
                        precision_delta: cm.precision,
                        status: RuleDeltaStatus::New,
                    });
                }
                std::cmp::Ordering::Greater => {
                    let (rule, bm) = base_iter.next().unwrap();
                    result.push(RuleDelta {
                        rule: rule.clone(),
                        current_tp: 0,
                        baseline_tp: bm.tp,
                        current_fp: 0,
                        baseline_fp: bm.fp,
                        precision_delta: -bm.precision,
                        status: RuleDeltaStatus::Removed,
                    });
                }
            },
            (Some(_), None) => {
                let (rule, cm) = curr_iter.next().unwrap();
                result.push(RuleDelta {
                    rule: rule.clone(),
                    current_tp: cm.tp,
                    baseline_tp: 0,
                    current_fp: cm.fp,
                    baseline_fp: 0,
                    precision_delta: cm.precision,
                    status: RuleDeltaStatus::New,
                });
            }
            (None, Some(_)) => {
                let (rule, bm) = base_iter.next().unwrap();
                result.push(RuleDelta {
                    rule: rule.clone(),
                    current_tp: 0,
                    baseline_tp: bm.tp,
                    current_fp: 0,
                    baseline_fp: bm.fp,
                    precision_delta: -bm.precision,
                    status: RuleDeltaStatus::Removed,
                });
            }
            (None, None) => break,
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    /// Build minimal EvalMetrics with the given AP and precision.
    fn metrics(ap: f64, precision: f64) -> EvalMetrics {
        EvalMetrics {
            average_precision: ap,
            precision,
            recall: 0.0,
            f1: 0.0,
            f2: 0.0,
            tp: 0,
            fp: 0,
            false_neg: 0,
            unlabeled: 0,
            baseline_ap: 0.0,
            precision_at_recall: vec![],
            recall_at_precision: vec![],
            ap_ci: None,
            per_rule: BTreeMap::new(),
        }
    }

    fn metrics_with_ci(ap: f64, precision: f64, ci_lower: f64, ci_upper: f64) -> EvalMetrics {
        let mut m = metrics(ap, precision);
        m.ap_ci = Some(ConfidenceInterval {
            lower: ci_lower,
            upper: ci_upper,
        });
        m
    }

    fn metrics_with_rules(ap: f64, precision: f64, rules: &[(&str, u64, u64)]) -> EvalMetrics {
        let mut m = metrics(ap, precision);
        for &(name, tp, fp) in rules {
            m.per_rule.insert(
                name.to_string(),
                RuleMetrics {
                    tp,
                    fp,
                    precision: safe_div(tp as f64, (tp + fp) as f64),
                },
            );
        }
        m
    }

    // ── Verdict properties ─────────────────────────────────────────────

    #[test]
    fn verdict_properties() {
        // Ordering: Pass < Warn < Block, max yields worst.
        assert!(Verdict::Pass < Verdict::Warn);
        assert!(Verdict::Warn < Verdict::Block);
        assert_eq!(Verdict::Pass.max(Verdict::Block), Verdict::Block);

        // Exit codes: only Block is non-zero.
        for (v, code) in [(Verdict::Pass, 0), (Verdict::Warn, 0), (Verdict::Block, 1)] {
            assert_eq!(v.exit_code(), code, "{v:?}.exit_code()");
        }

        // Display strings.
        for (v, label) in [
            (Verdict::Pass, "PASS"),
            (Verdict::Warn, "WARN"),
            (Verdict::Block, "BLOCK"),
        ] {
            assert_eq!(v.to_string(), label, "{v:?}.to_string()");
        }
    }

    // ── Metric threshold verdicts ───────────────────────────────────

    #[test]
    fn metric_threshold_verdicts() {
        // (curr_ap, curr_prec, base_ap, base_prec, check_idx, expected_verdict)
        let cases = [
            (0.92, 0.88, 0.92, 0.88, 0, Verdict::Pass),  // identical
            (0.90, 0.88, 0.93, 0.88, 0, Verdict::Block), // AP 3pp drop
            (0.91, 0.88, 0.92, 0.88, 0, Verdict::Warn),  // AP 1pp drop
            (0.917, 0.88, 0.92, 0.88, 0, Verdict::Pass), // AP 0.3pp drop
            (0.92, 0.85, 0.92, 0.88, 1, Verdict::Block), // Prec 3pp drop
            (0.92, 0.87, 0.92, 0.88, 1, Verdict::Warn),  // Prec 1pp drop
        ];
        for (curr_ap, curr_prec, base_ap, base_prec, idx, expected) in cases {
            let result = check_regression(
                &metrics(curr_ap, curr_prec),
                &metrics(base_ap, base_prec),
                &RegressionThresholds::default(),
            );
            assert_eq!(
                result.checks[idx].verdict, expected,
                "curr=({curr_ap},{curr_prec}) base=({base_ap},{base_prec}) check[{idx}]"
            );
        }
    }

    // ── CI gate ──────────────────────────────────────────────────────

    #[test]
    fn ci_gate_behavior() {
        // (curr_ap, ci_lower, ci_upper, base_ap, expected_verdict, ci_applied)
        let cases = [
            // CI includes baseline → noise, not regression.
            (0.91, 0.89, 0.93, 0.92, Verdict::Pass, true),
            // CI upper below baseline → real regression.
            (0.89, 0.87, 0.91, 0.92, Verdict::Block, false),
        ];
        for (curr_ap, ci_lo, ci_hi, base_ap, expected, ci_applied) in cases {
            let current = metrics_with_ci(curr_ap, 0.88, ci_lo, ci_hi);
            let baseline = metrics(base_ap, 0.88);
            let result = check_regression(&current, &baseline, &RegressionThresholds::default());
            assert_eq!(
                result.checks[0].verdict, expected,
                "ap={curr_ap} ci=[{ci_lo},{ci_hi}] base={base_ap}"
            );
            assert_eq!(
                result.checks[0].ci_gate_applied, ci_applied,
                "ci_gate_applied mismatch for ap={curr_ap}"
            );
        }
    }

    // ── Per-rule deltas ──────────────────────────────────────────────

    #[test]
    fn per_rule_delta_statuses() {
        fn assert_rule_status(
            curr_rules: &[(&str, u64, u64)],
            base_rules: &[(&str, u64, u64)],
            target: &str,
            expected: RuleDeltaStatus,
        ) {
            let result = check_regression(
                &metrics_with_rules(0.92, 0.88, curr_rules),
                &metrics_with_rules(0.92, 0.88, base_rules),
                &RegressionThresholds::default(),
            );
            let delta = result
                .per_rule_deltas
                .iter()
                .find(|d| d.rule == target)
                .unwrap_or_else(|| panic!("missing delta for {target}"));
            assert_eq!(delta.status, expected, "status for {target}");
        }

        // Rule only in baseline → Removed.
        assert_rule_status(
            &[("rule_a", 10, 2)],
            &[("rule_a", 10, 2), ("rule_b", 5, 1)],
            "rule_b",
            RuleDeltaStatus::Removed,
        );
        // Rule only in current → New.
        assert_rule_status(
            &[("rule_a", 10, 2), ("rule_c", 3, 0)],
            &[("rule_a", 10, 2)],
            "rule_c",
            RuleDeltaStatus::New,
        );
        // Rule in both → Changed.
        assert_rule_status(
            &[("rule_a", 12, 3)],
            &[("rule_a", 10, 2)],
            "rule_a",
            RuleDeltaStatus::Changed,
        );
    }

    #[test]
    fn empty_per_rule_maps() {
        // Both maps empty → no deltas emitted.
        let result = check_regression(
            &metrics(0.92, 0.88),
            &metrics(0.92, 0.88),
            &RegressionThresholds::default(),
        );
        assert!(result.per_rule_deltas.is_empty());

        // One empty, other non-empty → all entries are New or Removed.
        let result = check_regression(
            &metrics_with_rules(0.92, 0.88, &[("rule_a", 5, 1)]),
            &metrics(0.92, 0.88),
            &RegressionThresholds::default(),
        );
        assert_eq!(result.per_rule_deltas.len(), 1);
        assert_eq!(result.per_rule_deltas[0].status, RuleDeltaStatus::New);

        let result = check_regression(
            &metrics(0.92, 0.88),
            &metrics_with_rules(0.92, 0.88, &[("rule_b", 3, 0)]),
            &RegressionThresholds::default(),
        );
        assert_eq!(result.per_rule_deltas.len(), 1);
        assert_eq!(result.per_rule_deltas[0].status, RuleDeltaStatus::Removed);
    }

    #[test]
    fn inverted_thresholds_skip_warn_band() {
        // When warn > block, the Warn band vanishes: regressions jump
        // straight from Pass to Block because the block check fires first.
        let thresh = RegressionThresholds {
            ap_block: 0.005, // lower than warn
            ap_warn: 0.02,   // higher than block
            precision_block: 0.02,
            precision_warn: 0.005,
            use_ci: false,
        };
        // 1pp drop: exceeds block (0.005) → Block, not Warn.
        let result = check_regression(&metrics(0.91, 0.88), &metrics(0.92, 0.88), &thresh);
        assert_eq!(result.checks[0].verdict, Verdict::Block);

        // 0.3pp drop (0.003): below block (0.005) → Pass. The Warn band
        // (0.005–0.02) is unreachable because block fires first.
        let result = check_regression(&metrics(0.917, 0.88), &metrics(0.92, 0.88), &thresh);
        assert_eq!(result.checks[0].verdict, Verdict::Pass);
    }

    #[test]
    fn worst_verdict_wins() {
        // AP blocks, precision passes → overall Block.
        let current = metrics(0.88, 0.88);
        let baseline = metrics(0.92, 0.88);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.checks[0].verdict, Verdict::Block);
        assert_eq!(result.checks[1].verdict, Verdict::Pass);
    }

    // ── Proptest ─────────────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Larger drops never produce weaker verdicts.
            #[test]
            fn verdict_monotonicity(
                baseline_ap in 0.5f64..1.0,
                drop_small in 0.0f64..0.05,
                drop_extra in 0.001f64..0.05,
            ) {
                let small_current = metrics(baseline_ap - drop_small, 0.88);
                let large_current = metrics(baseline_ap - drop_small - drop_extra, 0.88);
                let baseline = metrics(baseline_ap, 0.88);
                let thresh = RegressionThresholds { use_ci: false, ..Default::default() };

                let r_small = check_regression(&small_current, &baseline, &thresh);
                let r_large = check_regression(&large_current, &baseline, &thresh);
                prop_assert!(
                    r_large.verdict >= r_small.verdict,
                    "larger drop ({}) has weaker verdict ({:?}) than smaller drop ({}) verdict ({:?})",
                    drop_small + drop_extra, r_large.verdict, drop_small, r_small.verdict,
                );
            }

            /// Same inputs always produce the same result.
            #[test]
            fn determinism(
                ap in 0.0f64..1.0,
                prec in 0.0f64..1.0,
                base_ap in 0.0f64..1.0,
                base_prec in 0.0f64..1.0,
            ) {
                let current = metrics(ap, prec);
                let baseline = metrics(base_ap, base_prec);
                let thresh = RegressionThresholds::default();
                let r1 = check_regression(&current, &baseline, &thresh);
                let r2 = check_regression(&current, &baseline, &thresh);
                prop_assert_eq!(r1.verdict, r2.verdict);
                prop_assert_eq!(r1.checks.len(), r2.checks.len());
                for (a, b) in r1.checks.iter().zip(r2.checks.iter()) {
                    prop_assert_eq!(a.verdict, b.verdict);
                    prop_assert!((a.delta - b.delta).abs() < EPS);
                }
            }

            /// NaN guard: safe_div guarantees no NaN in metrics, so AP and
            /// precision are always finite. This test verifies the assumption
            /// holds under arbitrary inputs.
            #[test]
            fn no_nan_in_result(
                ap in 0.0f64..1.0,
                prec in 0.0f64..1.0,
            ) {
                let current = metrics(ap, prec);
                let baseline = metrics(0.9, 0.9);
                let result = check_regression(&current, &baseline, &RegressionThresholds::default());
                for check in &result.checks {
                    prop_assert!(check.delta.is_finite(), "delta is not finite: {}", check.delta);
                    prop_assert!(check.current.is_finite());
                    prop_assert!(check.baseline.is_finite());
                }
            }
        }
    }
}
