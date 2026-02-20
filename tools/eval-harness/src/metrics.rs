//! Precision, recall, F1, and PRC-AUC (Average Precision) computation.
//!
//! Operates on a classified finding list produced by the matching layer:
//! each entry pairs a [`NormalizedFinding`] with its [`MatchClass`]. Only
//! [`MatchClass::TruePositive`], [`MatchClass::FalsePositive`], and
//! [`MatchClass::Unlabeled`] appear in this list; [`MatchClass::FalseNegative`]
//! items are unmatched truth annotations counted separately via the `fn_count`
//! parameter.
//!
//! ## Average Precision algorithm
//!
//! Uses the step-function (rectangular) formula with **tie collapsing**:
//!
//! 1. Filter to TP and FP only (skip Unlabeled).
//! 2. Sort by confidence descending (stable sort preserves input order within
//!    ties, though ordering within ties is irrelevant after collapsing).
//! 3. Collapse consecutive items sharing the same confidence into a single
//!    precision/recall operating point, accumulating TP and FP counts per
//!    group.
//! 4. `AP = sum of (recall_i - recall_{i-1}) * precision_i` over collapsed
//!    points.
//!
//! This matches sklearn's `average_precision_score` (post-v0.19) and avoids
//! the optimistic bias of breaking ties TP-before-FP, which produces
//! degenerate AP=1.0 for constant predictors.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::types::{MatchClass, NormalizedFinding};

// ── Public types ────────────────────────────────────────────────────────

/// Aggregate evaluation metrics for a classified finding set.
///
/// Combines threshold-free counts (precision, recall, F1) with a
/// confidence-aware ranking metric (Average Precision / PRC-AUC). The two
/// views are complementary: threshold-free metrics treat every finding
/// equally regardless of confidence, while AP rewards classifiers that
/// assign higher confidence to true positives.
///
/// # Field relationships
///
/// - `tp + fp + unlabeled` equals the length of the input `classified` slice
///   (excluding any `FalseNegative` entries, which must not appear).
/// - `total_positives = tp + false_neg` (invariant maintained by the caller).
/// - `baseline_ap` is the AP a random confidence ranker would achieve over the
///   scored population (TP + FP). When `precision_recall_auc` is close to
///   `baseline_ap`, the classifier's confidence ranking adds little value
///   beyond its raw detection rate. Can exceed `precision_recall_auc` when
///   recall is low.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalMetrics {
    /// Average Precision (step-function PRC-AUC with tie collapsing).
    pub precision_recall_auc: f64,
    /// Threshold-free precision: TP / (TP + FP). Equals 0.0 when
    /// there are no positive predictions (TP + FP = 0).
    pub precision: f64,
    /// Threshold-free recall: TP / total_positives. Equals 0.0 when
    /// there are no ground-truth positives.
    pub recall: f64,
    /// Harmonic mean of precision and recall. Always less than or equal
    /// to the arithmetic mean of the two (AM-HM inequality).
    pub f1: f64,
    /// True positive count from classified findings.
    pub tp: u64,
    /// False positive count from classified findings.
    pub fp: u64,
    /// False negative count (unmatched truth positives, passed externally).
    pub false_neg: u64,
    /// Findings with no ground-truth annotation (excluded from all metrics).
    pub unlabeled: u64,
    /// Reference AP for a random confidence ranker over the scored population:
    /// `tp / (tp + FP)`. Useful for gauging whether confidence ranking adds
    /// value beyond the raw detection rate. Uses scored positives (TP) rather
    /// than `total_positives` so the baseline stays achievable when recall is
    /// incomplete. Can exceed `precision_recall_auc` when recall is low.
    pub baseline_ap: f64,
    /// Per-rule breakdown keyed by rule name, sorted lexicographically.
    pub per_rule: BTreeMap<String, RuleMetrics>,
}

/// Per-rule precision breakdown.
///
/// Contains TP/FP counts and precision for a single detection rule.
/// Recall and F1 are omitted because per-rule false-negative counts
/// are not available from the classified finding list alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetrics {
    pub tp: u64,
    pub fp: u64,
    /// TP / (TP + FP).
    pub precision: f64,
}

// ── Public API ──────────────────────────────────────────────────────────

/// Compute all evaluation metrics from a classified finding list.
///
/// # Parameters
///
/// - `classified`: pairs of (finding, classification). Only `TruePositive`,
///   `FalsePositive`, and `Unlabeled` should appear. Panics if any
///   `FalseNegative` is present.
/// - `fn_count`: number of ground-truth positives not matched by any finding.
/// - `total_positives`: total ground-truth positive count (TP + FN).
pub fn compute_metrics(
    classified: &[(NormalizedFinding, MatchClass)],
    fn_count: u64,
    total_positives: u64,
) -> EvalMetrics {
    assert!(
        !classified
            .iter()
            .any(|(_, c)| *c == MatchClass::FalseNegative),
        "FalseNegative must not appear in classified list; pass FN count via fn_count",
    );

    let mut tp: u64 = 0;
    let mut fp: u64 = 0;
    let mut unlabeled: u64 = 0;

    for (_, class) in classified {
        match class {
            MatchClass::TruePositive => tp += 1,
            MatchClass::FalsePositive => fp += 1,
            MatchClass::Unlabeled => unlabeled += 1,
            MatchClass::FalseNegative => unreachable!(
                "FalseNegative must not appear in classified list; \
                 pass FN count via fn_count"
            ),
        }
    }

    assert_eq!(
        tp + fn_count,
        total_positives,
        "invariant violation: tp({tp}) + fn_count({fn_count}) != total_positives({total_positives})"
    );

    let precision = safe_div(tp as f64, (tp + fp) as f64);
    let recall = safe_div(tp as f64, total_positives as f64);
    let f1 = safe_div(2.0 * precision * recall, precision + recall);

    let precision_recall_auc = compute_average_precision(classified, total_positives);
    let baseline_ap = safe_div(tp as f64, (tp + fp) as f64);
    let per_rule = compute_per_rule(classified);

    EvalMetrics {
        precision_recall_auc,
        precision,
        recall,
        f1,
        tp,
        fp,
        false_neg: fn_count,
        unlabeled,
        baseline_ap,
        per_rule,
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Step-function Average Precision with tie collapsing.
///
/// Returns 0.0 when `total_positives` is zero or the classified list
/// contains no TP/FP items. Result is clamped to `max(0.0, ap)` to guard
/// against floating-point drift.
fn compute_average_precision(
    classified: &[(NormalizedFinding, MatchClass)],
    total_positives: u64,
) -> f64 {
    if total_positives == 0 {
        return 0.0;
    }

    // Extract (confidence, is_tp) for TP and FP only.
    let mut scored: Vec<(i8, bool)> = classified
        .iter()
        .filter_map(|(f, c)| match c {
            MatchClass::TruePositive => Some((f.confidence, true)),
            MatchClass::FalsePositive => Some((f.confidence, false)),
            MatchClass::Unlabeled | MatchClass::FalseNegative => None,
        })
        .collect();

    if scored.is_empty() {
        return 0.0;
    }

    // Sort by confidence descending (stable sort).
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    // Walk the sorted list, collapsing tied confidence groups into single
    // operating points.
    let total_pos_f64 = total_positives as f64;
    let mut cum_tp: u64 = 0;
    let mut cum_fp: u64 = 0;
    let mut prev_recall: f64 = 0.0;
    let mut ap: f64 = 0.0;

    let mut i = 0;
    while i < scored.len() {
        let current_conf = scored[i].0;
        let mut group_tp: u64 = 0;
        let mut group_fp: u64 = 0;

        // Consume all items sharing this confidence value.
        let mut j = i;
        while j < scored.len() && scored[j].0 == current_conf {
            if scored[j].1 {
                group_tp += 1;
            } else {
                group_fp += 1;
            }
            j += 1;
        }

        cum_tp += group_tp;
        cum_fp += group_fp;

        let precision = safe_div(cum_tp as f64, (cum_tp + cum_fp) as f64);
        let recall = safe_div(cum_tp as f64, total_pos_f64);

        ap += (recall - prev_recall) * precision;
        prev_recall = recall;

        i = j;
    }

    f64::max(0.0, ap)
}

/// Per-rule precision breakdown from classified findings.
///
/// Groups TP and FP findings by rule name, computes precision per rule.
/// Unlabeled and FalseNegative items are skipped.
fn compute_per_rule(
    classified: &[(NormalizedFinding, MatchClass)],
) -> BTreeMap<String, RuleMetrics> {
    let mut counts: HashMap<&str, (u64, u64)> = HashMap::new();

    for (finding, class) in classified {
        match class {
            MatchClass::TruePositive => {
                counts.entry(finding.rule.as_str()).or_default().0 += 1;
            }
            MatchClass::FalsePositive => {
                counts.entry(finding.rule.as_str()).or_default().1 += 1;
            }
            MatchClass::Unlabeled | MatchClass::FalseNegative => {}
        }
    }

    counts
        .into_iter()
        .map(|(rule, (tp, fp))| {
            let precision = safe_div(tp as f64, (tp + fp) as f64);
            (rule.to_string(), RuleMetrics { tp, fp, precision })
        })
        .collect()
}

/// Division that returns 0.0 when the denominator is zero.
///
/// Prevents NaN/Inf from propagating through metric computations when
/// there are no positive predictions (precision denominator = 0) or no
/// ground-truth positives (recall denominator = 0).
fn safe_div(num: f64, den: f64) -> f64 {
    if den == 0.0 { 0.0 } else { num / den }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NormalizedFinding;

    /// Tolerance for floating-point comparison.
    const EPS: f64 = 1e-9;

    /// Build a classified finding with minimal boilerplate.
    fn item(confidence: i8, class: MatchClass) -> (NormalizedFinding, MatchClass) {
        (
            NormalizedFinding::new("test.txt".into(), 0, 1, "test_rule".into(), confidence),
            class,
        )
    }

    /// Build a classified finding for a specific rule.
    fn item_rule(confidence: i8, class: MatchClass, rule: &str) -> (NormalizedFinding, MatchClass) {
        (
            NormalizedFinding::new("test.txt".into(), 0, 1, rule.into(), confidence),
            class,
        )
    }

    // ── AP oracle tests ─────────────────────────────────────────

    #[test]
    fn ap_single_tp() {
        // [TP(5)] total_pos=1 => AP=1.0
        let classified = vec![item(5, MatchClass::TruePositive)];
        let ap = compute_average_precision(&classified, 1);
        assert!((ap - 1.0).abs() < EPS, "expected 1.0, got {ap}");
    }

    #[test]
    fn ap_alternating_tp_fp() {
        // [TP(5),FP(4),TP(3),FP(2),TP(1)] total_pos=3 => AP=34/45
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::FalsePositive),
            item(3, MatchClass::TruePositive),
            item(2, MatchClass::FalsePositive),
            item(1, MatchClass::TruePositive),
        ];
        let ap = compute_average_precision(&classified, 3);
        let expected = 34.0 / 45.0;
        assert!((ap - expected).abs() < EPS, "expected {expected}, got {ap}");
    }

    #[test]
    fn ap_tp_heavy_front() {
        // [TP(5),TP(4),FP(3),TP(2),FP(1)] total_pos=3 => AP=11/12
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::TruePositive),
            item(3, MatchClass::FalsePositive),
            item(2, MatchClass::TruePositive),
            item(1, MatchClass::FalsePositive),
        ];
        let ap = compute_average_precision(&classified, 3);
        let expected = 11.0 / 12.0;
        assert!((ap - expected).abs() < EPS, "expected {expected}, got {ap}");
    }

    #[test]
    fn ap_all_fp_with_positives() {
        // [FP(5),FP(4),FP(3)] total_pos=3 => AP=0.0
        let classified = vec![
            item(5, MatchClass::FalsePositive),
            item(4, MatchClass::FalsePositive),
            item(3, MatchClass::FalsePositive),
        ];
        let ap = compute_average_precision(&classified, 3);
        assert!(ap.abs() < EPS, "expected 0.0, got {ap}");
    }

    #[test]
    fn ap_fp_heavy_front() {
        // [FP(5),TP(4),FP(3),TP(2),TP(1)] total_pos=3 => AP=8/15
        let classified = vec![
            item(5, MatchClass::FalsePositive),
            item(4, MatchClass::TruePositive),
            item(3, MatchClass::FalsePositive),
            item(2, MatchClass::TruePositive),
            item(1, MatchClass::TruePositive),
        ];
        let ap = compute_average_precision(&classified, 3);
        let expected = 8.0 / 15.0;
        assert!((ap - expected).abs() < EPS, "expected {expected}, got {ap}");
    }

    #[test]
    fn ap_tied_scores_collapse() {
        // [TP(5),FP(5),TP(5)] total_pos=2 => AP=2/3 (collapse)
        // Single group: cum_tp=2, cum_fp=1, P=2/3, R=1.0
        // AP = (1.0 - 0.0) * 2/3 = 2/3
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(5, MatchClass::FalsePositive),
            item(5, MatchClass::TruePositive),
        ];
        let ap = compute_average_precision(&classified, 2);
        let expected = 2.0 / 3.0;
        assert!((ap - expected).abs() < EPS, "expected {expected}, got {ap}");
    }

    #[test]
    fn ap_constant_predictor() {
        // [TP(5),FP(5),FP(5),FP(5)] total_pos=1 => AP=0.25
        // Single group: cum_tp=1, cum_fp=3, P=1/4=0.25, R=1.0
        // AP = (1.0 - 0.0) * 0.25 = 0.25
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(5, MatchClass::FalsePositive),
            item(5, MatchClass::FalsePositive),
            item(5, MatchClass::FalsePositive),
        ];
        let ap = compute_average_precision(&classified, 1);
        assert!((ap - 0.25).abs() < EPS, "expected 0.25, got {ap}");
    }

    #[test]
    fn ap_with_false_negatives() {
        // [TP(5), TP(4)] total_pos=4 (2 FN not in list)
        // conf=5: cum_tp=1, cum_fp=0, P=1.0, R=1/4. AP += 1/4
        // conf=4: cum_tp=2, cum_fp=0, P=1.0, R=2/4. AP += 1/4
        // AP = 0.5 (recall capped at 0.5 because 2 of 4 positives are missed)
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::TruePositive),
        ];
        let ap = compute_average_precision(&classified, 4);
        assert!((ap - 0.5).abs() < EPS, "expected 0.5, got {ap}");
    }

    #[test]
    fn ap_empty() {
        let ap = compute_average_precision(&[], 0);
        assert!(ap.abs() < EPS, "expected 0.0, got {ap}");
    }

    // ── compute_metrics integration tests ───────────────────────

    #[test]
    fn metrics_perfect_classifier() {
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::TruePositive),
            item(3, MatchClass::TruePositive),
        ];
        let m = compute_metrics(&classified, 0, 3);
        assert!((m.precision_recall_auc - 1.0).abs() < EPS);
        assert!((m.precision - 1.0).abs() < EPS);
        assert!((m.recall - 1.0).abs() < EPS);
        assert!((m.f1 - 1.0).abs() < EPS);
        assert_eq!(m.tp, 3);
        assert_eq!(m.fp, 0);
        assert_eq!(m.false_neg, 0);
        assert_eq!(m.unlabeled, 0);
    }

    #[test]
    fn metrics_all_fp() {
        let classified = vec![
            item(5, MatchClass::FalsePositive),
            item(4, MatchClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 3, 3);
        assert!(m.precision_recall_auc.abs() < EPS);
        assert!(m.precision.abs() < EPS);
        assert!(m.recall.abs() < EPS);
        assert!(m.f1.abs() < EPS);
        assert_eq!(m.tp, 0);
        assert_eq!(m.fp, 2);
        assert_eq!(m.false_neg, 3);
    }

    #[test]
    fn metrics_empty_input() {
        let m = compute_metrics(&[], 0, 0);
        assert!(m.precision_recall_auc.abs() < EPS);
        assert!(m.precision.abs() < EPS);
        assert!(m.recall.abs() < EPS);
        assert!(m.f1.abs() < EPS);
        assert_eq!(m.tp, 0);
        assert_eq!(m.fp, 0);
        assert_eq!(m.false_neg, 0);
        assert_eq!(m.unlabeled, 0);
    }

    #[test]
    fn metrics_unlabeled_excluded() {
        // Unlabeled findings should not affect P/R/F1/AP.
        let classified = vec![
            item(10, MatchClass::TruePositive),
            item(8, MatchClass::Unlabeled),
            item(6, MatchClass::Unlabeled),
            item(4, MatchClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 0, 1);
        assert!((m.precision - 0.5).abs() < EPS); // 1/(1+1)
        assert!((m.recall - 1.0).abs() < EPS); // 1/1
        assert_eq!(m.unlabeled, 2);
        assert_eq!(m.tp, 1);
        assert_eq!(m.fp, 1);
    }

    #[test]
    fn per_rule_grouping() {
        let classified = vec![
            item_rule(5, MatchClass::TruePositive, "rule_a"),
            item_rule(4, MatchClass::FalsePositive, "rule_a"),
            item_rule(3, MatchClass::TruePositive, "rule_b"),
            item_rule(2, MatchClass::TruePositive, "rule_b"),
            item_rule(1, MatchClass::Unlabeled, "rule_c"),
        ];
        let per = compute_per_rule(&classified);
        assert_eq!(per.len(), 2); // rule_c excluded (only Unlabeled)
        let a = &per["rule_a"];
        assert_eq!(a.tp, 1);
        assert_eq!(a.fp, 1);
        assert!((a.precision - 0.5).abs() < EPS);
        let b = &per["rule_b"];
        assert_eq!(b.tp, 2);
        assert_eq!(b.fp, 0);
        assert!((b.precision - 1.0).abs() < EPS);
    }

    #[test]
    fn baseline_ap_value() {
        // baseline_ap = tp / (tp + fp), derived from the scored population.
        let classified = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::FalsePositive),
            item(3, MatchClass::FalsePositive),
            item(2, MatchClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 2, 3);
        // tp=1, fp=3 → baseline = 1 / (1 + 3) = 0.25
        assert!((m.baseline_ap - 0.25).abs() < EPS);
    }

    #[test]
    fn baseline_ap_derived_from_scored_positives() {
        // baseline_ap uses scored positives (tp), not total_positives.
        // With 1 TP, 99 FN, 0 FP: old formula gave 100/(100+0) = 1.0,
        // new formula gives tp/(tp+fp) = 1/(1+0) = 1.0.
        // The formulas only diverge when there are both FNs and FPs.
        let classified = vec![item(5, MatchClass::TruePositive)];
        let m = compute_metrics(&classified, 99, 100);
        // tp=1, fp=0 → baseline = 1.0 (entire scored list is positive)
        assert!((m.baseline_ap - 1.0).abs() < EPS);

        // Divergent case: 1 TP, 2 FN, 3 FP.
        // Old formula: total_positives/(total_positives+fp) = 3/(3+3) = 0.5
        // New formula: tp/(tp+fp) = 1/(1+3) = 0.25
        // The old baseline was inflated by counting FNs not in the ranked list.
        let classified2 = vec![
            item(5, MatchClass::TruePositive),
            item(4, MatchClass::FalsePositive),
            item(3, MatchClass::FalsePositive),
            item(2, MatchClass::FalsePositive),
        ];
        let m2 = compute_metrics(&classified2, 2, 3);
        assert!(
            (m2.baseline_ap - 0.25).abs() < EPS,
            "expected baseline 0.25 (tp/(tp+fp)), got {}",
            m2.baseline_ap
        );
    }

    // ── Proptest properties ─────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        /// Generate a random classified list of TP/FP items.
        fn arb_classified_tp_fp(
            max_len: usize,
        ) -> impl Strategy<Value = Vec<(NormalizedFinding, MatchClass)>> {
            proptest::collection::vec((any::<i8>(), any::<bool>()), 0..=max_len).prop_map(|items| {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, (conf, is_tp))| {
                        let class = if is_tp {
                            MatchClass::TruePositive
                        } else {
                            MatchClass::FalsePositive
                        };
                        (
                            NormalizedFinding::new(
                                "f.txt".into(),
                                i as u64 * 10,
                                i as u64 * 10 + 5,
                                "r".into(),
                                conf,
                            ),
                            class,
                        )
                    })
                    .collect()
            })
        }

        /// Generate a classified list that includes Unlabeled items.
        fn arb_classified_with_unlabeled(
            max_len: usize,
        ) -> impl Strategy<Value = Vec<(NormalizedFinding, MatchClass)>> {
            proptest::collection::vec((any::<i8>(), 0u8..3), 0..=max_len).prop_map(|items| {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, (conf, class_idx))| {
                        let class = match class_idx {
                            0 => MatchClass::TruePositive,
                            1 => MatchClass::FalsePositive,
                            _ => MatchClass::Unlabeled,
                        };
                        (
                            NormalizedFinding::new(
                                "f.txt".into(),
                                i as u64 * 10,
                                i as u64 * 10 + 5,
                                "r".into(),
                                conf,
                            ),
                            class,
                        )
                    })
                    .collect()
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// AP is always in [0.0, 1.0].
            #[test]
            fn ap_bounded(classified in arb_classified_tp_fp(50)) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count.max(1);
                let ap = compute_average_precision(&classified, total_pos);
                prop_assert!((0.0..=1.0).contains(&ap), "AP out of bounds: {ap}");
            }

            /// AP is never NaN or Infinity.
            #[test]
            fn ap_always_finite(
                classified in arb_classified_tp_fp(50),
                total_pos in 0u64..100,
            ) {
                let ap = compute_average_precision(&classified, total_pos);
                prop_assert!(ap.is_finite(), "AP is not finite: {ap}");
            }

            /// All TPs ranked above all FPs => AP = 1.0.
            #[test]
            fn perfect_ranking_ap_one(n in 1u64..20) {
                let mut classified: Vec<_> = (0..n).map(|i| {
                    let conf = (n as i8 + 10).saturating_sub(i as i8);
                    item(conf, MatchClass::TruePositive)
                }).collect();
                for i in 0..n {
                    classified.push(item(-(i as i8) - 1, MatchClass::FalsePositive));
                }
                let ap = compute_average_precision(&classified, n);
                prop_assert!(
                    (ap - 1.0).abs() < 1e-9,
                    "perfect ranking AP should be 1.0, got {ap}"
                );
            }

            /// F1 is always in [0.0, 1.0].
            #[test]
            fn f1_bounded(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                prop_assert!(
                    m.f1 >= 0.0 && m.f1 <= 1.0,
                    "F1 out of bounds: {}", m.f1
                );
            }

            /// F1 <= arithmetic mean of precision and recall (AM-HM inequality).
            #[test]
            fn f1_le_arithmetic_mean(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                let am = (m.precision + m.recall) / 2.0;
                prop_assert!(
                    m.f1 <= am + 1e-12,
                    "F1 ({}) > AM ({}) of P and R", m.f1, am
                );
            }

            /// All items at the same confidence score produce finite AP.
            #[test]
            fn tied_scores_finite(
                is_tp in proptest::collection::vec(any::<bool>(), 1..30usize),
            ) {
                let classified: Vec<_> = is_tp.iter().enumerate().map(|(i, &tp)| {
                    let class = if tp {
                        MatchClass::TruePositive
                    } else {
                        MatchClass::FalsePositive
                    };
                    (
                        NormalizedFinding::new(
                            "f.txt".into(),
                            i as u64 * 10,
                            i as u64 * 10 + 5,
                            "r".into(),
                            42,
                        ),
                        class,
                    )
                }).collect();
                let tp_count = is_tp.iter().filter(|&&t| t).count() as u64;
                let total_pos = tp_count.max(1);
                let ap = compute_average_precision(&classified, total_pos);
                prop_assert!(ap.is_finite(), "AP with all-tied scores is not finite: {ap}");
            }

            /// tp + fp + unlabeled == classified.len().
            #[test]
            fn count_invariant(classified in arb_classified_with_unlabeled(30)) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let m = compute_metrics(&classified, 0, tp_count);
                prop_assert_eq!(
                    m.tp + m.fp + m.unlabeled,
                    classified.len() as u64,
                    "count invariant violated"
                );
            }

            /// Monotone score transform that preserves tie structure yields
            /// identical AP. Maps each distinct confidence value to a new
            /// value while preserving both order and equality.
            #[test]
            fn monotone_transform_preserves_ap(
                classified in arb_classified_tp_fp(20),
            ) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count.max(1);
                let ap_original = compute_average_precision(&classified, total_pos);

                // Apply a strictly monotone transform that preserves ties:
                // map each distinct confidence to its rank among distinct
                // values (not per-item rank). Equal values stay equal.
                let mut distinct: Vec<i8> = classified.iter().map(|(f, _)| f.confidence).collect();
                distinct.sort();
                distinct.dedup();
                let rank_of = |c: i8| -> i8 {
                    distinct.binary_search(&c).unwrap() as i8
                };

                let transformed: Vec<_> = classified.iter().map(|(f, c)| {
                    let mut f2 = f.clone();
                    f2.confidence = rank_of(f.confidence);
                    (f2, *c)
                }).collect();
                let ap_transformed = compute_average_precision(&transformed, total_pos);

                prop_assert!(
                    (ap_original - ap_transformed).abs() < 1e-9,
                    "AP changed under monotone transform: {ap_original} vs {ap_transformed}"
                );
            }

            /// AP is monotonically non-increasing as total_positives grows
            /// (more missed positives means lower recall ceiling).
            #[test]
            fn ap_decreases_with_more_positives(
                classified in arb_classified_tp_fp(20),
                total_pos_base in 1u64..50,
                extra in 1u64..50,
            ) {
                let tp_count = classified.iter()
                    .filter(|(_, c)| *c == MatchClass::TruePositive)
                    .count() as u64;
                let tp_low = total_pos_base.max(tp_count);
                let tp_high = tp_low + extra;
                let ap_low = compute_average_precision(&classified, tp_low);
                let ap_high = compute_average_precision(&classified, tp_high);
                prop_assert!(
                    ap_low >= ap_high - 1e-12,
                    "AP should decrease: AP({tp_low})={ap_low}, AP({tp_high})={ap_high}"
                );
            }
        }
    }
}
