//! Evaluation metrics: precision, recall, F1/F2, Average Precision, P@R, R@P, bootstrap CI.
//!
//! This is the final stage of the eval pipeline: it takes classified findings
//! from the matching layer and produces numeric accuracy metrics. The input is
//! a slice of [`ClassifiedFinding`] items where each finding has been
//! classified as TP, FP, or Unlabeled; false negatives (unmatched truth
//! positives) are counted separately via the `fn_count` parameter because they
//! have no corresponding [`NormalizedFinding`].
//!
//! ## Pipeline context
//!
//! ```text
//! Scanner output ──► NormalizedFinding ──► matching ──► ClassifiedFinding ──► this module
//! Ground truth   ──► TruthItem         ──►          ──► fn_count          ──►
//! ```
//!
//! ## Metric families
//!
//! Two complementary views of classifier quality are produced:
//!
//! - **Threshold-free** (precision, recall, F1, F2): treat every finding
//!   equally regardless of confidence. Answer "how good is detection
//!   overall?"
//! - **Confidence-aware** (Average Precision, P@R, R@P, bootstrap CI):
//!   reward classifiers that assign higher confidence to true positives.
//!   Answer "how good is the confidence ranking?"
//!
//! ## Average Precision algorithm
//!
//! Uses the step-function (rectangular) formula with **tie collapsing**:
//!
//! 1. Filter to TP and FP only (skip Unlabeled).
//! 2. Sort by confidence descending (unstable sort; tie-breaking order is
//!    irrelevant because all items at the same confidence are collapsed
//!    into a single operating point).
//! 3. Collapse consecutive items sharing the same confidence into a single
//!    precision/recall operating point, accumulating TP and FP counts per
//!    group.
//! 4. `AP = sum of (recall_i - recall_{i-1}) * precision_i` over collapsed
//!    points.
//!
//! This matches sklearn's `average_precision_score` (post-v0.19) and avoids
//! the optimistic bias of breaking ties TP-before-FP, which produces
//! degenerate AP=1.0 for constant predictors.
//!
//! ## Zero-denominator convention
//!
//! All ratios (precision, recall, F-scores, AP) return 0.0 when their
//! denominator is zero, rather than NaN or infinity. This is handled by
//! [`safe_div`] and means degenerate inputs (no predictions, no positives)
//! produce all-zero metrics rather than propagating NaN through downstream
//! aggregation.

use std::collections::{BTreeMap, HashMap};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::types::{ClassifiedFinding, FindingClass};

// ── Public types ────────────────────────────────────────────────────────

/// A threshold query result: "at the given target, what value was achieved?"
///
/// Used by [`EvalMetrics::precision_at_recall`] and
/// [`EvalMetrics::recall_at_precision`] to report operating-point metrics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdResult {
    /// The target threshold (e.g., target recall of 0.90).
    pub target: f64,
    /// The achieved metric value, or `None` if no operating point
    /// meets the target.
    pub value: Option<f64>,
}

/// A confidence interval with lower and upper bounds.
///
/// Used by [`EvalMetrics::ap_ci`] to report bootstrap confidence
/// intervals for Average Precision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound of the confidence interval.
    pub lower: f64,
    /// Upper bound of the confidence interval.
    pub upper: f64,
}

/// Aggregate evaluation metrics for a classified finding set.
///
/// Combines threshold-free counts (precision, recall, F1, F2) with a
/// confidence-aware ranking metric (Average Precision). The two
/// views are complementary: threshold-free metrics treat every finding
/// equally regardless of confidence, while AP rewards classifiers that
/// assign higher confidence to true positives.
///
/// # Field relationships
///
/// - `tp + fp + unlabeled` equals the length of the input `classified` slice.
/// - `total_positives = tp + false_neg` (invariant maintained by the caller).
/// - `f2 = 5 * P * R / (4*P + R)` when `4*P + R > 0`, else 0.0.
/// - `f2 >= f1` when `recall >= precision`, `f2 <= f1` otherwise.
/// - `baseline_ap` always equals `precision` (both are `tp / (tp + fp)`).
///   This is the class prevalence among scored items, which also equals the
///   expected AP of a random confidence ranker over the scored population.
///   The field exists as a separate concept even though the formula is
///   identical for the step-function AP definition used here.
/// - `precision_at_recall` targets come from `DEFAULT_PAR_TARGETS`.
/// - `recall_at_precision` targets come from `DEFAULT_RAP_TARGETS`.
/// - `ap_ci` is always `None` from `compute_metrics`; populate via
///   [`with_bootstrap_ci`](EvalMetrics::with_bootstrap_ci).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalMetrics {
    /// Average Precision (step-function AP with tie collapsing).
    ///
    /// Computed as `sum of (recall_i - recall_{i-1}) * precision_i` over
    /// collapsed operating points, matching sklearn's `average_precision_score`.
    /// This is *not* the trapezoidal area under the PR curve (`auc(recall, precision)`).
    pub average_precision: f64,
    /// Threshold-free precision: TP / (TP + FP). Equals 0.0 when
    /// there are no positive predictions (TP + FP = 0).
    pub precision: f64,
    /// Threshold-free recall: TP / total_positives. Equals 0.0 when
    /// there are no ground-truth positives.
    pub recall: f64,
    /// Harmonic mean of precision and recall. Always less than or equal
    /// to the arithmetic mean of the two (AM-HM inequality).
    pub f1: f64,
    /// F2 score: recall-weighted harmonic mean of precision and recall.
    /// `F2 = 5 * P * R / (4 * P + R)`. Weights recall 4x more than
    /// precision, suitable when false negatives are costlier than false
    /// positives (e.g., secret scanning where missed secrets are dangerous).
    pub f2: f64,
    /// True positive count from classified findings.
    pub tp: u64,
    /// False positive count from classified findings.
    pub fp: u64,
    /// False negative count (unmatched truth positives, passed externally).
    pub false_neg: u64,
    /// Findings with no ground-truth annotation (excluded from all metrics).
    pub unlabeled: u64,
    /// Baseline AP: class prevalence among scored items (`tp / (tp + fp)`).
    ///
    /// Equals the expected AP of a random confidence ranker over the scored
    /// population. Useful for gauging whether confidence ranking adds value
    /// beyond the raw detection rate. Uses scored positives (TP) rather
    /// than `total_positives` so the baseline stays achievable when recall is
    /// incomplete. Can exceed `average_precision` when recall is low.
    pub baseline_ap: f64,
    /// Precision at fixed recall targets.
    /// Default targets: 0.80, 0.90, 0.95.
    pub precision_at_recall: Vec<ThresholdResult>,
    /// Recall at fixed precision targets — the highest recall where
    /// precision is at least the target.
    /// Default target: 0.95.
    pub recall_at_precision: Vec<ThresholdResult>,
    /// Bootstrap confidence interval for AP. `None` when bootstrap has
    /// not been run (the default from [`compute_metrics`]).
    pub ap_ci: Option<ConfidenceInterval>,
    /// Per-rule breakdown keyed by rule name, sorted lexicographically.
    pub per_rule: BTreeMap<String, RuleMetrics>,
}

/// Per-rule precision breakdown.
///
/// Contains TP/FP counts and precision for a single detection rule.
/// Recall and F1 are intentionally omitted: computing per-rule recall
/// requires knowing how many ground-truth positives exist for each rule,
/// but the classified finding list only contains scanner output — it has
/// no record of truth items that went unmatched. Adding per-rule FN
/// counts would require threading truth metadata through the matching
/// layer, which is deferred until per-rule reporting is a priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetrics {
    pub tp: u64,
    pub fp: u64,
    /// TP / (TP + FP).
    pub precision: f64,
}

/// Configuration for bootstrap confidence interval estimation.
///
/// Bootstrap resampling computes a confidence interval for the Average
/// Precision metric by repeatedly resampling the classified findings
/// (stratified by class to preserve the TP and FP counts) and recomputing AP
/// on each resample. The resulting distribution of AP values yields
/// percentile-based confidence bounds.
///
/// The default configuration (1000 iterations, alpha=0.05, seed=42)
/// produces a deterministic 95% CI that is suitable for comparing model
/// runs in CI pipelines. For publication-quality intervals, consider
/// increasing `n_iterations` to 10,000.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Number of bootstrap iterations. Higher values yield tighter CI
    /// estimates but take longer. 1000 is generally sufficient for
    /// two-decimal-place stability. Default: 1000.
    pub n_iterations: u32,
    /// Significance level. The CI covers the `[alpha/2, 1 - alpha/2]`
    /// percentile range. Default: 0.05 (95% CI).
    pub alpha: f64,
    /// RNG seed for deterministic results. Fixed by default so that
    /// identical inputs always produce identical CIs. Default: 42.
    pub seed: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            n_iterations: 1000,
            alpha: 0.05,
            seed: 42,
        }
    }
}

impl EvalMetrics {
    /// Consume `self` and return it with bootstrap CI fields populated.
    ///
    /// Intended as the second step after [`compute_metrics`]: compute the
    /// point estimates first, then optionally attach a confidence interval
    /// via [`bootstrap_ap_ci`].
    ///
    /// ```rust,ignore
    /// let m = compute_metrics(&classified, fn_count, total_pos)
    ///     .with_bootstrap_ci(bootstrap_ap_ci(&classified, total_pos, &cfg));
    /// ```
    #[must_use]
    pub fn with_bootstrap_ci(mut self, ci: (f64, f64)) -> Self {
        debug_assert!(
            ci.0 <= ci.1,
            "CI lower ({}) must not exceed upper ({})",
            ci.0,
            ci.1,
        );
        debug_assert!(
            ci.0 >= 0.0 && ci.1 <= 1.0,
            "CI bounds must be in [0.0, 1.0], got ({}, {})",
            ci.0,
            ci.1,
        );
        self.ap_ci = Some(ConfidenceInterval {
            lower: ci.0,
            upper: ci.1,
        });
        self
    }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Compute all evaluation metrics from a classified finding list.
///
/// This is the primary entry point for the metrics module. It produces both
/// threshold-free metrics (precision, recall, F1, F2) and confidence-aware
/// metrics (AP, P@R, R@P) in a small number of linear passes plus an
/// O(n log n) sort for the PR curve.
///
/// Bootstrap CI fields are left as `None`; use [`with_bootstrap_ci`] to
/// attach them after calling [`bootstrap_ap_ci`] separately.
///
/// # Parameters
///
/// - `classified`: classified findings from the matching layer. Only
///   [`FindingClass::TruePositive`], [`FindingClass::FalsePositive`], and
///   [`FindingClass::Unlabeled`] can appear (enforced at compile time by
///   the [`FindingClass`] type, which has no `FalseNegative` variant).
/// - `fn_count`: number of ground-truth positives not matched by any finding.
/// - `total_positives`: total ground-truth positive count (`tp + fn_count`).
///
/// # Panics
///
/// - If `tp + fn_count != total_positives` (invariant check).
///
/// [`with_bootstrap_ci`]: EvalMetrics::with_bootstrap_ci
pub fn compute_metrics(
    classified: &[ClassifiedFinding],
    fn_count: u64,
    total_positives: u64,
) -> EvalMetrics {
    let mut tp: u64 = 0;
    let mut fp: u64 = 0;
    let mut unlabeled: u64 = 0;

    for cf in classified {
        match cf.class {
            FindingClass::TruePositive => tp += 1,
            FindingClass::FalsePositive => fp += 1,
            FindingClass::Unlabeled => unlabeled += 1,
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
    let f2 = safe_div(5.0 * precision * recall, 4.0 * precision + recall);

    let curve = build_pr_curve(classified, total_positives);
    let average_precision = ap_from_curve(&curve);
    let baseline_ap = precision;
    let per_rule = compute_per_rule(classified);

    let par = DEFAULT_PAR_TARGETS
        .iter()
        .map(|&t| ThresholdResult {
            target: t,
            value: precision_at_recall(&curve, t),
        })
        .collect();
    let rap = DEFAULT_RAP_TARGETS
        .iter()
        .map(|&t| ThresholdResult {
            target: t,
            value: recall_at_precision(&curve, t),
        })
        .collect();

    EvalMetrics {
        average_precision,
        precision,
        recall,
        f1,
        f2,
        tp,
        fp,
        false_neg: fn_count,
        unlabeled,
        baseline_ap,
        precision_at_recall: par,
        recall_at_precision: rap,
        ap_ci: None,
        per_rule,
    }
}

/// Compute a bootstrap confidence interval for Average Precision.
///
/// Uses stratified resampling: TP and FP items are resampled independently
/// (with replacement) to preserve the TP and FP counts in every iteration.
/// Each resampled set is run through `pr_curve_from_scored` + `ap_from_curve` to
/// produce an AP estimate. The resulting AP distribution is sorted and
/// percentiles at `[alpha/2, 1 - alpha/2]` are returned.
///
/// Stratification is critical here: naive (unstratified) resampling can
/// produce samples with very different TP/FP ratios than the original,
/// inflating the CI width and making it less useful for comparing models.
///
/// # Complexity
///
/// O(`n_iterations` * n * log n) where n is the number of TP + FP items.
/// Each iteration sorts the resampled set to build a PR curve.
///
/// # Panics
///
/// - If `config.n_iterations` is zero.
/// - If `config.alpha` is not in the open interval `(0.0, 1.0)`.
/// - If `total_positives` is less than the number of TP items in `classified`.
///
/// # Returns
///
/// `(ci_lower, ci_upper)` as the `[alpha/2, 1 - alpha/2]` percentiles.
/// Returns `(0.0, 0.0)` when there are zero TP *and* zero FP items
/// (Unlabeled items are excluded from bootstrap resampling).
pub fn bootstrap_ap_ci(
    classified: &[ClassifiedFinding],
    total_positives: u64,
    config: &BootstrapConfig,
) -> (f64, f64) {
    // Extract lightweight (confidence, is_tp) pairs — avoids cloning full
    // NormalizedFinding structs on every bootstrap iteration.
    let tp_scores: Vec<i8> = classified
        .iter()
        .filter(|cf| cf.class == FindingClass::TruePositive)
        .map(|cf| cf.finding.confidence)
        .collect();
    let fp_scores: Vec<i8> = classified
        .iter()
        .filter(|cf| cf.class == FindingClass::FalsePositive)
        .map(|cf| cf.finding.confidence)
        .collect();

    assert!(
        config.n_iterations > 0,
        "BootstrapConfig::n_iterations must be > 0, got {}",
        config.n_iterations,
    );
    assert!(
        config.alpha > 0.0 && config.alpha < 1.0,
        "BootstrapConfig::alpha must be in (0.0, 1.0), got {}",
        config.alpha,
    );
    assert!(
        total_positives >= tp_scores.len() as u64,
        "total_positives ({total_positives}) must be >= TP count ({}); \
         otherwise recall exceeds 1.0",
        tp_scores.len(),
    );

    if tp_scores.is_empty() && fp_scores.is_empty() {
        return (0.0, 0.0);
    }

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut ap_samples = Vec::with_capacity(config.n_iterations as usize);

    // Pre-allocate a single buffer for resampled scored pairs, reused
    // across iterations to avoid per-iteration allocation.
    let resample_len = tp_scores.len() + fp_scores.len();
    let mut resampled = Vec::with_capacity(resample_len);

    for _ in 0..config.n_iterations {
        resampled.clear();

        for _ in 0..tp_scores.len() {
            let idx = rng.gen_range(0..tp_scores.len());
            resampled.push((tp_scores[idx], true));
        }
        for _ in 0..fp_scores.len() {
            let idx = rng.gen_range(0..fp_scores.len());
            resampled.push((fp_scores[idx], false));
        }

        let curve = pr_curve_from_scored(&mut resampled, total_positives);
        ap_samples.push(ap_from_curve(&curve));
    }

    ap_samples.sort_by(|a, b| {
        a.partial_cmp(b)
            .expect("AP values must be finite for bootstrap CI")
    });

    // Percentile extraction: floor for the lower bound, ceil for the upper
    // bound produces a conservative (wider) CI — the interval never
    // understates uncertainty. Clamped to valid indices for safety when
    // n_iterations is very small. With alpha=0.05 and 1000 samples this
    // gives indices 25 and 975 (the 2.5th and 97.5th percentiles).
    let lo_idx = ((config.alpha / 2.0) * ap_samples.len() as f64).floor() as usize;
    let hi_idx = ((1.0 - config.alpha / 2.0) * ap_samples.len() as f64).ceil() as usize;
    let lo_idx = lo_idx.min(ap_samples.len().saturating_sub(1));
    let hi_idx = hi_idx.min(ap_samples.len().saturating_sub(1));

    (ap_samples[lo_idx], ap_samples[hi_idx])
}

// ── Internal helpers ────────────────────────────────────────────────────

/// A single operating point on the precision-recall curve after tie
/// collapsing. Each point represents the cumulative precision and recall
/// achieved when the confidence threshold is set at (or below) a
/// particular level. Points are produced in confidence-descending order,
/// so recall monotonically increases (non-decreasing) and precision
/// generally decreases as you walk the curve.
#[derive(Debug, Clone, Copy)]
struct PrPoint {
    /// TP_so_far / (TP_so_far + FP_so_far) at this threshold.
    precision: f64,
    /// TP_so_far / total_positives at this threshold.
    recall: f64,
}

/// Build the precision-recall curve from a classified finding list.
///
/// Extracts TP and FP items, sorts by confidence descending, collapses
/// tied confidence groups into single operating points, and returns the
/// resulting curve ordered from highest confidence (low recall) to lowest
/// confidence (high recall).
///
/// The curve has at most as many points as there are distinct confidence
/// values among TP/FP items. In the worst case (all unique) this equals
/// the number of scored items; in the best case (constant predictor) it
/// collapses to a single point.
///
/// # Complexity
///
/// O(n log n) for the sort, O(n) for the single-pass tie collapsing.
///
/// Returns an empty vec when `total_positives` is zero or no TP/FP items
/// are present.
fn build_pr_curve(classified: &[ClassifiedFinding], total_positives: u64) -> Vec<PrPoint> {
    if total_positives == 0 {
        return Vec::new();
    }

    let mut scored: Vec<(i8, bool)> = classified
        .iter()
        .filter_map(|cf| match cf.class {
            FindingClass::TruePositive => Some((cf.finding.confidence, true)),
            FindingClass::FalsePositive => Some((cf.finding.confidence, false)),
            FindingClass::Unlabeled => None,
        })
        .collect();

    pr_curve_from_scored(&mut scored, total_positives)
}

/// Build a PR curve from pre-extracted `(confidence, is_tp)` pairs.
///
/// Sorts `scored` in place by confidence descending, then collapses tied
/// confidence groups into single operating points. This is the shared
/// core used by both [`build_pr_curve`] (which extracts from full findings)
/// and [`bootstrap_ap_ci`] (which works on lightweight resampled pairs).
///
/// Takes `&mut` to sort in place, avoiding a clone on every bootstrap
/// iteration. Uses `sort_unstable_by` because tie-breaking order within
/// a confidence group is irrelevant — all items sharing a confidence
/// value are collapsed into a single operating point regardless of their
/// relative order.
fn pr_curve_from_scored(scored: &mut [(i8, bool)], total_positives: u64) -> Vec<PrPoint> {
    if scored.is_empty() {
        return Vec::new();
    }

    // Descending sort so the highest-confidence items come first,
    // producing a curve that sweeps from low recall to high recall.
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0));

    let total_pos_f64 = total_positives as f64;
    let mut cum_tp: u64 = 0;
    let mut cum_fp: u64 = 0;
    let mut curve = Vec::new();

    // Two-pointer sweep: outer pointer `i` marks the start of each
    // confidence group, inner pointer `j` scans to the end. All items
    // in [i, j) share the same confidence and are collapsed into one
    // operating point, which is what makes AP invariant to tie-breaking
    // order within a confidence level.
    let mut i = 0;
    while i < scored.len() {
        let current_conf = scored[i].0;
        let mut group_tp: u64 = 0;
        let mut group_fp: u64 = 0;

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

        curve.push(PrPoint {
            precision: safe_div(cum_tp as f64, (cum_tp + cum_fp) as f64),
            recall: safe_div(cum_tp as f64, total_pos_f64),
        });

        i = j;
    }

    curve
}

/// Compute step-function Average Precision from a pre-built PR curve.
///
/// `AP = sum of (recall_i - recall_{i-1}) * precision_i` over all
/// operating points. Returns 0.0 for an empty curve.
///
/// The result is clamped to `max(0.0, ap)` as a defensive guard: AP is
/// non-negative by construction (every `recall_i - recall_{i-1}` delta
/// and every `precision_i` are non-negative), but floating-point
/// subtraction can produce tiny negatives (e.g., `-1e-17`) when recall
/// values are very close together.
fn ap_from_curve(curve: &[PrPoint]) -> f64 {
    let mut prev_recall = 0.0;
    let mut ap = 0.0;

    for pt in curve {
        ap += (pt.recall - prev_recall) * pt.precision;
        prev_recall = pt.recall;
    }

    f64::max(0.0, ap)
}

/// Default recall targets for precision-at-recall queries.
///
/// These are industry-standard recall operating points: 0.80 is a
/// practical minimum for production secret scanning, 0.90 is a common
/// quality bar for CI gates, and 0.95 is a stretch target for
/// high-assurance environments. Also documented in the
/// `EvalMetrics::precision_at_recall` field doc.
const DEFAULT_PAR_TARGETS: &[f64] = &[0.80, 0.90, 0.95];

/// Default precision targets for recall-at-precision queries.
///
/// A single high-precision target (0.95) answers the practical question
/// "how much recall can I get if I need <=5% false positive rate?" This
/// is the operating point most relevant for automated remediation
/// workflows where FP cost is high. Also documented in the
/// `EvalMetrics::recall_at_precision` field doc.
const DEFAULT_RAP_TARGETS: &[f64] = &[0.95];

/// Find the best precision achievable at a given recall target.
///
/// Returns the **maximum** precision among all operating points where
/// `recall >= target`, rather than the precision at the first qualifying
/// point. This matters on recall plateaus where multiple points share
/// the same recall but have decreasing precision (e.g., after adding FP
/// items that lower precision without changing recall). Taking the max
/// selects the operating point where the classifier is most precise
/// while still meeting the recall floor.
///
/// Returns `None` if no point reaches the target recall.
///
/// The comparison uses a small epsilon (`1e-12`) to absorb floating-point
/// rounding in cumulative recall values (e.g., 3/3 computing to
/// 0.9999999999999998 instead of 1.0).
fn precision_at_recall(curve: &[PrPoint], target: f64) -> Option<f64> {
    let mut best: Option<f64> = None;
    for pt in curve {
        if pt.recall >= target - 1e-12 {
            best = Some(match best {
                Some(prev) => f64::max(prev, pt.precision),
                None => pt.precision,
            });
        }
    }
    best
}

/// Find the highest recall achievable at a given precision target.
///
/// Walks the curve **backwards** (from the last point to the first),
/// which means from high recall to low recall because the curve is
/// ordered confidence-descending (i.e., recall-ascending). The first
/// point encountered with `precision >= target` is therefore the
/// highest-recall point meeting the constraint — no need to scan
/// further.
///
/// Returns `None` if no operating point meets the precision threshold.
///
/// Uses the same `1e-12` epsilon as [`precision_at_recall`] for
/// floating-point tolerance.
fn recall_at_precision(curve: &[PrPoint], target: f64) -> Option<f64> {
    // Walk backwards (high recall to low recall) to find the
    // highest-recall point where precision is at least the target.
    for pt in curve.iter().rev() {
        if pt.precision >= target - 1e-12 {
            return Some(pt.recall);
        }
    }
    None
}

/// Step-function Average Precision with tie collapsing.
///
/// Thin wrapper around `build_pr_curve` + `ap_from_curve` retained as a
/// convenience for tests that only need the scalar AP value.
#[cfg(test)]
fn compute_average_precision(classified: &[ClassifiedFinding], total_positives: u64) -> f64 {
    ap_from_curve(&build_pr_curve(classified, total_positives))
}

/// Per-rule precision breakdown from classified findings.
///
/// Groups TP and FP findings by rule name, computes precision per rule.
/// Unlabeled items are skipped. Rules that produce only Unlabeled
/// findings are absent from the output entirely.
///
/// Accumulation uses a temporary `HashMap<&str, (u64, u64)>` for O(1)
/// amortized insertion, then converts to `BTreeMap<String, RuleMetrics>`
/// for deterministic iteration order in serialized output (JSON reports,
/// CLI tables). The `&str` keys borrow from the input to avoid
/// per-finding string allocation during counting.
///
/// # Complexity
///
/// O(n + r log r) where n is the number of classified findings and r is
/// the number of distinct rules (r << n in practice).
fn compute_per_rule(classified: &[ClassifiedFinding]) -> BTreeMap<String, RuleMetrics> {
    let mut counts: HashMap<&str, (u64, u64)> = HashMap::new();

    for cf in classified {
        match cf.class {
            FindingClass::TruePositive => {
                counts.entry(cf.finding.rule.as_str()).or_default().0 += 1;
            }
            FindingClass::FalsePositive => {
                counts.entry(cf.finding.rule.as_str()).or_default().1 += 1;
            }
            FindingClass::Unlabeled => {}
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
    fn item(confidence: i8, class: FindingClass) -> ClassifiedFinding {
        ClassifiedFinding {
            finding: NormalizedFinding::new(
                "test.txt".into(),
                0,
                1,
                "test_rule".into(),
                confidence,
            ),
            class,
        }
    }

    /// Build a classified finding for a specific rule.
    fn item_rule(confidence: i8, class: FindingClass, rule: &str) -> ClassifiedFinding {
        ClassifiedFinding {
            finding: NormalizedFinding::new("test.txt".into(), 0, 1, rule.into(), confidence),
            class,
        }
    }

    // ── AP oracle tests ─────────────────────────────────────────

    #[test]
    #[allow(clippy::type_complexity)]
    fn ap_oracle_cases() {
        use FindingClass::{FalsePositive as FP, TruePositive as TP};

        let cases: &[(&str, &[(i8, FindingClass)], u64, f64)] = &[
            ("single_tp", &[(5, TP)], 1, 1.0),
            (
                "alternating",
                &[(5, TP), (4, FP), (3, TP), (2, FP), (1, TP)],
                3,
                34.0 / 45.0,
            ),
            (
                "tp_heavy_front",
                &[(5, TP), (4, TP), (3, FP), (2, TP), (1, FP)],
                3,
                11.0 / 12.0,
            ),
            ("all_fp", &[(5, FP), (4, FP), (3, FP)], 3, 0.0),
            (
                "fp_heavy_front",
                &[(5, FP), (4, TP), (3, FP), (2, TP), (1, TP)],
                3,
                8.0 / 15.0,
            ),
            // Tied scores collapse into a single operating point.
            ("tied_collapse", &[(5, TP), (5, FP), (5, TP)], 2, 2.0 / 3.0),
            (
                "constant_pred",
                &[(5, TP), (5, FP), (5, FP), (5, FP)],
                1,
                0.25,
            ),
            // Recall capped at 0.5 because 2 of 4 positives are missed.
            ("with_fn", &[(5, TP), (4, TP)], 4, 0.5),
            ("empty", &[], 0, 0.0),
        ];

        for &(name, items, total_pos, expected) in cases {
            let classified: Vec<_> = items.iter().map(|&(c, cls)| item(c, cls)).collect();
            let ap = compute_average_precision(&classified, total_pos);
            assert!(
                (ap - expected).abs() < EPS,
                "case {name}: expected {expected}, got {ap}"
            );
        }
    }

    // ── compute_metrics integration tests ───────────────────────

    #[test]
    fn metrics_perfect_classifier() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::TruePositive),
            item(3, FindingClass::TruePositive),
        ];
        let m = compute_metrics(&classified, 0, 3);
        assert!((m.average_precision - 1.0).abs() < EPS);
        assert!((m.precision - 1.0).abs() < EPS);
        assert!((m.recall - 1.0).abs() < EPS);
        assert!((m.f1 - 1.0).abs() < EPS);
        assert!((m.f2 - 1.0).abs() < EPS);
        assert_eq!(m.tp, 3);
        assert_eq!(m.fp, 0);
        assert_eq!(m.false_neg, 0);
        assert_eq!(m.unlabeled, 0);
        for r in &m.precision_at_recall {
            assert_eq!(
                r.value,
                Some(1.0),
                "P@R={} should be Some(1.0), got {:?}",
                r.target,
                r.value,
            );
        }
        for r in &m.recall_at_precision {
            assert_eq!(
                r.value,
                Some(1.0),
                "R@P={} should be Some(1.0), got {:?}",
                r.target,
                r.value,
            );
        }
    }

    #[test]
    fn metrics_all_fp() {
        let classified = vec![
            item(5, FindingClass::FalsePositive),
            item(4, FindingClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 3, 3);
        assert!(m.average_precision.abs() < EPS);
        assert!(m.precision.abs() < EPS);
        assert!(m.recall.abs() < EPS);
        assert!(m.f1.abs() < EPS);
        assert!(m.f2.abs() < EPS);
        assert_eq!(m.tp, 0);
        assert_eq!(m.fp, 2);
        assert_eq!(m.false_neg, 3);
        for r in &m.precision_at_recall {
            assert_eq!(
                r.value, None,
                "P@R={} should be None when all FP, got {:?}",
                r.target, r.value
            );
        }
    }

    #[test]
    fn metrics_empty_input() {
        let m = compute_metrics(&[], 0, 0);
        assert!(m.average_precision.abs() < EPS);
        assert!(m.precision.abs() < EPS);
        assert!(m.recall.abs() < EPS);
        assert!(m.f1.abs() < EPS);
        assert_eq!(m.tp, 0);
        assert_eq!(m.fp, 0);
        assert_eq!(m.false_neg, 0);
        assert_eq!(m.unlabeled, 0);
        for r in &m.precision_at_recall {
            assert_eq!(r.value, None, "P@R should be None for empty input");
        }
        for r in &m.recall_at_precision {
            assert_eq!(r.value, None, "R@P should be None for empty input");
        }
    }

    #[test]
    fn metrics_unlabeled_excluded() {
        // Unlabeled findings should not affect P/R/F1/AP.
        let classified = vec![
            item(10, FindingClass::TruePositive),
            item(8, FindingClass::Unlabeled),
            item(6, FindingClass::Unlabeled),
            item(4, FindingClass::FalsePositive),
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
            item_rule(5, FindingClass::TruePositive, "rule_a"),
            item_rule(4, FindingClass::FalsePositive, "rule_a"),
            item_rule(3, FindingClass::TruePositive, "rule_b"),
            item_rule(2, FindingClass::TruePositive, "rule_b"),
            item_rule(1, FindingClass::Unlabeled, "rule_c"),
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
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
            item(3, FindingClass::FalsePositive),
            item(2, FindingClass::FalsePositive),
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
        let classified = vec![item(5, FindingClass::TruePositive)];
        let m = compute_metrics(&classified, 99, 100);
        // tp=1, fp=0 → baseline = 1.0 (entire scored list is positive)
        assert!((m.baseline_ap - 1.0).abs() < EPS);

        // Divergent case: 1 TP, 2 FN, 3 FP.
        // Old formula: total_positives/(total_positives+fp) = 3/(3+3) = 0.5
        // New formula: tp/(tp+fp) = 1/(1+3) = 0.25
        // The old baseline was inflated by counting FNs not in the ranked list.
        let classified2 = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
            item(3, FindingClass::FalsePositive),
            item(2, FindingClass::FalsePositive),
        ];
        let m2 = compute_metrics(&classified2, 2, 3);
        assert!(
            (m2.baseline_ap - 0.25).abs() < EPS,
            "expected baseline 0.25 (tp/(tp+fp)), got {}",
            m2.baseline_ap
        );
    }

    // ── P@R and R@P known-curve tests ──────────────────────────────

    #[test]
    fn par_rap_known_curve() {
        // [TP(5),FP(4),TP(3),FP(2),TP(1)] total_pos=3
        // Operating points (all distinct confidences):
        //   conf=5: P=1.0,   R=1/3
        //   conf=4: P=0.5,   R=1/3
        //   conf=3: P=2/3,   R=2/3
        //   conf=2: P=0.5,   R=2/3
        //   conf=1: P=0.6,   R=1.0
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
            item(3, FindingClass::TruePositive),
            item(2, FindingClass::FalsePositive),
            item(1, FindingClass::TruePositive),
        ];
        let m = compute_metrics(&classified, 0, 3);

        // P@R: all targets (0.80, 0.90, 0.95) met at conf=1 (R=1.0, P=0.6).
        for r in &m.precision_at_recall {
            let p = r.value.unwrap();
            assert!((p - 0.6).abs() < EPS, "expected P=0.6, got {p}");
        }

        // R@P=0.95: only conf=5 has P >= 0.95, so R=1/3.
        let r = m.recall_at_precision[0].value.unwrap();
        assert!((r - 1.0 / 3.0).abs() < EPS, "expected R=1/3, got {r}");
    }

    #[test]
    fn rap_no_point_meets_threshold() {
        // All points have precision < 0.95 → None.
        let classified = vec![
            item(5, FindingClass::FalsePositive),
            item(4, FindingClass::TruePositive),
        ];
        let m = compute_metrics(&classified, 0, 1);
        for r in &m.recall_at_precision {
            assert_eq!(
                r.value, None,
                "R@P should be None when no point meets threshold"
            );
        }
    }

    #[test]
    fn rap_returns_highest_recall() {
        // Curve where multiple points meet P >= 0.95.
        // [TP(5), TP(4), TP(3), FP(2)] total_pos=3
        // Operating points:
        //   conf=5: P=1.0,  R=1/3
        //   conf=4: P=1.0,  R=2/3
        //   conf=3: P=1.0,  R=1.0
        //   conf=2: P=0.75, R=1.0
        // All of conf=5,4,3 have P >= 0.95. The highest recall among
        // them is R=1.0 (at conf=3). A forward-walk bug would return
        // R=1/3 instead.
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::TruePositive),
            item(3, FindingClass::TruePositive),
            item(2, FindingClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 0, 3);
        let r = m.recall_at_precision[0].value.unwrap();
        assert!(
            (r - 1.0).abs() < EPS,
            "R@P=0.95 should be 1.0 (highest recall), got {r}"
        );
    }

    #[test]
    fn f2_intermediate_value() {
        // 1 TP, 1 FP, 0 FN → P=0.5, R=1.0.
        // F1 = 2 * 0.5 * 1.0 / (0.5 + 1.0) = 2/3
        // F2 = 5 * 0.5 * 1.0 / (4 * 0.5 + 1.0) = 2.5 / 3.0 = 5/6
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 0, 1);
        let expected_f2 = 5.0 / 6.0;
        assert!(
            (m.f2 - expected_f2).abs() < EPS,
            "F2 should be 5/6, got {}",
            m.f2
        );
        assert!(
            m.f2 > m.f1,
            "F2 should exceed F1 when R > P: F2={}, F1={}",
            m.f2,
            m.f1
        );
    }

    // ── Bootstrap CI tests ──────────────────────────────────────

    #[test]
    fn bootstrap_perfect_classifier() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::TruePositive),
            item(3, FindingClass::TruePositive),
        ];
        let config = BootstrapConfig {
            n_iterations: 100,
            ..Default::default()
        };
        let (lo, hi) = bootstrap_ap_ci(&classified, 3, &config);
        assert!(
            (lo - 1.0).abs() < EPS,
            "perfect CI lower should be 1.0, got {lo}"
        );
        assert!(
            (hi - 1.0).abs() < EPS,
            "perfect CI upper should be 1.0, got {hi}"
        );
    }

    #[test]
    fn bootstrap_deterministic() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
            item(3, FindingClass::TruePositive),
            item(2, FindingClass::FalsePositive),
            item(1, FindingClass::TruePositive),
        ];
        let config = BootstrapConfig::default();
        let (lo1, hi1) = bootstrap_ap_ci(&classified, 3, &config);
        let (lo2, hi2) = bootstrap_ap_ci(&classified, 3, &config);
        assert_eq!(lo1, lo2, "bootstrap should be deterministic");
        assert_eq!(hi1, hi2, "bootstrap should be deterministic");
    }

    #[test]
    fn bootstrap_ci_contains_ap() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
            item(3, FindingClass::TruePositive),
            item(2, FindingClass::FalsePositive),
            item(1, FindingClass::TruePositive),
        ];
        let total_pos = 3;
        let ap = compute_average_precision(&classified, total_pos);
        let config = BootstrapConfig {
            n_iterations: 500,
            ..Default::default()
        };
        let (lo, hi) = bootstrap_ap_ci(&classified, total_pos, &config);
        assert!(lo <= ap + EPS, "ci_lower ({lo}) > AP ({ap})");
        assert!(hi >= ap - EPS, "ci_upper ({hi}) < AP ({ap})");
    }

    #[test]
    fn bootstrap_all_fp() {
        let classified = vec![
            item(5, FindingClass::FalsePositive),
            item(4, FindingClass::FalsePositive),
        ];
        let config = BootstrapConfig {
            n_iterations: 100,
            ..Default::default()
        };
        let (lo, hi) = bootstrap_ap_ci(&classified, 3, &config);
        assert!(lo.abs() < EPS, "expected ci_lower=0.0, got {lo}");
        assert!(hi.abs() < EPS, "expected ci_upper=0.0, got {hi}");
    }

    #[test]
    fn bootstrap_with_metrics_convenience() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 0, 1);
        assert!(m.ap_ci.is_none());

        let ci = bootstrap_ap_ci(&classified, 1, &BootstrapConfig::default());
        let m = m.with_bootstrap_ci(ci);
        assert!(m.ap_ci.is_some());
        let ci = m.ap_ci.unwrap();
        assert!(ci.lower <= ci.upper);
    }

    // ── Proptest properties ─────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        /// Generate a random classified list of TP/FP items.
        fn arb_classified_tp_fp(max_len: usize) -> impl Strategy<Value = Vec<ClassifiedFinding>> {
            proptest::collection::vec((any::<i8>(), any::<bool>()), 0..=max_len).prop_map(|items| {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, (conf, is_tp))| {
                        let class = if is_tp {
                            FindingClass::TruePositive
                        } else {
                            FindingClass::FalsePositive
                        };
                        ClassifiedFinding {
                            finding: NormalizedFinding::new(
                                "f.txt".into(),
                                i as u64 * 10,
                                i as u64 * 10 + 5,
                                "r".into(),
                                conf,
                            ),
                            class,
                        }
                    })
                    .collect()
            })
        }

        /// Generate a classified list that includes Unlabeled items.
        fn arb_classified_with_unlabeled(
            max_len: usize,
        ) -> impl Strategy<Value = Vec<ClassifiedFinding>> {
            proptest::collection::vec((any::<i8>(), 0u8..3), 0..=max_len).prop_map(|items| {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, (conf, class_idx))| {
                        let class = match class_idx {
                            0 => FindingClass::TruePositive,
                            1 => FindingClass::FalsePositive,
                            _ => FindingClass::Unlabeled,
                        };
                        ClassifiedFinding {
                            finding: NormalizedFinding::new(
                                "f.txt".into(),
                                i as u64 * 10,
                                i as u64 * 10 + 5,
                                "r".into(),
                                conf,
                            ),
                            class,
                        }
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
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
                    item(conf, FindingClass::TruePositive)
                }).collect();
                for i in 0..n {
                    classified.push(item(-(i as i8) - 1, FindingClass::FalsePositive));
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
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
                        FindingClass::TruePositive
                    } else {
                        FindingClass::FalsePositive
                    };
                    ClassifiedFinding {
                        finding: NormalizedFinding::new(
                            "f.txt".into(),
                            i as u64 * 10,
                            i as u64 * 10 + 5,
                            "r".into(),
                            42,
                        ),
                        class,
                    }
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count.max(1);
                let ap_original = compute_average_precision(&classified, total_pos);

                // Apply a strictly monotone transform that preserves ties:
                // map each distinct confidence to its rank among distinct
                // values (not per-item rank). Equal values stay equal.
                let mut distinct: Vec<i8> = classified.iter().map(|cf| cf.finding.confidence).collect();
                distinct.sort();
                distinct.dedup();
                let rank_of = |c: i8| -> i8 {
                    distinct.binary_search(&c).unwrap() as i8
                };

                let transformed: Vec<_> = classified.iter().map(|cf| {
                    let mut f2 = cf.finding.clone();
                    f2.confidence = rank_of(cf.finding.confidence);
                    ClassifiedFinding {
                        finding: f2,
                        class: cf.class,
                    }
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
                    .filter(|cf| cf.class == FindingClass::TruePositive)
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

            /// P@R values (when Some) are in [0.0, 1.0].
            #[test]
            fn par_bounded(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                for r in &m.precision_at_recall {
                    if let Some(p) = r.value {
                        prop_assert!(
                            (0.0..=1.0).contains(&p),
                            "P@R out of bounds: {p}"
                        );
                    }
                }
            }

            /// R@P values (when Some) are in [0.0, 1.0].
            #[test]
            fn rap_bounded(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                for r in &m.recall_at_precision {
                    if let Some(v) = r.value {
                        prop_assert!(
                            (0.0..=1.0).contains(&v),
                            "R@P out of bounds: {v}"
                        );
                    }
                }
            }

            /// F2 is always in [0.0, 1.0].
            #[test]
            fn f2_bounded(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                prop_assert!(
                    m.f2 >= 0.0 && m.f2 <= 1.0,
                    "F2 out of bounds: {}", m.f2
                );
            }

            /// F2 >= F1 when recall > precision (recall-weighting),
            /// F2 <= F1 when precision > recall.
            #[test]
            fn f2_relationship_to_f1(
                classified in arb_classified_tp_fp(30),
                fn_count in 0u64..20,
            ) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count + fn_count;
                let m = compute_metrics(&classified, fn_count, total_pos);
                let eps = 1e-12;
                if m.recall > m.precision + eps {
                    prop_assert!(
                        m.f2 >= m.f1 - eps,
                        "F2 ({}) < F1 ({}) when R ({}) > P ({})",
                        m.f2, m.f1, m.recall, m.precision,
                    );
                } else if m.precision > m.recall + eps {
                    prop_assert!(
                        m.f2 <= m.f1 + eps,
                        "F2 ({}) > F1 ({}) when P ({}) > R ({})",
                        m.f2, m.f1, m.precision, m.recall,
                    );
                }
            }

            /// Bootstrap CI is ordered: lower <= upper.
            #[test]
            fn bootstrap_ci_ordered(classified in arb_classified_tp_fp(15)) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count.max(1);
                let config = BootstrapConfig { n_iterations: 50, ..Default::default() };
                let (lo, hi) = bootstrap_ap_ci(&classified, total_pos, &config);
                prop_assert!(lo <= hi + 1e-12, "ci_lower ({lo}) > ci_upper ({hi})");
            }

            /// Bootstrap CI bounds are in [0.0, 1.0].
            #[test]
            fn bootstrap_ci_bounded(classified in arb_classified_tp_fp(15)) {
                let tp_count = classified.iter()
                    .filter(|cf| cf.class == FindingClass::TruePositive)
                    .count() as u64;
                let total_pos = tp_count.max(1);
                let config = BootstrapConfig { n_iterations: 50, ..Default::default() };
                let (lo, hi) = bootstrap_ap_ci(&classified, total_pos, &config);
                prop_assert!((0.0..=1.0).contains(&lo), "ci_lower out of bounds: {lo}");
                prop_assert!((0.0..=1.0).contains(&hi), "ci_upper out of bounds: {hi}");
            }
        }
    }

    // ── Input validation tests ──────────────────────────────────

    #[test]
    fn par_selects_best_precision_on_recall_plateau() {
        // Curve: TP(conf=5), TP(conf=4), FP(conf=3), total_pos=2
        // Operating points:
        //   conf=5: P=1.0, R=0.5
        //   conf=4: P=1.0, R=1.0
        //   conf=3: P=2/3, R=1.0
        // Points at R=1.0: (P=1.0) and (P=2/3).
        // P@R=0.95 should return P=1.0 (the best precision where R >= 0.95).
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::TruePositive),
            item(3, FindingClass::FalsePositive),
        ];
        let m = compute_metrics(&classified, 0, 2);
        let par_095 = m
            .precision_at_recall
            .iter()
            .find(|r| (r.target - 0.95).abs() < EPS);
        let p = par_095
            .expect("0.95 target missing")
            .value
            .expect("should be Some");
        assert!(
            (p - 1.0).abs() < EPS,
            "P@R=0.95 should be 1.0 (best on plateau), got {p}"
        );
    }

    #[test]
    #[should_panic(expected = "n_iterations must be > 0")]
    fn bootstrap_zero_iterations_panics() {
        let classified = vec![item(5, FindingClass::TruePositive)];
        let config = BootstrapConfig {
            n_iterations: 0,
            ..Default::default()
        };
        bootstrap_ap_ci(&classified, 1, &config);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0.0, 1.0)")]
    fn bootstrap_alpha_zero_panics() {
        let classified = vec![item(5, FindingClass::TruePositive)];
        let config = BootstrapConfig {
            alpha: 0.0,
            ..Default::default()
        };
        bootstrap_ap_ci(&classified, 1, &config);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0.0, 1.0)")]
    fn bootstrap_alpha_one_panics() {
        let classified = vec![item(5, FindingClass::TruePositive)];
        let config = BootstrapConfig {
            alpha: 1.0,
            ..Default::default()
        };
        bootstrap_ap_ci(&classified, 1, &config);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0.0, 1.0)")]
    fn bootstrap_alpha_negative_panics() {
        let classified = vec![item(5, FindingClass::TruePositive)];
        let config = BootstrapConfig {
            alpha: -0.5,
            ..Default::default()
        };
        bootstrap_ap_ci(&classified, 1, &config);
    }

    #[test]
    #[should_panic(expected = "total_positives (1) must be >= TP count (3)")]
    fn bootstrap_total_positives_less_than_tp_panics() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::TruePositive),
            item(3, FindingClass::TruePositive),
        ];
        let config = BootstrapConfig::default();
        bootstrap_ap_ci(&classified, 1, &config);
    }

    #[test]
    fn bootstrap_single_iteration() {
        let classified = vec![
            item(5, FindingClass::TruePositive),
            item(4, FindingClass::FalsePositive),
        ];
        let config = BootstrapConfig {
            n_iterations: 1,
            ..Default::default()
        };
        let (lo, hi) = bootstrap_ap_ci(&classified, 1, &config);
        assert!(lo <= hi, "single iteration CI should have lo <= hi");
        assert!((0.0..=1.0).contains(&lo), "ci_lower out of bounds: {lo}");
        assert!((0.0..=1.0).contains(&hi), "ci_upper out of bounds: {hi}");
    }

    // ── Edge-case coverage ─────────────────────────────────────

    #[test]
    fn par_mixed_achievable_targets() {
        // Max recall ~0.85: 17 TP out of 20 total positives.
        // P@R=0.80 should be Some, P@R=0.90 and 0.95 should be None.
        let mut classified: Vec<_> = (0..17)
            .map(|i| item(100 - i as i8, FindingClass::TruePositive))
            .collect();
        classified.extend((0..3).map(|i| item(50 - i as i8, FindingClass::FalsePositive)));
        let m = compute_metrics(&classified, 3, 20);

        let par_80 = m
            .precision_at_recall
            .iter()
            .find(|r| (r.target - 0.80).abs() < EPS);
        assert!(
            par_80.unwrap().value.is_some(),
            "P@R=0.80 should be achievable"
        );

        let par_90 = m
            .precision_at_recall
            .iter()
            .find(|r| (r.target - 0.90).abs() < EPS);
        assert!(
            par_90.unwrap().value.is_none(),
            "P@R=0.90 should be None (max recall=0.85)"
        );

        let par_95 = m
            .precision_at_recall
            .iter()
            .find(|r| (r.target - 0.95).abs() < EPS);
        assert!(
            par_95.unwrap().value.is_none(),
            "P@R=0.95 should be None (max recall=0.85)"
        );
    }

    #[test]
    fn bootstrap_empty_scored_input() {
        // Empty classified list → (0.0, 0.0).
        let config = BootstrapConfig::default();
        let (lo, hi) = bootstrap_ap_ci(&[], 3, &config);
        assert!(lo.abs() < EPS, "expected 0.0, got {lo}");
        assert!(hi.abs() < EPS, "expected 0.0, got {hi}");
    }

    #[test]
    fn bootstrap_only_unlabeled() {
        // Only Unlabeled items → no TP/FP → (0.0, 0.0).
        let classified = vec![
            item(5, FindingClass::Unlabeled),
            item(4, FindingClass::Unlabeled),
        ];
        let config = BootstrapConfig::default();
        let (lo, hi) = bootstrap_ap_ci(&classified, 3, &config);
        assert!(lo.abs() < EPS, "expected 0.0, got {lo}");
        assert!(hi.abs() < EPS, "expected 0.0, got {hi}");
    }
}
