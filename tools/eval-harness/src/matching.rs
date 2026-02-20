//! Finding-to-truth matching for PRC-AUC evaluation.
//!
//! Classifies each [`NormalizedFinding`] against [`TruthItem`] annotations to
//! produce [`FindingClass`] labels (TP, FP, or Unlabeled) that feed into
//! precision/recall computation.
//!
//! # Algorithm
//!
//! Uses confidence-sorted greedy matching, the same strategy as COCO and
//! PASCAL VOC evaluation protocols:
//!
//! 1. Sort findings by confidence descending (deterministic tiebreak via
//!    [`NormalizedFinding::Ord`]).
//! 2. Group truth items by file path, sort each group by `line_start`.
//! 3. For each finding (highest confidence first):
//!    - Convert byte range to line range via [`LineIndex`].
//!    - Binary search for overlapping truth items.
//!    - Apply label priority: Positive > Negative > Placeholder.
//!    - Consume matched Positive truths (one-to-one TP counting).
//!
//! Greedy matching is **required** for valid PRC-AUC: it produces nested TP
//! sets across confidence thresholds, ensuring recall is monotonically
//! non-decreasing as the threshold decreases. Optimal (Hungarian) matching
//! violates this property.
//!
//! # Consumption rules
//!
//! - **Positive** truth items are consumed on match (one-to-one), preventing
//!   metric inflation where multiple findings inflate the TP count.
//! - **Negative** truth items are **not** consumed — they describe regions, not
//!   tokens. Multiple findings at a negative region should all be classified FP.
//! - **Placeholder** truth items are **not** consumed — multiple findings at an
//!   ignore region should all be excluded from scoring (Unlabeled).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::line_index::LineIndex;
use crate::types::{ClassifiedFinding, FindingClass, NormalizedFinding, TruthItem, TruthLabel};
use scanner_rs::stdx::bitset::DynamicBitSet;

/// Configuration for the matching algorithm.
///
/// All fields have sensible defaults for location-only matching. The
/// `require_rule_match` toggle adds an additional constraint when ground
/// truth uses rule-specific annotations (e.g., CredData categories).
#[derive(Clone, Copy, Debug)]
pub struct MatchConfig<'a> {
    /// Corpus root path used for human-readable diagnostics in error
    /// messages. Not consulted during matching logic — all finding and
    /// truth paths must already be normalized via
    /// [`crate::types::normalize_path`] before calling [`match_findings`].
    pub canonical_root: &'a str,

    /// When true, a finding only matches truth items where the finding's
    /// rule name exactly equals one colon-delimited segment of the truth
    /// item's `rule` field (see [`rule_matches`]). When false (default),
    /// matching is purely location-based — any finding overlapping a truth
    /// item's line range is considered a match regardless of rule name.
    pub require_rule_match: bool,
}

/// Result of matching findings against ground truth.
///
/// Carries both the per-finding classification and the unmatched positive
/// truths (false negatives). Together these provide everything needed for
/// precision/recall computation and PRC-AUC curve generation.
///
/// # Counting invariants
///
/// These hold for every valid result and are enforced by hard assertions
/// inside [`match_findings`]:
///
/// Every input finding is classified into exactly one bucket:
/// ```text
/// classified.len() == input_findings.len()
/// tp_count() + fp_count() + unlabeled_count() == classified.len() as u64
/// ```
///
/// Every positive truth item is either matched or a false negative:
/// ```text
/// tp_count() + fn_count() == total positive truth items
/// ```
///
/// # Diagnostic counters
///
/// The three `u64` counters (`unmatched_finding_paths`, `unmatchable_truth_paths`,
/// `out_of_bounds_findings`) are diagnostic signals, not error codes. Non-zero
/// values indicate data quality issues (stale scanner output, missing corpus
/// files, incomplete annotations) rather than matching bugs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Every input finding, classified as TP, FP, or Unlabeled.
    /// Order: confidence descending, then by [`NormalizedFinding::Ord`]
    /// tiebreak. This ordering is required by downstream PRC-AUC
    /// computation, which sweeps a threshold from high to low confidence.
    pub classified: Vec<ClassifiedFinding>,

    /// Positive truth items that no finding matched. These represent
    /// secrets the scanner failed to detect. Negative and Placeholder
    /// truths are never included here — only Positive labels contribute
    /// to recall.
    pub false_negatives: Vec<TruthItem>,

    /// Findings on paths with no corresponding truth entries at all.
    /// These findings are classified as Unlabeled because there is no
    /// annotation to compare against — they are neither penalized nor
    /// rewarded.
    pub unmatched_finding_paths: u64,

    /// Truth paths for which no file contents were provided. Without file
    /// bytes, [`LineIndex`] cannot be built, so truth items on these paths
    /// cannot participate in matching. Affected truth items with Positive
    /// labels will appear in `false_negatives`.
    pub unmatchable_truth_paths: u64,

    /// Findings whose `byte_end` exceeds the file size reported by
    /// [`LineIndex`]. Typically caused by stale scanner output run against
    /// a file that was subsequently truncated. Classified as Unlabeled.
    pub out_of_bounds_findings: u64,
}

impl MatchResult {
    /// Number of findings classified as True Positive (matched a Positive
    /// truth annotation). Bounded above by the total positive truth count.
    pub fn tp_count(&self) -> u64 {
        self.classified
            .iter()
            .filter(|c| c.class == FindingClass::TruePositive)
            .count() as u64
    }

    /// Number of findings classified as False Positive (matched a Negative
    /// truth annotation). Non-zero only when Negative truth items exist in
    /// the corpus.
    pub fn fp_count(&self) -> u64 {
        self.classified
            .iter()
            .filter(|c| c.class == FindingClass::FalsePositive)
            .count() as u64
    }

    /// Number of Positive truth items not matched by any finding (false
    /// negatives). Equivalent to `false_negatives.len()`.
    pub fn fn_count(&self) -> u64 {
        self.false_negatives.len() as u64
    }

    /// Findings excluded from scoring: either no annotation at their
    /// location, or matched a Placeholder. These do not affect precision
    /// or recall.
    pub fn unlabeled_count(&self) -> u64 {
        self.classified
            .iter()
            .filter(|c| c.class == FindingClass::Unlabeled)
            .count() as u64
    }

    /// Total ground-truth positive count: `tp_count() + fn_count()`.
    /// This is the denominator for recall computation.
    pub fn total_positives(&self) -> u64 {
        self.tp_count() + self.fn_count()
    }
}

/// Classify findings against truth items using position-based matching.
///
/// Pure function — no I/O. Caller provides file contents for [`LineIndex`]
/// construction. Findings and truth items must have paths already
/// normalized via [`crate::types::normalize_path`].
///
/// The output `classified` list is ordered by confidence descending (then by
/// [`NormalizedFinding::Ord`] for ties). Pass it to
/// [`crate::metrics::compute_metrics`] to obtain PRC-AUC and F1.
///
/// # Panics
///
/// Panics (hard `assert!`, not debug-only) if the conservation invariants
/// are violated after classification:
///
/// - `tp + fp + unlabeled != findings.len()`
/// - `tp + fn != total positive truth items`
/// - `consumed positive count != tp`
///
/// These indicate a logic bug in the matching algorithm, not bad input.
///
/// # Complexity
///
/// `O(F log F + T log T + B + sum_f(F_f * C_f) + T)` where F = findings,
/// T = truth items, B = total file bytes, F_f = findings in file f,
/// C_f = candidate truths scanned per finding (bounded by T_f, the truth
/// count in file f). Adequate for F up to 100K and T up to 200K spread
/// across thousands of files.
pub fn match_findings(
    findings: &[NormalizedFinding],
    truth: &[TruthItem],
    file_contents: &HashMap<String, Vec<u8>>,
    config: MatchConfig<'_>,
) -> MatchResult {
    // ── Precondition: findings are deduplicated ────────────────────
    debug_assert!(
        findings.windows(2).all(|w| w[0] != w[1]),
        "findings must be deduplicated before matching"
    );

    // ── Sort findings by (-confidence, identity) ──────────────────
    let mut sorted_indices: Vec<usize> = (0..findings.len()).collect();
    sorted_indices.sort_by(|&a, &b| {
        // Descending confidence via reverse comparison — never negate i8
        // (i8::MIN overflow wraps silently in release mode).
        findings[b]
            .confidence
            .cmp(&findings[a].confidence)
            .then_with(|| findings[a].cmp(&findings[b]))
    });

    // Sort postcondition.
    debug_assert!(
        sorted_indices
            .windows(2)
            .all(|w| findings[w[0]].confidence >= findings[w[1]].confidence),
        "sort must produce confidence-descending order"
    );

    // ── Group truth by file path, sort by line_start ──────────────
    let mut truth_by_file: HashMap<&str, Vec<(usize, &TruthItem)>> = HashMap::new();
    for (idx, item) in truth.iter().enumerate() {
        truth_by_file
            .entry(item.path.as_str())
            .or_default()
            .push((idx, item));
    }
    for group in truth_by_file.values_mut() {
        group.sort_by_key(|(_, t)| t.line_start);
    }

    // ── Build LineIndex cache + diagnostics ────────────────────────
    // Only truth-referenced paths need a LineIndex. Iterating truth_by_file
    // keys (not file_contents keys) ensures line_indices is a subset of
    // truth_by_file — classify_one_finding relies on this to distinguish
    // "no truth for this path" from "truth exists but file is missing".
    let mut line_indices: HashMap<&str, LineIndex> = HashMap::new();
    let mut unmatchable_truth_paths: u64 = 0;
    for path in truth_by_file.keys() {
        if let Some(bytes) = file_contents.get(*path) {
            line_indices.insert(path, LineIndex::new(bytes));
        } else {
            unmatchable_truth_paths += 1;
        }
    }

    // ── Global consumed-truth bitset (Positive truths only) ───────
    let mut consumed = DynamicBitSet::empty(truth.len());

    // ── Per-finding classification ────────────────────────────────
    let mut classified = Vec::with_capacity(findings.len());
    let mut unmatched_finding_paths: u64 = 0;
    let mut out_of_bounds_findings: u64 = 0;

    for &finding_idx in &sorted_indices {
        let finding = &findings[finding_idx];

        let class = classify_one_finding(
            finding,
            &truth_by_file,
            &line_indices,
            &mut consumed,
            &config,
            &mut unmatched_finding_paths,
            &mut out_of_bounds_findings,
        );

        classified.push(ClassifiedFinding {
            finding: finding.clone(),
            class,
        });
    }

    // ── Collect false negatives ───────────────────────────────────
    let false_negatives: Vec<TruthItem> = truth
        .iter()
        .enumerate()
        .filter(|(idx, item)| item.label == TruthLabel::Positive && !consumed.is_set(*idx))
        .map(|(_, item)| item.clone())
        .collect();

    // ── Conservation assertions ───────────────────────────────────
    // Three independent checks verify that the matching loop neither
    // dropped nor duplicated any finding or truth item:
    //   1. Finding partition: every finding lands in exactly one bucket.
    //   2. Truth partition: every Positive truth is either matched (TP)
    //      or unmatched (FN).
    //   3. Bitset cross-check: consumed bits agree with TP count,
    //      catching bugs where a Positive was consumed without producing
    //      a TP classification or vice versa.
    let tp = classified
        .iter()
        .filter(|c| c.class == FindingClass::TruePositive)
        .count() as u64;
    let fp = classified
        .iter()
        .filter(|c| c.class == FindingClass::FalsePositive)
        .count() as u64;
    let unlabeled = classified
        .iter()
        .filter(|c| c.class == FindingClass::Unlabeled)
        .count() as u64;
    let total_positives = truth
        .iter()
        .filter(|t| t.label == TruthLabel::Positive)
        .count() as u64;

    assert_eq!(
        tp + fp + unlabeled,
        findings.len() as u64,
        "finding count conservation"
    );
    assert_eq!(
        tp + false_negatives.len() as u64,
        total_positives,
        "truth count conservation"
    );

    // Cross-check: the number of Positive truths with their consumed bit set
    // must equal the TP count. A mismatch means a Positive was consumed without
    // incrementing TP, or vice versa — both indicate a bug in the matching loop.
    let consumed_positives = truth
        .iter()
        .enumerate()
        .filter(|(idx, t)| t.label == TruthLabel::Positive && consumed.is_set(*idx))
        .count() as u64;
    assert_eq!(
        consumed_positives, tp,
        "consumed positive count must equal TP"
    );

    MatchResult {
        classified,
        false_negatives,
        unmatched_finding_paths,
        unmatchable_truth_paths,
        out_of_bounds_findings,
    }
}

/// Classify a single finding against the truth index.
///
/// This is the per-finding core of the matching algorithm. For each finding,
/// it resolves byte offsets to line numbers, searches for overlapping truth
/// items via binary search, and selects the highest-priority match using
/// the label precedence Positive > Negative > Placeholder.
///
/// # Side effects
///
/// - **`consumed`**: Sets the bit for any matched Positive truth item
///   (one-to-one consumption). Negative and Placeholder bits are never set.
/// - **`unmatched_finding_paths`**: Incremented when the finding's path
///   has no corresponding truth entries (distinct from "truth exists but
///   file contents are missing", which is counted separately as
///   `unmatchable_truth_paths` in the caller).
/// - **`out_of_bounds_findings`**: Incremented when `byte_end` exceeds
///   the file size, indicating stale scanner output.
///
/// # Early-return paths
///
/// Returns [`FindingClass::Unlabeled`] early (without scanning truths) in
/// three cases:
///
/// 1. No [`LineIndex`] for this path — either no file contents were
///    provided, or no truth items reference this file.
/// 2. Byte offsets exceed file size (out-of-bounds).
/// 3. No truth items exist for this file path.
///
/// In all early-return cases, the finding cannot affect TP or FP counts.
fn classify_one_finding(
    finding: &NormalizedFinding,
    truth_by_file: &HashMap<&str, Vec<(usize, &TruthItem)>>,
    line_indices: &HashMap<&str, LineIndex>,
    consumed: &mut DynamicBitSet,
    config: &MatchConfig<'_>,
    unmatched_finding_paths: &mut u64,
    out_of_bounds_findings: &mut u64,
) -> FindingClass {
    // 1. Get LineIndex for this file. A missing LineIndex means either:
    //    (a) no truth items reference this path → count as unmatched, or
    //    (b) truth items exist but file_contents lacks the bytes → already
    //        counted as unmatchable_truth_paths by the caller.
    //    Only case (a) increments unmatched_finding_paths — case (b) is a
    //    file-supply issue, not a coverage gap.
    let Some(line_index) = line_indices.get(finding.path.as_str()) else {
        if !truth_by_file.contains_key(finding.path.as_str()) {
            *unmatched_finding_paths += 1;
        }
        return FindingClass::Unlabeled;
    };

    // 2. Validate byte offsets against file size. Out-of-bounds findings
    //    indicate stale scanner output or a truncated file read — diagnosable
    //    via the out_of_bounds_findings counter, but not a programming error.
    if finding.byte_end > line_index.data_len() as u64 {
        *out_of_bounds_findings += 1;
        return FindingClass::Unlabeled;
    }

    // 3. Convert byte range to line range.
    let (f_start, f_end) = line_index.line_range(finding.byte_start, finding.byte_end);

    // 4. Look up this file's truth items. Because line_indices is built
    //    only from truth_by_file keys (see caller), reaching here implies
    //    truth_by_file has an entry for this path. The None branch is
    //    retained defensively but should be unreachable in practice.
    let file_truths = match truth_by_file.get(finding.path.as_str()) {
        Some(truths) => truths.as_slice(),
        None => {
            *unmatched_finding_paths += 1;
            return FindingClass::Unlabeled;
        }
    };

    // Upper bound: first truth with line_start > f_end.
    // This predicate is SOUND on line_start-sorted data because line_start
    // is monotonically non-decreasing. The naive alternative —
    // `partition_point(|t| t.line_end < f_start)` — is UNSOUND because
    // line_end is NOT monotonic when truths are sorted by line_start
    // (e.g., [(1,10), (2,3)] has line_end = [10,3]).
    let upper = file_truths.partition_point(|(_, t)| t.line_start <= f_end);

    // Binary search postcondition.
    debug_assert!(
        file_truths[..upper]
            .iter()
            .all(|(_, t)| t.line_start <= f_end)
    );
    debug_assert!(
        file_truths[upper..]
            .iter()
            .all(|(_, t)| t.line_start > f_end)
    );

    // 5. Scan candidates for the first overlapping truth of each label.
    //    We track the first match per label rather than breaking early so
    //    that label priority (Positive > Negative > Placeholder) is resolved
    //    after scanning, not during. This avoids order-dependent bugs where
    //    a Negative encountered before a Positive would shadow it.
    let mut best_positive: Option<usize> = None;
    let mut best_negative: Option<usize> = None;
    let mut best_placeholder: Option<usize> = None;

    for &(truth_idx, truth_item) in &file_truths[..upper] {
        // No overlap: truth ends before finding starts.
        if truth_item.line_end < f_start {
            continue;
        }

        // Only check consumed for Positive truths — Negative/Placeholder
        // describe regions and are reusable across multiple findings.
        if truth_item.label == TruthLabel::Positive && consumed.is_set(truth_idx) {
            continue;
        }

        // Rule matching (optional).
        if config.require_rule_match && !rule_matches(&finding.rule, &truth_item.rule) {
            continue;
        }

        match truth_item.label {
            TruthLabel::Positive => {
                if best_positive.is_none() {
                    best_positive = Some(truth_idx);
                }
            }
            TruthLabel::Negative => {
                if best_negative.is_none() {
                    best_negative = Some(truth_idx);
                }
            }
            TruthLabel::Placeholder => {
                if best_placeholder.is_none() {
                    best_placeholder = Some(truth_idx);
                }
            }
        }
    }

    // 6. Classify with label priority — only consume Positive.
    if let Some(idx) = best_positive {
        debug_assert!(!consumed.is_set(idx), "truth item {} already consumed", idx);
        consumed.set(idx);
        debug_assert!(consumed.is_set(idx));
        FindingClass::TruePositive
    } else if best_negative.is_some() {
        FindingClass::FalsePositive
    } else {
        // Both Placeholder match and no match produce Unlabeled.
        // Placeholder = "exclude from scoring"; no match = "no annotation".
        FindingClass::Unlabeled
    }
}

/// Check if a finding's rule matches a truth item's rule field.
///
/// Truth rules from CredData use colon-separated category hierarchies
/// (e.g., `"Secret:Token"` → segments `["Secret", "Token"]`). Finding
/// rules are flat scanner-rs names (e.g., `"slack-bot-token"`). This
/// function returns true if `finding_rule` exactly equals any segment
/// after splitting `truth_rule` on `':'`.
///
/// Matching is case-sensitive and requires an exact segment match —
/// substring matches within a segment do not count (e.g., `"Tok"` does
/// not match the `"Token"` segment).
///
/// If `truth_rule` contains no colons, it is treated as a single segment
/// and the comparison reduces to `finding_rule == truth_rule`.
fn rule_matches(finding_rule: &str, truth_rule: &str) -> bool {
    truth_rule.split(':').any(|segment| segment == finding_rule)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_finding(
        path: &str,
        byte_start: u64,
        byte_end: u64,
        rule: &str,
        conf: i8,
    ) -> NormalizedFinding {
        NormalizedFinding::new(path.into(), byte_start, byte_end, rule.into(), conf)
    }

    fn make_truth(
        path: &str,
        line_start: u32,
        line_end: u32,
        label: TruthLabel,
        rule: &str,
    ) -> TruthItem {
        TruthItem::new(path.into(), line_start, line_end, label, rule.into())
    }

    fn default_config() -> MatchConfig<'static> {
        MatchConfig {
            canonical_root: "",
            require_rule_match: false,
        }
    }

    /// Create file_contents map from (path, content) pairs.
    fn contents(entries: &[(&str, &[u8])]) -> HashMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_vec()))
            .collect()
    }

    // ── Unit tests ──────────────────────────────────────────────────

    // Simple file: "aaaa\nbbbb\ncccc\n" => 3 lines, 15 bytes
    // Line 1: bytes 0-4 ("aaaa\n"), Line 2: bytes 5-9 ("bbbb\n"), Line 3: bytes 10-14 ("cccc\n")
    const SIMPLE_FILE: &[u8] = b"aaaa\nbbbb\ncccc\n";
    const SIMPLE_PATH: &str = "f.txt";

    #[test]
    fn single_finding_classification() {
        // Each truth label maps to exactly one finding class.
        let cases = [
            (TruthLabel::Positive, FindingClass::TruePositive),
            (TruthLabel::Negative, FindingClass::FalsePositive),
            (TruthLabel::Placeholder, FindingClass::Unlabeled),
        ];
        for (label, expected_class) in cases {
            let findings = [make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
            let truth = [make_truth(SIMPLE_PATH, 1, 1, label, "r")];
            let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

            let result = match_findings(&findings, &truth, &fc, default_config());
            assert_eq!(result.classified.len(), 1);
            assert_eq!(
                result.classified[0].class, expected_class,
                "label={label:?} should produce {expected_class:?}"
            );
        }
    }

    #[test]
    fn no_overlap() {
        // Finding on line 1, truth on line 3 — no overlap.
        let findings = [make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = [make_truth(SIMPLE_PATH, 3, 3, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn no_truth_file() {
        // Finding on a path with no truth items at all.
        let findings = [make_finding("other.txt", 0, 3, "r", 5)];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE), ("other.txt", b"abc")]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.unmatched_finding_paths, 1);
    }

    #[test]
    fn no_file_contents() {
        // Finding on a path with no file contents.
        let findings = [make_finding("missing.txt", 0, 3, "r", 5)];
        let truth: [TruthItem; 0] = [];
        let fc: HashMap<String, Vec<u8>> = HashMap::new();

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
    }

    #[test]
    fn label_priority_positive_wins() {
        // Finding overlaps both Positive (line 1) and Negative (line 1).
        // Positive takes priority. Negative is NOT consumed.
        let findings = [make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = [
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Negative, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result.false_negatives.len(), 0);
    }

    #[test]
    fn label_priority_placeholder_last() {
        // Finding overlaps Positive and Placeholder — Positive wins.
        let findings = [make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = [
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Placeholder, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn one_to_one_consumption() {
        // Two findings overlap the same Positive truth.
        // Higher confidence (10) gets TP, lower (5) gets Unlabeled.
        let findings = [
            make_finding(SIMPLE_PATH, 0, 4, "r", 10),
            make_finding(SIMPLE_PATH, 1, 4, "r", 5),
        ];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        // First in output is the higher-confidence one.
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result.classified[1].class, FindingClass::Unlabeled);
    }

    #[test]
    fn confidence_ordering() {
        // Lower confidence (3) listed first in input, but higher (8) should
        // get the TP because it's processed first in confidence order.
        let findings = [
            make_finding(SIMPLE_PATH, 0, 4, "r1", 3),
            make_finding(SIMPLE_PATH, 0, 4, "r2", 8),
        ];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        // The confidence-8 finding should be TP.
        let tp_finding = result
            .classified
            .iter()
            .find(|c| c.class == FindingClass::TruePositive)
            .unwrap();
        assert_eq!(tp_finding.finding.confidence, 8);
    }

    #[test]
    fn byte_offset_out_of_bounds() {
        let findings = [make_finding(SIMPLE_PATH, 0, 9999, "r", 5)];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.out_of_bounds_findings, 1);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn zero_width_finding() {
        // byte_start == byte_end — zero-width finding at start of line 1.
        let findings = [make_finding(SIMPLE_PATH, 0, 0, "r", 5)];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn rule_match_colon_split() {
        let findings = [make_finding(SIMPLE_PATH, 0, 4, "Token", 5)];
        let truth = [make_truth(
            SIMPLE_PATH,
            1,
            1,
            TruthLabel::Positive,
            "Secret:Token",
        )];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);
        let config = MatchConfig {
            canonical_root: "",
            require_rule_match: true,
        };

        let result = match_findings(&findings, &truth, &fc, config);
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn rule_match_disabled() {
        // Different rules but require_rule_match=false — still matches.
        let findings = [make_finding(SIMPLE_PATH, 0, 4, "scanner-rule", 5)];
        let truth = [make_truth(
            SIMPLE_PATH,
            1,
            1,
            TruthLabel::Positive,
            "CredDataCategory",
        )];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn fn_collection() {
        // No findings — all Positive truths become false negatives.
        let findings: [NormalizedFinding; 0] = [];
        let truth = [
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 2, 2, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 3, 3, TruthLabel::Negative, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.false_negatives.len(), 2);
        assert!(
            result
                .false_negatives
                .iter()
                .all(|t| t.label == TruthLabel::Positive)
        );
    }

    #[test]
    fn empty_inputs() {
        let result = match_findings(&[], &[], &HashMap::new(), default_config());
        assert!(result.classified.is_empty());
        assert!(result.false_negatives.is_empty());
        assert_eq!(result.unmatched_finding_paths, 0);
        assert_eq!(result.unmatchable_truth_paths, 0);
        assert_eq!(result.out_of_bounds_findings, 0);
    }

    // ── New tests from research ─────────────────────────────────────

    #[test]
    fn multi_line_partial_overlap() {
        // Finding spans lines 1-2 (bytes 0-9), truth covers lines 2-3.
        // Overlap at line 2 — should match.
        let findings = [make_finding(SIMPLE_PATH, 0, 10, "r", 5)];
        let truth = [make_truth(SIMPLE_PATH, 2, 3, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn non_consumed_truth_reusable() {
        // Negative and Placeholder truths are not consumed — multiple
        // findings at the same region all receive the same classification.
        let cases = [
            (TruthLabel::Negative, FindingClass::FalsePositive),
            (TruthLabel::Placeholder, FindingClass::Unlabeled),
        ];
        for (label, expected_class) in cases {
            let findings = [
                make_finding(SIMPLE_PATH, 0, 4, "r1", 10),
                make_finding(SIMPLE_PATH, 1, 4, "r2", 5),
            ];
            let truth = [make_truth(SIMPLE_PATH, 1, 1, label, "r")];
            let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

            let result = match_findings(&findings, &truth, &fc, default_config());
            assert_eq!(
                result.classified[0].class, expected_class,
                "label={label:?}"
            );
            assert_eq!(
                result.classified[1].class, expected_class,
                "label={label:?}"
            );
        }
    }

    #[test]
    fn confidence_tie_determinism() {
        // Two findings with identical confidence compete for the same truth.
        // The one with lower identity (Ord) should win deterministically.
        let findings = [
            make_finding(SIMPLE_PATH, 0, 4, "r1", 5), // identity: ("f.txt", 0, 4, "r1")
            make_finding(SIMPLE_PATH, 0, 4, "r2", 5), // identity: ("f.txt", 0, 4, "r2")
        ];
        let truth = [make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result1 = match_findings(&findings, &truth, &fc, default_config());
        let result2 = match_findings(&findings, &truth, &fc, default_config());

        // Deterministic: same output both times.
        assert_eq!(result1.classified[0].class, result2.classified[0].class);
        assert_eq!(result1.classified[1].class, result2.classified[1].class);

        // "r1" < "r2" in Ord, so r1 is processed first and gets TP.
        assert_eq!(result1.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result1.classified[0].finding.rule, "r1");
    }

    #[test]
    fn finding_spans_entire_file() {
        // Finding covers the entire file.
        let findings = [make_finding(
            SIMPLE_PATH,
            0,
            SIMPLE_FILE.len() as u64,
            "r",
            5,
        )];
        let truth = [make_truth(SIMPLE_PATH, 2, 2, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(&findings, &truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    // ── rule_matches helper tests ───────────────────────────────────

    #[test]
    fn rule_matches_cases() {
        let cases = [
            ("Token", "Token", true),         // exact match
            ("Token", "Secret:Token", true),  // colon-split match (suffix)
            ("Secret", "Secret:Token", true), // colon-split match (prefix)
            ("Other", "Secret:Token", false), // no segment match
            ("Tok", "Secret:Token", false),   // partial segment (not substring)
        ];
        for (finding_rule, truth_rule, expected) in cases {
            assert_eq!(
                rule_matches(finding_rule, truth_rule),
                expected,
                "rule_matches({finding_rule:?}, {truth_rule:?})"
            );
        }
    }

    // ── Property tests ──────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        /// Generate a small file with known content (1-200 bytes).
        fn file_bytes() -> impl Strategy<Value = Vec<u8>> {
            prop_oneof![
                // Lines of varying length with newlines.
                proptest::collection::vec(prop_oneof![Just(b'\n'), Just(b'x')], 1..200),
                // Single long line.
                proptest::collection::vec(Just(b'x'), 1..200),
            ]
        }

        /// Generate a valid truth item for a file with the given line count.
        fn truth_item_for(path: String, line_count: u32) -> impl Strategy<Value = TruthItem> {
            (
                1..=line_count,
                prop_oneof![
                    Just(TruthLabel::Positive),
                    Just(TruthLabel::Negative),
                    Just(TruthLabel::Placeholder),
                ],
                prop_oneof![Just("r1".to_string()), Just("r2".to_string())],
            )
                .prop_flat_map(move |(start, label, rule)| {
                    let p = path.clone();
                    (start..=line_count).prop_map(move |end| {
                        TruthItem::new(p.clone(), start, end, label, rule.clone())
                    })
                })
        }

        /// Generate a valid finding for a file with the given byte length.
        fn finding_for(path: String, data_len: u64) -> impl Strategy<Value = NormalizedFinding> {
            (
                0..data_len.max(1),
                -128i8..=127i8,
                prop_oneof![Just("r1".to_string()), Just("r2".to_string())],
            )
                .prop_flat_map(move |(start, conf, rule)| {
                    let p = path.clone();
                    (start..=data_len).prop_map(move |end| {
                        NormalizedFinding::new(p.clone(), start, end, rule.clone(), conf)
                    })
                })
        }

        /// Full test scenario: files + truth + findings.
        #[derive(Debug, Clone)]
        struct Scenario {
            file_contents: HashMap<String, Vec<u8>>,
            truth: Vec<TruthItem>,
            findings: Vec<NormalizedFinding>,
        }

        fn scenario() -> impl Strategy<Value = Scenario> {
            // 1-3 files, each 1-200 bytes.
            proptest::collection::vec(file_bytes(), 1..=3).prop_flat_map(|files| {
                let paths: Vec<String> = (0..files.len()).map(|i| format!("f{i}.txt")).collect();
                let file_contents: HashMap<String, Vec<u8>> =
                    paths.iter().cloned().zip(files.iter().cloned()).collect();

                // Build line indices to know valid ranges.
                let line_counts: Vec<u32> = files
                    .iter()
                    .map(|f| LineIndex::new(f).line_count())
                    .collect();
                let data_lens: Vec<u64> = files.iter().map(|f| f.len() as u64).collect();

                // Generate truth items (0-10 per file).
                let truth_strats: Vec<_> = paths
                    .iter()
                    .zip(line_counts.iter())
                    .map(|(p, &lc)| {
                        proptest::collection::vec(truth_item_for(p.clone(), lc), 0..=10)
                    })
                    .collect();

                // Generate findings (0-10 per file).
                let finding_strats: Vec<_> = paths
                    .iter()
                    .zip(data_lens.iter())
                    .map(|(p, &dl)| proptest::collection::vec(finding_for(p.clone(), dl), 0..=10))
                    .collect();

                (truth_strats, finding_strats).prop_map(move |(truth_groups, finding_groups)| {
                    let mut truth: Vec<TruthItem> = truth_groups.into_iter().flatten().collect();
                    let mut findings: Vec<NormalizedFinding> =
                        finding_groups.into_iter().flatten().collect();

                    // Dedup findings (matching requires deduped input).
                    findings.sort();
                    findings.dedup_by(|a, b| {
                        if a == b {
                            b.confidence = b.confidence.max(a.confidence);
                            true
                        } else {
                            false
                        }
                    });

                    // Dedup truth (same location, same label = same item).
                    truth.sort_by(|a, b| {
                        a.path
                            .cmp(&b.path)
                            .then(a.line_start.cmp(&b.line_start))
                            .then(a.line_end.cmp(&b.line_end))
                            .then(a.rule.cmp(&b.rule))
                    });
                    truth.dedup_by(|a, b| {
                        a.path == b.path
                            && a.line_start == b.line_start
                            && a.line_end == b.line_end
                            && a.rule == b.rule
                            && a.label == b.label
                    });

                    Scenario {
                        file_contents: file_contents.clone(),
                        truth,
                        findings,
                    }
                })
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// P1: Finding count conservation.
            #[test]
            fn conservation_finding_count(s in scenario()) {
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                prop_assert_eq!(
                    result.tp_count() + result.fp_count() + result.unlabeled_count(),
                    s.findings.len() as u64,
                    "tp+fp+unlabeled != findings.len()"
                );
            }

            /// P2: Truth count conservation.
            #[test]
            fn conservation_truth_count(s in scenario()) {
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;
                prop_assert_eq!(
                    result.tp_count() + result.fn_count(),
                    total_positives,
                    "tp+fn != total_positives"
                );
            }

            /// P3: Determinism.
            #[test]
            fn determinism(s in scenario()) {
                let r1 = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                let r2 = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                prop_assert_eq!(r1.classified.len(), r2.classified.len());
                for (a, b) in r1.classified.iter().zip(r2.classified.iter()) {
                    prop_assert_eq!(a.class, b.class);
                    prop_assert_eq!(&a.finding, &b.finding);
                }
                prop_assert_eq!(r1.false_negatives.len(), r2.false_negatives.len());
            }

            /// P4: One-to-one — no Positive truth consumed by two findings.
            #[test]
            fn one_to_one(s in scenario()) {
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                // TP count must not exceed total positive truths.
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;
                prop_assert!(
                    result.tp_count() <= total_positives,
                    "more TPs ({}) than positive truths ({})",
                    result.tp_count(), total_positives
                );
            }

            /// P5: Path isolation.
            #[test]
            fn path_isolation(
                file_a in file_bytes(),
                file_b in file_bytes(),
                conf in -128i8..=127i8,
            ) {
                prop_assume!(!file_a.is_empty() && !file_b.is_empty());
                let idx_b = LineIndex::new(&file_b);

                // Finding on "a.txt", truth on "b.txt".
                let findings = [NormalizedFinding::new(
                    "a.txt".into(), 0, file_a.len() as u64, "r".into(), conf,
                )];
                let truth = [TruthItem::new(
                    "b.txt".into(), 1, idx_b.line_count(), TruthLabel::Positive, "r".into(),
                )];
                let fc = contents(&[
                    ("a.txt", &file_a),
                    ("b.txt", &file_b),
                ]);

                let result = match_findings(&findings, &truth, &fc, default_config());
                prop_assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
                prop_assert_eq!(result.false_negatives.len(), 1);
            }

            /// P6: Label consistency — TP only from Positive truth, FP only from Negative.
            #[test]
            fn label_consistency_no_tp_from_negative(s in scenario()) {
                // If there are no Positive truths, there should be no TP.
                let has_positive = s.truth.iter().any(|t| t.label == TruthLabel::Positive);
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                if !has_positive {
                    prop_assert_eq!(
                        result.tp_count(), 0,
                        "TP found with no positive truths"
                    );
                }
            }

            /// P7: Negative truths never produce TP.
            #[test]
            fn negative_never_tp(s in scenario()) {
                // If all truths are Negative, TP must be 0.
                let all_negative = s.truth.iter().all(|t| t.label == TruthLabel::Negative);
                if all_negative {
                    let result = match_findings(
                        &s.findings, &s.truth, &s.file_contents, default_config(),
                    );
                    prop_assert_eq!(result.tp_count(), 0, "TP from Negative-only truths");
                }
            }

            /// P8: Placeholder neutrality — removing Placeholders doesn't change TP or FP.
            #[test]
            fn placeholder_neutrality(s in scenario()) {
                let result_with = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                let truth_no_placeholder: Vec<TruthItem> = s.truth.iter()
                    .filter(|t| t.label != TruthLabel::Placeholder)
                    .cloned()
                    .collect();
                let result_without = match_findings(
                    &s.findings, &truth_no_placeholder, &s.file_contents, default_config(),
                );
                prop_assert_eq!(
                    result_with.tp_count(), result_without.tp_count(),
                    "placeholder removal changed TP count"
                );
                prop_assert_eq!(
                    result_with.fp_count(), result_without.fp_count(),
                    "placeholder removal changed FP count"
                );
            }

            /// P9: FP bounded by Negative truth count.
            #[test]
            fn fp_bounded_by_negatives(s in scenario()) {
                // With require_rule_match=false, each finding can match any
                // negative in its file. But FP count can exceed negative count
                // when negatives are not consumed. So the property is:
                // fp_count > 0 implies at least one negative truth exists.
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                let has_negative = s.truth.iter().any(|t| t.label == TruthLabel::Negative);
                if !has_negative {
                    prop_assert_eq!(
                        result.fp_count(), 0,
                        "FP without any Negative truths"
                    );
                }
            }

            /// P10: Recall monotonicity (nested TP sets for valid PRC-AUC).
            ///
            /// Walking the confidence-sorted classified list, cumulative recall
            /// must never decrease. This is the defining property of greedy
            /// matching with confidence ordering.
            #[test]
            fn recall_monotonicity(s in scenario()) {
                let result = match_findings(
                    &s.findings, &s.truth, &s.file_contents, default_config(),
                );
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;

                if total_positives == 0 {
                    return Ok(());
                }

                // Classified list is in confidence-descending order.
                // Walk it, accumulating TP count. Recall = cumulative_tp / total_positives.
                let mut cumulative_tp: u64 = 0;
                let mut prev_recall: f64 = 0.0;

                for cf in &result.classified {
                    if cf.class == FindingClass::TruePositive {
                        cumulative_tp += 1;
                    }
                    let recall = cumulative_tp as f64 / total_positives as f64;
                    prop_assert!(
                        recall >= prev_recall,
                        "recall decreased from {} to {} at confidence {}",
                        prev_recall, recall, cf.finding.confidence
                    );
                    prev_recall = recall;
                }
            }
        }
    }
}
