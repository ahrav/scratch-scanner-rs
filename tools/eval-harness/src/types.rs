//! Core domain types for the eval harness.
//!
//! These types bridge scanner output and ground-truth corpora into a common
//! representation suitable for accuracy measurement (precision, recall,
//! PRC-AUC).

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use scanner_rs::store::canonicalize_path;
use serde::{Deserialize, Serialize};

// ── Scanner output (normalized) ─────────────────────────────────────────

/// A single scanner finding normalized for eval comparison.
///
/// Identity is `(path, byte_start, byte_end, rule)` — `confidence` is
/// intentionally excluded from `Eq`, `Hash`, and `Ord` because the same
/// detection at different confidence levels is still one finding. This
/// prevents inflated PRC-AUC from counting duplicates.
///
/// # Dedup pattern
///
/// After collecting findings, sort and dedup while keeping the highest
/// confidence score:
///
/// ```rust,ignore
/// findings.sort();
/// findings.dedup_by(|a, b| {
///     if a == b {
///         b.confidence = b.confidence.max(a.confidence);
///         true
///     } else {
///         false
///     }
/// });
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedFinding {
    /// Forward-slash normalized path relative to the corpus root.
    pub path: String,
    /// Byte offset of the finding start (inclusive). Matches
    /// `FindingEvent.start` (u64), not `FindingRec.span_start` (u32).
    pub byte_start: u64,
    /// Byte offset of the finding end (exclusive).
    pub byte_end: u64,
    /// Rule name that produced this finding.
    pub rule: String,
    /// Additive confidence score from gate signals. Excluded from identity
    /// comparisons — two findings at the same span with different scores
    /// represent the same detection.
    pub confidence: i8,
}

impl PartialEq for NormalizedFinding {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.byte_start == other.byte_start
            && self.byte_end == other.byte_end
            && self.rule == other.rule
    }
}

impl Eq for NormalizedFinding {}

impl Hash for NormalizedFinding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.byte_start.hash(state);
        self.byte_end.hash(state);
        self.rule.hash(state);
    }
}

impl Ord for NormalizedFinding {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then(self.byte_start.cmp(&other.byte_start))
            .then(self.byte_end.cmp(&other.byte_end))
            .then(self.rule.cmp(&other.rule))
    }
}

impl PartialOrd for NormalizedFinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ── Ground truth ────────────────────────────────────────────────────────

/// A single ground-truth annotation from a labeled corpus (CredData,
/// LeakyRepo, synthetic).
///
/// Uses **line numbers** because CSV corpora annotate by line, not byte
/// offset. The bridge from byte offsets to lines is `LineIndex`
/// (scratch-7i57), not this type's concern.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TruthItem {
    /// Forward-slash normalized path relative to the corpus root.
    pub path: String,
    /// 1-indexed, inclusive start line.
    pub line_start: u32,
    /// 1-indexed, inclusive end line.
    pub line_end: u32,
    /// Ground-truth label for this annotation.
    pub label: TruthLabel,
    /// Rule name this annotation applies to.
    pub rule: String,
}

/// Ground-truth classification for a labeled region.
///
/// Only three states are needed — `TrueNegative` is intentionally absent
/// because in secret scanning the set of true negatives (all file regions
/// that are not secrets and are not flagged) is enormous and unenumerable.
/// PRC-AUC only needs TP, FP, and total positives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TruthLabel {
    /// Should be detected — ground truth says a secret is here.
    Positive,
    /// Should NOT be detected — ground truth explicitly marks this as benign.
    Negative,
    /// Exclude from scoring. Used for test scaffolding or ambiguous
    /// annotations that cannot be confidently labeled either way.
    Placeholder,
}

impl std::fmt::Display for TruthLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Positive => write!(f, "positive"),
            Self::Negative => write!(f, "negative"),
            Self::Placeholder => write!(f, "placeholder"),
        }
    }
}

// ── Match classification ────────────────────────────────────────────────

/// Classification of a scanner finding after matching against ground truth.
///
/// Used by the metrics layer (scratch-96zp) to compute precision, recall,
/// and PRC-AUC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchClass {
    /// Scanner found a secret where ground truth says one exists.
    TruePositive,
    /// Scanner found a secret where ground truth explicitly says none exists
    /// (i.e., the location has a `TruthLabel::Negative` annotation).
    FalsePositive,
    /// Ground truth says a secret exists but scanner did not find it.
    FalseNegative,
    /// Scanner produced a finding at a location with no ground-truth
    /// annotation. Distinct from `FalsePositive`, which requires an
    /// explicit `TruthLabel::Negative` annotation.
    Unlabeled,
}

impl std::fmt::Display for MatchClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruePositive => write!(f, "TP"),
            Self::FalsePositive => write!(f, "FP"),
            Self::FalseNegative => write!(f, "FN"),
            Self::Unlabeled => write!(f, "unlabeled"),
        }
    }
}

// ── Path normalization ──────────────────────────────────────────────────

/// Normalize a path relative to the corpus root for cross-platform comparison.
///
/// Delegates to [`scanner_rs::store::canonicalize_path`] for lexical
/// normalization (backslash to forward-slash, collapse `.`/`..`, strip
/// leading `/`). Then strips the corpus root prefix if present.
///
/// Uses purely lexical normalization — no filesystem access, no symlink
/// resolution. Safe for offline evaluation when corpus files are not present.
pub fn normalize_path(raw: &str, corpus_root: &str) -> String {
    let canonical = canonicalize_path(raw);
    let root = canonicalize_path(corpus_root);
    if root.is_empty() {
        return canonical;
    }
    canonical
        .strip_prefix(root.as_str())
        .and_then(|s| s.strip_prefix('/'))
        .unwrap_or(&canonical)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TruthLabel serde ──────────────────────────────────────

    #[test]
    fn truth_label_serde_roundtrip() {
        for label in [
            TruthLabel::Positive,
            TruthLabel::Negative,
            TruthLabel::Placeholder,
        ] {
            let json = serde_json::to_string(&label).unwrap();
            let back: TruthLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(label, back);
        }
    }

    #[test]
    fn truth_label_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&TruthLabel::Positive).unwrap(),
            r#""positive""#
        );
        assert_eq!(
            serde_json::to_string(&TruthLabel::Negative).unwrap(),
            r#""negative""#
        );
    }

    // ── NormalizedFinding ordering contract ────────────────────

    #[test]
    fn finding_ord_excludes_confidence() {
        let a = NormalizedFinding {
            path: "a.txt".into(),
            byte_start: 10,
            byte_end: 20,
            rule: "r1".into(),
            confidence: 3,
        };
        let b = NormalizedFinding {
            path: "a.txt".into(),
            byte_start: 10,
            byte_end: 20,
            rule: "r1".into(),
            confidence: 7,
        };
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn finding_ord_is_path_start_end_rule() {
        let base = || NormalizedFinding {
            path: "a.txt".into(),
            byte_start: 10,
            byte_end: 20,
            rule: "r1".into(),
            confidence: 5,
        };

        // Primary: path.
        let a = base();
        let mut b = base();
        b.path = "b.txt".into();
        assert!(a < b);

        // Secondary: byte_start.
        let a = base();
        let mut b = base();
        b.byte_start = 20;
        assert!(a < b);

        // Tertiary: byte_end.
        let a = base();
        let mut b = base();
        b.byte_end = 30;
        assert!(a < b);

        // Quaternary: rule.
        let a = base();
        let mut b = base();
        b.rule = "r2".into();
        assert!(a < b);
    }

    // ── normalize_path examples ───────────────────────────────

    #[test]
    fn normalize_strips_corpus_root_prefix() {
        assert_eq!(
            normalize_path("corpus/foo/bar.txt", "corpus"),
            "foo/bar.txt"
        );
    }

    #[test]
    fn normalize_converts_backslashes() {
        assert_eq!(normalize_path("foo\\bar.txt", ""), "foo/bar.txt");
    }

    #[test]
    fn normalize_strips_dot_slash() {
        assert_eq!(normalize_path("./foo/bar.txt", ""), "foo/bar.txt");
    }

    #[test]
    fn normalize_empty_input() {
        assert_eq!(normalize_path("", ""), "");
    }

    // ── normalize_path property tests ─────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn normalize_is_idempotent(raw in "[a-zA-Z0-9_./\\\\]{0,80}") {
                let once = normalize_path(&raw, "");
                let twice = normalize_path(&once, "");
                prop_assert_eq!(&once, &twice);
            }

            #[test]
            fn output_never_contains_backslash(raw in "[a-zA-Z0-9_./\\\\]{0,80}") {
                let result = normalize_path(&raw, "");
                prop_assert!(!result.contains('\\'));
            }

            #[test]
            fn output_never_starts_with_dot_slash(raw in "[a-zA-Z0-9_./\\\\]{0,80}") {
                let result = normalize_path(&raw, "");
                prop_assert!(!result.starts_with("./"));
            }

            #[test]
            fn normalize_is_deterministic(raw in "\\PC{0,120}") {
                let a = normalize_path(&raw, "");
                let b = normalize_path(&raw, "");
                prop_assert_eq!(a, b);
            }
        }
    }
}
