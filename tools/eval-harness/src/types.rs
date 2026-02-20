//! Core domain types for the eval harness.
//!
//! These types bridge scanner output and ground-truth corpora into a common
//! representation suitable for accuracy measurement (precision, recall,
//! PRC-AUC). The evaluation pipeline has three phases:
//!
//! 1. **Normalize** — Scanner output is converted into [`NormalizedFinding`]
//!    records keyed by `(path, byte_start, byte_end, rule)`. Duplicate
//!    findings at the same location are collapsed, retaining the highest
//!    confidence score.
//!
//! 2. **Load ground truth** — Labeled corpora (CredData, LeakyRepo, synthetic
//!    datasets) are loaded as [`TruthItem`] records using line-number
//!    coordinates. A separate line-index layer converts between byte offsets
//!    and line numbers so findings and truth items can be compared.
//!
//! 3. **Classify** — Each finding is matched against truth items to produce a
//!    [`MatchClass`] (TP, FP, FN, or unlabeled). These classifications feed
//!    into precision/recall computation and PRC-AUC curves at varying
//!    confidence thresholds.
//!
//! All paths flowing through these types must be normalized via
//! [`normalize_path`] to ensure cross-platform comparability (forward slashes,
//! no `.`/`..`, corpus-root prefix stripped).

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

/// Identity comparison: two findings are equal iff they share the same
/// `(path, byte_start, byte_end, rule)` tuple. `confidence` is deliberately
/// excluded so that the same detection at different score levels collapses
/// to one entry during dedup.
impl PartialEq for NormalizedFinding {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.byte_start == other.byte_start
            && self.byte_end == other.byte_end
            && self.rule == other.rule
    }
}

impl Eq for NormalizedFinding {}

/// Hashes the same four identity fields as [`PartialEq`] to maintain the
/// invariant that `a == b` implies `hash(a) == hash(b)`. This allows
/// `NormalizedFinding` to be used in `HashSet`/`HashMap` for dedup without
/// confidence interfering with bucket assignment.
impl Hash for NormalizedFinding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.byte_start.hash(state);
        self.byte_end.hash(state);
        self.rule.hash(state);
    }
}

/// Lexicographic ordering over `(path, byte_start, byte_end, rule)`.
/// Consistent with [`Eq`] -- findings that compare equal also produce
/// [`Ordering::Equal`]. This lets `sort()` + `dedup_by()` collapse
/// duplicates in a single pass (see the dedup pattern on
/// [`NormalizedFinding`]).
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
/// offset. Scanner findings use byte offsets ([`NormalizedFinding::byte_start`]),
/// so a separate `LineIndex` component handles the byte-to-line conversion
/// during matching. This type intentionally stays in the line-number domain
/// to avoid lossy round-trips when ingesting corpus CSVs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TruthItem {
    /// Forward-slash normalized path relative to the corpus root.
    pub path: String,
    /// 1-indexed, inclusive start line. Matches the convention used by
    /// CredData and similar CSV corpora where annotations are line-based.
    pub line_start: u32,
    /// 1-indexed, inclusive end line. A single-line annotation has
    /// `line_start == line_end`.
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
    /// Exclude from scoring entirely. Used for test scaffolding, ambiguous
    /// annotations that cannot be confidently labeled either way, or
    /// regions under active relabeling. Findings matching a placeholder
    /// annotation are neither penalized nor rewarded.
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
/// The metrics layer uses these classifications to compute precision, recall,
/// and PRC-AUC. The four variants form a complete partition: every finding
/// is classified as exactly one of TP, FP, unlabeled, and every ground-truth
/// positive not matched by a finding becomes FN.
///
/// The distinction between [`FalsePositive`](MatchClass::FalsePositive) and
/// [`Unlabeled`](MatchClass::Unlabeled) matters for corpus coverage analysis:
/// a high unlabeled rate signals that the corpus has gaps, not necessarily
/// that the scanner is noisy.
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
/// Both [`NormalizedFinding::path`] and [`TruthItem::path`] should be
/// produced through this function to ensure they share the same canonical
/// form and can be compared by simple string equality.
///
/// Delegates to [`scanner_rs::store::canonicalize_path`] for lexical
/// normalization (backslash to forward-slash, collapse `.`/`..`, strip
/// leading `/`). Then strips the `corpus_root` prefix if the canonical
/// path starts with it.
///
/// Uses purely lexical normalization -- no filesystem access, no symlink
/// resolution. Safe for offline evaluation when corpus files are not present.
///
/// # Invariants
///
/// - **Idempotent**: `normalize_path(normalize_path(p, ""), "")` equals
///   `normalize_path(p, "")` for all `p`.
/// - **No backslashes**: output never contains `\`.
/// - **No `.`/`..` components**: these are resolved lexically.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(normalize_path("corpus/foo/bar.txt", "corpus"), "foo/bar.txt");
/// assert_eq!(normalize_path("foo\\bar.txt", ""), "foo/bar.txt");
/// assert_eq!(normalize_path("./foo/bar.txt", ""), "foo/bar.txt");
/// // Path outside the corpus root is returned as-is (after canonicalization).
/// assert_eq!(normalize_path("other/bar.txt", "corpus"), "other/bar.txt");
/// ```
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

    // ── MatchClass serde ──────────────────────────────────────

    #[test]
    fn match_class_serde_roundtrip() {
        for class in [
            MatchClass::TruePositive,
            MatchClass::FalsePositive,
            MatchClass::FalseNegative,
            MatchClass::Unlabeled,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: MatchClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn match_class_serializes_pascal_case() {
        assert_eq!(
            serde_json::to_string(&MatchClass::TruePositive).unwrap(),
            r#""TruePositive""#
        );
        assert_eq!(
            serde_json::to_string(&MatchClass::FalsePositive).unwrap(),
            r#""FalsePositive""#
        );
        assert_eq!(
            serde_json::to_string(&MatchClass::FalseNegative).unwrap(),
            r#""FalseNegative""#
        );
        assert_eq!(
            serde_json::to_string(&MatchClass::Unlabeled).unwrap(),
            r#""Unlabeled""#
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
    fn finding_hash_excludes_confidence() {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let hash_of = |f: &NormalizedFinding| {
            let mut h = DefaultHasher::new();
            f.hash(&mut h);
            h.finish()
        };
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
        assert_eq!(hash_of(&a), hash_of(&b));
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

    // ── Display impls ────────────────────────────────────────

    #[test]
    fn truth_label_display() {
        let cases = [
            (TruthLabel::Positive, "positive"),
            (TruthLabel::Negative, "negative"),
            (TruthLabel::Placeholder, "placeholder"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.to_string(), expected);
        }
    }

    #[test]
    fn match_class_display() {
        let cases = [
            (MatchClass::TruePositive, "TP"),
            (MatchClass::FalsePositive, "FP"),
            (MatchClass::FalseNegative, "FN"),
            (MatchClass::Unlabeled, "unlabeled"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.to_string(), expected);
        }
    }

    // ── normalize_path examples ───────────────────────────────

    #[test]
    fn normalize_path_examples() {
        let cases: &[(&str, &str, &str)] = &[
            // (raw, corpus_root, expected)
            ("corpus/foo/bar.txt", "corpus", "foo/bar.txt"),
            ("foo\\bar.txt", "", "foo/bar.txt"),
            ("./foo/bar.txt", "", "foo/bar.txt"),
            ("", "", ""),
            ("unrelated/bar.txt", "corpus", "unrelated/bar.txt"),
            // Edge case: path equals corpus root exactly. strip_prefix
            // yields "", which has no leading '/' to strip, so the
            // canonical path is returned unchanged.
            ("corpus", "corpus", "corpus"),
        ];
        for &(raw, root, expected) in cases {
            assert_eq!(
                normalize_path(raw, root),
                expected,
                "normalize_path({raw:?}, {root:?})"
            );
        }
    }

    // ── Property tests ─────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;
        use std::hash::{DefaultHasher, Hash, Hasher};

        fn hash_of(f: &NormalizedFinding) -> u64 {
            let mut h = DefaultHasher::new();
            f.hash(&mut h);
            h.finish()
        }

        // ── NormalizedFinding trait consistency ──────────────

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// `a == b` must imply `hash(a) == hash(b)` even when
            /// confidence differs. Violation silently corrupts HashSet/HashMap.
            #[test]
            fn finding_eq_implies_hash_eq(
                path in "[a-z]{1,10}",
                start in 0u64..1000,
                end in 0u64..1000,
                rule in "[a-z]{1,5}",
                conf_a in -128i8..127,
                conf_b in -128i8..127,
            ) {
                let a = NormalizedFinding {
                    path: path.clone(), byte_start: start, byte_end: end,
                    rule: rule.clone(), confidence: conf_a,
                };
                let b = NormalizedFinding {
                    path, byte_start: start, byte_end: end,
                    rule, confidence: conf_b,
                };
                prop_assert_eq!(&a, &b);
                prop_assert_eq!(hash_of(&a), hash_of(&b), "Eq/Hash inconsistency");
            }

            /// `a.cmp(&b) == Equal` iff `a == b`, regardless of confidence.
            #[test]
            fn finding_ord_consistent_with_eq(
                path_a in "[a-z]{1,5}", path_b in "[a-z]{1,5}",
                s_a in 0u64..100, s_b in 0u64..100,
                e_a in 0u64..100, e_b in 0u64..100,
                rule_a in "[a-z]{1,3}", rule_b in "[a-z]{1,3}",
                c_a in -128i8..127, c_b in -128i8..127,
            ) {
                let a = NormalizedFinding {
                    path: path_a, byte_start: s_a, byte_end: e_a,
                    rule: rule_a, confidence: c_a,
                };
                let b = NormalizedFinding {
                    path: path_b, byte_start: s_b, byte_end: e_b,
                    rule: rule_b, confidence: c_b,
                };
                if a == b {
                    prop_assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
                }
                if a.cmp(&b) == std::cmp::Ordering::Equal {
                    prop_assert_eq!(a, b);
                }
            }

            /// Serde roundtrip preserves all fields including confidence
            /// (which Eq excludes, so a naive `assert_eq!` would miss drift).
            #[test]
            fn finding_serde_roundtrip(
                path in "[a-z/]{1,20}",
                start in 0u64..10000,
                end in 0u64..10000,
                rule in "[a-z_]{1,10}",
                confidence in -128i8..127,
            ) {
                let f = NormalizedFinding {
                    path, byte_start: start, byte_end: end, rule, confidence,
                };
                let json = serde_json::to_string(&f).unwrap();
                let back: NormalizedFinding = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(&f.path, &back.path);
                prop_assert_eq!(f.byte_start, back.byte_start);
                prop_assert_eq!(f.byte_end, back.byte_end);
                prop_assert_eq!(&f.rule, &back.rule);
                prop_assert_eq!(f.confidence, back.confidence);
            }
        }

        // ── normalize_path properties ───────────────────────

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn normalize_is_idempotent(raw in "[a-zA-Z0-9_./\\\\]{0,80}") {
                let once = normalize_path(&raw, "");
                let twice = normalize_path(&once, "");
                prop_assert_eq!(&once, &twice);
            }

            #[test]
            fn normalize_is_idempotent_with_root(
                raw in "[a-zA-Z0-9_./]{0,40}",
                corpus_root in "[a-zA-Z0-9_]{0,20}",
            ) {
                let once = normalize_path(&raw, &corpus_root);
                let twice = normalize_path(&once, &corpus_root);
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
