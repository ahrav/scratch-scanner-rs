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
    /// Byte offset of the finding start (inclusive). Uses the full 64-bit byte
    /// offset from the scanner's streaming output, not the 32-bit truncated
    /// offset stored in persistent records.
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

impl NormalizedFinding {
    /// Create a new finding with debug-mode validity checks.
    ///
    /// Fields remain `pub` for test construction, but production code should
    /// prefer this constructor to catch malformed data early.
    ///
    /// # Panics (debug only)
    ///
    /// - `path` is empty
    /// - `rule` is empty
    /// - `byte_end < byte_start` (inverted span)
    pub fn new(path: String, byte_start: u64, byte_end: u64, rule: String, confidence: i8) -> Self {
        debug_assert!(!path.is_empty(), "finding path must not be empty");
        debug_assert!(!rule.is_empty(), "finding rule must not be empty");
        debug_assert!(
            byte_end >= byte_start,
            "inverted span: byte_end ({byte_end}) < byte_start ({byte_start})"
        );
        Self {
            path,
            byte_start,
            byte_end,
            rule,
            confidence,
        }
    }

    /// The four fields that define finding identity for dedup.
    /// All trait impls (`PartialEq`, `Hash`, `Ord`) delegate here so the
    /// field set cannot diverge between impls.
    fn identity(&self) -> (&str, u64, u64, &str) {
        (&self.path, self.byte_start, self.byte_end, &self.rule)
    }
}

/// Identity comparison — delegates to [`NormalizedFinding::identity`].
impl PartialEq for NormalizedFinding {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for NormalizedFinding {}

/// Hashes the same identity fields as [`PartialEq`] to maintain
/// `a == b` ⇒ `hash(a) == hash(b)`.
impl Hash for NormalizedFinding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

/// Lexicographic ordering over identity fields. Consistent with [`Eq`] —
/// findings that compare equal produce [`Ordering::Equal`].
impl Ord for NormalizedFinding {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity().cmp(&other.identity())
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
/// so a separate line-index layer (not yet implemented) handles the
/// byte-to-line conversion during matching. This type intentionally stays
/// in the line-number domain
/// to avoid lossy round-trips when ingesting corpus CSVs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl TruthItem {
    /// Create a new truth item with debug-mode validity checks.
    ///
    /// Fields remain `pub` for test construction, but production code should
    /// prefer this constructor to catch malformed corpus data early.
    ///
    /// # Panics (debug only)
    ///
    /// - `path` is empty
    /// - `rule` is empty
    /// - `line_start` is zero (lines are 1-indexed)
    /// - `line_end < line_start` (inverted range)
    pub fn new(
        path: String,
        line_start: u32,
        line_end: u32,
        label: TruthLabel,
        rule: String,
    ) -> Self {
        debug_assert!(!path.is_empty(), "truth item path must not be empty");
        debug_assert!(!rule.is_empty(), "truth item rule must not be empty");
        debug_assert!(line_start > 0, "line_start must be 1-indexed, got 0");
        debug_assert!(
            line_end >= line_start,
            "inverted line range: line_end ({line_end}) < line_start ({line_start})"
        );
        Self {
            path,
            line_start,
            line_end,
            label,
            rule,
        }
    }
}

/// Ground-truth classification for a labeled region.
///
/// Only three states are needed — `TrueNegative` is intentionally absent
/// because in secret scanning the set of true negatives (all file regions
/// that are not secrets and are not flagged) is enormous and unenumerable.
/// PRC-AUC only needs TP, FP, and total positives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        f.write_str(match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Placeholder => "placeholder",
        })
    }
}

// ── Match classification ────────────────────────────────────────────────

/// Classification of a scanner finding after matching against ground truth.
///
/// The metrics layer uses these classifications to compute precision, recall,
/// and PRC-AUC. Each scanner finding is classified as exactly one of TP, FP,
/// or Unlabeled. Separately, each ground-truth positive that no finding
/// matches produces an FN. Together the four variants cover both domains
/// without overlap.
///
/// The distinction between [`FalsePositive`](MatchClass::FalsePositive) and
/// [`Unlabeled`](MatchClass::Unlabeled) matters for corpus coverage analysis:
/// a high unlabeled rate signals that the corpus has gaps, not necessarily
/// that the scanner is noisy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        f.write_str(match self {
            Self::TruePositive => "TP",
            Self::FalsePositive => "FP",
            Self::FalseNegative => "FN",
            Self::Unlabeled => "unlabeled",
        })
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
/// normalization of `raw` (backslash to forward-slash, collapse `.`/`..`,
/// strip leading `/`). Then strips the `canonical_root` prefix if the
/// canonical path starts with it.
///
/// `canonical_root` must already be canonicalized via
/// [`canonicalize_path`](scanner_rs::store::canonicalize_path) (or be an
/// empty string for no root stripping). This avoids redundant work when the
/// same root is reused across many calls.
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
/// // Pre-canonicalize the corpus root once, then reuse across calls.
/// let root = canonicalize_path("corpus");
/// assert_eq!(normalize_path("corpus/foo/bar.txt", &root), "foo/bar.txt");
/// assert_eq!(normalize_path("foo\\bar.txt", ""), "foo/bar.txt");
/// assert_eq!(normalize_path("./foo/bar.txt", ""), "foo/bar.txt");
/// // Path outside the corpus root is returned as-is (after canonicalization).
/// assert_eq!(normalize_path("other/bar.txt", &root), "other/bar.txt");
/// ```
pub fn normalize_path(raw: &str, canonical_root: &str) -> String {
    let canonical = canonicalize_path(raw);
    if canonical_root.is_empty() {
        return canonical;
    }

    canonical
        .strip_prefix(canonical_root)
        .and_then(|s| s.strip_prefix('/'))
        .unwrap_or(&canonical)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TruthLabel traits (serde + display) ────────────────────

    #[test]
    fn truth_label_traits() {
        let cases: &[(TruthLabel, &str, &str)] = &[
            (TruthLabel::Positive, r#""positive""#, "positive"),
            (TruthLabel::Negative, r#""negative""#, "negative"),
            (TruthLabel::Placeholder, r#""placeholder""#, "placeholder"),
        ];
        for &(variant, json, display) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json, "{variant:?} serialization");
            let back: TruthLabel = serde_json::from_str(&serialized).unwrap();
            assert_eq!(back, variant, "{variant:?} roundtrip");
            assert_eq!(variant.to_string(), display, "{variant:?} display");
        }
    }

    // ── MatchClass traits (serde + display) ──────────────────

    #[test]
    fn match_class_traits() {
        let cases: &[(MatchClass, &str, &str)] = &[
            (MatchClass::TruePositive, r#""true_positive""#, "TP"),
            (MatchClass::FalsePositive, r#""false_positive""#, "FP"),
            (MatchClass::FalseNegative, r#""false_negative""#, "FN"),
            (MatchClass::Unlabeled, r#""unlabeled""#, "unlabeled"),
        ];
        for &(variant, json, display) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json, "{variant:?} serialization");
            let back: MatchClass = serde_json::from_str(&serialized).unwrap();
            assert_eq!(back, variant, "{variant:?} roundtrip");
            assert_eq!(variant.to_string(), display, "{variant:?} display");
        }
    }

    // ── NormalizedFinding ordering contract ────────────────────

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

    // ── Dedup pattern ────────────────────────────────────────

    #[test]
    fn dedup_retains_max_confidence() {
        let make = |conf| NormalizedFinding {
            path: "a.txt".into(),
            byte_start: 10,
            byte_end: 20,
            rule: "r1".into(),
            confidence: conf,
        };
        let mut findings = vec![make(3), make(7), make(1)];
        findings.sort();
        findings.dedup_by(|a, b| {
            if a == b {
                b.confidence = b.confidence.max(a.confidence);
                true
            } else {
                false
            }
        });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 7);
    }

    // ── TruthItem coverage ───────────────────────────────────

    #[test]
    fn truth_item_serde_roundtrip() {
        let items = [
            TruthItem {
                path: "foo/bar.txt".into(),
                line_start: 1,
                line_end: 5,
                label: TruthLabel::Positive,
                rule: "secret_key".into(),
            },
            TruthItem {
                path: "baz.txt".into(),
                line_start: 10,
                line_end: 10,
                label: TruthLabel::Negative,
                rule: "api_token".into(),
            },
            TruthItem {
                path: "qux.txt".into(),
                line_start: 3,
                line_end: 7,
                label: TruthLabel::Placeholder,
                rule: "password".into(),
            },
        ];
        for item in &items {
            let json = serde_json::to_string(item).unwrap();
            let back: TruthItem = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, item, "TruthItem roundtrip failed for {json}");
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
            // Multi-component corpus root.
            ("a/b/c/file.txt", "a/b", "c/file.txt"),
            // Un-canonicalized root with trailing slash — strip_prefix
            // consumes the slash so the second strip_prefix('/') sees no
            // leading '/' and falls back. Reinforces the API contract that
            // canonical_root must be pre-canonicalized.
            ("a/b/c/file.txt", "a/b/", "a/b/c/file.txt"),
            // Root is a prefix of a segment name — must not strip partial
            // segments (e.g., "corpus" must not strip from "corpus_data").
            ("corpus_data/file.txt", "corpus", "corpus_data/file.txt"),
            // Deeper variant of the segment-prefix case.
            (
                "corpusextra/sub/file.txt",
                "corpus",
                "corpusextra/sub/file.txt",
            ),
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

            /// sort + dedup_by on duplicates with varying confidence always
            /// collapses to one entry retaining the maximum confidence.
            #[test]
            fn dedup_keeps_highest_confidence(
                path in "[a-z]{1,5}",
                start in 0u64..100,
                end in 0u64..100,
                rule in "[a-z]{1,3}",
                confs in proptest::collection::vec(-128i8..127, 2..8),
            ) {
                let mut findings: Vec<NormalizedFinding> = confs.iter().map(|&c| {
                    NormalizedFinding {
                        path: path.clone(),
                        byte_start: start,
                        byte_end: end,
                        rule: rule.clone(),
                        confidence: c,
                    }
                }).collect();
                let max_conf = confs.iter().copied().max().unwrap();
                findings.sort();
                findings.dedup_by(|a, b| {
                    if a == b {
                        b.confidence = b.confidence.max(a.confidence);
                        true
                    } else {
                        false
                    }
                });
                prop_assert_eq!(findings.len(), 1);
                prop_assert_eq!(findings[0].confidence, max_conf);
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

            // NOTE: idempotency with non-empty root does NOT hold in general.
            // Example: normalize_path("a/a/b", "a") → "a/b", then
            // normalize_path("a/b", "a") → "b". The module-level doc
            // (line 296-297) correctly scopes idempotency to empty root,
            // which is tested by `normalize_is_idempotent` above.

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
