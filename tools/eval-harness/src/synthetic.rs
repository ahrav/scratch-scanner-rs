//! Synthetic corpus manifest loader.
//!
//! Loads a JSON manifest file containing ground-truth annotations into
//! [`Vec<TruthItem>`]. The manifest is a bare JSON array of objects with
//! fields matching [`TruthItem`]'s serde shape.
//!
//! # Expected JSON format
//!
//! ```json
//! [
//!   {"path": "src/a.py", "line_start": 1, "line_end": 1, "label": "positive", "rule": "aws-key"},
//!   {"path": "src/b.py", "line_start": 5, "line_end": 6, "label": "negative", "category": "generic-api-key"}
//! ]
//! ```
//!
//! The `rule` field also accepts `"category"` as an alias (via serde's
//! `#[serde(alias)]` on [`TruthItem::rule`]) for interoperability with
//! manifest generators that use that name.
//!
//! # Fail-fast vs partial-failure
//!
//! Unlike the CredData CSV loader ([`crate::creddata`]), which uses
//! counter-based partial-failure semantics to tolerate individual bad rows
//! in large multi-file corpora, this module fails on the first error.
//! Synthetic manifests are small, hand-authored files where any defect
//! signals a generation bug — silently skipping a corrupt item would
//! produce misleading precision/recall numbers.
//!
//! # Pipeline position
//!
//! This is Phase 2 (ground-truth loading) for synthetic corpora — a
//! complement to the CredData CSV loader in [`crate::creddata`] and the
//! JSONL finding parser in [`crate::finding_parser`].

use std::fmt;
use std::path::{Path, PathBuf};

use crate::types::{TruthItem, normalize_path};

// ── Error type ───────────────────────────────────────────────────────────

/// Error from loading or validating a synthetic manifest file.
///
/// Structured as a three-variant enum so callers can distinguish
/// infrastructure failures (I/O, JSON syntax) from semantic problems
/// (domain-constraint violations in an otherwise well-formed record).
/// The [`Validation`](SyntheticError::Validation) variant carries the
/// item index so error messages can pinpoint the exact offending record
/// without re-parsing.
///
/// This type is separate from [`crate::types::FileReadError`] because
/// synthetic manifests require richer error reporting: JSON parse errors,
/// per-item validation, and the file path for context. `FileReadError`
/// only covers raw I/O failures.
#[derive(Debug)]
pub enum SyntheticError {
    /// File could not be read from disk.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// File contents are not valid JSON or do not match the expected schema.
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// An individual item violates a domain constraint that serde cannot
    /// express (e.g., zero-indexed line number, inverted range).
    Validation { index: usize, reason: String },
}

impl fmt::Display for SyntheticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            }
            Self::Json { path, source } => {
                write!(f, "failed to parse {}: {}", path.display(), source)
            }
            Self::Validation { index, reason } => {
                write!(f, "invalid item at index {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for SyntheticError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Validation { .. } => None,
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Load a synthetic corpus manifest from disk.
///
/// The file must contain a bare JSON array of objects whose shape matches
/// [`TruthItem`] (fields: `path`, `line_start`, `line_end`, `label`,
/// `rule`). The `rule` field also accepts `"category"` as an alias.
///
/// An empty array (`[]`) is valid and returns an empty `Vec`.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from item paths. Must be pre-canonicalized
/// (forward slashes, no `.`/`..` components); use `""` for no stripping.
///
/// # Validation
///
/// After successful deserialization, every item is checked in order
/// against these domain constraints (serde cannot express them):
///
/// 1. `path` must be non-empty (before normalization).
/// 2. `line_start` must be >= 1 (1-indexed convention shared with
///    [`TruthItem`] and the CredData corpus).
/// 3. `rule` must be non-empty.
/// 4. `line_end` must be >= `line_start` (no inverted ranges).
/// 5. Normalized `path` must be non-empty (degenerate inputs like `".."`
///    normalize to `""`).
///
/// Validation halts on the first violation. The ordering is chosen so
/// the most informative error (missing path) surfaces before less
/// obvious ones (inverted range).
///
/// # Errors
///
/// - [`SyntheticError::Io`] — the file could not be read (missing,
///   permissions, etc.).
/// - [`SyntheticError::Json`] — file contents are not valid JSON or do
///   not match the expected `Vec<TruthItem>` schema (includes unknown
///   label values, which serde rejects at parse time).
/// - [`SyntheticError::Validation`] — an individual item passes serde
///   parsing but violates a domain constraint listed above.
///
/// The entire manifest must be valid because ground-truth corruption
/// would silently invalidate the full evaluation.
pub fn load_synthetic_manifest(
    path: &Path,
    canonical_root: &str,
) -> Result<Vec<TruthItem>, SyntheticError> {
    let contents = std::fs::read_to_string(path).map_err(|e| SyntheticError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut items: Vec<TruthItem> =
        serde_json::from_str(&contents).map_err(|e| SyntheticError::Json {
            path: path.to_path_buf(),
            source: e,
        })?;

    // Domain validation that serde's derive cannot express. Checked in a
    // deterministic order (path, line_start, rule, range, normalized path)
    // so the first error reported is always the most structurally fundamental.
    for (i, item) in items.iter_mut().enumerate() {
        if item.path.is_empty() {
            return Err(SyntheticError::Validation {
                index: i,
                reason: "path must not be empty".into(),
            });
        }
        if item.line_start == 0 {
            return Err(SyntheticError::Validation {
                index: i,
                reason: "line_start must be >= 1 (1-indexed)".into(),
            });
        }
        if item.rule.is_empty() {
            return Err(SyntheticError::Validation {
                index: i,
                reason: "rule must not be empty".into(),
            });
        }
        if item.line_end < item.line_start {
            return Err(SyntheticError::Validation {
                index: i,
                reason: format!(
                    "line_end ({}) < line_start ({})",
                    item.line_end, item.line_start
                ),
            });
        }

        // Normalize the path for cross-platform comparison, matching what
        // creddata and finding_parser do for their respective loaders.
        let normalized = normalize_path(&item.path, canonical_root);
        if normalized.is_empty() {
            return Err(SyntheticError::Validation {
                index: i,
                reason: "path normalizes to empty string".into(),
            });
        }
        item.path = normalized;
    }

    Ok(items)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TruthLabel;
    use std::io::Write as _;

    /// Helper: write `content` to a temp file and return its path.
    fn temp_json(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    // ── Unit tests ───────────────────────────────────────────────

    #[test]
    fn valid_manifest_loads() {
        let json = r#"[
            {"path":"src/a.py","line_start":1,"line_end":1,"label":"positive","rule":"aws-key"},
            {"path":"src/b.py","line_start":5,"line_end":6,"label":"negative","rule":"generic-api-key"},
            {"path":"src/c.py","line_start":10,"line_end":10,"label":"placeholder","rule":"password"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();

        assert_eq!(items.len(), 3);

        assert_eq!(items[0].path, "src/a.py");
        assert_eq!(items[0].line_start, 1);
        assert_eq!(items[0].line_end, 1);
        assert_eq!(items[0].label, TruthLabel::Positive);
        assert_eq!(items[0].rule, "aws-key");

        assert_eq!(items[1].label, TruthLabel::Negative);
        assert_eq!(items[2].label, TruthLabel::Placeholder);
    }

    #[test]
    fn category_alias_works() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","category":"aws-key"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items[0].rule, "aws-key");
    }

    #[test]
    fn invalid_label_rejected() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"unknown","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        assert!(matches!(err, SyntheticError::Json { .. }));
    }

    #[test]
    fn missing_file_io_error() {
        let err = load_synthetic_manifest(Path::new("/nonexistent/truth.json"), "").unwrap_err();
        assert!(matches!(err, SyntheticError::Io { .. }));
    }

    #[test]
    fn empty_array_ok() {
        let f = temp_json("[]");
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn validation_rejects_bad_items() {
        let cases: &[(&str, &str)] = &[
            // (json, keyword expected in reason)
            (
                r#"[{"path":"","line_start":1,"line_end":1,"label":"positive","rule":"r"}]"#,
                "path",
            ),
            (
                r#"[{"path":"x.py","line_start":0,"line_end":1,"label":"positive","rule":"r"}]"#,
                "line_start",
            ),
            (
                r#"[{"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":""}]"#,
                "rule",
            ),
            (
                r#"[{"path":"x.py","line_start":10,"line_end":5,"label":"positive","rule":"r"}]"#,
                "line_end",
            ),
        ];
        for (json, keyword) in cases {
            let f = temp_json(json);
            let err = load_synthetic_manifest(f.path(), "").unwrap_err();
            match err {
                SyntheticError::Validation { index, reason } => {
                    assert_eq!(index, 0, "json={json}");
                    assert!(reason.contains(keyword), "expected '{keyword}' in: {reason}");
                }
                other => panic!("expected Validation for '{keyword}', got {other}"),
            }
        }
    }

    #[test]
    fn duplicate_items_preserved() {
        let item = r#"{"path":"a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}"#;
        let json = format!("[{item},{item},{item}]");
        let f = temp_json(&json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items.len(), 3, "duplicates must not be silently removed");
    }

    #[test]
    fn extra_fields_ignored() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":"r","extra":"ignored"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn paths_are_normalized() {
        let json = r#"[
            {"path":"src/a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"},
            {"path":"src\\b.py","line_start":1,"line_end":1,"label":"positive","rule":"r"},
            {"path":"./src/c.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items[0].path, "src/a.py");
        assert_eq!(items[1].path, "src/b.py", "backslash should be normalized");
        assert_eq!(items[2].path, "src/c.py", "leading ./ should be stripped");
    }

    #[test]
    fn corpus_root_stripped_from_paths() {
        let json = r#"[
            {"path":"corpus/data/a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "corpus/data").unwrap();
        assert_eq!(items[0].path, "a.py");
    }

    #[test]
    fn degenerate_path_rejected() {
        let json = r#"[
            {"path":"..","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("normalizes to empty"), "{reason}");
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    // ── Property tests ───────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn truth_label_strategy() -> impl Strategy<Value = &'static str> {
            prop_oneof![Just("positive"), Just("negative"), Just("placeholder"),]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn roundtrip(
                path in "[a-z]{1,20}/[a-z]{1,20}\\.[a-z]{1,4}",
                line_start in 1u32..10_000,
                span in 0u32..100,
                label in truth_label_strategy(),
                rule in "[a-z_]{1,20}",
            ) {
                let line_end = line_start + span;
                let json = format!(
                    r#"[{{"path":"{path}","line_start":{line_start},"line_end":{line_end},"label":"{label}","rule":"{rule}"}}]"#,
                );
                let f = temp_json(&json);
                let items = load_synthetic_manifest(f.path(), "").unwrap();
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].path, path);
                assert_eq!(items[0].line_start, line_start);
                assert_eq!(items[0].line_end, line_end);
                assert_eq!(items[0].rule, rule);
            }

            #[test]
            fn never_panic(data: Vec<u8>) {
                let mut f = tempfile::NamedTempFile::new().unwrap();
                f.write_all(&data).unwrap();
                f.flush().unwrap();
                // Must return Ok or Err — never panic.
                let _ = load_synthetic_manifest(f.path(), "");
            }
        }
    }
}
