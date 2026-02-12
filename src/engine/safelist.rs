//! Global context safelist for post-scan suppression.
//!
//! The safelist is intentionally broad and conservative: if any pattern matches
//! nearby context for a finding, later pipeline stages can drop likely
//! placeholder/test artifacts before reporting.
//!
//! # Scope and Matching Model
//! - Matching runs on caller-provided context windows around already-detected
//!   candidates; this module does not search entire files on its own.
//! - Matching uses `RegexSet` ANY semantics: one pattern hit is enough to
//!   classify the context as safelisted.
//! - Patterns are tuned for synthetic/demo/placeholder recall. False positives
//!   are acceptable because this filter is only a suppression hint after
//!   detection, not a standalone detector.
//!
//! # Invariants
//! - Pattern inventory is fixed at 18 categories; changes require updating
//!   `SAFELIST_PATTERN_COUNT` and the compile-time assertion.
//! - Matching is byte-oriented and uses `regex::bytes::RegexSet` (ANY semantics).
//! - Case-insensitive handling is encoded inline in patterns via `(?i)` where needed.
//!
//! # Edge Cases
//! - Context may be non-UTF-8; byte regexes keep matching behavior stable.
//! - Extremely narrow caller-provided context windows can miss safelist markers,
//!   which is a deliberate trade-off controlled by the caller.
//!
//! # Complexity
//! - Construction cost is paid once per filter instance.
//! - `matches` is effectively linear in context length for a fixed pattern set.
//!
//! # Failure Modes
//! - A compile-time assertion guards the pattern count; adding or removing
//!   patterns without updating `SAFELIST_PATTERN_COUNT` is a compile error.
//! - Construction panics if any pattern is invalid; this is treated as a build-time
//!   configuration bug, not a recoverable runtime condition.

use regex::bytes::RegexSet;

const SAFELIST_PATTERN_COUNT: usize = 18;

const SAFELIST_PATTERNS: &[&str] = &[
    // Placeholder markers plus key/token/secret nouns.
    r"(?i)\b(?:placeholder|dummy|fake|sample|example|test)[-_ ]{0,3}(?:key|token|secret|password)\b|\b(?:key|token|secret|password)[-_ ]{0,3}(?:placeholder|dummy|fake|sample|example|test)\b",
    // AWS example key IDs (AKIA...EXAMPLE).
    r"\bAKIA[0-9A-Z]{9}EXAMPLE\b",
    // Redaction marker runs (***).
    r"\*{3,}",
    // Shell variable references in assigned values ($VAR, ${VAR}).
    r"[:=]\s*(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)",
    // Random generator shell commands ($(openssl...), $(uuidgen...)).
    r"(?i)\$\((?:openssl|uuidgen)\b[^)]*\)",
    // Metadata marker values (null, changeme, todo, fixme).
    r"(?i)[:=]\s*(?:null|changeme|todo|fixme)\b",
    // Known fake sample value hunter2.
    r"(?i)\bhunter2\b",
    // Sequential demo strings (0123456789, abcdefghij).
    r"(?i)\b(?:0123456789|abcdefghij)\b",
    // Schema/classpath/XML namespace references.
    r#"(?i)\b(?:classpath:[^\s"'`]+|xsi:schemaLocation\b|xmlns(?::[A-Za-z0-9_-]+)?=)"#,
    // Template vars (${FOO}, {{FOO}}).
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\})",
    // Example/localhost URIs.
    r#"(?i)\b(?:https?|ssh)://(?:localhost|(?:[A-Za-z0-9-]+\.)*example(?:\.[A-Za-z]{2,})?)(?::\d+)?(?:/[^\s"']*)?"#,
    // Secret-manager markup/tags.
    r"(?i)(?:<\s*/?\s*(?:secret|token|password)\s*>|(?:secretmanager|vault)://|secret(?:manager)?[:=])",
    // Documentation prose markers (for example, sample config).
    r"(?i)\b(?:for example|sample config|example config)\b",
    // INSERT_YOUR / REPLACE_WITH style markers.
    r"(?i)\b(?:INSERT[_\s-]?YOUR|REPLACE[_\s-]?WITH)[A-Z0-9_\s-]*\b",
    // Base64 for example/test/sample literals.
    r"(?:ZXhhbXBsZQ==|c2FtcGxl={0,2}|dGVzdA==)",
    // Git conflict markers.
    r"(?m)^(?:<{7}|={7}|>{7})(?: .*)?$",
    // Test fixture path markers (__test__, fixture, mock).
    r"(?i)\b(?:__tests?__|fixtures?|mocks?)\b",
    // Hash output format lines (sha256: ..., md5=...).
    r"(?i)\b(?:sha(?:1|224|256|384|512)|md5)\s*[:=]\s*[A-Fa-f0-9]{8,}\b",
];

const _: () = assert!(SAFELIST_PATTERNS.len() == SAFELIST_PATTERN_COUNT);

/// Precompiled global safelist matcher used for post-scan suppression.
///
/// A `SafelistFilter` is immutable after construction and safe to share across scans.
#[derive(Debug)]
pub(crate) struct SafelistFilter {
    regex_set: RegexSet,
}

impl SafelistFilter {
    /// Compile the static safelist pattern inventory into a `RegexSet`.
    ///
    /// Panics if any regex fails to compile. Pattern count is enforced at
    /// compile time by the `const _` assertion above.
    pub(crate) fn new() -> Self {
        let regex_set = RegexSet::new(SAFELIST_PATTERNS).unwrap_or_else(|e| {
            panic!(
                "safelist pattern compilation failed ({} patterns): {e}",
                SAFELIST_PATTERNS.len()
            )
        });
        Self { regex_set }
    }

    /// Returns a reference to the compiled matcher for use in hot loops.
    #[inline]
    pub(crate) fn matcher(&self) -> &RegexSet {
        &self.regex_set
    }

    /// Returns `true` when any safelist pattern matches the supplied context.
    ///
    /// Callers should treat `true` as "eligible for suppression review", not as a
    /// proof that the candidate is non-secret.
    #[inline]
    pub(crate) fn matches(&self, context: &[u8]) -> bool {
        self.regex_set.is_match(context)
    }
}

#[cfg(test)]
mod tests {
    use super::{SafelistFilter, SAFELIST_PATTERNS, SAFELIST_PATTERN_COUNT};

    #[test]
    fn safelist_inventory_has_expected_count() {
        assert_eq!(SAFELIST_PATTERNS.len(), SAFELIST_PATTERN_COUNT);
    }

    #[test]
    fn safelist_positive_examples_cover_all_categories() {
        let filter = SafelistFilter::new();
        let cases: [(&str, &[u8]); 18] = [
            ("placeholder+noun", br#"api_key = "placeholder_token""#),
            (
                "aws example key",
                br#"aws_access_key_id = "AKIA123456789EXAMPLE""#,
            ),
            ("redaction run", br#"github_token = "***REDACTED***""#),
            ("shell variable assignment", br#"password = ${DB_PASSWORD}"#),
            ("shell random command", br#"token=$(openssl rand -hex 32)"#),
            ("metadata marker value", br#"secret = changeme"#),
            ("hunter2 sample", br#"password = "hunter2""#),
            ("sequential demo string", br#"api_token = "0123456789""#),
            (
                "schema/xml namespace",
                br#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#,
            ),
            ("template variable", br#"auth_token = "{{API_TOKEN}}""#),
            (
                "localhost uri",
                br#"endpoint = "https://localhost:8443/token""#,
            ),
            ("secret-manager tag", br#"<secret>PLACEHOLDER</secret>"#),
            (
                "documentation prose marker",
                br#"for example, set this in sample config before deploy"#,
            ),
            (
                "insert/replace marker",
                br#"token = INSERT_YOUR_TOKEN_HERE"#,
            ),
            ("base64 sample literal", br#"value = "ZXhhbXBsZQ==""#),
            (
                "git conflict markers",
                b"<<<<<<< HEAD\nAPI_TOKEN=foo\n=======\nAPI_TOKEN=bar\n>>>>>>> branch\n",
            ),
            ("fixture/mock marker", br#"tests/fixtures/mock_secret.json"#),
            (
                "hash output line",
                br#"sha256: 3b83ef96387f14655fc854ddc3c6bd57b6dd65c4dbe90f1647f0f4a6d5f6c123"#,
            ),
        ];

        assert_eq!(
            cases.len(),
            SAFELIST_PATTERN_COUNT,
            "tests should cover each safelist category"
        );

        for (label, context) in cases {
            assert!(
                filter.matches(context),
                "expected safelist match for category: {label}"
            );
        }
    }

    #[test]
    fn safelist_negative_examples_keep_realistic_secrets() {
        let filter = SafelistFilter::new();
        let negatives: [&[u8]; 6] = [
            br#"aws_access_key_id = "AKIA1234567890ABCD12""#,
            br#"github_token = "ghp_2fK9sD6nL0pQ8rT1vW3xY5zA7bC9dE1fG3hI""#,
            br#"stripe_secret_key = "stripe_live_token_51Nn3t4ABcdEfGhIjKlMnOpQrStUvWxYz012345""#,
            br#"db_password = "9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK""#,
            br#"authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"#,
            br#"service_token = "v1.prod.2ab4ce6f77889900ddeeff1122334455""#,
        ];

        for context in negatives {
            assert!(
                !filter.matches(context),
                "unexpected safelist match for realistic secret context: {}",
                String::from_utf8_lossy(context)
            );
        }
    }
}
