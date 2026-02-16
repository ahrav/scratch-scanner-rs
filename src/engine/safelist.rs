//! Global context safelist for emit-time suppression.
//!
//! The safelist is intentionally broad and conservative: if any pattern matches
//! nearby context for a finding, the finding is suppressed before it is
//! recorded.
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
//! # Two-Tier Matching
//!
//! The safelist operates in two tiers:
//!
//! 1. **Context-window tier** (`regex_set`, 18 patterns): matches the full
//!    context buffer around a finding. Patterns may use context anchors like
//!    `[:=]\s*` or `(?m)^` that only make sense in surrounding text.
//!
//! 2. **Secret-bytes tier** (`secret_bytes_set`, 9 patterns): matches the
//!    extracted secret value directly (10–150 bytes typically). Only patterns
//!    that are meaningful on bare values are included — context-anchored
//!    patterns and short substrings ("mock") that risk false suppression of
//!    real secrets are excluded.
//!
//! Both tiers are checked during `apply_emit_time_policy`. The context tier
//! runs first (root findings only); the secret-bytes tier runs on all findings
//! (including decoded/transform-derived) when the context tier does not
//! suppress.
//!
//! # Invariants
//! - Pattern inventory is fixed at 18 context categories and 9 secret-bytes
//!   categories; changes require updating the corresponding `*_COUNT` constant
//!   and the compile-time assertions.
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
//! - `matcher().is_match(...)` is effectively linear in context length for a
//!   fixed pattern set.
//!
//! # Failure Modes
//! - A compile-time assertion guards both pattern counts; adding or removing
//!   patterns without updating the count constants is a compile error.
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

/// Number of patterns in the secret-bytes safelist subset.
///
/// This curated subset contains only patterns that are meaningful when matched
/// against bare extracted secret values (10–150 bytes). Context-anchored
/// patterns (e.g., `[:=]\s*`, `(?m)^`) and short substrings that risk
/// suppressing real secrets (e.g., "mock") are excluded.
///
/// # Pattern provenance (indices refer to `SAFELIST_PATTERNS`):
///
/// | Idx | Category | Included | Reason |
/// |-----|----------|----------|--------|
/// | 0   | placeholder+noun | YES | Self-contained word pairs |
/// | 1   | AWS example key  | YES | Self-contained literal |
/// | 2   | Redaction runs   | YES | Pure value match |
/// | 5   | Metadata values  | YES | Modified: `[:=]\s*` prefix removed |
/// | 6   | hunter2          | YES | Pure value match |
/// | 7   | Sequential digits/alpha | YES | Pure value match |
/// | 9   | Template vars    | YES | Unresolved templates aren't real secrets |
/// | 13  | INSERT_YOUR/REPLACE_WITH | YES | Pure value match |
/// | 14  | Base64 example literals  | YES | Pure value match |
/// | 3,4,8,10,11,12,15,17 | Context-anchored | NO | Meaningless on bare values |
/// | 16  | Test fixture markers     | NO | "mock" is 4 chars, would suppress real keys |
const SECRET_BYTES_PATTERN_COUNT: usize = 9;

/// Patterns safe for matching against bare extracted secret bytes.
///
/// Each pattern is derived from `SAFELIST_PATTERNS` but adapted for bare-value
/// matching. Context anchors (`[:=]\s*`, `(?m)^`, URL structure) are stripped
/// because extracted secret bytes lack surrounding assignment or line context.
///
/// # Safety against false suppression
///
/// Pattern 16 ("mock"/"fixture") is deliberately excluded: the 4-character
/// substring "mock" would match inside real high-entropy API keys. See
/// TruffleHog #2620 for a real-world incident where over-broad value filtering
/// suppressed valid AWS credentials.
const SECRET_BYTES_PATTERNS: &[&str] = &[
    // [from idx 0] Placeholder markers plus key/token/secret nouns.
    r"(?i)\b(?:placeholder|dummy|fake|sample|example|test)[-_ ]{0,3}(?:key|token|secret|password)\b|\b(?:key|token|secret|password)[-_ ]{0,3}(?:placeholder|dummy|fake|sample|example|test)\b",
    // [from idx 1] AWS example key IDs (AKIA...EXAMPLE).
    r"\bAKIA[0-9A-Z]{9}EXAMPLE\b",
    // [from idx 2] Redaction marker runs (***).
    r"\*{3,}",
    // [from idx 5] Metadata marker values — prefix-free variant for bare values.
    r"(?i)\b(?:null|changeme|todo|fixme)\b",
    // [from idx 6] Known fake sample value hunter2.
    r"(?i)\bhunter2\b",
    // [from idx 7] Sequential demo strings (0123456789, abcdefghij).
    r"(?i)\b(?:0123456789|abcdefghij)\b",
    // [from idx 9] Template vars (${FOO}, {{FOO}}).
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\})",
    // [from idx 13] INSERT_YOUR / REPLACE_WITH style markers.
    r"(?i)\b(?:INSERT[_\s-]?YOUR|REPLACE[_\s-]?WITH)[A-Z0-9_\s-]*\b",
    // [from idx 14] Base64 for example/test/sample literals.
    r"(?:ZXhhbXBsZQ==|c2FtcGxl={0,2}|dGVzdA==)",
];

const _: () = assert!(SECRET_BYTES_PATTERNS.len() == SECRET_BYTES_PATTERN_COUNT);

/// Precompiled global safelist matcher used for emit-time suppression.
///
/// Contains two `RegexSet` instances:
/// - `regex_set`: the full 18-pattern set for context-window matching.
/// - `secret_bytes_set`: a curated 9-pattern subset for bare secret-value matching.
///
/// A `SafelistFilter` is immutable after construction and safe to share across scans.
#[derive(Debug)]
pub(crate) struct SafelistFilter {
    regex_set: RegexSet,
    secret_bytes_set: RegexSet,
}

impl SafelistFilter {
    /// Compile the static safelist pattern inventories into `RegexSet`s.
    ///
    /// Panics if any regex fails to compile. Pattern counts are enforced at
    /// compile time by the `const _` assertions above.
    pub(crate) fn new() -> Self {
        let regex_set = RegexSet::new(SAFELIST_PATTERNS).unwrap_or_else(|e| {
            panic!(
                "safelist pattern compilation failed ({} patterns): {e}",
                SAFELIST_PATTERNS.len()
            )
        });
        let secret_bytes_set = RegexSet::new(SECRET_BYTES_PATTERNS).unwrap_or_else(|e| {
            panic!(
                "secret-bytes safelist pattern compilation failed ({} patterns): {e}",
                SECRET_BYTES_PATTERNS.len()
            )
        });
        Self {
            regex_set,
            secret_bytes_set,
        }
    }

    /// Returns a reference to the context-window matcher for use in hot loops.
    #[inline]
    pub(crate) fn matcher(&self) -> &RegexSet {
        &self.regex_set
    }

    /// Returns a reference to the secret-bytes matcher.
    ///
    /// This uses a curated subset of patterns safe for matching against bare
    /// extracted secret values (typically 10–150 bytes). Unlike [`matcher`],
    /// which targets the surrounding context window of root findings only, this
    /// set is intended for **all** findings — including decoded and
    /// transform-derived values — where no surrounding context is available.
    ///
    /// Context-anchored patterns and short substrings that risk false
    /// suppression are excluded. See [`SECRET_BYTES_PATTERNS`] for the full
    /// inclusion/exclusion rationale.
    #[inline]
    pub(crate) fn secret_bytes_matcher(&self) -> &RegexSet {
        &self.secret_bytes_set
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SafelistFilter, SAFELIST_PATTERNS, SAFELIST_PATTERN_COUNT, SECRET_BYTES_PATTERNS,
        SECRET_BYTES_PATTERN_COUNT,
    };

    #[test]
    fn safelist_inventory_has_expected_count() {
        assert_eq!(SAFELIST_PATTERNS.len(), SAFELIST_PATTERN_COUNT);
    }

    #[test]
    fn secret_bytes_inventory_has_expected_count() {
        assert_eq!(SECRET_BYTES_PATTERNS.len(), SECRET_BYTES_PATTERN_COUNT);
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
                filter.matcher().is_match(context),
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
                !filter.matcher().is_match(context),
                "unexpected safelist match for realistic secret context: {}",
                String::from_utf8_lossy(context)
            );
        }
    }

    // -- Secret-bytes matcher tests --

    #[test]
    fn secret_bytes_positive_examples_cover_all_categories() {
        let filter = SafelistFilter::new();
        let cases: [(&str, &[u8]); 9] = [
            // [idx 0] Placeholder+noun on bare value.
            ("placeholder+noun", b"placeholder_token"),
            // [idx 1] AWS example key ID as bare value.
            ("aws example key", b"AKIA123456789EXAMPLE"),
            // [idx 2] Redaction run as bare value.
            ("redaction run", b"****REDACTED****"),
            // [idx 5] Metadata marker without assignment prefix.
            ("metadata value", b"changeme"),
            // [idx 6] hunter2 as bare value.
            ("hunter2", b"hunter2"),
            // [idx 7] Sequential digits as bare value.
            ("sequential digits", b"0123456789"),
            // [idx 9] Template variable as bare value.
            ("template var", b"{{API_TOKEN}}"),
            // [idx 13] INSERT_YOUR marker as bare value.
            ("insert marker", b"INSERT_YOUR_TOKEN_HERE"),
            // [idx 14] Base64 example literal as bare value.
            ("base64 example", b"ZXhhbXBsZQ=="),
        ];

        assert_eq!(
            cases.len(),
            SECRET_BYTES_PATTERN_COUNT,
            "tests should cover each secret-bytes category"
        );

        for (label, value) in cases {
            assert!(
                filter.secret_bytes_matcher().is_match(value),
                "expected secret-bytes safelist match for category: {label}"
            );
        }
    }

    #[test]
    fn secret_bytes_rejects_high_entropy_real_secrets() {
        let filter = SafelistFilter::new();
        let negatives: &[(&str, &[u8])] = &[
            // Real GitHub PAT.
            ("github pat", b"ghp_2fK9sD6nL0pQ8rT1vW3xY5zA7bC9dE1fG3hI"),
            // Random hex string.
            ("random hex", b"9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK"),
            // JWT-like token.
            ("jwt", b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"),
            // AWS real-looking key.
            ("aws real key", b"AKIA1234567890ABCD12"),
            // Stripe key.
            ("stripe key", b"51Nn3t4ABcdEfGhIjKlMnOpQrStUvWxYz012345"),
            // Generic high-entropy.
            ("high entropy", b"v1.prod.2ab4ce6f77889900ddeeff1122334455"),
        ];

        for (label, value) in negatives {
            assert!(
                !filter.secret_bytes_matcher().is_match(value),
                "unexpected secret-bytes safelist match for realistic secret: {label}"
            );
        }
    }

    #[test]
    fn secret_bytes_mock_substring_does_not_suppress_real_key() {
        let filter = SafelistFilter::new();
        // Pattern 16 ("mock") is excluded from the secret-bytes set.
        // A real API key that happens to contain "mock" as a substring
        // must NOT be suppressed.
        let key_with_mock_substring = b"aMockR7tN9xQ2wE4yU6iO8pA0sD3fG5h";
        assert!(
            !filter
                .secret_bytes_matcher()
                .is_match(key_with_mock_substring),
            "pattern 16 (mock) must be excluded from secret-bytes set to avoid \
             suppressing real keys containing 'mock' as a substring"
        );
    }

    #[test]
    fn secret_bytes_metadata_values_match_without_prefix() {
        let filter = SafelistFilter::new();
        // The context-tier pattern 5 requires `[:=]\s*` prefix, but
        // the secret-bytes variant must match bare values.
        for value in &[b"changeme" as &[u8], b"todo", b"fixme", b"null"] {
            assert!(
                filter.secret_bytes_matcher().is_match(value),
                "metadata value {:?} should match in secret-bytes tier without prefix",
                std::str::from_utf8(value).unwrap()
            );
        }
    }

    #[test]
    fn secret_bytes_template_vars_cover_both_syntaxes() {
        let filter = SafelistFilter::new();
        assert!(
            filter.secret_bytes_matcher().is_match(b"${DATABASE_URL}"),
            "dollar-brace template should match"
        );
        assert!(
            filter.secret_bytes_matcher().is_match(b"{{SECRET_TOKEN}}"),
            "double-brace template should match"
        );
    }
}
