//! Dotenv (`.env`, `.env.*`) text extractor.
//!
//! Extracts normalized `KEY=VALUE` lines from dotenv content so scan rules keep
//! key context (for example `password=...`, `api_key=...`) while stripping
//! comments, quoting, and escape sequences.
//!
//! # Why extract rather than scan raw text?
//!
//! Raw dotenv files mix scannable secrets with noise (comments, `export`
//! prefixes, quoting punctuation, escape sequences). Feeding them through
//! this extractor first produces a clean `KEY=value\n` stream where every
//! line is a complete assignment, making downstream rule matching both
//! simpler and more accurate.
//!
//! # Supported syntax
//!
//! | Form | Behaviour |
//! |------|-----------|
//! | `KEY=VALUE` | Bare assignment |
//! | `export KEY=VALUE` | Lowercase `export` prefix stripped |
//! | Empty lines, `# ...` | Skipped entirely |
//! | Unquoted value | Trailing whitespace trimmed; `#` starts inline comment at the start of the value or after whitespace |
//! | `'...'` | Single-quoted: literal bytes, no escape processing |
//! | `"..."` | Double-quoted: `\n`, `\r`, `\t`, `\\`, `\"` unescaped; unknown `\x` keeps `x` |
//! | Quoted multiline | Spans physical lines until closing quote |
//!
//! # Algorithm
//!
//! The extractor performs a single forward pass over the input bytes:
//!
//! 1. Advance through lines, skipping blanks and comments.
//! 2. Strip an optional `export` prefix, then locate the `=` separator.
//! 3. Dispatch the value portion to a quoting-specific parser (unquoted,
//!    single-quoted, or double-quoted). Quoted parsers may consume
//!    additional lines from the raw input via the shared `pos` cursor.
//! 4. Each `KEY=value\n` entry is written atomically to `out` using a
//!    checkpoint/rollback pattern: if the value is malformed or the output
//!    budget ([`EXTRACT_OUTPUT_CAP`]) is exhausted, `out` is truncated back
//!    to its pre-entry length so callers never observe a partial assignment.
//!
//! # Performance
//!
//! The parser is byte-oriented and allocation-free beyond the caller-provided
//! output buffer. The `=` separator and single-quote delimiter searches use
//! `memchr` for SIMD-accelerated matching. Line scanning and double-quote
//! parsing use byte-at-a-time loops (the latter because escape processing is
//! interleaved). Malformed lines are skipped without panicking.
//!
//! [`EXTRACT_OUTPUT_CAP`]: super::extract::EXTRACT_OUTPUT_CAP

use memchr::memchr;

use super::extract::{ExtractResult, Extractor, EXTRACT_OUTPUT_CAP};

/// Extracts normalized `KEY=VALUE\n` lines from dotenv files.
///
/// Implements [`Extractor`] by appending one newline-terminated assignment per
/// recognized line. The `scratch` buffer is unused; all work is done directly
/// in `out`. See the [module docs](self) for the full grammar and algorithm.
pub struct DotEnvExtractor;

/// Outcome of attempting to write one `KEY=value\n` entry to `out`.
///
/// The main loop uses this three-way result to decide whether to continue
/// scanning (`Appended`, `Skipped`) or stop early (`CapReached`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineResult {
    /// Entry was fully written to `out`.
    Appended,
    /// Entry was malformed (e.g. unterminated quote) and `out` was rolled back.
    Skipped,
    /// The output budget was exhausted; `out` was rolled back and the caller
    /// should stop processing further lines.
    CapReached,
}

/// Result of parsing the value portion of an assignment (`...` in `KEY=...`).
///
/// The caller (`append_entry`) maps these into [`LineResult`] variants and
/// handles the checkpoint rollback on `Skip` and `CapReached`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueResult {
    /// Value was fully parsed and appended to `out` (without trailing newline).
    Ok,
    /// Value was malformed (e.g. EOF inside a quoted string). Caller must
    /// roll back any bytes this parser appended.
    Skip,
    /// Output budget exhausted mid-value. Caller must roll back.
    CapReached,
}

impl Extractor for DotEnvExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, _scratch: &mut Vec<u8>) -> ExtractResult {
        let start_len = out.len();
        let mut pos = 0usize;

        while pos < data.len() {
            let line = next_line(data, &mut pos);
            let mut line = trim_ascii_start(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }

            line = strip_export_prefix(line);
            let Some(eq) = memchr(b'=', line) else {
                continue;
            };

            let key = trim_ascii(&line[..eq]);
            if key.is_empty() {
                continue;
            }

            let value = &line[eq + 1..];
            match append_entry(key, value, data, &mut pos, out) {
                LineResult::Appended | LineResult::Skipped => {}
                LineResult::CapReached => break,
            }
        }

        if out.len() == start_len {
            ExtractResult::Empty
        } else {
            ExtractResult::Ok
        }
    }
}

/// Append one normalized `KEY=VALUE\n` entry atomically to `out`.
///
/// Uses two rollback mechanisms to maintain invariants:
///
/// - **Output rollback**: `out` is checkpointed before writing and truncated
///   back on any failure, so callers never observe a partial `KEY=value` entry.
/// - **Position rollback**: on `ValueResult::Skip` (malformed quote), the input
///   cursor `pos` is rewound to where it was before the value parser ran. This
///   prevents a runaway multiline quote from swallowing subsequent assignments;
///   instead, each continuation line is re-evaluated as a potential new entry.
fn append_entry(
    key: &[u8],
    value: &[u8],
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> LineResult {
    let checkpoint = out.len();
    if !push_bytes(out, key) || !push_byte(out, b'=') {
        out.truncate(checkpoint);
        return LineResult::CapReached;
    }

    let resume_pos = *pos;
    let value = trim_ascii_start(value);
    let value_result = match value.first().copied() {
        Some(b'"') => parse_double_quoted(&value[1..], data, pos, out),
        Some(b'\'') => parse_single_quoted(&value[1..], data, pos, out),
        _ => parse_unquoted(value, out),
    };

    match value_result {
        ValueResult::Ok => {
            if push_byte(out, b'\n') {
                LineResult::Appended
            } else {
                out.truncate(checkpoint);
                LineResult::CapReached
            }
        }
        ValueResult::Skip => {
            // Preserve forward progress: malformed multiline quotes should not
            // consume following assignments.
            *pos = resume_pos;
            out.truncate(checkpoint);
            LineResult::Skipped
        }
        ValueResult::CapReached => {
            out.truncate(checkpoint);
            LineResult::CapReached
        }
    }
}

/// Parse an unquoted value: strip any trailing inline comment (preceded by
/// whitespace), trim trailing whitespace, then append the result.
///
/// Unquoted values are always single-line, so this never advances `pos`.
fn parse_unquoted(value: &[u8], out: &mut Vec<u8>) -> ValueResult {
    let end = unquoted_comment_start(value).unwrap_or(value.len());
    let value = trim_ascii_end(&value[..end]);
    if push_bytes(out, value) {
        ValueResult::Ok
    } else {
        ValueResult::CapReached
    }
}

/// Parse a single-quoted value: copy bytes literally until the closing `'`.
///
/// Backslashes have no special meaning and are copied verbatim. If the closing
/// quote is not found on the current line, the parser fetches continuation
/// lines from `data` via `pos`, emitting `\n` between segments. Returns
/// [`ValueResult::Skip`] if EOF is reached without a closing quote.
fn parse_single_quoted<'a>(
    mut segment: &'a [u8],
    data: &'a [u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> ValueResult {
    loop {
        if let Some(end_quote) = memchr(b'\'', segment) {
            if push_bytes(out, &segment[..end_quote]) {
                return ValueResult::Ok;
            }
            return ValueResult::CapReached;
        }

        if !push_bytes(out, segment) {
            return ValueResult::CapReached;
        }
        if *pos >= data.len() {
            return ValueResult::Skip;
        }
        if !push_byte(out, b'\n') {
            return ValueResult::CapReached;
        }
        segment = next_line(data, pos);
    }
}

/// Parse a double-quoted value with escape processing until the closing `"`.
///
/// Recognized escapes: `\n`, `\r`, `\t`, `\\`, `\"`. Any other `\x` drops
/// the backslash and keeps `x`, matching the permissive behavior of most
/// dotenv libraries.
///
/// Like [`parse_single_quoted`], this fetches continuation lines from `data`
/// for multiline values. A backslash at a segment boundary (i.e. `\` is the
/// last byte before a line break) is emitted as a literal `\` because its
/// intended escape target is ambiguous.
fn parse_double_quoted<'a>(
    mut segment: &'a [u8],
    data: &'a [u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> ValueResult {
    loop {
        let mut idx = 0usize;
        let mut escaped = false;
        while idx < segment.len() {
            let b = segment[idx];
            if escaped {
                let unescaped = match b {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'\\' => b'\\',
                    b'"' => b'"',
                    other => other,
                };
                if !push_byte(out, unescaped) {
                    return ValueResult::CapReached;
                }
                escaped = false;
                idx += 1;
                continue;
            }

            match b {
                b'\\' => {
                    escaped = true;
                    idx += 1;
                }
                b'"' => return ValueResult::Ok,
                _ => {
                    if !push_byte(out, b) {
                        return ValueResult::CapReached;
                    }
                    idx += 1;
                }
            }
        }

        // A trailing `\` at the end of a segment has no character to escape.
        // Emit it as a literal backslash rather than silently dropping it.
        if escaped && !push_byte(out, b'\\') {
            return ValueResult::CapReached;
        }
        if *pos >= data.len() {
            return ValueResult::Skip;
        }
        if !push_byte(out, b'\n') {
            return ValueResult::CapReached;
        }
        segment = next_line(data, pos);
    }
}

/// Find the byte offset of the first `#` that starts an inline comment.
///
/// A `#` qualifies as a comment start only at position 0 or immediately after
/// ASCII whitespace. Mid-token hashes (e.g. `abc#def`, color codes) are kept
/// as part of the value, matching the behavior common among dotenv
/// implementations.
fn unquoted_comment_start(value: &[u8]) -> Option<usize> {
    (0..value.len())
        .find(|&idx| value[idx] == b'#' && (idx == 0 || value[idx - 1].is_ascii_whitespace()))
}

/// Strip a lowercase `export` prefix followed by at least one ASCII
/// whitespace character, returning the remainder.
///
/// Only the exact lowercase spelling is recognized; `EXPORT` and `Export`
/// are left as-is so that `EXPORT_PATH=...` is not misinterpreted.
fn strip_export_prefix(line: &[u8]) -> &[u8] {
    if line.len() <= 6 || &line[..6] != b"export" || !line[6].is_ascii_whitespace() {
        return line;
    }
    trim_ascii_start(&line[7..])
}

/// Return the next logical line from `data[*pos..]` and advance `pos` past
/// the LF terminator (if any).
///
/// The returned slice excludes line terminators (both `\n` and `\r\n`).
/// At EOF the final (possibly empty) line is returned and `pos` is left at
/// `data.len()`, so the caller's `while pos < data.len()` naturally exits.
fn next_line<'a>(data: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let start = *pos;
    while *pos < data.len() && data[*pos] != b'\n' {
        *pos += 1;
    }
    let mut end = *pos;
    if *pos < data.len() {
        *pos += 1;
    }
    if end > start && data[end - 1] == b'\r' {
        end -= 1;
    }
    &data[start..end]
}

/// Strip leading ASCII whitespace from a byte slice.
fn trim_ascii_start(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    while start < s.len() && s[start].is_ascii_whitespace() {
        start += 1;
    }
    &s[start..]
}

/// Strip trailing ASCII whitespace from a byte slice.
fn trim_ascii_end(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &s[..end]
}

/// Strip both leading and trailing ASCII whitespace from a byte slice.
fn trim_ascii(s: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(s))
}

/// Append one byte to `out` if the extraction budget has not been reached.
///
/// Returns `false` (without writing) when `out.len() >= EXTRACT_OUTPUT_CAP`,
/// signalling the caller to stop or roll back.
#[inline]
fn push_byte(out: &mut Vec<u8>, b: u8) -> bool {
    if out.len() >= EXTRACT_OUTPUT_CAP {
        return false;
    }
    out.push(b);
    true
}

/// Append `bytes` to `out` if the entire slice fits within the extraction
/// budget.
///
/// This is all-or-nothing: if the combined length would exceed
/// [`EXTRACT_OUTPUT_CAP`], nothing is written and `false` is returned. The
/// atomicity avoids partial value fragments in the output.
#[inline]
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> bool {
    if out.len().saturating_add(bytes.len()) > EXTRACT_OUTPUT_CAP {
        return false;
    }
    out.extend_from_slice(bytes);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Parameterized extraction cases covering every supported syntax variant.
    ///
    /// Each case feeds `input` through `DotEnvExtractor::extract` and asserts
    /// both the returned status and the exact output bytes.
    #[rstest]
    #[case::basic_assignments(
        b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n" as &[u8],
        ExtractResult::Ok,
        b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n" as &[u8],
    )]
    #[case::skips_comments_and_empty_lines(
        b"# comment\n \n\t# another\nTOKEN=abc\n",
        ExtractResult::Ok,
        b"TOKEN=abc\n"
    )]
    #[case::export_prefix(
        b"export API_KEY=abc\n export\tDB_URL=postgres://localhost\n",
        ExtractResult::Ok,
        b"API_KEY=abc\nDB_URL=postgres://localhost\n"
    )]
    #[case::double_quoted_escapes(
        b"KEY=\"line\\nnext\\t\\\"q\\\"\\\\\"\n",
        ExtractResult::Ok,
        b"KEY=line\nnext\t\"q\"\\\n"
    )]
    #[case::single_quoted_keeps_backslashes(
        b"KEY='line\\nnext\\t\\\"q\\\"'\n",
        ExtractResult::Ok,
        b"KEY=line\\nnext\\t\\\"q\\\"\n"
    )]
    #[case::unquoted_trim_and_inline_comment(
        b"A=foo # comment\nB=bar#not_comment\nC=   value   \n",
        ExtractResult::Ok,
        b"A=foo\nB=bar#not_comment\nC=value\n"
    )]
    #[case::multiline_double_quoted(
        b"CERT=\"line1\nline2\"\n",
        ExtractResult::Ok,
        b"CERT=line1\nline2\n"
    )]
    #[case::multiline_single_quoted(
        b"CERT='line1\nline2'\n",
        ExtractResult::Ok,
        b"CERT=line1\nline2\n"
    )]
    #[case::malformed_lines_skipped(
        b"NO_EQUALS\nBROKEN=\"unterminated\nNEXT=ok\n",
        ExtractResult::Ok,
        b"NEXT=ok\n"
    )]
    #[case::empty_when_no_assignments(
        b"# just comments\n   \n",
        ExtractResult::Empty,
        b"" as &[u8],
    )]
    fn extract_cases(
        #[case] input: &[u8],
        #[case] expected_result: ExtractResult,
        #[case] expected_output: &[u8],
    ) {
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, expected_result);
        assert_eq!(out, expected_output);
    }

    /// Budget enforcement: when `out` is already near capacity the extractor
    /// must not append partial data and must return `Empty`.
    #[test]
    fn respects_extract_output_cap() {
        let mut out = vec![b'x'; EXTRACT_OUTPUT_CAP - 2];
        let original = out.clone();
        let result = DotEnvExtractor.extract(b"A=1\n", &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Empty);
        assert_eq!(out, original);
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Generate a single dotenv line of a random syntax variant.
    fn dotenv_line() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // KEY=VALUE (unquoted)
            "[A-Z_]{1,20}=[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // comment
            "# [a-zA-Z ]{0,40}\n".prop_map(|s| s.into_bytes()),
            // blank
            Just(b"\n".to_vec()),
            // export KEY=VALUE
            "export [A-Z_]{1,20}=[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // double-quoted
            "[A-Z_]{1,20}=\"[a-zA-Z0-9_ ]{0,40}\"\n".prop_map(|s| s.into_bytes()),
            // single-quoted
            "[A-Z_]{1,20}='[a-zA-Z0-9_ ]{0,40}'\n".prop_map(|s| s.into_bytes()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Output length must never exceed the extraction budget.
        #[test]
        fn output_never_exceeds_cap(lines in prop::collection::vec(dotenv_line(), 0..50)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
            prop_assert!(out.len() <= EXTRACT_OUTPUT_CAP);
        }

        /// Every non-empty line in the output must contain at least one `=`
        /// with a non-empty key before it.
        #[test]
        fn output_lines_are_well_formed(lines in prop::collection::vec(dotenv_line(), 1..30)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
            for line in out.split(|&b| b == b'\n') {
                if line.is_empty() { continue; }
                let eq_count = line.iter().filter(|&&b| b == b'=').count();
                prop_assert!(eq_count >= 1, "line missing '=': {:?}",
                    String::from_utf8_lossy(line));
                let eq_pos = line.iter().position(|&b| b == b'=').unwrap();
                prop_assert!(eq_pos > 0, "empty key in line: {:?}",
                    String::from_utf8_lossy(line));
            }
        }

        /// Normalization converges after two passes.
        ///
        /// A single extraction can strip quoting while preserving interior
        /// whitespace that an unquoted re-parse would trim (e.g. `A=" "` →
        /// `A= ` → `A=`). The correct invariant is therefore that a second
        /// extraction produces a fixed point: `extract(extract(x))` ==
        /// `extract(extract(extract(x)))`.
        #[test]
        fn normalization_converges(lines in prop::collection::vec(dotenv_line(), 1..20)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut pass1 = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut pass1, &mut Vec::new());
            if pass1.is_empty() { return Ok(()); }
            let mut pass2 = Vec::new();
            let _ = DotEnvExtractor.extract(&pass1, &mut pass2, &mut Vec::new());
            if pass2.is_empty() { return Ok(()); }
            let mut pass3 = Vec::new();
            let _ = DotEnvExtractor.extract(&pass2, &mut pass3, &mut Vec::new());
            prop_assert_eq!(&pass2, &pass3,
                "normalization did not converge after two passes");
        }

        /// The extractor must never panic on arbitrary byte sequences.
        #[test]
        fn never_panics_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&data, &mut out, &mut Vec::new());
        }
    }
}
