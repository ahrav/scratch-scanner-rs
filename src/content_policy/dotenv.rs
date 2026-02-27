//! Dotenv (`.env`, `.env.*`) text extractor.
//!
//! Extracts normalized `KEY=VALUE` lines from dotenv content so scan rules keep
//! key context (for example `password=...`, `api_key=...`) while avoiding
//! comment noise.
//!
//! # Supported syntax
//!
//! - `KEY=VALUE` assignments
//! - Optional lowercase `export ` prefix (`export KEY=VALUE`)
//! - Empty lines and `#` comments
//! - Unquoted values (`#` starts an inline comment only at a token boundary)
//! - Single-quoted values (no escape processing)
//! - Double-quoted values (`\n`, `\r`, `\t`, `\\`, `\"` escapes)
//! - Multiline quoted values
//!
//! The parser is byte-oriented and allocation-free (beyond the caller-provided
//! output buffer). Malformed lines are skipped without panicking.

use memchr::memchr;

use super::extract::{ExtractResult, Extractor, EXTRACT_OUTPUT_CAP};

/// Extracts normalized `KEY=VALUE` lines from dotenv files.
pub struct DotEnvExtractor;

/// Outcome for one parsed assignment line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineResult {
    Appended,
    Skipped,
    CapReached,
}

/// Result of parsing just the value portion (`...` in `KEY=...`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueResult {
    Ok,
    Skip,
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

/// Append one normalized `KEY=VALUE\n` entry atomically.
///
/// `out` is rolled back to its original length on malformed values or when the
/// output cap is reached, so callers never observe partial assignments.
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

/// Parse an unquoted value and trim trailing whitespace/comment suffix.
fn parse_unquoted(value: &[u8], out: &mut Vec<u8>) -> ValueResult {
    let end = unquoted_comment_start(value).unwrap_or(value.len());
    let value = trim_ascii_end(&value[..end]);
    if push_bytes(out, value) {
        ValueResult::Ok
    } else {
        ValueResult::CapReached
    }
}

/// Parse a single-quoted value, allowing multiline content until the next `'`.
///
/// Backslashes are copied literally (no unescaping).
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

/// Parse a double-quoted value, allowing multiline content until the next `"`.
///
/// Recognized escapes: `\n`, `\r`, `\t`, `\\`, `\"`. Other `\x` forms keep
/// only `x` (the backslash is dropped).
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

/// Returns the first `#` that starts an inline comment in an unquoted value.
///
/// A `#` inside a token (e.g. `abc#def`) is treated as value content.
fn unquoted_comment_start(value: &[u8]) -> Option<usize> {
    (0..value.len())
        .find(|&idx| value[idx] == b'#' && (idx == 0 || value[idx - 1].is_ascii_whitespace()))
}

/// Strip a lowercase `export` prefix followed by ASCII whitespace.
///
/// Uppercase variants (e.g. `EXPORT`) are left unchanged.
fn strip_export_prefix(line: &[u8]) -> &[u8] {
    if line.len() <= 6 || &line[..6] != b"export" || !line[6].is_ascii_whitespace() {
        return line;
    }
    trim_ascii_start(&line[7..])
}

/// Return the next logical line and advance `pos` past the line terminator.
///
/// Supports both LF and CRLF inputs; the returned slice excludes terminators.
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

fn trim_ascii_start(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    while start < s.len() && s[start].is_ascii_whitespace() {
        start += 1;
    }
    &s[start..]
}

fn trim_ascii_end(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &s[..end]
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(s))
}

#[inline]
/// Append one byte if `out` has remaining extraction budget.
fn push_byte(out: &mut Vec<u8>, b: u8) -> bool {
    if out.len() >= EXTRACT_OUTPUT_CAP {
        return false;
    }
    out.push(b);
    true
}

#[inline]
/// Append a slice if it fits entirely within the extraction budget.
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

    #[test]
    fn extracts_basic_assignments() {
        let input = b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n");
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        let input = b"# comment\n \n\t# another\nTOKEN=abc\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"TOKEN=abc\n");
    }

    #[test]
    fn handles_export_prefix() {
        let input = b"export API_KEY=abc\n export\tDB_URL=postgres://localhost\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"API_KEY=abc\nDB_URL=postgres://localhost\n");
    }

    #[test]
    fn double_quoted_escapes_are_unescaped() {
        let input = b"KEY=\"line\\nnext\\t\\\"q\\\"\\\\\"\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"KEY=line\nnext\t\"q\"\\\n");
    }

    #[test]
    fn single_quoted_values_keep_backslashes() {
        let input = b"KEY='line\\nnext\\t\\\"q\\\"'\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"KEY=line\\nnext\\t\\\"q\\\"\n");
    }

    #[test]
    fn unquoted_values_trim_and_strip_inline_comment() {
        let input = b"A=foo # comment\nB=bar#not_comment\nC=   value   \n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"A=foo\nB=bar#not_comment\nC=value\n");
    }

    #[test]
    fn parses_multiline_double_quoted_values() {
        let input = b"CERT=\"line1\nline2\"\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"CERT=line1\nline2\n");
    }

    #[test]
    fn parses_multiline_single_quoted_values() {
        let input = b"CERT='line1\nline2'\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"CERT=line1\nline2\n");
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let input = b"NO_EQUALS\nBROKEN=\"unterminated\nNEXT=ok\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out, b"NEXT=ok\n");
    }

    #[test]
    fn returns_empty_when_no_assignments_found() {
        let input = b"# just comments\n   \n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Empty);
        assert!(out.is_empty());
    }

    #[test]
    fn respects_extract_output_cap() {
        let mut out = vec![b'x'; EXTRACT_OUTPUT_CAP - 2];
        let original = out.clone();
        let result = DotEnvExtractor.extract(b"A=1\n", &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Empty);
        assert_eq!(out, original);
    }
}
