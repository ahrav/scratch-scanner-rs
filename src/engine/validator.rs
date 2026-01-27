use crate::api::{DelimAfter, TailCharset, ValidatorKind};
use std::ops::Range;

// --------------------------
// Fast validator helpers
// --------------------------
//
// The validator fast-path is invoked directly on anchor hits. It assumes that
// the anchor is match-start aligned in the raw representation (i.e., the anchor
// start equals the regex match start). When enabled, it can emit findings
// without building windows or running the regex engine.
//
// All checks mirror `regex::bytes` semantics (ASCII word boundaries, ASCII
// character classes). The validator never expands its view beyond the input
// slice; any out-of-bounds access is treated as a non-match.

impl ValidatorKind {
    /// Returns true if this validator is enabled (i.e., not `None`).
    #[inline]
    pub(super) fn is_enabled(self) -> bool {
        !matches!(self, ValidatorKind::None)
    }

    /// Validate a rule at a raw anchor hit.
    ///
    /// `anchor_start` and `anchor_end` are the raw byte indices returned by the
    /// anchor automaton. On success, returns the matched span in raw bytes.
    pub(super) fn validate_raw_at_anchor(
        self,
        buf: &[u8],
        anchor_start: usize,
        anchor_end: usize,
    ) -> Option<Range<usize>> {
        if anchor_start > anchor_end || anchor_end > buf.len() {
            return None;
        }
        match self {
            ValidatorKind::None => None,
            ValidatorKind::AwsAccessKey => validate_aws_access_key(buf, anchor_start, anchor_end),
            ValidatorKind::PrefixFixed {
                tail_len,
                tail,
                require_word_boundary_before,
                delim_after,
            } => validate_prefix_fixed(
                buf,
                anchor_start,
                anchor_end,
                tail_len as usize,
                PrefixChecks {
                    tail,
                    require_word_boundary_before,
                    delim_after,
                },
            ),
            ValidatorKind::PrefixBounded {
                min_tail,
                max_tail,
                tail,
                require_word_boundary_before,
                delim_after,
            } => validate_prefix_bounded(
                buf,
                anchor_start,
                anchor_end,
                min_tail as usize,
                max_tail as usize,
                PrefixChecks {
                    tail,
                    require_word_boundary_before,
                    delim_after,
                },
            ),
        }
    }
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    // `regex::bytes` defines word bytes as ASCII `[A-Za-z0-9_]`. Non-ASCII
    // bytes are treated as non-word, so we mirror that here to keep the
    // fast validator path consistent with regex semantics.
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn has_word_boundary_before(buf: &[u8], start: usize) -> bool {
    if start == 0 || start >= buf.len() {
        return start == 0;
    }
    let prev = buf[start - 1];
    let cur = buf[start];
    is_word_byte(prev) != is_word_byte(cur)
}

#[inline]
fn is_gitleaks_token_terminator(b: u8) -> bool {
    matches!(b, b'\'' | b'"' | b'|' | b'`')
        || matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C')
}

#[inline]
fn match_end_with_delim(buf: &[u8], tail_end: usize, delim: DelimAfter) -> Option<usize> {
    match delim {
        DelimAfter::None => Some(tail_end),
        DelimAfter::GitleaksTokenTerminator => {
            if tail_end == buf.len() {
                return Some(tail_end);
            }
            match buf.get(tail_end) {
                Some(&b) if is_gitleaks_token_terminator(b) => Some(tail_end + 1),
                _ => None,
            }
        }
    }
}

#[inline]
fn tail_matches_charset(b: u8, charset: TailCharset) -> bool {
    match charset {
        TailCharset::UpperAlnum => matches!(b, b'A'..=b'Z' | b'0'..=b'9'),
        TailCharset::Alnum => b.is_ascii_alphanumeric(),
        TailCharset::LowerAlnum => matches!(b, b'a'..=b'z' | b'0'..=b'9'),
        TailCharset::AlnumDashUnderscore => b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'),
        TailCharset::Sendgrid66Set => {
            b.is_ascii_alphanumeric() || matches!(b, b'=' | b'_' | b'-' | b'.')
        }
        TailCharset::DatabricksSet => {
            b.is_ascii_digit() || matches!(b.to_ascii_uppercase(), b'A'..=b'H')
        }
        TailCharset::Base64Std => matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'
        ),
    }
}

#[derive(Clone, Copy, Debug)]
struct PrefixChecks {
    tail: TailCharset,
    require_word_boundary_before: bool,
    delim_after: DelimAfter,
}

fn validate_prefix_fixed(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    tail_len: usize,
    checks: PrefixChecks,
) -> Option<Range<usize>> {
    if checks.require_word_boundary_before && !has_word_boundary_before(buf, anchor_start) {
        return None;
    }

    let tail_start = anchor_end;
    let tail_end = tail_start.checked_add(tail_len)?;
    let tail_bytes = buf.get(tail_start..tail_end)?;

    if !tail_bytes
        .iter()
        .all(|&b| tail_matches_charset(b, checks.tail))
    {
        return None;
    }

    let match_end = match_end_with_delim(buf, tail_end, checks.delim_after)?;
    Some(anchor_start..match_end)
}

fn validate_prefix_bounded(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    min_tail: usize,
    max_tail: usize,
    checks: PrefixChecks,
) -> Option<Range<usize>> {
    if min_tail > max_tail {
        return None;
    }
    if checks.require_word_boundary_before && !has_word_boundary_before(buf, anchor_start) {
        return None;
    }

    let tail_start = anchor_end;
    if tail_start >= buf.len() {
        return None;
    }

    // Scan the tail until we hit a non-matching byte or the maximum length.
    let mut run_len = 0usize;
    while run_len < max_tail {
        let idx = tail_start + run_len;
        let Some(&b) = buf.get(idx) else {
            break;
        };
        if !tail_matches_charset(b, checks.tail) {
            break;
        }
        run_len += 1;
    }

    if run_len < min_tail {
        return None;
    }

    let max_len = run_len.min(max_tail);
    match checks.delim_after {
        DelimAfter::None => Some(anchor_start..(tail_start + max_len)),
        DelimAfter::GitleaksTokenTerminator => {
            // Backtrack to the longest tail that is immediately followed by a
            // valid terminator (or end-of-input), mirroring regex backtracking.
            for len in (min_tail..=max_len).rev() {
                let tail_end = tail_start + len;
                if let Some(match_end) = match_end_with_delim(buf, tail_end, checks.delim_after) {
                    return Some(anchor_start..match_end);
                }
            }
            None
        }
    }
}

fn validate_aws_access_key(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
) -> Option<Range<usize>> {
    let prefix_len = anchor_end.checked_sub(anchor_start)?;
    let end = anchor_start.checked_add(20)?;
    let block = buf.get(anchor_start..end)?;

    match prefix_len {
        // A3T + [A-Z0-9] + 16 tail chars
        3 => {
            if !matches!(block[3], b'A'..=b'Z' | b'0'..=b'9') {
                return None;
            }
            if !block[4..]
                .iter()
                .all(|&b| matches!(b, b'A'..=b'Z' | b'0'..=b'9'))
            {
                return None;
            }
        }
        // AKIA / AIDA / ... + 16 tail chars
        4 => {
            if !block[4..]
                .iter()
                .all(|&b| matches!(b, b'A'..=b'Z' | b'0'..=b'9'))
            {
                return None;
            }
        }
        _ => return None,
    }

    Some(anchor_start..end)
}
