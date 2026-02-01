//! Window-level validation against compiled rules.
//!
//! Purpose: run a compiled rule against a fixed-size window of bytes and record
//! findings while enforcing cheap gates and decode budgets.
//!
//! # Invariants
//! - Window ranges must be valid for the provided buffer.
//! - For `Variant::Raw`, match spans are in raw byte space; for UTF-16 variants,
//!   match spans are in decoded UTF-8 byte space.
//! - `root_hint` (when present) is expressed in the same coordinate space as
//!   `base_offset` and anchors findings back to the parent stream.
//!
//! # Algorithm
//! 1. Apply cheap byte gates (must-contain, confirm-all, keyword gate).
//! 2. For UTF-16 variants, decode with per-window and total-output budgets.
//! 3. Run regex via `captures_iter` to access capture groups.
//! 4. Apply entropy gates on the *full match* (group 0).
//! 5. Extract the secret span using capture group priority (see [`extract_secret_span`]).
//! 6. Record the finding with the extracted secret span.
//!
//! # Secret Extraction
//! The finding's `span_start`/`span_end` reflect the *secret* portion of the match,
//! not necessarily the full regex match. This enables accurate deduplication: two
//! findings with identical secrets (but different surrounding context) will hash
//! the same. The extraction priority is:
//! 1. Configured `secret_group` if present and non-empty.
//! 2. Capture group 1 if non-empty (gitleaks convention).
//! 3. Full match (group 0) as fallback.
//!
//! # Design Choices
//! - Keyword/confirm gates run on raw UTF-16 bytes to avoid wasting decode budget.
//! - UTF-16 findings attach a `DecodeStep::Utf16Window` so callers can map
//!   decoded spans back to parent byte offsets.
//!
//! [`extract_secret_span`]: super::helpers::extract_secret_span

use crate::api::{DecodeStep, FileId, FindingRec, StepId, Utf16Endianness};
use memchr::memmem;
use std::ops::Range;

use super::core::Engine;
use super::helpers::{
    contains_all_memmem, contains_any_memmem, decode_utf16be_to_buf, decode_utf16le_to_buf,
    entropy_gate_passes, extract_secret_span,
};
use super::rule_repr::{RuleCompiled, Variant};
use super::scratch::ScanScratch;

/// Number of bytes to scan backward from the anchor hint position.
///
/// This margin accounts for patterns where the anchor may be in the middle
/// of the match (e.g., backward-looking patterns). 64 bytes is sufficient
/// for most secret patterns while keeping overhead low.
const BACK_SCAN_MARGIN: usize = 64;

/// Cheap precheck for rules with assignment-value patterns.
///
/// Returns `false` if the regex cannot possibly match because the window lacks
/// the necessary structure: a separator (`=`, `:`, `>`) followed by a plausible
/// token (10+ alphanumeric/underscore/hyphen/dot characters).
///
/// This is a conservative filter: it only rejects windows where the regex
/// definitely cannot match, never producing false negatives.
///
/// # Performance
/// O(window.len()) byte scan vs O(regex_complexity × window.len()) for regex.
#[inline]
fn has_assignment_value_shape(window: &[u8]) -> bool {
    // Find any assignment separator. We check for `=`, `:`, and `>` (for `=>`).
    // The position we find may be part of `=>`, but that's fine for our purpose.
    let sep_pos = match window
        .iter()
        .position(|&b| b == b'=' || b == b':' || b == b'>')
    {
        Some(pos) => pos,
        None => return false,
    };

    // Check for plausible token run after separator (10+ alnum/underscore/hyphen/dot).
    let after_sep = &window[sep_pos + 1..];

    // Skip whitespace/quotes/extra separators after the separator.
    let token_start = after_sep
        .iter()
        .position(|&b| !matches!(b, b' ' | b'\t' | b'"' | b'\'' | b'`' | b'=' | b'>'))
        .unwrap_or(after_sep.len());

    if token_start >= after_sep.len() {
        return false;
    }

    // Count consecutive token chars.
    let token_bytes = &after_sep[token_start..];
    let token_len = token_bytes
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        .count();

    token_len >= 10
}

impl Engine {
    /// Runs a compiled rule against one window and appends findings into `scratch`.
    ///
    /// Guarantees / invariants:
    /// - `w` must be a valid range into `buf`.
    /// - For `Variant::Raw`, spans are expressed in raw `buf` byte space.
    /// - For UTF-16 variants, spans are in decoded UTF-8 byte space and the
    ///   parent raw span is recorded via `DecodeStep::Utf16Window`.
    /// - `root_hint`, when provided, is expected to be in the same coordinate
    ///   space as `buf`/`w` and is used as the finding root span.
    /// - `anchor_hint` is the byte offset (in `buf` coordinates) where Vectorscan
    ///   reported the match start. Regex search starts near this position with
    ///   a back-scan margin for correctness.
    ///
    /// Errors / edge cases:
    /// - Returns early when gates fail, decode budgets are exhausted, or decoding
    ///   fails.
    /// - May drop findings when the scratch capacity cap is reached.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_window(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        w: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        anchor_hint: usize,
    ) {
        match variant {
            Variant::Raw => {
                let window = &buf[w.clone()];

                if let Some(needle) = rule.must_contain {
                    if memmem::find(window, needle).is_none() {
                        return;
                    }
                }

                if let Some(confirm) = &rule.confirm_all {
                    let vidx = Variant::Raw.idx();
                    if let Some(primary) = &confirm.primary[vidx] {
                        if memmem::find(window, primary).is_none() {
                            return;
                        }
                    }
                    if !contains_all_memmem(window, &confirm.rest[vidx]) {
                        return;
                    }
                }

                if let Some(kws) = &rule.keywords {
                    // Keyword gate is a cheap pre-regex filter: if none of the
                    // keywords appear in this window, the regex cannot be relevant.
                    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                        return;
                    }
                }

                // Assignment-shape precheck: skip regex if window lacks required structure.
                if rule.needs_assignment_shape_check && !has_assignment_value_shape(window) {
                    return;
                }

                // Compute search start based on anchor hint with back-scan margin.
                // Gates still run on full window for correctness, but regex starts near anchor.
                let hint_in_window = anchor_hint.saturating_sub(w.start);
                let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
                let search_window = &window[search_start..];

                let entropy = rule.entropy;
                for caps in rule.re.captures_iter(search_window) {
                    // Get full match for entropy gating and anchor hint.
                    let full_match = caps.get(0).expect("group 0 always exists");
                    let match_start = search_start + full_match.start();
                    let match_end = search_start + full_match.end();

                    if let Some(ent) = entropy {
                        let mbytes = &window[match_start..match_end];
                        // Entropy is evaluated on the *matched* bytes, not the whole window.
                        // This keeps the signal tied to the candidate token itself.
                        if !entropy_gate_passes(
                            &ent,
                            mbytes,
                            &mut scratch.entropy_scratch,
                            &self.entropy_log2,
                        ) {
                            continue;
                        }
                    }

                    // Extract secret span using capture group logic.
                    let (secret_start, secret_end) = extract_secret_span(&caps, rule.secret_group);
                    let secret_start = search_start + secret_start;
                    let secret_end = search_start + secret_end;

                    let span_in_buf = (w.start + secret_start)..(w.start + secret_end);
                    // Use full window span for root_span_hint (aligned with UTF-16 path).
                    // The secret span is still tracked via span_start/span_end.
                    let root_span_hint = root_hint.clone().unwrap_or_else(|| w.clone());

                    scratch.push_finding(FindingRec {
                        file_id,
                        rule_id,
                        span_start: span_in_buf.start as u32,
                        span_end: span_in_buf.end as u32,
                        root_hint_start: base_offset + root_span_hint.start as u64,
                        root_hint_end: base_offset + root_span_hint.end as u64,
                        step_id,
                    });
                }
            }

            Variant::Utf16Le | Variant::Utf16Be => {
                // Decode this window as UTF-16 and run the same validators on UTF-8 output.
                let remaining = self
                    .tuning
                    .max_total_decode_output_bytes
                    .saturating_sub(scratch.total_decode_output_bytes);
                if remaining == 0 {
                    return;
                }

                if let Some(confirm) = &rule.confirm_all {
                    // Confirm-all literals are encoded like anchors/keywords so we can
                    // cheaply reject UTF-16 windows before decoding.
                    let raw_win = &buf[w.clone()];
                    let vidx = variant.idx();
                    if let Some(primary) = &confirm.primary[vidx] {
                        if memmem::find(raw_win, primary).is_none() {
                            return;
                        }
                    }
                    if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                        return;
                    }
                }

                if let Some(kws) = &rule.keywords {
                    // For UTF-16 variants, apply the keyword gate on the raw UTF-16 bytes
                    // *before* decoding to avoid spending decode budget on windows that
                    // could never pass the keyword check.
                    let raw_win = &buf[w.clone()];
                    let vidx = variant.idx();
                    if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                        return;
                    }
                }

                let max_out = self
                    .tuning
                    .max_utf16_decoded_bytes_per_window
                    .min(remaining);

                let decoded = match variant {
                    Variant::Utf16Le => {
                        decode_utf16le_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    Variant::Utf16Be => {
                        decode_utf16be_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    _ => unreachable!(),
                };

                if decoded.is_err() {
                    return;
                }

                let decoded = scratch.utf16_buf.as_slice();
                if decoded.is_empty() {
                    return;
                }

                scratch.total_decode_output_bytes = scratch
                    .total_decode_output_bytes
                    .saturating_add(decoded.len());
                if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
                    return;
                }

                if let Some(needle) = rule.must_contain {
                    if memmem::find(decoded, needle).is_none() {
                        return;
                    }
                }

                // Assignment-shape precheck on decoded UTF-8 bytes.
                if rule.needs_assignment_shape_check && !has_assignment_value_shape(decoded) {
                    return;
                }

                let endianness = match variant {
                    Variant::Utf16Le => Utf16Endianness::Le,
                    Variant::Utf16Be => Utf16Endianness::Be,
                    Variant::Raw => unreachable!("raw variant in UTF-16 branch"),
                };
                let utf16_step_id = scratch.step_arena.push(
                    step_id,
                    DecodeStep::Utf16Window {
                        endianness,
                        parent_span: w.clone(),
                    },
                );

                let max_findings = scratch.max_findings;
                let out = &mut scratch.out;
                let dropped = &mut scratch.findings_dropped;
                let entropy = rule.entropy;
                for caps in rule.re.captures_iter(decoded) {
                    let full_match = caps.get(0).expect("group 0 always exists");
                    let span = full_match.start()..full_match.end();

                    if let Some(ent) = entropy {
                        let mbytes = &decoded[span.clone()];
                        // Entropy gate runs on UTF-8 decoded bytes because the regex
                        // is evaluated there; this keeps thresholds consistent.
                        if !entropy_gate_passes(
                            &ent,
                            mbytes,
                            &mut scratch.entropy_scratch,
                            &self.entropy_log2,
                        ) {
                            continue;
                        }
                    }

                    // Extract secret span using capture group logic.
                    let (secret_start, secret_end) = extract_secret_span(&caps, rule.secret_group);

                    let root_span_hint = root_hint.clone().unwrap_or_else(|| w.clone());

                    if out.len() < max_findings {
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: secret_start as u32,
                            span_end: secret_end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            step_id: utf16_step_id,
                        });
                    } else {
                        *dropped = dropped.saturating_add(1);
                    }
                }
            }
        }
    }

    /// Validates a raw decoded-space window and appends findings into `scratch.tmp_findings`.
    ///
    /// Guarantees / invariants:
    /// - `window_start` is the decoded-stream offset for `window[0]`.
    /// - Span offsets in findings are expressed in decoded-stream byte space.
    /// - `root_hint`, when present, is in the same coordinate space as
    ///   `base_offset` and overrides the default root span.
    /// - `anchor_hint` is the decoded-stream offset where Vectorscan reported the
    ///   match start. Regex search starts near this position with a back-scan margin.
    ///
    /// # Effects
    /// - Sets `found_any` when any match passes gates.
    /// - Increments `dropped` when the per-chunk findings cap is exceeded.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_raw_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        window: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        dropped: &mut usize,
        found_any: &mut bool,
        anchor_hint: u64,
    ) {
        if let Some(needle) = rule.must_contain {
            if memmem::find(window, needle).is_none() {
                return;
            }
        }

        if let Some(confirm) = &rule.confirm_all {
            let vidx = Variant::Raw.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(window, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(window, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = &rule.keywords {
            if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                return;
            }
        }

        // Assignment-shape precheck: skip regex if window lacks required structure.
        if rule.needs_assignment_shape_check && !has_assignment_value_shape(window) {
            return;
        }

        // Compute search start based on anchor hint with back-scan margin.
        // Gates still run on full window for correctness, but regex starts near anchor.
        let hint_in_window = anchor_hint.saturating_sub(window_start) as usize;
        let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
        let search_window = &window[search_start..];

        let max_findings = scratch.max_findings;
        let out = &mut scratch.tmp_findings;
        let entropy = rule.entropy;
        for caps in rule.re.captures_iter(search_window) {
            let full_match = caps.get(0).expect("group 0 always exists");
            // Adjust match offsets back to window coordinates.
            let match_start = search_start + full_match.start();
            let match_end = search_start + full_match.end();

            if let Some(ent) = entropy {
                let mbytes = &window[match_start..match_end];
                if !entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                ) {
                    continue;
                }
            }

            *found_any = true;

            // Extract secret span using capture group logic.
            let (secret_start, secret_end) = extract_secret_span(&caps, rule.secret_group);
            let secret_start = search_start + secret_start;
            let secret_end = search_start + secret_end;

            let span_start = window_start.saturating_add(secret_start as u64) as usize;
            let span_end = window_start.saturating_add(secret_end as u64) as usize;
            let span_in_buf = span_start..span_end;
            let root_span_hint = root_hint.clone().unwrap_or_else(|| span_in_buf.clone());

            if out.len() < max_findings {
                out.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: span_in_buf.start as u32,
                    span_end: span_in_buf.end as u32,
                    root_hint_start: base_offset + root_span_hint.start as u64,
                    root_hint_end: base_offset + root_span_hint.end as u64,
                    step_id,
                });
            } else {
                *dropped = dropped.saturating_add(1);
            }
        }
    }

    /// Validates a UTF-16 window by decoding to UTF-8 and appending findings.
    ///
    /// Guarantees / invariants:
    /// - `window_start` is the decoded-stream offset for `raw_win[0]`.
    /// - Spans recorded in findings are in decoded UTF-8 byte space.
    /// - An attached [`DecodeStep::Utf16Window`] records the raw UTF-16 parent
    ///   span in decoded-stream byte offsets.
    /// - `root_hint`, when present, is in the same coordinate space as
    ///   `base_offset` and overrides the default root span.
    /// - `anchor_hint` is provided for API consistency but is not currently used
    ///   for offset search in UTF-16 path due to coordinate space differences
    ///   between raw UTF-16 bytes and decoded UTF-8.
    ///
    /// # Effects
    /// - Sets `found_any` when any match passes gates.
    /// - Increments `dropped` when the per-chunk findings cap is exceeded.
    ///
    /// # Edge cases
    /// - Returns early when decode budgets are exhausted or decoding fails.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_utf16_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        raw_win: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        dropped: &mut usize,
        found_any: &mut bool,
        _anchor_hint: u64,
    ) {
        // Decode this window as UTF-16 and run the same validators on UTF-8 output.
        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }

        if let Some(confirm) = &rule.confirm_all {
            let vidx = variant.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(raw_win, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = &rule.keywords {
            let vidx = variant.idx();
            if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                return;
            }
        }

        let max_out = self
            .tuning
            .max_utf16_decoded_bytes_per_window
            .min(remaining);

        let decoded = match variant {
            Variant::Utf16Le => decode_utf16le_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Utf16Be => decode_utf16be_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        if decoded.is_err() {
            return;
        }

        let decoded = scratch.utf16_buf.as_slice();
        if decoded.is_empty() {
            return;
        }

        scratch.total_decode_output_bytes = scratch
            .total_decode_output_bytes
            .saturating_add(decoded.len());
        if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
            return;
        }

        if let Some(needle) = rule.must_contain {
            if memmem::find(decoded, needle).is_none() {
                return;
            }
        }

        // Assignment-shape precheck on decoded UTF-8 bytes.
        if rule.needs_assignment_shape_check && !has_assignment_value_shape(decoded) {
            return;
        }

        let endianness = match variant {
            Variant::Utf16Le => Utf16Endianness::Le,
            Variant::Utf16Be => Utf16Endianness::Be,
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        let parent_span =
            window_start as usize..window_start.saturating_add(raw_win.len() as u64) as usize;
        let utf16_step_id = scratch.step_arena.push(
            step_id,
            DecodeStep::Utf16Window {
                endianness,
                parent_span: parent_span.clone(),
            },
        );

        let max_findings = scratch.max_findings;
        let out = &mut scratch.tmp_findings;
        let entropy = rule.entropy;
        for caps in rule.re.captures_iter(decoded) {
            let full_match = caps.get(0).expect("group 0 always exists");
            let span = full_match.start()..full_match.end();

            if let Some(ent) = entropy {
                let mbytes = &decoded[span.clone()];
                if !entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                ) {
                    continue;
                }
            }

            *found_any = true;

            // Extract secret span using capture group logic.
            let (secret_start, secret_end) = extract_secret_span(&caps, rule.secret_group);

            let root_span_hint = root_hint.clone().unwrap_or_else(|| parent_span.clone());

            if out.len() < max_findings {
                out.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: secret_start as u32,
                    span_end: secret_end as u32,
                    root_hint_start: base_offset + root_span_hint.start as u64,
                    root_hint_end: base_offset + root_span_hint.end as u64,
                    step_id: utf16_step_id,
                });
            } else {
                *dropped = dropped.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_assignment_value_shape_with_equals() {
        // Basic assignment with long token
        assert!(has_assignment_value_shape(b"api_key=AKIAIOSFODNN7EXAMPLE"));
        assert!(has_assignment_value_shape(b"token = abcdefghij1234567890"));
        assert!(has_assignment_value_shape(b"secret=\"longtoken1234\""));
    }

    #[test]
    fn test_has_assignment_value_shape_with_colon() {
        // JSON-style assignment
        assert!(has_assignment_value_shape(
            b"\"api_key\": \"AKIAIOSFODNN7EXAMPLE\""
        ));
        assert!(has_assignment_value_shape(b"token: abcdefghij1234567890"));
    }

    #[test]
    fn test_has_assignment_value_shape_with_arrow() {
        // Arrow assignment (=> becomes > after =)
        assert!(has_assignment_value_shape(b"key => longtoken1234567890"));
        assert!(has_assignment_value_shape(b"secret => AKIAIOSFODNN7EX"));
    }

    #[test]
    fn test_has_assignment_value_shape_short_token() {
        // Token too short (less than 10 chars)
        assert!(!has_assignment_value_shape(b"key=short"));
        assert!(!has_assignment_value_shape(b"x: abc"));
        assert!(!has_assignment_value_shape(b"token = 123456789")); // exactly 9 chars
    }

    #[test]
    fn test_has_assignment_value_shape_no_separator() {
        // No assignment separator at all
        assert!(!has_assignment_value_shape(
            b"some random text without assignment"
        ));
        assert!(!has_assignment_value_shape(b"api_key AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_has_assignment_value_shape_no_token_after_separator() {
        // Separator but no token after it
        assert!(!has_assignment_value_shape(b"key="));
        assert!(!has_assignment_value_shape(b"token:   "));
        assert!(!has_assignment_value_shape(b"secret = \"\""));
    }

    #[test]
    fn test_has_assignment_value_shape_with_special_chars_in_token() {
        // Token with allowed special chars (underscore, hyphen, dot)
        assert!(has_assignment_value_shape(b"key=abc_def-ghi.jkl"));
        assert!(has_assignment_value_shape(b"token: some-long-token-value"));
        assert!(has_assignment_value_shape(b"id = user.name.domain"));
    }

    #[test]
    fn test_has_assignment_value_shape_boundary_10_chars() {
        // Exactly 10 chars should pass
        assert!(has_assignment_value_shape(b"key=0123456789"));
        // 9 chars should fail
        assert!(!has_assignment_value_shape(b"key=012345678"));
    }

    #[test]
    fn test_has_assignment_value_shape_skips_whitespace_and_quotes() {
        // Whitespace and quotes after separator should be skipped
        assert!(has_assignment_value_shape(b"key=  longtokenvalue"));
        assert!(has_assignment_value_shape(b"key=\"longtokenvalue\""));
        assert!(has_assignment_value_shape(b"key='longtokenvalue'"));
        assert!(has_assignment_value_shape(b"key=`longtokenvalue`"));
    }
}
