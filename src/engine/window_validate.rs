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
//! 3. Run regex with reusable capture locations to access capture groups.
//! 4. Apply entropy gates on the *full match* (group 0).
//! 5. Extract the secret span using capture group priority (see [`extract_secret_span`]).
//! 6. Apply local context checks (when configured) on the secret span.
//! 7. Record the finding with the extracted secret span.
//!
//! # Secret Extraction
//! The finding's `span_start`/`span_end` reflect the *secret* portion of the match,
//! not necessarily the full regex match. The `root_hint_*` fields use the *full match*
//! span (not secret span or window span) to ensure correct deduplication in chunked
//! scans: `drop_prefix_findings()` uses `root_hint_end` to decide whether to keep a
//! finding. Using the full match span handles trailing context correctly (e.g., when
//! a pattern like `secret([a-z]+)(?:;|$)` has a delimiter that extends into new bytes).
//!
//! The extraction priority is:
//! 1. Configured `secret_group` if present and non-empty.
//! 2. Capture group 1 if non-empty (gitleaks convention).
//! 3. Full match (group 0) as fallback.
//!
//! # Design Choices
//! - Keyword/confirm gates run on raw UTF-16 bytes to avoid wasting decode budget.
//! - UTF-16 findings attach a `DecodeStep::Utf16Window` so callers can map
//!   decoded spans back to parent byte offsets.
//! - Capture locations are reused per rule to avoid per-match allocations in hot paths.
//!
//! # Entry Points
//! - `run_rule_on_window`: engine hot path that writes findings directly into
//!   `ScanScratch` and applies dedupe/drop-hint bookkeeping immediately.
//! - `run_rule_on_raw_window_into` / `run_rule_on_utf16_window_into`: scheduler
//!   adapters that accumulate findings in `scratch.tmp_findings` for the caller
//!   to commit and account for dropped findings.
//!
//! [`extract_secret_span`]: super::helpers::extract_secret_span

use crate::api::{
    DecodeStep, FileId, FindingRec, LocalContextSpec, StepId, Utf16Endianness, STEP_ROOT,
};
use memchr::memmem;
use regex::bytes::CaptureLocations;
use std::ops::Range;

use super::core::Engine;
use super::helpers::{
    contains_all_memmem, contains_any_memmem, decode_utf16be_to_buf, decode_utf16le_to_buf,
    entropy_gate_passes, extract_secret_span_locs, map_utf16_decoded_offset,
};
use super::rule_repr::{RuleCompiled, Variant};
use super::scratch::ScanScratch;

/// Number of bytes to scan backward from the anchor hint position.
///
/// This margin accounts for patterns where the anchor may be in the middle
/// of the match (e.g., backward-looking patterns). 64 bytes is sufficient
/// for most secret patterns while keeping overhead low.
const BACK_SCAN_MARGIN: usize = 64;

/// Iterate capture matches without allocating by reusing `CaptureLocations`.
///
/// Advances by one byte on empty matches to mirror `captures_iter` semantics.
#[inline]
fn for_each_capture_match(
    re: &regex::bytes::Regex,
    locs: &mut CaptureLocations,
    hay: &[u8],
    mut on_match: impl FnMut(&CaptureLocations, usize, usize),
) {
    let mut at = 0usize;
    while at <= hay.len() {
        let Some(m) = re.captures_read_at(locs, hay, at) else {
            break;
        };
        on_match(locs, m.start(), m.end());
        if m.end() == at {
            at = at.saturating_add(1);
        } else {
            at = m.end();
        }
    }
}

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

/// Returns the (line_start, line_end) bounds around `secret_start` when both
/// newline boundaries are found within the lookaround window.
///
/// If either boundary is missing within the bounded lookaround, returns `None`
/// to preserve fail-open behavior at chunk/window edges.
#[inline]
fn find_line_bounds(
    hay: &[u8],
    secret_start: usize,
    lookbehind: usize,
    lookahead: usize,
) -> Option<(usize, usize)> {
    let back = secret_start.min(lookbehind);
    let scan_start = secret_start - back;
    let mut line_start = None;
    for i in (scan_start..secret_start).rev() {
        if hay[i] == b'\n' {
            line_start = Some(i + 1);
            break;
        }
    }

    let fwd_end = secret_start.saturating_add(lookahead).min(hay.len());
    let mut line_end = None;
    for (i, &b) in hay.iter().enumerate().take(fwd_end).skip(secret_start) {
        if b == b'\n' {
            line_end = Some(i);
            break;
        }
    }

    match (line_start, line_end) {
        (Some(start), Some(end)) => Some((start, end)),
        _ => None,
    }
}

#[inline]
fn has_assignment_sep(line: &[u8]) -> bool {
    line.iter().any(|&b| b == b'=' || b == b':' || b == b'>')
}

#[inline]
fn contains_any_literal(hay: &[u8], needles: &[&[u8]]) -> bool {
    for &needle in needles {
        if memmem::find(hay, needle).is_some() {
            return true;
        }
    }
    false
}

#[inline]
fn is_quoted_at(hay: &[u8], secret_start: usize, secret_end: usize) -> Option<bool> {
    let left = secret_start.checked_sub(1)?;
    let ql = *hay.get(left)?;
    let qr = *hay.get(secret_end)?;
    let is_quote = ql == b'\'' || ql == b'"' || ql == b'`';
    Some(is_quote && ql == qr)
}

/// Bounded, fail-open local context gate.
///
/// Returns `false` only when the required context is definitively absent within
/// the bounded lookaround window. Missing line boundaries result in `true`.
#[inline]
fn local_context_passes(
    window: &[u8],
    secret_start: usize,
    secret_end: usize,
    spec: LocalContextSpec,
) -> bool {
    if spec.require_quoted {
        match is_quoted_at(window, secret_start, secret_end) {
            Some(true) => {}
            Some(false) => return false,
            None => {}
        }
    }

    if spec.require_same_line_assignment || spec.key_names_any.is_some() {
        let bounds = find_line_bounds(window, secret_start, spec.lookbehind, spec.lookahead);
        let (line_start, line_end) = match bounds {
            Some(bounds) => bounds,
            None => return true,
        };

        let line_before_secret = &window[line_start..line_end.min(secret_start)];

        if spec.require_same_line_assignment && !has_assignment_sep(line_before_secret) {
            return false;
        }

        if let Some(keys) = spec.key_names_any {
            if !contains_any_literal(line_before_secret, keys) {
                return false;
            }
        }
    }

    true
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
                let mut locs = scratch.capture_locs[rule_id as usize]
                    .take()
                    .expect("capture locations missing for rule");
                for_each_capture_match(&rule.re, &mut locs, search_window, |locs, start, end| {
                    // Get full match for entropy gating and anchor hint.
                    let match_start = search_start + start;
                    let match_end = search_start + end;

                    let entropy_ok = if let Some(ent) = entropy {
                        let mbytes = &window[match_start..match_end];
                        // Entropy is evaluated on the *matched* bytes, not the whole window.
                        // This keeps the signal tied to the candidate token itself.
                        entropy_gate_passes(
                            &ent,
                            mbytes,
                            &mut scratch.entropy_scratch,
                            &self.entropy_log2,
                        )
                    } else {
                        true
                    };

                    if entropy_ok {
                        // Extract secret span using capture group logic.
                        let (secret_start, secret_end) =
                            extract_secret_span_locs(locs, rule.secret_group);
                        let secret_start = search_start + secret_start;
                        let secret_end = search_start + secret_end;

                        let context_ok = if let Some(ctx) = rule.local_context {
                            local_context_passes(window, secret_start, secret_end, ctx)
                        } else {
                            true
                        };

                        if context_ok {
                            let span_in_buf = (w.start + secret_start)..(w.start + secret_end);
                            let match_span_in_buf = (w.start + match_start)..(w.start + match_end);
                            // Use FULL MATCH span for root_span_hint to ensure correct deduplication
                            // in chunked scans. drop_prefix_findings() uses root_hint_end to decide
                            // whether to keep a finding:
                            // - Window span: too wide → duplicates (the original bug)
                            // - Secret span: too narrow → missed findings when trailing context
                            //   (e.g., `;` delimiter) extends into new bytes
                            // - Full match span: correct → captures actual regex match extent
                            let root_span_hint =
                                if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                                    ctx.map_span(match_span_in_buf.clone())
                                } else {
                                    root_hint.clone().unwrap_or(match_span_in_buf)
                                };

                            let mut drop_hint_end = root_span_hint.end;
                            if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                                if let Some(end) =
                                    ctx.drop_hint_end_for_match(root_span_hint.clone())
                                {
                                    drop_hint_end = drop_hint_end.max(end);
                                }
                            }
                            let drop_hint_end = base_offset + drop_hint_end as u64;
                            // When root-span mapping is unavailable (nested transforms with
                            // length-changing parents), keep decoded spans in the dedupe key
                            // to avoid collapsing distinct matches.
                            let include_span =
                                step_id == STEP_ROOT || scratch.root_span_map_ctx.is_none();

                            let secret_bytes = &window[secret_start..secret_end];
                            let norm_hash = *blake3::hash(secret_bytes).as_bytes();
                            scratch.push_finding_with_drop_hint(
                                FindingRec {
                                    file_id,
                                    rule_id,
                                    span_start: span_in_buf.start as u32,
                                    span_end: span_in_buf.end as u32,
                                    root_hint_start: base_offset + root_span_hint.start as u64,
                                    root_hint_end: base_offset + root_span_hint.end as u64,
                                    dedupe_with_span: include_span,
                                    step_id,
                                },
                                norm_hash,
                                drop_hint_end,
                                include_span,
                            );
                        }
                    }
                });
                scratch.capture_locs[rule_id as usize] = Some(locs);
            }

            Variant::Utf16Le | Variant::Utf16Be => {
                // UTF-16 anchors can appear at either byte parity; merged windows may
                // cover both. Run both alignments to avoid dropping opposite-parity hits.
                let parity = anchor_hint.saturating_sub(w.start) & 1;
                let offsets = [parity, parity ^ 1];
                for offset in offsets {
                    let decode_start = w.start.saturating_add(offset);
                    if decode_start >= w.end {
                        continue;
                    }
                    let decode_range = decode_start..w.end;
                    self.run_rule_on_utf16_window_aligned(
                        rule_id,
                        rule,
                        variant,
                        buf,
                        decode_range,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        break;
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_utf16_window_aligned(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        decode_range: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        // Caller is responsible for UTF-16 alignment; `decode_range.start`
        // should be on a code-unit boundary (parity handled upstream).
        // Decode this window as UTF-16 and run the same validators on UTF-8 output.
        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }

        let raw_win = &buf[decode_range.clone()];

        if let Some(confirm) = &rule.confirm_all {
            // Confirm-all literals are encoded like anchors/keywords so we can
            // cheaply reject UTF-16 windows before decoding.
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
            _ => unreachable!(),
        };

        if decoded.is_err() {
            return;
        }

        // Create a slice that doesn't carry the borrow from `scratch`, allowing us to
        // call mutable methods on `scratch` while iterating over `decoded`. A simple
        // `scratch.utf16_buf.as_slice()` would hold an immutable borrow of `scratch`
        // for the slice's lifetime, preventing the mutable borrow needed for push_finding.
        // SAFETY: `utf16_buf` is not mutated while `decoded` is in use - the mutable
        // methods only modify `out`, `drop_hint_end`, `seen_findings`, not `utf16_buf`.
        let decoded_len = scratch.utf16_buf.len();
        let decoded_ptr = scratch.utf16_buf.as_slice().as_ptr();
        let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
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
                parent_span: decode_range.clone(),
            },
        );

        let entropy = rule.entropy;
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, decoded, |locs, start, end| {
            let span = start..end;

            let entropy_ok = if let Some(ent) = entropy {
                let mbytes = &decoded[span.clone()];
                // Entropy gate runs on UTF-8 decoded bytes because the regex
                // is evaluated there; this keeps thresholds consistent.
                entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                )
            } else {
                true
            };

            if entropy_ok {
                // Extract secret span using capture group logic.
                let (secret_start, secret_end) = extract_secret_span_locs(locs, rule.secret_group);

                let context_ok = if let Some(ctx) = rule.local_context {
                    local_context_passes(decoded, secret_start, secret_end, ctx)
                } else {
                    true
                };

                if context_ok {
                    // Map decoded UTF-8 match span back to raw UTF-16 byte offsets.
                    let match_raw_start = map_utf16_decoded_offset(
                        raw_win,
                        span.start,
                        matches!(variant, Variant::Utf16Le),
                    );
                    let match_raw_end = map_utf16_decoded_offset(
                        raw_win,
                        span.end,
                        matches!(variant, Variant::Utf16Le),
                    );
                    let mapped_span = (decode_range.start + match_raw_start)
                        ..(decode_range.start + match_raw_end);
                    // Apply root_span_map_ctx for transform-derived findings (same as Raw variant)
                    // to ensure each UTF-16 match gets a distinct root hint for deduplication.
                    let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                        ctx.map_span(mapped_span.clone())
                    } else {
                        root_hint.clone().unwrap_or(mapped_span)
                    };

                    let mut drop_hint_end = root_span_hint.end;
                    if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                        if let Some(end) = ctx.drop_hint_end_for_match(root_span_hint.clone()) {
                            drop_hint_end = drop_hint_end.max(end);
                        }
                    }
                    let drop_hint_end = base_offset + drop_hint_end as u64;
                    // Preserve decoded spans in the dedupe key when root-span mapping
                    // is unavailable for nested transforms.
                    let include_span =
                        utf16_step_id == STEP_ROOT || scratch.root_span_map_ctx.is_none();
                    let secret_bytes = &decoded[secret_start..secret_end];
                    let norm_hash = *blake3::hash(secret_bytes).as_bytes();
                    scratch.push_finding_with_drop_hint(
                        FindingRec {
                            file_id,
                            rule_id,
                            span_start: secret_start as u32,
                            span_end: secret_end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            dedupe_with_span: include_span,
                            step_id: utf16_step_id,
                        },
                        norm_hash,
                        drop_hint_end,
                        include_span,
                    );
                }
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
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
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, search_window, |locs, start, end| {
            // Adjust match offsets back to window coordinates.
            let match_start = search_start + start;
            let match_end = search_start + end;

            let entropy_ok = if let Some(ent) = entropy {
                let mbytes = &window[match_start..match_end];
                entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                )
            } else {
                true
            };

            if entropy_ok {
                // Extract secret span using capture group logic.
                let (secret_start, secret_end) = extract_secret_span_locs(locs, rule.secret_group);
                let secret_start = search_start + secret_start;
                let secret_end = search_start + secret_end;

                let context_ok = if let Some(ctx) = rule.local_context {
                    local_context_passes(window, secret_start, secret_end, ctx)
                } else {
                    true
                };

                if context_ok {
                    *found_any = true;

                    let span_start = window_start.saturating_add(secret_start as u64) as usize;
                    let span_end = window_start.saturating_add(secret_end as u64) as usize;
                    let span_in_buf = span_start..span_end;
                    // Use FULL MATCH span for root_span_hint (see Raw variant comment for rationale).
                    let match_hint_start = window_start.saturating_add(match_start as u64) as usize;
                    let match_hint_end = window_start.saturating_add(match_end as u64) as usize;
                    let match_span_in_buf = match_hint_start..match_hint_end;
                    let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                        ctx.map_span(match_span_in_buf.clone())
                    } else {
                        root_hint.clone().unwrap_or(match_span_in_buf)
                    };

                    if out.len() < max_findings {
                        let mut drop_hint_end = root_span_hint.end;
                        if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                            if let Some(end) = ctx.drop_hint_end_for_match(root_span_hint.clone()) {
                                drop_hint_end = drop_hint_end.max(end);
                            }
                        }
                        let drop_hint_end = base_offset + drop_hint_end as u64;
                        // Include span in dedupe key for root findings (stable offsets) or when
                        // root-span mapping is unavailable (nested transforms with length-changing
                        // parents). For mapped transforms, decoded spans can shift with chunk
                        // alignment, so dedupe uses only the root hint window.
                        let dedupe_with_span =
                            step_id == STEP_ROOT || scratch.root_span_map_ctx.is_none();

                        let secret_bytes = &window[secret_start..secret_end];
                        let norm_hash = *blake3::hash(secret_bytes).as_bytes();
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: span_in_buf.start as u32,
                            span_end: span_in_buf.end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            dedupe_with_span,
                            step_id,
                        });
                        scratch.tmp_drop_hint_end.push(drop_hint_end);
                        scratch.tmp_norm_hash.push(norm_hash);
                    } else {
                        *dropped = dropped.saturating_add(1);
                    }
                }
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
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
    fn run_rule_on_utf16_window_aligned_into(
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

        // Create a slice that doesn't carry the borrow from `scratch`, allowing us to
        // call mutable methods on `scratch` while iterating over `decoded`. A simple
        // `scratch.utf16_buf.as_slice()` would hold an immutable borrow of `scratch`
        // for the slice's lifetime, preventing the mutable borrow needed for push_finding.
        // SAFETY: `utf16_buf` is not mutated while `decoded` is in use - the mutable
        // methods only modify `out`, `drop_hint_end`, `seen_findings`, not `utf16_buf`.
        let decoded_len = scratch.utf16_buf.len();
        let decoded_ptr = scratch.utf16_buf.as_slice().as_ptr();
        let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
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
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, decoded, |locs, start, end| {
            let span = start..end;

            let entropy_ok = if let Some(ent) = entropy {
                let mbytes = &decoded[span.clone()];
                entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                )
            } else {
                true
            };

            if entropy_ok {
                // Extract secret span using capture group logic.
                let (secret_start, secret_end) = extract_secret_span_locs(locs, rule.secret_group);

                let context_ok = if let Some(ctx) = rule.local_context {
                    local_context_passes(decoded, secret_start, secret_end, ctx)
                } else {
                    true
                };

                if context_ok {
                    *found_any = true;

                    // Map decoded UTF-8 match span back to raw UTF-16 offsets, then
                    // lift into decoded-stream coordinates and (when available) map
                    // through the transform root-span context.
                    let match_raw_start = map_utf16_decoded_offset(
                        raw_win,
                        span.start,
                        matches!(variant, Variant::Utf16Le),
                    );
                    let match_raw_end = map_utf16_decoded_offset(
                        raw_win,
                        span.end,
                        matches!(variant, Variant::Utf16Le),
                    );
                    let match_stream_start = window_start as usize + match_raw_start;
                    let match_stream_end = window_start as usize + match_raw_end;
                    let mapped_span = match_stream_start..match_stream_end;
                    let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                        ctx.map_span(mapped_span.clone())
                    } else {
                        root_hint.clone().unwrap_or(mapped_span)
                    };

                    if out.len() < max_findings {
                        let mut drop_hint_end = root_span_hint.end;
                        if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                            if let Some(end) = ctx.drop_hint_end_for_match(root_span_hint.clone()) {
                                drop_hint_end = drop_hint_end.max(end);
                            }
                        }
                        let drop_hint_end = base_offset + drop_hint_end as u64;
                        // Include span in dedupe key for root findings or when root-span mapping
                        // is unavailable. See run_rule_on_raw_window_into for full rationale.
                        let dedupe_with_span =
                            utf16_step_id == STEP_ROOT || scratch.root_span_map_ctx.is_none();
                        let secret_bytes = &decoded[secret_start..secret_end];
                        let norm_hash = *blake3::hash(secret_bytes).as_bytes();
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: secret_start as u32,
                            span_end: secret_end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            dedupe_with_span,
                            step_id: utf16_step_id,
                        });
                        scratch.tmp_drop_hint_end.push(drop_hint_end);
                        scratch.tmp_norm_hash.push(norm_hash);
                    } else {
                        *dropped = dropped.saturating_add(1);
                    }
                }
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
    }

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
        anchor_hint: u64,
    ) {
        // UTF-16 anchors can land on either byte parity within a merged window;
        // scan both alignments so mixed-parity anchors are not missed.
        let parity = (anchor_hint.saturating_sub(window_start) & 1) as usize;
        let offsets = [parity, parity ^ 1];

        for offset in offsets {
            if offset >= raw_win.len() {
                continue;
            }
            self.run_rule_on_utf16_window_aligned_into(
                rule_id,
                rule,
                variant,
                &raw_win[offset..],
                window_start.saturating_add(offset as u64),
                step_id,
                root_hint,
                base_offset,
                file_id,
                scratch,
                dropped,
                found_any,
            );
            if scratch.total_decode_output_bytes >= self.tuning.max_total_decode_output_bytes {
                break;
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

    #[test]
    fn test_local_context_same_line_assignment_passes() {
        let spec = LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: true,
            require_quoted: false,
            key_names_any: None,
        };
        let window = b"prefix\nkey = SECRET\nsuffix";
        let secret_start = window.iter().position(|&b| b == b'S').unwrap();
        let secret_end = secret_start + "SECRET".len();
        assert!(local_context_passes(window, secret_start, secret_end, spec));
    }

    #[test]
    fn test_local_context_same_line_assignment_fails_when_missing() {
        let spec = LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: true,
            require_quoted: false,
            key_names_any: None,
        };
        let window = b"prefix\nnope SECRET\nsuffix";
        let secret_start = window.iter().position(|&b| b == b'S').unwrap();
        let secret_end = secret_start + "SECRET".len();
        assert!(!local_context_passes(
            window,
            secret_start,
            secret_end,
            spec
        ));
    }

    #[test]
    fn test_local_context_same_line_assignment_fail_open_without_bounds() {
        let spec = LocalContextSpec {
            lookbehind: 4,
            lookahead: 4,
            require_same_line_assignment: true,
            require_quoted: false,
            key_names_any: None,
        };
        let window = b"prefix SECRET suffix";
        let secret_start = window.iter().position(|&b| b == b'S').unwrap();
        let secret_end = secret_start + "SECRET".len();
        assert!(local_context_passes(window, secret_start, secret_end, spec));
    }

    #[test]
    fn test_local_context_requires_quotes() {
        let spec = LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: false,
            require_quoted: true,
            key_names_any: None,
        };
        let window = b"key='SECRET' ";
        let secret_start = window.iter().position(|&b| b == b'S').unwrap();
        let secret_end = secret_start + "SECRET".len();
        assert!(local_context_passes(window, secret_start, secret_end, spec));

        let window = b"key=SECRET ";
        let secret_start = window.iter().position(|&b| b == b'S').unwrap();
        let secret_end = secret_start + "SECRET".len();
        assert!(!local_context_passes(
            window,
            secret_start,
            secret_end,
            spec
        ));
    }
}
