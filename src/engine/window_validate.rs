//! Window-level validation against compiled rules.
//!
//! Purpose: run a compiled rule against a fixed-size window of bytes and record
//! findings while enforcing cheap gates and decode budgets.
//!
//! Invariants:
//! - Window ranges must be valid for the provided buffer.
//! - For `Variant::Raw`, match spans are in raw byte space; for UTF-16 variants,
//!   match spans are in decoded UTF-8 byte space.
//! - `root_hint` (when present) is expressed in the same coordinate space as
//!   `base_offset` and anchors findings back to the parent stream.
//!
//! High-level algorithm:
//! 1. Apply cheap byte gates (must-contain, confirm-all, keyword gate).
//! 2. For UTF-16 variants, decode with per-window and total-output budgets.
//! 3. Run the regex, apply entropy gates, and record findings.
//!
//! Design choices:
//! - Keyword/confirm gates run on raw UTF-16 bytes to avoid wasting decode budget.
//! - UTF-16 findings attach a `DecodeStep::Utf16Window` so callers can map
//!   decoded spans back to parent byte offsets.

use crate::api::{DecodeStep, FileId, FindingRec, StepId, Utf16Endianness};
use memchr::memmem;
use std::ops::Range;

use super::core::Engine;
use super::helpers::{
    contains_all_memmem, contains_any_memmem, decode_utf16be_to_buf, decode_utf16le_to_buf,
    entropy_gate_passes,
};
use super::rule_repr::{RuleCompiled, Variant};
use super::scratch::ScanScratch;

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

                let entropy = rule.entropy;
                for rm in rule.re.find_iter(window) {
                    if let Some(ent) = entropy {
                        let mbytes = &window[rm.start()..rm.end()];
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

                    let span_in_buf = (w.start + rm.start())..(w.start + rm.end());
                    let root_span_hint = root_hint.clone().unwrap_or_else(|| span_in_buf.clone());

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
                for rm in rule.re.find_iter(decoded) {
                    let span = rm.start()..rm.end();

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

                    let root_span_hint = root_hint.clone().unwrap_or_else(|| w.clone());

                    if out.len() < max_findings {
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: span.start as u32,
                            span_end: span.end as u32,
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

        let max_findings = scratch.max_findings;
        let out = &mut scratch.tmp_findings;
        let entropy = rule.entropy;
        for rm in rule.re.find_iter(window) {
            if let Some(ent) = entropy {
                let mbytes = &window[rm.start()..rm.end()];
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
            let span_start = window_start.saturating_add(rm.start() as u64) as usize;
            let span_end = window_start.saturating_add(rm.end() as u64) as usize;
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
        for rm in rule.re.find_iter(decoded) {
            let span = rm.start()..rm.end();

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
            let root_span_hint = root_hint.clone().unwrap_or_else(|| parent_span.clone());

            if out.len() < max_findings {
                out.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: span.start as u32,
                    span_end: span.end as u32,
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
