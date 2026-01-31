//! Transform span detection and streaming decode helpers.
//!
//! # Overview
//! This module implements the "transform" stage of the scanner for URL-percent
//! and Base64 payloads. Each transform has two pieces:
//! - a permissive span finder that favors recall over strict validation
//! - a streaming decoder that enforces correctness with bounded memory
//!
//! ## URL percent-encoding
//! - The span finder scans URL-ish runs (RFC3986 unreserved/reserved plus '%' and '+')
//!   and keeps runs that contain at least one escape (and optionally '+' when
//!   `plus_to_space` is enabled).
//! - The decoder converts `%HH` escapes and optional `+` to space; invalid or
//!   incomplete escapes pass through unchanged.
//!
//! ## Base64 (standard + URL-safe)
//! - The span finder scans runs of base64 alphabet plus allowed whitespace.
//!   `min_len` counts alphabet characters only; whitespace does not contribute.
//! - The decoder ignores whitespace, validates padding, and accepts an unpadded
//!   tail (2 or 3 characters in the final quantum).
//!
//! # Invariants and guarantees
//! - Span finders are single-pass and capped by `max_len` and `max_spans`.
//! - Spans are byte ranges into the original buffer, produced in ascending order.
//! - Long runs are split at `max_len` boundaries to bound worst-case work.
//! - Decoders are single-pass and O(1) memory; they emit bounded chunks via callbacks.
//!
//! # Span splitting (edge case)
//! Runs are split strictly on `max_len` byte boundaries, without aligning to
//! encoding quanta (`%HH` or 4-char base64). This is an explicit trade-off:
//! scanning stays bounded, but a valid encoding can be split across spans.
//! Downstream decode treats each span independently; percent-escape fragments
//! pass through unchanged, while base64 fragments can be rejected.
//!
//! # Trade-offs
//! These components intentionally trade precision for cheap scanning. Strict
//! validation happens in decode/gating, while span finders bias toward not
//! missing possible payloads.
//!
//! # Streaming usage
//! The `*SpanStream` scanners accept chunked input via `feed(chunk, base_offset, ...)`,
//! where `base_offset` is the absolute byte offset of `chunk[0]` in the original
//! buffer. Call `finish(end_offset, ...)` once at end-of-stream to flush a trailing
//! run; after `on_span` returns `false`, the stream becomes inert until `reset()`.
//! Chunks are expected to arrive in-order with monotonic `base_offset` (typically
//! contiguous). Gaps or overlaps split runs across chunk boundaries and may
//! suppress or fragment spans.

use super::hit_pool::SpanU32;
use crate::api::{TransformConfig, TransformId};
use crate::scratch_memory::ScratchVec;
use memchr::{memchr, memchr2};
use std::ops::{ControlFlow, Range};

/// Output buffer size used by streaming decoders.
pub(super) const STREAM_DECODE_CHUNK_BYTES: usize = 16 * 1024;

// --------------------------
// Transform: URL percent
// --------------------------

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

// Caller must check `is_hex` first; non-hex bytes map to 0.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// Byte-class table used by both URL and Base64 scanners.
const URLISH: u8 = 1 << 0;
const B64_CHAR: u8 = 1 << 1;
const B64_WS: u8 = 1 << 2;
const B64_WS_SPACE: u8 = 1 << 3;

const fn build_byte_class() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        let mut flags = 0u8;

        // URL-ish: RFC3986 unreserved + reserved + '%' and '+' (scanner-specific).
        if (b >= b'A' && b <= b'Z')
            || (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || matches!(
                b,
                b'%' | b'+'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b','
                    | b';'
                    | b'='
            )
        {
            flags |= URLISH;
        }

        // Base64 alphabet (standard + URL-safe) + padding.
        if (b >= b'A' && b <= b'Z')
            || (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
        {
            flags |= B64_CHAR;
        }

        match b {
            b'\n' | b'\r' | b'\t' => flags |= B64_WS,
            b' ' => flags |= B64_WS_SPACE,
            _ => {}
        }

        table[i] = flags;
        i += 1;
    }
    table
}

static BYTE_CLASS: [u8; 256] = build_byte_class();

/// Sentinel value indicating an invalid base64 byte in B64_DECODE table.
const B64_INVALID: u8 = 0xFF;
/// Sentinel value indicating padding ('=') in B64_DECODE table.
const B64_PAD: u8 = 64;

/// Lookup table for base64 decoding: 0-63 for valid chars, B64_PAD (64) for '=',
/// B64_INVALID (0xFF) for invalid bytes.
/// Accepts both standard (+/) and URL-safe (-_) alphabets.
const fn build_b64_decode_table() -> [u8; 256] {
    let mut table = [B64_INVALID; 256];
    let mut i = 0u8;
    loop {
        table[i as usize] = match i {
            b'A'..=b'Z' => i - b'A',
            b'a'..=b'z' => i - b'a' + 26,
            b'0'..=b'9' => i - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => B64_PAD,
            _ => B64_INVALID,
        };
        if i == 255 {
            break;
        }
        i += 1;
    }
    table
}

static B64_DECODE: [u8; 256] = build_b64_decode_table();

/// Target for span collection, allowing reuse of `Vec` or `ScratchVec`.
///
/// Spans are half-open byte ranges (`start..end`) into the input buffer.
/// Implementations are expected to preserve insertion order and tolerate
/// being cleared and reused across scans.
/// Callers must ensure spans are valid for the sink (for example, `SpanU32`
/// requires all offsets fit in `u32`).
/// Callers are responsible for ensuring `start <= end` and that spans are
/// within the input buffer.
pub(super) trait SpanSink {
    fn clear(&mut self);
    fn len(&self) -> usize;
    fn push(&mut self, span: Range<usize>);
}

/// Stateful URL-ish span detector for chunked input.
///
/// The scan is permissive: any URL-ish run containing at least one escape (or
/// `+` when `plus_to_space` is enabled) can produce a span. Runs are split at
/// `max_len` boundaries to cap worst-case work; each split segment must still
/// satisfy the trigger and `min_len` requirements to be emitted.
///
/// Note: `max_len` splitting does not align to `%HH`; a split escape will be
/// treated as literal by the decoder, which is acceptable for this scan-first
/// design.
pub(super) struct UrlSpanStream {
    min_len: usize,
    max_len: usize,
    plus_to_space: bool,
    in_run: bool,
    start: u64,
    run_len: usize,
    triggers: usize,
    done: bool,
}

impl UrlSpanStream {
    pub(super) fn new(tc: &TransformConfig) -> Self {
        Self {
            min_len: tc.min_len,
            max_len: tc.max_encoded_len,
            plus_to_space: tc.plus_to_space,
            in_run: false,
            start: 0,
            run_len: 0,
            triggers: 0,
            done: false,
        }
    }

    /// Feed the next chunk of bytes into the scanner.
    ///
    /// `base_offset` must be the absolute offset of `chunk[0]` in the original
    /// buffer. Chunks should be provided in order with a monotonic
    /// `base_offset` (typically contiguous) so runs can span chunk boundaries.
    /// Spans are reported as half-open absolute ranges. Returning `false` from
    /// `on_span` stops the scan early; the stream must be `reset()` before reuse.
    pub(super) fn feed<F>(&mut self, chunk: &[u8], base_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || chunk.is_empty() {
            return;
        }

        let mut i = 0usize;
        while i < chunk.len() {
            let b = chunk[i];
            let flags = BYTE_CLASS[b as usize];
            let urlish = (flags & URLISH) != 0;
            let abs = base_offset + i as u64;

            if !self.in_run {
                if !urlish {
                    i += 1;
                    continue;
                }
                self.in_run = true;
                self.start = abs;
                self.run_len = 0;
                self.triggers = 0;
            }

            if urlish {
                self.run_len += 1;
                if b == b'%' || (self.plus_to_space && b == b'+') {
                    self.triggers += 1;
                }
                i += 1;

                if self.run_len >= self.max_len {
                    if self.triggers > 0 && self.run_len >= self.min_len {
                        let end = self.start.saturating_add(self.run_len as u64);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                }
            } else {
                if self.triggers > 0 && self.run_len >= self.min_len {
                    let end = abs;
                    if !on_span(self.start, end) {
                        self.done = true;
                        return;
                    }
                }
                self.in_run = false;
                i += 1;
            }
        }
    }

    /// Flush a trailing run at end-of-stream.
    ///
    /// `end_offset` should be the absolute offset immediately after the last
    /// input byte. No spans are emitted if the current run lacks a trigger or
    /// is shorter than `min_len`.
    pub(super) fn finish<F>(&mut self, end_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || !self.in_run {
            return;
        }
        if self.triggers > 0 && self.run_len >= self.min_len && !on_span(self.start, end_offset) {
            self.done = true;
        }
        self.in_run = false;
    }
}

/// Stateful base64-ish span detector for chunked input.
///
/// Runs may include allowed whitespace, but spans are trimmed to the last base64
/// alphabet byte. `min_chars` counts alphabet characters only; whitespace does
/// not contribute. Runs are split at `max_len` boundaries to keep scanning bounded.
///
/// Note: `max_len` splitting does not align to 4-char base64 quanta. A split
/// segment may fail strict decode if it ends with a 1-char tail.
pub(super) struct Base64SpanStream {
    min_chars: usize,
    max_len: usize,
    allow_space_ws: bool,
    in_run: bool,
    start: u64,
    run_len: usize,
    b64_chars: usize,
    have_b64: bool,
    last_b64: u64,
    done: bool,
}

impl Base64SpanStream {
    pub(super) fn new(tc: &TransformConfig) -> Self {
        Self {
            min_chars: tc.min_len,
            max_len: tc.max_encoded_len,
            allow_space_ws: tc.base64_allow_space_ws,
            in_run: false,
            start: 0,
            run_len: 0,
            b64_chars: 0,
            have_b64: false,
            last_b64: 0,
            done: false,
        }
    }

    /// Feed the next chunk of bytes into the scanner.
    ///
    /// `base_offset` must be the absolute offset of `chunk[0]` in the original
    /// buffer. Chunks should be provided in order with a monotonic
    /// `base_offset` (typically contiguous) so runs can span chunk boundaries.
    /// Spans are reported as half-open absolute ranges trimmed to the last
    /// base64 byte. Returning `false` from `on_span` stops the scan early; the
    /// stream must be `reset()` before reuse.
    pub(super) fn feed<F>(&mut self, chunk: &[u8], base_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || chunk.is_empty() {
            return;
        }

        let allow_mask = if self.allow_space_ws {
            B64_CHAR | B64_WS | B64_WS_SPACE
        } else {
            B64_CHAR | B64_WS
        };

        let mut i = 0usize;
        while i < chunk.len() {
            let b = chunk[i];
            let flags = BYTE_CLASS[b as usize];
            let allowed = (flags & allow_mask) != 0;
            let abs = base_offset + i as u64;

            if !self.in_run {
                if !allowed {
                    i += 1;
                    continue;
                }
                self.in_run = true;
                self.start = abs;
                self.run_len = 0;
                self.b64_chars = 0;
                self.have_b64 = false;
            }

            if allowed {
                self.run_len += 1;
                if (flags & B64_CHAR) != 0 {
                    self.b64_chars += 1;
                    self.last_b64 = abs;
                    self.have_b64 = true;
                }
                i += 1;

                if self.run_len >= self.max_len {
                    if self.have_b64 && self.b64_chars >= self.min_chars {
                        let end = self.last_b64.saturating_add(1);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                }
            } else {
                if self.have_b64 && self.b64_chars >= self.min_chars {
                    let end = self.last_b64.saturating_add(1);
                    if !on_span(self.start, end) {
                        self.done = true;
                        return;
                    }
                }
                self.in_run = false;
                i += 1;
            }
        }
    }

    /// Flush a trailing run at end-of-stream, trimming trailing whitespace.
    ///
    /// The `_end_offset` parameter is accepted for API symmetry with `UrlSpanStream`
    /// but is unused here; base64 spans are self-delimiting by trailing whitespace.
    pub(super) fn finish<F>(&mut self, _end_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || !self.in_run {
            return;
        }
        if self.have_b64 && self.b64_chars >= self.min_chars {
            let end = self.last_b64.saturating_add(1);
            if !on_span(self.start, end) {
                self.done = true;
            }
        }
        self.in_run = false;
    }
}

impl SpanSink for Vec<Range<usize>> {
    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        Vec::push(self, span);
    }
}

impl SpanSink for ScratchVec<Range<usize>> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, span);
    }
}

// SpanU32 stores offsets as u32; callers must ensure spans fit in u32.
impl SpanSink for ScratchVec<SpanU32> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, SpanU32::new(span.start, span.end));
    }
}

/// Finds URL-encoded spans within `hay` and appends them to `spans`.
///
/// Spans are drawn from URL-ish runs that contain at least one escape (or `+`
/// when `plus_to_space` is enabled). The run is bounded by `max_len`, and runs
/// shorter than `min_len` are discarded. `min_len`/`max_len` are measured in
/// input bytes, not decoded output.
///
/// `spans` is cleared before results are appended.
///
/// Notes:
/// - "URL-ish" includes RFC3986 unreserved/reserved bytes plus '%' and '+'.
/// - Runs longer than `max_len` are split at the boundary to keep scans bounded.
///   Splits are byte-count based and may cut through a `%HH` escape.
/// - When `plus_to_space` is false, '+' is allowed in runs but does not trigger
///   a span by itself.
/// - Scanning stops after `max_spans` spans are appended.
pub(super) fn find_url_spans_into(
    hay: &[u8],
    min_len: usize,
    max_len: usize,
    max_spans: usize,
    plus_to_space: bool,
    spans: &mut impl SpanSink,
) {
    debug_assert!(max_len >= min_len);
    // Fast reject: URL spans require at least one '%' (or '+' when plus_to_space is enabled).
    // Note: the engine already applies this prefilter via transform_quick_trigger(),
    // but direct callers (e.g., microbench) can reach here without that guard.
    let has_trigger = if plus_to_space {
        memchr2(b'%', b'+', hay).is_some()
    } else {
        memchr(b'%', hay).is_some()
    };
    // Include unescaped prefixes by scanning URL-ish runs, not starting at the first '%'.
    // We still require at least one percent-escape (and optionally '+') to avoid
    // decoding every plain word.
    spans.clear();
    if !has_trigger {
        return;
    }
    let mut i = 0usize;

    while i < hay.len() && spans.len() < max_spans {
        let flags = BYTE_CLASS[hay[i] as usize];
        if (flags & URLISH) == 0 {
            i += 1;
            continue;
        }

        let start = i;
        let mut triggers = 0usize;

        while i < hay.len() && (i - start) < max_len {
            let b = hay[i];
            let flags = BYTE_CLASS[b as usize];
            if (flags & URLISH) == 0 {
                break;
            }
            if b == b'%' || (plus_to_space && b == b'+') {
                triggers += 1;
            }
            i += 1;
        }

        let end = i;
        if triggers > 0 && (end - start) >= min_len {
            spans.push(start..end);
        }
    }
}

/// Streaming URL-percent decoder.
///
/// Decodes `%HH` escapes and optionally converts `+` to space. Invalid or
/// incomplete escapes are passed through verbatim. Output is emitted in
/// bounded chunks (stream decode buffer), and the `on_bytes` callback may stop
/// decoding early by returning `ControlFlow::Break(())` (treated as success).
///
/// # Behavior
/// - Only `%` followed by two hex digits is decoded; all other bytes are
///   forwarded unchanged (including `%` itself).
/// - Output length is never larger than input length.
/// - `on_bytes` may be called multiple times; chunk boundaries are arbitrary.
///
/// # Errors
/// Currently infallible; the error type is reserved for test helpers that
/// enforce maximum output size.
fn stream_decode_url_percent(
    input: &[u8],
    plus_to_space: bool,
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) {
    fn flush_buf(
        out: &mut [u8],
        n: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *n == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*n]);
        *n = 0;
        cf
    }

    let mut out = [0u8; STREAM_DECODE_CHUNK_BYTES];
    let mut n = 0usize;

    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];

        let decoded =
            if b == b'%' && i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) {
                let hi = hex_val(input[i + 1]);
                let lo = hex_val(input[i + 2]);
                i += 3;
                (hi << 4) | lo
            } else if plus_to_space && b == b'+' {
                i += 1;
                b' '
            } else {
                i += 1;
                b
            };

        out[n] = decoded;
        n += 1;

        // Leave 4 bytes of headroom to safely write the next decoded output.
        // URL decoding produces 1 byte per decode; base64 can produce up to 3.
        // Using 4 covers both cases with a small margin.
        if n >= out.len() - 4 {
            match flush_buf(&mut out, &mut n, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return,
            }
        }
    }

    let _ = flush_buf(&mut out, &mut n, &mut on_bytes);
}

#[cfg(test)]
#[derive(Debug)]
enum UrlTestError {
    OutputTooLarge,
}

#[cfg(test)]
fn decode_url_percent_to_vec(
    input: &[u8],
    plus_to_space: bool,
    max_out: usize,
) -> Result<Vec<u8>, UrlTestError> {
    let mut out = Vec::with_capacity(input.len().min(max_out));
    let mut too_large = false;

    stream_decode_url_percent(input, plus_to_space, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    });

    if too_large {
        return Err(UrlTestError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform: Base64 (urlsafe + std alph, ignores whitespace)
// --------------------------

/// Internal error used to signal decode failures in tests.
#[derive(Debug)]
enum Base64DecodeError {
    InvalidByte,
    InvalidPadding,
    TruncatedQuantum,
}

/// Finds base64-ish spans within `hay` and appends them to `spans`.
///
/// Guarantees / invariants:
/// - Each byte is classified at most once (single-pass scan).
/// - Spans contain only base64 chars + allowed whitespace.
/// - Spans end at the last base64 byte; trailing whitespace is trimmed.
/// - Runs are split at `max_len` to bound worst-case work.
/// - Scanning stops after `max_spans` spans are appended.
///
/// Notes:
/// - `min_chars` counts base64 alphabet characters only; whitespace does not
///   contribute to the minimum.
/// - `max_len` counts all bytes in the run, including whitespace.
///   Splits are byte-count based and may cut through a 4-char base64 quantum.
/// - `allow_space_ws` adds ASCII space to the allowed whitespace set (in
///   addition to `\r`, `\n`, `\t`).
/// - The scan is intentionally permissive and relies on downstream decode gates
///   for strict validation.
pub(super) fn find_base64_spans_into(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
    spans: &mut impl SpanSink,
) {
    debug_assert!(max_len >= min_chars);
    spans.clear();
    if max_spans == 0 {
        return;
    }

    let allow_mask = if allow_space_ws {
        B64_CHAR | B64_WS | B64_WS_SPACE
    } else {
        B64_CHAR | B64_WS
    };
    let mut span_count = 0usize;

    // Current run state.
    let mut in_run = false;
    let mut start = 0usize;
    let mut run_len = 0usize;
    let mut b64_chars = 0usize;
    let mut have_b64 = false;
    let mut last_b64 = 0usize;

    let mut i = 0usize;
    while i < hay.len() {
        let flags = BYTE_CLASS[hay[i] as usize];
        let allowed = (flags & allow_mask) != 0;

        if !in_run {
            if !allowed {
                i += 1;
                continue;
            }
            in_run = true;
            start = i;
            run_len = 0;
            b64_chars = 0;
            have_b64 = false;
        }

        if allowed {
            run_len += 1;
            if (flags & B64_CHAR) != 0 {
                b64_chars += 1;
                last_b64 = i;
                have_b64 = true;
            }
            i += 1;

            if run_len >= max_len {
                // Split long runs eagerly; the next iteration starts fresh at `i`.
                if have_b64 && b64_chars >= min_chars {
                    spans.push(start..(last_b64 + 1));
                    span_count += 1;
                    if span_count >= max_spans {
                        return;
                    }
                }
                in_run = false;
            }
        } else {
            // Disallowed byte ends the run; consume it so we don't recheck it.
            if have_b64 && b64_chars >= min_chars {
                spans.push(start..(last_b64 + 1));
                span_count += 1;
                if span_count >= max_spans {
                    return;
                }
            }
            in_run = false;
            i += 1;
        }
    }

    if in_run && have_b64 && b64_chars >= min_chars && span_count < max_spans {
        spans.push(start..(last_b64 + 1));
    }
}

/// Streaming base64 decoder that accepts std + URL-safe alphabets.
///
/// Whitespace is ignored. Padding is validated, but an unpadded tail
/// (2 or 3 bytes in the final quantum) is accepted. Output is emitted in
/// bounded chunks (stream decode buffer). The `on_bytes` callback may stop
/// decoding early by returning `ControlFlow::Break(())` (treated as success).
///
/// # Behavior
/// - Once padding is seen, only trailing whitespace is allowed.
/// - Output may have been emitted before an error is returned.
///
/// # Errors
/// - `InvalidByte`: a non-base64, non-whitespace byte was encountered.
/// - `InvalidPadding`: padding appeared in an invalid position or after data.
/// - `TruncatedQuantum`: the input ends with a single leftover base64 char.
///
/// # Notes
/// Used both for full decode and decoded-gate streaming, so it is kept
/// branch-light and bounded in memory.
fn stream_decode_base64(
    input: &[u8],
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), Base64DecodeError> {
    fn flush_buf(
        out: &mut [u8],
        out_len: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *out_len == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*out_len]);
        *out_len = 0;
        cf
    }

    let mut quad: [u8; 4] = [0; 4];
    let mut qn = 0usize;
    let mut seen_pad = false;

    let mut out: [u8; STREAM_DECODE_CHUNK_BYTES] = [0; STREAM_DECODE_CHUNK_BYTES];
    let mut out_len = 0usize;

    for &b in input {
        // ignore whitespace broadly
        if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            continue;
        }

        // Single-lookup decode via B64_DECODE table: 0-63 valid, B64_PAD (64) for '=',
        // B64_INVALID (0xFF) for invalid bytes. Eliminates the match-per-byte overhead.
        let v = B64_DECODE[b as usize];
        if v == B64_INVALID {
            return Err(Base64DecodeError::InvalidByte);
        }

        // Once padding is seen, only trailing whitespace is allowed.
        if seen_pad {
            return Err(Base64DecodeError::InvalidPadding);
        }

        quad[qn] = v;
        qn += 1;

        if qn < 4 {
            continue;
        }

        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        let d = quad[3];

        if a == B64_PAD || b == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }

        let b0 = (a << 2) | (b >> 4);

        if c == B64_PAD && d != B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }

        if c == B64_PAD && d == B64_PAD {
            out[out_len] = b0;
            out_len += 1;
            seen_pad = true;
        } else {
            let b1 = ((b & 0x0F) << 4) | (c >> 2);

            if d == B64_PAD {
                out[out_len] = b0;
                out[out_len + 1] = b1;
                out_len += 2;
                seen_pad = true;
            } else {
                let b2 = ((c & 0x03) << 6) | d;

                out[out_len] = b0;
                out[out_len + 1] = b1;
                out[out_len + 2] = b2;
                out_len += 3;
            }
        }

        qn = 0;

        // Leave headroom so a full quantum (3 bytes) always fits.
        if out_len >= out.len() - 4 {
            match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    // Handle unpadded tail.
    if qn == 1 {
        return Err(Base64DecodeError::TruncatedQuantum);
    } else if qn == 2 {
        let a = quad[0];
        let b = quad[1];
        if a == B64_PAD || b == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        out[out_len] = b0;
        out_len += 1;
    } else if qn == 3 {
        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        if a == B64_PAD || b == B64_PAD || c == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        let b1 = ((b & 0x0F) << 4) | (c >> 2);
        out[out_len] = b0;
        out[out_len + 1] = b1;
        out_len += 2;
    }

    match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Ok(()),
    }
}

#[cfg(test)]
#[derive(Debug)]
enum Base64TestError {
    OutputTooLarge,
}

#[cfg(test)]
fn decode_base64_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Base64TestError> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut too_large = false;

    stream_decode_base64(input, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })
    .map_err(|_| Base64TestError::OutputTooLarge)?; // Map internal errors to generic failure for this helper

    if too_large {
        return Err(Base64TestError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform dispatch
// --------------------------

/// Quick prefilter to avoid running span scans when no trigger bytes are present.
pub(super) fn transform_quick_trigger(tc: &TransformConfig, buf: &[u8]) -> bool {
    match tc.id {
        TransformId::UrlPercent => {
            if memchr(b'%', buf).is_some() {
                return true;
            }
            if tc.plus_to_space && memchr(b'+', buf).is_some() {
                return true;
            }
            false
        }
        TransformId::Base64 => true, // span finder is the real filter; engine applies anchor gate when enabled
    }
}

/// Dispatch to the appropriate span finder for the configured transform.
pub(super) fn find_spans_into(tc: &TransformConfig, buf: &[u8], out: &mut impl SpanSink) {
    match tc.id {
        TransformId::UrlPercent => find_url_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.plus_to_space,
            out,
        ),
        TransformId::Base64 => find_base64_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.base64_allow_space_ws,
            out,
        ),
    }
}

/// Dispatch to the appropriate streaming decoder, erasing the error type.
pub(super) fn stream_decode(
    tc: &TransformConfig,
    input: &[u8],
    on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), ()> {
    match tc.id {
        TransformId::UrlPercent => {
            stream_decode_url_percent(input, tc.plus_to_space, on_bytes);
            Ok(())
        }
        TransformId::Base64 => stream_decode_base64(input, on_bytes).map_err(|_| ()),
    }
}

/// Decode into a `Vec` with output-size protection (tests only).
#[cfg(test)]
pub(super) fn decode_to_vec(
    tc: &TransformConfig,
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, ()> {
    match tc.id {
        TransformId::UrlPercent => {
            decode_url_percent_to_vec(input, tc.plus_to_space, max_out).map_err(|_| ())
        }
        TransformId::Base64 => decode_base64_to_vec(input, max_out).map_err(|_| ()),
    }
}

// --------------------------
// Benchmark helpers (bench feature only)
// --------------------------

/// Benchmark helper: stream decode URL percent-encoding, discarding output.
/// Returns bytes successfully decoded.
#[cfg(feature = "bench")]
pub fn bench_stream_decode_url(input: &[u8], plus_to_space: bool) -> usize {
    let mut decoded_bytes = 0usize;
    stream_decode_url_percent(input, plus_to_space, |chunk| {
        decoded_bytes += chunk.len();
        ControlFlow::Continue(())
    });
    decoded_bytes
}

/// Benchmark helper: stream decode Base64, discarding output.
/// Returns bytes successfully decoded.
#[cfg(feature = "bench")]
pub fn bench_stream_decode_base64(input: &[u8]) -> usize {
    let mut decoded_bytes = 0usize;
    let _ = stream_decode_base64(input, |chunk| {
        decoded_bytes += chunk.len();
        ControlFlow::Continue(())
    });
    decoded_bytes
}
