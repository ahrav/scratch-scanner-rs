//! Transform span detection and streaming decode helpers.
//!
//! Span finders are intentionally permissive: they prioritize recall, while
//! downstream gating and budgets bound cost and enforce correctness.

use super::SpanU32;
use crate::api::{TransformConfig, TransformId};
use crate::scratch_memory::ScratchVec;
use memchr::{memchr, memchr2};
use std::ops::{ControlFlow, Range};

// --------------------------
// Transform: URL percent
// --------------------------

#[derive(Debug)]
enum UrlDecodeError {
    OutputTooLarge,
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

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

#[inline]
fn is_urlish(b: u8) -> bool {
    (BYTE_CLASS[b as usize] & URLISH) != 0
}

/// Target for span collection, allowing reuse of `Vec` or `ScratchVec`.
pub(super) trait SpanSink {
    fn clear(&mut self);
    fn len(&self) -> usize;
    fn push(&mut self, span: Range<usize>);
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
/// shorter than `min_len` are discarded.
pub(super) fn find_url_spans_into(
    hay: &[u8],
    min_len: usize,
    max_len: usize,
    max_spans: usize,
    plus_to_space: bool,
    spans: &mut impl SpanSink,
) {
    assert!(max_len >= min_len);
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
/// incomplete escapes are passed through verbatim. The `on_bytes` callback may
/// stop decoding early by returning `ControlFlow::Break(())`.
fn stream_decode_url_percent(
    input: &[u8],
    plus_to_space: bool,
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), UrlDecodeError> {
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

    let mut out = [0u8; 1024];
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

        if n >= out.len() - 4 {
            match flush_buf(&mut out, &mut n, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    match flush_buf(&mut out, &mut n, &mut on_bytes) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Ok(()),
    }
}

#[cfg(test)]
fn decode_url_percent_to_vec(
    input: &[u8],
    plus_to_space: bool,
    max_out: usize,
) -> Result<Vec<u8>, UrlDecodeError> {
    let mut out = Vec::with_capacity(input.len().min(max_out));
    let mut too_large = false;

    stream_decode_url_percent(input, plus_to_space, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })?;

    if too_large {
        return Err(UrlDecodeError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform: Base64 (urlsafe + std alph, ignores whitespace)
// --------------------------

#[derive(Debug)]
enum Base64DecodeError {
    InvalidByte(u8),
    InvalidPadding,
    TruncatedQuantum,
    OutputTooLarge,
}

#[inline]
fn is_b64_char(b: u8) -> bool {
    (BYTE_CLASS[b as usize] & B64_CHAR) != 0
}

#[inline]
fn is_b64_ws(b: u8, allow_space: bool) -> bool {
    let flags = BYTE_CLASS[b as usize];
    if allow_space {
        (flags & (B64_WS | B64_WS_SPACE)) != 0
    } else {
        (flags & B64_WS) != 0
    }
}

fn is_b64_or_ws(b: u8, allow_space: bool) -> bool {
    is_b64_char(b) || is_b64_ws(b, allow_space)
}

#[inline]
fn find_b64ish_start(hay: &[u8], i: usize, allow_space: bool) -> usize {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        find_b64ish_start_neon(hay, i, allow_space)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut i = i;
        while i < hay.len() && !is_b64_or_ws(hay[i], allow_space) {
            i += 1;
        }
        i
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn find_b64ish_start_neon(hay: &[u8], mut i: usize, allow_space: bool) -> usize {
    use std::arch::aarch64::{
        vandq_u8, vceqq_u8, vcgeq_u8, vcleq_u8, vdupq_n_u8, vld1q_u8, vmaxvq_u8, vorrq_u8,
    };

    let len = hay.len();
    let ptr = hay.as_ptr();

    let a = vdupq_n_u8(b'A');
    let z = vdupq_n_u8(b'Z');
    let aa = vdupq_n_u8(b'a');
    let zz = vdupq_n_u8(b'z');
    let zero = vdupq_n_u8(b'0');
    let nine = vdupq_n_u8(b'9');

    let plus = vdupq_n_u8(b'+');
    let slash = vdupq_n_u8(b'/');
    let eq = vdupq_n_u8(b'=');
    let dash = vdupq_n_u8(b'-');
    let underscore = vdupq_n_u8(b'_');

    let lf = vdupq_n_u8(b'\n');
    let cr = vdupq_n_u8(b'\r');
    let tab = vdupq_n_u8(b'\t');
    let space = vdupq_n_u8(b' ');

    while i + 16 <= len {
        let v = vld1q_u8(ptr.add(i));

        let upper = vandq_u8(vcgeq_u8(v, a), vcleq_u8(v, z));
        let lower = vandq_u8(vcgeq_u8(v, aa), vcleq_u8(v, zz));
        let digit = vandq_u8(vcgeq_u8(v, zero), vcleq_u8(v, nine));

        let sym = vorrq_u8(
            vorrq_u8(vceqq_u8(v, plus), vceqq_u8(v, slash)),
            vorrq_u8(
                vceqq_u8(v, eq),
                vorrq_u8(vceqq_u8(v, dash), vceqq_u8(v, underscore)),
            ),
        );

        let mut ws = vorrq_u8(vceqq_u8(v, lf), vceqq_u8(v, cr));
        ws = vorrq_u8(ws, vceqq_u8(v, tab));
        if allow_space {
            ws = vorrq_u8(ws, vceqq_u8(v, space));
        }

        let b64ish = vorrq_u8(sym, vorrq_u8(upper, vorrq_u8(lower, vorrq_u8(digit, ws))));
        if vmaxvq_u8(b64ish) != 0 {
            break;
        }
        i += 16;
    }

    while i < len && !is_b64_or_ws(hay[i], allow_space) {
        i += 1;
    }
    i
}

// Simple span finder. It is permissive by design.
//
// Why permissive?
// - We want to avoid false negatives at this stage.
// - Tightening is handled by length caps, span limits, and decode gating.
//
// This keeps the span finder cheap and predictable, while later stages enforce
// cost limits and correctness.
/// Finds base64-ish spans within `hay` and appends them to `spans`.
///
/// The scan is permissive by design and relies on downstream decoding gates
/// for correctness. Trailing whitespace is trimmed so spans end at the last
/// base64 byte observed.
pub(super) fn find_base64_spans_into(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
    spans: &mut impl SpanSink,
) {
    assert!(max_len >= min_chars);
    spans.clear();
    let mut i = 0usize;
    let allow_mask = if allow_space_ws {
        B64_CHAR | B64_WS | B64_WS_SPACE
    } else {
        B64_CHAR | B64_WS
    };

    while i < hay.len() && spans.len() < max_spans {
        i = find_b64ish_start(hay, i, allow_space_ws);
        if i >= hay.len() {
            break;
        }

        let start = i;
        let mut b64_chars = 0usize;
        let mut last_b64 = None::<usize>;

        while i < hay.len() && (i - start) < max_len {
            let flags = BYTE_CLASS[hay[i] as usize];
            if (flags & allow_mask) == 0 {
                break;
            }
            if (flags & B64_CHAR) != 0 {
                b64_chars += 1;
                last_b64 = Some(i);
            }
            i += 1;
        }

        if b64_chars >= min_chars {
            if let Some(last) = last_b64 {
                // Trim trailing whitespace by ending at the last base64 byte.
                spans.push(start..(last + 1));
            }
        }
    }
}

/// Streaming base64 decoder that accepts std + URL-safe alphabets.
///
/// Whitespace is ignored. Padding is validated, but an unpadded tail
/// (2 or 3 bytes in the final quantum) is accepted. The `on_bytes` callback
/// may stop decoding early by returning `ControlFlow::Break(())`.
fn stream_decode_base64(
    input: &[u8],
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), Base64DecodeError> {
    // Streaming decoder that accepts both standard and URL-safe alphabets and
    // ignores whitespace. It validates padding rules and allows an unpadded tail
    // (2 or 3 bytes in the final quantum) because real-world data often omits '='.
    //
    // This is used for both actual decode and decoded-gate streaming, so we
    // keep it branch-light and bounded in memory (fixed 1KB output buffer).
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

    let mut out: [u8; 1024] = [0; 1024];
    let mut out_len = 0usize;

    for &b in input {
        // ignore whitespace broadly
        if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            continue;
        }

        let v = match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(64),
            _ => None,
        }
        .ok_or(Base64DecodeError::InvalidByte(b))?;

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

        if a == 64 || b == 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }

        let b0 = (a << 2) | (b >> 4);

        if c == 64 && d != 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }

        if c == 64 && d == 64 {
            out[out_len] = b0;
            out_len += 1;
            seen_pad = true;
        } else {
            let b1 = ((b & 0x0F) << 4) | (c >> 2);

            if d == 64 {
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

        if out_len >= out.len() - 4 {
            match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    // Handle unpadded tail
    if qn == 1 {
        return Err(Base64DecodeError::TruncatedQuantum);
    } else if qn == 2 {
        let a = quad[0];
        let b = quad[1];
        if a == 64 || b == 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        out[out_len] = b0;
        out_len += 1;
    } else if qn == 3 {
        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        if a == 64 || b == 64 || c == 64 {
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
fn decode_base64_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Base64DecodeError> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut too_large = false;

    stream_decode_base64(input, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })?;

    if too_large {
        return Err(Base64DecodeError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform dispatch
// --------------------------

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
        TransformId::Base64 => true, // span finder is the real filter; keep trigger cheap
    }
}

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

pub(super) fn stream_decode(
    tc: &TransformConfig,
    input: &[u8],
    on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), ()> {
    match tc.id {
        TransformId::UrlPercent => {
            stream_decode_url_percent(input, tc.plus_to_space, on_bytes).map_err(|_| ())
        }
        TransformId::Base64 => stream_decode_base64(input, on_bytes).map_err(|_| ()),
    }
}

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
