//! Streaming decode and scan logic.
//!
//! This module decodes transform output incrementally and scans it without
//! materializing the full decoded buffer whenever possible. The core path
//! keeps a decoded ring buffer, feeds Vectorscan stream DBs, and only
//! materializes candidate windows for rule evaluation.
//!
//! ## Invariants
//! - Decoded offsets are monotonically increasing during a stream decode.
//! - `pending_windows` is a timing wheel keyed by `hi` (G=1), so windows are
//!   only processed once the decoded offset has reached the window end.
//! - `scratch.slab` is append-only during a stream pass; on abort or fallback
//!   it is truncated back to its pre-decode length.
//! - Per-scan decode budgets (`max_total_decode_output_bytes`, per-transform
//!   `max_decoded_bytes`) are enforced on every chunk.
//!
//! ## Fallback triggers
//! Streaming will fall back to full decode when any of the following happen:
//! - the per-rule window cap is exceeded (risking unbounded work),
//! - a decoded window/span cannot be reconstructed from the ring,
//! - decode budgets are exceeded or the stream decoder errors.
//!
//! ## Gate behavior
//! For `Gate::AnchorsInDecoded`, the preferred path is the decoded-space
//! Vectorscan gate. If it cannot be used, we fall back to prefilter hits and
//! may relax enforcement to avoid dropping UTF-16-only matches.

use crate::api::{DecodeStep, FileId, StepId};
use crate::stdx::PushOutcome;
use memchr::memchr;
use std::ops::{ControlFlow, Range};
#[cfg(feature = "stats")]
use std::sync::atomic::Ordering;

use super::core::Engine;
use super::helpers::{coalesce_under_pressure_sorted, hash128, merge_ranges_with_gap_sorted};
use super::hit_pool::SpanU32;
use super::rule_repr::Variant;
use super::scratch::ScanScratch;
use super::transform::{stream_decode, Base64SpanStream, UrlSpanStream};
use super::vectorscan_prefilter::{
    gate_match_callback, stream_match_callback, utf16_stream_match_callback, VsScratch, VsStream,
    VsStreamDb, VsStreamMatchCtx, VsUtf16StreamMatchCtx,
};
use super::work_items::{
    BufRef, EncRef, PendingDecodeSpan, PendingWindow, SpanStreamEntry, SpanStreamState, WorkItem,
};
use crate::api::{Gate, TransformConfig, TransformId, TransformMode};

impl Engine {
    /// Decodes an encoded span in full, dedupes it, and enqueues it for scanning.
    ///
    /// This is the fallback path when stream decoding is unavailable or fails.
    ///
    /// The decoded buffer is hashed (128-bit) to avoid re-scanning identical
    /// output across transforms.
    ///
    /// # Preconditions
    /// - `enc` comes from the current scan buffer or decode slab.
    /// - `scratch` has been reset for the current scan.
    ///
    /// # Effects
    /// - May append decoded bytes to the slab and enqueue a `ScanBuf` work item.
    /// - Updates per-scan decode budgets and dedupe state.
    /// - On dedupe hits, rolls back the slab and skips enqueueing.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode_span_fallback(
        &self,
        tc: &TransformConfig,
        transform_idx: usize,
        enc: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        if enc.len() < tc.min_len {
            return;
        }

        if tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded {
            if let Some(gate) = &self.b64_gate {
                if !gate.hits(enc) {
                    return;
                }
            }
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);

        let decoded_range = match scratch.slab.append_stream_decode(
            tc,
            enc,
            max_out,
            &mut scratch.total_decode_output_bytes,
            self.tuning.max_total_decode_output_bytes,
        ) {
            Ok(r) => r,
            Err(_) => return,
        };

        let decoded = scratch.slab.slice(decoded_range.clone());
        if decoded.is_empty() {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        let h = hash128(decoded);
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        scratch.work_q.push(WorkItem::ScanBuf {
            buf: BufRef::Slab(decoded_range),
            step_id,
            root_hint,
            depth,
        });
        scratch.work_items_enqueued = scratch.work_items_enqueued.saturating_add(1);

        let _ = (base_offset, file_id, transform_idx);
    }

    /// Re-decodes the decoded-byte window `[lo, hi)` into `out`.
    ///
    /// This is used when the ring buffer no longer holds the full window.
    ///
    /// # Returns
    /// - `true` if exactly `hi - lo` bytes were reconstructed.
    /// - `false` if decoding fails, truncates, or exceeds `max_out`.
    ///
    /// # Notes
    /// - `out` is cleared and filled with the decoded bytes in `[lo, hi)`.
    /// - Decoding stops early once `hi` is reached.
    pub(super) fn redecode_window_into(
        &self,
        tc: &TransformConfig,
        encoded: &[u8],
        lo: u64,
        hi: u64,
        max_out: usize,
        out: &mut Vec<u8>,
    ) -> bool {
        if hi <= lo {
            return true;
        }
        let needed = match usize::try_from(hi.saturating_sub(lo)) {
            Ok(n) => n,
            Err(_) => return false,
        };
        out.clear();
        if needed > 0 {
            out.reserve(needed);
        }

        let mut decoded_offset: u64 = 0;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            local_out = local_out.saturating_add(chunk.len());

            let chunk_start = decoded_offset;
            let chunk_end = decoded_offset.saturating_add(chunk.len() as u64);
            if chunk_end > lo && chunk_start < hi {
                let copy_start = lo.saturating_sub(chunk_start) as usize;
                let copy_end = hi.min(chunk_end).saturating_sub(chunk_start) as usize;
                out.extend_from_slice(&chunk[copy_start..copy_end]);
            }
            decoded_offset = chunk_end;
            if decoded_offset >= hi {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });

        if res.is_err() || truncated {
            return false;
        }
        out.len() == needed
    }

    /// Stream-decodes `encoded` and scans windows without materializing the full buffer.
    ///
    /// # Strategy
    /// - Track decoded bytes in a ring buffer.
    /// - Use the stream Vectorscan DB to emit candidate windows.
    /// - Re-decode windows only when they fall outside the ring buffer.
    ///
    /// # Gate behavior
    /// - When `tc.gate == Gate::AnchorsInDecoded`, enforce decoded-space gating
    ///   when possible; otherwise fall back to prefilter-based gating.
    ///
    /// # Preconditions
    /// - `encoded` is the bytes for the current decode span.
    /// - `scratch` belongs to the current scan and has been reset.
    ///
    /// # Effects
    /// - Populates `scratch` findings and pending decode spans.
    /// - Falls back to `decode_span_fallback` if the stream path becomes unsafe
    ///   (window cap exceeded or a window/span cannot be reconstructed).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode_stream_and_scan(
        &self,
        vs_stream: &VsStreamDb,
        tc: &TransformConfig,
        transform_idx: usize,
        encoded: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        // Reset only touched counters to avoid clearing the full per-rule array.
        for idx in scratch.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = scratch.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }

        if encoded.is_empty() {
            return;
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);
        if max_out == 0 {
            return;
        }

        let total_decode_start = scratch.total_decode_output_bytes;
        let mut force_full = false;
        let gate_enabled = tc.gate == Gate::AnchorsInDecoded;
        // `gate_hit` is written by the Vectorscan callback to indicate an anchor hit.
        let mut gate_hit: u8 = 0;
        let mut gate_db_active = false;
        let mut gate_db_failed = false;
        let mut gate_stream: Option<VsStream> = None;
        let mut gate_scratch: Option<VsScratch> = None;
        let gate_cb = gate_match_callback();

        #[cfg(feature = "b64-stats")]
        let is_b64_gate = tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded;

        scratch.decode_ring.reset();
        scratch.window_bytes.clear();
        scratch.pending_windows.reset();
        scratch.vs_stream_matches.clear();
        scratch.pending_spans.clear();
        scratch.span_streams.clear();
        scratch.tmp_findings.clear();

        let mut local_out = 0usize;
        let mut truncated = false;
        let mut prefilter_gate_hit = false;
        let mut found_any = false;
        let mut local_dropped = 0usize;

        if gate_enabled {
            if let Some(db) = self.vs_gate.as_ref() {
                let mut vs_gate_scratch = match scratch.vs_gate_scratch.take() {
                    Some(s) => Some(s),
                    None => db.alloc_scratch().ok(),
                };
                if let Some(vs_gate_scratch) = vs_gate_scratch.take() {
                    match db.open_stream() {
                        Ok(stream) => {
                            gate_db_active = true;
                            gate_stream = Some(stream);
                            gate_scratch = Some(vs_gate_scratch);
                        }
                        Err(_) => {
                            scratch.vs_gate_scratch = Some(vs_gate_scratch);
                        }
                    }
                }
            }
        }

        let slab_start = scratch.slab.buf.len();
        let want_utf16_scan = self.tuning.scan_utf16_variants && self.has_utf16_anchors;
        let use_utf16_stream = want_utf16_scan && self.vs_utf16_stream.is_some();
        let decoded_full_start = slab_start;
        let mut decoded_full_len = 0usize;
        let mut decoded_has_nul = false;
        let mut utf16_stream: Option<VsStream> = None;
        let mut utf16_stream_scratch: Option<VsScratch> = None;
        let mut utf16_stream_ctx: Option<VsUtf16StreamMatchCtx> = None;
        let utf16_stream_cb = utf16_stream_match_callback();

        let process_window = |win: PendingWindow,
                              hi: u64,
                              scratch: &mut ScanScratch,
                              found_any: &mut bool,
                              local_dropped: &mut usize,
                              force_full: &mut bool| {
            if *force_full {
                return;
            }
            let lo = win.lo;
            if hi <= lo {
                return;
            }
            scratch.window_bytes.clear();
            // Prefer the ring buffer; re-decode if the window is no longer resident.
            if !scratch
                .decode_ring
                .extend_range_to(lo, hi, &mut scratch.window_bytes)
                && !self.redecode_window_into(
                    tc,
                    encoded,
                    lo,
                    hi,
                    max_out,
                    &mut scratch.window_bytes,
                )
            {
                *force_full = true;
                return;
            }
            let (bytes_ptr, bytes_len) = {
                let bytes = &scratch.window_bytes;
                (bytes.as_ptr(), bytes.len())
            };
            // SAFETY: `bytes_ptr` comes from `scratch.window_bytes`. We materialize the slice
            // from a raw pointer to avoid borrowing `scratch` across calls that mutate other
            // scratch fields. `window_bytes` is not mutated until after this slice is consumed.
            let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, bytes_len) };
            let rule = &self.rules[win.rule_id as usize];
            match win.variant {
                Variant::Raw => {
                    self.run_rule_on_raw_window_into(
                        win.rule_id,
                        rule,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        local_dropped,
                        found_any,
                        win.anchor_hint,
                    );
                }
                Variant::Utf16Le | Variant::Utf16Be => {
                    self.run_rule_on_utf16_window_into(
                        win.rule_id,
                        rule,
                        win.variant,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        local_dropped,
                        found_any,
                        win.anchor_hint,
                    );
                }
            }
        };

        // Use raw pointers to avoid borrowing `scratch` across timing-wheel callbacks.
        // The callbacks are synchronous and never outlive this function call.
        let scratch_ptr = scratch as *mut ScanScratch;
        let found_any_ptr = &mut found_any as *mut bool;
        let local_dropped_ptr = &mut local_dropped as *mut usize;
        let force_full_ptr = &mut force_full as *mut bool;

        if depth < self.tuning.max_transform_depth {
            for (tidx, tcfg) in self.transforms.iter().enumerate() {
                if tcfg.mode == TransformMode::Disabled {
                    continue;
                }
                let state = match tcfg.id {
                    TransformId::UrlPercent => SpanStreamState::Url(UrlSpanStream::new(tcfg)),
                    TransformId::Base64 => SpanStreamState::Base64(Base64SpanStream::new(tcfg)),
                };
                scratch.span_streams.push(SpanStreamEntry {
                    transform_idx: tidx,
                    state,
                    spans_emitted: 0,
                    max_spans: tcfg.max_spans_per_buffer,
                });
            }
        }

        let mut vs_scratch = match scratch.vs_stream_scratch.take() {
            Some(s) => s,
            None => match vs_stream.alloc_scratch() {
                Ok(s) => s,
                Err(_) => return,
            },
        };

        let mut stream = match vs_stream.open_stream() {
            Ok(s) => s,
            Err(_) => {
                scratch.vs_stream_scratch = Some(vs_scratch);
                return;
            }
        };

        let mut ctx = VsStreamMatchCtx {
            pending: &mut scratch.vs_stream_matches as *mut Vec<_>,
            meta: vs_stream.meta().as_ptr(),
            meta_len: vs_stream.meta().len() as u32,
        };

        let mut decoded_offset: u64 = 0;
        // Streamed 128-bit MAC over decoded bytes used for dedupe without buffering.
        let key = [0u8; 16];
        let mut mac = aegis::aegis128l::Aegis128LMac::<16>::new(&key);

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decode_attempts =
                scratch.base64_stats.decode_attempts.saturating_add(1);
            scratch.base64_stats.decode_attempt_bytes = scratch
                .base64_stats
                .decode_attempt_bytes
                .saturating_add(encoded.len() as u64);
        }

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len())
                > self.tuning.max_total_decode_output_bytes
            {
                truncated = true;
                return ControlFlow::Break(());
            }

            if want_utf16_scan && !use_utf16_stream {
                // We need the full decoded buffer to run the UTF-16 scanner later.
                if scratch.slab.buf.len().saturating_add(chunk.len()) > scratch.slab.limit {
                    truncated = true;
                    return ControlFlow::Break(());
                }
                scratch.slab.buf.extend_from_slice(chunk);
                decoded_full_len = decoded_full_len.saturating_add(chunk.len());
                if !decoded_has_nul && memchr(0, chunk).is_some() {
                    decoded_has_nul = true;
                }
            }

            local_out = local_out.saturating_add(chunk.len());
            scratch.total_decode_output_bytes = scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len());

            mac.update(chunk);
            scratch.decode_ring.push(chunk);

            if vs_stream
                .scan_stream(
                    &mut stream,
                    chunk,
                    &mut vs_scratch,
                    stream_match_callback(),
                    (&mut ctx as *mut VsStreamMatchCtx).cast(),
                )
                .is_err()
            {
                truncated = true;
                return ControlFlow::Break(());
            }

            if gate_db_active && gate_hit == 0 {
                if let (Some(db), Some(gstream), Some(gscratch)) = (
                    self.vs_gate.as_ref(),
                    gate_stream.as_mut(),
                    gate_scratch.as_mut(),
                ) {
                    if db
                        .scan_stream(
                            gstream,
                            chunk,
                            gscratch,
                            gate_cb,
                            (&mut gate_hit as *mut u8).cast(),
                        )
                        .is_err()
                    {
                        gate_db_active = false;
                        gate_db_failed = true;
                    }
                }
            }

            if use_utf16_stream {
                if let Some(db) = self.vs_utf16_stream.as_ref() {
                    let mut scanned_chunk = false;
                    if utf16_stream.is_none() && memchr(0, chunk).is_some() {
                        // Lazily start the UTF-16 stream once a NUL suggests wide encoding.
                        let mut vs_utf16_scratch = match scratch.vs_utf16_stream_scratch.take() {
                            Some(s) => s,
                            None => match db.alloc_scratch() {
                                Ok(s) => s,
                                Err(_) => {
                                    truncated = true;
                                    return ControlFlow::Break(());
                                }
                            },
                        };
                        let mut ustream = match db.open_stream() {
                            Ok(s) => s,
                            Err(_) => {
                                scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                        };
                        let base_offset = scratch.decode_ring.start_offset();
                        let mut uctx = VsUtf16StreamMatchCtx {
                            pending: &mut scratch.vs_stream_matches as *mut Vec<_>,
                            targets: db.targets().as_ptr(),
                            pat_offsets: db.pat_offsets().as_ptr(),
                            pat_lens: db.pat_lens().as_ptr(),
                            pat_count: db.pat_lens().len() as u32,
                            base_offset,
                        };
                        let (seg1, seg2) = scratch.decode_ring.segments();
                        if !seg1.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg1,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        if !seg2.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg2,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        utf16_stream = Some(ustream);
                        utf16_stream_scratch = Some(vs_utf16_scratch);
                        utf16_stream_ctx = Some(uctx);
                        scanned_chunk = true;
                    }

                    if !scanned_chunk {
                        if let (Some(ustream), Some(vs_utf16_scratch), Some(uctx)) = (
                            utf16_stream.as_mut(),
                            utf16_stream_scratch.as_mut(),
                            utf16_stream_ctx.as_mut(),
                        ) {
                            if db
                                .scan_stream(
                                    ustream,
                                    chunk,
                                    vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                            {
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                        }
                    }
                }
            }

            if !scratch.vs_stream_matches.is_empty() {
                let max_hits = self.tuning.max_windows_per_rule_variant as u32;
                let mut vs_matches = std::mem::take(&mut scratch.vs_stream_matches);
                for win in vs_matches.drain(..) {
                    if win.force_full {
                        force_full = true;
                        break;
                    }
                    let variant = match Variant::from_idx(win.variant_idx) {
                        Some(v) => v,
                        None => {
                            debug_assert!(
                                false,
                                "Invalid variant_idx {} from Vectorscan callback",
                                win.variant_idx
                            );
                            continue;
                        }
                    };
                    if variant == Variant::Raw {
                        prefilter_gate_hit = true;
                    }
                    let idx = win.rule_id as usize * 3 + variant.idx();
                    let hit = &mut scratch.stream_hit_counts[idx];
                    if *hit == 0 {
                        scratch.stream_hit_touched.push(idx as u32);
                    }
                    *hit = hit.saturating_add(1);
                    if *hit > max_hits {
                        // Too many windows for this rule/variant; bail to full decode.
                        #[cfg(feature = "stats")]
                        self.vs_stats
                            .stream_window_cap_exceeded
                            .fetch_add(1, Ordering::Relaxed);
                        force_full = true;
                        break;
                    }
                    let pending = PendingWindow {
                        hi: win.hi,
                        lo: win.lo,
                        rule_id: win.rule_id,
                        variant,
                        anchor_hint: win.anchor_hint,
                    };
                    match scratch.pending_windows.push(pending.hi, pending) {
                        Ok(PushOutcome::Scheduled) => {}
                        Ok(PushOutcome::Ready(win)) => {
                            let hi = win.hi.min(decoded_offset);
                            process_window(
                                win,
                                hi,
                                scratch,
                                &mut found_any,
                                &mut local_dropped,
                                &mut force_full,
                            );
                            if force_full {
                                break;
                            }
                        }
                        Err(_e) => {
                            #[cfg(debug_assertions)]
                            eprintln!("TimingWheel push failed: {:?}", _e);
                            force_full = true;
                            break;
                        }
                    }
                }
                vs_matches.clear();
                scratch.vs_stream_matches = vs_matches;
                if force_full {
                    return ControlFlow::Break(());
                }
            }

            decoded_offset = decoded_offset.saturating_add(chunk.len() as u64);

            scratch
                .pending_windows
                .advance_and_drain(decoded_offset, |win| {
                    // SAFETY: pending_windows is mutably borrowed; we only touch other fields.
                    let scratch = unsafe { &mut *scratch_ptr };
                    let found_any = unsafe { &mut *found_any_ptr };
                    let local_dropped = unsafe { &mut *local_dropped_ptr };
                    let force_full = unsafe { &mut *force_full_ptr };
                    if *force_full {
                        return;
                    }
                    let hi = win.hi.min(decoded_offset);
                    process_window(win, hi, scratch, found_any, local_dropped, force_full);
                });

            if force_full {
                return ControlFlow::Break(());
            }

            let chunk_start = decoded_offset.saturating_sub(chunk.len() as u64);
            if depth < self.tuning.max_transform_depth {
                // Streaming span detectors emit child decode spans as we go.
                for entry in scratch.span_streams.iter_mut() {
                    if entry.spans_emitted >= entry.max_spans {
                        continue;
                    }
                    let tcfg = &self.transforms[entry.transform_idx];
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            // Span bytes are no longer in the ring; force full decode.
                            force_full = true;
                            return false;
                        }

                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let range = span_start..scratch.slab.buf.len();

                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }

                        let parent_span = lo as usize..hi as usize;
                        let child_step_id = scratch.step_arena.push(
                            step_id,
                            DecodeStep::Transform {
                                transform_idx: entry.transform_idx,
                                parent_span: parent_span.clone(),
                            },
                        );
                        let child_root_hint = root_hint.clone().unwrap_or(parent_span);

                        scratch.pending_spans.push(PendingDecodeSpan {
                            transform_idx: entry.transform_idx,
                            range,
                            step_id: child_step_id,
                            root_hint: Some(child_root_hint),
                            depth: depth + 1,
                        });
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.feed(chunk, chunk_start, &mut on_span),
                        SpanStreamState::Base64(state) => {
                            state.feed(chunk, chunk_start, &mut on_span)
                        }
                    }
                    if force_full {
                        return ControlFlow::Break(());
                    }
                }
            }

            ControlFlow::Continue(())
        });

        let _ = vs_stream.close_stream(
            stream,
            &mut vs_scratch,
            stream_match_callback(),
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        );
        scratch.vs_stream_scratch = Some(vs_scratch);

        if let Some(db) = self.vs_gate.as_ref() {
            if let (Some(gstream), Some(mut gscratch)) = (gate_stream.take(), gate_scratch.take()) {
                let _ = db.close_stream(
                    gstream,
                    &mut gscratch,
                    gate_cb,
                    (&mut gate_hit as *mut u8).cast(),
                );
                gate_scratch = Some(gscratch);
            }
        }
        if let Some(gscratch) = gate_scratch.take() {
            scratch.vs_gate_scratch = Some(gscratch);
        }

        if let Some(db) = self.vs_utf16_stream.as_ref() {
            if let (Some(ustream), Some(mut vs_utf16_scratch), Some(mut uctx)) = (
                utf16_stream.take(),
                utf16_stream_scratch.take(),
                utf16_stream_ctx.take(),
            ) {
                let _ = db.close_stream(
                    ustream,
                    &mut vs_utf16_scratch,
                    utf16_stream_cb,
                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                );
                utf16_stream_scratch = Some(vs_utf16_scratch);
            }
        }
        if let Some(vs_utf16_scratch) = utf16_stream_scratch.take() {
            scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
        }

        if force_full {
            #[cfg(feature = "stats")]
            self.vs_stats
                .stream_force_full
                .fetch_add(1, Ordering::Relaxed);
            // Roll back streaming state/budgets before falling back to full decode.
            scratch.slab.buf.truncate(slab_start);
            scratch.total_decode_output_bytes = total_decode_start;
            scratch.pending_windows.reset();
            scratch.vs_stream_matches.clear();
            scratch.pending_spans.clear();
            scratch.span_streams.clear();
            scratch.tmp_findings.clear();
            self.decode_span_fallback(
                tc,
                transform_idx,
                encoded,
                step_id,
                root_hint,
                depth,
                base_offset,
                file_id,
                scratch,
            );
            return;
        }

        if res.is_ok() {
            if !scratch.vs_stream_matches.is_empty() {
                let max_hits = self.tuning.max_windows_per_rule_variant as u32;
                let mut vs_matches = std::mem::take(&mut scratch.vs_stream_matches);
                for win in vs_matches.drain(..) {
                    if win.force_full {
                        force_full = true;
                        break;
                    }
                    let variant = match Variant::from_idx(win.variant_idx) {
                        Some(v) => v,
                        None => {
                            debug_assert!(
                                false,
                                "Invalid variant_idx {} from Vectorscan callback",
                                win.variant_idx
                            );
                            continue;
                        }
                    };
                    if variant == Variant::Raw {
                        prefilter_gate_hit = true;
                    }
                    let idx = win.rule_id as usize * 3 + variant.idx();
                    let hit = &mut scratch.stream_hit_counts[idx];
                    if *hit == 0 {
                        scratch.stream_hit_touched.push(idx as u32);
                    }
                    *hit = hit.saturating_add(1);
                    if *hit > max_hits {
                        force_full = true;
                        break;
                    }
                    let pending = PendingWindow {
                        hi: win.hi,
                        lo: win.lo,
                        rule_id: win.rule_id,
                        variant,
                        anchor_hint: win.anchor_hint,
                    };
                    match scratch.pending_windows.push(pending.hi, pending) {
                        Ok(PushOutcome::Scheduled) => {}
                        Ok(PushOutcome::Ready(win)) => {
                            let hi = win.hi.min(decoded_offset);
                            process_window(
                                win,
                                hi,
                                scratch,
                                &mut found_any,
                                &mut local_dropped,
                                &mut force_full,
                            );
                            if force_full {
                                break;
                            }
                        }
                        Err(_e) => {
                            #[cfg(debug_assertions)]
                            eprintln!("TimingWheel push failed: {:?}", _e);
                            force_full = true;
                            break;
                        }
                    }
                }
                vs_matches.clear();
                scratch.vs_stream_matches = vs_matches;
                if force_full {
                    scratch.vs_stream_matches.clear();
                }
            }
            if !force_full {
                for entry in scratch.span_streams.iter_mut() {
                    let end_offset = decoded_offset;
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            // End-of-stream spans must still be in the ring to materialize.
                            force_full = true;
                            return false;
                        }
                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let range = span_start..scratch.slab.buf.len();
                        let tcfg = &self.transforms[entry.transform_idx];
                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }
                        let parent_span = lo as usize..hi as usize;
                        let child_step_id = scratch.step_arena.push(
                            step_id,
                            DecodeStep::Transform {
                                transform_idx: entry.transform_idx,
                                parent_span: parent_span.clone(),
                            },
                        );
                        let child_root_hint = root_hint.clone().unwrap_or(parent_span);
                        scratch.pending_spans.push(PendingDecodeSpan {
                            transform_idx: entry.transform_idx,
                            range,
                            step_id: child_step_id,
                            root_hint: Some(child_root_hint),
                            depth: depth + 1,
                        });
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.finish(end_offset, &mut on_span),
                        SpanStreamState::Base64(state) => state.finish(end_offset, &mut on_span),
                    }
                    if force_full {
                        break;
                    }
                }
            }
        }

        if res.is_ok() && !force_full {
            let final_offset = decoded_offset;
            scratch.pending_windows.advance_and_drain(u64::MAX, |win| {
                // SAFETY: pending_windows is mutably borrowed; we only touch other fields.
                let scratch = unsafe { &mut *scratch_ptr };
                let found_any = unsafe { &mut *found_any_ptr };
                let local_dropped = unsafe { &mut *local_dropped_ptr };
                let force_full = unsafe { &mut *force_full_ptr };
                if *force_full {
                    return;
                }
                let hi = win.hi.min(final_offset);
                process_window(win, hi, scratch, found_any, local_dropped, force_full);
            });
        }

        if force_full {
            scratch.slab.buf.truncate(slab_start);
            scratch.total_decode_output_bytes = total_decode_start;
            scratch.pending_windows.reset();
            scratch.vs_stream_matches.clear();
            scratch.pending_spans.clear();
            scratch.span_streams.clear();
            scratch.tmp_findings.clear();
            self.decode_span_fallback(
                tc,
                transform_idx,
                encoded,
                step_id,
                root_hint,
                depth,
                base_offset,
                file_id,
                scratch,
            );
            return;
        }

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decode_errors =
                    scratch.base64_stats.decode_errors.saturating_add(1);
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_error = scratch
                    .base64_stats
                    .decoded_bytes_wasted_error
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        if want_utf16_scan && !use_utf16_stream && decoded_has_nul && decoded_full_len > 0 {
            if let Some(vs_utf16) = self.vs_utf16.as_ref() {
                if let Some(mut vs_utf16_scratch) = scratch.vs_utf16_scratch.take() {
                    #[cfg(feature = "stats")]
                    self.vs_stats
                        .utf16_scans_attempted
                        .fetch_add(1, Ordering::Relaxed);

                    debug_assert!(scratch.touched_pairs.is_empty());
                    if !scratch.touched_pairs.is_empty() {
                        scratch
                            .hit_acc_pool
                            .reset_touched(scratch.touched_pairs.as_slice());
                        scratch.touched_pairs.clear();
                    }

                    let decoded_end = decoded_full_start.saturating_add(decoded_full_len);
                    let (decoded_ptr, decoded_len) = {
                        let decoded = &scratch.slab.buf[decoded_full_start..decoded_end];
                        (decoded.as_ptr(), decoded.len())
                    };
                    // SAFETY: `decoded_ptr` points to a slab range appended above. The slab does
                    // not reallocate during this scan, and we do not mutate the slab while
                    // `decoded` is in use.
                    let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
                    let result = vs_utf16.scan_utf16(decoded, scratch, &mut vs_utf16_scratch);
                    scratch.vs_utf16_scratch = Some(vs_utf16_scratch);

                    let used_vectorscan_utf16 = result.as_ref().map(|saw| *saw).unwrap_or(false);
                    match result {
                        Ok(_) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats.utf16_scans_ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats
                                .utf16_scans_err
                                .fetch_add(1, Ordering::Relaxed);

                            if !scratch.touched_pairs.is_empty() {
                                let touched_len = scratch.touched_pairs.len();
                                for i in 0..touched_len {
                                    let pair = scratch.touched_pairs[i] as usize;
                                    scratch.hit_acc_pool.reset_pair(pair);
                                }
                                scratch
                                    .hit_acc_pool
                                    .reset_touched(scratch.touched_pairs.as_slice());
                                scratch.touched_pairs.clear();
                            }
                            // Skip UTF-16 scan on error.
                        }
                    }

                    if !scratch.touched_pairs.is_empty() {
                        const VARIANTS: [Variant; 3] =
                            [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
                        let touched_len = scratch.touched_pairs.len();
                        let hay_len = decoded_len as u32;
                        let merge_gap = self.tuning.merge_gap as u32;
                        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

                        for i in 0..touched_len {
                            let pair = scratch.touched_pairs[i] as usize;
                            let rid = pair / 3;
                            let vidx = pair % 3;
                            let variant = VARIANTS[vidx];
                            if variant == Variant::Raw {
                                continue;
                            }
                            let rule = &self.rules[rid];

                            scratch.hit_acc_pool.take_into(pair, &mut scratch.windows);
                            if scratch.windows.is_empty() {
                                continue;
                            }

                            if used_vectorscan_utf16 && scratch.windows.len() > 1 {
                                scratch
                                    .windows
                                    .as_mut_slice()
                                    .sort_unstable_by_key(|s| s.start);
                            }

                            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
                            coalesce_under_pressure_sorted(
                                &mut scratch.windows,
                                hay_len,
                                pressure_gap_start,
                                self.tuning.max_windows_per_rule_variant,
                            );

                            if let Some(tp) = &rule.two_phase {
                                let seed_radius_bytes =
                                    tp.seed_radius.saturating_mul(variant.scale());
                                let full_radius_bytes =
                                    tp.full_radius.saturating_mul(variant.scale());
                                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                                scratch.expanded.clear();
                                let windows_len = scratch.windows.len();
                                for i in 0..windows_len {
                                    let seed = scratch.windows[i];
                                    let seed_range = seed.to_range();
                                    let win = &decoded[seed_range.clone()];
                                    if !super::helpers::contains_any_memmem(win, &tp.confirm[vidx])
                                    {
                                        continue;
                                    }

                                    let lo = seed_range.start.saturating_sub(extra);
                                    let hi = (seed_range.end + extra).min(decoded.len());
                                    // Preserve anchor_hint from the seed window.
                                    scratch.expanded.push(SpanU32::new(
                                        lo,
                                        hi,
                                        seed.anchor_hint as usize,
                                    ));
                                }

                                if scratch.expanded.is_empty() {
                                    continue;
                                }

                                merge_ranges_with_gap_sorted(&mut scratch.expanded, merge_gap);
                                coalesce_under_pressure_sorted(
                                    &mut scratch.expanded,
                                    hay_len,
                                    pressure_gap_start,
                                    self.tuning.max_windows_per_rule_variant,
                                );

                                let expanded_len = scratch.expanded.len();
                                for i in 0..expanded_len {
                                    let span = scratch.expanded[i];
                                    let w = span.to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut local_dropped,
                                        &mut found_any,
                                        span.anchor_hint as u64,
                                    );
                                }
                            } else {
                                let win_len = scratch.windows.len();
                                for i in 0..win_len {
                                    let span = scratch.windows[i];
                                    let w = span.to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut local_dropped,
                                        &mut found_any,
                                        span.anchor_hint as u64,
                                    );
                                }
                            }
                        }
                        scratch
                            .hit_acc_pool
                            .reset_touched(scratch.touched_pairs.as_slice());
                        scratch.touched_pairs.clear();
                    }
                }
            }
        }

        // Decide if the decoded-space gate was satisfied (or if prefilter hits are enough).
        let gate_satisfied = if gate_db_active || gate_hit != 0 {
            gate_hit != 0
        } else {
            prefilter_gate_hit
        };
        // Only enforce the gate when we are confident it reflects decoded-space anchors.
        let enforce_gate = if gate_enabled {
            if gate_db_failed {
                false
            } else if gate_db_active || gate_hit != 0 {
                true
            } else {
                !self.tuning.scan_utf16_variants || !self.has_utf16_anchors
            }
        } else {
            false
        };
        if enforce_gate && !gate_satisfied {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_no_anchor = scratch
                    .base64_stats
                    .decoded_bytes_wasted_no_anchor
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decoded_bytes_total = scratch
                .base64_stats
                .decoded_bytes_total
                .saturating_add(local_out as u64);
            scratch.base64_stats.decoded_bytes_kept = scratch
                .base64_stats
                .decoded_bytes_kept
                .saturating_add(local_out as u64);
        }

        let h = u128::from_le_bytes(mac.finalize());
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        if local_dropped > 0 {
            scratch.findings_dropped = scratch.findings_dropped.saturating_add(local_dropped);
        }
        let mut tmp_findings = std::mem::take(&mut scratch.tmp_findings);
        for rec in tmp_findings.drain(..) {
            scratch.push_finding(rec);
        }
        scratch.tmp_findings = tmp_findings;

        let found_any_in_buf = found_any;
        let mut enqueued = 0usize;
        for pending in scratch.pending_spans.drain(..) {
            let mode = self.transforms[pending.transform_idx].mode;
            if mode == TransformMode::IfNoFindingsInThisBuffer && found_any_in_buf {
                continue;
            }
            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                break;
            }
            scratch.work_q.push(WorkItem::DecodeSpan {
                transform_idx: pending.transform_idx,
                enc_ref: EncRef::Slab(pending.range),
                step_id: pending.step_id,
                root_hint: pending.root_hint,
                depth: pending.depth,
            });
            scratch.work_items_enqueued += 1;
            enqueued += 1;
        }

        let _ = enqueued;
        let _ = (transform_idx, base_offset, file_id);
    }
}
