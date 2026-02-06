//! Buffer-level scanning coordination.
//!
//! This module wires together the prefilter pipeline and final rule evaluation
//! for a single decoded buffer variant. The pipeline is:
//!
//! 1. **Prefilter** — Run the Vectorscan prefilter on raw bytes to collect hit
//!    windows, populating `touched_pairs` and per-pair hit accumulators.
//! 2. **Normalize** — For each touched (rule, variant) pair, sort hit windows,
//!    merge adjacent/overlapping ones (gap-tolerant), and coalesce under
//!    pressure if the window count exceeds the per-rule cap.
//! 3. **Two-phase confirm** (optional) — Re-check a narrow seed window with
//!    memmem confirmation before expanding to the full validation radius.
//!    This filters noisy prefilter hits cheaply.
//! 4. **Validate** — Run full regex matching on the resulting windows and emit
//!    findings via [`Engine::run_rule_on_window`](super::window_validate).
//!
//! ## Pair encoding
//!
//! Touched pairs are encoded as `pair = rule_id * 3 + variant_idx`, where
//! variant indices are `Raw = 0`, `Utf16Le = 1`, `Utf16Be = 2`. This flat
//! encoding avoids a two-level map and keeps the hot loop cache-friendly.
//!
//! ## One-shot prefilter skip
//!
//! When called from `scan_chunk_into` on the root buffer, the prefilter was
//! already run by the caller. The `scratch.root_prefilter_done` flag is a
//! one-shot signal consumed here: the first call (root buffer) skips the
//! prefilter; subsequent calls (transform buffers) see `false` and run it.
//!
//! All work is bounded by a `u32`-addressable buffer; windows and spans are
//! stored as [`SpanU32`] to keep hot-path memory compact.

use crate::api::{FileId, StepId};
use std::ops::Range;
#[cfg(feature = "stats")]
use std::sync::atomic::Ordering;

use super::core::Engine;
use super::helpers::{
    coalesce_under_pressure_sorted, contains_any_memmem, merge_ranges_with_gap_sorted,
};
use super::hit_pool::SpanU32;
use super::rule_repr::Variant;
use super::scratch::ScanScratch;

impl Engine {
    /// Applies the prefilter/gating pipeline to a single buffer variant.
    ///
    /// # Preconditions
    /// - `buf.len() <= u32::MAX`.
    /// - `scratch` belongs to the current scan and is not shared concurrently.
    /// - `root_hint` (if provided) is a range into `buf` (relative to this buffer).
    ///
    /// # Effects
    /// - Populates per-rule hit windows and emits findings into `scratch`.
    /// - May decode UTF-16 windows for validation when enabled.
    ///
    /// # Performance
    /// - Work scales with the number of touched (rule, variant) pairs rather than
    ///   all rules in the engine.
    pub(super) fn scan_rules_on_buffer(
        &self,
        buf: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        debug_assert!(buf.len() <= u32::MAX as usize);
        debug_assert!(self.tuning.merge_gap <= u32::MAX as usize);
        debug_assert!(self.tuning.pressure_gap_start <= u32::MAX as usize);
        let hay_len = buf.len() as u32;
        let merge_gap = self.tuning.merge_gap as u32;
        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

        // Check if scan_chunk_into already ran the prefilter for the root buffer.
        // This is a one-shot flag: consumed here so transform buffer calls see
        // `false` and run the full prefilter as normal.
        let (mut used_vectorscan_utf16, skip_prefilter) = if scratch.root_prefilter_done {
            scratch.root_prefilter_done = false;
            (scratch.root_prefilter_saw_utf16, true)
        } else {
            (false, false)
        };

        if !skip_prefilter {
            // `touched_pairs` is cleared after each buffer; fast-path when empty.
            debug_assert!(scratch.touched_pairs.is_empty());
            if !scratch.touched_pairs.is_empty() {
                scratch
                    .hit_acc_pool
                    .reset_touched(scratch.touched_pairs.as_slice());
                scratch.touched_pairs.clear();
            }
            // Stage 1: Vectorscan prefilter on raw bytes (required).
            let vs = self
                .vs
                .as_ref()
                .expect("vectorscan prefilter database unavailable (fallback disabled)");
            let mut vs_scratch_owned = scratch
                .vs_scratch
                .take()
                .expect("vectorscan scratch missing");
            #[cfg(feature = "stats")]
            self.vs_stats
                .scans_attempted
                .fetch_add(1, Ordering::Relaxed);
            let (result, _vs_nanos) =
                crate::git_scan::perf::time(|| vs.scan_raw(buf, scratch, &mut vs_scratch_owned));
            crate::git_scan::perf::record_scan_vs_prefilter(_vs_nanos);
            scratch.vs_scratch = Some(vs_scratch_owned);
            let saw_utf16 = match result {
                Ok(saw) => {
                    #[cfg(feature = "stats")]
                    self.vs_stats.scans_ok.fetch_add(1, Ordering::Relaxed);
                    saw
                }
                Err(err) => {
                    #[cfg(feature = "stats")]
                    self.vs_stats.scans_err.fetch_add(1, Ordering::Relaxed);
                    panic!("vectorscan scan failed with fallback disabled: {err}");
                }
            };

            used_vectorscan_utf16 = saw_utf16;

            if !vs.raw_missing_rules().is_empty() {
                panic!(
                    "vectorscan raw db missing {} rule patterns (fallback disabled)",
                    vs.raw_missing_rules().len()
                );
            }

            #[cfg(feature = "stats")]
            {
                if saw_utf16 {
                    self.vs_stats
                        .anchor_after_vs
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.vs_stats.anchor_skipped.fetch_add(1, Ordering::Relaxed);
                }
            }

            if scratch.touched_pairs.is_empty() {
                crate::git_scan::perf::record_scan_zero_hit_chunk();
                return;
            }
        }

        // Only process (rule, variant) pairs that were actually touched by a
        // prefilter hit in this buffer. This avoids O(rules × variants) work
        // when nothing matched, which is critical once rule counts grow.
        //
        // Each `pair` encodes `rule_id * 3 + variant_idx` (see module docs).
        // We decode via integer division/modulus rather than a struct to keep
        // the touched_pairs vector as a flat u32 list.
        #[cfg(feature = "git-perf")]
        let _validate_start = std::time::Instant::now();
        const VARIANTS: [Variant; 3] = [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
        let touched_len = scratch.touched_pairs.len();
        for i in 0..touched_len {
            let pair = scratch.touched_pairs[i] as usize;
            let rid = pair / 3;
            let vidx = pair % 3;
            let variant = VARIANTS[vidx];
            let rule = &self.rules[rid];

            scratch.hit_acc_pool.take_into(pair, &mut scratch.windows);
            if scratch.windows.is_empty() {
                continue;
            }

            // Vectorscan callbacks fire in match-end order (not start order),
            // and multiple patterns may interleave, so windows arrive unsorted.
            //
            // Raw variant: always needs sorting because Vectorscan always runs.
            // UTF-16 variants: only sort when the Vectorscan UTF-16 DB was used
            // for this buffer (`used_vectorscan_utf16`); if the UTF-16 DB was
            // absent, no UTF-16 hits were recorded and the windows are empty.
            //
            // The `len() > 1` guard avoids a no-op sort on a single window.
            if (variant == Variant::Raw && scratch.windows.len() > 1)
                || (used_vectorscan_utf16
                    && matches!(variant, Variant::Utf16Le | Variant::Utf16Be)
                    && scratch.windows.len() > 1)
            {
                scratch
                    .windows
                    .as_mut_slice()
                    .sort_unstable_by_key(|s| s.start);
            }

            // Post-sort invariant: windows are now in non-decreasing order of start.
            // Merge adjacent/overlapping windows with the configured gap tolerance.
            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
            coalesce_under_pressure_sorted(
                &mut scratch.windows,
                hay_len,
                pressure_gap_start,
                self.tuning.max_windows_per_rule_variant,
            );

            // Two-phase confirmation: a cost-saving optimization for rules whose
            // prefilter fires frequently but whose regex is expensive.
            //
            // Phase 1 (seed): memmem-check each seed window for the confirm
            //   pattern. Windows without a match are dropped immediately.
            // Phase 2 (expand): surviving windows are widened from seed_radius
            //   to full_radius (the actual regex validation radius). The extra
            //   padding is `(full_radius - seed_radius) * variant.scale()`.
            //
            // Correctness argument: if the seed pattern is absent in the narrow
            // window, the full regex cannot match in the wider window either
            // (the confirm patterns are mandatory sub-matches of the regex).
            if let Some(tp) = &rule.two_phase {
                let seed_radius_bytes = tp.seed_radius.saturating_mul(variant.scale());
                let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                scratch.expanded.clear();
                let windows_len = scratch.windows.len();
                for i in 0..windows_len {
                    let seed = scratch.windows[i];
                    let seed_range = seed.to_range();
                    let win = &buf[seed_range.clone()];
                    if !contains_any_memmem(win, &tp.confirm[vidx]) {
                        continue;
                    }

                    let lo = seed_range.start.saturating_sub(extra);
                    let hi = (seed_range.end + extra).min(buf.len());
                    // Preserve the anchor_hint from the seed window.
                    scratch
                        .expanded
                        .push(SpanU32::new(lo, hi, seed.anchor_hint as usize));
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
                    let anchor_hint = span.anchor_hint as usize;
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                        anchor_hint,
                    );
                }
                continue;
            }

            let win_len = scratch.windows.len();
            for i in 0..win_len {
                let span = scratch.windows[i];
                let w = span.to_range();
                let anchor_hint = span.anchor_hint as usize;
                self.run_rule_on_window(
                    rid as u32,
                    rule,
                    variant,
                    buf,
                    w,
                    step_id,
                    root_hint.clone(),
                    base_offset,
                    file_id,
                    scratch,
                    anchor_hint,
                );
            }
        }
        // Reset accumulators for all pairs touched in this buffer so the next
        // buffer starts clean. This must happen *after* the validation loop
        // because the loop reads from the accumulators via `take_into`.
        scratch
            .hit_acc_pool
            .reset_touched(scratch.touched_pairs.as_slice());
        scratch.touched_pairs.clear();

        #[cfg(feature = "git-perf")]
        crate::git_scan::perf::record_scan_validate(_validate_start.elapsed().as_nanos() as u64);
    }
}
