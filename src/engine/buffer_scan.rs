//! Buffer-level scanning coordination.
//!
//! This module wires together the prefilter pipeline and final rule evaluation
//! for a single decoded buffer variant. The pipeline is:
//! 1. Run the Vectorscan prefilter on raw bytes to collect hit windows.
//! 2. For each touched (rule, variant) pair, normalize windows (sort/merge/
//!    coalesce) and apply optional two-phase confirmation.
//! 3. Run full rule matching on the resulting windows and emit findings.
//!
//! All work is bounded by a `u32`-addressable buffer; windows and spans are
//! stored as `SpanU32` to keep hot-path memory compact.

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

        // `touched_pairs` is cleared after each buffer; fast-path when empty.
        debug_assert!(scratch.touched_pairs.is_empty());
        if !scratch.touched_pairs.is_empty() {
            scratch
                .hit_acc_pool
                .reset_touched(scratch.touched_pairs.as_slice());
            scratch.touched_pairs.clear();
        }
        // Stage 1: Vectorscan prefilter on raw bytes (required).
        let used_vectorscan = true;
        let vs = self
            .vs
            .as_ref()
            .expect("vectorscan prefilter database unavailable (fallback disabled)");
        let mut vs_scratch = scratch
            .vs_scratch
            .take()
            .expect("vectorscan scratch missing");
        #[cfg(feature = "stats")]
        self.vs_stats
            .scans_attempted
            .fetch_add(1, Ordering::Relaxed);
        let result = vs.scan_raw(buf, scratch, &mut vs_scratch);
        scratch.vs_scratch = Some(vs_scratch);
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

        let used_vectorscan_utf16 = saw_utf16;

        if !vs.raw_missing_rules().is_empty() {
            panic!(
                "vectorscan raw db missing {} rule patterns (fallback disabled)",
                vs.raw_missing_rules().len()
            );
        }

        #[cfg(feature = "stats")]
        {
            if used_vectorscan {
                if used_vectorscan_utf16 {
                    self.vs_stats
                        .anchor_after_vs
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.vs_stats.anchor_skipped.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                self.vs_stats.anchor_only.fetch_add(1, Ordering::Relaxed);
            }
        }

        if scratch.touched_pairs.is_empty() {
            return;
        }

        // Only process (rule, variant) pairs that were actually touched by a
        // prefilter hit in this buffer. This avoids O(rules * variants) work
        // when nothing matched, which is critical once rule counts grow.
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

            // Anchor scans push windows in non-decreasing order of match positions.
            // Vectorscan callbacks are not guaranteed to be ordered, so we must
            // sort the raw variant windows when Vectorscan ran.
            if (used_vectorscan && variant == Variant::Raw && scratch.windows.len() > 1)
                || (used_vectorscan_utf16
                    && matches!(variant, Variant::Utf16Le | Variant::Utf16Be)
                    && scratch.windows.len() > 1)
            {
                scratch
                    .windows
                    .as_mut_slice()
                    .sort_unstable_by_key(|s| s.start);
            }

            // Windows are pushed in non-decreasing order of match positions.
            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
            coalesce_under_pressure_sorted(
                &mut scratch.windows,
                hay_len,
                pressure_gap_start,
                self.tuning.max_windows_per_rule_variant,
            );

            // Two-phase rules re-check a narrow "seed" window before expanding to
            // the full radius. This filters noisy prefilter hits while keeping
            // correctness (if the seed match is missing, the full match cannot
            // succeed).
            if let Some(tp) = &rule.two_phase {
                // Two-phase: confirm in seed windows, then expand.
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
                    scratch.expanded.push(SpanU32::new(lo, hi));
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
                    let w = scratch.expanded[i].to_range();
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
                    );
                }
                continue;
            }

            let win_len = scratch.windows.len();
            for i in 0..win_len {
                let w = scratch.windows[i].to_range();
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
                );
            }
        }
        scratch
            .hit_acc_pool
            .reset_touched(scratch.touched_pairs.as_slice());
        scratch.touched_pairs.clear();
    }
}
