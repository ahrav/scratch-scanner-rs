//! Real Engine Trait Implementations
//!
//! This module implements the scheduler's engine traits for the production
//! scanning engine ([`crate::engine::Engine`]).
//!
//! # Usage
//!
//! Import this module to make the real engine compatible with the scheduler:
//!
//! ```ignore
//! use scanner_rs::scheduler::engine_impl::*;
//! use scanner_rs::scheduler::scan_local;
//! use scanner_rs::engine::Engine;
//!
//! let engine = Arc::new(Engine::new(rules, transforms, tuning));
//! let report = scan_local(engine, source, config, sink);
//! ```
//!
//! # Type Mapping
//!
//! | Scheduler Trait | Real Engine Type |
//! |-----------------|------------------|
//! | [`FindingRecord`](super::engine_trait::FindingRecord) | [`crate::api::FindingRec`] |
//! | [`EngineScratch`](super::engine_trait::EngineScratch) | [`RealEngineScratch`] (wraps [`crate::engine::ScanScratch`]) |
//! | [`ScanEngine`](super::engine_trait::ScanEngine) | [`crate::engine::Engine`] |
//!
//! # Design: Lazy Reset Pattern
//!
//! The real engine's `ScanScratch::reset_for_scan()` requires an `&Engine` reference,
//! but the trait's `clear()` method cannot provide one (engine reference isn't available
//! at that point). We solve this with a **lazy reset** pattern:
//!
//! 1. `clear()` only clears the findings buffer (no-op for internal scratch state)
//! 2. `Engine::scan_chunk_into()` calls `reset_for_scan()` internally before scanning
//!
//! This preserves the trait's simplicity while satisfying the real engine's requirements.

use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use crate::api::{FileId, FindingRec as ApiFindingRec};
use crate::engine::{Engine, ScanScratch as RealScanScratch};

// ============================================================================
// FindingRecord for api::FindingRec
// ============================================================================

impl FindingRecord for ApiFindingRec {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.rule_id
    }

    #[inline]
    fn root_hint_start(&self) -> u64 {
        self.root_hint_start
    }

    #[inline]
    fn root_hint_end(&self) -> u64 {
        self.root_hint_end
    }

    #[inline]
    fn span_start(&self) -> u64 {
        u64::from(self.span_start)
    }

    #[inline]
    fn span_end(&self) -> u64 {
        u64::from(self.span_end)
    }
}

// ============================================================================
// EngineScratch for engine::ScanScratch
// ============================================================================

/// Wrapper around the real `ScanScratch` that stores an engine reference.
///
/// The real `ScanScratch::reset_for_scan` requires an `&Engine` reference,
/// but the trait's `clear()` method doesn't provide one. We store the engine
/// reference when creating the scratch, then use it in `clear()`.
///
/// # Alternative Approaches Considered
///
/// 1. **Change trait signature**: Would break the abstraction and require
///    the scheduler to know about engine internals.
///
/// 2. **Store findings separately**: Would add copying overhead.
///
/// 3. **Lazy reset**: Clear only the local drain buffer; delay full engine scratch
///    reset until next scan. This is what we do: `clear()` clears `findings_buf`
///    (our local drain buffer), and `scan_chunk_into` calls `reset_for_scan`
///    internally before scanning to reset the engine's internal state.
pub struct RealEngineScratch {
    scratch: RealScanScratch,
    /// Temporary buffer for draining findings.
    findings_buf: Vec<ApiFindingRec>,
}

// SAFETY: RealEngineScratch wraps ScanScratch which is not automatically Send because
// it contains `Option<VsScratch>` fields holding raw pointers to Vectorscan FFI handles
// (`*mut hs_scratch_t`, `*mut hs_database_t`). Raw pointers are !Send by default.
//
// The unsafe impl Send is justified because:
//
// 1. **Ownership model**: Each scratch instance is created per-worker and never shared.
//    - Created once in `Executor::new()` via the `scratch_init` closure
//    - Stored in `WorkerCtx` which is pinned to a single worker thread
//    - Only accessed by the owning worker thread during `process_file()`
//
// 2. **Transfer semantics**: The Send bound is required by the `EngineScratch` trait
//    to allow the executor to pass scratch to worker threads at startup. After this
//    one-time transfer, each scratch instance is thread-local for the lifetime of
//    the scan.
//
// 3. **Vectorscan safety**: The underlying `hs_scratch_t` handles are not thread-safe
//    for concurrent use (Vectorscan requirement), but they ARE safe to transfer between
//    threads as long as only one thread uses them at a time. Our ownership model
//    guarantees single-thread access after initialization.
//
// 4. **Other fields**: `ScratchVec<T>` uses `NonNull` internally but owns its data
//    and follows Rust's aliasing rules. `Vec<u8>`, `Vec<FindingRec>`, etc. are all
//    Send when their contents are Send.
//
// If the executor's invariants change (e.g., work-stealing that moves scratch between
// workers), this unsafe impl would become unsound and must be revisited.
unsafe impl Send for RealEngineScratch {}

impl RealEngineScratch {
    /// Create a new wrapper around the real scratch.
    pub fn new(scratch: RealScanScratch, max_findings: usize) -> Self {
        Self {
            scratch,
            findings_buf: Vec::with_capacity(max_findings),
        }
    }

    /// Get mutable access to the underlying scratch for scanning.
    pub fn inner_mut(&mut self) -> &mut RealScanScratch {
        &mut self.scratch
    }
}

impl EngineScratch for RealEngineScratch {
    type Finding = ApiFindingRec;

    fn clear(&mut self) {
        // Lazy reset pattern: the real scratch's `reset_for_scan()` is called inside
        // `Engine::scan_chunk_into()`, not here. This is because `reset_for_scan()`
        // requires an `&Engine` reference that we don't have in this trait method.
        //
        // We only clear our temporary drain buffer here.
        self.findings_buf.clear();
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.scratch.drop_prefix_findings(new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        // The real scratch has drain_findings which requires a pre-sized output.
        // We first drain into our buffer, then append to out.
        self.findings_buf.clear();
        if self.findings_buf.capacity() >= self.scratch.pending_findings_len() {
            self.scratch.drain_findings(&mut self.findings_buf);
            out.append(&mut self.findings_buf);
        } else {
            // Reserve more capacity if needed
            self.findings_buf
                .reserve(self.scratch.pending_findings_len());
            self.scratch.drain_findings(&mut self.findings_buf);
            out.append(&mut self.findings_buf);
        }
    }
}

// ============================================================================
// ScanEngine for engine::Engine
// ============================================================================

impl ScanEngine for Engine {
    type Scratch = RealEngineScratch;

    fn required_overlap(&self) -> usize {
        self.required_overlap()
    }

    fn new_scratch(&self) -> Self::Scratch {
        let scratch = self.new_scratch();
        let max_findings = self.tuning.max_findings_per_chunk;
        RealEngineScratch::new(scratch, max_findings)
    }

    fn scan_chunk_into(
        &self,
        data: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        // The real engine's scan_chunk_into calls reset_for_scan internally.
        self.scan_chunk_into(data, file_id, base_offset, scratch.inner_mut());
    }

    fn rule_name(&self, rule_id: u32) -> &str {
        self.rule_name(rule_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{RuleSpec, TransformConfig, Tuning};
    use regex::bytes::Regex;

    fn test_tuning() -> Tuning {
        Tuning {
            merge_gap: 64,
            max_windows_per_rule_variant: 64,
            pressure_gap_start: 128,
            max_anchor_hits_per_rule_variant: 256,
            max_utf16_decoded_bytes_per_window: 4096,
            max_transform_depth: 2,
            max_total_decode_output_bytes: 1024 * 1024,
            max_work_items: 64,
            max_findings_per_chunk: 4096,
            scan_utf16_variants: true,
        }
    }

    fn simple_rule() -> RuleSpec {
        RuleSpec {
            name: "test-secret",
            anchors: &[b"SECRET"],
            radius: 32,
            validator: crate::api::ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            local_context: None,
            secret_group: None,
            re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
        }
    }

    #[test]
    fn real_engine_implements_scan_engine() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Engine::new(rules, transforms, test_tuning());

        // Verify trait methods work - use explicit trait syntax to avoid inherent method
        assert!(<Engine as ScanEngine>::required_overlap(&engine) > 0);
        let mut scratch = <Engine as ScanEngine>::new_scratch(&engine);

        let data = b"test SECRET12345678 end";
        <Engine as ScanEngine>::scan_chunk_into(&engine, data, FileId(0), 0, &mut scratch);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            <Engine as ScanEngine>::rule_name(&engine, findings[0].rule_id()),
            "test-secret"
        );
    }

    #[test]
    fn drop_prefix_findings_works() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Engine::new(rules, transforms, test_tuning());

        // Use trait method to get RealEngineScratch
        let mut scratch = <Engine as ScanEngine>::new_scratch(&engine);

        // Create two matches: one at offset 0, one at offset 100
        let data1 = b"SECRET12345678 padding";
        <Engine as ScanEngine>::scan_chunk_into(&engine, data1, FileId(0), 0, &mut scratch);

        // The finding root_hint_end should be around 14 (length of match)
        // Drop findings whose root_hint_end < 50
        scratch.drop_prefix_findings(50);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        // Should have dropped the finding since it ended before offset 50
        assert!(findings.is_empty());
    }
}
