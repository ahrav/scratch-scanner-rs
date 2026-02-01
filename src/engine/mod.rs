//! Core scanning engine: compiles rule specs into anchors/gates and executes
//! bounded scans with reusable scratch allocations.
//!
//! # Algorithm
//! 1. Compile rules into anchor patterns, confirm-all literals, and keyword gates.
//! 2. Prefilter input buffers (Vectorscan / gates) to build candidate windows.
//! 3. Validate windows with regexes/validators and record compact findings.
//! 4. Optionally decode transform spans into derived buffers and repeat via BFS.
//!
//! # Invariants
//! - The engine is immutable after construction; all mutable scan state lives in
//!   [`ScanScratch`], which is single-threaded and reused across scans.
//! - Scratch buffers are reused across scans and must be reset between scans.
//! - Decoded buffers are stored in an append-only slab; ranges and `StepId`
//!   references are only valid until the next `ScanScratch::reset_for_scan`.
//! - Offsets stored in hot paths use `u32`; callers must chunk inputs so buffer
//!   lengths fit in `u32`.
//! - `SpanU32` and `BufRef::Slab` ranges are only valid until the next reset.
//! - All per-scan work is bounded by tuning limits: windows, hits, findings,
//!   decode output bytes, transform depth, and work items.
//! - UTF-16 anchors always contain at least one NUL byte, enabling a raw-only
//!   fast path for NUL-free buffers.
//!
//! # Span Semantics
//! - Raw findings report byte offsets in the scanned buffer.
//! - UTF-16 variant findings report spans in decoded UTF-8 bytes and attach a
//!   [`DecodeStep::Utf16Window`] that records the source UTF-16 window.
//! - Findings from decoded/transformed buffers report spans in derived buffers;
//!   the decode step chain provides provenance back to the root input.
//!
//! # Safety
//! - Unsafe slices are formed only from ranges validated against the root buffer,
//!   the decode slab, or scratch-owned temporary buffers; those buffers are not
//!   reallocated while the slices are in use.
//!
//! # Design Notes
//! - The engine favors predictable cost over perfect precision: span/anchor
//!   selection is permissive, while validation and gates enforce correctness.
//! - Prefilters (Vectorscan, base64 pre-gate) are conservative: they may admit
//!   false positives but must not drop true matches.
//!
//! # Failure Modes and Limits
//! - Raw Vectorscan prefilter DB build failures are fatal (fallback disabled).
//! - UTF-16 prefilter DB build or scan failures disable UTF-16 anchor scans
//!   for the affected buffer.
//! - Budget enforcement may coalesce windows, skip deeper decode work, or drop
//!   findings; dropped findings are counted in
//!   [`ScanScratch::dropped_findings`].
//! - Stream decoding may fall back to full decode when window caps or budgets
//!   are exceeded; correctness is preserved at the cost of throughput.

// Internal compiled representation modules
mod decode_state;
mod hit_pool;
mod rule_repr;
mod work_items;

// Core engine and scratch modules
mod core;
mod scratch;

// Scanning implementation modules (Engine impl extensions)
mod buffer_scan;
mod stream_decode;
mod window_validate;

// Existing modules
mod helpers;
mod transform;
mod vectorscan_prefilter;

#[cfg(test)]
mod tests;

// Public re-exports
pub use core::Engine;
pub use scratch::ScanScratch;

#[cfg(feature = "stats")]
pub use core::{AnchorPlanStats, VectorscanStats};

#[cfg(feature = "bench")]
pub use core::{bench_find_spans_into, bench_stream_decode_base64, bench_stream_decode_url};
