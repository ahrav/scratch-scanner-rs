//! Work queue types for transform/scan traversal.
//!
//! Contains buffer references, pending decode spans, pending windows, and work
//! item enums used for breadth-first traversal during scanning. Range values
//! are half-open `[lo, hi)` in their respective address spaces and are only
//! valid for the current scan (decode slab resets invalidate slab ranges).
//!
//! `PendingWindow` ordering is intentionally reversed so a max-heap behaves as
//! a min-heap keyed by earliest window end.
//!
//! # Lifetime model
//! - `Slab` ranges are only valid until the decode slab is reset/truncated.
//! - Root ranges are tied to the current input buffer.

use crate::api::{StepId, STEP_ROOT};
use std::ops::Range;

use super::rule_repr::Variant;
use super::transform::{Base64SpanStream, UrlSpanStream};

/// Reference to a buffer being scanned.
///
/// `Root` points to the input chunk. `Slab(range)` points into `DecodeSlab`.
/// Slab ranges are only valid until the slab is reset or truncated.
///
/// # Invariants
/// - `Slab` ranges must stay within the decode slab for the current scan.
/// - Ranges are half-open `[lo, hi)` in slab address space.
#[derive(Default, Clone)]
pub(super) enum BufRef {
    #[default]
    Root,
    Slab(Range<usize>),
}

/// Reference to an encoded span to decode.
///
/// The range is relative to the source buffer referenced by the variant.
///
/// # Invariants
/// - Ranges are validated against the source buffer before decoding.
/// - Ranges are half-open `[lo, hi)` in the source buffer.
#[derive(Clone)]
pub(super) enum EncRef {
    Root(Range<usize>),
    Slab(Range<usize>),
}

/// Pending decode span captured during streaming decode.
///
/// These spans are produced incrementally from streaming transforms and later
/// enqueued as decode work. `root_hint` stores the originating root span to
/// preserve provenance when emitting findings.
///
/// # Invariants
/// - `range` indexes into the decode slab for the current scan.
/// - `depth` is bounded by the transform depth limit.
#[derive(Clone)]
pub(super) struct PendingDecodeSpan {
    pub(super) transform_idx: usize,
    pub(super) range: Range<usize>,
    pub(super) step_id: StepId,
    pub(super) root_hint: Option<Range<usize>>,
    pub(super) depth: usize,
}

/// Pending decoded-space window produced by stream scanning.
///
/// Offsets are in decoded-byte space (relative to the stream) and are
/// half-open: `[lo, hi)`.
///
/// # Fields
/// - `anchor_hint`: Vectorscan's `from` match offset in decoded-byte space.
///   Used to start regex searches near the anchor instead of at window start.
///
/// # Ordering
/// - Ordered by earliest `hi`, then `lo`, then `(rule_id, variant)` so priority
///   queues drain windows as soon as their end offset is reached.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct PendingWindow {
    pub(super) hi: u64,
    pub(super) lo: u64,
    pub(super) rule_id: u32,
    pub(super) variant: Variant,
    /// Anchor hint from Vectorscan's `from` offset.
    pub(super) anchor_hint: u64,
}

impl Ord for PendingWindow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .hi
            .cmp(&self.hi)
            .then_with(|| other.lo.cmp(&self.lo))
            .then_with(|| other.rule_id.cmp(&self.rule_id))
            .then_with(|| (other.variant.idx()).cmp(&self.variant.idx()))
    }
}

impl PartialOrd for PendingWindow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Streaming span detector state for nested transforms.
///
/// Each variant tracks incremental parsing state so we can emit spans while
/// decoding without rescanning the full buffer.
pub(super) enum SpanStreamState {
    Url(UrlSpanStream),
    Base64(Base64SpanStream),
}

/// Per-transform span stream bookkeeping during decoded scanning.
///
/// Tracks per-buffer span caps and transform modes alongside the stream state.
///
/// # Invariants
/// - `spans_emitted <= max_spans` for the current buffer.
pub(super) struct SpanStreamEntry {
    pub(super) transform_idx: usize,
    pub(super) state: SpanStreamState,
    pub(super) spans_emitted: usize, // Spans emitted so far for this buffer.
    pub(super) max_spans: usize,     // Per-buffer cap for this transform.
}

/// Work item in the transform/scan queue.
///
/// Carries the decode provenance (StepId) and a root-span hint for reporting.
/// Depth enforces the transform recursion limit and keeps traversal iterative.
///
/// # Invariants
/// - `depth` is bounded by the configured transform depth limit.
/// - `root_hint` is `None` for the root buffer and `Some` for derived buffers.
/// - `enc_ref` is only populated when the scan originates from a decoded span.
pub(super) enum WorkItem {
    ScanBuf {
        buf: BufRef,
        step_id: StepId,
        root_hint: Option<Range<usize>>, // None for root buffer; Some for derived buffers
        transform_idx: Option<usize>,
        enc_ref: Option<EncRef>,
        depth: usize,
    },
    DecodeSpan {
        transform_idx: usize,
        enc_ref: EncRef,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
    },
}

impl Default for WorkItem {
    fn default() -> Self {
        WorkItem::ScanBuf {
            buf: BufRef::Root,
            step_id: STEP_ROOT,
            root_hint: None,
            transform_idx: None,
            enc_ref: None,
            depth: 0,
        }
    }
}
