//! Decode provenance and output storage.
//!
//! This module contains data structures for tracking the decode step chain
//! (provenance) and storing decoded output bytes during transform scanning.

use crate::api::{DecodeStep, StepId, STEP_ROOT};
use crate::scratch_memory::ScratchVec;
use std::ops::{ControlFlow, Range};

use super::transform::stream_decode;
use crate::api::TransformConfig;

/// Node in the decode-step arena, linking to its parent step.
///
/// Each node records a single decode operation and a back-pointer to its
/// parent step. `StepId` values are indices into `StepArena::nodes` with
/// `STEP_ROOT` acting as the synthetic root.
pub(super) struct StepNode {
    pub(super) parent: StepId,
    pub(super) step: DecodeStep,
}

/// Arena for decode steps so findings store compact `StepId` references.
///
/// Why an arena?
/// - Decoding is recursive; each derived buffer adds provenance.
/// - Storing full `Vec<DecodeStep>` per finding would allocate and clone heavily.
/// - A parent-linked arena lets us store provenance once and share it across
///   findings, with O(length) reconstruction only when materializing output.
///
/// This is append-only and reset between scans. `StepId` values are only valid
/// while this arena is alive and not reset.
///
/// # Performance
/// - `push` is O(1); `materialize` is O(depth) for a single finding.
pub(super) struct StepArena {
    /// Parent-linked decode step nodes.
    ///
    /// Each node records a single decode operation (transform ID, span) and
    /// points to its parent step. This compact representation enables sharing
    /// provenance across multiple findings from the same decoded buffer.
    pub(super) nodes: ScratchVec<StepNode>,
}

impl StepArena {
    pub(super) fn reset(&mut self) {
        self.nodes.clear();
    }

    /// Adds a decode step and returns its arena `StepId`.
    ///
    /// # Preconditions
    /// - `parent` is either `STEP_ROOT` or a `StepId` previously returned by
    ///   this arena and still alive (i.e. before `reset`).
    pub(super) fn push(&mut self, parent: StepId, step: DecodeStep) -> StepId {
        let id = StepId(self.nodes.len() as u32);
        self.nodes.push(StepNode { parent, step });
        id
    }

    /// Reconstructs the step chain from root to leaf.
    ///
    /// The arena stores steps in leaf-to-root order via parent pointers.
    /// This function collects them and reverses in place to produce a
    /// root-to-leaf sequence suitable for reporting.
    pub(super) fn materialize(&self, mut id: StepId, out: &mut ScratchVec<DecodeStep>) {
        out.clear();
        while id != STEP_ROOT {
            let cur = id;
            let node = &self.nodes[cur.0 as usize];
            out.push(node.step.clone());
            id = node.parent;
        }
        // Reverse in place
        let len = out.len();
        for i in 0..len / 2 {
            out.as_mut_slice().swap(i, len - 1 - i);
        }
    }
}

/// Contiguous decoded-byte slab for derived buffers.
///
/// This is a monotonic append-only buffer:
/// - Decoders append into the slab and receive a `Range<usize>` back.
/// - Work items carry those ranges instead of owning new allocations.
/// - The slab never reallocates (capacity == global decode budget), so the
///   returned ranges remain valid for the lifetime of a scan.
///
/// The slab is cleared between scans, which invalidates all ranges at once.
///
/// # Invariants
/// - Append operations must not exceed `limit`; on overflow, callers roll back.
/// - Ranges returned from `append_stream_decode` are valid only until reset or
///   explicit truncation.
///
/// # Performance
/// - Avoids per-span allocations by reusing a single contiguous buffer.
pub(super) struct DecodeSlab {
    pub(super) buf: Vec<u8>,
    pub(super) limit: usize,
}

impl DecodeSlab {
    pub(super) fn with_limit(limit: usize) -> Self {
        let buf = Vec::with_capacity(limit);
        Self { buf, limit }
    }

    pub(super) fn reset(&mut self) {
        self.buf.clear();
    }

    pub(super) fn slice(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    /// Append decoded bytes into the slab while enforcing per-transform and
    /// global decode budgets.
    ///
    /// On decode error, truncation, or zero output, both the slab and
    /// `ctx_total_decode_output_bytes` are rolled back to their pre-call values
    /// and `Err(())` is returned. On success, the returned range points at the
    /// newly appended bytes.
    ///
    /// # Budgets
    /// - `max_out` is the per-transform output budget.
    /// - `global_limit` is the scan-level output budget.
    /// - `limit` is the slab capacity and is checked in addition to the other
    ///   budgets.
    pub(super) fn append_stream_decode(
        &mut self,
        tc: &TransformConfig,
        input: &[u8],
        max_out: usize,
        ctx_total_decode_output_bytes: &mut usize,
        global_limit: usize,
    ) -> Result<Range<usize>, ()> {
        let start_len = self.buf.len();
        let start_ctx = *ctx_total_decode_output_bytes;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, input, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if ctx_total_decode_output_bytes.saturating_add(chunk.len()) > global_limit {
                truncated = true;
                return ControlFlow::Break(());
            }
            if self.buf.len().saturating_add(chunk.len()) > self.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            self.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            *ctx_total_decode_output_bytes =
                ctx_total_decode_output_bytes.saturating_add(chunk.len());

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            self.buf.truncate(start_len);
            *ctx_total_decode_output_bytes = start_ctx;
            return Err(());
        }

        Ok(start_len..(start_len + local_out))
    }
}
