//! Tiger-style deterministic simulation harness for chunked scanning.
//!
//! Purpose:
//! - Treat chunking as input nondeterminism and assert invariants like
//!   "chunking must not lose findings" under a correctness-oriented config.
//!
//! Invariants mirrored from runtime:
//! - Each chunk buffer is `overlap_prefix + payload`.
//! - The prefix is the last `Engine::required_overlap()` bytes of the previous
//!   chunk buffer (shorter for the first few chunks).
//! - `base_offset` equals `payload_offset - prefix_len`.
//! - After each scan, `ScanScratch::drop_prefix_findings(payload_offset)` is
//!   called to remove duplicate findings fully contained in the overlap prefix.
//!
//! High-level flow:
//! 1. Build a correctness-oriented engine.
//! 2. Compute an oracle by scanning the full buffer as a single chunk.
//! 3. Scan the same buffer under multiple deterministic chunk plans.
//! 4. Assert coverage: every oracle finding is covered by some chunked finding
//!    with the same rule id and a root-span that contains the oracle root-span.
//!
//! Design choices:
//! - Coverage uses root-span containment rather than strict equality to tolerate
//!   benign differences in span rooting across chunk boundaries.
//! - Chunk plans are deterministic to keep failures reproducible from seeds.

use crate::{Engine, FileId, FindingRec, TransformMode};

/// Build an engine configuration suitable for correctness properties.
///
/// Guarantees:
/// - Uses the demo rules and transforms.
/// - Raises caps that could otherwise drop work on a per-buffer basis.
///
/// Rationale:
/// The harness is intended to test semantic invariants of chunking, not to
/// exercise DoS budgets or per-buffer caps that could legitimately diverge
/// between chunked and single-buffer scans.
pub(crate) fn correctness_engine() -> Engine {
    let rules = crate::demo::demo_rules();

    let mut transforms = crate::demo::demo_transforms();
    for tc in &mut transforms {
        // Avoid chunk-dependent transform semantics.
        tc.mode = TransformMode::Always;

        // Make span/decoder caps effectively "large enough" for tests.
        tc.max_spans_per_buffer = tc.max_spans_per_buffer.max(1024);
        tc.max_encoded_len = tc.max_encoded_len.max(256 * 1024);
        tc.max_decoded_bytes = tc.max_decoded_bytes.max(256 * 1024);

        // Keep gating as-is by default; gates should only skip work, not findings.
    }

    let mut tuning = crate::demo::demo_tuning();
    tuning.max_findings_per_chunk = tuning.max_findings_per_chunk.max(65_535);
    tuning.max_work_items = tuning.max_work_items.max(2048);
    tuning.max_total_decode_output_bytes =
        tuning.max_total_decode_output_bytes.max(4 * 1024 * 1024);

    Engine::new(rules, transforms, tuning)
}

/// A deterministic plan for how to segment an input stream into chunks.
#[derive(Clone, Debug)]
pub(crate) enum ChunkPattern {
    /// Fixed chunk length (except the last chunk, which is clamped to remaining bytes).
    Fixed(usize),

    /// Alternate between two sizes: a, b, a, b, ...
    Alternating { a: usize, b: usize },

    /// Deterministic pseudo-random chunk lengths in [min, max].
    RandomRange { min: usize, max: usize },

    /// Cycle through an explicit list of sizes.
    Sequence(Vec<usize>),
}

/// A chunking plan with an optional first-chunk override to shift alignment.
#[derive(Clone, Debug)]
pub(crate) struct ChunkPlan {
    pub(crate) pattern: ChunkPattern,
    pub(crate) seed: u64,
    pub(crate) first_chunk_len: Option<usize>,
}

impl ChunkPlan {
    pub(crate) fn fixed(size: usize) -> Self {
        Self {
            pattern: ChunkPattern::Fixed(size),
            seed: 0,
            first_chunk_len: None,
        }
    }

    pub(crate) fn fixed_shifted(size: usize, first_chunk_len: usize) -> Self {
        Self {
            pattern: ChunkPattern::Fixed(size),
            seed: 0,
            first_chunk_len: Some(first_chunk_len),
        }
    }

    pub(crate) fn alternating(a: usize, b: usize) -> Self {
        Self {
            pattern: ChunkPattern::Alternating { a, b },
            seed: 0,
            first_chunk_len: None,
        }
    }

    pub(crate) fn random_range(seed: u64, min: usize, max: usize) -> Self {
        Self {
            pattern: ChunkPattern::RandomRange { min, max },
            seed: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
            first_chunk_len: None,
        }
    }

    pub(crate) fn with_first_chunk(mut self, first_chunk_len: usize) -> Self {
        self.first_chunk_len = Some(first_chunk_len);
        self
    }

    fn next_len(&mut self, step: usize, remaining: usize) -> usize {
        let want = if step == 0 {
            self.first_chunk_len
                .unwrap_or_else(|| self.pattern_len(step))
        } else {
            self.pattern_len(step)
        };

        clamp_chunk_len(want, remaining)
    }

    fn pattern_len(&mut self, step: usize) -> usize {
        match &self.pattern {
            ChunkPattern::Fixed(n) => *n,
            ChunkPattern::Alternating { a, b } => {
                if step.is_multiple_of(2) {
                    *a
                } else {
                    *b
                }
            }
            ChunkPattern::RandomRange { min, max } => {
                let min = (*min).max(1);
                let max = (*max).max(min);
                let span = (max - min) + 1;

                let r = xorshift64(&mut self.seed);
                min + (r as usize % span)
            }
            ChunkPattern::Sequence(seq) => {
                if seq.is_empty() {
                    1
                } else {
                    seq[step % seq.len()].max(1)
                }
            }
        }
    }
}

/// Scan a buffer as a single chunk (the oracle runner).
///
/// Guarantees:
/// - Findings are drained after `drop_prefix_findings(0)` so output matches
///   the per-chunk semantics used by the runtime pipeline.
pub(crate) fn scan_one_chunk_records(engine: &Engine, buf: &[u8]) -> Vec<FindingRec> {
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(buf, FileId(0), 0, &mut scratch);

    // Payload starts at 0 in the file.
    scratch.drop_prefix_findings(0);

    let mut out = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
    scratch.drain_findings_into(&mut out);
    out
}

/// Scan a buffer using a deterministic chunk plan, matching runtime semantics.
///
/// Invariants:
/// - Each chunk buffer is `prefix + payload` where prefix length is <= overlap.
/// - `base_offset` is the file offset of the chunk buffer start.
/// - `drop_prefix_findings(payload_offset)` is applied after each scan.
pub(crate) fn scan_chunked_records(
    engine: &Engine,
    buf: &[u8],
    mut plan: ChunkPlan,
) -> Vec<FindingRec> {
    let overlap = engine.required_overlap();

    let mut scratch = engine.new_scratch();
    let mut out: Vec<FindingRec> = Vec::new();
    let mut batch = Vec::with_capacity(engine.tuning.max_findings_per_chunk);

    // Tail buffer holds the last `overlap` bytes from the previous chunk buffer.
    let mut tail = vec![0u8; overlap];
    let mut tail_len = 0usize;

    let mut offset = 0usize;
    let mut step = 0usize;

    while offset < buf.len() {
        let remaining = buf.len() - offset;
        let payload_len = plan.next_len(step, remaining);

        let payload = &buf[offset..offset + payload_len];

        // chunk = prefix(tail[..tail_len]) + payload
        let mut chunk = Vec::with_capacity(tail_len + payload.len());
        chunk.extend_from_slice(&tail[..tail_len]);
        chunk.extend_from_slice(payload);

        debug_assert!(
            tail_len <= offset,
            "prefix length cannot exceed payload offset"
        );
        let base_offset = (offset - tail_len) as u64;

        engine.scan_chunk_into(&chunk, FileId(0), base_offset, &mut scratch);

        // Drop duplicates that are entirely in the prefix (new bytes start at `offset`).
        scratch.drop_prefix_findings(offset as u64);

        scratch.drain_findings_into(&mut batch);
        out.append(&mut batch);

        // Update tail: keep last `overlap` bytes of this chunk buffer.
        let total_len = chunk.len();
        let keep = overlap.min(total_len);
        if keep > 0 {
            tail[..keep].copy_from_slice(&chunk[total_len - keep..]);
        }
        tail_len = keep;

        offset += payload_len;
        step += 1;
    }

    out
}

/// Coverage check: every oracle finding must be covered by a chunked finding.
///
/// Coverage rule:
/// - Same rule id.
/// - Root-span containment:
///   `chunked.root_hint_start <= oracle.root_hint_start` and
///   `chunked.root_hint_end   >= oracle.root_hint_end`.
///
/// Errors:
/// - Returns a message describing the first missing oracle finding.
pub(crate) fn check_oracle_covered(
    engine: &Engine,
    oracle: &[FindingRec],
    chunked: &[FindingRec],
) -> Result<(), String> {
    for o in oracle {
        let ok = chunked.iter().any(|s| {
            s.rule_id == o.rule_id
                && s.root_hint_start <= o.root_hint_start
                && s.root_hint_end >= o.root_hint_end
        });

        if !ok {
            return Err(format!(
                "missing coverage for rule={} (id={}) oracle[root_hint={}..{} span={}..{}]",
                engine.rule_name(o.rule_id),
                o.rule_id,
                o.root_hint_start,
                o.root_hint_end,
                o.span_start,
                o.span_end,
            ));
        }
    }

    Ok(())
}

// ---- deterministic RNG helpers ----

fn clamp_chunk_len(want: usize, remaining: usize) -> usize {
    if remaining == 0 {
        0
    } else if want == 0 {
        1.min(remaining)
    } else {
        want.min(remaining)
    }
}

fn xorshift64(state: &mut u64) -> u64 {
    // Xorshift64 style update (good enough for deterministic testing).
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}
