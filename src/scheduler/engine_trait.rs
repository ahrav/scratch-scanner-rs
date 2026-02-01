//! Engine Trait Abstraction Layer
//!
//! # Purpose
//!
//! This module defines traits that abstract the detection engine interface,
//! allowing the scheduler to work with both the mock engine (for testing) and
//! the real production engine (for scanning).
//!
//! # Architecture
//!
//! The abstraction consists of three traits:
//!
//! - [`FindingRecord`]: A single finding from a scan (rule ID + byte offsets)
//! - [`EngineScratch`]: Per-worker scratch space for accumulating findings
//! - [`ScanEngine`]: The scanning engine itself (overlap, scan_chunk_into, etc.)
//!
//! # Type Differences
//!
//! The mock and real engines have slightly different finding representations:
//!
//! | Field | MockEngine | Real Engine |
//! |-------|------------|-------------|
//! | rule_id | `RuleId(u16)` | `u32` |
//! | span_start/end | `u64` | `u32` |
//! | file_id | — | `FileId` |
//! | step_id | — | `StepId` |
//!
//! The traits abstract these differences by exposing a common interface.
//!
//! # Implementations
//!
//! - **Mock engine**: [`engine_stub::MockEngine`](super::engine_stub::MockEngine) for testing
//! - **Real engine**: [`engine_impl`](super::engine_impl) bridges to [`crate::engine::Engine`]
//!
//! # Thread Safety Model
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                         ScanEngine (Sync)                          │
//! │                    (shared across all workers)                     │
//! └────────────────────────────────────────────────────────────────────┘
//!                    │                    │                    │
//!                    ▼                    ▼                    ▼
//!          ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
//!          │ EngineScratch   │  │ EngineScratch   │  │ EngineScratch   │
//!          │   (Worker 0)    │  │   (Worker 1)    │  │   (Worker N)    │
//!          │   thread-local  │  │   thread-local  │  │   thread-local  │
//!          └─────────────────┘  └─────────────────┘  └─────────────────┘
//! ```
//!
//! The engine is immutable and shared; scratch is per-worker and never shared.

use crate::api::FileId;

// ============================================================================
// FindingRecord Trait
// ============================================================================

/// A single finding record from a scan operation.
///
/// This trait abstracts the finding representation, allowing different engines
/// to use their own finding types while providing a common interface for
/// deduplication and output.
///
/// # Required Methods
///
/// - `rule_id`: The rule that matched (as u32 for compatibility)
/// - `root_hint_start/end`: Byte offsets in the original buffer for dedup
///
/// # Deduplication Semantics
///
/// Findings are deduplicated across chunk boundaries using `root_hint_start/end`:
/// - If a finding's `root_hint_end < new_bytes_start`, it belongs to the previous chunk
/// - The scheduler calls `EngineScratch::drop_prefix_findings()` to remove duplicates
///
/// # Performance
///
/// Implementations should be `Copy` or cheaply `Clone` for efficient
/// accumulation in per-worker buffers.
///
/// # Implementors
///
/// - [`engine_stub::FindingRec`](super::engine_stub::FindingRec) (mock)
/// - [`crate::api::FindingRec`] (real engine)
pub trait FindingRecord: Clone + Send + 'static {
    /// Rule index that produced this finding.
    fn rule_id(&self) -> u32;

    /// Root hint start offset (byte position in original buffer).
    ///
    /// Used for cross-chunk deduplication: findings with `root_hint_end`
    /// within the overlap prefix are dropped.
    fn root_hint_start(&self) -> u64;

    /// Root hint end offset (byte position in original buffer).
    fn root_hint_end(&self) -> u64;

    /// Full match span start offset (byte position in original buffer).
    ///
    /// Used for within-chunk deduplication: findings with the same root_hint
    /// but different spans are distinct (e.g., from transformed content).
    fn span_start(&self) -> u64;

    /// Full match span end offset (byte position in original buffer).
    fn span_end(&self) -> u64;
}

// ============================================================================
// EngineScratch Trait
// ============================================================================

/// Per-worker scratch space for accumulating scan findings.
///
/// This trait abstracts the scratch memory that each worker thread uses to
/// collect findings during scanning. The scratch is reused across chunks
/// to avoid allocation churn.
///
/// # Lifetime
///
/// Scratch is single-threaded (one per worker) and never shared across threads.
/// It must be cleared between scans to avoid stale findings.
///
/// # Typical Usage Pattern
///
/// ```text
/// for each file:
///     scratch.clear()
///     for each chunk:
///         engine.scan_chunk_into(data, file_id, base_offset, scratch)
///         scratch.drop_prefix_findings(new_bytes_start)  // dedup
///         scratch.drain_findings_into(&mut output)
/// ```
///
/// # Deduplication
///
/// The `drop_prefix_findings` method implements overlap-based deduplication:
/// findings whose `root_hint_end` is less than `new_bytes_start` are removed
/// because they will be (or were) found by the chunk that "owns" those bytes.
///
/// # Implementors
///
/// - [`engine_stub::ScanScratch`](super::engine_stub::ScanScratch) (mock)
/// - [`engine_impl::RealEngineScratch`](super::engine_impl::RealEngineScratch) (real)
pub trait EngineScratch: Send + 'static {
    /// The finding type produced by this scratch.
    type Finding: FindingRecord;

    /// Clear all accumulated findings, preparing for a new scan.
    fn clear(&mut self);

    /// Drop findings whose root_hint_end is fully within the overlap prefix.
    ///
    /// # Arguments
    ///
    /// - `new_bytes_start`: Absolute offset where "new" bytes begin (after overlap)
    fn drop_prefix_findings(&mut self, new_bytes_start: u64);

    /// Drain all findings into the provided vector.
    ///
    /// This transfers ownership without allocation (when possible).
    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>);
}

// ============================================================================
// ScanEngine Trait
// ============================================================================

/// A scanning engine that detects secrets in byte buffers.
///
/// This trait abstracts the core scanning functionality, allowing the scheduler
/// to work with both mock and real engines. The engine is immutable after
/// construction; all mutable scan state lives in the associated `Scratch` type.
///
/// # Thread Safety
///
/// The engine itself is `Send + Sync` and can be shared across workers.
/// Each worker gets its own `Scratch` instance.
///
/// # Overlap Semantics
///
/// The engine declares a `required_overlap()` in bytes. The scheduler guarantees
/// that consecutive chunks overlap by at least this many bytes to ensure no
/// findings are missed at chunk boundaries.
pub trait ScanEngine: Send + Sync + 'static {
    /// The scratch type used by this engine for per-worker state.
    type Scratch: EngineScratch;

    /// Required overlap in bytes for chunked scanning.
    ///
    /// The scheduler must ensure each chunk overlaps with the previous chunk
    /// by at least this many bytes to guarantee no findings are missed.
    fn required_overlap(&self) -> usize;

    /// Create per-worker scratch space.
    ///
    /// Called once per worker at startup. The scratch is reused across all
    /// chunks scanned by that worker.
    fn new_scratch(&self) -> Self::Scratch;

    /// Scan a chunk, appending findings to scratch.
    ///
    /// # Arguments
    ///
    /// - `data`: Buffer to scan
    /// - `file_id`: File being scanned (for attribution)
    /// - `base_offset`: Absolute byte offset of `data[0]` in the file
    /// - `scratch`: Per-worker scratch space
    ///
    /// # Overlap Handling
    ///
    /// Findings are reported with absolute offsets. The scheduler is responsible
    /// for calling `scratch.drop_prefix_findings()` to deduplicate across chunks.
    fn scan_chunk_into(
        &self,
        data: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut Self::Scratch,
    );

    /// Get rule name by rule ID.
    ///
    /// Used for output formatting. Returns `"<unknown-rule>"` for invalid IDs.
    fn rule_name(&self, rule_id: u32) -> &str;
}
