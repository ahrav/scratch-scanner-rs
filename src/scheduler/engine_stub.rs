//! Engine Interface Stubs
//!
//! # Purpose
//!
//! These types represent the detection engine's interface as seen by the scheduler.
//! The actual detection logic is a black box; these stubs define the contract.
//!
//! # Why Stubs?
//!
//! 1. **Decoupling**: Scheduler development proceeds independently of engine
//! 2. **Testing**: Deterministic mock behavior for scheduler correctness tests
//! 3. **Documentation**: Explicit contract between scheduler and engine
//!
//! # Contract Summary
//!
//! The engine declares:
//! - `required_overlap()`: Bytes of overlap needed for chunked scanning
//! - `scan_chunk_into()`: Scan a buffer, appending findings to scratch
//! - `new_scratch()`: Per-worker scratch factory
//! - `tuning`: Budget/limit parameters
//!
//! The scheduler guarantees:
//! - Chunks overlap by at least `required_overlap()` bytes
//! - Per-worker scratch is never shared across workers
//! - Findings are deduplicated per-chunk (within overlap window)

// ============================================================================
// Constants
// ============================================================================

/// Maximum buffer length for scanning.
///
/// This bounds the largest single allocation and ensures buffer pool memory is bounded.
/// 4 MiB is chosen to fit in L3 cache on modern CPUs while allowing large patterns.
pub const BUFFER_LEN_MAX: usize = 4 * 1024 * 1024;

/// Buffer alignment for I/O.
///
/// 4096 = page alignment, required for:
/// - O_DIRECT reads
/// - io_uring registered buffers
/// - Memory-mapped I/O
///
/// Standard buffered I/O doesn't require this but doesn't hurt.
pub const BUFFER_ALIGN: usize = 4096;

// ============================================================================
// Identifiers
// ============================================================================

/// Run-scoped file identifier.
///
/// Monotonically assigned during discovery. Used instead of paths in hot paths
/// to avoid string comparisons and to enable redaction in logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub u32);

/// Rule identifier (index into engine's rule table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub u16);

// ============================================================================
// Finding Record
// ============================================================================

/// A single finding from the detection engine.
///
/// # Field Semantics
///
/// - `rule_id`: Which rule matched
/// - `root_hint_start/end`: Byte offsets in the *original* (pre-transform) buffer
///   where the match "root" (anchor) was found. Used for deduplication.
/// - `span_start/end`: Full match span (may extend beyond root hint)
///
/// # Deduplication Key
///
/// For overlap-based dedupe, the key is:
/// `(rule_id, root_hint_start, root_hint_end, span_start, span_end)`
///
/// `StepId` (transform chain) is intentionally excluded from the dedup key
/// because the same match found via different transform paths is still one finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingRec {
    pub rule_id: RuleId,
    /// Root hint start offset in original buffer.
    pub root_hint_start: u64,
    /// Root hint end offset in original buffer.
    pub root_hint_end: u64,
    /// Full match span start.
    pub span_start: u64,
    /// Full match span end.
    pub span_end: u64,
}

// ============================================================================
// Tuning Parameters
// ============================================================================

/// Engine tuning parameters that affect scheduler behavior.
///
/// These are declared by the engine and used by the scheduler for:
/// - Bounded data structure sizing
/// - Backpressure decisions
/// - Deduplication window sizing
#[derive(Clone, Debug)]
pub struct EngineTuning {
    /// Maximum findings expected per chunk scan.
    ///
    /// Used to bound per-worker `pending` vectors for dedupe.
    /// If exceeded, findings may be dropped or scan may fail.
    pub max_findings_per_chunk: usize,

    /// Maximum rules in the engine.
    ///
    /// Used to size rule-indexed data structures.
    pub max_rules: usize,
}

impl Default for EngineTuning {
    fn default() -> Self {
        Self {
            max_findings_per_chunk: 4096,
            max_rules: 1024,
        }
    }
}

// ============================================================================
// Scan Scratch (per-worker)
// ============================================================================

/// Per-worker scratch space for scanning.
///
/// The engine allocates internal buffers here; the scheduler treats it as opaque.
/// After each `scan_chunk_into()`, call `drain_findings_into()` to extract results.
///
/// # Ownership
///
/// - One scratch per worker thread
/// - Never shared across workers (no sync needed)
/// - Reused across chunks scanned by the same worker
pub struct ScanScratch {
    /// Findings accumulated during the current scan.
    findings: Vec<FindingRec>,

    /// Internal scratch for the mock engine (would be pattern state in real engine).
    #[allow(dead_code)]
    internal: Vec<u8>,
}

impl ScanScratch {
    /// Create new scratch with given capacity hint.
    pub fn new(findings_cap: usize) -> Self {
        Self {
            findings: Vec::with_capacity(findings_cap),
            internal: Vec::new(),
        }
    }

    /// Clear scratch for reuse.
    pub fn clear(&mut self) {
        self.findings.clear();
    }

    /// Drop findings whose root_hint_end is fully within the overlap prefix.
    ///
    /// Called after scanning a chunk to remove findings that will be re-found
    /// in the next chunk (since they're in the overlap region).
    ///
    /// # Arguments
    ///
    /// - `new_bytes_start`: Absolute offset where "new" bytes begin (after overlap)
    pub fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.findings.retain(|f| f.root_hint_end >= new_bytes_start);
    }

    /// Drain all findings into the provided vector.
    ///
    /// This transfers ownership without allocation (just pointer swap).
    pub fn drain_findings_into(&mut self, out: &mut Vec<FindingRec>) {
        out.append(&mut self.findings);
    }

    /// Add a finding (used by engine during scan).
    pub(crate) fn push_finding(&mut self, rec: FindingRec) {
        self.findings.push(rec);
    }
}

// ============================================================================
// Rule Specification (for mock engine)
// ============================================================================

/// Simplified rule specification for the mock engine.
///
/// Real engine has much more complex rule specs (anchors, validators, transforms).
/// This is sufficient to test scheduler correctness.
#[derive(Clone)]
pub struct MockRule {
    /// Rule name for output.
    pub name: String,
    /// Pattern to search for (simple substring match).
    pub pattern: Vec<u8>,
}

// ============================================================================
// Mock Engine
// ============================================================================

/// Mock detection engine for scheduler testing.
///
/// # Behavior
///
/// - Performs simple substring search for each rule's pattern
/// - Reports findings with correct byte offsets
/// - Respects overlap semantics (same as real engine contract)
///
/// # Limitations
///
/// - No regex, no anchors, no validators, no transforms
/// - Single-byte patterns may cause many findings (use longer patterns)
pub struct MockEngine {
    rules: Vec<MockRule>,
    /// Required overlap in bytes.
    overlap: usize,
    /// Tuning parameters.
    pub tuning: EngineTuning,
}

impl MockEngine {
    /// Create a mock engine with the given rules and overlap requirement.
    pub fn new(rules: Vec<MockRule>, overlap: usize) -> Self {
        Self {
            rules,
            overlap,
            tuning: EngineTuning::default(),
        }
    }

    /// Create a mock engine with custom tuning.
    pub fn with_tuning(rules: Vec<MockRule>, overlap: usize, tuning: EngineTuning) -> Self {
        Self {
            rules,
            overlap,
            tuning,
        }
    }

    /// Required overlap in bytes for chunked scanning.
    ///
    /// The scheduler must ensure each chunk overlaps with the previous chunk
    /// by at least this many bytes to guarantee no findings are missed.
    pub fn required_overlap(&self) -> usize {
        self.overlap
    }

    /// Create per-worker scratch space.
    pub fn new_scratch(&self) -> ScanScratch {
        ScanScratch::new(self.tuning.max_findings_per_chunk)
    }

    /// Get rule name by ID.
    ///
    /// # Panics
    ///
    /// Panics if rule_id is out of bounds.
    pub fn rule_name(&self, rule_id: RuleId) -> &str {
        &self.rules[rule_id.0 as usize].name
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

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
    pub fn scan_chunk_into(
        &self,
        data: &[u8],
        _file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        scratch.clear();

        // Simple substring search for each rule
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            let pattern = &rule.pattern;
            if pattern.is_empty() {
                continue;
            }

            // Naive search (real engine uses Aho-Corasick)
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if &data[pos..pos + pattern.len()] == pattern.as_slice() {
                    let abs_start = base_offset + pos as u64;
                    let abs_end = abs_start + pattern.len() as u64;

                    scratch.push_finding(FindingRec {
                        rule_id: RuleId(rule_idx as u16),
                        root_hint_start: abs_start,
                        root_hint_end: abs_end,
                        span_start: abs_start,
                        span_end: abs_end,
                    });

                    // Skip past this match
                    pos += pattern.len();
                } else {
                    pos += 1;
                }
            }
        }
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use crate::api::FileId as ApiFileId;

impl FindingRecord for FindingRec {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.rule_id.0 as u32
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
        self.span_start
    }

    #[inline]
    fn span_end(&self) -> u64 {
        self.span_end
    }
}

impl EngineScratch for ScanScratch {
    type Finding = FindingRec;

    fn clear(&mut self) {
        self.clear();
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.drop_prefix_findings(new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        self.drain_findings_into(out);
    }
}

impl ScanEngine for MockEngine {
    type Scratch = ScanScratch;

    fn required_overlap(&self) -> usize {
        self.required_overlap()
    }

    fn new_scratch(&self) -> Self::Scratch {
        self.new_scratch()
    }

    fn scan_chunk_into(
        &self,
        data: &[u8],
        file_id: ApiFileId,
        base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        // Convert api::FileId to engine_stub::FileId
        self.scan_chunk_into(data, FileId(file_id.0), base_offset, scratch);
    }

    fn rule_name(&self, rule_id: u32) -> &str {
        self.rule_name(RuleId(rule_id as u16))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_engine() -> MockEngine {
        MockEngine::new(
            vec![
                MockRule {
                    name: "secret".into(),
                    pattern: b"SECRET".to_vec(),
                },
                MockRule {
                    name: "password".into(),
                    pattern: b"PASSWORD".to_vec(),
                },
            ],
            16, // 16 byte overlap
        )
    }

    #[test]
    fn mock_engine_finds_pattern() {
        let engine = simple_engine();
        let mut scratch = engine.new_scratch();

        let data = b"hello SECRET world";
        engine.scan_chunk_into(data, FileId(0), 0, &mut scratch);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId(0));
        assert_eq!(findings[0].root_hint_start, 6);
        assert_eq!(findings[0].root_hint_end, 12); // "SECRET".len() = 6
    }

    #[test]
    fn mock_engine_multiple_matches() {
        let engine = simple_engine();
        let mut scratch = engine.new_scratch();

        let data = b"SECRET foo SECRET";
        engine.scan_chunk_into(data, FileId(0), 100, &mut scratch);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        assert_eq!(findings.len(), 2);
        // First at offset 100
        assert_eq!(findings[0].root_hint_start, 100);
        // Second at offset 100 + 11 = 111
        assert_eq!(findings[1].root_hint_start, 111);
    }

    #[test]
    fn mock_engine_multiple_rules() {
        let engine = simple_engine();
        let mut scratch = engine.new_scratch();

        let data = b"SECRET and PASSWORD";
        engine.scan_chunk_into(data, FileId(0), 0, &mut scratch);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        assert_eq!(findings.len(), 2);
        // Rule 0 = "secret", Rule 1 = "password"
        assert!(findings.iter().any(|f| f.rule_id == RuleId(0)));
        assert!(findings.iter().any(|f| f.rule_id == RuleId(1)));
    }

    #[test]
    fn drop_prefix_findings_filters_correctly() {
        let engine = simple_engine();
        let mut scratch = engine.new_scratch();

        // Finding at offset 5 (ends at 11)
        // Finding at offset 20 (ends at 26)
        let data = b"xxxxxSECRET---------SECRET---";
        engine.scan_chunk_into(data, FileId(0), 0, &mut scratch);

        // If new bytes start at offset 15, finding ending at 11 is in prefix
        scratch.drop_prefix_findings(15);

        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);

        // Only the second finding (ending at 26) should remain
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].root_hint_start, 20);
    }

    #[test]
    fn scratch_reuse() {
        let engine = simple_engine();
        let mut scratch = engine.new_scratch();

        // First scan
        engine.scan_chunk_into(b"SECRET", FileId(0), 0, &mut scratch);
        let mut findings = Vec::new();
        scratch.drain_findings_into(&mut findings);
        assert_eq!(findings.len(), 1);

        // Second scan - scratch should be clean
        engine.scan_chunk_into(b"no match here", FileId(0), 100, &mut scratch);
        findings.clear();
        scratch.drain_findings_into(&mut findings);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn required_overlap() {
        let engine = simple_engine();
        assert_eq!(engine.required_overlap(), 16);
    }

    #[test]
    fn rule_name_lookup() {
        let engine = simple_engine();
        assert_eq!(engine.rule_name(RuleId(0)), "secret");
        assert_eq!(engine.rule_name(RuleId(1)), "password");
    }

    #[test]
    fn constants_are_sane() {
        const {
            assert!(
                BUFFER_LEN_MAX >= 64 * 1024,
                "buffer too small for practical use"
            )
        };
        assert!(
            BUFFER_ALIGN.is_power_of_two(),
            "alignment must be power of 2"
        );
        const { assert!(BUFFER_ALIGN >= 512, "alignment too small for O_DIRECT") };
    }
}
