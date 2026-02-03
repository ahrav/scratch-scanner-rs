//! Public API data types for configuring the scanner and reporting results.
//!
//! Purpose: provide the shared configuration and result structs used by the
//! engine and its callers. These types are intentionally behavior-free; the
//! engine performs validation and enforcement when it is built.
//!
//! # Invariants
//! - `FileId` and `StepId` are opaque indices; they are only valid for the table/arena
//!   that created them.
//! - `DecodeSteps` is bounded by `MAX_DECODE_STEPS`, which must cover the root step plus
//!   the maximum transform depth.
//! - `RuleSpec`, `TransformConfig`, and `Tuning` are validated at engine build time;
//!   invalid combinations panic during construction.
//! - Hot-path offsets are stored as `u32`; callers must chunk inputs so any
//!   single buffer fits in `u32::MAX` bytes.
//!
//! # Algorithm
//! 1. Findings are accumulated as compact `FindingRec` values on the hot path.
//! 2. `FindingRec` is later materialized into `Finding` by expanding the decode-step chain.
//! 3. Optional transform decoding is bounded by per-rule and global budgets.
//!
//! # Design Notes
//! - Types here are intentionally lightweight and `Copy` where possible to keep scans
//!   allocation-free on the hot path.
//! - Some budget caps are hard limits and can drop work when exceeded; tune for your
//!   desired balance of throughput and completeness.

use crate::stdx::FixedVec;
use regex::bytes::Regex;
use std::ops::Range;

/// Opaque file identifier used to index into [`FileTable`].
///
/// This is not a filesystem path; callers must look up metadata in the
/// owning `FileTable`.
///
/// # Construction
/// Create via [`FileTable::insert`] or similar registration methods.
/// Direct construction with `FileId(n)` is valid but callers must ensure
/// the index corresponds to an entry in the associated `FileTable`.
///
/// # Invariants
/// - Only valid for the `FileTable` that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId(pub u32);

/// Compact index into the decode-step arena.
///
/// Steps are chained from the root buffer to derived buffers so findings can be
/// reconstructed without cloning vectors on the hot path.
///
/// # Invariants
/// - Only valid while the originating decode-step arena is alive and not reset.
/// - `STEP_ROOT` is the sentinel root for an empty provenance chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StepId(pub(crate) u32);

/// Hard cap on decode-step chains stored per finding.
///
/// Must be at least `Tuning::max_transform_depth + 1` (root + transforms);
/// enforced at engine build time. Raising this increases per-finding storage.
pub const MAX_DECODE_STEPS: usize = 8;

/// Sentinel step id that marks the root of a provenance chain.
pub(crate) const STEP_ROOT: StepId = StepId(u32::MAX);

impl Default for StepId {
    fn default() -> Self {
        STEP_ROOT
    }
}

/// Identifies a supported transform used for derived-buffer scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransformId {
    /// URL percent decoding (optionally treating `+` as space).
    UrlPercent,
    /// Base64 decoding (with optional whitespace allowances).
    Base64,
}

/// Controls when a transform is applied during scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformMode {
    /// Never apply this transform.
    Disabled,
    /// Always apply this transform, subject to span and budget caps.
    Always,

    /// Correctness trade (explicit).
    /// Skips this transform if the *current buffer* already produced any findings.
    ///
    /// Scope: This only considers findings from the current buffer being scanned;
    /// findings from parent buffers (that produced this one) or child buffers
    /// (derived via earlier transforms) are not considered. Each buffer tracks
    /// its own "has findings" flag independently.
    ///
    /// This can miss findings that only appear in nested encodings (e.g., base64
    /// inside URL-encoded content).
    IfNoFindingsInThisBuffer,
}

/// Gate policy for expensive transform decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No gate; decode all candidate spans (subject to caps).
    None,

    /// Stream-decode and proceed only if decoded bytes contain any anchor variant
    /// (raw + UTF-16LE/BE variants).
    ///
    /// This is only sound when anchors are required for a rule (the default),
    /// because the gate ignores non-anchor-only matches. False negatives are
    /// possible when anchors are optional (e.g., rules with `|` alternation where
    /// some branches have no anchor). Use `Gate::None` for such rules if
    /// completeness is critical.
    AnchorsInDecoded,
}

/// Configuration for a single transform stage.
///
/// Lengths are in bytes of the encoded input unless otherwise noted.
///
/// # Invariants
/// - `max_encoded_len >= min_len`.
/// - When `mode` is not `Disabled`, `max_spans_per_buffer` and `max_decoded_bytes` are > 0.
///
/// # Performance
/// - Span detection and decoding are capped per buffer to keep worst-case work bounded.
/// - `gate` can skip costly decodes when anchors are absent in decoded output.
#[derive(Clone, Debug)]
pub struct TransformConfig {
    /// Transform kind.
    pub id: TransformId,

    /// When this transform is applied.
    pub mode: TransformMode,

    /// Gate policy (if enabled).
    ///
    /// When set to `AnchorsInDecoded`, the engine scans decoded bytes for any
    /// anchor variant and discards the decoded buffer if none are found. For
    /// Base64, an extra encoded-space prefilter may skip decoding before this
    /// gate runs.
    pub gate: Gate,

    /// Minimum encoded length to consider for span detection.
    pub min_len: usize,
    /// Limit of candidate spans to process per buffer.
    pub max_spans_per_buffer: usize,
    /// Maximum encoded length to consider for a span.
    pub max_encoded_len: usize,

    /// Maximum decoded bytes produced per span.
    /// Decodes exceeding this cap are aborted for that span.
    pub max_decoded_bytes: usize,

    /// URL option: treat '+' as space. Ignored unless `id == UrlPercent`.
    pub plus_to_space: bool,

    /// Base64 option: allow space as whitespace during span detection.
    /// Ignored unless `id == Base64`.
    pub base64_allow_space_ws: bool,
}

impl TransformConfig {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.max_encoded_len >= self.min_len,
            "transform {:?} max_encoded_len < min_len",
            self.id
        );
        if self.mode != TransformMode::Disabled {
            assert!(
                self.max_spans_per_buffer > 0,
                "transform {:?} max_spans_per_buffer must be > 0 when enabled",
                self.id
            );
            assert!(
                self.max_decoded_bytes > 0,
                "transform {:?} max_decoded_bytes must be > 0 when enabled",
                self.id
            );
        }
    }
}

/// Base64 decode/gate instrumentation counters.
///
/// # Guarantees
/// - Counters saturate on overflow.
#[cfg(feature = "b64-stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Base64DecodeStats {
    /// Number of base64 spans considered (after span caps).
    pub spans: u64,
    /// Total encoded bytes across considered spans.
    pub span_bytes: u64,

    /// Number of spans checked by the pre-decode base64 gate.
    pub pre_gate_checks: u64,
    /// Spans that passed the pre-decode base64 gate.
    pub pre_gate_pass: u64,
    /// Spans skipped by the pre-decode base64 gate.
    pub pre_gate_skip: u64,
    /// Encoded bytes skipped by the pre-decode base64 gate.
    pub pre_gate_skip_bytes: u64,

    /// Number of spans actually sent to the base64 decoder.
    pub decode_attempts: u64,
    /// Total encoded bytes sent to the base64 decoder.
    pub decode_attempt_bytes: u64,
    /// Number of decode attempts that failed/truncated/empty.
    pub decode_errors: u64,

    /// Total decoded bytes produced by the decoder (even if discarded).
    pub decoded_bytes_total: u64,
    /// Decoded bytes kept (anchor hit).
    pub decoded_bytes_kept: u64,
    /// Decoded bytes discarded due to no anchor hit.
    pub decoded_bytes_wasted_no_anchor: u64,
    /// Decoded bytes discarded due to decode errors/truncation.
    pub decoded_bytes_wasted_error: u64,
}

#[cfg(feature = "b64-stats")]
impl Base64DecodeStats {
    /// Resets all counters to zero.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Accumulates counters from `other` into `self` with saturating arithmetic.
    pub(crate) fn add(&mut self, other: &Self) {
        self.spans = self.spans.saturating_add(other.spans);
        self.span_bytes = self.span_bytes.saturating_add(other.span_bytes);

        self.pre_gate_checks = self.pre_gate_checks.saturating_add(other.pre_gate_checks);
        self.pre_gate_pass = self.pre_gate_pass.saturating_add(other.pre_gate_pass);
        self.pre_gate_skip = self.pre_gate_skip.saturating_add(other.pre_gate_skip);
        self.pre_gate_skip_bytes = self
            .pre_gate_skip_bytes
            .saturating_add(other.pre_gate_skip_bytes);

        self.decode_attempts = self.decode_attempts.saturating_add(other.decode_attempts);
        self.decode_attempt_bytes = self
            .decode_attempt_bytes
            .saturating_add(other.decode_attempt_bytes);
        self.decode_errors = self.decode_errors.saturating_add(other.decode_errors);

        self.decoded_bytes_total = self
            .decoded_bytes_total
            .saturating_add(other.decoded_bytes_total);
        self.decoded_bytes_kept = self
            .decoded_bytes_kept
            .saturating_add(other.decoded_bytes_kept);
        self.decoded_bytes_wasted_no_anchor = self
            .decoded_bytes_wasted_no_anchor
            .saturating_add(other.decoded_bytes_wasted_no_anchor);
        self.decoded_bytes_wasted_error = self
            .decoded_bytes_wasted_error
            .saturating_add(other.decoded_bytes_wasted_error);
    }
}

/// UTF-16 endianness used when validating UTF-16 anchor hits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Utf16Endianness {
    /// Little-endian UTF-16.
    Le,
    /// Big-endian UTF-16.
    Be,
}

/// A single decode step in the provenance chain for a finding.
///
/// # Invariants
/// - `parent_span` is a byte range in the parent representation (half-open).
/// - `Transform::transform_idx` indexes into `Engine::transforms`.
#[derive(Clone, Debug)]
pub enum DecodeStep {
    /// Transform step is deterministic via transform_idx (index into Engine.transforms).
    Transform {
        transform_idx: usize,
        /// Span in the parent representation (half-open byte range).
        parent_span: Range<usize>,
    },

    /// Not a queued transform. This is a local validation step used when a UTF-16
    /// anchor variant hits. The consumer can replay this by decoding `parent_span`
    /// as UTF-16 with the given endianness.
    Utf16Window {
        endianness: Utf16Endianness,
        /// Span in the parent representation (half-open byte range).
        parent_span: Range<usize>,
    },
}

/// Fixed-capacity decode-step chain stored inline in [`Finding`].
///
/// Length is bounded by [`MAX_DECODE_STEPS`]; pushing past capacity panics.
/// Steps are ordered from root to leaf when materialized.
pub type DecodeSteps = FixedVec<DecodeStep, MAX_DECODE_STEPS>;

/// High-level finding with provenance and root-span hint.
///
/// # Guarantees
/// - `span` and `root_span_hint` are half-open byte ranges.
/// - `decode_steps` describes how to reach the representation where `span` applies.
///
/// # Performance
/// - `Finding` is the materialized, user-facing form; keep `FindingRec` on the hot path.
#[derive(Clone, Debug)]
pub struct Finding {
    /// Rule name that produced this finding.
    pub rule: &'static str,

    /// Span in the final representation obtained by applying `decode_steps`.
    /// - If `decode_steps` is empty, this is a span in the input buffer.
    /// - If the last step is `Utf16Window`, span is in the UTF-8 bytes produced by decoding.
    pub span: Range<usize>,

    /// Best-effort hint into the original/root buffer.
    /// - For raw findings in root: exact match span.
    /// - For derived buffers: outermost container span in root (or best available).
    /// - For UTF-16 window findings in root: the decoded window span in root.
    ///
    /// For file-backed scans this is an absolute byte offset within the file.
    pub root_span_hint: Range<usize>,

    /// Decode steps from root buffer to the representation where `span` applies.
    /// Stored inline with a fixed capacity to avoid per-finding allocations.
    pub decode_steps: DecodeSteps,
}

/// Compact finding record stored during scanning.
///
/// This is later materialized into [`Finding`] by expanding the decode-step chain.
///
/// # Performance
/// - Fixed-width fields keep the record compact and `Copy` for ring buffers.
///
/// # Invariants
/// - `span_start..span_end` is a half-open range in the current buffer.
/// - `root_hint_start..root_hint_end` is a half-open range in the root file buffer.
/// - `span_start`/`span_end` must fit in `u32`; callers must chunk inputs accordingly.
/// - `step_id` is only valid while the originating scratch arena is alive and not reset.
/// - `step_id == STEP_ROOT` denotes a root-buffer finding with no decode steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingRec {
    /// Source file id for the finding.
    pub file_id: FileId,
    /// Rule index (engine-local).
    pub rule_id: u32,
    /// Span start in the current buffer (byte index).
    pub span_start: u32,
    /// Span end in the current buffer (byte index).
    pub span_end: u32,
    /// Best-effort root span hint (absolute byte offset in file).
    pub root_hint_start: u64,
    /// Best-effort root span hint (absolute byte offset in file).
    pub root_hint_end: u64,
    /// Whether `span_start`/`span_end` should participate in dedupe for this finding.
    ///
    /// For transform-derived findings with precise root-span mapping, decoded spans
    /// can shift with chunk alignment, so dedupe uses only the root hint window.
    /// When root-span mapping is unavailable, include spans to avoid collapsing
    /// distinct matches that share a coarse root hint.
    pub dedupe_with_span: bool,
    /// Decode-step chain id for reconstructing provenance.
    /// Valid only while the originating `ScanScratch` arena is alive and not reset.
    pub step_id: StepId,
}

/// Two-phase rule specification: confirm in a smaller seed window, then expand.
///
/// # Algorithm
/// 1. Check `confirm_any` inside the seed window (`seed_radius`).
/// 2. If any confirm hits, expand to `full_radius` and run regex validation.
///
/// # Trade-offs
/// - Reduces regex work on noisy data, but may widen windows on confirm hits.
///
/// # Invariants
/// - `seed_radius <= full_radius`.
/// - `confirm_any` must be non-empty.
#[derive(Clone, Debug)]
pub struct TwoPhaseSpec {
    /// Radius for the seed window used for confirm checks.
    pub seed_radius: usize,
    /// Radius for the expanded window after confirmation.
    pub full_radius: usize,
    /// Patterns that must appear within the seed window to confirm.
    pub confirm_any: &'static [&'static [u8]],
}

impl TwoPhaseSpec {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.seed_radius <= self.full_radius,
            "two_phase seed_radius must be <= full_radius"
        );
        assert!(
            !self.confirm_any.is_empty(),
            "two_phase confirm_any must not be empty"
        );
    }
}

/// Fast-path validator used to confirm common token-like rules directly at
/// anchor hits, bypassing window accumulation and regex evaluation.
///
/// Validators assume the anchor match is **match-start aligned** in the raw
/// representation (i.e., `anchor_start` is the regex match start). If this
/// cannot be guaranteed for a rule, set [`ValidatorKind::None`].
///
/// # Preconditions
/// - Only use fast validators when anchors are match-start aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorKind {
    /// Prefix + fixed-length tail + optional boundary/terminator checks.
    PrefixFixed {
        /// Number of bytes in the tail immediately following the anchor.
        tail_len: u16,
        /// Character class used for each tail byte.
        tail: TailCharset,
        /// Require a regex word boundary (`\b`) before the prefix.
        require_word_boundary_before: bool,
        /// Optional delimiter check after the tail.
        delim_after: DelimAfter,
    },

    /// Prefix + bounded-length tail + optional boundary/terminator checks.
    ///
    /// The validator is greedy (matches the longest tail within bounds) and,
    /// when `delim_after` is required, it backtracks to the longest tail that
    /// is immediately followed by a valid delimiter or end-of-input.
    PrefixBounded {
        /// Minimum number of bytes in the tail.
        min_tail: u16,
        /// Maximum number of bytes in the tail.
        max_tail: u16,
        /// Character class used for each tail byte.
        tail: TailCharset,
        /// Require a regex word boundary (`\b`) before the prefix.
        require_word_boundary_before: bool,
        /// Optional delimiter check after the tail.
        delim_after: DelimAfter,
    },

    /// Special-case validator for AWS access key IDs (A3T... / AKIA...).
    AwsAccessKey,

    /// No validator; always use the regex/window path.
    None,
}

impl ValidatorKind {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(self) {
        match self {
            ValidatorKind::PrefixFixed { .. } => {}
            ValidatorKind::PrefixBounded {
                min_tail, max_tail, ..
            } => {
                assert!(
                    min_tail <= max_tail,
                    "validator min_tail must be <= max_tail"
                );
            }
            ValidatorKind::AwsAccessKey | ValidatorKind::None => {}
        }
    }
}

/// Post-match delimiter requirement for token-like rules.
///
/// Delimiter checks operate on raw bytes, not Unicode scalars.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelimAfter {
    /// No delimiter requirement; the match may be followed by any byte or end.
    None,
    /// Gitleaks-style token terminator:
    /// `['"|\\n|\\r|\\s|\\x60]` or end-of-input.
    GitleaksTokenTerminator,
}

/// Tail character class for validator checks.
///
/// All charsets are ASCII byte classes applied to raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailCharset {
    /// `[A-Z0-9]`
    UpperAlnum,
    /// `[A-Za-z0-9]`
    Alnum,
    /// `[a-z0-9]`
    LowerAlnum,
    /// `[A-Za-z0-9_-]`
    AlnumDashUnderscore,
    /// `[A-Za-z0-9=_\-.]` (case-insensitive)
    Sendgrid66Set,
    /// `[a-h0-9]` (case-insensitive)
    DatabricksSet,
    /// `[A-Za-z0-9+/]` (standard base64 alphabet, no padding)
    Base64Std,
}

/// Rule configuration for anchor scan + regex validation.
///
/// # Invariants
/// - `name` must be non-empty.
/// - `two_phase`, `must_contain`, `keywords_any`, and `entropy` must be valid when present.
///
/// # Design Notes
/// - Anchors should be ASCII-ish; UTF-16 variants are derived automatically.
/// - `radius` is in bytes and should be large enough to cover the regex match window.
/// - `re` is a bytes regex; no UTF-8 assumptions are made.
///
/// # Performance
/// - Smaller `radius` values reduce regex work but can miss matches if too small.
/// - `must_contain`, `keywords_any`, and `entropy` act as progressively cheaper filters.
#[derive(Clone, Debug)]
pub struct RuleSpec {
    /// Rule name used for reporting.
    pub name: &'static str,

    /// ASCII-ish anchors. The engine also generates UTF-16LE/BE variants.
    pub anchors: &'static [&'static [u8]],

    /// Radius in bytes around an anchor hit (raw representation).
    pub radius: usize,

    /// Optional fast validator for token-like rules.
    ///
    /// When set to something other than [`ValidatorKind::None`], anchors are
    /// expected to be match-start aligned in raw bytes. The engine will attempt
    /// to validate at each anchor hit and may skip window/regex work entirely
    /// when the validator is authoritative.
    pub validator: ValidatorKind,

    /// Optional two-phase confirm + expand configuration.
    pub two_phase: Option<TwoPhaseSpec>,

    /// Optional cheap byte-substring check before running regex.
    pub must_contain: Option<&'static [u8]>,

    /// Optional keyword gate (any-of) checked inside the same validation window.
    ///
    /// Keywords are *local context* gates: at least one must appear in the same
    /// window where the regex is evaluated. This keeps correctness aligned with
    /// single-pass, chunked scanning (no global context) while filtering noisy
    /// windows cheaply via memmem.
    ///
    /// # Encoding behavior
    /// Keywords are evaluated on the *raw representation* of the window (i.e., the
    /// bytes as they appear after any transform decoding, before UTF-8 interpretation).
    /// Like anchors, keywords are compiled into raw + UTF-16LE/BE variants so the
    /// gate works consistently whether scanning raw buffers or decoded UTF-16 content.
    pub keywords_any: Option<&'static [&'static [u8]]>,

    /// Optional entropy gate evaluated on each regex match.
    ///
    /// This is a *post-regex* filter applied to the match bytes. It is useful for
    /// secret-like tokens that should be high-entropy; low-entropy matches are
    /// likely false positives. Entropy is bounded by min/max length to keep cost
    /// predictable and avoid noisy small-sample statistics.
    pub entropy: Option<EntropySpec>,

    /// Optional capture group index for secret extraction.
    ///
    /// When set, the engine extracts the secret value from the specified capture
    /// group rather than using the default heuristic. The default behavior (when
    /// `None`) is to prefer capture group 1 if it exists and is non-empty, falling
    /// back to the full match span.
    ///
    /// # Fallback Behavior
    /// If the specified group did not participate in the match or captured an empty
    /// span, the engine falls back to the default behavior: prefer capture group 1
    /// if non-empty, otherwise use the full match (group 0).
    ///
    /// # Gitleaks Compatibility
    /// Gitleaks rules conventionally place the secret in capture group 1. Setting
    /// this field allows overriding that convention for rules with different capture
    /// group layouts.
    ///
    /// # Indexing
    /// - Group 0 is the full match; use `Some(0)` to always extract the full match
    ///   even when capture groups exist.
    /// - Groups 1+ are the parenthesized capture groups in order.
    ///
    /// # Validation
    /// The group index is validated at engine build time via [`RuleSpec::assert_valid`].
    /// Specifying a group that does not exist in the regex will panic during engine
    /// construction.
    pub secret_group: Option<u16>,

    /// Final check. Bytes regex (no UTF-8 assumption).
    pub re: Regex,
}

impl RuleSpec {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(&self) {
        assert!(!self.name.is_empty(), "rule name must not be empty");
        self.validator.assert_valid();
        if let Some(tp) = &self.two_phase {
            tp.assert_valid();
        }
        if let Some(needle) = self.must_contain {
            assert!(!needle.is_empty(), "must_contain must not be empty");
        }
        if let Some(kws) = self.keywords_any {
            assert!(!kws.is_empty(), "keywords_any must not be empty");
        }
        if let Some(ent) = &self.entropy {
            ent.assert_valid();
        }
        if let Some(gi) = self.secret_group {
            let group_count = self.re.captures_len();
            assert!(
                (gi as usize) < group_count,
                "secret_group {} does not exist in regex (only {} groups, including group 0)",
                gi,
                group_count
            );
        }
    }
}

/// Shannon-entropy gate configuration.
///
/// # Algorithm
/// - Entropy is computed over the matched byte slice (full regex match).
/// - Matches shorter than `min_len` pass (entropy is noisy on tiny samples).
/// - Matches longer than `max_len` are capped for cost control (first `max_len` bytes).
///
/// # Invariants
/// - Threshold is bits/byte in [0.0, 8.0].
/// - `min_len <= max_len`.
#[derive(Clone, Debug)]
pub struct EntropySpec {
    /// Minimum entropy threshold in bits/byte.
    pub min_bits_per_byte: f32,
    /// Matches shorter than this length pass without entropy checks.
    pub min_len: usize,
    /// Max number of bytes used for entropy calculation.
    pub max_len: usize,
}

impl EntropySpec {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.min_bits_per_byte >= 0.0,
            "entropy min_bits_per_byte must be >= 0"
        );
        assert!(
            self.min_bits_per_byte <= 8.0,
            "entropy min_bits_per_byte must be <= 8"
        );
        assert!(
            self.min_len <= self.max_len,
            "entropy min_len must be <= max_len"
        );
    }
}

/// Engine tuning knobs for performance and DoS protection.
///
/// # Trade-offs
/// - Window coalescing limits bound CPU cost but may widen validation windows.
/// - Decode/work-item caps can skip derived buffers when exceeded.
/// - `max_findings_per_chunk` is a hard cap; excess findings are dropped.
#[derive(Clone, Debug)]
pub struct Tuning {
    /// Window merge gap in bytes when coalescing adjacent anchor hits.
    /// Typical values: 64–256 bytes.
    pub merge_gap: usize,

    /// After merging, if windows per (rule, variant) still exceed this, coalesce under pressure.
    pub max_windows_per_rule_variant: usize,
    /// Starting gap in bytes used during pressure coalescing.
    pub pressure_gap_start: usize,

    /// Prevent vector blowups before merging by collapsing to a single coalesced range.
    pub max_anchor_hits_per_rule_variant: usize,

    /// Maximum bytes produced when decoding a UTF-16 window for validation.
    pub max_utf16_decoded_bytes_per_window: usize,

    /// Max transform depth (number of decode steps) per work item chain.
    /// Must be <= `MAX_DECODE_STEPS - 1`; enforced at engine build time.
    pub max_transform_depth: usize,

    /// Maximum total decoded output bytes across all transforms per scan.
    /// Counts ALL decoded output bytes:
    /// - full decodes
    /// - streaming gate decoded chunks
    /// - UTF-16 window decode output
    pub max_total_decode_output_bytes: usize,

    /// Hard cap on number of enqueued decoded buffers (DoS control).
    pub max_work_items: usize,

    /// Hard cap on findings per buffer/chunk.
    pub max_findings_per_chunk: usize,

    /// Whether to scan UTF-16 anchor variants at all.
    ///
    /// When false, only raw anchors are scanned (UTF-16 is skipped even if NULs
    /// are present). This is useful for modes that avoid binary/UTF-16 content.
    pub scan_utf16_variants: bool,
}

impl Tuning {
    /// Internal invariant checks used at engine build time.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.max_anchor_hits_per_rule_variant > 0,
            "max_anchor_hits_per_rule_variant must be > 0"
        );
        assert!(
            self.pressure_gap_start > 0,
            "pressure_gap_start must be > 0 to avoid infinite coalesce loops"
        );
    }
}

/// Policy for selecting anchors during engine compilation.
///
/// Determines whether to derive anchors from regexes, use manual anchors, or both.
/// This choice only affects compilation; runtime scanning uses the compiled anchors.
///
/// # Choosing a Policy
/// - [`PreferDerived`]: Default for most use cases; automatic anchor extraction
///   with manual fallback ensures coverage.
/// - [`ManualOnly`]: Use when regexes are complex and derivation produces poor anchors.
/// - [`DerivedOnly`]: Use when manual anchors are stale or you want pure automation.
///
/// [`PreferDerived`]: AnchorPolicy::PreferDerived
/// [`ManualOnly`]: AnchorPolicy::ManualOnly
/// [`DerivedOnly`]: AnchorPolicy::DerivedOnly
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorPolicy {
    /// Prefer derived anchors, falling back to manual anchors if derivation fails.
    PreferDerived,
    /// Only use manual anchors; skip derivation.
    ManualOnly,
    /// Only use derived anchors; ignore manual anchors entirely.
    DerivedOnly,
}

// -------------------------------------------------------------------------
// Policy-hash encodings (canonical, deterministic)
// -------------------------------------------------------------------------
// These encodings must stay in lockstep with `policy_hash` in
// `src/git_scan/policy_hash.rs`. Any semantic change requires bumping the
// policy hash version to avoid false cache hits.

impl RuleSpec {
    /// Encodes this rule into a canonical byte representation for policy hashing.
    ///
    /// The encoding is deterministic and order-invariant for anchor/keyword lists.
    /// Callers should treat this as an internal serialization format and bump
    /// the policy-hash version if it changes.
    pub(crate) fn encode_policy(&self, out: &mut Vec<u8>) {
        push_bytes_u32(out, self.name.as_bytes());
        encode_bytes_list(out, self.anchors);
        push_u64_le(out, self.radius as u64);
        self.validator.encode_policy(out);

        match &self.two_phase {
            None => out.push(0),
            Some(tp) => {
                out.push(1);
                tp.encode_policy(out);
            }
        }

        encode_opt_bytes(out, self.must_contain);
        encode_opt_bytes_list(out, self.keywords_any);

        match &self.entropy {
            None => out.push(0),
            Some(ent) => {
                out.push(1);
                ent.encode_policy(out);
            }
        }

        match self.secret_group {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                push_u16_le(out, v);
            }
        }

        push_bytes_u32(out, self.re.as_str().as_bytes());
    }
}

impl TwoPhaseSpec {
    /// Encodes this two-phase configuration into canonical bytes.
    pub(crate) fn encode_policy(&self, out: &mut Vec<u8>) {
        push_u64_le(out, self.seed_radius as u64);
        push_u64_le(out, self.full_radius as u64);
        encode_bytes_list(out, self.confirm_any);
    }
}

impl EntropySpec {
    /// Encodes this entropy configuration into canonical bytes.
    pub(crate) fn encode_policy(&self, out: &mut Vec<u8>) {
        push_u32_le(out, self.min_bits_per_byte.to_bits());
        push_u64_le(out, self.min_len as u64);
        push_u64_le(out, self.max_len as u64);
    }
}

impl ValidatorKind {
    /// Encodes this validator kind into canonical bytes.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        match self {
            ValidatorKind::None => out.push(0),
            ValidatorKind::AwsAccessKey => out.push(1),
            ValidatorKind::PrefixFixed {
                tail_len,
                tail,
                require_word_boundary_before,
                delim_after,
            } => {
                out.push(2);
                push_u16_le(out, tail_len);
                tail.encode_policy(out);
                push_bool(out, require_word_boundary_before);
                delim_after.encode_policy(out);
            }
            ValidatorKind::PrefixBounded {
                min_tail,
                max_tail,
                tail,
                require_word_boundary_before,
                delim_after,
            } => {
                out.push(3);
                push_u16_le(out, min_tail);
                push_u16_le(out, max_tail);
                tail.encode_policy(out);
                push_bool(out, require_word_boundary_before);
                delim_after.encode_policy(out);
            }
        }
    }
}

impl TailCharset {
    /// Encodes this tail charset into a stable tag.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        let tag = match self {
            TailCharset::UpperAlnum => 1,
            TailCharset::Alnum => 2,
            TailCharset::LowerAlnum => 3,
            TailCharset::AlnumDashUnderscore => 4,
            TailCharset::Sendgrid66Set => 5,
            TailCharset::DatabricksSet => 6,
            TailCharset::Base64Std => 7,
        };
        out.push(tag);
    }
}

impl DelimAfter {
    /// Encodes this delimiter requirement into a stable tag.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        let tag = match self {
            DelimAfter::None => 0,
            DelimAfter::GitleaksTokenTerminator => 1,
        };
        out.push(tag);
    }
}

impl TransformConfig {
    /// Encodes this transform config into canonical bytes.
    pub(crate) fn encode_policy(&self, out: &mut Vec<u8>) {
        self.id.encode_policy(out);
        self.mode.encode_policy(out);
        self.gate.encode_policy(out);
        push_u64_le(out, self.min_len as u64);
        push_u64_le(out, self.max_spans_per_buffer as u64);
        push_u64_le(out, self.max_encoded_len as u64);
        push_u64_le(out, self.max_decoded_bytes as u64);
        push_bool(out, self.plus_to_space);
        push_bool(out, self.base64_allow_space_ws);
    }
}

impl TransformId {
    /// Encodes this transform id into a stable tag.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        let tag = match self {
            TransformId::UrlPercent => 1,
            TransformId::Base64 => 2,
        };
        out.push(tag);
    }
}

impl TransformMode {
    /// Encodes this transform mode into a stable tag.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        let tag = match self {
            TransformMode::Disabled => 0,
            TransformMode::Always => 1,
            TransformMode::IfNoFindingsInThisBuffer => 2,
        };
        out.push(tag);
    }
}

impl Gate {
    /// Encodes this gate policy into a stable tag.
    pub(crate) fn encode_policy(self, out: &mut Vec<u8>) {
        let tag = match self {
            Gate::None => 0,
            Gate::AnchorsInDecoded => 1,
        };
        out.push(tag);
    }
}

impl Tuning {
    /// Encodes tuning into canonical bytes for policy hashing.
    pub(crate) fn encode_policy(&self, out: &mut Vec<u8>) {
        push_u64_le(out, self.merge_gap as u64);
        push_u64_le(out, self.max_windows_per_rule_variant as u64);
        push_u64_le(out, self.pressure_gap_start as u64);
        push_u64_le(out, self.max_anchor_hits_per_rule_variant as u64);
        push_u64_le(out, self.max_utf16_decoded_bytes_per_window as u64);
        push_u64_le(out, self.max_transform_depth as u64);
        push_u64_le(out, self.max_total_decode_output_bytes as u64);
        push_u64_le(out, self.max_work_items as u64);
        push_u64_le(out, self.max_findings_per_chunk as u64);
        push_bool(out, self.scan_utf16_variants);
    }
}

fn encode_opt_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            push_bytes_u32(out, bytes);
        }
    }
}

/// Encodes an optional list of byte slices.
///
/// `None` encodes as a single 0x00 byte; `Some` encodes as 0x01 followed by
/// `encode_bytes_list`, which is order- and duplicate-invariant.
fn encode_opt_bytes_list(out: &mut Vec<u8>, value: Option<&[&[u8]]>) {
    match value {
        None => out.push(0),
        Some(list) => {
            out.push(1);
            encode_bytes_list(out, list);
        }
    }
}

/// Encodes a list of byte slices in canonical, order-invariant form.
///
/// The list is sorted and deduplicated to make policy hashes independent
/// of anchor/keyword ordering.
fn encode_bytes_list(out: &mut Vec<u8>, list: &[&[u8]]) {
    let mut items: Vec<&[u8]> = list.to_vec();
    items.sort_unstable();
    items.dedup();

    assert!(
        items.len() <= u32::MAX as usize,
        "byte list too large for u32 prefix: {}",
        items.len()
    );
    push_u32_le(out, items.len() as u32);
    for item in items {
        push_bytes_u32(out, item);
    }
}

fn push_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn push_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Encodes a length-prefixed byte slice using a `u32` length in little-endian.
///
/// # Panics
///
/// Panics if `bytes.len() > u32::MAX` (defense-in-depth).
fn push_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(
        bytes.len() <= u32::MAX as usize,
        "byte slice too long for u32 prefix: {}",
        bytes.len()
    );
    push_u32_le(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
