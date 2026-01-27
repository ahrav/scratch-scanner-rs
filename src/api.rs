use crate::stdx::FixedVec;
use regex::bytes::Regex;
use std::ops::Range;

// --------------------------
// Public API types
// --------------------------

/// Opaque file identifier used to index into [`FileTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId(pub u32);

/// Compact index into the decode-step arena.
///
/// Steps are chained from the root buffer to derived buffers so findings can be
/// reconstructed without cloning vectors on the hot path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StepId(pub(crate) u32);

/// Hard cap on decode-step chains stored per finding.
///
/// Must be at least `Tuning::max_transform_depth + 1` (root + transforms);
/// enforced at engine build time. Raising this increases per-finding storage.
pub const MAX_DECODE_STEPS: usize = 8;

pub(crate) const STEP_ROOT: StepId = StepId(u32::MAX);

impl Default for StepId {
    fn default() -> Self {
        STEP_ROOT
    }
}

/// Identifies a supported transform used for derived-buffer scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransformId {
    UrlPercent,
    Base64,
    // Add more: JsonUnescape, HtmlUnescape, Gzip, Zlib, Brotli, etc.
}

/// Controls when a transform is applied during scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformMode {
    Disabled,
    Always,

    /// Correctness trade (explicit).
    /// Skips this transform if this buffer already produced any findings.
    /// This can miss findings that only appear in nested encodings.
    IfNoFindingsInThisBuffer,
}

/// Gate policy for expensive transform decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    None,

    /// Stream-decode and proceed only if decoded bytes contain any anchor variant
    /// (raw + UTF-16LE/BE variants).
    AnchorsInDecoded,
}

/// Configuration for a single transform stage.
#[derive(Clone, Debug)]
pub struct TransformConfig {
    /// Transform kind.
    pub id: TransformId,

    /// When this transform is applied.
    pub mode: TransformMode,

    /// Gate policy (if enabled).
    pub gate: Gate,

    /// Minimum encoded length to consider for span detection.
    pub min_len: usize,
    /// Limit of candidate spans to process per buffer.
    pub max_spans_per_buffer: usize,
    /// Maximum encoded length to consider for a span.
    pub max_encoded_len: usize,

    /// Maximum decoded bytes produced per span.
    pub max_decoded_bytes: usize,

    /// URL option: treat '+' as space.
    pub plus_to_space: bool,

    /// Base64 option: allow space as whitespace during span detection.
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
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

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
    Le,
    Be,
}

/// A single decode step in the provenance chain for a finding.
#[derive(Clone, Debug)]
pub enum DecodeStep {
    /// Transform step is deterministic via transform_idx (index into Engine.transforms).
    Transform {
        transform_idx: usize,
        parent_span: Range<usize>, // span in the parent representation
    },

    /// Not a queued transform. This is a local validation step used when an UTF-16 anchor variant hits.
    /// The consumer can replay this by decoding parent_span as UTF-16 with the given endianness.
    Utf16Window {
        endianness: Utf16Endianness,
        parent_span: Range<usize>, // span in the parent representation
    },
}

/// Fixed-capacity decode-step chain stored inline in [`Finding`].
///
/// Length is bounded by [`MAX_DECODE_STEPS`]; pushing past capacity panics.
pub type DecodeSteps = FixedVec<DecodeStep, MAX_DECODE_STEPS>;

/// High-level finding with provenance and root-span hint.
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
    pub root_span_hint: Range<usize>,

    /// Decode steps from root buffer to the representation where `span` applies.
    /// Stored inline with a fixed capacity to avoid per-finding allocations.
    pub decode_steps: DecodeSteps,
}

/// Compact finding record stored during scanning.
///
/// This is later materialized into [`Finding`] by expanding the decode-step chain.
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
    /// Decode-step chain id for reconstructing provenance.
    /// Valid only while the originating `ScanScratch` arena is alive and not reset.
    pub step_id: StepId,
}

/// Two-phase rule specification: confirm in a smaller seed window, then expand.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorKind {
    /// Prefix + fixed-length tail + optional boundary/terminator checks.
    PrefixFixed {
        /// Number of bytes in the tail immediately following the anchor.
        tail_len: u16,
        /// Character class used for each tail byte.
        tail: TailCharset,
        /// Require a `regex::bytes` word boundary (`\b`) before the prefix.
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
        /// Require a `regex::bytes` word boundary (`\b`) before the prefix.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelimAfter {
    /// No delimiter requirement; the match may be followed by any byte or end.
    None,
    /// Gitleaks-style token terminator:
    /// `['"|\n|\r|\\s|\\x60]` or end-of-input.
    GitleaksTokenTerminator,
}

/// Tail character class for validator checks.
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
    /// `[A-Za-z0-9=_\\-.]` (case-insensitive)
    Sendgrid66Set,
    /// `[a-h0-9]` (case-insensitive)
    DatabricksSet,
    /// `[A-Za-z0-9+/]` (standard base64 alphabet, no padding)
    Base64Std,
}

/// Rule configuration for anchor scan + regex validation.
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
    /// Keywords are compiled into raw + UTF-16LE/BE variants the same way anchors
    /// are, so the gate works consistently across encodings.
    pub keywords_any: Option<&'static [&'static [u8]]>,

    /// Optional entropy gate evaluated on each regex match.
    ///
    /// This is a *post-regex* filter applied to the match bytes. It is useful for
    /// secret-like tokens that should be high-entropy; low-entropy matches are
    /// likely false positives. Entropy is bounded by min/max length to keep cost
    /// predictable and avoid noisy small-sample statistics.
    pub entropy: Option<EntropySpec>,

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
    }
}

/// Shannon-entropy gate configuration.
///
/// - Entropy is computed over the matched byte slice (full regex match).
/// - Threshold is bits/byte in [0.0, 8.0].
/// - Matches shorter than `min_len` pass (entropy is noisy on tiny samples).
/// - Matches longer than `max_len` are capped for cost control.
#[derive(Clone, Debug)]
pub struct EntropySpec {
    pub min_bits_per_byte: f32,
    pub min_len: usize,
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
#[derive(Clone, Debug)]
pub struct Tuning {
    /// Window merge gap (bytes) when coalescing adjacent anchor hits.
    pub merge_gap: usize,

    /// After merging, if windows per (rule, variant) still exceed this, coalesce under pressure.
    pub max_windows_per_rule_variant: usize,
    /// Starting gap used during pressure coalescing.
    pub pressure_gap_start: usize,

    /// Prevent vector blowups before merging by collapsing to a single coalesced range.
    pub max_anchor_hits_per_rule_variant: usize,

    /// UTF-16 decoding (for validation).
    pub max_utf16_decoded_bytes_per_window: usize,

    /// Max transform depth (number of decode steps) per work item chain.
    /// Must be <= `MAX_DECODE_STEPS - 1`; enforced at engine build time.
    pub max_transform_depth: usize,

    /// Counts ALL decoded output bytes:
    /// - full decodes
    /// - streaming gate decoded chunks
    /// - UTF-16 window decode output
    pub max_total_decode_output_bytes: usize,

    /// Hard cap on number of enqueued decoded buffers (DoS control).
    pub max_work_items: usize,

    /// Hard cap on findings per buffer/chunk.
    pub max_findings_per_chunk: usize,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorPolicy {
    /// Prefer derived anchors, falling back to manual anchors if derivation fails.
    PreferDerived,
    /// Only use manual anchors; skip derivation.
    ManualOnly,
    /// Only use derived anchors; ignore manual anchors entirely.
    DerivedOnly,
}
