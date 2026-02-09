//! Phase A persistence identity contracts.
//!
//! This module defines versioned, deterministic contracts for:
//! - [`rule_fingerprint`]: canonical policy identity for a rule.
//! - [`secret_hash`]: keyed hash over existing engine `norm_hash`.
//! - [`occurrence_id`]: canonical finding identity that mirrors current dedupe
//!   semantics (root-hint normalization + UTF-16 variant discrimination).
//!
//! # Algorithm
//!
//! All three derivations follow the same pattern:
//! 1. Build a canonical byte payload from the input fields.
//! 2. Feed the payload through `keyed_hash` — a domain-separated BLAKE3 keyed
//!    hash using one of the subkeys from [`StoreKeys`].
//!
//! Domain separation (a NUL-terminated domain string prepended to the payload)
//! ensures that identical byte payloads used in different contexts produce
//! distinct hashes, preventing cross-contract collisions.
//!
//! `occurrence_id` additionally normalizes its inputs before hashing to absorb
//! benign variation that the engine's existing dedupe logic already collapses:
//! - **Root-hint end normalization**: base64 padding bytes (1–3 trailing `=`)
//!   cause the encoded-region length to vary for identical decoded content;
//!   `normalize_root_hint_end` snaps the end offset to the padding-free minimum
//!   so both padded and unpadded encodings hash identically.
//! - **Non-root span erasure**: for transform-derived findings, the decoded-buffer
//!   span is unstable across chunk boundaries, so it is zeroed out; only the
//!   root-hint window participates in identity.
//!
//! # Versioning
//!
//! [`IDENTITY_CONTRACT_VERSION`] is embedded in every canonical payload. Changing
//! any encoding detail requires bumping this version so that old and new hashes
//! never collide silently.

use crate::api::{FindingRec, RuleSpec, StepId, STEP_ROOT};

use super::keys::StoreKeys;

/// Identity contract version shared by all encodings in this module.
pub const IDENTITY_CONTRACT_VERSION: u8 = 1;

const RULE_FINGERPRINT_DOMAIN: &[u8] = b"scanner.store.identity.v1.rule_fingerprint";
const SECRET_HASH_DOMAIN: &[u8] = b"scanner.store.identity.v1.secret_hash";
const OCCURRENCE_ID_DOMAIN: &[u8] = b"scanner.store.identity.v1.occurrence_id";

/// Stable per-rule fingerprint used by persistence IDs.
pub type RuleFingerprint = [u8; 32];
/// Stable keyed hash of normalized secret bytes.
pub type SecretHash = [u8; 32];
/// Stable canonical occurrence identity.
pub type OccurrenceId = [u8; 32];

/// UTF-16 variant discriminator for occurrence identity.
///
/// The engine can discover the same secret in raw bytes and again inside a
/// UTF-16 LE or BE re-encoding of the same region. Each encoding produces a
/// distinct finding that must hash to a distinct [`OccurrenceId`], so the
/// variant is included in the canonical payload.
///
/// Values intentionally match the discriminant semantics from decode-state:
/// - 0: no UTF-16 variant
/// - 1: UTF-16 LE
/// - 2: UTF-16 BE
///
/// # Invariant
///
/// Root-step findings (`step_id == STEP_ROOT`) must always use [`None`](Self::None).
/// UTF-16 variants only arise from transform-derived buffers, so a root finding
/// with a non-`None` variant is a caller bug, rejected by `IdentityFlags::from_parts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VariantDiscriminant {
    /// No UTF-16 variant (root or non-UTF16 transform).
    None = 0,
    /// UTF-16 little-endian variant.
    Utf16Le = 1,
    /// UTF-16 big-endian variant.
    Utf16Be = 2,
}

/// Identity flags encoded into canonical occurrence payloads.
///
/// Rather than encoding boolean properties implicitly via which payload fields
/// are zero, flags make every semantic dimension explicit and machine-checkable.
/// This prevents silent breakage if a new dimension is added: unknown bits
/// cause [`from_bits_strict`](Self::from_bits_strict) to reject the payload.
///
/// # Layout
///
/// ```text
/// bit 0   FLAG_ROOT_STEP              — finding is from the root buffer
/// bit 1   FLAG_SPAN_INCLUDED          — decoded-buffer span participates in identity
/// bit 2   FLAG_ROOT_HINT_END_NORMALIZED — root_hint_end was padding-normalized
/// bits 8–9  UTF-16 variant (mutually exclusive)
///   bit 8   FLAG_UTF16_LE
///   bit 9   FLAG_UTF16_BE
/// ```
///
/// Bits 3–7 and 10–31 are reserved; setting any of them is rejected as unknown.
/// Bits 8 and 9 are mutually exclusive; setting both is a contradictory state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityFlags(u32);

impl IdentityFlags {
    const FLAG_ROOT_STEP: u32 = 1 << 0;
    const FLAG_SPAN_INCLUDED: u32 = 1 << 1;
    const FLAG_ROOT_HINT_END_NORMALIZED: u32 = 1 << 2;
    const FLAG_UTF16_LE: u32 = 1 << 8;
    const FLAG_UTF16_BE: u32 = 1 << 9;
    const KNOWN_MASK: u32 = Self::FLAG_ROOT_STEP
        | Self::FLAG_SPAN_INCLUDED
        | Self::FLAG_ROOT_HINT_END_NORMALIZED
        | Self::FLAG_UTF16_LE
        | Self::FLAG_UTF16_BE;

    /// Strictly validates flag bits and rejects unknown or contradictory sets.
    pub fn from_bits_strict(bits: u32) -> Result<Self, IdentityError> {
        let unknown = bits & !Self::KNOWN_MASK;
        if unknown != 0 {
            return Err(IdentityError::UnknownIdentityFlags { bits: unknown });
        }
        if bits & Self::FLAG_UTF16_LE != 0 && bits & Self::FLAG_UTF16_BE != 0 {
            return Err(IdentityError::ConflictingUtf16Flags { bits });
        }
        Ok(Self(bits))
    }

    /// Derives flags from `(step_id, include_span, variant)`, enforcing structural
    /// invariants:
    ///
    /// - Root findings (`STEP_ROOT`) always set `ROOT_STEP` and include span.
    /// - Transform findings (non-root) set `ROOT_HINT_END_NORMALIZED` because
    ///   their root-hint end may have been snapped by padding normalization.
    /// - Span inclusion follows engine dedupe semantics (`dedupe_with_span`):
    ///   included when root-span mapping is unavailable, excluded otherwise.
    /// - A root finding with a UTF-16 variant is rejected as a caller bug.
    fn from_parts(
        step_id: StepId,
        include_span: bool,
        variant: VariantDiscriminant,
    ) -> Result<Self, IdentityError> {
        if step_id == STEP_ROOT && !matches!(variant, VariantDiscriminant::None) {
            return Err(IdentityError::RootStepHasVariant { variant });
        }

        let mut bits = 0u32;
        if step_id == STEP_ROOT {
            bits |= Self::FLAG_ROOT_STEP;
        }
        if include_span {
            bits |= Self::FLAG_SPAN_INCLUDED;
        }
        if step_id != STEP_ROOT {
            bits |= Self::FLAG_ROOT_HINT_END_NORMALIZED;
        }
        match variant {
            VariantDiscriminant::None => {}
            VariantDiscriminant::Utf16Le => bits |= Self::FLAG_UTF16_LE,
            VariantDiscriminant::Utf16Be => bits |= Self::FLAG_UTF16_BE,
        }

        Self::from_bits_strict(bits)
    }

    /// Raw flags bits for canonical encoding.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Identity contract validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Flags include unknown bits.
    UnknownIdentityFlags { bits: u32 },
    /// Flags include contradictory UTF-16 variant bits.
    ConflictingUtf16Flags { bits: u32 },
    /// Root findings must not carry UTF-16 variant discriminants.
    RootStepHasVariant { variant: VariantDiscriminant },
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownIdentityFlags { bits } => {
                write!(f, "unknown identity flags bits: 0x{bits:08x}")
            }
            Self::ConflictingUtf16Flags { bits } => {
                write!(f, "conflicting UTF-16 flags in bits: 0x{bits:08x}")
            }
            Self::RootStepHasVariant { variant } => {
                write!(f, "root finding cannot carry variant {variant:?}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// Input payload for occurrence identity derivation.
///
/// The caller is responsible for computing [`rule_fingerprint`] and
/// [`secret_hash`] before constructing this struct. `object_key` must be a
/// stable, canonical byte representation of the scanned object (e.g. a
/// repo-relative path); using non-canonical keys (such as an absolute
/// filesystem path that varies by machine) will produce non-reproducible IDs.
pub struct OccurrenceInput<'a> {
    /// Stable object identity bytes (e.g. canonical repo-relative path).
    pub object_key: &'a [u8],
    /// Engine finding record for this occurrence.
    pub finding: &'a FindingRec,
    /// Precomputed rule fingerprint (from [`rule_fingerprint`]).
    pub rule_fingerprint: &'a RuleFingerprint,
    /// Precomputed secret hash (from [`secret_hash`]).
    pub secret_hash: &'a SecretHash,
    /// UTF-16 variant discriminator from decode provenance.
    pub variant: VariantDiscriminant,
}

/// Compute canonical rule fingerprint from `RuleSpec::encode_policy` bytes.
#[must_use]
pub fn rule_fingerprint(rule: &RuleSpec, keys: &StoreKeys) -> RuleFingerprint {
    let mut policy_bytes = Vec::with_capacity(256);
    rule.encode_policy(&mut policy_bytes);
    keyed_hash(keys.identity_key(), RULE_FINGERPRINT_DOMAIN, &policy_bytes)
}

/// Compute keyed secret hash over existing engine `norm_hash` bytes.
#[must_use]
pub fn secret_hash(norm_hash: &[u8; 32], keys: &StoreKeys) -> SecretHash {
    keyed_hash(keys.secret_key(), SECRET_HASH_DOMAIN, norm_hash)
}

/// Compute canonical occurrence ID for a finding.
///
/// The canonical encoding includes:
/// - contract version + tags
/// - identity flags word
/// - object key
/// - rule fingerprint
/// - secret hash
/// - root-hint start/end (with transform normalization)
/// - root-only span contribution
/// - variant discriminator
pub fn occurrence_id(
    input: OccurrenceInput<'_>,
    keys: &StoreKeys,
) -> Result<OccurrenceId, IdentityError> {
    let canonical = canonicalize_finding(input.finding, input.variant)?;
    let mut payload = Vec::with_capacity(256 + input.object_key.len());
    encode_occurrence_canonical(
        &mut payload,
        input.object_key,
        input.rule_fingerprint,
        input.secret_hash,
        &canonical,
    );
    Ok(keyed_hash(
        keys.identity_key(),
        OCCURRENCE_ID_DOMAIN,
        &payload,
    ))
}

/// Normalized snapshot of the identity-relevant fields from a [`FindingRec`].
///
/// This intermediate separates normalization (which may fail) from encoding
/// (which is infallible), keeping each step testable in isolation.
/// Fields that do not participate in identity for a given finding class are
/// zeroed during construction (e.g. `span_start`/`span_end` for non-root).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CanonicalFinding {
    flags: IdentityFlags,
    /// Decoded-buffer span; zero for non-root findings (unstable across chunks).
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    /// May have been snapped by [`normalize_root_hint_end`] for non-root findings.
    root_hint_end: u64,
    variant: VariantDiscriminant,
}

/// Normalize a [`FindingRec`] into identity-canonical form.
///
/// Two normalizations are applied:
/// 1. Non-root spans are zeroed (they shift with chunk alignment and must not
///    affect identity).
/// 2. `root_hint_end` is snapped to the padding-free minimum for non-root
///    findings whose encoded length falls in the base64 padding window.
fn canonicalize_finding(
    finding: &FindingRec,
    variant: VariantDiscriminant,
) -> Result<CanonicalFinding, IdentityError> {
    let root_hint_end = normalize_root_hint_end(finding);
    let include_span = finding.dedupe_with_span || finding.step_id == STEP_ROOT;
    let (span_start, span_end) = if include_span {
        (finding.span_start, finding.span_end)
    } else {
        (0, 0)
    };
    let flags = IdentityFlags::from_parts(finding.step_id, include_span, variant)?;

    Ok(CanonicalFinding {
        flags,
        span_start,
        span_end,
        root_hint_start: finding.root_hint_start,
        root_hint_end,
        variant,
    })
}

/// Snap `root_hint_end` to remove base64 padding jitter for non-root findings.
///
/// # Problem
///
/// Base64 encodes 3 raw bytes into 4 encoded characters. When the raw length
/// is not a multiple of 3, the encoder appends 1–3 `=` padding characters.
/// Different base64 implementations (or the same implementation across
/// versions) may or may not include the padding, causing `root_hint_end` to
/// vary by up to 3 bytes for identical decoded content.
///
/// # Solution
///
/// For non-root findings, compute the minimum encoded length that could
/// represent the decoded span (`ceil(decoded_len * 4 / 3)`). If the actual
/// encoded region length exceeds this minimum by 1–3 bytes — exactly the
/// padding window — snap `root_hint_end` back to the minimum. Differences
/// outside this window are left untouched because they indicate a genuinely
/// different encoded region, not mere padding variation.
///
/// Root findings are returned unchanged because their spans are authoritative.
fn normalize_root_hint_end(finding: &FindingRec) -> u64 {
    if finding.step_id == STEP_ROOT {
        return finding.root_hint_end;
    }

    let decoded_len = finding.span_end.saturating_sub(finding.span_start) as u64;
    let min_encoded = (decoded_len * 4).div_ceil(3);
    let actual_encoded = finding
        .root_hint_end
        .saturating_sub(finding.root_hint_start);
    if actual_encoded > min_encoded && actual_encoded <= min_encoded.saturating_add(3) {
        return finding.root_hint_start.saturating_add(min_encoded);
    }
    finding.root_hint_end
}

/// Serialize a canonical occurrence payload into `out`.
///
/// The encoding uses NUL-terminated ASCII tags before each field group so that
/// the byte stream is self-describing and unambiguous even without a length
/// prefix on every field. Tag ordering is fixed and must not be reordered;
/// doing so changes the hash and requires a version bump.
///
/// The payload begins with a fixed header (`"occurrence_canonical\0"` +
/// version byte) followed by tagged fields in this order: flags, object,
/// rule_fingerprint, secret_hash, span, root_hint, variant.
fn encode_occurrence_canonical(
    out: &mut Vec<u8>,
    object_key: &[u8],
    rule_fingerprint: &RuleFingerprint,
    secret_hash: &SecretHash,
    finding: &CanonicalFinding,
) {
    out.clear();
    out.extend_from_slice(b"occurrence_canonical");
    out.push(0);
    out.push(IDENTITY_CONTRACT_VERSION);

    push_tag(out, b"flags");
    push_u32_le(out, finding.flags.bits());

    push_tag(out, b"object");
    push_bytes_u32(out, object_key);

    push_tag(out, b"rule_fingerprint");
    out.extend_from_slice(rule_fingerprint);

    push_tag(out, b"secret_hash");
    out.extend_from_slice(secret_hash);

    push_tag(out, b"span");
    push_u32_le(out, finding.span_start);
    push_u32_le(out, finding.span_end);

    push_tag(out, b"root_hint");
    push_u64_le(out, finding.root_hint_start);
    push_u64_le(out, finding.root_hint_end);

    push_tag(out, b"variant");
    out.push(finding.variant as u8);
}

/// Domain-separated BLAKE3 keyed hash: `H_key(domain ‖ 0x00 ‖ payload)`.
///
/// The NUL byte between domain and payload prevents ambiguity when a domain
/// string is a prefix of another (e.g. `"foo"` vs `"foobar"`). Because BLAKE3
/// keyed mode accepts exactly 32-byte keys and provides PRF security, this
/// construction gives collision resistance across all `(domain, payload)` pairs
/// under the same key.
fn keyed_hash(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn push_tag(out: &mut Vec<u8>, tag: &[u8]) {
    out.extend_from_slice(tag);
    out.push(0);
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(
        bytes.len() <= u32::MAX as usize,
        "object key too large for canonical encoding: {}",
        bytes.len()
    );
    push_u32_le(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{FileId, ValidatorKind};
    use crate::store::keys::{
        CorrelationMode, KeySource, RunModeMetadata, StoreKeys, STORE_KEYS_VERSION,
    };
    use regex::bytes::Regex;

    #[derive(Clone)]
    struct OccurrenceCase {
        object_key: Vec<u8>,
        finding: FindingRec,
        rule_fingerprint: RuleFingerprint,
        secret_hash: SecretHash,
        variant: VariantDiscriminant,
    }

    fn test_keys() -> StoreKeys {
        StoreKeys::from_test_root_key(
            [0x5A; 32],
            RunModeMetadata {
                version: STORE_KEYS_VERSION,
                correlation_mode: CorrelationMode::Persistent,
                key_source: KeySource::EnvVar,
            },
        )
    }

    fn rule(name: &'static str, pattern: &str, anchors: &'static [&'static [u8]]) -> RuleSpec {
        RuleSpec {
            name,
            anchors,
            radius: 32,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            local_context: None,
            secret_group: None,
            re: Regex::new(pattern).expect("regex must compile"),
        }
    }

    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed
    }

    fn rand_arr(seed: &mut u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_exact_mut(8) {
            chunk.copy_from_slice(&lcg(seed).to_le_bytes());
        }
        out
    }

    fn collect_ids(cases: &[OccurrenceCase], keys: &StoreKeys) -> Vec<OccurrenceId> {
        let mut out = Vec::with_capacity(cases.len());
        for case in cases {
            let id = occurrence_id(
                OccurrenceInput {
                    object_key: &case.object_key,
                    finding: &case.finding,
                    rule_fingerprint: &case.rule_fingerprint,
                    secret_hash: &case.secret_hash,
                    variant: case.variant,
                },
                keys,
            )
            .expect("case should be valid");
            out.push(id);
        }
        out
    }

    #[test]
    fn rule_fingerprint_is_deterministic() {
        let keys = test_keys();
        let r1 = rule("token", r"tok_[A-Z0-9]{8}", &[b"tok_"]);
        let r2 = rule("token", r"tok_[A-Z0-9]{8}", &[b"tok_"]);
        let r3 = rule("token", r"tok_[A-Z0-9]{9}", &[b"tok_"]);

        let fp1 = rule_fingerprint(&r1, &keys);
        let fp2 = rule_fingerprint(&r2, &keys);
        let fp3 = rule_fingerprint(&r3, &keys);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn secret_hash_is_keyed_over_norm_hash() {
        let keys = test_keys();
        let a = [0x11; 32];
        let b = [0x22; 32];

        let h1 = secret_hash(&a, &keys);
        let h2 = secret_hash(&a, &keys);
        let h3 = secret_hash(&b, &keys);

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn occurrence_id_normalizes_base64_padding_tail() {
        let keys = test_keys();
        let rule_fp = rand_arr(&mut 1);
        let secret = rand_arr(&mut 2);

        let finding_pad = FindingRec {
            file_id: FileId(7),
            rule_id: 12,
            span_start: 200,
            span_end: 213, // decoded len = 13, min encoded = 18
            root_hint_start: 1000,
            root_hint_end: 1020, // min + 2 (padding)
            dedupe_with_span: false,
            step_id: StepId(1),
        };
        let finding_min = FindingRec {
            root_hint_end: 1018, // min encoded
            ..finding_pad
        };

        let id_pad = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/main.rs",
                finding: &finding_pad,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");
        let id_min = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/main.rs",
                finding: &finding_min,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");

        assert_eq!(id_pad, id_min);
    }

    #[test]
    fn occurrence_id_distinguishes_utf16_variants() {
        let keys = test_keys();
        let rule_fp = rand_arr(&mut 3);
        let secret = rand_arr(&mut 4);
        let finding = FindingRec {
            file_id: FileId(11),
            rule_id: 77,
            span_start: 50,
            span_end: 66,
            root_hint_start: 400,
            root_hint_end: 424,
            dedupe_with_span: false,
            step_id: StepId(2),
        };

        let le = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/lib.rs",
                finding: &finding,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::Utf16Le,
            },
            &keys,
        )
        .expect("valid LE occurrence");
        let be = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/lib.rs",
                finding: &finding,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::Utf16Be,
            },
            &keys,
        )
        .expect("valid BE occurrence");

        assert_ne!(le, be);
    }

    #[test]
    fn occurrence_id_is_invariant_to_non_root_span_offset() {
        let keys = test_keys();
        let rule_fp = rand_arr(&mut 5);
        let secret = rand_arr(&mut 6);
        let finding_a = FindingRec {
            file_id: FileId(17),
            rule_id: 1,
            span_start: 100,
            span_end: 116,
            root_hint_start: 10_000,
            root_hint_end: 10_024,
            dedupe_with_span: false,
            step_id: StepId(3),
        };
        let finding_b = FindingRec {
            span_start: 900,
            span_end: 916,
            ..finding_a
        };

        let id_a = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/engine/scratch.rs",
                finding: &finding_a,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");
        let id_b = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/engine/scratch.rs",
                finding: &finding_b,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");

        assert_eq!(id_a, id_b);
    }

    #[test]
    fn occurrence_id_distinguishes_non_root_span_when_dedupe_with_span_true() {
        let keys = test_keys();
        let rule_fp = rand_arr(&mut 21);
        let secret = rand_arr(&mut 22);
        let finding_a = FindingRec {
            file_id: FileId(19),
            rule_id: 3,
            span_start: 100,
            span_end: 116,
            root_hint_start: 20_000,
            root_hint_end: 20_024,
            dedupe_with_span: true,
            step_id: StepId(4),
        };
        let finding_b = FindingRec {
            span_start: 900,
            span_end: 916,
            ..finding_a
        };

        let id_a = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/engine/stream_decode.rs",
                finding: &finding_a,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");
        let id_b = occurrence_id(
            OccurrenceInput {
                object_key: b"repo:src/engine/stream_decode.rs",
                finding: &finding_b,
                rule_fingerprint: &rule_fp,
                secret_hash: &secret,
                variant: VariantDiscriminant::None,
            },
            &keys,
        )
        .expect("valid occurrence");

        assert_ne!(id_a, id_b);
    }

    #[test]
    fn root_step_with_utf16_variant_is_rejected() {
        let keys = test_keys();
        let finding = FindingRec {
            file_id: FileId(2),
            rule_id: 9,
            span_start: 0,
            span_end: 8,
            root_hint_start: 0,
            root_hint_end: 8,
            dedupe_with_span: true,
            step_id: STEP_ROOT,
        };

        let err = occurrence_id(
            OccurrenceInput {
                object_key: b"obj",
                finding: &finding,
                rule_fingerprint: &[0x11; 32],
                secret_hash: &[0x22; 32],
                variant: VariantDiscriminant::Utf16Le,
            },
            &keys,
        )
        .expect_err("root variant must fail");

        assert!(matches!(
            err,
            IdentityError::RootStepHasVariant {
                variant: VariantDiscriminant::Utf16Le
            }
        ));
    }

    #[test]
    fn strict_flags_reject_unknown_bits() {
        let err = IdentityFlags::from_bits_strict(1 << 31).expect_err("unknown bits should fail");
        assert!(matches!(err, IdentityError::UnknownIdentityFlags { .. }));
    }

    #[test]
    fn occurrence_ids_are_stable_across_order_and_batch_partitions() {
        let keys = test_keys();
        let mut seed = 0x7f4a_3d91_55aa_u64;
        let mut cases = Vec::with_capacity(192);

        for i in 0..192usize {
            let root = (lcg(&mut seed) & 1) == 0;
            let span_start = (lcg(&mut seed) % 4096) as u32;
            let span_len = ((lcg(&mut seed) % 48) + 8) as u32;
            let span_end = span_start + span_len;
            let root_hint_start = lcg(&mut seed) % 100_000;
            let step_id = if root {
                STEP_ROOT
            } else {
                StepId(((i % 11) + 1) as u32)
            };
            let variant = if root {
                VariantDiscriminant::None
            } else {
                match lcg(&mut seed) % 3 {
                    0 => VariantDiscriminant::None,
                    1 => VariantDiscriminant::Utf16Le,
                    _ => VariantDiscriminant::Utf16Be,
                }
            };

            let root_hint_end = if root {
                root_hint_start + u64::from(span_len)
            } else {
                let min_encoded = (u64::from(span_len) * 4).div_ceil(3);
                let pad = lcg(&mut seed) % 4;
                root_hint_start + min_encoded + pad
            };

            cases.push(OccurrenceCase {
                object_key: format!("obj-{}", lcg(&mut seed) % 23).into_bytes(),
                finding: FindingRec {
                    file_id: FileId((lcg(&mut seed) % 31) as u32),
                    rule_id: (lcg(&mut seed) % 128) as u32,
                    span_start,
                    span_end,
                    root_hint_start,
                    root_hint_end,
                    dedupe_with_span: (lcg(&mut seed) & 1) == 1,
                    step_id,
                },
                rule_fingerprint: rand_arr(&mut seed),
                secret_hash: rand_arr(&mut seed),
                variant,
            });
        }

        let mut baseline = collect_ids(&cases, &keys);
        baseline.sort_unstable();

        // Deterministic shuffle and random partitioning.
        let mut shuffled = cases.clone();
        let mut perm_seed = 0x42u64;
        for i in (1..shuffled.len()).rev() {
            let j = (lcg(&mut perm_seed) as usize) % (i + 1);
            shuffled.swap(i, j);
        }

        let mut partitioned = Vec::with_capacity(shuffled.len());
        let mut idx = 0usize;
        while idx < shuffled.len() {
            let batch_len = ((lcg(&mut perm_seed) % 9) + 1) as usize;
            let end = (idx + batch_len).min(shuffled.len());
            partitioned.extend(collect_ids(&shuffled[idx..end], &keys));
            idx = end;
        }
        partitioned.sort_unstable();

        assert_eq!(baseline, partitioned);
    }
}
