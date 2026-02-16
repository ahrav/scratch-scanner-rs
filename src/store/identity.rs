//! Persistence identity contracts.
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
//! 2. Feed the payload through a domain-separated BLAKE3 hash — `keyed_hash`
//!    for `secret_hash` and `occurrence_id`, or `unkeyed_hash` for
//!    `rule_fingerprint` (which must be comparable across operators).
//!
//! Domain separation (a NUL-terminated domain string prepended to the payload)
//! ensures that identical byte payloads used in different contexts produce
//! distinct hashes, preventing cross-contract collisions.
//!
//! `occurrence_id` additionally normalizes its inputs before hashing to absorb
//! benign variation that the engine's existing dedupe logic already collapses:
//! - **Root-hint end normalization**: base64 padding (up to 2 trailing `=`
//!   characters, inflating the encoded region by up to 2 bytes) causes the
//!   encoded-region length to vary for identical decoded content;
//!   `normalize_root_hint_end` snaps the end offset to the padding-free minimum
//!   so both padded and unpadded encodings hash identically. This normalization
//!   only applies to `Base64` transforms; other transforms (e.g. `UrlPercent`)
//!   preserve length exactly and are left unchanged.
//! - **Non-root span erasure**: for transform-derived findings, the decoded-buffer
//!   span is unstable across chunk boundaries, so it is zeroed out; only the
//!   root-hint window participates in identity.
//!
//! # Versioning
//!
//! [`IDENTITY_CONTRACT_VERSION`] is embedded in every canonical payload. Changing
//! any encoding detail requires bumping this version so that old and new hashes
//! never collide silently.

use crate::api::{FindingRec, RuleSpec, StepId, TransformId, STEP_ROOT};

use super::keys::StoreKeys;

/// Identity contract version shared by all encodings in this module.
///
/// Embedded as the first metadata byte in the occurrence canonical payload.
/// Any change to field ordering, normalization logic, or domain strings
/// requires bumping this version so that hashes produced under different
/// contracts never collide.
pub const IDENTITY_CONTRACT_VERSION: u8 = 1;

// Domain-separation strings for BLAKE3 keyed/unkeyed hashes.
// Each domain is prepended (with a NUL terminator) to the payload before
// hashing, ensuring that identical byte payloads used in different contexts
// produce distinct digests. Changing any string is a contract-breaking change.
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

    /// Derives flags from `(step_id, include_span, variant, normalized)`,
    /// enforcing structural invariants:
    ///
    /// - Root findings (`STEP_ROOT`) set `ROOT_STEP`; callers are expected to
    ///   pass `include_span = true` for root findings.
    /// - `ROOT_HINT_END_NORMALIZED` is set when `normalized` is true (i.e., the
    ///   finding is a Base64 non-root finding that went through padding normalization).
    /// - Span inclusion follows engine dedupe semantics (`dedupe_with_span`):
    ///   included when root-span mapping is unavailable, excluded otherwise.
    /// - A root finding with a UTF-16 variant is rejected as a caller bug.
    fn from_parts(
        step_id: StepId,
        include_span: bool,
        variant: VariantDiscriminant,
        normalized: bool,
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
        if normalized {
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
    /// Object key exceeds the `u32::MAX` length limit for canonical encoding.
    ObjectKeyTooLarge { len: usize },
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
            Self::ObjectKeyTooLarge { len } => {
                write!(
                    f,
                    "object key too large for canonical encoding: {len} bytes (max {})",
                    u32::MAX
                )
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
    /// The leaf transform that produced this finding, if any.
    ///
    /// Used to gate root-hint normalization: only `Base64` findings have
    /// padding-induced length variation that needs snapping. Other transforms
    /// (e.g. `UrlPercent`) preserve length exactly and must not be normalized.
    ///
    /// `None` means the finding is from the root buffer (no transform) **or**
    /// the caller does not know the transform. In either case normalization
    /// is skipped, which is safe: root findings bypass normalization by
    /// design, and unknown-transform findings produce a conservative
    /// (non-snapped) identity.
    pub leaf_transform: Option<TransformId>,
}

/// Maximum bytes of secret content fed to the hash function.
///
/// Secrets larger than this are truncated to a prefix/suffix hash to bound
/// memory and CPU. 64 KiB is generous for any realistic secret value.
pub const MAX_SECRET_HASH_BYTES: usize = 64 * 1024;

/// Secret length bucket thresholds (in bytes).
const SECRET_LEN_SHORT_MAX: usize = 64;
const SECRET_LEN_MEDIUM_MAX: usize = 512;

/// Coarse length bucket for the secret value.
///
/// Used in the `secrets` table to enable approximate length filtering without
/// storing the actual secret content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecretLenBucket {
    /// Length unknown or not applicable.
    Unknown = 0,
    /// Short secret (≤ 64 bytes).
    Short = 1,
    /// Medium secret (65–512 bytes).
    Medium = 2,
    /// Long secret (> 512 bytes).
    Long = 3,
}

impl SecretLenBucket {
    /// Classify a secret by its byte length.
    #[must_use]
    pub const fn from_len(len: usize) -> Self {
        if len <= SECRET_LEN_SHORT_MAX {
            Self::Short
        } else if len <= SECRET_LEN_MEDIUM_MAX {
            Self::Medium
        } else {
            Self::Long
        }
    }
}

/// Compute canonical rule fingerprint from `RuleSpec::encode_policy` bytes.
///
/// **Always unkeyed** regardless of [`IdHashMode`](super::keys::IdHashMode) —
/// rules are stable policy definitions that must be comparable across operators.
#[must_use]
pub fn rule_fingerprint(rule: &RuleSpec, _keys: &StoreKeys) -> RuleFingerprint {
    let mut policy_bytes = Vec::with_capacity(256);
    rule.encode_policy(&mut policy_bytes);
    unkeyed_hash(RULE_FINGERPRINT_DOMAIN, &policy_bytes)
}

/// Compute keyed secret hash over existing engine `norm_hash` bytes.
///
/// **Always keyed** regardless of [`IdHashMode`](super::keys::IdHashMode) —
/// prevents rainbow-table attacks against secret hashes stored on disk.
#[must_use]
pub fn secret_hash(norm_hash: &[u8; 32], keys: &StoreKeys) -> SecretHash {
    keyed_hash(keys.secret_key(), SECRET_HASH_DOMAIN, norm_hash)
}

/// Compute keyed secret hash with optional truncation for oversized secrets.
///
/// For secrets ≤ [`MAX_SECRET_HASH_BYTES`], hashes all bytes.
/// For oversized secrets, hashes a `prefix(32 KiB) ‖ length ‖ suffix(32 KiB)`
/// window. Using both prefix and suffix (rather than prefix alone) ensures
/// that changes near either end of the secret are reflected in the hash,
/// while the interleaved length prevents collisions between secrets whose
/// prefix+suffix bytes happen to match but whose total lengths differ.
#[must_use]
pub fn secret_hash_with_truncation(secret_bytes: &[u8], keys: &StoreKeys) -> SecretHash {
    if secret_bytes.len() <= MAX_SECRET_HASH_BYTES {
        let norm = blake3::hash(secret_bytes);
        return keyed_hash(keys.secret_key(), SECRET_HASH_DOMAIN, norm.as_bytes());
    }
    // For oversized: hash(prefix(32K) ‖ length ‖ suffix(32K))
    let half = MAX_SECRET_HASH_BYTES / 2;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&secret_bytes[..half]);
    hasher.update(&(secret_bytes.len() as u64).to_le_bytes());
    hasher.update(&secret_bytes[secret_bytes.len() - half..]);
    let norm = hasher.finalize();
    keyed_hash(keys.secret_key(), SECRET_HASH_DOMAIN, norm.as_bytes())
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
///
/// The hash is keyed or unkeyed based on [`IdHashMode`](super::keys::IdHashMode).
pub fn occurrence_id(
    input: OccurrenceInput<'_>,
    keys: &StoreKeys,
) -> Result<OccurrenceId, IdentityError> {
    let canonical = canonicalize_finding(input.finding, input.variant, input.leaf_transform)?;
    let mut payload = Vec::with_capacity(256 + input.object_key.len());
    encode_occurrence_canonical(
        &mut payload,
        input.object_key,
        input.rule_fingerprint,
        input.secret_hash,
        &canonical,
    )?;
    Ok(keyed_hash(
        keys.effective_identity_key(),
        OCCURRENCE_ID_DOMAIN,
        &payload,
    ))
}

/// Normalized snapshot of the identity-relevant fields from a [`FindingRec`].
///
/// This intermediate separates normalization (which may fail) from encoding,
/// keeping each step testable in isolation.
/// Fields that do not participate in identity for a given finding class are
/// zeroed during construction (e.g. `span_start`/`span_end` for non-root).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CanonicalFinding {
    flags: IdentityFlags,
    /// Decoded-buffer span; zero for non-root findings unless `dedupe_with_span`
    /// is set (unstable across chunks otherwise).
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    /// May have been snapped by [`normalize_root_hint_end`] for non-root findings.
    root_hint_end: u64,
    variant: VariantDiscriminant,
}

/// Normalize a [`FindingRec`] into identity-canonical form.
///
/// Three normalizations are applied:
/// 1. **Span inclusion policy**: root findings always include span; non-root
///    findings include span only when `dedupe_with_span` is set (meaning
///    root-span mapping is unavailable and the decoded-buffer span is the
///    only distinguishing coordinate).
/// 2. **Non-root span erasure**: when span is excluded, `span_start`/`span_end`
///    are zeroed so that chunk-alignment-induced offsets do not affect identity.
/// 3. **Root-hint-end snapping**: for non-root Base64 findings, `root_hint_end`
///    is snapped to the padding-free minimum encoded length.
fn canonicalize_finding(
    finding: &FindingRec,
    variant: VariantDiscriminant,
    leaf_transform: Option<TransformId>,
) -> Result<CanonicalFinding, IdentityError> {
    let root_hint_end = normalize_root_hint_end(finding, leaf_transform);
    // The flag signals "this finding went through the normalization path" (i.e.,
    // it's a Base64 non-root finding), not "the value actually changed". This
    // ensures that pre-normalized values (already at min_encoded) produce the same
    // flags as values that were snapped, so both hash identically.
    let normalized = finding.step_id != STEP_ROOT && leaf_transform == Some(TransformId::Base64);
    let include_span = finding.dedupe_with_span || finding.step_id == STEP_ROOT;
    let (span_start, span_end) = if include_span {
        (finding.span_start, finding.span_end)
    } else {
        (0, 0)
    };
    let flags = IdentityFlags::from_parts(finding.step_id, include_span, variant, normalized)?;

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
/// is not a multiple of 3, the encoder appends 1–2 `=` padding characters.
/// Different base64 implementations (or the same implementation across
/// versions) may or may not include the padding, causing `root_hint_end` to
/// vary by up to 2 bytes for identical decoded content.
///
/// # Solution
///
/// For non-root findings, compute the minimum encoded length that could
/// represent the decoded span (`ceil(decoded_len * 4 / 3)`). If the actual
/// encoded region length exceeds this minimum by 1–2 bytes — exactly the
/// padding window — snap `root_hint_end` back to the minimum. Differences
/// outside this window are left untouched because they indicate a genuinely
/// different encoded region, not mere padding variation.
///
/// Root findings are returned unchanged because their spans are authoritative.
fn normalize_root_hint_end(finding: &FindingRec, leaf_transform: Option<TransformId>) -> u64 {
    if finding.step_id == STEP_ROOT {
        return finding.root_hint_end;
    }

    // Only Base64 has 4/3 padding rules; other transforms must not normalize.
    if leaf_transform != Some(TransformId::Base64) {
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
) -> Result<(), IdentityError> {
    out.clear();
    out.extend_from_slice(b"occurrence_canonical");
    out.push(0);
    out.push(IDENTITY_CONTRACT_VERSION);

    push_tag(out, b"flags");
    push_u32_le(out, finding.flags.bits());

    push_tag(out, b"object");
    push_bytes_u32(out, object_key)?;

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
    Ok(())
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

/// Domain-separated BLAKE3 **unkeyed** hash: `H(domain ‖ 0x00 ‖ payload)`.
///
/// Used for rule fingerprints where operator-independence is required.
fn unkeyed_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
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

/// Append a length-prefixed byte slice: `LE32(len) ‖ bytes`.
///
/// Fails if `bytes.len()` exceeds `u32::MAX`, which would corrupt the
/// canonical payload's fixed-width length field.
fn push_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IdentityError> {
    if bytes.len() > u32::MAX as usize {
        return Err(IdentityError::ObjectKeyTooLarge { len: bytes.len() });
    }
    push_u32_le(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::api::{FileId, StepId, STEP_ROOT};

    /// For all u16 values cast to u32, `from_bits_strict` accepts iff no unknown
    /// bits are set AND bits 8 and 9 are not both set.
    #[kani::proof]
    fn kani_from_bits_strict_accepts_iff_valid() {
        let raw: u16 = kani::any();
        let bits = raw as u32;

        let known_mask = (1u32 << 0) | (1 << 1) | (1 << 2) | (1 << 8) | (1 << 9);
        let has_unknown = (bits & !known_mask) != 0;
        let has_both_utf16 = (bits & (1 << 8) != 0) && (bits & (1 << 9) != 0);

        let result = IdentityFlags::from_bits_strict(bits);
        if has_unknown {
            kani::assert(
                matches!(result, Err(IdentityError::UnknownIdentityFlags { .. })),
                "unknown bits must be rejected",
            );
        } else if has_both_utf16 {
            kani::assert(
                matches!(result, Err(IdentityError::ConflictingUtf16Flags { .. })),
                "conflicting UTF-16 must be rejected",
            );
        } else {
            kani::assert(result.is_ok(), "valid bits must be accepted");
            if let Ok(flags) = result {
                kani::assert(flags.bits() == bits, "round-trip bits must match");
            }
        }
    }

    /// Bounded symbolic inputs to `normalize_root_hint_end` never cause panic.
    #[kani::proof]
    fn kani_normalize_root_hint_end_no_panic() {
        let span_start: u32 = kani::any();
        let span_end: u32 = kani::any();
        let root_hint_start: u64 = kani::any();
        let root_hint_end: u64 = kani::any();
        let is_root: bool = kani::any();

        // Bound the search space to keep verification tractable.
        kani::assume(span_start <= 4096);
        kani::assume(span_end <= 4096);
        kani::assume(root_hint_start <= 100_000);
        kani::assume(root_hint_end <= 100_100);

        let step_id = if is_root { STEP_ROOT } else { StepId(1) };

        let finding = FindingRec {
            file_id: FileId(0),
            rule_id: 0,
            span_start,
            span_end,
            root_hint_start,
            root_hint_end,
            dedupe_with_span: false,
            step_id,
        };

        let leaf_transform = if is_root {
            None
        } else {
            Some(TransformId::Base64)
        };

        // Must not panic.
        let _ = normalize_root_hint_end(&finding, leaf_transform);
    }
}
