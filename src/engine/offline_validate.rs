//! Offline structural validation for extracted secrets.
//!
//! Each validator runs a deterministic, network-free check on secret bytes
//! already extracted by the regex engine. The goal is to reject structurally
//! invalid tokens (likely false positives) before they reach the output sink.
//!
//! ## Supported token types
//!
//! - **CRC-32 + base-62** — generic parameterised validator (used by npm, PyPI, etc.)
//! - **GitHub fine-grained PAT** — `github_pat_` prefix with CRC-32/base-62 checksum
//! - **Grafana service-account** — `glsa_` prefix with CRC-32/hex checksum
//! - **AWS access key ID** — base-32-encoded account ID with range check
//! - **Sentry org-auth-token** — `sntrys_` prefix with base64 JSON payload check
//!
//! ## Design constraints
//!
//! - **No allocation in validator logic.** Decode buffers are stack-local
//!   (`[u8; N]`) so the hot path stays allocation-free.
//! - **Conservative verdicts.** When a token is too short or structurally
//!   ambiguous, return [`Indeterminate`](OfflineVerdict::Indeterminate)
//!   rather than [`Invalid`](OfflineVerdict::Invalid) to avoid suppressing
//!   legitimate findings.
//! - **No regex or I/O.** Validators work on the already-extracted `&[u8]`
//!   slice; they must not compile regexes, open files, or make network calls.

use crate::api::{OfflineValidationSpec, OfflineVerdict};

/// Dispatch an offline validation check for the given spec and secret bytes.
///
/// Called by the post-scan filter when a rule has an `offline_validation` gate.
/// Returns [`OfflineVerdict::Valid`], [`Invalid`](OfflineVerdict::Invalid),
/// or [`Indeterminate`](OfflineVerdict::Indeterminate).
pub(super) fn validate(spec: OfflineValidationSpec, secret: &[u8]) -> OfflineVerdict {
    match spec {
        OfflineValidationSpec::Crc32Base62 {
            prefix_skip,
            payload_len,
            checksum_len,
        } => validate_crc32_base62(secret, prefix_skip, payload_len, checksum_len),
        OfflineValidationSpec::GithubFinegrainedPat => validate_github_fine_grained_pat(secret),
        OfflineValidationSpec::GrafanaServiceAccount => validate_grafana_service_account(secret),
        OfflineValidationSpec::AwsAccessKey => validate_aws_access_key(secret),
        OfflineValidationSpec::SentryOrgToken => validate_sentry_org_token(secret),
    }
}

// ---------------------------------------------------------------------------
// Base-62 helpers
// ---------------------------------------------------------------------------

/// Base-62 alphabet: `0-9 A-Z a-z`.
const BASE62_CHARS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Branchless base-62 decode table. `0xFF` marks invalid characters.
const BASE62_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0';
        } else if b >= b'A' && b <= b'Z' {
            lut[i as usize] = b - b'A' + 10;
        } else if b >= b'a' && b <= b'z' {
            lut[i as usize] = b - b'a' + 36;
        }
        i += 1;
    }
    lut
};

/// Decode a single base-62 digit, returning `None` for invalid characters.
#[inline]
fn base62_digit(b: u8) -> Option<u32> {
    let v = BASE62_LUT[b as usize];
    if v == 0xFF {
        None
    } else {
        Some(v as u32)
    }
}

/// Decode a base-62 byte string into a `u32`, returning `None` on overflow
/// or invalid characters.
#[inline]
fn base62_decode_u32(bytes: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &b in bytes {
        let digit = base62_digit(b)?;
        acc = acc.checked_mul(62)?.checked_add(digit)?;
    }
    Some(acc)
}

/// Encode a `u32` into a fixed-width base-62 string, zero-padded on the left.
/// Writes exactly `buf.len()` bytes into `buf`; the caller sizes the buffer.
///
/// If `val` requires more base-62 digits than `buf.len()`, the high-order
/// digits are silently truncated. Callers must ensure the buffer is wide
/// enough (6 chars suffice for any `u32`).
fn base62_encode_u32(mut val: u32, buf: &mut [u8]) {
    for slot in buf.iter_mut().rev() {
        *slot = BASE62_CHARS[(val % 62) as usize];
        val /= 62;
    }
}

// ---------------------------------------------------------------------------
// CRC-32 + Base-62 (generic parameterised validator)
// ---------------------------------------------------------------------------

/// Validate a token using CRC-32 with base-62-encoded checksum.
///
/// Layout: `[prefix_skip bytes][payload_len bytes][checksum_len bytes]`.
/// The checksum is the base-62 encoding of `crc32(payload)`.
fn validate_crc32_base62(
    secret: &[u8],
    prefix_skip: u8,
    payload_len: u8,
    checksum_len: u8,
) -> OfflineVerdict {
    let skip = prefix_skip as usize;
    let plen = payload_len as usize;
    let clen = checksum_len as usize;
    let required = skip + plen + clen;

    if secret.len() < required {
        return OfflineVerdict::Indeterminate;
    }

    let payload = &secret[skip..skip + plen];
    let checksum_bytes = &secret[skip + plen..skip + plen + clen];

    let actual_crc = crc32fast::hash(payload);

    let decoded_crc = match base62_decode_u32(checksum_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

// ---------------------------------------------------------------------------
// GitHub fine-grained PAT
// ---------------------------------------------------------------------------

/// Literal prefix of a GitHub fine-grained personal access token.
const GH_PAT_PREFIX: &[u8] = b"github_pat_";
/// Total length of a GitHub fine-grained PAT: `github_pat_` (11) + 76 body + 6 checksum = 93.
const GH_PAT_TOTAL_LEN: usize = 93;
/// Trailing CRC-32 checksum encoded as 6 base-62 characters.
const GH_PAT_CHECKSUM_LEN: usize = 6;

/// Validate a GitHub fine-grained personal access token.
///
/// Format: `github_pat_<76 body chars><6 char CRC-32 base-62>` (93 bytes total).
/// The CRC-32 is computed over the first 87 bytes (everything before the checksum),
/// which **includes the `github_pat_` prefix** — unlike [`validate_crc32_base62`]
/// where the prefix is skipped before hashing.
fn validate_github_fine_grained_pat(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < GH_PAT_TOTAL_LEN {
        return OfflineVerdict::Indeterminate;
    }

    if !secret.starts_with(GH_PAT_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let data = &secret[..GH_PAT_TOTAL_LEN - GH_PAT_CHECKSUM_LEN];
    let checksum_bytes = &secret[GH_PAT_TOTAL_LEN - GH_PAT_CHECKSUM_LEN..GH_PAT_TOTAL_LEN];

    let actual_crc = crc32fast::hash(data);
    let decoded_crc = match base62_decode_u32(checksum_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

// ---------------------------------------------------------------------------
// Grafana service-account token
// ---------------------------------------------------------------------------

/// Literal prefix of a Grafana service-account token.
const GLSA_PREFIX: &[u8] = b"glsa_";
/// Minimum length: `glsa_` (5) + 32 random + `_` (1) + 8 hex = 46.
const GLSA_MIN_LEN: usize = 46;
/// Length of the alphanumeric random segment between the prefix and separator.
const GLSA_RANDOM_LEN: usize = 32;
/// CRC-32 encoded as 8 lowercase hex characters.
const GLSA_CHECKSUM_HEX_LEN: usize = 8;

/// Validate a Grafana service-account token.
///
/// Format: `glsa_<32 alphanumeric>_<8 hex CRC-32>`.
/// The CRC-32 is computed over `glsa_<32 chars>` (37 bytes) and hex-encoded
/// in lowercase in the trailing 8 characters.
fn validate_grafana_service_account(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < GLSA_MIN_LEN {
        return OfflineVerdict::Indeterminate;
    }

    if !secret.starts_with(GLSA_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let sep_pos = GLSA_PREFIX.len() + GLSA_RANDOM_LEN;
    if secret[sep_pos] != b'_' {
        return OfflineVerdict::Indeterminate;
    }

    // Data over which CRC is computed: `glsa_<32 chars>`.
    let data = &secret[..sep_pos];
    let hex_bytes = &secret[sep_pos + 1..sep_pos + 1 + GLSA_CHECKSUM_HEX_LEN];

    let actual_crc = crc32fast::hash(data);
    let decoded_crc = match hex_decode_u32(hex_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

/// Branchless hex decode table. `0xFF` marks invalid characters.
const HEX_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0';
        } else if b >= b'a' && b <= b'f' {
            lut[i as usize] = b - b'a' + 10;
        } else if b >= b'A' && b <= b'F' {
            lut[i as usize] = b - b'A' + 10;
        }
        i += 1;
    }
    lut
};

/// Decode an 8-byte hex string (case-insensitive) into a `u32`.
#[inline]
fn hex_decode_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 8 {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in bytes {
        let nibble = HEX_LUT[b as usize];
        if nibble == 0xFF {
            return None;
        }
        // 8 hex digits cannot overflow u32 (max = 0xFFFF_FFFF = u32::MAX).
        acc = (acc << 4) | nibble as u32;
    }
    Some(acc)
}

// ---------------------------------------------------------------------------
// AWS access key ID
// ---------------------------------------------------------------------------

/// Fixed length of an AWS access key ID (4-byte prefix + 16-byte base-32 suffix).
const AWS_KEY_LEN: usize = 20;

/// Validate an AWS access key ID.
///
/// Format: `(AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}` (20 bytes).
///
/// AWS key IDs encode an account number in a base-32–like scheme. This
/// validator checks:
/// 1. Length is exactly 20 bytes.
/// 2. Prefix matches a known type.
/// 3. Characters 4–19 are in `[A-Z2-7]` (the AWS base-32 alphabet).
/// 4. The decoded 10-byte suffix encodes a 40-bit account ID in the
///    expected range (≤ 999_999_999_999, i.e., 12 decimal digits).
fn validate_aws_access_key(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < AWS_KEY_LEN {
        return OfflineVerdict::Indeterminate;
    }

    let key = &secret[..AWS_KEY_LEN];

    // Validate known prefix.
    let valid_prefix = key.starts_with(b"AKIA")
        || key.starts_with(b"ASIA")
        || key.starts_with(b"ABIA")
        || key.starts_with(b"ACCA")
        || (key.starts_with(b"A3T") && (key[3].is_ascii_uppercase() || key[3].is_ascii_digit()));

    if !valid_prefix {
        return OfflineVerdict::Indeterminate;
    }

    // Decode the base-32 suffix to extract the embedded account ID. Invalid
    // charset bytes are treated as Invalid once the fixed length/prefix checks
    // have passed.
    let suffix = &key[4..];
    if !matches!(suffix[0], b'A'..=b'Z' | b'2'..=b'7') {
        return OfflineVerdict::Invalid;
    }

    // AWS encodes a 40-bit account number in bits [1..41] of the 80-bit decoded
    // value (16 base-32 chars = 80 bits). The account ID must be a valid AWS
    // account number (≤ 999_999_999_999).
    match decode_aws_account_id(suffix) {
        Some(id) if id <= 999_999_999_999 => OfflineVerdict::Valid,
        Some(_) => OfflineVerdict::Invalid,
        None => OfflineVerdict::Invalid,
    }
}

/// Decode a 16-char AWS base-32 suffix into the embedded account ID.
///
/// The 16 base-32 characters encode 80 bits (10 bytes). The account ID
/// occupies bits 1–40 (0-indexed from MSB, skipping the top flag bit),
/// which spans decoded bytes 0–5 (bit 1 of byte 0 through bit 0 of byte 5).
#[inline]
fn decode_aws_account_id(suffix: &[u8]) -> Option<u64> {
    if suffix.len() != 16 {
        return None;
    }

    // Decode base-32 chars into a single 80-bit value spread across 10 bytes.
    let mut decoded = [0u8; 10];
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut out_idx = 0;

    for &b in suffix {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u64,
            b'2'..=b'7' => (b - b'2') as u64 + 26,
            _ => return None,
        };
        bit_buf = (bit_buf << 5) | val;
        bits_in_buf += 5;

        while bits_in_buf >= 8 {
            bits_in_buf -= 8;
            decoded[out_idx] = (bit_buf >> bits_in_buf) as u8;
            bit_buf &= (1u64 << bits_in_buf) - 1;
            out_idx += 1;
        }
    }
    debug_assert_eq!(out_idx, decoded.len());

    // Account ID is in bits [1..41] from the MSB of the 80-bit value.
    // In byte terms: skip bit 0 of decoded[0], then take 40 bits.
    let raw_40 = ((decoded[0] as u64 & 0x7F) << 33)
        | ((decoded[1] as u64) << 25)
        | ((decoded[2] as u64) << 17)
        | ((decoded[3] as u64) << 9)
        | ((decoded[4] as u64) << 1)
        | ((decoded[5] as u64) >> 7);

    Some(raw_40)
}

// ---------------------------------------------------------------------------
// Sentry org-auth-token
// ---------------------------------------------------------------------------

/// Literal prefix of a Sentry org-auth-token.
const SENTRY_PREFIX: &[u8] = b"sntrys_";

/// Validate a Sentry org-auth-token.
///
/// Format: `sntrys_<base64-payload>_<43 base64 signature>`.
///
/// Validation:
/// 1. Starts with `sntrys_`.
/// 2. Contains a `_` separator between the payload and the 43-char signature.
/// 3. The base64 payload decodes successfully.
/// 4. The decoded payload starts with `{"iat":` (JSON with `iat` field).
fn validate_sentry_org_token(secret: &[u8]) -> OfflineVerdict {
    if !secret.starts_with(SENTRY_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let after_prefix = &secret[SENTRY_PREFIX.len()..];

    // Find the last `_` separator — everything after it is the 43-char signature.
    let sep_pos = match after_prefix.iter().rposition(|&b| b == b'_') {
        Some(p) => p,
        None => return OfflineVerdict::Indeterminate,
    };

    let sig_part = &after_prefix[sep_pos + 1..];
    if sig_part.len() < 43 {
        return OfflineVerdict::Indeterminate;
    }

    // Validate signature characters are base64.
    let sig_bytes = &sig_part[..43];
    if !sig_bytes.iter().all(|&b| is_base64_char(b)) {
        return OfflineVerdict::Invalid;
    }

    // The payload is between the prefix and the last `_`.
    let payload_b64 = &after_prefix[..sep_pos];
    if payload_b64.is_empty() {
        return OfflineVerdict::Indeterminate;
    }

    // Validate and decode in one pass while only checking the decoded prefix.
    // A 512-byte decoded cap preserves existing conservative behavior on
    // oversized payloads.
    match base64_decoded_starts_with(payload_b64, b"{\"iat\":", 512) {
        Ok(true) => OfflineVerdict::Valid,
        Ok(false) => OfflineVerdict::Invalid,
        Err(Base64DecodeError::InvalidChar) => OfflineVerdict::Invalid,
        Err(Base64DecodeError::OutputTooSmall) => OfflineVerdict::Indeterminate,
    }
}

/// Branchless base64 decode table. `0xFF` = invalid, `0xFE` = padding (`=`).
const BASE64_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'A' && b <= b'Z' {
            lut[i as usize] = b - b'A';
        } else if b >= b'a' && b <= b'z' {
            lut[i as usize] = b - b'a' + 26;
        } else if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0' + 52;
        } else if b == b'+' {
            lut[i as usize] = 62;
        } else if b == b'/' {
            lut[i as usize] = 63;
        } else if b == b'=' {
            lut[i as usize] = 0xFE; // padding sentinel
        }
        i += 1;
    }
    lut
};

/// Check if a byte is a valid base64 character (not padding).
#[inline]
fn is_base64_char(b: u8) -> bool {
    BASE64_LUT[b as usize] < 64
}

/// Reasons a base64-prefix check can fail.
///
/// The Sentry validator maps these to different verdicts:
/// `InvalidChar` → [`OfflineVerdict::Invalid`] (structurally broken),
/// `OutputTooSmall` → [`OfflineVerdict::Indeterminate`] (can't tell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base64DecodeError {
    /// Input contains a byte outside the base64 alphabet (not `[A-Za-z0-9+/=]`).
    InvalidChar,
    /// Estimated decoded size exceeds the caller-supplied cap.
    OutputTooSmall,
}

/// Minimal base64 decoder into a caller-provided buffer (no heap allocation).
///
/// Returns the number of decoded bytes, or `None` if the output buffer is
/// too small or the input contains characters outside the base64 alphabet.
#[inline]
fn base64_decode(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let max_decoded = input.len() * 3 / 4;
    if max_decoded > output.len() {
        return None;
    }

    let mut out_idx = 0;
    let mut buf: u32 = 0;
    let mut buf_bits: u32 = 0;

    for &b in input {
        let v = BASE64_LUT[b as usize];
        if v == 0xFE {
            continue; // padding
        }
        if v == 0xFF {
            return None;
        }
        let val = v as u32;
        buf = (buf << 6) | val;
        buf_bits += 6;

        if buf_bits >= 8 {
            buf_bits -= 8;
            if out_idx >= output.len() {
                return None;
            }
            output[out_idx] = (buf >> buf_bits) as u8;
            buf &= (1u32 << buf_bits) - 1;
            out_idx += 1;
        }
    }

    Some(out_idx)
}

/// Validate base64 input and check whether decoded bytes start with `prefix`.
///
/// Every input byte is checked against the base64 alphabet (invalid chars
/// return [`Base64DecodeError::InvalidChar`]), but actual decode work stops
/// once the prefix comparison concludes — either a mismatch or full match.
/// This avoids decoding the entire payload while still rejecting malformed
/// input.
#[inline]
fn base64_decoded_starts_with(
    input: &[u8],
    prefix: &[u8],
    max_decoded_bytes: usize,
) -> Result<bool, Base64DecodeError> {
    let max_decoded = input.len() * 3 / 4;
    if max_decoded > max_decoded_bytes {
        return Err(Base64DecodeError::OutputTooSmall);
    }

    let mut buf: u32 = 0;
    let mut buf_bits: u32 = 0;
    let mut prefix_idx = 0usize;
    let mut matches_prefix = true;
    let mut decode_prefix = !prefix.is_empty();

    for &b in input {
        let v = BASE64_LUT[b as usize];
        if v == 0xFE {
            continue; // padding
        }
        if v == 0xFF {
            return Err(Base64DecodeError::InvalidChar);
        }
        let val = v as u32;

        if !decode_prefix {
            continue;
        }

        buf = (buf << 6) | val;
        buf_bits += 6;

        while buf_bits >= 8 && decode_prefix {
            buf_bits -= 8;
            let decoded = (buf >> buf_bits) as u8;
            buf &= (1u32 << buf_bits) - 1;

            if decoded != prefix[prefix_idx] {
                matches_prefix = false;
                decode_prefix = false;
                break;
            }

            prefix_idx += 1;
            if prefix_idx == prefix.len() {
                decode_prefix = false;
            }
        }
    }

    if prefix_idx < prefix.len() {
        return Ok(false);
    }
    Ok(matches_prefix)
}

// ---------------------------------------------------------------------------
// Bench-only exports
// ---------------------------------------------------------------------------

/// Bench hook for AWS access-key offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_aws_access_key(secret: &[u8]) -> bool {
    matches!(validate_aws_access_key(secret), OfflineVerdict::Valid)
}

/// Bench hook for Sentry org-token offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_sentry_org_token(secret: &[u8]) -> bool {
    matches!(validate_sentry_org_token(secret), OfflineVerdict::Valid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Base-62 round-trip ----

    #[test]
    fn base62_encode_decode_round_trip() {
        let values = [0u32, 1, 61, 62, 3843, 999_999, u32::MAX];
        for &val in &values {
            let mut buf = [0u8; 6];
            base62_encode_u32(val, &mut buf);
            let decoded = base62_decode_u32(&buf).unwrap();
            assert_eq!(val, decoded, "round-trip failed for {val}");
        }
    }

    #[test]
    fn base62_decode_invalid_char() {
        assert_eq!(base62_decode_u32(b"abc!ef"), None);
    }

    #[test]
    fn base62_decode_overflow() {
        // 7 chars of 'z' (max digit = 61) overflows u32.
        assert_eq!(base62_decode_u32(b"zzzzzzz"), None);
    }

    // ---- Hex decode ----

    #[test]
    fn hex_decode_valid() {
        assert_eq!(hex_decode_u32(b"00000000"), Some(0));
        assert_eq!(hex_decode_u32(b"ffffffff"), Some(u32::MAX));
        assert_eq!(hex_decode_u32(b"DEADBEEF"), Some(0xDEADBEEF));
        assert_eq!(hex_decode_u32(b"0000007b"), Some(123));
    }

    #[test]
    fn hex_decode_wrong_length() {
        assert_eq!(hex_decode_u32(b"0000000"), None);
        assert_eq!(hex_decode_u32(b"000000000"), None);
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert_eq!(hex_decode_u32(b"0000000g"), None);
    }

    // ---- Base64 decode ----

    #[test]
    fn base64_decode_basic() {
        let mut buf = [0u8; 64];
        // "eyJpYXQiOg==" decodes to `{"iat":` (7 bytes).
        let input = b"eyJpYXQiOg==";
        let len = base64_decode(input, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"{\"iat\":");
    }

    #[test]
    fn base64_decode_no_padding() {
        let mut buf = [0u8; 64];
        // "QUJD" = "ABC"
        let len = base64_decode(b"QUJD", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"ABC");
    }

    #[test]
    fn base64_decode_invalid_char() {
        let mut buf = [0u8; 64];
        assert_eq!(base64_decode(b"QUJ!", &mut buf), None);
    }

    // ---- CRC-32 + Base-62 validator ----

    #[test]
    fn crc32_base62_valid_token() {
        // Construct a token: [prefix(4)][payload(10)][checksum(6)]
        let prefix = b"pfx_";
        let payload = b"helloworld";
        let crc = crc32fast::hash(payload);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);

        let mut token = Vec::new();
        token.extend_from_slice(prefix);
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, &token), OfflineVerdict::Valid);
    }

    #[test]
    fn crc32_base62_invalid_checksum() {
        let prefix = b"pfx_";
        let payload = b"helloworld";
        let mut checksum = [0u8; 6];
        base62_encode_u32(12345, &mut checksum); // wrong CRC

        let mut token = Vec::new();
        token.extend_from_slice(prefix);
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, &token), OfflineVerdict::Invalid);
    }

    #[test]
    fn crc32_base62_too_short() {
        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, b"short"), OfflineVerdict::Indeterminate);
    }

    // ---- GitHub fine-grained PAT ----

    #[test]
    fn github_pat_valid() {
        // Build a valid token: github_pat_ + 76 chars + 6 char CRC.
        let mut token = Vec::new();
        token.extend_from_slice(b"github_pat_");
        // 76 payload chars (type + underscore + random).
        let payload_filler: Vec<u8> = std::iter::repeat_n(b'A', 76).collect();
        token.extend_from_slice(&payload_filler);

        // CRC of everything so far (87 bytes).
        let crc = crc32fast::hash(&token);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);
        token.extend_from_slice(&checksum);

        assert_eq!(token.len(), 93);
        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn github_pat_invalid_checksum() {
        let mut token = Vec::new();
        token.extend_from_slice(b"github_pat_");
        let payload_filler: Vec<u8> = std::iter::repeat_n(b'A', 76).collect();
        token.extend_from_slice(&payload_filler);
        token.extend_from_slice(b"000000"); // wrong checksum

        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn github_pat_too_short() {
        assert_eq!(
            validate(
                OfflineValidationSpec::GithubFinegrainedPat,
                b"github_pat_short"
            ),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn github_pat_wrong_prefix() {
        let token = vec![b'X'; 93];
        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Indeterminate,
        );
    }

    // ---- Grafana service-account token ----

    #[test]
    fn grafana_valid() {
        let mut token = Vec::new();
        token.extend_from_slice(b"glsa_");
        let random: Vec<u8> = std::iter::repeat_n(b'a', 32).collect();
        token.extend_from_slice(&random);

        // CRC over `glsa_<32 chars>` (37 bytes).
        let crc = crc32fast::hash(&token);
        token.push(b'_');
        let hex = format!("{crc:08x}");
        token.extend_from_slice(hex.as_bytes());

        assert_eq!(token.len(), 46);
        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn grafana_invalid_checksum() {
        let mut token = Vec::new();
        token.extend_from_slice(b"glsa_");
        token.extend_from_slice(&[b'a'; 32]);
        token.push(b'_');
        token.extend_from_slice(b"deadbeef"); // wrong CRC

        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn grafana_too_short() {
        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, b"glsa_short"),
            OfflineVerdict::Indeterminate,
        );
    }

    // ---- AWS access key ----

    #[test]
    fn aws_valid_charset() {
        // AKIA followed by 16 chars from [A-Z2-7].
        let key = b"AKIAIOSFODNN7EXAMPLE";
        assert_eq!(key.len(), 20);
        let verdict = validate(OfflineValidationSpec::AwsAccessKey, key);
        // Valid structure — account ID check may yield Valid or Indeterminate.
        assert_ne!(verdict, OfflineVerdict::Invalid);
    }

    #[test]
    fn aws_invalid_charset() {
        // lowercase letters are not in [A-Z2-7].
        let key = b"AKIAiosfodnn7example";
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, key),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn aws_too_short() {
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, b"AKIA1234"),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn aws_unknown_prefix() {
        let key = b"XXXX1234567890123456";
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, key),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn aws_a3t_prefix_valid() {
        // A3T followed by uppercase letter, then 16 chars from [A-Z2-7].
        let key = b"A3TXABCDEFGHIJKLMNOP";
        assert_eq!(key.len(), 20);
        let verdict = validate(OfflineValidationSpec::AwsAccessKey, key);
        assert_ne!(verdict, OfflineVerdict::Invalid);
    }

    // ---- Sentry org token ----

    #[test]
    fn sentry_valid_structure() {
        // Build: sntrys_<base64 of {"iat":...}>_<43 base64 chars>
        let payload_json = b"{\"iat\":1234567890,\"region_url\":\"https://sentry.io\"}";
        // Base64-encode the payload.
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload_json, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        // 43-char base64 signature.
        let sig: Vec<u8> = std::iter::repeat_n(b'A', 43).collect();
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn sentry_invalid_payload() {
        // Payload decodes to something not starting with {"iat":
        let payload = b"not_json_at_all_here";
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        let sig: Vec<u8> = std::iter::repeat_n(b'A', 43).collect();
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn sentry_invalid_payload_char() {
        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_eyJpYXQiO@==_");
        token.extend_from_slice(&[b'A'; 43]);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn sentry_too_short() {
        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, b"sntrys_"),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn sentry_wrong_prefix() {
        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, b"sntryu_abc"),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn sentry_no_separator() {
        // No underscore after prefix — payload has no signature separator.
        let token = b"sntrys_eyJpYXQiOjEyMzR9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, token),
            OfflineVerdict::Indeterminate,
        );
    }

    // ---- Dispatcher ----

    #[test]
    fn dispatch_crc32_base62() {
        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 0,
            payload_len: 3,
            checksum_len: 6,
        };
        let payload = b"abc";
        let crc = crc32fast::hash(payload);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);

        let mut token = Vec::new();
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        assert_eq!(validate(spec, &token), OfflineVerdict::Valid);
    }

    // ---- Test-only helper ----

    /// Minimal base64 encoder for constructing test vectors.
    fn base64_encode_for_test(input: &[u8], output: &mut Vec<u8>) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut i = 0;
        while i + 2 < input.len() {
            let n =
                ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(ALPHABET[((n >> 6) & 63) as usize]);
            output.push(ALPHABET[(n & 63) as usize]);
            i += 3;
        }

        let remaining = input.len() - i;
        if remaining == 2 {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(ALPHABET[((n >> 6) & 63) as usize]);
            output.push(b'=');
        } else if remaining == 1 {
            let n = (input[i] as u32) << 16;
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(b'=');
            output.push(b'=');
        }
    }
}
