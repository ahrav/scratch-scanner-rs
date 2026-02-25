//! Token family definitions and deterministic valid-token generators.
//!
//! Each `TokenFamily` variant knows how to generate a structurally valid token
//! for a specific secret format and which mutation operators are applicable.
//! Format details are verified against `engine/offline_validate.rs` and
//! `default_rules.yaml` (see plan for references).

use serde::{Deserialize, Serialize};

use super::encode::{
    base62_encode_u32, base64_encode_std, base64url_encode_nopad, percent_encode_all, BASE62_CHARS,
};
use super::op::{MutOp, MutOpKind};
use super::plan::Outcome;
use crate::sim::rng::SimRng;

/// AWS base-32 alphabet: A-Z (0–25) then 2-7 (26–31).
const AWS_BASE32_CHARS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Token family describing a specific secret format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenFamily {
    /// AKIA + 16 chars from [A-Z2-7] = 20 bytes total.
    AwsAccessKey,
    /// github_pat_ + 76 body + 6 CRC = 93 bytes total.
    GithubFinegrainedPat,
    /// ghp_ + 30 body + 6 CRC = 40 bytes total.
    GithubClassicPat,
    /// eyJ<b64url header>.eyJ<b64url payload>.<b64url sig>
    JwtLike,
    /// base64_encode_std(24–48 random bytes)
    Base64Blob,
    /// percent_encode_all(16–32 random bytes)
    UrlEncodedBlob,
}

impl TokenFamily {
    /// Generate a deterministically valid token for this family.
    pub fn gen_valid(&self, rng: &mut SimRng) -> Vec<u8> {
        match self {
            TokenFamily::AwsAccessKey => gen_aws_access_key(rng),
            TokenFamily::GithubFinegrainedPat => gen_github_fine_grained_pat(rng),
            TokenFamily::GithubClassicPat => gen_github_classic_pat(rng),
            TokenFamily::JwtLike => gen_jwt_like(rng),
            TokenFamily::Base64Blob => gen_base64_blob(rng),
            TokenFamily::UrlEncodedBlob => gen_url_encoded_blob(rng),
        }
    }

    /// Which mutation operator kinds are valid for this family.
    pub fn allowed_ops(&self) -> &'static [MutOpKind] {
        use MutOpKind::*;
        match self {
            TokenFamily::AwsAccessKey => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::GithubFinegrainedPat | TokenFamily::GithubClassicPat => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                ChecksumCorrupt,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::JwtLike => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::Base64Blob | TokenFamily::UrlEncodedBlob => {
                &[Truncate, CharsetViolate, EntropyReduce, Encode, Extend]
            }
        }
    }

    /// Expected detection result after applying the given mutations.
    ///
    /// Receives the canonical (pre-mutation) token so variable-length families
    /// can reason about length-dependent operators like Truncate.
    pub fn expectation(&self, canonical: &[u8], ops: &[MutOp]) -> Outcome {
        if ops.is_empty() {
            return Outcome::MustMatch;
        }

        for op in ops {
            match op {
                MutOp::Truncate { len } if *len < canonical.len() => {
                    return Outcome::MustNotMatch;
                }
                MutOp::CharsetViolate { positions, .. } => {
                    if positions.iter().any(|&p| p < canonical.len()) {
                        return Outcome::MustNotMatch;
                    }
                }
                MutOp::PrefixMangle { .. } => return Outcome::MustNotMatch,
                MutOp::ChecksumCorrupt => {
                    return match self {
                        TokenFamily::GithubFinegrainedPat | TokenFamily::GithubClassicPat => {
                            Outcome::MustNotMatch
                        }
                        _ => Outcome::MayMatch,
                    };
                }
                MutOp::EntropyReduce { count, .. } if *count > 0 => {
                    return Outcome::MayMatch;
                }
                MutOp::Encode { .. } => return Outcome::MayMatch,
                MutOp::Extend { suffix } if !suffix.is_empty() => {
                    return Outcome::MayMatch;
                }
                _ => {}
            }
        }

        Outcome::MustMatch
    }
}

// ---------------------------------------------------------------------------
// Per-family generators
// ---------------------------------------------------------------------------

/// AKIA + 16 random chars from [A-Z2-7].
fn gen_aws_access_key(rng: &mut SimRng) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(b"AKIA");
    for _ in 0..16 {
        let idx = rng.gen_range(0, 32) as usize;
        out.push(AWS_BASE32_CHARS[idx]);
    }
    out
}

/// github_pat_ + 76 random base-62 chars + CRC-32 of first 87 bytes as 6 base-62 chars.
fn gen_github_fine_grained_pat(rng: &mut SimRng) -> Vec<u8> {
    let mut out = Vec::with_capacity(93);
    out.extend_from_slice(b"github_pat_");
    // 76 random base-62 body chars
    for _ in 0..76 {
        let idx = rng.gen_range(0, 62) as usize;
        out.push(BASE62_CHARS[idx]);
    }
    debug_assert_eq!(out.len(), 87);
    // CRC-32 of first 87 bytes (prefix included)
    let crc = crc32fast::hash(&out[..87]);
    let mut cksum = [0u8; 6];
    base62_encode_u32(crc, &mut cksum);
    out.extend_from_slice(&cksum);
    debug_assert_eq!(out.len(), 93);
    out
}

/// ghp_ + 30 random base-62 chars + CRC-32 of payload (bytes 4–33) as 6 base-62 chars.
fn gen_github_classic_pat(rng: &mut SimRng) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(b"ghp_");
    // 30 random base-62 payload chars
    for _ in 0..30 {
        let idx = rng.gen_range(0, 62) as usize;
        out.push(BASE62_CHARS[idx]);
    }
    debug_assert_eq!(out.len(), 34);
    // CRC-32 of payload only (prefix excluded)
    let crc = crc32fast::hash(&out[4..34]);
    let mut cksum = [0u8; 6];
    base62_encode_u32(crc, &mut cksum);
    out.extend_from_slice(&cksum);
    debug_assert_eq!(out.len(), 40);
    out
}

/// JWT: header.payload.signature (three base64url-encoded segments).
fn gen_jwt_like(rng: &mut SimRng) -> Vec<u8> {
    // Fixed header: {"alg":"HS256"}
    let header = base64url_encode_nopad(b"{\"alg\":\"HS256\"}");

    // Payload: {"sub":"<8 random alnum>"} — starts with eyJ
    let mut sub = [0u8; 8];
    for b in sub.iter_mut() {
        let idx = rng.gen_range(0, 36);
        *b = if idx < 10 {
            b'0' + idx as u8
        } else {
            b'a' + (idx - 10) as u8
        };
    }
    let mut payload_json = Vec::with_capacity(16 + sub.len());
    payload_json.extend_from_slice(b"{\"sub\":\"");
    payload_json.extend_from_slice(&sub);
    payload_json.extend_from_slice(b"\"}");
    let payload = base64url_encode_nopad(&payload_json);

    // Signature: 32 random bytes, base64url-encoded
    let mut sig_raw = [0u8; 32];
    for b in sig_raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    let signature = base64url_encode_nopad(&sig_raw);

    // Assemble: header.payload.signature
    let mut out = Vec::with_capacity(header.len() + 1 + payload.len() + 1 + signature.len());
    out.extend_from_slice(&header);
    out.push(b'.');
    out.extend_from_slice(&payload);
    out.push(b'.');
    out.extend_from_slice(&signature);
    out
}

/// base64(24–48 random bytes).
fn gen_base64_blob(rng: &mut SimRng) -> Vec<u8> {
    let len = rng.gen_range(24, 49) as usize;
    let mut raw = vec![0u8; len];
    for b in raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    base64_encode_std(&raw)
}

/// percent_encode_all(16–32 random bytes).
fn gen_url_encoded_blob(rng: &mut SimRng) -> Vec<u8> {
    let len = rng.gen_range(16, 33) as usize;
    let mut raw = vec![0u8; len];
    for b in raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    percent_encode_all(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::rng::SimRng;

    #[test]
    fn determinism_all_families() {
        let families = [
            TokenFamily::AwsAccessKey,
            TokenFamily::GithubFinegrainedPat,
            TokenFamily::GithubClassicPat,
            TokenFamily::JwtLike,
            TokenFamily::Base64Blob,
            TokenFamily::UrlEncodedBlob,
        ];
        for family in families {
            let a = family.gen_valid(&mut SimRng::new(42));
            let b = family.gen_valid(&mut SimRng::new(42));
            assert_eq!(a, b, "determinism failed for {family:?}");
        }
    }

    #[test]
    fn aws_access_key_format() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(99));
        assert_eq!(token.len(), 20);
        assert!(token.starts_with(b"AKIA"));
        for &b in &token[4..] {
            assert!(
                b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b),
                "invalid AWS base-32 char: {b:#x}",
            );
        }
    }

    #[test]
    fn github_fine_grained_pat_format_and_checksum() {
        let token = TokenFamily::GithubFinegrainedPat.gen_valid(&mut SimRng::new(7));
        assert_eq!(token.len(), 93);
        assert!(token.starts_with(b"github_pat_"));
        // Verify CRC: hash first 87 bytes, decode last 6.
        let expected_crc = crc32fast::hash(&token[..87]);
        let decoded_crc = base62_decode_test(&token[87..93]);
        assert_eq!(expected_crc, decoded_crc, "CRC-32 mismatch");
    }

    #[test]
    fn github_classic_pat_format_and_checksum() {
        let token = TokenFamily::GithubClassicPat.gen_valid(&mut SimRng::new(13));
        assert_eq!(token.len(), 40);
        assert!(token.starts_with(b"ghp_"));
        // CRC of payload only (bytes 4–33)
        let expected_crc = crc32fast::hash(&token[4..34]);
        let decoded_crc = base62_decode_test(&token[34..40]);
        assert_eq!(expected_crc, decoded_crc, "CRC-32 mismatch");
    }

    #[test]
    fn jwt_like_format() {
        let token = TokenFamily::JwtLike.gen_valid(&mut SimRng::new(21));
        let parts: Vec<&[u8]> = token.split(|&b| b == b'.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated segments");
        // Header starts with eyJ (base64url of '{"')
        assert!(parts[0].starts_with(b"eyJ"), "header must start with eyJ");
        // Payload starts with eyJ
        assert!(parts[1].starts_with(b"eyJ"), "payload must start with eyJ");
        // No padding chars
        assert!(!token.contains(&b'='), "JWT must not contain padding");
        assert!(!token.contains(&b'+'), "JWT must use - not +");
        assert!(!token.contains(&b'/'), "JWT must use _ not /");
    }

    #[test]
    fn base64_blob_is_valid_base64() {
        let token = TokenFamily::Base64Blob.gen_valid(&mut SimRng::new(55));
        // Should be valid base64 (all chars in standard alphabet + =)
        for &b in &token {
            assert!(
                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
                "invalid base64 char: {b:#x}",
            );
        }
    }

    #[test]
    fn url_encoded_blob_format() {
        let token = TokenFamily::UrlEncodedBlob.gen_valid(&mut SimRng::new(77));
        // Must be %XX triples
        assert_eq!(
            token.len() % 3,
            0,
            "percent-encoded length must be multiple of 3"
        );
        for chunk in token.chunks(3) {
            assert_eq!(chunk[0], b'%');
            assert!(chunk[1].is_ascii_hexdigit());
            assert!(chunk[2].is_ascii_hexdigit());
        }
    }

    #[test]
    fn expectation_empty_ops_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &[]),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn expectation_checksum_corrupt_on_crc_family() {
        let token = TokenFamily::GithubClassicPat.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::GithubClassicPat.expectation(&token, &[MutOp::ChecksumCorrupt]),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn expectation_prefix_mangle_is_must_not_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(
                &token,
                &[MutOp::PrefixMangle {
                    replacement: b"XXXX".to_vec(),
                }]
            ),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn allowed_ops_excludes_checksum_for_aws() {
        let ops = TokenFamily::AwsAccessKey.allowed_ops();
        assert!(!ops.contains(&MutOpKind::ChecksumCorrupt));
    }

    #[test]
    fn allowed_ops_includes_checksum_for_github() {
        assert!(TokenFamily::GithubFinegrainedPat
            .allowed_ops()
            .contains(&MutOpKind::ChecksumCorrupt));
        assert!(TokenFamily::GithubClassicPat
            .allowed_ops()
            .contains(&MutOpKind::ChecksumCorrupt));
    }

    /// Minimal base-62 decoder for test assertions.
    fn base62_decode_test(bytes: &[u8]) -> u32 {
        let mut acc: u64 = 0;
        for &b in bytes {
            let v = match b {
                b'0'..=b'9' => (b - b'0') as u64,
                b'A'..=b'Z' => (b - b'A') as u64 + 10,
                b'a'..=b'z' => (b - b'a') as u64 + 36,
                _ => panic!("invalid base62 char: {b:#x}"),
            };
            acc = acc * 62 + v;
        }
        acc as u32
    }
}
