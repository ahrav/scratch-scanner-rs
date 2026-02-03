//! Policy hash canonicalization for Git scanning.
//!
//! The policy hash identifies the scanning policy used for incremental Git
//! scans. It is a BLAKE3 hash over a canonical encoding of:
//! - Rule specs (canonicalized and order-invariant)
//! - Transform configs (order-preserving)
//! - Tuning parameters
//! - Merge diff mode
//! - Path policy version
//!
//! # Invariants
//! - Identical inputs yield identical hashes across platforms.
//! - Rule ordering does not affect the hash.
//! - Any semantically relevant change in inputs changes the hash.
//! - The encoding is versioned; bumping `POLICY_HASH_VERSION` invalidates
//!   all previous hashes (forcing full rescans).

use crate::api::{RuleSpec, TransformConfig, Tuning};

/// 32-byte stable identity for a Git scanning policy.
pub type PolicyHash = [u8; 32];

/// Merge diff semantics for commit traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeDiffMode {
    /// Diff against all parents, unioning blob changes.
    AllParents,
    /// Diff against the first parent only.
    FirstParentOnly,
}

impl MergeDiffMode {
    /// Encodes this mode as a stable tag for policy hashing.
    #[inline]
    fn encode(self, out: &mut Vec<u8>) {
        let tag = match self {
            MergeDiffMode::AllParents => 1,
            MergeDiffMode::FirstParentOnly => 2,
        };
        out.push(tag);
    }
}

const POLICY_HASH_VERSION: u8 = 1;

/// Computes the canonical policy hash for Git scanning.
///
/// # Semantics
/// - `rules` are order-invariant (canonicalized and sorted).
/// - `transforms` are order-preserving (pipeline order is significant).
/// - `tuning`, `merge_diff_mode`, and `path_policy_version` are included
///   verbatim; any change yields a different hash.
#[must_use]
pub fn policy_hash(
    rules: &[RuleSpec],
    transforms: &[TransformConfig],
    tuning: &Tuning,
    merge_diff_mode: MergeDiffMode,
    path_policy_version: u32,
) -> PolicyHash {
    let mut buf = Vec::with_capacity(4096);
    encode_policy_hash(
        &mut buf,
        rules,
        transforms,
        tuning,
        merge_diff_mode,
        path_policy_version,
    );

    *blake3::hash(&buf).as_bytes()
}

fn encode_policy_hash(
    out: &mut Vec<u8>,
    rules: &[RuleSpec],
    transforms: &[TransformConfig],
    tuning: &Tuning,
    merge_diff_mode: MergeDiffMode,
    path_policy_version: u32,
) {
    // Canonical, versioned encoding with field tags to preserve order and
    // allow future extension without ambiguity. The output is not intended
    // to be parsed; it is a stable byte stream for hashing.
    out.clear();

    out.extend_from_slice(b"policy_hash");
    out.push(0);
    out.push(POLICY_HASH_VERSION);

    out.extend_from_slice(b"merge_diff");
    out.push(0);
    merge_diff_mode.encode(out);

    out.extend_from_slice(b"path_policy");
    out.push(0);
    push_u32_le(out, path_policy_version);

    out.extend_from_slice(b"tuning");
    out.push(0);
    tuning.encode_policy(out);

    out.extend_from_slice(b"transforms");
    out.push(0);
    encode_transforms(out, transforms);

    out.extend_from_slice(b"rules");
    out.push(0);
    encode_rules(out, rules);
}

/// Encodes rules in a canonical, order-invariant form.
///
/// Each rule is encoded independently and then the byte blobs are sorted.
/// This keeps hashes stable across rule ordering changes.
fn encode_rules(out: &mut Vec<u8>, rules: &[RuleSpec]) {
    let mut encoded = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut buf = Vec::new();
        rule.encode_policy(&mut buf);
        encoded.push(buf);
    }
    encoded.sort_unstable();

    push_u32_le(out, encoded.len() as u32);
    for bytes in encoded {
        push_u32_le(out, bytes.len() as u32);
        out.extend_from_slice(&bytes);
    }
}

/// Encodes transforms in a stable, order-preserving form.
///
/// Transform order is significant because it defines the decode pipeline.
fn encode_transforms(out: &mut Vec<u8>, transforms: &[TransformConfig]) {
    push_u32_le(out, transforms.len() as u32);
    for transform in transforms {
        transform.encode_policy(out);
    }
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Gate, TransformId, TransformMode};
    use crate::demo::demo_tuning;
    use regex::bytes::Regex;

    fn rule(name: &'static str, pattern: &str, anchors: &'static [&'static [u8]]) -> RuleSpec {
        RuleSpec {
            name,
            anchors,
            radius: 64,
            validator: crate::api::ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            secret_group: None,
            re: Regex::new(pattern).unwrap(),
        }
    }

    fn transforms() -> Vec<TransformConfig> {
        vec![TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 256,
            max_decoded_bytes: 256,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }]
    }

    #[test]
    fn policy_hash_is_stable() {
        let rules = vec![rule("a", "a", &[b"a"]), rule("b", "b", &[b"b"])];
        let tuning = demo_tuning();
        let h1 = policy_hash(&rules, &transforms(), &tuning, MergeDiffMode::AllParents, 1);
        let h2 = policy_hash(&rules, &transforms(), &tuning, MergeDiffMode::AllParents, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn policy_hash_is_order_invariant_for_rules() {
        let r1 = rule("a", "a", &[b"a"]);
        let r2 = rule("b", "b", &[b"b"]);
        let tuning = demo_tuning();

        let h1 = policy_hash(
            &[r1.clone(), r2.clone()],
            &transforms(),
            &tuning,
            MergeDiffMode::AllParents,
            1,
        );
        let h2 = policy_hash(
            &[r2, r1],
            &transforms(),
            &tuning,
            MergeDiffMode::AllParents,
            1,
        );
        assert_eq!(h1, h2);
    }
}
