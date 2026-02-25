//! Mutation operators for deterministic near-miss counterexample generation.
//!
//! Each operator is a small, composable perturbation that pushes a valid token
//! across (or near) a detection boundary. By combining operators in sequence,
//! the test harness can systematically probe every rejection path in the engine:
//! wrong length, wrong charset, corrupted prefix, bad checksum, low entropy,
//! extra encoding layers, and trailing garbage.
//!
//! Operators are applied left-to-right via [`apply_ops`]. The pipeline is
//! **order-dependent** -- `Truncate` then `Extend` yields a different result
//! than `Extend` then `Truncate`. Out-of-range parameters (e.g. positions
//! beyond the token length) are clamped deterministically rather than causing
//! panics, so randomly generated operator parameters never produce undefined
//! behavior.

use serde::{Deserialize, Serialize};

use super::encode::SecretRepr;

/// Maximum nesting depth for `Encode { repr: Nested { depth } }`.
///
/// Each base64 layer expands by ~4/3x and each percent layer by 3x; at
/// depth 4 the compounded expansion is ~16x, easily reaching kilobytes
/// from a short input. Clamping here prevents accidental multi-megabyte
/// allocations when the depth field is generated randomly.
pub const MAX_NESTED_DEPTH: u8 = 4;

/// Maximum output size (1 MiB) -- safety net against exponential blowup.
///
/// If any single operator would push the output past this limit, `apply_ops`
/// stops the pipeline and returns the last in-bounds result. This guards
/// against pathological chains of `Encode` operators.
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;

/// A concrete mutation operation with fully specified parameters.
///
/// Each variant targets a different detection-engine gate. The test harness
/// generates these randomly (constrained by [`TokenFamily::allowed_ops`]) and
/// uses [`TokenFamily::expectation`] to predict the detection outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MutOp {
    /// Cut the token to `len` bytes. Tests the engine's minimum-length gate.
    /// If `len >= input.len()`, the token is left unchanged (no-op).
    Truncate { len: usize },
    /// Replace bytes at `positions` with `replacement`, injecting characters
    /// outside the token's valid alphabet. Tests charset validation.
    /// Out-of-bounds positions are silently skipped.
    CharsetViolate {
        positions: Vec<usize>,
        replacement: u8,
    },
    /// Overwrite the leading bytes with `replacement`, destroying the
    /// structural prefix (e.g. `AKIA`, `ghp_`). If `replacement` is longer
    /// than the input, only `input.len()` bytes are overwritten.
    PrefixMangle { replacement: Vec<u8> },
    /// XOR the last byte with `0xFF`, corrupting any trailing checksum.
    /// For CRC-bearing families this breaks the checksum; for other families
    /// the corrupted byte may or may not affect detection.
    ChecksumCorrupt,
    /// Overwrite the first `count` bytes with `repeat_byte`, reducing Shannon
    /// entropy. Tests the engine's minimum-entropy threshold. `count` is
    /// clamped to `input.len()`.
    EntropyReduce { repeat_byte: u8, count: usize },
    /// Wrap the entire token in an additional encoding layer. Tests whether
    /// the engine can see through double/triple encoding. Nested depths are
    /// clamped to [`MAX_NESTED_DEPTH`].
    Encode { repr: SecretRepr },
    /// Append `suffix` bytes after the token, adding trailing garbage that
    /// may or may not confuse boundary detection.
    Extend { suffix: Vec<u8> },
}

/// Fieldless mirror of [`MutOp`] used by [`TokenFamily::allowed_ops`] to
/// declare which operator categories are valid for a given token format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutOpKind {
    Truncate,
    CharsetViolate,
    PrefixMangle,
    ChecksumCorrupt,
    EntropyReduce,
    Encode,
    Extend,
}

/// Apply mutation operators left-to-right, returning the final bytes.
///
/// An empty `ops` slice returns a copy of `input` unchanged. If any single
/// operator would produce output exceeding [`MAX_OUTPUT_BYTES`], the pipeline
/// halts early and returns the last in-bounds state. This makes the function
/// safe to call with arbitrarily deep randomly-generated operator chains.
pub fn apply_ops(input: &[u8], ops: &[MutOp]) -> Vec<u8> {
    let mut cur = input.to_vec();
    for op in ops {
        let next = apply_single(&cur, op);
        if next.len() > MAX_OUTPUT_BYTES {
            return cur;
        }
        cur = next;
    }
    cur
}

/// Apply a single mutation operator. All out-of-range parameters are clamped
/// rather than panicking, so callers need not pre-validate operator fields.
fn apply_single(input: &[u8], op: &MutOp) -> Vec<u8> {
    match op {
        MutOp::Truncate { len } => {
            if *len >= input.len() {
                input.to_vec()
            } else {
                input[..*len].to_vec()
            }
        }
        MutOp::CharsetViolate {
            positions,
            replacement,
        } => {
            let mut out = input.to_vec();
            for &pos in positions {
                if pos < out.len() {
                    out[pos] = *replacement;
                }
            }
            out
        }
        MutOp::PrefixMangle { replacement } => {
            let mut out = input.to_vec();
            let copy_len = replacement.len().min(out.len());
            out[..copy_len].copy_from_slice(&replacement[..copy_len]);
            out
        }
        MutOp::ChecksumCorrupt => {
            let mut out = input.to_vec();
            if let Some(last) = out.last_mut() {
                *last ^= 0xFF;
            }
            out
        }
        MutOp::EntropyReduce { repeat_byte, count } => {
            let mut out = input.to_vec();
            let fill = (*count).min(out.len());
            for b in out.iter_mut().take(fill) {
                *b = *repeat_byte;
            }
            out
        }
        MutOp::Encode { repr } => {
            if let SecretRepr::Nested { depth } = repr {
                let clamped = (*depth).min(MAX_NESTED_DEPTH);
                return super::encode::encode_nested(input, clamped, MAX_OUTPUT_BYTES);
            }
            super::encode::encode_secret(input, repr)
        }
        MutOp::Extend { suffix } => {
            let mut out = input.to_vec();
            out.extend_from_slice(suffix);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ops_returns_input_unchanged() {
        let input = b"hello";
        assert_eq!(apply_ops(input, &[]), input);
    }

    #[test]
    fn determinism() {
        let input = b"test_token_12345";
        let ops = vec![
            MutOp::Truncate { len: 10 },
            MutOp::Extend {
                suffix: b"_extra".to_vec(),
            },
        ];
        let a = apply_ops(input, &ops);
        let b = apply_ops(input, &ops);
        assert_eq!(a, b);
    }

    #[test]
    fn truncate_beyond_length_is_identity() {
        let input = b"short";
        assert_eq!(apply_ops(input, &[MutOp::Truncate { len: 100 }]), input);
    }

    #[test]
    fn charset_violate_skips_out_of_range() {
        let input = b"abc";
        let ops = vec![MutOp::CharsetViolate {
            positions: vec![0, 999],
            replacement: b'X',
        }];
        let result = apply_ops(input, &ops);
        assert_eq!(result, b"Xbc");
    }

    #[test]
    fn prefix_mangle_clamps_to_input_len() {
        let input = b"ab";
        let ops = vec![MutOp::PrefixMangle {
            replacement: b"LONGPREFIX".to_vec(),
        }];
        let result = apply_ops(input, &ops);
        assert_eq!(result, b"LO");
    }

    #[test]
    fn checksum_corrupt_flips_last_byte() {
        let input = b"abc";
        let result = apply_ops(input, &[MutOp::ChecksumCorrupt]);
        assert_eq!(result, &[b'a', b'b', b'c' ^ 0xFF]);
    }

    #[test]
    fn entropy_reduce_clamps() {
        let input = b"abc";
        let result = apply_ops(
            input,
            &[MutOp::EntropyReduce {
                repeat_byte: b'A',
                count: 100,
            }],
        );
        assert_eq!(result, b"AAA");
    }

    #[test]
    fn left_to_right_composition() {
        let input = b"abcdef";
        let trunc_then_extend = apply_ops(
            input,
            &[
                MutOp::Truncate { len: 3 },
                MutOp::Extend {
                    suffix: b"XY".to_vec(),
                },
            ],
        );
        let extend_then_trunc = apply_ops(
            input,
            &[
                MutOp::Extend {
                    suffix: b"XY".to_vec(),
                },
                MutOp::Truncate { len: 3 },
            ],
        );
        assert_ne!(trunc_then_extend, extend_then_trunc);
        assert_eq!(trunc_then_extend, b"abcXY");
        assert_eq!(extend_then_trunc, b"abc");
    }

    #[test]
    fn nested_depth_clamped() {
        let input = b"hi";
        let deep = apply_ops(
            input,
            &[MutOp::Encode {
                repr: SecretRepr::Nested { depth: 255 },
            }],
        );
        let clamped = apply_ops(
            input,
            &[MutOp::Encode {
                repr: SecretRepr::Nested {
                    depth: MAX_NESTED_DEPTH,
                },
            }],
        );
        assert_eq!(deep, clamped);
    }

    #[test]
    fn max_output_bytes_guard() {
        // Build a chain of Encode ops that would grow exponentially.
        let input = vec![0u8; 1024];
        let ops: Vec<MutOp> = (0..30)
            .map(|_| MutOp::Encode {
                repr: SecretRepr::Base64,
            })
            .collect();
        let result = apply_ops(&input, &ops);
        assert!(result.len() <= MAX_OUTPUT_BYTES);
    }
}
