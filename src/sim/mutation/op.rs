//! Mutation operators for deterministic near-miss counterexample generation.
//!
//! Operators are applied left-to-right via `apply_ops`. Out-of-range parameters
//! are clamped deterministically rather than causing panics.

use serde::{Deserialize, Serialize};

use super::encode::SecretRepr;

/// Maximum nesting depth for `Encode { repr: Nested { depth } }`.
pub const MAX_NESTED_DEPTH: u8 = 4;

/// Maximum output size (1 MiB) — safety net against exponential blowup.
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;

/// A concrete mutation operation with parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MutOp {
    Truncate {
        len: usize,
    },
    CharsetViolate {
        positions: Vec<usize>,
        replacement: u8,
    },
    PrefixMangle {
        replacement: Vec<u8>,
    },
    ChecksumCorrupt,
    EntropyReduce {
        repeat_byte: u8,
        count: usize,
    },
    Encode {
        repr: SecretRepr,
    },
    Extend {
        suffix: Vec<u8>,
    },
}

/// Fieldless mirror of `MutOp` for `allowed_ops()` filtering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
                return super::encode::encode_nested(input, clamped);
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
