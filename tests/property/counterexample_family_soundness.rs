//! Soundness property tests for the mutation oracle's outcome classification.
//!
//! The oracle ([`TokenFamily::expectation`]) classifies mutated tokens into a
//! three-valued outcome: `MustMatch`, `MustNotMatch`, or `MayMatch`. This file
//! tests that the oracle correctly classifies the **boundary cases** — the
//! transitions between these outcome categories:
//!
//! | Property | Boundary tested | Expected outcome |
//! |----------|--------------------------------------------------------------|------------------|
//! | P1 | No mutation (identity) | `MustMatch` |
//! | P2 | Single hard-breaking mutation (prefix, charset, length) | `MustNotMatch` |
//! | P5 | Checksum corruption on CRC-bearing families | `MustNotMatch` |
//! | P7 | Soft-only mutations (encoding, entropy, trailing bytes) | `MayMatch` |
//!
//! These four properties together verify that the oracle's classification
//! boundaries are sound: every hard constraint violation is recognized as
//! `MustNotMatch`, every soft-only mutation stays at `MayMatch`, and unmutated
//! tokens are always `MustMatch`. A misclassification in any direction means
//! the test harness would silently accept false positives or false negatives.
//!
//! P1 exercises the full pipeline ([`execute_plan`]) to verify end-to-end
//! correctness. P2, P5, and P7 call [`TokenFamily::expectation`] directly to
//! isolate the oracle from generation and wrapping stages — the oracle itself
//! is the system under test.
//!
//! Properties P3, P4, and P6 (determinism, non-commutativity, offset
//! correctness) live in the sibling `counterexample_determinism` module. The
//! P-numbering is a stable cross-reference scheme within the test suite.

use proptest::prelude::*;

use scanner_rs::sim::mutation::{
    execute_plan, ContextWrap, MutOp, MutationPlan, Outcome, SecretRepr, TokenFamily,
};
use scanner_rs::sim::SimRng;

use super::proptest_support::arb_family;

// P1: Identity axiom — no mutation means MustMatch.
//
// For any family and seed, a plan with empty ops and Raw context must produce
// MustMatch. This is the oracle's ground truth: gen_valid always produces a
// structurally valid token, and the empty-ops pipeline must preserve that
// validity through all four stages (generate, mutate, predict, wrap).
//
// Unlike P2/P5/P7, this test goes through execute_plan rather than calling
// expectation() directly, because the identity property must hold end-to-end —
// if any pipeline stage corrupts an unmutated token, that is a bug.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn valid_seed_cases_always_must_match(
        family in arb_family(),
        seed in any::<u64>(),
    ) {
        let plan = MutationPlan {
            family,
            base_seed: seed,
            case_id: 0,
            ops: vec![],
            context: ContextWrap::Raw,
        };
        let case = execute_plan(&plan);
        prop_assert_eq!(
            case.expectation,
            Outcome::MustMatch,
            "empty-ops plan for {:?} seed={} should be MustMatch",
            family,
            seed,
        );
    }
}

// P2: Single hard-breaking mutations produce MustNotMatch.
//
// Each of PrefixMangle, CharsetViolate, and Truncate independently breaks a
// hard detection gate (prefix structure, character set, or minimum length).
// The oracle must classify every one of these as MustNotMatch, regardless of
// the family or seed.
//
// Family subset: only the four families that support PrefixMangle are tested
// (AwsAccessKey, GithubFinegrainedPat, GithubClassicPat, JwtLike). The blob
// families (Base64Blob, UrlEncodedBlob) exclude PrefixMangle from their
// allowed_ops because they have no structural prefix to corrupt.
//
// Parameter choices are deliberately extreme to guarantee the hard break:
//   - PrefixMangle with b"ZZZZ": no real token family uses this prefix.
//   - CharsetViolate at position 0 with 0xFF: byte 0xFF is outside every
//     family's valid charset (base-32, base-62, base-64, printable ASCII).
//   - Truncate to len 1: every family's canonical token is longer than 1 byte.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn near_miss_mutations_change_outcome(
        family in prop_oneof![
            Just(TokenFamily::AwsAccessKey),
            Just(TokenFamily::GithubFinegrainedPat),
            Just(TokenFamily::GithubClassicPat),
            Just(TokenFamily::JwtLike),
        ],
        seed in any::<u64>(),
        mutation_kind in 0u8..3,
    ) {
        let canonical = family.gen_valid(&mut SimRng::new(seed));

        // Each arm targets a distinct hard gate in the oracle. The parameters
        // are chosen to unconditionally trigger MustNotMatch regardless of the
        // canonical token's contents — see the comment block above for rationale.
        let op = match mutation_kind {
            0 => MutOp::PrefixMangle { replacement: b"ZZZZ".to_vec() },
            1 => MutOp::CharsetViolate { positions: vec![0], replacement: 0xFF },
            2 => MutOp::Truncate { len: 1 },
            _ => unreachable!(),
        };

        // Call expectation() directly rather than execute_plan() to isolate
        // the oracle's classification logic from generation and wrapping.
        let outcome = family.expectation(&canonical, &[op]);
        prop_assert_eq!(
            outcome,
            Outcome::MustNotMatch,
            "family={:?} seed={} mutation_kind={}: \
             expected MustNotMatch for hard-breaking mutation",
            family,
            seed,
            mutation_kind,
        );
    }
}

// P5: Checksum corruption on CRC-bearing families produces MustNotMatch.
//
// Only GithubFinegrainedPat and GithubClassicPat carry embedded CRC-32
// checksums (the other four families have no checksum gate). For these two
// families, ChecksumCorrupt XORs the last byte to invalidate the CRC, and the
// oracle must recognize this as a hard constraint violation.
//
// This is tested separately from P2 because ChecksumCorrupt is a distinct
// detection gate that only applies to a subset of families — applying it to a
// non-CRC family would produce MayMatch, not MustNotMatch.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn checksum_corrupt_on_crc_family_invalidates(
        family in prop_oneof![
            Just(TokenFamily::GithubFinegrainedPat),
            Just(TokenFamily::GithubClassicPat),
        ],
        seed in any::<u64>(),
    ) {
        let canonical = family.gen_valid(&mut SimRng::new(seed));
        let outcome = family.expectation(&canonical, &[MutOp::ChecksumCorrupt]);
        prop_assert_eq!(
            outcome,
            Outcome::MustNotMatch,
            "family={:?} seed={}: ChecksumCorrupt on CRC family should be MustNotMatch",
            family,
            seed,
        );
    }
}

// P7: Soft-only mutations produce MayMatch (never MustNotMatch).
//
// Encode, EntropyReduce, and Extend affect soft heuristics (encoding depth,
// entropy, trailing bytes) that the detection engine may or may not enforce.
// The oracle must classify these as MayMatch — not MustMatch (which would
// assert the engine must detect the token) and not MustNotMatch (which would
// assert the engine must reject it).
//
// Unlike P2, this test covers ALL six families via arb_family() because soft
// ops are in every family's allowed_ops set.
//
// Each op is constructed with non-identity parameters to ensure it actually
// shifts the outcome away from MustMatch:
//   - Encode with Base64: a non-identity repr (neither Raw nor Nested{0})
//     triggers MayMatch.
//   - EntropyReduce with count=1: at least one byte is replaced, affecting
//     the entropy signal.
//   - Extend with a 1-byte suffix: adds trailing bytes the engine may ignore.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn soft_only_mutations_are_may_match(
        family in arb_family(),
        seed in any::<u64>(),
        soft_op_kind in 0u8..3,
        repeat_byte in any::<u8>(),
        suffix_byte in any::<u8>(),
    ) {
        let canonical = family.gen_valid(&mut SimRng::new(seed));

        let op = match soft_op_kind {
            // Encode with a non-identity repr (Base64 always shifts to MayMatch).
            0 => MutOp::Encode { repr: SecretRepr::Base64 },
            // EntropyReduce with count > 0.
            1 => MutOp::EntropyReduce { repeat_byte, count: 1 },
            // Extend with a non-empty suffix.
            2 => MutOp::Extend { suffix: vec![suffix_byte] },
            _ => unreachable!(),
        };

        let outcome = family.expectation(&canonical, &[op]);
        prop_assert_eq!(
            outcome,
            Outcome::MayMatch,
            "family={:?} seed={} soft_op_kind={}: \
             expected MayMatch for soft-only mutation",
            family,
            seed,
            soft_op_kind,
        );
    }
}
