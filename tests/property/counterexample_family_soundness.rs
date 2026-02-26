//! Per-family near-miss property tests for the mutation oracle.
//!
//! These tests exercise the oracle's boundary behavior: no-mutation plans must
//! produce `MustMatch`, single hard-breaking mutations must produce
//! `MustNotMatch`, and checksum corruption on CRC-bearing families must
//! invalidate.
//!
//! All tests use `arb_family()` from the shared strategy module to sample
//! uniformly across token families, ensuring coverage of every archetype.

use proptest::prelude::*;

use scanner_rs::sim::mutation::{
    execute_plan, ContextWrap, MutOp, MutationPlan, Outcome, TokenFamily,
};
use scanner_rs::sim::SimRng;

use super::proptest_support::arb_family;

// P1: The oracle's identity axiom -- no mutation means MustMatch.
//
// For any family and seed, a plan with empty ops and Raw context produces a
// canonical token that the engine must detect. This is the ground truth:
// gen_valid always produces a structurally valid token.
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
// For families with prefix+charset constraints, each of PrefixMangle,
// CharsetViolate, and Truncate independently breaks a hard detection gate.
// Base64Blob and UrlEncodedBlob are excluded because PrefixMangle is not
// in their allowed_ops.
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

        let op = match mutation_kind {
            0 => MutOp::PrefixMangle { replacement: b"ZZZZ".to_vec() },
            1 => MutOp::CharsetViolate { positions: vec![0], replacement: 0xFF },
            2 => MutOp::Truncate { len: 1 },
            _ => unreachable!(),
        };

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

// P5: Checksum corruption on CRC-bearing families invalidates detection.
//
// GithubFinegrainedPat and GithubClassicPat both carry CRC-32 checksums.
// XOR-ing the last byte breaks the checksum, which the oracle recognizes
// as a hard constraint violation.
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
