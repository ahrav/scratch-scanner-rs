//! Determinism and structural invariant property tests for the mutation framework.
//!
//! These tests verify three core properties:
//!
//! - **Determinism (P3)**: identical plans always produce byte-identical output.
//! - **Non-commutativity (P4)**: op ordering is semantically significant —
//!   Truncate-then-Extend differs from Extend-then-Truncate.
//! - **Offset correctness (P6)**: the `WrappedToken` offset metadata correctly
//!   locates the mutated token within its context bytes.

use proptest::prelude::*;

use scanner_rs::sim::mutation::{apply_ops, execute_plan, ContextWrap, MutOp};
use scanner_rs::sim::SimRng;

use super::proptest_support::{arb_family, arb_plan};

// P3: Determinism -- same plan executed twice yields identical output.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn same_seed_same_plan_same_bytes(plan in arb_plan()) {
        let a = execute_plan(&plan);
        let b = execute_plan(&plan.clone());

        prop_assert_eq!(&a.canonical, &b.canonical, "canonical bytes differ");
        prop_assert_eq!(&a.mutated, &b.mutated, "mutated bytes differ");
        prop_assert_eq!(&a.wrapped.bytes, &b.wrapped.bytes, "wrapped bytes differ");
        prop_assert_eq!(a.expectation, b.expectation, "expectation differs");
    }
}

// P4: Op ordering is semantically significant.
//
// Truncate-then-Extend and Extend-then-Truncate produce different byte
// sequences for any non-trivial token. Given a canonical token of length N,
// truncating to N/2 then extending by 1 byte yields (N/2 + 1) bytes, while
// extending by 1 then truncating to N/2 yields N/2 bytes.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn op_order_is_semantically_significant(
        family in arb_family(),
        seed in any::<u64>(),
        suffix_byte in any::<u8>(),
    ) {
        let canonical = family.gen_valid(&mut SimRng::new(seed));
        let trunc_len = canonical.len() / 2;

        let ops_ab = vec![
            MutOp::Truncate { len: trunc_len },
            MutOp::Extend { suffix: vec![suffix_byte] },
        ];
        let ops_ba = vec![
            MutOp::Extend { suffix: vec![suffix_byte] },
            MutOp::Truncate { len: trunc_len },
        ];

        let result_ab = apply_ops(&canonical, &ops_ab);
        let result_ba = apply_ops(&canonical, &ops_ba);

        // Truncate(N/2) then Extend(1) => N/2 + 1 bytes
        // Extend(1) then Truncate(N/2) => N/2 bytes
        prop_assert_ne!(
            result_ab.bytes,
            result_ba.bytes,
            "family={:?} seed={}: Truncate-then-Extend should differ from Extend-then-Truncate",
            family,
            seed,
        );
    }
}

// P6: WrappedToken offset metadata correctly locates the mutated token.
//
// Three sub-invariants:
// 1. token_offset + token_len <= bytes.len() (bounds)
// 2. bytes[token_offset..token_offset+token_len] == mutated (content)
// 3. Raw context implies token_offset == 0
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn wrapped_token_at_correct_offset(plan in arb_plan()) {
        let case = execute_plan(&plan);
        let w = &case.wrapped;

        // Sub-invariant 1: bounds
        prop_assert!(
            w.token_offset + w.token_len <= w.bytes.len(),
            "offset ({}) + len ({}) exceeds buffer ({})",
            w.token_offset,
            w.token_len,
            w.bytes.len(),
        );
        // Sub-invariant 2: content
        prop_assert_eq!(
            &w.bytes[w.token_offset..w.token_offset + w.token_len],
            case.mutated.as_slice(),
            "wrapped token bytes do not match mutated bytes",
        );
        // Sub-invariant 3: Raw context => offset 0
        if plan.context == ContextWrap::Raw {
            prop_assert_eq!(
                w.token_offset, 0,
                "Raw context should have token_offset == 0",
            );
        }
    }
}
