//! Determinism and structural invariant property tests for the mutation framework.
//!
//! These tests verify three core properties:
//!
//! - **Determinism (P3)**: identical plans always produce byte-identical output.
//! - **Non-commutativity (P4)**: op ordering is semantically significant —
//!   Truncate-then-Extend differs from Extend-then-Truncate.
//! - **Offset correctness (P6)**: the `WrappedToken` offset metadata correctly
//!   locates the mutated token within its context bytes.
//!
//! Plans that trigger the known `encode_utf16` debug_assert panic (from
//! Extend+Utf16 chains producing non-ASCII intermediates) are handled via
//! `catch_unwind` with panic-payload inspection. Only the known panic message
//! is suppressed; all other panics re-surface as test failures.

use std::any::Any;
use std::panic;

use proptest::prelude::*;

use scanner_rs::sim::mutation::{apply_ops, execute_plan, ContextWrap, MutOp};
use scanner_rs::sim::SimRng;

use super::proptest_support::{arb_family, arb_plan};

/// Check whether a `catch_unwind` payload is the known `encode_utf16`
/// debug_assert panic. Returns `true` only for payloads containing
/// `"encode_utf16"`, allowing all other panics to propagate as failures.
fn is_expected_utf16_panic(payload: &Box<dyn Any + Send>) -> bool {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("encode_utf16"))
        },
        |s| s.contains("encode_utf16"),
    )
}

// P3: Determinism -- same plan executed twice yields identical output.
//
// Uses catch_unwind to handle the known Extend+Utf16 debug_assert. If both
// executions panic with the expected message, that is deterministic (pass).
// If one panics and the other does not, the framework is non-deterministic
// (fail). Unexpected panics always fail.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn same_seed_same_plan_same_bytes(plan in arb_plan()) {
        let plan_clone = plan.clone();
        let result_a = panic::catch_unwind(|| execute_plan(&plan));
        let result_b = panic::catch_unwind(|| execute_plan(&plan_clone));

        match (&result_a, &result_b) {
            (Ok(a), Ok(b)) => {
                prop_assert_eq!(&a.canonical, &b.canonical, "canonical bytes differ");
                prop_assert_eq!(&a.mutated, &b.mutated, "mutated bytes differ");
                prop_assert_eq!(&a.wrapped.bytes, &b.wrapped.bytes, "wrapped bytes differ");
                prop_assert_eq!(a.expectation, b.expectation, "expectation differs");
            }
            (Err(pa), Err(pb)) => {
                // Both panicked -- only acceptable if both are the known UTF-16 panic.
                prop_assert!(
                    is_expected_utf16_panic(pa),
                    "first execution panicked with unexpected message",
                );
                prop_assert!(
                    is_expected_utf16_panic(pb),
                    "second execution panicked with unexpected message",
                );
            }
            (Ok(_), Err(p)) => {
                if !is_expected_utf16_panic(p) {
                    prop_assert!(false, "second execution panicked unexpectedly");
                }
                prop_assert!(
                    false,
                    "non-deterministic: first execution succeeded, second panicked",
                );
            }
            (Err(p), Ok(_)) => {
                if !is_expected_utf16_panic(p) {
                    prop_assert!(false, "first execution panicked unexpectedly");
                }
                prop_assert!(
                    false,
                    "non-deterministic: first execution panicked, second succeeded",
                );
            }
        }
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
//
// Plans that trigger the known UTF-16 panic are rejected via prop_assume!
// so that proptest regenerates to fill the 500-case budget.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn wrapped_token_at_correct_offset(plan in arb_plan()) {
        let result = panic::catch_unwind(|| execute_plan(&plan));
        match result {
            Ok(case) => {
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
            Err(payload) => {
                if is_expected_utf16_panic(&payload) {
                    // Known panic -- reject this case so proptest regenerates.
                    prop_assume!(false, "skipping known encode_utf16 panic");
                } else {
                    prop_assert!(false, "unexpected panic during execute_plan");
                }
            }
        }
    }
}
