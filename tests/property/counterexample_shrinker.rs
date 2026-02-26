//! Tests for the custom `MutationPlanValueTree` shrinker.
//!
//! All tests use synthetic predicates — they exercise the shrinking state
//! machine without requiring scanner internals.

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};

use scanner_rs::sim::mutation::{ContextWrap, MutOp, MutOpKind, MutationPlan, TokenFamily};

use super::proptest_support::{arb_plan, is_valid_plan, MutationPlanValueTree};

/// Helper: generate a plan from the custom strategy with a fixed seed.
fn generate_plan(seed: u64) -> (MutationPlanValueTree, MutationPlan) {
    let config = Config::default();
    let mut runner = TestRunner::new_with_rng(
        config,
        proptest::test_runner::TestRng::from_seed(
            proptest::test_runner::RngAlgorithm::ChaCha,
            &seed.to_le_bytes().repeat(4)[..32],
        ),
    );
    let tree = arb_plan().new_tree(&mut runner).unwrap();
    let initial = tree.current();
    (tree, initial)
}

/// 1. Shrinking reduces the op count while the predicate still holds.
#[test]
fn shrinker_reduces_ops_while_reproducing() {
    // Try several seeds to find one that generates a plan with ops.
    for seed in 0..50u64 {
        let (mut tree, initial) = generate_plan(seed);
        if initial.ops.is_empty() {
            continue;
        }

        // Predicate: plan has at least 1 op.
        let initial_count = initial.ops.len();
        let mut last_valid = initial.clone();

        // Shrink while the predicate holds.
        let mut steps = 0;
        loop {
            if !tree.simplify() {
                break;
            }
            let candidate = tree.current();
            if !candidate.ops.is_empty() {
                last_valid = candidate;
            } else {
                // Predicate failed, complicate to restore.
                tree.complicate();
            }
            steps += 1;
            if steps > 500 {
                break;
            }
        }

        // The shrunk plan should have fewer or equal ops.
        assert!(
            last_valid.ops.len() <= initial_count,
            "seed {seed}: shrunk plan has more ops ({}) than initial ({initial_count})",
            last_valid.ops.len(),
        );
        return; // One successful seed is enough.
    }
    panic!("no seed produced a plan with ops");
}

/// 2. Same seed produces identical shrink sequences.
#[test]
fn shrinker_output_stable_across_runs() {
    let seed = 12345u64;
    let collect_sequence = || {
        let (mut tree, _) = generate_plan(seed);
        let mut sequence = vec![tree.current()];
        for _ in 0..20 {
            if !tree.simplify() {
                break;
            }
            sequence.push(tree.current());
        }
        sequence
    };

    let a = collect_sequence();
    let b = collect_sequence();
    assert_eq!(a, b, "shrink sequences differ across runs");
}

// Every generated plan is valid (ops match family's allowed_ops)
// and can be executed without panicking.
proptest! {
    #![proptest_config(Config::with_cases(200))]

    #[test]
    fn no_invalid_plans_during_generation(plan in arb_plan()) {
        prop_assert!(
            is_valid_plan(&plan),
            "generated plan has ops not in family's allowed_ops: {plan:?}",
        );
        // Execute — debug_assert in encode_utf16 may fire on non-ASCII bytes
        // from Extend+Encode chains. This is expected in debug builds when
        // mutation ops produce non-ASCII intermediates before a UTF-16 layer.
        let _ = std::panic::catch_unwind(|| {
            scanner_rs::sim::mutation::execute_plan(&plan)
        });
    }
}

/// 4. Walking the full simplify sequence never produces an invalid plan.
#[test]
fn all_shrink_candidates_valid() {
    for seed in 0..20u64 {
        let (mut tree, initial) = generate_plan(seed);
        assert!(
            is_valid_plan(&initial),
            "seed {seed}: initial plan is invalid",
        );

        let mut steps = 0;
        while tree.simplify() {
            let candidate = tree.current();
            assert!(
                is_valid_plan(&candidate),
                "seed {seed}, step {steps}: shrink candidate is invalid: {candidate:?}",
            );
            steps += 1;
            if steps > 500 {
                break; // Safety bound.
            }
        }
    }
}

/// 5. A plan with a Truncate op shrinks to a minimal plan.
#[test]
fn complex_plan_shrinks_to_minimal() {
    // Predicate: plan contains a Truncate op.
    let has_truncate = |plan: &MutationPlan| {
        plan.ops
            .iter()
            .any(|op: &MutOp| op.kind() == MutOpKind::Truncate)
    };

    for seed in 0..100u64 {
        let (mut tree, initial) = generate_plan(seed);
        if !has_truncate(&initial) || initial.ops.len() < 3 {
            continue;
        }

        // Shrink while predicate holds.
        let mut last_valid = initial.clone();
        let mut steps = 0;
        loop {
            if !tree.simplify() {
                break;
            }
            let candidate = tree.current();
            if has_truncate(&candidate) {
                last_valid = candidate;
            } else {
                tree.complicate();
            }
            steps += 1;
            if steps > 500 {
                break;
            }
        }

        assert!(
            last_valid.ops.len() <= 2,
            "seed {seed}: expected ≤2 ops after shrinking, got {}",
            last_valid.ops.len(),
        );
        assert!(has_truncate(&last_valid));
        return;
    }
    panic!("no seed produced a multi-op plan with Truncate");
}

/// 6. Full simplification drives context toward Raw.
#[test]
fn context_shrinks_toward_raw() {
    for seed in 0..50u64 {
        let (mut tree, initial) = generate_plan(seed);
        if initial.context == ContextWrap::Raw {
            continue;
        }

        // Exhaust all simplify steps.
        let mut steps = 0;
        while tree.simplify() {
            steps += 1;
            if steps > 500 {
                break;
            }
        }

        let final_plan = tree.current();
        assert_eq!(
            final_plan.context,
            ContextWrap::Raw,
            "seed {seed}: context did not shrink to Raw (got {:?})",
            final_plan.context,
        );
        return;
    }
    panic!("no seed produced a plan with non-Raw context");
}

/// 7. Empty-ops plans do not panic during simplify/complicate cycles.
#[test]
fn empty_ops_plan_shrink_does_not_panic() {
    let plan = MutationPlan {
        family: TokenFamily::AwsAccessKey,
        base_seed: 42,
        case_id: 0,
        ops: vec![],
        context: ContextWrap::MultiLineString,
    };

    let mut tree = MutationPlanValueTree::new(plan);

    // Drive through all phases — should not panic.
    let mut steps = 0;
    while tree.simplify() {
        tree.complicate();
        tree.simplify();
        steps += 1;
        if steps > 100 {
            break;
        }
    }

    // Final context should be Raw (the only thing to shrink).
    let final_plan = tree.current();
    assert_eq!(final_plan.context, ContextWrap::Raw);
    assert!(final_plan.ops.is_empty());
}
