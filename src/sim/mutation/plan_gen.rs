//! Random `MutationPlan` generation for the sim-harness.
//!
//! Produces valid, deterministic plans from a [`SimRng`] seed so that
//! random-seed test modes can exercise mutation-generated tokens through the
//! full scanning pipeline.

use super::encode::SecretRepr;
use super::family::TokenFamily;
use super::op::{MutOp, MutOpKind};
use super::plan::{ContextWrap, MutationPlan};
use crate::sim::rng::SimRng;

/// Generate a single random [`MutationPlan`] for a random family.
pub fn random_mutation_plan(rng: &mut SimRng, case_id: u64) -> MutationPlan {
    let families = TokenFamily::ALL;
    let family = families[rng.gen_range(0, families.len() as u32) as usize];
    random_plan_for_family(rng, family, case_id)
}

/// Generate `plans_per_family` random plans for *each* token family.
///
/// Returns `TokenFamily::ALL.len() * plans_per_family` plans in family order.
pub fn random_mutation_plans_all_families(
    rng: &mut SimRng,
    plans_per_family: u32,
) -> Vec<MutationPlan> {
    let mut plans = Vec::with_capacity(TokenFamily::ALL.len() * plans_per_family as usize);
    let mut case_id = 0u64;
    for family in TokenFamily::ALL {
        for _ in 0..plans_per_family {
            plans.push(random_plan_for_family(rng, family, case_id));
            case_id += 1;
        }
    }
    plans
}

/// Build a single plan for a specific family.
fn random_plan_for_family(rng: &mut SimRng, family: TokenFamily, case_id: u64) -> MutationPlan {
    let base_seed = rng.next_u64();
    let op_count = rng.gen_range(0, 5) as usize; // 0–4 ops
    let bound = family.param_bound();
    let allowed = family.allowed_ops();

    let mut ops = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        let kind = allowed[rng.gen_range(0, allowed.len() as u32) as usize];
        ops.push(random_op(rng, kind, bound));
    }

    let wraps = ContextWrap::ALL;
    let context = wraps[rng.gen_range(0, wraps.len() as u32) as usize];

    MutationPlan {
        family,
        base_seed,
        case_id,
        ops,
        context,
    }
}

/// Produce one random `MutOp` for the given kind, with parameters bounded
/// by the family's `param_bound()`.
fn random_op(rng: &mut SimRng, kind: MutOpKind, bound: usize) -> MutOp {
    match kind {
        MutOpKind::Truncate => MutOp::Truncate {
            len: rng.gen_range(0, bound.saturating_add(1) as u32) as usize,
        },
        MutOpKind::CharsetViolate => {
            let count = rng.gen_range(1, 4) as usize;
            let positions: Vec<usize> = (0..count)
                .map(|_| rng.gen_range(0, bound as u32) as usize)
                .collect();
            MutOp::CharsetViolate {
                positions,
                replacement: rng.gen_range(0, 256) as u8,
            }
        }
        MutOpKind::PrefixMangle => {
            let len = rng.gen_range(1, 9) as usize;
            let replacement: Vec<u8> = (0..len).map(|_| rng.gen_range(0, 256) as u8).collect();
            MutOp::PrefixMangle { replacement }
        }
        MutOpKind::ChecksumCorrupt => MutOp::ChecksumCorrupt,
        MutOpKind::EntropyReduce => MutOp::EntropyReduce {
            repeat_byte: rng.gen_range(0, 256) as u8,
            count: rng.gen_range(0, bound.saturating_add(1) as u32) as usize,
        },
        MutOpKind::Encode => {
            let repr = match rng.gen_range(0, 4) {
                0 => SecretRepr::Base64,
                1 => SecretRepr::UrlPercent,
                2 => SecretRepr::Utf16Le,
                _ => SecretRepr::Nested {
                    depth: rng.gen_range(1, 4) as u8,
                },
            };
            MutOp::Encode { repr }
        }
        MutOpKind::Extend => {
            let len = rng.gen_range(1, 17) as usize;
            let suffix: Vec<u8> = (0..len).map(|_| rng.gen_range(0, 256) as u8).collect();
            MutOp::Extend { suffix }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_plan_determinism() {
        let mut rng_a = SimRng::new(42);
        let mut rng_b = SimRng::new(42);
        let a = random_mutation_plan(&mut rng_a, 0);
        let b = random_mutation_plan(&mut rng_b, 0);
        assert_eq!(a, b, "same seed must produce identical plans");
    }

    #[test]
    fn all_families_covered() {
        let plans = random_mutation_plans_all_families(&mut SimRng::new(7), 1);
        assert_eq!(plans.len(), TokenFamily::ALL.len());
        for (plan, family) in plans.iter().zip(TokenFamily::ALL.iter()) {
            assert_eq!(plan.family, *family);
        }
    }

    #[test]
    fn plans_per_family_count() {
        let plans = random_mutation_plans_all_families(&mut SimRng::new(99), 3);
        assert_eq!(plans.len(), TokenFamily::ALL.len() * 3);
    }

    #[test]
    fn ops_within_allowed_set() {
        let plans = random_mutation_plans_all_families(&mut SimRng::new(123), 5);
        for plan in &plans {
            let allowed = plan.family.allowed_ops();
            for op in &plan.ops {
                assert!(
                    allowed.contains(&op.kind()),
                    "op {:?} not in allowed set for {:?}",
                    op.kind(),
                    plan.family,
                );
            }
        }
    }
}
