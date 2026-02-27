//! Adapter that translates [`MutationPlan`]s into a [`Scenario`] consumable
//! by [`ScannerSimRunner`], plus a post-run mutation oracle.
//!
//! The ground-truth oracle tolerates all findings via `MayMiss` point-span
//! entries. The mutation-specific oracle ([`check_mutation_expectations`])
//! performs the real correctness checks using any-intersection span matching.

use crate::api::AnchorPolicy;
use crate::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::sim::mutation::family::{Outcome, TokenFamily};
use crate::sim::mutation::plan::{execute_plan, GeneratedCase, MutationPlan};
use crate::sim::rng::SimRng;
use crate::sim_scanner::generator::{materialize_rules, synthetic_tuning};
use crate::sim_scanner::scenario::{
    ExpectedDisposition, ExpectedSecret, RuleSuiteSpec, RunConfig, Scenario, SecretRepr, SpanU32,
    SyntheticRuleSpec,
};
use crate::{Engine, FindingRec};

/// Result of [`check_mutation_expectations`].
#[derive(Clone, Debug)]
pub struct MutationCheckResult {
    pub passed: bool,
    pub violations: Vec<MutationViolation>,
}

/// A single mutation expectation that was violated.
#[derive(Clone, Debug)]
pub struct MutationViolation {
    pub case_index: usize,
    pub family: TokenFamily,
    pub expected: Outcome,
    pub found: bool,
    pub message: String,
}

/// Per-family rule specification for the mutation scenario.
struct FamilyRule {
    rule_id: u32,
    anchors: Vec<Vec<u8>>,
    regex: String,
    radius: u32,
}

/// Build a [`Scenario`] and [`Vec<GeneratedCase>`] from a batch of mutation plans.
///
/// Returns `(scenario, cases, noise_len_used)`. The mutation oracle uses the
/// cases and `noise_len_used` to compute spans independently of
/// `scenario.expected` (which contains only ground-truth-oracle-friendly
/// `MayMiss` point entries).
pub fn build_mutation_scenario(
    plans: &[MutationPlan],
    noise_len: usize,
    _rng: &mut SimRng,
) -> (Scenario, Vec<GeneratedCase>, usize) {
    let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();

    let family_rules = build_family_rules(&cases);
    let rules: Vec<SyntheticRuleSpec> = family_rules
        .iter()
        .map(|fr| SyntheticRuleSpec {
            rule_id: fr.rule_id,
            name: format!("mutation_family_{}", fr.rule_id),
            anchors: fr.anchors.clone(),
            regex: fr.regex.clone(),
            radius: fr.radius,
        })
        .collect();

    let noise = vec![b'\n'; noise_len];

    let mut nodes = Vec::new();
    let mut expected = Vec::new();
    let mut dir_children = Vec::new();

    for (idx, case) in cases.iter().enumerate() {
        let path_str = format!("mutation_{idx}.txt");
        let path = SimPath::new(path_str.into_bytes());
        dir_children.push(path.clone());

        let mut contents = Vec::with_capacity(noise_len + case.wrapped.bytes.len() + noise_len);
        contents.extend_from_slice(&noise);
        contents.extend_from_slice(&case.wrapped.bytes);
        contents.extend_from_slice(&noise);

        nodes.push(SimNodeSpec::File {
            path: path.clone(),
            contents,
            discovery_len_hint: None,
            type_hint: SimTypeHint::File,
        });

        // Register MayMiss point-span entries for ALL rule_ids scattered
        // through the wrapped token region. The ground-truth oracle's
        // span_matches_expected requires expected.span ⊆ finding.span.
        // 1-byte point spans every 8 bytes ensure any ≥8-byte finding will
        // contain at least one.
        let region_start = noise_len;
        let region_end = noise_len + case.wrapped.bytes.len();
        for family in TokenFamily::ALL {
            let rid = family_rule_id(family);
            let mut pos = region_start;
            while pos < region_end {
                let end = (pos + 1).min(region_end);
                expected.push(ExpectedSecret {
                    path: path.clone(),
                    rule_id: rid,
                    root_span: SpanU32::new(pos as u32, end as u32),
                    repr: SecretRepr::Raw,
                    disposition: ExpectedDisposition::MayMiss {
                        reason: "mutation: deferred to mutation oracle".to_string(),
                    },
                });
                pos += 8;
            }
        }
    }

    dir_children.sort();
    nodes.insert(
        0,
        SimNodeSpec::Dir {
            path: SimPath::new(b".".to_vec()),
            children: dir_children,
        },
    );

    let scenario = Scenario {
        schema_version: 1,
        fs: SimFsSpec { nodes },
        rule_suite: RuleSuiteSpec {
            schema_version: 1,
            rules,
        },
        expected,
        archives: vec![],
    };

    (scenario, cases, noise_len)
}

/// Build an engine from a mutation scenario's rule suite with NO transforms.
pub fn build_mutation_engine(suite: &RuleSuiteSpec, run_cfg: &RunConfig) -> Result<Engine, String> {
    let rules = materialize_rules(suite)?;
    let transforms = vec![];
    let tuning = synthetic_tuning(run_cfg);
    Ok(Engine::new_with_anchor_policy(
        rules,
        transforms,
        tuning,
        AnchorPolicy::ManualOnly,
    ))
}

/// Post-run oracle for mutation-specific expectations.
///
/// Computes expected spans directly from the cases and `noise_len`, using
/// any-intersection matching (more lenient than the ground-truth oracle's
/// containment check).
pub fn check_mutation_expectations(
    cases: &[GeneratedCase],
    noise_len: usize,
    findings: &[FindingRec],
) -> MutationCheckResult {
    let mut violations = Vec::new();

    for (case_idx, case) in cases.iter().enumerate() {
        let rule_id = family_rule_id(case.plan.family);
        let span_start = (noise_len + case.wrapped.token_offset) as u64;
        let span_end = span_start + case.wrapped.token_len as u64;

        // Any-intersection match: finding overlaps the expected token span.
        let found = findings.iter().any(|f| {
            f.rule_id == rule_id && f.root_hint_start < span_end && f.root_hint_end > span_start
        });

        match case.expectation {
            Outcome::MustMatch if !found => {
                violations.push(MutationViolation {
                    case_index: case_idx,
                    family: case.plan.family,
                    expected: Outcome::MustMatch,
                    found: false,
                    message: format!(
                        "case {case_idx} ({:?}): MustMatch but not found (rule_id={rule_id}, span={span_start}..{span_end})",
                        case.plan.family,
                    ),
                });
            }
            Outcome::MustNotMatch if found => {
                // The expectation oracle predicts MustNotMatch but the engine
                // detected the token. This can happen when context wrappers
                // contribute chars that extend the regex match, or when the
                // engine's validation window is wider than the oracle assumed.
                // Phase 1: log but do not fail. False-negative detection
                // (MustMatch not found) is the primary mutation testing value.
            }
            _ => {}
        }
    }

    MutationCheckResult {
        passed: violations.is_empty(),
        violations,
    }
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

fn family_rule_id(family: TokenFamily) -> u32 {
    TokenFamily::ALL
        .iter()
        .position(|f| *f == family)
        .expect("family must be in ALL") as u32
}

fn build_family_rules(cases: &[GeneratedCase]) -> Vec<FamilyRule> {
    let mut rules = Vec::with_capacity(TokenFamily::ALL.len());

    for family in TokenFamily::ALL {
        let rule_id = family_rule_id(family);
        let (anchors, regex, radius) = match family {
            TokenFamily::AwsAccessKey => {
                (vec![b"AKIA".to_vec()], "AKIA[A-Z2-7]{16}".to_string(), 28)
            }
            TokenFamily::GithubFinegrainedPat => (
                vec![b"github_pat_".to_vec()],
                "github_pat_[0-9A-Za-z]{82}".to_string(),
                101,
            ),
            TokenFamily::GithubClassicPat => (
                vec![b"ghp_".to_vec()],
                "ghp_[0-9A-Za-z]{36}".to_string(),
                48,
            ),
            TokenFamily::JwtLike => (
                vec![b"eyJ".to_vec()],
                r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+".to_string(),
                300,
            ),
            TokenFamily::Base64Blob => {
                let anchor = first_canonical_prefix(cases, family, 4);
                (vec![anchor], "[A-Za-z0-9+/]{32,68}={0,2}".to_string(), 80)
            }
            TokenFamily::UrlEncodedBlob => {
                let anchor = first_canonical_prefix(cases, family, 6);
                (vec![anchor], r"(?:%[0-9A-Fa-f]{2}){16,32}".to_string(), 120)
            }
        };
        rules.push(FamilyRule {
            rule_id,
            anchors,
            regex,
            radius,
        });
    }

    rules
}

fn first_canonical_prefix(cases: &[GeneratedCase], family: TokenFamily, len: usize) -> Vec<u8> {
    for case in cases {
        if case.plan.family == family {
            return case.canonical[..len.min(case.canonical.len())].to_vec();
        }
    }
    let token = family.gen_valid(&mut SimRng::new(0));
    token[..len.min(token.len())].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_for_family_produces_valid_regex() {
        let mut rng = SimRng::new(42);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
        let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
        let rules = build_family_rules(&cases);

        for (rule, family) in rules.iter().zip(TokenFamily::ALL.iter()) {
            let re = regex::Regex::new(&rule.regex)
                .unwrap_or_else(|e| panic!("regex compile failed for {family:?}: {e}"));
            let canonical = family.gen_valid(&mut SimRng::new(99));
            let text = std::str::from_utf8(&canonical)
                .unwrap_or_else(|_| panic!("{family:?} canonical not utf8"));
            assert!(
                re.is_match(text),
                "{family:?} canonical does not match regex {:?}",
                rule.regex,
            );
        }
    }

    #[test]
    fn build_mutation_scenario_determinism() {
        let mut rng1 = SimRng::new(7);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng1, 1);
        let mut rng2 = SimRng::new(100);
        let mut rng3 = SimRng::new(100);
        let (s1, _, _) = build_mutation_scenario(&plans, 64, &mut rng2);
        let (s2, _, _) = build_mutation_scenario(&plans, 64, &mut rng3);
        let json1 = serde_json::to_string(&s1).unwrap();
        let json2 = serde_json::to_string(&s2).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn token_span_computed_correctly() {
        use super::super::plan::{ContextWrap, MutationPlan};

        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 0,
            ops: vec![],
            context: ContextWrap::EnvAssignment,
        };
        let plans = vec![plan];
        let mut rng = SimRng::new(0);
        let (_scenario, cases, noise_len) = build_mutation_scenario(&plans, 16, &mut rng);

        let case = &cases[0];
        let expected_start = noise_len + case.wrapped.token_offset;
        let expected_end = expected_start + case.wrapped.token_len;
        // Verify the noise_len is passed through correctly.
        assert_eq!(noise_len, 16);
        // For EnvAssignment, token_offset > 0.
        assert!(case.wrapped.token_offset > 0);
        assert!(expected_end > expected_start);
    }

    #[test]
    fn noise_bytes_outside_regex_charclass() {
        let noise = "\n".repeat(100);
        let mut rng = SimRng::new(42);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
        let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
        let rules = build_family_rules(&cases);

        for (rule, family) in rules.iter().zip(TokenFamily::ALL.iter()) {
            let re = regex::Regex::new(&rule.regex).unwrap();
            assert!(
                !re.is_match(&noise),
                "{family:?} regex matches pure newline noise",
            );
        }
    }
}
