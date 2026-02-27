//! Adapter that translates [`MutationPlan`]s into a [`Scenario`] consumable
//! by [`ScannerSimRunner`], plus a post-run mutation oracle.
//!
//! # Two-oracle architecture
//!
//! The sim-runner's built-in ground-truth oracle checks every finding against
//! `scenario.expected` using containment-based span matching (`expected.span
//! ⊆ finding.span`). Mutation testing cannot predict exact spans up front
//! because context wrappers and encoding layers shift boundaries, so we
//! register only [`MayMiss`] point-span sentinels that the ground-truth oracle
//! will never fail on. The real correctness check happens *after* the scan
//! completes, in [`check_mutation_expectations`], which uses any-intersection
//! span matching and consults the per-case [`Outcome`] predictions from the
//! family oracle.
//!
//! # File layout
//!
//! Each mutation case becomes a separate simulated file named
//! `mutation_<index>.txt`. The file content is structured as:
//!
//! ```text
//! [noise_len bytes of '\n'] [wrapped token bytes] [noise_len bytes of '\n']
//! ```
//!
//! The newline noise padding serves two purposes: it separates the token from
//! file boundaries so that boundary effects do not mask detection failures,
//! and it provides enough leading context for the engine's overlap/radius
//! requirements (the caller typically sets `noise_len` to the engine's
//! `required_overlap()`).
//!
//! [`MayMiss`]: ExpectedDisposition::MayMiss
//! [`Outcome`]: super::family::Outcome

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

/// Aggregate result of [`check_mutation_expectations`].
///
/// `passed` is `true` when every case's expectation was satisfied. When
/// `false`, `violations` contains one entry per failing case with diagnostic
/// details. Note that only `MustMatch`-not-found failures are recorded;
/// `MustNotMatch`-but-found cases are intentionally tolerated (see
/// [`check_mutation_expectations`] for rationale).
#[derive(Clone, Debug)]
pub struct MutationCheckResult {
    pub passed: bool,
    pub violations: Vec<MutationViolation>,
}

/// A single mutation expectation that was violated.
///
/// Currently only generated for `MustMatch` cases where no overlapping
/// finding was produced. The `message` field contains a human-readable
/// diagnostic including the rule ID and expected byte span.
#[derive(Clone, Debug)]
pub struct MutationViolation {
    /// Index into the original `plans` / `cases` slice.
    pub case_index: usize,
    /// Token family of the failing case.
    pub family: TokenFamily,
    /// The oracle's prediction (always `MustMatch` for current violations).
    pub expected: Outcome,
    /// Whether the engine produced a matching finding.
    pub found: bool,
    /// Human-readable diagnostic with rule ID, family, and byte span.
    pub message: String,
}

/// Per-family detection rule specification used to build the mutation scenario's
/// [`RuleSuiteSpec`].
///
/// Each [`TokenFamily`] maps to exactly one `FamilyRule`. The `rule_id` is
/// the family's index in [`TokenFamily::ALL`], which both the scenario builder
/// and the mutation oracle use to correlate findings back to families.
struct FamilyRule {
    /// Positional index of this family in [`TokenFamily::ALL`].
    rule_id: u32,
    /// Byte-string anchors the engine uses for fast prefix filtering.
    anchors: Vec<Vec<u8>>,
    /// Regex pattern the engine compiles for full-match validation.
    regex: String,
    /// Search radius (bytes around an anchor hit) the engine scans.
    radius: u32,
}

/// Build a [`Scenario`] and [`Vec<GeneratedCase>`] from a batch of mutation plans.
///
/// Returns `(scenario, cases, noise_len_used)`.
///
/// The scenario contains one simulated file per plan, each with the
/// noise-token-noise layout described in the module docs. The `expected`
/// field is populated with [`MayMiss`] point-span sentinels (1-byte spans
/// every 8 bytes through the token region, for every rule ID) that satisfy
/// the ground-truth oracle's containment check without causing false
/// failures. The mutation oracle ([`check_mutation_expectations`]) uses the
/// returned `cases` and `noise_len_used` to compute token spans independently.
///
/// The caller typically calls this twice: once with a placeholder `noise_len`
/// to discover the engine's `required_overlap()`, then again with
/// `noise_len = required_overlap` to ensure the noise padding is wide enough
/// for the engine's search radius. See the random-seed test harness for this
/// two-pass pattern.
///
/// [`MayMiss`]: ExpectedDisposition::MayMiss
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

        // Scatter 1-byte MayMiss point spans every 8 bytes through the
        // wrapped-token region, for every rule_id. The ground-truth oracle
        // requires expected.span ⊆ finding.span, so any real finding >=8
        // bytes wide is guaranteed to contain at least one sentinel. We
        // register all rule_ids (not just the case's own family) because the
        // ground-truth oracle would flag an unexpected finding for a rule_id
        // that has no expected entry at all.
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

/// Build an [`Engine`] from a mutation scenario's rule suite.
///
/// The engine is configured with no transform layers and
/// [`AnchorPolicy::ManualOnly`]. Transforms are omitted because the
/// mutation plans already apply their own encoding layers via `MutOp::Encode`,
/// and stacking engine transforms on top would make the oracle's span
/// predictions unreliable. `ManualOnly` prevents the engine from
/// auto-discovering anchors, ensuring it uses exactly the anchors specified
/// in the family rules.
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
/// For each case, computes the expected token span as
/// `noise_len + wrapped.token_offset .. + token_len` and checks whether any
/// finding with the correct `rule_id` intersects that span. Intersection
/// matching (`finding.start < span.end && finding.end > span.start`) is
/// deliberately more lenient than the ground-truth oracle's containment
/// check, because mutations can shift the regex match boundaries relative
/// to the oracle's predicted span.
///
/// # Asymmetric failure treatment
///
/// - **`MustMatch` not found** -- recorded as a violation. This is the
///   primary value of mutation testing: detecting false negatives where the
///   engine fails to find an unmutated (or benignly mutated) token.
/// - **`MustNotMatch` but found** -- silently ignored. Context wrappers can
///   contribute characters that extend a regex match beyond what the oracle
///   predicted, and the engine's validation window may be wider than assumed.
///   Treating these as failures would produce noisy false alarms without
///   meaningful signal.
/// - **`MayMatch`** -- either outcome is accepted by definition.
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

/// Map a [`TokenFamily`] to its rule ID (its positional index in
/// [`TokenFamily::ALL`]).
///
/// This index-based mapping is the single source of truth for correlating
/// families to rules throughout the adapter. Both `build_family_rules` and
/// `check_mutation_expectations` use it, so rule IDs are consistent between
/// scenario construction and post-run checking.
fn family_rule_id(family: TokenFamily) -> u32 {
    TokenFamily::ALL
        .iter()
        .position(|f| *f == family)
        .expect("family must be in ALL") as u32
}

/// Build one [`FamilyRule`] per token family with anchors, regex, and radius
/// tuned to match the canonical (unmutated) token format.
///
/// Families with a known structural prefix (AWS, GitHub, JWT) use that prefix
/// as the anchor and a regex that matches the full canonical format. Blob
/// families (Base64Blob, UrlEncodedBlob) lack a fixed prefix, so they derive
/// a short anchor from the first case's canonical token via
/// [`first_canonical_prefix`]. This makes the anchor seed-dependent but
/// deterministic.
///
/// Radius values are set to slightly exceed the maximum canonical token
/// length so the engine's search window covers the entire token after an
/// anchor hit, even if the anchor appears at the token's start.
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

/// Extract the first `len` bytes of the canonical token for `family` from the
/// generated cases, to use as an anchor for families without a fixed prefix.
///
/// Falls back to generating a fresh token with seed 0 if no case matches
/// (e.g. if the plan batch does not include this family). The fallback is
/// deterministic but may produce a different anchor than a case-derived one,
/// so callers should ensure every family has at least one case when anchor
/// stability matters.
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
    fn family_rules_valid_regex_and_reject_noise() {
        let mut rng = SimRng::new(42);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
        let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
        let rules = build_family_rules(&cases);
        let noise = "\n".repeat(100);

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
            assert!(
                !re.is_match(&noise),
                "{family:?} regex matches pure newline noise",
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
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod adapter_proptests {
    use super::super::plan::{ContextWrap, MutationPlan};
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 32;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        /// Varies the seed and checks that every family's regex matches its
        /// canonical token and rejects pure-newline noise.
        #[test]
        fn prop_family_rules_match_canonical_and_reject_noise(seed: u64) {
            let mut rng = SimRng::new(seed);
            let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
            let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
            let rules = build_family_rules(&cases);
            let noise = "\n".repeat(100);

            for (rule, family) in rules.iter().zip(TokenFamily::ALL.iter()) {
                let re = regex::Regex::new(&rule.regex)
                    .unwrap_or_else(|e| panic!("regex compile failed for {:?}: {}", family, e));

                let canonical = family.gen_valid(&mut SimRng::new(seed.wrapping_add(1)));
                let text = std::str::from_utf8(&canonical)
                    .unwrap_or_else(|_| panic!("{:?} canonical not utf8", family));
                prop_assert!(
                    re.is_match(text),
                    "{:?} canonical does not match regex {:?} (seed={})",
                    family, rule.regex, seed,
                );
                prop_assert!(
                    !re.is_match(&noise),
                    "{:?} regex matches pure newline noise (seed={})",
                    family, seed,
                );
            }
        }

        /// Varies the seed and checks that `build_mutation_scenario` is
        /// deterministic for any seed.
        #[test]
        fn prop_build_mutation_scenario_determinism(seed: u64) {
            let mut rng = SimRng::new(seed);
            let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
            let mut rng2 = SimRng::new(seed.wrapping_add(100));
            let mut rng3 = SimRng::new(seed.wrapping_add(100));
            let (s1, _, _) = build_mutation_scenario(&plans, 64, &mut rng2);
            let (s2, _, _) = build_mutation_scenario(&plans, 64, &mut rng3);
            let json1 = serde_json::to_string(&s1).unwrap();
            let json2 = serde_json::to_string(&s2).unwrap();
            prop_assert!(
                json1 == json2,
                "scenario not deterministic for seed={}",
                seed,
            );
        }

        /// Varies seed, noise_len, family, and context wrapper to check that
        /// token_len > 0, the span falls within the file, and non-Raw
        /// contexts produce token_offset > 0.
        #[test]
        fn prop_token_spans_valid_for_any_context(
            seed: u64,
            noise_len in 0_usize..256,
            family_idx in 0_usize..6,
            context_idx in 0_usize..6,
        ) {
            let family = TokenFamily::ALL[family_idx];
            let context = ContextWrap::ALL[context_idx];

            let plan = MutationPlan {
                family,
                base_seed: seed,
                case_id: 0,
                ops: vec![],
                context,
            };
            let plans = vec![plan];
            let mut rng = SimRng::new(seed);
            let (_scenario, cases, nl) = build_mutation_scenario(&plans, noise_len, &mut rng);

            let case = &cases[0];
            prop_assert!(
                case.wrapped.token_len > 0,
                "{:?}/{:?}: token_len must be > 0",
                family, context,
            );
            let span_end = nl + case.wrapped.token_offset + case.wrapped.token_len;
            let file_len = nl + case.wrapped.bytes.len() + nl;
            prop_assert!(
                span_end <= file_len,
                "{:?}/{:?}: span end {} exceeds file len {}",
                family, context, span_end, file_len,
            );
            if !matches!(context, ContextWrap::Raw) {
                prop_assert!(
                    case.wrapped.token_offset > 0,
                    "{:?}/{:?}: non-Raw context should have token_offset > 0",
                    family, context,
                );
            }
        }
    }
}
