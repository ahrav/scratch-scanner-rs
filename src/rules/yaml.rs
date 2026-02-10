//! YAML rule deserialization and conversion to `RuleSpec`.
//!
//! Defines serde intermediate types that mirror the YAML schema, then converts
//! them into `RuleSpec` values with interned `'static` references. Rule literals
//! are process-lifetime data by design, but interning avoids repeated growth
//! when the same YAML is parsed multiple times.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde::Deserialize;

use crate::api::{EntropySpec, LocalContextSpec, RuleSpec, TwoPhaseSpec, ValidatorKind};

use super::RulesError;

// ---------------------------------------------------------------------------
// YAML serde types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlRulesFile {
    pub rules: Vec<YamlRule>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlRule {
    pub name: String,
    pub regex: String,
    pub anchors: Vec<String>,
    pub radius: usize,
    #[serde(default)]
    pub must_contain: Option<String>,
    #[serde(default)]
    pub keywords_any: Option<Vec<String>>,
    #[serde(default)]
    pub value_suppressors_any: Option<Vec<String>>,
    #[serde(default)]
    pub entropy: Option<YamlEntropy>,
    #[serde(default)]
    pub two_phase: Option<YamlTwoPhase>,
    #[serde(default)]
    pub local_context: Option<YamlLocalContext>,
    #[serde(default)]
    pub secret_group: Option<u16>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlEntropy {
    pub min_bits_per_byte: f32,
    pub min_len: usize,
    pub max_len: usize,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlTwoPhase {
    pub seed_radius: usize,
    pub full_radius: usize,
    pub confirm_any: Vec<String>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlLocalContext {
    pub lookbehind: usize,
    pub lookahead: usize,
    #[serde(default)]
    pub require_same_line_assignment: bool,
    #[serde(default)]
    pub require_quoted: bool,
    #[serde(default)]
    pub key_names_any: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Atom interning — rules live for the entire process, so we store interned
// allocations in a global pool and reuse them across parse calls.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RuleAtomPool {
    strings: HashMap<String, &'static str>,
    bytes: HashMap<Vec<u8>, &'static [u8]>,
    bytes_slices: HashMap<Vec<Vec<u8>>, &'static [&'static [u8]]>,
}

impl RuleAtomPool {
    fn intern_str(&mut self, s: String) -> &'static str {
        if let Some(existing) = self.strings.get(&s) {
            return existing;
        }
        let leaked = Box::leak(s.clone().into_boxed_str());
        self.strings.insert(s, leaked);
        leaked
    }

    fn intern_bytes(&mut self, s: String) -> &'static [u8] {
        self.intern_bytes_vec(s.into_bytes())
    }

    fn intern_bytes_vec(&mut self, bytes: Vec<u8>) -> &'static [u8] {
        if let Some(existing) = self.bytes.get(&bytes) {
            return existing;
        }
        let leaked = Box::leak(bytes.clone().into_boxed_slice());
        self.bytes.insert(bytes, leaked);
        leaked
    }

    fn intern_bytes_slice(&mut self, values: Vec<String>) -> &'static [&'static [u8]] {
        let keys: Vec<Vec<u8>> = values.into_iter().map(String::into_bytes).collect();
        if let Some(existing) = self.bytes_slices.get(&keys) {
            return existing;
        }

        let mut refs: Vec<&'static [u8]> = Vec::with_capacity(keys.len());
        for key in &keys {
            refs.push(self.intern_bytes_vec(key.clone()));
        }
        let leaked = Box::leak(refs.into_boxed_slice());
        self.bytes_slices.insert(keys, leaked);
        leaked
    }
}

static RULE_ATOMS: LazyLock<Mutex<RuleAtomPool>> =
    LazyLock::new(|| Mutex::new(RuleAtomPool::default()));

fn with_rule_atoms<T>(f: impl FnOnce(&mut RuleAtomPool) -> T) -> T {
    let mut guard = RULE_ATOMS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

// ---------------------------------------------------------------------------
// Core conversion
// ---------------------------------------------------------------------------

/// Parse YAML content into a `Vec<RuleSpec>`.
///
/// Deserializes the YAML, then converts each `YamlRule` into a `RuleSpec`
/// by compiling regexes and interning textual fields into reusable `'static`
/// references.
pub(crate) fn parse_yaml_rules(content: &str) -> Result<Vec<RuleSpec>, RulesError> {
    let file: YamlRulesFile = serde_yml::from_str(content).map_err(RulesError::Yaml)?;

    let mut rules = Vec::with_capacity(file.rules.len());
    for yr in file.rules {
        let YamlRule {
            name,
            regex,
            anchors,
            radius,
            must_contain,
            keywords_any,
            value_suppressors_any,
            entropy,
            two_phase,
            local_context,
            secret_group,
        } = yr;

        let re = super::build_regex(&regex).map_err(|error| RulesError::Regex {
            rule_name: name.clone(),
            pattern: regex.clone(),
            error,
        })?;

        let (
            name,
            anchors,
            must_contain,
            keywords_any,
            value_suppressors_any,
            two_phase,
            local_context,
        ) = with_rule_atoms(|atoms| {
            let anchors = atoms.intern_bytes_slice(anchors);
            let must_contain = must_contain.map(|s| atoms.intern_bytes(s));
            let keywords_any = keywords_any.map(|kws| atoms.intern_bytes_slice(kws));
            let value_suppressors_any =
                value_suppressors_any.map(|vs| atoms.intern_bytes_slice(vs));
            let two_phase = two_phase.map(|tp| TwoPhaseSpec {
                seed_radius: tp.seed_radius,
                full_radius: tp.full_radius,
                confirm_any: atoms.intern_bytes_slice(tp.confirm_any),
            });
            let local_context = local_context.map(|lc| LocalContextSpec {
                lookbehind: lc.lookbehind,
                lookahead: lc.lookahead,
                require_same_line_assignment: lc.require_same_line_assignment,
                require_quoted: lc.require_quoted,
                key_names_any: lc.key_names_any.map(|keys| atoms.intern_bytes_slice(keys)),
            });
            (
                atoms.intern_str(name),
                anchors,
                must_contain,
                keywords_any,
                value_suppressors_any,
                two_phase,
                local_context,
            )
        });

        let entropy = entropy.map(|e| EntropySpec {
            min_bits_per_byte: e.min_bits_per_byte,
            min_len: e.min_len,
            max_len: e.max_len,
        });

        rules.push(RuleSpec {
            name,
            anchors,
            radius,
            // NOTE: ValidatorKind is not expressible in the YAML schema.
            // Fast validators are tightly coupled to specific regex patterns
            // and are only set programmatically. All YAML-loaded rules use None.
            validator: ValidatorKind::None,
            two_phase,
            must_contain,
            keywords_any,
            value_suppressors_any,
            entropy,
            local_context,
            secret_group,
            re,
        });
    }

    Ok(rules)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ValidatorKind;
    use crate::rules::builtin_rules;
    use crate::{demo_tuning, AnchorPolicy, Engine, Finding};
    use std::path::Path;

    /// Convert `RuleSpec` back to YAML intermediate type for round-trip testing.
    fn rulespec_to_yaml(rule: &RuleSpec) -> YamlRule {
        let anchors: Vec<String> = rule
            .anchors
            .iter()
            .map(|a| String::from_utf8(a.to_vec()).expect("anchors should be ASCII"))
            .collect();

        let keywords_any = rule.keywords_any.map(|kws| {
            kws.iter()
                .map(|k| String::from_utf8(k.to_vec()).expect("keywords should be ASCII"))
                .collect()
        });
        let value_suppressors_any = rule.value_suppressors_any.map(|sups| {
            sups.iter()
                .map(|s| {
                    // Suppressors originate from YAML string scalars, so they are
                    // guaranteed to be valid UTF-8 on the round-trip path.
                    std::str::from_utf8(s)
                        .expect("value suppressors should be valid UTF-8")
                        .to_owned()
                })
                .collect()
        });

        let must_contain = rule
            .must_contain
            .map(|mc| String::from_utf8(mc.to_vec()).expect("must_contain should be ASCII"));

        let entropy = rule.entropy.as_ref().map(|e| YamlEntropy {
            min_bits_per_byte: e.min_bits_per_byte,
            min_len: e.min_len,
            max_len: e.max_len,
        });

        let two_phase = rule.two_phase.as_ref().map(|tp| YamlTwoPhase {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm_any: tp
                .confirm_any
                .iter()
                .map(|c| String::from_utf8(c.to_vec()).expect("confirm_any should be ASCII"))
                .collect(),
        });

        let local_context = rule.local_context.as_ref().map(|lc| YamlLocalContext {
            lookbehind: lc.lookbehind,
            lookahead: lc.lookahead,
            require_same_line_assignment: lc.require_same_line_assignment,
            require_quoted: lc.require_quoted,
            key_names_any: lc.key_names_any.map(|kns| {
                kns.iter()
                    .map(|k| String::from_utf8(k.to_vec()).expect("key_names should be ASCII"))
                    .collect()
            }),
        });

        YamlRule {
            name: rule.name.to_string(),
            regex: rule.re.as_str().to_string(),
            anchors,
            radius: rule.radius,
            must_contain,
            keywords_any,
            value_suppressors_any,
            entropy,
            two_phase,
            local_context,
            secret_group: rule.secret_group,
        }
    }

    fn assert_rules_equal(original_rules: &[RuleSpec], parsed_rules: &[RuleSpec]) {
        assert_eq!(
            original_rules.len(),
            parsed_rules.len(),
            "rule count mismatch"
        );

        for (orig, parsed) in original_rules.iter().zip(parsed_rules.iter()) {
            assert_eq!(orig.name, parsed.name, "name mismatch");
            assert_eq!(
                orig.radius, parsed.radius,
                "radius mismatch for {}",
                orig.name
            );
            assert_eq!(
                orig.re.as_str(),
                parsed.re.as_str(),
                "regex mismatch for {}",
                orig.name
            );

            // Anchors.
            assert_eq!(
                orig.anchors.len(),
                parsed.anchors.len(),
                "anchor count mismatch for {}",
                orig.name
            );
            for (oa, pa) in orig.anchors.iter().zip(parsed.anchors.iter()) {
                assert_eq!(*oa, *pa, "anchor mismatch for {}", orig.name);
            }

            // Keywords.
            match (orig.keywords_any, parsed.keywords_any) {
                (Some(ok), Some(pk)) => {
                    assert_eq!(
                        ok.len(),
                        pk.len(),
                        "keywords count mismatch for {}",
                        orig.name
                    );
                    for (okw, pkw) in ok.iter().zip(pk.iter()) {
                        assert_eq!(*okw, *pkw, "keyword mismatch for {}", orig.name);
                    }
                }
                (None, None) => {}
                _ => panic!("keywords_any presence mismatch for {}", orig.name),
            }

            // Value suppressors.
            match (orig.value_suppressors_any, parsed.value_suppressors_any) {
                (Some(os), Some(ps)) => {
                    assert_eq!(
                        os.len(),
                        ps.len(),
                        "value_suppressors_any count mismatch for {}",
                        orig.name
                    );
                    for (ovs, pvs) in os.iter().zip(ps.iter()) {
                        assert_eq!(*ovs, *pvs, "value_suppressor mismatch for {}", orig.name);
                    }
                }
                (None, None) => {}
                _ => panic!("value_suppressors_any presence mismatch for {}", orig.name),
            }

            // Entropy.
            match (&orig.entropy, &parsed.entropy) {
                (Some(oe), Some(pe)) => {
                    assert_eq!(
                        oe.min_bits_per_byte, pe.min_bits_per_byte,
                        "entropy min_bits_per_byte mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        oe.min_len, pe.min_len,
                        "entropy min_len mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        oe.max_len, pe.max_len,
                        "entropy max_len mismatch for {}",
                        orig.name
                    );
                }
                (None, None) => {}
                _ => panic!("entropy presence mismatch for {}", orig.name),
            }

            // Two-phase.
            match (&orig.two_phase, &parsed.two_phase) {
                (Some(otp), Some(ptp)) => {
                    assert_eq!(
                        otp.seed_radius, ptp.seed_radius,
                        "two_phase seed_radius mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        otp.full_radius, ptp.full_radius,
                        "two_phase full_radius mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        otp.confirm_any.len(),
                        ptp.confirm_any.len(),
                        "two_phase confirm_any count mismatch for {}",
                        orig.name
                    );
                    for (oc, pc) in otp.confirm_any.iter().zip(ptp.confirm_any.iter()) {
                        assert_eq!(*oc, *pc, "two_phase confirm_any mismatch for {}", orig.name);
                    }
                }
                (None, None) => {}
                _ => panic!("two_phase presence mismatch for {}", orig.name),
            }

            // Local context.
            match (&orig.local_context, &parsed.local_context) {
                (Some(olc), Some(plc)) => {
                    assert_eq!(
                        olc.lookbehind, plc.lookbehind,
                        "local_context lookbehind mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        olc.lookahead, plc.lookahead,
                        "local_context lookahead mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        olc.require_same_line_assignment, plc.require_same_line_assignment,
                        "local_context require_same_line_assignment mismatch for {}",
                        orig.name
                    );
                    assert_eq!(
                        olc.require_quoted, plc.require_quoted,
                        "local_context require_quoted mismatch for {}",
                        orig.name
                    );
                    match (olc.key_names_any, plc.key_names_any) {
                        (Some(ok), Some(pk)) => {
                            assert_eq!(
                                ok.len(),
                                pk.len(),
                                "local_context key_names count mismatch for {}",
                                orig.name
                            );
                            for (okn, pkn) in ok.iter().zip(pk.iter()) {
                                assert_eq!(
                                    *okn, *pkn,
                                    "local_context key_name mismatch for {}",
                                    orig.name
                                );
                            }
                        }
                        (None, None) => {}
                        _ => panic!(
                            "local_context key_names_any presence mismatch for {}",
                            orig.name
                        ),
                    }
                }
                (None, None) => {}
                _ => panic!("local_context presence mismatch for {}", orig.name),
            }

            // Secret group.
            assert_eq!(
                orig.secret_group, parsed.secret_group,
                "secret_group mismatch for {}",
                orig.name
            );

            // Validator (always None for builtin rules).
            assert_eq!(
                orig.validator, parsed.validator,
                "validator mismatch for {}",
                orig.name
            );
        }
    }

    fn scan_yaml_rules(yaml: &str, hay: &[u8]) -> Vec<Finding> {
        let rules = parse_yaml_rules(yaml).expect("parse YAML rules");
        let engine = Engine::new_with_anchor_policy(
            rules,
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );
        let mut scratch = engine.new_scratch();
        let mut findings = Vec::with_capacity(1024);
        engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
        findings
    }

    fn builtin_rule_by_name(rule_name: &str) -> RuleSpec {
        builtin_rules()
            .into_iter()
            .find(|rule| rule.name == rule_name)
            .unwrap_or_else(|| panic!("missing builtin rule: {rule_name}"))
    }

    fn scan_single_builtin_rule(rule_name: &str, hay: &[u8]) -> Vec<Finding> {
        let rule = builtin_rule_by_name(rule_name);
        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );
        let mut scratch = engine.new_scratch();
        let mut findings = Vec::with_capacity(16);
        engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
        findings
    }

    /// Build an engine for a single rule, returning a closure that scans a
    /// haystack without rebuilding the Vectorscan database each time.
    fn make_rule_scanner(rule_name: &str) -> impl FnMut(&[u8]) -> Vec<Finding> {
        let rule = builtin_rule_by_name(rule_name);
        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );
        move |hay: &[u8]| {
            let mut scratch = engine.new_scratch();
            let mut findings = Vec::with_capacity(16);
            engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
            findings
        }
    }

    fn has_rule_hit(hits: &[Finding], rule_name: &str) -> bool {
        hits.iter().any(|hit| hit.rule == rule_name)
    }

    fn lcg_next(state: &mut u64) -> u64 {
        // Knuth's MMIX LCG (TAOCP Vol 2): a = 6364136223846793005, c = 1442695040888963407.
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    fn deterministic_secret(state: &mut u64, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let next = lcg_next(state);
            let idx = (next % ALPHABET.len() as u64) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    #[test]
    fn default_rules_yaml_matches_builtin_rules() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("default_rules.yaml");
        let yaml_str = std::fs::read_to_string(&path).expect("read default_rules.yaml");
        let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse default_rules.yaml");
        let expected_rules = builtin_rules();
        assert_rules_equal(&expected_rules, &parsed_rules);
    }

    #[test]
    fn roundtrip_builtin_rules() {
        let original_rules = builtin_rules();

        // Convert to YAML and back.
        let yaml_rules: Vec<YamlRule> = original_rules.iter().map(rulespec_to_yaml).collect();
        let file = YamlRulesFile { rules: yaml_rules };
        let yaml_str = serde_yml::to_string(&file).expect("serialize to YAML");
        let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse YAML rules");
        assert_rules_equal(&original_rules, &parsed_rules);
    }

    #[test]
    fn rulespec_to_yaml_emits_value_suppressors_any_when_present() {
        let yaml = r#"
rules:
  - name: "emit-value-suppressors"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
    secret_group: 1
"#;
        let parsed = parse_yaml_rules(yaml).expect("parse YAML into rulespec");
        let yaml_rule = rulespec_to_yaml(&parsed[0]);

        assert_eq!(
            yaml_rule.value_suppressors_any,
            Some(vec!["EXAMPLE".to_string(), "DUMMY_TOKEN".to_string()])
        );
    }

    #[test]
    fn rulespec_to_yaml_omits_value_suppressors_any_when_absent() {
        let yaml = r#"
rules:
  - name: "omit-value-suppressors"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    secret_group: 1
"#;
        let parsed = parse_yaml_rules(yaml).expect("parse YAML into rulespec");
        let yaml_rule = rulespec_to_yaml(&parsed[0]);

        assert!(yaml_rule.value_suppressors_any.is_none());
    }

    #[test]
    fn roundtrip_yaml_preserves_value_suppressors_any() {
        let yaml = r#"
rules:
  - name: "roundtrip-value-suppressors"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
    secret_group: 1
"#;

        let original_rules = parse_yaml_rules(yaml).expect("parse original YAML");
        let yaml_rules: Vec<YamlRule> = original_rules.iter().map(rulespec_to_yaml).collect();
        let file = YamlRulesFile { rules: yaml_rules };
        let yaml_str = serde_yml::to_string(&file).expect("serialize to YAML");
        let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse round-tripped YAML");

        assert_rules_equal(&original_rules, &parsed_rules);
    }

    #[test]
    fn yaml_to_engine_suppresses_matching_secret_value() {
        let yaml = r#"
rules:
  - name: "yaml-suppressor-e2e"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    value_suppressors_any: ["EXAMPLE"]
    secret_group: 1
"#;

        let hay = b"prefix TOK_AEXAMPLE1234 suffix";
        let hits = scan_yaml_rules(yaml, hay);
        assert!(
            !hits.iter().any(|h| h.rule == "yaml-suppressor-e2e"),
            "expected suppressor match to prevent finding emission"
        );
    }

    #[test]
    fn yaml_to_engine_emits_when_value_suppressor_absent() {
        let yaml = r#"
rules:
  - name: "yaml-suppressor-e2e"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    secret_group: 1
"#;

        let hay = b"prefix TOK_AEXAMPLE1234 suffix";
        let hits = scan_yaml_rules(yaml, hay);
        assert!(
            hits.iter().any(|h| h.rule == "yaml-suppressor-e2e"),
            "expected finding when suppressors are not configured"
        );
    }

    #[test]
    fn builtin_rules_use_no_fast_validators() {
        let rules = builtin_rules();
        assert!(!rules.is_empty(), "builtin rule set should not be empty");
        for rule in rules {
            assert_eq!(
                rule.validator,
                ValidatorKind::None,
                "rule '{}' unexpectedly enables fast validator",
                rule.name
            );
        }
    }

    #[test]
    fn builtin_rules_count() {
        let rules = builtin_rules();
        assert_eq!(rules.len(), 223, "expected 223 builtin rules");
    }

    #[test]
    fn top_fp_rules_have_value_suppressors_configured() {
        let target_rules = [
            "generic-api-key",
            "hashicorp-tf-password",
            "curl-auth-header",
            "curl-auth-user",
            "atlassian-api-token",
        ];

        for rule_name in target_rules {
            let rule = builtin_rule_by_name(rule_name);
            let suppressors = rule
                .value_suppressors_any
                .unwrap_or_else(|| panic!("expected value_suppressors_any for {rule_name}"));
            assert!(
                !suppressors.is_empty(),
                "expected non-empty value_suppressors_any for {rule_name}"
            );
            assert!(
                suppressors.iter().any(|v| *v == b"example"),
                "expected shared suppressor 'example' for {rule_name}"
            );
        }
    }

    #[test]
    fn generic_api_key_suppresses_placeholder_value() {
        let rule_name = "generic-api-key";
        let hay = b"API_KEY=YOUR_EXAMPLE_1";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder API key to be suppressed"
        );
    }

    #[test]
    fn generic_api_key_allows_real_value() {
        let rule_name = "generic-api-key";
        let hay = b"API_KEY=a8f2k9x7m4p1q6w3";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected real-looking API key to be reported"
        );
    }

    #[test]
    fn generic_api_key_random_high_entropy_values_are_not_suppressed() {
        let rule_name = "generic-api-key";
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .expect("generic-api-key should have value suppressors");
        let suppressors: Vec<&str> = suppressors
            .iter()
            .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
            .collect();

        let mut scan = make_rule_scanner(rule_name);
        let mut seed = 0x9E3779B97F4A7C15_u64;
        let mut checked = 0usize;
        for _ in 0..192 {
            let secret = deterministic_secret(&mut seed, 24);
            // Skip generated values that happen to contain a suppressor substring.
            if suppressors.iter().any(|sup| secret.contains(sup)) {
                continue;
            }

            let distinct = secret
                .as_bytes()
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<u8>>()
                .len();
            if distinct < 8 {
                continue;
            }

            let hay = format!("API_KEY={secret}");
            let hits = scan(hay.as_bytes());
            assert!(
                has_rule_hit(&hits, rule_name),
                "expected randomized secret '{secret}' to be reported"
            );
            checked += 1;
        }

        assert!(
            checked >= 96,
            "expected to validate at least 96 randomized secrets, got {checked}"
        );
    }

    #[test]
    fn hashicorp_tf_password_random_high_entropy_values_are_not_suppressed() {
        let rule_name = "hashicorp-tf-password";
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .expect("hashicorp-tf-password should have value suppressors");
        let suppressors: Vec<&str> = suppressors
            .iter()
            .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
            .collect();

        let mut scan = make_rule_scanner(rule_name);
        let mut seed = 0xA5A5A5A5A5A5A5A5_u64;
        let mut checked = 0usize;
        for _ in 0..192 {
            let secret = deterministic_secret(&mut seed, 12);
            if suppressors
                .iter()
                .any(|sup| secret.to_lowercase().contains(&sup.to_lowercase()))
            {
                continue;
            }

            let distinct = secret
                .as_bytes()
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<u8>>()
                .len();
            if distinct < 6 {
                continue;
            }

            let hay = format!("password = \"{secret}\"");
            let hits = scan(hay.as_bytes());
            assert!(
                has_rule_hit(&hits, rule_name),
                "expected randomized terraform password '{secret}' to be reported"
            );
            checked += 1;
        }

        assert!(
            checked >= 96,
            "expected to validate at least 96 randomized secrets, got {checked}"
        );
    }

    #[test]
    fn atlassian_api_token_random_high_entropy_values_are_not_suppressed() {
        let rule_name = "atlassian-api-token";
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .expect("atlassian-api-token should have value suppressors");
        let suppressors: Vec<&str> = suppressors
            .iter()
            .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
            .collect();

        // The atlassian rule's group 1 expects [a-z0-9]{20}[a-f0-9]{4} — 24 lowercase hex-ish chars.
        let hex_alphabet: &[u8] = b"0123456789abcdef";
        let alnum_alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let mut scan = make_rule_scanner(rule_name);
        let mut seed = 0xCAFEBABEDEAD5678_u64;
        let mut checked = 0usize;
        for _ in 0..192 {
            // Build a valid secret: 20 [a-z0-9] chars + 4 [a-f0-9] chars.
            let mut secret = String::with_capacity(24);
            for _ in 0..20 {
                let next = lcg_next(&mut seed);
                secret.push(alnum_alphabet[(next % alnum_alphabet.len() as u64) as usize] as char);
            }
            for _ in 0..4 {
                let next = lcg_next(&mut seed);
                secret.push(hex_alphabet[(next % hex_alphabet.len() as u64) as usize] as char);
            }

            if suppressors
                .iter()
                .any(|sup| secret.to_lowercase().contains(&sup.to_lowercase()))
            {
                continue;
            }

            let distinct = secret
                .as_bytes()
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<u8>>()
                .len();
            if distinct < 6 {
                continue;
            }

            let hay = format!("JIRA_TOKEN={secret}");
            let hits = scan(hay.as_bytes());
            assert!(
                has_rule_hit(&hits, rule_name),
                "expected randomized atlassian token '{secret}' to be reported"
            );
            checked += 1;
        }

        assert!(
            checked >= 96,
            "expected to validate at least 96 randomized secrets, got {checked}"
        );
    }

    #[test]
    fn hashicorp_tf_password_suppresses_placeholder_value() {
        let rule_name = "hashicorp-tf-password";
        let hay = br#"password = "changeme123""#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder terraform password to be suppressed"
        );
    }

    #[test]
    fn hashicorp_tf_password_allows_real_value() {
        let rule_name = "hashicorp-tf-password";
        let hay = br#"password = "a8f2k9x7m4p1q6w3""#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected real-looking terraform password to be reported"
        );
    }

    #[test]
    fn hashicorp_tf_password_allows_real_value_with_password_substring() {
        let rule_name = "hashicorp-tf-password";
        let hay = br#"password = "prodpassword19""#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected terraform password containing 'password' to be reported"
        );
    }

    #[test]
    fn curl_auth_header_suppresses_placeholder_bearer_token() {
        let rule_name = "curl-auth-header";
        let hay = br#"curl -H "Authorization: Bearer YOUR_TOKEN_HERE" https://api.example.com"#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder bearer token to be suppressed"
        );
    }

    #[test]
    fn curl_auth_header_allows_real_bearer_token() {
        let rule_name = "curl-auth-header";
        let hay =
            br#"curl -H "Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9" https://api.internal"#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected real-looking bearer token to be reported"
        );
    }

    #[test]
    fn curl_auth_header_suppresses_placeholder_api_key() {
        let rule_name = "curl-auth-header";
        let hay = br#"curl -H "X-Api-Key: EXAMPLE_KEY_12345" https://api.example.com"#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder X-Api-Key value to be suppressed"
        );
    }

    #[test]
    fn curl_auth_user_suppresses_placeholder_user_password() {
        let rule_name = "curl-auth-user";
        let hay = b"curl -u admin:changeme https://api.example.com";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder user:password to be suppressed"
        );
    }

    #[test]
    fn curl_auth_user_allows_real_user_password() {
        let rule_name = "curl-auth-user";
        let hay = b"curl -u deploy_bot:a8f2k9x7m4p1q6w3 https://registry.internal";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected real-looking curl -u credentials to be reported"
        );
    }

    #[test]
    fn curl_auth_user_allows_real_password_with_password_substring() {
        let rule_name = "curl-auth-user";
        let hay = b"curl -u deploy_bot:password1234 https://registry.internal";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected curl -u credentials containing 'password' to be reported"
        );
    }

    #[test]
    fn curl_auth_user_suppresses_literal_password_example() {
        let rule_name = "curl-auth-user";
        let hay = b"curl -u 'user:password' https://api.example.com";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected user:password literal example to be suppressed"
        );
    }

    /// Regression test for PR #43 review comment:
    /// Reviewer claimed URL text like "example.com" in a curl command could
    /// trigger the "example" suppressor and hide a real bearer token.
    /// The regex only captures the token inside the header value, so the URL
    /// is never part of the extracted secret.
    #[test]
    fn curl_auth_header_url_with_example_does_not_suppress_real_token() {
        let rule_name = "curl-auth-header";
        // Real token + URL containing "example" — should still be reported.
        let hay =
            br#"curl https://api.example.com -H "Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9""#;
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "URL containing 'example' must not suppress a real bearer token"
        );
    }

    /// Regression test for PR #43 review comment:
    /// Reviewer claimed "password" was in hashicorp-tf-password's
    /// value_suppressors_any, which would suppress real passwords containing
    /// that substring. In fact, "password" is NOT a suppressor for this rule.
    #[test]
    fn hashicorp_tf_password_suppressors_do_not_include_password() {
        let rule = builtin_rule_by_name("hashicorp-tf-password");
        let suppressors = rule
            .value_suppressors_any
            .expect("hashicorp-tf-password should have value suppressors");
        assert!(
            !suppressors.iter().any(|s| s == b"password"),
            "literal 'password' must not be a value suppressor — it would cause false negatives"
        );
    }

    #[test]
    fn atlassian_api_token_suppresses_placeholder_value() {
        let rule_name = "atlassian-api-token";
        let hay = b"JIRA_TOKEN=yourexampletokenabcd1234";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            !has_rule_hit(&hits, rule_name),
            "expected placeholder atlassian token to be suppressed"
        );
    }

    #[test]
    fn atlassian_api_token_allows_real_value() {
        let rule_name = "atlassian-api-token";
        let hay = b"JIRA_TOKEN=a8f2k9x7m4p1q6w3b5n0c1d2";
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected real-looking atlassian token to be reported"
        );
    }

    #[test]
    fn curl_auth_header_random_high_entropy_values_are_not_suppressed() {
        let rule_name = "curl-auth-header";
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .expect("curl-auth-header should have value suppressors");
        let suppressors: Vec<&str> = suppressors
            .iter()
            .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
            .collect();

        let mut scan = make_rule_scanner(rule_name);
        let mut seed = 0xDEADBEEFCAFEBABE_u64;
        let mut checked = 0usize;
        for _ in 0..192 {
            let secret = deterministic_secret(&mut seed, 24);
            // Skip generated values that happen to contain a suppressor substring.
            if suppressors.iter().any(|sup| {
                secret
                    .to_ascii_lowercase()
                    .contains(&sup.to_ascii_lowercase())
            }) {
                continue;
            }

            let distinct = secret
                .as_bytes()
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<u8>>()
                .len();
            if distinct < 8 {
                continue;
            }

            let hay = format!("curl -H \"Authorization: Bearer {secret}\" https://api.internal");
            let hits = scan(hay.as_bytes());
            assert!(
                has_rule_hit(&hits, rule_name),
                "expected randomized bearer token '{secret}' to be reported"
            );
            checked += 1;
        }

        assert!(
            checked >= 96,
            "expected to validate at least 96 randomized bearer tokens, got {checked}"
        );
    }

    #[test]
    fn curl_auth_user_random_high_entropy_values_are_not_suppressed() {
        let rule_name = "curl-auth-user";
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .expect("curl-auth-user should have value suppressors");
        let suppressors: Vec<&str> = suppressors
            .iter()
            .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
            .collect();

        let mut scan = make_rule_scanner(rule_name);
        let mut seed = 0xA5A5A5A5B4B4B4B4_u64;
        let mut checked = 0usize;
        for _ in 0..192 {
            let secret = deterministic_secret(&mut seed, 20);
            // Skip generated values that happen to contain a suppressor substring.
            if suppressors.iter().any(|sup| {
                secret
                    .to_ascii_lowercase()
                    .contains(&sup.to_ascii_lowercase())
            }) {
                continue;
            }

            let distinct = secret
                .as_bytes()
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<u8>>()
                .len();
            if distinct < 8 {
                continue;
            }

            let hay = format!("curl -u deploy_svc:{secret} https://registry.internal");
            let hits = scan(hay.as_bytes());
            assert!(
                has_rule_hit(&hits, rule_name),
                "expected randomized curl -u password '{secret}' to be reported"
            );
            checked += 1;
        }

        assert!(
            checked >= 96,
            "expected to validate at least 96 randomized curl -u passwords, got {checked}"
        );
    }

    #[test]
    fn parse_minimal_yaml() {
        let yaml = r#"
rules:
  - name: "test-rule"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
"#;
        let rules = parse_yaml_rules(yaml).expect("parse minimal YAML");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test-rule");
        assert_eq!(rules[0].radius, 64);
        assert!(rules[0].keywords_any.is_none());
        assert!(rules[0].value_suppressors_any.is_none());
        assert!(rules[0].entropy.is_none());
        assert!(rules[0].two_phase.is_none());
        assert!(rules[0].local_context.is_none());
        assert!(rules[0].secret_group.is_none());
    }

    #[test]
    fn parse_yaml_with_value_suppressors_any() {
        let yaml = r#"
rules:
  - name: "suppressor-rule"
    regex: '(tok_)[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
"#;

        let rules = parse_yaml_rules(yaml).expect("parse yaml with value_suppressors_any");
        assert_eq!(rules.len(), 1);
        let suppressors = rules[0]
            .value_suppressors_any
            .expect("value_suppressors_any should be present");
        assert_eq!(suppressors.len(), 2);
        assert_eq!(suppressors[0], b"EXAMPLE");
        assert_eq!(suppressors[1], b"DUMMY_TOKEN");
    }

    #[test]
    fn parse_yaml_without_value_suppressors_any_defaults_to_none() {
        let yaml = r#"
rules:
  - name: "no-suppressor-rule"
    regex: '(tok_)[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
"#;

        let rules = parse_yaml_rules(yaml).expect("parse yaml without value_suppressors_any");
        assert_eq!(rules.len(), 1);
        assert!(rules[0].value_suppressors_any.is_none());
    }

    #[test]
    fn parse_bad_regex_reports_rule_name() {
        let yaml = r#"
rules:
  - name: "bad-rule"
    regex: '[invalid'
    anchors: ["tok"]
    radius: 64
"#;
        match parse_yaml_rules(yaml) {
            Err(RulesError::Regex { rule_name, .. }) => {
                assert_eq!(rule_name, "bad-rule");
            }
            other => panic!("expected Regex error, got: {:?}", other),
        }
    }

    #[test]
    fn parse_empty_rules_list() {
        let yaml = "rules: []\n";
        // parse_yaml_rules itself returns Ok with empty vec;
        // load_rules catches the NoRules case.
        let rules = parse_yaml_rules(yaml).expect("parse empty rules");
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_invalid_yaml_returns_yaml_error() {
        let yaml = "{{{{not valid yaml";
        match parse_yaml_rules(yaml) {
            Err(RulesError::Yaml(_)) => {}
            other => panic!("expected Yaml error, got: {other:?}"),
        }
    }

    #[test]
    fn parse_full_featured_yaml_rule() {
        let yaml = r#"
rules:
  - name: "full-rule"
    regex: '(secret_)[a-z0-9]{16}'
    anchors: ["secret_"]
    radius: 128
    must_contain: "secret_"
    keywords_any: ["secret", "key"]
    value_suppressors_any: ["EXAMPLE", "DUMMY_SECRET"]
    entropy:
      min_bits_per_byte: 3.5
      min_len: 8
      max_len: 64
    two_phase:
      seed_radius: 32
      full_radius: 128
      confirm_any: ["secret"]
    local_context:
      lookbehind: 64
      lookahead: 64
      require_same_line_assignment: true
      require_quoted: false
      key_names_any: ["api_key", "token"]
    secret_group: 1
"#;
        let rules = parse_yaml_rules(yaml).expect("parse full-featured YAML");
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.name, "full-rule");
        assert_eq!(r.radius, 128);
        assert_eq!(r.anchors.len(), 1);
        assert_eq!(r.anchors[0], b"secret_");
        assert_eq!(r.must_contain, Some(b"secret_".as_slice()));
        assert_eq!(r.secret_group, Some(1));
        assert_eq!(r.validator, ValidatorKind::None);

        let kws = r.keywords_any.expect("keywords_any should be present");
        assert_eq!(kws.len(), 2);
        assert_eq!(kws[0], b"secret");
        assert_eq!(kws[1], b"key");

        let suppressors = r
            .value_suppressors_any
            .expect("value_suppressors_any should be present");
        assert_eq!(suppressors.len(), 2);
        assert_eq!(suppressors[0], b"EXAMPLE");
        assert_eq!(suppressors[1], b"DUMMY_SECRET");

        let ent = r.entropy.as_ref().expect("entropy should be present");
        assert_eq!(ent.min_bits_per_byte, 3.5);
        assert_eq!(ent.min_len, 8);
        assert_eq!(ent.max_len, 64);

        let tp = r.two_phase.as_ref().expect("two_phase should be present");
        assert_eq!(tp.seed_radius, 32);
        assert_eq!(tp.full_radius, 128);
        assert_eq!(tp.confirm_any.len(), 1);
        assert_eq!(tp.confirm_any[0], b"secret");

        let lc = r
            .local_context
            .as_ref()
            .expect("local_context should be present");
        assert_eq!(lc.lookbehind, 64);
        assert_eq!(lc.lookahead, 64);
        assert!(lc.require_same_line_assignment);
        assert!(!lc.require_quoted);
        let kns = lc.key_names_any.expect("key_names_any should be present");
        assert_eq!(kns.len(), 2);
        assert_eq!(kns[0], b"api_key");
        assert_eq!(kns[1], b"token");
    }

    #[test]
    fn parse_reuses_interned_storage_across_calls() {
        let yaml = r#"
rules:
  - name: "interned-rule"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_", "TOK_"]
    radius: 64
    must_contain: "tok_"
    keywords_any: ["api", "token"]
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
    two_phase:
      seed_radius: 32
      full_radius: 128
      confirm_any: ["api", "token"]
"#;

        let first = parse_yaml_rules(yaml).expect("first parse");
        let second = parse_yaml_rules(yaml).expect("second parse");
        let a = &first[0];
        let b = &second[0];

        assert!(
            std::ptr::eq(a.name, b.name),
            "name should be interned and reused"
        );
        assert!(
            std::ptr::eq(a.anchors, b.anchors),
            "anchor list should be interned and reused"
        );
        assert!(
            std::ptr::eq(a.anchors[0], b.anchors[0]),
            "anchor bytes should be interned and reused"
        );

        let a_must = a.must_contain.expect("must_contain set");
        let b_must = b.must_contain.expect("must_contain set");
        assert!(
            std::ptr::eq(a_must, b_must),
            "must_contain should be interned and reused"
        );

        let a_keywords = a.keywords_any.expect("keywords_any set");
        let b_keywords = b.keywords_any.expect("keywords_any set");
        assert!(
            std::ptr::eq(a_keywords, b_keywords),
            "keywords list should be interned and reused"
        );
        assert!(
            std::ptr::eq(a_keywords[0], b_keywords[0]),
            "keyword bytes should be interned and reused"
        );

        let a_suppressors = a.value_suppressors_any.expect("value_suppressors_any set");
        let b_suppressors = b.value_suppressors_any.expect("value_suppressors_any set");
        assert!(
            std::ptr::eq(a_suppressors, b_suppressors),
            "value_suppressors_any list should be interned and reused"
        );
        assert!(
            std::ptr::eq(a_suppressors[0], b_suppressors[0]),
            "value_suppressors_any bytes should be interned and reused"
        );

        let a_tp = a.two_phase.as_ref().expect("two_phase set");
        let b_tp = b.two_phase.as_ref().expect("two_phase set");
        assert!(
            std::ptr::eq(a_tp.confirm_any, b_tp.confirm_any),
            "two_phase confirm list should be interned and reused"
        );
        assert!(
            std::ptr::eq(a_tp.confirm_any[0], b_tp.confirm_any[0]),
            "two_phase confirm bytes should be interned and reused"
        );
    }

    #[test]
    fn parse_yaml_with_unknown_fields_succeeds() {
        // Unknown fields are silently ignored (no deny_unknown_fields).
        let yaml = r#"
rules:
  - name: "extra-fields"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
    description: "this field is not in the schema"
    extra_field: 42
"#;
        let rules = parse_yaml_rules(yaml).expect("unknown fields should be ignored");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "extra-fields");
    }

    #[test]
    fn parse_yaml_missing_required_field_returns_yaml_error() {
        let yaml = r#"
rules:
  - name: "no-regex"
    anchors: ["tok"]
    radius: 64
"#;
        match parse_yaml_rules(yaml) {
            Err(RulesError::Yaml(_)) => {}
            other => panic!("expected Yaml error, got: {other:?}"),
        }
    }
}
