//! YAML rule deserialization and conversion to `RuleSpec`.
//!
//! Defines serde intermediate types that mirror the YAML schema, then converts
//! them into `RuleSpec` values with leaked static references (rules live for
//! the entire process lifetime).

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
// Leak helpers — rules live for the entire process, so we leak into 'static.
// ---------------------------------------------------------------------------

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak_bytes(s: String) -> &'static [u8] {
    Box::leak(s.into_bytes().into_boxed_slice())
}

fn leak_bytes_slice(v: Vec<String>) -> &'static [&'static [u8]] {
    let leaked: Vec<&'static [u8]> = v.into_iter().map(leak_bytes).collect();
    Box::leak(leaked.into_boxed_slice())
}

// ---------------------------------------------------------------------------
// Core conversion
// ---------------------------------------------------------------------------

/// Parse YAML content into a `Vec<RuleSpec>`.
///
/// Deserializes the YAML, then converts each `YamlRule` into a `RuleSpec`
/// by compiling regexes and leaking string data into `'static` references.
pub(crate) fn parse_yaml_rules(content: &str) -> Result<Vec<RuleSpec>, RulesError> {
    let file: YamlRulesFile = serde_yml::from_str(content).map_err(RulesError::Yaml)?;

    let mut rules = Vec::with_capacity(file.rules.len());
    for yr in file.rules {
        let name = yr.name.clone();
        let pattern = yr.regex.clone();
        let re = super::build_regex(&pattern).map_err(|error| RulesError::Regex {
            rule_name: name.clone(),
            pattern,
            error,
        })?;

        let anchors = leak_bytes_slice(yr.anchors);

        let must_contain: Option<&'static [u8]> = yr.must_contain.map(leak_bytes);

        let keywords_any: Option<&'static [&'static [u8]]> = yr.keywords_any.map(leak_bytes_slice);

        let entropy = yr.entropy.map(|e| EntropySpec {
            min_bits_per_byte: e.min_bits_per_byte,
            min_len: e.min_len,
            max_len: e.max_len,
        });

        let two_phase = yr.two_phase.map(|tp| TwoPhaseSpec {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm_any: leak_bytes_slice(tp.confirm_any),
        });

        let local_context = yr.local_context.map(|lc| LocalContextSpec {
            lookbehind: lc.lookbehind,
            lookahead: lc.lookahead,
            require_same_line_assignment: lc.require_same_line_assignment,
            require_quoted: lc.require_quoted,
            key_names_any: lc.key_names_any.map(leak_bytes_slice),
        });

        rules.push(RuleSpec {
            name: leak_str(name),
            anchors,
            radius: yr.radius,
            validator: ValidatorKind::None,
            two_phase,
            must_contain,
            keywords_any,
            entropy,
            local_context,
            secret_group: yr.secret_group,
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
            entropy,
            two_phase,
            local_context,
            secret_group: rule.secret_group,
        }
    }

    #[test]
    fn roundtrip_builtin_rules() {
        let original_rules = builtin_rules();

        // Convert to YAML and back.
        let yaml_rules: Vec<YamlRule> = original_rules.iter().map(rulespec_to_yaml).collect();
        let file = YamlRulesFile { rules: yaml_rules };
        let yaml_str = serde_yml::to_string(&file).expect("serialize to YAML");
        let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse YAML rules");

        assert_eq!(
            original_rules.len(),
            parsed_rules.len(),
            "rule count mismatch"
        );

        for (orig, parsed) in original_rules.iter().zip(parsed_rules.iter()) {
            assert_eq!(orig.name, parsed.name, "name mismatch");
            assert_eq!(orig.radius, parsed.radius, "radius mismatch for {}", orig.name);
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
        assert!(rules[0].entropy.is_none());
        assert!(rules[0].two_phase.is_none());
        assert!(rules[0].local_context.is_none());
        assert!(rules[0].secret_group.is_none());
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
}
