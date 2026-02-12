use super::*;
use crate::api::{OfflineVerdict, ValidatorKind};
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

    let offline_validation = rule.offline_validation.map(|ov| match ov {
        OfflineValidationSpec::Crc32Base62 {
            prefix_skip,
            payload_len,
            checksum_len,
        } => YamlOfflineValidation {
            kind: "crc32_base62".into(),
            prefix_skip: Some(prefix_skip),
            payload_len: Some(payload_len),
            checksum_len: Some(checksum_len),
        },
        OfflineValidationSpec::GithubFinegrainedPat => YamlOfflineValidation {
            kind: "github_fine_grained_pat".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::GrafanaServiceAccount => YamlOfflineValidation {
            kind: "grafana_service_account".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::AwsAccessKey => YamlOfflineValidation {
            kind: "aws_access_key".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::SentryOrgToken => YamlOfflineValidation {
            kind: "sentry_org_token".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
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
        offline_validation,
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

        // Offline validation.
        assert_eq!(
            orig.offline_validation, parsed.offline_validation,
            "offline_validation mismatch for {}",
            orig.name
        );

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
    let engine =
        Engine::new_with_anchor_policy(rules, Vec::new(), demo_tuning(), AnchorPolicy::ManualOnly);
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
///
/// NOTE: Scratch is allocated per-call intentionally. `ScanScratch`
/// carries inter-chunk state (dedup sets, stream counters) that causes
/// incorrect results when reused across independent inputs. Production
/// code reuses scratch across *chunks of the same file*, not across
/// unrelated scans.
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
        "adafruit-api-key",
        "adobe-client-id",
        "algolia-api-key",
        "confluent-access-token",
        "confluent-secret-key",
        "discord-api-token",
        "discord-client-secret",
        "heroku-api-key",
        "linear-client-secret",
        "zendesk-secret-key",
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
/// Guardrail: strongly prefix-structured tokens intentionally stay off the
/// generic placeholder suppressor baseline to avoid format-specific false negatives.
fn structured_prefix_rules_keep_value_suppressors_unset() {
    let structured_prefix_rules = [
        "aws-access-token",
        "github-pat",
        "npm-access-token",
        "grafana-service-account-token",
        "sentry-org-token",
        // Explicitly commented in YAML as prefix-structured.
        "heroku-api-key-v2",
        "linear-api-key",
        // Shopify family (shpat_, shpca_, shppa_, shpss_).
        "shopify-access-token",
        "shopify-custom-access-token",
        "shopify-private-app-access-token",
        "shopify-shared-secret",
        // GitLab family (glpat-).
        "gitlab-pat",
    ];

    for rule_name in structured_prefix_rules {
        let rule = builtin_rule_by_name(rule_name);
        assert!(
            rule.value_suppressors_any.is_none(),
            "expected value_suppressors_any to remain unset for {rule_name}"
        );
    }
}

#[test]
/// Regression: adafruit now carries the shared placeholder suppressor baseline.
fn adafruit_api_key_suppresses_placeholder_value() {
    let rule_name = "adafruit-api-key";
    let hay = b"adafruit_token=exampleexampleexampleexampleabcd";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        !has_rule_hit(&hits, rule_name),
        "expected placeholder adafruit API key to be suppressed"
    );
}

#[test]
fn adafruit_api_key_allows_real_value() {
    let rule_name = "adafruit-api-key";
    let hay = b"adafruit_token=a8f2k9x7m4p1q6w3b5n0j4c9d2e7h6m1";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        has_rule_hit(&hits, rule_name),
        "expected real-looking adafruit API key to be reported"
    );
}

#[test]
fn heroku_api_key_suppresses_placeholder_uuid() {
    let rule_name = "heroku-api-key";
    let hay = b"heroku_key=00000000-0000-0000-0000-000000000000";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        !has_rule_hit(&hits, rule_name),
        "expected all-zeros placeholder UUID to be suppressed"
    );
}

#[test]
fn heroku_api_key_allows_real_uuid() {
    let rule_name = "heroku-api-key";
    let hay = b"heroku_key=7e2f19c4-83d1-4a56-b7e9-1f3c8d2a5b60";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        has_rule_hit(&hits, rule_name),
        "expected real-looking Heroku UUID to be reported"
    );
}

#[test]
fn discord_client_secret_suppresses_placeholder_value() {
    let rule_name = "discord-client-secret";
    // 32-char value containing "example" (suppressor substring).
    // Uses "discord_app_key" to avoid triggering the global safelist on `secret[:=]`.
    let hay = b"discord_app_key=exampleexampleexampleexampleabcd";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        !has_rule_hit(&hits, rule_name),
        "expected placeholder discord client secret to be suppressed"
    );
}

#[test]
fn discord_client_secret_allows_real_value() {
    let rule_name = "discord-client-secret";
    // Use "discord_app_key" instead of "discord_secret" to avoid
    // triggering the global safelist pattern `secret[:=]`.
    let hay = b"discord_app_key=\"a8f2c9d7e4b1063895fa2d7c4e0b1a39\"";
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        has_rule_hit(&hits, rule_name),
        "expected real-looking discord client secret to be reported"
    );
}

#[test]
/// Validate that default_rules.yaml uses only known field names, catching
/// typos that serde would silently ignore.
fn default_rules_yaml_has_no_unknown_fields() {
    let yaml_str = include_str!("../../default_rules.yaml");
    let raw: serde_yml::Value = serde_yml::from_str(yaml_str).expect("parse default_rules.yaml");

    let rule_fields: &[&str] = &[
        "name",
        "regex",
        "anchors",
        "radius",
        "must_contain",
        "keywords_any",
        "value_suppressors_any",
        "entropy",
        "two_phase",
        "local_context",
        "offline_validation",
        "secret_group",
    ];
    let offline_validation_fields: &[&str] =
        &["type", "prefix_skip", "payload_len", "checksum_len"];
    let entropy_fields: &[&str] = &["min_bits_per_byte", "min_len", "max_len"];
    let two_phase_fields: &[&str] = &["seed_radius", "full_radius", "confirm_any"];
    let local_ctx_fields: &[&str] = &[
        "lookbehind",
        "lookahead",
        "require_same_line_assignment",
        "require_quoted",
        "key_names_any",
    ];

    let rules = raw
        .get("rules")
        .and_then(|v| v.as_sequence())
        .expect("rules key");
    for (i, rule) in rules.iter().enumerate() {
        let map = rule.as_mapping().unwrap();
        let name = map
            .get(serde_yml::Value::String("name".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        for key in map.keys() {
            let k = key.as_str().unwrap_or("");
            assert!(
                rule_fields.contains(&k),
                "rule {i} ({name}) has unknown field '{k}'"
            );
        }
        // Check nested entropy fields.
        if let Some(ent) = map.get(serde_yml::Value::String("entropy".into())) {
            if let Some(em) = ent.as_mapping() {
                for key in em.keys() {
                    let k = key.as_str().unwrap_or("");
                    assert!(
                        entropy_fields.contains(&k),
                        "rule {i} ({name}) entropy has unknown field '{k}'"
                    );
                }
            }
        }
        // Check nested two_phase fields.
        if let Some(tp) = map.get(serde_yml::Value::String("two_phase".into())) {
            if let Some(tm) = tp.as_mapping() {
                for key in tm.keys() {
                    let k = key.as_str().unwrap_or("");
                    assert!(
                        two_phase_fields.contains(&k),
                        "rule {i} ({name}) two_phase has unknown field '{k}'"
                    );
                }
            }
        }
        // Check nested local_context fields.
        if let Some(lc) = map.get(serde_yml::Value::String("local_context".into())) {
            if let Some(lm) = lc.as_mapping() {
                for key in lm.keys() {
                    let k = key.as_str().unwrap_or("");
                    assert!(
                        local_ctx_fields.contains(&k),
                        "rule {i} ({name}) local_context has unknown field '{k}'"
                    );
                }
            }
        }
        // Check nested offline_validation fields.
        if let Some(ov) = map.get(serde_yml::Value::String("offline_validation".into())) {
            if let Some(om) = ov.as_mapping() {
                for key in om.keys() {
                    let k = key.as_str().unwrap_or("");
                    assert!(
                        offline_validation_fields.contains(&k),
                        "rule {i} ({name}) offline_validation has unknown field '{k}'"
                    );
                }
            }
        }
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
    let hay = br#"curl -H "Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9" https://api.internal"#;
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
/// Reviewer claimed URL text could trigger the "example" suppressor and
/// hide a real bearer token. With emit-time safelist enabled, `example`
/// hosts are intentionally suppressed; this test uses a non-safelisted
/// host to keep value suppressor behavior isolated.
#[test]
fn curl_auth_header_non_safelisted_url_does_not_suppress_real_token() {
    let rule_name = "curl-auth-header";
    // Real token + non-safelisted URL should still be reported.
    let hay = br#"curl https://api.internal -H "Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9""#;
    let hits = scan_single_builtin_rule(rule_name, hay);
    assert!(
        has_rule_hit(&hits, rule_name),
        "non-safelisted URL must not suppress a real bearer token"
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

// ---- offline_validation YAML parsing tests ----

#[test]
fn parse_offline_validation_crc32_base62() {
    let yaml = r#"
rules:
  - name: "ov-crc32"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      prefix_skip: 4
      payload_len: 30
      checksum_len: 6
"#;
    let rules = parse_yaml_rules(yaml).expect("parse crc32_base62");
    assert_eq!(
        rules[0].offline_validation,
        Some(OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 30,
            checksum_len: 6,
        })
    );
}

#[test]
fn parse_offline_validation_github_fine_grained_pat() {
    let yaml = r#"
rules:
  - name: "ov-ghpat"
    regex: 'github_pat_[A-Za-z0-9_]{82}'
    anchors: ["github_pat_"]
    radius: 128
    offline_validation:
      type: github_fine_grained_pat
"#;
    let rules = parse_yaml_rules(yaml).expect("parse github_fine_grained_pat");
    assert_eq!(
        rules[0].offline_validation,
        Some(OfflineValidationSpec::GithubFinegrainedPat)
    );
}

#[test]
fn parse_offline_validation_grafana_service_account() {
    let yaml = r#"
rules:
  - name: "ov-grafana"
    regex: 'glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}'
    anchors: ["glsa_"]
    radius: 64
    offline_validation:
      type: grafana_service_account
"#;
    let rules = parse_yaml_rules(yaml).expect("parse grafana_service_account");
    assert_eq!(
        rules[0].offline_validation,
        Some(OfflineValidationSpec::GrafanaServiceAccount)
    );
}

#[test]
fn parse_offline_validation_aws_access_key() {
    let yaml = r#"
rules:
  - name: "ov-aws"
    regex: 'AKIA[0-9A-Z]{16}'
    anchors: ["AKIA"]
    radius: 32
    offline_validation:
      type: aws_access_key
"#;
    let rules = parse_yaml_rules(yaml).expect("parse aws_access_key");
    assert_eq!(
        rules[0].offline_validation,
        Some(OfflineValidationSpec::AwsAccessKey)
    );
}

#[test]
fn parse_offline_validation_sentry_org_token() {
    let yaml = r#"
rules:
  - name: "ov-sentry"
    regex: 'sntrys_[A-Za-z0-9+/=]{64,}'
    anchors: ["sntrys_"]
    radius: 128
    offline_validation:
      type: sentry_org_token
"#;
    let rules = parse_yaml_rules(yaml).expect("parse sentry_org_token");
    assert_eq!(
        rules[0].offline_validation,
        Some(OfflineValidationSpec::SentryOrgToken)
    );
}

#[test]
fn parse_offline_validation_absent_yields_none() {
    let yaml = r#"
rules:
  - name: "no-ov"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
"#;
    let rules = parse_yaml_rules(yaml).expect("parse rule without offline_validation");
    assert!(rules[0].offline_validation.is_none());
}

#[test]
fn parse_offline_validation_unknown_type_fails() {
    let yaml = r#"
rules:
  - name: "ov-bad"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: nonexistent_algo
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::OfflineValidation { rule_name, message }) => {
            assert_eq!(rule_name, "ov-bad");
            assert!(
                message.contains("nonexistent_algo"),
                "error should mention the unknown type: {message}"
            );
        }
        other => panic!("expected OfflineValidation error, got: {other:?}"),
    }
}

#[test]
fn parse_offline_validation_crc32_missing_payload_len_fails() {
    let yaml = r#"
rules:
  - name: "ov-incomplete"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      prefix_skip: 4
      checksum_len: 6
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::OfflineValidation { rule_name, message }) => {
            assert_eq!(rule_name, "ov-incomplete");
            assert!(
                message.contains("payload_len"),
                "error should mention missing field: {message}"
            );
        }
        other => panic!("expected OfflineValidation error, got: {other:?}"),
    }
}

#[test]
fn parse_offline_validation_crc32_missing_prefix_skip_fails() {
    let yaml = r#"
rules:
  - name: "ov-no-prefix"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      payload_len: 30
      checksum_len: 6
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::OfflineValidation { rule_name, message }) => {
            assert_eq!(rule_name, "ov-no-prefix");
            assert!(
                message.contains("prefix_skip"),
                "error should mention missing field: {message}"
            );
        }
        other => panic!("expected OfflineValidation error, got: {other:?}"),
    }
}

#[test]
fn parse_offline_validation_crc32_missing_checksum_len_fails() {
    let yaml = r#"
rules:
  - name: "ov-no-crc"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      prefix_skip: 4
      payload_len: 30
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::OfflineValidation { rule_name, message }) => {
            assert_eq!(rule_name, "ov-no-crc");
            assert!(
                message.contains("checksum_len"),
                "error should mention missing field: {message}"
            );
        }
        other => panic!("expected OfflineValidation error, got: {other:?}"),
    }
}

#[test]
fn roundtrip_offline_validation_crc32_base62() {
    let yaml = r#"
rules:
  - name: "rt-crc32"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      prefix_skip: 4
      payload_len: 30
      checksum_len: 6
"#;
    let original = parse_yaml_rules(yaml).expect("parse");
    let yaml_rules: Vec<YamlRule> = original.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_yml::to_string(&file).expect("serialize");
    let parsed = parse_yaml_rules(&yaml_str).expect("re-parse");
    assert_eq!(original[0].offline_validation, parsed[0].offline_validation);
}

#[test]
fn roundtrip_offline_validation_unit_variants() {
    let yaml = r#"
rules:
  - name: "rt-ghpat"
    regex: 'github_pat_[A-Za-z0-9_]{82}'
    anchors: ["github_pat_"]
    radius: 128
    offline_validation:
      type: github_fine_grained_pat
  - name: "rt-grafana"
    regex: 'glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}'
    anchors: ["glsa_"]
    radius: 64
    offline_validation:
      type: grafana_service_account
  - name: "rt-aws"
    regex: 'AKIA[0-9A-Z]{16}'
    anchors: ["AKIA"]
    radius: 32
    offline_validation:
      type: aws_access_key
  - name: "rt-sentry"
    regex: 'sntrys_[A-Za-z0-9+/=]{64,}'
    anchors: ["sntrys_"]
    radius: 128
    offline_validation:
      type: sentry_org_token
"#;
    let original = parse_yaml_rules(yaml).expect("parse");
    let yaml_rules: Vec<YamlRule> = original.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_yml::to_string(&file).expect("serialize");
    let parsed = parse_yaml_rules(&yaml_str).expect("re-parse");

    for (orig, reparsed) in original.iter().zip(parsed.iter()) {
        assert_eq!(
            orig.offline_validation, reparsed.offline_validation,
            "round-trip mismatch for {}",
            orig.name
        );
    }
}

// ---- default_rules.yaml offline validation spec assertions ----

#[test]
fn default_rules_offline_validation_specs() {
    let rules = builtin_rules();
    let find = |name: &str| -> &RuleSpec {
        rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing rule: {name}"))
    };

    let crc32_spec = OfflineValidationSpec::Crc32Base62 {
        prefix_skip: 4,
        payload_len: 30,
        checksum_len: 6,
    };

    // CRC32/Base62 rules (5 rules sharing the same token format).
    for rule_name in [
        "github-pat",
        "github-oauth",
        "github-app-token",
        "github-refresh-token",
        "npm-access-token",
    ] {
        assert_eq!(
            find(rule_name).offline_validation,
            Some(crc32_spec),
            "{rule_name} should have crc32_base62 offline validation"
        );
    }

    // Unit-variant rules.
    assert_eq!(
        find("github-fine-grained-pat").offline_validation,
        Some(OfflineValidationSpec::GithubFinegrainedPat),
    );
    assert_eq!(
        find("grafana-service-account-token").offline_validation,
        Some(OfflineValidationSpec::GrafanaServiceAccount),
    );
    assert_eq!(
        find("aws-access-token").offline_validation,
        Some(OfflineValidationSpec::AwsAccessKey),
    );
    assert_eq!(
        find("sentry-org-token").offline_validation,
        Some(OfflineValidationSpec::SentryOrgToken),
    );

    // Unrelated rules should have no offline validation.
    assert_eq!(
        find("generic-api-key").offline_validation,
        None,
        "generic-api-key should not have offline validation"
    );
}

// ---- offline validation rejection with default_rules.yaml specs ----

#[test]
fn default_rules_offline_validators_reject_bad_tokens() {
    use crate::engine::offline_validate;

    let rules = builtin_rules();
    let find = |name: &str| -> &RuleSpec {
        rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing rule: {name}"))
    };

    // CRC32/Base62 rules: token matches regex format but checksum is wrong.
    // 4-char prefix + 30 alphanumeric payload + 6 wrong checksum = 40 chars.
    let bad_crc32_token = b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd000000";
    for rule_name in [
        "github-pat",
        "github-oauth",
        "github-app-token",
        "github-refresh-token",
        "npm-access-token",
    ] {
        let spec = find(rule_name)
            .offline_validation
            .expect("should have offline_validation");
        let verdict = offline_validate::validate(spec, bad_crc32_token);
        assert_eq!(
            verdict,
            OfflineVerdict::Invalid,
            "{rule_name}: bad CRC32 token should be rejected"
        );
    }

    // GitHub fine-grained PAT: valid prefix but wrong checksum.
    let mut bad_ghpat = Vec::with_capacity(93);
    bad_ghpat.extend_from_slice(b"github_pat_");
    bad_ghpat.extend_from_slice(&[b'A'; 76]);
    bad_ghpat.extend_from_slice(b"000000"); // wrong checksum
    assert_eq!(bad_ghpat.len(), 93);
    let spec = find("github-fine-grained-pat").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_ghpat),
        OfflineVerdict::Invalid,
    );

    // Grafana: valid prefix but wrong hex checksum.
    let mut bad_grafana = Vec::new();
    bad_grafana.extend_from_slice(b"glsa_");
    bad_grafana.extend_from_slice(&[b'a'; 32]);
    bad_grafana.push(b'_');
    bad_grafana.extend_from_slice(b"deadbeef"); // wrong CRC
    let spec = find("grafana-service-account-token")
        .offline_validation
        .unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_grafana),
        OfflineVerdict::Invalid,
    );

    // AWS: lowercase chars in suffix → invalid.
    let bad_aws = b"AKIAiosfodnn7example";
    let spec = find("aws-access-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, bad_aws),
        OfflineVerdict::Invalid,
    );

    // Sentry: payload decodes to non-JSON → invalid.
    let mut bad_sentry = Vec::new();
    bad_sentry.extend_from_slice(b"sntrys_");
    // Base64 of "not_json_at_all_here" = "bm90X2pzb25fYXRfYWxsX2hlcmU="
    bad_sentry.extend_from_slice(b"bm90X2pzb25fYXRfYWxsX2hlcmU=");
    bad_sentry.push(b'_');
    bad_sentry.extend_from_slice(&[b'A'; 43]);
    let spec = find("sentry-org-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_sentry),
        OfflineVerdict::Invalid,
    );
}
