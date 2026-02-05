//! Synthetic scenario generator for scanner simulations.
//!
//! The generator produces deterministic filesystem contents with known secrets
//! and an accompanying rule suite that should detect only those secrets. It is
//! intended for differential + ground-truth oracles in the sim harness.
//!
//! Invariants:
//! - Rule prefixes are ASCII and included in anchors; regexes match `prefix + tail`.
//! - Noise bytes are lowercase `x` to avoid accidental prefix matches.
//! - `ExpectedSecret.root_span` refers to the encoded bytes stored in `SimFs`.

use regex::bytes::Regex;

use crate::api::{
    AnchorPolicy, Gate, RuleSpec, TransformConfig, TransformId, TransformMode, Tuning,
    ValidatorKind,
};
use crate::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::sim::rng::SimRng;
use crate::sim_scanner::scenario::{
    ExpectedSecret, RuleSuiteSpec, RunConfig, Scenario, SecretRepr, SpanU32, SyntheticRuleSpec,
};
use crate::Engine;

const TOKEN_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const DEFAULT_SCHEMA_VERSION: u32 = 1;

/// Configuration for generating synthetic scanner scenarios.
#[derive(Clone, Debug)]
pub struct ScenarioGenConfig {
    /// Scenario schema version to stamp on outputs.
    pub schema_version: u32,
    /// Number of synthetic rules to generate.
    pub rule_count: u32,
    /// Number of files to generate.
    pub file_count: u32,
    /// Number of secrets inserted per file.
    pub secrets_per_file: u32,
    /// Length of the random token tail appended to each rule prefix.
    pub token_len: u32,
    /// Minimum number of noise bytes between secrets.
    pub min_noise_len: u32,
    /// Maximum number of noise bytes between secrets.
    pub max_noise_len: u32,
    /// Allowed secret representations to choose from.
    pub representations: Vec<SecretRepr>,
}

impl Default for ScenarioGenConfig {
    fn default() -> Self {
        Self {
            schema_version: DEFAULT_SCHEMA_VERSION,
            rule_count: 2,
            file_count: 2,
            secrets_per_file: 3,
            token_len: 12,
            min_noise_len: 8,
            max_noise_len: 32,
            representations: vec![
                SecretRepr::Raw,
                SecretRepr::Base64,
                SecretRepr::UrlPercent,
                SecretRepr::Utf16Le,
                SecretRepr::Utf16Be,
            ],
        }
    }
}

impl ScenarioGenConfig {
    /// Validate configuration invariants, returning a human-readable error.
    fn validate(&self) -> Result<(), String> {
        if self.rule_count == 0 {
            return Err("rule_count must be > 0".to_string());
        }
        if self.file_count == 0 {
            return Err("file_count must be > 0".to_string());
        }
        if self.token_len == 0 {
            return Err("token_len must be > 0".to_string());
        }
        if self.min_noise_len > self.max_noise_len {
            return Err("min_noise_len must be <= max_noise_len".to_string());
        }
        if self.representations.is_empty() {
            return Err("representations must be non-empty".to_string());
        }
        Ok(())
    }
}

/// Generate a deterministic scenario and rule suite from a seed.
///
/// The returned `ExpectedSecret` spans refer to the encoded payload inserted
/// into each file, not the decoded representation.
pub fn generate_scenario(seed: u64, cfg: &ScenarioGenConfig) -> Result<Scenario, String> {
    cfg.validate()?;

    let mut rng = SimRng::new(seed);
    let rule_suite = build_rule_suite(cfg);

    let mut nodes = Vec::with_capacity(cfg.file_count as usize);
    let mut expected =
        Vec::with_capacity((cfg.file_count.saturating_mul(cfg.secrets_per_file)) as usize);

    for file_idx in 0..cfg.file_count {
        let path = SimPath::new(format!("file_{file_idx}.txt").into_bytes());
        let mut buf = Vec::new();

        for _ in 0..cfg.secrets_per_file {
            append_noise(&mut rng, cfg, &mut buf);

            let rule_id = rng.gen_range(0, cfg.rule_count);
            let repr = pick_repr(&mut rng, &cfg.representations);
            let token = make_token(rule_id, cfg.token_len, &mut rng);
            let encoded = encode_secret(&token, &repr);

            let start = buf.len() as u32;
            buf.extend_from_slice(&encoded);
            let end = buf.len() as u32;

            expected.push(ExpectedSecret {
                path: path.clone(),
                rule_id,
                root_span: SpanU32::new(start, end),
                repr,
            });
        }

        append_noise(&mut rng, cfg, &mut buf);
        nodes.push(SimNodeSpec::File {
            path,
            contents: buf,
            // Generator defaults to a known file type; tests override as needed.
            discovery_len_hint: None,
            type_hint: SimTypeHint::File,
        });
    }

    Ok(Scenario {
        schema_version: cfg.schema_version,
        fs: SimFsSpec { nodes },
        rule_suite,
        expected,
    })
}

/// Build a deterministic engine from a synthetic rule suite.
///
/// This leaks rule names and anchors to obtain `'static` lifetimes and should
/// be used only in test harnesses or short-lived simulations.
pub fn build_engine_from_suite(
    suite: &RuleSuiteSpec,
    run_cfg: &RunConfig,
) -> Result<Engine, String> {
    let rules = materialize_rules(suite)?;
    let transforms = synthetic_transforms();
    let tuning = synthetic_tuning(run_cfg);
    Ok(Engine::new_with_anchor_policy(
        rules,
        transforms,
        tuning,
        AnchorPolicy::ManualOnly,
    ))
}

/// Convert a rule suite spec into engine rule specs.
///
/// This leaks the anchors and names to satisfy the engine's `'static` lifetime
/// requirements for `RuleSpec`.
pub fn materialize_rules(suite: &RuleSuiteSpec) -> Result<Vec<RuleSpec>, String> {
    let mut rules = Vec::with_capacity(suite.rules.len());
    for spec in &suite.rules {
        let name: &'static str = Box::leak(spec.name.clone().into_boxed_str());
        let mut anchors = Vec::with_capacity(spec.anchors.len());
        for anchor in &spec.anchors {
            let leaked: &'static [u8] = Box::leak(anchor.clone().into_boxed_slice());
            anchors.push(leaked);
        }
        let anchors: &'static [&'static [u8]] = Box::leak(anchors.into_boxed_slice());
        let re =
            Regex::new(&spec.regex).map_err(|e| format!("rule {} regex error: {e}", spec.name))?;

        rules.push(RuleSpec {
            name,
            anchors,
            radius: spec.radius as usize,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            local_context: None,
            secret_group: None,
            re,
        });
    }
    Ok(rules)
}

/// Transforms suitable for synthetic scenarios.
pub fn synthetic_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

/// Tuning defaults for synthetic scenarios derived from the run config.
pub fn synthetic_tuning(run_cfg: &RunConfig) -> Tuning {
    let mut tuning = crate::demo::demo_tuning();
    tuning.max_transform_depth = run_cfg.max_transform_depth as usize;
    tuning.scan_utf16_variants = run_cfg.scan_utf16_variants;
    tuning
}

/// Build a deterministic rule suite with fixed prefixes and regex shapes.
///
/// Radius covers `prefix + token` plus a small slack (8 bytes) to avoid
/// boundary misses in synthetic data.
fn build_rule_suite(cfg: &ScenarioGenConfig) -> RuleSuiteSpec {
    let mut rules = Vec::with_capacity(cfg.rule_count as usize);
    for rule_id in 0..cfg.rule_count {
        let prefix = rule_prefix(rule_id);
        let regex = format!("{prefix}[A-Z0-9]{{{}}}", cfg.token_len);
        let radius = prefix
            .len()
            .saturating_add(cfg.token_len as usize)
            .saturating_add(8);
        rules.push(SyntheticRuleSpec {
            rule_id,
            name: format!("sim_rule_{rule_id}"),
            anchors: vec![prefix.as_bytes().to_vec()],
            radius: radius as u32,
            regex,
        });
    }

    RuleSuiteSpec {
        schema_version: cfg.schema_version,
        rules,
    }
}

fn rule_prefix(rule_id: u32) -> String {
    format!("SIM{rule_id}_")
}

fn make_token(rule_id: u32, token_len: u32, rng: &mut SimRng) -> Vec<u8> {
    let prefix = rule_prefix(rule_id);
    let mut out = Vec::with_capacity(prefix.len() + token_len as usize);
    out.extend_from_slice(prefix.as_bytes());
    for _ in 0..token_len {
        let idx = rng.gen_range(0, TOKEN_ALPHABET.len() as u32) as usize;
        out.push(TOKEN_ALPHABET[idx]);
    }
    out
}

fn pick_repr(rng: &mut SimRng, reprs: &[SecretRepr]) -> SecretRepr {
    let idx = rng.gen_range(0, reprs.len() as u32) as usize;
    reprs[idx].clone()
}

fn append_noise(rng: &mut SimRng, cfg: &ScenarioGenConfig, buf: &mut Vec<u8>) {
    let noise_len = if cfg.min_noise_len == cfg.max_noise_len {
        cfg.min_noise_len
    } else {
        rng.gen_range(cfg.min_noise_len, cfg.max_noise_len + 1)
    };
    // Use lowercase filler to avoid matching uppercase rule prefixes.
    buf.resize(buf.len().saturating_add(noise_len as usize), b'x');
}

/// Encode the raw token into the requested representation.
fn encode_secret(raw: &[u8], repr: &SecretRepr) -> Vec<u8> {
    match repr {
        SecretRepr::Raw => raw.to_vec(),
        SecretRepr::Base64 => base64_encode_std(raw),
        SecretRepr::UrlPercent => percent_encode_all(raw),
        SecretRepr::Utf16Le => encode_utf16(raw, false),
        SecretRepr::Utf16Be => encode_utf16(raw, true),
        SecretRepr::Nested { depth } => encode_nested(raw, *depth),
    }
}

/// Apply alternating base64 and URL-percent layers `depth` times.
///
/// Depth 0 returns the raw bytes unchanged.
fn encode_nested(raw: &[u8], depth: u8) -> Vec<u8> {
    if depth == 0 {
        return raw.to_vec();
    }
    let mut cur = raw.to_vec();
    // Alternate between base64 and URL percent to build nested transforms.
    for i in 0..depth {
        if i % 2 == 0 {
            cur = base64_encode_std(&cur);
        } else {
            cur = percent_encode_all(&cur);
        }
    }
    cur
}

/// Percent-encode every byte using uppercase hex.
fn percent_encode_all(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().saturating_mul(3));
    for &b in input {
        out.push(b'%');
        out.push(hex_nibble((b >> 4) & 0x0f));
        out.push(hex_nibble(b & 0x0f));
    }
    out
}

/// Base64-encode with the standard alphabet and `=` padding.
fn base64_encode_std(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(BASE64_STD[(n & 63) as usize]);
        i += 3;
    }

    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(b'=');
    }

    out
}

fn hex_nibble(n: u8) -> u8 {
    debug_assert!(n < 16);
    match n {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

/// Widen ASCII bytes into UTF-16 code units (not a general Unicode encoder).
fn encode_utf16(bytes: &[u8], be: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = 0u8;
        let lo = b;
        if be {
            out.push(hi);
            out.push(lo);
        } else {
            out.push(lo);
            out.push(hi);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_generation_is_deterministic() {
        let cfg = ScenarioGenConfig::default();
        let a = generate_scenario(42, &cfg).expect("scenario a");
        let b = generate_scenario(42, &cfg).expect("scenario b");
        assert_eq!(a.expected.len(), b.expected.len());
        assert_eq!(a.fs.nodes.len(), b.fs.nodes.len());
        assert_eq!(a.rule_suite.rules.len(), b.rule_suite.rules.len());
    }
}
