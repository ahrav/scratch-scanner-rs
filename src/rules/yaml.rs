//! YAML rule deserialization and conversion to [`RuleSpec`].
//!
//! # Schema overview
//!
//! A YAML rules file is a mapping with a single `rules` key whose value is a
//! sequence of rule objects. Each rule must specify `name`, `regex`, `anchors`,
//! and `radius`; all other fields are optional. See [`YamlRule`] for the full
//! field set.
//!
//! Unknown fields are silently ignored (serde's default behavior) so that newer
//! YAML files can be read by older parser versions. The companion test
//! `default_rules_yaml_has_no_unknown_fields` catches accidental typos in the
//! canonical `default_rules.yaml`.
//!
//! # Interning
//!
//! Parsed rule data — names, anchors, keywords, etc. — are interned into a
//! process-global [`RuleAtomPool`] and returned as `&'static` references.
//! This is intentional: rule literals live for the entire process, and
//! interning avoids repeated heap growth when the same YAML is parsed
//! multiple times (e.g. across configuration reloads).
//!
//! The pool is protected by a [`Mutex`] with poison recovery, so a panic
//! during interning does not permanently lock out subsequent callers.
//!
//! # Thread safety
//!
//! [`parse_yaml_rules`] is safe to call from multiple threads. The global
//! atom pool serializes interning but the critical section is short (hash
//! lookups and pointer copies for already-interned atoms).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde::Deserialize;

use crate::api::{
    EntropySpec, LocalContextSpec, OfflineValidationSpec, RuleSpec, TwoPhaseSpec, ValidatorKind,
};

use super::RulesError;

// ---------------------------------------------------------------------------
// YAML serde types
// ---------------------------------------------------------------------------

/// Top-level YAML structure: `{ rules: [...] }`.
///
/// This is the serde target for the entire rules file. The `rules` key
/// maps to a list of [`YamlRule`] objects.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlRulesFile {
    pub rules: Vec<YamlRule>,
}

/// One detection rule as expressed in YAML.
///
/// # Required fields
///
/// - `name` — unique rule identifier (e.g. `"generic-api-key"`).
/// - `regex` — pattern compiled into a [`regex::bytes::Regex`].
/// - `anchors` — literal byte strings used by the Vectorscan pre-filter
///   to narrow scan windows before the regex is applied.
/// - `radius` — byte radius around an anchor match to feed to the regex.
///
/// # Optional fields
///
/// All other fields default to `None` / absent. See the corresponding
/// `*Spec` types in [`crate::api`] for semantics.
///
/// `ValidatorKind` is intentionally absent from the YAML schema — fast
/// validators are tightly coupled to specific regex patterns and are only
/// set programmatically.
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
    pub offline_validation: Option<YamlOfflineValidation>,
    #[serde(default)]
    pub secret_group: Option<u16>,
}

/// Entropy gate parameters for a rule.
///
/// When present, the secret value (captured group) must have at least
/// `min_bits_per_byte` bits of Shannon entropy per byte. Secrets shorter
/// than `min_len` bypass the entropy check (noisy on small samples);
/// secrets longer than `max_len` are evaluated on only the first
/// `max_len` bytes.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlEntropy {
    pub min_bits_per_byte: f32,
    pub min_len: usize,
    pub max_len: usize,
    #[serde(default)]
    pub min_entropy_bits_per_byte: Option<f32>,
}

/// Two-phase scanning configuration.
///
/// Phase 1 uses `seed_radius` to locate potential matches, then checks
/// each seed window for at least one `confirm_any` literal — windows
/// without a match are dropped immediately.
/// Phase 2 expands surviving windows from `seed_radius` to `full_radius`
/// and runs the regex on the wider view.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlTwoPhase {
    pub seed_radius: usize,
    pub full_radius: usize,
    pub confirm_any: Vec<String>,
}

/// Local-context validation for reducing false positives.
///
/// Examines the bytes immediately surrounding a regex match
/// (`lookbehind` bytes before, `lookahead` bytes after) for structural
/// cues such as assignment operators, quoting, or specific key names.
/// Gates that fail suppress the finding.
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

/// Offline structural validation configuration.
///
/// The `type` field selects the validation algorithm. Parameterised variants
/// (currently only `crc32_base62`) require additional numeric fields; unit
/// variants need only the type selector.
///
/// # Supported types
///
/// | YAML `type` value          | Maps to                                |
/// |----------------------------|----------------------------------------|
/// | `crc32_base62`             | [`OfflineValidationSpec::Crc32Base62`] |
/// | `github_fine_grained_pat`  | [`OfflineValidationSpec::GithubFinegrainedPat`] |
/// | `grafana_service_account`  | [`OfflineValidationSpec::GrafanaServiceAccount`] |
/// | `aws_access_key`           | [`OfflineValidationSpec::AwsAccessKey`] |
/// | `sentry_org_token`         | [`OfflineValidationSpec::SentryOrgToken`] |
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlOfflineValidation {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub prefix_skip: Option<u8>,
    #[serde(default)]
    pub payload_len: Option<u8>,
    #[serde(default)]
    pub checksum_len: Option<u8>,
}

// ---------------------------------------------------------------------------
// Atom interning — rules live for the entire process, so we store interned
// allocations in a global pool and reuse them across parse calls.
// ---------------------------------------------------------------------------

/// Content-addressed interning pool for rule atoms.
///
/// Each `intern_*` method returns a `&'static` reference. If the value
/// was already interned, the existing pointer is returned (dedup by
/// content equality). Otherwise, the value is `Box::leak`-ed into
/// process-lifetime storage and inserted into the lookup table.
///
/// Three maps cover the three shapes needed by [`RuleSpec`]:
/// - `strings` — rule names (`&'static str`).
/// - `bytes` — individual byte slices (anchors, keywords, etc.).
/// - `bytes_slices` — slices-of-slices (e.g. the full anchors array).
#[derive(Default)]
struct RuleAtomPool {
    strings: HashMap<String, &'static str>,
    bytes: HashMap<Vec<u8>, &'static [u8]>,
    bytes_slices: HashMap<Vec<Vec<u8>>, &'static [&'static [u8]]>,
}

impl RuleAtomPool {
    /// Intern a string, returning a `&'static str` pointer-equal across calls
    /// with the same content.
    fn intern_str(&mut self, s: String) -> &'static str {
        if let Some(existing) = self.strings.get(&s) {
            return existing;
        }
        let leaked = Box::leak(s.clone().into_boxed_str());
        self.strings.insert(s, leaked);
        leaked
    }

    /// Intern a string's UTF-8 bytes.
    fn intern_bytes(&mut self, s: String) -> &'static [u8] {
        self.intern_bytes_vec(s.into_bytes())
    }

    /// Intern a raw byte vector, deduplicating by content.
    fn intern_bytes_vec(&mut self, bytes: Vec<u8>) -> &'static [u8] {
        if let Some(existing) = self.bytes.get(&bytes) {
            return existing;
        }
        let leaked = Box::leak(bytes.clone().into_boxed_slice());
        self.bytes.insert(bytes, leaked);
        leaked
    }

    /// Intern a list of strings as a `&'static [&'static [u8]]`.
    ///
    /// Both the outer slice and each inner byte slice are interned
    /// independently, so element-level sharing works across rules.
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

/// Acquire the global atom pool and run `f` under the lock.
///
/// Poison recovery (`into_inner`) is deliberate: a prior panic during
/// interning leaves the pool in a consistent state (partial inserts are
/// harmless because `Box::leak` is idempotent for the leaked value) so
/// subsequent callers should not be blocked.
fn with_rule_atoms<T>(f: impl FnOnce(&mut RuleAtomPool) -> T) -> T {
    let mut guard = RULE_ATOMS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

// ---------------------------------------------------------------------------
// Core conversion
// ---------------------------------------------------------------------------

/// Convert a [`YamlOfflineValidation`] into an [`OfflineValidationSpec`].
///
/// The `crc32_base62` type requires all three numeric parameters (`prefix_skip`,
/// `payload_len`, `checksum_len`); all other types are unit variants that need
/// only the `type` selector. Returns an error for unknown type strings or
/// missing required parameters.
fn yaml_offline_to_spec(
    rule_name: &str,
    ov: YamlOfflineValidation,
) -> Result<OfflineValidationSpec, RulesError> {
    match ov.kind.as_str() {
        "crc32_base62" => {
            let prefix_skip = ov
                .prefix_skip
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'prefix_skip'".into(),
                })?;
            let payload_len = ov
                .payload_len
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'payload_len'".into(),
                })?;
            let checksum_len = ov
                .checksum_len
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'checksum_len'".into(),
                })?;
            Ok(OfflineValidationSpec::Crc32Base62 {
                prefix_skip,
                payload_len,
                checksum_len,
            })
        }
        "github_fine_grained_pat" => Ok(OfflineValidationSpec::GithubFinegrainedPat),
        "grafana_service_account" => Ok(OfflineValidationSpec::GrafanaServiceAccount),
        "aws_access_key" => Ok(OfflineValidationSpec::AwsAccessKey),
        "sentry_org_token" => Ok(OfflineValidationSpec::SentryOrgToken),
        "pypi_token" => Ok(OfflineValidationSpec::PyPiToken),
        "slack_token" => Ok(OfflineValidationSpec::SlackToken),
        unknown => Err(RulesError::OfflineValidation {
            rule_name: rule_name.to_string(),
            message: format!("unknown offline_validation type '{unknown}'"),
        }),
    }
}

/// Parse YAML content into a `Vec<RuleSpec>`.
///
/// Deserializes the YAML, then converts each [`YamlRule`] into a [`RuleSpec`]
/// by compiling regexes and interning textual fields into reusable `'static`
/// references via the global [`RuleAtomPool`].
///
/// # Errors
///
/// - [`RulesError::Yaml`] — the input is not valid YAML or does not match
///   the expected schema (missing required fields).
/// - [`RulesError::Regex`] — a rule's `regex` field fails to compile.
///   The error includes the rule name and pattern for diagnostics.
pub(crate) fn parse_yaml_rules(content: &str) -> Result<Vec<RuleSpec>, RulesError> {
    let file: YamlRulesFile = serde_norway::from_str(content).map_err(RulesError::Yaml)?;

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
            offline_validation,
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
            min_entropy_bits_per_byte: e.min_entropy_bits_per_byte,
        });

        let offline_validation = offline_validation
            .map(|ov| yaml_offline_to_spec(name, ov))
            .transpose()?;

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
            char_class: None,
            local_context,
            offline_validation,
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
#[path = "yaml_unit_tests.rs"]
mod tests;

// Property-based parser/interning invariants live in a sibling module to keep
// this file's unit tests focused and to preserve fast default `cargo test`.
#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "yaml_tests.rs"]
mod yaml_tests;
