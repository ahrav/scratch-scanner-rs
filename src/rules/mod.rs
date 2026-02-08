//! Rule loading for the scanner.
//!
//! Rules can be loaded from an external YAML file at runtime, or from the
//! built-in set embedded via `include_str!`. The YAML schema mirrors `RuleSpec`
//! fields and uses the same `build_regex()` + `assert_valid()` validation.

pub(crate) mod yaml;

use std::fmt;
use std::path::{Path, PathBuf};

use crate::api::RuleSpec;
use regex::bytes::Regex;

/// Progressive regex size limits (bytes) to tolerate large DFAs on complex rules.
///
/// We retry compilation on `CompiledTooBig` so a single oversized rule does not
/// require globally lifting size limits for all patterns.
const REGEX_SIZE_LIMITS: &[usize] = &[32 * 1024 * 1024, 128 * 1024 * 1024, 512 * 1024 * 1024];

/// Build a bytes regex with increasing size limits.
///
/// Returns an error if the pattern is invalid or exceeds the maximum configured limits.
pub(crate) fn build_regex(pattern: &str) -> Result<Regex, String> {
    for &limit in REGEX_SIZE_LIMITS {
        let mut builder = regex::bytes::RegexBuilder::new(pattern);
        builder.unicode(false);
        builder.size_limit(limit);
        builder.dfa_size_limit(limit);
        match builder.build() {
            Ok(re) => return Ok(re),
            Err(regex::Error::CompiledTooBig(_)) => continue,
            Err(err) => return Err(err.to_string()),
        }
    }
    Err(format!(
        "regex compiled too big even at {} bytes",
        REGEX_SIZE_LIMITS[REGEX_SIZE_LIMITS.len() - 1]
    ))
}

/// Errors that can occur when loading rules from an external file.
#[derive(Debug)]
pub(crate) enum RulesError {
    /// I/O error reading the rules file.
    Io(std::io::Error),
    /// YAML parsing error.
    Yaml(serde_yml::Error),
    /// Regex compilation failure for a specific rule.
    Regex {
        rule_name: String,
        pattern: String,
        error: String,
    },
    /// Rule validation failure (e.g., invalid invariants).
    Validation { rule_name: String, message: String },
    /// The rules file contained no rules.
    NoRules,
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::Io(e) => write!(f, "I/O error: {e}"),
            RulesError::Yaml(e) => write!(f, "YAML parse error: {e}"),
            RulesError::Regex {
                rule_name,
                pattern,
                error,
            } => write!(
                f,
                "regex error in rule '{rule_name}': {error} (pattern: {pattern})"
            ),
            RulesError::Validation { rule_name, message } => {
                write!(f, "validation error in rule '{rule_name}': {message}")
            }
            RulesError::NoRules => write!(f, "rules file contains no rules"),
        }
    }
}

impl std::error::Error for RulesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RulesError::Io(e) => Some(e),
            RulesError::Yaml(e) => Some(e),
            _ => None,
        }
    }
}

/// Load and validate rules from a YAML file.
///
/// Reads the file, parses it via [`yaml::parse_yaml_rules`], then runs
/// `assert_valid()` on each rule (catching panics as `Validation` errors).
pub(crate) fn load_rules(path: &Path) -> Result<Vec<RuleSpec>, RulesError> {
    let content = std::fs::read_to_string(path).map_err(RulesError::Io)?;
    let rules = yaml::parse_yaml_rules(&content)?;
    if rules.is_empty() {
        return Err(RulesError::NoRules);
    }

    // Validate each rule, catching panics from assert_valid().
    for rule in &rules {
        let name = rule.name.to_string();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rule.assert_valid();
        }));
        if let Err(payload) = result {
            let message = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown validation panic".to_string()
            };
            return Err(RulesError::Validation {
                rule_name: name,
                message,
            });
        }
    }

    Ok(rules)
}

/// Returns the default rules file path next to the current executable.
///
/// Returns `None` if the executable path cannot be determined.
pub(crate) fn default_rules_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()?
        .join("default_rules.yaml")
        .into()
}

/// The built-in rule set, embedded from `default_rules.yaml` at compile time.
const BUILTIN_RULES_YAML: &str = include_str!("../../default_rules.yaml");

/// Parse and return the built-in rule set.
///
/// This replaces the old `gitleaks_rules()` function. Rules are compiled
/// from the embedded YAML on each call (regex compilation dominates cost).
pub(crate) fn builtin_rules() -> Vec<RuleSpec> {
    yaml::parse_yaml_rules(BUILTIN_RULES_YAML).expect("built-in rules YAML must be valid")
}
