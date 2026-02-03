//! Scenario schema for scanner simulation runs.
//!
//! The schema is designed to be serialized as part of repro artifacts. It keeps
//! filesystem contents, synthetic rules, and expected secrets explicit and
//! deterministic.

use serde::{Deserialize, Serialize};

use crate::sim::fs::{SimFsSpec, SimPath};

/// Configuration for a single simulation run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunConfig {
    /// Number of simulated workers.
    pub workers: u32,
    /// Chunk size used for scanning.
    pub chunk_size: u32,
    /// Overlap bytes between chunks.
    pub overlap: u32,
    /// Maximum number of in-flight filesystem objects.
    pub max_in_flight_objects: u32,
    /// Maximum number of buffers in the simulated pool.
    pub buffer_pool_cap: u32,

    /// Maximum file size in bytes to scan.
    ///
    /// Files larger than this are skipped at open time. Discovery may also
    /// pre-filter using size hints.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Maximum number of simulation steps before declaring a hang.
    pub max_steps: u64,

    /// Maximum depth for transform decoding.
    pub max_transform_depth: u32,
    /// Whether to scan UTF-16 variants.
    pub scan_utf16_variants: bool,

    /// Number of stability runs per scenario (different schedules).
    pub stability_runs: u32,
}

fn default_max_file_size() -> u64 {
    u64::MAX
}

/// Top-level scenario schema for scanner simulations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    /// Schema version for forward-compatible evolution.
    pub schema_version: u32,
    /// Filesystem layout and file contents.
    pub fs: SimFsSpec,
    /// Synthetic rules used to generate expected findings.
    pub rule_suite: RuleSuiteSpec,
    /// Expected secrets for ground-truth validation.
    pub expected: Vec<ExpectedSecret>,
}

/// Expected secret inserted by the scenario generator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectedSecret {
    pub path: SimPath,
    pub rule_id: u32,
    /// Span in the root/original buffer.
    pub root_span: SpanU32,
    /// Representation used to derive the secret bytes.
    pub repr: SecretRepr,
}

/// Classification of how a secret is represented in the file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SecretRepr {
    Raw,
    Base64,
    UrlPercent,
    Utf16Le,
    Utf16Be,
    Nested { depth: u8 },
}

/// Byte span with half-open semantics `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanU32 {
    pub start: u32,
    pub end: u32,
}

impl SpanU32 {
    #[inline(always)]
    pub fn new(start: u32, end: u32) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }
}

/// Synthetic rule suite specification for scenario generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSuiteSpec {
    pub schema_version: u32,
    pub rules: Vec<SyntheticRuleSpec>,
}

/// Minimal synthetic rule description used by the sim harness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyntheticRuleSpec {
    pub rule_id: u32,
    pub name: String,
    /// Anchor bytes inserted alongside the secret to force candidate windows.
    pub anchors: Vec<Vec<u8>>,
    /// Validation radius in bytes around an anchor hit.
    #[serde(default = "default_rule_radius")]
    pub radius: u32,
    /// Regex pattern used by the engine during validation.
    pub regex: String,
}

fn default_rule_radius() -> u32 {
    64
}
