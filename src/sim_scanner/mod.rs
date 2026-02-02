//! Scenario and runner types for the scanner simulation harness.
//!
//! This module hosts the scenario schema and will eventually include the
//! deterministic runner and replay logic. The schema is versioned to support
//! forward-compatible artifact evolution.

pub mod scenario;

pub use scenario::{
    ExpectedSecret, RuleSuiteSpec, RunConfig, Scenario, SecretRepr, SimPath, SpanU32,
    SyntheticRuleSpec,
};
