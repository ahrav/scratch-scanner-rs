//! Deterministic Git simulation runner (Phase 0 scaffold).
//!
//! This runner is a placeholder that defines the failure taxonomy and
//! run result types. The full stage orchestration is implemented in
//! later phases once the Git simulation adapters are in place.

use serde::{Deserialize, Serialize};

use super::fault::GitFaultPlan;
use super::scenario::{GitRunConfig, GitScenario};

/// Result of a Git simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    /// Run completed without detected failures.
    Ok { report: RunReport },
    /// Run failed with a structured report.
    Failed(FailureReport),
}

/// Summary report for a successful run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunReport {
    /// Total steps executed.
    pub steps: u64,
}

/// Structured failure report captured in artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    /// Failure classification.
    pub kind: FailureKind,
    /// Human-readable message for logs and artifacts.
    pub message: String,
    /// Monotonic step counter at the time of failure.
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    /// A panic escaped from harness logic.
    Panic,
    /// The simulation failed to reach a terminal state within the step budget.
    Hang,
    /// An invariant about ordering or gating was violated.
    InvariantViolation { code: u32 },
    /// A correctness oracle failed.
    OracleMismatch,
    /// The same scenario produced different outputs across schedules.
    StabilityMismatch,
    /// Placeholder for unimplemented phases.
    Unimplemented,
}

/// Deterministic Git simulation runner.
///
/// The schedule seed drives the scheduler RNG; deterministic behavior is
/// expected given identical scenario, fault plan, and configuration.
pub struct GitSimRunner {
    cfg: GitRunConfig,
    schedule_seed: u64,
}

impl GitSimRunner {
    /// Create a new runner with a fixed schedule seed.
    pub fn new(cfg: GitRunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed and fault plan.
    pub fn run(&self, _scenario: &GitScenario, _fault_plan: &GitFaultPlan) -> RunOutcome {
        RunOutcome::Failed(FailureReport {
            kind: FailureKind::Unimplemented,
            message: "Git simulation runner not implemented".to_string(),
            step: 0,
        })
    }

    /// Returns the configured run settings.
    #[must_use]
    pub fn config(&self) -> &GitRunConfig {
        &self.cfg
    }

    /// Returns the base schedule seed.
    #[must_use]
    pub fn schedule_seed(&self) -> u64 {
        self.schedule_seed
    }
}
