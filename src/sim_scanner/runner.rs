//! Runner outcome types for scanner simulation.
//!
//! These types are shared between the runner and artifact schema to ensure
//! stable serialization.

use serde::{Deserialize, Serialize};

/// Result of a simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    Ok,
    Failed(FailureReport),
}

/// Structured failure report captured in artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub kind: FailureKind,
    pub message: String,
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    Panic,
    Hang,
    InvariantViolation { code: u32 },
    OracleMismatch,
    StabilityMismatch,
    Unimplemented,
}
