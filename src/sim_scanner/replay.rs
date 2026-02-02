//! Artifact replay entry points for the scanner simulation.
//!
//! The full runner will rebuild the engine and filesystem from the artifact
//! and re-execute the simulation. For now this is a stub that returns a
//! structured "unimplemented" failure.

use crate::sim::artifact::ReproArtifact;
use crate::sim_scanner::runner::{FailureKind, FailureReport, RunOutcome};

/// Replay a previously captured artifact.
pub fn replay_artifact(_artifact: &ReproArtifact) -> RunOutcome {
    RunOutcome::Failed(FailureReport {
        kind: FailureKind::Unimplemented,
        message: "replay not implemented".to_string(),
        step: 0,
    })
}
