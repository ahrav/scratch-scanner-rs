//! Replay support for Git simulation artifacts.
//!
//! Phase 0 provides a minimal adapter that replays an artifact by
//! constructing a runner with the stored schedule seed and invoking it.
//! Callers are responsible for schema validation and any compatibility checks.

use super::artifact::GitReproArtifact;
use super::runner::{GitSimRunner, RunOutcome};

/// Replay a Git simulation artifact with deterministic settings.
#[must_use]
pub fn replay_artifact(artifact: &GitReproArtifact) -> RunOutcome {
    let runner = GitSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
    runner.run(&artifact.scenario, &artifact.fault_plan)
}
