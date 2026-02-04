//! Deterministic Git simulation harness.
//!
//! Purpose:
//! - Provide a replayable, schedule-deterministic harness for Git scan stages.
//! - Exercise stage invariants (ordering, gating, and resource bounds) without
//!   relying on OS time, filesystem races, or real repository layouts.
//!
//! Design principles:
//! - Keep production Git scanning untouched; introduce narrow seams only.
//! - Prefer data-driven scenarios and deterministic scheduling via `SimExecutor`.
//! - Emit bounded trace events that make failures reproducible and debuggable.
//!
//! Module layout:
//! - `scenario`: schema for Git simulation inputs and run configuration.
//! - `runner`: deterministic runner and failure taxonomy.
//! - `trace`: bounded trace ring and Git-specific events.
//! - `artifact`: reproducible failure artifact schema.
//! - `fault`: deterministic fault plan schema for Git resources.
//! - `replay`: load + replay artifacts.
//! - `minimize`: deterministic shrink passes (placeholder in Phase 0).

pub mod artifact;
pub mod fault;
pub mod minimize;
pub mod replay;
pub mod runner;
pub mod scenario;
pub mod trace;

pub use artifact::{GitReproArtifact, GitTraceDump};
pub use fault::{GitCorruption, GitFaultPlan, GitIoFault, GitReadFault, GitResourceId};
pub use minimize::{minimize_git_case, MinimizerCfg};
pub use replay::replay_artifact;
pub use runner::{FailureKind, FailureReport, GitSimRunner, RunOutcome, RunReport};
pub use scenario::{
    GitArtifactBundle, GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitPackBytes,
    GitRefSpec, GitRepoModel, GitRunConfig, GitScenario, GitTreeEntryKind, GitTreeEntrySpec,
    GitTreeSpec,
};
pub use trace::{GitTraceEvent, GitTraceRing};
