//! Deterministic minimizer for Git simulation artifacts (scaffold).
//!
//! Phase 0 exposes the API surface and configuration, but does not yet
//! implement shrink passes. Later phases will add targeted reductions.
//! The minimizer is expected to preserve determinism: any returned artifact
//! must still reproduce the failure under the same schedule seed and config.

use super::artifact::GitReproArtifact;

/// Configuration for deterministic minimization.
#[derive(Clone, Copy, Debug)]
pub struct MinimizerCfg {
    /// Maximum full-pass iterations (prevents non-terminating shrink loops).
    pub max_iterations: u32,
}

impl Default for MinimizerCfg {
    fn default() -> Self {
        Self { max_iterations: 8 }
    }
}

/// Minimize a failing Git simulation case (placeholder).
///
/// The `reproduce` callback should return true only when the failure still
/// reproduces under the candidate artifact.
///
/// Phase 0 behavior: returns the input artifact unchanged.
pub fn minimize_git_case(
    failing: &GitReproArtifact,
    _cfg: MinimizerCfg,
    _reproduce: impl Fn(&GitReproArtifact) -> bool,
) -> GitReproArtifact {
    failing.clone()
}
