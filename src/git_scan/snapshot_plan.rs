//! Snapshot commit planning (snapshot mode).
//!
//! Snapshot mode emits each ref tip and treats it as a diff against the empty
//! tree (no history walk). Watermarks are ignored and no deduplication is
//! performed: if multiple refs point to the same tip, it will appear multiple
//! times to preserve per-ref reporting semantics.

use super::commit_walk::{CommitGraph, PlannedCommit};
use super::commit_walk_limits::CommitWalkLimits;
use super::errors::Phase2PlanError;
use super::repo_open::RepoJobState;

/// Produces a snapshot plan: each ref tip appears once as a "diff vs empty tree".
///
/// # Errors
/// - `CommitGraphTooLarge` if the graph exceeds the configured limit.
/// - `TipNotFound` if a ref tip is missing from the commit-graph.
pub fn snapshot_plan<CG: CommitGraph>(
    repo: &RepoJobState,
    cg: &CG,
    limits: CommitWalkLimits,
) -> Result<Vec<PlannedCommit>, Phase2PlanError> {
    limits.validate();

    let commits = cg.num_commits();
    if commits > limits.max_commits_in_graph {
        return Err(Phase2PlanError::CommitGraphTooLarge {
            commits,
            max: limits.max_commits_in_graph,
        });
    }

    let mut out = Vec::with_capacity(repo.start_set.len());
    for r in &repo.start_set {
        let tip_pos = cg.lookup(&r.tip)?.ok_or(Phase2PlanError::TipNotFound)?;
        out.push(PlannedCommit {
            pos: tip_pos,
            snapshot_root: true,
        });
    }

    Ok(out)
}
