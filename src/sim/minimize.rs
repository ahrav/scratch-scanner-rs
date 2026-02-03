//! Deterministic minimizer for scanner simulation artifacts.
//!
//! The minimizer applies greedy, deterministic shrink passes. Each candidate
//! reduction is replayed via a caller-provided predicate and kept only if it
//! reproduces the failure. No randomness is used.

use crate::sim::artifact::ReproArtifact;
use crate::sim::fault::{FaultPlan, FileFaultPlan};
use crate::sim::fs::{SimNodeSpec, SimPath};
use crate::sim_scanner::scenario::Scenario;

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

/// Minimize a failing scanner case by applying deterministic shrink passes.
///
/// The `reproduce` callback should return true only when the failure still
/// reproduces under the candidate artifact.
pub fn minimize_scanner_case(
    failing: &ReproArtifact,
    cfg: MinimizerCfg,
    reproduce: impl Fn(&ReproArtifact) -> bool,
) -> ReproArtifact {
    let mut cur = failing.clone();

    let mut iter = 0u32;
    loop {
        if iter >= cfg.max_iterations {
            break;
        }
        iter = iter.saturating_add(1);

        let mut changed = false;
        if reduce_workers(&mut cur, &reproduce) {
            changed = true;
        }
        if reduce_faults(&mut cur, &reproduce) {
            changed = true;
        }
        if reduce_files(&mut cur, &reproduce) {
            changed = true;
        }

        if !changed {
            break;
        }
    }

    cur
}

fn reduce_workers(cur: &mut ReproArtifact, reproduce: &impl Fn(&ReproArtifact) -> bool) -> bool {
    let mut changed = false;
    let start = cur.run_config.workers;
    for workers in (1..start).rev() {
        let mut cand = cur.clone();
        cand.run_config.workers = workers;
        if reproduce(&cand) {
            *cur = cand;
            changed = true;
        }
    }
    changed
}

fn reduce_faults(cur: &mut ReproArtifact, reproduce: &impl Fn(&ReproArtifact) -> bool) -> bool {
    let mut changed = false;

    loop {
        let keys: Vec<Vec<u8>> = cur.fault_plan.per_file.keys().cloned().collect();
        let mut progress = false;

        for path in keys {
            // Pass 1: drop the entire file fault entry.
            let mut cand = cur.clone();
            cand.fault_plan.per_file.remove(&path);
            if reproduce(&cand) {
                *cur = cand;
                changed = true;
                progress = true;
                break;
            }

            let Some(file_plan) = cur.fault_plan.per_file.get(&path).cloned() else {
                continue;
            };

            // Pass 2: remove open fault.
            if file_plan.open.is_some() {
                let mut cand = cur.clone();
                if let Some(plan) = cand.fault_plan.per_file.get_mut(&path) {
                    plan.open = None;
                }
                prune_empty_file_plan(&mut cand.fault_plan, &path);
                if reproduce(&cand) {
                    *cur = cand;
                    changed = true;
                    progress = true;
                    break;
                }
            }

            // Pass 3: remove cancellation.
            if file_plan.cancel_after_reads.is_some() {
                let mut cand = cur.clone();
                if let Some(plan) = cand.fault_plan.per_file.get_mut(&path) {
                    plan.cancel_after_reads = None;
                }
                prune_empty_file_plan(&mut cand.fault_plan, &path);
                if reproduce(&cand) {
                    *cur = cand;
                    changed = true;
                    progress = true;
                    break;
                }
            }

            // Pass 4: truncate read faults from the tail.
            let read_len = file_plan.reads.len();
            for new_len in (0..read_len).rev() {
                let mut cand = cur.clone();
                if let Some(plan) = cand.fault_plan.per_file.get_mut(&path) {
                    plan.reads.truncate(new_len);
                }
                prune_empty_file_plan(&mut cand.fault_plan, &path);
                if reproduce(&cand) {
                    *cur = cand;
                    changed = true;
                    progress = true;
                    break;
                }
            }

            if progress {
                break;
            }
        }

        if !progress {
            break;
        }
    }

    changed
}

fn reduce_files(cur: &mut ReproArtifact, reproduce: &impl Fn(&ReproArtifact) -> bool) -> bool {
    let mut changed = false;

    loop {
        let files = sorted_file_paths(&cur.scenario);
        let mut progress = false;

        for path in files {
            let mut cand = cur.clone();
            remove_file_from_scenario(&mut cand.scenario, &path);
            cand.fault_plan.per_file.remove(&path.bytes);
            if reproduce(&cand) {
                *cur = cand;
                changed = true;
                progress = true;
                break;
            }
        }

        if !progress {
            break;
        }
    }

    changed
}

fn prune_empty_file_plan(plan: &mut FaultPlan, path: &[u8]) {
    let remove = plan
        .per_file
        .get(path)
        .map(file_plan_empty)
        .unwrap_or(false);
    if remove {
        plan.per_file.remove(path);
    }
}

fn file_plan_empty(plan: &FileFaultPlan) -> bool {
    plan.open.is_none() && plan.cancel_after_reads.is_none() && plan.reads.is_empty()
}

fn remove_file_from_scenario(scenario: &mut Scenario, path: &SimPath) {
    scenario.fs.nodes.retain(|node| match node {
        SimNodeSpec::File { path: p, .. } => p.bytes != path.bytes,
        _ => true,
    });

    for node in &mut scenario.fs.nodes {
        if let SimNodeSpec::Dir { children, .. } = node {
            children.retain(|child| child.bytes != path.bytes);
        }
    }

    scenario.expected.retain(|exp| exp.path.bytes != path.bytes);
}

fn sorted_file_paths(scenario: &Scenario) -> Vec<SimPath> {
    let mut files = Vec::new();
    for node in &scenario.fs.nodes {
        if let SimNodeSpec::File { path, .. } = node {
            files.push(path.clone());
        }
    }
    files.sort_by(|a, b| a.bytes.cmp(&b.bytes));
    files
}
