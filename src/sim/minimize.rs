//! Deterministic minimizer for scanner simulation artifacts.
//!
//! The minimizer applies greedy, deterministic shrink passes. Each candidate
//! reduction is replayed via a caller-provided predicate and kept only if it
//! reproduces the failure. No randomness is used.

use std::collections::BTreeMap;

use crate::sim::artifact::ReproArtifact;
use crate::sim::fault::{FaultPlan, FileFaultPlan};
use crate::sim::fs::{SimNodeSpec, SimPath};
use crate::sim_archive::materialize_archive_with_paths;
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
        if reduce_archives(&mut cur, &reproduce) {
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

    scenario
        .archives
        .retain(|spec| spec.root_path.bytes != path.bytes);

    let root = &path.bytes;
    scenario.expected.retain(|exp| {
        if exp.path.bytes == *root {
            return false;
        }
        !is_virtual_child_path(root, &exp.path.bytes)
    });
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

/// Archive-specific shrink passes (entries, payloads, metadata, corruption).
fn reduce_archives(cur: &mut ReproArtifact, reproduce: &impl Fn(&ReproArtifact) -> bool) -> bool {
    if cur.scenario.archives.is_empty() {
        return false;
    }

    let mut changed = false;
    loop {
        let mut progress = false;

        for archive_idx in 0..cur.scenario.archives.len() {
            if reduce_archive_entries(cur, reproduce, archive_idx) {
                changed = true;
                progress = true;
                break;
            }
            if reduce_archive_payloads(cur, reproduce, archive_idx) {
                changed = true;
                progress = true;
                break;
            }
            if reduce_archive_names(cur, reproduce, archive_idx) {
                changed = true;
                progress = true;
                break;
            }
            if reduce_archive_corruption(cur, reproduce, archive_idx) {
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

fn reduce_archive_entries(
    cur: &mut ReproArtifact,
    reproduce: &impl Fn(&ReproArtifact) -> bool,
    archive_idx: usize,
) -> bool {
    let entry_len = match cur.scenario.archives.get(archive_idx) {
        Some(spec) => spec.entries.len(),
        None => return false,
    };
    if entry_len <= 1 {
        return false;
    }

    for entry_idx in (0..entry_len).rev() {
        let mut cand = cur.clone();
        let old_paths = archive_entry_paths(&cand, archive_idx).ok();

        if let Some(spec) = cand.scenario.archives.get_mut(archive_idx) {
            spec.entries.remove(entry_idx);
        } else {
            continue;
        }

        if rematerialize_archive(&mut cand, archive_idx, old_paths.as_deref()).is_err() {
            continue;
        }
        if reproduce(&cand) {
            *cur = cand;
            return true;
        }
    }

    false
}

fn reduce_archive_payloads(
    cur: &mut ReproArtifact,
    reproduce: &impl Fn(&ReproArtifact) -> bool,
    archive_idx: usize,
) -> bool {
    let Some(spec) = cur.scenario.archives.get(archive_idx) else {
        return false;
    };
    if spec.entries.is_empty() {
        return false;
    }

    for entry_idx in 0..spec.entries.len() {
        let payload_len = spec.entries[entry_idx].payload.len();
        if payload_len <= 1 {
            continue;
        }

        for &target in &[payload_len / 2, 0] {
            let mut cand = cur.clone();
            let old_paths = archive_entry_paths(&cand, archive_idx).ok();
            if let Some(entry) = cand
                .scenario
                .archives
                .get_mut(archive_idx)
                .and_then(|spec| spec.entries.get_mut(entry_idx))
            {
                entry.payload.truncate(target);
            }
            if rematerialize_archive(&mut cand, archive_idx, old_paths.as_deref()).is_err() {
                continue;
            }
            if reproduce(&cand) {
                *cur = cand;
                return true;
            }
        }
    }

    false
}

fn reduce_archive_names(
    cur: &mut ReproArtifact,
    reproduce: &impl Fn(&ReproArtifact) -> bool,
    archive_idx: usize,
) -> bool {
    let Some(spec) = cur.scenario.archives.get(archive_idx) else {
        return false;
    };

    for entry_idx in 0..spec.entries.len() {
        let name_len = spec.entries[entry_idx].name_bytes.len();
        if name_len <= 1 {
            continue;
        }

        let target = name_len / 2;
        let mut cand = cur.clone();
        let old_paths = archive_entry_paths(&cand, archive_idx).ok();
        if let Some(entry) = cand
            .scenario
            .archives
            .get_mut(archive_idx)
            .and_then(|spec| spec.entries.get_mut(entry_idx))
        {
            entry.name_bytes.truncate(target.max(1));
        }

        if rematerialize_archive(&mut cand, archive_idx, old_paths.as_deref()).is_err() {
            continue;
        }
        if reproduce(&cand) {
            *cur = cand;
            return true;
        }
    }

    false
}

fn reduce_archive_corruption(
    cur: &mut ReproArtifact,
    reproduce: &impl Fn(&ReproArtifact) -> bool,
    archive_idx: usize,
) -> bool {
    let Some(spec) = cur.scenario.archives.get(archive_idx) else {
        return false;
    };
    let Some(corruption) = spec.corruption.clone() else {
        return false;
    };

    match corruption {
        crate::sim_scanner::scenario::ArchiveCorruptionSpec::TruncateTo { len } => {
            if len <= 1 {
                return false;
            }
            let target = len / 2;
            let mut cand = cur.clone();
            let old_paths = archive_entry_paths(&cand, archive_idx).ok();
            if let Some(spec) = cand.scenario.archives.get_mut(archive_idx) {
                spec.corruption = Some(
                    crate::sim_scanner::scenario::ArchiveCorruptionSpec::TruncateTo { len: target },
                );
            }
            if rematerialize_archive(&mut cand, archive_idx, old_paths.as_deref()).is_err() {
                return false;
            }
            if reproduce(&cand) {
                *cur = cand;
                return true;
            }
        }
    }

    false
}

fn archive_entry_paths(
    artifact: &ReproArtifact,
    archive_idx: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let spec = artifact
        .scenario
        .archives
        .get(archive_idx)
        .ok_or_else(|| "archive missing".to_string())?;
    let (_bytes, paths) = materialize_archive_with_paths(spec, &artifact.run_config.archive)?;
    Ok(paths)
}

/// Rebuild archive bytes and expected paths after modifying an archive spec.
fn rematerialize_archive(
    artifact: &mut ReproArtifact,
    archive_idx: usize,
    old_paths: Option<&[Vec<u8>]>,
) -> Result<(), String> {
    let (bytes, new_paths, root_path, entry_lens) = {
        let spec = artifact
            .scenario
            .archives
            .get(archive_idx)
            .ok_or_else(|| "archive missing".to_string())?;
        let (bytes, new_paths) =
            materialize_archive_with_paths(spec, &artifact.run_config.archive)?;
        let root_path = spec.root_path.clone();
        let entry_lens: Vec<u64> = spec
            .entries
            .iter()
            .map(|e| e.payload.len() as u64)
            .collect();
        (bytes, new_paths, root_path, entry_lens)
    };

    update_archive_fs_node(&mut artifact.scenario, &root_path, bytes);

    if let Some(old_paths) = old_paths {
        update_expected_paths_for_archive(
            &mut artifact.scenario,
            old_paths,
            &new_paths,
            &entry_lens,
        );
    }

    Ok(())
}

fn update_archive_fs_node(scenario: &mut Scenario, root: &SimPath, bytes: Vec<u8>) {
    for node in &mut scenario.fs.nodes {
        if let SimNodeSpec::File { path, contents, .. } = node {
            if path.bytes == root.bytes {
                *contents = bytes;
                return;
            }
        }
    }
}

/// Update expected paths by mapping old entry paths to new ones (same order).
fn update_expected_paths_for_archive(
    scenario: &mut Scenario,
    old_paths: &[Vec<u8>],
    new_paths: &[Vec<u8>],
    entry_lens: &[u64],
) {
    let mut map: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for (idx, path) in old_paths.iter().enumerate() {
        map.insert(path.clone(), idx);
    }

    let mut updated = Vec::with_capacity(scenario.expected.len());
    for mut exp in scenario.expected.drain(..) {
        if let Some(&idx) = map.get(&exp.path.bytes) {
            if idx >= new_paths.len() {
                continue;
            }
            if let Some(&len) = entry_lens.get(idx) {
                if exp.root_span.end as u64 > len {
                    continue;
                }
            }
            exp.path.bytes = new_paths[idx].clone();
        }
        updated.push(exp);
    }
    scenario.expected = updated;
}

fn is_virtual_child_path(root: &[u8], path: &[u8]) -> bool {
    if path.len() <= root.len() + 2 {
        return false;
    }
    if !path.starts_with(root) {
        return false;
    }
    path[root.len()..].starts_with(b"::")
}
