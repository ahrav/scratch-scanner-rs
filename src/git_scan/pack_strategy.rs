//! Pack execution strategy selection.
//!
//! This module chooses between sparse and pack-linear execution modes based
//! on pack plan statistics. The decision is deterministic and relies only
//! on precomputed plan metadata: candidate counts, candidate span, and
//! cluster distribution. No pack bytes are inspected here.
//!
//! # Strategy Heuristics
//! - Dense, tightly clustered candidate sets prefer `Linear`.
//! - Sparse or widely scattered candidates prefer `Sparse`.
//! - Clustering is bounded by `CLUSTER_GAP_BYTES` to limit seeks.
//!
//! # Invariants
//! - Offsets provided to `cluster_offsets` must be sorted and unique.
//! - Cluster boundaries are split when the gap exceeds `CLUSTER_GAP_BYTES`.

use super::pack_plan_model::{Cluster, PackPlan, PackPlanStats, CLUSTER_GAP_BYTES};

/// Execution strategy for a pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackStrategy {
    /// Decode only required offsets (candidates + bases).
    Sparse,
    /// Decode in pack order and gate candidates with a filter.
    Linear,
}

/// Minimum number of candidates to consider pack-linear decoding.
const MIN_LINEAR_CANDIDATES: u32 = 4096;
/// Minimum candidate density (per MiB of candidate span) for linear mode.
const MIN_LINEAR_DENSITY_PER_MB: u64 = 256;
/// Maximum number of clusters allowed for linear mode.
const MAX_LINEAR_CLUSTERS: u32 = 8;
/// Maximum candidate span (bytes) for linear mode.
const MAX_LINEAR_SPAN_BYTES: u64 = CLUSTER_GAP_BYTES * 4;

/// Selects the execution strategy for a pack plan.
///
/// The decision is deterministic and depends only on plan stats and
/// precomputed clusters.
#[must_use]
pub fn select_pack_strategy(plan: &PackPlan) -> PackStrategy {
    select_pack_strategy_with_clusters(plan.stats, plan.clusters.len() as u32)
}

fn select_pack_strategy_with_clusters(stats: PackPlanStats, cluster_count: u32) -> PackStrategy {
    // Reject linear mode when the plan has no useful density or has forward deps.
    if stats.candidate_count == 0 || stats.candidate_span == 0 {
        return PackStrategy::Sparse;
    }
    if stats.forward_deps > 0 {
        return PackStrategy::Sparse;
    }

    let span_bytes = stats.candidate_span.max(1);
    let density_per_mb = (stats.candidate_count as u64 * 1024 * 1024) / span_bytes;
    let dense_enough = stats.candidate_count >= MIN_LINEAR_CANDIDATES
        && density_per_mb >= MIN_LINEAR_DENSITY_PER_MB;

    let span_ok = stats.candidate_span <= MAX_LINEAR_SPAN_BYTES;
    let clusters_ok = cluster_count <= MAX_LINEAR_CLUSTERS;

    if dense_enough && span_ok && clusters_ok {
        PackStrategy::Linear
    } else {
        PackStrategy::Sparse
    }
}

/// Clusters sorted offsets using the `CLUSTER_GAP_BYTES` threshold.
///
/// # Panics
/// Panics in debug builds if offsets are not sorted.
#[must_use]
pub fn cluster_offsets(offsets: &[u64]) -> Vec<Cluster> {
    if offsets.is_empty() {
        return Vec::new();
    }

    debug_assert!(is_sorted_unique(offsets));

    let mut clusters = Vec::new();
    let mut start_idx = 0usize;
    let mut start_offset = offsets[0];
    let mut last_offset = offsets[0];

    for (idx, &offset) in offsets.iter().enumerate().skip(1) {
        if offset - last_offset > CLUSTER_GAP_BYTES {
            clusters.push(Cluster {
                start_idx: start_idx as u32,
                end_idx: idx as u32,
                start_offset,
                end_offset: last_offset,
            });
            start_idx = idx;
            start_offset = offset;
        }
        last_offset = offset;
    }

    clusters.push(Cluster {
        start_idx: start_idx as u32,
        end_idx: offsets.len() as u32,
        start_offset,
        end_offset: last_offset,
    });

    clusters
}

fn is_sorted_unique(offsets: &[u64]) -> bool {
    offsets.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(candidate_count: u32, candidate_span: u64) -> PackPlanStats {
        PackPlanStats {
            candidate_count,
            need_count: candidate_count,
            external_bases: 0,
            forward_deps: 0,
            candidate_span,
        }
    }

    #[test]
    fn cluster_offsets_splits_on_gap() {
        let offsets = vec![
            100,
            200,
            400,
            2 * CLUSTER_GAP_BYTES + 10,
            2 * CLUSTER_GAP_BYTES + 20,
            5 * CLUSTER_GAP_BYTES + 1,
        ];
        let clusters = cluster_offsets(&offsets);

        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters[0].start_idx, 0);
        assert_eq!(clusters[0].end_idx, 3);
        assert_eq!(clusters[1].start_idx, 3);
        assert_eq!(clusters[1].end_idx, 5);
        assert_eq!(clusters[2].start_idx, 5);
        assert_eq!(clusters[2].end_idx, 6);
    }

    #[test]
    fn strategy_prefers_linear_for_dense_clusters() {
        let stats = stats(6000, CLUSTER_GAP_BYTES * 2);
        let strategy = select_pack_strategy_with_clusters(stats, 2);
        assert_eq!(strategy, PackStrategy::Linear);
    }

    #[test]
    fn strategy_prefers_sparse_for_low_density() {
        let stats = stats(512, CLUSTER_GAP_BYTES * 64);
        let strategy = select_pack_strategy_with_clusters(stats, 2);
        assert_eq!(strategy, PackStrategy::Sparse);
    }

    #[test]
    fn strategy_prefers_sparse_for_many_clusters() {
        let stats = stats(6000, CLUSTER_GAP_BYTES * 2);
        let strategy = select_pack_strategy_with_clusters(stats, 20);
        assert_eq!(strategy, PackStrategy::Sparse);
    }

    #[test]
    fn strategy_forwards_deps_force_sparse() {
        let mut stats = stats(6000, CLUSTER_GAP_BYTES * 2);
        stats.forward_deps = 1;
        let strategy = select_pack_strategy_with_clusters(stats, 1);
        assert_eq!(strategy, PackStrategy::Sparse);
    }
}
