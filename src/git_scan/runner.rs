//! End-to-end Git scan runner.
//!
//! Orchestrates repo open, commit walk, tree diff, spill/dedupe, pack planning,
//! pack decode + scan, finalize, and persistence.
//!
//! # Pipeline
//! 1. Open the repo (start set resolution, watermarks, artifact readiness check).
//! 2. Plan commits, diff trees, and collect candidate blobs.
//! 3. Spill/dedupe candidates and map them to pack entries.
//! 4. Plan packs, decode + scan, then finalize and optionally persist.
//!
//! # Artifact Construction
//! The runner always builds MIDX and commit-graph in memory from pack/idx
//! files via `artifact_acquire` before scanning.
//!
//! # Modes
//! - Diff-history: walk commits, diff trees, spill/dedupe candidates, then plan
//!   packs for decode + scan.
//! - ODB-blob fast: compute first-introduced blobs from the commit graph, then
//!   scan in pack order; if candidate caps or path arena limits are exceeded,
//!   retry via the spill/dedupe pipeline.
//!
//! # Invariants
//! - MIDX completeness is verified before pack execution.
//! - Pack cache sizing must fit in `u32` (checked before execution).
//!
//! # Notes
//! - Loose objects are decoded via `PackIo::load_loose_object`; failures are
//!   recorded as skipped candidates.
//! - Persistence is optional; callers can run the pipeline without a store.
//! - Stage `mapping`/`scan` timings are sourced from perf counters when enabled.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::scheduler::AllocStatsDelta;
use crate::Engine;

use super::artifact_acquire::{
    acquire_commit_graph, acquire_midx, ArtifactAcquireError, ArtifactBuildLimits,
};
use super::byte_arena::ByteArena;
use super::commit_graph::CommitGraphIndex;
use super::commit_walk::introduced_by_plan;
use super::commit_walk_limits::CommitWalkLimits;
use super::engine_adapter::{EngineAdapterConfig, ScannedBlobs};
use super::errors::{CommitPlanError, PersistError, RepoOpenError, SpillError, TreeDiffError};
use super::finalize::{build_finalize_ops, FinalizeInput, FinalizeOutput};
use super::limits::RepoOpenLimits;
use super::mapping_bridge::{MappingBridgeConfig, MappingStats};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{PackExecError, PackExecReport, SkipReason};
use super::pack_io::{PackIoError, PackIoLimits};
use super::pack_plan::{PackPlanConfig, PackPlanError};
use super::pack_plan_model::PackPlanStats;
use super::persist::{persist_finalize_output, PersistenceStore};
use super::policy_hash::MergeDiffMode;
use super::repo_open::{repo_open, RefWatermarkStore, StartSetResolver};
use super::seen_store::SeenBlobStore;
use super::spill_limits::SpillLimits;
use super::spiller::SpillStats;
use super::start_set::StartSetConfig;
use super::tree_diff::TreeDiffStats;
use super::tree_diff_limits::TreeDiffLimits;

use super::runner_exec::build_ref_entries;

/// Limits for pack file mmapping during scan execution.
#[derive(Clone, Copy, Debug)]
pub struct PackMmapLimits {
    /// Maximum number of pack files to mmap.
    ///
    /// Counted from MIDX-resolved pack paths.
    pub max_open_packs: u16,
    /// Maximum total bytes to mmap across all packs.
    ///
    /// Computed from file sizes; this caps address space usage, not RSS.
    pub max_total_bytes: u64,
}

impl PackMmapLimits {
    /// Safe defaults suitable for large monorepos.
    pub const DEFAULT: Self = Self {
        max_open_packs: 128,
        max_total_bytes: 8 * 1024 * 1024 * 1024,
    };

    /// Restrictive limits for testing or constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_open_packs: 8,
        max_total_bytes: 512 * 1024 * 1024,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_open_packs > 0, "must allow at least 1 pack");
        assert!(self.max_total_bytes > 0, "pack mmap budget must be > 0");
    }
}

/// Git scan runner configuration.
///
/// The defaults mirror the Git scanning limits and are intended for
/// production usage. Callers should set `repo_id` and `policy_hash` to
/// stable identifiers for their environment to ensure consistent
/// persistence keys and scan identity.
///
/// `pack_cache_bytes` is an in-memory cache cap; oversized values are rejected
/// at runtime when converting to `u32`.
///
/// `spill_dir` controls where intermediate spill files are written. When
/// `None`, a unique temp directory is created per run.
#[derive(Clone, Debug)]
pub struct GitScanConfig {
    /// Scan mode selection (diff-history vs ODB-blob fast path).
    pub scan_mode: GitScanMode,
    /// Stable repository identifier used to namespace persisted keys.
    pub repo_id: u64,
    /// Stable policy hash that identifies the scan configuration.
    pub policy_hash: [u8; 32],
    /// Start set selection (default branch, explicit refs, etc.).
    pub start_set: StartSetConfig,
    /// Merge diff strategy for merge commits.
    pub merge_diff_mode: MergeDiffMode,
    /// Path-policy version for scan configuration hashing.
    pub path_policy_version: u32,
    /// Repo-open limits (mmap sizes, ref caps, etc.).
    pub repo_open: RepoOpenLimits,
    /// Commit-walk limits (parents, batching).
    pub commit_walk: CommitWalkLimits,
    /// Tree-diff limits (depth, byte budgets, candidate caps).
    pub tree_diff: TreeDiffLimits,
    /// Spill/dedupe limits (chunk sizes, run caps, seen batching).
    pub spill: SpillLimits,
    /// Mapping bridge limits (arena sizes, candidate caps).
    pub mapping: MappingBridgeConfig,
    /// Pack planning configuration (cluster sizing, delta bounds).
    pub pack_plan: PackPlanConfig,
    /// Pack decode limits (inflate and object size caps).
    pub pack_decode: PackDecodeLimits,
    /// Pack IO limits (loose object caps, base resolution).
    pub pack_io: PackIoLimits,
    /// Engine adapter configuration (chunk sizes and overlap).
    pub engine_adapter: EngineAdapterConfig,
    /// Pack mmap limits during pack execution (count + total bytes).
    pub pack_mmap: PackMmapLimits,
    /// Pack cache size in bytes (must fit in `u32`).
    pub pack_cache_bytes: usize,
    /// Pack exec worker count (1 = single-threaded).
    ///
    /// Default oversubscribes 2x cores (capped at 24) to hide pack IO + decode
    /// stalls while avoiding unbounded memory-bandwidth contention.
    ///
    /// Applies to both scan modes (`odb-blob` and `diff-history`).
    pub pack_exec_workers: usize,
    /// Optional spill directory override. When `None`, a unique temp directory is used.
    pub spill_dir: Option<PathBuf>,
    /// Limits for in-memory artifact construction.
    ///
    /// Applied when disk artifacts are missing and `run_git_scan` builds
    /// MIDX and commit-graph in memory.
    pub artifact_build: ArtifactBuildLimits,
}

impl Default for GitScanConfig {
    fn default() -> Self {
        let pack_decode = PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024);
        Self {
            // Default to ODB-blob for throughput; diff-history must be explicit.
            scan_mode: GitScanMode::OdbBlobFast,
            repo_id: 1,
            policy_hash: [0u8; 32],
            start_set: StartSetConfig::DefaultBranchOnly,
            merge_diff_mode: MergeDiffMode::AllParents,
            path_policy_version: 1,
            repo_open: RepoOpenLimits::DEFAULT,
            commit_walk: CommitWalkLimits::DEFAULT,
            tree_diff: TreeDiffLimits::DEFAULT,
            spill: SpillLimits::DEFAULT,
            mapping: MappingBridgeConfig::default(),
            pack_plan: PackPlanConfig::default(),
            pack_decode,
            pack_io: PackIoLimits::new(pack_decode, PackPlanConfig::default().max_delta_depth),
            engine_adapter: EngineAdapterConfig::default(),
            pack_mmap: PackMmapLimits::DEFAULT,
            pack_cache_bytes: 64 * 1024 * 1024,
            pack_exec_workers: default_pack_exec_workers(),
            spill_dir: None,
            artifact_build: ArtifactBuildLimits::default(),
        }
    }
}

/// Chooses a throughput-optimized pack exec worker count.
///
/// We oversubscribe 2x cores to mask IO/decode latency, but cap at 24 to avoid
/// cache thrash and memory-bandwidth collapse on large machines.
fn default_pack_exec_workers() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let doubled = parallelism.saturating_mul(2);
    let capped = if doubled > 24 { 24 } else { doubled };
    capped.max(1)
}

/// Git scan execution mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitScanMode {
    /// Current diff-history pipeline (tree diff + spill + mapping + pack plan).
    DiffHistory,
    /// ODB-blob fast path (first-introduced blob walk + pack-order scan).
    #[default]
    OdbBlobFast,
}

impl std::fmt::Display for GitScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiffHistory => write!(f, "diff-history"),
            Self::OdbBlobFast => write!(f, "odb-blob"),
        }
    }
}

/// Result of a Git scan run.
///
/// Wraps `GitScanReport` as a newtype so callers destructure explicitly.
/// The report contains stage timings, finding counts, skip records, and
/// the finalize output (including watermark operations).
#[derive(Debug)]
pub struct GitScanResult(pub GitScanReport);

/// Reason a candidate blob was skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSkipReason {
    /// Loose object was missing on disk.
    LooseMissing,
    /// Loose object failed to decode.
    LooseDecode,
    /// Loose object was not a blob.
    LooseNotBlob,
    /// Pack entry was not a blob.
    PackNotBlob,
    /// Pack entry failed to decode.
    PackDecode,
    /// Delta application failed.
    PackDelta,
    /// Delta base offset was missing from the cache.
    PackBaseMissing,
    /// External base OID could not be resolved.
    PackExternalBaseMissing,
    /// External base provider failed.
    PackExternalBaseError,
    /// Pack parse error surfaced as a skip.
    PackParse,
}

impl CandidateSkipReason {
    pub(super) fn from_pack_skip(reason: &SkipReason) -> Self {
        match reason {
            SkipReason::PackParse(_) => Self::PackParse,
            SkipReason::Decode(_) => Self::PackDecode,
            SkipReason::Delta(_) => Self::PackDelta,
            SkipReason::BaseMissing { .. } => Self::PackBaseMissing,
            SkipReason::ExternalBaseMissing { .. } => Self::PackExternalBaseMissing,
            SkipReason::ExternalBaseError => Self::PackExternalBaseError,
            SkipReason::NotBlob => Self::PackNotBlob,
        }
    }

    /// Returns a stable label for reporting.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LooseMissing => "loose_missing",
            Self::LooseDecode => "loose_decode",
            Self::LooseNotBlob => "loose_not_blob",
            Self::PackNotBlob => "pack_not_blob",
            Self::PackDecode => "pack_decode",
            Self::PackDelta => "pack_delta",
            Self::PackBaseMissing => "pack_base_missing",
            Self::PackExternalBaseMissing => "pack_external_base_missing",
            Self::PackExternalBaseError => "pack_external_base_error",
            Self::PackParse => "pack_parse",
        }
    }
}

/// Candidate blob skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Why the candidate was skipped.
    pub reason: CandidateSkipReason,
}

/// Wall-clock timing per Git scan stage (nanoseconds).
///
/// `mapping` and `scan` are populated from the `git-perf` counters when
/// available; they are zero when the feature is disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitScanStageNanos {
    /// Tree diff stage time.
    pub tree_diff: u64,
    /// Commit-plan construction time.
    pub commit_plan: u64,
    /// First-introduced blob walk time (ODB-blob mode).
    pub blob_intro: u64,
    /// Spill/dedupe stage time.
    pub spill: u64,
    /// Pack candidate collection time (ODB-blob mode).
    pub pack_collect: u64,
    /// Mapping bridge stage time (from perf counters when enabled).
    pub mapping: u64,
    /// Pack planning stage time.
    pub pack_plan: u64,
    /// Pack execution stage time.
    pub pack_exec: u64,
    /// Loose object scan time (ODB-blob mode).
    pub loose_scan: u64,
    /// Scan stage time (from perf counters when enabled).
    pub scan: u64,
}

/// Allocation deltas captured across hot stages.
///
/// These are best-effort global deltas and require the counting allocator
/// to be installed (tests do this by default).
#[derive(Debug, Clone, Copy, Default)]
pub struct GitScanAllocStats {
    /// Allocation deltas for pack decode + scan.
    pub pack_exec: AllocStatsDelta,
}

/// Snapshot of key Git scan metrics for reporting.
///
/// Throughput values are derived via integer division. `cycles_per_byte`
/// uses the optional `GIT_SCAN_CPU_HZ` hint and reports `0` when unset.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitScanMetricsSnapshot {
    /// Stage timing in nanoseconds.
    pub stages: GitScanStageNanos,
    /// Pack/scan perf counters.
    pub perf: super::perf::GitPerfStats,
    /// Total bytes read by tree diff.
    pub tree_diff_bytes: u64,
    /// Number of spill runs produced.
    pub spill_runs: usize,
    /// Total spill bytes written.
    pub spill_bytes: u64,
    /// Allocation deltas for hot stages.
    pub alloc: GitScanAllocStats,
}

impl GitScanMetricsSnapshot {
    /// Formats metrics as stable key=value lines.
    ///
    /// `cycles_per_byte` uses `GIT_SCAN_CPU_HZ` when set; otherwise it is `0`.
    #[must_use]
    pub fn format(&self) -> String {
        fn bytes_per_sec(bytes: u64, nanos: u64) -> u64 {
            if bytes == 0 || nanos == 0 {
                0
            } else {
                bytes.saturating_mul(1_000_000_000).saturating_div(nanos)
            }
        }

        fn nanos_per_byte(bytes: u64, nanos: u64) -> u64 {
            if bytes == 0 {
                0
            } else {
                nanos.saturating_div(bytes)
            }
        }

        fn cycles_per_byte(bytes: u64, nanos: u64, cpu_hz: Option<u64>) -> u64 {
            let Some(hz) = cpu_hz else {
                return 0;
            };
            if bytes == 0 || nanos == 0 {
                return 0;
            }
            let cycles = hz.saturating_mul(nanos).saturating_div(1_000_000_000);
            cycles.saturating_div(bytes)
        }

        let cpu_hz = std::env::var("GIT_SCAN_CPU_HZ")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());

        fn push_line<T: std::fmt::Display>(out: &mut String, key: &str, value: T) {
            out.push_str(key);
            out.push('=');
            out.push_str(&value.to_string());
            out.push('\n');
        }

        let mut out = String::new();

        push_line(&mut out, "stage.tree_diff.nanos", self.stages.tree_diff);
        push_line(&mut out, "stage.commit_plan.nanos", self.stages.commit_plan);
        push_line(&mut out, "stage.blob_intro.nanos", self.stages.blob_intro);
        push_line(&mut out, "stage.spill.nanos", self.stages.spill);
        push_line(
            &mut out,
            "stage.pack_collect.nanos",
            self.stages.pack_collect,
        );
        push_line(&mut out, "stage.mapping.nanos", self.stages.mapping);
        push_line(&mut out, "stage.pack_plan.nanos", self.stages.pack_plan);
        push_line(&mut out, "stage.pack_exec.nanos", self.stages.pack_exec);
        push_line(&mut out, "stage.loose_scan.nanos", self.stages.loose_scan);
        push_line(&mut out, "stage.scan.nanos", self.stages.scan);

        push_line(&mut out, "tree_diff.bytes", self.tree_diff_bytes);
        push_line(
            &mut out,
            "tree_diff.bytes_per_sec",
            bytes_per_sec(self.tree_diff_bytes, self.stages.tree_diff),
        );
        push_line(
            &mut out,
            "tree_diff.ns_per_byte",
            nanos_per_byte(self.tree_diff_bytes, self.stages.tree_diff),
        );

        push_line(&mut out, "tree_load.calls", self.perf.tree_load_calls);
        push_line(&mut out, "tree_load.bytes", self.perf.tree_load_bytes);
        push_line(&mut out, "tree_load.nanos", self.perf.tree_load_nanos);
        push_line(
            &mut out,
            "tree_load.bytes_per_sec",
            bytes_per_sec(self.perf.tree_load_bytes, self.perf.tree_load_nanos),
        );
        push_line(
            &mut out,
            "tree_load.ns_per_byte",
            nanos_per_byte(self.perf.tree_load_bytes, self.perf.tree_load_nanos),
        );
        push_line(&mut out, "tree_cache.hits", self.perf.tree_cache_hits);
        push_line(
            &mut out,
            "tree_delta_cache.hits",
            self.perf.tree_delta_cache_hits,
        );
        push_line(
            &mut out,
            "tree_delta_cache.misses",
            self.perf.tree_delta_cache_misses,
        );
        push_line(
            &mut out,
            "tree_delta_cache.bytes",
            self.perf.tree_delta_cache_bytes,
        );
        push_line(
            &mut out,
            "tree_delta_cache.hit_nanos",
            self.perf.tree_delta_cache_hit_nanos,
        );
        push_line(
            &mut out,
            "tree_delta_cache.miss_nanos",
            self.perf.tree_delta_cache_miss_nanos,
        );
        push_line(&mut out, "tree_delta_chain.0", self.perf.tree_delta_chain_0);
        push_line(&mut out, "tree_delta_chain.1", self.perf.tree_delta_chain_1);
        push_line(
            &mut out,
            "tree_delta_chain.2_3",
            self.perf.tree_delta_chain_2_3,
        );
        push_line(
            &mut out,
            "tree_delta_chain.4_7",
            self.perf.tree_delta_chain_4_7,
        );
        push_line(
            &mut out,
            "tree_delta_chain.8_plus",
            self.perf.tree_delta_chain_8_plus,
        );
        push_line(&mut out, "tree_spill.hits", self.perf.tree_spill_hits);
        push_line(&mut out, "tree_object.loads", self.perf.tree_object_loads);
        push_line(&mut out, "tree_object.bytes", self.perf.tree_object_bytes);
        push_line(&mut out, "tree_object.nanos", self.perf.tree_object_nanos);
        push_line(
            &mut out,
            "tree_object.bytes_per_sec",
            bytes_per_sec(self.perf.tree_object_bytes, self.perf.tree_object_nanos),
        );
        push_line(
            &mut out,
            "tree_object.ns_per_byte",
            nanos_per_byte(self.perf.tree_object_bytes, self.perf.tree_object_nanos),
        );
        push_line(&mut out, "tree_object.pack", self.perf.tree_object_pack);
        push_line(&mut out, "tree_object.loose", self.perf.tree_object_loose);
        push_line(&mut out, "tree_inflate.bytes", self.perf.tree_inflate_bytes);
        push_line(&mut out, "tree_inflate.nanos", self.perf.tree_inflate_nanos);
        push_line(
            &mut out,
            "tree_inflate.bytes_per_sec",
            bytes_per_sec(self.perf.tree_inflate_bytes, self.perf.tree_inflate_nanos),
        );
        push_line(
            &mut out,
            "tree_inflate.ns_per_byte",
            nanos_per_byte(self.perf.tree_inflate_bytes, self.perf.tree_inflate_nanos),
        );
        push_line(
            &mut out,
            "tree_delta_apply.bytes",
            self.perf.tree_delta_apply_bytes,
        );
        push_line(
            &mut out,
            "tree_delta_apply.nanos",
            self.perf.tree_delta_apply_nanos,
        );
        push_line(
            &mut out,
            "tree_delta_apply.bytes_per_sec",
            bytes_per_sec(
                self.perf.tree_delta_apply_bytes,
                self.perf.tree_delta_apply_nanos,
            ),
        );
        push_line(
            &mut out,
            "tree_delta_apply.ns_per_byte",
            nanos_per_byte(
                self.perf.tree_delta_apply_bytes,
                self.perf.tree_delta_apply_nanos,
            ),
        );

        push_line(&mut out, "pack_inflate.bytes", self.perf.pack_inflate_bytes);
        push_line(&mut out, "pack_inflate.nanos", self.perf.pack_inflate_nanos);
        push_line(
            &mut out,
            "pack_inflate.bytes_per_sec",
            bytes_per_sec(self.perf.pack_inflate_bytes, self.perf.pack_inflate_nanos),
        );
        push_line(
            &mut out,
            "pack_inflate.ns_per_byte",
            nanos_per_byte(self.perf.pack_inflate_bytes, self.perf.pack_inflate_nanos),
        );
        push_line(
            &mut out,
            "pack_inflate.cycles_per_byte",
            cycles_per_byte(
                self.perf.pack_inflate_bytes,
                self.perf.pack_inflate_nanos,
                cpu_hz,
            ),
        );

        push_line(&mut out, "delta_apply.bytes", self.perf.delta_apply_bytes);
        push_line(&mut out, "delta_apply.nanos", self.perf.delta_apply_nanos);
        push_line(
            &mut out,
            "delta_apply.bytes_per_sec",
            bytes_per_sec(self.perf.delta_apply_bytes, self.perf.delta_apply_nanos),
        );
        push_line(
            &mut out,
            "delta_apply.ns_per_byte",
            nanos_per_byte(self.perf.delta_apply_bytes, self.perf.delta_apply_nanos),
        );
        push_line(
            &mut out,
            "delta_apply.cycles_per_byte",
            cycles_per_byte(
                self.perf.delta_apply_bytes,
                self.perf.delta_apply_nanos,
                cpu_hz,
            ),
        );

        push_line(&mut out, "scan.bytes", self.perf.scan_bytes);
        push_line(&mut out, "scan.nanos", self.perf.scan_nanos);
        push_line(
            &mut out,
            "scan.bytes_per_sec",
            bytes_per_sec(self.perf.scan_bytes, self.perf.scan_nanos),
        );
        push_line(
            &mut out,
            "scan.ns_per_byte",
            nanos_per_byte(self.perf.scan_bytes, self.perf.scan_nanos),
        );
        push_line(
            &mut out,
            "scan.cycles_per_byte",
            cycles_per_byte(self.perf.scan_bytes, self.perf.scan_nanos, cpu_hz),
        );

        push_line(&mut out, "mapping.calls", self.perf.mapping_calls);
        push_line(&mut out, "mapping.nanos", self.perf.mapping_nanos);
        push_line(
            &mut out,
            "mapping.ns_per_call",
            nanos_per_byte(self.perf.mapping_calls.max(1), self.perf.mapping_nanos),
        );

        push_line(&mut out, "spill.runs", self.spill_runs);
        push_line(&mut out, "spill.bytes", self.spill_bytes);

        push_line(
            &mut out,
            "alloc.pack_exec.allocs",
            self.alloc.pack_exec.allocs,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.bytes",
            self.alloc.pack_exec.bytes_allocated,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.reallocs",
            self.alloc.pack_exec.reallocs,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.deallocs",
            self.alloc.pack_exec.deallocs,
        );

        out
    }
}

/// Summary report for a completed scan.
#[derive(Debug)]
pub struct GitScanReport {
    /// Number of commits processed in the plan.
    pub commit_count: usize,
    /// Tree diff stage statistics.
    pub tree_diff_stats: TreeDiffStats,
    /// Spill/dedupe stage statistics.
    pub spill_stats: SpillStats,
    /// Pack mapping statistics.
    pub mapping_stats: MappingStats,
    /// Per-pack-plan statistics.
    pub pack_plan_stats: Vec<PackPlanStats>,
    /// Pack plan configuration used for this run.
    pub pack_plan_config: PackPlanConfig,
    /// Total delta dependency count across pack plans.
    pub pack_plan_delta_deps_total: u64,
    /// Maximum delta dependency count in a single pack plan.
    pub pack_plan_delta_deps_max: u32,
    /// Pack decode + scan reports, in the same order as `pack_plan_stats`.
    pub pack_exec_reports: Vec<PackExecReport>,
    /// Candidates skipped with explicit reasons.
    pub skipped_candidates: Vec<SkippedCandidate>,
    /// Finalize output and persistence stats.
    pub finalize: FinalizeOutput,
    /// Stage timing data (nanoseconds).
    pub stage_nanos: GitScanStageNanos,
    /// Git perf counter snapshot (pack decode, scan, mapping).
    pub perf_stats: super::perf::GitPerfStats,
    /// Allocation deltas for hot stages.
    pub alloc_stats: GitScanAllocStats,
}

impl GitScanReport {
    /// Returns a snapshot of key metrics for reporting.
    #[must_use]
    pub fn metrics_snapshot(&self) -> GitScanMetricsSnapshot {
        GitScanMetricsSnapshot {
            stages: self.stage_nanos,
            perf: self.perf_stats,
            tree_diff_bytes: self.tree_diff_stats.tree_bytes_loaded,
            spill_runs: self.spill_stats.spill_runs,
            spill_bytes: self.spill_stats.spill_bytes,
            alloc: self.alloc_stats,
        }
    }

    /// Formats metrics as stable key=value lines.
    #[must_use]
    pub fn format_metrics(&self) -> String {
        self.metrics_snapshot().format()
    }
}

/// Common output from a scan mode pipeline.
///
/// Both ODB-blob and diff-history modes produce this struct. The dispatcher
/// uses it to build the final `GitScanReport` after finalize and persist.
///
/// This is a post-hoc gather: assembled after all execution completes and
/// destructured once during finalize. If execution becomes incremental,
/// consider splitting into a hot accumulator (scanned, skips, reports) and
/// cold stats (everything else) for cache locality.
pub(super) struct ScanModeOutput {
    /// Scanned blob results and finding arena.
    pub scanned: ScannedBlobs,
    /// Path arena used for candidate path storage.
    pub path_arena: ByteArena,
    /// Candidates skipped with explicit reasons.
    pub skipped_candidates: Vec<SkippedCandidate>,
    /// Pack decode + scan reports, one per pack plan.
    pub pack_exec_reports: Vec<PackExecReport>,
    /// Per-pack-plan statistics.
    pub pack_plan_stats: Vec<PackPlanStats>,
    /// Pack plan configuration used for this run.
    pub pack_plan_config: PackPlanConfig,
    /// Total delta dependency count across pack plans.
    pub pack_plan_delta_deps_total: u64,
    /// Maximum delta dependency count in a single pack plan.
    pub pack_plan_delta_deps_max: u32,
    /// Tree diff stage statistics.
    pub tree_diff_stats: TreeDiffStats,
    /// Spill/dedupe stage statistics.
    pub spill_stats: SpillStats,
    /// Pack mapping statistics.
    pub mapping_stats: MappingStats,
    /// Stage timing data (nanoseconds).
    pub stage_nanos: GitScanStageNanos,
    /// Allocation deltas for hot stages.
    pub alloc_stats: GitScanAllocStats,
}

/// Git scan error taxonomy.
#[derive(Debug)]
pub enum GitScanError {
    /// Repo open phase failed (bad metadata, missing refs, etc.).
    RepoOpen(RepoOpenError),
    /// Commit plan construction failed.
    CommitPlan(CommitPlanError),
    /// Tree diff walker encountered an error.
    TreeDiff(TreeDiffError),
    /// Spill/dedupe pipeline error.
    Spill(SpillError),
    /// MIDX parsing or validation error.
    Midx(MidxError),
    /// Pack plan construction error.
    PackPlan(PackPlanError),
    /// Fatal pack execution error.
    PackExec(PackExecError),
    /// Pack I/O (loose object or cross-pack base resolution) error.
    PackIo(PackIoError),
    /// Persistence store write failed.
    Persist(PersistError),
    /// Underlying I/O error.
    Io(io::Error),
    /// Resource limit exceeded (pack mmap counts or bytes).
    ResourceLimit(String),
    /// Scan mode not yet implemented.
    UnsupportedMode(GitScanMode),
    /// In-memory artifact construction failed.
    ArtifactAcquire(ArtifactAcquireError),
    /// Artifacts changed during the scan (concurrent git maintenance detected).
    ConcurrentMaintenance,
}

impl std::fmt::Display for GitScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RepoOpen(err) => write!(f, "{err}"),
            Self::CommitPlan(err) => write!(f, "{err}"),
            Self::TreeDiff(err) => write!(f, "{err}"),
            Self::Spill(err) => write!(f, "{err}"),
            Self::Midx(err) => write!(f, "{err}"),
            Self::PackPlan(err) => write!(f, "{err}"),
            Self::PackExec(err) => write!(f, "{err}"),
            Self::PackIo(err) => write!(f, "{err}"),
            Self::Persist(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::ResourceLimit(msg) => write!(f, "resource limit exceeded: {msg}"),
            Self::UnsupportedMode(mode) => write!(f, "scan mode not implemented: {mode}"),
            Self::ArtifactAcquire(err) => write!(f, "artifact acquisition failed: {err}"),
            Self::ConcurrentMaintenance => {
                write!(
                    f,
                    "concurrent git maintenance detected; artifacts changed during scan"
                )
            }
        }
    }
}

impl std::error::Error for GitScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RepoOpen(err) => Some(err),
            Self::CommitPlan(err) => Some(err),
            Self::TreeDiff(err) => Some(err),
            Self::Spill(err) => Some(err),
            Self::Midx(err) => Some(err),
            Self::PackPlan(err) => Some(err),
            Self::PackExec(err) => Some(err),
            Self::PackIo(err) => Some(err),
            Self::Persist(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::ArtifactAcquire(err) => Some(err),
            Self::ResourceLimit(_) | Self::UnsupportedMode(_) | Self::ConcurrentMaintenance => None,
        }
    }
}

impl From<RepoOpenError> for GitScanError {
    fn from(err: RepoOpenError) -> Self {
        Self::RepoOpen(err)
    }
}
impl From<CommitPlanError> for GitScanError {
    fn from(err: CommitPlanError) -> Self {
        Self::CommitPlan(err)
    }
}
impl From<TreeDiffError> for GitScanError {
    fn from(err: TreeDiffError) -> Self {
        Self::TreeDiff(err)
    }
}
impl From<SpillError> for GitScanError {
    fn from(err: SpillError) -> Self {
        Self::Spill(err)
    }
}
impl From<MidxError> for GitScanError {
    fn from(err: MidxError) -> Self {
        Self::Midx(err)
    }
}
impl From<PackPlanError> for GitScanError {
    fn from(err: PackPlanError) -> Self {
        Self::PackPlan(err)
    }
}
impl From<PackExecError> for GitScanError {
    fn from(err: PackExecError) -> Self {
        Self::PackExec(err)
    }
}
impl From<PackIoError> for GitScanError {
    fn from(err: PackIoError) -> Self {
        Self::PackIo(err)
    }
}
impl From<PersistError> for GitScanError {
    fn from(err: PersistError) -> Self {
        Self::Persist(err)
    }
}
impl From<io::Error> for GitScanError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<ArtifactAcquireError> for GitScanError {
    fn from(err: ArtifactAcquireError) -> Self {
        Self::ArtifactAcquire(err)
    }
}

/// Runs a full Git scan with the provided configuration and stores.
///
/// When disk artifacts (MIDX, commit-graph) are missing, this function
/// builds them in memory via `artifact_acquire`. On success, the scan is
/// finalized and optionally persisted.
///
/// # Inputs
/// - `repo_root` must reference a Git repository with readable metadata.
/// - `resolver` controls how the start set is chosen (default branch, refs, etc.).
/// - `seen_store` is used to dedupe candidates across runs.
/// - `watermark_store` supplies existing ref watermarks; it is not mutated here.
/// - `persist_store` is optional; when `Some`, finalize output (including
///   watermarks on complete runs) is committed atomically.
///
/// If no persistence store is provided, the caller is responsible for
/// interpreting `FinalizeOutcome` and storing watermarks as needed.
///
/// # Returns
/// A `GitScanResult` containing the `GitScanReport` when the scan finishes.
///
/// # Errors
/// Returns `ConcurrentMaintenance` if artifacts changed during the scan,
/// indicating another process modified the repository.
/// Pack mmap limits and cache sizing may surface as `GitScanError::ResourceLimit`.
/// Missing or corrupt maintenance artifacts (commit-graph, MIDX) surface as
/// `GitScanError::CommitPlan` or `GitScanError::Midx`.
///
/// # Determinism
/// Pack plans are built in pack order, and parallel execution reassembles
/// results by pack (and shard) order before finalize. This keeps scan output
/// stable even when multiple workers are used.
///
/// # Caveats
/// - Loose object decode failures are recorded as skipped candidates and may
///   yield a `FinalizeOutcome::Partial`, suppressing watermark writes.
#[allow(clippy::too_many_arguments)]
pub fn run_git_scan(
    repo_root: &Path,
    engine: &Engine,
    resolver: &dyn StartSetResolver,
    seen_store: &dyn SeenBlobStore,
    watermark_store: &dyn RefWatermarkStore,
    persist_store: Option<&dyn PersistenceStore>,
    config: &GitScanConfig,
) -> Result<GitScanResult, GitScanError> {
    super::perf::reset();

    let start_set_id = config.start_set.id();
    let mut repo = repo_open(
        repo_root,
        config.repo_id,
        config.policy_hash,
        start_set_id,
        resolver,
        watermark_store,
        config.repo_open,
    )?;

    let midx_result = acquire_midx(&mut repo, &config.artifact_build)?;
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), repo.object_format)?;
    let cg = acquire_commit_graph(
        &repo,
        &midx_view,
        &midx_result.pack_paths,
        &config.artifact_build,
    )?;

    // Commit plan (shared across both modes).
    let plan_start = Instant::now();
    let plan = introduced_by_plan(&repo, &cg, config.commit_walk)?;
    let commit_plan_nanos = plan_start.elapsed().as_nanos() as u64;

    // Dispatch to mode-specific pipeline.
    let mut output = match config.scan_mode {
        GitScanMode::OdbBlobFast => {
            let cg_index = CommitGraphIndex::build(&cg)?;
            super::runner_odb_blob::run_odb_blob(
                &repo, engine, seen_store, &cg_index, &plan, config,
            )?
        }
        GitScanMode::DiffHistory => super::runner_diff_history::run_diff_history(
            &repo, engine, seen_store, &cg, &plan, config,
        )?,
    };
    output.stage_nanos.commit_plan = commit_plan_nanos;

    // Post-execution artifact stability check.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // Finalize + persist.
    let refs = build_ref_entries(&repo);
    let skipped_candidate_oids = output
        .skipped_candidates
        .iter()
        .map(|entry| entry.oid)
        .collect();
    let finalize = build_finalize_ops(FinalizeInput {
        repo_id: config.repo_id,
        policy_hash: config.policy_hash,
        start_set_id,
        refs,
        scanned_blobs: output.scanned.blobs,
        finding_arena: &output.scanned.finding_arena,
        skipped_candidate_oids,
        path_arena: &output.path_arena,
    });

    if let Some(store) = persist_store {
        persist_finalize_output(store, &finalize)?;
    }

    // Perf snapshot + report.
    let perf_stats = super::perf::snapshot();
    output.stage_nanos.mapping = perf_stats.mapping_nanos;
    output.stage_nanos.scan = perf_stats.scan_nanos;

    Ok(GitScanResult(GitScanReport {
        commit_count: plan.len(),
        tree_diff_stats: output.tree_diff_stats,
        spill_stats: output.spill_stats,
        mapping_stats: output.mapping_stats,
        pack_plan_stats: output.pack_plan_stats,
        pack_plan_config: output.pack_plan_config,
        pack_plan_delta_deps_total: output.pack_plan_delta_deps_total,
        pack_plan_delta_deps_max: output.pack_plan_delta_deps_max,
        pack_exec_reports: output.pack_exec_reports,
        skipped_candidates: output.skipped_candidates,
        finalize,
        stage_nanos: output.stage_nanos,
        perf_stats,
        alloc_stats: output.alloc_stats,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_mode_matches_config_default() {
        assert_eq!(GitScanConfig::default().scan_mode, GitScanMode::default());
    }

    #[test]
    fn metrics_format_is_stable() {
        let snapshot = GitScanMetricsSnapshot {
            stages: GitScanStageNanos {
                tree_diff: 2_000,
                commit_plan: 1_000,
                blob_intro: 0,
                spill: 3_000,
                pack_collect: 0,
                mapping: 4_000,
                pack_plan: 5_000,
                pack_exec: 6_000,
                loose_scan: 0,
                scan: 8_000,
            },
            perf: crate::git_scan::GitPerfStats {
                pack_inflate_bytes: 2_000,
                pack_inflate_nanos: 4_000,
                delta_apply_bytes: 3_000,
                delta_apply_nanos: 6_000,
                scan_bytes: 4_000,
                scan_nanos: 8_000,
                mapping_calls: 5,
                mapping_nanos: 2_500,
                cache_hits: 0,
                cache_misses: 0,
                tree_load_calls: 0,
                tree_load_bytes: 0,
                tree_load_nanos: 0,
                tree_cache_hits: 0,
                tree_delta_cache_hits: 0,
                tree_delta_cache_misses: 0,
                tree_delta_cache_bytes: 0,
                tree_delta_cache_hit_nanos: 0,
                tree_delta_cache_miss_nanos: 0,
                tree_delta_chain_0: 0,
                tree_delta_chain_1: 0,
                tree_delta_chain_2_3: 0,
                tree_delta_chain_4_7: 0,
                tree_delta_chain_8_plus: 0,
                tree_spill_hits: 0,
                tree_object_loads: 0,
                tree_object_bytes: 0,
                tree_object_nanos: 0,
                tree_inflate_bytes: 0,
                tree_inflate_nanos: 0,
                tree_delta_apply_bytes: 0,
                tree_delta_apply_nanos: 0,
                tree_object_pack: 0,
                tree_object_loose: 0,
                scan_vs_prefilter_nanos: 0,
                scan_validate_nanos: 0,
                scan_transform_nanos: 0,
                scan_sort_dedup_nanos: 0,
                scan_reset_nanos: 0,
                scan_blob_count: 0,
                scan_chunk_count: 0,
                scan_zero_hit_chunks: 0,
                scan_findings_count: 0,
                scan_chunker_bypass_count: 0,
                scan_binary_skip_count: 0,
                scan_prefilter_bypass_count: 0,
            },
            tree_diff_bytes: 1_000,
            spill_runs: 2,
            spill_bytes: 4_096,
            alloc: GitScanAllocStats {
                pack_exec: AllocStatsDelta {
                    allocs: 3,
                    deallocs: 2,
                    reallocs: 1,
                    bytes_allocated: 4_096,
                    bytes_deallocated: 2_048,
                },
            },
        };

        let expected = "\
stage.tree_diff.nanos=2000
stage.commit_plan.nanos=1000
stage.blob_intro.nanos=0
stage.spill.nanos=3000
stage.pack_collect.nanos=0
stage.mapping.nanos=4000
stage.pack_plan.nanos=5000
stage.pack_exec.nanos=6000
stage.loose_scan.nanos=0
stage.scan.nanos=8000
tree_diff.bytes=1000
tree_diff.bytes_per_sec=500000000
tree_diff.ns_per_byte=2
tree_load.calls=0
tree_load.bytes=0
tree_load.nanos=0
tree_load.bytes_per_sec=0
tree_load.ns_per_byte=0
tree_cache.hits=0
tree_delta_cache.hits=0
tree_delta_cache.misses=0
tree_delta_cache.bytes=0
tree_delta_cache.hit_nanos=0
tree_delta_cache.miss_nanos=0
tree_delta_chain.0=0
tree_delta_chain.1=0
tree_delta_chain.2_3=0
tree_delta_chain.4_7=0
tree_delta_chain.8_plus=0
tree_spill.hits=0
tree_object.loads=0
tree_object.bytes=0
tree_object.nanos=0
tree_object.bytes_per_sec=0
tree_object.ns_per_byte=0
tree_object.pack=0
tree_object.loose=0
tree_inflate.bytes=0
tree_inflate.nanos=0
tree_inflate.bytes_per_sec=0
tree_inflate.ns_per_byte=0
tree_delta_apply.bytes=0
tree_delta_apply.nanos=0
tree_delta_apply.bytes_per_sec=0
tree_delta_apply.ns_per_byte=0
pack_inflate.bytes=2000
pack_inflate.nanos=4000
pack_inflate.bytes_per_sec=500000000
pack_inflate.ns_per_byte=2
pack_inflate.cycles_per_byte=0
delta_apply.bytes=3000
delta_apply.nanos=6000
delta_apply.bytes_per_sec=500000000
delta_apply.ns_per_byte=2
delta_apply.cycles_per_byte=0
scan.bytes=4000
scan.nanos=8000
scan.bytes_per_sec=500000000
scan.ns_per_byte=2
scan.cycles_per_byte=0
mapping.calls=5
mapping.nanos=2500
mapping.ns_per_call=500
spill.runs=2
spill.bytes=4096
alloc.pack_exec.allocs=3
alloc.pack_exec.bytes=4096
alloc.pack_exec.reallocs=1
alloc.pack_exec.deallocs=2
";

        assert_eq!(snapshot.format(), expected);
    }
}
