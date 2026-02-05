//! End-to-end Git scan runner.
//!
//! Orchestrates preflight, repo open, commit walk, tree diff, spill/dedupe,
//! pack planning, pack decode + scan, finalize, and persistence.
//!
//! # Pipeline
//! 1. Preflight repository metadata and artifact readiness.
//! 2. Open the repo (start set resolution, watermarks, and artifact status).
//! 3. Plan commits, diff trees, and collect candidate blobs.
//! 4. Spill/dedupe candidates and map them to pack entries.
//! 5. Plan packs, decode + scan, then finalize and optionally persist.
//!
//! # Invariants
//! - If preflight or repo open detects missing artifacts, the run returns
//!   `GitScanResult::NeedsMaintenance` and skips the scan pipeline.
//! - MIDX completeness is verified before pack execution.
//! - Pack cache sizing must fit in `u32` (checked before execution).
//!
//! # Notes
//! - Loose objects are decoded via `PackIo::load_loose_object`; failures are
//!   recorded as skipped candidates.
//! - Persistence is optional; callers can run the pipeline without a store.
//! - When artifacts are missing, the run short-circuits with `NeedsMaintenance`.

use std::fs;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use crate::scheduler::{alloc_stats, AllocStats, AllocStatsDelta};
use crate::Engine;

use super::blob_introducer::BlobIntroducer;
use super::byte_arena::ByteArena;
use super::commit_graph::CommitGraphIndex;
use super::commit_walk::{
    introduced_by_plan, CommitGraph, CommitGraphView, ParentScratch, PlannedCommit,
};
use super::commit_walk_limits::CommitWalkLimits;
use super::engine_adapter::{EngineAdapter, EngineAdapterConfig, ScannedBlobs};
use super::errors::{CommitPlanError, PersistError, RepoOpenError, SpillError, TreeDiffError};
use super::finalize::{build_finalize_ops, FinalizeInput, FinalizeOutput, RefEntry};
use super::limits::RepoOpenLimits;
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::{ObjectFormat, OidBytes};
use super::object_store::ObjectStore;
use super::oid_index::OidIndex;
use super::pack_cache::PackCache;
use super::pack_candidates::{CappedPackCandidateSink, LooseCandidate, PackCandidateCollector};
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{
    build_candidate_ranges, execute_pack_plan_with_scratch, execute_pack_plan_with_scratch_indices,
    merge_pack_exec_reports, PackExecError, PackExecReport, PackExecScratch, SkipReason,
    SkipRecord,
};
use super::pack_inflate::ObjectKind;
use super::pack_io::{PackIo, PackIoError, PackIoLimits};
use super::pack_plan::{
    bucket_pack_candidates, build_pack_plan_for_pack, build_pack_plans, PackPlanConfig,
    PackPlanError, PackView,
};
use super::pack_plan_model::{PackPlan, PackPlanStats};
use super::persist::{persist_finalize_output, PersistenceStore};
use super::policy_hash::MergeDiffMode;
use super::preflight::{preflight, PreflightReport};
use super::preflight_error::PreflightError;
use super::preflight_limits::PreflightLimits;
use super::repo::GitRepoPaths;
use super::repo_open::{repo_open, RefWatermarkStore, RepoJobState, StartSetResolver};
use super::seen_store::SeenBlobStore;
use super::spill_limits::SpillLimits;
use super::spiller::{SpillStats, Spiller};
use super::start_set::StartSetConfig;
use super::tree_candidate::CandidateSink;
use super::tree_diff::{TreeDiffStats, TreeDiffWalker};
use super::tree_diff_limits::TreeDiffLimits;

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

/// Heuristic bytes-per-candidate for path arena sizing in ODB-blob mode.
///
/// This is a safety cushion to keep path arenas from overflowing when
/// candidates greatly exceed default caps, while still bounding capacity
/// to `u32::MAX`.
const PATH_BYTES_PER_CANDIDATE_ESTIMATE: u64 = 64;
/// Denominator for pack cache sizing heuristic (total_bytes / denom).
const PACK_CACHE_FRACTION_DENOM: u64 = 64;
/// Upper bound for pack cache sizing in ODB-blob mode (2 GiB).
const PACK_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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

/// Candidate sink that forwards tree-diff output to the spill/dedupe stage.
struct SpillCandidateSink<'a> {
    spiller: &'a mut Spiller,
}

impl<'a> SpillCandidateSink<'a> {
    fn new(spiller: &'a mut Spiller) -> Self {
        Self { spiller }
    }
}

impl CandidateSink for SpillCandidateSink<'_> {
    fn emit(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: super::tree_candidate::ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        self.spiller
            .push(
                oid,
                path,
                commit_id,
                parent_idx,
                change_kind,
                ctx_flags,
                cand_flags,
            )
            .map_err(|err| TreeDiffError::CandidateSinkError {
                detail: err.to_string(),
            })
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
    /// Preflight limits and readiness thresholds.
    pub preflight: PreflightLimits,
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
    /// Default is tuned for throughput; override only with perf data.
    pub pack_exec_workers: usize,
    /// Optional spill directory override. When `None`, a unique temp directory is used.
    pub spill_dir: Option<PathBuf>,
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
            preflight: PreflightLimits::DEFAULT,
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
            pack_exec_workers: 24,
            spill_dir: None,
        }
    }
}

/// Git scan execution mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitScanMode {
    /// Current diff-history pipeline (tree diff + spill + mapping + pack plan).
    #[default]
    DiffHistory,
    /// ODB-blob fast path (first-introduced blob walk + pack-order scan).
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum GitScanResult {
    /// The repo is missing required maintenance artifacts (commit-graph, MIDX, etc.).
    NeedsMaintenance { preflight: PreflightReport },
    /// Scan completed; consult `finalize.outcome` and `skipped_candidates` for partial runs.
    Completed(GitScanReport),
}

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
    fn from_pack_skip(reason: &SkipReason) -> Self {
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

/// Git scan error taxonomy.
#[derive(Debug)]
pub enum GitScanError {
    Preflight(PreflightError),
    RepoOpen(RepoOpenError),
    CommitPlan(CommitPlanError),
    TreeDiff(TreeDiffError),
    Spill(SpillError),
    Midx(MidxError),
    PackPlan(PackPlanError),
    PackExec(PackExecError),
    PackIo(PackIoError),
    Persist(PersistError),
    Io(io::Error),
    /// Resource limit exceeded (pack mmap counts or bytes).
    ResourceLimit(String),
    /// Scan mode not yet implemented.
    UnsupportedMode(GitScanMode),
}

impl std::fmt::Display for GitScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preflight(err) => write!(f, "{err}"),
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
        }
    }
}

impl std::error::Error for GitScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(err) => Some(err),
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
            Self::ResourceLimit(_) => None,
            Self::UnsupportedMode(_) => None,
        }
    }
}

impl From<PreflightError> for GitScanError {
    fn from(err: PreflightError) -> Self {
        Self::Preflight(err)
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

/// Runs a full Git scan with the provided configuration and stores.
///
/// The pipeline short-circuits with `NeedsMaintenance` if preflight or repo
/// open indicates missing artifacts (MIDX, commit graph, etc.). On success,
/// the scan is finalized and optionally persisted.
///
/// # Inputs
/// - `repo_root` must reference a Git repository with readable metadata.
/// - `resolver` controls how the start set is chosen (default branch, refs, etc.).
/// - `seen_store` is used to dedupe candidates across runs.
/// - `watermark_store` records ref watermarks when finalize succeeds.
/// - `persist_store` is optional; when `None`, finalize output is returned only.
///
/// If no persistence store is provided, the caller is responsible for
/// interpreting `FinalizeOutcome` and storing watermarks as needed.
///
/// # Returns
/// - `NeedsMaintenance` when repo artifacts are missing or out of date.
/// - `Completed` with a `GitScanReport` when the scan finishes.
///
/// # Maintenance
/// Preflight pack-count recommendations are advisory only; the scan proceeds
/// as long as required artifacts are present.
///
/// # Errors
/// Pack mmap limits and cache sizing may surface as `GitScanError::ResourceLimit`.
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
    // Reset perf counters for a clean per-run snapshot.
    super::perf::reset();

    let mut stage_nanos = GitScanStageNanos::default();
    let mut alloc_deltas = GitScanAllocStats::default();

    // Preflight (metadata-only readiness). Pack count recommendations are advisory.
    let preflight = preflight(repo_root, config.preflight)?;
    if !preflight.status.is_ready() {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    let start_set_id = config.start_set.id();
    let repo = repo_open(
        repo_root,
        config.repo_id,
        config.policy_hash,
        start_set_id,
        resolver,
        watermark_store,
        config.repo_open,
    )?;
    if !repo.artifact_status.is_ready() {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    if config.scan_mode == GitScanMode::OdbBlobFast {
        // Commit walk plan.
        let cg = CommitGraphView::open_repo(&repo)?;
        let plan_start = Instant::now();
        let plan = introduced_by_plan(&repo, &cg, config.commit_walk)?;
        stage_nanos.commit_plan = plan_start.elapsed().as_nanos() as u64;
        let cg_index = CommitGraphIndex::build(&cg)?;

        // Shared spill directory for tree payloads and pack-exec large blobs.
        let spill_dir = match &config.spill_dir {
            Some(path) => path.clone(),
            None => make_spill_dir()?,
        };

        let midx = load_midx(&repo)?;
        let mut mapping_cfg = config.mapping;
        let packed_cap = mapping_cfg.max_packed_candidates.max(midx.object_count());
        mapping_cfg.max_packed_candidates = packed_cap;
        mapping_cfg.path_arena_capacity = estimate_path_arena_capacity(
            mapping_cfg.path_arena_capacity,
            mapping_cfg.max_packed_candidates,
            mapping_cfg.max_loose_candidates,
        );
        let oid_index = OidIndex::from_midx(&midx);
        let mut object_store = ObjectStore::open(&repo, &config.tree_diff, &spill_dir)?;

        let mut introducer = BlobIntroducer::new(
            &config.tree_diff,
            repo.object_format.oid_len(),
            midx.object_count(),
            config.path_policy_version,
            mapping_cfg.max_loose_candidates,
        );

        let intro_start = Instant::now();
        let (intro_stats, mut packed, loose, path_arena, spill_stats, mapping_stats) = {
            let mut collector = PackCandidateCollector::new(
                &midx,
                &oid_index,
                mapping_cfg.path_arena_capacity,
                mapping_cfg.max_packed_candidates,
                mapping_cfg.max_loose_candidates,
            );

            match introducer.introduce(
                &mut object_store,
                &cg_index,
                &plan,
                &oid_index,
                &mut collector,
            ) {
                Ok(stats) => {
                    stage_nanos.blob_intro = intro_start.elapsed().as_nanos() as u64;
                    let collect_start = Instant::now();
                    let (packed, loose, path_arena) = collector.finish();
                    stage_nanos.pack_collect = collect_start.elapsed().as_nanos() as u64;
                    let mapping_stats = MappingStats {
                        unique_blobs_in: packed.len().saturating_add(loose.len()) as u64,
                        packed_matched: packed.len() as u64,
                        loose_unmatched: loose.len() as u64,
                    };
                    (
                        stats,
                        packed,
                        loose,
                        path_arena,
                        SpillStats::default(),
                        mapping_stats,
                    )
                }
                Err(
                    TreeDiffError::CandidateLimitExceeded { .. } | TreeDiffError::PathArenaFull,
                ) => {
                    let first_elapsed = intro_start.elapsed().as_nanos() as u64;
                    introducer.reset_seen();

                    let retry_start = Instant::now();
                    let mut spiller =
                        Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
                    let mut sink = SpillCandidateSink::new(&mut spiller);
                    let stats = introducer.introduce(
                        &mut object_store,
                        &cg_index,
                        &plan,
                        &oid_index,
                        &mut sink,
                    )?;
                    let retry_elapsed = retry_start.elapsed().as_nanos() as u64;
                    stage_nanos.blob_intro = first_elapsed.saturating_add(retry_elapsed);

                    let spill_start = Instant::now();
                    let mut bridge = MappingBridge::new(
                        &midx,
                        CappedPackCandidateSink::new(
                            mapping_cfg.max_packed_candidates,
                            mapping_cfg.max_loose_candidates,
                        ),
                        mapping_cfg,
                    );
                    let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
                    stage_nanos.spill = spill_start.elapsed().as_nanos() as u64;
                    let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;
                    let packed = std::mem::take(&mut sink.packed);
                    let loose = std::mem::take(&mut sink.loose);
                    (
                        stats,
                        packed,
                        loose,
                        mapping_arena,
                        spill_stats,
                        mapping_stats,
                    )
                }
                Err(err) => return Err(err.into()),
            }
        };

        // Pack planning + execution.
        let pack_plan_start = Instant::now();
        let pack_dirs = collect_pack_dirs(&repo.paths);
        let pack_names = list_pack_files(&pack_dirs)?;
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
        let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
        let loose_dirs = collect_loose_dirs(&repo.paths);
        let mut used_pack_ids: Vec<u16> = packed.iter().map(|cand| cand.pack_id).collect();
        used_pack_ids.sort_unstable();
        used_pack_ids.dedup();
        let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
        let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

        let packed_len = packed.len();
        let loose_len = loose.len();
        let mut pack_plan_stats = Vec::with_capacity(used_pack_ids.len());
        let mut pack_plan_cfg = config.pack_plan;
        let mut pack_plan_delta_deps_total: u64 = 0;
        let mut pack_plan_delta_deps_max: u32 = 0;

        // Artifact fingerprints must remain stable; we check before planning and
        // again after exec because planning now overlaps execution.
        if !repo.artifacts_unchanged()? {
            return Ok(GitScanResult::NeedsMaintenance { preflight });
        }

        // Planning prelude remains serial; the plan builder runs on a worker
        // thread and is tracked separately for metrics.
        let pack_plan_prelude_nanos = pack_plan_start.elapsed().as_nanos() as u64;
        let pack_plan_thread_nanos = AtomicU64::new(0);

        // Execute pack plans + scan.
        let pack_exec_workers = config.pack_exec_workers.max(1);
        let pack_cache_target =
            estimate_pack_cache_bytes(config.pack_cache_bytes, &pack_mmaps, &used_pack_ids);
        let pack_cache_bytes: u32 = pack_cache_target
            .try_into()
            .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
        let mut pack_exec_reports = Vec::with_capacity(used_pack_ids.len());
        let mut skipped_candidates = Vec::new();

        let mut scanned = ScannedBlobs {
            blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
            finding_arena: Vec::new(),
        };

        let mut pack_exec_started = false;
        let mut pack_exec_start = Instant::now();
        let mut pack_exec_alloc_before = AllocStats::default();
        let mut start_pack_exec = || {
            if !pack_exec_started {
                pack_exec_started = true;
                pack_exec_start = Instant::now();
                pack_exec_alloc_before = alloc_stats();
            }
        };

        if packed_len > 0 {
            // Scale plan caps for large candidate sets in ODB-blob mode.
            let scaled = packed_len.saturating_mul(2);
            pack_plan_cfg.max_worklist_entries = pack_plan_cfg.max_worklist_entries.max(scaled);
            pack_plan_cfg.max_base_lookups = pack_plan_cfg.max_base_lookups.max(scaled);

            let (mut buckets, pack_ids) =
                bucket_pack_candidates(packed.drain(..), pack_views.len())?;
            // Stream per-pack plans to overlap planning with execution while
            // keeping deterministic pack order.
            let (tx, rx) = mpsc::sync_channel::<Result<PackPlan, PackPlanError>>(1);

            std::thread::scope(|scope| -> Result<(), GitScanError> {
                let pack_plan_thread_nanos = &pack_plan_thread_nanos;
                let pack_views = &pack_views;
                let midx = &midx;
                let pack_plan_cfg = pack_plan_cfg;

                scope.spawn(move || {
                    let plan_start = Instant::now();
                    let result = (|| -> Result<(), PackPlanError> {
                        for pack_id in pack_ids {
                            let pack_idx = pack_id as usize;
                            let pack = pack_views
                                .get(pack_idx)
                                .and_then(|pack| pack.as_ref())
                                .ok_or(PackPlanError::PackIdOutOfRange {
                                    pack_id,
                                    pack_count: pack_views.len(),
                                })?;
                            let pack_candidates = std::mem::take(&mut buckets[pack_idx]);

                            let plan = build_pack_plan_for_pack(
                                pack_id,
                                pack,
                                pack_candidates,
                                midx,
                                &pack_plan_cfg,
                            )?;
                            if tx.send(Ok(plan)).is_err() {
                                return Ok(());
                            }
                        }
                        Ok(())
                    })();

                    pack_plan_thread_nanos
                        .store(plan_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

                    if let Err(err) = result {
                        let _ = tx.send(Err(err));
                    }
                });

                if pack_exec_workers == 1 {
                    let mut cache = PackCache::new(pack_cache_bytes);
                    let mut external = PackIo::from_parts(
                        *midx,
                        pack_paths.clone(),
                        loose_dirs.clone(),
                        config.pack_io,
                    )
                    .map_err(GitScanError::PackIo)?;
                    let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                    adapter.reserve_results(packed_len.saturating_add(loose_len));
                    let mut exec_scratch = PackExecScratch::default();
                    for plan in rx {
                        let plan = plan?;
                        pack_plan_stats.push(plan.stats);
                        let deps_len = plan.delta_deps.len() as u32;
                        pack_plan_delta_deps_total =
                            pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                        pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);

                        start_pack_exec();

                        let pack_id = plan.pack_id as usize;
                        let pack_bytes = pack_mmaps
                            .get(pack_id)
                            .and_then(|mmap| mmap.as_ref())
                            .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                                pack_id: plan.pack_id,
                                pack_count: pack_mmaps.len(),
                            }))?
                            .as_ref();

                        let report = execute_pack_plan_with_scratch(
                            &plan,
                            pack_bytes,
                            &path_arena,
                            &config.pack_decode,
                            &mut cache,
                            &mut external,
                            &mut adapter,
                            &spill_dir,
                            &mut exec_scratch,
                        )?;
                        collect_skipped_candidates(&plan, &report.skips, &mut skipped_candidates);
                        pack_exec_reports.push(report);
                    }

                    if !loose.is_empty() {
                        start_pack_exec();
                        let loose_start = Instant::now();
                        scan_loose_candidates(
                            &loose,
                            &path_arena,
                            &mut adapter,
                            &mut external,
                            &mut skipped_candidates,
                        )?;
                        stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
                    }

                    scanned = adapter.take_results();
                } else {
                    for plan in rx {
                        let plan = plan?;
                        pack_plan_stats.push(plan.stats);
                        let deps_len = plan.delta_deps.len() as u32;
                        pack_plan_delta_deps_total =
                            pack_plan_delta_deps_total.saturating_add(deps_len as u64);
                        pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);

                        start_pack_exec();

                        let plan_ref = &plan;
                        let pack_id = plan_ref.pack_id as usize;
                        let pack_bytes = pack_mmaps
                            .get(pack_id)
                            .and_then(|mmap| mmap.as_ref())
                            .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                                pack_id: plan_ref.pack_id,
                                pack_count: pack_mmaps.len(),
                            }))?
                            .as_ref();

                        let exec_indices = build_exec_indices(plan_ref);
                        if exec_indices.is_empty() {
                            continue;
                        }

                        let mut candidate_ranges = Vec::new();
                        build_candidate_ranges(plan_ref, &mut candidate_ranges);

                        let ranges = shard_ranges(exec_indices.len(), pack_exec_workers);
                        let shard_outputs = std::thread::scope(
                            |scope| -> Result<
                                Vec<(usize, PackExecReport, ScannedBlobs)>,
                                PackExecError,
                            > {
                                let mut handles = Vec::with_capacity(ranges.len());
                                for (shard_idx, (start, end)) in ranges.iter().enumerate() {
                                    let exec_slice = &exec_indices[*start..*end];
                                    let candidate_ranges = &candidate_ranges;
                                    let pack_paths = pack_paths.clone();
                                    let loose_dirs = loose_dirs.clone();
                                    let pack_decode = config.pack_decode;
                                    let pack_io_limits = config.pack_io;
                                    let adapter_cfg = config.engine_adapter;
                                    let paths = &path_arena;
                                    let spill_dir = &spill_dir;

                                    handles.push(scope.spawn(move || {
                                        let mut cache = PackCache::new(pack_cache_bytes);
                                        let mut external = PackIo::from_parts(
                                            *midx,
                                            pack_paths,
                                            loose_dirs,
                                            pack_io_limits,
                                        )
                                        .map_err(|err| {
                                            PackExecError::ExternalBase(err.to_string())
                                        })?;
                                        let mut adapter = EngineAdapter::new(engine, adapter_cfg);
                                        let shard_candidates: usize = exec_slice
                                            .iter()
                                            .filter_map(|idx| {
                                                candidate_ranges[*idx].map(|(s, e)| e - s)
                                            })
                                            .sum();
                                        adapter.reserve_results(shard_candidates);
                                        let mut scratch = PackExecScratch::default();
                                        let report = execute_pack_plan_with_scratch_indices(
                                            plan_ref,
                                            pack_bytes,
                                            paths,
                                            &pack_decode,
                                            &mut cache,
                                            &mut external,
                                            &mut adapter,
                                            spill_dir,
                                            &mut scratch,
                                            exec_slice,
                                            candidate_ranges,
                                        )?;
                                        Ok::<_, PackExecError>((
                                            shard_idx,
                                            report,
                                            adapter.take_results(),
                                        ))
                                    }));
                                }

                                let mut outputs = Vec::with_capacity(handles.len());
                                for handle in handles {
                                    let joined =
                                        handle.join().expect("pack exec worker panicked")?;
                                    outputs.push(joined);
                                }
                                Ok(outputs)
                            },
                        )?;

                        let mut outputs: Vec<Option<(PackExecReport, ScannedBlobs)>> =
                            (0..ranges.len()).map(|_| None).collect();
                        for (shard_idx, report, scanned_shard) in shard_outputs {
                            outputs[shard_idx] = Some((report, scanned_shard));
                        }

                        let mut reports = Vec::with_capacity(outputs.len());
                        let mut scanned_shards = Vec::with_capacity(outputs.len());
                        for output in outputs.into_iter() {
                            let (report, scanned_shard) =
                                output.expect("missing pack exec shard output");
                            reports.push(report);
                            scanned_shards.push(scanned_shard);
                        }

                        let merged_report = merge_pack_exec_reports(reports);
                        collect_skipped_candidates(
                            plan_ref,
                            &merged_report.skips,
                            &mut skipped_candidates,
                        );
                        pack_exec_reports.push(merged_report);

                        let merged_scanned = merge_scanned_blobs(scanned_shards);
                        append_scanned_blobs(&mut scanned, merged_scanned);
                    }

                    if !loose.is_empty() {
                        start_pack_exec();
                        let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
                        adapter.reserve_results(loose.len());
                        let mut external = PackIo::from_parts(
                            *midx,
                            pack_paths.clone(),
                            loose_dirs.clone(),
                            config.pack_io,
                        )
                        .map_err(GitScanError::PackIo)?;
                        let loose_start = Instant::now();
                        scan_loose_candidates(
                            &loose,
                            &path_arena,
                            &mut adapter,
                            &mut external,
                            &mut skipped_candidates,
                        )?;
                        stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
                        append_scanned_blobs(&mut scanned, adapter.take_results());
                    }
                }

                Ok(())
            })?;
        } else if !loose.is_empty() {
            start_pack_exec();
            let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
            adapter.reserve_results(loose.len());
            let mut external =
                PackIo::from_parts(midx, pack_paths.clone(), loose_dirs.clone(), config.pack_io)
                    .map_err(GitScanError::PackIo)?;
            let loose_start = Instant::now();
            scan_loose_candidates(
                &loose,
                &path_arena,
                &mut adapter,
                &mut external,
                &mut skipped_candidates,
            )?;
            stage_nanos.loose_scan = loose_start.elapsed().as_nanos() as u64;
            append_scanned_blobs(&mut scanned, adapter.take_results());
        }

        stage_nanos.pack_plan =
            pack_plan_prelude_nanos.saturating_add(pack_plan_thread_nanos.load(Ordering::Relaxed));

        if pack_exec_started {
            stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
            let pack_exec_alloc_after = alloc_stats();
            alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);
        }

        if !repo.artifacts_unchanged()? {
            return Ok(GitScanResult::NeedsMaintenance { preflight });
        }

        let refs = build_ref_entries(&repo);
        let skipped_candidate_oids = skipped_candidates.iter().map(|entry| entry.oid).collect();

        let finalize = build_finalize_ops(FinalizeInput {
            repo_id: config.repo_id,
            policy_hash: config.policy_hash,
            start_set_id,
            refs,
            scanned_blobs: scanned.blobs,
            finding_arena: &scanned.finding_arena,
            skipped_candidate_oids,
            path_arena: &path_arena,
        });

        if let Some(store) = persist_store {
            persist_finalize_output(store, &finalize)?;
        }

        let perf_stats = super::perf::snapshot();
        stage_nanos.mapping = perf_stats.mapping_nanos;
        stage_nanos.scan = perf_stats.scan_nanos;

        return Ok(GitScanResult::Completed(GitScanReport {
            commit_count: plan.len(),
            tree_diff_stats: TreeDiffStats::from(intro_stats),
            spill_stats,
            mapping_stats,
            pack_plan_stats,
            pack_plan_config: pack_plan_cfg,
            pack_plan_delta_deps_total,
            pack_plan_delta_deps_max,
            pack_exec_reports,
            skipped_candidates,
            finalize,
            stage_nanos,
            perf_stats,
            alloc_stats: alloc_deltas,
        }));
    }

    // Commit walk plan.
    let cg = CommitGraphView::open_repo(&repo)?;
    let plan_start = Instant::now();
    let plan = introduced_by_plan(&repo, &cg, config.commit_walk)?;
    stage_nanos.commit_plan = plan_start.elapsed().as_nanos() as u64;

    // Spill + dedupe (stream candidates during tree diff).
    // Shared spill directory for tree payloads and pack-exec large blobs.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
    let mut object_store = ObjectStore::open(&repo, &config.tree_diff, &spill_dir)?;
    let mut walker = TreeDiffWalker::new(&config.tree_diff, repo.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    {
        let diff_start = Instant::now();
        let mut sink = SpillCandidateSink::new(&mut spiller);
        for PlannedCommit { pos, snapshot_root } in &plan {
            let commit_id = pos.0;
            let new_tree = cg.root_tree_oid(*pos)?;

            if *snapshot_root {
                walker.diff_trees(
                    &mut object_store,
                    &mut sink,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                )?;
                continue;
            }

            parent_scratch.clear();
            cg.collect_parents(
                *pos,
                config.commit_walk.max_parents_per_commit,
                &mut parent_scratch,
            )?;
            let parents = parent_scratch.as_slice();

            if parents.is_empty() {
                walker.diff_trees(
                    &mut object_store,
                    &mut sink,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                )?;
                continue;
            }

            match config.merge_diff_mode {
                MergeDiffMode::AllParents => {
                    for (idx, parent_pos) in parents.iter().enumerate() {
                        let old_tree = cg.root_tree_oid(*parent_pos)?;
                        walker.diff_trees(
                            &mut object_store,
                            &mut sink,
                            Some(&new_tree),
                            Some(&old_tree),
                            commit_id,
                            idx as u8,
                        )?;
                    }
                }
                MergeDiffMode::FirstParentOnly => {
                    let old_tree = cg.root_tree_oid(parents[0])?;
                    walker.diff_trees(
                        &mut object_store,
                        &mut sink,
                        Some(&new_tree),
                        Some(&old_tree),
                        commit_id,
                        0,
                    )?;
                }
            }
        }
        stage_nanos.tree_diff = diff_start.elapsed().as_nanos() as u64;
    }

    let spill_start = Instant::now();
    let midx = load_midx(&repo)?;
    let mut bridge = MappingBridge::new(
        &midx,
        CappedPackCandidateSink::new(
            config.mapping.max_packed_candidates,
            config.mapping.max_loose_candidates,
        ),
        config.mapping,
    );
    let spill_stats = spiller.finalize(seen_store, &mut bridge)?;
    stage_nanos.spill = spill_start.elapsed().as_nanos() as u64;
    let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;

    // Pack planning.
    let pack_plan_start = Instant::now();
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    let mut used_pack_ids: Vec<u16> = sink.packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    // Enforce pack mmap limits before decoding to cap address space usage.
    let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    let packed_len = sink.packed.len();
    let loose_len = sink.loose.len();
    if !sink.packed.is_empty() {
        let packed = std::mem::take(&mut sink.packed);
        let mut pack_plans = build_pack_plans(packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }
    let (pack_plan_delta_deps_total, pack_plan_delta_deps_max) = summarize_pack_plan_deps(&plans);
    stage_nanos.pack_plan = pack_plan_start.elapsed().as_nanos() as u64;

    // Validate artifacts before decoding packs to avoid scanning during maintenance.
    if !repo.artifacts_unchanged()? {
        return Ok(GitScanResult::NeedsMaintenance { preflight });
    }

    // Execute pack plans + scan.
    let pack_cache_bytes: u32 = config
        .pack_cache_bytes
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut cache = PackCache::new(pack_cache_bytes);
    let mut external = PackIo::open(&repo, config.pack_io)?;
    let mut adapter = EngineAdapter::new(engine, config.engine_adapter);
    adapter.reserve_results(packed_len.saturating_add(loose_len));
    let mut pack_exec_reports = Vec::with_capacity(plans.len());
    let mut skipped_candidates = Vec::new();

    let pack_exec_start = Instant::now();
    let pack_exec_alloc_before: AllocStats = alloc_stats();
    let mut exec_scratch = PackExecScratch::default();
    for plan in &plans {
        let pack_id = plan.pack_id as usize;
        let pack_bytes = pack_mmaps
            .get(pack_id)
            .and_then(|mmap| mmap.as_ref())
            .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                pack_id: plan.pack_id,
                pack_count: pack_mmaps.len(),
            }))?
            .as_ref();

        let report = execute_pack_plan_with_scratch(
            plan,
            pack_bytes,
            &mapping_arena,
            &config.pack_decode,
            &mut cache,
            &mut external,
            &mut adapter,
            &spill_dir,
            &mut exec_scratch,
        )?;
        collect_skipped_candidates(plan, &report.skips, &mut skipped_candidates);
        pack_exec_reports.push(report);
    }

    if !sink.loose.is_empty() {
        scan_loose_candidates(
            &sink.loose,
            &mapping_arena,
            &mut adapter,
            &mut external,
            &mut skipped_candidates,
        )?;
    }
    stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
    let pack_exec_alloc_after = alloc_stats();
    alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);

    let scanned = adapter.take_results();
    let path_arena = &mapping_arena;

    // Finalize ops.
    let refs = build_ref_entries(&repo);
    let skipped_candidate_oids = skipped_candidates.iter().map(|entry| entry.oid).collect();

    let finalize = build_finalize_ops(FinalizeInput {
        repo_id: config.repo_id,
        policy_hash: config.policy_hash,
        start_set_id,
        refs,
        scanned_blobs: scanned.blobs,
        finding_arena: &scanned.finding_arena,
        skipped_candidate_oids,
        path_arena,
    });

    if let Some(store) = persist_store {
        persist_finalize_output(store, &finalize)?;
    }

    let perf_stats = super::perf::snapshot();
    stage_nanos.mapping = perf_stats.mapping_nanos;
    stage_nanos.scan = perf_stats.scan_nanos;

    Ok(GitScanResult::Completed(GitScanReport {
        commit_count: plan.len(),
        tree_diff_stats: walker.stats().clone(),
        spill_stats,
        mapping_stats,
        pack_plan_stats,
        pack_plan_config: config.pack_plan,
        pack_plan_delta_deps_total,
        pack_plan_delta_deps_max,
        pack_exec_reports,
        skipped_candidates,
        finalize,
        stage_nanos,
        perf_stats,
        alloc_stats: alloc_deltas,
    }))
}

/// Create a unique spill directory under the OS temp directory.
///
/// The directory name is derived from the PID and a nanosecond timestamp.
fn make_spill_dir() -> Result<PathBuf, io::Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "git_scan_spill_{}_{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Estimate a path arena capacity based on candidate volume.
///
/// Uses a bytes-per-candidate heuristic and returns at least `base`,
/// clamped to `u32::MAX`.
fn estimate_path_arena_capacity(base: u32, packed: u32, loose: u32) -> u32 {
    let total = packed as u64 + loose as u64;
    let est = total
        .saturating_mul(PATH_BYTES_PER_CANDIDATE_ESTIMATE)
        .min(u32::MAX as u64) as u32;
    base.max(est)
}

/// Estimate a pack cache size from mapped pack bytes.
///
/// Uses a fixed fraction of total mapped pack size, clamped to the configured
/// minimum and an upper safety bound. Only packs referenced by `used_pack_ids`
/// contribute to the estimate.
fn estimate_pack_cache_bytes(
    base: usize,
    pack_mmaps: &[Option<Mmap>],
    used_pack_ids: &[u16],
) -> usize {
    let total_bytes: u64 = used_pack_ids
        .iter()
        .filter_map(|id| pack_mmaps.get(*id as usize).and_then(|m| m.as_ref()))
        .map(|m| m.len() as u64)
        .sum();

    if total_bytes == 0 {
        return base;
    }

    let target = total_bytes / PACK_CACHE_FRACTION_DENOM;
    let target = target.min(PACK_CACHE_MAX_BYTES).max(base as u64);
    target as usize
}

/// Load the MIDX view for the repository.
///
/// The parser uses the repo's object format to validate OID lengths.
///
/// # Errors
/// Returns `GitScanError::Midx` if the MIDX mmap is missing or corrupted.
fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_bytes = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx bytes missing")))?;
    Ok(MidxView::parse(midx_bytes.as_slice(), repo.object_format)?)
}

/// Convert the repo start set into finalize `RefEntry` values.
///
/// The ref names are taken from the repo's shared name table.
fn build_ref_entries(repo: &RepoJobState) -> Vec<RefEntry> {
    let mut refs = Vec::with_capacity(repo.start_set.len());
    for r in &repo.start_set {
        refs.push(RefEntry {
            ref_name: repo.ref_names.get(r.name).to_vec(),
            tip_oid: r.tip,
        });
    }
    refs
}

/// Collect pack directories, including alternates.
///
/// Alternates that resolve to the main objects dir are ignored.
/// The primary pack dir is returned first.
fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

/// Collect loose object directories, including alternates.
///
/// Alternates that resolve to the main objects dir are ignored.
/// The primary objects dir is returned first.
fn collect_loose_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.objects_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.clone());
    }
    dirs
}

/// List pack file names from the provided pack directories.
///
/// Returns raw file names (as bytes) for `.pack` files. Missing pack
/// directories are ignored; other IO errors are returned.
fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, GitScanError> {
    let mut names = Vec::new();
    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(GitScanError::Io(err)),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }
    Ok(names)
}

/// Resolve pack file paths referenced by the MIDX.
///
/// The MIDX stores pack basenames; we add the `.pack` suffix and search
/// each pack directory until a match is found. The first match wins, so
/// `pack_dirs` order is significant.
fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, GitScanError> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);
    for name in midx.pack_names() {
        let mut base = strip_pack_suffix(name);
        base.extend_from_slice(b".pack");
        let file_name = String::from_utf8_lossy(&base).into_owned();

        let mut found = None;
        for dir in pack_dirs {
            let candidate = dir.join(&file_name);
            if is_file(&candidate) {
                found = Some(candidate);
                break;
            }
        }
        match found {
            Some(path) => paths.push(path),
            None => {
                return Err(GitScanError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("pack file not found for {}", String::from_utf8_lossy(name)),
                )))
            }
        }
    }
    Ok(paths)
}

/// Strip a `.pack` or `.idx` suffix from a pack-related file name.
fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") {
        name[..name.len() - 5].to_vec()
    } else if name.ends_with(b".idx") {
        name[..name.len() - 4].to_vec()
    } else {
        name.to_vec()
    }
}

/// Memory-map pack files for zero-copy decoding.
///
/// The mappings are read-only and may outlive the file handles.
/// Returns `GitScanError::ResourceLimit` if pack counts or total bytes exceed
/// the configured mmap limits.
fn mmap_pack_files(
    pack_paths: &[PathBuf],
    used_pack_ids: &[u16],
    limits: PackMmapLimits,
) -> Result<Vec<Option<Mmap>>, GitScanError> {
    limits.validate();
    if used_pack_ids.len() > limits.max_open_packs as usize {
        return Err(GitScanError::ResourceLimit(format!(
            "pack count {} exceeds limit {}",
            used_pack_ids.len(),
            limits.max_open_packs
        )));
    }

    let mut out = Vec::with_capacity(pack_paths.len());
    out.resize_with(pack_paths.len(), || None);
    let mut total_bytes = 0_u64;
    for &pack_id in used_pack_ids {
        let idx = pack_id as usize;
        let path =
            pack_paths
                .get(idx)
                .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                    pack_id,
                    pack_count: pack_paths.len(),
                }))?;
        let metadata = fs::metadata(path)?;
        total_bytes = total_bytes.saturating_add(metadata.len());
        if total_bytes > limits.max_total_bytes {
            return Err(GitScanError::ResourceLimit(format!(
                "mapped pack bytes {} exceed limit {}",
                total_bytes, limits.max_total_bytes
            )));
        }
        let file = File::open(path)?;
        // SAFETY: mapping read-only pack files; the OS keeps the mapping valid
        // even after `file` is dropped.
        let mmap = unsafe { Mmap::map(&file)? };
        advise_sequential(&file, &mmap);
        out[idx] = Some(mmap);
    }
    Ok(out)
}

#[cfg(unix)]
fn advise_sequential(file: &File, reader: &Mmap) {
    unsafe {
        // SAFETY: The file descriptor and mmap are valid for the duration of
        // these advisory calls; failures are ignored because they are hints.
        #[cfg(target_os = "linux")]
        let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        #[cfg(not(target_os = "linux"))]
        let _ = file;
        let _ = libc::madvise(
            reader.as_ptr() as *mut libc::c_void,
            reader.len(),
            libc::MADV_SEQUENTIAL,
        );
    }
}

#[cfg(not(unix))]
fn advise_sequential(_file: &File, _reader: &Mmap) {}

/// Parse pack headers into `PackView`s used for planning.
///
/// Each pack view validates header structure and captures offsets needed by
/// the planning stage.
fn build_pack_views<'a>(
    pack_mmaps: &'a [Option<Mmap>],
    format: ObjectFormat,
) -> Result<Vec<Option<PackView<'a>>>, GitScanError> {
    let mut views = Vec::with_capacity(pack_mmaps.len());
    for mmap in pack_mmaps {
        if let Some(mmap) = mmap {
            let view = PackView::parse(mmap.as_ref(), format.oid_len())
                .map_err(|err| GitScanError::PackPlan(PackPlanError::PackParse(err)))?;
            views.push(Some(view));
        } else {
            views.push(None);
        }
    }
    Ok(views)
}

/// Returns total delta dependency count and the maximum deps in any plan.
fn summarize_pack_plan_deps(plans: &[PackPlan]) -> (u64, u32) {
    let mut total = 0u64;
    let mut max = 0u32;
    for plan in plans {
        let len = plan.delta_deps.len() as u32;
        total = total.saturating_add(len as u64);
        if len > max {
            max = len;
        }
    }
    (total, max)
}

/// Returns execution indices in deterministic order for a plan.
///
/// When `exec_order` is present, it is used to handle forward delta
/// dependencies. Otherwise the offsets are executed sequentially.
fn build_exec_indices(plan: &PackPlan) -> Vec<usize> {
    if let Some(order) = plan.exec_order.as_ref() {
        order.iter().map(|&idx| idx as usize).collect()
    } else {
        (0..plan.need_offsets.len()).collect()
    }
}

/// Splits a range into `shards` contiguous ranges covering `[0, len)`.
///
/// The first `len % shards` ranges receive one extra element.
fn shard_ranges(len: usize, shards: usize) -> Vec<(usize, usize)> {
    if len == 0 {
        return Vec::new();
    }
    let shards = shards.max(1).min(len);
    let base = len / shards;
    let extra = len % shards;
    let mut out = Vec::with_capacity(shards);
    let mut start = 0usize;
    for idx in 0..shards {
        let mut end = start + base;
        if idx < extra {
            end += 1;
        }
        out.push((start, end));
        start = end;
    }
    out
}

/// Merge per-shard results in shard order, rebasing finding spans.
///
/// Shards should already be ordered deterministically (for example by pack id).
fn merge_scanned_blobs(mut shards: Vec<ScannedBlobs>) -> ScannedBlobs {
    let total_blobs: usize = shards.iter().map(|s| s.blobs.len()).sum();
    let total_findings: usize = shards.iter().map(|s| s.finding_arena.len()).sum();

    let mut merged = ScannedBlobs {
        blobs: Vec::with_capacity(total_blobs),
        finding_arena: Vec::with_capacity(total_findings),
    };

    for shard in shards.drain(..) {
        let base = merged.finding_arena.len() as u32;
        merged.finding_arena.extend_from_slice(&shard.finding_arena);
        for mut blob in shard.blobs {
            blob.findings.start = blob.findings.start.saturating_add(base);
            merged.blobs.push(blob);
        }
    }

    merged
}

/// Append scanned blobs while rebasing finding spans.
fn append_scanned_blobs(dst: &mut ScannedBlobs, mut src: ScannedBlobs) {
    let base = dst.finding_arena.len() as u32;
    dst.finding_arena.extend_from_slice(&src.finding_arena);
    for mut blob in src.blobs.drain(..) {
        blob.findings.start = blob.findings.start.saturating_add(base);
        dst.blobs.push(blob);
    }
}

/// Load loose candidates and scan blob payloads.
///
/// Missing or undecodable loose objects are recorded as skips so the run can
/// complete with partial results. Paths are re-interned into the adapter's
/// arena via `emit_loose`.
///
/// Missing objects, decode errors, and non-blob kinds are recorded as skips.
/// Unexpected pack I/O errors are returned as fatal scan errors.
fn scan_loose_candidates(
    candidates: &[LooseCandidate],
    paths: &ByteArena,
    adapter: &mut EngineAdapter,
    pack_io: &mut PackIo<'_>,
    skipped: &mut Vec<SkippedCandidate>,
) -> Result<(), GitScanError> {
    for candidate in candidates {
        let path = paths.get(candidate.ctx.path_ref);
        match pack_io.load_loose_object(&candidate.oid) {
            Ok(Some((ObjectKind::Blob, bytes))) => {
                adapter.emit_loose(candidate, path, &bytes)?;
            }
            Ok(Some((_kind, _bytes))) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseNotBlob,
                });
            }
            Ok(None) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseMissing,
                });
            }
            Err(PackIoError::LooseObject { .. }) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseDecode,
                });
            }
            Err(err) => return Err(GitScanError::PackIo(err)),
        }
    }
    Ok(())
}

/// Collect candidates that were skipped during pack execution.
///
/// The skip records are offsets into the pack stream; we map them back to
/// candidate offsets and record the corresponding OIDs with a reason.
/// If multiple candidates share an offset, each one is recorded.
fn collect_skipped_candidates(
    plan: &PackPlan,
    skips: &[SkipRecord],
    out: &mut Vec<SkippedCandidate>,
) {
    if skips.is_empty() {
        return;
    }
    // `candidate_offsets` are sorted by pack offset, enabling binary partitioning.
    let offsets = &plan.candidate_offsets;
    for skip in skips {
        let reason = CandidateSkipReason::from_pack_skip(&skip.reason);
        let start = offsets.partition_point(|c| c.offset < skip.offset);
        let end = offsets.partition_point(|c| c.offset <= skip.offset);
        for cand in &offsets[start..end] {
            let idx = cand.cand_idx as usize;
            if let Some(entry) = plan.candidates.get(idx) {
                out.push(SkippedCandidate {
                    oid: entry.oid,
                    reason,
                });
            }
        }
    }
}

fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::{ByteRef, CandidateContext, ChangeKind};
    use crate::{
        demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId,
        TransformMode, ValidatorKind,
    };
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use regex::bytes::Regex;
    use std::io::Write;
    use tempfile::tempdir;

    /// Helper for constructing a minimal SHA-1 MIDX buffer.
    ///
    /// Only the chunks needed by `MidxView` lookups are populated.
    #[derive(Default)]
    struct MidxBuilder {
        pack_names: Vec<Vec<u8>>,
        objects: Vec<([u8; 20], u16, u64)>,
    }

    impl MidxBuilder {
        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn build(&self) -> Vec<u8> {
            const MIDX_MAGIC: [u8; 4] = *b"MIDX";
            const VERSION: u8 = 1;
            const HEADER_SIZE: usize = 12;
            const CHUNK_ENTRY_SIZE: usize = 12;
            const CHUNK_PNAM: [u8; 4] = *b"PNAM";
            const CHUNK_OIDF: [u8; 4] = *b"OIDF";
            const CHUNK_OIDL: [u8; 4] = *b"OIDL";
            const CHUNK_OOFF: [u8; 4] = *b"OOFF";

            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let pack_count = self.pack_names.len() as u32;

            let mut pnam = Vec::new();
            for name in &self.pack_names {
                pnam.extend_from_slice(name);
                pnam.push(0);
            }

            let mut oidf = vec![0u8; 256 * 4];
            let mut counts = [0u32; 256];
            for (oid, _, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            let mut oidl = Vec::with_capacity(objects.len() * 20);
            for (oid, _, _) in &objects {
                oidl.extend_from_slice(oid);
            }

            let mut ooff = Vec::with_capacity(objects.len() * 8);
            for (_, pack_id, offset) in &objects {
                ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
                ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
            }

            let chunk_count = 4u8;
            let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
            let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
            let oidf_off = pnam_off + pnam.len() as u64;
            let oidl_off = oidf_off + oidf.len() as u64;
            let ooff_off = oidl_off + oidl.len() as u64;
            let end_off = ooff_off + ooff.len() as u64;

            let mut out = Vec::new();
            out.extend_from_slice(&MIDX_MAGIC);
            out.push(VERSION);
            out.push(1); // SHA-1
            out.push(chunk_count);
            out.push(0); // base count
            out.extend_from_slice(&pack_count.to_be_bytes());

            let mut push_chunk = |id: [u8; 4], off: u64| {
                out.extend_from_slice(&id);
                out.extend_from_slice(&off.to_be_bytes());
            };

            push_chunk(CHUNK_PNAM, pnam_off);
            push_chunk(CHUNK_OIDF, oidf_off);
            push_chunk(CHUNK_OIDL, oidl_off);
            push_chunk(CHUNK_OOFF, ooff_off);
            push_chunk([0, 0, 0, 0], end_off);

            out.extend_from_slice(&pnam);
            out.extend_from_slice(&oidf);
            out.extend_from_slice(&oidl);
            out.extend_from_slice(&ooff);

            out
        }
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

    fn test_engine() -> Engine {
        let rule = RuleSpec {
            name: "tok",
            anchors: &[b"TOK_"],
            radius: 16,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            local_context: None,
            secret_group: Some(1),
            re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
        };

        let transforms = vec![TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 4,
            max_encoded_len: 1024,
            max_decoded_bytes: 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }];

        Engine::new_with_anchor_policy(
            vec![rule],
            transforms,
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        )
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn oid_to_hex(oid: &OidBytes) -> String {
        let mut out = String::with_capacity(oid.len() as usize * 2);
        for &b in oid.as_slice() {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }

    fn write_loose_blob(objects_dir: &Path, oid: OidBytes, payload: &[u8]) {
        let mut header = Vec::new();
        header.extend_from_slice(b"blob ");
        header.extend_from_slice(payload.len().to_string().as_bytes());
        header.push(0);
        header.extend_from_slice(payload);

        let compressed = compress(&header);
        let hex = oid_to_hex(&oid);
        let (dir, file) = hex.split_at(2);
        let dir_path = objects_dir.join(dir);
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join(file), &compressed).unwrap();
    }

    fn build_pack_io(objects_dir: &Path) -> PackIo<'static> {
        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-test");
        let midx_bytes = builder.build();
        // Leak the bytes for the duration of the test to satisfy `MidxView` lifetimes.
        let midx_bytes: &'static [u8] = Box::leak(midx_bytes.into_boxed_slice());
        let midx = MidxView::parse(midx_bytes, ObjectFormat::Sha1).unwrap();

        let pack_paths = vec![objects_dir.join("pack-test.pack")];
        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024), 2);
        PackIo::from_parts(midx, pack_paths, vec![objects_dir.to_path_buf()], limits).unwrap()
    }

    fn loose_candidate(path_ref: ByteRef, oid: OidBytes) -> LooseCandidate {
        LooseCandidate {
            oid,
            ctx: CandidateContext {
                commit_id: 1,
                parent_idx: 0,
                change_kind: ChangeKind::Add,
                ctx_flags: 0,
                cand_flags: 0,
                path_ref,
            },
        }
    }

    #[test]
    fn loose_blob_with_secret_is_scanned() {
        let engine = test_engine();
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");

        let oid = OidBytes::sha1([0xAB; 20]);
        write_loose_blob(&objects_dir, oid, b"hello TOK_ABCDEFGH");

        let mut pack_io = build_pack_io(&objects_dir);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        adapter.reserve_results(1);
        adapter.reserve_findings(4);
        adapter.reserve_findings_buf(4);

        let mut paths = ByteArena::with_capacity(64);
        let path_ref = paths.intern(b"src/lib.rs").unwrap();
        let candidate = loose_candidate(path_ref, oid);
        let mut skipped = Vec::new();

        scan_loose_candidates(
            &[candidate],
            &paths,
            &mut adapter,
            &mut pack_io,
            &mut skipped,
        )
        .unwrap();

        assert!(skipped.is_empty());
        let scanned = adapter.take_results();
        assert_eq!(scanned.blobs.len(), 1);
        assert!(!scanned.finding_arena.is_empty());
    }

    #[test]
    fn missing_loose_object_is_skipped() {
        let engine = test_engine();
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");

        let oid = OidBytes::sha1([0xCD; 20]);
        let mut pack_io = build_pack_io(&objects_dir);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        let mut paths = ByteArena::with_capacity(64);
        let path_ref = paths.intern(b"src/lib.rs").unwrap();
        let candidate = loose_candidate(path_ref, oid);
        let mut skipped = Vec::new();

        scan_loose_candidates(
            &[candidate],
            &paths,
            &mut adapter,
            &mut pack_io,
            &mut skipped,
        )
        .unwrap();

        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].oid, oid);
        assert_eq!(skipped[0].reason, CandidateSkipReason::LooseMissing);
        let scanned = adapter.take_results();
        assert!(scanned.blobs.is_empty());
    }
}
