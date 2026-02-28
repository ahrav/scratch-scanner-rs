//! High-throughput content scanner with bounded decoding and explicit provenance.
//!
//! ## Scope
//! This crate scans byte streams for secret-like patterns using anchor-first rules
//! (anchor + regex) and optional transform decoding (for example URL percent and Base64).
//!
//! ## Key invariants
//! - Work is bounded by explicit budgets: window sizes, transform depth, decoded bytes,
//!   and work item counts.
//! - Expensive regex validation only runs inside windows seeded by anchor hits.
//! - Decoding is gated by anchors in decoded output to avoid wasteful full decodes.
//! - Scratch buffers are fixed-capacity and reused to avoid per-chunk allocation churn.
//!
//! ## Engine flow (single chunk)
//! 1) Anchor scan over raw bytes (optional UTF-16 variants).
//! 2) Build and coalesce windows around anchor hits.
//! 3) Optional two-phase confirm, then expand to full windows.
//! 4) Regex validation inside windows.
//! 5) Optional transform decoding with streaming scan, bounded recursion, and dedupe.
//!
//! ## Pipeline flow (files)
//! `Path -> Walker -> FileTable -> Reader -> Chunk -> Engine -> Findings -> Output`
//!
//! ## Notable entry points
//! - `Engine` / `ScanScratch`: low-level chunk scanning.
//! - `ScannerRuntime` / `ScannerConfig`: staged pipeline for file scanning.
//! - `RuleSpec`, `TwoPhaseSpec`, `TransformConfig`: rule and transform definitions.
//! - `FindingRec` (hot-path) and `Finding` (materialized output).
//! - `git_scan`: Git repository scanning pipeline with persistence support.
//!
//! ## Design trade-offs
//! Anchors reduce regex cost at the expense of requiring rules to supply
//! representative anchor strings. Two-phase rules trade an extra confirm
//! step for reduced false positives on noisy patterns.
//!
//! For a longer design walkthrough, see `docs/architecture.md`.

pub mod archive;
pub mod b64_yara_gate;
pub mod content_policy;
pub mod git_scan;
pub mod lsm;
pub mod pipeline;
pub mod pool;
pub mod regex2anchor;
pub mod scheduler;
pub mod scratch_memory;
#[cfg(feature = "sim-harness")]
pub mod sim;
#[cfg(feature = "sim-harness")]
pub mod sim_archive;
#[cfg(feature = "sim-harness")]
pub mod sim_git_scan;
#[cfg(feature = "sim-harness")]
pub mod sim_scanner;
#[cfg(feature = "sim-harness")]
pub mod sim_scheduler;
pub mod stdx;
pub mod store;
#[cfg(test)]
pub mod test_utils;
#[cfg(any(test, feature = "tiger-harness"))]
pub mod tiger_harness;
pub mod unified;

mod api;
mod demo;
mod engine;
mod perf_stats;
mod rules;
mod runtime;

// Guard: stat instrumentation features carry non-trivial overhead and must
// never ship in release binaries.  The `perf_stats` module compiles its
// helpers to no-ops when the gate is off, but the structs themselves still
// occupy memory; this fence catches accidental feature-flag leaks in CI.
#[cfg(all(
    not(debug_assertions),
    any(
        feature = "perf-stats",
        feature = "stats",
        feature = "b64-stats",
        feature = "git-perf"
    )
))]
compile_error!(
    "perf/stat instrumentation features are debug-only; disable them for release builds"
);

#[cfg(feature = "b64-stats")]
pub use api::Base64DecodeStats;
pub use api::{
    AnchorPolicy, CharClassSpec, DecodeStep, DecodeSteps, DelimAfter, EntropySpec, FileId, Finding,
    FindingRec, Gate, LocalContextSpec, OfflineValidationSpec, OfflineVerdict, RuleSpec, StepId,
    TailCharset, TransformConfig, TransformId, TransformMode, Tuning, TwoPhaseSpec,
    Utf16Endianness, ValidatorKind, LOCAL_CONTEXT_MAX_LOOKAROUND, MAX_DECODE_STEPS,
};

pub use demo::{
    demo_engine, demo_engine_with_anchor_mode,
    demo_engine_with_anchor_mode_and_max_transform_depth, demo_engine_with_anchor_mode_and_tuning,
    demo_rules, demo_transforms, demo_tuning, AnchorMode,
};

#[cfg(feature = "tiger-harness")]
pub use engine::fuzz_try_load;
#[cfg(feature = "bench")]
pub use engine::BenchHitAccPool;
#[cfg(feature = "tiger-harness")]
pub use engine::FuzzHitAccPool;
#[cfg(feature = "bench")]
pub use engine::{
    bench_build_entropy_state, bench_build_merge_ranges_state, bench_build_utf16_decode_state,
    bench_classify_window, bench_contains_all_memmem, bench_contains_any_memmem,
    bench_decode_utf16be, bench_decode_utf16be_with_state, bench_decode_utf16le,
    bench_decode_utf16le_with_state, bench_entropy_gate_passes,
    bench_entropy_gate_passes_with_state, bench_extract_secret_span_locs, bench_find_spans_into,
    bench_hash128, bench_map_utf16_decoded_offset, bench_merge_ranges, bench_merge_ranges_load,
    bench_merge_ranges_run, bench_offline_validate_aws_access_key,
    bench_offline_validate_pypi_token, bench_offline_validate_sentry_org_token,
    bench_offline_validate_slack_token, bench_pack_patterns_raw, bench_shannon_entropy,
    bench_shannon_entropy_with_state, bench_stream_decode_base64, bench_stream_decode_url,
    BenchEntropyState, BenchMergeRangesState, BenchPackedPatterns, BenchUtf16DecodeState,
};
#[cfg(feature = "tiger-harness")]
pub use engine::{fuzz_classify_window, fuzz_offline_validate};
#[cfg(feature = "stats")]
pub use engine::{AnchorPlanStats, VectorscanStats};
pub use engine::{Engine, NormHash, ScanScratch};

#[cfg(feature = "bench")]
pub use git_scan::{
    bench_apply_locality_shard_cap, bench_select_strategy, bench_synthetic_locality_plan,
    bench_synthetic_plan,
};

#[cfg(all(feature = "bench", feature = "connector-pipeline"))]
pub use scheduler::bench_connector::{bench_track_page_items, BenchBarrier, BenchToken};

pub use runtime::{
    read_file_chunks, BufferHandle, BufferPool, Chunk, FileTable, ScannerConfig, ScannerRuntime,
    BUFFER_ALIGN, BUFFER_LEN_MAX, FILE_FLAG_BINARY, FILE_FLAG_SKIPPED,
};
