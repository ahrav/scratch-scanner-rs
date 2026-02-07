#![allow(dead_code)] // Public API surface is intentionally broader than internal use.
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
//! - `AsyncScanner` and platform scanners: async file scanning (platform-gated).
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
pub mod async_io;
pub mod b64_yara_gate;
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
#[cfg(test)]
pub mod test_utils;
#[cfg(any(test, feature = "tiger-harness"))]
pub mod tiger_harness;
pub mod unified;

mod api;
mod demo;
mod engine;
mod gitleaks_rules;
mod perf_stats;
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
    AnchorPolicy, DecodeStep, DecodeSteps, DelimAfter, EntropySpec, FileId, Finding, FindingRec,
    Gate, LocalContextSpec, RuleSpec, StepId, TailCharset, TransformConfig, TransformId,
    TransformMode, Tuning, TwoPhaseSpec, Utf16Endianness, ValidatorKind,
    LOCAL_CONTEXT_MAX_LOOKAROUND, MAX_DECODE_STEPS,
};

pub use demo::{
    demo_engine, demo_engine_with_anchor_mode,
    demo_engine_with_anchor_mode_and_max_transform_depth, demo_engine_with_anchor_mode_and_tuning,
    demo_rules, demo_transforms, demo_tuning, AnchorMode,
};

/// Returns the built-in gitleaks rule set (bench feature only).
#[cfg(feature = "bench")]
pub fn gitleaks_rules() -> Vec<RuleSpec> {
    crate::gitleaks_rules::gitleaks_rules()
}

#[cfg(feature = "tiger-harness")]
pub use engine::fuzz_try_load;
#[cfg(feature = "bench")]
pub use engine::{bench_find_spans_into, bench_stream_decode_base64, bench_stream_decode_url};
#[cfg(feature = "stats")]
pub use engine::{AnchorPlanStats, VectorscanStats};
pub use engine::{Engine, NormHash, ScanScratch};

pub use async_io::AsyncIoConfig;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use async_io::AsyncScanner;
#[cfg(target_os = "linux")]
pub use async_io::UringScanner;
#[cfg(target_os = "macos")]
pub use async_io::{AioScanner, MacosAioScanner};

pub use runtime::{
    read_file_chunks, BufferHandle, BufferPool, Chunk, FileTable, ScannerConfig, ScannerRuntime,
    BUFFER_ALIGN, BUFFER_LEN_MAX, FILE_FLAG_BINARY, FILE_FLAG_SKIPPED,
};
