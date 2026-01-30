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
//!
//! ## Design trade-offs
//! Anchors reduce regex cost at the expense of requiring rules to supply
//! representative anchor strings. Two-phase rules trade an extra confirm
//! step for reduced false positives on noisy patterns.
//!
//! For a longer design walkthrough, see `docs/architecture.md`.

pub mod async_io;
pub mod b64_yara_gate;
pub mod lsm;
pub mod pipeline;
pub mod pool;
pub mod regex2anchor;
pub mod scratch_memory;
pub mod stdx;
#[cfg(test)]
pub mod test_utils;
#[cfg(any(test, feature = "tiger-harness"))]
pub mod tiger_harness;
pub mod util;

mod api;
mod demo;
mod engine;
mod gitleaks_rules;
mod runtime;

#[cfg(feature = "b64-stats")]
pub use api::Base64DecodeStats;
pub use api::{
    AnchorPolicy, DecodeStep, DecodeSteps, DelimAfter, EntropySpec, FileId, Finding, FindingRec,
    Gate, RuleSpec, StepId, TailCharset, TransformConfig, TransformId, TransformMode, Tuning,
    TwoPhaseSpec, Utf16Endianness, ValidatorKind, MAX_DECODE_STEPS,
};

pub use demo::{
    demo_engine, demo_engine_with_anchor_mode,
    demo_engine_with_anchor_mode_and_max_transform_depth, demo_engine_with_anchor_mode_and_tuning,
    demo_tuning, AnchorMode,
};

#[cfg(feature = "bench")]
pub use engine::{bench_find_spans_into, bench_stream_decode_base64, bench_stream_decode_url};
#[cfg(feature = "bench")]
pub use engine::{
    bench_is_word_byte, bench_tail_matches_charset, bench_validate_aws_access_key,
    bench_validate_prefix_bounded, bench_validate_prefix_fixed,
};
#[cfg(feature = "stats")]
pub use engine::{AnchorPlanStats, VectorscanStats};
pub use engine::{Engine, ScanScratch};

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
