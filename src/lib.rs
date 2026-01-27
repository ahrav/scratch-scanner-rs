#![allow(dead_code, unused_imports, unused_variables, unused_assignments)]
//! High-throughput content scanner with bounded decoding and explicit provenance.
//!
//! The engine is optimized for scanning large byte streams using:
//! - Anchor-based windowing (Aho-Corasick) to limit regex work.
//! - Optional two-phase confirmation for noisy rules.
//! - Transform decoding (URL percent, Base64) with streaming gates and budgets.
//! - Base64 encoded-space pre-gate (YARA-style) to skip wasteful decodes.
//! - Fixed-capacity scratch buffers to avoid per-chunk allocation churn.
//!
//! High-level flow (single chunk):
//! 1) Anchor scan over raw + UTF-16 variants.
//! 2) Build and merge windows around anchors.
//! 3) Optional two-phase confirm, then expand to full windows.
//! 4) Regex validation inside windows.
//! 5) Optional transform decode with gating, bounded recursion, and dedupe.
//!
//! Pipeline flow (files):
//! Path -> Walker -> FileTable -> Reader -> Chunk -> Engine -> Findings -> Output.
//!
//! For a longer design walkthrough, see `docs/architecture.md`.

pub mod async_io;
pub mod b64_yara_gate;
pub mod pipeline;
pub mod pool;
pub mod regex2anchor;
pub mod scratch_memory;
pub mod stdx;
#[cfg(test)]
pub mod test_utils;
pub mod util;

mod api;
mod demo;
mod gitleaks_rules;
mod engine;
mod runtime;

#[cfg(feature = "b64-stats")]
pub use api::Base64DecodeStats;
pub use api::{
    AnchorPolicy, DecodeStep, DelimAfter, EntropySpec, FileId, Finding, FindingRec, Gate, RuleSpec,
    StepId, TailCharset, TransformConfig, TransformId, TransformMode, Tuning, TwoPhaseSpec,
    Utf16Endianness, ValidatorKind,
};

pub use demo::{demo_engine, demo_engine_with_anchor_mode, AnchorMode};

pub use engine::{AnchorPlanStats, Engine, ScanScratch};

pub use async_io::AsyncIoConfig;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use async_io::AsyncScanner;
#[cfg(target_os = "linux")]
pub use async_io::UringScanner;
#[cfg(target_os = "macos")]
pub use async_io::{DispatchScanner, MacosAioScanner};

pub use runtime::{
    read_file_chunks, BufferHandle, BufferPool, Chunk, FileTable, ScannerConfig, ScannerRuntime,
    BUFFER_ALIGN, BUFFER_LEN_MAX, FILE_FLAG_BINARY, FILE_FLAG_SKIPPED,
};
