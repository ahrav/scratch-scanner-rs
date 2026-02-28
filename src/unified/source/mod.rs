//! Source drivers for the unified scanner.
//!
//! Each source (filesystem, git) has its own driver module containing
//! the types and helpers needed for that scan mode.
//!
//! # Current Status
//!
//! Source wiring is centralized in [`factory`](self::factory):
//!
//! - **FS** — connector-backed execution via unified source factory.
//!
//! - **Git** — `run_git_scan()` with an `EventSink` threaded through
//!   to `EngineAdapter`. Findings stream during pack/loose scanning.
//!   Persistence metadata (`ScannedBlobs`) is still accumulated per-shard
//!   and merged during finalize, unchanged from the pre-unified path.

#[cfg(feature = "connector-pipeline")]
pub mod factory;
pub mod git;
