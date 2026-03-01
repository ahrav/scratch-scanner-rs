//! Source drivers for the unified scanner.
//!
//! Each source (filesystem, git) has its own driver module containing
//! the types and helpers needed for that scan mode.
//!
//! # Architecture
//!
//! Source wiring is centralized in [`factory`](self::factory):
//!
//! - **FS** — [`factory::build_connector`] constructs a connector instance
//!   that the scheduler drives through enumerate → dispatch → scan phases.
//!
//! - **Git** — `run_git_scan()` with an `EventSink` threaded through
//!   to `EngineAdapter`. Findings stream during pack/loose scanning.
//!   Persistence metadata (`ScannedBlobs`) is accumulated per-shard
//!   and merged during finalize.

#[cfg(feature = "connector-pipeline")]
pub mod factory;
pub mod git;
