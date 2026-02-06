//! Source drivers for the unified scanner.
//!
//! Each source (filesystem, git) has its own driver module containing
//! the types and helpers needed for that scan mode.
//!
//! # Current Status
//!
//! Both source modes delegate to their existing execution backends:
//!
//! - **FS** — `parallel_scan_dir()` with an `EventSink` wired through
//!   `ParallelScanConfig`. Findings are emitted as structured JSONL.
//!
//! - **Git** — `run_git_scan()` with an `EventSink` threaded through
//!   to `EngineAdapter`. Findings stream during pack/loose scanning.
//!   Persistence metadata (`ScannedBlobs`) is still accumulated per-shard
//!   and merged during finalize, unchanged from the pre-unified path.

pub mod git;
