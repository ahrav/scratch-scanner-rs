//! Scanner Scheduler: work-stealing runtime for secret scanning.
//!
//! # Overview
//!
//! This module provides the scheduling infrastructure for parallel secret scanning.
//! It manages work distribution across CPU cores, memory budgets, chunking of large
//! objects, and metrics collection—all while maintaining deterministic behavior
//! for reproducible scans.
//!
//! # Architecture
//!
//! ```text
//!                          ┌─────────────────────────────────────────────────────┐
//!                          │                   Scheduler                         │
//!                          │                                                     │
//!  ┌──────────────┐        │  ┌───────────┐    ┌───────────┐    ┌───────────┐   │
//!  │ I/O Backend  │───────►│  │  Injector │───►│  Worker 0 │◄──►│  Worker N │   │
//!  │ (discovery)  │        │  │  (global) │    │  (deque)  │    │  (deque)  │   │
//!  └──────────────┘        │  └───────────┘    └─────┬─────┘    └─────┬─────┘   │
//!        │                 │                         │                │         │
//!        │                 │                    steal│                │steal    │
//!        ▼                 │                         └────────────────┘         │
//!  ┌──────────────┐        │                                                    │
//!  │ ByteBudget   │◄───────│  Backpressure: budgets gate work admission         │
//!  │ TokenBudget  │        │                                                    │
//!  └──────────────┘        └─────────────────────────────────────────────────────┘
//! ```
//!
//! Two engines, one interface:
//! - **CPU engine**: work-stealing executor for compute-bound scanning
//! - **I/O engine**: backend-specific completion system for fetch (external)
//!
//! The scheduler bridges these via [`ExecutorHandle`], which I/O completion
//! handlers use to inject CPU work without knowing executor internals.
//!
//! # Module Organization
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`contract`] | Run-scoped IDs, engine contracts, limits, invariants |
//! | [`executor`] | Work-stealing thread pool with per-worker scratch space |
//! | [`budget`] | Lock-free byte/token budgets for backpressure |
//! | [`chunking`] | Chunk iteration and overlap-based deduplication |
//! | [`metrics`] | Per-worker metrics with cache-line isolation |
//! | [`rng`] | Deterministic RNG for reproducible steal patterns |
//!
//! # Non-Negotiable Invariants
//!
//! These invariants are documented in [`contract`] and enforced throughout:
//!
//! - **Work-conserving**: Backpressure delays work, never drops it.
//! - **Exactly-once**: Each object version scanned exactly once per run.
//! - **Hard caps**: Bounded in-flight objects, reads, bytes, and tasks.
//! - **Budget invariance**: Limits enforced identically regardless of timing.
//! - **Leak-free cancellation**: Buffers and tokens always returned on any exit path.
//!
//! # Determinism
//!
//! Given the same seed ([`RunConfig::seed`]) and input order, the scheduler
//! produces identical steal patterns and execution order on a single worker.
//! Multi-worker runs are deterministic in *work assignment* but not *timing*.
//!
//! This enables:
//! - Reproducible bug investigations
//! - Deterministic property tests
//! - Bisection of non-deterministic failures
//!
//! # Usage Example
//!
//! ```ignore
//! use scheduler::{Executor, ExecutorConfig, ChunkParams, ByteBudget};
//!
//! // Define your task type (prefer small, Copy types over Box<dyn FnOnce>)
//! #[derive(Clone, Copy)]
//! enum Task {
//!     ScanChunk { object_id: ObjectId, chunk_idx: u32 },
//!     Finalize { object_id: ObjectId },
//! }
//!
//! // Configure the executor
//! let config = ExecutorConfig {
//!     workers: 4,
//!     seed: 0xDEADBEEF,
//!     ..Default::default()
//! };
//!
//! // Create executor with per-worker scratch space
//! let executor = Executor::<Task>::new(
//!     config,
//!     |worker_id| ScannerScratch::new(), // scratch_init
//!     |task, ctx| match task {           // runner
//!         Task::ScanChunk { object_id, chunk_idx } => {
//!             // Use ctx.scratch for scanner buffers
//!             // Spawn follow-up work locally for cache locality
//!             ctx.spawn_local(Task::Finalize { object_id });
//!         }
//!         Task::Finalize { object_id } => {
//!             // Aggregate results
//!         }
//!     },
//! );
//!
//! // Inject initial work
//! executor.spawn_external(Task::ScanChunk { object_id, chunk_idx: 0 })?;
//!
//! // Wait for completion and get metrics
//! let metrics = executor.join();
//! println!("Scanned {} bytes at {:.2} GB/s", metrics.bytes_scanned, metrics.gb_per_sec());
//! ```
//!
//! # Performance Considerations
//!
//! - **Local-first spawning**: [`WorkerCtx::spawn_local`] keeps work on the same
//!   core, maximizing cache locality. Use [`WorkerCtx::spawn_global`] sparingly.
//!
//! - **Budget contention**: [`ByteBudget`] and [`TokenBudget`] use a single atomic.
//!   Under extreme contention, consider sharding (see budget module docs).
//!
//! - **Metrics overhead**: Per-worker metrics use plain integers (no atomics).
//!   Histograms are O(1) record. Aggregation happens only on `join()`.
//!
//! - **Chunk sizing**: Larger chunks reduce scheduling overhead but increase
//!   memory pressure. See [`ChunkParams`] for tuning guidance.
//!
//! # Safety
//!
//! Unsafe code is used sparingly and only where performance requires it:
//! - `metrics.rs`: bounds-check-free histogram recording (index proven in-range)
//!
//! All unsafe blocks have documented invariants and are tested.

pub mod budget;
pub mod chunking;
pub mod contract;
pub mod executor;
pub mod metrics;
pub mod rng;

// Re-exports for ergonomic API surface.
// Users can `use scheduler::*` to get the primary types without
// navigating submodule structure.

pub use budget::{ByteBudget, BytePermit, TokenBudget, TokenPermit};
pub use chunking::{ChunkIter, ChunkMeta, ChunkParams};
pub use contract::{EngineContract, Limits, ObjectId, RunConfig, SourceId, ViewId};
pub use executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
pub use metrics::{Log2Hist, MetricsSnapshot, WorkerMetricsLocal};
pub use rng::XorShift64;
