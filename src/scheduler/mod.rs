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
//! ## Core Scheduling
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
//! ## Engine Abstraction
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`engine_trait`] | Trait definitions ([`ScanEngine`], [`EngineScratch`], [`FindingRecord`]) |
//! | [`engine_stub`] | Mock engine for testing scheduler in isolation |
//! | [`engine_impl`] | Bridges traits to real [`crate::engine::Engine`] |
//!
//! ## Supporting Primitives
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`count_budget`] | Integer-based permits (e.g., max concurrent fetches) |
//! | [`findings`] | Per-worker finding buffers with dedup via [`SecretHash`] |
//! | [`output_sink`] | Pluggable finding destinations (stdout, file, vec) |
//! | [`ts_buffer_pool`] | Thread-safe buffer recycling to avoid allocation churn |
//! | [`ts_chunk`] | Thread-safe chunk wrapper for cross-thread handoff |
//! | [`worker_id`] | Thread-local worker ID for metrics/debugging |
//!
//! ## I/O Backends
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`local`] | Low-level filesystem scanning with `std::fs` |
//! | [`parallel_scan`] | High-level directory scanning with gitignore support |
//! | [`local_fs_uring`] | Linux-only io_uring backend (feature `io-uring`) |
//! | [`remote`] | HTTP/object-store backend with retry policies |
//!
//! ## Observability
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`affinity`] | CPU pinning and topology queries |
//! | [`alloc`] | Allocation tracking via custom global allocator |
//! | [`bench`] | Micro-benchmark harness with warmup and statistics |
//! | [`rusage`] | Process resource usage (wall time, RSS, faults) |
//!
//! ## Testing Infrastructure
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`failure`] | Error classification (retryable vs permanent vs exhaustion) |
//! | [`sim`] | Deterministic simulation for property testing |
//! | [`task_graph`] | Object lifecycle FSM (enumerate → fetch → scan → done) |
//!
//! ## Benchmarks
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`bench_compare`] | A/B comparison between scheduler configurations |
//! | [`bench_executor`] | Executor-level benchmarks (steal overhead, spawn cost) |
//! | [`bench_local`] | Filesystem scan benchmarks |
//! | [`bench_synthetic`] | Synthetic workload generators |
//!
//! ## Resource Control
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`device_slots`] | Per-device I/O concurrency limits (SSD vs HDD vs network) |
//! | [`global_resource_pool`] | Centralized permits for "fat" jobs (large mmap, etc.) |
//! | [`yield_policy`] | Cooperative yield strategies to prevent starvation |
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
//!
//! # Feature Flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `io-uring` | Enables [`local_fs_uring`] for async filesystem I/O on Linux |
//!
//! # Re-exports
//!
//! The crate root re-exports commonly used types so users can write
//! `use scheduler::{Executor, ByteBudget, ...}` without navigating submodules.
//! Re-exports are grouped by layer:
//!
//! - **Core**: [`Executor`], [`ExecutorConfig`], [`WorkerCtx`], [`ByteBudget`],
//!   [`TokenBudget`], [`ChunkParams`], [`RunConfig`], [`Limits`]
//! - **Supporting**: [`CountBudget`], [`TsBufferPool`], [`OutputSink`] variants,
//!   [`WorkerFindingsBuffer`]
//! - **Local scanning**: [`scan_local`], [`LocalConfig`], [`scan_local_fs_uring`] (Linux)
//! - **Advanced**: [`affinity`] functions, [`failure`] types, [`sim`] harness

// Core scheduling
pub mod budget;
pub mod chunking;
pub mod contract;
pub mod executor;
pub mod metrics;
pub mod rng;

// Supporting primitives
pub mod count_budget;
pub mod engine_impl;
pub mod engine_stub;
pub mod engine_trait;
pub mod findings;
pub mod output_sink;
pub mod ts_buffer_pool;
pub mod ts_chunk;
pub mod worker_id;

// I/O backends
pub mod local;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod local_fs_uring;
pub mod parallel_scan;
pub mod remote;

// Observability
pub mod affinity;
pub mod alloc;
pub mod bench;
pub mod rusage;

// Testing infrastructure
pub mod failure;
pub mod sim;
pub mod task_graph;

// Benchmarks
pub mod bench_compare;
pub mod bench_executor;
pub mod bench_local;
pub mod bench_synthetic;

// Resource control
pub mod device_slots;
pub mod global_resource_pool;
pub mod yield_policy;

// ---------------------------------------------------------------------------
// Re-exports (see module docs for organization by layer)
// ---------------------------------------------------------------------------

// Core scheduling
pub use budget::{ByteBudget, BytePermit, TokenBudget, TokenPermit};
pub use chunking::{ChunkIter, ChunkMeta, ChunkParams};
pub use contract::{EngineContract, Limits, ObjectId, RunConfig, SourceId, ViewId};
pub use executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
pub use metrics::{Log2Hist, MetricsSnapshot, WorkerMetricsLocal};
pub use rng::XorShift64;

// Supporting primitives
pub use count_budget::{CountBudget, CountPermit};
pub use engine_impl::RealEngineScratch;
pub use engine_stub::{
    FileId, FindingRec, MockEngine, RuleId, ScanScratch, BUFFER_ALIGN, BUFFER_LEN_MAX,
};
pub use engine_trait::{EngineScratch, FindingRecord, ScanEngine};
pub use findings::{GlobalFindingsCollector, SecretHash, WorkerFindingsBuffer};
pub use output_sink::{FileSink, NullSink, OutputSink, StdoutSink, VecSink};
pub use ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
pub use ts_chunk::TsChunk;
pub use worker_id::{current_worker_id, set_current_worker_id};

// I/O backends
pub use local::{
    scan_local, FileSource, LocalConfig, LocalFile, LocalReport, LocalStats, VecFileSource,
};
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use local_fs_uring::{scan_local_fs_uring, LocalFsUringConfig, UringIoStats};
pub use parallel_scan::{parallel_scan_dir, ParallelScanConfig, ParallelScanReport};
pub use remote::{ErrorClass, RemoteBackend, RemoteConfig, RetryPolicy};

// Observability
pub use affinity::{
    allowed_cpus, first_allowed_cpu, num_cpus, pin_current_thread_to_core, try_pin_to_core,
    try_pin_to_first_allowed, CpuSet, CPU_SET_CAPACITY,
};
pub use alloc::{alloc_stats, AllocGuard, AllocStats, AllocStatsDelta, CountingAllocator};
pub use bench::{
    run_benchmark, BenchConfig, BenchIter, BenchIterMetrics, BenchReport, Benchmarkable, Stopwatch,
};
pub use rusage::{rusage_children, rusage_self, ProcUsage, ProcUsageDelta};

// Testing infrastructure
pub use failure::{
    ClassifyError, ExhaustionReason, FailureSummary, HttpStatusClassifier, IoErrorClassifier,
    ObjectOutcome, PartialResultsPolicy, PermanentReason, RetryBudget, RetryDecision,
    RetryableReason,
};
pub use sim::{
    replay_sim, run_sim, Action, BudgetEnforcement, ObjectSpec, SimConfig, SimError, SimReport,
    SimTrace,
};
pub use task_graph::{
    CursorState, EnumCursor, ObjectCtx, ObjectDescriptor, ObjectFrontier, ObjectPermit, ObjectRef,
    Task, TaskMetrics, ENUM_BATCH_SIZE, MAX_FETCH_SPAWNS_PER_ENUM,
};

// Resource control
pub use device_slots::{DeviceId, DeviceSlotPermit, DeviceSlots, DeviceSlotsConfig, IoModel};
pub use global_resource_pool::{
    FatJobPermit, FatJobRequest, GlobalResourcePool, GlobalResourcePoolConfig,
};
pub use yield_policy::{
    AdaptiveYield, AlwaysYield, BoxedYieldPolicy, EveryN, GitPhase, GitYieldPolicy, NeverYield,
    YieldPolicy,
};
