//! Scanner Scheduler: work-stealing runtime for secret scanning
//!
//! # Architecture
//!
//! Two engines, one interface:
//! - **CPU engine**: work-stealing executor for compute-bound scanning
//! - **I/O engine**: backend-specific completion system for fetch
//!
//! # Phase 0 Deliverables
//!
//! This module establishes the measurement model and non-negotiable invariants
//! before any scheduler logic is written.

// Unsafe is used sparingly and only where performance requires it:
// - metrics.rs: bounds-check-free histogram recording
// All unsafe blocks have documented invariants and are tested.

pub mod budget;
pub mod chunking;
pub mod contract;
pub mod executor;
pub mod metrics;
pub mod rng;

// Re-exports for primary types
pub use budget::{ByteBudget, BytePermit, TokenBudget, TokenPermit};
pub use chunking::{ChunkIter, ChunkMeta, ChunkParams};
pub use contract::{EngineContract, Limits, ObjectId, RunConfig, SourceId, ViewId};
pub use executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
pub use metrics::{Log2Hist, MetricsSnapshot, WorkerMetricsLocal};
pub use rng::XorShift64;
