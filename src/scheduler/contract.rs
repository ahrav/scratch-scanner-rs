//! # Scheduler Contract (Phase 0)
//!
//! Run-scoped identifiers, engine contract, and scheduler limits.
//!
//! ## Non-negotiable invariants
//!
//! ### Work-conserving
//! - Backpressure delays work, never drops it.
//! - When limits prevent progress, the scheduler blocks or parks and resumes later.
//!
//! ### Exactly-once (within a run)
//! - Each object version is scanned exactly once within a run, unless explicitly
//!   configured otherwise.
//! - Retries are bounded and observable (attempt count, reason, backoff).
//!
//! ### Hard caps (tokens)
//! - in-flight objects
//! - in-flight reads
//! - buffered bytes (buffer pool / byte budget)
//! - queued tasks
//!
//! ### Budget invariance
//! - Per-object and per-chunk budgets must be enforced identically regardless
//!   of concurrency and completion order.
//!
//! ### Cancellation is leak-free
//! - Cancel is explicit and leak-free.
//! - Buffers and tokens are always returned exactly once, even on early exit paths.

/// Run-scoped source identifier.
///
/// Do not log raw paths/URLs/etc. IDs are monotonic within a run
/// if discovery order is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceId(pub u32);

/// Run-scoped object identifier.
///
/// Uniquely identifies an object within a scan run.
/// Do not log raw paths/URLs - use this ID for tracing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub source: SourceId,
    pub idx: u32,
}

/// View identity for bytes passed to the engine (raw vs decoded etc).
///
/// The scheduler doesn't interpret this; it just passes it through
/// so findings can be attributed to the correct transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ViewId(pub u16);

/// What the detection engine declares about chunking correctness.
///
/// This is intentionally phrased as "required overlap" to match the engine's
/// `required_overlap()` semantics, not as an interpretation of max span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineContract {
    /// Required overlap in bytes for overlap-only chunking correctness.
    ///
    /// - `Some(n)`: overlap-only scanning is safe if `prefix_len >= n` per chunk.
    /// - `None`: overlap-only scanning is not safe; streaming-state scanning required.
    pub required_overlap_bytes: Option<u32>,
}

impl EngineContract {
    /// Create a contract for an engine with bounded overlap requirement.
    pub const fn bounded(overlap_bytes: u32) -> Self {
        Self {
            required_overlap_bytes: Some(overlap_bytes),
        }
    }

    /// Create a contract for an engine that requires streaming state.
    pub const fn unbounded() -> Self {
        Self {
            required_overlap_bytes: None,
        }
    }

    /// Check if overlap-only chunking is safe with this contract.
    pub const fn overlap_only_safe(&self) -> bool {
        self.required_overlap_bytes.is_some()
    }
}

/// Scheduler limits. These become hard caps and tests.
///
/// All limits must be non-zero. Zero limits would mean no work can proceed.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max number of objects in flight (discovered but not fully processed).
    pub in_flight_objects: u32,
    /// Max concurrent reads/fetch operations.
    pub in_flight_reads: u32,
    /// Max bytes buffered across all in-flight chunks/buffers.
    pub buffered_bytes: u64,
    /// Max tasks buffered/queued (sum of injector + locals).
    pub queued_tasks: u32,
}

impl Limits {
    /// Validate that all limits are non-zero.
    ///
    /// # Panics
    /// Panics if any limit is zero.
    pub fn validate(&self) {
        assert!(self.in_flight_objects > 0, "in_flight_objects must be > 0");
        assert!(self.in_flight_reads > 0, "in_flight_reads must be > 0");
        assert!(self.buffered_bytes > 0, "buffered_bytes must be > 0");
        assert!(self.queued_tasks > 0, "queued_tasks must be > 0");
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            in_flight_objects: 1024,
            in_flight_reads: 256,
            buffered_bytes: 512 * 1024 * 1024, // 512 MiB
            queued_tasks: 65536,
        }
    }
}

/// Run configuration spine for determinism.
///
/// Scheduler policy will grow later, but seed and limits belong here from day 0.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunConfig {
    /// Seed for deterministic scheduling decisions.
    /// seed=0 is allowed; rng module will map it to a non-zero internal state.
    pub seed: u64,
    /// Resource limits for backpressure.
    pub limits: Limits,
}

impl RunConfig {
    /// Create a new run config with the given seed and default limits.
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            limits: Limits {
                in_flight_objects: 1024,
                in_flight_reads: 256,
                buffered_bytes: 512 * 1024 * 1024,
                queued_tasks: 65536,
            },
        }
    }

    /// Validate the configuration.
    ///
    /// # Panics
    /// Panics if limits are invalid.
    pub fn validate(&self) {
        self.limits.validate();
        // seed=0 is allowed; rng module will map it to a non-zero internal state.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_id_equality() {
        assert_eq!(SourceId(0), SourceId(0));
        assert_ne!(SourceId(0), SourceId(1));
    }

    #[test]
    fn object_id_equality() {
        let a = ObjectId {
            source: SourceId(0),
            idx: 42,
        };
        let b = ObjectId {
            source: SourceId(0),
            idx: 42,
        };
        let c = ObjectId {
            source: SourceId(1),
            idx: 42,
        };

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn engine_contract_bounded() {
        let contract = EngineContract::bounded(256);
        assert!(contract.overlap_only_safe());
        assert_eq!(contract.required_overlap_bytes, Some(256));
    }

    #[test]
    fn engine_contract_unbounded() {
        let contract = EngineContract::unbounded();
        assert!(!contract.overlap_only_safe());
        assert_eq!(contract.required_overlap_bytes, None);
    }

    #[test]
    fn limits_default_valid() {
        let limits = Limits::default();
        limits.validate(); // Should not panic
    }

    #[test]
    #[should_panic(expected = "in_flight_objects must be > 0")]
    fn limits_zero_objects_panics() {
        let limits = Limits {
            in_flight_objects: 0,
            ..Default::default()
        };
        limits.validate();
    }

    #[test]
    fn run_config_default_valid() {
        let config = RunConfig::default();
        config.validate(); // Should not panic
    }
}
