//! Fault plan schema for Git simulation.
//!
//! The fault plan is keyed by logical resources (commit-graph, MIDX, pack IDs,
//! persistence) rather than filesystem paths. This keeps fault injection
//! deterministic even when repository layouts vary.
//!
//! Invariants and expectations:
//! - Resource identifiers should be stable across runs and schema versions.
//! - Read faults are consumed in read-index order; missing entries imply no fault.
//! - Corruption applies only to bytes returned by a read (if any).

use serde::{Deserialize, Serialize};

/// Logical resource identifiers for Git fault injection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GitResourceId {
    /// Commit-graph file (if present).
    CommitGraph,
    /// Multi-pack-index file (if present).
    Midx,
    /// Pack file identified by logical pack id.
    Pack { pack_id: u16 },
    /// Persistence store (watermarks/seen store).
    Persist,
    /// Catch-all for non-core resources (keep names stable for replay).
    Other(String),
}

/// I/O fault variants for Git simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitIoFault {
    /// Return an I/O error by kind (mirrors `std::io::ErrorKind` mapping).
    ErrKind { kind: u8 },
    /// Return at most `max_len` bytes (short read).
    PartialRead { max_len: u32 },
    /// Single EINTR-style interruption (subsequent reads proceed normally).
    EIntrOnce,
}

/// Data corruption variants for Git simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitCorruption {
    /// Truncate the returned data to `new_len` bytes.
    TruncateTo { new_len: u32 },
    /// Flip bits at a specific offset.
    FlipBit { offset: u32, mask: u8 },
    /// Overwrite bytes starting at `offset`.
    Overwrite { offset: u32, bytes: Vec<u8> },
}

/// Fault injection for a single read step.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitReadFault {
    /// Optional I/O fault.
    pub fault: Option<GitIoFault>,
    /// Simulated latency ticks before completion.
    pub latency_ticks: u64,
    /// Optional data corruption.
    pub corruption: Option<GitCorruption>,
}

/// Faults for a specific resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitResourceFaults {
    /// Target logical resource.
    pub resource: GitResourceId,
    /// Faults to apply in read index order.
    pub reads: Vec<GitReadFault>,
}

/// Top-level fault plan for Git simulation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitFaultPlan {
    /// Resource-specific fault sequences.
    pub resources: Vec<GitResourceFaults>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_plan_round_trip() {
        let plan = GitFaultPlan {
            resources: vec![GitResourceFaults {
                resource: GitResourceId::Pack { pack_id: 2 },
                reads: vec![GitReadFault {
                    fault: Some(GitIoFault::PartialRead { max_len: 16 }),
                    latency_ticks: 1,
                    corruption: Some(GitCorruption::TruncateTo { new_len: 8 }),
                }],
            }],
        };
        let json = serde_json::to_string(&plan).expect("serialize plan");
        let decoded: GitFaultPlan = serde_json::from_str(&json).expect("deserialize plan");
        assert_eq!(decoded.resources.len(), 1);
    }
}
