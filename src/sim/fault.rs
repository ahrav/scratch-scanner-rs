//! Deterministic fault plans and injection hooks for simulation.
//!
//! Faults are keyed by path bytes and per-operation index so the same scenario
//! and schedule seeds reproduce identical behavior.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Fault plan keyed by file path bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaultPlan {
    pub per_file: BTreeMap<Vec<u8>, FileFaultPlan>,
}

/// Fault plan for a single file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileFaultPlan {
    /// Optional fault on open.
    pub open: Option<IoFault>,
    /// Per-read fault plan, indexed by read count (0-based).
    pub reads: Vec<ReadFault>,
    /// Optional cancellation after N reads.
    pub cancel_after_reads: Option<u32>,
}

/// Fault configuration for an individual read operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadFault {
    pub fault: Option<IoFault>,
    pub latency_ticks: u64,
    pub corruption: Option<Corruption>,
}

/// I/O fault kinds understood by the simulation runner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IoFault {
    /// Map to a stable `io::ErrorKind` in the runner.
    ErrKind { kind: u16 },
    /// Return at most `max_len` bytes for the read.
    PartialRead { max_len: u32 },
    /// Emulate a single EINTR-style interruption.
    EIntrOnce,
}

/// Optional data corruption applied to read results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Corruption {
    TruncateTo { new_len: u32 },
    FlipBit { offset: u32, mask: u8 },
    Overwrite { offset: u32, bytes: Vec<u8> },
}

/// Runtime fault injector that tracks per-file read indices.
#[derive(Clone, Debug)]
pub struct FaultInjector {
    plan: FaultPlan,
    read_idx: BTreeMap<Vec<u8>, u32>,
}

impl FaultInjector {
    /// Create a new injector from a deterministic fault plan.
    pub fn new(plan: FaultPlan) -> Self {
        Self {
            plan,
            read_idx: BTreeMap::new(),
        }
    }

    /// Retrieve the open fault for a path, if any.
    pub fn on_open(&mut self, path: &[u8]) -> Option<IoFault> {
        self.plan.per_file.get(path).and_then(|p| p.open.clone())
    }

    /// Retrieve the next read fault for a path.
    pub fn on_read(&mut self, path: &[u8]) -> ReadFault {
        let idx = self.read_idx.entry(path.to_vec()).or_insert(0);
        let i = *idx as usize;
        *idx = idx.saturating_add(1);

        self.plan
            .per_file
            .get(path)
            .and_then(|p| p.reads.get(i).cloned())
            .unwrap_or(ReadFault {
                fault: None,
                latency_ticks: 0,
                corruption: None,
            })
    }

    /// Return whether the file should be cancelled after `reads_done` reads.
    pub fn should_cancel(&self, path: &[u8], reads_done: u32) -> bool {
        self.plan
            .per_file
            .get(path)
            .and_then(|p| p.cancel_after_reads)
            .map(|n| reads_done >= n)
            .unwrap_or(false)
    }
}
