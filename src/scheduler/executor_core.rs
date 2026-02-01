//! Executor core policy/state helpers shared by production and simulation.
//!
//! This module centralizes the combined state bitpacking and hot-path atomics
//! so the threaded executor and deterministic harness stay in lockstep.

use std::sync::atomic::{AtomicUsize, Ordering};

/// LSB in the combined state: 1 when accepting external spawns.
pub(crate) const ACCEPTING_BIT: usize = 1;
/// Count unit for the combined state (count stored in bits 1+).
pub(crate) const COUNT_UNIT: usize = 2;

/// Threshold for local spawns before waking a sibling.
///
/// # Problem: Work Hoarding
///
/// Without this heuristic, a worker that rapidly spawns local tasks might
/// accumulate thousands of tasks while siblings sleep. By the time siblings
/// wake (on next steal attempt), tail latency spikes.
///
/// # Solution: Wake-on-Hoard
///
/// After `N` consecutive local spawns, wake one sibling proactively.
/// This bounds the "hoarding window" to ~N tasks.
///
/// # Why 32?
///
/// | Threshold | Wakeup Rate | Overhead | Tail Latency |
/// |-----------|-------------|----------|--------------|
/// | 8 | High | ~12.5% of spawns trigger syscall | Low |
/// | 32 | Medium | ~3% of spawns trigger syscall | Medium |
/// | 128 | Low | ~0.8% of spawns trigger syscall | Higher |
///
/// 32 balances responsiveness with syscall overhead. For workloads with
/// very short tasks (<1µs), consider lowering. For long tasks (>100µs),
/// stealing latency is less critical.
///
/// # Tuning
///
/// Measure `steal_attempts` vs `steal_successes` in
/// [`super::metrics::MetricsSnapshot`].
/// If success rate is low and tail latency is high, lower this threshold.
pub(crate) const WAKE_ON_HOARD_THRESHOLD: u32 = 32;

/// Extract the in-flight count from the combined state word.
#[inline(always)]
pub(crate) fn in_flight(state: usize) -> usize {
    state >> 1
}

/// Check whether the executor is accepting external spawns.
#[inline(always)]
pub(crate) fn is_accepting(state: usize) -> bool {
    (state & ACCEPTING_BIT) != 0
}

/// Clear the accepting bit and return the previous state word.
#[inline(always)]
pub(crate) fn close_gate(state: &AtomicUsize) -> usize {
    state.fetch_and(!ACCEPTING_BIT, Ordering::AcqRel)
}

/// Increment the in-flight count in the combined state word.
#[inline(always)]
pub(crate) fn increment_count(state: &AtomicUsize) -> usize {
    state.fetch_add(COUNT_UNIT, Ordering::AcqRel)
}

/// Decrement the in-flight count in the combined state word.
#[inline(always)]
pub(crate) fn decrement_count(state: &AtomicUsize) -> usize {
    state.fetch_sub(COUNT_UNIT, Ordering::AcqRel)
}
