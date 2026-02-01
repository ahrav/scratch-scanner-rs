//! Deterministic simulation primitives used by the sim harnesses.
//!
//! Purpose:
//! - Provide a stable RNG, simulated time source, and bounded trace buffer.
//! - Keep replay inputs small and deterministic by avoiding OS time/scheduling.
//!
//! Invariants:
//! - `SimClock` is monotonic and advances only through explicit calls.
//! - `TraceRing` never exceeds its capacity and evicts oldest events first.
//! - `SimRng` is deterministic and remaps a zero seed to a non-zero state.
//!
//! This module is only available with the `sim-harness` feature.

pub mod clock;
pub mod rng;
pub mod trace;

pub use clock::SimClock;
pub use rng::SimRng;
pub use trace::{TraceEvent, TraceRing};
