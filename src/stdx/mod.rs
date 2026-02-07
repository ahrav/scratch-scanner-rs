#![allow(dead_code)]
//! Small, self-contained data structures used across the project.
//!
//! # Scope
//! `stdx` hosts narrow, allocation-light utilities that back the scanner
//! pipeline. They are tuned for predictable memory use and fast paths rather
//! than general-purpose ergonomics.
//!
//! # Design themes
//! - Fixed or upfront capacity; many operations panic or error on overflow.
//! - Tight invariants enable `unsafe` fast paths (documented per type).
//! - Deterministic iteration/reset behavior for reuse in hot loops.
//!
//! # Module map
//! - `atomic_bitset`: lock-free bitset with atomic test-and-set for concurrent dedup.
//! - `atomic_seen_sets`: composite concurrent dedup tracker wrapping three `AtomicBitSet`s.
//! - `bitset`: fixed-size and dynamic bitsets with word-level operations.
//! - `byte_ring`: internal byte ring keyed by absolute stream offsets.
//! - `fixed_set`: fixed-capacity hash set with epoch-based O(1) reset.
//! - `fixed_vec`: stack-allocated vector with constant capacity.
//! - `released_set`: fixed-capacity hash set with O(1) pop and fast clear.
//! - `ring_buffer`: stack-allocated ring buffer with power-of-two capacity.
//! - `timing_wheel`: hashed timing wheel with FIFO per bucket and bitmap occupancy.
//!
//! # Safety
//! Several types use `unsafe` internally and rely on invariants called out in
//! their module docs. Read those before extending or reusing the internals.

pub mod atomic_bitset;
pub mod atomic_seen_sets;
pub mod bitset;
pub mod byte_ring;
pub mod fastrange;
pub mod fixed_set;
pub mod fixed_vec;
pub mod released_set;
pub mod ring_buffer;
pub mod spsc;
pub mod timing_wheel;

pub use atomic_bitset::AtomicBitSet;
pub use atomic_seen_sets::AtomicSeenSets;
pub use bitset::{words_for_bits, DynamicBitSet, DynamicBitSetIterator};
pub(crate) use byte_ring::ByteRing;
pub use fixed_set::FixedSet128;
pub use fixed_vec::FixedVec;
pub use released_set::ReleasedSet;
pub use ring_buffer::RingBuffer;
pub use spsc::{spsc_channel, OwnedSpscConsumer, OwnedSpscProducer};
pub use timing_wheel::{Bitset2, PushError, PushOutcome, TimingWheel};
