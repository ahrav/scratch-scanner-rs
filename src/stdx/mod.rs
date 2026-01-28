#![allow(dead_code)]
//! Small, self-contained data structures used across the project.

pub mod bitset;
pub mod fixed_set;
pub mod fixed_vec;
pub mod queue;
pub mod released_set;
pub mod ring_buffer;

pub use bitset::{words_for_bits, BitSet, BitSetIterator, DynamicBitSet, DynamicBitSetIterator};
pub use fixed_set::FixedSet128;
pub use fixed_vec::FixedVec;
pub use queue::{Queue, QueueLink, QueueNode};
pub use released_set::ReleasedSet;
pub use ring_buffer::RingBuffer;
