//! Approximate membership filter for pack-linear candidate gating.
//!
//! This implementation uses XOR-family filters from the `xorf` crate.
//! We prefer `BinaryFuse8` for compactness and speed and fall back to
//! `Xor8` if Binary Fuse construction fails (usually only on duplicate
//! keys). The filter is built once per pack from candidate offsets and
//! guarantees **no false negatives** for inserted offsets.
//!
//! # Design
//! - Static filter built once per pack.
//! - Offsets are deduplicated before construction.
//! - Build failures fall back to `Xor8` to preserve availability.
//!
//! # Invariants
//! - `maybe_contains` returns `false` only when an offset was not inserted.
//! - Empty filters never report membership.

use xorf::{BinaryFuse8, Filter, Xor8};

/// Approximate membership filter for pack offsets.
#[derive(Clone, Debug)]
pub enum PackAmq {
    /// No entries; always returns false.
    Empty,
    /// Binary Fuse filter (preferred).
    BinaryFuse8(BinaryFuse8),
    /// XOR filter fallback when Binary Fuse construction fails.
    Xor8(Xor8),
}

impl PackAmq {
    /// Builds a filter from candidate offsets.
    #[must_use]
    pub fn build(offsets: &[u64]) -> Self {
        if offsets.is_empty() {
            return Self::Empty;
        }

        let mut keys = offsets.to_vec();
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return Self::Empty;
        }

        match BinaryFuse8::try_from(keys.as_slice()) {
            Ok(filter) => Self::BinaryFuse8(filter),
            Err(_) => {
                let filter = Xor8::from(keys.as_slice());
                Self::Xor8(filter)
            }
        }
    }

    /// Returns true if the offset may be present.
    ///
    /// False means the offset was definitely not inserted.
    #[must_use]
    pub fn maybe_contains(&self, offset: u64) -> bool {
        match self {
            Self::Empty => false,
            Self::BinaryFuse8(filter) => filter.contains(&offset),
            Self::Xor8(filter) => filter.contains(&offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_is_false() {
        let filter = PackAmq::build(&[]);
        assert!(!filter.maybe_contains(42));
    }

    #[test]
    fn filter_contains_inserted_offsets() {
        let offsets = vec![10, 20, 30, 40, 20];
        let filter = PackAmq::build(&offsets);
        for offset in offsets {
            assert!(filter.maybe_contains(offset));
        }
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "pack_amq_tests.rs"]
mod pack_amq_tests;
