//! Allocation-free set-associative cache for `secret_hash(norm_hash)`.
//!
//! # Problem
//!
//! Each finding in a batch requires a keyed BLAKE3 hash of the normalised
//! secret (`secret_hash`). When the same secret appears multiple times in a
//! single file — common for leaked API keys or repeated passwords — recomputing
//! the hash is pure waste on the hot encoding path.
//!
//! # Design
//!
//! A two-level lookup avoids the hash on repeat hits:
//!
//! 1. **Last-value fast path** — a single `(key, value)` pair that catches
//!    immediate temporal locality (consecutive findings with the same secret).
//! 2. **Set-associative table** — 32 sets × 2 ways = 64 entries, indexed by a
//!    MurmurHash3-style mix of the 32-byte `norm_hash`. Handles the case where
//!    a file contains a few distinct secrets interleaved across findings.
//!
//! Replacement within a set is round-robin (clock hand per set).
//!
//! # Layout
//!
//! Entries use Array-of-Structs layout so that key and value share a single
//! 64-byte cache line (`CacheEntry`). Validity and replacement state are
//! packed into scalar bitsets (`u64` and `u32`) to eliminate per-slot memory
//! indirections on the L2 lookup path.
//!
//! Total footprint: ~4.1 KiB — fits comfortably in L1 cache.
//! No heap allocations occur after construction.

use crate::store::identity::secret_hash;
use crate::store::keys::StoreKeys;

/// Number of sets in the associative table. Must be a power of two so the
/// set-index mask (`& (SETS - 1)`) works correctly.
const SECRET_HASH_CACHE_SETS: usize = 32;

/// Associativity (ways per set). 2-way keeps the linear scan per-set trivial
/// while still tolerating one collision per set.
const SECRET_HASH_CACHE_WAYS: usize = 2;

/// Total slot count: sets × ways.
const SECRET_HASH_CACHE_ENTRIES: usize = SECRET_HASH_CACHE_SETS * SECRET_HASH_CACHE_WAYS;

/// A single cache entry pairing a 32-byte key with its 32-byte hashed value.
///
/// `#[repr(C)]` guarantees `key` is at offset 0 and `value` at offset 32,
/// making the pair exactly 64 bytes — one hardware cache line. When the CPU
/// fetches the key for comparison, the value is already resident.
#[repr(C)]
#[derive(Clone, Copy)]
struct CacheEntry {
    key: [u8; 32],
    value: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<CacheEntry>() == 64);

impl CacheEntry {
    const ZERO: Self = Self {
        key: [0; 32],
        value: [0; 32],
    };
}

/// Per-batch, stack-local cache that memoises `secret_hash(norm_hash)` calls.
///
/// Constructed once per [`super::writer::AppendLogStoreProducer::build_finding_frame`]
/// invocation and discarded when the batch is fully encoded.
pub struct SecretHashCache {
    // ── fast path (level 1) ──────────────────────────────────────────
    /// Whether `last_key` / `last_value` hold a valid entry.
    last_valid: bool,
    last_key: [u8; 32],
    last_value: [u8; 32],

    // ── set-associative table (level 2) ──────────────────────────────
    /// Per-set round-robin replacement pointer. Bit `i` encodes which way
    /// (0 or 1) to evict next in set `i`.
    next_way: u32,
    /// Validity bitset — bit `i` set means `entries[i]` holds a valid mapping.
    valid: u64,
    /// Interleaved key/value entries. Each entry is exactly one cache line.
    entries: [CacheEntry; SECRET_HASH_CACHE_ENTRIES],
}

impl SecretHashCache {
    /// Create an empty cache with all slots invalid.
    #[inline]
    pub fn new() -> Self {
        Self {
            last_valid: false,
            last_key: [0; 32],
            last_value: [0; 32],
            next_way: 0,
            valid: 0,
            entries: [CacheEntry::ZERO; SECRET_HASH_CACHE_ENTRIES],
        }
    }

    /// Return the cached `secret_hash` for `norm_hash`, computing it on a miss.
    ///
    /// Lookup order: last-value fast path → set-associative table → compute.
    /// On any hit or fresh computation the result is promoted to the
    /// last-value slot so the next call with the same key is O(1).
    #[inline(always)]
    pub fn get_or_compute(&mut self, norm_hash: &[u8; 32], keys: &StoreKeys) -> [u8; 32] {
        // Level 1: last-value fast path.
        if self.last_valid && self.last_key == *norm_hash {
            return self.last_value;
        }

        // Level 2: set-associative lookup.
        let set = Self::set_index(norm_hash);
        let base = set * SECRET_HASH_CACHE_WAYS;
        for way in 0..SECRET_HASH_CACHE_WAYS {
            let idx = base + way;
            if (self.valid >> idx) & 1 != 0 && self.entries[idx].key == *norm_hash {
                let value = self.entries[idx].value;
                self.last_valid = true;
                self.last_key = *norm_hash;
                self.last_value = value;
                return value;
            }
        }

        // Miss: compute and insert into both levels.
        let value = secret_hash(norm_hash, keys);
        let way = ((self.next_way >> set) & 1) as usize;
        let idx = base + way;
        self.valid |= 1u64 << idx;
        self.entries[idx] = CacheEntry {
            key: *norm_hash,
            value,
        };
        self.next_way ^= 1u32 << set;
        self.last_valid = true;
        self.last_key = *norm_hash;
        self.last_value = value;
        value
    }

    /// Map a 32-byte `norm_hash` to a set index in `0..SECRET_HASH_CACHE_SETS`.
    ///
    /// Reads all four 64-bit lanes of the hash, XORs them with distinct
    /// rotations to break positional symmetry, then applies a MurmurHash3
    /// fmix64-inspired finalizer to spread the entropy across the low bits
    /// before masking to the set count.
    #[inline(always)]
    fn set_index(norm_hash: &[u8; 32]) -> usize {
        debug_assert!(SECRET_HASH_CACHE_SETS.is_power_of_two());
        let (a, rest) = norm_hash.split_first_chunk::<8>().unwrap();
        let (b, rest) = rest.split_first_chunk::<8>().unwrap();
        let (c, rest) = rest.split_first_chunk::<8>().unwrap();
        let (d, _) = rest.split_first_chunk::<8>().unwrap();
        let h0 = u64::from_le_bytes(*a);
        let h1 = u64::from_le_bytes(*b);
        let h2 = u64::from_le_bytes(*c);
        let h3 = u64::from_le_bytes(*d);
        let mut h = h0 ^ h1.rotate_left(17) ^ h2.rotate_left(31) ^ h3.rotate_left(47);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        (h as usize) & (SECRET_HASH_CACHE_SETS - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::identity::secret_hash;
    use crate::store::keys::{
        CorrelationMode, KeySource, RunModeMetadata, StoreKeys, STORE_KEYS_VERSION,
    };

    fn test_keys() -> StoreKeys {
        StoreKeys::from_test_root_key(
            [0x5A; 32],
            RunModeMetadata {
                version: STORE_KEYS_VERSION,
                correlation_mode: CorrelationMode::Persistent,
                key_source: KeySource::EnvVar,
            },
        )
    }

    /// Oracle: compute the expected value directly (no cache).
    fn oracle(norm_hash: &[u8; 32], keys: &StoreKeys) -> [u8; 32] {
        secret_hash(norm_hash, keys)
    }

    // ── 1. Smoke test ────────────────────────────────────────────────

    #[test]
    fn new_cache_returns_computed_value() {
        let keys = test_keys();
        let h = [0xAA; 32];
        let mut cache = SecretHashCache::new();
        let result = cache.get_or_compute(&h, &keys);
        assert_eq!(result, oracle(&h, &keys));
    }

    // ── 2. set_index bounded ─────────────────────────────────────────

    #[test]
    fn set_index_bounded_for_known_inputs() {
        let cases: &[[u8; 32]] = &[
            [0u8; 32],
            [0xFF; 32],
            [0x42; 32],
            [0x01; 32],
            {
                let mut h = [0u8; 32];
                h[0] = 1;
                h
            },
            {
                let mut h = [0u8; 32];
                h[31] = 1;
                h
            },
        ];
        for h in cases {
            let idx = SecretHashCache::set_index(h);
            assert!(
                idx < SECRET_HASH_CACHE_SETS,
                "set_index({:02X?}) = {idx}, expected < {SECRET_HASH_CACHE_SETS}",
                &h[..4]
            );
        }
    }

    // ── 3. Consecutive same key → L1 hit ─────────────────────────────

    #[test]
    fn consecutive_same_key_hits_level1() {
        let keys = test_keys();
        let h = [0xBB; 32];
        let expected = oracle(&h, &keys);
        let mut cache = SecretHashCache::new();

        let first = cache.get_or_compute(&h, &keys);
        assert_eq!(first, expected);

        // Second call: should hit L1 fast path.
        let second = cache.get_or_compute(&h, &keys);
        assert_eq!(second, expected);
    }

    // ── 4. Different key evicts L1 ───────────────────────────────────

    #[test]
    fn different_key_evicts_level1() {
        let keys = test_keys();
        let h1 = [0x01; 32];
        let h2 = [0x02; 32];
        let mut cache = SecretHashCache::new();

        let r1a = cache.get_or_compute(&h1, &keys);
        assert_eq!(r1a, oracle(&h1, &keys));

        // h2 evicts h1 from L1.
        let r2 = cache.get_or_compute(&h2, &keys);
        assert_eq!(r2, oracle(&h2, &keys));

        // h1 again — should still return correct value (from L2 or recompute).
        let r1b = cache.get_or_compute(&h1, &keys);
        assert_eq!(r1b, oracle(&h1, &keys));
    }

    // ── 5. L2 hit promotes to L1 ─────────────────────────────────────

    #[test]
    fn level2_hit_promotes_to_level1() {
        let keys = test_keys();
        let h1 = [0x10; 32];
        let h2 = [0x20; 32];
        let mut cache = SecretHashCache::new();

        // Insert h1 into L2.
        cache.get_or_compute(&h1, &keys);
        // Evict h1 from L1 by inserting h2.
        cache.get_or_compute(&h2, &keys);

        // h1 again — L2 hit, promoted to L1.
        let r1 = cache.get_or_compute(&h1, &keys);
        assert_eq!(r1, oracle(&h1, &keys));

        // h1 once more — should now be L1 hit.
        let r1_again = cache.get_or_compute(&h1, &keys);
        assert_eq!(r1_again, oracle(&h1, &keys));
    }

    // ── 6. Many distinct keys all correct ────────────────────────────

    #[test]
    fn many_distinct_keys_correct() {
        let keys = test_keys();
        let mut cache = SecretHashCache::new();

        for i in 0u8..128 {
            let h = [i; 32];
            let result = cache.get_or_compute(&h, &keys);
            assert_eq!(result, oracle(&h, &keys), "mismatch for key [{i}; 32]");
        }
    }

    // ── 7. Round-robin replacement in set ────────────────────────────

    #[test]
    fn round_robin_replacement_in_set() {
        let keys = test_keys();

        // Build a map of set → colliding hashes, then pick any set with 3+.
        let mut by_set: [Vec<[u8; 32]>; SECRET_HASH_CACHE_SETS] =
            std::array::from_fn(|_| Vec::new());
        for i in 0u16..512 {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = (i >> 8) as u8;
            let set = SecretHashCache::set_index(&h);
            if by_set[set].len() < 3 {
                by_set[set].push(h);
            }
        }
        let colliders = by_set
            .iter()
            .find(|v| v.len() >= 3)
            .expect("512 inputs across 32 sets must produce at least one set with 3+ colliders");

        let mut cache = SecretHashCache::new();
        let (h0, h1, h2) = (colliders[0], colliders[1], colliders[2]);

        // Insert h0 into way 0, h1 into way 1.
        cache.get_or_compute(&h0, &keys);
        cache.get_or_compute(&h1, &keys);

        // h2 should evict h0 (round-robin wraps back to way 0).
        cache.get_or_compute(&h2, &keys);

        // All three must still return the correct oracle value.
        assert_eq!(cache.get_or_compute(&h0, &keys), oracle(&h0, &keys));
        assert_eq!(cache.get_or_compute(&h1, &keys), oracle(&h1, &keys));
        assert_eq!(cache.get_or_compute(&h2, &keys), oracle(&h2, &keys));
    }

    // ── 8. Interleaved access pattern ────────────────────────────────

    #[test]
    fn interleaved_access_pattern() {
        let keys = test_keys();
        let mut cache = SecretHashCache::new();

        // 5 distinct secrets repeated in clusters (mimics build_finding_frame).
        let secrets: [[u8; 32]; 5] = [[0x10; 32], [0x20; 32], [0x30; 32], [0x40; 32], [0x50; 32]];
        let pattern = [0, 0, 0, 1, 1, 2, 2, 2, 0, 3, 3, 4, 4, 4, 1, 0, 2, 3, 4, 0];

        for &idx in &pattern {
            let h = &secrets[idx];
            let result = cache.get_or_compute(h, &keys);
            assert_eq!(result, oracle(h, &keys), "mismatch at secret index {idx}");
        }
    }

    // ── 9. Zero and max hash edge cases ──────────────────────────────

    #[test]
    fn zero_and_max_hash_edge_cases() {
        let keys = test_keys();
        let mut cache = SecretHashCache::new();

        let zero = [0u8; 32];
        let max = [0xFF; 32];

        assert_eq!(cache.get_or_compute(&zero, &keys), oracle(&zero, &keys));
        assert_eq!(cache.get_or_compute(&max, &keys), oracle(&max, &keys));

        // Re-access both to exercise L2 → L1 promotion after eviction.
        assert_eq!(cache.get_or_compute(&zero, &keys), oracle(&zero, &keys));
        assert_eq!(cache.get_or_compute(&max, &keys), oracle(&max, &keys));
    }

    // ── Structural invariant ─────────────────────────────────────────

    #[test]
    fn cache_entry_is_one_cache_line() {
        assert_eq!(core::mem::size_of::<CacheEntry>(), 64);
    }

    // ================================================================
    // Property-based tests
    // ================================================================

    mod prop {
        use super::*;
        use proptest::collection::vec;
        use proptest::prelude::*;

        proptest! {
            // ── P1. Oracle correctness ───────────────────────────────
            #[test]
            fn prop_oracle_correctness(
                sequence in vec(proptest::array::uniform32(any::<u8>()), 1..200)
            ) {
                let keys = test_keys();
                let mut cache = SecretHashCache::new();
                for h in &sequence {
                    let cached = cache.get_or_compute(h, &keys);
                    let expected = oracle(h, &keys);
                    prop_assert_eq!(cached, expected);
                }
            }

            // ── P2. set_index always bounded ─────────────────────────
            #[test]
            fn prop_set_index_bounded(
                h in proptest::array::uniform32(any::<u8>())
            ) {
                let idx = SecretHashCache::set_index(&h);
                prop_assert!(idx < SECRET_HASH_CACHE_SETS);
            }

            // ── P3. Determinism: two caches, same sequence ───────────
            #[test]
            fn prop_determinism(
                sequence in vec(proptest::array::uniform32(any::<u8>()), 1..100)
            ) {
                let keys = test_keys();
                let mut cache_a = SecretHashCache::new();
                let mut cache_b = SecretHashCache::new();
                for h in &sequence {
                    let a = cache_a.get_or_compute(h, &keys);
                    let b = cache_b.get_or_compute(h, &keys);
                    prop_assert_eq!(a, b);
                }
            }

            // ── P4. Idempotence: repeated calls, same result ─────────
            #[test]
            fn prop_idempotence(
                h in proptest::array::uniform32(any::<u8>()),
                repeats in 2u32..20
            ) {
                let keys = test_keys();
                let mut cache = SecretHashCache::new();
                let first = cache.get_or_compute(&h, &keys);
                for _ in 1..repeats {
                    let again = cache.get_or_compute(&h, &keys);
                    prop_assert_eq!(first, again);
                }
            }

            // ── P5. Collision pressure: restricted byte range ────────
            #[test]
            fn prop_collision_pressure(
                sequence in vec(proptest::array::uniform32(0u8..8), 1..300)
            ) {
                let keys = test_keys();
                let mut cache = SecretHashCache::new();
                for h in &sequence {
                    let cached = cache.get_or_compute(h, &keys);
                    let expected = oracle(h, &keys);
                    prop_assert_eq!(cached, expected);
                }
            }
        }
    }
}

// ============================================================================
// Kani bounded model-checking proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// For ALL `[u8; 32]` inputs, `set_index` returns `< SECRET_HASH_CACHE_SETS`
    /// and does not panic (including the `split_first_chunk().unwrap()` calls).
    #[kani::proof]
    fn kani_set_index_bounded_no_panic() {
        let h: [u8; 32] = kani::any();
        let idx = SecretHashCache::set_index(&h);
        kani::assert(
            idx < SECRET_HASH_CACHE_SETS,
            "set_index must be < SECRET_HASH_CACHE_SETS",
        );
    }

    /// The XOR-toggle expression `next_way ^ (1 << set)` keeps the replacement
    /// bit for the target set in `{0, 1}` (i.e. `< WAYS`) for all valid states.
    #[kani::proof]
    fn kani_next_way_stays_in_bounds() {
        let next_way: u32 = kani::any();
        let set: usize = kani::any();
        kani::assume(set < SECRET_HASH_CACHE_SETS);

        let way = ((next_way >> set) & 1) as usize;
        kani::assert(way < SECRET_HASH_CACHE_WAYS, "way must be < WAYS");

        let updated = next_way ^ (1u32 << set);
        let next = ((updated >> set) & 1) as usize;
        kani::assert(next < SECRET_HASH_CACHE_WAYS, "next_way must stay < WAYS");
    }

    /// `set * WAYS + way < ENTRIES` for all valid `(set, way)` pairs.
    #[kani::proof]
    fn kani_cache_slot_index_in_bounds() {
        let set: usize = kani::any();
        let way: usize = kani::any();
        kani::assume(set < SECRET_HASH_CACHE_SETS);
        kani::assume(way < SECRET_HASH_CACHE_WAYS);
        let idx = set * SECRET_HASH_CACHE_WAYS + way;
        kani::assert(
            idx < SECRET_HASH_CACHE_ENTRIES,
            "slot index must be < ENTRIES",
        );
    }
}
