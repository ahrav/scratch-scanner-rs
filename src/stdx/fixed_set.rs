//! Fixed-capacity dedupe sets with O(1) reset via generation counters.
//!
//! The key trick is "epoch tagging": each slot stores a generation number
//! indicating when it was last written. Reset is just `cur += 1`, so the table
//! becomes logically empty without clearing memory. On rare wraparound, we pay
//! a full clear once to re-establish the invariant.

/// Fixed-capacity hash set for deduplication (128-bit keys).
///
/// - Open addressing with linear probing.
/// - Reset is O(1) by advancing a generation counter.
/// - Insert returns `true` on first insertion, `false` for duplicates.
/// - When the table is full, insert returns `true` for new keys (best-effort dedupe).
///
/// We use the upper 64 bits for initial slot selection to better spread values
/// when the lower bits have patterns (common with some hash functions).
///
/// This "best-effort when full" behavior is intentional for dedupe: it keeps
/// the scanner moving under load without panicking or allocating.
pub struct FixedSet128 {
    keys: Vec<u128>,
    gen: Vec<u32>,
    cur: u32,
    mask: usize,
}

impl FixedSet128 {
    pub fn with_pow2(cap_pow2: usize) -> Self {
        assert!(cap_pow2.is_power_of_two());
        Self {
            keys: vec![0; cap_pow2],
            gen: vec![0; cap_pow2],
            cur: 1,
            mask: cap_pow2 - 1,
        }
    }

    pub fn reset(&mut self) {
        self.cur = self.cur.wrapping_add(1);
        if self.cur == 0 {
            // Rare wrap: pay full clear once.
            self.gen.fill(0);
            self.cur = 1;
        }
    }

    pub fn insert(&mut self, key: u128) -> bool {
        // Use upper 64 bits for initial slot selection (better distribution).
        let mut i = ((key >> 64) as usize) & self.mask;
        for _ in 0..=self.mask {
            if self.gen[i] != self.cur {
                self.gen[i] = self.cur;
                self.keys[i] = key;
                return true;
            }
            if self.keys[i] == key {
                return false;
            }
            i = (i + 1) & self.mask;
        }
        // Table full: dedupe is best-effort only.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::FixedSet128;

    #[test]
    fn fixed_set_128_insert_and_duplicate() {
        let mut set = FixedSet128::with_pow2(16);
        assert!(set.insert(42));
        assert!(!set.insert(42));
        assert!(set.insert(7));
        assert!(!set.insert(7));
        // Test with large 128-bit values.
        let big = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0u128;
        assert!(set.insert(big));
        assert!(!set.insert(big));
    }

    #[test]
    fn fixed_set_128_reset_clears_generation() {
        let mut set = FixedSet128::with_pow2(8);
        assert!(set.insert(1));
        assert!(!set.insert(1));
        set.reset();
        assert!(set.insert(1));
    }

    #[test]
    fn fixed_set_128_wrap_resets_gen_table() {
        let mut set = FixedSet128::with_pow2(8);
        set.gen.fill(123);
        set.cur = u32::MAX;
        set.reset();
        assert_eq!(set.cur, 1);
        assert!(set.gen.iter().all(|&g| g == 0));
    }

    #[test]
    fn fixed_set_128_full_table_keeps_dedup_for_existing_keys() {
        let mut set = FixedSet128::with_pow2(8);
        for k in 0..8u128 {
            assert!(set.insert(k));
        }
        assert!(!set.insert(3));
        assert!(!set.insert(7));
        // New keys after full table are best-effort; no assert on return value.
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::FixedSet128;
    use proptest::prelude::*;
    use std::collections::HashSet;

    const PROPTEST_CASES: u32 = 16;
    const CAP: usize = 64;

    #[derive(Clone, Debug)]
    enum Op128 {
        Insert(u128),
        Reset,
    }

    fn op128_strategy() -> impl Strategy<Value = Op128> {
        prop_oneof![any::<u128>().prop_map(Op128::Insert), Just(Op128::Reset),]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        // FixedSet128 proptests

        #[test]
        fn insert_duplicates_report_false_128(keys in proptest::collection::vec(any::<u128>(), 0..32)) {
            let mut set = FixedSet128::with_pow2(CAP);
            let mut seen = std::collections::HashSet::new();

            for key in keys {
                let inserted = set.insert(key);
                if seen.contains(&key) {
                    prop_assert!(!inserted);
                } else {
                    prop_assert!(inserted);
                    seen.insert(key);
                }
            }
        }

        #[test]
        fn reset_forgets_prior_keys_128(keys in proptest::collection::vec(any::<u128>(), 0..32)) {
            let mut set = FixedSet128::with_pow2(CAP);

            for key in &keys {
                let _ = set.insert(*key);
            }

            set.reset();

            for key in keys {
                prop_assert!(set.insert(key));
            }
        }

        #[test]
        fn op_sequence_matches_model_128(
            cap_exp in 0usize..7,
            ops in proptest::collection::vec(op128_strategy(), 0..128),
        ) {
            let cap = 1usize << cap_exp;
            let mut set = FixedSet128::with_pow2(cap);
            let mut model: HashSet<u128> = HashSet::new();

            for op in ops {
                match op {
                    Op128::Insert(key) => {
                        let inserted = set.insert(key);
                        let expected = !model.contains(&key);
                        prop_assert_eq!(inserted, expected);
                        if expected && model.len() < cap {
                            model.insert(key);
                        }
                    }
                    Op128::Reset => {
                        set.reset();
                        model.clear();
                    }
                }
            }
        }

        #[test]
        fn linear_probing_handles_collisions_128(
            high in any::<u64>(),
            lows in proptest::collection::vec(any::<u64>(), 0..=CAP),
        ) {
            let mut set = FixedSet128::with_pow2(CAP);
            let mut seen: HashSet<u128> = HashSet::new();
            let high_bits = (high as u128) << 64;

            for low in lows {
                let key = high_bits | low as u128;
                let inserted = set.insert(key);
                let expected = seen.insert(key);
                prop_assert_eq!(inserted, expected);
            }
        }

        #[test]
        fn full_table_reports_duplicates_128(
            keys in proptest::collection::hash_set(any::<u128>(), CAP..=CAP),
            probes in proptest::collection::vec(any::<u128>(), 0..64),
        ) {
            let mut set = FixedSet128::with_pow2(CAP);

            for key in &keys {
                prop_assert!(set.insert(*key));
            }
            for key in &keys {
                prop_assert!(!set.insert(*key));
            }

            for key in probes {
                let inserted = set.insert(key);
                let expected = !keys.contains(&key);
                prop_assert_eq!(inserted, expected);
            }
        }
    }
}
