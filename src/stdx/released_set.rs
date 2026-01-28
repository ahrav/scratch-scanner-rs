//! A fixed-capacity, deterministic hash set optimized for tracking "released" items.
//!
//! This data structure combines a linear-probing hash table with a supplementary stack
//! to support efficient iteration and clearing. It is designed for scenarios where:
//! 1. The maximum number of elements is known in advance (no resizing).
//! 2. Memory allocation should be static or upfront (no reallocation during insertion).
//! 3. Iterating/draining the set needs to be proportional to the number of elements,
//!    not the capacity of the table.
//!
//! The "stack" ensures that `pop()` is O(1) and `clear_retaining_capacity()` is fast,
//! avoiding the need to scan the entire sparse hash table to find occupied slots.

/// Entry state in the hash table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleasedEntry {
    /// Slot is available for insertion.
    Empty,
    /// Slot contains the given key.
    Occupied(u64),
}

/// A fixed-capacity hash set optimized for tracking "released" items.
///
/// Combines a linear-probing hash table with a supplementary stack to provide
/// O(1) `pop` operations and efficient clearing. Designed for deterministic
/// systems where:
///
/// - The maximum capacity is known at construction time
/// - No reallocation occurs during insertion
/// - Iteration/draining is proportional to element count, not table capacity
///
/// # Panics
///
/// Panics on insertion if capacity is exceeded. This is intentional for
/// deterministic systems where resource limits must be explicitly modeled.
///
/// # Example
///
/// ```
/// use scanner_rs::stdx::ReleasedSet;
///
/// let mut set = ReleasedSet::with_capacity(16);
/// set.insert(42);
/// set.insert(17);
///
/// assert!(set.contains(42));
/// assert_eq!(set.len(), 2);
///
/// while let Some(key) = set.pop() {
///     println!("Released: {}", key);
/// }
/// assert!(set.is_empty());
/// ```
#[derive(Debug)]
pub struct ReleasedSet {
    /// The hash table backing storage. Uses open addressing with linear probing.
    /// Capacity is always a power of two to allow efficient masking.
    entries: Vec<ReleasedEntry>,
    /// A dense list of all keys currently in the set.
    /// This allows O(1) selection of an element to remove (via `pop`) and
    /// eliminates the need to scan `entries` to find active elements.
    stack: Vec<u64>,
    /// Bitmask for fast modulo operations (size - 1).
    mask: usize,
    /// Maximum number of elements allowed in the set.
    limit: usize,
}

impl ReleasedSet {
    /// Creates a new set capable of holding *up to* `cap` elements without resizing.
    ///
    /// The underlying hash table will be sized to `2 * cap` (rounded up to the next power of two)
    /// to ensure the load factor never exceeds 0.5. This low load factor is critical for
    /// minimizing collision chain lengths in linear probing, maintaining high performance
    /// without complex collision resolution strategies.
    ///
    /// The `cap` is a strict maximum: inserting more than `cap` distinct elements will panic.
    ///
    /// # Panics
    ///
    /// Panics if `cap * 2` overflows or if the resulting capacity cannot be
    /// represented as a power of two.
    pub fn with_capacity(cap: usize) -> Self {
        let slots = released_set_slots(cap);
        Self {
            entries: vec![ReleasedEntry::Empty; slots],
            stack: Vec::with_capacity(cap),
            mask: slots - 1,
            limit: cap,
        }
    }

    /// Returns the number of elements in the set.
    #[inline]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Returns the number of elements in the set.
    #[inline]
    pub fn count(&self) -> usize {
        self.len()
    }

    /// Returns `true` if the set contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Removes all elements from the set but keeps the allocated memory.
    ///
    /// This operation is efficient because we simply clear the `stack` and reset the `entries`.
    /// While resetting `entries` is linear in the table size, this is acceptable for a
    /// reused component where allocations are the primary cost to avoid.
    pub fn clear_retaining_capacity(&mut self) {
        self.stack.clear();
        self.entries.fill(ReleasedEntry::Empty);
    }

    /// Returns `true` if the set contains the specified key.
    ///
    /// This operation is O(1) on average, with worst-case O(n) if the table
    /// has many collisions (unlikely given the 0.5 load factor constraint).
    #[inline]
    pub fn contains(&self, key: u64) -> bool {
        let mut idx = (released_set_hash(key) as usize) & self.mask;

        // Linear probing: check slots sequentially until we find the key or an empty slot.
        // The table guarantees enough capacity that we will eventually find an Empty slot
        // if the key is missing, preventing an infinite loop.
        for _ in 0..self.entries.len() {
            // bound check
            match self.entries[idx] {
                ReleasedEntry::Empty => return false,
                ReleasedEntry::Occupied(k) if k == key => return true,
                _ => idx = (idx + 1) & self.mask,
            }
        }

        false
    }

    /// Inserts a key into the set.
    ///
    /// # Panics
    ///
    /// Panics if the set is full (capacity exceeded). This design is intentional for
    /// deterministic systems where resource limits must be explicitly modeled and respected.
    pub fn insert(&mut self, key: u64) {
        let mut idx = (released_set_hash(key) as usize) & self.mask;

        for _ in 0..self.entries.len() {
            match self.entries[idx] {
                ReleasedEntry::Empty => {
                    // Enforce a strict element cap; released_set_slots guarantees that
                    // limit <= entries.len() / 2, preserving the <= 0.5 load factor invariant.
                    if self.stack.len() >= self.limit {
                        panic!("released set capacity exceeded");
                    }
                    self.entries[idx] = ReleasedEntry::Occupied(key);
                    self.stack.push(key);
                    return;
                }
                ReleasedEntry::Occupied(k) if k == key => return,
                _ => idx = (idx + 1) & self.mask,
            }
        }

        // Should be unreachable given the load factor check and capacity calculation.
        panic!("released set probe exhaustion (table unexpectedly full");
    }

    /// Removes and returns an arbitrary element from the set, or `None` if empty.
    ///
    /// The element returned is not guaranteed to follow any particular order;
    /// internally elements are removed in LIFO order relative to insertion,
    /// but this should not be relied upon.
    ///
    /// Uses the internal stack to locate an element in O(1).
    #[inline]
    pub fn pop(&mut self) -> Option<u64> {
        let key = self.stack.pop()?;
        // We must remove from the table as well to keep `contains` consistent.
        let removed = self.remove(key);
        debug_assert!(
            removed,
            "ReleasedSet invariant broken; stack/table diverged"
        );
        Some(key)
    }

    /// Internal removal from the linear-probing table.
    ///
    /// Returns `true` if the key was present and removed.
    #[inline]
    fn remove(&mut self, key: u64) -> bool {
        let mut idx = (released_set_hash(key) as usize) & self.mask;

        for _ in 0..self.entries.len() {
            match self.entries[idx] {
                ReleasedEntry::Empty => return false,
                ReleasedEntry::Occupied(k) if k == key => {
                    self.backshift_delete(idx);
                    return true;
                }
                _ => idx = (idx + 1) & self.mask,
            }
        }

        false
    }

    /// Deletes an entry at `hole` and performs "backward shift deletion".
    ///
    /// In linear probing, simply marking a slot as Empty breaks the search chain for
    /// any elements that collided and were stored in subsequent slots.
    /// This function moves such elements "back" to fill the `hole`, ensuring that
    /// all remaining elements are still reachable from their native hash index.
    #[inline]
    fn backshift_delete(&mut self, mut hole: usize) {
        let mut i = (hole + 1) & self.mask;

        loop {
            match self.entries[i] {
                ReleasedEntry::Empty => {
                    // End of the chain. We can safely clear the hole now.
                    self.entries[hole] = ReleasedEntry::Empty;
                    return;
                }
                ReleasedEntry::Occupied(k) => {
                    let home = (released_set_hash(k) as usize) & self.mask;

                    // Calculate distances to determine if this element 'belongs'
                    // before the hole (and thus should be moved back).
                    // We use wrapping arithmetic to handle the circular buffer topology.
                    let dist_home_to_i = i.wrapping_sub(home) & self.mask;
                    let dist_hole_to_i = i.wrapping_sub(hole) & self.mask;

                    // If the element at `i` is effectively "farther" from its home bucket
                    // than the hole is from that same home bucket, it means `k`'s probe
                    // chain passed through `hole`. We must fill `hole` with `k` to restore
                    // continuity.
                    if dist_home_to_i >= dist_hole_to_i {
                        self.entries[hole] = ReleasedEntry::Occupied(k);
                        hole = i;
                    }
                }
            }
            i = (i + 1) & self.mask;
        }
    }
}

/// Calculates the next power of two capacity for the hash table, ensuring a
/// load factor <= 0.5.
///
/// We allocate `2 * limit` slots. The `limit` is the maximum number of items
/// we expect to store. By doubling the size, we keep the table sparsely populated,
/// which reduces the length of collision chains in linear probing.
fn released_set_slots(limit: usize) -> usize {
    let min = limit
        .checked_mul(2)
        .expect("released set capacity overflow; limit too large");
    let min = min.max(2);
    min.checked_next_power_of_two()
        .expect("released set capacity overflow; next_power_of_two failed")
}

/// SplitMix64 mixing constants.
///
/// These constants, combined with the specific shift amounts (30, 27, 31),
/// were empirically derived by Sebastiano Vigna to maximize avalanche
/// properties — ensuring small input changes produce ~50% output bit flips.
///
/// Reference: https://prng.di.unimi.it/splitmix64.c
const SPLITMIX64_MUL_1: u64 = 0xbf58476d1ce4e5b9;
const SPLITMIX64_MUL_2: u64 = 0x94d049bb133111eb;

/// First shift amount, tuned with `SPLITMIX64_MUL_1` for optimal avalanche.
const SHIFT_1: u32 = 30;
/// Second shift amount, tuned with `SPLITMIX64_MUL_2` for optimal avalanche.
const SHIFT_2: u32 = 27;
/// Final shift amount for output mixing.
const SHIFT_3: u32 = 31;

/// Hashes a key using the SplitMix64 algorithm.
///
/// This is a high-quality, stateless hash function that is extremely fast on
/// 64-bit architectures. It provides excellent avalanche properties, which is
/// important for linear probing to avoid clustering.
#[inline]
fn released_set_hash(key: u64) -> u64 {
    let mut x = key;
    x ^= x >> SHIFT_1;
    x = x.wrapping_mul(SPLITMIX64_MUL_1);
    x ^= x >> SHIFT_2;
    x = x.wrapping_mul(SPLITMIX64_MUL_2);
    x ^ (x >> SHIFT_3)
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const LIMIT: usize = 16;
    const KEY_MAX: u64 = 64;
    const PROPTEST_CASES: u32 = 16;

    #[test]
    fn empty_set_has_no_members() {
        let set = ReleasedSet::with_capacity(LIMIT);
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        assert!(!set.contains(0));
        assert!(!set.contains(KEY_MAX - 1));
    }

    #[test]
    fn insert_is_idempotent() {
        let mut set = ReleasedSet::with_capacity(LIMIT);
        set.insert(10);
        set.insert(10);
        assert_eq!(set.len(), 1);
        assert!(set.contains(10));
    }

    #[test]
    fn clear_retaining_capacity_resets_len() {
        let mut set = ReleasedSet::with_capacity(LIMIT);
        set.insert(1);
        set.insert(2);
        set.clear_retaining_capacity();
        assert!(set.is_empty());
        assert!(!set.contains(1));
        assert!(!set.contains(2));
    }

    #[test]
    fn pop_drains_all_elements() {
        let mut set = ReleasedSet::with_capacity(LIMIT);
        set.insert(1);
        set.insert(2);
        set.insert(3);

        let mut drained: HashSet<u64> = HashSet::new();
        while let Some(key) = set.pop() {
            assert!(drained.insert(key));
        }

        assert_eq!(drained.len(), 3);
        assert!(set.is_empty());
    }

    #[test]
    fn slots_are_power_of_two_and_min_two() {
        let slots_zero = released_set_slots(0);
        assert!(slots_zero.is_power_of_two());
        assert!(slots_zero >= 2);

        let slots = released_set_slots(LIMIT);
        assert!(slots.is_power_of_two());
        assert!(slots >= LIMIT * 2);
    }

    #[test]
    #[should_panic(expected = "released set capacity exceeded")]
    fn insert_panics_on_overflow() {
        let mut set = ReleasedSet::with_capacity(2);
        set.insert(1);
        set.insert(2);
        set.insert(3);
    }

    #[test]
    #[should_panic(expected = "released set capacity exceeded")]
    fn insert_panics_on_overflow_with_rounded_capacity() {
        let mut set = ReleasedSet::with_capacity(3);
        set.insert(1);
        set.insert(2);
        set.insert(3);
        set.insert(4);
    }

    #[test]
    fn contains_returns_within_timeout_after_limit_one_sequence() {
        let mut set = ReleasedSet::with_capacity(1);
        set.insert(0);
        assert_eq!(set.pop(), Some(0));
        set.insert(1);
        assert_eq!(set.pop(), Some(1));
        assert!(set.is_empty());

        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = (set.contains(0), set.contains(1));
            let _ = tx.send(result);
        });

        let (has_0, has_1) = rx
            .recv_timeout(Duration::from_millis(200))
            .expect("contains timed out");
        assert!(!has_0);
        assert!(!has_1);
        handle.join().expect("contains thread panicked");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_insert_contains_len(keys in proptest::collection::vec(0u64..KEY_MAX, 0..128)) {
            let mut set = ReleasedSet::with_capacity(LIMIT);
            let mut model: HashSet<u64> = HashSet::new();

            for key in keys {
                if model.len() == LIMIT && !model.contains(&key) {
                    continue;
                }
                set.insert(key);
                model.insert(key);
            }

            prop_assert_eq!(set.len(), model.len());
            for key in 0..KEY_MAX {
                prop_assert_eq!(set.contains(key), model.contains(&key));
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_pop_drains(keys in proptest::collection::hash_set(0u64..KEY_MAX, 0..=LIMIT)) {
            let mut set = ReleasedSet::with_capacity(LIMIT);
            let mut model: HashSet<u64> = HashSet::new();
            for key in &keys {
                set.insert(*key);
                model.insert(*key);
            }

            let mut drained: HashSet<u64> = HashSet::new();
            while let Some(key) = set.pop() {
                prop_assert!(drained.insert(key));
            }

            prop_assert!(set.is_empty());
            prop_assert_eq!(drained, model);
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        Insert(u64),
        Contains(u64),
        Pop,
        Clear,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u64..KEY_MAX).prop_map(Op::Insert),
            (0u64..KEY_MAX).prop_map(Op::Contains),
            Just(Op::Pop),
            Just(Op::Clear),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_operation_sequence(ops in proptest::collection::vec(op_strategy(), 0..256)) {
            let mut set = ReleasedSet::with_capacity(LIMIT);
            let mut model: HashSet<u64> = HashSet::new();

            for op in ops {
                match op {
                    Op::Insert(key) => {
                        if model.len() == LIMIT && !model.contains(&key) {
                            continue;
                        }
                        set.insert(key);
                        model.insert(key);
                    }
                    Op::Contains(key) => {
                        prop_assert_eq!(set.contains(key), model.contains(&key));
                    }
                    Op::Pop => {
                        let got = set.pop();
                        match got {
                            Some(key) => {
                                prop_assert!(model.remove(&key));
                            }
                            None => {
                                prop_assert!(model.is_empty());
                            }
                        }
                    }
                    Op::Clear => {
                        set.clear_retaining_capacity();
                        model.clear();
                    }
                }
            }

            prop_assert_eq!(set.len(), model.len());
            for key in 0..KEY_MAX {
                prop_assert_eq!(set.contains(key), model.contains(&key));
            }
        }
    }
}
