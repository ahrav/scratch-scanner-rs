//! Tiered set-associative cache for decoded pack objects.
//!
//! Stores inflated object bytes in fixed-size slots keyed by pack offset.
//! Two tiers handle different object size ranges:
//!
//! - **Small tier** (≤ 64 KiB slots) — holds the majority of objects; receives
//!   ~2/3 of the total capacity budget.
//! - **Large tier** (≤ 2 MiB slots) — covers popular delta bases in the
//!   64 KiB–2 MiB range; receives ~1/3 of the budget.
//!
//! Both tiers are 4-way set-associative with CLOCK eviction and do not
//! allocate on the hot path after initialization. Oversize entries (> 2 MiB)
//! are not cached. Individual tiers are disabled if the configured capacity
//! cannot fit at least one full set (`WAYS × slot_size`).

use super::pack_inflate::ObjectKind;

/// Default slot size for small cached pack objects (64 KiB).
const DEFAULT_SMALL_SLOT_SIZE: u32 = 64 * 1024;
/// Default slot size for large cached pack objects (2 MiB).
///
/// Objects between 64 KiB and 2 MiB (common delta bases in large repos) are
/// cached in the large tier. This covers the bulk of popular delta bases,
/// avoiding repeated fallback decodes.
const DEFAULT_LARGE_SLOT_SIZE: u32 = 2 * 1024 * 1024;
/// Minimum bytes reserved for the large tier when enabled.
const MIN_LARGE_TIER_BYTES: u32 = 32 * 1024 * 1024;
/// Minimum slot size (prevents tiny, inefficient caches).
const MIN_SLOT_SIZE: u32 = 1024;
/// Number of ways per set (4-way associativity).
///
/// 4-way is a practical compromise: enough associativity to avoid frequent
/// conflict misses on clustered offsets, but few enough ways that the
/// CLOCK sweep per set is cheap.
const WAYS: usize = 4;

/// Metadata for one cache slot within a set-associative tier.
///
/// Each slot maps a pack offset to a contiguous region in the tier's
/// backing `storage` buffer. The `clock` bit drives CLOCK eviction:
/// it is set on access and cleared during victim selection sweeps.
#[derive(Clone, Copy, Debug)]
struct Slot {
    /// Pack-file byte offset that identifies this entry.
    offset: u64,
    /// Inflated object length stored in the slot (may be less than `slot_size`).
    len: u32,
    /// Git object type (blob, tree, commit, tag).
    kind: ObjectKind,
    /// CLOCK reference bit: 1 = recently accessed, 0 = eligible for eviction.
    clock: u8,
    /// Whether this slot contains a valid entry.
    valid: bool,
}

impl Slot {
    #[inline]
    fn empty() -> Self {
        Self {
            offset: 0,
            len: 0,
            kind: ObjectKind::Blob,
            clock: 0,
            valid: false,
        }
    }
}

/// Cached entry returned by `PackCache::get`.
#[derive(Clone, Copy, Debug)]
pub struct CachedObject<'a> {
    /// Object kind stored in the pack.
    pub kind: ObjectKind,
    /// Inflated object bytes.
    pub bytes: &'a [u8],
}

/// Fixed-size cache tier for decoded pack objects.
///
/// # Invariants
/// - `sets` is a power of two (or zero when disabled).
/// - Each set has exactly `WAYS` slots.
/// - Slot storage is contiguous and indexed by `(set, way)`.
#[derive(Debug)]
struct PackCacheTier {
    capacity_bytes: u32,
    slot_size: u32,
    sets: usize,
    storage: Vec<u8>,
    slots: Vec<Slot>,
    clock_hands: Vec<u8>,
}

impl PackCacheTier {
    /// Creates a new cache tier with the given capacity and slot size.
    ///
    /// If the capacity is too small for at least one set, the tier is
    /// initialized in a disabled state.
    ///
    /// The actual capacity may be rounded down to satisfy power-of-two
    /// set counts and slot sizes.
    #[must_use]
    fn new_with_slot(capacity_bytes: u32, slot_size: u32) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self::disabled(capacity_bytes);
        }

        let slot_size = slot_size.min(capacity_bytes / WAYS as u32);
        let slot_size = round_down_power_of_two_u32(slot_size).max(MIN_SLOT_SIZE);

        let slots_total = capacity_bytes / slot_size;
        let sets = round_down_power_of_two_usize((slots_total / WAYS as u32) as usize);
        if sets == 0 {
            return Self::disabled(capacity_bytes);
        }

        let total_slots = sets * WAYS;
        let storage_len = (total_slots as u32).saturating_mul(slot_size) as usize;

        Self {
            capacity_bytes: storage_len as u32,
            slot_size,
            sets,
            storage: vec![0u8; storage_len],
            slots: vec![Slot::empty(); total_slots],
            clock_hands: vec![0u8; sets],
        }
    }

    /// Returns the configured capacity in bytes (rounded to usable bytes).
    #[must_use]
    const fn capacity_bytes(&self) -> u32 {
        self.capacity_bytes
    }

    /// Returns the slot size in bytes.
    #[must_use]
    const fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Looks up cached bytes by pack offset.
    ///
    /// A hit updates the CLOCK bit for the slot.
    fn get(&mut self, offset: u64) -> Option<CachedObject<'_>> {
        if self.sets == 0 {
            return None;
        }

        let set = self.set_index(offset);
        let base = set * WAYS;
        for way in 0..WAYS {
            let idx = base + way;
            let slot = &mut self.slots[idx];
            if slot.valid && slot.offset == offset {
                slot.clock = 1;
                let offset_bytes = idx * self.slot_size as usize;
                let end = offset_bytes + slot.len as usize;
                return Some(CachedObject {
                    kind: slot.kind,
                    bytes: &self.storage[offset_bytes..end],
                });
            }
        }
        None
    }

    /// Inserts bytes for an offset into the cache.
    ///
    /// If an entry with the same offset already exists in the set, it is
    /// overwritten in place (no duplicate slots). Otherwise a victim is
    /// selected via CLOCK eviction.
    ///
    /// Returns `true` if the entry was cached. Oversize entries (bytes >
    /// `slot_size`) are silently rejected and return `false`.
    fn insert(&mut self, offset: u64, kind: ObjectKind, bytes: &[u8]) -> bool {
        if self.sets == 0 {
            return false;
        }
        if bytes.len() > self.slot_size as usize {
            return false;
        }

        let set = self.set_index(offset);
        let base = set * WAYS;
        // Dedup: if the offset already exists, overwrite in place.
        for way in 0..WAYS {
            let idx = base + way;
            if self.slots[idx].valid && self.slots[idx].offset == offset {
                self.write_slot(idx, offset, kind, bytes);
                self.slots[idx].clock = 1;
                return true;
            }
        }

        let victim = self.select_victim(base, set);
        self.write_slot(victim, offset, kind, bytes);
        true
    }

    /// Builds a disabled cache that always misses.
    fn disabled(capacity_bytes: u32) -> Self {
        Self {
            capacity_bytes,
            slot_size: 0,
            sets: 0,
            storage: Vec::new(),
            slots: Vec::new(),
            clock_hands: Vec::new(),
        }
    }

    /// Maps a pack offset to a set index via [`hash_offset`] and a bitmask.
    ///
    /// Requires `self.sets` to be a power of two so the mask `sets - 1`
    /// produces a uniform distribution over set indices.
    #[inline]
    fn set_index(&self, offset: u64) -> usize {
        let hash = hash_offset(offset);
        hash as usize & (self.sets - 1)
    }

    /// Selects a victim slot within a set using the CLOCK algorithm.
    ///
    /// Scans the set starting from the persisted hand position. Slots with
    /// `clock == 0` (or invalid) are immediately chosen as victims. Slots
    /// with `clock == 1` have their bit cleared ("second chance") and the
    /// hand advances. If all `WAYS` slots survive a full sweep, the slot
    /// under the hand after the sweep is evicted unconditionally.
    fn select_victim(&mut self, base: usize, set: usize) -> usize {
        let mut hand = self.clock_hands[set] as usize % WAYS;
        for _ in 0..WAYS {
            let idx = base + hand;
            if !self.slots[idx].valid || self.slots[idx].clock == 0 {
                self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
                return idx;
            }
            self.slots[idx].clock = 0;
            hand = (hand + 1) % WAYS;
        }
        let idx = base + hand;
        self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
        idx
    }

    /// Writes bytes into the backing storage and updates slot metadata.
    fn write_slot(&mut self, idx: usize, offset: u64, kind: ObjectKind, bytes: &[u8]) {
        let offset_bytes = idx * self.slot_size as usize;
        let end = offset_bytes + bytes.len();
        self.storage[offset_bytes..end].copy_from_slice(bytes);

        let slot = &mut self.slots[idx];
        slot.offset = offset;
        slot.len = bytes.len() as u32;
        slot.kind = kind;
        slot.clock = 1;
        slot.valid = true;
    }

    /// Returns `true` if this tier was initialized in a disabled state
    /// (zero sets) and will always miss on lookups.
    #[inline]
    fn is_disabled(&self) -> bool {
        self.sets == 0
    }

    /// Invalidates all entries without releasing storage.
    ///
    /// After reset, the tier retains its allocated `storage`, `slots`, and
    /// `clock_hands` buffers. All slots are marked invalid and clock hands
    /// are zeroed, making the tier behave as freshly constructed.
    fn reset(&mut self) {
        for slot in &mut self.slots {
            *slot = Slot::empty();
        }
        for hand in &mut self.clock_hands {
            *hand = 0;
        }
        // storage bytes are stale but will be overwritten on insert — no need to zero.
    }
}

/// Tiered cache for decoded pack objects.
///
/// Tier A uses small fixed slots; Tier B uses larger slots for oversized bases.
/// Both tiers are set-associative with CLOCK eviction and preallocated storage.
#[derive(Debug)]
pub struct PackCache {
    small: PackCacheTier,
    large: PackCacheTier,
}

impl PackCache {
    /// Creates a new tiered cache with the given total capacity.
    ///
    /// The cache splits capacity into a small and large tier. If either tier
    /// cannot fit at least one full set, it is disabled and the other tier
    /// receives the full capacity.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self {
                small: PackCacheTier::disabled(capacity_bytes),
                large: PackCacheTier::disabled(0),
            };
        }

        if capacity_bytes < MIN_LARGE_TIER_BYTES {
            return Self::single_tier(capacity_bytes, DEFAULT_SMALL_SLOT_SIZE);
        }

        // Give the large tier 1/3 of the budget. This balances large-slot
        // capacity (enough 2 MiB slots for good hash distribution) against
        // small-tier slot count (2/3 of capacity preserves a dense small-
        // object working set with minimal evictions).
        let mut large_bytes = (capacity_bytes / 3).max(MIN_LARGE_TIER_BYTES);
        if large_bytes > capacity_bytes {
            large_bytes = capacity_bytes;
        }
        let small_bytes = capacity_bytes.saturating_sub(large_bytes);

        let mut small = PackCacheTier::new_with_slot(small_bytes, DEFAULT_SMALL_SLOT_SIZE);
        let mut large = PackCacheTier::new_with_slot(large_bytes, DEFAULT_LARGE_SLOT_SIZE);

        if small.is_disabled() && large.is_disabled() {
            return Self { small, large };
        }
        if small.is_disabled() && !large.is_disabled() {
            large = PackCacheTier::new_with_slot(capacity_bytes, DEFAULT_LARGE_SLOT_SIZE);
            return Self { small, large };
        }
        if large.is_disabled() && !small.is_disabled() {
            small = PackCacheTier::new_with_slot(capacity_bytes, DEFAULT_SMALL_SLOT_SIZE);
            return Self { small, large };
        }

        Self { small, large }
    }

    /// Returns the configured capacity in bytes (rounded to usable bytes).
    #[must_use]
    pub fn capacity_bytes(&self) -> u32 {
        self.small
            .capacity_bytes()
            .saturating_add(self.large.capacity_bytes())
    }

    /// Returns the small-tier slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        DEFAULT_SMALL_SLOT_SIZE
    }

    /// Looks up cached bytes by pack offset.
    ///
    /// Searches the small tier first, then the large tier. A hit in either
    /// tier updates that slot's CLOCK reference bit.
    pub fn get(&mut self, offset: u64) -> Option<CachedObject<'_>> {
        self.small.get(offset).or_else(|| self.large.get(offset))
    }

    /// Inserts bytes for an offset into the cache.
    ///
    /// Returns true if the entry was cached. Oversize entries are ignored.
    pub fn insert(&mut self, offset: u64, kind: ObjectKind, bytes: &[u8]) -> bool {
        if bytes.len() <= self.small.slot_size() as usize {
            return self.small.insert(offset, kind, bytes);
        }
        if bytes.len() <= self.large.slot_size() as usize {
            return self.large.insert(offset, kind, bytes);
        }
        false
    }

    /// Clears all cached entries without releasing allocated memory.
    ///
    /// This is the Tiger-Style equivalent of creating a fresh cache:
    /// the backing storage is retained so no allocations occur on the
    /// next scan. Call this between repo scans or between pack plans
    /// that should not share cached data.
    pub fn reset(&mut self) {
        self.small.reset();
        self.large.reset();
    }

    /// Grows the cache to at least `capacity_bytes` if currently smaller.
    ///
    /// If the current capacity is already >= `capacity_bytes`, this is a
    /// no-op (no allocation). If growth is needed, the cache is
    /// reconstructed with the new capacity. Follows the
    /// `PackExecScratch::prepare()` pattern: only grows, never shrinks.
    pub fn ensure_capacity(&mut self, capacity_bytes: u32) {
        if self.capacity_bytes() >= capacity_bytes {
            // Already large enough — just reset entries for the new scan.
            self.reset();
            return;
        }
        // Need more space — reconstruct. This allocates but only happens
        // when a larger repo is encountered for the first time.
        *self = Self::new(capacity_bytes);
    }

    /// Builds a cache with only the small tier enabled, using the full
    /// capacity. Used when total capacity is below [`MIN_LARGE_TIER_BYTES`].
    fn single_tier(capacity_bytes: u32, slot_size: u32) -> Self {
        Self {
            small: PackCacheTier::new_with_slot(capacity_bytes, slot_size),
            large: PackCacheTier::disabled(0),
        }
    }
}

/// Hashes a pack offset to a 32-bit value for set-index computation.
///
/// Uses the MurmurHash3 64-bit finalizer (fmix64) to spread sequential
/// pack offsets uniformly across cache sets, then folds the 64-bit result
/// to 32 bits with an XOR.
fn hash_offset(offset: u64) -> u32 {
    let mut x = offset;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    (x as u32) ^ ((x >> 32) as u32)
}

/// Rounds `value` down to the largest power of two ≤ `value`.
///
/// Returns 0 for an input of 0. Uses bit-smearing to fill all bits
/// below the highest set bit, then subtracts the smeared value shifted
/// right by one to isolate the leading bit.
fn round_down_power_of_two_usize(mut value: usize) -> usize {
    if value == 0 {
        return 0;
    }
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    if usize::BITS == 64 {
        value |= value >> 32;
    }
    value - (value >> 1)
}

/// Rounds `value` down to the largest power of two ≤ `value`.
///
/// Returns 0 for an input of 0. 32-bit variant of
/// [`round_down_power_of_two_usize`].
fn round_down_power_of_two_u32(mut value: u32) -> u32 {
    if value == 0 {
        return 0;
    }
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value - (value >> 1)
}

#[cfg(test)]
mod tests {
    use super::super::pack_inflate::ObjectKind;
    use super::*;

    #[test]
    fn cache_insert_and_get() {
        let mut cache = PackCache::new(64 * 1024);
        let data = vec![0x11u8; 32];
        assert!(cache.insert(100, ObjectKind::Blob, &data));
        let hit = cache.get(100).expect("cache hit");
        assert_eq!(hit.kind, ObjectKind::Blob);
        assert_eq!(hit.bytes, data.as_slice());
    }

    #[test]
    fn cache_large_tier_insert() {
        // Large tier needs at least WAYS (4) × 2 MiB = 8 MiB for one set.
        let small = PackCacheTier::new_with_slot(256 * 1024, DEFAULT_SMALL_SLOT_SIZE);
        let large = PackCacheTier::new_with_slot(16 * 1024 * 1024, DEFAULT_LARGE_SLOT_SIZE);
        let mut cache = PackCache { small, large };
        let data = vec![0x22u8; 128 * 1024];
        assert!(cache.insert(200, ObjectKind::Blob, &data));
        let hit = cache.get(200).expect("cache hit");
        assert_eq!(hit.bytes.len(), data.len());
    }
}
