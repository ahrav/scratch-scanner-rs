//! Set-associative cache for decoded pack objects.
//!
//! Stores inflated object bytes in fixed-size slots keyed by pack offset.
//! The cache is set-associative with CLOCK eviction and does not allocate
//! on the hot path after initialization.
//!
//! Oversize entries are not cached. The cache is disabled if the configured
//! capacity cannot fit at least one full set (WAYS * MIN_SLOT_SIZE).

use super::pack_inflate::ObjectKind;

/// Default slot size for cached pack objects (64 KiB).
const DEFAULT_SLOT_SIZE: u32 = 64 * 1024;
/// Minimum slot size (prevents tiny, inefficient caches).
const MIN_SLOT_SIZE: u32 = 1024;
/// Number of ways per set.
const WAYS: usize = 4;

#[derive(Clone, Copy, Debug)]
struct Slot {
    offset: u64,
    len: u32,
    kind: ObjectKind,
    clock: u8,
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

/// Fixed-size cache for decoded pack objects.
///
/// # Invariants
/// - `sets` is a power of two (or zero when disabled).
/// - Each set has exactly `WAYS` slots.
/// - Slot storage is contiguous and indexed by `(set, way)`.
#[derive(Debug)]
pub struct PackCache {
    capacity_bytes: u32,
    slot_size: u32,
    sets: usize,
    storage: Vec<u8>,
    slots: Vec<Slot>,
    clock_hands: Vec<u8>,
}

impl PackCache {
    /// Creates a new cache with the given capacity.
    ///
    /// If the capacity is too small for at least one set, the cache is
    /// initialized in a disabled state.
    ///
    /// The actual capacity may be rounded down to satisfy power-of-two
    /// set counts and slot sizes.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self::disabled(capacity_bytes);
        }

        let mut slot_size = (capacity_bytes / WAYS as u32).min(DEFAULT_SLOT_SIZE);
        slot_size = round_down_power_of_two_u32(slot_size).max(MIN_SLOT_SIZE);

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
    pub const fn capacity_bytes(&self) -> u32 {
        self.capacity_bytes
    }

    /// Returns the slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Looks up cached bytes by pack offset.
    ///
    /// A hit updates the CLOCK bit for the slot.
    pub fn get(&mut self, offset: u64) -> Option<CachedObject<'_>> {
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
    /// Returns true if the entry was cached. Oversize entries are ignored.
    pub fn insert(&mut self, offset: u64, kind: ObjectKind, bytes: &[u8]) -> bool {
        if self.sets == 0 {
            return false;
        }
        if bytes.len() > self.slot_size as usize {
            return false;
        }

        let set = self.set_index(offset);
        let base = set * WAYS;
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

    #[inline]
    fn set_index(&self, offset: u64) -> usize {
        let hash = hash_offset(offset);
        hash as usize & (self.sets - 1)
    }

    /// Selects a victim slot using CLOCK within a set.
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
}

fn hash_offset(offset: u64) -> u32 {
    // 64-bit mix to spread nearby offsets across sets.
    let mut x = offset;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    (x as u32) ^ ((x >> 32) as u32)
}

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
}
