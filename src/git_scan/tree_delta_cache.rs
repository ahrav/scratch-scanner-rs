//! Set-associative cache for tree delta base bytes.
//!
//! Stores decompressed tree payloads keyed by `(pack_id, offset)` in
//! fixed-size slots backed by a pre-allocated arena. The cache is
//! set-associative with CLOCK eviction and does not allocate on the hot
//! path (after initialization).
//!
//! # Layout
//! - `WAYS` slots per set (fixed)
//! - Number of sets is rounded down to a power of two
//! - Each slot owns a fixed `slot_size` byte range in the arena
//!
//! Tree payloads larger than `slot_size` are not cached.
//!
//! # Invariants
//! - `sets` is 0 (disabled) or a power of two
//! - `slot_size` is a power of two, >= `MIN_SLOT_SIZE`
//! - `storage.len() == sets * WAYS * slot_size`
//! - Cache is best-effort; insertions may evict existing entries
//! - Pinned slots are never evicted; handles must be dropped to release pins

use std::cell::Cell;

use super::pack_inflate::ObjectKind;

/// Default slot size for cached delta bases.
const DEFAULT_SLOT_SIZE: u32 = 4096;
/// Minimum slot size (prevents tiny, inefficient caches).
const MIN_SLOT_SIZE: u32 = 256;
/// Number of ways per set.
const WAYS: usize = 4;

/// Cache slot metadata.
#[derive(Clone, Debug)]
struct Slot {
    pack_id: u16,
    offset: u64,
    kind: ObjectKind,
    chain_len: u8,
    len: u32,
    clock: u8,
    valid: bool,
    pins: Cell<u16>,
}

impl Slot {
    #[inline]
    fn empty() -> Self {
        Self {
            pack_id: 0,
            offset: 0,
            kind: ObjectKind::Tree,
            chain_len: 0,
            len: 0,
            clock: 0,
            valid: false,
            pins: Cell::new(0),
        }
    }
}

/// Set-associative cache for tree delta base bytes.
///
/// The cache is not thread-safe; callers must synchronize shared access.
#[derive(Debug)]
pub struct TreeDeltaCache {
    capacity_bytes: u32,
    slot_size: u32,
    sets: usize,
    storage: Vec<u8>,
    slots: Vec<Slot>,
    clock_hands: Vec<u8>,
}

/// Handle to a pinned delta base stored in the cache.
///
/// The handle keeps the slot pinned until drop so cached bytes are not
/// overwritten while the caller is still borrowing them.
///
/// # Safety
/// The handle must not outlive the cache that created it.
#[derive(Debug)]
pub struct TreeDeltaCacheHandle {
    cache: *const TreeDeltaCache,
    slot: usize,
    offset: usize,
    len: usize,
    kind: ObjectKind,
    chain_len: u8,
}

impl TreeDeltaCacheHandle {
    /// Returns the cached base bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `TreeDeltaCacheHandle` pins the slot for the duration of its
        // lifetime. Callers ensure the cache outlives the handle.
        unsafe {
            let cache = &*self.cache;
            &cache.storage[self.offset..self.offset + self.len]
        }
    }

    /// Returns the cached object kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Returns the cached delta chain length for this base.
    #[must_use]
    pub const fn chain_len(&self) -> u8 {
        self.chain_len
    }

    /// Returns the cached payload length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the cached payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for TreeDeltaCacheHandle {
    fn drop(&mut self) {
        // SAFETY: The handle is only constructed with a valid cache pointer.
        unsafe {
            let cache = &*self.cache;
            let slot = &cache.slots[self.slot];
            let pins = slot.pins.get();
            debug_assert!(pins > 0, "tree delta cache pin count underflow");
            slot.pins.set(pins.saturating_sub(1));
        }
    }
}

impl TreeDeltaCache {
    /// Creates a new cache with a byte capacity.
    ///
    /// If the capacity is too small to hold at least one set, the cache is
    /// initialized in a disabled state (all operations are no-ops).
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

    /// Returns the configured capacity (rounded to usable bytes).
    #[must_use]
    pub const fn capacity_bytes(&self) -> u32 {
        self.capacity_bytes
    }

    /// Returns the fixed slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Looks up cached base bytes by `(pack_id, offset)` and returns a pinned handle.
    ///
    /// Returns `None` if the cache is disabled or if the entry is missing.
    /// On hit, the slot is pinned and the CLOCK bit is set.
    pub fn get_handle(&mut self, pack_id: u16, offset: u64) -> Option<TreeDeltaCacheHandle> {
        if self.sets == 0 {
            return None;
        }

        let set = self.set_index(pack_id, offset);
        let base = set * WAYS;
        for way in 0..WAYS {
            let idx = base + way;
            let (kind, chain_len, len, hit) = {
                let slot = &mut self.slots[idx];
                if slot.valid && slot.pack_id == pack_id && slot.offset == offset {
                    slot.clock = 1;
                    slot.pins.set(slot.pins.get().saturating_add(1));
                    (slot.kind, slot.chain_len, slot.len as usize, true)
                } else {
                    (ObjectKind::Tree, 0, 0, false)
                }
            };
            if hit {
                let offset = idx * self.slot_size as usize;
                return Some(TreeDeltaCacheHandle {
                    cache: self as *const TreeDeltaCache,
                    slot: idx,
                    offset,
                    len,
                    kind,
                    chain_len,
                });
            }
        }
        None
    }

    /// Inserts base bytes into the cache.
    ///
    /// Returns true if the entry was cached. Returns false if the cache is
    /// disabled, the payload is too large for a slot, or all candidate slots
    /// are pinned.
    pub fn insert(
        &mut self,
        pack_id: u16,
        offset: u64,
        kind: ObjectKind,
        chain_len: u8,
        bytes: &[u8],
    ) -> bool {
        if self.sets == 0 {
            return false;
        }
        if bytes.len() > self.slot_size as usize {
            return false;
        }

        let set = self.set_index(pack_id, offset);
        let base = set * WAYS;

        for way in 0..WAYS {
            let idx = base + way;
            if self.slots[idx].valid
                && self.slots[idx].pack_id == pack_id
                && self.slots[idx].offset == offset
            {
                self.slots[idx].clock = 1;
                self.slots[idx].kind = kind;
                self.slots[idx].chain_len = chain_len;
                return true;
            }
        }

        let Some(victim) = self.select_victim(base, set) else {
            return false;
        };
        self.write_slot(victim, pack_id, offset, kind, chain_len, bytes);
        true
    }

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
    fn set_index(&self, pack_id: u16, offset: u64) -> usize {
        let hash = hash_key(pack_id, offset);
        hash as usize & (self.sets - 1)
    }

    fn select_victim(&mut self, base: usize, set: usize) -> Option<usize> {
        // CLOCK: pick the first slot with clock=0, clearing clock bits as we go.
        let mut hand = self.clock_hands[set] as usize % WAYS;
        for _ in 0..(WAYS * 2) {
            let idx = base + hand;
            let pins = self.slots[idx].pins.get();
            if pins > 0 {
                hand = (hand + 1) % WAYS;
                continue;
            }
            let slot = &mut self.slots[idx];
            if !slot.valid || slot.clock == 0 {
                self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
                return Some(idx);
            }
            slot.clock = 0;
            hand = (hand + 1) % WAYS;
        }

        None
    }

    fn write_slot(
        &mut self,
        idx: usize,
        pack_id: u16,
        offset: u64,
        kind: ObjectKind,
        chain_len: u8,
        bytes: &[u8],
    ) {
        // Copy into the slot's fixed storage region.
        let base = idx * self.slot_size as usize;
        let end = base + bytes.len();
        self.storage[base..end].copy_from_slice(bytes);

        let slot = &mut self.slots[idx];
        slot.pack_id = pack_id;
        slot.offset = offset;
        slot.kind = kind;
        slot.chain_len = chain_len;
        slot.len = bytes.len() as u32;
        slot.clock = 1;
        slot.valid = true;
        slot.pins.set(0);
    }
}

fn round_down_power_of_two_usize(val: usize) -> usize {
    if val == 0 {
        return 0;
    }
    1_usize << (usize::BITS - val.leading_zeros() - 1)
}

fn round_down_power_of_two_u32(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    1_u32 << (u32::BITS - val.leading_zeros() - 1)
}

#[inline]
fn hash_key(pack_id: u16, offset: u64) -> u64 {
    // Mix pack_id into the high bits and apply a cheap avalanche to
    // distribute sequential offsets across sets.
    let mut hash = offset ^ ((pack_id as u64) << 48);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = TreeDeltaCache::new(64 * 1024);
        let payload = b"tree-bytes";

        assert!(cache.insert(7, 42, ObjectKind::Tree, 0, payload));
        let handle = cache.get_handle(7, 42).unwrap();
        assert_eq!(handle.as_slice(), payload);
        assert_eq!(handle.kind(), ObjectKind::Tree);
        assert_eq!(handle.chain_len(), 0);
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = TreeDeltaCache::new(64 * 1024);
        let payload = vec![0u8; cache.slot_size as usize + 1];

        assert!(!cache.insert(1, 99, ObjectKind::Tree, 0, &payload));
        assert!(cache.get_handle(1, 99).is_none());
    }

    #[test]
    fn eviction_within_set() {
        let mut cache = TreeDeltaCache::new(16 * 1024);
        let slots_total = cache.capacity_bytes() as usize / cache.slot_size() as usize;
        let sets = slots_total / WAYS;
        assert_eq!(sets, 1);

        let mut offsets = Vec::new();
        for i in 0..=WAYS {
            let offset = (i as u64) << 20;
            offsets.push(offset);
        }

        for offset in &offsets {
            assert!(cache.insert(1, *offset, ObjectKind::Tree, 0, b"x"));
        }

        let hits = offsets
            .iter()
            .filter(|offset| cache.get_handle(1, **offset).is_some())
            .count();
        assert!(hits <= WAYS);
    }
}
