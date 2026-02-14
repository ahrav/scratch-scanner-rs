//! Set-associative cache for tree object bytes.
//!
//! Stores decompressed tree payloads in fixed-size slots backed by a
//! pre-allocated arena. The cache is set-associative with CLOCK eviction
//! and does not allocate on the hot path (after initialization).
//!
//! # Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  Set 0           │  Set 1           │  ...      │
//! │ [w0][w1][w2][w3] │ [w0][w1][w2][w3] │           │
//! └─────────────────────────────────────────────────┘
//!        ▲ each slot is `slot_size` bytes in the arena
//! ```
//!
//! - `WAYS` slots per set (4-way associative)
//! - Number of sets is rounded down to a power of two for bitmask indexing
//! - Each slot owns a fixed `slot_size` byte range in the contiguous arena
//!
//! Tree payloads larger than `slot_size` are silently not cached.
//!
//! # Eviction (CLOCK)
//!
//! Each slot carries a 1-bit "clock" (recently-used) flag. On eviction the
//! hand sweeps through the set, clearing clock bits it encounters. The first
//! slot found with `clock == 0` (or an invalid slot) is chosen as the victim.
//! Pinned slots (those with an outstanding [`TreeCacheHandle`]) are skipped
//! unconditionally. The hand sweeps at most `2 × WAYS` positions; if every
//! slot is either pinned or recently used, the insertion is dropped.
//!
//! # Pinning
//!
//! [`TreeCacheHandle`] increments a per-slot pin count on creation and
//! decrements it on drop. While any pin is held the slot is immune to
//! eviction, guaranteeing the borrowed bytes remain stable. Callers must
//! ensure the handle does not outlive the cache itself.
//!
//! # Invariants
//! - `sets` is 0 (disabled) or a power of two
//! - `slot_size` is a power of two, >= `MIN_SLOT_SIZE`
//! - `storage.len() == sets * WAYS * slot_size`
//! - Cache is best-effort; insertions may evict existing entries
//! - Pinned slots are never evicted; handles must be dropped to release pins

use std::cell::Cell;

use super::object_id::OidBytes;

/// Default slot size for cached tree payloads.
const DEFAULT_SLOT_SIZE: u32 = 4096;
/// Minimum slot size (prevents tiny, inefficient caches).
const MIN_SLOT_SIZE: u32 = 256;
/// Number of ways per set.
const WAYS: usize = 4;

/// Metadata for a single cache slot.
///
/// Each slot corresponds to a fixed region in the arena (`storage`). The
/// `valid` flag distinguishes populated slots from empty ones so the cache
/// can be initialized without sentinel OIDs.
#[derive(Clone, Debug)]
struct Slot {
    /// Object identifier of the cached tree.
    oid: OidBytes,
    /// Actual byte length of the payload (may be less than `slot_size`).
    len: u32,
    /// CLOCK bit: set to 1 on access, cleared during eviction sweeps.
    clock: u8,
    /// Whether this slot holds a valid entry.
    valid: bool,
    /// Number of outstanding [`TreeCacheHandle`]s referencing this slot.
    /// Uses `Cell` so pin counts can be mutated through shared references
    /// (the handle holds a raw pointer, not `&mut`).
    pins: Cell<u16>,
}

impl Slot {
    #[inline]
    fn empty() -> Self {
        Self {
            oid: OidBytes::default(),
            len: 0,
            clock: 0,
            valid: false,
            pins: Cell::new(0),
        }
    }
}

/// Set-associative cache for tree payload bytes.
///
/// See the [module documentation](self) for layout, eviction, and pinning
/// details. When `sets == 0` the cache is disabled and all operations are
/// no-ops; this avoids special-casing callers when the budget is too small.
///
/// Not thread-safe; callers must synchronize shared access.
#[derive(Debug)]
pub struct TreeCache {
    /// Usable capacity (rounded from the requested value to fit whole sets).
    capacity_bytes: u32,
    /// Fixed byte size of every slot in the arena (power of two).
    slot_size: u32,
    /// Number of sets (power of two, or 0 when disabled).
    sets: usize,
    /// Contiguous arena: `sets * WAYS * slot_size` bytes, pre-allocated once.
    storage: Vec<u8>,
    /// Per-slot metadata, indexed as `set * WAYS + way`.
    slots: Vec<Slot>,
    /// Per-set CLOCK hand position (index into 0..WAYS).
    clock_hands: Vec<u8>,
}

/// Handle to a pinned tree payload stored in the cache.
///
/// While this handle exists the underlying slot is pinned (its pin count
/// is > 0), preventing the CLOCK eviction algorithm from reclaiming the
/// slot. Dropping the handle releases the pin.
///
/// # Lifetime constraint
///
/// The handle stores a raw pointer to the parent [`TreeCache`]. Callers
/// must ensure the cache is not dropped or moved while any handle is live.
/// In practice this is enforced structurally: handles are created from
/// `&mut TreeCache` and consumed within the same tree-walk scope.
#[derive(Debug)]
pub struct TreeCacheHandle {
    /// Raw pointer back to the owning cache (for arena access on read and
    /// pin-count decrement on drop).
    cache: *const TreeCache,
    /// Absolute slot index in `slots` (used for pin-count bookkeeping).
    slot: usize,
    /// Byte offset into `storage` where the payload begins.
    offset: usize,
    /// Byte length of the cached payload.
    len: usize,
}

impl TreeCacheHandle {
    /// Returns the cached tree bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `TreeCacheHandle` pins the slot for the duration of its
        // lifetime. Callers ensure the cache outlives the handle.
        unsafe {
            let cache = &*self.cache;
            &cache.storage[self.offset..self.offset + self.len]
        }
    }
}

impl Drop for TreeCacheHandle {
    fn drop(&mut self) {
        // SAFETY: The handle is only constructed with a valid cache pointer.
        unsafe {
            let cache = &*self.cache;
            let slot = &cache.slots[self.slot];
            let pins = slot.pins.get();
            debug_assert!(pins > 0, "tree cache pin count underflow");
            slot.pins.set(pins.saturating_sub(1));
        }
    }
}

impl TreeCache {
    /// Creates a new cache sized to approximately `capacity_bytes`.
    ///
    /// The actual usable capacity may be slightly smaller: the constructor
    /// rounds `slot_size` down to a power of two and the set count down to
    /// a power of two so that set indexing is a simple bitmask.
    ///
    /// If the budget is too small for even one full set (`WAYS` ×
    /// `MIN_SLOT_SIZE`), the cache enters a disabled state where all
    /// operations are no-ops.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self::disabled(capacity_bytes);
        }

        // Derive slot size: spread capacity across at least WAYS slots,
        // cap at DEFAULT_SLOT_SIZE, then round down to a power of two.
        let mut slot_size = (capacity_bytes / WAYS as u32).min(DEFAULT_SLOT_SIZE);
        slot_size = round_down_power_of_two_u32(slot_size).max(MIN_SLOT_SIZE);

        // Derive set count from remaining budget after fixing slot size.
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

    /// Looks up cached tree bytes by OID and returns a pinned handle.
    ///
    /// Returns `None` if the cache is disabled or if the entry is missing.
    /// On hit, the slot is pinned and the CLOCK bit is set.
    pub fn get_handle(&mut self, oid: &OidBytes) -> Option<TreeCacheHandle> {
        if self.sets == 0 {
            return None;
        }

        let set = self.set_index(oid);
        let base = set * WAYS;
        for way in 0..WAYS {
            let idx = base + way;
            let slot = &mut self.slots[idx];
            if slot.valid && slot.oid == *oid {
                slot.clock = 1;
                let offset = idx * self.slot_size as usize;
                slot.pins.set(slot.pins.get().saturating_add(1));
                let len = slot.len as usize;
                return Some(TreeCacheHandle {
                    cache: self as *const TreeCache,
                    slot: idx,
                    offset,
                    len,
                });
            }
        }
        None
    }

    /// Inserts tree bytes into the cache.
    ///
    /// If the OID is already present the clock bit is refreshed without
    /// copying bytes (dedup fast path). Otherwise a victim slot is selected
    /// via the CLOCK algorithm and overwritten.
    ///
    /// Returns `true` if the entry was cached (including dedup hits).
    /// Returns `false` if the cache is disabled, the payload exceeds
    /// `slot_size`, or all candidate slots are pinned.
    pub fn insert(&mut self, oid: OidBytes, bytes: &[u8]) -> bool {
        if self.sets == 0 {
            return false;
        }
        if bytes.len() > self.slot_size as usize {
            return false;
        }

        let set = self.set_index(&oid);
        let base = set * WAYS;

        // Dedup: if the OID already lives in this set, just refresh the
        // clock bit and return without copying.
        for way in 0..WAYS {
            let idx = base + way;
            if self.slots[idx].valid && self.slots[idx].oid == oid {
                self.slots[idx].clock = 1;
                return true;
            }
        }

        let Some(victim) = self.select_victim(base, set) else {
            return false;
        };
        self.write_slot(victim, oid, bytes);
        true
    }

    /// Returns a cache in the disabled state (`sets == 0`).
    ///
    /// All public methods early-return when `sets == 0`, so callers do not
    /// need to check for the disabled state explicitly.
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

    /// Maps an OID to its set index via bitmask (requires `sets` is a power of two).
    #[inline]
    fn set_index(&self, oid: &OidBytes) -> usize {
        let hash = hash_oid(oid);
        hash as usize & (self.sets - 1)
    }

    /// Selects a victim slot within the set using the CLOCK algorithm.
    ///
    /// The hand sweeps at most `2 × WAYS` positions. On the first pass a
    /// recently-used slot has its clock bit cleared (second chance). On the
    /// second pass the same slot will be evictable. Pinned slots are always
    /// skipped. Returns `None` when every slot in the set is pinned or
    /// recently used (all slots survived two passes).
    fn select_victim(&mut self, base: usize, set: usize) -> Option<usize> {
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

    /// Overwrites slot `idx` with a new entry, copying `bytes` into the arena.
    ///
    /// Resets the pin count to 0 (the caller ensures the slot is unpinned
    /// before calling this).
    fn write_slot(&mut self, idx: usize, oid: OidBytes, bytes: &[u8]) {
        let offset = idx * self.slot_size as usize;
        let end = offset + bytes.len();
        self.storage[offset..end].copy_from_slice(bytes);

        let slot = &mut self.slots[idx];
        slot.oid = oid;
        slot.len = bytes.len() as u32;
        slot.clock = 1;
        slot.valid = true;
        slot.pins.set(0);
    }
}

/// Returns the largest power of two ≤ `val`, or 0 if `val` is 0.
fn round_down_power_of_two_usize(val: usize) -> usize {
    if val == 0 {
        return 0;
    }
    1_usize << (usize::BITS - val.leading_zeros() - 1)
}

/// Returns the largest power of two ≤ `val`, or 0 if `val` is 0.
fn round_down_power_of_two_u32(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    1_u32 << (u32::BITS - val.leading_zeros() - 1)
}

/// Cheap hash for set selection: interprets the first 8 OID bytes as a
/// little-endian `u64`. Git OIDs are already uniformly distributed so no
/// mixing is needed; collisions within a set are handled by the
/// associative lookup.
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = TreeCache::new(64 * 1024);
        let oid = OidBytes::sha1([0x11; 20]);
        let payload = b"tree-bytes";

        assert!(cache.insert(oid, payload));
        let handle = cache.get_handle(&oid).unwrap();
        assert_eq!(handle.as_slice(), payload);
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = TreeCache::new(64 * 1024);
        let oid = OidBytes::sha1([0x22; 20]);
        let payload = vec![0u8; cache.slot_size as usize + 1];

        assert!(!cache.insert(oid, &payload));
        assert!(cache.get_handle(&oid).is_none());
    }

    #[test]
    fn eviction_within_set() {
        let mut cache = TreeCache::new(64 * 1024);
        assert!(cache.sets > 0);

        let mut oids = Vec::new();
        for i in 0..=WAYS {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&[0x55; 8]);
            bytes[8] = i as u8;
            oids.push(OidBytes::sha1(bytes));
        }

        for (idx, oid) in oids.iter().enumerate() {
            let data = vec![idx as u8];
            assert!(cache.insert(*oid, &data));
        }

        assert!(cache.get_handle(&oids[0]).is_none());
        let mut hit_count = 0;
        for oid in oids.iter().skip(1) {
            if cache.get_handle(oid).is_some() {
                hit_count += 1;
            }
        }
        assert!(hit_count >= 1);
    }

    #[test]
    fn disabled_when_capacity_too_small() {
        let mut cache = TreeCache::new(MIN_SLOT_SIZE * WAYS as u32 - 1);
        let oid = OidBytes::sha1([0x33; 20]);
        assert!(!cache.insert(oid, b"data"));
        assert!(cache.get_handle(&oid).is_none());
    }
}
