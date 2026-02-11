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
//! Both tiers are 4-way set-associative and do not allocate on the hot path
//! after initialization. Default eviction is CLOCK. An opt-in
//! `SCANNER_RS_PACK_CACHE_EVICTION=dependency_clock` prototype adds bounded
//! dependency protection on top of CLOCK for likely delta bases.
//! Oversize entries (> 2 MiB) are not cached. Individual tiers are disabled if
//! the configured capacity cannot fit at least one full set
//! (`WAYS × slot_size`).

use super::pack_inflate::ObjectKind;
use std::sync::OnceLock;

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
/// Max distance between a likely base hit and dependent insert.
///
/// This keeps dependency protection conservative: we only protect recently hit
/// entries when the dependent offset is nearby (typical for Git delta chains).
const DEPENDENCY_HINT_MAX_DISTANCE: u64 = 16 * 1024 * 1024;
/// Number of dependency-protection passes before a slot is fully eligible.
const DEPENDENCY_GUARD_MAX: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvictionPolicy {
    Clock,
    DependencyClock,
}

impl EvictionPolicy {
    #[inline]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::DependencyClock => "dependency_clock",
        }
    }
}

fn selected_eviction_policy() -> EvictionPolicy {
    static POLICY: OnceLock<EvictionPolicy> = OnceLock::new();
    *POLICY.get_or_init(|| match std::env::var("SCANNER_RS_PACK_CACHE_EVICTION") {
        Ok(raw) if raw.eq_ignore_ascii_case("dependency_clock") => EvictionPolicy::DependencyClock,
        Ok(raw) if raw.eq_ignore_ascii_case("dep_clock") => EvictionPolicy::DependencyClock,
        Ok(raw) if raw.eq_ignore_ascii_case("depclock") => EvictionPolicy::DependencyClock,
        _ => EvictionPolicy::Clock,
    })
}

/// Eviction instrumentation intended for benchmarks and profiling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackCacheEvictionStats {
    /// Number of insert attempts routed to enabled tiers.
    pub insert_attempts: u64,
    /// Number of set-victim selections.
    pub victim_selections: u64,
    /// Number of times a likely dependency base was protected.
    pub dependency_marks: u64,
    /// Number of eviction probes deferred by dependency protection.
    pub dependency_protected_skips: u64,
    /// Number of unconditional fallback evictions after bounded sweeps.
    pub forced_evictions: u64,
}

impl PackCacheEvictionStats {
    fn merge_from(&mut self, other: Self) {
        self.insert_attempts = self.insert_attempts.saturating_add(other.insert_attempts);
        self.victim_selections = self
            .victim_selections
            .saturating_add(other.victim_selections);
        self.dependency_marks = self.dependency_marks.saturating_add(other.dependency_marks);
        self.dependency_protected_skips = self
            .dependency_protected_skips
            .saturating_add(other.dependency_protected_skips);
        self.forced_evictions = self.forced_evictions.saturating_add(other.forced_evictions);
    }
}

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
    /// Bounded dependency protection credit for likely delta bases.
    dependency_guard: u8,
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
            dependency_guard: 0,
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
    eviction_policy: EvictionPolicy,
    eviction_stats: PackCacheEvictionStats,
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
    fn new_with_slot_and_policy(
        capacity_bytes: u32,
        slot_size: u32,
        eviction_policy: EvictionPolicy,
    ) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self::disabled_with_policy(capacity_bytes, eviction_policy);
        }

        let slot_size = slot_size.min(capacity_bytes / WAYS as u32);
        let slot_size = round_down_power_of_two_u32(slot_size).max(MIN_SLOT_SIZE);

        let slots_total = capacity_bytes / slot_size;
        let sets = round_down_power_of_two_usize((slots_total / WAYS as u32) as usize);
        if sets == 0 {
            return Self::disabled_with_policy(capacity_bytes, eviction_policy);
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
            eviction_policy,
            eviction_stats: PackCacheEvictionStats::default(),
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
    /// selected via the active eviction policy.
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
        self.eviction_stats.insert_attempts = self.eviction_stats.insert_attempts.saturating_add(1);

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

    fn disabled_with_policy(capacity_bytes: u32, eviction_policy: EvictionPolicy) -> Self {
        Self {
            capacity_bytes,
            slot_size: 0,
            sets: 0,
            storage: Vec::new(),
            slots: Vec::new(),
            clock_hands: Vec::new(),
            eviction_policy,
            eviction_stats: PackCacheEvictionStats::default(),
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
        self.eviction_stats.victim_selections =
            self.eviction_stats.victim_selections.saturating_add(1);
        match self.eviction_policy {
            EvictionPolicy::Clock => self.select_victim_clock(base, set),
            EvictionPolicy::DependencyClock => self.select_victim_dependency_clock(base, set),
        }
    }

    fn select_victim_clock(&mut self, base: usize, set: usize) -> usize {
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

    fn select_victim_dependency_clock(&mut self, base: usize, set: usize) -> usize {
        let mut hand = self.clock_hands[set] as usize % WAYS;

        // Bounded two-sweep search:
        // 1) clear CLOCK bits (second-chance)
        // 2) allow dependency-guarded entries to defer eviction briefly
        for _ in 0..(WAYS * 2) {
            let idx = base + hand;
            let slot = &mut self.slots[idx];
            if !slot.valid {
                self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
                return idx;
            }
            if slot.clock != 0 {
                slot.clock = 0;
                hand = (hand + 1) % WAYS;
                continue;
            }
            if slot.dependency_guard != 0 {
                slot.dependency_guard -= 1;
                self.eviction_stats.dependency_protected_skips = self
                    .eviction_stats
                    .dependency_protected_skips
                    .saturating_add(1);
                hand = (hand + 1) % WAYS;
                continue;
            }
            self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
            return idx;
        }

        let idx = base + hand;
        self.slots[idx].dependency_guard = 0;
        self.eviction_stats.forced_evictions =
            self.eviction_stats.forced_evictions.saturating_add(1);
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
        slot.dependency_guard = 0;
        slot.valid = true;
    }

    /// Marks a cached base as dependency-protected if present.
    ///
    /// Returns `true` if the base existed in this tier and was marked.
    fn protect_dependency_base(&mut self, base_offset: u64) -> bool {
        if self.sets == 0 || self.eviction_policy != EvictionPolicy::DependencyClock {
            return false;
        }
        let set = self.set_index(base_offset);
        let base = set * WAYS;
        for way in 0..WAYS {
            let idx = base + way;
            let slot = &mut self.slots[idx];
            if slot.valid && slot.offset == base_offset {
                slot.clock = 1;
                slot.dependency_guard = DEPENDENCY_GUARD_MAX;
                self.eviction_stats.dependency_marks =
                    self.eviction_stats.dependency_marks.saturating_add(1);
                return true;
            }
        }
        false
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
/// Both tiers are set-associative with preallocated storage.
#[derive(Debug)]
pub struct PackCache {
    small: PackCacheTier,
    large: PackCacheTier,
    eviction_policy: EvictionPolicy,
    pending_dependency_hint: Option<u64>,
}

impl PackCache {
    /// Creates a new tiered cache with the given total capacity.
    ///
    /// The cache splits capacity into a small and large tier. If either tier
    /// cannot fit at least one full set, it is disabled and the other tier
    /// receives the full capacity.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        Self::new_with_policy(capacity_bytes, selected_eviction_policy())
    }

    fn new_with_policy(capacity_bytes: u32, eviction_policy: EvictionPolicy) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self {
                small: PackCacheTier::disabled_with_policy(capacity_bytes, eviction_policy),
                large: PackCacheTier::disabled_with_policy(0, eviction_policy),
                eviction_policy,
                pending_dependency_hint: None,
            };
        }

        if capacity_bytes < MIN_LARGE_TIER_BYTES {
            return Self::single_tier(capacity_bytes, DEFAULT_SMALL_SLOT_SIZE, eviction_policy);
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

        let mut small = PackCacheTier::new_with_slot_and_policy(
            small_bytes,
            DEFAULT_SMALL_SLOT_SIZE,
            eviction_policy,
        );
        let mut large = PackCacheTier::new_with_slot_and_policy(
            large_bytes,
            DEFAULT_LARGE_SLOT_SIZE,
            eviction_policy,
        );

        if small.is_disabled() && large.is_disabled() {
            return Self {
                small,
                large,
                eviction_policy,
                pending_dependency_hint: None,
            };
        }
        if small.is_disabled() && !large.is_disabled() {
            large = PackCacheTier::new_with_slot_and_policy(
                capacity_bytes,
                DEFAULT_LARGE_SLOT_SIZE,
                eviction_policy,
            );
            return Self {
                small,
                large,
                eviction_policy,
                pending_dependency_hint: None,
            };
        }
        if large.is_disabled() && !small.is_disabled() {
            small = PackCacheTier::new_with_slot_and_policy(
                capacity_bytes,
                DEFAULT_SMALL_SLOT_SIZE,
                eviction_policy,
            );
            return Self {
                small,
                large,
                eviction_policy,
                pending_dependency_hint: None,
            };
        }

        Self {
            small,
            large,
            eviction_policy,
            pending_dependency_hint: None,
        }
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
        if let Some(hit) = self.small.get(offset) {
            if self.eviction_policy == EvictionPolicy::DependencyClock {
                self.pending_dependency_hint = Some(offset);
            }
            return Some(hit);
        }
        if let Some(hit) = self.large.get(offset) {
            if self.eviction_policy == EvictionPolicy::DependencyClock {
                self.pending_dependency_hint = Some(offset);
            }
            return Some(hit);
        }
        self.pending_dependency_hint = None;
        None
    }

    /// Inserts bytes for an offset into the cache.
    ///
    /// Returns true if the entry was cached. Oversize entries are ignored.
    pub fn insert(&mut self, offset: u64, kind: ObjectKind, bytes: &[u8]) -> bool {
        let dependency_hint = self.pending_dependency_hint.take();
        if let Some(base_offset) = dependency_hint {
            self.maybe_protect_dependency_base(base_offset, offset);
        }

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
        self.pending_dependency_hint = None;
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
        *self = Self::new_with_policy(capacity_bytes, self.eviction_policy);
    }

    /// Builds a cache with only the small tier enabled, using the full
    /// capacity. Used when total capacity is below [`MIN_LARGE_TIER_BYTES`].
    fn single_tier(capacity_bytes: u32, slot_size: u32, eviction_policy: EvictionPolicy) -> Self {
        Self {
            small: PackCacheTier::new_with_slot_and_policy(
                capacity_bytes,
                slot_size,
                eviction_policy,
            ),
            large: PackCacheTier::disabled_with_policy(0, eviction_policy),
            eviction_policy,
            pending_dependency_hint: None,
        }
    }

    /// Active eviction policy label (`clock` or `dependency_clock`).
    #[must_use]
    pub fn eviction_policy_name(&self) -> &'static str {
        self.eviction_policy.as_str()
    }

    /// Aggregate eviction stats across both tiers.
    #[must_use]
    pub fn eviction_stats(&self) -> PackCacheEvictionStats {
        let mut stats = self.small.eviction_stats;
        stats.merge_from(self.large.eviction_stats);
        stats
    }

    fn maybe_protect_dependency_base(&mut self, base_offset: u64, child_offset: u64) {
        if self.eviction_policy != EvictionPolicy::DependencyClock {
            return;
        }
        if base_offset >= child_offset {
            return;
        }
        if child_offset - base_offset > DEPENDENCY_HINT_MAX_DISTANCE {
            return;
        }
        if self.small.protect_dependency_base(base_offset) {
            return;
        }
        let _ = self.large.protect_dependency_base(base_offset);
    }

    #[cfg(test)]
    fn new_with_policy_for_test(capacity_bytes: u32, eviction_policy: EvictionPolicy) -> Self {
        Self::new_with_policy(capacity_bytes, eviction_policy)
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
        let small = PackCacheTier::new_with_slot_and_policy(
            256 * 1024,
            DEFAULT_SMALL_SLOT_SIZE,
            EvictionPolicy::Clock,
        );
        let large = PackCacheTier::new_with_slot_and_policy(
            16 * 1024 * 1024,
            DEFAULT_LARGE_SLOT_SIZE,
            EvictionPolicy::Clock,
        );
        let mut cache = PackCache {
            small,
            large,
            eviction_policy: EvictionPolicy::Clock,
            pending_dependency_hint: None,
        };
        let data = vec![0x22u8; 128 * 1024];
        assert!(cache.insert(200, ObjectKind::Blob, &data));
        let hit = cache.get(200).expect("cache hit");
        assert_eq!(hit.bytes.len(), data.len());
    }

    #[test]
    fn dependency_policy_protects_recent_base() {
        let mut cache =
            PackCache::new_with_policy_for_test(4 * 1024, EvictionPolicy::DependencyClock);
        let payload = [0x55u8; 32];

        assert!(cache.insert(100, ObjectKind::Blob, &payload));
        assert!(cache.insert(200, ObjectKind::Blob, &payload));
        assert!(cache.insert(300, ObjectKind::Blob, &payload));
        assert!(cache.insert(400, ObjectKind::Blob, &payload));

        let _ = cache.get(100).expect("base must exist");
        assert!(cache.insert(500, ObjectKind::Blob, &payload));

        assert!(
            cache.get(100).is_some(),
            "dependency-protected base should survive first eviction"
        );
        assert!(
            cache.get(200).is_none(),
            "unprotected peer should be evicted first"
        );

        let stats = cache.eviction_stats();
        assert!(stats.dependency_marks > 0);
        assert!(stats.dependency_protected_skips > 0);
    }

    #[test]
    fn clock_policy_matches_previous_eviction_behavior() {
        let mut cache = PackCache::new_with_policy_for_test(4 * 1024, EvictionPolicy::Clock);
        let payload = [0x33u8; 32];

        assert!(cache.insert(100, ObjectKind::Blob, &payload));
        assert!(cache.insert(200, ObjectKind::Blob, &payload));
        assert!(cache.insert(300, ObjectKind::Blob, &payload));
        assert!(cache.insert(400, ObjectKind::Blob, &payload));

        let _ = cache.get(100).expect("seed hit");
        assert!(cache.insert(500, ObjectKind::Blob, &payload));

        assert!(
            cache.get(100).is_none(),
            "CLOCK fallback should evict first-hand slot after a full sweep"
        );
    }
}
