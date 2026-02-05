//! Fixed-capacity OID index for fast OID -> MIDX index lookups.
//!
//! This is a simple open-addressing hash table with linear probing and a
//! fixed load factor. It is optimized for OID workloads where keys are
//! uniformly distributed (SHA-1/SHA-256), enabling predictable O(1) lookups
//! without per-lookup allocations.
//!
//! # Invariants
//! - Table size is a power of two and `mask = len - 1`.
//! - Empty slots use `NONE_U32` as the sentinel value.
//! - `len <= capacity * LOAD_FACTOR` (enforced at build time).
//!
//! # Performance
//! - Insert and lookup are O(1) expected time with linear probing.
//! - A single-byte hash tag avoids full-key compares on most misses.

use super::midx::MidxView;
use super::object_id::OidBytes;

/// Sentinel value for empty slots.
const NONE_U32: u32 = u32::MAX;
/// Load factor numerator (e.g. 7/10 = 0.7).
const LOAD_FACTOR_NUM: usize = 7;
/// Load factor denominator.
const LOAD_FACTOR_DEN: usize = 10;

#[derive(Clone, Copy, Debug)]
struct Entry {
    key: OidBytes,
    value: u32,
    tag: u8,
}

impl Entry {
    #[inline]
    fn empty() -> Self {
        Self {
            key: OidBytes::default(),
            value: NONE_U32,
            tag: 0,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.value == NONE_U32
    }
}

/// OID index with fixed capacity and open addressing.
#[derive(Debug)]
pub struct OidIndex {
    entries: Vec<Entry>,
    mask: usize,
    oid_len: u8,
    len: u32,
}

impl OidIndex {
    /// Builds an index for the OIDs stored in the MIDX.
    pub fn from_midx(midx: &MidxView<'_>) -> Self {
        let count = midx.object_count() as usize;
        let capacity = table_size_for_count(count);
        let mut index = Self {
            entries: vec![Entry::empty(); capacity],
            mask: capacity - 1,
            oid_len: midx.oid_len(),
            len: 0,
        };

        for idx in 0..midx.object_count() {
            let oid = OidBytes::from_slice(midx.oid_at(idx));
            index.insert(oid, idx);
        }

        index
    }

    /// Returns the number of entries stored.
    #[inline]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Returns true if the index is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the OID length this index was built for.
    #[inline]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the underlying table size (power of two).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// Looks up the MIDX index for the given OID.
    #[inline]
    pub fn get(&self, oid: &OidBytes) -> Option<u32> {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &self.entries[slot];
            if entry.is_empty() {
                return None;
            }
            if entry.tag == tag && entry.key == *oid {
                return Some(entry.value);
            }
            slot = (slot + 1) & self.mask;
        }

        None
    }

    fn insert(&mut self, oid: OidBytes, value: u32) {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(&oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &mut self.entries[slot];
            if entry.is_empty() {
                entry.key = oid;
                entry.value = value;
                entry.tag = tag;
                self.len += 1;
                return;
            }
            if entry.tag == tag && entry.key == oid {
                return;
            }
            slot = (slot + 1) & self.mask;
        }

        unreachable!("oid index capacity exceeded; load factor too high");
    }
}

fn table_size_for_count(count: usize) -> usize {
    let min_capacity = count
        .saturating_mul(LOAD_FACTOR_DEN)
        .div_ceil(LOAD_FACTOR_NUM);
    min_capacity.max(1).next_power_of_two()
}

/// Hash an OID using head/tail bytes to avoid full-key mixing.
#[inline]
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let head = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut h = head ^ tail.rotate_left(32);
    h ^= (bytes.len() as u64) << 56;
    mix64(h)
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::midx::MidxView;
    use crate::git_scan::object_id::ObjectFormat;

    struct MidxBuilder {
        objects: Vec<([u8; 20], u16, u64)>,
        pack_names: Vec<Vec<u8>>,
    }

    impl MidxBuilder {
        fn new() -> Self {
            Self {
                objects: Vec::new(),
                pack_names: Vec::new(),
            }
        }

        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
            self.objects.push((oid, pack_id, offset));
        }

        fn build(&self) -> Vec<u8> {
            const MIDX_MAGIC: [u8; 4] = *b"MIDX";
            const VERSION: u8 = 1;
            const HEADER_SIZE: usize = 12;
            const CHUNK_ENTRY_SIZE: usize = 12;
            const CHUNK_PNAM: [u8; 4] = *b"PNAM";
            const CHUNK_OIDF: [u8; 4] = *b"OIDF";
            const CHUNK_OIDL: [u8; 4] = *b"OIDL";
            const CHUNK_OOFF: [u8; 4] = *b"OOFF";

            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let pack_count = self.pack_names.len() as u32;

            let mut pnam = Vec::new();
            for name in &self.pack_names {
                pnam.extend_from_slice(name);
                pnam.push(0);
            }

            let mut oidf = vec![0u8; 256 * 4];
            let mut counts = [0u32; 256];
            for (oid, _, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            let mut oidl = Vec::with_capacity(objects.len() * 20);
            for (oid, _, _) in &objects {
                oidl.extend_from_slice(oid);
            }

            let mut ooff = Vec::with_capacity(objects.len() * 8);
            for (_, pack_id, offset) in &objects {
                ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
                ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
            }

            let chunk_count = 4u8;
            let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
            let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
            let oidf_off = pnam_off + pnam.len() as u64;
            let oidl_off = oidf_off + oidf.len() as u64;
            let ooff_off = oidl_off + oidl.len() as u64;
            let end_off = ooff_off + ooff.len() as u64;

            let mut out = Vec::new();
            out.extend_from_slice(&MIDX_MAGIC);
            out.push(VERSION);
            out.push(1); // SHA-1
            out.push(chunk_count);
            out.push(0); // base count
            out.extend_from_slice(&pack_count.to_be_bytes());

            let mut push_chunk = |id: [u8; 4], off: u64| {
                out.extend_from_slice(&id);
                out.extend_from_slice(&off.to_be_bytes());
            };

            push_chunk(CHUNK_PNAM, pnam_off);
            push_chunk(CHUNK_OIDF, oidf_off);
            push_chunk(CHUNK_OIDL, oidl_off);
            push_chunk(CHUNK_OOFF, ooff_off);
            push_chunk([0, 0, 0, 0], end_off);

            out.extend_from_slice(&pnam);
            out.extend_from_slice(&oidf);
            out.extend_from_slice(&oidl);
            out.extend_from_slice(&ooff);

            out
        }
    }

    #[test]
    fn oid_index_matches_midx_lookup() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-a");
        builder.add_pack(b"pack-b");

        builder.add_object([0x11; 20], 0, 100);
        builder.add_object([0x22; 20], 1, 200);
        builder.add_object([0x33; 20], 1, 300);

        let data = builder.build();
        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let index = OidIndex::from_midx(&midx);

        for idx in 0..midx.object_count() {
            let oid = OidBytes::from_slice(midx.oid_at(idx));
            assert_eq!(index.get(&oid), Some(idx));
        }

        let missing = OidBytes::sha1([0x44; 20]);
        assert_eq!(index.get(&missing), None);
    }
}
