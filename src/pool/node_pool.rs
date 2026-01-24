//! Pre-allocated fixed-size node pool for LSM tree structures.
//!
//! Avoids per-node allocation overhead by pre-allocating a contiguous buffer and
//! tracking free slots via bitset. This gives O(1) acquire/release and enables
//! memory budgeting upfront. Panics on drop if nodes are leaked to catch bugs early.

use std::{
    alloc::{alloc, dealloc, handle_alloc_error, Layout},
    ptr::NonNull,
};

use crate::stdx::DynamicBitSet;

/// Fixed-size node memory pool.
///
/// Acquired nodes must be released exactly once. Panics on exhaustion or double-free
/// rather than returning errors - memory issues in LSM structures are fatal.
pub trait NodePool {
    /// Node size in bytes. Must be power of two and multiple of `NODE_ALIGNMENT`.
    const NODE_SIZE: usize;
    /// Node alignment in bytes. Must be power of two and <= 4096.
    const NODE_ALIGNMENT: usize;

    fn acquire(&mut self) -> NonNull<u8>;
    fn release(&mut self, node: NonNull<u8>);
}

/// Pre-allocated node pool backed by contiguous buffer and bitset.
///
/// Uses a bitset where set bits indicate free nodes, enabling O(1) first-fit allocation.
/// Panics on drop if any nodes weren't released - intentional leak detection.
pub struct NodePoolType<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> {
    buffer: NonNull<u8>,
    len: usize,
    free: DynamicBitSet,
}

impl<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> NodePoolType<NODE_SIZE, NODE_ALIGNMENT> {
    pub const NODE_SIZE: usize = NODE_SIZE;
    pub const NODE_ALIGNMENT: usize = NODE_ALIGNMENT;

    /// Creates pool with capacity for `node_count` nodes.
    ///
    /// All memory is allocated upfront to enable budgeting and avoid runtime allocation
    /// failures during critical operations.
    pub fn init(node_count: u32) -> Self {
        assert!(node_count > 0);
        Self::assert_layout();

        let size = NODE_SIZE
            .checked_mul(node_count as usize)
            .expect("node buffer size overflow");
        let layout = Layout::from_size_align(size, NODE_ALIGNMENT)
            .unwrap_or_else(|_| panic!("invalid layout size"));

        // SAFETY: Layout validated above; null checked via NonNull::new.
        let raw = unsafe { alloc(layout) };
        let buffer = NonNull::new(raw).unwrap_or_else(|| handle_alloc_error(layout));

        let mut free = DynamicBitSet::empty(node_count as usize);
        Self::set_all(&mut free);

        Self {
            buffer,
            len: size,
            free,
        }
    }

    /// Explicitly deallocates the pool. Idempotent.
    ///
    /// Panics if nodes weren't released - this catches leaks during development.
    pub fn deinit(&mut self) {
        self.deinit_internal(true);
    }

    /// Marks all nodes as free without deallocating the buffer.
    ///
    /// Useful for bulk reset scenarios. Invalidates all outstanding node pointers.
    pub fn reset(&mut self) {
        Self::set_all(&mut self.free);
    }

    /// Returns pointer to an uninitialized node.
    ///
    /// Panics on exhaustion rather than returning an error - running out of nodes
    /// indicates a configuration issue that should fail fast.
    pub fn acquire(&mut self) -> NonNull<u8> {
        let node_index = Self::find_first_set(&self.free)
            .unwrap_or_else(|| panic!("node pool exhausted; increase pool capacity"));
        assert!(self.free.is_set(node_index));
        self.free.unset(node_index);

        let offset = node_index * NODE_SIZE;
        assert!(offset + NODE_SIZE <= self.len);

        // SAFETY: Offset bounds verified by assertion above.
        unsafe { NonNull::new_unchecked(self.buffer.as_ptr().add(offset)) }
    }

    /// Returns a node to the pool.
    ///
    /// Validates the pointer came from this pool and wasn't already released.
    /// These checks catch use-after-free and double-free bugs immediately.
    pub fn release(&mut self, node: NonNull<u8>) {
        let base = self.buffer.as_ptr() as usize;
        let ptr = node.as_ptr() as usize;

        assert!(ptr >= base);
        assert!(ptr + NODE_SIZE <= base + self.len);

        let node_offset = ptr - base;
        assert!(node_offset.is_multiple_of(NODE_SIZE));

        let node_index = node_offset / NODE_SIZE;
        assert!(!self.free.is_set(node_index));
        self.free.set(node_index);
    }

    fn assert_layout() {
        assert!(NODE_SIZE > 0);
        assert!(NODE_ALIGNMENT > 0);
        assert!(NODE_ALIGNMENT <= 4096);
        assert!(NODE_SIZE.is_power_of_two());
        assert!(NODE_ALIGNMENT.is_power_of_two());
        assert!(NODE_SIZE.is_multiple_of(NODE_ALIGNMENT));
    }

    fn deinit_internal(&mut self, verify_free: bool) {
        if self.len == 0 {
            return;
        }

        if verify_free {
            assert_eq!(self.free.count(), self.free.bit_length());
        }

        let layout = Layout::from_size_align(self.len, NODE_ALIGNMENT)
            .unwrap_or_else(|_| panic!("invalid layout"));

        // SAFETY: Same layout as alloc; len != 0 check prevents double-free.
        unsafe {
            dealloc(self.buffer.as_ptr(), layout);
        }

        self.buffer = NonNull::dangling();
        self.len = 0;
        self.free = DynamicBitSet::empty(0);
    }

    fn set_all(bits: &mut DynamicBitSet) {
        bits.clear();
        bits.toggle_all();
    }

    fn find_first_set(bits: &DynamicBitSet) -> Option<usize> {
        bits.iter_set().next()
    }
}

impl<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> NodePool
    for NodePoolType<NODE_SIZE, NODE_ALIGNMENT>
{
    const NODE_SIZE: usize = NODE_SIZE;
    const NODE_ALIGNMENT: usize = NODE_ALIGNMENT;

    #[inline]
    fn acquire(&mut self) -> NonNull<u8> {
        NodePoolType::acquire(self)
    }

    #[inline]
    fn release(&mut self, ptr: NonNull<u8>) {
        NodePoolType::release(self, ptr)
    }
}

impl<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> Drop
    for NodePoolType<NODE_SIZE, NODE_ALIGNMENT>
{
    fn drop(&mut self) {
        self.deinit_internal(true);
    }
}

#[cfg(test)]
mod tests {
    use super::NodePoolType;
    use std::{mem, ptr::NonNull, slice};

    #[derive(Clone)]
    struct Prng {
        s: [u64; 4],
    }

    impl Prng {
        fn from_seed(seed: u64) -> Self {
            let mut state = seed;
            Self {
                s: [
                    Self::splitmix64(&mut state),
                    Self::splitmix64(&mut state),
                    Self::splitmix64(&mut state),
                    Self::splitmix64(&mut state),
                ],
            }
        }

        fn splitmix64(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }

        fn next_u64(&mut self) -> u64 {
            let result = (self.s[0].wrapping_add(self.s[3]))
                .rotate_left(23)
                .wrapping_add(self.s[0]);
            let t = self.s[1] << 17;

            self.s[2] ^= self.s[0];
            self.s[3] ^= self.s[1];
            self.s[1] ^= self.s[2];
            self.s[0] ^= self.s[3];
            self.s[2] ^= t;
            self.s[3] = self.s[3].rotate_left(45);

            result
        }

        fn int_inclusive_u64(&mut self, max: u64) -> u64 {
            if max == u64::MAX {
                return self.next_u64();
            }

            let less_than = max + 1;
            let mut x = self.next_u64();
            let mut m = (x as u128) * (less_than as u128);
            let mut l = m as u64;
            if l < less_than {
                let mut t = less_than.wrapping_neg();
                if t >= less_than {
                    t = t.wrapping_sub(less_than);
                    if t >= less_than {
                        t %= less_than;
                    }
                }
                while l < t {
                    x = self.next_u64();
                    m = (x as u128) * (less_than as u128);
                    l = m as u64;
                }
            }
            (m >> 64) as u64
        }

        fn index(&mut self, len: usize) -> usize {
            assert!(len > 0);
            self.int_inclusive_u64(len as u64 - 1) as usize
        }
    }

    #[derive(Copy, Clone)]
    enum Action {
        Acquire,
        Release,
    }

    struct TestContext<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> {
        node_count: usize,
        sentinel: u64,
        node_pool: NodePoolType<NODE_SIZE, NODE_ALIGNMENT>,
        nodes: Vec<(NonNull<u8>, u64)>,
        acquires: u64,
        releases: u64,
    }

    impl<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> TestContext<NODE_SIZE, NODE_ALIGNMENT> {
        fn init(prng: &mut Prng, node_count: u32) -> Self {
            let node_pool = NodePoolType::<NODE_SIZE, NODE_ALIGNMENT>::init(node_count);
            let sentinel = prng.next_u64();
            assert!(NODE_ALIGNMENT >= mem::align_of::<u64>());
            assert_eq!(NODE_SIZE % mem::size_of::<u64>(), 0);

            let mut context = Self {
                node_count: node_count as usize,
                sentinel,
                node_pool,
                nodes: Vec::new(),
                acquires: 0,
                releases: 0,
            };
            context.fill_buffer();
            context
        }

        fn run(&mut self, prng: &mut Prng) {
            for _ in 0..self.node_count * 4 {
                match Self::choose_action(prng, 60, 40) {
                    Action::Acquire => self.acquire(prng),
                    Action::Release => self.release(prng),
                }
            }

            for _ in 0..self.node_count * 4 {
                match Self::choose_action(prng, 40, 60) {
                    Action::Acquire => self.acquire(prng),
                    Action::Release => self.release(prng),
                }
            }

            self.release_all(prng);
        }

        fn acquire(&mut self, prng: &mut Prng) {
            if self.nodes.len() == self.node_count {
                return;
            }

            let node = self.node_pool.acquire();
            assert!(self.nodes.iter().all(|(ptr, _)| *ptr != node));

            unsafe {
                let words = Self::node_as_u64_slice(node);
                for &word in words.iter() {
                    assert_eq!(self.sentinel, word);
                }
                let id = prng.next_u64();
                for word in words.iter_mut() {
                    *word = id;
                }
                self.nodes.push((node, id));
            }

            self.acquires += 1;
        }

        fn release(&mut self, prng: &mut Prng) {
            if self.nodes.is_empty() {
                return;
            }

            let index = prng.index(self.nodes.len());
            let (node, id) = self.nodes[index];

            unsafe {
                let words = Self::node_as_u64_slice(node);
                for &word in words.iter() {
                    assert_eq!(id, word);
                }
                for word in words.iter_mut() {
                    *word = self.sentinel;
                }
            }

            self.node_pool.release(node);
            self.nodes.swap_remove(index);
            self.releases += 1;
        }

        fn release_all(&mut self, prng: &mut Prng) {
            while !self.nodes.is_empty() {
                self.release(prng);
            }

            let sentinel = self.sentinel;
            unsafe {
                let words = self.buffer_as_u64_slice();
                for &word in words.iter() {
                    assert_eq!(sentinel, word);
                }
            }

            assert!(self.acquires > 0);
            assert_eq!(self.acquires, self.releases);
        }

        fn choose_action(prng: &mut Prng, acquire_weight: u64, release_weight: u64) -> Action {
            let total = acquire_weight + release_weight;
            let pick = prng.int_inclusive_u64(total - 1);
            if pick < acquire_weight {
                Action::Acquire
            } else {
                Action::Release
            }
        }

        fn fill_buffer(&mut self) {
            let sentinel = self.sentinel;
            unsafe {
                let words = self.buffer_as_u64_slice();
                for word in words.iter_mut() {
                    *word = sentinel;
                }
            }
        }

        unsafe fn buffer_as_u64_slice(&mut self) -> &mut [u64] {
            // Safety: buffer is aligned and sized for u64 access in these tests.
            let bytes = self.node_pool.len;
            assert_eq!(bytes % mem::size_of::<u64>(), 0);
            unsafe {
                slice::from_raw_parts_mut(
                    self.node_pool.buffer.as_ptr() as *mut u64,
                    bytes / mem::size_of::<u64>(),
                )
            }
        }

        unsafe fn node_as_u64_slice<'a>(node: NonNull<u8>) -> &'a mut [u64] {
            // Safety: node is aligned and sized for u64 access in these tests.
            unsafe {
                slice::from_raw_parts_mut(
                    node.as_ptr() as *mut u64,
                    NODE_SIZE / mem::size_of::<u64>(),
                )
            }
        }
    }

    fn run_for<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize>(prng: &mut Prng) {
        let mut node_count: u32 = 1;
        while node_count < 64 {
            let mut context = TestContext::<NODE_SIZE, NODE_ALIGNMENT>::init(prng, node_count);
            context.run(prng);
            node_count += 1;
        }
    }

    #[test]
    fn node_pool() {
        let mut prng = Prng::from_seed(42);
        run_for::<8, 8>(&mut prng);
        run_for::<16, 8>(&mut prng);
        run_for::<64, 8>(&mut prng);
        run_for::<16, 16>(&mut prng);
        run_for::<32, 16>(&mut prng);
        run_for::<128, 16>(&mut prng);
    }
}
