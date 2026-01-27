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
    // Bitset of free slots. A set bit means "available".
    // This is inverted from typical "in-use" tracking because it makes
    // "find first free" a fast "find first set" operation.
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

#[cfg(all(test, feature = "stdx-proptest"))]
mod tests {
    use super::NodePoolType;
    use proptest::prelude::*;
    use std::{mem, ptr::NonNull, slice};

    const PROPTEST_CASES: u32 = 256;
    const SENTINEL: u64 = 0xDEAD_BEEF_CAFE_BABE;

    #[derive(Debug, Clone)]
    enum Op {
        Acquire,
        Release(usize),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            2 => Just(Op::Acquire),
            1 => (0usize..64).prop_map(Op::Release),
        ]
    }

    struct TestContext<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> {
        node_pool: NodePoolType<NODE_SIZE, NODE_ALIGNMENT>,
        held: Vec<(NonNull<u8>, u64)>,
        node_count: usize,
        next_id: u64,
    }

    impl<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize> TestContext<NODE_SIZE, NODE_ALIGNMENT> {
        fn new(node_count: u32) -> Self {
            assert!(NODE_ALIGNMENT >= mem::align_of::<u64>());
            assert_eq!(NODE_SIZE % mem::size_of::<u64>(), 0);

            let pool = NodePoolType::<NODE_SIZE, NODE_ALIGNMENT>::init(node_count);

            // Fill entire buffer with sentinel
            unsafe {
                let bytes = pool.len;
                let words = slice::from_raw_parts_mut(
                    pool.buffer.as_ptr() as *mut u64,
                    bytes / mem::size_of::<u64>(),
                );
                for word in words.iter_mut() {
                    *word = SENTINEL;
                }
            }

            Self {
                node_pool: pool,
                held: Vec::new(),
                node_count: node_count as usize,
                next_id: 1,
            }
        }

        fn acquire(&mut self) -> bool {
            if self.held.len() >= self.node_count {
                return false;
            }

            let node = self.node_pool.acquire();

            // Verify no duplicate pointers
            assert!(
                self.held.iter().all(|(ptr, _)| *ptr != node),
                "duplicate node pointer returned"
            );

            // Verify sentinel pattern
            unsafe {
                let words = Self::node_as_u64_slice(node);
                for &word in words.iter() {
                    assert_eq!(SENTINEL, word, "node memory corrupted: expected sentinel");
                }

                // Fill with unique ID
                let id = self.next_id;
                self.next_id += 1;
                for word in words.iter_mut() {
                    *word = id;
                }
                self.held.push((node, id));
            }
            true
        }

        fn release(&mut self, index: usize) -> bool {
            if self.held.is_empty() {
                return false;
            }

            let idx = index % self.held.len();
            let (node, id) = self.held[idx];

            unsafe {
                let words = Self::node_as_u64_slice(node);

                // Verify content integrity
                for &word in words.iter() {
                    assert_eq!(id, word, "node memory corrupted: expected id {}", id);
                }

                // Restore sentinel
                for word in words.iter_mut() {
                    *word = SENTINEL;
                }
            }

            self.node_pool.release(node);
            self.held.swap_remove(idx);
            true
        }

        fn release_all(&mut self) {
            while !self.held.is_empty() {
                self.release(0);
            }
        }

        fn verify_all_released(&mut self) {
            assert!(self.held.is_empty(), "not all nodes released");

            // Verify entire buffer is sentinel
            unsafe {
                let bytes = self.node_pool.len;
                let words = slice::from_raw_parts(
                    self.node_pool.buffer.as_ptr() as *const u64,
                    bytes / mem::size_of::<u64>(),
                );
                for &word in words.iter() {
                    assert_eq!(SENTINEL, word, "buffer not fully restored to sentinel");
                }
            }
        }

        unsafe fn node_as_u64_slice<'a>(node: NonNull<u8>) -> &'a mut [u64] {
            unsafe {
                slice::from_raw_parts_mut(
                    node.as_ptr() as *mut u64,
                    NODE_SIZE / mem::size_of::<u64>(),
                )
            }
        }
    }

    fn run_ops<const NODE_SIZE: usize, const NODE_ALIGNMENT: usize>(node_count: u32, ops: Vec<Op>) {
        let mut ctx = TestContext::<NODE_SIZE, NODE_ALIGNMENT>::new(node_count);
        let mut acquired = false;

        for op in ops {
            match op {
                Op::Acquire => {
                    if ctx.acquire() {
                        acquired = true;
                    }
                }
                Op::Release(idx) => {
                    ctx.release(idx);
                }
            }
        }

        // Ensure at least one acquire happened
        if !acquired {
            ctx.acquire();
        }

        ctx.release_all();
        ctx.verify_all_released();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_node_pool_8_8(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<8, 8>(node_count, ops);
        }

        #[test]
        fn prop_node_pool_16_8(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<16, 8>(node_count, ops);
        }

        #[test]
        fn prop_node_pool_64_8(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<64, 8>(node_count, ops);
        }

        #[test]
        fn prop_node_pool_16_16(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<16, 16>(node_count, ops);
        }

        #[test]
        fn prop_node_pool_32_16(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<32, 16>(node_count, ops);
        }

        #[test]
        fn prop_node_pool_128_16(
            node_count in 1u32..64,
            ops in prop::collection::vec(op_strategy(), 1..256)
        ) {
            run_ops::<128, 16>(node_count, ops);
        }
    }
}
