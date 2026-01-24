#![allow(dead_code)] // API is exercised in tests; main wiring is pending.

use std::mem::MaybeUninit;

// Compile-time proof that u32 -> usize is safe on this platform.
// This fails to compile on 16-bit platforms.
const _: () = assert!(
    std::mem::size_of::<usize>() >= std::mem::size_of::<u32>(),
    "Platform must have at least 32-bit addressing"
);

#[inline(always)]
fn index(i: u32) -> usize {
    i as usize
}

/// Fixed-capacity ring buffer backed by stack-allocated storage.
///
/// Values are stored in-place using `MaybeUninit` so no heap allocation is
/// required. Capacity is a const generic known at compile time; insertion past
/// capacity is a logic error unless handled via `push_back`.
pub struct RingBuffer<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    head: u32,
    len: u32,
}

fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> RingBuffer<T, N> {
    const CAPACITY: u32 = {
        assert!(N > 0, "RingBuffer capacity must be > 0");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Constructs an empty ring buffer with capacity `N` without heap
    /// allocation.
    pub fn new() -> Self {
        let _ = Self::CAPACITY;

        let ring = Self {
            buf: uninit_array(),
            head: 0,
            len: 0,
        };

        assert!(ring.len == 0);
        assert!(ring.head == 0);

        ring
    }

    #[inline]
    pub fn capacity(&self) -> u32 {
        Self::CAPACITY
    }

    /// Number of initialized elements currently stored.
    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Returns true when no elements are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true when `len == capacity`.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == Self::CAPACITY
    }

    /// Attempts to append `value`, returning `Err(value)` if the buffer is
    /// already full.
    ///
    /// This keeps ownership with the caller on overflow instead of dropping
    /// silently.
    pub fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        self.push_back_assume_capacity(value);
        Ok(())
    }

    /// Appends `value` assuming spare capacity exists.
    ///
    /// # Panics
    ///
    /// Panics (debug-asserts) if the buffer is full. Use `push_back` when the
    /// caller cannot guarantee capacity.
    pub fn push_back_assume_capacity(&mut self, value: T) {
        assert!(self.len < Self::CAPACITY);
        assert!(self.head < Self::CAPACITY);

        let tail = (self.head + self.len) % Self::CAPACITY;

        assert!(tail < Self::CAPACITY);
        assert!(self.len < Self::CAPACITY);

        self.buf[index(tail)].write(value);
        self.len += 1;

        assert!(self.len <= Self::CAPACITY);
        assert!(self.len > 0);
    }

    /// Removes and returns the oldest element, or `None` when empty.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        assert!(self.len > 0);
        assert!(self.head <= Self::CAPACITY);

        let idx = self.head;
        assert!(idx < Self::CAPACITY);

        // SAFETY: idx < CAPACITY proven, element initialized because len > 0
        let value = unsafe { self.buf[index(idx)].as_ptr().read() };

        self.head = (self.head + 1) % Self::CAPACITY;
        self.len -= 1;

        assert!(self.head < Self::CAPACITY);

        Some(value)
    }

    /// Borrows the oldest element without removal.
    pub fn front(&self) -> Option<&T> {
        if self.is_empty() {
            return None;
        }

        assert!(self.len > 0);
        assert!(self.head <= Self::CAPACITY);

        let idx = self.head;
        assert!(idx < Self::CAPACITY);

        // SAFETY: idx < CAPACITY proven, element initialized because len > 0
        Some(unsafe { &*self.buf[index(idx)].as_ptr() })
    }

    /// Mutably borrows the oldest element without removal.
    ///
    /// Useful for in-place updates while preserving position.
    pub fn front_mut(&mut self) -> Option<&mut T> {
        if self.is_empty() {
            return None;
        }

        assert!(self.len > 0);
        assert!(self.head <= Self::CAPACITY);

        let idx = self.head;
        assert!(idx < Self::CAPACITY);

        // SAFETY: idx < CAPACITY proven, element initialized because len > 0
        Some(unsafe { &mut *self.buf[index(idx)].as_mut_ptr() })
    }

    /// Returns a reference to the element at logical index `logical_idx`.
    ///
    /// Index `0` refers to the current front; indices grow toward the back,
    /// even after wraparound.
    pub fn get(&self, logical_idx: u32) -> Option<&T> {
        if logical_idx >= self.len {
            return None;
        }

        assert!(logical_idx < self.len);
        assert!(self.head < Self::CAPACITY);
        assert!(self.len <= Self::CAPACITY);

        let idx = (self.head + logical_idx) % Self::CAPACITY;
        assert!(idx < Self::CAPACITY);

        // SAFETY: idx < CAPACITY proven, element initialized because len > 0
        Some(unsafe { &*self.buf[index(idx)].as_ptr() })
    }

    /// Returns a mutable reference to the element at logical index `logical_idx`.
    ///
    /// Indexing semantics mirror `get`; callers can update values in place
    /// without changing ordering.
    pub fn get_mut(&mut self, logical_idx: u32) -> Option<&mut T> {
        if logical_idx >= self.len {
            return None;
        }

        assert!(logical_idx < self.len);
        assert!(self.head < Self::CAPACITY);
        assert!(self.len <= Self::CAPACITY);

        let idx = (self.head + logical_idx) % Self::CAPACITY;
        assert!(idx < Self::CAPACITY);

        // SAFETY: idx < CAPACITY proven, element initialized because len > 0
        Some(unsafe { &mut *self.buf[index(idx)].as_mut_ptr() })
    }

    /// Removes all elements, dropping them in FIFO order.
    ///
    /// Buffer remains usable afterwards without reallocating.
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}

        assert!(self.len == 0);
        assert!(self.is_empty());
    }
}

impl<T, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for RingBuffer<T, N> {
    fn drop(&mut self) {
        self.clear();
        assert!(self.len == 0);
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod tests {
    use super::RingBuffer;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 16;

    #[derive(Debug)]
    struct DropTracker {
        value: i32,
        drops: Rc<Cell<usize>>,
    }

    impl DropTracker {
        fn new(value: i32, drops: Rc<Cell<usize>>) -> Self {
            Self { value, drops }
        }
    }

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn new_buffer_is_empty_with_correct_capacity() {
        let mut rb: RingBuffer<i32, 8> = RingBuffer::new();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.capacity(), 8);
        assert_eq!(rb.front(), None);
        assert_eq!(rb.pop_front(), None);
    }

    #[test]
    fn default_creates_empty_buffer() {
        let rb: RingBuffer<i32, 4> = RingBuffer::default();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.capacity(), 4);
    }

    #[test]
    fn operations_on_empty_buffer_return_none() {
        let mut rb: RingBuffer<i32, 4> = RingBuffer::new();
        assert_eq!(rb.pop_front(), None);
        assert_eq!(rb.front(), None);
        assert_eq!(rb.front_mut(), None);
        assert_eq!(rb.get(0), None);
        assert_eq!(rb.get_mut(0), None);
        // Verify buffer is still usable after operations on empty
        rb.push_back_assume_capacity(42);
        assert_eq!(rb.front(), Some(&42));
    }

    #[test]
    fn basic_push_pop() {
        let mut rb: RingBuffer<i32, 4> = RingBuffer::new();
        assert!(rb.is_empty());
        rb.push_back_assume_capacity(1);
        rb.push_back_assume_capacity(2);
        rb.push_back_assume_capacity(3);
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.front(), Some(&1));
        assert_eq!(rb.pop_front(), Some(1));
        assert_eq!(rb.pop_front(), Some(2));
        assert_eq!(rb.pop_front(), Some(3));
        assert_eq!(rb.pop_front(), None);
        assert!(rb.is_empty());
    }

    #[test]
    fn wraparound() {
        let mut rb: RingBuffer<i32, 3> = RingBuffer::new();
        rb.push_back_assume_capacity(1);
        rb.push_back_assume_capacity(2);
        assert_eq!(rb.pop_front(), Some(1));
        rb.push_back_assume_capacity(3);
        rb.push_back_assume_capacity(4);
        // Now buffer is full: contents [2,3,4]
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.front(), Some(&2));
        assert_eq!(rb.get(0), Some(&2));
        assert_eq!(rb.get(1), Some(&3));
        assert_eq!(rb.get(2), Some(&4));
    }

    #[test]
    fn get_mut_wraparound_updates_correct_slot() {
        let mut rb: RingBuffer<i32, 3> = RingBuffer::new();
        rb.push_back_assume_capacity(10);
        rb.push_back_assume_capacity(20);
        assert_eq!(rb.pop_front(), Some(10));
        rb.push_back_assume_capacity(30);
        rb.push_back_assume_capacity(40);

        if let Some(elem) = rb.get_mut(1) {
            *elem += 1;
        }

        assert_eq!(rb.get(0), Some(&20));
        assert_eq!(rb.get(1), Some(&31));
        assert_eq!(rb.get(2), Some(&40));
    }

    #[test]
    fn front_mut_allows_in_place_update() {
        let mut rb: RingBuffer<i32, 2> = RingBuffer::new();
        rb.push_back_assume_capacity(5);
        rb.push_back_assume_capacity(6);

        if let Some(front) = rb.front_mut() {
            *front *= 2;
        }

        assert_eq!(rb.front(), Some(&10));
        assert_eq!(rb.pop_front(), Some(10));
        assert_eq!(rb.pop_front(), Some(6));
    }

    #[test]
    fn clear_drops_elements_and_allows_reuse() {
        let drops = Rc::new(Cell::new(0));
        {
            let mut rb: RingBuffer<DropTracker, 3> = RingBuffer::new();
            rb.push_back_assume_capacity(DropTracker::new(1, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(2, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(3, Rc::clone(&drops)));

            rb.clear();

            assert_eq!(drops.get(), 3);
            assert!(rb.is_empty());

            rb.push_back_assume_capacity(DropTracker::new(4, Rc::clone(&drops)));
            assert_eq!(rb.len(), 1);
            assert_eq!(rb.front().map(|t| t.value), Some(4));
        }
        // Drop should also clear any remaining elements.
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn drop_clears_elements_with_head_offset() {
        let drops = Rc::new(Cell::new(0));
        {
            let mut rb: RingBuffer<DropTracker, 4> = RingBuffer::new();
            rb.push_back_assume_capacity(DropTracker::new(1, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(2, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(3, Rc::clone(&drops)));

            // Advance head so Drop must walk from a non-zero offset.
            drop(rb.pop_front());

            // Remaining elements should be released when rb drops.
            assert_eq!(drops.get(), 1);
        }

        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn drop_with_buffer_in_wrapped_state() {
        let drops = Rc::new(Cell::new(0));
        {
            let mut rb: RingBuffer<DropTracker, 3> = RingBuffer::new();

            // Fill: physical [1, 2, 3], head=0, len=3
            rb.push_back_assume_capacity(DropTracker::new(1, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(2, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(3, Rc::clone(&drops)));

            // Pop two: physical [_, _, 3], head=2, len=1
            rb.pop_front(); // drops 1
            rb.pop_front(); // drops 2

            // Push two: physical [4, 5, 3], head=2, len=3 (WRAPPED: tail < head)
            rb.push_back_assume_capacity(DropTracker::new(4, Rc::clone(&drops)));
            rb.push_back_assume_capacity(DropTracker::new(5, Rc::clone(&drops)));

            assert_eq!(drops.get(), 2); // Only 1 and 2 dropped so far
            assert!(rb.is_full());

            // Verify logical order is [3, 4, 5]
            assert_eq!(rb.get(0).map(|t| t.value), Some(3));
            assert_eq!(rb.get(1).map(|t| t.value), Some(4));
            assert_eq!(rb.get(2).map(|t| t.value), Some(5));

            // Buffer drops here - must correctly drop 3, 4, 5
        }

        // All 5 elements should have been dropped exactly once
        assert_eq!(drops.get(), 5);
    }

    #[derive(Debug)]
    struct OrderTracker {
        value: i32,
        order: Rc<std::cell::RefCell<Vec<i32>>>,
    }

    impl OrderTracker {
        fn new(value: i32, order: Rc<std::cell::RefCell<Vec<i32>>>) -> Self {
            Self { value, order }
        }
    }

    impl Drop for OrderTracker {
        fn drop(&mut self) {
            self.order.borrow_mut().push(self.value);
        }
    }

    #[test]
    fn drops_occur_in_fifo_order() {
        let order = Rc::new(std::cell::RefCell::new(Vec::new()));
        {
            let mut rb: RingBuffer<OrderTracker, 3> = RingBuffer::new();
            rb.push_back_assume_capacity(OrderTracker::new(1, Rc::clone(&order)));
            rb.push_back_assume_capacity(OrderTracker::new(2, Rc::clone(&order)));
            rb.push_back_assume_capacity(OrderTracker::new(3, Rc::clone(&order)));
            // rb drops here via Drop trait
        }
        // clear() uses pop_front() which should drop in FIFO order
        assert_eq!(*order.borrow(), vec![1, 2, 3]);
    }

    #[test]
    fn drops_occur_in_fifo_order_wrapped() {
        let order = Rc::new(std::cell::RefCell::new(Vec::new()));
        {
            let mut rb: RingBuffer<OrderTracker, 3> = RingBuffer::new();
            rb.push_back_assume_capacity(OrderTracker::new(1, Rc::clone(&order)));
            rb.push_back_assume_capacity(OrderTracker::new(2, Rc::clone(&order)));
            rb.pop_front(); // drops 1
            rb.push_back_assume_capacity(OrderTracker::new(3, Rc::clone(&order)));
            rb.push_back_assume_capacity(OrderTracker::new(4, Rc::clone(&order)));
            // Buffer is wrapped: logical [2, 3, 4]
        }
        // Should drop in FIFO order: 1 (from pop), then 2, 3, 4 (from Drop)
        assert_eq!(*order.borrow(), vec![1, 2, 3, 4]);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Push(i32),
        Pop,
        Get(u8),
        Front,
        Clear,
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_sequence_matches_vecdeque(ops in prop::collection::vec(
            prop_oneof![
                any::<i32>().prop_map(Op::Push),
                Just(Op::Pop),
                any::<u8>().prop_map(Op::Get),
                Just(Op::Front),
                Just(Op::Clear),
            ],
            1..200,
        )) {
            const CAPACITY: usize = 8;

            let mut rb: RingBuffer<i32, CAPACITY> = RingBuffer::new();
            let mut dq: VecDeque<i32> = VecDeque::with_capacity(CAPACITY);

            for op in ops {
                match op {
                    Op::Push(v) => {
                        let was_full = dq.len() == CAPACITY;
                        let rb_res = rb.push_back(v);
                        if was_full {
                            prop_assert!(rb_res.is_err());
                            prop_assert_eq!(rb_res.unwrap_err(), v);
                        } else {
                            prop_assert!(rb_res.is_ok());
                            dq.push_back(v);
                        }
                    }
                    Op::Pop => {
                        prop_assert_eq!(rb.pop_front(), dq.pop_front());
                    }
                    Op::Get(idx) => {
                        let idx = (idx as usize) % (CAPACITY + 2);
                        prop_assert_eq!(rb.get(idx as u32).copied(), dq.get(idx).copied());
                    }
                    Op::Front => {
                        prop_assert_eq!(rb.front().copied(), dq.front().copied());
                    }
                    Op::Clear => {
                        rb.clear();
                        dq.clear();
                    }
                }

                prop_assert_eq!(rb.len() as usize, dq.len());
                prop_assert_eq!(rb.is_empty(), dq.is_empty());
                prop_assert_eq!(rb.is_full(), dq.len() == CAPACITY);
                prop_assert!(rb.len() <= rb.capacity());
            }
        }

        #[test]
        fn prop_sequence_capacity_one(ops in prop::collection::vec(
            prop_oneof![
                any::<i32>().prop_map(Op::Push),
                Just(Op::Pop),
                any::<u8>().prop_map(Op::Get),
                Just(Op::Front),
                Just(Op::Clear),
            ],
            1..200,
        )) {
            const CAPACITY: usize = 1;

            let mut rb: RingBuffer<i32, CAPACITY> = RingBuffer::new();
            let mut dq: VecDeque<i32> = VecDeque::with_capacity(CAPACITY);

            for op in ops {
                match op {
                    Op::Push(v) => {
                        let was_full = dq.len() == CAPACITY;
                        let rb_res = rb.push_back(v);
                        if was_full {
                            prop_assert!(rb_res.is_err());
                            prop_assert_eq!(rb_res.unwrap_err(), v);
                        } else {
                            prop_assert!(rb_res.is_ok());
                            dq.push_back(v);
                        }
                    }
                    Op::Pop => {
                        prop_assert_eq!(rb.pop_front(), dq.pop_front());
                    }
                    Op::Get(idx) => {
                        let idx = (idx as usize) % (CAPACITY + 2);
                        prop_assert_eq!(rb.get(idx as u32).copied(), dq.get(idx).copied());
                    }
                    Op::Front => {
                        prop_assert_eq!(rb.front().copied(), dq.front().copied());
                    }
                    Op::Clear => {
                        rb.clear();
                        dq.clear();
                    }
                }

                prop_assert_eq!(rb.len() as usize, dq.len());
                prop_assert_eq!(rb.is_empty(), dq.is_empty());
                prop_assert_eq!(rb.is_full(), dq.len() == CAPACITY);
                prop_assert!(rb.len() <= rb.capacity());
            }
        }
    }

    /// Property test for verifying drop count equals successful push count.
    /// Only creates DropTrackers for pushes that will succeed to avoid
    /// counting failed push attempts (which return Err(value) and drop immediately).
    #[test]
    fn prop_drop_count_matches_push_count() {
        use proptest::test_runner::{Config, TestRunner};

        #[derive(Debug, Clone)]
        enum DropOp {
            Push,
            Pop,
            Clear,
        }

        let mut runner = TestRunner::new(Config::with_cases(crate::test_utils::proptest_cases(
            PROPTEST_CASES,
        )));
        runner
            .run(
                &prop::collection::vec(
                    prop_oneof![Just(DropOp::Push), Just(DropOp::Pop), Just(DropOp::Clear),],
                    1..100,
                ),
                |ops| {
                    let drops = Rc::new(Cell::new(0usize));
                    let mut push_count = 0usize;

                    {
                        let mut rb: RingBuffer<DropTracker, 8> = RingBuffer::new();

                        for op in ops {
                            match op {
                                DropOp::Push => {
                                    // Only create DropTracker if there's capacity
                                    // to avoid counting failed push drops
                                    if !rb.is_full() {
                                        rb.push_back_assume_capacity(DropTracker::new(
                                            0,
                                            Rc::clone(&drops),
                                        ));
                                        push_count += 1;
                                    }
                                }
                                DropOp::Pop => {
                                    rb.pop_front();
                                }
                                DropOp::Clear => {
                                    rb.clear();
                                }
                            }
                        }
                        // rb drops here, remaining elements should be dropped
                    }

                    // After buffer drops, drop count must equal push count
                    prop_assert_eq!(
                        drops.get(),
                        push_count,
                        "Drop count {} != push count {}",
                        drops.get(),
                        push_count
                    );
                    Ok(())
                },
            )
            .unwrap();
    }
}
