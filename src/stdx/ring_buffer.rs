//! Fixed-capacity ring buffer with stack-allocated storage and `MaybeUninit<T>`.
//!
//! # Invariants
//! - `N` is a power of 2 and fits in `u32` (validated at compile time).
//! - `head < capacity` and `len <= capacity`.
//! - Slots in the logical range `[head, head + len)` (wrapping by mask) are
//!   initialized; all other slots are uninitialized.
//!
//! # Threading
//! This type is not synchronized; it assumes single-threaded usage.

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
/// Design intent:
/// - Explicit, compile-time capacity so backpressure is deterministic.
/// - Zero heap allocations in the hot path (storage is `[MaybeUninit<T>; N]`).
/// - Simple head/len bookkeeping so operations are branch-light and predictable.
///
/// **Performance note**: Capacity `N` must be a power of 2. This enables
/// single-cycle bitwise AND for index calculation instead of expensive
/// division/modulo operations.
///
/// This is a single-producer/single-consumer style queue in the pipeline, but
/// the implementation itself is not synchronized; it relies on single-threaded
/// usage. Insertion past capacity is a logic error unless handled via `push_back`.
///
/// # Invariants
/// - `head` always indexes the logical front.
/// - `len` tracks the number of initialized elements.
/// - The element at logical index `i` lives at `(head + i) & MASK`.
pub struct RingBuffer<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    head: u32,
    len: u32,
}

/// Create an uninitialized `[MaybeUninit<T>; N]` without running any constructors.
fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> RingBuffer<T, N> {
    const CAPACITY: u32 = {
        assert!(N > 0, "RingBuffer capacity must be > 0");
        assert!(N & (N - 1) == 0, "RingBuffer capacity must be power of 2");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Bitmask for power-of-2 modulo: (head + len) & MASK == (head + len) % CAPACITY
    const MASK: u32 = Self::CAPACITY - 1;

    /// Constructs an empty ring buffer with capacity `N` without heap allocation.
    pub fn new() -> Self {
        let _ = Self::CAPACITY;

        let ring = Self {
            buf: uninit_array(),
            head: 0,
            len: 0,
        };

        debug_assert!(ring.len == 0);
        debug_assert!(ring.head == 0);

        ring
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
    #[inline]
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
    /// Panics in debug builds if the buffer is full. Use `push_back` when the
    /// caller cannot guarantee capacity.
    #[inline]
    pub fn push_back_assume_capacity(&mut self, value: T) {
        debug_assert!(
            self.len < Self::CAPACITY,
            "push_back_assume_capacity called on full buffer"
        );
        debug_assert!(self.head < Self::CAPACITY, "head out of bounds");

        // PERF: Uses bitwise AND instead of modulo for power-of-2 capacity.
        // This compiles to a single AND instruction vs expensive div/mul sequence.
        let tail = (self.head + self.len) & Self::MASK;

        debug_assert!(tail < Self::CAPACITY, "tail out of bounds");

        // SAFETY: tail < CAPACITY guaranteed by mask operation on power-of-2 capacity.
        // The mask ensures the result is always in [0, CAPACITY).
        unsafe { self.buf.get_unchecked_mut(index(tail)).write(value) };
        self.len += 1;

        debug_assert!(self.len <= Self::CAPACITY);
    }

    /// Removes and returns the oldest element, or `None` when empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        debug_assert!(self.len > 0);
        debug_assert!(self.head < Self::CAPACITY, "head out of bounds");

        let idx = self.head;

        // SAFETY: idx < CAPACITY proven by invariant, element initialized because len > 0
        let value = unsafe { self.buf.get_unchecked(index(idx)).as_ptr().read() };

        // PERF: Uses bitwise AND instead of modulo.
        self.head = (self.head + 1) & Self::MASK;
        self.len -= 1;

        debug_assert!(self.head < Self::CAPACITY);

        Some(value)
    }

    /// Removes all elements, dropping them in FIFO order.
    ///
    /// Buffer remains usable afterwards without reallocating. The drop path
    /// walks either one contiguous region or two wrapped regions to preserve
    /// FIFO order.
    pub fn clear(&mut self) {
        if self.len == 0 {
            return;
        }

        let head = self.head as usize;
        let len = self.len as usize;

        if head + len <= N {
            // Contiguous region: [head..head+len]
            for i in head..head + len {
                // SAFETY: All elements in [head, head+len) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
        } else {
            // Wrapped region: [head..N] + [0..wrap_len]
            let wrap_len = (head + len) - N;

            for i in head..N {
                // SAFETY: Elements in [head, N) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
            for i in 0..wrap_len {
                // SAFETY: Elements in [0, wrap_len) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
        }

        self.head = 0;
        self.len = 0;

        debug_assert!(self.is_empty());
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
        debug_assert!(self.len == 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Drop tracker — detects double-drop, leak, and use-after-free under Miri.
    // -----------------------------------------------------------------------
    #[derive(Debug)]
    struct DropTracker(Arc<AtomicUsize>);

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dt(c: &Arc<AtomicUsize>) -> DropTracker {
        DropTracker(c.clone())
    }

    // -----------------------------------------------------------------------
    // Basic push/pop — exercises get_unchecked write + as_ptr().read().
    // -----------------------------------------------------------------------

    #[test]
    fn empty_pop_returns_none() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.pop_front(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn push_then_pop() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert!(ring.push_back(42).is_ok());
        assert_eq!(ring.pop_front(), Some(42));
        assert!(ring.is_empty());
    }

    #[test]
    fn fifo_ordering() {
        let mut ring = RingBuffer::<u32, 4>::new();
        for i in 0..4 {
            assert!(ring.push_back(i).is_ok());
        }
        assert!(ring.is_full());
        for i in 0..4 {
            assert_eq!(ring.pop_front(), Some(i));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn push_when_full_returns_err() {
        let mut ring = RingBuffer::<u32, 2>::new();
        assert!(ring.push_back(1).is_ok());
        assert!(ring.push_back(2).is_ok());
        assert_eq!(ring.push_back(3), Err(3));
    }

    // -----------------------------------------------------------------------
    // Wraparound — exercises index masking across the buffer boundary.
    // -----------------------------------------------------------------------

    #[test]
    fn wraparound_correctness() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Fill and drain multiple times to force head past capacity.
        for round in 0..10u32 {
            let base = round * 4;
            for i in 0..4 {
                assert!(ring.push_back(base + i).is_ok());
            }
            for i in 0..4 {
                assert_eq!(ring.pop_front(), Some(base + i));
            }
        }
    }

    #[test]
    fn partial_fill_drain_wraparound() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Push 3, pop 2 — head advances to 2.
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        assert_eq!(ring.pop_front(), Some(10));
        assert_eq!(ring.pop_front(), Some(20));

        // Push 3 more — tail wraps around: slots [2,3,0] used.
        ring.push_back(40).unwrap();
        ring.push_back(50).unwrap();
        ring.push_back(60).unwrap();
        assert!(ring.is_full());

        // Drain in order.
        assert_eq!(ring.pop_front(), Some(30));
        assert_eq!(ring.pop_front(), Some(40));
        assert_eq!(ring.pop_front(), Some(50));
        assert_eq!(ring.pop_front(), Some(60));
        assert!(ring.is_empty());
    }

    // -----------------------------------------------------------------------
    // Drop — exercises the contiguous and wrapped drop paths.
    // -----------------------------------------------------------------------

    #[test]
    fn drop_contiguous_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = RingBuffer::<DropTracker, 4>::new();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            // head=0, len=3 → contiguous region [0,1,2].
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_wrapped_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = RingBuffer::<DropTracker, 4>::new();
            // Fill and pop 2 to advance head to 2.
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            assert!(ring.pop_front().is_some());
            assert!(ring.pop_front().is_some());
            assert_eq!(drops.load(Ordering::Relaxed), 2); // 2 popped

            // Fill 4 more — wraps: head=2, slots [2,3,0,1].
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            assert!(ring.is_full());
            // Drop with wrapped region: [2..4) + [0..2).
        }
        // 2 popped + 4 dropped by Drop = 6 total.
        assert_eq!(drops.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn drop_empty_is_noop() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let _ring = RingBuffer::<DropTracker, 4>::new();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    // -----------------------------------------------------------------------
    // Clear — exercises both contiguous and wrapped clear paths + reuse.
    // -----------------------------------------------------------------------

    #[test]
    fn clear_contiguous() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ring = RingBuffer::<DropTracker, 4>::new();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn clear_wrapped() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ring = RingBuffer::<DropTracker, 4>::new();
        // Advance head to 3.
        for _ in 0..3 {
            ring.push_back(dt(&drops)).unwrap();
            ring.pop_front();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);

        // Now push 4 — wraps: head=3, slots [3,0,1,2].
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.clear();
        // 3 from pops + 4 from clear = 7.
        assert_eq!(drops.load(Ordering::Relaxed), 7);
        assert!(ring.is_empty());
    }

    #[test]
    fn clear_then_reuse() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.clear();

        // Reuse after clear.
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        assert_eq!(ring.pop_front(), Some(10));
        assert_eq!(ring.pop_front(), Some(20));
        assert_eq!(ring.pop_front(), Some(30));
    }

    #[test]
    fn clear_empty_is_noop() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.clear(); // should not panic or UB.
        assert!(ring.is_empty());
    }

    // -----------------------------------------------------------------------
    // push_back_assume_capacity — exercises the unchecked fast path.
    // -----------------------------------------------------------------------

    #[test]
    fn push_back_assume_capacity_fifo() {
        let mut ring = RingBuffer::<u64, 8>::new();
        for i in 0..8 {
            ring.push_back_assume_capacity(i);
        }
        for i in 0..8 {
            assert_eq!(ring.pop_front(), Some(i));
        }
    }
}
