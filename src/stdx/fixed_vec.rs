//! Fixed-capacity, stack-allocated vector for small, bounded collections.
//!
//! # Invariants
//! - `len <= N` at all times.
//! - Elements in `0..len` are initialized and valid.
//! - Elements in `len..N` are uninitialized and must never be read or dropped.
//!
//! # Design Notes
//! - Uses `MaybeUninit` to avoid `T: Default` and to skip zeroing.
//! - Overflow panics instead of allocating, keeping hot paths allocation-free.
//! - All internal `unsafe` blocks rely on the invariants above.

use std::fmt;
use std::mem::MaybeUninit;
use std::ops::Deref;

/// Fixed-capacity vector backed by an inline array.
///
/// # Guarantees
/// - Capacity is always `N`; this type never reallocates.
/// - Elements are stored contiguously and in insertion order.
///
/// # Invariants
/// - `len` tracks the initialized prefix; `len <= N`.
/// - Only `0..len` is initialized; `len..N` is uninitialized storage.
///
/// # Panics
/// - `extend_from_slice` panics if it would exceed capacity.
///
/// # Performance
/// - `extend_from_slice` is O(m) for `m` appended elements.
pub struct FixedVec<T, const N: usize> {
    // Number of initialized elements in `buf`.
    len: usize,
    // Inline storage; only `0..len` is initialized.
    buf: [MaybeUninit<T>; N],
}

fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized `MaybeUninit<T>` is always valid, and the array
    // only contains `MaybeUninit` values.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> FixedVec<T, N> {
    /// Creates an empty `FixedVec` with all slots uninitialized.
    ///
    /// # Performance
    /// - O(1), no allocation and no element initialization.
    pub fn new() -> Self {
        Self {
            len: 0,
            buf: uninit_array(),
        }
    }

    /// Appends cloned elements from `slice`.
    ///
    /// # Panics
    /// - Panics if the new length would exceed `N`. No elements are written
    ///   in that case.
    ///
    /// # Complexity
    /// - O(m) for `m = slice.len()`.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        let new_len = self.len + slice.len();
        assert!(new_len <= N, "FixedVec capacity exceeded");
        // Write directly to buffer.
        for (i, item) in slice.iter().enumerate() {
            self.buf[self.len + i].write(item.clone());
        }
        self.len = new_len;
    }

    /// Returns a shared slice of the initialized prefix.
    ///
    /// # Complexity
    /// - O(1).
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `0..len` is initialized and contiguous.
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr().cast::<T>(), self.len) }
    }

    /// Drops all initialized elements, leaving capacity unchanged.
    ///
    /// # Effects
    /// - `len` becomes 0.
    /// - The old elements are dropped if `T: Drop`.
    ///
    /// # Performance
    /// - O(len) when `T: Drop`, otherwise O(1).
    fn clear(&mut self) {
        // Skip drop loop for types that don't need it (e.g., DecodeStep).
        // needs_drop is a const fn, so this branch is eliminated at compile time.
        if std::mem::needs_drop::<T>() {
            // SAFETY: only the first `len` elements are initialized.
            unsafe {
                for i in 0..self.len {
                    std::ptr::drop_in_place(self.buf[i].as_mut_ptr());
                }
            }
        }
        self.len = 0;
    }
}

impl<T, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const N: usize> Clone for FixedVec<T, N> {
    fn clone(&self) -> Self {
        let mut out = Self::new();
        out.extend_from_slice(self.as_slice());
        out
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for FixedVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<T, const N: usize> Deref for FixedVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, const N: usize> Drop for FixedVec<T, N> {
    fn drop(&mut self) {
        self.clear();
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
    struct DropTracker {
        id: usize,
        count: Arc<AtomicUsize>,
    }

    impl Clone for DropTracker {
        fn clone(&self) -> Self {
            Self {
                id: self.id,
                count: self.count.clone(),
            }
        }
    }

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn tracker(id: usize, count: &Arc<AtomicUsize>) -> DropTracker {
        DropTracker {
            id,
            count: count.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Basic operations — exercises MaybeUninit write + from_raw_parts read.
    // -----------------------------------------------------------------------

    #[test]
    fn new_is_empty() {
        let v = FixedVec::<u32, 4>::new();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.as_slice(), &[] as &[u32]);
    }

    #[test]
    fn extend_from_slice_and_read() {
        let mut v = FixedVec::<u32, 8>::new();
        v.extend_from_slice(&[10, 20, 30]);
        assert_eq!(v.as_slice(), [10, 20, 30]);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn extend_to_capacity() {
        let mut v = FixedVec::<u8, 4>::new();
        v.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn extend_multiple_batches() {
        let mut v = FixedVec::<u32, 8>::new();
        v.extend_from_slice(&[1, 2]);
        v.extend_from_slice(&[3, 4, 5]);
        v.extend_from_slice(&[6]);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    #[should_panic(expected = "FixedVec capacity exceeded")]
    fn extend_past_capacity_panics() {
        let mut v = FixedVec::<u32, 2>::new();
        v.extend_from_slice(&[1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // Deref — exercises the from_raw_parts path via slice coercion.
    // -----------------------------------------------------------------------

    #[test]
    fn deref_as_slice() {
        let mut v = FixedVec::<i32, 4>::new();
        v.extend_from_slice(&[100, 200]);
        let slice: &[i32] = &v;
        assert_eq!(slice, &[100, 200]);
    }

    // -----------------------------------------------------------------------
    // Clone — exercises as_slice read + extend_from_slice write on fresh buf.
    // -----------------------------------------------------------------------

    #[test]
    fn clone_produces_equal_slice() {
        let mut v = FixedVec::<u32, 4>::new();
        v.extend_from_slice(&[1, 2, 3]);
        let v2 = v.clone();
        assert_eq!(v.as_slice(), v2.as_slice());
    }

    #[test]
    fn clone_is_independent() {
        let drops = Arc::new(AtomicUsize::new(0));
        // Keep source alive so we can isolate FixedVec drop counts.
        let source = [tracker(1, &drops), tracker(2, &drops)];
        {
            let mut v = FixedVec::<DropTracker, 4>::new();
            v.extend_from_slice(&source); // clones 2 into v
            let _v2 = v.clone(); // clones 2 more into v2
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
        // v (2 clones) + v2 (2 clones) dropped = 4.
        assert_eq!(drops.load(Ordering::Relaxed), 4);
        drop(source); // 2 originals dropped = 6 total.
        assert_eq!(drops.load(Ordering::Relaxed), 6);
    }

    // -----------------------------------------------------------------------
    // Drop — exercises drop_in_place on initialized elements.
    // -----------------------------------------------------------------------

    #[test]
    fn drop_calls_element_destructors() {
        let drops = Arc::new(AtomicUsize::new(0));
        let source = [tracker(1, &drops), tracker(2, &drops), tracker(3, &drops)];
        {
            let mut v = FixedVec::<DropTracker, 4>::new();
            v.extend_from_slice(&source);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
        // Only the 3 clones inside v are dropped.
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_empty_is_noop() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let _v = FixedVec::<DropTracker, 4>::new();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn drop_after_clear_no_double_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let source = [tracker(1, &drops), tracker(2, &drops)];
        {
            let mut v = FixedVec::<DropTracker, 4>::new();
            v.extend_from_slice(&source);
            v.clear();
            // clear drops the 2 clones, then Drop::drop sees len == 0.
        }
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    // -----------------------------------------------------------------------
    // Clear + reuse — exercises drop_in_place then re-write to same slots.
    // -----------------------------------------------------------------------

    #[test]
    fn clear_and_reuse() {
        let drops = Arc::new(AtomicUsize::new(0));
        let source_a = [tracker(1, &drops), tracker(2, &drops)];
        let source_b = [tracker(3, &drops), tracker(4, &drops), tracker(5, &drops)];
        {
            let mut v = FixedVec::<DropTracker, 4>::new();
            v.extend_from_slice(&source_a);
            assert_eq!(v.len(), 2);

            v.clear();
            assert_eq!(v.len(), 0);
            assert_eq!(drops.load(Ordering::Relaxed), 2); // 2 clones dropped by clear

            // Re-fill the same slots with new clones.
            v.extend_from_slice(&source_b);
            assert_eq!(v.len(), 3);
        }
        // 2 from clear + 3 from final drop = 5 clone drops total.
        assert_eq!(drops.load(Ordering::Relaxed), 5);
    }

    // -----------------------------------------------------------------------
    // Zero-size type — edge case for uninit_array and from_raw_parts.
    // -----------------------------------------------------------------------

    #[test]
    fn zst_extend_and_read() {
        let mut v = FixedVec::<(), 8>::new();
        v.extend_from_slice(&[(), (), ()]);
        assert_eq!(v.len(), 3);
        assert_eq!(v.as_slice(), &[(), (), ()]);
    }

    // -----------------------------------------------------------------------
    // Debug — exercises from_raw_parts via as_slice in fmt.
    // -----------------------------------------------------------------------

    #[test]
    fn debug_format() {
        let mut v = FixedVec::<u32, 4>::new();
        v.extend_from_slice(&[1, 2]);
        let s = format!("{v:?}");
        assert_eq!(s, "[1, 2]");
    }
}
