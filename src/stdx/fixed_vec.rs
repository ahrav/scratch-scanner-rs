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
