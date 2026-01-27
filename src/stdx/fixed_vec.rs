//! Fixed-capacity, stack-allocated vector for small, bounded collections.

use std::fmt;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut, Index};

/// Fixed-capacity vector backed by an inline array.
///
/// Invariant: elements in `0..len` are initialized and valid; `len <= N`.
/// The remaining slots are uninitialized and must never be read or dropped.
/// Pushing past capacity panics to keep the container allocation-free.
pub struct FixedVec<T, const N: usize> {
    // Number of initialized elements in `buf`.
    len: usize,
    // Inline storage; only `0..len` is initialized.
    buf: [MaybeUninit<T>; N],
}

fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> FixedVec<T, N> {
    /// Returns the fixed capacity of this vector (the const generic `N`).
    pub const fn capacity() -> usize {
        N
    }

    /// Creates an empty `FixedVec` with all slots uninitialized.
    pub fn new() -> Self {
        Self {
            len: 0,
            buf: uninit_array(),
        }
    }

    /// Returns the number of initialized elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the vector has no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Drops all initialized elements, leaving capacity unchanged.
    pub fn clear(&mut self) {
        // SAFETY: only the first `len` elements are initialized.
        unsafe {
            for i in 0..self.len {
                std::ptr::drop_in_place(self.buf[i].as_mut_ptr());
            }
        }
        self.len = 0;
    }

    /// Appends a new value, panicking if the capacity is exceeded.
    pub fn push(&mut self, value: T) {
        assert!(self.len < N, "FixedVec capacity exceeded");
        self.buf[self.len].write(value);
        self.len += 1;
    }

    /// Appends cloned elements from `slice`, panicking if capacity is exceeded.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        let new_len = self.len + slice.len();
        assert!(new_len <= N, "FixedVec capacity exceeded");
        for item in slice {
            self.push(item.clone());
        }
    }

    /// Returns a shared slice of the initialized prefix.
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `0..len` is initialized and contiguous.
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr().cast::<T>(), self.len) }
    }

    /// Returns a mutable slice of the initialized prefix.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: `0..len` is initialized and contiguous.
        unsafe { std::slice::from_raw_parts_mut(self.buf.as_mut_ptr().cast::<T>(), self.len) }
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

impl<T, const N: usize> DerefMut for FixedVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T, const N: usize> Index<usize> for FixedVec<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T, const N: usize> Drop for FixedVec<T, N> {
    fn drop(&mut self) {
        self.clear();
    }
}
