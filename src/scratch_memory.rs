//! Page-aligned, fixed-capacity scratch storage for hot paths.
//!
//! # Scope
//! This module makes allocation behavior explicit and predictable in tight
//! loops. Regular `Vec` growth can allocate at unpredictable points, so we
//! provide `ScratchVec`: a fixed-capacity vector that never reallocates.
//!
//! The goal is not general-purpose convenience. It is deterministic memory
//! usage with clear failure modes when capacity is exceeded.
//!
//! # Invariants
//! - `ScratchVec` has a hard capacity; exceeding it is a logic error and will
//!   panic in debug builds.
//! - Memory is page-aligned (minimum 4 KiB) to keep alignment predictable.
//!
//! # Failure modes
//! - Capacity overruns are treated as bugs (debug assertions).
//! - Allocation failures and invalid layouts are reported via
//!   `ScratchMemoryError`.

use std::alloc::{alloc, dealloc, Layout};
use std::mem::{align_of, size_of, MaybeUninit};
use std::ptr::NonNull;

const PAGE_SIZE_MIN: usize = 4096;

/// Errors returned by scratch allocators.
#[derive(Debug)]
pub enum ScratchMemoryError {
    /// Size or element size was zero where a non-zero allocation is required.
    SizeZero,
    /// The requested layout was invalid (overflow or bad alignment).
    InvalidLayout,
    /// The allocator returned null.
    OutOfMemory,
}

/// Fixed-capacity scratch vector backed by page-aligned storage.
///
/// This is a `Vec`-like API with a hard capacity. It never reallocates, so
/// once constructed it is safe to use in hot loops without risking
/// allocations.
///
/// # Invariants
/// - `len <= cap` at all times.
/// - Elements in `0..len` are initialized; elements in `len..cap` are not.
///
/// Capacity overruns are treated as bugs and only checked in debug builds.
pub struct ScratchVec<T> {
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
    cap: usize,
    layout: Layout,
}

impl<T> ScratchVec<T> {
    /// Allocate a fixed-capacity scratch vector.
    ///
    /// # Errors
    /// - `SizeZero` if `T` has zero size and `cap > 0`.
    /// - `InvalidLayout` if `cap * size_of::<T>()` overflows or alignment is invalid.
    /// - `OutOfMemory` if allocation fails.
    ///
    /// # Notes
    /// - `cap == 0` returns a dangling allocation with zero length/capacity.
    ///   Pushing into a zero-capacity vector is a logic error.
    pub fn with_capacity(cap: usize) -> Result<Self, ScratchMemoryError> {
        if cap == 0 {
            return Ok(Self {
                ptr: NonNull::dangling(),
                len: 0,
                cap: 0,
                layout: Layout::from_size_align(1, 1)
                    .map_err(|_| ScratchMemoryError::InvalidLayout)?,
            });
        }

        let elem_size = size_of::<T>();
        if elem_size == 0 {
            return Err(ScratchMemoryError::SizeZero);
        }

        let size = cap
            .checked_mul(elem_size)
            .ok_or(ScratchMemoryError::InvalidLayout)?;
        // Page alignment keeps allocations predictable and makes it safe to
        // reuse scratch buffers for SIMD-friendly workloads without worrying
        // about alignment faults.
        let align = PAGE_SIZE_MIN.max(align_of::<T>());
        let layout =
            Layout::from_size_align(size, align).map_err(|_| ScratchMemoryError::InvalidLayout)?;

        // SAFETY: layout is valid and has non-zero size.
        let raw = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw).ok_or(ScratchMemoryError::OutOfMemory)?;

        Ok(Self {
            ptr: ptr.cast(),
            len: 0,
            cap,
            layout,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Push a value onto the end of the vector.
    ///
    /// # Panics (debug builds)
    /// Panics if `self.len() == self.capacity()`. In release builds this is a
    /// logic error that can write out of bounds.
    pub fn push(&mut self, value: T) {
        debug_assert!(self.len < self.cap, "scratch vec capacity exceeded");
        unsafe {
            self.ptr
                .as_ptr()
                .add(self.len)
                .write(MaybeUninit::new(value));
        }
        self.len += 1;
    }

    /// Shorten the vector to `new_len`, dropping elements above the new length.
    ///
    /// # Panics (debug builds)
    /// Panics if `new_len > self.len()`. In release builds this is a logic
    /// error that can leave the vector with uninitialized elements.
    pub fn truncate(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.len, "scratch vec truncate out of bounds");
        unsafe {
            for i in new_len..self.len {
                std::ptr::drop_in_place(self.ptr.as_ptr().add(i).cast::<T>());
            }
        }
        self.len = new_len;
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<T>(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), self.len) }
    }

    /// Appends all elements from `slice` to the vector.
    ///
    /// This is the fixed-capacity equivalent of `Vec::extend_from_slice`. Unlike
    /// `Vec`, this method debug-asserts if the resulting length would exceed
    /// capacity, making capacity overruns immediately visible during development.
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `self.len() + slice.len() > self.capacity()`. In release builds
    /// this is a logic error that can write out of bounds.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Copy,
    {
        let new_len = self.len.saturating_add(slice.len());
        debug_assert!(
            new_len <= self.cap,
            "scratch vec capacity exceeded on extend_from_slice"
        );
        unsafe {
            std::ptr::copy_nonoverlapping(
                slice.as_ptr(),
                self.ptr.as_ptr().add(self.len).cast::<T>(),
                slice.len(),
            );
        }
        self.len = new_len;
    }

    /// Appends a range from this vector's existing contents.
    ///
    /// This is useful for building new data from previous bytes without
    /// allocating intermediate buffers. The source range may overlap with
    /// the destination (memmove semantics).
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `start + len` exceeds the current length or if the new
    /// length would exceed capacity. In release builds, violating these
    /// preconditions can corrupt memory.
    pub fn extend_from_self_range(&mut self, start: usize, len: usize)
    where
        T: Copy,
    {
        debug_assert!(start <= self.len, "scratch vec range start out of bounds");
        debug_assert!(
            start.saturating_add(len) <= self.len,
            "scratch vec range end out of bounds"
        );
        let new_len = self.len.saturating_add(len);
        debug_assert!(
            new_len <= self.cap,
            "scratch vec capacity exceeded on extend_from_self_range"
        );
        unsafe {
            std::ptr::copy(
                self.ptr.as_ptr().add(start).cast::<T>(),
                self.ptr.as_ptr().add(self.len).cast::<T>(),
                len,
            );
        }
        self.len = new_len;
    }

    /// Removes and returns the last element, or `None` if empty.
    ///
    /// This is the fixed-capacity equivalent of `Vec::pop`. The capacity remains
    /// unchanged; only the logical length decreases.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: We just confirmed len > 0, so self.len (now decremented) is a valid index.
        // The element is initialized; we read and return it without dropping (caller owns it).
        unsafe { Some(self.ptr.as_ptr().add(self.len).cast::<T>().read()) }
    }

    /// Returns a reference to the element at `index`, or `None` if out of bounds.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            // SAFETY: index is in bounds and element is initialized.
            unsafe { Some(&*self.ptr.as_ptr().add(index).cast::<T>()) }
        } else {
            None
        }
    }

    /// Returns a mutable reference to the element at `index`, or `None` if out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len {
            // SAFETY: index is in bounds and element is initialized.
            unsafe { Some(&mut *self.ptr.as_ptr().add(index).cast::<T>()) }
        } else {
            None
        }
    }

    /// Creates a draining iterator that removes and yields elements in order.
    ///
    /// After the iterator is dropped (or fully consumed), the vector is empty.
    /// This is the fixed-capacity equivalent of `Vec::drain(..)`.
    pub fn drain(&mut self) -> Drain<'_, T> {
        let len = self.len;
        // Set length to 0 immediately; Drain owns the elements and will drop
        // any remaining on its own drop.
        self.len = 0;
        Drain {
            ptr: self.ptr.cast::<T>(),
            idx: 0,
            len,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Draining iterator for [`ScratchVec`].
///
/// Yields elements by value and drops any remaining elements when the iterator
/// is dropped. After iteration completes (or the iterator is dropped), the
/// source `ScratchVec` is empty.
pub struct Drain<'a, T> {
    ptr: NonNull<T>,
    idx: usize,
    len: usize,
    _marker: std::marker::PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            return None;
        }
        // SAFETY: idx < len, so the element is valid and initialized.
        let val = unsafe { self.ptr.as_ptr().add(self.idx).read() };
        self.idx += 1;
        Some(val)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.idx);
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for Drain<'a, T> {}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        // Drop any remaining elements that were not yielded.
        for i in self.idx..self.len {
            unsafe {
                std::ptr::drop_in_place(self.ptr.as_ptr().add(i));
            }
        }
    }
}

impl<T> std::ops::Index<usize> for ScratchVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T> std::ops::IndexMut<usize> for ScratchVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

impl<T> Drop for ScratchVec<T> {
    fn drop(&mut self) {
        self.truncate(0);
        if self.cap == 0 {
            return;
        }
        unsafe {
            dealloc(self.ptr.as_ptr().cast::<u8>(), self.layout);
        }
    }
}

// SAFETY: ScratchVec exclusively owns its allocation, same as Vec<T>.
// When T: Send, the owned data is safe to transfer between threads.
unsafe impl<T: Send> Send for ScratchVec<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_vec_basic() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        assert_eq!(vec.as_slice(), &[10, 20]);
        vec.truncate(1);
        assert_eq!(vec.as_slice(), &[10]);
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn scratch_vec_extend_from_slice() {
        let mut vec = ScratchVec::<u8>::with_capacity(10).unwrap();
        vec.extend_from_slice(&[1, 2, 3]);
        assert_eq!(vec.as_slice(), &[1, 2, 3]);
        vec.extend_from_slice(&[4, 5]);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5]);
        vec.clear();
        vec.extend_from_slice(&[]);
        assert!(vec.is_empty());
    }

    #[test]
    #[should_panic(expected = "scratch vec capacity exceeded")]
    fn scratch_vec_extend_from_slice_overflow() {
        let mut vec = ScratchVec::<u8>::with_capacity(3).unwrap();
        vec.extend_from_slice(&[1, 2, 3, 4]);
    }

    #[test]
    fn scratch_vec_pop() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        assert_eq!(vec.pop(), None);
        vec.push(10);
        vec.push(20);
        vec.push(30);
        assert_eq!(vec.pop(), Some(30));
        assert_eq!(vec.pop(), Some(20));
        assert_eq!(vec.as_slice(), &[10]);
        assert_eq!(vec.pop(), Some(10));
        assert_eq!(vec.pop(), None);
        assert!(vec.is_empty());
    }

    #[test]
    fn scratch_vec_get() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        assert_eq!(vec.get(0), Some(&10));
        assert_eq!(vec.get(1), Some(&20));
        assert_eq!(vec.get(2), None);
        assert_eq!(vec.get(100), None);
    }

    #[test]
    fn scratch_vec_get_mut() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        if let Some(v) = vec.get_mut(0) {
            *v = 100;
        }
        assert_eq!(vec.as_slice(), &[100, 20]);
        assert!(vec.get_mut(5).is_none());
    }

    #[test]
    fn scratch_vec_drain() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        let drained: Vec<u32> = vec.drain().collect();
        assert_eq!(drained, vec![1, 2, 3]);
        assert!(vec.is_empty());
        assert_eq!(vec.capacity(), 4);
    }

    #[test]
    fn scratch_vec_drain_partial() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        {
            let mut drain = vec.drain();
            assert_eq!(drain.next(), Some(1));
            // Drop without consuming all - remaining should be dropped
        }

        assert!(vec.is_empty());
    }

    #[test]
    fn scratch_vec_drain_empty() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        let drained: Vec<u32> = vec.drain().collect();
        assert!(drained.is_empty());
        assert!(vec.is_empty());
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 32;

    #[derive(Clone, Debug)]
    enum Op {
        Push(u32),
        Pop,
        Truncate(usize),
        Clear,
        ExtendFromSlice(Vec<u32>),
        Drain,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u32>().prop_map(Op::Push),
            Just(Op::Pop),
            (0usize..128).prop_map(Op::Truncate),
            Just(Op::Clear),
            prop::collection::vec(any::<u32>(), 0..8).prop_map(Op::ExtendFromSlice),
            Just(Op::Drain),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_scratch_vec_matches_vec(
            cap in 0usize..32,
            ops in prop::collection::vec(op_strategy(), 0..128)
        ) {
            let mut scratch = ScratchVec::<u32>::with_capacity(cap).unwrap();
            let mut shadow = Vec::new();

            for op in ops {
                match op {
                    Op::Push(v) => {
                        if scratch.len() < scratch.capacity() {
                            scratch.push(v);
                            shadow.push(v);
                        }
                    }
                    Op::Pop => {
                        let s = scratch.pop();
                        let v = shadow.pop();
                        prop_assert_eq!(s, v);
                    }
                    Op::Truncate(n) => {
                        let new_len = n.min(scratch.len());
                        scratch.truncate(new_len);
                        shadow.truncate(new_len);
                    }
                    Op::Clear => {
                        scratch.clear();
                        shadow.clear();
                    }
                    Op::ExtendFromSlice(slice) => {
                        if scratch.len().saturating_add(slice.len()) <= scratch.capacity() {
                            scratch.extend_from_slice(&slice);
                            shadow.extend_from_slice(&slice);
                        }
                    }
                    Op::Drain => {
                        let s: Vec<_> = scratch.drain().collect();
                        let v: Vec<_> = std::mem::take(&mut shadow);
                        prop_assert_eq!(s, v);
                    }
                }

                prop_assert_eq!(scratch.as_slice(), shadow.as_slice());
            }
        }
    }
}
