//! Page-aligned, fixed-capacity scratch storage for hot paths.
//!
//! This module makes allocation behavior explicit and predictable in tight
//! loops. Regular `Vec` growth can allocate at unpredictable points, so we
//! provide:
//! - `ScratchMemory`: a single-use arena for temporary slices.
//! - `ScratchVec`: a fixed-capacity vector that never reallocates.
//!
//! The goal is not general-purpose convenience. It is deterministic memory
//! usage with clear failure modes when capacity is exceeded.

use std::alloc::{alloc, dealloc, Layout};
use std::cell::Cell;
use std::mem::{align_of, size_of, MaybeUninit};
use std::ptr::NonNull;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum State {
    Free,
    Busy,
}

#[derive(Debug)]
pub enum ScratchMemoryError {
    SizeZero,
    InvalidLayout,
    OutOfMemory,
}

/// Page-aligned scratch buffer for intermediate computations.
///
/// Some hot-path operations only need transient space, but we want to avoid
/// allocations after startup. `ScratchMemory` provides a single backing
/// allocation and enforces that only one slice is active at a time so the
/// caller cannot accidentally alias or grow beyond the reserved space.
pub struct ScratchMemory {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    state: Cell<State>,
}

impl ScratchMemory {
    /// Minimum page size for alignment.
    /// If you target a platform with a larger minimum page size, adjust this constant.
    pub const PAGE_SIZE_MIN: usize = 4096;

    pub fn init(size: usize) -> Result<Self, ScratchMemoryError> {
        if size == 0 {
            return Err(ScratchMemoryError::SizeZero);
        }

        let layout = Layout::from_size_align(size, Self::PAGE_SIZE_MIN)
            .map_err(|_| ScratchMemoryError::InvalidLayout)?;

        // SAFETY: layout is valid and has non-zero size.
        let raw = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw).ok_or(ScratchMemoryError::OutOfMemory)?;

        Ok(Self {
            ptr,
            len: size,
            layout,
            state: Cell::new(State::Free),
        })
    }

    /// Explicit deinit that asserts the buffer is not in use.
    /// In normal Rust code you can just let Drop run instead.
    pub fn deinit(self) {
        assert_eq!(self.state.get(), State::Free);
    }

    /// Acquire `count` elements of scratch space for `T`.
    ///
    /// This prevents accidental heap growth by asserting the requested size
    /// fits inside the pre-allocated buffer. The returned guard releases the
    /// buffer on drop to keep use sites scoped and easy to audit.
    ///
    /// Returns a guard that derefs to `[MaybeUninit<T>]`.
    /// - Use `.write(...)` to initialize each element.
    /// - If you fully initialized the region, you may call `unsafe { assume_init_mut() }`.
    pub fn acquire<T>(&self, count: usize) -> ScratchSlice<'_, T> {
        assert!(align_of::<T>() < Self::PAGE_SIZE_MIN);

        let scratch_size = count
            .checked_mul(size_of::<T>())
            .expect("count * size_of::<T>() overflow");
        assert!(scratch_size <= self.len);

        assert_eq!(self.state.replace(State::Busy), State::Free);

        // Buffer is page-aligned, so it's aligned for any T with align < PAGE_SIZE_MIN.
        let t_ptr = self.ptr.as_ptr().cast::<MaybeUninit<T>>();
        let t_ptr = unsafe { NonNull::new_unchecked(t_ptr) };

        ScratchSlice {
            scratch: self,
            ptr: t_ptr,
            len: count,
        }
    }

    /// Release the scratch slice early (dropping it also releases).
    pub fn release<T>(&self, slice: ScratchSlice<'_, T>) {
        drop(slice);
    }

    pub fn capacity_bytes(&self) -> usize {
        self.len
    }
}

impl Drop for ScratchMemory {
    fn drop(&mut self) {
        // Avoid panicking in Drop (double-panics during unwind can abort).
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Guard returned by `ScratchMemory::acquire`.
///
/// The guard makes the "only one active slice" rule visible in the type system
/// and ensures the scratch buffer always returns to the `Free` state.
pub struct ScratchSlice<'a, T> {
    scratch: &'a ScratchMemory,
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
}

impl<'a, T> ScratchSlice<'a, T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// View as uninitialized elements (safe).
    pub fn as_mut_uninit(&mut self) -> &mut [MaybeUninit<T>] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// View as initialized `T` (unsafe -- caller must guarantee full initialization).
    ///
    /// # Safety
    /// All elements in the slice must be fully initialized before calling this.
    pub unsafe fn assume_init_mut(&mut self) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), self.len)
    }

    /// Explicit release; dropping does the same thing.
    pub fn release(self) {}
}

impl<'a, T> std::ops::Deref for ScratchSlice<'a, T> {
    type Target = [MaybeUninit<T>];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<'a, T> std::ops::DerefMut for ScratchSlice<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<'a, T> Drop for ScratchSlice<'a, T> {
    fn drop(&mut self) {
        debug_assert!(align_of::<T>() < ScratchMemory::PAGE_SIZE_MIN);
        debug_assert_eq!(self.scratch.state.get(), State::Busy);

        debug_assert_eq!(
            self.ptr.as_ptr().cast::<u8>() as usize,
            self.scratch.ptr.as_ptr() as usize
        );

        let scratch_size = self
            .len
            .checked_mul(size_of::<T>())
            .expect("len * size_of::<T>() overflow");
        debug_assert!(scratch_size <= self.scratch.len);

        debug_assert_eq!((self.ptr.as_ptr() as usize) % align_of::<T>(), 0);

        self.scratch.state.set(State::Free);
    }
}

/// Fixed-capacity scratch vector backed by page-aligned storage.
///
/// This is a `Vec`-like API with a hard capacity. It never reallocates, so
/// once constructed it is safe to use in hot loops without risking
/// allocations. Capacity overruns are treated as bugs and panic.
pub struct ScratchVec<T> {
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
    cap: usize,
    layout: Layout,
}

impl<T> ScratchVec<T> {
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
        let align = ScratchMemory::PAGE_SIZE_MIN.max(align_of::<T>());
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

    pub fn push(&mut self, value: T) {
        assert!(self.len < self.cap, "scratch vec capacity exceeded");
        unsafe {
            self.ptr
                .as_ptr()
                .add(self.len)
                .write(MaybeUninit::new(value));
        }
        self.len += 1;
    }

    pub fn truncate(&mut self, new_len: usize) {
        assert!(new_len <= self.len);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of, MaybeUninit};

    #[test]
    fn scratch_memory_basic() {
        let scratch = ScratchMemory::init(size_of::<u64>() * 10).unwrap();

        let mut slice = scratch.acquire::<u64>(10);
        for n in 0..10 {
            let ptr = &slice[n] as *const MaybeUninit<u64> as usize;
            assert_eq!(ptr % align_of::<u64>(), 0);
            slice[n].write(n as u64);
        }

        scratch.release(slice);
    }

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
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 32;

    #[derive(Clone, Debug)]
    enum Op {
        Push(u32),
        Truncate(usize),
        Clear,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u32>().prop_map(Op::Push),
            (0usize..128).prop_map(Op::Truncate),
            Just(Op::Clear),
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
                    Op::Truncate(n) => {
                        let new_len = n.min(scratch.len());
                        scratch.truncate(new_len);
                        shadow.truncate(new_len);
                    }
                    Op::Clear => {
                        scratch.clear();
                        shadow.clear();
                    }
                }

                prop_assert_eq!(scratch.as_slice(), shadow.as_slice());
            }
        }
    }
}
