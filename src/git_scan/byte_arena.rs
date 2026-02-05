//! Byte arena for Git scanning.
//!
//! Provides compact storage for variable-length byte sequences with
//! stable `ByteRef` handles.
//!
//! # Design
//! - Append-only: bytes are never removed, so references remain valid.
//! - References are offsets, not pointers, so Vec reallocation does not
//!   invalidate them.
//! - No deduplication is performed; repeated inserts store repeated bytes.
//!
//! # Complexity
//! - `intern` is `O(n)` in the inserted length.
//! - `get` is `O(1)`.

/// Reference to bytes stored in a `ByteArena`.
///
/// This is a small, copyable handle. It does not track lifetimes, so the
/// caller must ensure it is only used with the arena it was created from.
///
/// # Invariants
/// - `off + len` must not overflow `u32` (enforced by `end()`)
/// - The referenced range must be valid in the owning arena
/// - `len` is at most `MAX_LEN` (fits in `u16`)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteRef {
    /// Offset into the arena.
    pub off: u32,
    /// Length in bytes (max 65535).
    pub len: u16,
}

impl ByteRef {
    /// Maximum length for a byte reference.
    pub const MAX_LEN: u16 = u16::MAX;

    /// Creates a new byte reference.
    ///
    /// This does not validate the range. Use only with trusted inputs.
    #[inline]
    #[must_use]
    pub const fn new(off: u32, len: u16) -> Self {
        Self { off, len }
    }

    /// Returns the offset.
    #[inline]
    #[must_use]
    pub const fn off(&self) -> u32 {
        self.off
    }

    /// Returns the length.
    #[inline]
    #[must_use]
    pub const fn length(&self) -> u16 {
        self.len
    }

    /// Returns the end offset (exclusive).
    ///
    /// # Panics
    ///
    /// Panics if `off + len` overflows `u32`.
    #[inline]
    #[must_use]
    pub const fn end(&self) -> u32 {
        match self.off.checked_add(self.len as u32) {
            Some(v) => v,
            None => panic!("ByteRef::end overflow"),
        }
    }

    /// Returns the end offset, or `None` if overflow would occur.
    #[inline]
    #[must_use]
    pub const fn checked_end(&self) -> Option<u32> {
        self.off.checked_add(self.len as u32)
    }
}

/// Bump allocator for variable-length byte sequences.
///
/// This arena stores bytes contiguously and returns offset-based references.
/// The `capacity` is a hard limit; the internal `Vec` may reserve less to
/// avoid large upfront allocations.
///
/// # Invariants
/// - Total bytes never exceeds `capacity`
/// - All returned `ByteRef` values remain valid for arena lifetime
/// - All returned `ByteRef` values have `off + len <= capacity`
#[derive(Clone, Debug)]
pub struct ByteArena {
    bytes: Vec<u8>,
    capacity: u32,
}

impl ByteArena {
    /// Maximum pre-allocation size (1 MiB).
    const PREALLOC_MAX_BYTES: u32 = 1024 * 1024;

    /// Creates a new arena with the specified maximum capacity.
    ///
    /// The internal pre-allocation is capped to avoid large eager allocations.
    #[must_use]
    pub fn with_capacity(capacity: u32) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(Self::PREALLOC_MAX_BYTES) as usize),
            capacity,
        }
    }

    /// Pushes a byte slice into the arena, returning a reference.
    ///
    /// This is an append-only operation; previously returned references
    /// remain valid after insertion.
    ///
    /// Returns `None` if the slice is too long or exceeds capacity.
    pub fn intern(&mut self, data: &[u8]) -> Option<ByteRef> {
        if data.len() > ByteRef::MAX_LEN as usize {
            return None;
        }
        let len = data.len() as u16;

        let off = self.bytes.len() as u32;
        let end = off.checked_add(len as u32)?;
        if end > self.capacity {
            return None;
        }

        debug_assert!(end <= self.capacity);

        self.bytes.extend_from_slice(data);
        Some(ByteRef::new(off, len))
    }

    /// Retrieves the bytes for a reference.
    ///
    /// # Panics
    ///
    /// Panics if `r` is invalid (overflow in `end()` or out-of-bounds range).
    #[inline]
    #[must_use]
    pub fn get(&self, r: ByteRef) -> &[u8] {
        let start = r.off as usize;
        let end = r.end() as usize;

        debug_assert!(
            start <= self.bytes.len(),
            "ByteRef start out of bounds: {} > {}",
            start,
            self.bytes.len()
        );
        debug_assert!(
            end <= self.bytes.len(),
            "ByteRef end out of bounds: {} > {}",
            end,
            self.bytes.len()
        );

        &self.bytes[start..end]
    }

    /// Returns current usage in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// Returns true if the arena is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns remaining capacity in bytes.
    ///
    /// Saturates at 0 if the arena is at or above capacity.
    #[inline]
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.capacity.saturating_sub(self.bytes.len() as u32)
    }

    /// Returns the maximum capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(std::mem::size_of::<ByteRef>() == 8);
        assert!(std::mem::align_of::<ByteRef>() == 4);
    };

    #[test]
    fn byte_arena_basic() {
        let mut arena = ByteArena::with_capacity(1024);

        let r1 = arena.intern(b"refs/heads/main").unwrap();
        let r2 = arena.intern(b"refs/heads/develop").unwrap();

        assert_eq!(arena.get(r1), b"refs/heads/main");
        assert_eq!(arena.get(r2), b"refs/heads/develop");
    }

    #[test]
    fn byte_arena_capacity_limit() {
        let mut arena = ByteArena::with_capacity(10);

        let r1 = arena.intern(b"hello");
        assert!(r1.is_some());

        let r2 = arena.intern(b"world!");
        assert!(r2.is_none());

        let r3 = arena.intern(b"hi");
        assert!(r3.is_some());
    }

    #[test]
    fn byte_arena_max_len() {
        let mut arena = ByteArena::with_capacity(u32::MAX);

        let long_data = vec![0u8; ByteRef::MAX_LEN as usize + 1];
        let result = arena.intern(&long_data);
        assert!(result.is_none());
    }

    #[test]
    fn byte_ref_end_valid() {
        let r = ByteRef::new(100, 50);
        assert_eq!(r.end(), 150);
        assert_eq!(r.checked_end(), Some(150));
    }

    #[test]
    #[should_panic(expected = "ByteRef::end overflow")]
    fn byte_ref_end_overflow_panics() {
        let r = ByteRef::new(u32::MAX - 10, 100);
        let _ = r.end();
    }

    #[test]
    fn byte_ref_checked_end_overflow() {
        let r = ByteRef::new(u32::MAX - 10, 100);
        assert!(r.checked_end().is_none());
    }
}
