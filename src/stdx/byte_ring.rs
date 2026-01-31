//! Byte ring keyed by absolute stream offsets.
//!
//! This buffer models a logical, ever-growing byte stream. Each `push` appends
//! new bytes at the current `end_offset`, and the ring retains only the most
//! recent `capacity` bytes. The absolute offset of the first retained byte is
//! tracked in `start_offset`, so callers can ask whether a `[lo, hi)` range is
//! still available and materialize it into an output buffer.
//!
//! # Invariants
//! - `len <= capacity` and `head < capacity`.
//! - When `len > 0`, `start_offset` is the absolute offset of the byte at
//!   `head`.
//! - `end_offset == start_offset + len` (using saturating arithmetic on
//!   overflow).
//!
//! # Layout
//! Data lives in a circular `Vec<u8>`. The retained bytes are contiguous in
//! logical order but may wrap in the underlying buffer; `segments()` exposes up
//! to two slices that, when concatenated, yield the retained bytes in order.
//!
//! # Edge cases
//! - Empty ranges with `hi <= lo` are treated as present.
//! - Pushing `n >= capacity` bytes keeps only the last `capacity` bytes and
//!   advances `start_offset` past all earlier data.

/// Fixed-capacity ring buffer for the tail of a byte stream.
pub(crate) struct ByteRing {
    buf: Vec<u8>,
    head: usize,
    len: usize,
    start_offset: u64,
}

impl ByteRing {
    /// Creates an empty ring with a fixed `capacity`.
    ///
    /// # Panics
    /// Panics if `capacity == 0`.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "ByteRing capacity must be > 0");
        Self {
            buf: vec![0u8; capacity],
            head: 0,
            len: 0,
            start_offset: 0,
        }
    }

    /// Returns the maximum number of bytes the ring can retain.
    pub(crate) fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Returns the absolute offset of the first retained byte.
    ///
    /// Meaningful when `len > 0`; when empty, callers should treat this as the
    /// offset where the next retained byte would begin.
    pub(crate) fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Returns the retained bytes as up to two slices in logical order.
    ///
    /// The first slice starts at `head`; the second (possibly empty) slice
    /// contains the wrapped remainder. The slices are valid until the ring is
    /// mutated.
    pub(crate) fn segments(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }
        let cap = self.buf.len();
        let start = self.head;
        if self.len <= cap - start {
            (&self.buf[start..start + self.len], &[])
        } else {
            let first = cap - start;
            (&self.buf[start..], &self.buf[..(self.len - first)])
        }
    }

    /// Clears all retained bytes and resets offsets.
    pub(crate) fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
        self.start_offset = 0;
    }

    /// Appends bytes to the ring, evicting the oldest bytes on overflow.
    ///
    /// The data is treated as a continuation of the logical stream. If
    /// `data.len() >= capacity`, only the last `capacity` bytes are retained.
    ///
    /// Complexity: O(n) for `n = data.len()`.
    pub(crate) fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let cap = self.buf.len();
        let n = data.len();
        let old_len = self.len;
        let old_end = self.start_offset.saturating_add(old_len as u64);

        if n >= cap {
            let start = n - cap;
            self.buf.copy_from_slice(&data[start..]);
            self.head = 0;
            self.len = cap;
            self.start_offset = old_end.saturating_add(n as u64 - cap as u64);
            return;
        }

        let mut drop = old_len + n;
        if drop > cap {
            drop -= cap;
        } else {
            drop = 0;
        }
        if drop > 0 {
            self.head = (self.head + drop) % cap;
            self.len = self.len.saturating_sub(drop);
            self.start_offset = self.start_offset.saturating_add(drop as u64);
        }

        let tail = (self.head + self.len) % cap;
        let first = (cap - tail).min(n);
        self.buf[tail..tail + first].copy_from_slice(&data[..first]);
        if n > first {
            self.buf[..(n - first)].copy_from_slice(&data[first..]);
        }
        self.len = self.len.saturating_add(n);
    }

    /// Returns true when the full `[lo, hi)` range is currently retained.
    ///
    /// Empty ranges (`hi <= lo`) are treated as present.
    pub(crate) fn has_range(&self, lo: u64, hi: u64) -> bool {
        if hi <= lo {
            return true;
        }
        if self.len == 0 {
            return false;
        }
        lo >= self.start_offset && hi <= self.start_offset.saturating_add(self.len as u64)
    }

    /// Extends `out` with bytes in `[lo, hi)`, returning false if the range
    /// is not fully retained.
    ///
    /// On failure, `out` is left unchanged. Empty ranges (`hi <= lo`) append
    /// nothing and return true.
    ///
    /// Complexity: O(len) for `len = hi - lo`.
    pub(crate) fn extend_range_to(&self, lo: u64, hi: u64, out: &mut Vec<u8>) -> bool {
        if hi <= lo {
            return true;
        }
        if !self.has_range(lo, hi) {
            return false;
        }

        let offset = (lo - self.start_offset) as usize;
        let len = (hi - lo) as usize;
        if len == 0 {
            return true;
        }

        let cap = self.buf.len();
        let start = (self.head + offset) % cap;
        let first = (cap - start).min(len);
        out.extend_from_slice(&self.buf[start..start + first]);
        if len > first {
            out.extend_from_slice(&self.buf[..(len - first)]);
        }
        true
    }
}
