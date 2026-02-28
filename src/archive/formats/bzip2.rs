//! bzip2 sniff helpers + streaming decoder wrapper.
//!
//! # Invariants
//! - The stream is read sequentially; no seeking.
//! - Compressed-byte accounting is sourced from [`CountedRead`].
//!
//! # Design Notes
//! - bzip2 streams do not carry a standard original-filename field, so callers
//!   synthesize display names (for example `<bunzip2>`) at attribution time.

use std::io::{self, Read};

use bzip2::read::BzDecoder;

use crate::archive::util::CountedRead;

/// bzip2 magic prefix: ASCII `BZh`.
pub const BZIP2_MAGIC: [u8; 3] = [0x42, 0x5A, 0x68];

#[inline(always)]
pub fn is_bzip2_magic(header: &[u8]) -> bool {
    header.len() >= 3
        && header[0] == BZIP2_MAGIC[0]
        && header[1] == BZIP2_MAGIC[1]
        && header[2] == BZIP2_MAGIC[2]
}

/// Streaming bzip2 decoder with compressed-byte delta reporting.
pub struct Bzip2Stream<R: Read> {
    dec: BzDecoder<CountedRead<R>>,
    last_bytes: u64,
}

impl<R: Read> Bzip2Stream<R> {
    #[inline]
    pub fn new(reader: R) -> Self {
        Self {
            dec: BzDecoder::new(CountedRead::new(reader)),
            last_bytes: 0,
        }
    }

    /// Read decompressed bytes.
    #[inline]
    pub fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }

    /// Returns compressed bytes consumed since the previous call.
    ///
    /// This mirrors [`crate::archive::formats::GzipStream::take_compressed_delta`]
    /// so budget-charging code can stay codec-agnostic.
    #[inline]
    pub fn take_compressed_delta(&mut self) -> u64 {
        let now = self.dec.get_ref().bytes();
        let delta = now.saturating_sub(self.last_bytes);
        self.last_bytes = now;
        delta
    }

    #[inline]
    pub fn total_compressed(&self) -> u64 {
        self.dec.get_ref().bytes()
    }

    #[inline]
    pub fn into_inner(self) -> R {
        self.dec.into_inner().into_inner()
    }
}

impl<R: Read> Read for Bzip2Stream<R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_bzip2_magic() {
        assert!(is_bzip2_magic(b"BZh9"));
        assert!(!is_bzip2_magic(b"BZ"));
        assert!(!is_bzip2_magic(b"PK\x03\x04"));
    }
}
