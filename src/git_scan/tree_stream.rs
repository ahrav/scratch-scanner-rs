//! Streaming tree entry parser backed by a fixed-size buffer.
//!
//! This module provides a streaming parser that can consume tree bytes from
//! any `Read` source while retaining only a bounded window in memory.

use std::io::Read;

use super::errors::TreeDiffError;
use super::object_store::TreeBytes;
use super::tree_entry::{parse_entry, ParseOutcome, ParsedTreeEntry, TreeEntry};

/// Reader over tree bytes owned by the object store.
pub(crate) struct TreeBytesReader {
    bytes: TreeBytes,
    pos: usize,
}

impl TreeBytesReader {
    pub(crate) fn new(bytes: TreeBytes) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn in_flight_len(&self) -> usize {
        self.bytes.in_flight_len()
    }
}

impl Read for TreeBytesReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let data = self.bytes.as_slice();
        if self.pos >= data.len() {
            return Ok(0);
        }

        let available = data.len() - self.pos;
        let n = out.len().min(available);
        out[..n].copy_from_slice(&data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Streaming tree entry parser.
pub(crate) struct TreeStream<R: Read> {
    reader: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    oid_len: u8,
    cached: Option<ParsedTreeEntry>,
}

impl<R: Read> TreeStream<R> {
    pub(crate) fn new(reader: R, oid_len: u8, capacity: usize) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );
        assert!(capacity > 0, "tree stream buffer must be > 0");

        Self {
            reader,
            buf: vec![0u8; capacity],
            start: 0,
            end: 0,
            eof: false,
            oid_len,
            cached: None,
        }
    }

    pub(crate) fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        if let Some(parsed) = self.cached {
            return Ok(Some(parsed.materialize(&self.buf, self.oid_len)));
        }

        loop {
            if self.start >= self.end {
                if self.eof {
                    return Ok(None);
                }
                self.fill()?;
                if self.start >= self.end && self.eof {
                    return Ok(None);
                }
            }

            let data = &self.buf[self.start..self.end];
            match parse_entry(data, self.oid_len)? {
                ParseOutcome::Complete(mut parsed) => {
                    parsed.offset_by(self.start);
                    self.cached = Some(parsed);
                    return Ok(Some(parsed.materialize(&self.buf, self.oid_len)));
                }
                ParseOutcome::Incomplete(stage) => {
                    if self.eof {
                        return Err(TreeDiffError::CorruptTree {
                            detail: stage.error_detail(),
                        });
                    }
                    if self.end - self.start == self.buf.len() {
                        return Err(TreeDiffError::CorruptTree {
                            detail: "tree entry exceeds stream buffer",
                        });
                    }
                    self.fill()?;
                }
            }
        }
    }

    pub(crate) fn advance(&mut self) -> Result<(), TreeDiffError> {
        if self.cached.is_none() {
            let _ = self.peek_entry()?;
        }
        if let Some(parsed) = self.cached.take() {
            self.start = self.start.saturating_add(parsed.entry_len);
        }
        Ok(())
    }

    fn fill(&mut self) -> Result<(), TreeDiffError> {
        debug_assert!(
            self.cached.is_none(),
            "cannot fill while a cached entry is active"
        );

        if self.eof {
            return Ok(());
        }

        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.start > 0 {
            let len = self.end - self.start;
            self.buf.copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = len;
        }

        let n = self.reader.read(&mut self.buf[self.end..]).map_err(|err| {
            TreeDiffError::ObjectStoreError {
                detail: format!("tree stream read error: {err}"),
            }
        })?;
        if n == 0 {
            self.eof = true;
        } else {
            self.end += n;
        }
        Ok(())
    }
}

impl TreeStream<TreeBytesReader> {
    pub(crate) fn in_flight_len(&self) -> usize {
        self.reader.in_flight_len()
    }
}
