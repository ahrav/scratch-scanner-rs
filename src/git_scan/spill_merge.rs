//! K-way merge of spill runs.
//!
//! Merges sorted spill runs into a single sorted stream with duplicate
//! records removed. The merge preserves the canonical ordering defined
//! by `RunRecord`.
//!
//! # Requirements
//! - Each input run must already be sorted by `RunRecord` ordering.
//! - All runs must use the same OID length.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io::Read;

use super::errors::SpillError;
use super::run_format::{RunHeader, RunRecord};
use super::run_reader::RunReader;

/// K-way merge reader for spill runs.
///
/// The merger performs dedupe by suppressing adjacent equal records in the
/// merged order.
pub struct RunMerger<R: Read> {
    cursors: Vec<RunCursor<R>>,
    heap: BinaryHeap<HeapItem>,
    last: Option<RunRecord>,
    oid_len: u8,
}

impl<R: Read> RunMerger<R> {
    /// Creates a new merger from run readers.
    ///
    /// # Errors
    /// Returns `OidLengthMismatch` if run headers disagree on OID length.
    pub fn new(readers: Vec<RunReader<R>>) -> Result<Self, SpillError> {
        let mut cursors = Vec::with_capacity(readers.len());
        let mut heap = BinaryHeap::new();
        let mut oid_len = None;

        for (idx, reader) in readers.into_iter().enumerate() {
            let header = reader.header();
            match oid_len {
                None => oid_len = Some(header.oid_len),
                Some(len) if len != header.oid_len => {
                    return Err(SpillError::OidLengthMismatch {
                        got: header.oid_len,
                        expected: len,
                    })
                }
                _ => {}
            }

            let mut cursor = RunCursor { reader, next: None };
            cursor.advance()?;
            if let Some(record) = cursor.next.take() {
                heap.push(HeapItem {
                    record,
                    cursor: idx,
                });
            }
            cursors.push(cursor);
        }

        Ok(Self {
            cursors,
            heap,
            last: None,
            oid_len: oid_len.unwrap_or(20),
        })
    }

    /// Returns the OID length for the merged runs.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the next unique record, or `Ok(None)` when exhausted.
    ///
    /// The dedupe logic only compares against the last emitted record, which
    /// is sufficient because inputs are globally ordered.
    pub fn next_unique(&mut self) -> Result<Option<RunRecord>, SpillError> {
        while let Some(item) = self.heap.pop() {
            let cursor_idx = item.cursor;
            let record = item.record;

            if let Some(next) = self.cursors[cursor_idx].advance()? {
                self.heap.push(HeapItem {
                    record: next,
                    cursor: cursor_idx,
                });
            }

            if let Some(last) = &self.last {
                if last == &record {
                    continue;
                }
            }
            self.last = Some(record.clone());
            return Ok(Some(record));
        }
        Ok(None)
    }
}

struct RunCursor<R: Read> {
    reader: RunReader<R>,
    next: Option<RunRecord>,
}

impl<R: Read> RunCursor<R> {
    fn advance(&mut self) -> Result<Option<RunRecord>, SpillError> {
        let record = self.reader.next_record()?;
        self.next = record.clone();
        Ok(record)
    }
}

#[derive(Debug)]
struct HeapItem {
    record: RunRecord,
    cursor: usize,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap behavior.
        other
            .record
            .cmp(&self.record)
            .then_with(|| other.cursor.cmp(&self.cursor))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.record == other.record && self.cursor == other.cursor
    }
}

impl Eq for HeapItem {}

/// Convenience helper to merge runs fully into memory.
///
/// This is suitable for tests or small repositories; large runs should be
/// streamed instead.
pub fn merge_all<R: Read>(readers: Vec<RunReader<R>>) -> Result<Vec<RunRecord>, SpillError> {
    let mut merger = RunMerger::new(readers)?;
    let mut out = Vec::new();
    while let Some(record) = merger.next_unique()? {
        out.push(record);
    }
    Ok(out)
}

/// Validates headers for a set of run readers.
///
/// Returns the shared OID length if all headers are consistent.
pub fn validate_headers(headers: &[RunHeader]) -> Result<u8, SpillError> {
    let mut oid_len = None;
    for header in headers {
        match oid_len {
            None => oid_len = Some(header.oid_len),
            Some(len) if len != header.oid_len => {
                return Err(SpillError::OidLengthMismatch {
                    got: header.oid_len,
                    expected: len,
                })
            }
            _ => {}
        }
    }
    Ok(oid_len.unwrap_or(20))
}
