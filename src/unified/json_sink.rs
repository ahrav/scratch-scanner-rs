//! Streaming JSON array event sink.
//!
//! Writes a single valid JSON array document — one top-level `[…]` whose
//! elements are the same JSON objects as the JSONL sink but separated by
//! commas instead of newlines. Use this when the consumer expects a single
//! parseable JSON value (e.g. `jq '.[0]'`); prefer [`JsonlEventSink`] for
//! streaming / line-oriented consumers.
//!
//! [`JsonlEventSink`]: super::events::JsonlEventSink
//!
//! # Example output
//!
//! ```text
//! [
//! {"type":"finding","source":"fs","path":"src/main.rs", …},
//! {"type":"summary","source":"fs","status":"complete", …}
//! ]
//! ```
//!
//! # Thread safety
//!
//! Multiple workers call [`emit()`](EventSink::emit) concurrently. Each call
//! formats into a per-thread scratch buffer (via `with_format_buf`), then
//! acquires the writer mutex for separator selection and `write_all`. The
//! mutex hold time is two small `write_all` calls (separator + payload),
//! not JSON encoding cost, so contention stays low.
//!
//! **Element order is non-deterministic** — it depends on which thread
//! acquires the mutex first, not on the order events were produced. This
//! is acceptable because consumers should join by event keys (for findings:
//! `type` + `source` + `path`) rather than relying on array position.
//!
//! # Wire invariants
//!
//! - The opening `[` is written eagerly in [`JsonEventSink::new`].
//! - Each element is preceded by `\n` (first) or `,\n` (subsequent).
//! - [`flush()`](EventSink::flush) writes `\n]\n` and flushes the
//!   underlying `BufWriter`. It must be called **exactly once** at
//!   end-of-scan; a second call would emit a stray `]\n`.
//! - Broken-pipe errors are silently swallowed (for piped consumers like
//!   `head`); all other I/O errors panic.

use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::events::{
    encode_commit_meta, encode_diagnostic, encode_finding, encode_identity_dictionary,
    encode_progress, encode_summary, handle_sink_io, with_format_buf, EventSink, ScanEvent,
};

/// Default `BufWriter` capacity (64 KiB).
///
/// Matches the JSONL sink and the typical OS pipe buffer, keeping
/// syscall frequency low without over-allocating for small scans.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// JSON array event sink: streams `[{…},{…},…]`.
///
/// The opening `[` is written on construction. Each [`emit()`](EventSink::emit)
/// appends one comma-separated JSON object. [`flush()`](EventSink::flush)
/// closes the array with `]\n` and flushes the underlying writer.
///
/// See the [module docs](self) for wire format, threading model, and error
/// contract.
pub struct JsonEventSink<W: Write + Send> {
    /// Buffered writer, mutex-guarded for concurrent `emit()` calls.
    writer: Mutex<BufWriter<W>>,
    /// `true` until the first element is written; controls whether
    /// the separator is `\n` (first) or `,\n` (subsequent).
    first: AtomicBool,
}

impl<W: Write + Send> JsonEventSink<W> {
    /// Create a new JSON array sink over `writer`.
    ///
    /// Eagerly writes the opening `[`. If this write fails (e.g. the
    /// writer is already broken-pipe) it is silently ignored — the
    /// subsequent `emit()` will surface the error on its payload write.
    pub fn new(mut writer: W) -> Self {
        let _ = writer.write_all(b"[");
        Self {
            writer: Mutex::new(BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, writer)),
            first: AtomicBool::new(true),
        }
    }
}

impl<W: Write + Send + 'static> EventSink for JsonEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        with_format_buf(
            |buf| match &event {
                ScanEvent::Finding(f) => encode_finding(f, buf),
                ScanEvent::Progress(p) => encode_progress(p, buf),
                ScanEvent::Summary(s) => encode_summary(s, buf),
                ScanEvent::Diagnostic(d) => encode_diagnostic(d, buf),
                ScanEvent::CommitMeta(m) => encode_commit_meta(m, buf),
                ScanEvent::IdentityDictionary(d) => encode_identity_dictionary(d, buf),
            },
            |bytes| {
                let mut writer = self.writer.lock().expect("json sink mutex poisoned");
                // Determine separator under the mutex so the first element
                // is guaranteed to be preceded by `\n` (not `,\n`).
                // `Relaxed` is sufficient: the mutex itself provides the
                // happens-before edge between competing threads.
                let sep: &[u8] = if self.first.swap(false, Ordering::Relaxed) {
                    b"\n"
                } else {
                    b",\n"
                };
                handle_sink_io(writer.write_all(sep), "json event sink write");
                handle_sink_io(writer.write_all(bytes), "json event sink write");
            },
        );
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("json sink mutex poisoned");
        handle_sink_io(writer.write_all(b"\n]\n"), "json event sink write");
        handle_sink_io(writer.flush(), "json event sink flush");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified::events::{FindingEvent, ProgressEvent, SummaryEvent};
    use crate::unified::SourceKind;

    fn collect_json(events: Vec<ScanEvent<'_>>) -> String {
        let buf = Vec::new();
        let sink = JsonEventSink::new(buf);
        for e in events {
            sink.emit(e);
        }
        sink.flush();
        let writer = sink.writer.lock().unwrap();
        String::from_utf8(writer.get_ref().clone()).unwrap()
    }

    fn sample_finding<'a>() -> ScanEvent<'a> {
        ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 42,
            end: 80,
            rule_id: 7,
            rule_name: "aws-access-key",
            commit_id: None,
            change_kind: None,
        })
    }

    #[test]
    fn single_event_valid_json() {
        let out = collect_json(vec![sample_finding()]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["type"], "finding");
        assert_eq!(parsed[0]["rule"], "aws-access-key");
    }

    #[test]
    fn multiple_events_valid_json() {
        let events = vec![
            sample_finding(),
            ScanEvent::Progress(ProgressEvent {
                source: SourceKind::Fs,
                stage: "scanning",
                objects_scanned: 100,
                bytes_scanned: 1024,
                findings_emitted: 1,
            }),
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 500,
                bytes_scanned: 1024,
                findings_emitted: 1,
                errors: 0,
                throughput_mib_s: 2.0,
            }),
        ];
        let out = collect_json(events);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0]["type"], "finding");
        assert_eq!(parsed[1]["type"], "progress");
        assert_eq!(parsed[2]["type"], "summary");
    }

    #[test]
    fn empty_array_valid_json() {
        let out = collect_json(vec![]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert!(parsed.is_empty());
    }
}

/// Loom model of the separator logic in [`JsonEventSink::emit`].
///
/// Two threads race to emit an element. The model captures the essential
/// synchronization: an [`AtomicBool`] swap determines `\n` vs `,\n`, and
/// a [`Mutex`] guards the write. The assertion checks that the first byte
/// written is always `\n` (not `,`), which holds only when the swap
/// happens **inside** the mutex.
///
/// Run with: `RUSTFLAGS="--cfg loom" cargo test --lib unified::json_sink::loom_tests`
#[cfg(loom)]
mod loom_tests {
    use loom::sync::atomic::{AtomicBool, Ordering};
    use loom::sync::{Arc, Mutex};

    #[test]
    fn separator_first_element_never_has_comma() {
        loom::model(|| {
            let first = Arc::new(AtomicBool::new(true));
            let writer = Arc::new(Mutex::new(Vec::<u8>::new()));

            let handles: Vec<_> = (0..2)
                .map(|id| {
                    let first = first.clone();
                    let writer = writer.clone();
                    loom::thread::spawn(move || {
                        // --- mirrors production emit() ---
                        // "Format" payload (like with_format_buf encode closure).
                        let payload = vec![b'A' + id];

                        // Lock, determine separator, then write both
                        // (like the write closure in the fixed emit()).
                        let mut w = writer.lock().unwrap();
                        let sep: &[u8] = if first.swap(false, Ordering::Relaxed) {
                            b"\n"
                        } else {
                            b",\n"
                        };
                        w.extend_from_slice(sep);
                        w.extend_from_slice(&payload);
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            let output = writer.lock().unwrap();
            // Valid: "\nA,\nB" or "\nB,\nA"
            // Buggy: ",\nB\nA" or ",\nA\nB" (leading comma)
            assert!(
                output.starts_with(b"\n"),
                "TOCTOU: first element preceded by comma: {:?}",
                String::from_utf8_lossy(&output),
            );
        });
    }
}
