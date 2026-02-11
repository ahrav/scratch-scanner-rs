//! Streaming JSON array event sink.
//!
//! Writes a single valid JSON array document (`[{...},{...},...]`).
//! Results are streamed as they arrive; the closing `]\n` is written
//! on [`flush()`](EventSink::flush).
//!
//! # Thread safety
//!
//! Multiple workers call [`emit()`](EventSink::emit) concurrently. Each call
//! formats into a per-thread scratch buffer (via `with_format_buf`), then
//! acquires the writer mutex only for the `write_all`. This keeps lock hold
//! time proportional to a single memcpy, not to JSON encoding cost.
//!
//! # Wire invariants
//!
//! - The opening `[` is written eagerly in [`JsonEventSink::new`].
//! - Each element is preceded by `\n` (first) or `,\n` (subsequent).
//! - `flush()` writes `\n]\n` and flushes the underlying `BufWriter`.
//! - Broken-pipe errors are silently swallowed (for piped consumers like
//!   `head`); all other I/O errors panic.

use std::io::{BufWriter, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::events::{
    encode_commit_meta, encode_diagnostic, encode_finding, encode_progress, encode_summary,
    with_format_buf, EventSink, ScanEvent,
};

/// Default buffer size (64 KiB).
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// JSON array event sink: streams `[{...},{...},...]`.
///
/// The opening `[` is written on construction. Each `emit()` appends one
/// JSON object (comma-separated). `flush()` writes `]\n` and flushes the
/// underlying writer.
pub struct JsonEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    first: AtomicBool,
}

impl<W: Write + Send> JsonEventSink<W> {
    pub fn new(mut writer: W) -> Self {
        // Write the opening bracket immediately.
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
            },
            |bytes| {
                let mut writer = self.writer.lock().expect("json sink mutex poisoned");
                // Write comma separator between elements.
                if self.first.swap(false, Ordering::Relaxed) {
                    let _ = writer.write_all(b"\n");
                } else {
                    let _ = writer.write_all(b",\n");
                }
                if let Err(e) = writer.write_all(bytes) {
                    if e.kind() == ErrorKind::BrokenPipe {
                        return;
                    }
                    panic!("json event sink write failed: {}", e);
                }
            },
        );
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("json sink mutex poisoned");
        if let Err(e) = writer.write_all(b"\n]\n") {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("json event sink write failed: {}", e);
        }
        if let Err(e) = writer.flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("json event sink flush failed: {}", e);
        }
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
