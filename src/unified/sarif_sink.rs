//! SARIF 2.1.0 event sink.
//!
//! Streams findings into a valid [SARIF 2.1.0] JSON document. The envelope
//! (version, schema, tool driver) is written eagerly in
//! [`SarifEventSink::new`]; each `Finding` event appends one result object
//! to `runs[0].results`. Non-finding events (`Progress`, `Summary`,
//! `Diagnostic`) are silently dropped — they have no SARIF representation.
//!
//! `flush()` writes the closing `]}]}\n` and flushes the writer.
//!
//! # SARIF result mapping
//!
//! | `FindingEvent` field | SARIF path |
//! |----------------------|------------|
//! | `rule_name` | `ruleId` |
//! | `rule_name` | `message.text` (as `"Secret matched rule {name}"`) |
//! | `object_path` | `locations[0].physicalLocation.artifactLocation.uri` |
//! | `start` | `locations[0].physicalLocation.region.byteOffset` |
//! | `end - start` | `locations[0].physicalLocation.region.byteLength` |
//!
//! [SARIF 2.1.0]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use std::io::{BufWriter, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::events::{with_format_buf, EventSink, FindingEvent, ScanEvent};
use super::json_write::{write_json_bytes, write_json_str, write_u64};

/// Default buffer size (64 KiB).
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

const SARIF_SCHEMA: &str = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";

/// SARIF 2.1.0 event sink.
///
/// Only `Finding` events produce SARIF results. Progress, summary, and
/// diagnostic events are silently ignored.
pub struct SarifEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    first: AtomicBool,
}

impl<W: Write + Send> SarifEventSink<W> {
    pub fn new(mut writer: W) -> Self {
        let version = env!("CARGO_PKG_VERSION");
        // Write the SARIF envelope up to the start of the results array.
        let _ = write!(
            writer,
            "{{\"version\":\"2.1.0\",\"$schema\":\"{SARIF_SCHEMA}\",\
             \"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"scanner-rs\",\
             \"version\":\"{version}\"}}}},\"results\":["
        );
        Self {
            writer: Mutex::new(BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, writer)),
            first: AtomicBool::new(true),
        }
    }
}

impl<W: Write + Send + 'static> EventSink for SarifEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        // Only findings produce SARIF results.
        let f = match &event {
            ScanEvent::Finding(f) => f,
            _ => return,
        };

        with_format_buf(
            |buf| encode_sarif_result(f, buf),
            |bytes| {
                let mut writer = self.writer.lock().expect("sarif sink mutex poisoned");
                if self.first.swap(false, Ordering::Relaxed) {
                    // No comma before first result.
                } else {
                    let _ = writer.write_all(b",");
                }
                if let Err(e) = writer.write_all(bytes) {
                    if e.kind() == ErrorKind::BrokenPipe {
                        return;
                    }
                    panic!("sarif event sink write failed: {}", e);
                }
            },
        );
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("sarif sink mutex poisoned");
        // Close: results array, run object, runs array, root object.
        if let Err(e) = writer.write_all(b"]}]}\n") {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("sarif event sink write failed: {}", e);
        }
        if let Err(e) = writer.flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("sarif event sink flush failed: {}", e);
        }
    }
}

/// Encode a single SARIF `result` object for a finding.
///
/// Produces: `{"ruleId":"…","message":{…},"locations":[{…}]}`
/// See module-level table for the full field mapping.
fn encode_sarif_result(f: &FindingEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"ruleId\":\"");
    write_json_str(f.rule_name, buf);
    buf.extend_from_slice(b"\",\"message\":{\"text\":\"Secret matched rule ");
    write_json_str(f.rule_name, buf);
    buf.extend_from_slice(
        b"\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"",
    );
    write_json_bytes(f.object_path, buf);
    buf.extend_from_slice(b"\"},\"region\":{\"byteOffset\":");
    write_u64(f.start, buf);
    buf.extend_from_slice(b",\"byteLength\":");
    write_u64(f.end.saturating_sub(f.start), buf);
    buf.extend_from_slice(b"}}}]}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified::events::ScanEvent;
    use crate::unified::SourceKind;

    fn collect_sarif(events: Vec<ScanEvent<'_>>) -> String {
        let buf = Vec::new();
        let sink = SarifEventSink::new(buf);
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
    fn valid_sarif_envelope() {
        let out = collect_sarif(vec![sample_finding()]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SARIF_SCHEMA);
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "scanner-rs");
    }

    #[test]
    fn sarif_result_fields() {
        let out = collect_sarif(vec![sample_finding()]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "aws-access-key");
        assert!(result["message"]["text"]
            .as_str()
            .unwrap()
            .contains("aws-access-key"));
        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/main.rs");
        assert_eq!(loc["region"]["byteOffset"], 42);
        assert_eq!(loc["region"]["byteLength"], 38); // 80 - 42
    }

    #[test]
    fn multiple_findings() {
        let events = vec![
            sample_finding(),
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: b"config/.env",
                start: 0,
                end: 40,
                rule_id: 3,
                rule_name: "generic-secret",
                commit_id: Some(1),
                change_kind: Some("add"),
            }),
        ];
        let out = collect_sarif(events);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn non_finding_events_ignored() {
        use crate::unified::events::{DiagnosticEvent, ProgressEvent, SummaryEvent};

        let events: Vec<ScanEvent<'_>> = vec![
            ScanEvent::Progress(ProgressEvent {
                source: SourceKind::Fs,
                stage: "scanning",
                objects_scanned: 100,
                bytes_scanned: 1024,
                findings_emitted: 0,
            }),
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 500,
                bytes_scanned: 1024,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: 2.0,
            }),
            ScanEvent::Diagnostic(DiagnosticEvent {
                level: "debug",
                message: "test",
            }),
        ];
        let out = collect_sarif(events);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn empty_results_valid_sarif() {
        let out = collect_sarif(vec![]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }
}
