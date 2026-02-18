#![no_main]

//! Fuzz target for the JSONL encode pipeline.
//!
//! Exercises `encode_finding`, `encode_commit_meta`, `encode_diagnostic`,
//! and `encode_identity_dictionary` with arbitrary inputs, verifying:
//!
//! 1. Output is valid UTF-8.
//! 2. Output parses as valid JSON.
//! 3. The `"type"` field matches the expected event type.

use libfuzzer_sys::fuzz_target;

use scanner_rs::git_scan::identity_intern::CommitIdentityIds;
use scanner_rs::git_scan::object_id::OidBytes;
use scanner_rs::unified::events::{
    CommitMetaEvent, DiagnosticEvent, FindingEvent, IdentityDictionaryEvent,
};
use scanner_rs::unified::harness_api;
use scanner_rs::unified::SourceKind;

/// Validate that `buf` is valid UTF-8 and parseable as a JSON object
/// with the expected `"type"` field.
fn validate(buf: &[u8], expected_type: &str) {
    let s = std::str::from_utf8(buf).expect("output must be valid UTF-8");
    let v: serde_json::Value =
        serde_json::from_str(s).unwrap_or_else(|e| panic!("invalid JSON: {e}\nraw: {s}"));
    assert_eq!(
        v.get("type").and_then(|v| v.as_str()),
        Some(expected_type),
    );
}

fn le_u64(data: &[u8], off: usize) -> u64 {
    data.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

/// Return the longest valid UTF-8 prefix of `data`, or a fallback.
fn utf8_prefix(data: &[u8]) -> &str {
    match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) if e.valid_up_to() > 0 => {
            // SAFETY: from_utf8 proved this prefix is valid.
            unsafe { std::str::from_utf8_unchecked(&data[..e.valid_up_to()]) }
        }
        _ => "fuzz",
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    match data[0] % 4 {
        0 => {
            let source = if data[1] & 1 == 0 {
                SourceKind::Fs
            } else {
                SourceKind::Git
            };
            // Split data: first half for object_path, second half for string fields.
            let mid = data.len() / 2;
            let f = FindingEvent {
                source,
                object_path: &data[2..mid],
                start: le_u64(data, 2),
                end: le_u64(data, 10),
                rule_id: le_u32(data, 18),
                rule_name: utf8_prefix(&data[mid..]),
                commit_id: if data[1] & 2 != 0 {
                    Some(le_u32(data, 22))
                } else {
                    None
                },
                change_kind: if data[1] & 4 != 0 {
                    Some(utf8_prefix(&data[mid + 1..]))
                } else {
                    None
                },
                confidence_score: 0,
            };
            let mut buf = Vec::new();
            harness_api::encode_finding(&f, &mut buf);
            validate(&buf, "finding");
        }
        1 => {
            let mut raw = [0u8; 20];
            let n = raw.len().min(data.len().saturating_sub(1));
            raw[..n].copy_from_slice(&data[1..1 + n]);
            let m = CommitMetaEvent {
                commit_id: le_u32(data, 21),
                commit_oid: OidBytes::sha1(raw),
                timestamp: le_u64(data, 25),
                identity: if data[1] & 1 != 0 {
                    Some(CommitIdentityIds {
                        author_name: le_u32(data, 1),
                        author_email: le_u32(data, 5),
                        committer_name: le_u32(data, 9),
                        committer_email: le_u32(data, 13),
                    })
                } else {
                    None
                },
            };
            let mut buf = Vec::new();
            harness_api::encode_commit_meta(&m, &mut buf);
            validate(&buf, "commit_meta");
        }
        2 => {
            let level = match data[1] % 3 {
                0 => "debug",
                1 => "warn",
                _ => "error",
            };
            let d = DiagnosticEvent {
                level,
                message: utf8_prefix(&data[2..]),
            };
            let mut buf = Vec::new();
            harness_api::encode_diagnostic(&d, &mut buf);
            validate(&buf, "diagnostic");
        }
        _ => {
            let d = IdentityDictionaryEvent {
                id: le_u32(data, 1),
                value: &data[5..],
            };
            let mut buf = Vec::new();
            harness_api::encode_identity_dictionary(&d, &mut buf);
            validate(&buf, "identity_dictionary");
        }
    }
});
