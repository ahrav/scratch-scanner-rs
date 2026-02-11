//! Property tests for `CommitMetaEvent` encoding and exactly-once emission.
//!
//! # Invariants
//! - JSONL encoding produces valid JSON with correct field values.
//! - OID hex length is always `2 * oid.len()`.
//! - `AtomicBitSet::test_and_set` fires exactly once per bit under sequential replay.

use proptest::prelude::*;

use scanner_rs::git_scan::OidBytes;
use scanner_rs::stdx::AtomicBitSet;
use scanner_rs::unified::events::{CommitMetaEvent, EventEncoder, JsonlEncoder, ScanEvent};

/// Strategy for SHA-1 OidBytes.
fn sha1_oid_strategy() -> impl Strategy<Value = OidBytes> {
    prop::array::uniform20(any::<u8>()).prop_map(OidBytes::sha1)
}

/// Strategy for SHA-256 OidBytes.
fn sha256_oid_strategy() -> impl Strategy<Value = OidBytes> {
    prop::array::uniform32(any::<u8>()).prop_map(OidBytes::sha256)
}

/// Strategy for either SHA-1 or SHA-256 OidBytes.
fn oid_strategy() -> impl Strategy<Value = OidBytes> {
    prop_oneof![sha1_oid_strategy(), sha256_oid_strategy()]
}

proptest! {
    /// Encoding a `CommitMetaEvent` produces valid JSON with matching fields.
    #[test]
    fn encoding_roundtrip(
        oid in oid_strategy(),
        commit_id in any::<u32>(),
        timestamp in any::<u64>(),
    ) {
        let event = CommitMetaEvent {
            commit_id,
            commit_oid: oid,
            timestamp,
            identity: None,
        };

        let encoder = JsonlEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&ScanEvent::CommitMeta(event), &mut buf);
        let line = std::str::from_utf8(&buf).expect("valid UTF-8");

        // Must be a complete JSON object with trailing newline.
        assert!(line.starts_with('{'), "line must start with open brace");
        assert!(line.ends_with("}\n"), "line must end with close brace + newline");

        // Must contain correct type.
        prop_assert!(line.contains("\"type\":\"commit_meta\""));

        // commit_id must match.
        let cid_needle = format!("\"commit_id\":{commit_id}");
        prop_assert!(line.contains(&cid_needle), "missing commit_id in output");

        // timestamp must match.
        let ts_needle = format!("\"timestamp\":{timestamp}");
        prop_assert!(line.contains(&ts_needle), "missing timestamp in output");

        // OID hex length must be 2 * oid byte length.
        let oid_start = line.find("\"oid\":\"").expect("missing oid field") + 7;
        let oid_end = line[oid_start..].find('"').expect("unterminated oid") + oid_start;
        let hex_str = &line[oid_start..oid_end];
        prop_assert_eq!(hex_str.len(), oid.len() as usize * 2);

        // Verify hex decodes back to original bytes.
        let decoded: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect();
        prop_assert_eq!(decoded.as_slice(), oid.as_slice());
    }

    /// Each commit_id with findings triggers emission exactly once under
    /// sequential replay through an `AtomicBitSet`.
    #[test]
    fn exactly_once_under_sequential_replay(
        events in prop::collection::vec(
            (0u32..16, any::<bool>()), // (commit_id, has_findings)
            1..64,
        ),
    ) {
        let bitset = AtomicBitSet::empty(16);
        let mut emitted: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

        for &(commit_id, has_findings) in &events {
            if has_findings && bitset.test_and_set(commit_id as usize) {
                *emitted.entry(commit_id).or_insert(0) += 1;
            }
        }

        // Each commit_id that was emitted must have been emitted exactly once.
        for (&cid, &count) in &emitted {
            prop_assert!(
                count == 1,
                "commit_id {} emitted {} times (expected 1)", cid, count
            );
        }

        // Every commit_id that had findings at least once must have been emitted.
        let expected_ids: std::collections::HashSet<u32> = events
            .iter()
            .filter(|(_, has)| *has)
            .map(|(id, _)| *id)
            .collect();
        for id in &expected_ids {
            prop_assert!(
                emitted.contains_key(id),
                "commit_id {} had findings but was never emitted", id
            );
        }
    }
}
