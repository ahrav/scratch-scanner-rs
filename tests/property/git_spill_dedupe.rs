//! Property tests for spill run merge/dedupe.
//!
//! The merged output should match a naive in-memory sort+dedupe across all
//! records, regardless of how they are partitioned into runs.

use std::io::Cursor;

use proptest::prelude::*;

use scanner_rs::git_scan::{ChangeKind, OidBytes};
use scanner_rs::git_scan::{RunContext, RunHeader, RunMerger, RunReader, RunRecord, RunWriter};

fn record_strategy() -> impl Strategy<Value = RunRecord> {
    // Keep paths short and ASCII to avoid blowing up run sizes while still
    // exercising ordering and dedupe across OID/path/context combinations.
    let oid = prop::array::uniform20(any::<u8>()).prop_map(OidBytes::sha1);
    let path = "[a-z]{1,6}".prop_map(|s| s.into_bytes());
    let commit_id = any::<u32>();
    let parent_idx = any::<u8>();
    let change_kind = any::<bool>();
    let ctx_flags = any::<u16>();
    let cand_flags = any::<u16>();

    (
        oid,
        path,
        commit_id,
        parent_idx,
        change_kind,
        ctx_flags,
        cand_flags,
    )
        .prop_map(
            |(oid, path, commit_id, parent_idx, change_kind, ctx_flags, cand_flags)| RunRecord {
                oid,
                ctx: RunContext {
                    commit_id,
                    parent_idx,
                    change_kind: if change_kind {
                        ChangeKind::Add
                    } else {
                        ChangeKind::Modify
                    },
                    ctx_flags,
                    cand_flags,
                },
                path,
            },
        )
}

fn write_run(records: &[RunRecord]) -> Vec<u8> {
    // The on-disk format expects sorted+deduped input; emulate that here.
    let mut run_records = records.to_vec();
    run_records.sort();
    run_records.dedup();

    let header = RunHeader::new(20, run_records.len() as u32).unwrap();
    let mut buf = Vec::new();
    let mut writer = RunWriter::new(&mut buf, header).unwrap();
    for record in &run_records {
        writer.write_record(record).unwrap();
    }
    writer.finish().unwrap();
    buf
}

proptest! {
    #[test]
    fn spill_merge_matches_naive(
        records in prop::collection::vec(record_strategy(), 1..50),
        run_count in 1usize..6,
    ) {
        // Naive reference: all records combined, then globally sorted+deduped.
        let mut expected = records.clone();
        expected.sort();
        expected.dedup();

        let mut runs: Vec<Vec<RunRecord>> = vec![Vec::new(); run_count];
        for (idx, rec) in records.into_iter().enumerate() {
            runs[idx % run_count].push(rec);
        }

        let mut readers = Vec::new();
        for run in runs {
            let buf = write_run(&run);
            let reader = RunReader::new(Cursor::new(buf), 8192).unwrap();
            readers.push(reader);
        }

        // Merge should preserve global ordering and suppress duplicates.
        let mut merger = RunMerger::new(readers).unwrap();
        let mut actual = Vec::new();
        while let Some(record) = merger.next_unique().unwrap() {
            actual.push(record);
        }

        prop_assert_eq!(actual, expected);
    }
}
