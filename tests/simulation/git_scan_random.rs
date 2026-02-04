#![cfg(any(test, feature = "sim-harness"))]
//! Deterministic Git simulation integration coverage.
//!
//! Validates that the Git simulation runner yields stable outputs across
//! multiple schedule seeds for a minimal repository model.
//!
//! This is a high-level stability check; it does not validate pack decoding
//! or fault injection paths.

use scanner_rs::sim_git_scan::{
    GitBlobSpec, GitCommitSpec, GitFaultPlan, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel,
    GitRunConfig, GitScenario, GitSimRunner, GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec,
    RunOutcome,
};

fn oid(val: u8) -> GitOid {
    GitOid {
        bytes: vec![val; 20],
    }
}

fn simple_scenario() -> GitScenario {
    GitScenario {
        schema_version: scanner_rs::sim_git_scan::scenario::GIT_SCENARIO_SCHEMA_VERSION,
        repo: GitRepoModel {
            object_format: GitObjectFormat::Sha1,
            refs: vec![GitRefSpec {
                name: b"refs/heads/main".to_vec(),
                tip: oid(1),
                watermark: None,
            }],
            commits: vec![GitCommitSpec {
                oid: oid(1),
                parents: Vec::new(),
                tree: oid(2),
                generation: 1,
            }],
            trees: vec![GitTreeSpec {
                oid: oid(2),
                entries: vec![GitTreeEntrySpec {
                    name: b"file.txt".to_vec(),
                    mode: 0o100644,
                    oid: oid(3),
                    kind: GitTreeEntryKind::Blob,
                }],
            }],
            blobs: vec![GitBlobSpec {
                oid: oid(3),
                bytes: b"hello".to_vec(),
            }],
        },
        artifacts: None,
    }
}

#[test]
fn git_scan_stability_across_schedule_seeds() {
    let scenario = simple_scenario();
    let cfg = GitRunConfig {
        workers: 2,
        max_steps: 0,
        stability_runs: 3,
        trace_capacity: 128,
    };
    let runner = GitSimRunner::new(cfg, 42);
    match runner.run(&scenario, &GitFaultPlan::default()) {
        RunOutcome::Ok { .. } => {}
        RunOutcome::Failed(fail) => {
            panic!("git sim stability failure: {fail:?}");
        }
    }
}
