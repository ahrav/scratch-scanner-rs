#![cfg(any(test, feature = "scheduler-sim"))]

use std::fs;

use scanner_rs::scheduler::sim_executor_harness::{
    assert_deterministic, run_with_choices, trace_hash, DriverChoice, ExternalEvent, Instruction,
    LogicalTaskInit, ResourceSpec, SimCase, SimExecCfg, SpawnPlacement, TaskProgram,
};

/// Minimal deterministic case used to sanity-check replay logic.
fn simple_case(seed: u64) -> SimCase {
    let exec_cfg = SimExecCfg {
        workers: 2,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![TaskProgram {
        name: "root".to_string(),
        code: vec![
            Instruction::Yield {
                placement: SpawnPlacement::Local,
            },
            Instruction::Complete,
        ],
    }];

    SimCase {
        exec_cfg,
        resources: vec![ResourceSpec { id: 0, total: 4 }],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![
            scanner_rs::scheduler::sim_executor_harness::ScheduledEvent {
                at_step: 3,
                event: ExternalEvent::CloseGateJoin,
            },
        ],
        max_steps: 50,
    }
}

/// Ensures deterministic traces for a fixed case + choices.
#[test]
fn scheduler_sim_deterministic_basic() {
    let case = simple_case(42);
    let choices = vec![DriverChoice { idx: 0 }; 16];
    assert_deterministic(&case, &choices);

    let trace = run_with_choices(&case, &choices);
    let _ = trace_hash(&trace);
}

/// Replays any stored repro artifacts and validates trace hashes.
#[test]
fn scheduler_sim_replay_corpus() {
    let corpus_dir = "tests/scheduler_corpus";
    let entries = fs::read_dir(corpus_dir).unwrap_or_else(|_| panic!("missing {corpus_dir}"));

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let data = fs::read_to_string(&path).expect("read corpus");
        let artifact: scanner_rs::scheduler::sim_executor_harness::ReproArtifact =
            serde_json::from_str(&data).expect("parse artifact");
        let trace = run_with_choices(&artifact.case, &artifact.driver_choices);
        let hash = trace_hash(&trace);
        assert_eq!(
            hash, artifact.expected_trace_hash,
            "trace hash mismatch for {path:?}"
        );
    }
}
