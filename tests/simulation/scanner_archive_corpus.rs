#![cfg(any(test, feature = "sim-harness"))]
//! Deterministic archive simulation cases for regression coverage.
//!
//! Focus areas: long names, duplicate locators, traversal/clamping, encrypted
//! entries, truncated archives, nested archives, budget caps (entry/archive/root),
//! path-budget enforcement, gzip name fallback, and directory entries.

use std::collections::BTreeMap;

use scanner_rs::archive::ArchiveConfig;
use scanner_rs::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use scanner_rs::sim::FaultPlan;
use scanner_rs::sim_archive::{entry_paths, materialize_archive, materialize_archive_with_paths};
use scanner_rs::sim_scanner::{
    build_engine_from_suite, generate_scenario, ArchiveCorruptionSpec, ArchiveEntrySpec,
    ArchiveFileSpec, ArchiveKindSpec, EntryCompressionSpec, EntryKindSpec, ExpectedDisposition,
    ExpectedSecret, RuleSuiteSpec, RunConfig, RunOutcome, ScannerSimRunner, Scenario,
    ScenarioGenConfig, SecretRepr, SpanU32, SyntheticRuleSpec,
};

const SCHEMA_VERSION: u32 = 1;
const SECRET_PRIMARY: &[u8] = b"SIM0_AB12";
const SECRET_SECONDARY: &[u8] = b"SIM0_CD34";

#[test]
fn archive_corpus_smoke() {
    let archive_cfg = ArchiveConfig {
        enabled: true,
        ..ArchiveConfig::default()
    };

    let gen_cfg = ScenarioGenConfig {
        file_count: 0,
        archive_count: 1,
        archive_entries: 2,
        secrets_per_file: 2,
        representations: vec![SecretRepr::Raw],
        archive: archive_cfg.clone(),
        ..ScenarioGenConfig::default()
    };

    let scenario = generate_scenario(2025, &gen_cfg).expect("generate scenario");
    let mut run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 4,
        buffer_pool_cap: 4,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: archive_cfg,
        stability_runs: 1,
        archive_deadline_countdown: None,
    };

    run_cfg.adjust_for_overlap(engine.required_overlap() as u32);

    let runner = ScannerSimRunner::new(run_cfg, seed);
    match runner.run(&scenario, &engine, &FaultPlan::default()) {
        RunOutcome::Ok { .. } => {}
        RunOutcome::Failed(fail) => panic!("archive corpus sim failed: {fail:?}"),
    }
}

fn run_archive_scenario(scenario: Scenario, archive_cfg: ArchiveConfig, seed: u64) {
    let mut run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 4,
        buffer_pool_cap: 4,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: archive_cfg,
        stability_runs: 1,
    };

    let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
    let required = engine.required_overlap() as u32;
    if run_cfg.overlap < required {
        run_cfg.overlap = required;
    }
    if run_cfg.chunk_size < run_cfg.overlap {
        run_cfg.chunk_size = run_cfg.overlap;
    }

    let runner = ScannerSimRunner::new(run_cfg, seed);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    match runner.run(&scenario, &engine, &fault_plan) {
        RunOutcome::Ok { .. } => {}
        RunOutcome::Failed(fail) => {
            panic!("archive corpus sim failed: {fail:?}");
        }
    }
}
