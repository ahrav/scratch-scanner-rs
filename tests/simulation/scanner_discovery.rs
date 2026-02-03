#![cfg(any(test, feature = "sim-harness"))]
//! Scanner simulation coverage for discovery type-hint fallback.

use std::collections::BTreeMap;

use scanner_rs::sim::FaultPlan;
use scanner_rs::sim::SimNodeSpec;
use scanner_rs::sim_scanner::{
    build_engine_from_suite, generate_scenario, RunConfig, RunOutcome, ScannerSimRunner,
    ScenarioGenConfig, SimTypeHint,
};

#[test]
fn discovery_falls_back_when_type_hint_missing() {
    let gen_cfg = ScenarioGenConfig {
        rule_count: 1,
        file_count: 1,
        secrets_per_file: 1,
        token_len: 12,
        min_noise_len: 4,
        max_noise_len: 8,
        representations: vec![scanner_rs::sim_scanner::SecretRepr::Raw],
        ..ScenarioGenConfig::default()
    };

    let mut scenario = generate_scenario(1234, &gen_cfg).expect("generate scenario");
    // Force discovery to treat the file type as unknown and require fallback.
    for node in &mut scenario.fs.nodes {
        if let SimNodeSpec::File { type_hint, .. } = node {
            *type_hint = SimTypeHint::Unknown;
            break;
        }
    }

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
        stability_runs: 1,
    };

    let engine =
        build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine from suite");
    let required = engine.required_overlap() as u32;
    if run_cfg.overlap < required {
        run_cfg.overlap = required;
    }

    let runner = ScannerSimRunner::new(run_cfg.clone(), 0xC0FF_EE01);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    let first = runner.run(&scenario, &engine, &fault_plan);
    let second = runner.run(&scenario, &engine, &fault_plan);

    match (first, second) {
        (RunOutcome::Ok { findings: a }, RunOutcome::Ok { findings: b }) => {
            assert_eq!(a, b);
            assert!(!a.is_empty());
        }
        (RunOutcome::Failed(fail), _) | (_, RunOutcome::Failed(fail)) => {
            panic!("discovery fallback sim failed: {fail:?}");
        }
    }
}
