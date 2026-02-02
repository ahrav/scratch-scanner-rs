#![cfg(feature = "sim-harness")]
//! Bounded random scanner simulations to exercise scheduling, chunking, and faults.

use std::collections::BTreeMap;

use scanner_rs::sim::fault::{Corruption, FaultPlan, FileFaultPlan, IoFault, ReadFault};
use scanner_rs::sim::SimRng;
use scanner_rs::sim_scanner::{
    build_engine_from_suite, generate_scenario, RunConfig, RunOutcome, ScannerSimRunner,
    ScenarioGenConfig, SecretRepr,
};

const DEFAULT_SEED_COUNT: u64 = 25;

fn seed_value_from_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn bounded_random_scanner_sims() {
    let seed_start = seed_value_from_env("SIM_SCANNER_SEED_START", 0);
    let seed_count = seed_value_from_env("SIM_SCANNER_SEED_COUNT", DEFAULT_SEED_COUNT);
    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let mut rng = SimRng::new(seed.wrapping_add(0xA5A5_5A5A));
        let run_cfg = random_run_config(&mut rng);
        let gen_cfg = ScenarioGenConfig {
            rule_count: 3,
            file_count: 3,
            secrets_per_file: 3,
            token_len: 12,
            min_noise_len: 4,
            max_noise_len: 16,
            representations: vec![
                SecretRepr::Raw,
                SecretRepr::Base64,
                SecretRepr::UrlPercent,
                SecretRepr::Utf16Le,
                SecretRepr::Utf16Be,
            ],
            ..ScenarioGenConfig::default()
        };

        let scenario = generate_scenario(seed, &gen_cfg).expect("generate scenario");
        let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
        let mut run_cfg = run_cfg;
        let required = engine.required_overlap() as u32;
        if run_cfg.overlap < required {
            run_cfg.overlap = required;
        }

        let fault_plan = random_fault_plan(&mut rng, &scenario, run_cfg.chunk_size);
        let schedule_seed = seed.wrapping_add(0xC0FF_EE00);
        let runner = ScannerSimRunner::new(run_cfg.clone(), schedule_seed);

        match runner.run(&scenario, &engine, &fault_plan) {
            RunOutcome::Ok { .. } => {}
            RunOutcome::Failed(fail) => {
                if std::env::var_os("DUMP_SIM_FAIL").is_some() {
                    eprintln!(
                        "sim failure (seed {seed}):\nrun_config={run_cfg:?}\nscenario={}\nfault_plan={fault_plan:?}",
                        serde_json::to_string_pretty(&scenario).unwrap()
                    );
                }
                panic!("scanner sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}

fn random_run_config(rng: &mut SimRng) -> RunConfig {
    let workers = rng.gen_range(1, 5);
    let chunk_size = rng.gen_range(16, 64);
    RunConfig {
        workers,
        chunk_size,
        overlap: 64,
        max_in_flight_objects: 16,
        buffer_pool_cap: 8,
        max_steps: 0,
        max_transform_depth: 3,
        scan_utf16_variants: true,
        stability_runs: 2,
    }
}

fn random_fault_plan(
    rng: &mut SimRng,
    scenario: &scanner_rs::sim_scanner::Scenario,
    chunk_size: u32,
) -> FaultPlan {
    let mut per_file = BTreeMap::new();
    let max_len = chunk_size.max(4);

    for node in &scenario.fs.nodes {
        let scanner_rs::sim::SimNodeSpec::File { path, .. } = node else {
            continue;
        };
        let mut plan = FileFaultPlan {
            open: None,
            reads: Vec::new(),
            cancel_after_reads: None,
        };

        if rng.gen_bool(1, 10) {
            plan.open = Some(IoFault::ErrKind { kind: 2 });
        }

        let read_faults = rng.gen_range(0, 3);
        for _ in 0..read_faults {
            let fault = match rng.gen_range(0, 3) {
                0 => IoFault::PartialRead {
                    max_len: rng.gen_range(1, max_len),
                },
                1 => IoFault::EIntrOnce,
                _ => IoFault::ErrKind { kind: 5 },
            };
            let latency = if rng.gen_bool(1, 3) {
                rng.gen_range(1, 4) as u64
            } else {
                0
            };
            let corruption = if rng.gen_bool(1, 12) {
                Some(Corruption::FlipBit {
                    offset: 0,
                    mask: 0x01,
                })
            } else {
                None
            };
            plan.reads.push(ReadFault {
                fault: Some(fault),
                latency_ticks: latency,
                corruption,
            });
        }

        if rng.gen_bool(1, 20) {
            plan.cancel_after_reads = Some(rng.gen_range(1, 4));
        }

        if plan.open.is_some() || plan.cancel_after_reads.is_some() || !plan.reads.is_empty() {
            per_file.insert(path.bytes.clone(), plan);
        }
    }

    FaultPlan { per_file }
}
