#![cfg(any(test, feature = "sim-harness"))]
//! Replay checked-in `.mutation.case.json` artifacts for regression prevention.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use scanner_rs::sim::fault::FaultPlan;
use scanner_rs::sim::mutation::{
    build_mutation_engine, build_mutation_scenario, check_mutation_expectations, MutationPlan,
};
use scanner_rs::sim::SimRng;
use scanner_rs::sim_scanner::{RunConfig, RunOutcome, ScannerSimRunner};

#[derive(serde::Deserialize)]
struct MutationCorpusEntry {
    seed: u64,
    run_config: RunConfig,
    plans: Vec<MutationPlan>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from("tests")
        .join("corpus")
        .join("scanner_mutation")
}

fn list_cases(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut cases: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.ends_with(".mutation.case.json"))
        })
        .collect();
    cases.sort();
    cases
}

#[test]
fn replay_mutation_corpus_cases() {
    let dir = corpus_dir();
    let cases = list_cases(&dir);
    if cases.is_empty() {
        return;
    }

    let empty_fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    for path in cases {
        let bytes = fs::read(&path).expect("read corpus case");
        let entry: MutationCorpusEntry = serde_json::from_slice(&bytes).expect("parse corpus case");

        // Initial build to discover required overlap.
        let mut scenario_rng = SimRng::new(entry.seed);
        let (scenario, _, _) = build_mutation_scenario(&entry.plans, 64, &mut scenario_rng);
        let engine = build_mutation_engine(&scenario.rule_suite, &entry.run_config)
            .expect("build mutation engine");
        let mut run_config = entry.run_config.clone();
        let required = engine.required_overlap() as u32;
        if run_config.overlap < required {
            run_config.overlap = required;
        }
        if run_config.chunk_size < run_config.overlap {
            run_config.chunk_size = run_config.overlap;
        }

        // Rebuild with overlap-adjusted noise.
        let mut scenario_rng = SimRng::new(entry.seed);
        let (scenario, gen_cases, noise_len) =
            build_mutation_scenario(&entry.plans, required as usize, &mut scenario_rng);
        let engine = build_mutation_engine(&scenario.rule_suite, &run_config)
            .expect("build mutation engine");
        let required = engine.required_overlap() as u32;
        if run_config.overlap < required {
            run_config.overlap = required;
        }
        if run_config.chunk_size < run_config.overlap {
            run_config.chunk_size = run_config.overlap;
        }

        let schedule_seed = entry.seed.wrapping_add(0xC0FF_EE00);
        let runner = ScannerSimRunner::new(run_config, schedule_seed);
        let outcome = runner.run(&scenario, &engine, &empty_fault_plan);

        match outcome {
            RunOutcome::Ok { findings } => {
                let check = check_mutation_expectations(&gen_cases, noise_len, &findings);
                if !check.passed {
                    let msgs: Vec<&str> = check
                        .violations
                        .iter()
                        .map(|v| v.message.as_str())
                        .collect();
                    panic!(
                        "mutation corpus replay failed for {:?}:\n{}",
                        path,
                        msgs.join("\n"),
                    );
                }
            }
            RunOutcome::Failed(fail) => {
                panic!("mutation corpus replay failed for {:?}: {:?}", path, fail);
            }
        }
    }
}
