#![cfg(feature = "sim-harness")]
//! Replay minimized scheduler corpus cases and assert regressions stay fixed.

use std::fs;
use std::path::{Path, PathBuf};

use scanner_rs::sim_scheduler::{Program, RunOutcome, SimSchedulerConfig, SimSchedulerRunner};

#[derive(Debug, serde::Deserialize)]
struct SchedulerCorpusCase {
    seed: u64,
    config: SimSchedulerConfig,
    program: Program,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from("tests").join("corpus").join("scheduler")
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
                .map(|name| name.ends_with(".case.json"))
                .unwrap_or(false)
        })
        .collect();
    cases.sort();
    cases
}

#[test]
fn replay_scheduler_corpus_cases() {
    let dir = corpus_dir();
    let cases = list_cases(&dir);
    if cases.is_empty() {
        return;
    }

    for path in cases {
        let bytes = fs::read(&path).expect("read corpus case");
        let case: SchedulerCorpusCase = serde_json::from_slice(&bytes).expect("parse corpus case");
        let runner = SimSchedulerRunner::new(case.program, case.config, case.seed);
        match runner.run() {
            RunOutcome::Ok => {}
            RunOutcome::Failed(fail) => {
                panic!("scheduler corpus replay failed for {:?}: {:?}", path, fail);
            }
        }
    }
}
