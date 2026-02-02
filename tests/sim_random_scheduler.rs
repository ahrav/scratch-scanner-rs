#![cfg(feature = "sim-harness")]
//! Bounded random scheduler simulations to exercise scheduling fairness.

use std::collections::BTreeMap;

use scanner_rs::sim_scheduler::{
    Instr, Program, RunOutcome, SimSchedulerConfig, SimSchedulerRunner, TaskProgram,
};

const DEFAULT_SEED_COUNT: u64 = 50;

fn seed_value_from_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn bounded_random_scheduler_sims() {
    let program = Program {
        tasks: vec![
            TaskProgram {
                name: "holder".to_string(),
                code: vec![
                    Instr::Acquire { budget: 1 },
                    Instr::Yield,
                    Instr::Release { budget: 1 },
                    Instr::Complete,
                ],
            },
            TaskProgram {
                name: "waiter".to_string(),
                code: vec![
                    Instr::Yield,
                    Instr::Acquire { budget: 1 },
                    Instr::Release { budget: 1 },
                    Instr::Complete,
                ],
            },
            TaskProgram {
                name: "signaler".to_string(),
                code: vec![
                    Instr::Sleep { ticks: 2 },
                    Instr::SignalEvent { event: 1 },
                    Instr::Complete,
                ],
            },
            TaskProgram {
                name: "event_waiter".to_string(),
                code: vec![Instr::WaitEvent { event: 1 }, Instr::Complete],
            },
        ],
    };

    let mut budgets = BTreeMap::new();
    budgets.insert(1u16, 1u32);
    let cfg = SimSchedulerConfig {
        workers: 3,
        max_steps: 200,
        fairness_bound: 40,
        budgets,
    };

    let seed_start = seed_value_from_env("SIM_SCHEDULER_SEED_START", 0);
    let seed_count = seed_value_from_env("SIM_SCHEDULER_SEED_COUNT", DEFAULT_SEED_COUNT);
    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let runner = SimSchedulerRunner::new(program.clone(), cfg.clone(), seed);
        match runner.run() {
            RunOutcome::Ok => {}
            RunOutcome::Failed(fail) => {
                panic!("scheduler sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}
