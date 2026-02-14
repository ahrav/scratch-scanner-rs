//! Benchmark: Concurrent output contention patterns.
//!
//! Compares three concurrency patterns for storing per-task results:
//!
//! - **`single_mutex`**: All threads lock one `Mutex<Vec<Option<[u8;64]>>>`.
//! - **`single_mutex_with_error_check`**: Same, plus every thread locks a
//!   second `Mutex<Option<()>>` before executing (old error-check pattern).
//! - **`per_slot_atomic`**: Each thread locks only its own
//!   `Mutex<Option<[u8;64]>>` slot and checks an `AtomicBool` for abort.
//!
//! Each "task" hashes a 64-byte buffer to prevent dead-code elimination,
//! then stores the result. Uses `std::thread::scope` with explicit thread counts.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Deterministic lightweight hash to simulate per-task work.
///
/// Not cryptographic — just enough ALU work to prevent the compiler from
/// eliding the "task body" while keeping the benchmark focused on
/// synchronization overhead.
#[inline(never)]
fn hash_work(seed: u64) -> [u8; 64] {
    let mut state = seed ^ 0x517cc1b727220a95;
    let mut out = [0u8; 64];
    for chunk in out.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    out
}

/// Pattern 1 (old): single mutex guarding the entire result vector.
fn single_mutex(thread_count: usize, tasks: usize) {
    let results: Mutex<Vec<Option<[u8; 64]>>> = Mutex::new(vec![None; tasks]);

    std::thread::scope(|s| {
        for t in 0..thread_count {
            let results = &results;
            s.spawn(move || {
                let chunk = tasks / thread_count;
                let start = t * chunk;
                let end = if t == thread_count - 1 {
                    tasks
                } else {
                    start + chunk
                };
                for i in start..end {
                    let val = hash_work(i as u64);
                    let mut guard = results.lock().unwrap();
                    guard[i] = Some(val);
                }
            });
        }
    });

    black_box(&results);
}

/// Pattern 2 (old): single mutex + error-check mutex.
///
/// Before each task, the thread acquires a second mutex to check for
/// abort — the pattern used before switching to `AtomicBool`.
fn single_mutex_with_error_check(thread_count: usize, tasks: usize) {
    let results: Mutex<Vec<Option<[u8; 64]>>> = Mutex::new(vec![None; tasks]);
    let error: Mutex<Option<()>> = Mutex::new(None);

    std::thread::scope(|s| {
        for t in 0..thread_count {
            let results = &results;
            let error = &error;
            s.spawn(move || {
                let chunk = tasks / thread_count;
                let start = t * chunk;
                let end = if t == thread_count - 1 {
                    tasks
                } else {
                    start + chunk
                };
                for i in start..end {
                    // Old pattern: lock error mutex to check abort before work.
                    if error.lock().unwrap().is_some() {
                        return;
                    }
                    let val = hash_work(i as u64);
                    let mut guard = results.lock().unwrap();
                    guard[i] = Some(val);
                }
            });
        }
    });

    black_box(&results);
}

/// Pattern 3 (new): per-slot mutex + atomic abort flag.
///
/// Each thread only locks its own slot. Abort is checked via a cheap
/// `AtomicBool::load(Relaxed)` — no mutex acquisition.
fn per_slot_atomic(thread_count: usize, tasks: usize) {
    let slots: Vec<Mutex<Option<[u8; 64]>>> = (0..tasks).map(|_| Mutex::new(None)).collect();
    let abort = AtomicBool::new(false);

    std::thread::scope(|s| {
        for t in 0..thread_count {
            let slots = &slots;
            let abort = &abort;
            s.spawn(move || {
                let chunk = tasks / thread_count;
                let start = t * chunk;
                let end = if t == thread_count - 1 {
                    tasks
                } else {
                    start + chunk
                };
                for (i, slot) in slots.iter().enumerate().take(end).skip(start) {
                    if abort.load(Ordering::Relaxed) {
                        return;
                    }
                    let val = hash_work(i as u64);
                    *slot.lock().unwrap() = Some(val);
                }
            });
        }
    });

    black_box(&slots);
}

fn bench_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("runner_exec_contention");
    // Fixed task count so we measure contention, not work volume.
    let tasks = 4096;

    for &threads in &[1, 4, 8, 16, 24] {
        group.bench_with_input(
            BenchmarkId::new("single_mutex", threads),
            &threads,
            |b, &tc| {
                b.iter(|| single_mutex(tc, tasks));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("single_mutex_error_check", threads),
            &threads,
            |b, &tc| {
                b.iter(|| single_mutex_with_error_check(tc, tasks));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("per_slot_atomic", threads),
            &threads,
            |b, &tc| {
                b.iter(|| per_slot_atomic(tc, tasks));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_contention);
criterion_main!(benches);
