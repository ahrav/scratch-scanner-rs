# Scanner Test Harness User Guide

This guide explains how to use the deterministic scanner simulation harness to test the detection engine's chunked scanning, overlap deduplication, and fault tolerance.

## Overview

The scanner test harness validates the **detection engine's correctness under adversarial conditions** - not executor policy (see the scheduler harness for that). It simulates file I/O, chunking, and transform decoding without touching the real filesystem, enabling reproducible bug discovery and systematic testing.

**What it tests:**
- Chunked scanning with overlap preservation
- Overlap deduplication (findings not duplicated across chunk boundaries)
- Transform chain decoding (Base64, URL percent, UTF-16, nested)
- Fault tolerance (I/O errors, partial reads, cancellations, corruption)
- Ground-truth validation (expected secrets found, no unexpected findings)
- Differential correctness (chunked scan == single-chunk reference)
- Schedule stability (same findings across different task orderings)

**Why deterministic simulation:**
- **Reproducible bugs**: Any failure produces an artifact that replays identically
- **Systematic edge cases**: Exercise chunk boundaries, transform depths, and fault combinations
- **Real engine code**: Uses the actual `Engine::scan_chunk_into()` - no mocking

**Difference from scheduler harness:**
The scheduler harness tests work distribution policy (stealing, parking, resource accounting). The scanner harness tests detection logic (chunking, overlap, transforms, faults). They share `SimExecutor` infrastructure but validate different invariants.

## Quick Start

```bash
# Run corpus regression tests
cargo test --features sim-harness --test sim_corpus_scanner

# Run bounded random simulations
cargo test --features sim-harness --test sim_random_scanner

# Scale via environment variables
SIM_SCANNER_SEED_COUNT=100 cargo test --features sim-harness --test sim_random_scanner

# Enable deep testing (more files, secrets, faults)
SIM_SCANNER_DEEP=1 cargo test --features sim-harness --test sim_random_scanner

# Debug a failing case
DUMP_SIM_FAIL=1 cargo test --features sim-harness --test sim_random_scanner
```

**Key paths:**
- **Corpus**: `tests/corpus/scanner/*.case.json` - regression tests replayed on every run
- **Random tests**: `tests/sim_random_scanner.rs` - bounded random scenario generation

## ScenarioGenConfig Reference

Configuration for generating synthetic scanner scenarios.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema_version` | u32 | 1 | Schema version for forward-compatible evolution |
| `rule_count` | u32 | 2 | Number of synthetic rules to generate |
| `file_count` | u32 | 2 | Number of files to generate |
| `secrets_per_file` | u32 | 3 | Secrets inserted per file |
| `token_len` | u32 | 12 | Random token length (appended to rule prefix) |
| `min_noise_len` | u32 | 8 | Minimum padding bytes between secrets |
| `max_noise_len` | u32 | 32 | Maximum padding bytes between secrets |
| `representations` | `Vec<SecretRepr>` | all variants | Allowed secret encodings to choose from |

**Example:**
```rust
let gen_cfg = ScenarioGenConfig {
    rule_count: 4,
    file_count: 5,
    secrets_per_file: 6,
    token_len: 16,
    min_noise_len: 4,
    max_noise_len: 64,
    representations: vec![SecretRepr::Raw, SecretRepr::Base64],
    ..Default::default()
};
let scenario = generate_scenario(42, &gen_cfg)?;
```

## RunConfig Reference

Configuration for a single simulation run.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `workers` | u32 | required | Number of simulated worker threads |
| `chunk_size` | u32 | required | Scanning chunk size in bytes |
| `overlap` | u32 | required | Overlap bytes between chunks (must >= `engine.required_overlap()`) |
| `max_in_flight_objects` | u32 | 16 | Maximum concurrent file operations |
| `buffer_pool_cap` | u32 | 8 | Buffer pool capacity |
| `max_steps` | u64 | auto | Simulation step limit (0 = auto-derived) |
| `max_transform_depth` | u32 | 3 | Maximum decode nesting depth |
| `scan_utf16_variants` | bool | true | Enable UTF-16 LE/BE scanning |
| `stability_runs` | u32 | 2 | Runs per scenario with different schedule seeds |

**Example:**
```rust
let run_cfg = RunConfig {
    workers: 2,
    chunk_size: 64,
    overlap: 32,
    max_in_flight_objects: 16,
    buffer_pool_cap: 8,
    max_steps: 0,  // auto
    max_transform_depth: 3,
    scan_utf16_variants: true,
    stability_runs: 3,
};
```

## SecretRepr Reference

How a secret is encoded in the generated file.

| Variant | Description | Example |
|---------|-------------|---------|
| `Raw` | No encoding, plaintext | `SIM0_TOKEN123ABC` |
| `Base64` | Standard base64 encoding | `U0lNMF9UT0tFTjEyM0FCQw==` |
| `UrlPercent` | URL percent encoding (all bytes) | `%53%49%4D%30%5F%54%4F%4B%45%4E...` |
| `Utf16Le` | UTF-16 Little Endian | Each ASCII byte becomes `[byte, 0x00]` |
| `Utf16Be` | UTF-16 Big Endian | Each ASCII byte becomes `[0x00, byte]` |
| `Nested { depth }` | Alternating base64/URL | Multi-layer encoding |

**Nested encoding example (depth=2):**
```
raw -> base64 -> url_percent
SIM0_TOKEN123 -> U0lNMF9UT0tFTjEyMw== -> %55%30%6C%4E%4D%46%39%55...
```

## FaultPlan DSL Reference

Fault plans are keyed by file path bytes and specify deterministic I/O behaviors.

### Structure

```json
{
  "per_file": {
    "file_0.txt": {
      "open": { "ErrKind": { "kind": 2 } },
      "reads": [
        {
          "fault": { "PartialRead": { "max_len": 16 } },
          "latency_ticks": 2,
          "corruption": null
        }
      ],
      "cancel_after_reads": 3
    }
  }
}
```

### IoFault Variants

| Variant | Description |
|---------|-------------|
| `ErrKind { kind }` | Return an I/O error (kind maps to `std::io::ErrorKind`) |
| `PartialRead { max_len }` | Return at most `max_len` bytes (short read) |
| `EIntrOnce` | Single EINTR-style interruption |

### Corruption Variants

| Variant | Description |
|---------|-------------|
| `TruncateTo { new_len }` | Truncate read data to `new_len` bytes |
| `FlipBit { offset, mask }` | XOR `mask` into byte at `offset` |
| `Overwrite { offset, bytes }` | Overwrite bytes starting at `offset` |

### ReadFault Fields

| Field | Type | Description |
|-------|------|-------------|
| `fault` | `Option<IoFault>` | I/O fault to inject |
| `latency_ticks` | u64 | Simulated I/O latency (blocks task) |
| `corruption` | `Option<Corruption>` | Data corruption to apply |

## Common Scenarios

### Scenario 1: Basic Ground-Truth Validation

Verify that secrets in plaintext are detected correctly.

```rust
let gen_cfg = ScenarioGenConfig {
    rule_count: 2,
    file_count: 2,
    secrets_per_file: 3,
    token_len: 12,
    representations: vec![SecretRepr::Raw],
    ..Default::default()
};
let scenario = generate_scenario(42, &gen_cfg)?;
let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg)?;
let runner = ScannerSimRunner::new(run_cfg, 0xCAFE);
match runner.run(&scenario, &engine, &FaultPlan::default()) {
    RunOutcome::Ok { findings } => { /* success */ }
    RunOutcome::Failed(fail) => panic!("{:?}", fail),
}
```

### Scenario 2: Transform Chain Testing

Exercise the decode pipeline with encoded secrets.

```rust
let gen_cfg = ScenarioGenConfig {
    representations: vec![
        SecretRepr::Base64,
        SecretRepr::UrlPercent,
        SecretRepr::Nested { depth: 2 },
    ],
    ..Default::default()
};
```

### Scenario 3: Chunk Boundary Edge Cases

Use small chunks to force many boundary crossings.

```rust
let run_cfg = RunConfig {
    chunk_size: 32,
    overlap: 16,
    workers: 2,
    ..Default::default()
};
```

### Scenario 4: Fault Injection

Test I/O error handling and cancellation recovery.

```rust
use std::collections::BTreeMap;
use scanner_rs::sim::fault::*;

let mut per_file = BTreeMap::new();
per_file.insert(
    b"file_0.txt".to_vec(),
    FileFaultPlan {
        open: Some(IoFault::ErrKind { kind: 2 }), // NotFound
        reads: vec![],
        cancel_after_reads: None,
    }
);
per_file.insert(
    b"file_1.txt".to_vec(),
    FileFaultPlan {
        open: None,
        reads: vec![
            ReadFault {
                fault: Some(IoFault::PartialRead { max_len: 8 }),
                latency_ticks: 1,
                corruption: None,
            },
        ],
        cancel_after_reads: Some(2),
    }
);
let fault_plan = FaultPlan { per_file };
```

### Scenario 5: UTF-16 Variant Testing

Ensure UTF-16 encoded secrets are detected.

```rust
let gen_cfg = ScenarioGenConfig {
    representations: vec![SecretRepr::Utf16Le, SecretRepr::Utf16Be],
    ..Default::default()
};
let run_cfg = RunConfig {
    scan_utf16_variants: true,
    ..Default::default()
};
```

## Workflow Guide

### When to Create New Test Cases

- **After finding a scanning bug**: Create a regression test from the failure artifact
- **Before major engine changes**: Add coverage for the changed behavior
- **When adding new transforms**: Ensure the decode chain handles them
- **For edge cases**: Chunk boundaries, max depths, empty files

### Adding a Test to the Corpus

1. Run simulation and capture failure artifact (or construct manually)
2. Minimize with `minimize_scanner_case()` if needed
3. Copy minimized artifact to `tests/corpus/scanner/<name>.case.json`
4. Verify replay passes:
   ```bash
   cargo test --features sim-harness --test sim_corpus_scanner
   ```

### Using the Minimizer

```rust
use scanner_rs::sim::{minimize_scanner_case, MinimizerCfg, ReproArtifact};

fn reproduce(artifact: &ReproArtifact) -> bool {
    let engine = build_engine_from_suite(&artifact.scenario.rule_suite, &artifact.run_config)
        .expect("build engine");
    let runner = ScannerSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
    matches!(runner.run(&artifact.scenario, &engine, &artifact.fault_plan), RunOutcome::Failed(_))
}

let minimized = minimize_scanner_case(&failing_artifact, MinimizerCfg::default(), reproduce);
```

The minimizer applies deterministic shrink passes:
1. Reduce worker count
2. Remove fault entries (open, cancel, reads)
3. Remove files from the scenario

### Environment Variables

**Random test configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SIM_SCANNER_SEED_START` | 0 | First seed in the range |
| `SIM_SCANNER_SEED_COUNT` | 25 | Number of seeds to test |
| `SIM_SCANNER_DEEP` | false | Enable larger scenarios and more faults |
| `DUMP_SIM_FAIL` | unset | Print failure details on panic |

**Scenario overrides:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SIM_SCENARIO_RULES` | 3 (8 deep) | Number of synthetic rules |
| `SIM_SCENARIO_FILES` | 3 (8 deep) | Number of files |
| `SIM_SCENARIO_SECRETS` | 3 (6 deep) | Secrets per file |
| `SIM_SCENARIO_TOKEN_LEN` | 12 (24 deep) | Token length |
| `SIM_SCENARIO_MIN_NOISE` | 4 (8 deep) | Min noise bytes |
| `SIM_SCENARIO_MAX_NOISE` | 16 (128 deep) | Max noise bytes |

**Run config overrides:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SIM_RUN_WORKERS` | random 1-4 | Fixed worker count |
| `SIM_RUN_WORKERS_MIN` | 1 | Min workers (random) |
| `SIM_RUN_WORKERS_MAX` | 4 (8 deep) | Max workers (random) |
| `SIM_RUN_CHUNK_SIZE` | random 16-64 | Fixed chunk size |
| `SIM_RUN_CHUNK_MIN` | 16 | Min chunk (random) |
| `SIM_RUN_CHUNK_MAX` | 64 (128 deep) | Max chunk (random) |
| `SIM_RUN_OVERLAP` | 64 (128 deep) | Overlap bytes |
| `SIM_RUN_MAX_STEPS` | 0 (auto) | Step limit |
| `SIM_RUN_MAX_TRANSFORM_DEPTH` | 3 (4 deep) | Max decode depth |
| `SIM_RUN_SCAN_UTF16` | true | Enable UTF-16 variants |
| `SIM_RUN_STABILITY_RUNS` | 2 (4 deep) | Stability replays |

## Oracles Checked

The harness validates these invariants during and after each run:

| Oracle | When | Description |
|--------|------|-------------|
| **Termination** | Every step | `max_steps` bound prevents infinite loops |
| **Monotonic Progress** | Per chunk | File cursor never moves backward |
| **Overlap Dedupe** | Per finding | No finding ends at or before the overlap prefix boundary |
| **No Duplicates** | End of run | Emitted findings have unique normalized keys |
| **Ground Truth** | End of run | Expected secrets found (for fully-observed files), no unexpected findings |
| **Differential** | End of run | Chunked results match single-chunk reference scan |
| **Stability** | Multi-run | Same finding set across different schedule seeds |

### Failure Kinds

| Kind | Meaning |
|------|---------|
| `Panic` | Panic escaped from engine or harness logic |
| `Hang` | Simulation did not reach terminal state within step budget |
| `InvariantViolation { code }` | Internal invariant violated (see code for details) |
| `OracleMismatch` | Ground-truth or differential oracle failed |
| `StabilityMismatch` | Different findings across schedule seeds |

## ReproArtifact Schema

Artifacts are self-contained JSON files for deterministic replay:

```json
{
  "schema_version": 1,
  "scanner_pkg_version": "0.1.0",
  "git_commit": "abc123...",
  "target": "x86_64-apple-darwin",

  "scenario_seed": 42,
  "schedule_seed": 3405691648,

  "run_config": { ... },
  "scenario": { ... },
  "fault_plan": { ... },

  "failure": {
    "kind": { "InvariantViolation": { "code": 23 } },
    "message": "prefix dedupe failed",
    "step": 47
  },
  "trace": {
    "ring": [ ... ],
    "full": null
  }
}
```

## FAQ

**Q: How is this different from the scheduler harness?**

A: The scheduler harness tests executor policy (work-stealing, parking, resource accounting). The scanner harness tests detection logic (chunking, overlap, transforms, faults). They share `SimExecutor` but validate different invariants.

**Q: How do I debug a failing scenario?**

A: Set `DUMP_SIM_FAIL=1` to print scenario and fault details on failure. Then use the minimizer to reduce the case, and add it to the corpus.

**Q: What's the relationship between seeds?**

A: `scenario_seed` determines file contents and secret placement. `schedule_seed` determines task ordering in the executor. Same scenario seed + different schedule seeds = stability testing.

**Q: Why does ground-truth skip some files?**

A: Files with data-affecting faults (open errors, cancellations, corruption) are excluded from ground-truth checks because the engine didn't see the expected bytes.

**Q: What does `overlap` need to be?**

A: At minimum `engine.required_overlap()`, which depends on rule radiuses. The harness validates this precondition.

**Q: How is max_steps auto-derived?**

A: When `max_steps = 0`, the bound is computed as: `32 + 8*(file_count + chunk_count) + 4*fault_ops`. This provides a conservative upper bound that scales with workload.

**Q: Can I test actual file I/O?**

A: No. The harness uses `SimFs`, an in-memory filesystem. For real I/O testing, use integration tests against the production pipeline.
