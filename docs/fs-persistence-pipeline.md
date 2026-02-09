# FS Persistence Pipeline

Write-side plumbing that carries post-dedupe findings from the scheduler's
FS scan loops into a persistence backend.

**Source**: `src/store/fs.rs`, `src/store/log/format.rs`,
`src/store/log/writer.rs`, `src/scheduler/local_fs_owner.rs`,
`src/scheduler/parallel_scan.rs`, `src/unified/orchestrator.rs`

## Purpose

The detection engine emits findings during scanning, but those findings are
transient — they flow through the `EventSink` to stdout and are gone. The
FS persistence pipeline adds a **durable write path** so post-dedupe findings
are persisted to append-only segment logs for cross-run deduplication,
tracking, and reporting.

This module defines the **producer-side contracts** (what the scheduler
emits). The consumer side (actual backend storage) is plugged in via the
`StoreProducer` trait.

## Relationship to Other Persistence Modules

| Module | Scope | Purpose |
|--------|-------|---------|
| `src/store/fs.rs` | FS persistence producer | Write-side trait + data types for FS scan findings |
| `src/store/log/format.rs` | FS log codec | Framed on-disk record format (`len + crc32 + type + payload`) |
| `src/store/log/writer.rs` | FS append-log backend | Bounded single-writer runtime with `.open` -> `.bin` finalize |
| `src/store/identity.rs` | Identity contracts | Stable `RuleFingerprint`, `SecretHash`, `OccurrenceId` derivation |
| `src/store/keys.rs` | Key bootstrap | `SCANNER_SECRET_KEY` KDF for keyed identity hashes |
| `src/git_scan/persist.rs` | Git persistence | Two-phase persist contract for Git blob scan results |

The identity contracts (`identity.rs`) define *how to compute stable IDs*
for findings. The FS persistence pipeline (`fs.rs`) defines *how findings
flow from scan workers into a backend*. A production backend would use both:
the pipeline delivers `FsFindingRecord` batches, and the backend computes
`OccurrenceId` from each record before storing.

## Data Flow

```text
                     ┌─────────────────────────────────────────────────────────────┐
                     │                    Per-Worker Scan Loop                      │
                     │                                                             │
  Engine             │   scan_chunk_into()                                         │
  ──────────────────►│──────────┬──────────────────────────────────────────────────►│
                     │          │                                                   │
                     │          ▼                                                   │
                     │   drain_findings_with_hashes()                               │
                     │          │                                                   │
                     │          │  Vec<FindingWithHash<F>>                          │
                     │          ▼                                                   │
                     │   drop_prefix_findings()      (cross-chunk overlap dedupe)   │
                     │          │                                                   │
                     │          ▼                                                   │
                     │   dedupe_findings()            (within-chunk dedupe)         │
                     │          │                     now includes norm_hash in key │
                     │          ▼                                                   │
                     │   ┌──────┴──────────────┐                                   │
                     │   │                     │                                   │
                     │   ▼                     ▼                                   │
                     │  emit_findings()   emit_persistence_batch()                 │
                     │  (EventSink)            │                                   │
                     │                         │  build_persistence_batch()        │
                     │                         │  converts to FsFindingRecord[]    │
                     │                         │  wraps in FsFindingBatch          │
                     │                         ▼                                   │
                     │                  StoreProducer::emit_fs_batch()             │
                     │                         │                                   │
                     │           ┌─────────────┼──────────────┬─────────────┐      │
                     │           ▼             ▼              ▼             ▼      │
                     │   AppendLogProducer  InMemoryProd  NullProducer   (custom)   │
                     │    (.open/.bin)       (test/diag)    (discard)               │
                     └─────────────────────────────────────────────────────────────┘

                     At run end:
                     ┌─────────────────────────────────────────┐
                     │  Aggregate worker metrics                │
                     │  ──► FsRunLoss { dropped, failures }    │
                     │  ──► StoreProducer::record_fs_run_loss() │
                     └─────────────────────────────────────────┘
```

## Key Types

### FsFindingRecord

Backend-agnostic representation of one post-dedupe finding. All offsets are
absolute byte positions within the scanned object.

```text
┌──────────────────────────────────────┐
│         FsFindingRecord              │
├──────────────────────────────────────┤
│  rule_id: u32                        │  ◄── engine rule that matched
│  root_hint_start: u64                │  ◄── dedup region start
│  root_hint_end: u64                  │  ◄── dedup region end (excl.)
│  span_start: u64                     │  ◄── matched span start
│  span_end: u64                       │  ◄── matched span end (excl.)
│  norm_hash: [u8; 32]                 │  ◄── BLAKE3 of normalized secret
└──────────────────────────────────────┘
```

The `norm_hash` is the BLAKE3 digest of the normalized secret value
(whitespace-collapsed, case-folded). Two findings with the same `norm_hash`
matched the same logical secret, regardless of surrounding context.

### FsFindingBatch

Groups all post-dedupe findings for a single scanned object (plain file or
archive entry).

```text
┌──────────────────────────────────────┐
│         FsFindingBatch<'a>           │
├──────────────────────────────────────┤
│  object_path: &'a [u8]              │  ◄── FS path or virtual archive path
│  findings: &'a [FsFindingRecord]    │  ◄── deduplicated findings
└──────────────────────────────────────┘
```

The batch borrows from per-worker scratch buffers. Implementations must
copy or serialize before returning from `emit_fs_batch()`.

### FsRunLoss

Run-level loss accounting emitted once at scan end.

```text
┌──────────────────────────────────────┐
│           FsRunLoss                  │
├──────────────────────────────────────┤
│  dropped_findings: u64               │  ◄── engine cap drops
│  persistence_emit_failures: u64      │  ◄── batch emit errors
│  incomplete: bool                    │  ◄── should mark run partial?
└──────────────────────────────────────┘
```

The backend uses `incomplete` to decide whether to mark the run as a
complete scan or flag data loss.

### StoreProducer Trait

```rust
pub trait StoreProducer: Send + Sync + 'static {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError>;
    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError>;
}
```

**Contract:**
- `emit_fs_batch` is called zero or more times during a scan, once per
  scanned object that produced findings. Batches may arrive out of file
  order when workers run in parallel.
- `record_fs_run_loss` is called exactly once at the end of a scan run.
- Errors from either method are counted but do **not** abort the scan.

### Implementations

| Type | Purpose |
|------|---------|
| `AppendLogStoreProducer` | Default FS backend: bounded single-writer append-log with framed records and segment finalize |
| `NullStoreProducer` | Default no-op — CLI default, feature-off, benchmarks |
| `InMemoryStoreProducer` | Collects batches in memory for tests and diagnostics |

### Append-Log Backend (Phase C)

When `--persist-findings` is enabled for FS scans, the orchestrator now wires
`AppendLogStoreProducer` by default. Behavior:

- Writer runtime:
  - Bounded MPSC ingestion with both batch-count and byte-budget limits.
  - Explicit error on over-budget single frames (no silent drop).
  - Single writer thread is the only mutator of segment files.
- On-disk records:
  - `RunStart`, `RuleDef`, `FindingBatch`, `RunEnd`.
  - Frame header: `u32_le len`, `u32_le crc32`, `u8 frame_type`, payload.
  - Rule definitions are emitted in fingerprint-sorted order for deterministic metadata ordering.
- Segment lifecycle:
  - Active segment is `segment-<seq>.open`.
  - Rotation/finalize performs durable close (`sync_data`) and atomic rename to `.bin`.
  - Reader/query paths consume finalized `.bin` segments only in MVP.

## Loss Accounting

Findings can be lost at two points, and both are tracked:

```text
  Per-chunk:                              Per-run:
  ┌──────────────────────┐               ┌────────────────────────────────┐
  │ Engine scan caps     │               │  FsRunLoss                     │
  │ (max_findings/chunk) │──aggregate───►│    dropped_findings            │
  │ → dropped_findings() │               │                                │
  └──────────────────────┘               │                                │
  ┌──────────────────────┐               │                                │
  │ emit_fs_batch()      │──on error────►│    persistence_emit_failures   │
  │ backend failure      │               │                                │
  └──────────────────────┘               │    incomplete = drops > 0      │
                                         │              OR failures > 0   │
                                         └────────────────────────────────┘
                                                       │
                                                       ▼
                                              record_fs_run_loss()
                                              Backend decides: complete
                                              vs partial run
```

### Metrics Rollup

Worker-level counters are aggregated into `MetricsSnapshot`:

| Worker counter | Snapshot counter | Rollup |
|----------------|-----------------|--------|
| `findings_dropped` | `findings_dropped` | sum across workers |
| `persistence_emit_failures` | `persistence_emit_failures` | sum across workers |

These feed into `LocalStats` and then into `FsRunLoss` at run end.

## Scan Site Coverage

The `emit_persistence_batch()` call is inserted at every scan site that
produces findings:

| Scan site | Function | File |
|-----------|----------|------|
| Plain file chunk loop | `process_file()` | `local_fs_owner.rs` |
| Binary text extraction | `extract_and_scan_file()` | `local_fs_owner.rs` |
| Top-level gzip | `process_gzip_file()` | `local_fs_owner.rs` |
| Nested gzip stream | `scan_gzip_stream_nested()` | `local_fs_owner.rs` |
| Tar entry stream | `scan_tar_stream_nested()` | `local_fs_owner.rs` |
| Zip entry | `process_zip_file()` | `local_fs_owner.rs` |

## Configuration and Wiring

### CLI Flag

```bash
scanner scan fs --path=/some/dir --persist-findings
```

The `--persist-findings` flag sets `FsScanConfig.persist_findings = true`,
which causes the orchestrator to wire a `StoreProducer` into the
`ParallelScanConfig`. The default producer is `AppendLogStoreProducer`, which
writes run directories under the append-log root.

### Wiring Path

```text
CLI --persist-findings
  │
  ▼
FsScanConfig { persist_findings: true }
  │
  ▼
run_fs() in orchestrator.rs
  │  creates Arc<AppendLogStoreProducer>
  ▼
ParallelScanConfig { store_producer: Some(Arc<dyn StoreProducer>) }
  │
  ▼
LocalConfig { store_producer: Some(Arc<dyn StoreProducer>) }
  │
  ▼
Per-worker LocalScratch {
    store_producer: Some(Arc<dyn StoreProducer>),
    persist_batch: Vec<FsFindingRecord>,   ◄── reusable buffer
}
```

### Per-Worker Scratch Layout

Each worker carries a `persist_batch: Vec<FsFindingRecord>` buffer that is
reused across scan iterations to avoid per-file allocation. The
`store_producer` reference is `Arc`-cloned so all workers share the same
producer instance.

## Deduplication Changes

The within-chunk dedup function `dedupe_findings()` was updated to include
`norm_hash` in the dedup key:

**Before**: `(rule_id, root_hint_start, root_hint_end, span_start, span_end)`
**After**: `(rule_id, root_hint_start, root_hint_end, span_start, span_end, norm_hash)`

This ensures two findings at the same byte span but with different
normalized secret hashes are preserved (not incorrectly collapsed). This
aligns the FS path with the git-scan path, which already uses `norm_hash`
in its `FindingKey`.

## Output Changes

The orchestrator now reports persistence-related counters in the summary
line:

```
files=N chunks=N bytes=N findings=N errors=N dropped_findings=N persist_emit_failures=N persist_incomplete=false ...
```

The `SummaryEvent.status` field is set to `"partial"` when
`persistence_incomplete` is true, instead of the default `"complete"`.

## What's NOT Included (Future Work)

- **No live `.open` readers in MVP** — query/replay is over finalized `.bin`
  segments only.
- **No mid-segment salvage** — malformed frame handling is stop-at-first-bad-frame;
  advanced resync/recovery policy is handled in Phase D.
- **No derived index yet** — logs are the source of truth; SQLite/indexed query
  acceleration is post-MVP.

## Related Documentation

| Document | Relevance |
|----------|-----------|
| [persistence-identity.md](persistence-identity.md) | Identity contracts (RuleFingerprint, SecretHash, OccurrenceId) |
| [pipeline-flow.md](pipeline-flow.md) | FS pipeline stages and buffer lifecycle |
| [scheduler-engine-abstraction.md](scheduler-engine-abstraction.md) | FindingWithHashRecord trait, EngineScratch changes |
| [scheduler-engine-impl.md](scheduler-engine-impl.md) | Real engine adapter, drain_findings_with_hashes |
| [architecture-overview.md](architecture-overview.md) | Component diagram and FS scan path |
| [data-types.md](data-types.md) | Class diagrams for store::fs types |
