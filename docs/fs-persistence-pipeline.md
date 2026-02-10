# FS Persistence Pipeline

Write-side plumbing that carries post-dedupe findings from the scheduler's
FS scan loops into a persistence backend.

**Source**: `src/store/fs.rs`, `src/store/log/format.rs`,
`src/store/log/reader.rs`, `src/store/log/writer.rs`,
`src/scheduler/local_fs_owner.rs`, `src/scheduler/parallel_scan.rs`,
`src/unified/orchestrator.rs`

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
| `src/store/log/format.rs` | FS log codec | Framed on-disk record format (V1 + V2, position-bound CRC, segment trailer) |
| `src/store/log/reader.rs` | FS log reader | Streaming frame decoder with reason-coded errors and `.open` recovery |
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
├──────────────────────────────────────┤
│  fn incomplete(&self) -> bool        │  ◄── derived: any loss?
└──────────────────────────────────────┘
```

`incomplete()` is a derived method (not a stored field) that returns `true`
when `dropped_findings > 0 || persistence_emit_failures > 0`.

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

### Append-Log Backend

When `--persist-findings` is enabled for FS scans, the orchestrator wires
`AppendLogStoreProducer` by default.

#### Store Root Resolution

The append-log root directory is resolved in this order:

1. **`SCANNER_FS_LOG_DIR` env var** — used verbatim if set.
2. **Sibling of scan root** — `<parent>/.<name>.scanner-rs-store` where
   `<name>` is the scan root's directory name (sanitized for safe path chars).

Example: scanning `/data/repos/myproject` creates
`/data/repos/.myproject.scanner-rs-store/`.

#### On-Disk Directory Layout

```text
<store_root>/
  └── run-<hex_id>/
        └── segments/
              ├── segment-00000000000000000000.bin   ← finalized
              ├── segment-00000000000000000001.bin   ← finalized
              └── segment-00000000000000000002.open  ← active (only during scan)
```

- Each scan run gets its own `run-<hex_id>/` directory.
- Segments use a 20-digit zero-padded sequence number.
- Active segments have the `.open` extension; finalized segments have `.bin`.
- After a clean shutdown, no `.open` files remain.
- `list_finalized_segment_files()` walks `run-*/segments/segment-*.bin` in
  lexical order and ignores `.open` files.

#### Binary Frame Format

Every record is wrapped in a self-describing frame with an 8-byte header.
Readers accept both legacy V1 and current V2 frames:

```text
V1 body:
 byte:  0       4       8    9                     N
        ┌───────┬───────┬────┬──────────────────────┐
        │ len   │ CRC32 │type│      payload          │
        │ u32le │ u32le │ u8 │   [len − 1] bytes     │
        └───────┴───────┴────┴──────────────────────┘

V2 body (position-bound CRC):
 byte:  0       4       8          16         24   25                 N
        ┌───────┬───────┬──────────┬──────────┬────┬──────────────────┐
        │len|F2 │ CRC32 │frame_seq │segment_id│type│payload            │
        │ u32le │ u32le │  u64le   │  u64le   │ u8 │ [len − 17] bytes  │
        └───────┴───────┴──────────┴──────────┴────┴──────────────────┘
```

| Field | Bytes | Encoding | Description |
|-------|-------|----------|-------------|
| `frame_len` | 0–3 | `u32_le` | Body length excluding header. In V2 the high bit (`F2`) is set; the lower 31 bits hold body length. |
| `crc32` | 4–7 | `u32_le` | CRC-32/ISO-HDLC over the entire body. In V2 this includes `frame_seq` + `segment_id` + `type` + payload. |
| `frame_seq` (V2) | 8–15 | `u64_le` | Monotonic per-run frame counter. |
| `segment_id` (V2) | 16–23 | `u64_le` | Segment sequence number where the frame is committed. |
| `type` | 8 (V1), 24 (V2) | `u8` | `FrameType`: `1`=RunStart, `2`=RuleDef, `3`=FindingBatch, `4`=RunEnd. |
| `payload` | 9+ (V1), 25+ (V2) | variable | Record-specific bytes. Variable fields are length-prefixed with `u32_le`. |

Invariants:
- All multi-byte integers are little-endian.
- No inter-frame padding — segments are contiguous frame sequences.
- Payload size hard cap: `DEFAULT_MAX_FRAME_PAYLOAD_BYTES` = **16 MB**.

#### Record Type Layouts

**RunStart** (frame type `1`) — emitted once at the start of the run (first segment).

```text
offset  size   field
  0     u16    version               (LOG_FORMAT_VERSION = 2, readers accept 1..=2)
  2     u64    run_id
 10     u64    started_unix_ms
 18     u8     durability            (0 = SegmentClose, 1 = Batch)
 19     u8     correlation_mode      (0 = Persistent, 1 = Ephemeral)
 20     u8     key_source            (0 = EnvVar, 1 = MissingEnvVar, 2 = InvalidEnvVar)
 21     u32    max_inflight_batches
 25     u64    max_inflight_bytes
 33     u32    max_frame_payload_bytes
                                     total: 37 bytes payload
```

**RuleDef** (frame type `2`) — one per loaded rule, emitted in ascending
BLAKE3 fingerprint order for deterministic metadata.

```text
offset  size   field
  0     u32    rule_id               (engine rule index, 0-based)
  4     [32]   rule_fingerprint      (BLAKE3-keyed)
 36     u32    rule_name_len
 40     [N]    rule_name             (UTF-8, N = rule_name_len)
                                     total: 40 + N bytes payload
```

**FindingBatch** (frame type `3`) — one per scanned object that produced
findings.

```text
offset  size   field
  0     u32    object_path_len
  4     [P]    object_path           (raw bytes, P = object_path_len)
4+P     u32    findings_count
8+P     ...    findings[]            (findings_count × 132 bytes each)
```

Each finding record within the batch is fixed-size:

```text
offset  size   field
  0     u32    rule_id
  4     [32]   rule_fingerprint
 36     [32]   secret_hash           (BLAKE3 of normalized secret)
 68     [32]   finding_id            (deterministic occurrence ID)
100     u64    root_hint_start       (dedup region start)
108     u64    root_hint_end         (dedup region end, exclusive)
116     u64    span_start            (matched secret start)
124     u64    span_end              (matched secret end, exclusive)
                                     total: 132 bytes per finding
```

**RunEnd** (frame type `4`) — final frame sealing the run.

```text
offset  size   field
  0     u64    ended_unix_ms
  8     u64    dropped_findings      (engine cap drops)
 16     u64    persistence_emit_failures
  24     u8     incomplete            (1 if any loss, 0 otherwise)
                                     total: 25 bytes payload
```

#### Segment Integrity Trailer (V2)

Finalized `.bin` segments append a fixed trailer after the last frame:

```text
offset  size   field
  0     [8]    magic                ("SCRSEGv2")
  8     u64    segment_id
 16     u64    frame_count           (# of frames in this segment)
 24     u64    total_frame_bytes     (sum of frame byte lengths, excludes trailer)
 32     [32]   frame_crc_chain       (BLAKE3 chain over per-frame crc32 values)
                                     total: 64 bytes
```

Readers validate trailer fields against observed frame stream state when
present. `.open` files may not contain a trailer; recovery scans treat clean
EOF at a frame boundary as valid for `.open`.

#### Run Content Ordering

A well-formed run (which may span multiple segments due to rotation) follows
this frame sequence:

```text
┌──────────────────────────────────────────────────────────────┐
│  RunStart       (1 frame, first segment only)                │
├──────────────────────────────────────────────────────────────┤
│  RuleDef        (N frames, sorted by fingerprint ascending)  │
├──────────────────────────────────────────────────────────────┤
│  FindingBatch   (M frames, one per scanned object)           │
│                 ← segment rotation may occur here →          │
├──────────────────────────────────────────────────────────────┤
│  RunEnd         (1 frame, final segment only)                │
└──────────────────────────────────────────────────────────────┘
```

The writer enforces this order across segment boundaries. The reader decodes
frames in whatever order they appear (no ordering validation).

#### Reader API

Use `store::log::reader::LogReader` when replaying persisted runs or scanning
segments for recovery:

```rust
use scanner_rs::store::log::LogReader;

let file = std::fs::File::open("segment-00000000000000000000.bin")?;
let mut reader = LogReader::with_default_limit(file);
while let Some(record) = reader.next_record()? {
    // process record
}
```

`LogReader` keeps a reusable frame buffer and reports deterministic,
reason-coded failures via `LogReadError`:

| Reason | Meaning |
|--------|---------|
| `CrcMismatch` | Frame CRC does not match payload bytes |
| `Truncated` | EOF before full header/body completion |
| `UnsupportedFrame` | Unknown frame discriminant |
| `UnsupportedVersion` | `RunStart.version` is outside supported range (`1..=LOG_FORMAT_VERSION`) |
| `MalformedFrame` | Invalid frame shape or payload fields |
| `Io` | Underlying read error from the transport |

On any failure, callers also get:
- `frame_index` (0-based frame number),
- `frame_offset` (byte offset where that frame started).

These fields make startup recovery deterministic: truncate `.open` at the last
known-good offset and stop at first bad frame.

#### Startup `.open` Recovery

Use `recover_open_segments(store_root, max_frame_payload_bytes)` before
query/replay startup to convert stale `.open` files into finalized `.bin`
segments.

Policy:
- Scan each `.open` frame-by-frame in lexical order.
- On first recoverable decode error, treat that frame boundary as EOF.
- Surface `Io` and `UnsupportedVersion` as hard recovery errors (do not
  truncate/rename the source `.open`).
- Truncate tail bytes beyond the last valid frame.
- Rename `.open` → `.bin`.
- If matching `.bin` already exists, discard `.open` and record
  `DiscardedDuplicateBin` in the recovery report.

The returned `OpenSegmentRecoveryReport` captures per-file outcomes and
truncation metadata for audit/telemetry.

#### Segment Rotation

Segments rotate when writing a frame would exceed `max_segment_bytes`
*after reserving trailer space* (default **64 MB**):

```text
write_frame(data):
    trailer_bytes = 64
    if bytes_written > 0 AND bytes_written + len(data) + trailer_bytes > max_segment_bytes:
        append trailer(frame_count, total_frame_bytes, frame_crc_chain)
        sync_data()              ← flush to disk
        rename .open → .bin      ← atomic finalization
        sync_dir()               ← directory entry durable
        open new .open (seq++)
        bytes_written = 0
    write data to current .open
    bytes_written += len(data)
```

A single frame is never split across segments. Frames larger than
`max_segment_bytes - trailer_bytes` are rejected outright.

#### Durability Modes

The `LogDurabilityMode` controls how often `sync_data()` (fdatasync) is
called:

| Mode | Discriminant | Behavior | Trade-off |
|------|-------------|----------|-----------|
| `SegmentClose` | `0` | `sync_data` only at segment rotation/finalize | Higher throughput; up to one segment of findings at risk on crash |
| `Batch` | `1` | `sync_data` after every `FindingBatch` frame write | Lower throughput; at most one batch at risk on crash |

Default: `SegmentClose`.

#### Writer Configuration Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_inflight_batches` | 256 | Max queued finding-batch frames before backpressure blocks producers |
| `max_inflight_bytes` | 64 MB | Max queued encoded bytes before backpressure blocks producers |
| `max_segment_bytes` | 64 MB | Segment rotation threshold |
| `max_frame_payload_bytes` | 16 MB | Hard cap on any single frame's payload |
| `durability` | `SegmentClose` | fsync strategy |

Validation rejects: any zero-valued budget, `max_inflight_batches` > `u32::MAX`
(wire format limit), and segment sizes that cannot fit at least one minimal
V2 frame plus the 64-byte segment trailer.

#### Backpressure

Two budgets are enforced atomically on the producer side:

```text
Producer thread                       Writer thread
───────────────                      ─────────────
reserve_inflight(frame_bytes)
  ├─ batches < 256 AND               write frame to disk
  │  bytes < 64 MB?                  release_inflight()
  │     YES → proceed                     │
  │     NO  → block on Condvar  ◄─────────┘ notify_all()
  ▼
send frame on channel ──────────►  recv → write → release
```

- A single frame exceeding `max_inflight_bytes` is rejected immediately
  (not silently dropped).
- Blocked producers wait on a `Condvar`, not spin.

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

#### Environment Variables

| Variable | Purpose |
|----------|---------|
| `SCANNER_FS_LOG_DIR` | Override the append-log store root directory (takes precedence over the default sibling-of-scan-root path) |
| `SCANNER_SECRET_KEY` | Stable secret key for BLAKE3-keyed identity hashes; if unset, an ephemeral key is generated (cross-run dedup disabled) |

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
