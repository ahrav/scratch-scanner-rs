# Pipeline State Machine

Cooperative scheduling loop and state transitions in the scanner-rs pipeline.

```mermaid
stateDiagram-v2
    [*] --> Running: scan_path() called

    state Running {
        [*] --> PumpOutput

        PumpOutput --> PumpScanner: output.pump()
        PumpScanner --> PumpReader: scanner.pump()
        PumpReader --> PumpWalker: reader.pump()
        PumpWalker --> CheckProgress: walker.pump()

        CheckProgress --> PumpOutput: progressed = true
        CheckProgress --> CheckDone: progressed = false

        CheckDone --> PumpOutput: !done
        CheckDone --> [*]: done
    }

    Running --> Done: all stages idle
    Running --> Stalled: no progress & not done

    Done --> [*]: return Ok(stats)
    Stalled --> [*]: return Err("pipeline stalled")
```

## Pump Order

The pipeline processes stages in **reverse order** (output to input) to maximize throughput:

```mermaid
sequenceDiagram
    participant Loop as Main Loop
    participant Output as OutputStage
    participant Scanner as ScanStage
    participant Reader as ReaderStage
    participant Walker as Walker

    loop Every iteration
        Loop->>Output: pump() - drain findings
        Output-->>Loop: progressed?

        Loop->>Scanner: pump() - scan chunks
        Scanner-->>Loop: progressed?

        Loop->>Reader: pump() - read files
        Reader-->>Loop: progressed?

        Loop->>Walker: pump() - discover files
        Walker-->>Loop: progressed?

        Loop->>Loop: Check termination
    end
```

**Why reverse order?**
1. Output first creates space in `out_ring`
2. Scanner can then emit new findings
3. Reader can push chunks when `chunk_ring` has space
4. Walker fills `file_ring` with more work

This prevents deadlocks where upstream stages block on full queues.

## Stage States

```mermaid
stateDiagram-v2
    state Walker {
        [*] --> Walking
        Walking --> Walking: found directory
        Walking --> Walking: found file
        Walking --> Done: stack empty
        Walking --> Done: max_files reached
    }

    state ReaderStage {
        [*] --> Idle
        Idle --> Reading: file_ring.pop()
        Reading --> Reading: more chunks
        Reading --> Idle: EOF reached
    }

    state ScanStage {
        [*] --> Scanning
        Scanning --> Flushing: chunk scanned
        Flushing --> Scanning: pending drained
    }

    state OutputStage {
        [*] --> Outputting
        Outputting --> Outputting: findings available
    }
```

## Termination Conditions

```rust
let done = walker.is_done()           // No more files to discover
    && reader.is_idle()               // No active file being read
    && file_ring.is_empty()           // No pending file IDs
    && chunk_ring.is_empty()          // No pending chunks
    && !scanner.has_pending()         // No buffered findings
    && out_ring.is_empty();           // All findings written
```

```mermaid
graph TB
    subgraph Termination["Termination Check"]
        WD["walker.is_done()"]
        RI["reader.is_idle()"]
        FE["file_ring.is_empty()"]
        CE["chunk_ring.is_empty()"]
        NP["!scanner.has_pending()"]
        OE["out_ring.is_empty()"]
    end

    WD --> AND
    RI --> AND
    FE --> AND
    CE --> AND
    NP --> AND
    OE --> AND

    AND{{"ALL true?"}}
    AND --> |yes| Done["Break loop"]
    AND --> |no| Continue["Next iteration"]

    style Termination fill:#e8f5e9
```

## Progress Tracking

Each `pump()` returns a boolean indicating whether progress was made:

```rust
loop {
    let mut progressed = false;

    progressed |= output.pump(&engine, &files, &mut out_ring, &mut stats)?;
    progressed |= scanner.pump(&engine, &mut chunk_ring, &mut out_ring);
    progressed |= reader.pump(&mut file_ring, &mut chunk_ring, &pool, &files, &mut stats)?;
    progressed |= walker.pump(&mut files, &mut file_ring, &mut stats)?;

    // ... termination check ...

    if !progressed {
        return Err(io::Error::new(io::ErrorKind::Other, "pipeline stalled"));
    }
}
```

This check prevents a silent busy loop when rings are full/empty in a way that
should not be possible. It surfaces deadlocks early during development.

## Stall Detection

A stall occurs when:
- No stage made progress (`progressed = false`)
- Termination conditions not met

This indicates a logic error (e.g., deadlock) rather than empty input:

```mermaid
graph TB
    subgraph StallScenario["Stall Scenario (Bug)"]
        FR["file_ring: FULL"]
        CR["chunk_ring: FULL"]
        OR["out_ring: FULL"]

        Walker["Walker: blocked<br/>(file_ring full)"]
        Reader["Reader: blocked<br/>(chunk_ring full)"]
        Scanner["Scanner: blocked<br/>(out_ring full)"]
        Output["Output: blocked<br/>(??? - should drain)"]
    end

    style StallScenario fill:#ffebee
```

In practice, stalls shouldn't occur because:
- Ring buffer sizes are chosen to prevent blocking
- Output stage always drains when data is available
- Pool size exceeds chunk ring capacity

## Backpressure Handling

```mermaid
sequenceDiagram
    participant Scanner as ScanStage
    participant OutRing as out_ring
    participant Output as OutputStage

    Note over Scanner: scan_chunk_into() produces 100 findings
    Scanner->>Scanner: drain_findings_into(pending)

    loop While pending.len() > 0
        Scanner->>OutRing: push(finding)
        alt Ring full
            OutRing-->>Scanner: Err(finding)
            Note over Scanner: pending_idx stays put
            Scanner-->>Scanner: Break, try next iteration
        else Ring has space
            OutRing-->>Scanner: Ok(())
            Scanner->>Scanner: pending_idx += 1
        end
    end

    Note over Output: Next pump() iteration
    Output->>OutRing: pop()
    OutRing-->>Output: FindingRec
    Output->>Output: write to stdout
```

The `ScanStage` buffers findings in `pending` when `out_ring` is full, ensuring no findings are dropped.

## Ring Buffer Flow Control

```mermaid
graph LR
    subgraph Capacities
        FR["file_ring<br/>cap=1024"]
        CR["chunk_ring<br/>cap=128"]
        OR["out_ring<br/>cap=8192"]
    end

    subgraph FlowControl
        WC{{"file_ring.is_full()?"}}
        RC{{"chunk_ring.is_full()?"}}
        SC{{"out_ring.is_full()?"}}
    end

    Walker --> WC
    WC --> |no| FR
    WC --> |yes| WaitW["Wait next iteration"]

    Reader --> RC
    RC --> |no| CR
    RC --> |yes| WaitR["Wait next iteration"]

    Scanner --> SC
    SC --> |no| OR
    SC --> |yes| Buffer["Buffer in pending"]
```

## Statistics Collection

```rust
pub struct PipelineStats {
    pub files: u64,     // Files discovered by Walker
    pub chunks: u64,    // Chunks read by Reader
    pub findings: u64,  // Findings written by Output
    pub errors: u64,    // File open/read errors
}
```

Stats are updated atomically at each stage:
- `Walker::pump()`: `stats.files += 1` per file
- `Reader::pump()`: `stats.chunks += 1` per chunk, `stats.errors += 1` on open failure
- `Output::pump()`: `stats.findings += 1` per finding written
