# Transform Chain

Recursive decoding flow for URL percent-encoding and Base64 transforms.

```mermaid
flowchart TB
    subgraph WorkQueue["Work Queue Processing"]
        WQ["work_q: Vec&lt;WorkItem&gt;"]
        WH["work_head: usize"]
        Loop["while work_head < work_q.len()"]
    end

    subgraph WorkItem["WorkItem Structure"]
        BufRef["buf: BufRef<br/>(Root | Slab)"]
        StepId["step_id: StepId"]
        RootHint["root_hint: Option&lt;Range&gt;"]
        Depth["depth: usize"]
    end

    subgraph Scan["Scan Current Buffer"]
        ScanRules["scan_rules_on_buffer()"]
        Findings["Emit FindingRecs"]
    end

    subgraph TransformLoop["Transform Processing"]
        CheckDepth{{"depth >= max_depth?"}}
        CheckItems{{"work_items >= max_items?"}}
        ForTransform["for transform in transforms"]
    end

    subgraph SpanDetection["Span Detection"]
        URL["find_url_spans_into()"]
        B64["find_base64_spans_into()"]
        Spans["spans: ScratchVec&lt;SpanU32&gt;"]
    end

    subgraph Gating["Gate Policy"]
        CheckB64{{"transform == Base64?"}}
        PreGate["b64_yara_gate.hits()<br/>(YARA-style encoded prefilter)"]
        Gate{{"gate == AnchorsInDecoded?"}}
        StreamGate["decoded anchor gate<br/>stream_decode + VS"]
        VSMatch["vs_gate anchor check"]
    end

    subgraph Decode["Decode & Dedupe"]
        StreamDecode["stream_decode()"]
        Slab["DecodeSlab::append_stream_decode()"]
        Hash["hash128(decoded)"]
        Seen["seen.insert(hash)"]
    end

    subgraph Enqueue["Enqueue Child"]
        PushStep["step_arena.push()"]
        PushWork["work_q.push(WorkItem)"]
    end

    WQ --> Loop
    Loop --> |"pop item"| WorkItem
    WorkItem --> ScanRules
    ScanRules --> Findings
    ScanRules --> CheckDepth

    CheckDepth --> |"yes"| Loop
    CheckDepth --> |"no"| CheckItems
    CheckItems --> |"yes"| Loop
    CheckItems --> |"no"| ForTransform

    ForTransform --> URL
    ForTransform --> B64
    URL --> Spans
    B64 --> Spans

    Spans --> CheckB64
    CheckB64 --> |"yes"| PreGate
    CheckB64 --> |"no"| Gate
    PreGate --> |"pass"| Gate
    PreGate --> |"fail"| ForTransform
    Gate --> |"yes"| StreamGate
    StreamGate --> VSMatch
    VSMatch --> |"no anchor"| ForTransform
    VSMatch --> |"anchor found"| Decode
    Gate --> |"no"| Decode

    Decode --> StreamDecode
    StreamDecode --> |"anchor matches"| TimingWheel["TimingWheel<br/>pending_windows"]
    TimingWheel --> |"advance_and_drain"| WindowValidation["Window Validation"]
    StreamDecode --> Slab
    Slab --> Hash
    Hash --> Seen

    Seen --> |"duplicate"| ForTransform
    Seen --> |"new"| Enqueue

    Enqueue --> PushStep
    PushStep --> PushWork
    PushWork --> Loop

    style WorkQueue fill:#e3f2fd
    style WorkItem fill:#fff3e0
    style Scan fill:#e8f5e9
    style TransformLoop fill:#f3e5f5
    style SpanDetection fill:#ffebee
    style Gating fill:#e8eaf6
    style Decode fill:#fce4ec
    style Enqueue fill:#c8e6c9
```

## Budget Limits

```mermaid
graph LR
    subgraph Limits["DoS Protection Limits"]
        MaxDepth["max_transform_depth: 3"]
        MaxOutput["max_total_decode_output_bytes: 512KB"]
        MaxItems["max_work_items: 256"]
        MaxSpans["max_spans_per_buffer: 8"]
        MaxDecoded["max_decoded_bytes: 64KB per span"]
    end

    style Limits fill:#ffebee
```

## Archive Entry Context

When archive scanning is enabled, entry payload bytes flow through the same
transform chain and decoding budgets as regular files. Archive entry paths are
canonicalized separately in the archive subsystem and do not affect transform
logic or decode limits.
See `src/archive/` for archive-specific invariants and budget guardrails.

## Unified Scanner Output Integration

Transform findings produced by the engine flow through the unified event
contract (`ScanEvent::Finding`) in both filesystem and git scan modes. The
decode/transform decision logic and budgets in this document are unchanged;
only emission/reporting wiring changed.

See [`scanner-unification.md`](scanner-unification.md) for routing/output
details.

| Limit | Default | Purpose |
|-------|---------|---------|
| `max_transform_depth` | 3 | Maximum decode chain length |
| `max_total_decode_output_bytes` | 512KB | Global decode output budget |
| `max_work_items` | 256 | Maximum queued decoded buffers |
| `max_spans_per_buffer` | 8 | Candidate spans per transform per buffer |
| `max_decoded_bytes` | 64KB | Output limit per span decode |

## Transform Types

### URL Percent Decoding

```mermaid
graph LR
    Input["ghp%5Fabc123..."]
    Detect["find_url_spans_into()<br/>requires % trigger"]
    Decode["stream_decode_url_percent()"]
    Output["ghp_abc123..."]

    Input --> Detect --> Decode --> Output
```

**Span Detection Rules**:
- Requires at least one `%` (or `+` if `plus_to_space` enabled)
- Matches URL-safe character runs: `A-Za-z0-9%+-_.~:/?#[]@!$&'()*,;=`
- Minimum length: 16 characters

### Base64 Decoding

```mermaid
graph LR
    Input["Z2hwX2FiYzEyMw=="]
    Detect["find_base64_spans_into()<br/>B64 char runs"]
    Decode["stream_decode_base64()"]
    Output["ghp_abc123..."]

    Input --> Detect --> Decode --> Output
```

**Span Detection Rules**:
- Matches Base64 alphabet: `A-Za-z0-9+/=-_` plus optional whitespace
- Handles both standard and URL-safe alphabets
- Minimum length: 32 characters

### Base64 Pre-Decode Gate (YARA-style)

Base64 spans can be long, and decoding them just to discover "no anchor present"
is expensive. To avoid that, Base64 transforms add a **pre-gate** that runs on
the *encoded* bytes before any decoding.

**Core idea**: a decoded anchor can appear at any of three byte offsets inside a
base64 quantum. YARA documents this by generating three encoded permutations
and stripping the unstable prefix/suffix characters. We do the same and then
search the encoded stream with Vectorscan.

**Why this is safe**:
- It is **conservative**: if decoded bytes contain an anchor, at least one of
  the derived base64 permutations must appear in the encoded bytes.
- False positives are fine because the decoded gate still confirms anchors
  before accepting the transform.

**Normalization rules**:
- Ignore RFC4648 whitespace (space is only ignored if the span finder allows it).
- Treat URL-safe `-`/`_` as `+`/`/`.
- Stop scanning at `=` padding to avoid cross-span false matches.

## Gate Policy: AnchorsInDecoded

The decoded gate avoids expensive full decodes by streaming and checking for anchors.
For Base64 spans, there is **also** an encoded-space pre-gate that runs first:

```mermaid
sequenceDiagram
    participant Transform as Transform
    participant Pre as b64_yara_gate (encoded prefilter)
    participant Gate as decoded gate
    participant Stream as stream_decode()
    participant VS as Vectorscan
    participant Budget as total_decode_output_bytes

    Note over Transform,Pre: Base64 only
    Transform->>Pre: Encoded pre-gate
    Pre-->>Transform: pass/fail
    Transform->>Gate: Decoded gate (if enabled)
    Gate->>Stream: Start streaming decode

    loop Each chunk
        Stream-->>Gate: decoded chunk
        Gate->>Budget: Add chunk.len()
        Gate->>Gate: Prepend tail from previous chunk
        Gate->>VS: is_match(tail + chunk)?
        alt Anchor found
            Gate-->>Transform: true (proceed with full decode)
        else Budget exceeded
            Gate-->>Transform: false (skip)
        end
        Gate->>Gate: Keep tail (max_anchor_pat_len - 1)
    end

    Gate-->>Transform: false (no anchor found)
```

## Stream Decode Window Scheduling

During streaming decode, anchor matches are discovered incrementally as chunks
decode. The **TimingWheel** schedules these matches for validation without
waiting for the full buffer:

```mermaid
sequenceDiagram
    participant Stream as stream_decode()
    participant VS as Vectorscan (streaming)
    participant TW as TimingWheel
    participant Val as process_window()

    loop Each decoded chunk
        Stream->>VS: scan_chunk(decoded_bytes)
        VS-->>Stream: anchor match at offset X
        Stream->>TW: push(hi=X+radius, window)
        TW-->>Stream: Scheduled | Ready
        Stream->>TW: advance_and_drain(current_offset)
        TW-->>Val: windows with hi <= offset
        Val->>Val: regex validation
    end

    Note over Stream,TW: End of stream
    Stream->>TW: advance_and_drain(u64::MAX)
    TW-->>Val: remaining windows
```

**Key invariant**: `pending_windows` uses `G=1` (exact scheduling), so windows
fire precisely when `decoded_offset >= hi`. This avoids both early firing
(incomplete window) and excessive latency.

See `docs/detection-engine.md` for TimingWheel data structure details.

## StepArena Provenance

```mermaid
graph TB
    Root["StepId::ROOT<br/>(original buffer)"]

    Step1["StepId(0)<br/>Transform { idx: 0, span: 100..200 }"]
    Step2["StepId(1)<br/>Transform { idx: 1, span: 50..150 }"]
    Step3["StepId(2)<br/>Utf16Window { Le, span: 0..64 }"]

    Root --> Step1
    Step1 --> Step2
    Root --> Step3

    style Root fill:#e8f5e9
```

The StepArena enables zero-copy finding records by storing decode provenance as a linked chain:

```rust
struct StepNode {
    parent: StepId,      // Links to parent step (or STEP_ROOT)
    step: DecodeStep,    // Transform or Utf16Window
}

// Materialization walks the chain backwards
fn materialize(&self, mut id: StepId, out: &mut Vec<DecodeStep>) {
    while id != STEP_ROOT {
        let node = &self.nodes[id.0 as usize];
        out.push(node.step.clone());
        id = node.parent;
    }
    out.reverse();
}
```

## Deduplication

The `FixedSet128` provides O(1) hash-based deduplication with generation-based reset:

```rust
struct FixedSet128 {
    keys: Vec<u128>,    // Hash keys
    gen: Vec<u32>,      // Generation counters
    cur: u32,           // Current generation
    mask: usize,        // Capacity mask (power of 2)
}

// Reset is O(1) - just increment generation
fn reset(&mut self) {
    self.cur = self.cur.wrapping_add(1);
    if self.cur == 0 {
        self.gen.fill(0);  // Handle wraparound
        self.cur = 1;
    }
}
```

This prevents re-scanning identical decoded content (e.g., same Base64 blob appearing multiple times).
The engine hashes decoded buffers with a 128-bit AEGIS-128L tag for collision resistance.
