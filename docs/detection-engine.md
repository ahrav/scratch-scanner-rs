# Detection Engine Flow

Multi-phase pattern matching flow within `Engine::scan_chunk_into()`.

```mermaid
flowchart TB
    subgraph Input["Input"]
        Chunk["Chunk Data<br/>(raw bytes)"]
    end

    subgraph Phase1["Phase 1: Anchor Scan"]
        AC["AhoCorasick<br/>find_overlapping_iter()"]
        Raw["Raw Anchors"]
        U16LE["UTF-16LE Anchors"]
        U16BE["UTF-16BE Anchors"]
    end

    subgraph Phase2["Phase 2: Window Building"]
        HitAcc["HitAccumulator<br/>per (rule, variant)"]
        Merge["merge_ranges_with_gap_sorted()<br/>gap=64"]
        Coalesce["coalesce_under_pressure_sorted()<br/>max_windows=16"]
    end

    subgraph Phase3["Phase 3: Two-Phase Validation"]
        SeedWin["Seed Window<br/>(seed_radius)"]
        Confirm["confirm_any check<br/>memmem search"]
        Expand["Expand to full_radius"]
    end

    subgraph Phase4["Phase 4: Regex Confirmation"]
        MustContain["must_contain check<br/>(optional)"]
        ConfirmAll["confirm_all check<br/>(optional)"]
        Regex["rule.re.find_iter()"]
        UTF16Dec["UTF-16 Decode<br/>(for UTF-16 variants)"]
    end

    subgraph Output["Output"]
        FindingRec["FindingRec<br/>{ file_id, rule_id, span, step_id }"]
    end

    Chunk --> AC
    AC --> Raw
    AC --> U16LE
    AC --> U16BE

    Raw --> HitAcc
    U16LE --> HitAcc
    U16BE --> HitAcc

    HitAcc --> Merge
    Merge --> Coalesce

    Coalesce --> |"if two_phase"| SeedWin
    SeedWin --> Confirm
    Confirm --> |"if confirmed"| Expand
    Expand --> Phase4

    Coalesce --> |"if !two_phase"| Phase4

    Phase4 --> MustContain
    MustContain --> ConfirmAll
    ConfirmAll --> Regex
    Regex --> |"Raw variant"| FindingRec

    Regex --> |"UTF-16 variant"| UTF16Dec
    UTF16Dec --> FindingRec

    style Input fill:#e3f2fd
    style Phase1 fill:#fff3e0
    style Phase2 fill:#e8f5e9
    style Phase3 fill:#f3e5f5
    style Phase4 fill:#ffebee
    style Output fill:#e8eaf6
```

## Phase Details

### Phase 1: Anchor Scan

The engine uses Aho-Corasick for multi-pattern matching of anchor strings:

```rust
// Anchor patterns are deduplicated and mapped to rule targets
for m in self.ac_anchors.find_overlapping_iter(buf) {
    let pid = m.pattern().as_usize();
    let start = self.pat_offsets[pid] as usize;
    let end = self.pat_offsets[pid + 1] as usize;
    let targets = &self.pat_targets[start..end];  // flat Target list

    for &t in targets {
        let rule_id = t.rule_id();
        let variant = t.variant(); // Raw/Utf16Le/Utf16Be
        let rule = &self.rules[rule_id];
        let radius = compute_radius(rule, variant);
        let window = (m.start() - radius)..(m.end() + radius);
        accs[rule_id][variant.idx()].push(window);
    }
}
```

Each anchor is stored in three variants:
- **Raw**: Original bytes (e.g., `ghp_`)
- **UTF-16LE**: Little-endian encoding (e.g., `g\0h\0p\0_\0`)
- **UTF-16BE**: Big-endian encoding (e.g., `\0g\0h\0p\0_`)

### Phase 2: Window Building

Windows are accumulated per (rule, variant) pair:

```mermaid
graph LR
    subgraph Before["Before Merge"]
        W1["0..100"]
        W2["50..150"]
        W3["200..300"]
        W4["250..350"]
    end

    subgraph After["After Merge (gap=64)"]
        M1["0..150"]
        M2["200..350"]
    end

    W1 --> M1
    W2 --> M1
    W3 --> M2
    W4 --> M2
```

**Pressure Coalescing**: If windows exceed `max_windows_per_rule_variant` (16), the gap doubles until windows fit, or everything merges into one.

### Phase 3: Two-Phase Validation

For noisy rules (like private keys), two-phase confirmation reduces false positives:

```mermaid
sequenceDiagram
    participant Anchor as Anchor Hit
    participant Seed as Seed Window (256 bytes)
    participant Full as Full Window (16KB)
    participant Regex as Regex Validation

    Anchor->>Seed: Extract seed_radius window
    Seed->>Seed: memmem search for confirm_any
    alt Confirmed
        Seed->>Full: Expand to full_radius
        Full->>Regex: Run regex on expanded window
    else Not Confirmed
        Seed--xRegex: Skip this window
    end
```

Example: Private key detection
- `seed_radius`: 256 bytes (fast check)
- `confirm_any`: ["PRIVATE KEY"]
- `full_radius`: 16KB (for full PEM block)

### Phase 4: Regex Confirmation

For raw variants:
```rust
for rm in rule.re.find_iter(window) {
    scratch.out.push(FindingRec { ... });
}
```

For UTF-16 variants:
```rust
// Decode UTF-16 window to UTF-8
let decoded = decode_utf16le_to_buf(&buf[window], max_out)?;

// Create decode step for provenance
let utf16_step_id = scratch.step_arena.push(
    step_id,
    DecodeStep::Utf16Window { endianness, parent_span: window }
);

// Run regex on decoded bytes
for rm in rule.re.find_iter(&decoded) {
    scratch.out.push(FindingRec { step_id: utf16_step_id, ... });
}
```

## Transform Gating (URL/Base64)

After raw/UTF-16 scanning, the engine may generate derived buffers by decoding
URL-percent or Base64 spans. These transforms are expensive, so they are gated:

- **Decoded-space gate**: stream-decode and check for any anchor in the decoded
  bytes. If no anchor is found, the transform is skipped. This is conservative
  and avoids a full decode when the span is irrelevant.
- **Base64 pre-gate (encoded-space)**: Base64 uses an additional, cheaper prefilter
  that runs on the encoded bytes. It uses YARA-style base64 permutations of the
  anchors to cheaply reject spans that cannot possibly decode to an anchor. The
  decoded-space gate still runs afterward to preserve correctness.

Selection detail:
- The decoded-space gate chooses between a raw-only and a combined (raw + UTF-16)
  anchor automaton based on whether the decoded window contains any NUL bytes.
  This avoids UTF-16 overhead on NUL-free data while keeping a single pass on
  NUL-heavy buffers.

See `docs/transform-chain.md` for diagrams and the gating sequence.

## Keyword + Entropy Gates

Some rules benefit from additional semantic filters beyond anchors + regex:

- **Keyword gate (any-of)**: at least one keyword must appear inside the same
  validation window as the regex. This is a cheap memmem filter that reduces
  false positives without requiring global context.
- **Entropy gate**: after a regex match, compute Shannon entropy (bits/byte)
  of the matched bytes. Low-entropy matches are rejected as likely false
  positives (e.g., repeated characters or structured IDs).

These gates are designed to be **local and bounded**:
- Keywords are checked *before* regex, and for UTF-16 windows the check happens
  **before decoding** to avoid wasting decode budget.
- Entropy runs only on the regex match and is capped by `max_len` to keep cost
  predictable.

## Tuning Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `merge_gap` | 64 | Window merge gap (bytes) |
| `max_windows_per_rule_variant` | 16 | Max windows before pressure coalescing |
| `pressure_gap_start` | 128 | Starting gap for pressure coalescing |
| `max_anchor_hits_per_rule_variant` | 2048 | Hard cap on anchor hits |
| `max_utf16_decoded_bytes_per_window` | 64KB | UTF-16 decode output limit |

## Finding Output

```rust
FindingRec {
    file_id: FileId(0),
    rule_id: 1,              // Index into Engine.rules
    span_start: 100,
    span_end: 140,
    root_hint_start: 100,    // Offset in original file
    root_hint_end: 140,
    step_id: StepId(0),      // Decode provenance chain
}
```
