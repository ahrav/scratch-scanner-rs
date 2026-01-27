* **Decision**: treat keywords as **local context**, required **inside the same validation window** that you already run the regex over.

  * Anything “keyword can be far from the finding” is not compatible with your current **single-pass, chunked + overlap** design without either:

    * increasing radius/overlap dramatically (perf hit), or
    * doing a file-level prepass / two-pass scan (pipeline change), or
    * buffering and revisiting earlier chunks (complex and memory heavy).
  * If a rule genuinely needs “far context”, that rule is poorly specified for this architecture. Make that context an **anchor** (or add a second rule stage later with composite/proximity logic).

* **Keywords are still first-line defense** where it matters:

  * The actual first defense is **anchors** (they decide which windows even exist).
  * Inside a window, keyword gating is a **pre-regex gate**.
  * For UTF-16 windows, keyword gating should happen **before decoding** to avoid spending decode budget on windows that cannot pass.

* **Why keyword check goes after `must_contain`**

  * `must_contain` is a single `memmem` search.
  * `keywords_any` is N `memmem` searches.
  * Running the 1-search gate first is strictly cheaper and often similarly selective.
  * If you later want to get fancy, you can order gates by estimated selectivity, but don’t start there.

---

## Rust implementation (keywords + entropy) integrated into your current design

### What this implementation does

* **Keywords**

  * Adds `keywords_any: Option<&'static [&'static [u8]]>` to `RuleSpec`.
  * Compiles keywords into the existing `PackedPatterns` slab format for **Raw/UTF16LE/UTF16BE**.
  * Applies keywords as a **pre-regex window gate**:

    * Raw: search in the raw window bytes.
    * UTF-16 windows: search the raw UTF-16 bytes **before decoding** (ASCII-only encoding logic, same as your anchor UTF-16 generation).

* **Entropy**

  * Adds `entropy: Option<EntropySpec>` to `RuleSpec`.
  * Computes **Shannon entropy (bits per byte)** on each regex match.
  * Uses:

    * a per-scan fixed histogram (`EntropyScratch`) with “touched bins” reset to avoid per-match allocations
    * a precomputed `log2(n)` table in `Engine` to avoid repeated `log2` calls

---

## Code you need (drop-in changes)

### 1) Public config additions

```rust
#[derive(Clone, Debug)]
pub struct RuleSpec {
    pub name: &'static str,
    pub anchors: &'static [&'static [u8]],
    pub radius: usize,
    pub two_phase: Option<TwoPhaseSpec>,
    pub must_contain: Option<&'static [u8]>,

    // NEW: keyword gate (any-of)
    pub keywords_any: Option<&'static [&'static [u8]]>,

    // NEW: entropy gate
    pub entropy: Option<EntropySpec>,

    pub re: Regex,
}

/// Shannon-entropy gate configuration.
/// - Entropy is computed over the matched byte slice (currently full regex match)
/// - Threshold is bits/byte (0.0..=8.0)
/// - Matches shorter than `min_len` pass (entropy is noisy on tiny samples)
#[derive(Clone, Debug)]
pub struct EntropySpec {
    pub min_bits_per_byte: f32,
    pub min_len: usize,
    pub max_len: usize,
}
```

### 2) Compiled rule additions

```rust
#[derive(Clone, Debug)]
struct KeywordsCompiled {
    any: [PackedPatterns; 3], // Raw / Utf16Le / Utf16Be
}

#[derive(Clone, Copy, Debug)]
struct EntropyCompiled {
    min_bits_per_byte: f32,
    min_len: usize,
    max_len: usize,
}

#[derive(Clone, Debug)]
struct RuleCompiled {
    name: &'static str,
    radius: usize,
    must_contain: Option<&'static [u8]>,

    // NEW
    keywords: Option<KeywordsCompiled>,
    entropy: Option<EntropyCompiled>,

    re: Regex,
    two_phase: Option<TwoPhaseCompiled>,
}
```

### 3) Entropy scratch (no allocations)

```rust
#[derive(Clone, Copy)]
struct EntropyScratch {
    counts: [u32; 256],
    used: [u8; 256],
    used_len: u16,
}

impl EntropyScratch {
    fn new() -> Self {
        Self {
            counts: [0u32; 256],
            used: [0u8; 256],
            used_len: 0,
        }
    }

    #[inline]
    fn reset(&mut self) {
        let used_len = self.used_len as usize;
        for i in 0..used_len {
            let b = self.used[i] as usize;
            self.counts[b] = 0;
        }
        self.used_len = 0;
    }
}
```

### 4) Engine stores log2 table

```rust
pub struct Engine {
    rules: Vec<RuleCompiled>,
    transforms: Vec<TransformConfig>,
    tuning: Tuning,

    // NEW: log2 lookup table for entropy
    entropy_log2: Vec<f32>,

    // existing...
    ac_anchors: AhoCorasick,
    pat_targets: Vec<Target>,
    pat_offsets: Vec<u32>,
    // ...
}
```

In `Engine::new(...)` after compiling rules:

```rust
let rules_compiled = rules.iter().map(compile_rule).collect::<Vec<_>>();

let max_entropy_len = rules_compiled
    .iter()
    .filter_map(|r| r.entropy.map(|e| e.max_len))
    .max()
    .unwrap_or(0);

let entropy_log2 = build_log2_table(max_entropy_len);

// later in Self { ... } include entropy_log2
```

### 5) ScanScratch stores EntropyScratch

```rust
pub struct ScanScratch {
    // ...
    utf16_buf: Vec<u8>,
    entropy_scratch: EntropyScratch, // NEW
    steps_buf: Vec<DecodeStep>,
}
```

In `ScanScratch::new(...)`:

```rust
entropy_scratch: EntropyScratch::new(),
```

In `reset_for_scan(...)`:

```rust
self.entropy_scratch.reset();
```

### 6) Compile keywords + entropy in `compile_rule`

```rust
fn compile_rule(spec: &RuleSpec) -> RuleCompiled {
    let two_phase = spec.two_phase.as_ref().map(|tp| {
        let count = tp.confirm_any.len();
        let raw_bytes = tp.confirm_any.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);

        let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
        let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
        let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

        for &p in tp.confirm_any {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        TwoPhaseCompiled {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm: [raw, le, be],
        }
    });

    let keywords = spec.keywords_any.map(|kws| {
        let count = kws.len();
        let raw_bytes = kws.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);

        let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
        let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
        let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

        for &p in kws {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        KeywordsCompiled { any: [raw, le, be] }
    });

    let entropy = spec.entropy.as_ref().map(|e| EntropyCompiled {
        min_bits_per_byte: e.min_bits_per_byte,
        min_len: e.min_len,
        max_len: e.max_len,
    });

    RuleCompiled {
        name: spec.name,
        radius: spec.radius,
        must_contain: spec.must_contain,
        keywords,
        entropy,
        re: spec.re.clone(),
        two_phase,
    }
}
```

### 7) Apply keyword gate pre-regex + entropy gate per match

Raw branch (in `run_rule_on_window`):

```rust
if let Some(kws) = &rule.keywords {
    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
        return;
    }
}

scratch.regex_evals = scratch.regex_evals.saturating_add(1);
for rm in rule.re.find_iter(window) {
    if let Some(ent) = rule.entropy {
        let mbytes = &window[rm.start()..rm.end()];
        if !entropy_gate_passes(&ent, mbytes, &mut scratch.entropy_scratch, &self.entropy_log2) {
            continue;
        }
    }

    // push finding...
}
```

UTF-16 branch: keyword gate on UTF-16 bytes **before decode**, then entropy per match on decoded bytes:

```rust
if let Some(kws) = &rule.keywords {
    let raw_win = &buf[w.clone()];
    let vidx = variant.idx();
    if !contains_any_memmem(raw_win, &kws.any[vidx]) {
        return;
    }
}

// decode...
for rm in rule.re.find_iter(decoded) {
    if let Some(ent) = rule.entropy {
        let mbytes = &decoded[rm.start()..rm.end()];
        if !entropy_gate_passes(&ent, mbytes, &mut scratch.entropy_scratch, &self.entropy_log2) {
            continue;
        }
    }

    // push finding...
}
```

### 8) Entropy helpers

```rust
fn build_log2_table(max: usize) -> Vec<f32> {
    let len = max.saturating_add(1).max(2);
    let mut t = vec![0.0f32; len];
    for i in 1..len {
        t[i] = (i as f32).log2();
    }
    t
}

#[inline]
fn log2_lookup(table: &[f32], n: usize) -> f32 {
    if n < table.len() {
        table[n]
    } else {
        (n as f32).log2()
    }
}

#[inline]
fn shannon_entropy_bits_per_byte(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> f32 {
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }

    for &b in bytes {
        let idx = b as usize;
        let c = scratch.counts[idx];
        if c == 0 {
            let used_len = scratch.used_len as usize;
            if used_len < scratch.used.len() {
                scratch.used[used_len] = b;
                scratch.used_len = (used_len + 1) as u16;
            }
        }
        scratch.counts[idx] = c + 1;
    }

    let log2_n = log2_lookup(log2_table, n);
    let mut sum_c_log2_c = 0.0f32;

    let used_len = scratch.used_len as usize;
    for i in 0..used_len {
        let idx = scratch.used[i] as usize;
        let c = scratch.counts[idx] as usize;
        sum_c_log2_c += (c as f32) * log2_lookup(log2_table, c);
    }

    scratch.reset();

    log2_n - (sum_c_log2_c / (n as f32))
}

#[inline]
fn entropy_gate_passes(
    spec: &EntropyCompiled,
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> bool {
    let len = bytes.len();
    if len < spec.min_len {
        return true;
    }
    let capped = len.min(spec.max_len);
    let e = shannon_entropy_bits_per_byte(&bytes[..capped], scratch, log2_table);
    e >= spec.min_bits_per_byte
}
```

---

## Example: a rule with keywords + entropy

```rust
static KEYWORDS: &[&[u8]] = &[b"api_key", b"apikey", b"token", b"secret"];

let rule = RuleSpec {
    name: "generic-token",
    anchors: &[b"="],            // example only, use something better
    radius: 128,
    two_phase: None,
    must_contain: None,

    keywords_any: Some(KEYWORDS),
    entropy: Some(EntropySpec {
        min_bits_per_byte: 3.5,
        min_len: 20,
        max_len: 256,
    }),

    re: Regex::new(r"[A-Za-z0-9_\-]{20,}").unwrap(),
};
```
