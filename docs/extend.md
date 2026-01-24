## Extensibility

### 1. `RuleSpec` is hard-coded to `'static` data, blocking runtime rule loading

* **What happens**

  * `RuleSpec.name`, `RuleSpec.anchors`, `TwoPhaseSpec.confirm_any`, `must_contain` are all `'static`.
    Evidence (lib.rs:L193-L221).
* **Why this blocks future work**

  * Loading rules from a config file (gitleaks-like) becomes awkward or impossible without leaking allocations to `'static`.
  * This will become painful the moment you want dynamic rule updates, per-tenant configs, or hot reload.
* **Fix**

  * Make `RuleSpec` own its data:

    * `name: String`
    * `anchors: Vec<Vec<u8>>`
    * `confirm_any: Vec<Vec<u8>>`
    * `must_contain: Option<Vec<u8>>`
  * Compile into `RuleCompiled` as you already do. The engine can still store owned compiled data.

### 2. Pipeline is tightly coupled to “filesystem path tree -> stdout lines”

* **What happens**

  * Output is hardwired to stdout formatting (pipeline.rs:L400-L437).
  * `FileTable` assumes filesystem `PathBuf` (lib.rs earlier).
* **Why this hurts adding other sources**

  * Scanning “Git blobs”, “S3 objects”, “database rows”, “stdin stream”, etc. does not naturally map to a `PathBuf`.
  * Stdout formatting as a stage prevents embedding this library into other services cleanly.
* **Fix**

  * Define a source-agnostic “artifact identifier”:

    * `enum ArtifactId { Path(PathBuf), Url(String), S3{...}, Git{...}, ... }`
  * Make pipeline generic over an output sink trait:

    * `trait FindingSink { fn on_finding(&mut self, f: FindingRec, meta: &ArtifactMeta); }`
  * Keep a CLI wrapper that prints to stdout, but do not bake stdout into the core pipeline.

### 3. `Rc` + interior mutability in `BufferPool` blocks parallel pipeline evolution

* **What happens**

  * `BufferPool` is `Rc`-backed and explicitly “intended for single-threaded use” (lib.rs:L388-L399).
* **Why this matters**

  * If your stated roadmap includes additional scanning sources, performance pressure will push you toward parallelism (multi-threaded scanning, async readers, etc.).
  * This pool becomes a dead-end: you will rewrite it or introduce per-thread pools anyway.
* **Fix**

  * Either:

    * Make it explicitly per-thread and structure the pipeline to not share it.
    * Or redesign around `Arc` + lock-free freelist / `Mutex` depending on goals.

### 4. Fixed-capacity, stack-allocated rings are an inflexible abstraction boundary

* **What happens**

  * `RingBuffer<T, const N: usize>` is stack-allocated, and pipeline ring capacities are const generics.
* **Why this matters**

  * As soon as you want runtime tuning (different machines, different repos), you want runtime-configurable capacities.
  * Large `OUT_CAP` makes a big stack frame. It’s fine today, but brittle.
* **Fix**

  * Use `VecDeque` or heap-backed ring with explicit caps if you want bounds.
  * Or keep the const-generic version only for microbench builds.

---
