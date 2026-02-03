# io_uring Open/Stat Plan (Default + Fallback)

Last updated: 2026-02-03

## Goal

Make io_uring-based open/stat the default for `local_fs_uring`, with a config
option to force the blocking `openat` + `fstat` path. The goal is to reduce
per-file syscall overhead while preserving current correctness (size-at-open
semantics, symlink policy, and error handling).

## Constraints And Semantics

- **Open-time size semantics**: size enforcement must use the snapshot taken
  after the file is opened, not discovery-time metadata.
- **Symlink policy parity**: current behavior uses `O_NOFOLLOW` on the final
  path component when `follow_symlinks = false`. io_uring path must match this
  by default; stronger path resolution must be opt-in.
- **Kernel variability**: op support (OPENAT, OPENAT2, STATX) is kernel- and
  config-dependent; we must probe and fall back cleanly.
- **Memory lifetime**: path strings and `open_how`/`statx` buffers must remain
  valid until submitted; on older kernels without `IORING_FEAT_SUBMIT_STABLE`,
  they may need to remain valid until completion.

## Feature Plan (Default + Fallback)

### Config Surface

Add a dedicated open/stat mode with clear fallback semantics:

```rust
pub enum OpenStatMode {
    /// Default: use io_uring open/stat when supported, otherwise fallback.
    UringPreferred,
    /// Force blocking open + fstat path (parity/debug).
    BlockingOnly,
    /// Require io_uring open/stat; error if unsupported.
    UringRequired,
}

pub struct LocalFsUringConfig {
    pub open_stat_mode: OpenStatMode,
    pub use_registered_buffers: bool,
    pub follow_symlinks: bool,
    pub resolve_policy: ResolvePolicy, // new, optional
    // ...
}

pub enum ResolvePolicy {
    /// Default: no path resolution constraints (match current behavior).
    Default,
    /// Stronger: disallow symlink traversal in all components.
    NoSymlinks,
    /// Optional: restrict traversal beneath dirfd root.
    BeneathRoot,
}
```

Defaults:
- `open_stat_mode = UringPreferred`
- `resolve_policy = Default`

### Capability Probe

At io_uring init, probe op support using `IORING_REGISTER_PROBE`:
- Required: `IORING_OP_OPENAT` or `IORING_OP_OPENAT2`
- Required: `IORING_OP_STATX`

If any required opcode is missing:
- `UringPreferred` → fallback to blocking open/stat
- `UringRequired` → return error

Also capture `IORING_FEAT_SUBMIT_STABLE` to decide whether to keep parameter
memory alive until submission or completion.

### Open Path: OPENAT2 Preferred

Use `IORING_OP_OPENAT2` when supported; otherwise fall back to `IORING_OP_OPENAT`.

Open flags:
- `O_RDONLY | O_CLOEXEC`
- `O_NOFOLLOW` when `follow_symlinks = false` (match current behavior)

Resolve policy:
- `ResolvePolicy::Default` → `how.resolve = 0` (match current behavior)
- `ResolvePolicy::NoSymlinks` → `RESOLVE_NO_SYMLINKS` (opt-in only; can be noisy)
- `ResolvePolicy::BeneathRoot` → `RESOLVE_BENEATH` (requires dirfd root strategy)

### Stat Path: Use STATX With `AT_EMPTY_PATH`

To preserve **open-time** semantics, perform statx on the opened file
descriptor using `AT_EMPTY_PATH` and an empty path string:

- `dirfd = <opened fd>`
- `path = ""` (NUL-terminated)
- `flags = AT_EMPTY_PATH`
- `mask = STATX_SIZE | STATX_TYPE | STATX_MODE` (minimum for size + type)

This uses `IORING_OP_STATX` and yields a `statx` buffer that must remain valid
until completion.

### Direct Descriptors (Phase 2)

If we later want direct descriptors for extra wins:
- Register file table with `IORING_REGISTER_FILES`
- Use `IORING_OP_OPENAT2` with direct descriptor allocation
- Set `IOSQE_FIXED_FILE` on subsequent ops

Defer until open/stat baseline is stable; direct descriptors complicate fd
lifetime and error handling.

## State Machine Changes

Introduce op kinds and per-file states:

```
FileWork -> PendingOpen -> PendingStat -> ReadyRead -> Done
```

`OpKind`:
- `Open` (OPENAT/OPENAT2)
- `Stat` (STATX)
- `Read` (existing)

Each op slot stores:
- Kind
- File slot
- Pointers to path / open_how / statx buffer

On CQE:
- `Open` success → enqueue `Stat`
- `Stat` success → build `ReadState` (size snapshot), enqueue for reads
- Any failure → update stats, release permit, cleanup

## Fallback Behavior

Fallback to blocking open/stat when:
- op probe fails
- kernel returns `-EINVAL`/`-EOPNOTSUPP` for the opcode
- `open_stat_mode = BlockingOnly`

Per-file fallback is allowed if only some paths fail (e.g., permission errors).

## Metrics And Observability

Add counters:
- `open_ops_submitted/completed`
- `stat_ops_submitted/completed`
- `open_failures`, `stat_failures`
- `open_stat_fallbacks`

## Work Units Checklist

- [x] Unit 1: Add config surface (`OpenStatMode`, `ResolvePolicy`), probe io_uring capabilities, track fallback counters; final step run doc-rigor on code touched.
- [x] Unit 2: Wire open/stat ops and per-file state machine (pending open/stat), include per-file fallback path; final step run doc-rigor on code touched.
- [x] Unit 3: Implement openat2/openat flags + resolve policy mapping, statx `AT_EMPTY_PATH`, open-time size enforcement; final step run doc-rigor on code touched.
- [x] Unit 4: Linux parity tests + metrics validation + doc updates; final step run doc-rigor on code touched.

## Test Plan (Linux Only)

- Functional parity vs blocking path on the same dataset.
- Size cap enforcement still matches open-time snapshot.
- Symlink policy: ensure `O_NOFOLLOW` behavior is unchanged by default.
- Probe-based skip when ops unsupported.

## Rollout

1. Land behind `open_stat_mode` (default `UringPreferred`).
2. Run Linux micro-bench on tiny-file workloads:
   - Compare syscall counts (`openat`, `statx`, `io_uring_enter`)
   - Compare wall time and throughput
3. If regressions or instability, switch default back to `BlockingOnly`.

## References

These references justify kernel availability, op semantics, and path safety
choices. Keep them updated when changing behavior.

```
io_uring_prep_openat2(3)  (liburing man page)
io_uring_prep_statx(3)    (liburing man page)
io_uring_enter2(2)        (direct descriptors and OPENAT2 availability)
openat2(2)                (RESOLVE_NO_SYMLINKS vs O_NOFOLLOW semantics)
statx(2)                  (AT_EMPTY_PATH for fd-based statx)
IORING_REGISTER_PROBE     (opcode probing)
```
