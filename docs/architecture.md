# Scanner Architecture

## Overview

This crate scans byte streams for secret-like patterns using an anchor-first
approach. The design favors explicit memory budgets, bounded decoding, and
reusable scratch buffers so large scans do not trigger per-chunk allocations.

## Pipeline Flow

```
Path
  |
Walker -> FileTable -> ReaderStage -> Chunk -> Engine -> FindingRec -> OutputStage -> stdout
             ^            |
             |            +-- BufferPool (fixed-size aligned buffers)
             +-- FileId (stable indexing into metadata)
```

- Walker traverses the filesystem and enqueues FileId values.
- ReaderStage pulls FileId values, reads files in fixed-size chunks with
  overlap, and returns Chunk values backed by the BufferPool.
- Engine scans each Chunk and produces FindingRec entries.
- OutputStage formats findings for stdout.

The pipeline is intentionally staged with fixed-capacity rings so backpressure
is explicit and memory usage stays bounded.

## Engine Flow (per buffer)

```
Root buffer
  -> Anchor scan (raw + UTF-16 variants, Aho-Corasick)
  -> Window build and merge/coalesce
  -> Optional two-phase confirm + expand
  -> Regex validation (bytes regex)
  -> Transform worklist:
       - span detection
       - optional gate (anchors in decoded stream)
       - streaming decode into DecodeSlab
       - dedupe decoded output
       - enqueue WorkItem (bounded depth and count)
```

Key details:

- Anchors reduce work: regex is only applied inside windows around anchor hits.
- Two-phase rules (seed + confirm) keep noisy patterns cheaper: confirm in a
  smaller seed window, then expand to the full window.
- Transform decoding is gated by anchor checks in decoded output to avoid
  expensive full decodes when no anchors exist.
- Budgets cap recursion depth, decoded bytes, and work items to prevent DoS.

## Core Data Structures

- BufferPool / BufferHandle
  Fixed-capacity pool of aligned buffers sized for file chunks. The pool is
  Rc-backed (single-threaded) and buffers are returned automatically on drop.

- DecodeSlab
  Pre-allocated slab for decoded bytes. Transform decoders append into the slab
  and return ranges, so derived buffers are represented by offsets instead of
  heap allocations.

- StepArena and StepId
  Decode provenance is stored as a parent-linked arena. Findings carry a StepId
  that can be materialized into a DecodeStep chain without cloning vectors on
  the hot path.

- FixedSet128
  Small fixed-capacity hash set used to dedupe decoded buffers (128-bit keys).
  Generation counters make reset O(1) without clearing memory.

- HitAccumulator
  Collects anchor hit windows and switches to a single coalesced window when
  hit volume exceeds a configured limit.

## Findings and Spans

- FindingRec stores compact spans and a StepId. It is the hot-path format used
  during scanning.
- Finding is the materialized, user-facing format with DecodeStep chains and
  root-span hints for reporting.

## Extending the Scanner

- Add rules by supplying RuleSpec values (anchors + regex), optionally with
  TwoPhaseSpec to reduce false positives.
- Add transforms by extending TransformId and the transform dispatch helpers.
  Each transform should provide span detection, streaming decode, and gating
  where possible.
