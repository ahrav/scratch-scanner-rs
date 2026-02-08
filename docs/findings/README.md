# Performance Findings

This directory contains performance investigation reports and benchmark findings.
Each report captures a specific investigation with methodology, results, and
conclusions to build an institutional record over time.

## Reports

| Date | Report | Summary |
|------|--------|---------|
| 2026-02-08 | [Phase 2 data layout benchmarks](2026-02-08-phase2-data-layout-benchmarks.md) | Phase 2 vs Phase 1: Tier2 mean +3.95%, Tier3 mean +0.95%, transform-heavy cases +10.36%; keep changes and follow up on rule-scaling regressions |
| 2026-02-08 | [Phase 1 data layout benchmarks](2026-02-08-phase1-data-layout-benchmarks.md) | Phase 1 reference run across scanner throughput, rule scaling, and vectorscan overhead; no pre-optimization baseline available |
| 2026-02-07 | [FS scan transform overhead](2026-02-07-fs-scan-transform-overhead.md) | Transform decoding accounts for 2.26x overhead on source-code corpora; disabling transforms yields ~8 GiB/s on 12 cores |
