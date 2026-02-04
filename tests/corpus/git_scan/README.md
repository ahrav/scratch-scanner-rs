# Git Scan Corpus Index

This directory contains deterministic Git simulation scenarios. Each
`*.case.json` file is a complete `GitReproArtifact` used by the sim harness.

## Scenarios

| File | Description |
|---|---|
| `minimal_sha1.case.json` | Single-ref, single-commit SHA-1 repo with a blob candidate; validates trace hash replay and pipeline ordering. |
