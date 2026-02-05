# Git Pack Regression Corpus

This directory stores minimized pack files used for regression coverage of pack
parsing and delta-apply behavior. These artifacts are intentionally small and
synthetic; pack trailer hashes are zeroed because checksums are not the focus.

Files:
- `corrupt_header.pack`: Pack with an invalid entry header (continuation bit, no follow-up bytes).
- `truncated_zlib.pack`: Pack with a blob entry whose zlib stream is truncated.
- `deep_delta_chain.pack`: Pack with a 3-object OFS-delta chain (base -> delta1 -> delta2).
- `external_base_base.pack`: Pack containing the base blob for external base tests.
- `external_base_delta.pack`: Pack containing a REF-delta referencing the base blob.

Regeneration:
- Command: `python3 scripts/gen_git_pack_corpus.py`
- Git version at time of generation: `git version 2.51.2`
- Notes: External base uses the SHA-1 of `blob 4\0BASE` as the base OID.
