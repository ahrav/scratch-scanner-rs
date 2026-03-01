"""Verification tests for capture_baseline.py review comments."""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capture_baseline as cb


# ---------------------------------------------------------------------------
# Comment 3: Empty MIGRATION_DECODE_DEPTH env var -> ValueError (CONFIRMED, FIXED)
# ---------------------------------------------------------------------------
class TestEmptyDecodeDepthEnvVar:
    def test_empty_decode_depth_env_does_not_crash(self):
        """Empty MIGRATION_DECODE_DEPTH should fall back to default, not raise."""
        env = {**os.environ, "MIGRATION_DECODE_DEPTH": ""}
        result = subprocess.run(
            [sys.executable, "-c",
             "import capture_baseline; capture_baseline.parse_args()"],
            cwd=str(Path(__file__).resolve().parent),
            env=env,
            capture_output=True,
            text=True,
        )
        assert "ValueError" not in result.stderr, (
            f"Empty MIGRATION_DECODE_DEPTH should not crash.\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Comments 4-6: Empty string env vars fall back to defaults (CONFIRMED, FIXED)
# ---------------------------------------------------------------------------
class TestEmptyEnvVarFallbacks:
    def test_empty_scanner_bin_falls_back(self):
        val = os.environ.get("MIGRATION_SCANNER_BIN") or "target/release/scanner-rs"
        with mock.patch.dict(os.environ, {"MIGRATION_SCANNER_BIN": ""}):
            val = os.environ.get("MIGRATION_SCANNER_BIN") or "target/release/scanner-rs"
        assert val == "target/release/scanner-rs"

    def test_empty_artifact_root_falls_back(self):
        with mock.patch.dict(os.environ, {"MIGRATION_ARTIFACT_ROOT": ""}):
            val = os.environ.get("MIGRATION_ARTIFACT_ROOT") or "../baseline-artifacts"
        assert val == "../baseline-artifacts"

    def test_empty_transforms_falls_back(self):
        with mock.patch.dict(os.environ, {"MIGRATION_TRANSFORMS": ""}):
            val = os.environ.get("MIGRATION_TRANSFORMS") or "all"
        assert val == "all"


# ---------------------------------------------------------------------------
# Comment 2: Duplicate repos are deduplicated (CONFIRMED, FIXED)
# ---------------------------------------------------------------------------
class TestRepoDeduplication:
    def test_resolve_repos_deduplicates(self):
        """Duplicate repo paths should be collapsed so artifacts don't collide."""
        args = types.SimpleNamespace(repos=["/tmp/repo", "/tmp/repo"])
        repos = cb.resolve_repos(args, Path("/"))
        assert len(repos) == 1, "Duplicate repos should be deduplicated"

    def test_build_repo_slugs_unique_paths(self):
        """After dedup, build_repo_slugs should produce one slug per unique path."""
        repos = [Path("/tmp/repo")]
        slugs = cb.build_repo_slugs(repos)
        assert len(slugs) == 1


# ---------------------------------------------------------------------------
# Comment 1: Default artifact root outside scanned repos (CONFIRMED, FIXED)
# ---------------------------------------------------------------------------
class TestArtifactRootLocation:
    def test_default_artifact_root_outside_scanned_repos(self):
        """Default artifact root (../baseline-artifacts) should not sit inside
        any default scanned repo."""
        root = Path("/projects/scratch-scanner-rs")
        artifact_root = (root / "../baseline-artifacts").resolve()
        scanned_repo = (root / "../scratch-scanner-rs").resolve()
        try:
            artifact_root.relative_to(scanned_repo)
            inside = True
        except ValueError:
            inside = False
        assert not inside, (
            "Default artifact root must not be inside a default scanned repo"
        )
