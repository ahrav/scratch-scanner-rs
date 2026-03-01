#!/usr/bin/env python3
"""Capture scanner-rs direct-mode baseline artifacts for migration parity."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


DEFAULT_REPOS = (
    "../linux",
    "../gossip-rs",
    "../tigerbeetle",
    "../trufflehog",
    "../gitleaks",
    "../scratch-scanner-rs",
)
MODES = ("fs", "git")
BYTES_PER_MIB = 1024 * 1024


@dataclass
class RunResult:
    repo_path: Path
    repo_slug: str
    mode: str
    exit_code: int
    wall_time_s: float
    bytes_scanned: int
    throughput_mib_s: float
    findings_count: int
    malformed_lines: int
    non_finding_lines: int
    command: str
    findings_path: Path
    stderr_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run scanner-rs direct fs+git scans and capture baseline artifacts "
            "for migration parity checks."
        )
    )
    parser.add_argument(
        "--repo",
        dest="repos",
        action="append",
        default=None,
        help=(
            "Repository path (repeatable). If omitted, uses MIGRATION_REPOS or "
            f"default matrix: {', '.join(DEFAULT_REPOS)}"
        ),
    )
    parser.add_argument(
        "--scanner-bin",
        default=os.environ.get("MIGRATION_SCANNER_BIN", "target/release/scanner-rs"),
        help="Path to scanner-rs binary (default: MIGRATION_SCANNER_BIN or target/release/scanner-rs)",
    )
    parser.add_argument(
        "--artifact-root",
        default=os.environ.get("MIGRATION_ARTIFACT_ROOT", "artifacts/baseline"),
        help="Artifact root (default: MIGRATION_ARTIFACT_ROOT or artifacts/baseline)",
    )
    parser.add_argument(
        "--decode-depth",
        type=int,
        default=int(os.environ.get("MIGRATION_DECODE_DEPTH", "2")),
        help="Value passed to --decode-depth (default: MIGRATION_DECODE_DEPTH or 2)",
    )
    parser.add_argument(
        "--transforms",
        default=os.environ.get("MIGRATION_TRANSFORMS", "all"),
        help="Value passed to --transforms (default: MIGRATION_TRANSFORMS or all)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Exit immediately on first non-zero scanner exit code",
    )
    return parser.parse_args()


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(root: Path, raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def parse_repo_env(raw: str) -> list[str]:
    # Accept comma or newline separators for convenience.
    chunks = raw.replace("\n", ",").split(",")
    return [chunk.strip() for chunk in chunks if chunk.strip()]


def resolve_repos(args: argparse.Namespace, root: Path) -> list[Path]:
    if args.repos:
        raw_repos = args.repos
    else:
        env_value = os.environ.get("MIGRATION_REPOS")
        if env_value:
            raw_repos = parse_repo_env(env_value)
        else:
            raw_repos = list(DEFAULT_REPOS)
    repos = [resolve_path(root, raw) for raw in raw_repos]
    return repos


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return slug or "repo"


def build_repo_slugs(repos: Sequence[Path]) -> dict[Path, str]:
    counts: dict[str, int] = {}
    out: dict[Path, str] = {}
    for repo in repos:
        base = slugify(repo.name or repo.as_posix())
        seen = counts.get(base, 0)
        counts[base] = seen + 1
        slug = base if seen == 0 else f"{base}-{seen + 1}"
        out[repo] = slug
    return out


def require_executable(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"scanner binary not found: {path}")
    if not os.access(path, os.X_OK):
        raise SystemExit(f"scanner binary is not executable: {path}")


def require_repo_dirs(repos: Sequence[Path]) -> None:
    missing = [str(repo) for repo in repos if not repo.is_dir()]
    if missing:
        joined = "\n".join(f"- {item}" for item in missing)
        raise SystemExit(f"repo directories not found:\n{joined}")


def run_cmd(
    cmd: Sequence[str], *, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=True,
    )


def scanner_sha256(scanner_bin: Path) -> str:
    digest = hashlib.sha256()
    with scanner_bin.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit_sha(path: Path) -> str:
    try:
        completed = run_cmd(["git", "-C", str(path), "rev-parse", "HEAD"], check=True)
        return completed.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def fs_bytes(path: Path) -> int:
    try:
        completed = run_cmd(["du", "-sk", str(path)], check=True)
        kib = int(completed.stdout.split()[0])
        return kib * 1024
    except Exception:
        # Portable fallback if du parsing differs.
        total = 0
        for root, _, files in os.walk(path):
            root_path = Path(root)
            for name in files:
                file_path = root_path / name
                try:
                    total += file_path.stat().st_size
                except OSError:
                    continue
        return total


def git_pack_bytes(path: Path) -> int:
    try:
        completed = run_cmd(["git", "-C", str(path), "count-objects", "-v"], check=True)
        for line in completed.stdout.splitlines():
            if line.startswith("size-pack:"):
                kib = int(line.split(":", 1)[1].strip())
                return kib * 1024
    except Exception:
        pass
    # Fallback to filesystem bytes when git metadata is unavailable.
    return fs_bytes(path)


def build_scan_command(
    scanner_bin: Path, repo: Path, mode: str, decode_depth: int, transforms: str
) -> list[str]:
    if mode == "fs":
        return [
            str(scanner_bin),
            "scan",
            "fs",
            f"--path={repo}",
            "--event-format=jsonl",
            f"--transforms={transforms}",
            f"--decode-depth={decode_depth}",
            "--scan-archives",
        ]
    if mode == "git":
        return [
            str(scanner_bin),
            "scan",
            "git",
            f"--repo={repo}",
            "--event-format=jsonl",
            f"--transforms={transforms}",
            f"--decode-depth={decode_depth}",
        ]
    raise ValueError(f"unsupported mode: {mode}")


def extract_findings(
    events_path: Path, findings_path: Path
) -> tuple[int, int, int, dict[str, object] | None]:
    findings: list[str] = []
    malformed_lines = 0
    non_finding_lines = 0
    summary_event: dict[str, object] | None = None

    with events_path.open("r", encoding="utf-8", errors="replace") as input_file:
        for raw_line in input_file:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue
            if not isinstance(payload, dict):
                non_finding_lines += 1
                continue
            if payload.get("type") == "summary":
                summary_event = payload
                non_finding_lines += 1
                continue
            if payload.get("type") != "finding":
                non_finding_lines += 1
                continue
            findings.append(json.dumps(payload, sort_keys=True, separators=(",", ":")))

    findings.sort()
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    with findings_path.open("w", encoding="utf-8") as output_file:
        for line in findings:
            output_file.write(line)
            output_file.write("\n")
    return len(findings), malformed_lines, non_finding_lines, summary_event


def summary_int(summary_event: dict[str, object] | None, *keys: str) -> int | None:
    if summary_event is None:
        return None
    for key in keys:
        value = summary_event.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                continue
    return None


def summary_float(summary_event: dict[str, object] | None, *keys: str) -> float | None:
    if summary_event is None:
        return None
    for key in keys:
        value = summary_event.get(key)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def format_command(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def write_perf_csv(csv_path: Path, run_timestamp: str, rows: Sequence[RunResult]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "run_timestamp_utc",
                "repo",
                "repo_slug",
                "mode",
                "exit_code",
                "wall_time_s",
                "bytes_scanned",
                "throughput_mib_s",
                "findings_count",
                "malformed_lines",
                "non_finding_lines",
                "findings_path",
                "stderr_path",
                "command",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    run_timestamp,
                    str(row.repo_path),
                    row.repo_slug,
                    row.mode,
                    row.exit_code,
                    f"{row.wall_time_s:.6f}",
                    row.bytes_scanned,
                    f"{row.throughput_mib_s:.6f}",
                    row.findings_count,
                    row.malformed_lines,
                    row.non_finding_lines,
                    str(row.findings_path),
                    str(row.stderr_path),
                    row.command,
                ]
            )


def aggregate_mode(rows: Sequence[RunResult], mode: str) -> tuple[int, float, int]:
    mode_rows = [row for row in rows if row.mode == mode]
    total_bytes = sum(row.bytes_scanned for row in mode_rows)
    total_time = sum(row.wall_time_s for row in mode_rows)
    total_findings = sum(row.findings_count for row in mode_rows)
    throughput = (total_bytes / BYTES_PER_MIB / total_time) if total_time > 0 else 0.0
    return total_bytes, throughput, total_findings


def summary_lines(
    *,
    run_timestamp_iso: str,
    invocation: str,
    scanner_bin: Path,
    scanner_hash: str,
    scanner_commit: str,
    repos: Sequence[Path],
    artifact_root: Path,
    perf_csv: Path,
    rows: Sequence[RunResult],
    decode_depth: int,
    transforms: str,
) -> list[str]:
    fs_template = format_command(
        build_scan_command(scanner_bin, Path("<repo>"), "fs", decode_depth, transforms)
    )
    git_template = format_command(
        build_scan_command(scanner_bin, Path("<repo>"), "git", decode_depth, transforms)
    )

    total_bytes = sum(row.bytes_scanned for row in rows)
    total_time = sum(row.wall_time_s for row in rows)
    total_findings = sum(row.findings_count for row in rows)
    total_throughput = (total_bytes / BYTES_PER_MIB / total_time) if total_time > 0 else 0.0

    fs_bytes_total, fs_throughput, fs_findings = aggregate_mode(rows, "fs")
    git_bytes_total, git_throughput, git_findings = aggregate_mode(rows, "git")

    lines = [
        "# Migration Baseline Summary",
        "",
        f"- Run timestamp (UTC): `{run_timestamp_iso}`",
        f"- Invocation: `{invocation}`",
        f"- Scanner binary: `{scanner_bin}`",
        f"- Scanner binary SHA256: `{scanner_hash}`",
        f"- Scanner commit SHA: `{scanner_commit}`",
        f"- Artifact root: `{artifact_root}`",
        f"- Performance CSV: `{perf_csv}`",
        f"- Findings directory: `{artifact_root / 'findings'}`",
        "",
        "## Repo Matrix",
    ]
    lines.extend(f"- `{repo}`" for repo in repos)
    lines.extend(
        [
            "",
            "## Command Templates",
            f"- FS direct: `{fs_template}`",
            f"- Git direct: `{git_template}`",
            "",
            "## Throughput Summary",
            "| scope | total bytes | aggregate MiB/s | findings |",
            "|---|---:|---:|---:|",
            f"| fs | {fs_bytes_total} | {fs_throughput:.2f} | {fs_findings} |",
            f"| git | {git_bytes_total} | {git_throughput:.2f} | {git_findings} |",
            f"| all | {total_bytes} | {total_throughput:.2f} | {total_findings} |",
            "",
            "## Run Details",
            "| repo | mode | exit | findings | wall_s | bytes | MiB/s | findings artifact |",
            "|---|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            f"{row.repo_slug} | {row.mode} | {row.exit_code} | {row.findings_count} | "
            f"{row.wall_time_s:.2f} | {row.bytes_scanned} | {row.throughput_mib_s:.2f} | "
            f"`{row.findings_path}` |"
        )
    return lines


def write_summary(path: Path, lines: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def main() -> int:
    args = parse_args()
    if args.decode_depth < 0:
        raise SystemExit("--decode-depth must be >= 0")

    root = repo_root()
    scanner_bin = resolve_path(root, args.scanner_bin)
    artifact_root = resolve_path(root, args.artifact_root)
    repos = resolve_repos(args, root)
    repo_slugs = build_repo_slugs(repos)

    require_executable(scanner_bin)
    require_repo_dirs(repos)

    run_timestamp = dt.datetime.now(dt.timezone.utc)
    run_stamp = run_timestamp.strftime("%Y%m%dT%H%M%SZ")
    run_timestamp_iso = run_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    perf_csv = artifact_root / "perf" / f"{run_stamp}.csv"
    summary_md = artifact_root / "summary.md"
    invocation = format_command(sys.argv)
    scanner_hash = scanner_sha256(scanner_bin)
    scanner_commit = git_commit_sha(scanner_bin.parent)
    if scanner_commit == "unknown":
        scanner_commit = git_commit_sha(root)

    print("==========================================")
    print(" Migration Baseline Capture (scanner-rs) ")
    print(f" Timestamp: {run_timestamp_iso}")
    print(f" Scanner:   {scanner_bin}")
    print(f" Repos:     {len(repos)}")
    print(" Modes:     fs git")
    print("==========================================")

    logs_root = artifact_root / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)

    results: list[RunResult] = []
    total_runs = len(repos) * len(MODES)
    run_index = 0

    with tempfile.TemporaryDirectory(prefix="migration-baseline-") as tmp_dir_raw:
        tmp_dir = Path(tmp_dir_raw)
        for repo in repos:
            repo_slug = repo_slugs[repo]
            for mode in MODES:
                run_index += 1
                command = build_scan_command(
                    scanner_bin, repo, mode, args.decode_depth, args.transforms
                )
                command_str = format_command(command)
                stderr_path = logs_root / repo_slug / f"{mode}.stderr.log"
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                events_path = tmp_dir / f"{repo_slug}.{mode}.events.jsonl"
                findings_path = artifact_root / "findings" / repo_slug / f"{mode}.jsonl"

                print(f"[{run_index}/{total_runs}] {repo_slug} {mode}")

                start = time.perf_counter()
                with events_path.open("wb") as events_handle, stderr_path.open("wb") as err_handle:
                    proc = subprocess.run(command, stdout=events_handle, stderr=err_handle)
                wall_time = time.perf_counter() - start

                findings_count, malformed, non_finding, summary_event = extract_findings(
                    events_path, findings_path
                )
                bytes_scanned = summary_int(summary_event, "bytes_scanned", "bytes")
                if bytes_scanned is None:
                    bytes_scanned = fs_bytes(repo) if mode == "fs" else git_pack_bytes(repo)

                throughput_mib = summary_float(summary_event, "throughput_mib_s")
                if throughput_mib is None:
                    throughput_mib = (
                        bytes_scanned / BYTES_PER_MIB / wall_time if wall_time > 0 else 0.0
                    )

                result = RunResult(
                    repo_path=repo,
                    repo_slug=repo_slug,
                    mode=mode,
                    exit_code=proc.returncode,
                    wall_time_s=wall_time,
                    bytes_scanned=bytes_scanned,
                    throughput_mib_s=throughput_mib,
                    findings_count=findings_count,
                    malformed_lines=malformed,
                    non_finding_lines=non_finding,
                    command=command_str,
                    findings_path=findings_path,
                    stderr_path=stderr_path,
                )
                results.append(result)
                print(
                    "  "
                    f"exit={result.exit_code} findings={result.findings_count} "
                    f"time={result.wall_time_s:.2f}s throughput={result.throughput_mib_s:.2f} MiB/s"
                )

                if args.fail_fast and proc.returncode != 0:
                    write_perf_csv(perf_csv, run_stamp, results)
                    write_summary(
                        summary_md,
                        summary_lines(
                            run_timestamp_iso=run_timestamp_iso,
                            invocation=invocation,
                            scanner_bin=scanner_bin,
                            scanner_hash=scanner_hash,
                            scanner_commit=scanner_commit,
                            repos=repos,
                            artifact_root=artifact_root,
                            perf_csv=perf_csv,
                            rows=results,
                            decode_depth=args.decode_depth,
                            transforms=args.transforms,
                        ),
                    )
                    print("Fail-fast enabled; exiting after first non-zero exit code.")
                    return proc.returncode

    write_perf_csv(perf_csv, run_stamp, results)
    write_summary(
        summary_md,
        summary_lines(
            run_timestamp_iso=run_timestamp_iso,
            invocation=invocation,
            scanner_bin=scanner_bin,
            scanner_hash=scanner_hash,
            scanner_commit=scanner_commit,
            repos=repos,
            artifact_root=artifact_root,
            perf_csv=perf_csv,
            rows=results,
            decode_depth=args.decode_depth,
            transforms=args.transforms,
        ),
    )

    non_zero_runs = [row for row in results if row.exit_code != 0]
    print("")
    print("==========================================")
    print(f" Baseline capture complete: {len(results)} runs")
    print(f" Perf CSV: {perf_csv}")
    print(f" Summary:  {summary_md}")
    print("==========================================")
    if non_zero_runs:
        print(f"WARNING: {len(non_zero_runs)} run(s) exited non-zero.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
