#!/usr/bin/env python3
"""Evaluate the execution-mode sustained-green policy for migration closeout."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_REQUIRED_JOBS = (
    "Execution Mode Parity",
    "Clippy",
    "Test",
    "Test (aarch64)",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check whether recent CI runs satisfy the sustained-green defaulting "
            "policy for execution-mode parity migration closeout."
        )
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help=(
            "GitHub repo in owner/name form. Defaults to GITHUB_REPOSITORY when set."
        ),
    )
    parser.add_argument(
        "--workflow",
        default="ci.yml",
        help="Workflow file name or workflow id (default: ci.yml).",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to inspect (default: main).",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        default=50,
        help="Maximum completed workflow runs to inspect (default: 50).",
    )
    parser.add_argument(
        "--required-job",
        action="append",
        dest="required_jobs",
        default=None,
        help=(
            "Required job name for each run (repeatable). Defaults to: "
            + ", ".join(DEFAULT_REQUIRED_JOBS)
        ),
    )
    parser.add_argument(
        "--min-consecutive",
        type=int,
        default=7,
        help="Minimum consecutive green runs required (default: 7).",
    )
    parser.add_argument(
        "--min-day-span",
        type=float,
        default=3.0,
        help=(
            "Minimum day span covered by consecutive green runs (default: 3.0 days)."
        ),
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub token for API requests (defaults to GITHUB_TOKEN env var).",
    )
    parser.add_argument(
        "--input-runs-json",
        type=Path,
        default=None,
        help=(
            "Optional offline runs payload JSON. Accepts either {workflow_runs:[...]} "
            "or a raw list of runs."
        ),
    )
    parser.add_argument(
        "--input-jobs-dir",
        type=Path,
        default=None,
        help=(
            "Optional offline jobs payload directory containing <run_id>.json files. "
            "Each file can be {jobs:[...]} or a raw list of jobs."
        ),
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional path to write machine-readable policy report JSON.",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=None,
        help="Optional path to write human-readable policy report markdown.",
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Exit with code 1 when sustained-green policy is not met.",
    )
    return parser.parse_args()


def ensure_utc(timestamp: str) -> dt.datetime:
    normalized = timestamp
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return dt.datetime.fromisoformat(normalized).astimezone(dt.timezone.utc)


def api_get_json(url: str, token: str | None) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "scanner-rs-sustained-green-gate",
        },
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_runs_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        runs = payload.get("workflow_runs", [])
    elif isinstance(payload, list):
        runs = payload
    else:
        raise ValueError("runs payload must be an object or list")
    return [run for run in runs if isinstance(run, dict)]


def normalize_jobs_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        jobs = payload.get("jobs", [])
    elif isinstance(payload, list):
        jobs = payload
    else:
        raise ValueError("jobs payload must be an object or list")
    return [job for job in jobs if isinstance(job, dict)]


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fetch_workflow_runs(
    *,
    repo: str,
    workflow: str,
    branch: str,
    max_runs: int,
    token: str | None,
) -> list[dict[str, Any]]:
    workflow_ref = urllib.parse.quote(workflow, safe="")
    runs: list[dict[str, Any]] = []
    page = 1
    while len(runs) < max_runs:
        per_page = min(100, max_runs - len(runs))
        query = urllib.parse.urlencode(
            {
                "branch": branch,
                "status": "completed",
                "per_page": str(per_page),
                "page": str(page),
            }
        )
        url = (
            f"https://api.github.com/repos/{repo}/actions/workflows/"
            f"{workflow_ref}/runs?{query}"
        )
        payload = api_get_json(url, token)
        page_runs = normalize_runs_payload(payload)
        runs.extend(page_runs)
        if len(page_runs) < per_page:
            break
        page += 1
    return runs[:max_runs]


def fetch_jobs_for_run(
    *,
    repo: str,
    run_id: int,
    token: str | None,
) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
        url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs?{query}"
        payload = api_get_json(url, token)
        page_jobs = normalize_jobs_payload(payload)
        jobs.extend(page_jobs)
        if len(page_jobs) < 100:
            break
        page += 1
    return jobs


def load_jobs_for_run(run_id: int, jobs_dir: Path) -> list[dict[str, Any]]:
    payload = load_json_file(jobs_dir / f"{run_id}.json")
    return normalize_jobs_payload(payload)


def run_status(
    *,
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
    required_jobs: list[str],
) -> dict[str, Any]:
    workflow_conclusion = str(run.get("conclusion") or "unknown")
    job_conclusions: dict[str, str] = {}
    for job in jobs:
        name = job.get("name")
        conclusion = job.get("conclusion")
        if isinstance(name, str):
            job_conclusions[name] = str(conclusion) if conclusion is not None else "missing"

    required: dict[str, str] = {}
    missing_jobs: list[str] = []
    failed_jobs: list[str] = []
    for required_name in required_jobs:
        conclusion = job_conclusions.get(required_name)
        if conclusion is None:
            required[required_name] = "missing"
            missing_jobs.append(required_name)
            continue
        required[required_name] = conclusion
        if conclusion != "success":
            failed_jobs.append(required_name)

    run_pass = (
        workflow_conclusion == "success"
        and not missing_jobs
        and not failed_jobs
    )

    return {
        "run_id": run.get("id"),
        "run_number": run.get("run_number"),
        "created_at": run.get("created_at"),
        "html_url": run.get("html_url"),
        "workflow_conclusion": workflow_conclusion,
        "required_job_conclusions": required,
        "missing_required_jobs": missing_jobs,
        "failed_required_jobs": failed_jobs,
        "passes_policy": run_pass,
    }


def evaluate_policy(
    *,
    runs: list[dict[str, Any]],
    jobs_by_run_id: dict[int, list[dict[str, Any]]],
    required_jobs: list[str],
    min_consecutive: int,
    min_day_span: float,
) -> dict[str, Any]:
    statuses: list[dict[str, Any]] = []
    for run in runs:
        run_id_raw = run.get("id")
        if not isinstance(run_id_raw, int):
            continue
        jobs = jobs_by_run_id.get(run_id_raw, [])
        statuses.append(
            run_status(run=run, jobs=jobs, required_jobs=required_jobs)
        )

    def created_at_sort_key(status: dict[str, Any]) -> dt.datetime:
        created = status.get("created_at")
        if isinstance(created, str):
            try:
                return ensure_utc(created)
            except ValueError:
                pass
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)

    # API responses are typically newest-first; sort anyway so offline fixtures
    # and future API changes cannot silently skew consecutive-run evaluation.
    statuses.sort(key=created_at_sort_key, reverse=True)

    consecutive_green = 0
    newest_green_time: dt.datetime | None = None
    oldest_green_time: dt.datetime | None = None
    first_non_green: dict[str, Any] | None = None

    for status in statuses:
        if not status["passes_policy"]:
            first_non_green = status
            break
        created_at = status.get("created_at")
        if isinstance(created_at, str):
            ts = ensure_utc(created_at)
            if newest_green_time is None:
                newest_green_time = ts
            oldest_green_time = ts
        consecutive_green += 1

    if newest_green_time and oldest_green_time:
        day_span = (newest_green_time - oldest_green_time).total_seconds() / 86400.0
    else:
        day_span = 0.0

    gate_pass = consecutive_green >= min_consecutive and day_span >= min_day_span

    return {
        "policy": {
            "min_consecutive": min_consecutive,
            "min_day_span": min_day_span,
            "required_jobs": required_jobs,
        },
        "summary": {
            "gate_pass": gate_pass,
            "consecutive_green_runs": consecutive_green,
            "consecutive_day_span": day_span,
            "evaluated_runs": len(statuses),
            "blocking_run_id": first_non_green.get("run_id") if first_non_green else None,
            "blocking_reason": None
            if first_non_green is None
            else {
                "workflow_conclusion": first_non_green.get("workflow_conclusion"),
                "missing_required_jobs": first_non_green.get("missing_required_jobs"),
                "failed_required_jobs": first_non_green.get("failed_required_jobs"),
            },
        },
        "runs": statuses,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def markdown_report(report: dict[str, Any], source: str) -> str:
    summary = report["summary"]
    policy = report["policy"]
    lines = [
        "# Sustained-Green Policy Report",
        "",
        f"- Source: `{source}`",
        f"- Generated (UTC): `{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}`",
        f"- Gate pass: `{'yes' if summary['gate_pass'] else 'no'}`",
        f"- Consecutive green runs: `{summary['consecutive_green_runs']}`",
        f"- Consecutive day span: `{summary['consecutive_day_span']:.2f}`",
        f"- Policy min consecutive: `{policy['min_consecutive']}`",
        f"- Policy min day span: `{policy['min_day_span']:.2f}`",
        "",
        "## Required Jobs",
    ]
    lines.extend(f"- `{name}`" for name in policy["required_jobs"])
    lines.extend(
        [
            "",
            "## Recent Runs",
            "| run_id | run_number | created_at | workflow | required jobs | policy |",
            "|---:|---:|---|---|---|---|",
        ]
    )

    for status in report["runs"][:20]:
        required = status["required_job_conclusions"]
        jobs_cell = ", ".join(f"{k}:{v}" for k, v in required.items()) if required else "-"
        lines.append(
            "| "
            f"{status.get('run_id', '-')}"
            f" | {status.get('run_number', '-')}"
            f" | {status.get('created_at', '-')}"
            f" | {status.get('workflow_conclusion', '-')}"
            f" | {jobs_cell}"
            f" | {'pass' if status.get('passes_policy') else 'fail'} |"
        )

    if summary.get("blocking_run_id") is not None:
        lines.extend(
            [
                "",
                "## Blocking Run",
                f"- Run id: `{summary['blocking_run_id']}`",
                f"- Reason: `{summary['blocking_reason']}`",
            ]
        )

    return "\n".join(lines) + "\n"


def write_markdown(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def resolve_required_jobs(raw: list[str] | None) -> list[str]:
    if not raw:
        return list(DEFAULT_REQUIRED_JOBS)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in raw:
        value = item.strip()
        if value and value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def main() -> int:
    args = parse_args()
    if args.max_runs <= 0:
        raise SystemExit("--max-runs must be > 0")
    if args.min_consecutive <= 0:
        raise SystemExit("--min-consecutive must be > 0")
    if args.min_day_span < 0:
        raise SystemExit("--min-day-span must be >= 0")

    required_jobs = resolve_required_jobs(args.required_jobs)
    if not required_jobs:
        raise SystemExit("at least one --required-job is required")

    if args.input_runs_json is not None:
        runs_payload = load_json_file(args.input_runs_json)
        runs = normalize_runs_payload(runs_payload)
        source = f"offline runs: {args.input_runs_json}"
    else:
        if not args.repo:
            raise SystemExit(
                "--repo is required when --input-runs-json is not provided "
                "(or set GITHUB_REPOSITORY)"
            )
        runs = fetch_workflow_runs(
            repo=args.repo,
            workflow=args.workflow,
            branch=args.branch,
            max_runs=args.max_runs,
            token=args.github_token,
        )
        source = f"github api: {args.repo}/{args.workflow}@{args.branch}"

    jobs_by_run_id: dict[int, list[dict[str, Any]]] = {}
    for run in runs:
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue
        if args.input_jobs_dir is not None:
            jobs_by_run_id[run_id] = load_jobs_for_run(run_id, args.input_jobs_dir)
        else:
            if not args.repo:
                raise SystemExit(
                    "--repo is required when --input-jobs-dir is not provided "
                    "(or set GITHUB_REPOSITORY)"
                )
            jobs_by_run_id[run_id] = fetch_jobs_for_run(
                repo=args.repo,
                run_id=run_id,
                token=args.github_token,
            )

    report = evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run_id,
        required_jobs=required_jobs,
        min_consecutive=args.min_consecutive,
        min_day_span=args.min_day_span,
    )
    report["source"] = source
    report["generated_at_utc"] = dt.datetime.now(dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    if args.output_json is not None:
        write_json(args.output_json, report)
    if args.output_markdown is not None:
        write_markdown(args.output_markdown, markdown_report(report, source))

    summary = report["summary"]
    gate_status = "PASS" if summary["gate_pass"] else "FAIL"
    print(
        "sustained-green gate "
        f"{gate_status}: consecutive={summary['consecutive_green_runs']} "
        f"day_span={summary['consecutive_day_span']:.2f} "
        f"(need consecutive>={args.min_consecutive}, day_span>={args.min_day_span:.2f})"
    )
    if summary["blocking_run_id"] is not None:
        print(f"first blocking run id: {summary['blocking_run_id']}")

    if args.require_pass and not summary["gate_pass"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as error:
        print(
            f"GitHub API request failed ({error.code}): {error.reason}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    except urllib.error.URLError as error:
        print(f"GitHub API request failed: {error.reason}", file=sys.stderr)
        raise SystemExit(2)
