"""Unit tests for sustained_green_gate.py policy evaluation."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sustained_green_gate as gate


def make_run(
    run_id: int,
    *,
    created_at: str,
    conclusion: str = "success",
    run_number: int | None = None,
) -> dict[str, object]:
    return {
        "id": run_id,
        "run_number": run_number if run_number is not None else run_id,
        "created_at": created_at,
        "conclusion": conclusion,
        "html_url": f"https://example.invalid/{run_id}",
    }


def make_jobs(*, parity: str = "success", clippy: str = "success") -> list[dict[str, str]]:
    return [
        {"name": "Execution Mode Parity", "conclusion": parity},
        {"name": "Clippy", "conclusion": clippy},
    ]


def test_evaluate_policy_passes_when_consecutive_and_day_span_met() -> None:
    runs = [
        make_run(301, created_at="2026-02-28T12:00:00Z"),
        make_run(300, created_at="2026-02-27T12:00:00Z"),
        make_run(299, created_at="2026-02-25T12:00:00Z"),
    ]
    jobs_by_run = {
        301: make_jobs(),
        300: make_jobs(),
        299: make_jobs(),
    }

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=3,
        min_day_span=2.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is True
    assert summary["consecutive_green_runs"] == 3
    assert summary["consecutive_day_span"] >= 3.0
    assert summary["blocking_run_id"] is None


def test_evaluate_policy_stops_at_first_non_green_run() -> None:
    runs = [
        make_run(401, created_at="2026-02-28T12:00:00Z"),
        make_run(400, created_at="2026-02-27T12:00:00Z", conclusion="failure"),
        make_run(399, created_at="2026-02-26T12:00:00Z"),
    ]
    jobs_by_run = {
        401: make_jobs(),
        400: make_jobs(),
        399: make_jobs(),
    }

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=2,
        min_day_span=1.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is False
    assert summary["consecutive_green_runs"] == 1
    assert summary["blocking_run_id"] == 400
    assert summary["blocking_reason"]["workflow_conclusion"] == "failure"


def test_evaluate_policy_fails_when_required_job_is_missing_or_failed() -> None:
    runs = [make_run(501, created_at="2026-02-28T12:00:00Z")]
    jobs_by_run = {
        501: [
            {"name": "Execution Mode Parity", "conclusion": "success"},
            {"name": "Clippy", "conclusion": "failure"},
        ]
    }

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy", "Test"],
        min_consecutive=1,
        min_day_span=0.0,
    )

    run = report["runs"][0]
    assert run["passes_policy"] is False
    assert "Clippy" in run["failed_required_jobs"]
    assert "Test" in run["missing_required_jobs"]


def test_evaluate_policy_empty_runs_list() -> None:
    report = gate.evaluate_policy(
        runs=[],
        jobs_by_run_id={},
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=1,
        min_day_span=0.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is False
    assert summary["consecutive_green_runs"] == 0
    assert summary["consecutive_day_span"] == 0.0
    assert summary["evaluated_runs"] == 0
    assert summary["blocking_run_id"] is None


def test_evaluate_policy_single_green_run_day_span_zero() -> None:
    runs = [make_run(601, created_at="2026-02-28T12:00:00Z")]
    jobs_by_run = {601: make_jobs()}

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=1,
        min_day_span=0.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is True
    assert summary["consecutive_green_runs"] == 1
    assert summary["consecutive_day_span"] == 0.0


def test_evaluate_policy_single_run_fails_when_day_span_required() -> None:
    runs = [make_run(701, created_at="2026-02-28T12:00:00Z")]
    jobs_by_run = {701: make_jobs()}

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=1,
        min_day_span=1.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is False
    assert summary["consecutive_green_runs"] == 1
    assert summary["consecutive_day_span"] == 0.0


def test_evaluate_policy_enough_runs_but_insufficient_day_span() -> None:
    # 3 consecutive green runs but all within the same hour.
    runs = [
        make_run(803, created_at="2026-02-28T12:30:00Z"),
        make_run(802, created_at="2026-02-28T12:15:00Z"),
        make_run(801, created_at="2026-02-28T12:00:00Z"),
    ]
    jobs_by_run = {803: make_jobs(), 802: make_jobs(), 801: make_jobs()}

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=3,
        min_day_span=1.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is False
    assert summary["consecutive_green_runs"] == 3
    assert summary["consecutive_day_span"] < 1.0


def test_evaluate_policy_enough_day_span_but_insufficient_consecutive() -> None:
    # 2 green runs over 5 days, but policy requires 3 consecutive.
    runs = [
        make_run(902, created_at="2026-02-28T12:00:00Z"),
        make_run(901, created_at="2026-02-23T12:00:00Z"),
    ]
    jobs_by_run = {902: make_jobs(), 901: make_jobs()}

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=3,
        min_day_span=3.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is False
    assert summary["consecutive_green_runs"] == 2
    assert summary["consecutive_day_span"] == 5.0


def test_evaluate_policy_exact_boundary_consecutive_and_day_span() -> None:
    # Exactly min_consecutive=2 and day_span exactly 1.0 — should pass (>=).
    runs = [
        make_run(1002, created_at="2026-02-28T12:00:00Z"),
        make_run(1001, created_at="2026-02-27T12:00:00Z"),
    ]
    jobs_by_run = {1002: make_jobs(), 1001: make_jobs()}

    report = gate.evaluate_policy(
        runs=runs,
        jobs_by_run_id=jobs_by_run,
        required_jobs=["Execution Mode Parity", "Clippy"],
        min_consecutive=2,
        min_day_span=1.0,
    )

    summary = report["summary"]
    assert summary["gate_pass"] is True
    assert summary["consecutive_green_runs"] == 2
    assert summary["consecutive_day_span"] == 1.0
