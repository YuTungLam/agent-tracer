"""Prepare run-level evidence for tables without treating repeats as new tasks.

This module reads saved JSON only. Missing measurements remain ``None``; in
particular, absent recording metadata does not imply recording was disabled.
"""

import csv
import json
import math
from pathlib import Path

FIELDS = (
    "run_id",
    "model",
    "benchmark_version",
    "suite",
    "task_ids",
    "task_count",
    "evaluated_tasks",
    "successful_tasks",
    "status",
    "model_requests",
    "proposed_tool_calls",
    "tool_errors",
    "input_tokens",
    "output_tokens",
    "elapsed_seconds",
    "recording_enabled",
    "recording_complete",
    "event_count",
    "tool_output_exposures",
)


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _duration(value: object) -> float | int | None:
    return value if type(value) in (float, int) and math.isfinite(value) and value >= 0 else None


def _boolean(value: object) -> bool | None:
    return value if type(value) is bool else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _read_object(path: Path) -> tuple[dict | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"{path.name}: {type(exc).__name__}"
    if not isinstance(value, dict):
        return None, f"{path.name}: expected a JSON object"
    return value, None


def _sum_tasks(tasks: list[dict], field: str) -> int | None:
    values = [_count(task.get(field)) for task in tasks]
    return sum(values) if values and all(value is not None for value in values) else None


def _recording_enabled(summary: dict, manifest: dict) -> bool | None:
    recording = _mapping(summary.get("recording"))
    # An explicitly null measurement is unknown, not an invitation to guess.
    if "enabled" in recording:
        return _boolean(recording["enabled"])
    event_recording = _mapping(manifest.get("event_recording"))
    if "enabled" in event_recording:
        return _boolean(event_recording["enabled"])
    return _boolean(_mapping(manifest.get("config")).get("record_events"))


def _row(run_id: str, summary: dict, manifest: dict) -> tuple[dict, set[tuple[str, str, str]]]:
    config = _mapping(manifest.get("config"))
    usage = _mapping(summary.get("usage"))
    recording = _mapping(summary.get("recording"))
    audit = _mapping(recording.get("audit"))
    raw_tasks = summary.get("tasks")
    tasks = raw_tasks if isinstance(raw_tasks, list) and all(isinstance(t, dict) for t in raw_tasks) else []
    configured_tasks = config.get("user_tasks")
    configured_tasks = (
        configured_tasks
        if isinstance(configured_tasks, list) and all(_text(t) is not None for t in configured_tasks)
        else None
    )
    evaluated = [task for task in tasks if task.get("status") == "evaluated"]
    evaluated_count = _count(summary.get("evaluable_task_count"))
    if evaluated_count is None and tasks and all(_text(task.get("status")) for task in tasks):
        evaluated_count = len(evaluated)
    success_count = _count(summary.get("task_success_count"))
    if success_count is None and tasks and all(_text(task.get("status")) for task in tasks):
        utilities = [_boolean(task.get("utility")) for task in evaluated]
        if all(utility is not None for utility in utilities):
            success_count = sum(utilities)
    task_count = _count(summary.get("task_count"))
    if task_count is None and configured_tasks is not None:
        task_count = len(configured_tasks)
    benchmark_version = _text(config.get("benchmark_version"))
    suite = _text(config.get("suite"))
    identities = {
        (benchmark_version, suite, task["task"])
        for task in evaluated
        if benchmark_version is not None and suite is not None and _text(task.get("task")) is not None
    }
    return {
        "run_id": run_id,
        "model": _text(config.get("model")),
        "benchmark_version": benchmark_version,
        "suite": suite,
        "task_ids": ",".join(configured_tasks) if configured_tasks is not None else None,
        "task_count": task_count,
        "evaluated_tasks": evaluated_count,
        "successful_tasks": success_count,
        "status": _text(summary.get("status")),
        "model_requests": _count(usage.get("request_count")),
        "proposed_tool_calls": _sum_tasks(tasks, "proposed_tool_calls"),
        "tool_errors": _sum_tasks(tasks, "tool_errors"),
        "input_tokens": _count(usage.get("prompt_tokens")),
        "output_tokens": _count(usage.get("completion_tokens")),
        "elapsed_seconds": _duration(summary.get("elapsed_seconds")),
        "recording_enabled": _recording_enabled(summary, manifest),
        "recording_complete": _boolean(recording.get("complete")),
        "event_count": _count(recording.get("event_count")),
        "tool_output_exposures": _count(audit.get("tool_output_exposures")),
    }, identities


def collect_runs(runs_dir: Path) -> dict:
    """Collect direct child runs with summaries, including failed real runs.

    Inventory records every candidate's inclusion decision. Eligibility requires
    both saved records to affirm the real Groq mode and the manifest to declare
    explicitly that neither an attack nor a defense was configured. Unique task
    count uses evaluated task identities, independent of model or repeated run.
    """
    rows = []
    inventory = []
    identities = set()
    for directory in sorted(runs_dir.iterdir()):
        if not directory.is_dir() or not (directory / "summary.json").exists():
            continue
        summary, summary_error = _read_object(directory / "summary.json")
        manifest, manifest_error = _read_object(directory / "manifest.json")
        errors = [error for error in (summary_error, manifest_error) if error]
        if not errors:
            if summary.get("real_llm") is not True or manifest.get("real_llm") is not True:
                errors.append("real_llm must be true in both summary and manifest")
            if summary.get("mode") != "live-groq" or manifest.get("mode") != "live-groq":
                errors.append("mode must be live-groq in both summary and manifest")
            for field in ("attack", "defense"):
                if field not in manifest or manifest[field] is not None:
                    errors.append(f"manifest.{field} must be explicitly null")
            if (
                _mapping(manifest.get("config")).get("canary_enabled")
                or manifest.get("input_condition") == "canary_intervention"
            ):
                errors.append("canary intervention excluded from the passive clean baseline")
        included = not errors
        inventory.append(
            {
                "run_id": directory.name,
                "included": included,
                "reason": "; ".join(errors) if errors else "included: clean live Groq run",
            }
        )
        if included:
            row, task_identities = _row(directory.name, summary, manifest)
            rows.append(row)
            identities.update(task_identities)
    return {"rows": rows, "inventory": inventory, "unique_tasks": len(identities)}


def write_csv(path: Path, rows: list[dict]) -> None:
    """Write stable columns with empty cells for unknown measurements."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
