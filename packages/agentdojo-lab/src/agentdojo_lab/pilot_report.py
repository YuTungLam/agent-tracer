"""Read-only, schedule-based pilot summaries; missing and failed trials stay visible."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
import secrets
from collections import Counter
from importlib.resources import files
from pathlib import Path

from agentdojo_lab.html_report import _escaped_json
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.pilot import atomic_json, read_plan


def read_object(path: Path, errors: list | None = None) -> dict:
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("Expected object")
        return value
    except (OSError, ValueError) as exc:
        if errors is not None and path.exists():
            errors.append(f"{path.name}: {type(exc).__name__}")
        return {}


def number(value):
    return value if type(value) in (float, int) and math.isfinite(value) and value >= 0 else None


def event_metrics(run: Path) -> dict:
    path = run / "events.jsonl"
    if not path.is_file():
        return {
            "audit_valid": None,
            "event_count": None,
            "tools": [],
            "event_counts": {},
            "event_read_errors": [],
            "http_error_codes": [],
            "log_bytes": None,
            "batch_tool_responses": None,
            "requests_with_tool_messages": None,
            "proposal_requests_with_prior_tool_messages": None,
        }
    events, read_errors = [], []
    try:
        with path.open() as stream:
            for line in stream:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        events.append(item)
                except ValueError:
                    continue
    except (OSError, UnicodeError) as exc:
        read_errors.append(f"events.jsonl: {type(exc).__name__}")
    counts = Counter(event.get("event_type") for event in events if isinstance(event.get("event_type"), str))
    tools = set()
    errors = set()
    proposals = Counter()
    requests_with_outputs = set()
    for event in events:
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        kind = event.get("event_type")
        if kind == "TOOL_RUNTIME_STARTED" and isinstance(data.get("function"), str):
            tools.add(data["function"])
        if kind == "MODEL_RESPONSE" and type(data.get("status_code")) is int and data["status_code"] >= 400:
            errors.add(data["status_code"])
        request = event.get("model_request_id")
        if isinstance(request, str):
            if kind == "TOOL_CALL_PROPOSED":
                proposals[request] += 1
            if kind == "TOOL_OUTPUT_EXPOSED":
                requests_with_outputs.add(request)
    try:
        audit = inspect_events(path)
        valid = audit["valid"] and not read_errors
        log_bytes = path.stat().st_size
    except (OSError, UnicodeError) as exc:
        valid, log_bytes = False, None
        read_errors.append(f"events audit: {type(exc).__name__}")
    return {
        "audit_valid": valid,
        "event_count": len(events),
        "event_counts": dict(counts),
        "tools": sorted(tools),
        "http_error_codes": sorted(errors),
        "log_bytes": log_bytes,
        "event_read_errors": read_errors,
        # These structural metrics are withheld for invalid logs. Co-occurrence
        # with an exposed output is only an attribution opportunity, not a match.
        "batch_tool_responses": sum(n > 1 for n in proposals.values()) if valid else None,
        "requests_with_tool_messages": len(requests_with_outputs) if valid else None,
        "proposal_requests_with_prior_tool_messages": len(set(proposals) & requests_with_outputs)
        if valid
        else None,
    }


def collect_pilot(batch: Path) -> dict:
    batch = batch.expanduser().resolve()
    plan = read_plan(batch)
    specs = {task["id"]: task for task in plan["tasks"]}
    rows = []
    hashes = {}
    for entry in plan["schedule"]:
        trial = entry["id"]
        run = batch / "runs" / trial
        job = batch / "jobs" / trial
        for directory in (run, job):
            if not directory.resolve().is_relative_to(batch):
                raise ValueError("Pilot records must remain inside the batch directory")
        for path in (
            run / "summary.json",
            run / "manifest.json",
            run / "events.jsonl",
            job / "execution.json",
        ):
            if not path.resolve().is_relative_to(batch):
                raise ValueError("Pilot source file resolves outside the batch")
        read_errors = []
        summary = read_object(run / "summary.json", read_errors)
        manifest = read_object(run / "manifest.json", read_errors)
        execution = read_object(job / "execution.json", read_errors)
        tasks = summary.get("tasks", [])
        if not isinstance(tasks, list):
            tasks = []
            read_errors.append("summary.json: invalid tasks")
        task = next((t for t in tasks if isinstance(t, dict) and t.get("task") == entry["task_id"]), {})
        started = job.exists()
        status = "pending" if not started else "unfinished"
        if execution:
            status = (
                task.get("status", "error")
                if execution.get("status") == "finished"
                else execution.get("status", "error")
            )
        elif summary:
            status = task.get("status", "error")
        eligible = (
            manifest.get("real_llm") is True
            and manifest.get("mode") == "live-groq"
            and summary.get("real_llm") is True
            and summary.get("mode") == "live-groq"
            and "attack" in manifest
            and manifest["attack"] is None
            and "defense" in manifest
            and manifest["defense"] is None
            and manifest.get("config") == {**plan["run_config"], "user_tasks": [entry["task_id"]]}
        )
        if summary and not eligible:
            status = "ineligible"
        utility = task.get("utility") if status == "evaluated" and eligible else None
        utility = utility if type(utility) is bool else None
        recording = summary.get("recording", {})
        if not isinstance(recording, dict):
            recording = {}
            read_errors.append("summary.json: invalid recording")
        metrics = event_metrics(run)
        complete = recording.get("complete")
        complete = (complete is True and metrics["audit_valid"] is True) if type(complete) is bool else None
        usage = summary.get("usage", {})
        if not isinstance(usage, dict):
            usage = {}
            read_errors.append("summary.json: invalid usage")
        row = {
            "trial_id": trial,
            "task_id": entry["task_id"],
            "repeat": entry["repeat"],
            "label": specs[entry["task_id"]]["label"],
            "area": specs[entry["task_id"]]["area"],
            "started": started,
            "eligible": eligible,
            "status": status,
            "run_status": summary.get("status"),
            "utility": utility,
            "recording_complete": complete,
            "model_requests": number(usage.get("request_count")),
            "input_tokens": number(usage.get("prompt_tokens")),
            "output_tokens": number(usage.get("completion_tokens")),
            "pacing_wait_seconds": number(usage.get("pacing_wait_seconds")),
            "elapsed_seconds": number(summary.get("elapsed_seconds")),
            "process_wall_seconds": number(execution.get("wall_seconds")),
            "exit_code": execution.get("exit_code"),
            "tool_errors_final_native_history": number(task.get("tool_errors")),
            "read_errors": read_errors,
            "report": f"runs/{trial}/report.html" if (run / "report.html").is_file() else None,
            **metrics,
        }
        rows.append(row)
        for root in (run, job):
            if root.is_dir():
                for path in sorted(root.rglob("*")):
                    if path.is_file() and path.suffix in (".json", ".jsonl"):
                        if not path.resolve().is_relative_to(batch):
                            raise ValueError("Pilot source file resolves outside the batch")
                        try:
                            hashes[str(path.relative_to(batch))] = hashlib.sha256(
                                path.read_bytes()
                            ).hexdigest()
                        except OSError as exc:
                            read_errors.append(f"source hash: {type(exc).__name__}")
    started_rows = [row for row in rows if row["started"]]
    evaluated = [row for row in rows if row["status"] == "evaluated" and row["utility"] is not None]
    totals = {
        "planned_trials": len(rows),
        "started_trials": len(started_rows),
        "finished_trials": sum(
            row["started"] and row["status"] not in {"pending", "unfinished"} for row in rows
        ),
        "distinct_planned_tasks": len(specs),
        "distinct_started_tasks": len({row["task_id"] for row in started_rows}),
        "evaluated_trials": len(evaluated),
        "passed_trials": sum(row["utility"] is True for row in evaluated),
        "failed_trials": sum(row["utility"] is False for row in evaluated),
        "unscorable_trials": sum(
            row["started"] and row["status"] != "unfinished" and row["utility"] is None for row in rows
        ),
        "complete_recordings": sum(
            row["eligible"] and row["recording_complete"] is True for row in started_rows
        ),
        "pending_trials": sum(row["status"] == "pending" for row in rows),
        "observed_tools": sorted({tool for row in rows if row["eligible"] for tool in row["tools"]}),
    }
    coverage = []
    for task in plan["tasks"]:
        task_rows = [row for row in rows if row["task_id"] == task["id"]]
        observed = sorted({tool for row in task_rows if row["eligible"] for tool in row["tools"]})
        coverage.append(
            {
                **task,
                "started": sum(row["started"] for row in task_rows),
                "evaluated": sum(row["utility"] is not None for row in task_rows),
                "passed": sum(row["utility"] is True for row in task_rows),
                "complete": sum(row["recording_complete"] is True for row in task_rows),
                "observed_tools": observed,
                "expected_tools_not_observed": sorted(set(task["expected_tools"]) - set(observed)),
            }
        )
    return {
        "schema_version": 1,
        "plan": plan,
        "totals": totals,
        "rows": rows,
        "coverage": coverage,
        "source_hashes": hashes,
    }


def english_pilot_view(data: dict) -> dict:
    """Translate only known descriptive metadata in a copy of a frozen pilot.

    Measurements, prompts, event records and source hashes remain unchanged.
    The embedded payload explicitly identifies its translated presentation.
    """
    mapping = json.loads(files("agentdojo_lab").joinpath("localization/pilot_metadata_en.json").read_text())
    view = copy.deepcopy(data)
    translated = []
    for prefix, rows in (
        ("/plan/tasks", view["plan"]["tasks"]),
        ("/rows", view["rows"]),
        ("/coverage", view["coverage"]),
    ):
        for index, row in enumerate(rows):
            for key in ("label", "area", "rationale"):
                if isinstance(row.get(key), str) and row[key] in mapping:
                    row[key] = mapping[row[key]]
                    translated.append(f"{prefix}/{index}/{key}")
    view["presentation"] = {
        "language": "en",
        "translated_fields": translated,
        "source_records_changed": False,
        "note": "English rendering of descriptive task metadata. Source hashes refer to the original files.",
    }
    return view


def render_pilot_html(data: dict) -> str:
    template = files("agentdojo_lab").joinpath("templates/pilot_report.html").read_text()
    return template.replace("@@NONCE@@", secrets.token_urlsafe(24)).replace(
        "@@RECORD@@", _escaped_json(english_pilot_view(data))
    )


def export_pilot_report(batch: Path) -> dict:
    """Overwrite derived reports only; never change plan, execution or raw runs."""
    batch = batch.expanduser().resolve()
    data = collect_pilot(batch)
    atomic_json(batch / "batch-summary.json", data)
    with (batch / "trials.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(data["rows"][0]))
        writer.writeheader()
        for row in data["rows"]:
            writer.writerow(
                {
                    key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
                    for key, value in row.items()
                }
            )
    with (batch / "coverage.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(data["coverage"][0]))
        writer.writeheader()
        for row in data["coverage"]:
            writer.writerow(
                {
                    key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
                    for key, value in row.items()
                }
            )
    html = render_pilot_html(data)
    temporary = batch / "index.html.tmp"
    temporary.write_text(html, encoding="utf-8")
    temporary.replace(batch / "index.html")
    return data
