import csv
import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentdojo_lab.report_data import FIELDS, collect_runs, write_csv


@pytest.fixture
def records():
    return {
        "manifest": {
            "mode": "live-groq",
            "real_llm": True,
            "attack": None,
            "defense": None,
            "config": {
                "model": "example-model",
                "suite": "workspace",
                "benchmark_version": "v1.2.2",
                "user_tasks": ["user_task_0"],
            },
        },
        "summary": {
            "mode": "live-groq",
            "real_llm": True,
            "status": "completed",
            "tasks": [
                {
                    "task": "user_task_0",
                    "status": "evaluated",
                    "utility": True,
                    "proposed_tool_calls": 2,
                    "tool_errors": 1,
                }
            ],
            "task_count": 1,
            "evaluable_task_count": 1,
            "task_success_count": 1,
            "usage": {"request_count": 3, "prompt_tokens": 5000, "completion_tokens": 100},
            "elapsed_seconds": 2.25,
        },
    }


def save_run(root: Path, run_id: str, records: dict) -> Path:
    directory = root / run_id
    directory.mkdir(parents=True)
    for filename, value in records.items():
        (directory / f"{filename}.json").write_text(json.dumps(value))
    return directory


def test_real_runs_keep_run_metrics_and_do_not_count_repeats_as_new_tasks(tmp_path, records):
    save_run(tmp_path, "first", records)
    second = deepcopy(records)
    second["manifest"]["config"]["model"] = "another-model"
    save_run(tmp_path, "second", second)
    result = collect_runs(tmp_path)
    assert result["unique_tasks"] == 1
    assert len(result["rows"]) == 2
    assert all(item["included"] for item in result["inventory"])
    row = result["rows"][0]
    assert row["task_ids"] == "user_task_0"
    assert row["model_requests"] == 3
    assert row["input_tokens"] == 5000
    assert row["output_tokens"] == 100
    assert row["elapsed_seconds"] == 2.25
    assert row["proposed_tool_calls"] == 2
    assert row["tool_errors"] == 1
    assert row["recording_enabled"] is None


@pytest.mark.parametrize(
    ("document", "field", "value"),
    [
        ("summary", "real_llm", False),
        ("manifest", "real_llm", 1),
        ("summary", "mode", "offline-fixture"),
        ("manifest", "mode", "offline-fixture"),
        ("manifest", "attack", "something"),
        ("manifest", "defense", "something"),
    ],
)
def test_excluded_runs_are_visible_in_inventory(tmp_path, records, document, field, value):
    records[document][field] = value
    save_run(tmp_path, "excluded", records)
    result = collect_runs(tmp_path)
    assert result["rows"] == []
    assert result["unique_tasks"] == 0
    assert result["inventory"][0]["included"] is False
    assert field in result["inventory"][0]["reason"]


def test_failure_is_included_with_unknown_measurements_not_zeros(tmp_path, records):
    records["summary"] = {"mode": "live-groq", "real_llm": True, "status": "failed", "usage": {}}
    save_run(tmp_path, "failed", records)
    result = collect_runs(tmp_path)
    row = result["rows"][0]
    assert row["status"] == "failed"
    assert row["task_count"] == 1  # Known configured task count.
    assert result["unique_tasks"] == 0
    for field in (
        "evaluated_tasks",
        "successful_tasks",
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
    ):
        assert row[field] is None, field


def test_failed_tasks_do_not_enter_unique_evaluated_sample_count(tmp_path, records):
    records["summary"]["tasks"][0].update(status="error", utility=None)
    records["summary"].pop("evaluable_task_count")
    records["summary"].pop("task_success_count")
    save_run(tmp_path, "error", records)
    result = collect_runs(tmp_path)
    assert result["unique_tasks"] == 0
    assert result["rows"][0]["evaluated_tasks"] == 0
    assert result["rows"][0]["successful_tasks"] == 0


def test_unique_tasks_include_version_suite_and_id(tmp_path, records):
    save_run(tmp_path, "first", records)
    for index, (field, value) in enumerate((("suite", "travel"), ("benchmark_version", "v2"))):
        other = deepcopy(records)
        other["manifest"]["config"][field] = value
        save_run(tmp_path, f"other-{index}", other)
    result = collect_runs(tmp_path)
    assert result["unique_tasks"] == 3


def test_multitask_run_does_not_duplicate_run_usage(tmp_path, records):
    records["manifest"]["config"]["user_tasks"].append("user_task_1")
    records["summary"]["tasks"].append(
        {
            "task": "user_task_1",
            "status": "evaluated",
            "utility": False,
            "proposed_tool_calls": 4,
            "tool_errors": 0,
        }
    )
    records["summary"].update(task_count=2, evaluable_task_count=2)
    save_run(tmp_path, "batch", records)
    result = collect_runs(tmp_path)
    assert len(result["rows"]) == 1
    row = result["rows"][0]
    assert row["task_ids"] == "user_task_0,user_task_1"
    assert row["proposed_tool_calls"] == 6
    assert row["tool_errors"] == 1
    assert row["input_tokens"] == 5000
    assert row["evaluated_tasks"] == 2
    assert row["successful_tasks"] == 1
    assert result["unique_tasks"] == 2


@pytest.mark.parametrize("source", ["config", "event_recording", "summary"])
@pytest.mark.parametrize("enabled", [True, False, None])
def test_recording_metadata_is_explicit_and_null_stays_unknown(tmp_path, records, source, enabled):
    manifest = records["manifest"]
    if source == "config":
        manifest["config"]["record_events"] = enabled
    elif source == "event_recording":
        manifest["event_recording"] = {"enabled": enabled}
    else:
        records["summary"]["recording"] = {"enabled": enabled}
        manifest["config"]["record_events"] = True
    save_run(tmp_path, "run", records)
    assert collect_runs(tmp_path)["rows"][0]["recording_enabled"] is enabled


def test_recording_counts_and_completion_use_observed_summary(tmp_path, records):
    records["summary"]["recording"] = {
        "enabled": True,
        "complete": False,
        "event_count": 12,
        "audit": {"tool_output_exposures": 2},
    }
    save_run(tmp_path, "run", records)
    row = collect_runs(tmp_path)["rows"][0]
    assert row["recording_complete"] is False
    assert row["event_count"] == 12
    assert row["tool_output_exposures"] == 2


def test_partial_null_invalid_measurements_are_not_coerced(tmp_path, records):
    records["summary"]["usage"] = {"request_count": True, "prompt_tokens": None, "completion_tokens": -1}
    records["summary"]["elapsed_seconds"] = float("nan")
    records["summary"]["tasks"][0]["tool_errors"] = None
    records["summary"]["tasks"].append({"task": "user_task_1", "status": "error"})
    save_run(tmp_path, "run", records)
    row = collect_runs(tmp_path)["rows"][0]
    for field in (
        "model_requests",
        "input_tokens",
        "output_tokens",
        "elapsed_seconds",
        "proposed_tool_calls",
        "tool_errors",
    ):
        assert row[field] is None, field


def test_missing_and_invalid_json_files_are_visible(tmp_path, records):
    save_run(tmp_path, "missing-manifest", {"summary": records["summary"]})
    invalid = save_run(tmp_path, "invalid-summary", records)
    (invalid / "summary.json").write_text("{")
    save_run(tmp_path, "non-object", {"summary": [], "manifest": records["manifest"]})
    result = collect_runs(tmp_path)
    assert len(result["inventory"]) == 3
    assert all(not item["included"] for item in result["inventory"])
    assert any("FileNotFoundError" in item["reason"] for item in result["inventory"])
    assert any("JSONDecodeError" in item["reason"] for item in result["inventory"])
    assert any("expected a JSON object" in item["reason"] for item in result["inventory"])


def test_no_clean_mode_guess_and_only_direct_children_with_summary(tmp_path, records):
    records["manifest"].pop("attack")
    save_run(tmp_path, "unknown-clean-status", records)
    save_run(tmp_path / "nested", "run", records)
    save_run(tmp_path, "no-summary", {"manifest": records["manifest"]})
    result = collect_runs(tmp_path)
    assert len(result["inventory"]) == 1
    assert result["inventory"][0]["included"] is False


def test_csv_unknowns_are_empty_and_column_order_is_stable(tmp_path, records):
    save_run(tmp_path, "run", records)
    path = tmp_path / "table.csv"
    write_csv(path, collect_runs(tmp_path)["rows"])
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == FIELDS
        row = next(reader)
    assert row["recording_enabled"] == ""
    assert row["model_requests"] == "3"
    assert row["task_ids"] == "user_task_0"


def test_empty_csv_still_has_headers(tmp_path):
    path = tmp_path / "empty.csv"
    write_csv(path, [])
    assert path.read_text().strip() == ",".join(FIELDS)
