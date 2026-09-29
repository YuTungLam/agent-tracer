"""Integrity and denominator tests for the offline closeout export."""

import hashlib
import json
from pathlib import Path

import pytest

from agentdojo_lab import closeout


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, allow_nan=False) + "\n")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ratio(values):
    known = [v for v in values if v is not None]
    return {
        "numerator": sum(known),
        "denominator": len(known),
        "unknown_count": len(values) - len(known),
        "rate": sum(known) / len(known) if known else None,
    }


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "evidence.md").write_text("Recorded evidence.\n")
    progress = {
        "milestones": [{"id": str(i), "status": "accepted" if i < 7 else "not_accepted"} for i in range(8)],
        "efficacy": {"independent_attribution_accuracy": None},
    }
    write(root / "progress.json", progress)
    experiments = []
    for i in range(3):
        batch = root / "runs" / f"batch{i}"
        rows = []
        for condition in ["clean", "injected"]:
            run = batch / "runs" / condition
            run.mkdir(parents=True)
            write(run / "summary.json", {"saved": condition})
            rows.append(
                {
                    "trial_id": condition,
                    "run_path": str(run),
                    "condition": condition,
                    "input_condition": "passive",
                    "started": True,
                    "evaluation_valid": True,
                    "evaluation_completed": True,
                    "execution_status": "completed",
                    "process_status": "completed",
                    "utility": True,
                    "attack_goal_success": False if condition == "injected" else None,
                    "payload_exposed": True if condition == "injected" else None,
                }
            )
        write(
            batch / "plan.json",
            {
                "schedule": [
                    {
                        "trial_id": row["trial_id"],
                        "condition": row["condition"],
                        "input_condition": row["input_condition"],
                    }
                    for row in rows
                ]
            },
        )
        snapshots = {str(p.relative_to(batch)): digest(p) for p in batch.rglob("*") if p.is_file()}
        report = root / "reports" / f"batch{i}"
        report.mkdir(parents=True)
        (report / "index.html").write_text("<html lang='en'>Original report</html>")
        conditions = [
            {
                "condition": row["condition"],
                "metrics": {
                    key: ratio([row[key]])
                    if key == "utility" or row["condition"] == "injected"
                    else ratio([])
                    for key in ("utility", "attack_goal_success", "payload_exposed")
                },
            }
            for row in rows
        ]
        summary = {
            "schema_version": 1,
            "batch_path": str(batch),
            "trials": rows,
            "counts": {"planned": 2},
            "conditions": conditions,
            "attribution_accuracy": {"precision": None, "recall": None, "f1": None},
            "source_files_unchanged": True,
            "source_hashes_before": snapshots,
            "source_hashes_after": snapshots,
            "primary_usage": {"request_count": {"known_sum": 6}},
            "primary_usage_scope": "Reported usage only",
            "timing": {"run_elapsed_seconds": {"known_sum": 5}},
            "timing_scope": "Pacing included; initial loading excluded",
        }
        write(report / "summary.json", summary)
        write(report / "quality.json", {"passed": True})
        experiments.append(
            {
                "id": f"experiment{i}",
                "title": f"Study {i}",
                "summary": str((report / "summary.json").relative_to(root)),
                "report": str((report / "index.html").relative_to(root)),
                "arm_key": "conditions",
                "group_label": "Separate assigned case",
                "validation": str((report / "quality.json").relative_to(root)),
            }
        )
    config = {
        "schema_version": 1,
        "title": "Evidence closeout",
        "verdict": "Engineering complete; independent accuracy unavailable.",
        "closure_status": "completed_with_evidence_limits",
        "accepted_gates": 7,
        "total_gates": 8,
        "progress_path": "progress.json",
        "paper": {
            "title": "Paper",
            "url": "https://example.org/paper",
            "verified_at": "2026-09-09",
            "reading_scope": "Method and evaluation",
        },
        "components": [
            {
                "id": "component",
                "title": "Observer",
                "assessment": "verified_in_scope",
                "paper_anchor": "#S4",
                "method_reference": "Prefix-only observation",
                "local_result": "Recorded before actions",
                "limits": "Not causal accuracy",
                "evidence": ["evidence.md"],
            }
        ],
        "experiments": experiments,
        "findings": [
            {
                "id": "finding",
                "title": "No independent labels",
                "status": "unvalidated",
                "observation": "Accuracy is null",
                "limit": "No maliciousness conclusion",
                "evidence": ["evidence.md"],
            }
        ],
        "fallacy_checks": [
            {"id": str(i), "title": f"Check {i}", "assessment": "checked", "reason": "No overclaim"}
            for i in range(11)
        ],
        "limitations": ["No pooled rates"],
    }
    path = write(root / "configs" / "closeout.json", config)
    return root, path, config


def run(fixture, output="reports/closeout"):
    root, path, _ = fixture
    return closeout.build_closeout(path, root / output, root)


def mutate_summary(fixture, index, action):
    root, _, config = fixture
    path = root / config["experiments"][index]["summary"]
    value = json.loads(path.read_text())
    action(value)
    write(path, value)


def test_exports_three_separate_studies_and_verifiable_snapshots(fixture):
    root, path, _ = fixture
    before = digest(root / "evidence.md")
    result = run(fixture)
    output = Path(result["output"])
    data = json.loads((output / "closeout.json").read_text())
    assert data["counts"]["unique_batches"] == 3
    assert data["counts"]["planned_slots"] == 6
    assert data["gate_progress"] == {"accepted": 7, "total": 8, "independent_accuracy": None}
    assert "metrics" not in data
    for exp in data["experiments"]:
        assert exp["arms"][0]["metrics"]["attack_goal_success"]["applicable"] is False
        assert exp["arms"][1]["metrics"]["attack_goal_success"]["denominator"] == 1
        assert exp["timing_scope"] == "Pacing included; initial loading excluded"
    assert (output / "config.json").read_bytes() == path.read_bytes()
    assert digest(root / "evidence.md") == before
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["source_hashes_before"] == manifest["source_hashes_after"]
    assert all(digest(output / name) == sha for name, sha in manifest["output_hashes"].items())
    page = (output / "index.html").read_text()
    assert "<script" not in page
    assert "N/A" in page
    assert "<summary>Evidence and limits</summary>" in page
    assert "<details><summary>Eleven claim checks</summary>" in page
    assert 'href="https://example.org/paper#S4"' in page
    for name in ("claims.jsonl", "components.csv", "outcomes.csv", "closeout.md"):
        assert f'href="{name}"' in page


def test_retains_unstarted_slot_as_unknown_without_turning_it_into_failure(fixture):
    def action(summary):
        row = summary["trials"][1]
        row.update(
            started=False,
            evaluation_valid=False,
            evaluation_completed=False,
            execution_status="unstarted",
            process_status=None,
            utility=None,
            attack_goal_success=None,
            payload_exposed=None,
        )
        summary["conditions"][1]["metrics"] = {
            key: ratio([None]) for key in ("utility", "attack_goal_success", "payload_exposed")
        }

    mutate_summary(fixture, 0, action)
    result = run(fixture)
    data = json.loads((Path(result["output"]) / "closeout.json").read_text())
    exp = data["experiments"][0]
    assert exp["planned_slots"] == 2
    assert exp["raw_status_counts"]["execution_status"]["unstarted"] == 1
    assert exp["arms"][1]["metrics"]["utility"] == {
        "applicable": True,
        "numerator": 0,
        "denominator": 0,
        "unknown_count": 1,
        "rate": None,
    }


def test_duplicate_batch_presentation_version_is_rejected(fixture):
    root, path, config = fixture
    config["experiments"][1]["summary"] = config["experiments"][0]["summary"]
    write(path, config)
    with pytest.raises(ValueError, match="Duplicate"):
        run(fixture)
    assert not (root / "reports/closeout").exists()


def test_duplicate_or_foreign_run_is_rejected(fixture):
    mutate_summary(fixture, 0, lambda d: d["trials"][1].update(run_path=d["trials"][0]["run_path"]))
    with pytest.raises(ValueError, match="Duplicate or foreign"):
        run(fixture)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["source_hashes_after"].update({"plan.json": "0" * 64}),
        lambda d: d["source_hashes_before"].update({"plan.json": "0" * 64}),
    ],
)
def test_mutated_analysis_snapshot_rejected(fixture, change):
    mutate_summary(fixture, 0, change)
    with pytest.raises(ValueError, match="snapshots must match"):
        run(fixture)


def test_current_batch_evidence_must_match_saved_snapshot(fixture):
    root, _, _ = fixture
    (root / "runs/batch0/runs/clean/summary.json").write_text("mutated")
    with pytest.raises(ValueError, match="snapshot does not match"):
        run(fixture)


def test_evidence_mutation_during_export_cannot_create_verified_manifest(fixture, monkeypatch):
    root, _, _ = fixture
    original = closeout._html

    def mutate(*args):
        (root / "evidence.md").write_text("changed during generation")
        return original(*args)

    monkeypatch.setattr(closeout, "_html", mutate)
    with pytest.raises(ValueError, match="mutated during generation"):
        run(fixture)
    assert not (root / "reports/closeout/manifest.json").exists()


@pytest.mark.parametrize(
    "metric",
    [
        {"numerator": 2, "denominator": 1, "unknown_count": 0, "rate": 2},
        {"numerator": True, "denominator": 1, "unknown_count": 0, "rate": 1},
        {"numerator": 0, "denominator": 0, "unknown_count": 0, "rate": 0},
        {"numerator": 0, "denominator": 1, "unknown_count": 0, "rate": None},
        {"numerator": 0, "denominator": 1, "unknown_count": 0, "rate": 0.5},
    ],
)
def test_invalid_saved_ratios_rejected(fixture, metric):
    mutate_summary(fixture, 0, lambda d: d["conditions"][0]["metrics"].update(utility=metric))
    with pytest.raises(ValueError, match="ratio"):
        run(fixture)


def test_valid_but_inconsistent_aggregate_ratio_rejected(fixture):
    mutate_summary(fixture, 0, lambda d: d["conditions"][0]["metrics"].update(utility=ratio([False])))
    with pytest.raises(ValueError, match="differs from its trial"):
        run(fixture)


@pytest.mark.parametrize(
    "field,value", [("utility", 1), ("attack_goal_success", "false"), ("payload_exposed", 0)]
)
def test_non_boolean_outcomes_rejected(fixture, field, value):
    mutate_summary(fixture, 0, lambda d: d["trials"][1].update({field: value}))
    with pytest.raises(ValueError, match="booleans or null"):
        run(fixture)


def test_unknown_evaluation_cannot_supply_known_success(fixture):
    mutate_summary(fixture, 0, lambda d: d["trials"][1].update(evaluation_valid=False))
    with pytest.raises(ValueError, match="completed valid"):
        run(fixture)


def test_accuracy_cannot_be_invented(fixture):
    mutate_summary(fixture, 0, lambda d: d["attribution_accuracy"].update(precision=1.0))
    with pytest.raises(ValueError, match="accuracy must remain null"):
        run(fixture)


def test_progress_gate_count_must_match(fixture):
    root, _, _ = fixture
    path = root / "progress.json"
    progress = json.loads(path.read_text())
    progress["milestones"][-1]["status"] = "accepted"
    write(path, progress)
    with pytest.raises(ValueError, match="Progress snapshot"):
        run(fixture)


@pytest.mark.parametrize("name", ["missing.md", "../escape.md", "/outside.md"])
def test_missing_or_escaping_reference_rejected(fixture, name):
    _, path, config = fixture
    config["findings"][0]["evidence"] = [name]
    write(path, config)
    with pytest.raises(ValueError):
        run(fixture)


def test_safe_escaping_and_relative_links(fixture):
    _, path, config = fixture
    marker = '<img src=x onerror="alert(1)">'
    config["title"] = marker
    config["findings"][0]["observation"] = marker
    write(path, config)
    result = run(fixture)
    text = (Path(result["output"]) / "index.html").read_text()
    assert marker not in text and "&lt;img" in text
    assert 'href="../../evidence.md"' in text


@pytest.mark.parametrize("output", ["runs/batch0/new", "runs", "reports/batch0/new", "reports", "configs"])
def test_fresh_path_and_source_overlap_protected(fixture, output):
    with pytest.raises(ValueError, match="fresh|overlaps"):
        run(fixture, output)


def test_duplicate_json_keys_rejected(fixture):
    _, path, _ = fixture
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        run(fixture)


def test_symlink_evidence_rejected(fixture):
    root, path, config = fixture
    (root / "link.md").symlink_to(root / "evidence.md")
    config["findings"][0]["evidence"] = ["link.md"]
    write(path, config)
    with pytest.raises(ValueError):
        run(fixture)


def test_new_batch_file_during_export_invalidates_source_inventory(fixture, monkeypatch):
    root, _, _ = fixture
    original = closeout._html

    def mutate(*args):
        (root / "runs/batch0/late-file.json").write_text("{}")
        return original(*args)

    monkeypatch.setattr(closeout, "_html", mutate)
    with pytest.raises(ValueError, match="mutated during generation"):
        run(fixture)
    assert not (root / "reports/closeout/manifest.json").exists()
    saved = json.loads((root / "reports/closeout/closeout.json").read_text())
    assert saved["verification"]["sources_unchanged"] is False


def test_input_condition_must_match_frozen_slot(fixture):
    mutate_summary(fixture, 0, lambda d: d["trials"][1].update(input_condition="canary"))
    with pytest.raises(ValueError, match="input condition differs"):
        run(fixture)


def test_planned_slot_cannot_be_dropped(fixture):
    mutate_summary(fixture, 0, lambda d: d["trials"].pop())
    with pytest.raises(ValueError, match="every planned slot"):
        run(fixture)
