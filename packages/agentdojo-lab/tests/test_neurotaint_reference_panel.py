"""Frozen held-out panel construction, measurement, and artifact tests."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from test_semantic import FakeEncoder

from agentdojo_lab import neurotaint_reference_panel as panel
from agentdojo_lab.neurotaint_eval import _verify_reference_evidence

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "configs/neurotaint_reference_panel_v1.json"


def load(path):
    return json.loads(path.read_text())


def run(tmp_path, encoder=None, *, name="panel"):
    return panel.run_reference_panel(
        tmp_path / name,
        config_path=CONFIG,
        encoder_factory=lambda: encoder or FakeEncoder(),
        encoder_mode="deterministic_test_double",
    )


def test_frozen_panel_has_balanced_definitive_pairs_in_three_domains():
    config, raw = panel.load_panel_config(CONFIG)
    references = panel.compile_panel_references(config)
    assert raw == CONFIG.read_bytes()
    assert len(references) == 24
    assert sum(item["reference"] is True for item in references) == 12
    assert sum(item["reference"] is False for item in references) == 12
    assert not any(item["reference"] is None for item in references)
    assert {item["domain"] for item in references} == {"calendar", "email", "file"}
    for domain in ("calendar", "email", "file"):
        group = [item for item in references if item["domain"] == domain]
        assert len(group) == 8
        assert sum(item["reference"] is True for item in group) == 4
        assert sum(item["reference"] is False for item in group) == 4
    for item in references:
        assert item["label_frozen_before_detector_invocation"] is True
        assert bool(item["construction_witnesses"]) is item["reference"]
        assert item["reference_scope"] == panel.SCOPE
        json.dumps(item).encode("ascii")


def test_plan_references_and_labels_exist_before_encoder_creation(tmp_path):
    output = tmp_path / "report"
    encoder = FakeEncoder()
    observed = []

    def factory():
        plan = load(output / "panel-plan.json")
        references = (output / "references.jsonl").read_bytes()
        assert plan["reference_sha256"] == hashlib.sha256(references).hexdigest()
        assert plan["reference_labels_frozen_before_encoder_creation"] is True
        assert plan["selection_completed_before_detector_invocation"] is True
        assert len(plan["schedule"]) == 24
        assert not (output / "results.jsonl").exists()
        assert not encoder.calls
        observed.append(references)
        return encoder

    summary = panel.run_reference_panel(
        output,
        config_path=CONFIG,
        encoder_factory=factory,
        encoder_mode="deterministic_test_double",
    )
    assert summary["status"] == "completed"
    assert summary["planned_pairs"] == summary["recorded_pairs"] == 24
    assert summary["reference_label_counts"] == {"positive": 12, "negative": 12, "unknown": 0}
    assert all(summary["integrity"].values())
    assert (output / "references.jsonl").read_bytes() == observed[0]
    assert encoder.calls
    assert summary["generative_model_requests"] == 0
    assert summary["native_agent_runs"] == 0
    assert summary["external_api_requests"] == 0


def test_evaluation_freeze_rejects_a_deterministic_test_double_reference(tmp_path):
    run(tmp_path)
    with pytest.raises(ValueError, match="stale or inconsistent"):
        _verify_reference_evidence(tmp_path / "panel")


def test_summary_reports_confusion_metrics_unknowns_and_bounded_scope(tmp_path):
    summary = run(tmp_path)
    metrics = summary["attribution_metrics"]
    assert sum(metrics[key] for key in ("tp", "fp", "fn", "tn")) == 24
    assert metrics["evaluated_pairs"] == 24
    assert metrics["unknown_reference"] == 0
    assert metrics["unknown_prediction_with_known_reference"] == 0
    assert metrics["unknown_pairs"] == 0
    assert metrics["precision"] == metrics["tp"] / (metrics["tp"] + metrics["fp"])
    assert metrics["recall"] == metrics["tp"] / (metrics["tp"] + metrics["fn"])
    assert metrics["f1"] == 2 * metrics["tp"] / (
        2 * metrics["tp"] + metrics["fp"] + metrics["fn"]
    )
    sensitivity = metrics["tp"] / (metrics["tp"] + metrics["fn"])
    specificity = metrics["tn"] / (metrics["tn"] + metrics["fp"])
    assert metrics["balanced_accuracy"] == (sensitivity + specificity) / 2
    assert metrics["scored_coverage"] == {
        "numerator": 24,
        "denominator": 24,
        "rate": 1.0,
        "unknown_count": 0,
        "scope": "controlled_pairs_with_known_reference_and_definitive_prediction",
    }
    assert metrics["availability_accounting"] == {
        "scored": 24,
        "abstention": 0,
        "unavailable": 0,
        "error": 0,
        "unknown_reference": 0,
    }
    routing = metrics["ordered_cascade_distribution"]
    assert [row["stage"] for row in routing["stage_entry"]] == [
        "tier1",
        "tier2",
        "tier3",
        "tier4",
    ]
    assert all(row["denominator"] == 24 for row in routing["stage_entry"])
    assert [row["outcome"] for row in routing["first_hit"]] == [
        "tier1",
        "tier2",
        "tier3",
        "tier4",
        "complete_negative",
        "unknown",
    ]
    assert sum(row["count"] for row in routing["first_hit"]) == 24
    assert metrics["metric_scope"] == panel.SCOPE
    assert summary["unknowns"] == {
        "reference": 0,
        "prediction_with_known_reference": 0,
        "cascade_pairs": 0,
        "measurement_errors": {},
    }
    assert summary["natural_agent_attribution_metrics"] == {
        "precision": None,
        "recall": None,
        "f1": None,
    }
    assert set(summary["measurements"]) == set(panel.reference_controls.MEASUREMENTS)
    for domain in ("calendar", "email", "file"):
        assert summary["domains"][domain]["pair_count"] == 8
        assert summary["domains"][domain]["reference_label_counts"] == {
            "positive": 4,
            "negative": 4,
            "unknown": 0,
        }


def test_coverage_accounting_separates_abstention_unavailable_error_and_unknown_reference():
    evidence = [
        {"status": "scored", "complete": True, "truncated": False, "matched": True},
        {"status": "scored", "complete": False, "truncated": False, "matched": None},
        {"status": "disabled_condition", "complete": False, "truncated": False, "matched": None},
        {"status": "encoder_error", "complete": False, "truncated": False, "matched": None},
        {"status": "scored", "complete": True, "truncated": False, "matched": False},
    ]
    rows = [
        {"reference": reference, "evidence": {"fixture": item}}
        for reference, item in zip((True, True, False, False, None), evidence, strict=True)
    ]
    metric = panel.reference_controls.confusion(rows, "fixture", references_valid=True)

    enriched = panel._enrich_confusion(
        metric, rows, "fixture", references_valid=True
    )

    assert enriched["scored_coverage"] == {
        "numerator": 1,
        "denominator": 5,
        "rate": 0.2,
        "unknown_count": 4,
        "scope": "controlled_pairs_with_known_reference_and_definitive_prediction",
    }
    assert enriched["availability_accounting"] == {
        "scored": 1,
        "abstention": 1,
        "unavailable": 1,
        "error": 1,
        "unknown_reference": 1,
    }


def test_results_jsonl_contains_one_bound_record_per_pair(tmp_path):
    run(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "panel/results.jsonl").read_text().splitlines()]
    assert len(rows) == 24
    assert [row["record_sequence"] for row in rows] == list(range(1, 25))
    assert len({row["reference_id"] for row in rows}) == 24
    assert {row["protocol"] for row in rows} == {panel.PROTOCOL}
    assert {row["profile"] for row in rows} == {"ordinary"}
    for row in rows:
        assert row["source_tool"]
        assert row["sink_tool"]
        assert row["sink_argument_path"].startswith("/")
        assert set(row["evidence"]) == set(panel.reference_controls.MEASUREMENTS)
        for witness in row["construction_witnesses"]:
            a, b = witness["source_span"]
            c, d = witness["target_span"]
            assert row["source"][a:b] == row["target"][c:d]


def test_encoder_failure_retains_pairs_and_never_persists_error_text(tmp_path):
    def failure():
        raise RuntimeError("private encoder setup detail")

    summary = panel.run_reference_panel(
        tmp_path / "report",
        config_path=CONFIG,
        encoder_factory=failure,
        encoder_mode="deterministic_test_double",
    )
    assert summary["status"] == "completed_with_encoder_failure"
    assert summary["encoder_initialization_error"] == "RuntimeError"
    assert summary["recorded_pairs"] == 24
    assert "private encoder" not in (tmp_path / "report/summary.json").read_text()
    assert len((tmp_path / "report/results.jsonl").read_text().splitlines()) == 24


def test_mutating_frozen_references_invalidates_all_reference_scoring(tmp_path):
    output = tmp_path / "report"

    def factory():
        with (output / "references.jsonl").open("ab") as stream:
            stream.write(b" ")
        return FakeEncoder()

    summary = panel.run_reference_panel(
        output,
        config_path=CONFIG,
        encoder_factory=factory,
        encoder_mode="deterministic_test_double",
    )
    assert summary["status"] == "invalidated_inputs"
    assert summary["integrity"]["references_unchanged"] is False
    assert summary["attribution_metrics"]["evaluated_pairs"] == 0
    assert summary["attribution_metrics"]["unknown_reference"] == 24
    assert summary["attribution_metrics"]["balanced_accuracy"] is None
    assert summary["attribution_metrics"]["scored_coverage"]["numerator"] == 0
    assert summary["attribution_metrics"]["availability_accounting"]["unknown_reference"] == 24


def test_manifest_hashes_outputs_and_existing_output_is_rejected(tmp_path):
    run(tmp_path)
    output = tmp_path / "panel"
    manifest = load(output / "manifest.json")
    assert manifest["status"] == "completed"
    assert manifest["protocol"] == panel.PROTOCOL
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert set(manifest["files"]) == {
        "panel-config.json",
        "panel-plan.json",
        "panel-plan.sha256",
        "references.jsonl",
        "results.jsonl",
        "summary.json",
    }
    with pytest.raises(FileExistsError):
        run(tmp_path)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda value: value["pairs"].pop(), "exactly 24"),
        (lambda value: value["pairs"][0].update(reference=False), "disagrees"),
        (
            lambda value: value["pairs"][0]["expression"][0].update(value="missing fragment"),
            "exactly once",
        ),
        (lambda value: value["pairs"][0].update(pair_id=value["pairs"][1]["pair_id"]), "unique"),
        (lambda value: value["pairs"][0].update(source_text="non-English cafe"), "exactly once"),
    ],
)
def test_invalid_panel_mutations_are_rejected(tmp_path, mutation, match):
    value = copy.deepcopy(load(CONFIG))
    mutation(value)
    path = tmp_path / "panel.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match=match):
        config, _ = panel.load_panel_config(path)
        panel.compile_panel_references(config)


def test_non_ascii_configuration_is_rejected_before_compilation(tmp_path):
    value = copy.deepcopy(load(CONFIG))
    value["pairs"][0]["user_text"] = "Non-ASCII caf\u00e9"
    path = tmp_path / "panel.json"
    path.write_text(json.dumps(value, ensure_ascii=False))
    with pytest.raises(ValueError, match="English ASCII"):
        panel.load_panel_config(path)


def test_real_encoder_identity_is_required_before_output_creation(tmp_path):
    called = []
    with pytest.raises(ValueError, match="path and revision"):
        panel.run_reference_panel(
            tmp_path / "report",
            config_path=CONFIG,
            encoder_factory=lambda: called.append(True),
            encoder_mode="real_local_minilm",
        )
    assert not called
    assert not (tmp_path / "report").exists()


def test_real_encoder_mode_rejects_an_injected_factory_before_output_creation(tmp_path):
    called = []
    with pytest.raises(ValueError, match="sealed internal encoder"):
        panel.run_reference_panel(
            tmp_path / "report",
            config_path=CONFIG,
            encoder_factory=lambda: called.append(True),
            encoder_mode="real_local_minilm",
            encoder_configuration={"model_path": "/tmp/model", "revision": "a" * 40},
        )
    assert not called
    assert not (tmp_path / "report").exists()


def test_script_help_does_not_construct_an_encoder(monkeypatch):
    script = ROOT / "scripts/run_neurotaint_reference_panel.py"
    spec = importlib.util.spec_from_file_location("neurotaint_reference_panel_script", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr("sys.argv", [str(script), "--help"])
    with pytest.raises(SystemExit) as result:
        module.main()
    assert result.value.code == 0
