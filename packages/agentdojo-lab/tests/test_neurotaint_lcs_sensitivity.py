import csv
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest
from test_semantic import FakeEncoder

from agentdojo_lab import neurotaint_reference_panel as reference_panel
from agentdojo_lab.neurotaint_lcs_sensitivity import (
    ALTERNATIVES,
    METHOD,
    ORDINARY_THRESHOLD,
    _aggregate,
    _score,
    analyze_lcs_sensitivity,
)

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "configs/neurotaint_reference_panel_v1.json"


def create_panel(path):
    summary = reference_panel.run_reference_panel(
        path,
        config_path=CONFIG,
        encoder_factory=FakeEncoder,
        encoder_mode="deterministic_test_double",
    )
    assert summary["status"] == "completed"
    return path


def read_json(path):
    return json.loads(path.read_text(encoding="ascii"))


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def source_hashes(path):
    return {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in path.iterdir()
        if item.is_file()
    }


def update_manifest_hash(panel, name):
    path = panel / "manifest.json"
    value = read_json(path)
    value["files"][name] = hashlib.sha256((panel / name).read_bytes()).hexdigest()
    path.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def test_completed_panel_produces_immutable_ascii_jsonl_csv_and_hash_manifest(tmp_path):
    panel = create_panel(tmp_path / "panel")
    before = source_hashes(panel)
    output = tmp_path / "sensitivity"
    summary = analyze_lcs_sensitivity(panel, output)

    assert summary["status"] == "completed"
    assert summary["method"] == METHOD
    assert summary["pair_count"] == 24
    assert summary["input_integrity"]["verified_before_analysis"] is True
    assert summary["input_integrity"]["source_files_unchanged_during_analysis"] is True
    assert source_hashes(panel) == before
    assert {path.name for path in output.iterdir()} == {
        "manifest.json",
        "metrics.csv",
        "results.jsonl",
        "summary.json",
    }
    for path in output.iterdir():
        path.read_bytes().decode("ascii")
    manifest = read_json(output / "manifest.json")
    assert manifest["immutable_output"] is True
    assert manifest["source_panel_files_sha256"] == summary["input_integrity"][
        "source_files_sha256"
    ]
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert read_json(output / "summary.json") == summary
    rows = read_jsonl(output / "results.jsonl")
    assert len(rows) == 24 * len(ALTERNATIVES)
    assert Counter(row["alternative_id"] for row in rows) == {
        alternative["id"]: 24 for alternative in ALTERNATIVES
    }
    with (output / "metrics.csv").open(newline="", encoding="ascii") as stream:
        metrics = list(csv.DictReader(stream))
    expected_strata = 1 + 3 + len(summary["families"])
    assert len(metrics) == expected_strata * len(ALTERNATIVES)


def test_frozen_baseline_matches_panel_and_fixed_alternatives_report_full_confusions(tmp_path):
    panel = create_panel(tmp_path / "panel")
    source_summary = read_json(panel / "summary.json")
    summary = analyze_lcs_sensitivity(panel, tmp_path / "sensitivity")

    baseline = summary["overall"]["paper_char_min"]
    frozen = source_summary["measurements"]["lcs"]
    assert {key: baseline[key] for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1")} == {
        key: frozen[key] for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1")
    }
    assert {key: baseline[key] for key in ("tp", "fp", "fn", "tn")} == {
        "tp": 12,
        "fp": 12,
        "fn": 0,
        "tn": 0,
    }
    assert {key: summary["overall"]["char_max"][key] for key in ("tp", "fp", "fn", "tn")} == {
        "tp": 11,
        "fp": 3,
        "fn": 1,
        "tn": 9,
    }
    assert {key: summary["overall"]["char_dice"][key] for key in ("tp", "fp", "fn", "tn")} == {
        "tp": 12,
        "fp": 8,
        "fn": 0,
        "tn": 4,
    }
    assert {key: summary["overall"]["token_min"][key] for key in ("tp", "fp", "fn", "tn")} == {
        "tp": 11,
        "fp": 8,
        "fn": 1,
        "tn": 4,
    }
    for alternative in ALTERNATIVES:
        metric = summary["overall"][alternative["id"]]
        assert metric["evaluated_pairs"] == 24
        assert metric["unknown_pairs"] == 0
        assert sum(metric[key] for key in ("tp", "fp", "fn", "tn")) == 24


def test_all_variants_are_explicitly_post_hoc_not_ranked_or_installed_as_a_fix(tmp_path):
    summary = analyze_lcs_sensitivity(
        create_panel(tmp_path / "panel"), tmp_path / "sensitivity"
    )
    assert summary["post_hoc_sensitivity"] is True
    assert summary["preregistered_result"] is False
    assert summary["production_fix"] is False
    assert summary["threshold_selected_on_panel_performance"] is False
    assert summary["threshold"] == ORDINARY_THRESHOLD
    assert summary["absolute_minimum_evidence_floor"] == {
        "included": False,
        "reason": "No post-hoc evidence floor was added or tuned on this panel.",
    }
    assert "rank or select" in summary["alternative_selection_rule"]
    assert "best" not in summary
    assert [item["id"] for item in summary["alternatives"]] == [
        item["id"] for item in ALTERNATIVES
    ]
    for item in summary["alternatives"]:
        assert item["post_hoc_sensitivity"] is True
        assert item["preregistered_result"] is False
        assert item["production_fix"] is False
        assert item["threshold"] == ORDINARY_THRESHOLD
    for row in read_jsonl(tmp_path / "sensitivity/results.jsonl"):
        assert row["post_hoc_sensitivity"] is True
        assert row["preregistered_result"] is False
        assert row["production_fix"] is False


def test_reachability_uses_frozen_stages_and_accepts_passive_disabled_tier1(tmp_path):
    summary = analyze_lcs_sensitivity(
        create_panel(tmp_path / "panel"), tmp_path / "sensitivity"
    )
    baseline = summary["overall"]["paper_char_min"]["stage_reachability"]
    assert baseline["tier2_positive_exits"] == 24
    assert baseline["tier3_eligible"]["numerator"] == 0
    assert baseline["strict_causal_eligible"] == {
        "numerator": 0,
        "denominator": 24,
        "rate": 0.0,
        "unknown_count": 0,
    }
    assert baseline["strict_causal_status_counts"] == {"ineligible_positive_stage": 24}
    max_length = summary["overall"]["char_max"]["stage_reachability"]
    assert max_length["tier3_eligible"] == {
        "numerator": 10,
        "denominator": 24,
        "rate": 10 / 24,
        "unknown_count": 0,
    }
    assert max_length["newly_tier3_eligible_vs_frozen_current"] == 10
    # The deterministic test encoder marks each frozen direct Tier 3 result
    # positive, so the sensitivity router must consume those saved decisions.
    assert max_length["tier3_positive_exits"] == 10
    assert max_length["tier4_eligible"]["numerator"] == 0
    assert max_length["strict_causal_eligible"]["numerator"] == 0
    rows = read_jsonl(tmp_path / "sensitivity/results.jsonl")
    assert all(row["stage_implications"]["tier1_measurement_negative"] is False for row in rows)
    assert all(row["stage_implications"]["tier1_gate_acceptable"] is True for row in rows)
    assert all(
        row["stage_implications"]["tier1_gate_status"] == "acceptable_disabled_condition"
        for row in rows
    )
    assert "no semantic component is rerun" in summary["stage_reachability_scope"]


def test_metrics_are_reported_by_domain_and_family_with_explicit_unknowns(tmp_path):
    summary = analyze_lcs_sensitivity(
        create_panel(tmp_path / "panel"), tmp_path / "sensitivity"
    )
    assert set(summary["domains"]) == {"calendar", "email", "file"}
    assert "short_user_only_overlap" in summary["families"]
    for domain in summary["domains"].values():
        for alternative in ALTERNATIVES:
            metric = domain[alternative["id"]]
            assert metric["pair_count"] == 8
            assert metric["unknown_pairs"] == 0
    for alternative in ALTERNATIVES:
        unknown = summary["unknowns"][alternative["id"]]
        assert unknown["reference"] == 0
        assert unknown["prediction_with_known_reference"] == 0
        assert unknown["stage_reachability"] == {"tier3": 0, "tier4": 0, "post_tier4": 0}


def test_unscored_inputs_remain_unknown_instead_of_becoming_negatives():
    alternative = ALTERNATIVES[0]
    score = _score("", "target", alternative, ORDINARY_THRESHOLD)
    row = {
        "classification": "unknown_prediction_with_known_reference",
        "status": score["status"],
        "matched": score["matched"],
        "stage_implications": {
            "tier3_eligible": None,
            "tier4_eligible": None,
            "post_tier4_negative": None,
            "newly_tier3_eligible_vs_frozen_current": None,
            "lost_tier3_eligibility_vs_frozen_current": None,
            "strict_causal_eligible": False,
            "strict_causal_status": "ineligible_unknown_stage",
            "tier3_frozen_direct_prediction": None,
            "tier4_frozen_direct_prediction": None,
        },
    }
    metric = _aggregate([row])
    assert score["matched"] is None
    assert metric["tp"] == metric["fp"] == metric["fn"] == metric["tn"] == 0
    assert metric["unknown_prediction_with_known_reference"] == 1
    assert metric["unknown_pairs"] == 1
    assert metric["stage_reachability"]["tier3_eligible"]["unknown_count"] == 1


@pytest.mark.parametrize("name", ["references.jsonl", "results.jsonl", "summary.json", "panel-plan.json"])
def test_manifest_hash_mutation_is_rejected_before_output(tmp_path, name):
    panel = create_panel(tmp_path / "panel")
    with (panel / name).open("ab") as stream:
        stream.write(b" ")
    output = tmp_path / "sensitivity"
    with pytest.raises(ValueError, match="manifest hash mismatch"):
        analyze_lcs_sensitivity(panel, output)
    assert not output.exists()


def test_rehashed_reference_or_result_identity_drift_is_still_rejected(tmp_path):
    reference_panel_path = create_panel(tmp_path / "reference-panel")
    references = read_jsonl(reference_panel_path / "references.jsonl")
    references[0]["source"] += " changed"
    (reference_panel_path / "references.jsonl").write_text(
        "".join(
            json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
            for row in references
        ),
        encoding="ascii",
    )
    update_manifest_hash(reference_panel_path, "references.jsonl")
    with pytest.raises(ValueError, match="reference hash"):
        analyze_lcs_sensitivity(reference_panel_path, tmp_path / "reference-output")

    result_panel_path = create_panel(tmp_path / "result-panel")
    results = read_jsonl(result_panel_path / "results.jsonl")
    results[0]["reference_id"] = "different_reference"
    (result_panel_path / "results.jsonl").write_text(
        "".join(
            json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
            for row in results
        ),
        encoding="ascii",
    )
    update_manifest_hash(result_panel_path, "results.jsonl")
    with pytest.raises(ValueError, match="identity mismatch"):
        analyze_lcs_sensitivity(result_panel_path, tmp_path / "result-output")


def test_existing_or_overlapping_output_is_rejected_without_modifying_panel(tmp_path):
    panel = create_panel(tmp_path / "panel")
    before = source_hashes(panel)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        analyze_lcs_sensitivity(panel, existing)
    with pytest.raises(ValueError, match="separate"):
        analyze_lcs_sensitivity(panel, panel / "derived")
    assert source_hashes(panel) == before


def test_script_help_and_offline_execution(tmp_path, monkeypatch, capsys):
    script = ROOT / "scripts/run_neurotaint_lcs_sensitivity.py"
    spec = importlib.util.spec_from_file_location("neurotaint_lcs_sensitivity_script", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr("sys.argv", [str(script), "--help"])
    with pytest.raises(SystemExit) as help_result:
        module.main()
    assert help_result.value.code == 0
    capsys.readouterr()

    panel = create_panel(tmp_path / "panel")
    output = tmp_path / "sensitivity"
    monkeypatch.setattr(
        "sys.argv",
        [str(script), "--panel", str(panel), "--output", str(output)],
    )
    assert module.main() == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "completed"
    assert printed["post_hoc_sensitivity"] is True
    assert printed["input_integrity"]["verified_before_analysis"] is True
    assert output.is_dir()
