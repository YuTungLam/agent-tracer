"""Mode separation, frozen annotations and inert policy/cascade report content."""

import hashlib
import json
from pathlib import Path

import pytest

from agentdojo_lab import cli
from agentdojo_lab.policy import load_policy
from agentdojo_lab.provenance_report import export_provenance
from agentdojo_lab.runner import ROOT, RunConfig, run_clean


def hashes(path):
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in path.rglob("*")
        if p.is_file()
    }


def test_cascade_export_keeps_raw_evidence_and_blank_annotations(tmp_path):
    run = tmp_path / "run"
    run_clean(RunConfig(), offline=True, output=run)
    before = hashes(run)
    baseline = tmp_path / "baseline"
    export_provenance(run_dirs=[run], output=baseline)
    output = tmp_path / "cascade"
    policy = load_policy(ROOT / "configs/workspace_policy_v1.yaml")
    result = export_provenance(run_dirs=[run], output=output, policy=policy)
    analysis = json.loads((output / "analysis.json").read_text())
    assert analysis["component_mode"] == "ordered_cascade"
    assert analysis["policy"] == policy.metadata
    assert "nt_style_ordered_cascade_v1" in analysis["methods"]
    assert "nt_style_semantic_v1" not in analysis["methods"]
    assert analysis["counts"]["cascade"]["policy_sink_proposals"] == 0
    assert analysis["counts"]["cascade"]["pair_count"] == 0
    assert analysis["counts"]["accuracy"] is None
    assert (output / "annotations/items.jsonl").read_bytes() == (
        baseline / "annotations/items.jsonl"
    ).read_bytes()
    assert before == hashes(run)
    text = (output / "index.html").read_text()
    assert "Ordered cascade" in text and "not_a_policy_sink" in text
    assert "Skipped stages have no measured score" in text
    assert result


def test_policy_suite_mismatch_rejects_export_before_output(tmp_path):
    run = tmp_path / "run"
    run_clean(RunConfig(), offline=True, output=run)
    document = load_policy(ROOT / "configs/workspace_policy_v1.yaml").metadata["document"]
    document["suite"] = "banking"
    from agentdojo_lab.policy import ToolPolicy

    with pytest.raises(ValueError, match="suite/benchmark"):
        export_provenance(run_dirs=[run], output=tmp_path / "invalid", policy=ToolPolicy.from_dict(document))
    assert not (tmp_path / "invalid").exists()


def test_policy_requires_online_opt_in_and_is_passed_by_cli(monkeypatch):
    with pytest.raises(ValueError, match="policy"):
        RunConfig(provenance_policy="policy.yaml")
    captured = []

    def capture(config, **kwargs):
        captured.append(config)
        return {"task_count": 1, "task_success_count": 1}

    monkeypatch.setattr(cli, "run_clean", capture)
    assert cli.main(["smoke", "--offline", "--online-provenance", "--policy", "policy.yaml"]) == 0
    assert captured[0].provenance_policy == "policy.yaml"


def test_fresh_runner_embeds_policy_and_keeps_default_native_result(tmp_path):
    path = ROOT / "configs/workspace_policy_v1.yaml"
    default = run_clean(RunConfig(), offline=True, output=tmp_path / "default")
    ordered = run_clean(
        RunConfig(online_provenance=True, provenance_policy=str(path)),
        offline=True,
        output=tmp_path / "ordered",
    )
    assert default["tasks"] == ordered["tasks"]
    assert default["usage"] == ordered["usage"]
    assert ordered["online_provenance"]["component_mode"] == "ordered_cascade"
    assert ordered["online_provenance"]["complete"]
    assert ordered["online_provenance"]["policy_sink_count"] == 0
    manifest = json.loads((Path(ordered["run_dir"]) / "manifest.json").read_text())
    assert manifest["online_provenance"]["policy"] == load_policy(path).metadata
