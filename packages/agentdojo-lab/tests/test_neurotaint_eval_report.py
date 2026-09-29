import copy
import csv
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from agentdojo_lab.neurotaint_eval_report import (
    export_neurotaint_eval_report,
    normalize_neurotaint_eval_input,
    render_neurotaint_eval_html,
)


class ReportParser(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self.tags = []
        self.active = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "script":
            self.active = {"attrs": attributes, "text": ""}
            self.scripts.append(self.active)

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = None

    def handle_data(self, data):
        if self.active is not None:
            self.active["text"] += data

    @property
    def record(self):
        payload = next(item for item in self.scripts if item["attrs"].get("id") == "record")
        return json.loads(payload["text"])


def normalized_summary(marker="fixture"):
    return {
        "schema_version": 1,
        "title": "NeuroTaint held-out testbed",
        "batch_id": "batch-1",
        "plan": {
            "schedule": [
                {
                    "trial_id": "trial-clean-r1",
                    "scenario_id": "scenario-1",
                    "condition": "clean",
                    "repeat": 1,
                },
                {
                    "trial_id": "trial-attack-r1",
                    "scenario_id": "scenario-1",
                    "condition": "injected",
                    "repeat": 1,
                },
                {
                    "trial_id": "trial-attack-r2",
                    "scenario_id": "scenario-1",
                    "condition": "injected",
                    "repeat": 2,
                },
            ]
        },
        "counts": {"planned": 3, "completed": 1, "unknown": 1, "failed": 1},
        "metrics": {
            "utility": {"numerator": 1, "denominator": 1, "rate": 1.0, "unknown_count": 2},
            "attack_success_rate": {
                "numerator": 1,
                "denominator": 1,
                "rate": 1.0,
                "unknown_count": 1,
            },
            "exposure_conditioned_attack_success": {
                "numerator": 1,
                "denominator": 1,
                "rate": 1.0,
                "unknown_count": 0,
            },
            "payload_exposure": {
                "numerator": 1,
                "denominator": 2,
                "rate": 0.5,
                "unknown_count": 0,
            },
            "safe_useful_joint": {
                "numerator": 0,
                "denominator": 1,
                "rate": 0.0,
                "unknown_count": 1,
            },
        },
        "attribution_accuracy": {
            "status": "independent_reference_available",
            "precision": {"numerator": 1, "denominator": 2, "rate": 0.5, "unknown_count": 0},
            "recall": {"numerator": 1, "denominator": 1, "rate": 1.0, "unknown_count": 0},
            "f1": 2 / 3,
            "balanced_accuracy": 0.5,
            "scored_coverage": {
                "numerator": 2,
                "denominator": 3,
                "rate": 2 / 3,
                "unknown_count": 1,
            },
            "availability_accounting": {
                "scored": 2,
                "abstention": 1,
                "unavailable": 0,
                "error": 0,
                "unknown_reference": 0,
            },
            "ordered_cascade_distribution": {
                "stage_entry": [
                    {"stage": "tier2", "count": 3, "denominator": 3, "rate": 1.0}
                ],
                "first_hit": [
                    {"outcome": "tier2", "count": 2, "denominator": 3, "rate": 2 / 3}
                ],
            },
        },
        "scenario_family_metrics": {
            "independent_unit": "scenario_family",
            "safe_useful_joint": {
                "numerator": 1,
                "denominator": 2,
                "rate": 0.5,
                "unknown_count": 1,
                "wilson_95": {"lower": 0.0945, "upper": 0.9055},
            },
        },
        "routing_funnel": [
            {"stage": "selected_sinks", "count": 3, "denominator": 3, "unknown_count": 0},
            {"stage": "causal_eligible", "count": 2, "denominator": 3, "unknown_count": 0},
            {"stage": "judge_valid", "count": 1, "denominator": 2, "unknown_count": 1},
        ],
        "causal": {
            "eligible": 2,
            "judge_attempted": 2,
            "valid_judgments": 1,
            "before_runtime": 1,
        },
        "latency": {"primary_seconds": 3.2, "judge_seconds": 0.4, "unknown_count": 1},
        "tokens": {"primary_total": 100, "judge_total": 20, "unknown_count": 1},
        "unknowns": {"trial_outcome": 1, "causal_judgment": 1},
        "failures": [{"trial_id": "trial-attack-r2", "type": "timeout", "detail": marker}],
        "trials": [
            {
                "trial_id": "trial-clean-r1",
                "scenario_id": "scenario-1",
                "condition": "clean",
                "repeat": 1,
                "status": "completed",
                "utility": True,
                "attack_success": None,
                "exposure": False,
                "report": "runs/trial-clean-r1/report.html",
            },
            {
                "trial_id": "trial-attack-r1",
                "scenario_id": "scenario-1",
                "condition": "injected",
                "repeat": 1,
                "status": "failed",
                "utility": None,
                "attack_success": True,
                "exposure": True,
                "report": "javascript:alert(1)",
                "detector_positive": True,
            },
        ],
        "proposals": [
            {
                "proposal_id": "proposal-1",
                "trial_id": "trial-clean-r1",
                "source_ids": [marker],
                "sink_id": "fixture_tool.arguments.text",
                "attribution": {"prediction": True, "reference": False},
                "causal_eligibility": "eligible",
                "causal_judgment": {"status": "valid", "would_call_anyway": False},
                "judge_tokens": 20,
            }
        ],
    }


def test_exports_normalized_rows_and_self_contained_english_dashboard(tmp_path):
    marker = "</script><b data-probe='1'>unsafe</b>"
    source = normalized_summary(marker)
    before = copy.deepcopy(source)
    result = export_neurotaint_eval_report(source, tmp_path / "report")

    assert source == before
    assert result["status"] == "generated"
    assert result["trial_count"] == 2
    assert result["proposal_count"] == 1
    output = tmp_path / "report"
    assert {path.name for path in output.iterdir()} == {"index.html", "trials.csv", "proposals.jsonl"}

    with (output / "trials.csv").open(newline="", encoding="utf-8") as stream:
        trial_rows = list(csv.DictReader(stream))
    assert [row["trial_id"] for row in trial_rows] == ["trial-clean-r1", "trial-attack-r1"]
    assert all("_report_href" not in row for row in trial_rows)
    proposal = json.loads((output / "proposals.jsonl").read_text(encoding="utf-8"))
    assert proposal == source["proposals"][0]

    content = (output / "index.html").read_text(encoding="utf-8")
    parsed = ReportParser(content)
    assert len(parsed.scripts) == 2
    assert parsed.record["metrics"] == source["metrics"]
    assert parsed.record["attribution_accuracy"] == source["attribution_accuracy"]
    assert parsed.record["trials"][0]["_report_href"] == "runs/trial-clean-r1/report.html"
    assert parsed.record["trials"][1]["_report_href"] is None
    assert parsed.record["proposals"][0]["_report_href"] == "runs/trial-clean-r1/report.html"
    assert not any("data-probe" in attrs for _, attrs in parsed.tags)
    assert "Completeness matrix" in content
    assert "Security, utility, exposure, and attribution" in content
    assert "Exposure-conditioned ASR" in content
    assert "Safe and useful joint outcome" in content
    assert "Scenario-family outcomes" in content
    assert "Wilson 95% interval" in content
    assert "Attribution availability" in content
    assert "Ordered attribution routing" in content
    assert "Routing funnel" in content
    assert "count/denominator" in content
    assert "funnelMax" not in content
    assert "Causal reachability and validity" in content
    assert "Controlled causal panel" in content
    assert "Native exact-prefix replay" in content
    assert "Unknown and failure accounting" in content
    assert "ground truth from detector output" in content
    assert "connect-src 'none'" in content
    node = shutil.which("node")
    if node is not None:
        script = next(item["text"] for item in parsed.scripts if item["attrs"].get("id") != "record")
        checked = subprocess.run([node, "--check"], input=script, text=True, capture_output=True)
        assert checked.returncode == 0, checked.stderr


def test_null_attribution_is_preserved_even_with_positive_detector_rows(tmp_path):
    source = normalized_summary()
    source["attribution_accuracy"] = {"status": "no_independent_reference", "precision": None, "recall": None, "f1": None}
    source["trials"][0]["detector_positive"] = True
    data = normalize_neurotaint_eval_input(source, output=tmp_path)

    assert data["attribution_accuracy"]["precision"] is None
    assert data["attribution_accuracy"]["recall"] is None
    assert data["attribution_accuracy"]["f1"] is None
    assert data["presentation"]["ground_truth_inferred_by_renderer"] is False
    content = render_neurotaint_eval_html(data)
    assert ReportParser(content).record["attribution_accuracy"]["precision"] is None


def test_summary_path_resolves_existing_run_report_without_reading_run_results(tmp_path):
    batch = tmp_path / "batch"
    run = batch / "runs" / "trial-clean-r1"
    run.mkdir(parents=True)
    (run / "report.html").write_text("existing", encoding="utf-8")
    source = normalized_summary()
    source["trials"][0].pop("report")
    source["trials"][0]["run_path"] = "runs/trial-clean-r1"
    summary_path = batch / "summary.json"
    summary_path.write_text(json.dumps(source), encoding="utf-8")

    output = tmp_path / "derived"
    export_neurotaint_eval_report(summary_path, output)
    record = ReportParser((output / "index.html").read_text(encoding="utf-8")).record
    assert record["trials"][0]["_report_href"] == "../batch/runs/trial-clean-r1/report.html"


def test_exports_are_deterministic_except_for_the_csp_nonce(tmp_path):
    output = tmp_path / "report"
    export_neurotaint_eval_report(normalized_summary(), output)
    first = {name: (output / name).read_text(encoding="utf-8") for name in ("index.html", "trials.csv", "proposals.jsonl")}
    export_neurotaint_eval_report(normalized_summary(), output)
    second = {name: (output / name).read_text(encoding="utf-8") for name in first}

    assert first["trials.csv"] == second["trials.csv"]
    assert first["proposals.jsonl"] == second["proposals.jsonl"]

    def without_nonce(text):
        text = re.sub(r"nonce=\"[^\"]+\"", 'nonce="NONCE"', text)
        return re.sub(r"nonce-[A-Za-z0-9_-]+", "nonce-NONCE", text)

    assert without_nonce(first["index.html"]) == without_nonce(second["index.html"])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(trials=["not an object"]),
        lambda value: value["plan"].update(schedule=["not an object"]),
        lambda value: value["metrics"].update(utility=float("nan")),
    ],
)
def test_rejects_non_object_rows_and_non_finite_values(mutation):
    source = normalized_summary()
    mutation(source)
    with pytest.raises(ValueError):
        normalize_neurotaint_eval_input(source)
