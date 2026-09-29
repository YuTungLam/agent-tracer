"""Freeze and export the optional offline decoded-scalar diagnostic."""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from agentdojo_lab.evaluation_analysis import _tree
from agentdojo_lab.evaluation_review import _canonical, _local, _read, _sha, _strict
from agentdojo_lab.span_evidence import analyze_span_evidence

ROOT = Path(__file__).resolve().parents[2]
CONTROL_SHA = "3060eddacb6e28b6c912d5dd5c5ac846c6d16cd77f9c81d8dbe7b73cec1198de"


def _write(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def _implementation() -> dict:
    paths = sorted((ROOT / "src/agentdojo_lab").glob("*.py"))
    paths += [ROOT / "src/agentdojo_lab/span_report.html", ROOT / "SPAN-DIAGNOSTIC.md", ROOT / "HELDOUT.md"]
    return {str(path.relative_to(ROOT)): _sha(_read(path)) for path in paths}


def _observed(evidence: dict) -> dict:
    alignment, literal = evidence["optimal_alignment"], evidence["literal_evidence"]
    return {
        **{
            key: alignment[key]
            for key in (
                "lcs_length",
                "min_injection_matched_codepoints",
                "max_injection_matched_codepoints",
                "region_relation",
            )
        },
        "literal_occurrence_count": literal["occurrence_count"],
        "literal_classification": literal["classification"],
        "low_information_target": evidence["low_information_target"],
    }


def render_span_report(result: dict, output: Path) -> None:
    # JSON is inert script data; source/payload text only enters DOM textContent.
    payload = json.dumps(result, ensure_ascii=False, allow_nan=False)
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    payload = payload.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    template = (Path(__file__).with_name("span_report.html")).read_text()
    output.write_text(template.replace("__SPAN_DATA__", payload))


def export_span_diagnostic(runs: list[Path], output: Path) -> dict:
    """Account for every requested run and twelve frozen engineering controls.

    Input experiment protocols remain distinct. No API clients, judges, or encoder
    models are constructed. Fresh output paths and a before/after inventory keep
    prior experiment artifacts intact. The run adapter supplies prefix binding.
    """
    from agentdojo_lab.span_diagnostic import analyze_span_run

    output = _local(output)
    runs = [_local(run) for run in runs]
    if not runs or len(runs) > 64 or len(set(runs)) != len(runs):
        raise ValueError("Select 1 to 64 distinct saved runs")
    if output.exists() or any(
        output == run or run in output.parents or output in run.parents for run in runs
    ):
        raise ValueError("Use a new output directory outside all source runs")
    if not all(run.is_dir() for run in runs):
        raise ValueError("Every selected run must be an existing local directory")
    config_path = ROOT / "configs/SPAN-CONTROLS.json"
    config_raw = _read(config_path)
    if _sha(config_raw) != CONTROL_SHA:
        raise ValueError("Frozen engineering controls changed; create a new protocol version")
    config = _strict(config_raw)
    before = {str(run): _tree(run) for run in runs}
    implementation = _implementation()
    plan = {
        "schema_version": 1,
        "method": "decoded_scalar_span_evidence_v1",
        "mode": "offline_prefix_diagnostic",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "selection": "Explicit ordered saved runs; experimental status belongs to each original frozen batch, not this offline export.",
        "runs": [str(run) for run in runs],
        "controls_sha256": CONTROL_SHA,
        "implementation_sha256": implementation,
        "input_inventory": before,
        "model_calls": 0,
        "independent_accuracy": None,
    }
    output.mkdir(parents=True, exist_ok=False)
    _write(output / "plan.json", plan)
    (output / "controls.json").write_bytes(config_raw)
    controls = []
    for case in config["cases"]:
        evidence = analyze_span_evidence(case["source"], case["target"], case["injection_spans"])
        observed = _observed(evidence)
        controls.append(
            {**case, "observed": observed, "passed": observed == case["expected"], "evidence": evidence}
        )
    results = []
    with (output / "span-results.jsonl").open("x", encoding="utf-8") as stream:
        for run in runs:
            record = analyze_span_run(run)
            record["original_report_href"] = (
                quote(os.path.relpath(run / "report.html", output), safe="/")
                if (run / "report.html").is_file()
                else None
            )
            results.append(record)
            stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
    after = {str(run): _tree(run) for run in runs}
    unchanged = before == after
    implementation_unchanged = implementation == _implementation() and _sha(_read(config_path)) == CONTROL_SHA
    fields = [field for run in results for field in run.get("fields", [])]
    sources = [source for field in fields for source in field.get("sources", [])]
    evidences = [source["evidence"] for source in sources if isinstance(source.get("evidence"), dict)]
    selected = [source for source in sources if source.get("injection_spans")]
    summary = {
        "requested_runs": len(runs),
        "run_status_counts": dict(Counter(run["status"] for run in results)),
        "controls_passed": sum(case["passed"] for case in controls),
        "controls_total": len(controls),
        "argument_fields": len(fields),
        "selected_fields": sum(field.get("policy_selected") is True for field in fields),
        "field_status_counts": dict(Counter(field["status"] for field in fields)),
        "decoded_comparisons": len(evidences),
        "comparison_status_counts": dict(Counter(e["status"] for e in evidences)),
        "annotated_scalar_comparisons": len(selected),
        "annotated_literal_classifications": dict(
            Counter(
                source["evidence"]["literal_evidence"]["classification"]
                for source in selected
                if isinstance(source.get("evidence"), dict)
            )
        ),
        "annotated_alignment_relations": dict(
            Counter(
                source["evidence"]["optimal_alignment"]["region_relation"]
                for source in selected
                if isinstance(source.get("evidence"), dict)
            )
        ),
        "unavailable_source_records": sum(not isinstance(s.get("evidence"), dict) for s in sources),
        "source_files_checked": sum(len(tree) for tree in before.values()),
        "source_files_unchanged": unchanged,
        "implementation_unchanged": implementation_unchanged,
        "model_calls": 0,
        "independent_accuracy": None,
    }
    result = {
        "schema_version": 1,
        "method": plan["method"],
        "mode": plan["mode"],
        "plan_sha256": _sha(_canonical(plan)),
        "controls_sha256": CONTROL_SHA,
        "summary": summary,
        "interpretation": "Lexical location only. Outside assigned regions does not mean benign. "
        "Full-target exact misses do not exclude copied subphrases or semantic influence. "
        "LCS region bounds describe optimal character alignments, not model reliance or maliciousness. "
        "Engineering controls and lexical measurements do not establish independent attribution accuracy.",
        "controls": controls,
        "runs": results,
    }
    _write(output / "span-summary.json", result)
    render_span_report(result, output / "index.html")
    if not unchanged or not implementation_unchanged:
        raise ValueError("Input or implementation changed during analysis; retained result is invalid")
    return {"output": str(output), "summary": summary}
