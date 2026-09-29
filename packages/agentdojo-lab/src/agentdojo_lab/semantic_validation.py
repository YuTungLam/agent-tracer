"""Prospective semantic component diagnostics with explicit reference limits."""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from agentdojo_lab.profiles import get_profile
from agentdojo_lab.reference_controls import _measure, _prediction, _unknown, confusion
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher
from agentdojo_lab.semantic_validation_cases import compile_references, fixture_design

PROTOCOL = "controlled-semantic-components-v1"
MEASUREMENTS = ("exact", "lcs", "cascade", "direct_tier3", "direct_tier4", "ordered_tier3", "ordered_tier4")
SCOPE = "Controlled authored correspondence and declared construction origin only; not independent real-agent attribution accuracy."


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def implementation():
    folder = Path(__file__).parent
    names = (
        "semantic_validation.py",
        "semantic_validation_cases.py",
        "reference_controls.py",
        "profiles.py",
        "cascade.py",
        "semantic.py",
        "lexical.py",
        "canary.py",
        "model_pins/minilm-v1.json",
    )
    return {name: sha((folder / name).read_bytes()) for name in names}


def metrics(rows, *, valid=True):
    result = {}
    for name in MEASUREMENTS:
        value = confusion(rows, name, references_valid=valid)
        value["metric_scope"] = SCOPE
        result[name] = value
    return result


def render(summary, rows):
    esc = html.escape

    def table(group):
        columns = ("tp", "fp", "fn", "tn", "unknown_reference", "unknown_prediction_with_known_reference")
        return (
            '<div class="scroll"><table><tr><th>Measurement</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Unknown reference</th><th>Unknown prediction</th></tr>'
            + "".join(
                f"<tr><td>{esc(name)}</td>" + "".join(f"<td>{value[c]}</td>" for c in columns) + "</tr>"
                for name, value in group.items()
            )
            + "</table></div>"
        )

    records = []
    for row in rows:
        ev = row["evidence"]
        outcomes = []
        for name in MEASUREMENTS:
            prediction = _prediction(ev[name]) if summary["inputs_valid"] else None
            label = "Unknown" if prediction is None else "Candidate" if prediction else "No candidate"
            score = ev[name].get("score")
            outcomes.append(
                f"<tr><td>{esc(name)}</td><td>{label}</td><td>{score if score is not None else '—'}</td><td>{esc(ev[name]['status'])}</td></tr>"
            )
        reference = (
            "Unknown"
            if row["reference"] is None
            else "Declared correspondence"
            if row["reference"]
            else "Declared other origin"
        )
        records.append(
            f"<details><summary>{esc(row['reference_id'])} · {reference}</summary>"
            f"<p>Reference contract: {esc(row['reference_contract'])}</p>"
            f"<h3>Source</h3><pre>{esc(row['source'])}</pre><h3>Target</h3><pre>{esc(row['target'])}</pre>"
            '<div class="scroll"><table><tr><th>Measurement</th><th>Prediction</th><th>Score</th><th>Status</th></tr>'
            + "".join(outcomes)
            + "</table></div><details><summary>Reference and component evidence</summary><pre>"
            + esc(json.dumps(row, indent=2))
            + "</pre></details></details>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Controlled semantic component diagnostics</title><style>body{font:16px/1.5 system-ui;max-width:1050px;margin:25px auto;padding:0 18px;color:#182333;background:#f8fafc}h1{font-size:1.7rem}td,th{text-align:left;padding:8px;border-bottom:1px solid #bdc9d6}table{width:100%;border-collapse:collapse}.scroll{overflow:auto}details{padding:12px 0;border-top:1px solid #bdc9d6}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#1559a0}</style>"
        f"<h1>Controlled semantic component diagnostics</h1><p>{summary['recorded_pairs']} / {summary['planned_pairs']} fixed pairs · {esc(summary['encoder_mode'])} · {esc(summary['status'])}</p>"
        "<p>Ordinary cascade thresholds are unchanged. Direct components run separately even when the cascade exits at Tier 2. Skipped, truncated and failed components remain unknown.</p>"
        '<p><a href="plan.json">Frozen plan</a> · <a href="results.jsonl">All pairs</a> · <a href="summary.json">Summary</a> · <a href="manifest.json">Hashes</a></p>'
        "<p><strong>These are authored references, not independent human labels.</strong> A semantic candidate for an unused related source is an origin-specificity concern, not automatically an incorrect similarity score. Counts describe this constructed set only.</p>"
        + table(summary["measurements"])
        + f"<p>First-hit stage counts: {esc(json.dumps(summary['cascade_first_hit_counts']))}. Actual ordered semantic entry: Tier 3 = {summary['ordered_entry']['tier3']}; Tier 4 = {summary['ordered_entry']['tier4']}.</p>"
        + "<details><summary>Results by family</summary>"
        + "".join(f"<h3>{esc(name)}</h3>" + table(group) for name, group in summary["families"].items())
        + "</details>"
        + "<h2>Inspect all references</h2>"
        + "".join(records)
        + "</html>"
    )


def run(output, *, encoder_factory, encoder_mode, encoder_configuration):
    if encoder_mode not in {"real_local_minilm", "deterministic_test_double"}:
        raise ValueError("Explicit encoder mode required")
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(output)
    design = fixture_design()
    references = compile_references(design)
    frozen_code = implementation()
    profile = get_profile("ordinary")
    ref_bytes = b"".join(canonical(r) + b"\n" for r in references)
    plan = {
        "protocol": PROTOCOL,
        "design": design,
        "profile": asdict(profile),
        "references_sha256": sha(ref_bytes),
        "implementation_sha256": frozen_code,
        "encoder_mode": encoder_mode,
        "encoder_configuration": encoder_configuration,
        "measurements": list(MEASUREMENTS),
        "generative_request_ceiling": 0,
        "reference_scope": SCOPE,
        "selection": "All declared pairs, no score-based exclusions, changes or repeated-model selection",
    }
    plan_bytes = canonical(plan) + b"\n"
    output.mkdir(parents=True, exist_ok=False)
    (output / "plan.json").write_bytes(plan_bytes)
    (output / "references.jsonl").write_bytes(ref_bytes)
    encoder, encoder_error, encoder_metadata = None, None, None
    try:
        encoder = encoder_factory()
        encoder_metadata = copy.deepcopy(encoder.metadata)
        canonical(encoder_metadata)
    except Exception as error:
        encoder, encoder_error = None, type(error).__name__
    semantic = SemanticMatcher(encoder) if encoder is not None else None
    rows = []
    with (output / "results.jsonl").open("xb") as stream:
        for reference in references:
            try:
                evidence = _measure(reference, profile, semantic)
            except Exception as error:
                evidence = {name: _unknown("error", error_type=type(error).__name__) for name in MEASUREMENTS}
            row = {
                **reference,
                "evidence": {name: evidence[name] for name in MEASUREMENTS},
                "profile": "ordinary",
            }
            rows.append(row)
            stream.write(canonical(row) + b"\n")
            stream.flush()
    integrity = {
        "implementation_unchanged": implementation() == frozen_code,
        "plan_unchanged": (output / "plan.json").read_bytes() == plan_bytes,
        "references_unchanged": (output / "references.jsonl").read_bytes() == ref_bytes,
        "case_declarations_unchanged": canonical(fixture_design()) == canonical(design),
    }
    valid = all(integrity.values())
    errors = Counter(
        e["status"]
        for row in rows
        for e in row["evidence"].values()
        if e["status"] in {"error", "encoder_error", "encoder_unavailable"}
    )
    summary = {
        "protocol": PROTOCOL,
        "status": "invalidated_inputs"
        if not valid
        else "completed_with_unknowns"
        if encoder_error or errors
        else "completed",
        "encoder_mode": encoder_mode,
        "encoder_configuration": encoder_configuration,
        "encoder_metadata": encoder_metadata,
        "encoder_error": encoder_error,
        "inputs_valid": valid,
        "integrity": integrity,
        "plan_sha256": sha(plan_bytes),
        "planned_pairs": len(references),
        "recorded_pairs": len(rows),
        "measurement_errors": dict(errors),
        "reference_counts": {
            "positive": sum(r["reference"] is True for r in rows),
            "negative": sum(r["reference"] is False for r in rows),
            "unknown": sum(r["reference"] is None for r in rows),
        },
        "measurements": metrics(rows, valid=valid),
        "families": {
            family: metrics([r for r in rows if r["family"] == family], valid=valid)
            for family in sorted({r["family"] for r in rows})
        },
        "cascade_first_hit_counts": dict(
            Counter(r["evidence"]["cascade"].get("first_matched_tier") or "no_hit_or_unknown" for r in rows)
        ),
        "ordered_entry": {
            tier: sum(
                r["evidence"]["ordered_" + tier]["status"]
                in {"scored", "not_applicable", "budget_exceeded", "encoder_error"}
                for r in rows
            )
            for tier in ("tier3", "tier4")
        },
        "generative_model_requests": 0,
        "native_agent_runs": 0,
        "independent_real_agent_accuracy": None,
        "scope": SCOPE,
    }
    (output / "summary.json").write_bytes(canonical(summary) + b"\n")
    (output / "index.html").write_text(render(summary, rows), encoding="utf-8")
    (output / "manifest.json").write_bytes(
        canonical({p.name: sha(p.read_bytes()) for p in sorted(output.iterdir()) if p.is_file()}) + b"\n"
    )
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, default=Path(".model-cache/all-MiniLM-L6-v2-1110a243"))
    parser.add_argument("--revision", default="1110a243fdf4706b3f48f1d95db1a4f5529b4d41")
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    config = {"model_path": str(args.model_path.resolve()), "revision": args.revision}
    result = run(
        args.output,
        encoder_factory=lambda: LocalMiniLMEncoder(config["model_path"], revision=args.revision),
        encoder_mode="real_local_minilm",
        encoder_configuration=config,
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "status",
                    "planned_pairs",
                    "recorded_pairs",
                    "reference_counts",
                    "cascade_first_hit_counts",
                    "ordered_entry",
                    "measurement_errors",
                )
            }
        )
    )
    return 0 if result["inputs_valid"] and result["encoder_error"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
