"""Read-only descriptive audit of one preselected passive / Canary pair.

No model calls, outcome selection, marker stripping, or causal effect estimates.
The separately saved verifier results establish prefix/replay integrity.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from collections import Counter
from pathlib import Path

from agentdojo_lab.canary import validate_assignment
from agentdojo_lab.policy import ToolPolicy


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def read_arm(run: Path) -> dict:
    run = run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    summary = json.loads((run / "summary.json").read_text())
    events = lines(run / "events.jsonl")
    calls = [
        {**r["call"], "call_ref": r["call_ref"]}
        for r in lines(run / "provenance.jsonl")
        if r["record_type"] == "call_analysis"
    ]
    policy = ToolPolicy.from_dict(manifest["online_provenance"]["policy"]["document"])

    def of_type(kind):
        return [e for e in events if e["event_type"] == kind]

    interventions = of_type("TOOL_OUTPUT_INTERVENTION")
    results = of_type("TOOL_RESULT")
    exposures = of_type("TOOL_OUTPUT_EXPOSED")
    runtimes = {e["call_ref"]: e for e in of_type("TOOL_RUNTIME_RETURNED")}
    pairs = [p for call in calls for f in call["fields"] for p in f.get("nt_style_cascade", [])]
    sink_calls = [call for call in calls if call["policy"]["sink"]["selected"]]
    proposals = of_type("TOOL_CALL_PROPOSED")
    sink_proposals = [
        event for event in proposals if policy.sink_decision(event["data"]["function"])["selected"]
    ]
    markers = []
    for event in interventions:
        if event["data"]["status"] != "assigned":
            continue
        audit = validate_assignment(event["data"])
        published = [e for e in results if e["data"].get("intervention_event_id") == event["event_id"]]
        applied = (
            len(published) == 1 and published[0]["data"]["message"]["content"] == audit["marked_content"]
        )
        result_id = published[0]["event_id"] if len(published) == 1 else None
        exposed = [e for e in exposures if e["data"]["source_result_event_id"] == result_id]
        hits = []
        for call in sink_calls:
            for field in call["fields"]:
                for pair in field["nt_style_cascade"]:
                    if pair["source_event_id"] != result_id or pair["first_matched_tier"] != "tier1":
                        continue
                    returned = runtimes.get(call["call_ref"])
                    hits.append(
                        {
                            "proposal_event_id": call["proposal_event_id"],
                            "call_ref": call["call_ref"],
                            "function": call["function"],
                            "argument_path": field["argument_path"],
                            "target_spans": pair["stages"]["tier1"]["target_spans"],
                            "native_return_succeeded": returned is not None
                            and returned["data"].get("error") is None
                            and returned["data"].get("raised_exception_type") is None,
                        }
                    )
        markers.append(
            {
                "token": audit["token"],
                "assignment_event_id": event["event_id"],
                "source_result_event_id": result_id,
                "origin_tool": audit["function"],
                "applied": applied,
                "exposure_event_ids": [e["event_id"] for e in exposed],
                "original_text_sha256": audit["original_text_sha256"],
                "marked_text_sha256": audit["marked_text_sha256"],
                "source_span": audit["joined_token_span"],
                "sink_hits": hits,
            }
        )
    stage1 = [p["stages"]["tier1"] for p in pairs]
    sink_returns = [runtimes[e["call_ref"]] for e in sink_proposals if e["call_ref"] in runtimes]
    checkpoint = run / "lineage-state.json"
    graph = json.loads(checkpoint.read_text())["state"] if checkpoint.exists() else None
    return {
        "path": str(run),
        "run_id": run.name,
        "condition": "canary_intervention" if manifest["config"].get("canary_enabled") else "passive",
        "real_llm": manifest["real_llm"],
        "config": manifest["config"],
        "status": summary["status"],
        "tasks": summary.get("tasks", []),
        "elapsed_seconds": summary.get("elapsed_seconds"),
        "usage": summary.get("usage", {}),
        "request_pacing": manifest.get("request_pacing"),
        "recording_complete": summary["recording"]["complete"],
        "sidecar_complete": summary["online_provenance"]["complete"],
        "scoring_complete": summary["online_provenance"].get("scoring_complete"),
        "lineage_counts": {key: len(graph[key]) for key in ("nodes", "edges", "registry", "memory_bindings")}
        if graph is not None
        else None,
        "canary_status": summary.get("canary"),
        "counts": {
            "requests_attempted": len(of_type("MODEL_REQUEST")),
            "responses_received": len(of_type("MODEL_RESPONSE")),
            "model_errors": len(of_type("MODEL_ERROR")),
            "proposals": len(proposals),
            "saved_call_analyses": len(calls),
            "runtime_entries": len(of_type("TOOL_RUNTIME_STARTED")),
            "sink_proposals": len(sink_proposals),
            "sink_returns": len(sink_returns),
            "successful_sink_returns": sum(
                e["data"].get("error") is None and e["data"].get("raised_exception_type") is None
                for e in sink_returns
            ),
            "source_policy_tool_results": sum(
                policy.source_decision("tool", e["data"]["message"]["tool_call"]["function"])["eligible"]
                for e in results
            ),
            "assigned_markers": len(markers),
            "applied_markers": sum(m["applied"] for m in markers),
            "exposed_markers": sum(bool(m["exposure_event_ids"]) for m in markers),
            "marker_exposures": sum(len(m["exposure_event_ids"]) for m in markers),
            "markers_at_sink_proposal": sum(bool(m["sink_hits"]) for m in markers),
            "markers_at_successful_sink_return": sum(
                any(h["native_return_succeeded"] for h in m["sink_hits"]) for m in markers
            ),
            "tier1_scored_pairs": sum(s["status"] == "scored" for s in stage1),
            "tier1_matched_pairs": sum(s["matched"] is True for s in stage1),
            "tier1_nonmatched_pairs": sum(s["matched"] is False for s in stage1),
            "incomplete_cascade_pairs": sum(
                not p["complete"] and p["status"] != "not_applicable" for p in pairs
            ),
        },
        "intervention_statuses": dict(Counter(e["data"]["status"] for e in interventions)),
        "intervention_reasons": dict(Counter(e["data"]["reason"] for e in interventions)),
        "first_hit_tiers": dict(Counter(p["first_matched_tier"] or "none" for p in pairs)),
        "markers": markers,
        "proposed_actions": [
            {"function": e["data"]["function"], "arguments": e["data"]["arguments"]} for e in proposals
        ],
        "runtime_actions": [
            {"function": e["data"]["function"], "arguments": e["data"]["runtime_input_args"]}
            for e in of_type("TOOL_RUNTIME_STARTED")
        ],
        "request_bodies": [e["data"]["body"] for e in of_type("MODEL_REQUEST")],
        "environment_changes": [e["data"] for e in of_type("ENVIRONMENT_CHANGE")],
        "input_sha256": {
            name: hashlib.sha256((run / name).read_bytes()).hexdigest()
            for name in ("manifest.json", "summary.json", "events.jsonl", "provenance.jsonl")
        },
    }


def report(passive: Path, canary: Path, output: Path) -> dict:
    arms = [read_arm(passive), read_arm(canary)]
    if [arm["condition"] for arm in arms] != ["passive", "canary_intervention"]:
        raise ValueError("Expected the preselected passive arm followed by Canary")
    configs = [{k: v for k, v in arm["config"].items() if k != "canary_enabled"} for arm in arms]
    if configs[0] != configs[1]:
        raise ValueError("Paired configurations differ beyond the canary switch")
    requests = [arm["request_bodies"] for arm in arms]
    comparisons = {
        "configuration_equal_except_canary": True,
        "first_actual_request_equal": requests[0][0] == requests[1][0] if all(requests) else None,
        "full_request_sequences_equal": requests[0] == requests[1],
        "proposed_action_sequences_equal": arms[0]["proposed_actions"] == arms[1]["proposed_actions"],
        "runtime_action_sequences_equal": arms[0]["runtime_actions"] == arms[1]["runtime_actions"],
        "environment_change_sequences_equal": arms[0]["environment_changes"]
        == arms[1]["environment_changes"],
    }
    result = {
        "schema_version": 1,
        "arm_order": ["passive", "canary_intervention"],
        "arms": arms,
        "comparisons": comparisons,
        "scope": "Two prospectively selected sequential trials. Exact observed differences are descriptive; fixed order, elapsed time and model stochasticity prevent a causal effect estimate. No UUID or action text is stripped. Offline native controls separately test input-only transformation.",
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "pair.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    esc = html.escape
    rows = "".join(
        f"<tr><th>{esc(key.replace('_', ' '))}</th>"
        + "".join(f"<td>{arm['counts'][key]}</td>" for arm in arms)
        + "</tr>"
        for key in arms[0]["counts"]
    )
    details = ""
    for arm in arms:
        link = Path(os.path.relpath(Path(arm["path"]) / "report.html", output)).as_posix()
        details += f"<section><h2>{esc(arm['condition'])}</h2><p><a href='{esc(link, quote=True)}'>Open interactive timeline and agent diagram</a></p>"
        for key in (
            "tasks",
            "markers",
            "proposed_actions",
            "runtime_actions",
            "environment_changes",
            "canary_status",
            "usage",
            "first_hit_tiers",
            "input_sha256",
        ):
            details += f"<details><summary>{esc(key.replace('_', ' '))}</summary><pre>{esc(json.dumps(arm[key], ensure_ascii=False, indent=2))}</pre></details>"
        details += "</section>"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Canary paired experiment</title><style>
    :root{{color-scheme:light dark;font-family:system-ui,sans-serif}}body{{max-width:1000px;margin:36px auto;padding:0 20px;line-height:1.5}}table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:8px;border-bottom:1px solid GrayText}}td{{font-variant-numeric:tabular-nums}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}summary{{cursor:pointer;padding:10px 0}}section{{margin-top:32px}}.table{{overflow-x:auto}}a{{color:LinkText}}
    </style></head><body><h1>Canary paired experiment</h1><p>{esc(result["scope"])}</p><p>Native task outcomes: inspect each arm below. Missing evaluation remains unknown.</p><div class="table"><table><thead><tr><th>Recorded quantity</th><th>Passive</th><th>Canary</th></tr></thead><tbody>{rows}</tbody></table></div><details open><summary>Observed pair comparison</summary><pre>{esc(json.dumps(comparisons, indent=2))}</pre></details>{details}</body></html>"""
    (output / "index.html").write_text(page)
    return {
        "output": str(output.resolve()),
        "counts": {arm["condition"]: arm["counts"] for arm in arms},
        "comparisons": comparisons,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--passive", type=Path, required=True)
    parser.add_argument("--canary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(report(args.passive, args.canary, args.output), indent=2))
