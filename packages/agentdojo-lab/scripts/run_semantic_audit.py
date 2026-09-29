"""Six fresh format-v3 predictions on the previously frozen first-proposal probes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentdojo_lab.causal_v2_audit import _new_client, _validate_export, run_audit
from agentdojo_lab.pacing import RequestPacer

FORMAT = "english_punctuation_v1"
SELECTED = ("conditional_action-r01-both", "conditional_action-r02-both")
ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(folder):
    return {str(p.relative_to(folder)): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def code_snapshot():
    return {
        str(p.relative_to(ROOT)): sha(p)
        for p in [
            Path(__file__).resolve(),
            *[
                ROOT / "src/agentdojo_lab" / name
                for name in (
                    "causal_v2_audit.py",
                    "causal_v2.py",
                    "judgment_formats.py",
                    "counterfactual.py",
                    "pacing.py",
                    "profiles.py",
                )
            ],
        ]
    }


def preflight(source):
    manifest = read(source / "manifest.json")
    if not all((source / p).is_file() and sha(source / p) == h for p, h in manifest.items()):
        raise ValueError("Original follow-up manifest mismatch")
    original = read(source / "summary.json")
    selected = {s["slot_id"]: s for s in original["slots"]}
    groups = []
    for name in SELECTED:
        record = selected[name]
        plans, _, _, _, slots = _validate_export(source / name / "plans")
        replay = read(source / name / "replay/summary.json")
        comparisons = replay["comparisons"]
        if (
            not replay["input_integrity_verified"]
            or record["status"] != "selected"
            or len(slots) != 3
            or len(comparisons) != 3
        ):
            raise ValueError("Expected one complete fixed three-probe group per repetition")
        bound = {c["probe_id"]: c for c in comparisons}
        for plan, probe in slots:
            comparison = bound[probe["probe_id"]]
            if (
                plan["proposal_event_id"] != record["target_proposal_id"]
                or comparison["probe_binding_sha256"] != probe["binding_sha256"]
                or comparison["status"] != "observed_comparison"
                or comparison["baseline_reproduced_original_sink"] is not True
            ):
                raise ValueError("Prior observation is not bound to the predeclared proposal")
        groups.append(
            {"slot_id": name, "proposal_event_id": record["target_proposal_id"], "comparisons": comparisons}
        )
    return groups


def concordance(comparisons, judgments, *, inputs_valid):
    by_id = {r["probe_id"]: r for r in judgments}
    rows = []
    for comparison in comparisons:
        judgment = by_id.get(comparison["probe_id"], {})
        predicted = judgment.get("judgment", {}).get("would_call_anyway")
        known = (
            inputs_valid
            and judgment.get("status") == "valid"
            and judgment.get("judgment_format") == FORMAT
            and judgment.get("binding_sha256") == comparison["probe_binding_sha256"]
            and type(predicted) is bool
        )
        rows.append(
            {
                "probe_id": comparison["probe_id"],
                "known": known,
                "predicted_call": predicted if known else None,
                "observed_call": comparison["intervention_exact_sink_proposed"],
                "agreement": predicted == comparison["intervention_exact_sink_proposed"] if known else None,
            }
        )
    return rows


def run(source, output, *, live=False):
    source, output = source.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Use fresh output outside the original follow-ups")
    groups = preflight(source)
    before, code = snapshot(source), code_snapshot()
    output.mkdir(parents=True, exist_ok=False)
    plan = {
        "protocol": "fresh-english-punctuation-audit-v1",
        "judgment_format": FORMAT,
        "source_followups": str(source),
        "groups": groups,
        "request_ceiling": 6,
        "real_llm": live,
        "source_hashes": before,
        "implementation_hashes": code,
        "client_mode": "Real configured Groq SDK with pacing only; injected_client is SDK provisioning, not mocked responses",
        "scope": "Fresh predictions on previously observed prefixes; not held-out or independent causal accuracy",
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    pacer = RequestPacer(7000, output / "pacing.json")
    records = []
    for group in groups:
        name = group["slot_id"]
        folder = output / name
        record = {"slot_id": name, "status": "unknown", "summary": None}
        try:
            if live:
                with _new_client() as client:
                    create = client.chat.completions.create

                    def paced(**kwargs):
                        ticket, _ = pacer.before_request(kwargs["messages"], [])
                        response = create(**kwargs)
                        pacer.after_response(ticket, response.usage.total_tokens if response.usage else None)
                        return response

                    client.chat.completions.create = paced
                    summary = run_audit(
                        source / name / "plans",
                        folder,
                        client=client,
                        live=True,
                        max_requests=3,
                        judgment_format=FORMAT,
                    )
            else:
                summary = run_audit(source / name / "plans", folder, max_requests=3, judgment_format=FORMAT)
            record.update(status="recorded", summary=summary)
            judgments = [json.loads(line) for line in (folder / "judgments.jsonl").read_text().splitlines()]
            valid = (
                summary["source_files_unchanged"]
                and summary["plan_export_hashes_before"] == summary["plan_export_hashes_after"]
                and code_snapshot() == code
                and snapshot(source) == before
            )
            record["concordance"] = concordance(group["comparisons"], judgments, inputs_valid=valid)
        except (ValueError, OSError, KeyError, TypeError) as error:
            record["error_type"] = type(error).__name__
        if record["summary"] is None and (folder / "summary.json").is_file():
            record["summary"] = read(folder / "summary.json")
        record["request_count_unknown"] = record["summary"] is None and folder.exists()
        records.append(record)
        with (output / "live-slots.jsonl").open("a") as stream:
            stream.write(json.dumps(record, ensure_ascii=True) + "\n")
        print(
            json.dumps(
                {
                    "slot_id": name,
                    "status": record["status"],
                    "valid_judgments": (record["summary"] or {}).get("valid_judgments"),
                }
            ),
            flush=True,
        )
    valid = snapshot(source) == before and code_snapshot() == code
    if not valid:
        for row in records:
            for item in row.get("concordance", []):
                item.update(known=False, predicted_call=None, agreement=None)
    # The incremental journal is provisional; the final ledger uses the final
    # integrity verdict, including any late downgrade, just like summary.json.
    with (output / "slots.jsonl").open("x") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=True) + "\n")
    request_count = sum((r["summary"] or {}).get("request_count", 0) for r in records)
    assert request_count <= 6
    summary = {
        "protocol": plan["protocol"],
        "real_llm": live,
        "planned_slots": 6,
        "request_count": None if any(r["request_count_unknown"] for r in records) else request_count,
        "known_request_count": request_count,
        "inputs_valid": valid,
        "slots": records,
        "valid_judgments": sum((r["summary"] or {}).get("valid_judgments", 0) for r in records),
        "unknown_judgments": 6 - sum((r["summary"] or {}).get("valid_judgments", 0) for r in records),
        "known_agreements": sum(c["agreement"] is True for r in records for c in r.get("concordance", [])),
        "known_disagreements": sum(
            c["agreement"] is False for r in records for c in r.get("concordance", [])
        ),
        "unknown_comparisons": 6 - sum(c["known"] for r in records for c in r.get("concordance", [])),
        "independent_causal_accuracy": None,
        "native_tool_calls": 0,
        "scope": plan["scope"],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "manifest.json").write_text(json.dumps(snapshot(output), indent=2) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    outcome = run(args.source, args.output, live=args.live)
    print(json.dumps({k: v for k, v in outcome.items() if k != "slots"}))
