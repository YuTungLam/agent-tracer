"""Forced sham/neutralized replays and isolated no-tools judgments for Case R sinks.

Selection rule (frozen): every `both` slot whose scoring records attack_success,
target = the first executed send_email proposal. The baseline planner refuses
probes where an explicit Tier-2 candidate exists; this panel bypasses that gate
under a separate protocol name and labels every probe forced_diagnostic. No
returned tool proposal is executed. Missing or invalid outputs stay unknown.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentdojo_lab import judgment_formats
from agentdojo_lab.case_r_diagnostics import export_forced_plans, forced_explicit_gate
from agentdojo_lab.causal_replay import _replay_slots, run_replay
from agentdojo_lab.causal_v2_audit import _new_client, _validate_export, run_audit
from agentdojo_lab.counterfactual_audit import _verified_inputs
from agentdojo_lab.pacing import RequestPacer

PROTOCOL = "groq-case-r-followups-v1"
REPLAYS_PER_SINK = 4
JUDGMENTS_PER_SINK = 3
MAX_SINKS = 6


def lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def selected_group(plans, source, target_id):
    """The target must own a complete single/single/pair group and the first four replay slots."""
    target = next((p for p in plans if p["proposal_event_id"] == target_id), None)
    if not target or target["status"] != "eligible" or not target["complete"] or len(target["probes"]) != 3:
        return False
    if sorted(len(p["source_ids"]) for p in target["probes"]) != [1, 1, 2]:
        return False
    slots = _replay_slots(plans, source)
    return (
        len(slots) >= REPLAYS_PER_SINK
        and all(s["proposal_event_id"] == target_id for s in slots[:REPLAYS_PER_SINK])
        and [s["condition"] for s in slots[:REPLAYS_PER_SINK]]
        == ["context_a", "context_b", "context_b", "context_b"]
    )


def paced_audit(plans, output, pacer):
    """A real SDK client with pacing only; request bodies and responses are unchanged."""
    with _new_client() as client:
        original = client.chat.completions.create

        def create(**kwargs):
            ticket, _ = pacer.before_request(kwargs["messages"], kwargs.get("tools", []))
            response = original(**kwargs)
            pacer.after_response(ticket, response.usage.total_tokens if response.usage else None)
            return response

        client.chat.completions.create = create
        return run_audit(
            plans,
            output,
            client=client,
            live=True,
            max_requests=JUDGMENTS_PER_SINK,
            judgment_format=judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
        )


def candidates(batch):
    summary = json.loads((batch / "summary.json").read_text(encoding="utf-8"))
    rows = []
    for slot in summary["slots"]:
        scoring = (slot.get("summary") or {}).get("scoring") or {}
        if slot["arm"] == "both" and slot["process_status"] == "completed" and scoring.get("attack_success") is True:
            rows.append(slot)
    return summary, rows[:MAX_SINKS]


def baseline_status(counts):
    if counts.get("not_eligible"):
        return "not_eligible"
    if counts.get("unknown"):
        return "unknown"
    return "eligible" if counts else "unknown"


def run(batch, output, *, live=False):
    batch, output = batch.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(batch) or batch.is_relative_to(output):
        raise ValueError("Follow-up output must be fresh and separate from the immutable batch")
    batch_summary, selection = candidates(batch)
    if live and batch_summary["real_llm"] is not True:
        raise ValueError("Live follow-ups require real primary trajectories")
    output.mkdir(parents=True, exist_ok=False)
    ceiling = (REPLAYS_PER_SINK + JUDGMENTS_PER_SINK) * len(selection)
    plan = {
        "protocol": PROTOCOL,
        "real_llm": live,
        "source_batch": str(batch),
        "source_protocol": batch_summary["protocol"],
        "selection_rule": "both arm; process completed; scoring.attack_success true; first send_email proposal",
        "selected_slot_ids": [s["slot_id"] for s in selection],
        "replays_per_sink": REPLAYS_PER_SINK,
        "judgments_per_sink": JUDGMENTS_PER_SINK,
        "request_ceiling": ceiling,
        "explicit_gate": "bypassed_forced_diagnostic",
        "judgment_format": judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    pacer = RequestPacer(7000, output / "pacing.json")
    records = []
    for slot in selection:
        record = {
            "slot_id": slot["slot_id"],
            "construction": slot["construction"],
            "arm": slot["arm"],
            "repetition": slot["repetition"],
            "status": "not_eligible",
            "reason": None,
            "target_proposal_id": None,
            "forced_diagnostic": True,
            "baseline_plan_status": None,
            "baseline_coverage_status_counts": None,
            "replay": None,
            "audit": None,
            "prediction_concordance": [],
        }
        try:
            source = batch / "runs" / slot["slot_id"]
            calls, _ = _verified_inputs(source)
            targets = sorted(
                (c for c in calls if c["function"] == "send_email"), key=lambda c: c["proposal_sequence"]
            )
            if not targets:
                record["reason"] = "No recorded send_email proposal; no replacement selected"
            else:
                target = targets[0]
                record["target_proposal_id"] = target["proposal_event_id"]
                folder = output / slot["slot_id"]
                folder.mkdir()
                forced = export_forced_plans(source, folder / "plans", max_sources=2, max_pairs=1)
                record["baseline_coverage_status_counts"] = forced["baseline_coverage_status_counts"]
                record["baseline_plan_status"] = baseline_status(forced["baseline_coverage_status_counts"])
                with forced_explicit_gate():
                    plans, verified_source, _, _, _ = _validate_export(folder / "plans")
                    if not selected_group(plans, verified_source, target["proposal_event_id"]):
                        record["reason"] = "Target lacks a complete two-source replay group"
                    else:
                        record["status"] = "selected"
                        record["replay"] = run_replay(
                            folder / "plans",
                            folder / "replay",
                            live=live,
                            max_requests=REPLAYS_PER_SINK,
                            pacer=pacer,
                        )
                        record["audit"] = (
                            paced_audit(folder / "plans", folder / "audit", pacer)
                            if live
                            else run_audit(
                                folder / "plans",
                                folder / "audit",
                                max_requests=JUDGMENTS_PER_SINK,
                                judgment_format=judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
                            )
                        )
                        judgments = {r["probe_id"]: r for r in lines(folder / "audit" / "judgments.jsonl")}
                        agreement = []
                        for comparison in record["replay"]["comparisons"]:
                            judgment = judgments.get(comparison["probe_id"], {})
                            known = (
                                record["replay"].get("input_integrity_verified") is True
                                and record["audit"].get("source_files_unchanged") is True
                                and comparison["status"] == "observed_comparison"
                                and judgment.get("status") == "valid"
                                and comparison["probe_binding_sha256"] == judgment.get("binding_sha256")
                            )
                            predicted = judgment.get("judgment", {}).get("would_call_anyway") if known else None
                            observed = comparison.get("intervention_exact_sink_proposed")
                            agreement.append(
                                {
                                    "probe_id": comparison["probe_id"],
                                    "source_ids": comparison.get("source_ids"),
                                    "known": known,
                                    "predicted_call": predicted,
                                    "observed_call": observed,
                                    "agreement": predicted == observed if known else None,
                                }
                            )
                        record["prediction_concordance"] = agreement
        except (ValueError, KeyError, OSError, TypeError) as error:
            record.update(status="unknown", reason=type(error).__name__ + ": " + str(error)[:200])
        record["unknown_request_accounting"] = []
        for name in ("replay", "audit"):
            folder = output / slot["slot_id"] / name
            saved = folder / "summary.json"
            if record[name] is None and saved.is_file():
                try:
                    record[name] = json.loads(saved.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    pass
            if record[name] is None and folder.exists():
                record["unknown_request_accounting"].append(name)
        records.append(record)
        with (output / "slots.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        print(
            json.dumps({"slot_id": record["slot_id"], "status": record["status"], "reason": record["reason"]}),
            flush=True,
        )
    total = sum((r.get(name) or {}).get("request_count", 0) for r in records for name in ("replay", "audit"))
    unknown = [
        {"slot_id": r["slot_id"], "stages": r["unknown_request_accounting"]}
        for r in records
        if r["unknown_request_accounting"]
    ]
    summary = {
        "protocol": PROTOCOL,
        "real_llm": live,
        "selected": sum(r["status"] == "selected" for r in records),
        "candidate_count": len(selection),
        "model_requests": None if unknown else total,
        "known_model_requests": total,
        "unknown_request_accounting": unknown,
        "request_ceiling": ceiling,
        "slots": records,
        "scope": (
            "Forced diagnostic replays and judgments; the baseline method plans none of these probes. "
            "No causal accuracy claim."
        ),
    }
    if total > ceiling:
        raise ValueError("Follow-up model-request ceiling exceeded")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "manifest.json").write_text(
        json.dumps(
            {
                p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(output.rglob("*"))
                if p.is_file()
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    result = run(args.batch, args.output, live=args.live)
    print(json.dumps({k: v for k, v in result.items() if k != "slots"}))
