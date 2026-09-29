"""Bind optional lexical region measurements to verified saved proposal prefixes."""

from __future__ import annotations

from pathlib import Path

from agentdojo_lab.evaluation_analysis import _read_bytes
from agentdojo_lab.evaluation_review import _canonical, _local, _sha, _strict
from agentdojo_lab.evaluation_runner import EvaluationTrial, InputComparisonTrial, payload_exposure_audit
from agentdojo_lab.heldout_runner import HeldoutTrial
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker, _text
from agentdojo_lab.runner import RunConfig
from agentdojo_lab.span_evidence import analyze_span_evidence
from agentdojo_lab.span_scalars import decode_span_scalars

FILES = ("manifest.json", "summary.json", "events.jsonl", "provenance.jsonl")
MAX_COMPARISONS = 4096
MAX_RUN_LENGTH_PRODUCT = 20_000_000
CALL_KEYS = (
    "run_id",
    "task_id",
    "episode_id",
    "proposal_event_id",
    "proposal_sequence",
    "model_request_id",
    "request_event_id",
    "request_sequence",
    "cutoff_event_id",
    "function",
    "arguments",
    "request_messages",
)
SOURCE_KEYS = (
    "source_id",
    "source_event_id",
    "kind",
    "text",
    "text_sha256",
    "message_index",
    "request_pointer",
    "exposure_event_id",
    "policy",
    "origin_tool",
    "canary",
)


def _require(value, message):
    if not value:
        raise ValueError(message)


def _project(value, keys):
    return {key: value.get(key) for key in keys}


def _jsonl(raw):
    rows = [_strict(line) for line in raw.splitlines() if line.strip()]
    _require(len(rows) <= 100_000 and all(isinstance(row, dict) for row in rows), "Invalid row inventory")
    return rows


def _baseline(pair):
    """Retain recorded metrics, with a digest linking the full immutable pair.

    Encoder paths/metadata are not replicated per scalar. Nothing is re-scored
    as a semantic result, and downstream native outcomes do not label a field.
    """
    return {
        "recorded_pair_sha256": _sha(_canonical(pair)),
        **_project(
            pair,
            (
                "source_id",
                "request_pointer",
                "status",
                "matched",
                "complete",
                "truncated",
                "first_matched_tier",
                "source_length",
                "target_length",
            ),
        ),
        "stages": {
            name: _project(
                stage,
                ("status", "matched", "score", "lcs_length", "threshold", "complete", "truncated", "reason"),
            )
            for name, stage in pair.get("stages", {}).items()
        },
    }


def _verify_call(call, saved, wrapper):
    _require(
        _canonical(_project(call, CALL_KEYS)) == _canonical(_project(saved, CALL_KEYS)),
        "Saved proposal or request identity differs from reconstructed prefix",
    )
    for key in ("run_id", "task_id", "episode_id", "proposal_event_id", "model_request_id"):
        _require(wrapper.get(key) == call[key], "Sidecar wrapper identity mismatch")
    _require(
        _canonical([_project(s, SOURCE_KEYS) for s in call["visible_sources"]])
        == _canonical([_project(s, SOURCE_KEYS) for s in saved["visible_sources"]]),
        "Saved visible sources differ from reconstructed prefix",
    )
    keys = ("item_id", "argument_path", "value")
    _require(
        _canonical([_project(f, keys) for f in call["fields"]])
        == _canonical([_project(f, keys) for f in saved["fields"]]),
        "Saved field binding mismatch",
    )
    for field, original in zip(call["fields"], saved["fields"], strict=True):
        _require(field["cascade_scope"] == original["cascade_scope"], "Saved source/sink scope mismatch")


def _source_rows(call, field, original, occurrences, payload, budget):
    rows = []
    pairs = original["nt_style_cascade"]
    expected = [
        (s["source_id"], s["request_pointer"]) for s in call["visible_sources"] if s["policy"]["eligible"]
    ]
    actual = [(p["source_id"], p["request_pointer"]) for p in pairs]
    _require(expected == actual, "Saved baseline pair inventory mismatch")
    for source in call["visible_sources"]:
        if source["kind"] != "tool" or not source["policy"]["eligible"]:
            continue
        pair = next(
            p
            for p in pairs
            if (p["source_id"], p["request_pointer"]) == (source["source_id"], source["request_pointer"])
        )
        _require(
            pair["source_event_id"] == source["source_event_id"]
            and pair["exposure_event_id"] == source["exposure_event_id"]
            and pair["source_length"] == len(source["text"])
            and pair["target_length"] == len(field["target"]),
            "Saved baseline source binding mismatch",
        )
        base = {
            **_project(source, ("source_id", "source_event_id", "exposure_event_id", "request_pointer")),
            "original_source_cascade": _baseline(pair),
        }
        parsed = decode_span_scalars(source["text"])
        relevant = [
            o
            for o in occurrences
            if (
                o["request_event_id"],
                o["model_request_id"],
                o["source_result_event_id"],
                o["exposure_event_id"],
                o["request_pointer"],
                o["message_index"],
            )
            == (
                call["request_event_id"],
                call["model_request_id"],
                source["source_event_id"],
                source["exposure_event_id"],
                source["request_pointer"],
                source["message_index"],
            )
        ]
        if not parsed["complete"]:
            rows.append(
                {
                    **base,
                    "status": "unavailable",
                    "reason": parsed["reason"],
                    "decode_status": parsed["status"],
                    "scalar_pointer": None,
                    "source_text": None,
                    "injection_spans": None,
                    "evidence": None,
                }
            )
            continue
        pointers = {s["scalar_pointer"]: s for s in parsed["scalars"]}
        for occurrence in relevant:
            scalar = pointers.get(occurrence["scalar_pointer"])
            _require(scalar is not None, "Exposure scalar is absent from decoded source")
            span = occurrence["scalar_span"]
            _require(
                occurrence["wire_content_sha256"] == source["text_sha256"]
                and occurrence["scalar_sha256"] == scalar["decoded_sha256"]
                and scalar["decoded_text"][span[0] : span[1]] == payload,
                "Exposure scalar hash or range mismatch",
            )
        for scalar in parsed["scalars"]:
            regions = sorted(
                [o["scalar_span"] for o in relevant if o["scalar_pointer"] == scalar["scalar_pointer"]]
            )
            row = {
                **base,
                "scalar_pointer": scalar["scalar_pointer"],
                "source_text": scalar["decoded_text"],
                "source_text_sha256": scalar["decoded_sha256"],
                "injection_spans": regions,
                "wire_span": scalar["wire_span"],
                "wire_token_sha256": scalar["wire_token_sha256"],
                "decode_status": parsed["status"],
                "decode_mode": scalar["decode_mode"],
                "status": "scored",
                "reason": None,
            }
            product = len(scalar["decoded_text"]) * len(field["target"])
            if (
                budget["comparisons"] >= MAX_COMPARISONS
                or product + budget["length_product"] > MAX_RUN_LENGTH_PRODUCT
            ):
                row.update(status="unavailable", reason="run_comparison_budget", evidence=None)
            else:
                budget["comparisons"] += 1
                budget["length_product"] += product
                row["evidence"] = analyze_span_evidence(scalar["decoded_text"], field["target"], regions)
                row["status"] = row["evidence"]["status"]
            rows.append(row)
    return rows


def analyze_span_run(run: Path) -> dict:
    """Return explicit unavailable evidence for unsupported/inconsistent recordings.

    This version accepts complete frozen task29 and named task8 held-out recordings.
    It validates actual event prefixes, never treats native outcomes as attribution
    labels, and does not construct an SDK client, encoder, or counterfactual judge.
    """
    run = _local(run)
    result = {
        "schema_version": 1,
        "method": "decoded_scalar_span_evidence_v1",
        "status": "unavailable",
        "run_dir": str(run),
        "fields": [],
        "reason": None,
        "input_condition": None,
        "condition": None,
        "source_hashes_before": {},
        "source_hashes_after": {},
        "source_unchanged": None,
    }
    try:
        raw = {name: _read_bytes(_local(run / name)) for name in FILES}
        result["source_hashes_before"] = {name: _sha(value) for name, value in raw.items()}
        manifest, summary = _strict(raw["manifest.json"]), _strict(raw["summary.json"])
        spec_data = manifest["evaluation"]
        spec_type = {
            None: EvaluationTrial,
            "native-injected-input-comparison-v1": InputComparisonTrial,
            "native-heldout-passive-v1": HeldoutTrial,
        }.get(spec_data.get("protocol"))
        _require(spec_type is not None, "Unsupported saved evaluation protocol")
        spec = spec_type.model_validate(spec_data)
        config = RunConfig.model_validate(manifest["config"])
        expected_canary = (
            spec.input_condition == "canary"
            if isinstance(spec, (InputComparisonTrial, HeldoutTrial))
            else True
        )
        _require(
            config.suite == "workspace"
            and config.benchmark_version == "v1.2.2"
            and config.user_tasks == [spec.user_task_id]
            and config.canary_enabled is expected_canary
            and config.record_events
            and config.online_provenance,
            "Unsupported frozen run configuration",
        )
        expected_condition = "canary_intervention" if expected_canary else "passive"
        _require(manifest["input_condition"] == expected_condition, "Input condition mismatch")
        _require(
            manifest["attack"]["injection_assigned"] is (spec.condition == "injected"),
            "Injection assignment mismatch",
        )
        result.update(condition=spec.condition, input_condition=expected_condition)
        _require(
            summary["recording"]["complete"] is True and summary["online_provenance"]["complete"] is True,
            "Incomplete recording or online sidecar",
        )
        inspection = inspect_events(run / "events.jsonl")
        _require(inspection["valid"], "Event integrity check failed")
        audit = payload_exposure_audit(run / "events.jsonl", spec)
        _require(audit["complete"], "Payload exposure audit incomplete")
        snapshot = manifest["online_provenance"]["policy"]
        policy = ToolPolicy.from_dict(snapshot["document"])
        _require(policy.metadata["sha256"] == snapshot["sha256"], "Frozen policy digest mismatch")
        policy.validate_context(config.suite, config.benchmark_version)
        tracker = ProvenanceTracker(policy=policy, canary_enabled=expected_canary)
        saved = {}
        for row in _jsonl(raw["provenance.jsonl"]):
            if row.get("record_type") == "call_analysis":
                key = row["proposal_event_id"]
                _require(key not in saved, "Duplicate saved proposal")
                saved[key] = row
        fields, seen = [], set()
        budget = {"comparisons": 0, "length_product": 0}
        for event in _jsonl(raw["events.jsonl"]):
            call = tracker.consume(event)
            if call is None:
                continue
            key = call["proposal_event_id"]
            _require(key in saved, "Missing saved proposal")
            wrapper = saved[key]
            _verify_call(call, wrapper["call"], wrapper)
            seen.add(key)
            for field, original in zip(call["fields"], wrapper["call"]["fields"], strict=True):
                selected = field["cascade_scope"]["sink"]["selected"]
                value = field["value"]
                target = _text(value)
                item = {
                    "item_id": field["item_id"],
                    "function": call["function"],
                    "argument_path": field["argument_path"],
                    "target": target,
                    "target_value": value,
                    "proposal_sequence": call["proposal_sequence"],
                    "model_request_id": call["model_request_id"],
                    "proposal_event_id": key,
                    "policy_selected": selected,
                    "status": "complete" if selected else "not_selected",
                    "sources": [],
                }
                if selected and target is None:
                    item.update(status="unavailable", reason="non_scalar_argument")
                elif selected:
                    item["sources"] = _source_rows(
                        call, item, original, audit["occurrences"], spec.payload, budget
                    )
                    if any(s["status"] not in ("scored", "not_applicable") for s in item["sources"]):
                        item["status"] = "partial"
                    elif not item["sources"]:
                        item.update(status="not_applicable", reason="no_eligible_value_scalar")
                fields.append(item)
        _require(seen == set(saved), "Saved proposal is absent from events")
        result.update(
            status="complete",
            fields=fields,
            counts=budget,
            validation={
                "verified_proposals": len(seen),
                "event_integrity": True,
                "payload_exposure_complete": True,
                "prefix_bindings": True,
            },
            limits={"max_comparisons": MAX_COMPARISONS, "max_run_length_product": MAX_RUN_LENGTH_PRODUCT},
        )
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as error:
        # Do not return partially trusted fields after a binding/integrity error.
        result.update(status="unavailable", fields=[], reason=f"{type(error).__name__}: {error}")
    finally:
        try:
            result["source_hashes_after"] = {name: _sha(_read_bytes(_local(run / name))) for name in FILES}
            result["source_unchanged"] = result["source_hashes_before"] == result["source_hashes_after"]
        except (OSError, ValueError):
            result["source_unchanged"] = False
        if result["source_unchanged"] is not True:
            result.update(status="unavailable", fields=[], reason="Source inventory incomplete or changed")
    return result
