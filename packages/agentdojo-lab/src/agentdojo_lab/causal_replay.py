"""Bounded one-step primary-model replays of verified v2 source interventions.

Replay preserves the original request settings and advertised tools, but never
executes a returned tool call. CLI requests require --live; an injected client
explicitly enables transport for offline tests. No additional prompt is inserted.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import time
import tomllib
from collections import Counter
from pathlib import Path

from agentdojo_lab.causal_v2_audit import (
    MAX_REQUEST_BYTES,
    _client_config,
    _new_client,
    _snapshot,
    _usage,
    _validate_export,
)
from agentdojo_lab.counterfactual import _canonical, _hash
from agentdojo_lab.counterfactual_audit import _contains_cjk, _verified_inputs
from agentdojo_lab.evaluation_review import _local, _strict
from agentdojo_lab.providers import EndpointSettings

PROTOCOL = "observed-one-step-source-replay-v1"
OPENAI_COMPATIBLE_PROTOCOL = "observed-one-step-source-replay-openai-compatible-v1"
SCOPE = (
    "Observed next-step model proposals under recorded and neutralized prefixes; no tool execution, "
    "whole-task outcomes, hidden-history access, causal ground truth or calibrated causality."
)
MAX_REQUESTS = 8
REQUEST_KEYS = {
    "model",
    "messages",
    "tools",
    "tool_choice",
    "temperature",
    "max_completion_tokens",
    "reasoning_effort",
    "parallel_tool_calls",
    "seed",
    "top_p",
    "stop",
    "frequency_penalty",
    "presence_penalty",
    "response_format",
    "n",
}
DEPENDENCIES = (
    "causal_replay.py",
    "causal_v2_audit.py",
    "causal_v2.py",
    "counterfactual.py",
    "counterfactual_audit.py",
    "evaluation_review.py",
    "inspection.py",
    "profiles.py",
    "pacing.py",
    "providers.py",
    "runner.py",
)


def _implementation_hashes():
    return {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in DEPENDENCIES
    }


def _original_request(event, probe):
    body = event["data"]["body"]
    if (
        event.get("event_type") != "MODEL_REQUEST"
        or not isinstance(body, dict)
        or set(body) - REQUEST_KEYS
        or body.get("messages") != probe["context_a"]
        or not isinstance(body.get("model"), str)
        or not body["model"].strip()
        or type(body.get("max_completion_tokens")) is not int
        or not 1 <= body["max_completion_tokens"] <= 65536
        or type(body.get("temperature")) not in (int, float)
        or not 0 <= body["temperature"] <= 2
        or ("n" in body and (type(body["n"]) is not int or body["n"] != 1))
        or ("reasoning_effort" in body and body["reasoning_effort"] not in ("low", "medium", "high"))
        or not isinstance(body.get("tools"), list)
    ):
        raise ValueError("Unsupported or mismatched recorded primary request")
    functions = []
    for tool in body["tools"]:
        if (
            not isinstance(tool, dict)
            or tool.get("type") != "function"
            or not isinstance(tool.get("function"), dict)
        ):
            raise ValueError("Only recorded function-tool schemas are supported")
        functions.append(tool["function"].get("name"))
    if probe["sink"]["function"] not in functions:
        raise ValueError("Recorded sink is absent from the original advertised tools")
    if _contains_cjk(_canonical(body).decode()):
        raise ValueError("Non-English recorded requests cannot enter English replay artifacts")
    return copy.deepcopy(body)


def _replay_slots(plans, source, *, protocol=PROTOCOL):
    """Bind every request body to a verified event, analysis line and flush receipt."""
    calls, _ = _verified_inputs(source)
    by_id = {call["proposal_event_id"]: call for call in calls}
    events = {
        row["event_id"]: row
        for row in (
            _strict(raw) for raw in (source / "events.jsonl").read_bytes().splitlines() if raw.strip()
        )
    }
    raw_rows = (source / "provenance.jsonl").read_bytes().splitlines(keepends=True)
    rows = [_strict(raw) for raw in raw_rows]
    analyses = {
        row["proposal_event_id"]: (row, raw)
        for row, raw in zip(rows, raw_rows, strict=True)
        if row["record_type"] == "call_analysis"
    }
    flushes = {row["analysis_record_sequence"]: row for row in rows if row["record_type"] == "analysis_flush"}
    slots = []
    for plan in sorted(plans, key=lambda p: by_id[p["proposal_event_id"]]["proposal_sequence"]):
        if not plan["probes"]:
            continue
        call = by_id[plan["proposal_event_id"]]
        first = plan["probes"][0]
        request = events[call["request_event_id"]]
        original = _original_request(request, first)
        analysis, raw = analyses[call["proposal_event_id"]]
        flush = flushes[analysis["record_sequence"]]
        common = {
            "protocol": protocol,
            "proposal_event_id": call["proposal_event_id"],
            "call_binding": first["call_binding"],
            "sink": first["sink"],
            "original_request_sha256": _hash(original),
            "original_request_event_sha256": _hash(request),
            "analysis_line_sha256": hashlib.sha256(raw).hexdigest(),
            "analysis_flush_sha256": _hash(flush),
            "plan_sha256": _hash(plan),
        }
        baseline = {
            **common,
            "condition": "context_a",
            "probe_id": None,
            "probe_binding_sha256": None,
            "source_ids": [],
            "covered_probe_ids": [probe["probe_id"] for probe in plan["probes"]],
            "body": original,
        }
        group = [baseline]
        for probe in plan["probes"]:
            if (
                probe["context_a"] != first["context_a"]
                or probe["sink"] != first["sink"]
                or probe["call_binding"] != first["call_binding"]
            ):
                raise ValueError("Proposal probes do not share the exact original prefix and sink")
            body = copy.deepcopy(original)
            body["messages"] = copy.deepcopy(probe["context_b"])
            group.append(
                {
                    **common,
                    "condition": "context_b",
                    "probe_id": probe["probe_id"],
                    "probe_binding_sha256": probe["binding_sha256"],
                    "source_ids": probe["source_ids"],
                    "intervention_kind": probe["kind"],
                    "body": body,
                }
            )
        for slot in group:
            slot["request_body_sha256"] = _hash(slot["body"])
            slot["binding_sha256"] = _hash(slot)
            slot["slot_id"] = "replay:" + slot["binding_sha256"]
        slots.extend(group)
    return slots


def classify_response(response, sink):
    """A valid response says only what the next step proposed, never what executed."""
    unknown = {"status": "invalid", "exact_sink_proposed": None, "response_kind": "unknown"}
    try:
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            return {**unknown, "reason": "ambiguous_response_choices"}
        choice = choices[0]
        if choice.get("finish_reason") == "length":
            return {**unknown, "reason": "truncated_response"}
        if choice.get("finish_reason") not in ("stop", "tool_calls"):
            return {**unknown, "reason": "unsupported_finish_reason"}
        message = choice["message"]
        if message.get("role") != "assistant" or message.get("function_call"):
            return {**unknown, "reason": "invalid_or_legacy_assistant_response"}
        calls = message.get("tool_calls")
        if calls is not None and not isinstance(calls, list):
            return {**unknown, "reason": "invalid_tool_call_inventory"}
        if calls:
            if not isinstance(calls, list) or len(calls) > 128:
                return {**unknown, "reason": "invalid_tool_call_inventory"}
            proposed, identifiers = [], set()
            for call in calls:
                if (
                    call.get("type") != "function"
                    or not isinstance(call.get("id"), str)
                    or not call["id"]
                    or call["id"] in identifiers
                ):
                    return {**unknown, "reason": "invalid_or_duplicate_tool_call"}
                identifiers.add(call["id"])
                function = call["function"]
                if (
                    not isinstance(function.get("name"), str)
                    or not function["name"]
                    or not isinstance(function.get("arguments"), str)
                ):
                    return {**unknown, "reason": "invalid_function_proposal"}
                arguments = _strict(function["arguments"].encode())
                if not isinstance(arguments, dict):
                    return {**unknown, "reason": "non_object_tool_arguments"}
                proposed.append({"function": function["name"], "arguments": arguments})
            matches = sum(_canonical(value) == _canonical(sink) for value in proposed)
            return {
                "status": "observed",
                "reason": None,
                "response_kind": "tool_proposal",
                "exact_sink_proposed": matches > 0,
                "matching_proposal_count": matches,
                "tool_proposal_count": len(proposed),
                "proposed_calls": proposed,
                "only_exact_sink_proposed": matches == len(proposed),
            }
        if choice.get("finish_reason") != "stop":
            return {**unknown, "reason": "tool_finish_without_proposals"}
        content = message.get("content")
        refusal = message.get("refusal")
        if not (isinstance(content, str) and content.strip()) and not (
            isinstance(refusal, str) and refusal.strip()
        ):
            return {**unknown, "reason": "empty_final_response"}
        return {
            "status": "observed",
            "reason": None,
            "response_kind": "final_refusal" if refusal else "final_response",
            "exact_sink_proposed": False,
            "matching_proposal_count": 0,
            "tool_proposal_count": 0,
            "proposed_calls": [],
            "only_exact_sink_proposed": False,
        }
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return {**unknown, "reason": "malformed_response_or_arguments"}


def _comparisons(results, inputs_unchanged):
    baselines = {row["proposal_event_id"]: row for row in results if row["condition"] == "context_a"}
    comparisons = []
    for row in results:
        if row["condition"] != "context_b":
            continue
        base = baselines[row["proposal_event_id"]]
        observed = inputs_unchanged and base["status"] == row["status"] == "observed"
        reproduced = base["exact_sink_proposed"] if observed else None
        comparisons.append(
            {
                "proposal_event_id": row["proposal_event_id"],
                "probe_id": row["probe_id"],
                "probe_binding_sha256": row["probe_binding_sha256"],
                "baseline_slot_id": base["slot_id"],
                "intervention_slot_id": row["slot_id"],
                "baseline_reproduced_original_sink": reproduced,
                "intervention_exact_sink_proposed": row["exact_sink_proposed"] if observed else None,
                "observed_sink_proposal_changed": (not row["exact_sink_proposed"]) if reproduced else None,
                "status": "observed_comparison"
                if reproduced
                else "baseline_not_reproduced"
                if observed
                else "unknown",
                "scope": "One observed next step per prefix; no causal reference labels or tool execution",
            }
        )
    return comparisons


def run_replay(
    plans_dir: Path, output: Path, *, client=None, live=False, max_requests=8, pacer=None,
    endpoint=None,
):
    """Execute one baseline per proposal and frozen interventions, up to eight SDK attempts."""
    if type(live) is not bool or type(max_requests) is not int or not 0 <= max_requests <= MAX_REQUESTS:
        raise ValueError("Replay permits a total of zero through eight SDK requests")
    if endpoint is not None and client is not None:
        raise ValueError("An explicit endpoint cannot be combined with an injected client")
    if endpoint is not None:
        endpoint = EndpointSettings.model_validate(endpoint)
        if endpoint.provider != "openai_compatible":
            raise ValueError("The configured replay protocol requires an openai_compatible endpoint")
        if not live:
            raise ValueError("An explicit endpoint requires --live")
        if pacer is not None:
            raise ValueError("Local endpoint replay does not use Groq pacing state")
        endpoint_key = endpoint.require_key()
    else:
        endpoint_key = None
    folder, output = _local(plans_dir), _local(output)
    plans, source, export_before, source_before, _ = _validate_export(folder)
    if live and client is None and endpoint is None:
        from agentdojo_lab.providers import reject_implicit_groq_audit

        reject_implicit_groq_audit(source)
    for tree in (folder, source):
        if output.exists() or output.is_relative_to(tree) or tree.is_relative_to(output):
            raise ValueError("Use a fresh replay output separate from both input trees")
    if client is not None:
        _client_config(client)
    if pacer is not None and getattr(pacer, "path", None) is not None:
        path = _local(Path(pacer.path))
        if any(path.is_relative_to(tree) or tree.is_relative_to(path) for tree in (folder, source)):
            raise ValueError("Pacing state must be separate from input artifacts")
    protocol = OPENAI_COMPATIBLE_PROTOCOL if endpoint is not None else PROTOCOL
    slots = _replay_slots(plans, source, protocol=protocol)
    if endpoint is not None and any(slot["body"]["model"] != endpoint.model for slot in slots):
        raise ValueError("Endpoint model does not match the recorded primary request model")
    if _snapshot(source) != source_before or _snapshot(folder) != export_before:
        raise ValueError("Input artifacts changed while preparing replay slots")
    implementation = _implementation_hashes()
    output.mkdir(parents=True)
    (output / "plans.jsonl").write_bytes((folder / "plans.jsonl").read_bytes())
    (output / "replay-plan.jsonl").write_bytes(b"".join(_canonical(slot) + b"\n" for slot in slots))
    mode = (
        "live_openai_compatible" if endpoint is not None
        else "injected_client" if client is not None
        else "live_groq" if live else "plan_only"
    )
    manifest = {
        "schema_version": 1,
        "protocol": protocol,
        "scope": SCOPE,
        "mode": mode,
        **({"provider": endpoint.provider} if endpoint is not None else {}),
        **({"endpoint": endpoint.model_dump()} if endpoint is not None else {}),
        "source_run": str(source),
        "plan_export": str(folder),
        "planned_slots": len(slots),
        "max_requests": max_requests,
        "sdk_max_retries": 0,
        "request_timeout_seconds": 60,
        "max_request_bytes": MAX_REQUEST_BYTES,
        "implementation_hashes": implementation,
        "source_hashes_before": source_before,
        "plan_export_hashes_before": export_before,
        "request_policy": "Original body preserved exactly; only context_b messages replaced; no added instruction",
        "ordering": "Chronological proposals, one original baseline then each frozen intervention",
        "native_tool_calls": 0,
        "pacing_enabled": pacer is not None,
    }
    (output / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
    started = time.monotonic()
    request_count, results, changed, owned_client = 0, [], False, False

    def unchanged():
        try:
            return (
                _snapshot(source) == source_before
                and _snapshot(folder) == export_before
                and _implementation_hashes() == implementation
            )
        except (OSError, ValueError):
            return False

    try:
        with (
            (output / "results.jsonl").open("xb") as result_file,
            (output / "requests.jsonl").open("xb") as request_file,
        ):
            for ordinal, slot in enumerate(slots, 1):
                row = {key: value for key, value in slot.items() if key != "body"}
                row.update(
                    status="not_run",
                    reason=None,
                    request_attempted=False,
                    exact_sink_proposed=None,
                    response_kind="unknown",
                    usage={},
                )
                changed = changed or not unchanged()
                body = slot["body"]
                if changed:
                    row["reason"] = "source_export_or_implementation_changed"
                elif not (live or client is not None):
                    row["reason"] = "live_not_enabled"
                elif request_count >= max_requests:
                    row["reason"] = "request_budget_exhausted"
                elif len(_canonical(body)) > MAX_REQUEST_BYTES:
                    row["reason"] = "request_size_budget_exceeded"
                else:
                    tick, ticket = time.monotonic(), None
                    try:
                        if pacer is not None:
                            ticket, waited = pacer.before_request(
                                copy.deepcopy(body["messages"]), copy.deepcopy(body.get("tools", []))
                            )
                            row["pacing_wait_seconds"] = waited
                        if not unchanged():
                            changed = True
                            row["reason"] = "source_export_or_implementation_changed"
                        else:
                            if client is None:
                                client = (
                                    endpoint.client(key=endpoint_key, timeout=60.0)
                                    if endpoint is not None else _new_client()
                                )
                                owned_client = True
                                _client_config(client)
                            request_file.write(
                                _canonical(
                                    {
                                        "slot_id": slot["slot_id"],
                                        "binding_sha256": slot["binding_sha256"],
                                        "body": body,
                                        "body_sha256": slot["request_body_sha256"],
                                    }
                                )
                                + b"\n"
                            )
                            request_file.flush()
                            request_count += 1
                            row["request_attempted"] = True
                            response = client.chat.completions.create(**body, timeout=60.0).model_dump(
                                mode="json"
                            )
                            encoded = _canonical(response)
                            key = getattr(client, "api_key", "")
                            if isinstance(key, str) and key:
                                encoded = encoded.replace(key.encode(), b"[REDACTED]")
                                response = _strict(encoded)
                            row["response_sha256"] = hashlib.sha256(encoded).hexdigest()
                            row["response_hash_scope"] = "SDK model_dump after API-key redaction"
                            row["usage"] = (
                                response.get("usage") if isinstance(response.get("usage"), dict) else {}
                            )
                            response_model = response.get("model")
                            if endpoint is not None and (
                                not isinstance(response_model, str) or not response_model.strip()
                            ):
                                row.update(
                                    status="invalid", reason="missing_or_invalid_response_model"
                                )
                            elif endpoint is not None and response_model != body["model"]:
                                row.update(status="invalid", reason="response_model_mismatch")
                            elif _contains_cjk(encoded.decode()):
                                name = f"response-{ordinal:04d}.bin"
                                (output / name).write_bytes(encoded)
                                row.update(
                                    status="invalid", reason="non_english_response", response_file=name
                                )
                            else:
                                row["response"] = response
                                row.update(classify_response(response, slot["sink"]))
                            if pacer is not None:
                                try:
                                    pacer.after_response(ticket, row["usage"].get("total_tokens"))
                                except Exception as error:
                                    row["pacing_update_error_type"] = type(error).__name__
                    except Exception as error:
                        row.update(
                            status="error",
                            reason="request_or_response_failed",
                            error_type=type(error).__name__,
                        )
                    row["elapsed_seconds"] = time.monotonic() - tick
                result_file.write(_canonical(row) + b"\n")
                result_file.flush()
                results.append(row)
    finally:
        if owned_client:
            client.close()
    changed = changed or not unchanged()
    summary = {
        "schema_version": 1,
        "protocol": protocol,
        "scope": SCOPE,
        "mode": mode,
        **({"provider": endpoint.provider} if endpoint is not None else {}),
        **({"endpoint": endpoint.model_dump()} if endpoint is not None else {}),
        "planned_slots": len(slots),
        "result_slots": len(results),
        "request_count": request_count,
        "request_count_scope": "SDK invocation attempts including failures, with zero SDK retries",
        "observed_slots": sum(row["status"] == "observed" for row in results),
        "unknown_slots": sum(row["status"] != "observed" for row in results),
        "status_counts": dict(Counter(row["status"] for row in results)),
        "reported_usage": _usage([row for row in results if row["request_attempted"]]),
        "usage_scope": "Returned API usage only; missing usage and provider billing are not estimated",
        "elapsed_seconds": time.monotonic() - started,
        "timing_scope": "Replay after preflight, including optional pacing; separate from primary trajectory",
        "native_tool_calls": 0,
        "original_primary_run_writes": 0,
        "independent_causal_accuracy": None,
        "source_hashes_before": source_before,
        "plan_export_hashes_before": export_before,
        "implementation_hashes_before": implementation,
    }

    def finalize():
        try:
            source_after, export_after = _snapshot(source), _snapshot(folder)
            implementation_after = _implementation_hashes()
        except (OSError, ValueError):
            source_after, export_after, implementation_after = {}, {}, {}
        stable = (
            not changed
            and source_after == source_before
            and export_after == export_before
            and implementation_after == implementation
        )
        summary.update(
            source_files_unchanged=source_after == source_before,
            plan_export_unchanged=export_after == export_before,
            implementation_unchanged=implementation_after == implementation,
            input_integrity_verified=stable,
            source_hashes_after=source_after,
            plan_export_hashes_after=export_after,
            implementation_hashes_after=implementation_after,
            comparisons=_comparisons(results, stable),
        )
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        _report(output, summary, results)

    finalize()
    if not unchanged():
        changed = True
        finalize()
    return summary


def _report(output, summary, results):
    esc = html.escape
    rows = "".join(
        f"<tr><td>{esc(row['condition'])}</td><td>{esc(row['status'])}</td><td>{esc(str(row['exact_sink_proposed']))}</td><td>{esc(str(row['reason'] or row['response_kind']))}</td></tr>"
        for row in results
    )
    body = f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Observed one-step source replay</title><style>body{{max-width:1000px;margin:30px auto;padding:20px;font:16px/1.5 system-ui}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}summary{{cursor:pointer}}</style><h1>Observed one-step source replay</h1><p>{summary["planned_slots"]} planned slots; {summary["request_count"]} SDK attempts; {summary["observed_slots"]} observed responses; {summary["unknown_slots"]} unknown slots.</p><p>{esc(SCOPE)}</p><p>Input integrity verified: {summary["input_integrity_verified"]}.</p><details><summary>Next-step results</summary><table><tr><th>Context</th><th>Status</th><th>Exact sink proposed</th><th>Observation</th></tr>{rows}</table></details><details><summary>Bound comparisons and limits</summary><pre>{esc(json.dumps(summary["comparisons"], indent=2))}</pre></details><p><a href="summary.json">Summary</a> · <a href="results.jsonl">Every result slot</a> · <a href="replay-plan.jsonl">Bound requests</a> · <a href="manifest.json">Protocol</a></p></html>'
    (output / "index.html").write_text(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-requests", type=int, default=8)
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--endpoint-config", type=Path,
        help="Credential-free OpenAI-compatible endpoint TOML; requires --live",
    )
    parser.add_argument("--pacing-state", type=Path)
    args = parser.parse_args()
    pacer = None
    if args.pacing_state is not None:
        from agentdojo_lab.pacing import RequestPacer

        pacer = RequestPacer(7000, args.pacing_state)
    endpoint = (
        EndpointSettings.model_validate(tomllib.loads(args.endpoint_config.read_text()))
        if args.endpoint_config is not None else None
    )
    if endpoint is not None and args.pacing_state is not None:
        raise ValueError("Local endpoint replay does not use Groq pacing state")
    result = run_replay(
        args.plans, args.output, live=args.live, max_requests=args.max_requests, pacer=pacer,
        endpoint=endpoint,
    )
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "mode",
                    "planned_slots",
                    "request_count",
                    "observed_slots",
                    "unknown_slots",
                    "input_integrity_verified",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
