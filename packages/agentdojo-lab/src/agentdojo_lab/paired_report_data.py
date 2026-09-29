"""Presentation data for inspecting saved paired traces without executing either run.

Event IDs identify events within one arm only. The display alignment follows
the existing proposal alignment and recorded request/call bindings; it does not
establish that a source caused an action or repair missing evidence.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from difflib import SequenceMatcher

PHASES = {
    "RUN_STARTED": "setup",
    "EPISODE_STARTED": "setup",
    "MODEL_REQUEST": "request",
    "TOOL_OUTPUT_EXPOSED": "source",
    "MODEL_RESPONSE": "response",
    "MODEL_PARSED": "response",
    "TOOL_CALL_PROPOSED": "action",
    "TOOL_RUNTIME_STARTED": "execution",
    "TOOL_RUNTIME_RETURNED": "execution",
    "TOOL_RESULT": "source",
    "ENVIRONMENT_CHANGE": "state",
    "EPISODE_ENDED": "finish",
    "RUN_END": "finish",
}


def _changes(before, after):
    # Lazy import keeps the report renderer free to import this presentation module.
    from agentdojo_lab.paired_report import json_changes

    return [
        {
            **change,
            "kind": "added"
            if not change["before_present"]
            else "removed"
            if not change["after_present"]
            else "changed",
        }
        for change in json_changes(before, after)
    ]


def _text(value):
    """Readable content without interpreting embedded HTML or instructions."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        if all("content" in item or "text" in item for item in value):
            return "\n\n".join(_text(item.get("content", item.get("text"))) for item in value)
    return json.dumps(value, ensure_ascii=False, indent=2)


def _short(value, limit=170):
    text = " ".join(_text(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _function(event, proposals):
    data = event.get("data") or {}
    message = data.get("message") or {}
    return (
        data.get("function")
        or (message.get("tool_call") or {}).get("function")
        or proposals.get(event.get("call_ref"), {}).get("data", {}).get("function")
    )


def _presentation_fields(event):
    """Separate known transport identifiers from displayed content comparisons.

    Only declared recorder/transport locations are removed. Business values such
    as a document's ``id`` or timestamp remain content, even if they differ.
    """
    data = copy.deepcopy(event.get("data"))
    metadata = {key: value for key, value in event.items() if key != "data"}
    metadata["transport_fields"] = {}
    neutral = metadata["transport_fields"]
    if not isinstance(data, dict):
        return data, metadata

    def pop(container, key, path):
        if key in container:
            neutral[path + "/" + key] = container.pop(key)

    def message(item, path):
        if not isinstance(item, dict):
            return
        pop(item, "tool_call_id", path)
        call = item.get("tool_call")
        if isinstance(call, dict):
            pop(call, "id", path + "/tool_call")
        calls = item.get("tool_calls")
        if isinstance(calls, list):
            for index, tool in enumerate(calls):
                if not isinstance(tool, dict):
                    continue
                tool_path = f"{path}/tool_calls/{index}"
                pop(tool, "id", tool_path)
                function = tool.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    try:
                        parsed = json.loads(function["arguments"])
                    except (ValueError, TypeError):
                        continue
                    # Raw serialization stays available for exact-byte inspection.
                    neutral[tool_path + "/function/raw_arguments"] = function["arguments"]
                    function["arguments"] = parsed

    kind = event.get("event_type")
    if kind in {"MODEL_REQUEST", "MODEL_RESPONSE"}:
        for key in ("body_bytes", "body_sha256"):
            pop(data, key, "")
        body = data.get("body")
        if isinstance(body, dict):
            if kind == "MODEL_RESPONSE":
                for key in (
                    "id",
                    "created",
                    "usage",
                    "system_fingerprint",
                    "metrics",
                    "service_tier",
                    "prompt_logprobs",
                    "prompt_text",
                    "prompt_token_ids",
                    "ec_transfer_params",
                    "kv_transfer_params",
                ):
                    pop(body, key, "/body")
                for index, choice in enumerate(body.get("choices") or []):
                    if isinstance(choice, dict):
                        for key in ("logprobs", "routed_experts", "token_ids"):
                            pop(choice, key, f"/body/choices/{index}")
                        message(choice.get("message"), f"/body/choices/{index}/message")
            else:
                for index, item in enumerate(body.get("messages") or []):
                    message(item, f"/body/messages/{index}")
    if kind in {"TOOL_RESULT", "TOOL_OUTPUT_EXPOSED"}:
        message(data.get("message"), "/message")
        for key in ("source_result_event_id", "message_index"):
            pop(data, key, "")
    if kind == "TOOL_CALL_PROPOSED":
        pop(data, "call_index", "")
    if kind == "RUN_STARTED" and isinstance(data.get("config"), dict):
        pop(data["config"], "lineage_namespace", "/config")
    return data, metadata


def _description(event, function):
    data = event.get("data") or {}
    kind = event.get("event_type", "UNKNOWN")
    label = kind.replace("_", " ").capitalize()
    content = ""
    if kind == "TOOL_CALL_PROPOSED":
        label = f"Propose {function or 'tool'}"
        content = _text(data.get("arguments"))
    elif kind == "TOOL_RUNTIME_STARTED":
        label = f"Execute {function or 'tool'}"
        content = _text(data.get("runtime_input_args"))
    elif kind == "TOOL_RUNTIME_RETURNED":
        label = f"{function or 'Tool'} returned"
        content = _text(data.get("result"))
        if data.get("error") or data.get("raised_exception_type"):
            label += " with error"
            content += "\n" + _text(data.get("error") or data.get("raised_exception_type"))
    elif kind in {"TOOL_RESULT", "TOOL_OUTPUT_EXPOSED"}:
        label = f"{'Expose' if kind == 'TOOL_OUTPUT_EXPOSED' else 'Record'} {function or 'tool output'}"
        content = _text((data.get("message") or {}).get("content"))
    elif kind == "MODEL_RESPONSE":
        pieces = []
        for choice in (data.get("body") or {}).get("choices") or []:
            message = choice.get("message") or {}
            if message.get("content"):
                pieces.append(_text(message["content"]))
            for call in message.get("tool_calls") or []:
                function_data = call.get("function") or {}
                arguments = function_data.get("arguments")
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except ValueError:
                        pass
                pieces.append(f"{function_data.get('name', 'tool')}\n{_text(arguments)}")
        content = "\n\n".join(pieces)
        label = "Model response"
    elif kind == "MODEL_REQUEST":
        messages = (data.get("body") or {}).get("messages") or []
        label = f"Model request · {len(messages)} messages"
        user = [item for item in messages if item.get("role") == "user"]
        content = _text(user[-1].get("content")) if user else "No user message recorded."
    elif kind == "ENVIRONMENT_CHANGE":
        changes = _changes(data.get("before"), data.get("after"))
        label = f"State changed · {len(changes)} fields"
        content = "\n".join(
            f"{change['path'] or '/'}: {_short(change['before'], 100)} → {_short(change['after'], 100)}"
            for change in changes
        )
    elif kind == "EPISODE_STARTED":
        content = "Initial simulated environment recorded. Expand raw evidence to inspect its state."
    elif kind == "RUN_STARTED":
        content = "Run configuration recorded. Expand raw evidence for all settings."
    else:
        content = _text(data)
    return label, _short(content), content


def _prepare_arm(arm, record):
    events = record.get("events", [])
    by_id = {event.get("event_id"): event for event in events}
    positions = {event.get("event_id"): index for index, event in enumerate(events)}
    proposals = {
        event.get("call_ref"): event
        for event in events
        if event.get("event_type") == "TOOL_CALL_PROPOSED" and event.get("call_ref")
    }
    exposure_events = [event for event in events if event.get("event_type") == "TOOL_OUTPUT_EXPOSED"]
    sources = []
    for exposure in exposure_events:
        result_id = (exposure.get("data") or {}).get("source_result_event_id")
        source = by_id.get(result_id)
        valid_result = bool(source and source.get("event_type") == "TOOL_RESULT")
        before = bool(valid_result and positions[source["event_id"]] < positions[exposure["event_id"]])
        resolution = (
            "resolved_earlier_tool_result"
            if before
            else "source_not_earlier"
            if valid_result
            else "wrong_source_event_type"
            if source
            else "unresolved_source_reference"
        )
        sources.append(
            {
                "source_result_event_id": result_id,
                "source_event_id": result_id,
                "source_index": positions.get(result_id),
                "exposure_event_id": exposure.get("event_id"),
                "exposure_index": positions.get(exposure.get("event_id")),
                "model_request_id": exposure.get("model_request_id"),
                "call_ref": exposure.get("call_ref"),
                "function": _function(source or exposure, proposals),
                "content": _text((exposure.get("data") or {}).get("message", {}).get("content")),
                "source_content": _text((source or {}).get("data", {}).get("message", {}).get("content")),
                "exposure_status": "recorded_outbound_exposure",
                "resolution_status": resolution,
                "semantics": (exposure.get("data") or {}).get("semantics"),
            }
        )
    prepared = []
    for index, event in enumerate(events):
        function = _function(event, proposals)
        title, summary, content = _description(event, function)
        data, metadata = _presentation_fields(event)
        request_id = event.get("model_request_id") or proposals.get(event.get("call_ref"), {}).get(
            "model_request_id"
        )
        # A result is recorded before any later request exposes it. Show those
        # later exposure records as future observations, not prior visibility.
        if event.get("event_type") == "TOOL_RESULT":
            linked = [item for item in sources if item["source_result_event_id"] == event.get("event_id")]
        elif event.get("event_type") == "TOOL_OUTPUT_EXPOSED":
            linked = [item for item in sources if item["exposure_event_id"] == event.get("event_id")]
        else:
            linked = [
                item
                for item in sources
                if request_id
                and item["model_request_id"] == request_id
                and (item["exposure_index"] < index or event.get("event_type") == "MODEL_REQUEST")
            ]
        linked = [
            {
                **item,
                "at_or_before_selected_event": item["exposure_index"] <= index,
                "relation": "later_exposure_of_this_result"
                if event.get("event_type") == "TOOL_RESULT"
                else "this_outbound_exposure"
                if event.get("event_type") == "TOOL_OUTPUT_EXPOSED"
                else "outbound_exposure_for_this_request"
                if event.get("event_type") == "MODEL_REQUEST"
                else "earlier_outbound_exposure_in_request",
            }
            for item in linked
        ]
        prepared.append(
            {
                **event,
                "index": index,
                "title": title,
                "summary": summary,
                "phase": PHASES.get(event.get("event_type"), "other"),
                "function": function,
                "content": content,
                "comparison_data": data,
                "display_metadata": metadata,
                "sources": linked,
                "resolved_request_id": request_id,
                "source_status": "recorded_exposure_links"
                if linked
                else "unknown_no_linked_exposure_evidence",
            }
        )
    summary = record.get("summary") or {}
    manifest = record.get("manifest") or {}
    config = manifest.get("config") or {}
    return {
        "condition": arm.get("condition"),
        "run_id": arm.get("run_id", record.get("run_id")),
        "path": arm.get("path", summary.get("run_dir")),
        "status": arm.get("status", summary.get("status")),
        "native_tasks": arm.get("native_tasks", summary.get("tasks", [])),
        "model": config.get("model"),
        "requests": sum(event.get("event_type") == "MODEL_REQUEST" for event in events),
        "tool_count": len(proposals),
        "events": prepared,
        "sources": sources,
        "outcome": record.get("outcome", record.get("oracle", record.get("case_outcome"))),
        "warnings": arm.get("warnings", record.get("warnings", [])),
        "audit": record.get("audit"),
    }


def _alignment_keys(result, arms):
    """Resolve arm-local references into shared proposal/request display anchors."""
    calls = [{}, {}]
    requests = [{}, {}]
    event_maps = [{event.get("event_id"): event for event in arm["events"]} for arm in arms]
    request_pairs = []
    for row in result.get("alignment", {}).get("rows", []):
        paired = row.get("status") == "paired"
        proposals = [
            event_maps[index].get(row.get(name + "_event_id"))
            for index, name in enumerate(("clean", "attacked"))
        ]
        for index, proposal in enumerate(proposals):
            if proposal and proposal.get("call_ref"):
                calls[index][proposal["call_ref"]] = ("shared" if paired else f"only-{index}", row["index"])
        if all(proposals) and all(proposal.get("model_request_id") for proposal in proposals):
            request_pairs.append(
                (proposals[0]["model_request_id"], proposals[1]["model_request_id"], row["index"])
            )
    forward, backward = defaultdict(set), defaultdict(set)
    for clean, attacked, _ in request_pairs:
        forward[clean].add(attacked)
        backward[attacked].add(clean)
    for clean, attacked, row in request_pairs:
        if len(forward[clean]) == 1 and len(backward[attacked]) == 1:
            requests[0].setdefault(clean, row)
            requests[1].setdefault(attacked, row)

    keys = [[], []]
    for index, arm in enumerate(arms):
        for event in arm["events"]:
            kind = event.get("event_type")
            call = event.get("call_ref")
            request = requests[index].get(event.get("model_request_id"))
            if kind == "TOOL_OUTPUT_EXPOSED":
                source_id = (event.get("data") or {}).get("source_result_event_id")
                source = event_maps[index].get(source_id) or {}
                call_anchor = calls[index].get(source.get("call_ref") or call)
                key = (kind, call_anchor, request, event.get("function"))
                if call_anchor is None:
                    # An unresolved source has no cross-arm identity claim.
                    key = (kind, f"unresolved-{index}", event.get("event_id"))
            elif call:
                key = (kind, calls[index].get(call, (f"unbound-{index}", call)), event.get("function"))
            elif request is not None:
                key = (kind, "request", request)
            else:
                key = (kind, event.get("function"))
            keys[index].append(key)
    return keys, calls


def build_paired_view(result, records):
    """Return JSON-ready, non-mutating display data for exactly two saved arms.

    ``rows`` index ``arms[0].events`` and ``arms[1].events``. Equal display
    signatures are matched in sequence; replacements become separate missing
    rows. Numeric event IDs are never used to establish cross-arm identity.
    """
    if len(records) != 2 or len(result.get("arms", [])) != 2:
        raise ValueError("The paired event view requires exactly two arms")
    arms = [_prepare_arm(arm, record) for arm, record in zip(result["arms"], records, strict=True)]
    keys, calls = _alignment_keys(result, arms)
    aligner = SequenceMatcher(None, *keys, autojunk=False)
    indices = []
    for tag, i1, i2, j1, j2 in aligner.get_opcodes():
        if tag == "equal":
            indices.extend(zip(range(i1, i2), range(j1, j2), strict=True))
        else:
            indices.extend((index, None) for index in range(i1, i2))
            indices.extend((None, index) for index in range(j1, j2))
    actions = {row["index"]: row for row in result.get("alignment", {}).get("rows", [])}
    rows = []
    for clean_index, attacked_index in indices:
        clean = arms[0]["events"][clean_index] if clean_index is not None else None
        attacked = arms[1]["events"][attacked_index] if attacked_index is not None else None
        present = clean or attacked
        call_anchor = calls[0 if clean else 1].get(present.get("call_ref"))
        action_index = call_anchor[1] if call_anchor else None
        if clean and attacked:
            changes = _changes(clean["comparison_data"], attacked["comparison_data"])
            metadata_changes = _changes(clean["display_metadata"], attacked["display_metadata"])
            status = "changed" if changes else "same"
        else:
            changes = [
                {
                    "path": "",
                    "before_present": clean is not None,
                    "after_present": attacked is not None,
                    "before": clean["comparison_data"] if clean else None,
                    "after": attacked["comparison_data"] if attacked else None,
                    "kind": "removed" if clean else "added",
                }
            ]
            metadata_changes = []
            status = "clean_only" if clean else "attacked_only"
        rows.append(
            {
                "index": len(rows),
                "clean_index": clean_index,
                "attacked_index": attacked_index,
                "clean_event_id": clean.get("event_id") if clean else None,
                "attacked_event_id": attacked.get("event_id") if attacked else None,
                "event_type": present.get("event_type"),
                "title": present["title"],
                "phase": present["phase"],
                "status": status,
                "changes": changes,
                "metadata_changes": metadata_changes,
                "changed": bool(changes),
                "security_relevant": bool(
                    present.get("event_type") == "TOOL_CALL_PROPOSED"
                    and actions.get(action_index, {}).get("security_relevant")
                ),
                "action_row": action_index,
            }
        )
    return {
        "schema_version": 1,
        "comparability": copy.deepcopy(result.get("comparability", {})),
        "sensitive_paths": copy.deepcopy(result.get("sensitive_paths", {})),
        "first_tool_proposal_divergence": copy.deepcopy(result.get("first_tool_proposal_divergence", {})),
        "arms": arms,
        "rows": rows,
        "alignment": {
            "status": "display_hypothesis",
            "proposal_status": result.get("alignment", {}).get("status"),
            "rule": "Recorded proposal alignment anchors call and request events; equal event types and anchors are sequence-matched. Unmatched events stay visible. Run-local IDs are never cross-arm identities.",
            "limitations": "One display alignment is shown. Repeated events and ambiguous proposal/request bindings can admit other alignments; exposure and correspondence do not establish causation.",
        },
        "first_changed_row": next((row["index"] for row in rows if row["changed"]), None),
        "first_security_row": next((row["index"] for row in rows if row["security_relevant"]), None),
        "counts": {
            "rows": len(rows),
            "changed": sum(row["status"] == "changed" for row in rows),
            "same": sum(row["status"] == "same" for row in rows),
            "clean_only": sum(row["status"] == "clean_only" for row in rows),
            "attacked_only": sum(row["status"] == "attacked_only" for row in rows),
            "security_relevant": sum(row["security_relevant"] for row in rows),
        },
    }
