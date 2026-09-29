"""Read-only structural checks of v1 observation logs, without model requests.

Passing these checks establishes internal recording consistency. It does not
establish behavioral influence, causal attribution, or non-interference.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def _identifier(value) -> bool:
    return isinstance(value, str) and bool(value)


def inspect_events(path: Path) -> dict:
    """Inspect event order, references, request outcomes, and output exposures.

    Error messages include line numbers and schema field names only; payloads and
    exception messages are intentionally excluded. Unknown event types and extra
    fields are accepted so the schema can acquire new observation boundaries.
    """
    errors = []
    counts = Counter()
    event_count = 0
    seen_events = set()
    episode_ids = set()
    episode_starts = {}
    episode_ends = Counter()
    requests = {}
    proposals = {}
    runtime_starts = {}
    runtime_returns = {}
    results = {}
    run_id = None
    previous_sequence = 0
    previous_clock = None
    run_started = False
    run_ended = False

    def fail(line, message):
        errors.append(f"line {line}: {message}" if line is not None else message)

    def known_request(event, line):
        request_id = event.get("model_request_id")
        if not _identifier(request_id) or request_id not in requests:
            fail(line, "model_request_id must reference an earlier MODEL_REQUEST")
            return None
        return requests[request_id]

    def known_proposal(event, line):
        call_ref = event.get("call_ref")
        if not _identifier(call_ref) or call_ref not in proposals:
            fail(line, "call_ref must reference an earlier TOOL_CALL_PROPOSED")
            return None
        proposal = proposals[call_ref]
        if event.get("model_request_id") != proposal["model_request_id"]:
            fail(line, "model_request_id differs from the referenced proposal")
        return call_ref

    try:
        stream = Path(path).open(encoding="utf-8")
    except OSError as error:
        fail(None, f"cannot open event log: {type(error).__name__}")
        stream = None

    if stream is not None:
        try:
            with stream:
                for line_number, raw in enumerate(stream, 1):
                    try:
                        event = json.loads(raw)
                    except (ValueError, TypeError):
                        fail(line_number, "invalid JSON line")
                        continue
                    if not isinstance(event, dict):
                        fail(line_number, "event must be a JSON object")
                        continue
                    event_count += 1
                    sequence = event.get("event_sequence")
                    if type(sequence) is not int or sequence < 1:
                        fail(line_number, "event_sequence must be a positive integer")
                    else:
                        if sequence != previous_sequence + 1:
                            fail(line_number, "event_sequence is not consecutive from 1")
                        previous_sequence = sequence
                    if type(event.get("schema_version")) is not int or event["schema_version"] != 1:
                        fail(line_number, "unsupported or missing schema_version")
                    current_run = event.get("run_id")
                    if not _identifier(current_run):
                        fail(line_number, "run_id must be a nonempty string")
                    elif run_id is None:
                        run_id = current_run
                    elif current_run != run_id:
                        fail(line_number, "run_id changed within the file")
                    event_id = event.get("event_id")
                    if not _identifier(event_id):
                        fail(line_number, "event_id must be a nonempty string")
                    elif event_id in seen_events:
                        fail(line_number, "duplicate event_id")
                    parents = event.get("parent_event_ids")
                    if not isinstance(parents, list):
                        fail(line_number, "parent_event_ids must be an array")
                    elif any(not _identifier(parent) or parent not in seen_events for parent in parents):
                        fail(line_number, "parent_event_ids must reference earlier events")
                    # Add after checking parents to reject self-edges as well.
                    if _identifier(event_id):
                        seen_events.add(event_id)
                    clock = event.get("monotonic_ns")
                    if type(clock) is not int or clock < 0:
                        fail(line_number, "monotonic_ns must be a nonnegative integer")
                    else:
                        if previous_clock is not None and clock < previous_clock:
                            fail(line_number, "monotonic_ns moved backwards")
                        previous_clock = clock
                    if not _identifier(event.get("time_utc")):
                        fail(line_number, "time_utc must be a nonempty string")
                    episode_id = event.get("episode_id")
                    if episode_id is not None:
                        if _identifier(episode_id):
                            episode_ids.add(episode_id)
                        else:
                            fail(line_number, "episode_id must be a string or null")
                    event_type = event.get("event_type")
                    if not _identifier(event_type):
                        fail(line_number, "event_type must be a nonempty string")
                        continue
                    counts[event_type] += 1
                    data = event.get("data")
                    if not isinstance(data, dict):
                        fail(line_number, "data must be an object")
                        continue

                    if event_type == "RUN_STARTED":
                        if run_started:
                            fail(line_number, "duplicate RUN_STARTED")
                        if run_ended:
                            fail(line_number, "RUN_STARTED follows RUN_END")
                        run_started = True
                    elif event_type == "RUN_END":
                        if run_ended:
                            fail(line_number, "duplicate RUN_END")
                        run_ended = True
                    elif event_type == "EPISODE_STARTED":
                        if not _identifier(episode_id):
                            fail(line_number, "EPISODE_STARTED requires episode_id")
                        elif episode_id in episode_starts:
                            fail(line_number, "duplicate EPISODE_STARTED")
                        else:
                            episode_starts[episode_id] = line_number
                    elif event_type == "EPISODE_ENDED":
                        if not _identifier(episode_id) or episode_id not in episode_starts:
                            fail(line_number, "EPISODE_ENDED lacks earlier EPISODE_STARTED")
                        else:
                            episode_ends[episode_id] += 1
                            if episode_ends[episode_id] > 1:
                                fail(line_number, "duplicate EPISODE_ENDED")
                    elif event_type == "MODEL_REQUEST":
                        request_id = event.get("model_request_id")
                        if not _identifier(request_id):
                            fail(line_number, "MODEL_REQUEST requires model_request_id")
                            continue
                        if request_id in requests:
                            fail(line_number, "duplicate MODEL_REQUEST model_request_id")
                            continue
                        body = data.get("body")
                        messages = body.get("messages") if isinstance(body, dict) else None
                        if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
                            fail(line_number, "MODEL_REQUEST data.body.messages must be an array of objects")
                            messages = []
                        requests[request_id] = {
                            "line": line_number,
                            "responses": 0,
                            "errors": 0,
                            "tool_messages": {
                                i: m for i, m in enumerate(messages) if m.get("role") == "tool"
                            },
                            "exposures": 0,
                            "exposed_indices": set(),
                        }
                    elif event_type in {"MODEL_RESPONSE", "MODEL_ERROR"}:
                        request = known_request(event, line_number)
                        if request is not None:
                            key = "responses" if event_type == "MODEL_RESPONSE" else "errors"
                            request[key] += 1
                            if request[key] > 1:
                                fail(line_number, f"duplicate {event_type} for one MODEL_REQUEST")
                    elif event_type == "MODEL_PARSED":
                        known_request(event, line_number)
                    elif event_type == "TOOL_CALL_PROPOSED":
                        known_request(event, line_number)
                        call_ref = event.get("call_ref")
                        if not _identifier(call_ref):
                            fail(line_number, "TOOL_CALL_PROPOSED requires call_ref")
                        elif call_ref in proposals:
                            fail(line_number, "duplicate TOOL_CALL_PROPOSED call_ref")
                        else:
                            proposals[call_ref] = event
                    elif event_type.startswith("TOOL_RUNTIME_"):
                        known_request(event, line_number)
                        call_ref = known_proposal(event, line_number)
                        if call_ref is None:
                            continue
                        if event_type == "TOOL_RUNTIME_STARTED":
                            if call_ref in runtime_starts:
                                fail(line_number, "duplicate TOOL_RUNTIME_STARTED for call_ref")
                            runtime_starts[call_ref] = line_number
                        elif event_type == "TOOL_RUNTIME_RETURNED":
                            if call_ref not in runtime_starts:
                                fail(line_number, "TOOL_RUNTIME_RETURNED lacks earlier TOOL_RUNTIME_STARTED")
                            if call_ref in runtime_returns:
                                fail(line_number, "duplicate TOOL_RUNTIME_RETURNED for call_ref")
                            runtime_returns[call_ref] = event
                    elif event_type == "TOOL_RESULT":
                        call_ref = known_proposal(event, line_number)
                        if call_ref is not None:
                            if call_ref in results:
                                fail(line_number, "duplicate TOOL_RESULT for call_ref")
                            if call_ref in runtime_starts and call_ref not in runtime_returns:
                                fail(line_number, "TOOL_RESULT precedes its TOOL_RUNTIME_RETURNED")
                            results[call_ref] = event
                    elif event_type == "TOOL_OUTPUT_EXPOSED":
                        request = known_request(event, line_number)
                        call_ref = event.get("call_ref")
                        if not _identifier(call_ref) or call_ref not in results:
                            fail(
                                line_number,
                                "TOOL_OUTPUT_EXPOSED lacks earlier TOOL_RESULT with same call_ref",
                            )
                        elif data.get("source_result_event_id") is not None:
                            if data["source_result_event_id"] != results[call_ref].get("event_id"):
                                fail(
                                    line_number,
                                    "TOOL_OUTPUT_EXPOSED source_result_event_id disagrees with call_ref",
                                )
                        if request is not None:
                            request["exposures"] += 1
                            index = data.get("message_index")
                            if type(index) is not int or index not in request["tool_messages"]:
                                fail(
                                    line_number,
                                    "TOOL_OUTPUT_EXPOSED message_index is not a request tool message",
                                )
                            else:
                                if index in request["exposed_indices"]:
                                    fail(line_number, "duplicate TOOL_OUTPUT_EXPOSED message_index")
                                request["exposed_indices"].add(index)
                                if "message" in data and data["message"] != request["tool_messages"][index]:
                                    fail(line_number, "TOOL_OUTPUT_EXPOSED message differs from request body")
        except (OSError, UnicodeError) as error:
            fail(None, f"cannot finish reading event log: {type(error).__name__}")

    if not event_count:
        fail(None, "empty event log")
    if run_started and not run_ended:
        fail(None, "RUN_STARTED lacks RUN_END; log is incomplete")
    for episode_id, line_number in episode_starts.items():
        if not episode_ends[episode_id]:
            fail(line_number, "EPISODE_STARTED lacks EPISODE_ENDED; log is incomplete")
    for request in requests.values():
        # An HTTP response followed by an SDK/parser error is one legal outcome.
        if not (request["responses"] or request["errors"]):
            fail(request["line"], "MODEL_REQUEST lacks MODEL_RESPONSE or MODEL_ERROR; log is incomplete")
        if request["exposures"] != len(request["tool_messages"]):
            fail(request["line"], "request tool message count differs from TOOL_OUTPUT_EXPOSED count")
    for call_ref, line_number in runtime_starts.items():
        if call_ref not in runtime_returns:
            fail(line_number, "TOOL_RUNTIME_STARTED lacks TOOL_RUNTIME_RETURNED; log is incomplete")

    return {
        "event_count": event_count,
        "event_counts": dict(sorted(counts.items())),
        "model_requests": counts["MODEL_REQUEST"],
        "tool_proposals": counts["TOOL_CALL_PROPOSED"],
        "runtime_calls": counts["TOOL_RUNTIME_STARTED"],
        "tool_results": counts["TOOL_RESULT"],
        "tool_output_exposures": counts["TOOL_OUTPUT_EXPOSED"],
        "episodes": len(episode_ids),
        "valid": not errors,
        "errors": errors,
    }
