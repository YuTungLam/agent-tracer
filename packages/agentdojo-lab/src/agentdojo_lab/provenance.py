"""Prefix-only source candidates for proposed arguments, never maliciousness labels.

The engine consumes saved v1 events in order. Its inputs are the actual outbound
messages plus verified exposure references, not runtime metadata or evaluator
results. The consume API supports both saved-prefix replay and a separate live
observer. Only that observer measures availability before runtime entry; replay
outputs retain their explicit offline availability label.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from agentdojo_lab.lexical import exact_spans, lcs_evidence


def pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def argument_leaves(value, path="") -> Iterator[tuple[str, object]]:
    """Keep array indices, JSON Pointer escaping and empty containers explicit."""
    if isinstance(value, dict) and value:
        for key, child in value.items():
            yield from argument_leaves(child, f"{path}/{pointer_token(key)}")
    elif isinstance(value, list) and value:
        for index, child in enumerate(value):
            yield from argument_leaves(child, f"{path}/{index}")
    else:
        yield path, value


def _text(value) -> str | None:
    if isinstance(value, str):
        return value
    if value is None or type(value) in (int, float, bool):
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    return None


def _identity(*parts) -> str:
    raw = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def _message_parts(message: dict) -> Iterator[tuple[str, str]]:
    """Only actual request text; call metadata is included only for assistant role."""
    content = message.get("content")
    if isinstance(content, str):
        yield "/content", content
    elif isinstance(content, list):
        for index, part in enumerate(content):
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                yield f"/content/{index}/text", part["text"]
    if message.get("role") == "assistant":
        for index, call in enumerate(message.get("tool_calls") or []):
            args = call.get("function", {}).get("arguments")
            if isinstance(args, str):
                yield f"/tool_calls/{index}/function/arguments", args


def structured_scalars(text: str) -> dict:
    """Locate scalars in JSON/YAML message text without constructing Python objects.

    BaseLoader compose does not execute tags or coerce dates. Reject aliases,
    duplicate mapping keys and excessive structure; use raw text matching as a
    separately labelled fallback. Offsets index the original Unicode string.
    """
    limits = {"max_codepoints": 65536, "max_nodes": 4096, "max_depth": 32}
    if len(text) > limits["max_codepoints"]:
        return {"status": "budget_exceeded", "scalars": [], "limits": limits}
    try:
        root = yaml.compose(text, Loader=yaml.BaseLoader)
        if not isinstance(root, (MappingNode, SequenceNode)):
            return {"status": "plain_text", "scalars": [], "limits": limits}
        leaves, seen = [], set()

        def walk(node, path, depth):
            if id(node) in seen or len(seen) >= limits["max_nodes"] or depth > limits["max_depth"]:
                raise ValueError("unsupported aliases or structure budget")
            seen.add(id(node))
            if isinstance(node, ScalarNode):
                leaves.append(
                    {
                        "field_path": path,
                        "value": node.value,
                        "start": node.start_mark.index,
                        "end": node.end_mark.index,
                    }
                )
            elif isinstance(node, SequenceNode):
                for index, child in enumerate(node.value):
                    walk(child, f"{path}/{index}", depth + 1)
            elif isinstance(node, MappingNode):
                keys = set()
                for key, child in node.value:
                    if not isinstance(key, ScalarNode) or key.value in keys:
                        raise ValueError("non-scalar or duplicate key")
                    keys.add(key.value)
                    walk(child, f"{path}/{pointer_token(key.value)}", depth + 1)

        walk(root, "", 0)
        return {"status": "parsed", "scalars": leaves, "limits": limits}
    except (yaml.YAMLError, ValueError, RecursionError):
        return {"status": "unsupported_structure", "scalars": [], "limits": limits}


class ProvenanceTracker:
    """Incremental, deterministic candidate generation over one event stream."""

    def __init__(
        self,
        semantic_matcher=None,
        policy=None,
        lineage=None,
        *,
        canary_enabled=False,
        cascade_profile="ordinary",
    ):
        from agentdojo_lab.profiles import get_profile

        selected_profile = get_profile(cascade_profile)
        if selected_profile.name != "ordinary" and policy is None:
            raise ValueError("A nonordinary cascade profile requires a frozen source/sink policy")
        self.semantic_matcher = semantic_matcher
        self.policy = policy
        self.lineage = lineage
        if type(canary_enabled) is not bool or (canary_enabled and policy is None):
            raise ValueError("Canary tracking requires an explicit condition and frozen policy")
        self.canary_enabled = canary_enabled
        self.canary_assignments = {}
        self.canary_runtime_returns = {}
        if lineage is not None and policy is None:
            raise ValueError("Lineage tracking requires a frozen source/sink policy")
        if lineage is not None and lineage.policy_sha256 != policy.metadata["sha256"]:
            raise ValueError("Lineage and tracker policy hashes must match")
        if lineage is not None and lineage.canary_enabled != canary_enabled:
            raise ValueError("Lineage and tracker canary conditions must match")
        self.cascade_matcher = None
        if policy is not None:
            from agentdojo_lab.cascade import CascadeMatcher

            self.cascade_matcher = CascadeMatcher(
                semantic_matcher, profile=selected_profile.name, canary_enabled=canary_enabled
            )
        self.tool_proposals = {}
        self.run_id = None
        self.sequence = 0
        self.seen = set()
        self.results = {}
        self.requests = {}
        self.sources = {}
        self.calls = []

    def _register(self, request, index, message, exposure=None):
        for part_path, text in _message_parts(message):
            role = message["role"]
            source_event = exposure["data"]["source_result_event_id"] if exposure else None
            key = _identity(
                self.run_id, request["episode_id"], role, source_event or f"message:{index}", part_path, text
            )
            source_id = f"source:{key}"
            if source_id not in self.sources:
                self.sources[source_id] = {
                    "source_id": source_id,
                    "run_id": self.run_id,
                    "episode_id": request["episode_id"],
                    "kind": role,
                    "source_event_id": source_event or request["event_id"],
                    "first_observed_sequence": exposure["event_sequence"]
                    if exposure
                    else request["sequence"],
                    "text": text,
                    "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "structure": structured_scalars(text),
                }
                if self.policy is not None:
                    origin = self.results[source_event].get("origin_tool") if source_event else None
                    self.sources[source_id].update(
                        origin_tool=origin,
                        policy=self.policy.source_decision(role, origin),
                    )
                if self.canary_enabled and source_event:
                    reference = self.results[source_event].get("canary")
                    if reference is not None:
                        from agentdojo_lab.canary import validate_reference

                        self.sources[source_id]["canary"] = validate_reference(reference, text)
            request["sources"].append(
                {
                    "source_id": source_id,
                    "message_index": index,
                    "request_pointer": f"/data/body/messages/{index}{part_path}",
                    "exposure_event_id": exposure["event_id"] if exposure else None,
                }
            )

    def _record_intervention(self, event):
        if not self.canary_enabled:
            raise ValueError("Intervention events require the declared canary condition")
        audit = event["data"]
        origin = self.tool_proposals.get(event.get("call_ref"))
        if (
            not origin
            or any(audit.get(key) != event.get(key) for key in ("run_id", "episode_id", "call_ref"))
            or origin["episode_id"] != event["episode_id"]
            or origin["model_request_id"] != event["model_request_id"]
            or origin["tool_call_id"] != event.get("tool_call_id")
            or audit.get("function") != origin["function"]
            or audit.get("policy_sha256") != self.policy.metadata["sha256"]
            or audit.get("status") not in {"assigned", "skipped"}
        ):
            raise ValueError("Invalid or failed canary intervention record")
        if any(row["audit"]["call_ref"] == event["call_ref"] for row in self.canary_assignments.values()):
            raise ValueError("A tool result may have only one intervention audit")
        if audit["status"] == "assigned":
            from agentdojo_lab.canary import validate_assignment

            validate_assignment(audit)
            returned = self.canary_runtime_returns.get(event["call_ref"])
            if (
                not self.policy.source_decision("tool", origin["function"])["eligible"]
                or returned is None
                or returned["episode_id"] != event["episode_id"]
                or returned["model_request_id"] != event["model_request_id"]
                or returned.get("tool_call_id") != origin["tool_call_id"]
                or returned["event_sequence"] >= event["event_sequence"]
                or returned["data"].get("error") is not None
                or returned["data"].get("raised_exception_type") is not None
                or returned["event_id"] not in event["parent_event_ids"]
            ):
                raise ValueError("Canary assignment lacks a successful eligible source return")
            if any(row["audit"].get("token") == audit["token"] for row in self.canary_assignments.values()):
                raise ValueError("Canary tokens must be unique within the run")
        self.canary_assignments[event["event_id"]] = {
            "audit": audit,
            "model_request_id": event["model_request_id"],
            "tool_call_id": event.get("tool_call_id"),
            "result_event_id": None,
        }

    def _record_canary_result(self, event):
        reference_id = event["data"].get("intervention_event_id")
        assignment = self.canary_assignments.get(reference_id)
        if assignment is None or assignment["result_event_id"] is not None:
            raise ValueError("Canary result lacks its unique prior intervention audit")
        audit = assignment["audit"]
        if (
            audit["call_ref"] != event["call_ref"]
            or audit["episode_id"] != event["episode_id"]
            or assignment["model_request_id"] != event["model_request_id"]
            or assignment["tool_call_id"] != event.get("tool_call_id")
            or reference_id not in event["parent_event_ids"]
            or event["data"]["message"].get("role") != "tool"
            or event["data"]["message"].get("tool_call", {}).get("id") != assignment["tool_call_id"]
            or event["data"]["message"].get("tool_call", {}).get("function") != audit["function"]
        ):
            raise ValueError("Canary result identity differs from the intervention")
        assignment["result_event_id"] = event["event_id"]
        if audit["status"] != "assigned":
            return
        message = event["data"]["message"]
        if (
            message.get("content") != audit["marked_content"]
            or message.get("error") is not None
            or not event["data"].get("runtime_entered")
        ):
            raise ValueError("Applied result differs from its recorded canary transformation")
        from agentdojo_lab.canary import compact_reference

        self.results[event["event_id"]]["canary"] = {
            **compact_reference(audit),
            "assignment_event_id": reference_id,
            "source_result_event_id": event["event_id"],
        }

    def consume(self, event: dict) -> dict | None:
        """Return one frozen call analysis at a proposal; never consult later events."""
        event = copy.deepcopy(event)
        if event.get("schema_version") != 1:
            raise ValueError("Unsupported observation schema")
        if type(event.get("event_sequence")) is not int or event["event_sequence"] != self.sequence + 1:
            raise ValueError("Provenance requires consecutive event order")
        if not event.get("event_id") or event["event_id"] in self.seen:
            raise ValueError("Missing or duplicate event ID")
        if self.run_id is None:
            self.run_id = event.get("run_id")
        if not self.run_id or event.get("run_id") != self.run_id:
            raise ValueError("A tracker consumes exactly one run")
        self.sequence = event["event_sequence"]
        self.seen.add(event["event_id"])
        kind, data = event["event_type"], event["data"]
        if kind == "TOOL_OUTPUT_INTERVENTION":
            self._record_intervention(event)
        if self.canary_enabled and kind == "TOOL_RUNTIME_RETURNED":
            self.canary_runtime_returns[event.get("call_ref")] = event
        if kind == "TOOL_RESULT":
            # Identity only: data.message.tool_call.args is NOT exposed content.
            self.results[event["event_id"]] = {
                "episode_id": event["episode_id"],
                "call_ref": event.get("call_ref"),
                "sequence": self.sequence,
                "tool_call_id": event.get("tool_call_id"),
            }
            if self.policy is not None:
                origin = self.tool_proposals.get(event.get("call_ref"))
                valid_origin = (
                    origin
                    and origin["episode_id"] == event["episode_id"]
                    and origin["model_request_id"] == event["model_request_id"]
                )
                self.results[event["event_id"]]["origin_tool"] = origin["function"] if valid_origin else None
            if self.canary_enabled:
                self._record_canary_result(event)
        elif kind == "MODEL_REQUEST":
            request_id = event["model_request_id"]
            if request_id in self.requests:
                raise ValueError("Duplicate model request ID")
            request = {
                "event_id": event["event_id"],
                "sequence": self.sequence,
                "episode_id": event["episode_id"],
                "messages": data["body"].get("messages", []),
                "sources": [],
                "exposed_indices": set(),
                "proposed": False,
            }
            self.requests[request_id] = request
            for index, message in enumerate(request["messages"]):
                if message.get("role") in {"user", "assistant", "system", "developer"}:
                    self._register(request, index, message)
        elif kind == "TOOL_OUTPUT_EXPOSED":
            request = self.requests[event["model_request_id"]]
            index = data["message_index"]
            source = self.results.get(data.get("source_result_event_id"))
            if request["proposed"]:
                raise ValueError("Exposure arrived after a proposal using its request")
            if (
                type(index) is not int
                or index < 0
                or index >= len(request["messages"])
                or index in request["exposed_indices"]
            ):
                raise ValueError("Invalid or duplicate exposure position")
            message = request["messages"][index]
            if (
                message.get("role") != "tool"
                or message != data["message"]
                or source is None
                or source["episode_id"] != request["episode_id"]
                or event["episode_id"] != request["episode_id"]
                or source["call_ref"] != event.get("call_ref")
                or source["sequence"] >= request["sequence"]
                or source["tool_call_id"] != message.get("tool_call_id")
                or event.get("tool_call_id") != message.get("tool_call_id")
            ):
                raise ValueError("Exposure does not match its actual request and source")
            request["exposed_indices"].add(index)
            self._register(request, index, message, event)
        elif kind == "TOOL_CALL_PROPOSED":
            request = self.requests[event["model_request_id"]]
            expected = {i for i, m in enumerate(request["messages"]) if m.get("role") == "tool"}
            if expected != request["exposed_indices"] or request["episode_id"] != event["episode_id"]:
                raise ValueError("Proposal lacks its complete request exposure mapping")
            request["proposed"] = True
            if self.policy is not None:
                if not event.get("call_ref") or event["call_ref"] in self.tool_proposals:
                    raise ValueError("Policy attribution requires a unique proposal call reference")
                self.tool_proposals[event["call_ref"]] = {
                    "function": data["function"],
                    "episode_id": event["episode_id"],
                    "model_request_id": event["model_request_id"],
                    **({"tool_call_id": event.get("tool_call_id")} if self.canary_enabled else {}),
                }
            call = self._analyze(event, request)
            if self.lineage is not None:
                call = self.lineage.consume(event, call=call)
            self.calls.append(copy.deepcopy(call))
            return copy.deepcopy(call)
        if self.lineage is not None:
            exposed = []
            if kind == "TOOL_OUTPUT_EXPOSED":
                exposed = [
                    {**self.sources[occurrence["source_id"]], **occurrence}
                    for occurrence in self.requests[event["model_request_id"]]["sources"]
                    if occurrence["exposure_event_id"] == event["event_id"]
                ]
            self.lineage.consume(event, exposed_sources=exposed)
        return None

    def _analyze(self, event, request):
        fields = []
        for path, value in argument_leaves(event["data"]["arguments"]):
            # A zero-argument call has no argument attribution target.
            if path == "" and value == {}:
                continue
            text = _text(value)
            exact, lexical, semantic = [], [], []
            for occurrence in request["sources"]:
                source = self.sources[occurrence["source_id"]]
                base = {**occurrence, "kind": source["kind"], "source_event_id": source["source_event_id"]}
                if text is not None and text:
                    equal = [x for x in source["structure"]["scalars"] if x["value"] == text]
                    if equal:
                        for scalar in equal:
                            exact.append(
                                {
                                    **base,
                                    "evidence_type": "structured_scalar_equal",
                                    "source_field_path": scalar["field_path"],
                                    "start": scalar["start"],
                                    "end": scalar["end"],
                                }
                            )
                    else:
                        for start, end in exact_spans(source["text"], text):
                            exact.append(
                                {
                                    **base,
                                    "evidence_type": "bounded_exact_text",
                                    "source_field_path": None,
                                    "start": start,
                                    "end": end,
                                }
                            )
                if self.policy is None:
                    score = lcs_evidence(source["text"], text or "")
                    lexical.append({**base, **score})
                if self.semantic_matcher is not None and self.policy is None:
                    # The scorer sees only this request's visible source and current argument.
                    semantic.append(
                        {**base, **copy.deepcopy(self.semantic_matcher.compare(source["text"], text or ""))}
                    )
            distinct = {x["source_id"] for x in exact}
            fields.append(
                {
                    "item_id": "item:" + _identity(self.run_id, event["episode_id"], event["event_id"], path),
                    "argument_path": path,
                    "value": value,
                    "exact_status": (
                        "multiple_source_candidates"
                        if len(distinct) > 1
                        else "single_source_candidate"
                        if distinct
                        else "no_exact_evidence"
                    ),
                    "exact_candidates": exact,
                    "nt_style_lcs": lexical,
                    **(
                        {"nt_style_semantic": semantic}
                        if self.semantic_matcher is not None and self.policy is None
                        else {}
                    ),
                    "provenance_verdict": "unreviewed",
                    "maliciousness": "not_assessed",
                    "causal_influence": "not_assessed",
                }
            )
            if self.policy is not None:
                sink = self.policy.sink_decision(event["data"]["function"], path)
                eligible = [
                    occurrence
                    for occurrence in request["sources"]
                    if self.sources[occurrence["source_id"]]["policy"]["eligible"]
                ]
                comparisons = []
                if sink["selected"]:
                    for occurrence in eligible:
                        source = self.sources[occurrence["source_id"]]
                        comparisons.append(
                            {
                                **occurrence,
                                "kind": source["kind"],
                                "source_event_id": source["source_event_id"],
                                "origin_tool": source["origin_tool"],
                                **self.cascade_matcher.compare(
                                    source["text"],
                                    text or "",
                                    **({"canary": source.get("canary")} if self.canary_enabled else {}),
                                ),
                            }
                        )
                fields[-1].update(
                    nt_style_cascade=comparisons,
                    cascade_scope={
                        "status": "analyzed"
                        if sink["selected"] and eligible
                        else "no_eligible_source"
                        if sink["selected"]
                        else sink["reason"],
                        "sink": sink,
                        "eligible_source_count": len(eligible),
                        "comparison_count": len(comparisons),
                        "excluded_sources": [
                            {
                                "source_id": occurrence["source_id"],
                                "request_pointer": occurrence["request_pointer"],
                                "reason": self.sources[occurrence["source_id"]]["policy"]["reason"],
                            }
                            for occurrence in request["sources"]
                            if not self.sources[occurrence["source_id"]]["policy"]["eligible"]
                        ],
                    },
                )
        visible = []
        for occurrence in request["sources"]:
            source = self.sources[occurrence["source_id"]]
            visible.append({**source, **occurrence})
        call = {
            "run_id": self.run_id,
            "task_id": event.get("task_id"),
            "episode_id": event["episode_id"],
            "proposal_event_id": event["event_id"],
            "proposal_sequence": event["event_sequence"],
            "model_request_id": event["model_request_id"],
            "request_event_id": request["event_id"],
            "request_sequence": request["sequence"],
            "cutoff_event_id": event["event_id"],
            "function": event["data"]["function"],
            "arguments": event["data"]["arguments"],
            "request_messages": request["messages"],
            "visible_sources": visible,
            "fields": fields,
            "availability": "offline_prefix_replay; pre-execution latency not measured",
        }
        if self.canary_enabled:
            pairs = [p for field in fields for p in field.get("nt_style_cascade", [])]
            call["canary"] = {
                "condition": "canary_intervention",
                "available_source_markers": [
                    {"source_id": source["source_id"], **source["canary"]}
                    for source in visible
                    if "canary" in source
                ],
                "tier1_scored_pairs": sum(p["stages"]["tier1"]["status"] == "scored" for p in pairs),
                "tier1_matched_pairs": sum(p["first_matched_tier"] == "tier1" for p in pairs),
                "interpretation": "exact_registered_marker_carryover; no_maliciousness_or_causal_verdict",
            }
        if self.policy is not None:
            pairs = [pair for field in fields for pair in field["nt_style_cascade"]]
            sink = self.policy.sink_decision(call["function"])
            explicit = any(pair["matched"] is True for pair in pairs)
            eligible_count = sum(source["policy"]["eligible"] for source in visible)
            selected_fields = sum(field["cascade_scope"]["sink"]["selected"] for field in fields)
            applicable_pairs = sum(pair["status"] != "not_applicable" for pair in pairs)
            call.update(
                component_mode="ordered_cascade",
                policy={
                    "policy_id": self.policy.metadata["policy_id"],
                    "sha256": self.policy.metadata["sha256"],
                    "sink": sink,
                    "eligible_source_count": eligible_count,
                    "unclassified_source_count": sum(
                        source["policy"].get("reason") == "unclassified_tool" for source in visible
                    ),
                    "scope": "direct_visible_sources; proposed_sink_arguments; no_DCPG_inheritance",
                },
                cascade_summary={
                    "pair_count": len(pairs),
                    "matched_pair_count": sum(pair["matched"] is True for pair in pairs),
                    "selected_field_count": selected_fields,
                    "applicable_pair_count": applicable_pairs,
                    "status": sink["reason"]
                    if not sink["selected"]
                    else "explicit_candidates"
                    if explicit
                    else "incomplete_explicit_analysis"
                    if any(pair["status"] in {"indeterminate", "encoder_error"} for pair in pairs)
                    else "no_argument_targets"
                    if not fields
                    else "no_selected_argument_targets"
                    if not selected_fields
                    else "no_eligible_source"
                    if not eligible_count
                    else "not_applicable_comparisons"
                    if not applicable_pairs
                    else "no_explicit_candidate",
                    "causal_analysis": "not_implemented"
                    if sink["selected"] and eligible_count and not explicit
                    else "not_requested",
                    "causal_scope": "future_component; no_probes_executed",
                    "maliciousness": "not_assessed",
                    "authorization": "not_assessed",
                },
            )
        return call


METHODS = {
    "exact_v1": {
        "description": "Structured scalar equality; otherwise bounded case-sensitive literal text",
        "raw_min_codepoints": 3,
        "short_values": "structured scalar equality only",
        "source_types": ["user", "tool", "assistant", "system", "developer"],
        "normalization": "none for raw text; YAML/JSON scalar decoding is explicitly labelled",
    },
    "nt_style_lcs_v1": {
        "paper": "https://arxiv.org/html/2604.23374v1#S4.SS2",
        "formula": "longest_common_subsequence_length / min(source_length, argument_length)",
        "threshold": 0.15,
        "unit": "unicode_codepoint",
        "case_sensitive": True,
        "source_unit": "actual outbound message text part; no chunking",
        "argument_unit": "JSON leaf; scalar JSON rendering for non-string values",
        "source_types": ["user", "tool", "assistant", "system", "developer"],
        "scope": "paper-based Tier 2 component adaptation; not full NeuroTaint reproduction",
        "assumptions": [
            "paper does not specify character/token unit or serialization",
            "no canary, embeddings, memory lineage, causal judge or policy-based thresholds",
            "user/assistant/system controls are labelled separately from tool sources",
            "threshold hits are candidates, not verified provenance or maliciousness",
        ],
    },
}
