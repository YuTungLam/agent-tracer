"""Bounded auditor-context planning, not agent reruns or causal identification."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import date, datetime

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

METHOD = "nt_style_counterfactual_plan_v1"
PLACEHOLDER = "Neutral reference information."
LIMITS = {
    "request_messages": 512,
    "sources": 64,
    "comparisons": 4096,
    "source_codepoints": 65536,
    "call_json_nodes": 100000,
    "call_string_codepoints": 2097152,
    "context_output_bytes": 16777216,
    "graph_nodes": 20000,
    "graph_edges": 100000,
    "graph_labels": 4096,
    "structure_nodes": 4096,
    "structure_depth": 32,
    "judgment_codepoints": 16384,
    "results": 4096,
    "lineage_path_edges": 256,
}
_POINTER = re.compile(r"/data/body/messages/(0|[1-9][0-9]*)/content(?:/(0|[1-9][0-9]*)/text)?\Z")


def _metadata():
    return {
        "method": METHOD,
        "limits": copy.deepcopy(LIMITS),
        "auditor": "one_isolated_judgment_per_source; not_an_agent_rerun",
        "eligibility": "selected_sink; all_four_stages_scored_complete_negative_including_recovered_pairs",
        "context": "exact_recorded_request_prefix_only; repeated_source_occurrences_neutralized_together",
        "graph": "select_proposal_bound_context_edges; ignore_unrelated_final_graph_nodes_and_outcomes",
        "compatibility": "structural_scalar_types_and_container_shape_only; no_native_semantic_schema_validation",
        "serialization": "valid_JSON_stays_JSON; YAML_structures_stay_YAML; plain_prose_placeholder",
        "timestamp_neutralization": "local_fixed_epoch_date_or_midnight_datetime; preserve_timezone_awareness_and_offset",
        "judgment_language_check": "ASCII_English_compatible_prose_required; no_language_classifier",
        "neutrality_limitations": [
            "The fixed placeholder is a local design choice, not a proven task-neutral intervention.",
            "Structural field names and dialogue metadata remain unchanged and may retain information.",
            "Dependent later messages already present in the prefix are retained unchanged.",
            "One-source comparisons cannot identify joint or interacting causes.",
            "Auditor self-reported confidence is not calibrated causal probability.",
        ],
        "maliciousness": "not_assessed",
        "action_enforcement": "none",
    }


class _Skip(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise _Skip(reason)


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _hash(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else _canonical(value)).hexdigest()


def _bounded_json(value):
    stack, count, text_size = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        count += 1
        _require(count <= LIMITS["call_json_nodes"] and depth <= 64, "input_budget_exceeded")
        if isinstance(item, str):
            text_size += len(item)
            _require(text_size <= LIMITS["call_string_codepoints"], "input_budget_exceeded")
        elif type(item) in (int, bool) or item is None:
            pass
        elif type(item) is float:
            _require(math.isfinite(item), "non_json_input")
        elif isinstance(item, dict):
            _require(all(isinstance(key, str) for key in item), "non_json_input")
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        else:
            raise _Skip("non_json_input")


def _negative(pair):
    if pair.get("matched") is True:
        raise _Skip("explicit_candidate_present")
    _require(
        pair.get("status") == "scored"
        and pair.get("matched") is False
        and pair.get("complete") is True
        and pair.get("truncated") is False
        and pair.get("first_matched_tier") is None,
        "incomplete_explicit_evidence",
    )
    stages = pair.get("stages", {})
    semantic_threshold = 0.85 if pair.get("metadata", {}).get("profile") == "memory" else 0.60
    for name in ("tier1", "tier2", "tier3", "tier4"):
        stage = stages.get(name, {})
        _require(
            stage.get("status") == "scored"
            and stage.get("matched") is False
            and stage.get("complete") is True
            and stage.get("truncated") is False,
            "incomplete_explicit_evidence",
        )
        score = stage.get("score")
        _require(type(score) in (int, float) and math.isfinite(score), "incomplete_explicit_evidence")
        if name == "tier1":
            _require(score == 0, "inconsistent_explicit_evidence")
        elif name == "tier2":
            _require(0 <= score < 0.15, "inconsistent_explicit_evidence")
        elif name == "tier3":
            _require(-1 <= score < semantic_threshold, "inconsistent_explicit_evidence")
        if name == "tier4":
            coverage = stage.get("coverage")
            _require(
                type(coverage) in (int, float) and math.isfinite(coverage) and 0 <= coverage <= 1,
                "incomplete_explicit_evidence",
            )
            _require(
                -1 <= score <= 1 and not (score >= semantic_threshold and coverage >= 0.10),
                "inconsistent_explicit_evidence",
            )


def _index(graph, field, identity, limit):
    rows = graph.get(field)
    _require(isinstance(rows, list) and len(rows) <= limit, "missing_or_oversized_graph")
    _require(
        all(isinstance(row, dict) and isinstance(row.get(identity), str) for row in rows),
        "invalid_graph_identity",
    )
    indexed = {row[identity]: row for row in rows}
    _require(len(indexed) == len(rows), "duplicate_graph_identity")
    return indexed


def _source_binding(source, messages, call):
    _require(
        source.get("kind") == "tool" and source.get("policy", {}).get("eligible") is True,
        "source_not_eligible",
    )
    _require(
        source.get("run_id") == call["run_id"] and source.get("episode_id") == call["episode_id"],
        "foreign_source_identity",
    )
    text = source.get("text")
    _require(isinstance(text, str) and len(text) <= LIMITS["source_codepoints"], "source_budget_exceeded")
    _require(source.get("text_sha256") == _hash(text), "source_hash_mismatch")
    observed = source.get("first_observed_sequence")
    _require(type(observed) is int and 0 < observed < call["proposal_sequence"], "source_after_cutoff")
    _require(
        isinstance(source.get("exposure_event_id"), str) and source["exposure_event_id"],
        "missing_source_exposure",
    )
    match = _POINTER.fullmatch(source.get("request_pointer", ""))
    _require(match is not None, "unsupported_request_pointer")
    index, part = int(match[1]), match[2]
    _require(
        type(source.get("message_index")) is int
        and source["message_index"] == index
        and index < len(messages),
        "source_message_index_mismatch",
    )
    message = messages[index]
    _require(isinstance(message, dict) and message.get("role") == "tool", "source_not_tool_message")
    content = message.get("content")
    if part is None:
        _require(content == text, "source_text_mismatch")
    else:
        part = int(part)
        _require(
            isinstance(content, list)
            and part < len(content)
            and isinstance(content[part], dict)
            and content[part].get("type") == "text"
            and content[part].get("text") == text,
            "source_text_mismatch",
        )
    return index, part


def _neutralize(text):
    _require(bool(text.strip()), "empty_source_text")
    try:
        _require(
            not any(isinstance(token, (AliasToken, AnchorToken, TagToken)) for token in yaml.scan(text)),
            "unsupported_structural_alias_or_tag",
        )
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        raise _Skip("unsupported_source_serialization") from None
    changes, seen = [], set()
    loader = yaml.SafeLoader("")
    try:
        json.loads(text)
        is_json = True
    except (ValueError, RecursionError):
        is_json = False

    def scalar_digest(value):
        encoded = (
            {"scalar_type": type(value).__name__, "isoformat": value.isoformat()}
            if type(value) in (date, datetime)
            else value
        )
        return _hash(_canonical(encoded).decode())

    def walk(node, path, depth):
        _require(
            id(node) not in seen
            and len(seen) < LIMITS["structure_nodes"]
            and depth <= LIMITS["structure_depth"],
            "source_structure_budget_exceeded",
        )
        seen.add(id(node))
        if isinstance(node, MappingNode):
            result = {}
            for key, child in node.value:
                _require(
                    isinstance(key, ScalarNode) and key.tag == "tag:yaml.org,2002:str",
                    "unsupported_non_string_mapping_key",
                )
                _require(key.value not in result, "duplicate_structural_key")
                result[key.value] = walk(
                    child, path + "/" + key.value.replace("~", "~0").replace("/", "~1"), depth + 1
                )
            _require(
                not {"$schema", "$ref", "$defs"}.intersection(result)
                and not {"type", "properties"}.issubset(result),
                "schema_document_not_supported",
            )
            return result
        if isinstance(node, SequenceNode):
            return [walk(child, path + f"/{index}", depth + 1) for index, child in enumerate(node.value)]
        _require(
            isinstance(node, ScalarNode)
            and node.tag
            in {
                "tag:yaml.org,2002:str",
                "tag:yaml.org,2002:int",
                "tag:yaml.org,2002:float",
                "tag:yaml.org,2002:bool",
                "tag:yaml.org,2002:null",
                "tag:yaml.org,2002:timestamp",
            },
            "unsupported_scalar_type",
        )
        try:
            value = loader.construct_object(node, deep=True)
        except (ValueError, TypeError, OverflowError):
            raise _Skip("malformed_structural_scalar") from None
        _require(type(value) is not float or math.isfinite(value), "unsupported_nonfinite_scalar")
        replacement = (
            datetime(1970, 1, 1, tzinfo=value.tzinfo)
            if type(value) is datetime
            else date(1970, 1, 1)
            if type(value) is date
            else PLACEHOLDER
            if isinstance(value, str)
            else False
            if type(value) is bool
            else 0.0
            if type(value) is float
            else 0
            if type(value) is int
            else None
        )
        changes.append(
            {
                "path": path,
                "before_sha256": scalar_digest(value),
                "after_sha256": scalar_digest(replacement),
                "scalar_type": type(value).__name__,
            }
        )
        return replacement

    try:
        replaced = walk(root, "", 0)
    finally:
        loader.dispose()
    if is_json:
        after, method = (
            json.dumps(replaced, ensure_ascii=False, allow_nan=False),
            "JSON_scalar_neutralization",
        )
    elif isinstance(root, ScalarNode) and root.tag == "tag:yaml.org,2002:str":
        after, method = PLACEHOLDER, "plain_text_placeholder"
    else:
        after, method = (
            yaml.safe_dump(replaced, allow_unicode=True, sort_keys=False),
            "YAML_scalar_neutralization",
        )
    _require(after != text and bool(changes), "no_neutralizable_content")
    return after, method, changes


def _plan_probe(
    call: dict,
    graph: dict,
    *,
    negative_check=_negative,
    allow_no_argument_sink: bool = False,
) -> dict:
    """Build bounded detached A/B contexts from verified prefix evidence only.

    The wrapper must verify consistency of saved event/provenance files. Graph hashes are
    consistency checks, not authenticity guarantees; later graph data are ignored.
    Unsupported or ambiguous carriers are listed explicitly and never guessed.
    """
    plan = {
        "schema_version": 1,
        "method": METHOD,
        "proposal_event_id": None,
        "status": "skipped",
        "reason": None,
        "probes": [],
        "unsupported_sources": [],
        "metadata": _metadata(),
    }
    try:
        _require(isinstance(call, dict) and isinstance(graph, dict), "invalid_input")
        _bounded_json(call)
        plan["proposal_event_id"] = call.get("proposal_event_id")
        _require(call.get("policy", {}).get("sink", {}).get("selected") is True, "not_selected_sink")
        _require(call.get("component_mode") == "ordered_cascade", "missing_ordered_cascade")
        _require(
            type(call.get("proposal_sequence")) is int
            and type(call.get("request_sequence")) is int
            and 0 < call["request_sequence"] < call["proposal_sequence"]
            and call.get("cutoff_event_id") == call.get("proposal_event_id"),
            "invalid_prefix_cutoff",
        )
        messages = call.get("request_messages")
        _require(
            isinstance(messages, list) and 0 < len(messages) <= LIMITS["request_messages"],
            "missing_or_oversized_request",
        )
        visible = call.get("visible_sources")
        _require(isinstance(visible, list) and len(visible) <= LIMITS["sources"], "source_budget_exceeded")
        sources = [
            source
            for source in visible
            if source.get("kind") == "tool" and source.get("policy", {}).get("eligible") is True
        ]
        _require(bool(sources), "no_eligible_source")
        fields = [
            field
            for field in call.get("fields", [])
            if field.get("cascade_scope", {}).get("sink", {}).get("selected") is True
        ]
        no_argument_sink = allow_no_argument_sink and call.get("arguments") == {} and call.get("fields") == []
        _require(bool(fields) or no_argument_sink, "no_selected_argument_targets")
        expected = [
            (source["source_id"], source["request_pointer"], source["exposure_event_id"])
            for source in sources
        ]
        count = 0
        for field in fields:
            pairs = field.get("nt_style_cascade")
            _require(isinstance(pairs, list), "missing_explicit_evidence")
            count += len(pairs)
            _require(count <= LIMITS["comparisons"], "comparison_budget_exceeded")
            actual = [
                (pair.get("source_id"), pair.get("request_pointer"), pair.get("exposure_event_id"))
                for pair in pairs
            ]
            _require(sorted(actual) == sorted(expected), "missing_or_foreign_explicit_evidence")
            for pair in pairs:
                negative_check(pair)
        lineage = call.get("lineage")
        _require(
            isinstance(lineage, dict)
            and type(graph.get("schema_version")) is int
            and graph["schema_version"] == 1
            and graph.get("method") == "nt_style_dcpg_v1"
            and graph.get("failed") is False
            and graph.get("policy_sha256") == call["policy"].get("sha256"),
            "missing_or_incompatible_lineage",
        )
        recovered, recovered_pairs = lineage.get("recovered_sources"), lineage.get("comparisons")
        _require(
            isinstance(recovered, list) and isinstance(recovered_pairs, list), "missing_recovered_evidence"
        )
        _require(count + len(recovered_pairs) <= LIMITS["comparisons"], "comparison_budget_exceeded")
        recovered_expected = [
            (field["argument_path"], item["label_id"], item["carrier_source_id"])
            for field in fields
            for item in recovered
        ]
        _require(
            sorted(
                (item.get("argument_path"), item.get("label_id"), item.get("carrier_source_id"))
                for item in recovered_pairs
            )
            == sorted(recovered_expected),
            "missing_or_foreign_recovered_evidence",
        )
        for pair in recovered_pairs:
            negative_check(pair)
        nodes = _index(graph, "nodes", "node_id", LIMITS["graph_nodes"])
        edges = _index(graph, "edges", "edge_id", LIMITS["graph_edges"])
        labels = _index(graph, "registry", "label_id", LIMITS["graph_labels"])
        current = nodes.get(lineage.get("node_id"), {})
        _require(
            current.get("kind") == "tool_step"
            and all(
                current.get(key) == call.get(key)
                for key in (
                    "run_id",
                    "episode_id",
                    "proposal_event_id",
                    "proposal_sequence",
                    "function",
                    "arguments",
                )
            ),
            "lineage_proposal_mismatch",
        )
        grouped = {}
        for source in sources:
            grouped.setdefault(source["source_id"], []).append(source)
        output_bytes = 0
        for source_id, occurrences in grouped.items():
            try:
                bindings = [_source_binding(source, messages, call) for source in occurrences]
                source = occurrences[0]
                _require(
                    all(
                        item["text"] == source["text"]
                        and item["source_event_id"] == source["source_event_id"]
                        for item in occurrences
                    ),
                    "inconsistent_repeated_source",
                )
                _require(len(bindings) == len(set(bindings)), "duplicate_source_occurrence")
                direct = [label for label in labels.values() if label.get("source_id") == source_id]
                _require(len(direct) == 1, "missing_or_ambiguous_source_label")
                label = direct[0]
                _require(
                    all(
                        label.get(key) == source.get(key)
                        for key in (
                            "source_id",
                            "source_event_id",
                            "run_id",
                            "episode_id",
                            "text",
                            "text_sha256",
                        )
                    )
                    and label.get("policy_sha256") == call["policy"]["sha256"],
                    "source_label_mismatch",
                )
                origin, result = (
                    nodes.get(label.get("origin_node_id"), {}),
                    nodes.get(label.get("origin_result_node_id"), {}),
                )
                _require(
                    origin.get("kind") == "tool_step"
                    and origin.get("run_id") == call["run_id"]
                    and origin.get("episode_id") == call["episode_id"]
                    and origin.get("function") == source.get("origin_tool") == label.get("origin_tool")
                    and type(origin.get("proposal_sequence")) is int
                    and origin["proposal_sequence"] < call["request_sequence"]
                    and result.get("kind") == "tool_result"
                    and result.get("event_id") == source["source_event_id"]
                    and result.get("run_id") == call["run_id"]
                    and result.get("episode_id") == call["episode_id"],
                    "source_origin_not_in_prefix",
                )
                _require(
                    any(
                        edge.get("relation") == "tool_return"
                        and edge.get("from_node") == origin["node_id"]
                        and edge.get("to_node") == result["node_id"]
                        and edge.get("event_id") == source["source_event_id"]
                        for edge in edges.values()
                    ),
                    "missing_source_return_edge",
                )
                context_edges = [
                    edge["edge_id"]
                    for edge in edges.values()
                    if edge.get("relation") == "context_exposure"
                    and edge.get("event_id") == call["proposal_event_id"]
                    and edge.get("from_node") == result["node_id"]
                    and edge.get("to_node") == current["node_id"]
                    and label["label_id"] in edge.get("label_ids", [])
                ]
                _require(bool(context_edges), "missing_proposal_bound_context_edge")
                ancestors = [item for item in recovered if item.get("carrier_source_id") == source_id]
                _require(
                    len({item["origin_source_id"] for item in ancestors}) <= 1,
                    "inseparable_multiple_recovered_origins",
                )
                routes, references = [], []
                for ancestor in ancestors:
                    old = labels.get(ancestor.get("label_id"), {})
                    _require(
                        old.get("source_id") == ancestor.get("origin_source_id")
                        and isinstance(old.get("text"), str)
                        and len(old["text"]) <= LIMITS["source_codepoints"]
                        and old.get("text_sha256") == _hash(old["text"])
                        and old.get("text_sha256") == ancestor.get("original_text_sha256")
                        and old.get("text") == ancestor.get("original_text")
                        and old.get("origin_node_id") == ancestor.get("origin_node_id")
                        and old.get("policy_sha256") == call["policy"]["sha256"]
                        and ancestor.get("carrier_event_id") == source["source_event_id"]
                        and ancestor.get("carrier_node_id") == origin["node_id"],
                        "recovered_origin_binding_mismatch",
                    )
                    route = ancestor.get("path_edge_ids")
                    _require(
                        isinstance(route, list) and 0 < len(route) <= LIMITS["lineage_path_edges"],
                        "unsupported_recovered_path",
                    )
                    cursor = old["origin_node_id"]
                    for edge_id in route:
                        edge = edges.get(edge_id, {})
                        _require(
                            edge.get("from_node") == cursor
                            and edge.get("relation")
                            in {
                                "candidate_content",
                                "memory_persist",
                                "memory_append_preserved",
                                "memory_restore",
                            }
                            and old["label_id"] in edge.get("label_ids", [])
                            and edge.get("to_node") in nodes,
                            "disconnected_recovered_path",
                        )
                        cursor = edge["to_node"]
                        node = nodes[cursor]
                        if node.get("run_id") == call["run_id"] and node.get("kind") == "tool_step":
                            _require(
                                type(node.get("proposal_sequence")) is int
                                and node["proposal_sequence"] < call["proposal_sequence"],
                                "recovered_path_after_cutoff",
                            )
                    _require(
                        cursor == origin["node_id"] and edges[route[-1]].get("relation") == "memory_restore",
                        "recovered_path_not_to_carrier",
                    )
                    _require(
                        edges[route[-1]].get("event_id")
                        in {item["exposure_event_id"] for item in occurrences},
                        "recovered_path_not_current_exposure",
                    )
                    routes.extend(route)
                    references.append(
                        {
                            key: ancestor[key]
                            for key in (
                                "label_id",
                                "origin_source_id",
                                "origin_node_id",
                                "carrier_source_id",
                                "carrier_event_id",
                                "record_key",
                                "version",
                                "content_sha256",
                            )
                        }
                    )
                after, method, leaf_changes = _neutralize(source["text"])
                context_a, context_b = copy.deepcopy(messages), copy.deepcopy(messages)
                replacements = []
                for occurrence, (index, part) in zip(occurrences, bindings, strict=True):
                    if part is None:
                        context_b[index]["content"] = after
                    else:
                        context_b[index]["content"][part]["text"] = after
                    replacements.append(
                        {
                            "request_pointer": occurrence["request_pointer"],
                            "message_index": index,
                            "before_sha256": _hash(source["text"]),
                            "after_sha256": _hash(after),
                            "method": method,
                            "leaf_paths": [item["path"] for item in leaf_changes],
                            "leaf_replacements": copy.deepcopy(leaf_changes),
                        }
                    )
                output_bytes += len(_canonical(context_a)) + len(_canonical(context_b))
                _require(output_bytes <= LIMITS["context_output_bytes"], "context_output_budget_exceeded")
                probe = {
                    "probe_id": "probe:"
                    + _hash([call["run_id"], call["proposal_event_id"], source_id, replacements]),
                    "source_id": source_id,
                    "label_ids": sorted({label["label_id"], *(item["label_id"] for item in ancestors)}),
                    "origin_source_ids": sorted(
                        {source_id, *(item["origin_source_id"] for item in ancestors)}
                    ),
                    "context_a": context_a,
                    "context_b": context_b,
                    "sink": {"function": call["function"], "arguments": copy.deepcopy(call["arguments"])},
                    "replacements": replacements,
                    "lineage": {
                        "context_edge_ids": sorted(context_edges),
                        "origin_node_ids": [origin["node_id"]],
                        "recovered_origin_refs": references,
                        "path_edge_ids": list(dict.fromkeys(routes)),
                        "path_confidence": None,
                    },
                }
                plan["probes"].append(probe)
            except _Skip as error:
                plan["unsupported_sources"].append({"source_id": source_id, "reason": str(error)})
        plan.update(
            status="eligible" if plan["probes"] else "skipped",
            reason="complete_negative_explicit_evidence" if plan["probes"] else "no_supported_source",
        )
    except _Skip as error:
        plan.update(status="skipped", reason=str(error), probes=[])
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError, OverflowError):
        plan.update(status="skipped", reason="malformed_evidence", probes=[])
    return plan


def plan_probe(call: dict, graph: dict) -> dict:
    """Version 1 planner: require complete negative evidence from all four tiers."""
    return _plan_probe(call, graph)


def parse_judgment(raw: str) -> dict:
    """Parse one strict JSON judgment; invalid/unknown never becomes no-alert."""
    invalid = {"status": "invalid", "reason": "invalid_judgment_schema"}
    if not isinstance(raw, str) or len(raw) > LIMITS["judgment_codepoints"]:
        return {"status": "invalid", "reason": "judgment_input_budget_or_type"}

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate judgment key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())
        )
        if not isinstance(value, dict) or set(value) != {"would_call_anyway", "confidence", "reasoning"}:
            return invalid
        confidence, reasoning = value["confidence"], value["reasoning"]
        if (
            type(value["would_call_anyway"]) is not bool
            or type(confidence) not in (int, float)
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
            or not isinstance(reasoning, str)
            or not reasoning.strip()
            or not reasoning.isascii()
            or not re.search(r"[A-Za-z]", reasoning)
            or any(ord(character) < 32 and character not in "\n\t\r" for character in reasoning)
        ):
            return invalid
        return {"status": "valid", "judgment": value}
    except (ValueError, TypeError, RecursionError, OverflowError):
        return invalid


def summarize_results(results: list[dict]) -> dict:
    """Only a valid false answer alerts; unknown evidence remains explicit."""
    summary = {
        "status": "unknown",
        "alert": None,
        "confidence": None,
        "total_count": None,
        "valid_count": 0,
        "unknown_count": 0,
        "alert_count": 0,
        "interpretation": "auditor_judgment_only; no_threshold_or_joint_causality_inference",
    }
    if not isinstance(results, list) or len(results) > LIMITS["results"]:
        summary["reason"] = "result_input_budget_or_type"
        return summary
    summary["total_count"] = len(results)
    confidences = []
    for item in results:
        parsed = {"status": "invalid"}
        if isinstance(item, dict) and item.get("status") == "valid":
            try:
                parsed = parse_judgment(json.dumps(item.get("judgment"), allow_nan=False))
            except (TypeError, ValueError, OverflowError, RecursionError):
                pass
        if parsed["status"] != "valid":
            summary["unknown_count"] += 1
            continue
        summary["valid_count"] += 1
        if parsed["judgment"]["would_call_anyway"] is False:
            confidences.append(parsed["judgment"]["confidence"])
    summary["alert_count"] = len(confidences)
    if confidences:
        summary.update(status="alert", alert=True, confidence=max(confidences))
    elif results and summary["unknown_count"] == 0:
        summary.update(status="no_alert", alert=False)
    return summary
