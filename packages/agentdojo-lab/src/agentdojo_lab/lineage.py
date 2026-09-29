"""Passive, exact-bound memory lineage over already validated recorder events.

The graph stores candidate evidence and structural continuity separately. It does
not change model inputs, trust labels supplied inside tool content, or establish
maliciousness or causal influence. Checkpoint loading does not restore agent data.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.provenance import structured_scalars

METHOD = "nt_style_dcpg_v1"
LIMITS = {
    "nodes": 20_000,
    "edges": 100_000,
    "registry": 4_096,
    "memory_bindings": 4_096,
    "memory_events": 20_000,
    "source_codepoints": 65_536,
    "retained_text_codepoints": 4_194_304,
    "records_per_result": 128,
    "checkpoint_bytes": 33_554_432,
}
READ_TOOLS = frozenset({"get_file_by_id", "list_files", "search_files", "search_files_by_filename"})
WRITE_TOOLS = frozenset({"create_file", "append_to_file", "delete_file"})
ASSUMPTIONS = {
    "adapter": "workspace_cloud_drive_id_and_content_v1",
    "write_confirmation": "runtime_success_and_correlated_visible_tool_result_matching_proposed_content",
    "restore": "exact_namespace_record_key_and_original_UTF8_content_SHA256; actual_request_exposure_required",
    "metadata": "trusted_sidecar_only; tool_content_nt_taint_is_not_imported",
    "transformation": "candidate_cascade_evidence_at_write; exact_stored_value_binding_at_read",
    "confidence": "per_comparison_scores_only; path_confidence_not_defined",
    "episode_reset": "retire_active_bindings_on_subsequent_episode; first_episode_after_load_may_restore",
    "context": "loaded_labels_dormant_until_verified_memory_result_exposure",
    "retrieval_time": "freeze_binding_at_successful_visible_tool_result; reexposure_preserves_that_historical_result",
    "environment": "checkpoint_restores_observer_state_only; caller_must_restore_actual_store_separately",
    "graph": "tool_step_core_with_tool_result_and_memory_version_structural_nodes",
    "inference": "no_blanket_taint_of_tool_outputs; no_causal_or_malicious_verdict",
}


class LineageBudgetError(ValueError):
    """The declared lineage resource budget was exceeded."""


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _message_texts(message: dict) -> list[str]:
    content = message.get("content")
    if isinstance(content, str):
        return [content]
    texts = []
    for part in content or []:
        if isinstance(part, dict) and part.get("type") == "text":
            # Native AgentDojo TextContent uses content; HTTP text parts use text.
            text = part.get("text", part.get("content"))
            if isinstance(text, str):
                texts.append(text)
    return texts


def _records(text: str) -> list[dict]:
    if len(text) > LIMITS["source_codepoints"]:
        raise LineageBudgetError("source_codepoints")
    parsed = structured_scalars(text)
    if parsed["status"] != "parsed":
        return []
    groups = {}
    for scalar in parsed["scalars"]:
        match = re.fullmatch(r"(?:/(\d+))?/(id_|content)", scalar["field_path"])
        if match:
            groups.setdefault(match[1], {})[match[2]] = scalar["value"]
    if len(groups) > LIMITS["records_per_result"]:
        raise LineageBudgetError("records_per_result")
    records = []
    seen = set()
    for value in groups.values():
        if set(value) == {"id_", "content"} and value["id_"]:
            if value["id_"] in seen:
                return []  # Ambiguous duplicate record identity is not an exact binding.
            seen.add(value["id_"])
            records.append({"record_key": value["id_"], "content": value["content"]})
    return records


class DCPG:
    def __init__(self, namespace: str, policy, semantic_matcher=None, *, canary_enabled=False):
        if not isinstance(namespace, str) or not namespace.strip() or len(namespace) > 256:
            raise ValueError("A nonempty bounded store namespace is required")
        self.namespace, self.policy = namespace, policy
        self.policy_sha256 = policy.metadata["sha256"]
        self.canary_enabled = canary_enabled
        self.matcher = CascadeMatcher.for_memory(semantic_matcher, canary_enabled=canary_enabled)
        self.nodes, self.edges, self.registry, self.memory_bindings = {}, {}, {}, {}
        self.memory_events = []
        self._calls, self._results, self._direct, self._carriers = {}, {}, {}, {}
        self._episode = None
        self._run = None
        self._sequence = 0
        self._seen_events = set()
        self._failed = False
        self._parent_checkpoint_sha256 = None

    @property
    def metadata(self):
        return copy.deepcopy(
            {
                "method": METHOD,
                "namespace": self.namespace,
                "policy_sha256": self.policy_sha256,
                "assumptions": ASSUMPTIONS,
                "limits": LIMITS,
                "memory_cascade": self.matcher.metadata,
                **(
                    {"canary_condition": "canary_intervention; persist_original_marker_references"}
                    if self.canary_enabled
                    else {}
                ),
                "maliciousness": "not_assessed",
                "causal_influence": "not_assessed",
            }
        )

    def _id(self, kind, *parts):
        return f"{kind}:" + _digest([self.namespace, *parts])

    @staticmethod
    def _call_key(event):
        return event["run_id"], event["episode_id"], event.get("call_ref")

    @staticmethod
    def _request_key(event):
        return event["run_id"], event["episode_id"], event.get("model_request_id")

    def _edge(self, source, target, relation, *, labels=(), evidence=None, event_id=None):
        details = {
            "from_node": source,
            "to_node": target,
            "relation": relation,
            "label_ids": sorted(set(labels)),
            "event_id": event_id,
            "candidate": relation == "candidate_content",
            "path_confidence": None,
            "tier": evidence.get("first_matched_tier") if evidence else None,
            "evidence_score": None,
            "evidence": copy.deepcopy(evidence),
        }
        if evidence and details["tier"]:
            details["evidence_score"] = evidence["stages"][details["tier"]].get("score")
        edge_id = self._id("edge", details)
        self.edges.setdefault(edge_id, {"edge_id": edge_id, **details})
        return edge_id

    def _memory_event(self, event, status, **details):
        record = {
            "event_id": event["event_id"],
            "run_id": event["run_id"],
            "episode_id": event["episode_id"],
            "call_ref": event.get("call_ref"),
            "status": status,
            **details,
            "propagation_verdict": "not_emitted",
        }
        self.memory_events.append(record)
        return record

    def _budget(self):
        for name in ("nodes", "edges", "registry", "memory_bindings", "memory_events"):
            if len(getattr(self, name)) > LIMITS[name]:
                raise LineageBudgetError(name)
        total = sum(len(item["text"]) for item in self.registry.values())
        total += sum(len(item["content"]) for item in self.memory_bindings.values())
        if total > LIMITS["retained_text_codepoints"]:
            raise LineageBudgetError("retained_text_codepoints")

    def _register_sources(self, event, sources):
        result = self._results.get((event["run_id"], event["data"]["source_result_event_id"]))
        if result is None:
            raise ValueError("Exposed source lacks its observed tool result")
        request_key = self._request_key(event)
        for source in sources:
            if (
                source.get("exposure_event_id") != event["event_id"]
                or source.get("source_event_id") != event["data"]["source_result_event_id"]
            ):
                raise ValueError("Source occurrence does not match the verified exposure")
            if source.get("kind") != "tool" or not source.get("policy", {}).get("eligible"):
                continue
            if len(source["text"]) > LIMITS["source_codepoints"]:
                raise LineageBudgetError("source_codepoints")
            label_id = self._id("label", source["source_id"])
            self.registry.setdefault(
                label_id,
                {
                    "label_id": label_id,
                    "source_id": source["source_id"],
                    "source_event_id": source["source_event_id"],
                    "origin_node_id": result["step_id"],
                    "origin_result_node_id": result["result_node_id"],
                    "run_id": event["run_id"],
                    "episode_id": event["episode_id"],
                    "origin_tool": source.get("origin_tool"),
                    "text": source["text"],
                    "text_sha256": _content_hash(source["text"]),
                    "policy_sha256": self.policy_sha256,
                    "path_confidence": None,
                    **(
                        {"canary": copy.deepcopy(source["canary"])}
                        if self.canary_enabled and "canary" in source
                        else {}
                    ),
                },
            )
            self._direct[(request_key, source["source_id"])] = label_id
            if result["function"] not in READ_TOOLS or not result["success"]:
                continue
            exposed = _records(source["text"])
            if not exposed:
                self._memory_event(event, "no_extractable_memory_record")
            for record in exposed:
                key = record["record_key"]
                if result["function"] == "get_file_by_id" and result["arguments"].get("file_id") != key:
                    self._memory_event(event, "retrieval_key_mismatch", record_key=key)
                    continue
                binding = result["memory_candidates"].get(key)
                if binding is None:
                    self._memory_event(event, "no_binding_at_retrieval", record_key=key)
                    continue
                if _content_hash(record["content"]) != binding["content_sha256"]:
                    self._memory_event(event, "retrieval_exposure_content_mismatch", record_key=key)
                    continue
                restore = self._edge(
                    binding["node_id"],
                    result["step_id"],
                    "memory_restore",
                    labels=binding["_nt_taint"],
                    event_id=event["event_id"],
                )
                carriers = self._carriers.setdefault((request_key, source["source_id"]), [])
                for original_label in binding["_nt_taint"]:
                    ancestor = self.registry[original_label]
                    carrier = {
                        "label_id": original_label,
                        "origin_source_id": ancestor["source_id"],
                        "origin_node_id": ancestor["origin_node_id"],
                        "original_text": ancestor["text"],
                        "original_text_sha256": ancestor["text_sha256"],
                        **(
                            {"original_canary": copy.deepcopy(ancestor["canary"])}
                            if "canary" in ancestor
                            else {}
                        ),
                        "carrier_source_id": source["source_id"],
                        "carrier_event_id": source["source_event_id"],
                        "carrier_node_id": result["step_id"],
                        "record_key": key,
                        "version": binding["version"],
                        "content_sha256": binding["content_sha256"],
                        "path_edge_ids": [*binding["paths"][original_label], restore],
                    }
                    if carrier not in carriers:
                        carriers.append(carrier)
                self._memory_event(
                    event,
                    "lineage_restored",
                    record_key=key,
                    version=binding["version"],
                    label_count=len(binding["_nt_taint"]),
                )

    def _proposal(self, event, call):
        if call is None:
            raise ValueError("A validated call analysis is required at proposal time")
        key = self._call_key(event)
        if key in self._calls:
            raise ValueError("Duplicate lineage tool proposal")
        node_id = self._id("step", event["run_id"], event["episode_id"], event["event_id"])
        self.nodes[node_id] = {
            "node_id": node_id,
            "kind": "tool_step",
            "run_id": event["run_id"],
            "episode_id": event["episode_id"],
            "proposal_event_id": event["event_id"],
            "proposal_sequence": event["event_sequence"],
            "call_ref": event["call_ref"],
            "function": call["function"],
            "arguments": copy.deepcopy(call["arguments"]),
            "outcome": "proposed",
            "label_ids": [],
        }
        current = {
            "node_id": node_id,
            "function": call["function"],
            "arguments": copy.deepcopy(call["arguments"]),
            "request_id": event["model_request_id"],
            "started": False,
            "success": False,
            "content_paths": {},
        }
        self._calls[key] = current
        request_key = self._request_key(event)
        recovered, comparisons, paths = [], [], []
        for source in call["visible_sources"]:
            direct = self._direct.get((request_key, source["source_id"]))
            if direct:
                self._edge(
                    self.registry[direct]["origin_result_node_id"],
                    node_id,
                    "context_exposure",
                    labels=[direct],
                    event_id=event["event_id"],
                )
            recovered.extend(copy.deepcopy(self._carriers.get((request_key, source["source_id"]), [])))
        for field in call["fields"]:
            for pair in field.get("nt_style_cascade", []):
                label = self._direct.get((request_key, pair["source_id"]))
                if label and pair["matched"] is True:
                    edge = self._edge(
                        self.registry[label]["origin_node_id"],
                        node_id,
                        "candidate_content",
                        labels=[label],
                        evidence={"argument_path": field["argument_path"], **pair},
                        event_id=event["event_id"],
                    )
                    paths.append({"label_id": label, "edge_ids": [edge], "path_confidence": None})
                    if field["argument_path"] == "/content":
                        current["content_paths"].setdefault(label, [edge])
            if not field.get("cascade_scope", {}).get("sink", {}).get("selected"):
                continue
            value = field["value"]
            target = (
                value
                if isinstance(value, str)
                else json.dumps(value, ensure_ascii=False, allow_nan=False)
                if value is None or type(value) in (bool, int, float)
                else ""
            )
            for carrier in recovered:
                evidence = self.matcher.compare(
                    carrier["original_text"],
                    target,
                    **({"canary": carrier.get("original_canary")} if self.canary_enabled else {}),
                )
                comparison = {
                    "argument_path": field["argument_path"],
                    "label_id": carrier["label_id"],
                    "carrier_source_id": carrier["carrier_source_id"],
                    **evidence,
                }
                comparisons.append(comparison)
                if evidence["status"] == "encoder_error":
                    raise ValueError("Recovered lineage encoder failure")
                if evidence["matched"] is True:
                    edge = self._edge(
                        carrier["carrier_node_id"],
                        node_id,
                        "candidate_content",
                        labels=[carrier["label_id"]],
                        evidence=comparison,
                        event_id=event["event_id"],
                    )
                    route = [*carrier["path_edge_ids"], edge]
                    paths.append(
                        {"label_id": carrier["label_id"], "edge_ids": route, "path_confidence": None}
                    )
                    if field["argument_path"] == "/content":
                        current["content_paths"].setdefault(carrier["label_id"], route)
        self.nodes[node_id]["label_ids"] = sorted({path["label_id"] for path in paths})
        call["lineage"] = {
            "node_id": node_id,
            "recovered_sources": recovered,
            "comparisons": comparisons,
            "paths": paths,
            "memory_events": copy.deepcopy(
                [
                    item
                    for item in self.memory_events
                    if item["run_id"] == event["run_id"] and item["episode_id"] == event["episode_id"]
                ]
            ),
            "summary": {
                "recovered_source_count": len(recovered),
                "comparison_count": len(comparisons),
                "matched_comparison_count": sum(item["matched"] is True for item in comparisons),
                "incomplete_comparison_count": sum(
                    not item["complete"] and item["status"] != "not_applicable" for item in comparisons
                ),
                "status": "recovered_candidates"
                if any(item["matched"] is True for item in comparisons)
                else "incomplete_recovered_analysis"
                if any(item["status"] in {"indeterminate", "encoder_error"} for item in comparisons)
                else "no_recovered_lineage"
                if not recovered
                else "no_selected_argument_targets"
                if not comparisons
                else "not_applicable_comparisons"
                if all(item["status"] == "not_applicable" for item in comparisons)
                else "no_recovered_candidate",
                "maliciousness": "not_assessed",
                "causal_influence": "not_assessed",
            },
        }
        return call

    def _result(self, event):
        current = self._calls.get(self._call_key(event))
        if current is None or current["request_id"] != event["model_request_id"]:
            raise ValueError("Tool result lacks its correlated lineage proposal")
        result_id = self._id("result", event["run_id"], event["episode_id"], event["event_id"])
        success = current["success"] and event["data"]["message"].get("error") is None
        self.nodes[result_id] = {
            "node_id": result_id,
            "kind": "tool_result",
            "run_id": event["run_id"],
            "episode_id": event["episode_id"],
            "event_id": event["event_id"],
            "outcome": "success" if success else "unconfirmed_or_failed",
            "label_ids": [],
        }
        self.nodes[current["node_id"]]["outcome"] = self.nodes[result_id]["outcome"]
        self._edge(current["node_id"], result_id, "tool_return", event_id=event["event_id"])
        self._results[(event["run_id"], event["event_id"])] = {
            "step_id": current["node_id"],
            "result_node_id": result_id,
            "function": current["function"],
            "arguments": current["arguments"],
            "success": success,
            "memory_candidates": {},
        }
        function = current["function"]
        if function in READ_TOOLS and success:
            # Freeze storage identity at read time, before any later writes. These
            # candidates remain dormant until this exact result enters a request.
            candidates = self._results[(event["run_id"], event["event_id"])]["memory_candidates"]
            records = [
                record for text in _message_texts(event["data"]["message"]) for record in _records(text)
            ]
            for record in records:
                key = record["record_key"]
                if function == "get_file_by_id" and current["arguments"].get("file_id") != key:
                    continue
                binding = self.memory_bindings.get(key)
                if binding is None or not binding["active"]:
                    self._memory_event(event, "no_active_binding", record_key=key)
                    continue
                if record["content"] != binding["content"]:
                    binding.update(active=False, inactive_reason="observed_retrieval_content_mismatch")
                    self._memory_event(event, "retrieval_content_mismatch", record_key=key)
                    continue
                candidates[key] = copy.deepcopy(
                    {
                        name: binding[name]
                        for name in ("node_id", "version", "content_sha256", "_nt_taint", "paths")
                    }
                )
        if function not in WRITE_TOOLS:
            return
        if not success:
            self._memory_event(event, "write_not_confirmed", function=function)
            return
        records = [record for text in _message_texts(event["data"]["message"]) for record in _records(text)]
        if len(records) != 1:
            self._memory_event(event, "unsupported_write_result", function=function)
            return
        record = records[0]
        key, content = record["record_key"], record["content"]
        previous = self.memory_bindings.get(key)
        if function != "create_file" and current["arguments"].get("file_id") != key:
            self._memory_event(event, "write_key_mismatch", record_key=key)
            return
        if function == "delete_file":
            if previous and previous["active"]:
                previous.update(
                    active=False, inactive_reason="deleted", invalidated_event_id=event["event_id"]
                )
            self._memory_event(
                event, "binding_deleted" if previous else "delete_without_binding", record_key=key
            )
            return
        intended = current["arguments"].get("content")
        if not isinstance(intended, str):
            self._memory_event(event, "unsupported_write_arguments", record_key=key)
            return
        paths = copy.deepcopy(current["content_paths"])
        if function == "append_to_file":
            if not previous or not previous["active"]:
                self._memory_event(event, "append_without_prior_binding", record_key=key)
                return
            if previous["content"] + intended != content:
                previous.update(active=False, inactive_reason="append_content_mismatch")
                self._memory_event(event, "append_content_mismatch", record_key=key)
                return
            for label, route in previous["paths"].items():
                paths.setdefault(label, route)
        elif intended != content:
            if previous and previous["active"]:
                previous.update(active=False, inactive_reason="write_content_mismatch")
            self._memory_event(event, "write_content_mismatch", record_key=key)
            return
        version = previous["version"] + 1 if previous else 1
        node_id = self._id("memory", event["run_id"], event["event_id"], key, version, _content_hash(content))
        self.nodes[node_id] = {
            "node_id": node_id,
            "kind": "memory_version",
            "run_id": event["run_id"],
            "episode_id": event["episode_id"],
            "record_key": key,
            "version": version,
            "content_sha256": _content_hash(content),
            "label_ids": sorted(paths),
        }
        edge = self._edge(
            current["node_id"], node_id, "memory_persist", labels=paths, event_id=event["event_id"]
        )
        if function == "append_to_file":
            previous_edge = self._edge(
                previous["node_id"],
                node_id,
                "memory_append_preserved",
                labels=previous["_nt_taint"],
                event_id=event["event_id"],
            )
            paths = {
                label: [
                    *route,
                    previous_edge
                    if label in previous["paths"] and route == previous["paths"][label]
                    else edge,
                ]
                for label, route in paths.items()
            }
        else:
            paths = {label: [*route, edge] for label, route in paths.items()}
        self.memory_bindings[key] = {
            "namespace": self.namespace,
            "record_key": key,
            "version": version,
            "node_id": node_id,
            "content": content,
            "content_sha256": _content_hash(content),
            "confirmed_write_event_id": event["event_id"],
            "run_id": event["run_id"],
            "episode_id": event["episode_id"],
            "active": True,
            "_nt_taint": sorted(paths),
            "paths": paths,
        }
        self._memory_event(
            event, "binding_committed", record_key=key, version=version, label_count=len(paths)
        )

    def consume(self, event: dict, call: dict | None = None, exposed_sources: list[dict] | None = None):
        if self._failed:
            raise ValueError("Lineage is disabled after an earlier failure")
        try:
            event, call, sources = copy.deepcopy((event, call, exposed_sources or []))
            if self._run is None:
                if any(node.get("run_id") == event["run_id"] for node in self.nodes.values()):
                    raise ValueError("A loaded checkpoint requires a fresh run identity")
                self._run = event["run_id"]
            if (
                event["run_id"] != self._run
                or type(event["event_sequence"]) is not int
                or event["event_sequence"] != self._sequence + 1
                or event["event_id"] in self._seen_events
            ):
                raise ValueError("Lineage requires one consecutive, unique event stream")
            self._sequence = event["event_sequence"]
            self._seen_events.add(event["event_id"])
            kind = event["event_type"]
            if kind == "EPISODE_STARTED":
                if self._episode is not None:
                    for binding in self.memory_bindings.values():
                        if binding["active"]:
                            binding.update(active=False, inactive_reason="episode_environment_reset")
                    self._memory_event(event, "episode_bindings_retired")
                self._episode = event["episode_id"]
            elif kind == "TOOL_CALL_PROPOSED":
                call = self._proposal(event, call)
            elif kind in {"TOOL_RUNTIME_STARTED", "TOOL_RUNTIME_RETURNED"}:
                current = self._calls.get(self._call_key(event))
                if current is None or current["request_id"] != event["model_request_id"]:
                    raise ValueError("Runtime event lacks correlated lineage proposal")
                if kind == "TOOL_RUNTIME_STARTED":
                    current["started"] = True
                else:
                    data = event["data"]
                    current["success"] = (
                        current["started"]
                        and "error" in data
                        and data["error"] is None
                        and "raised_exception_type" in data
                        and data["raised_exception_type"] is None
                    )
            elif kind == "TOOL_RESULT":
                self._result(event)
            elif kind == "TOOL_OUTPUT_EXPOSED":
                self._register_sources(event, sources)
            self._budget()
            return copy.deepcopy(call)
        except Exception:
            self._failed = True
            raise

    def snapshot(self):
        return copy.deepcopy(
            {
                "schema_version": 1,
                "method": METHOD,
                "namespace": self.namespace,
                "policy_sha256": self.policy_sha256,
                "metadata": self.metadata,
                "parent_checkpoint_sha256": self._parent_checkpoint_sha256,
                "failed": self._failed,
                "nodes": list(self.nodes.values()),
                "edges": list(self.edges.values()),
                "registry": list(self.registry.values()),
                "memory_bindings": list(self.memory_bindings.values()),
                "memory_events": self.memory_events,
            }
        )

    def save_state(self, path: Path):
        if self._failed:
            raise ValueError("Cannot checkpoint incomplete lineage state")
        self._budget()
        state = self.snapshot()
        digest = _digest(state)
        raw = _canonical({"schema_version": 1, "state_sha256": digest, "state": state}) + b"\n"
        if len(raw) > LIMITS["checkpoint_bytes"]:
            raise LineageBudgetError("checkpoint_bytes")
        with Path(path).open("xb") as stream:
            if stream.write(raw) != len(raw):
                raise OSError("Incomplete checkpoint write")
            stream.flush()
        return {
            "path": str(path),
            "state_sha256": digest,
            "file_sha256": hashlib.sha256(raw).hexdigest(),
            "flush_semantics": "Python_file_flush; not_fsync",
        }

    @classmethod
    def load_state(cls, path: Path, namespace: str, policy, semantic_matcher=None, *, canary_enabled=False):
        with Path(path).open("rb") as stream:
            raw = stream.read(LIMITS["checkpoint_bytes"] + 1)
        if len(raw) > LIMITS["checkpoint_bytes"]:
            raise LineageBudgetError("checkpoint_bytes")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate checkpoint key")
                result[key] = value
            return result

        envelope = json.loads(raw, object_pairs_hook=unique)
        state = envelope["state"]
        if (
            type(envelope.get("schema_version")) is not int
            or envelope["schema_version"] != 1
            or type(state.get("schema_version")) is not int
            or state["schema_version"] != 1
            or state.get("method") != METHOD
            or state.get("failed") is not False
        ):
            raise ValueError("Unsupported or incomplete lineage checkpoint")
        if _digest(state) != envelope["state_sha256"]:
            raise ValueError("Lineage checkpoint digest mismatch")
        graph = cls(namespace, policy, semantic_matcher, canary_enabled=canary_enabled)
        if state["namespace"] != namespace or state["policy_sha256"] != graph.policy_sha256:
            raise ValueError("Checkpoint namespace or policy mismatch")
        if state["metadata"] != graph.metadata:
            raise ValueError("Checkpoint lineage method configuration mismatch")
        for field, id_field in (
            ("nodes", "node_id"),
            ("edges", "edge_id"),
            ("registry", "label_id"),
            ("memory_bindings", "record_key"),
        ):
            values = state[field]
            mapped = {value[id_field]: value for value in values}
            if len(mapped) != len(values):
                raise ValueError("Duplicate checkpoint identity")
            setattr(graph, field, mapped)
        graph.memory_events = state["memory_events"]
        graph._parent_checkpoint_sha256 = envelope["state_sha256"]
        for node in graph.nodes.values():
            if node["kind"] not in {"tool_step", "tool_result", "memory_version"} or any(
                label not in graph.registry for label in node["label_ids"]
            ):
                raise ValueError("Invalid graph node or dangling node label")
        for label in graph.registry.values():
            if (
                label["origin_node_id"] not in graph.nodes
                or label["origin_result_node_id"] not in graph.nodes
                or label["text_sha256"] != _content_hash(label["text"])
                or label["policy_sha256"] != graph.policy_sha256
            ):
                raise ValueError("Invalid source registry reference")
            if "canary" in label:
                from agentdojo_lab.canary import validate_reference

                if (
                    not graph.canary_enabled
                    or label["canary"].get("source_result_event_id") != label["source_event_id"]
                    or label["canary"].get("policy_sha256") != graph.policy_sha256
                ):
                    raise ValueError("Invalid persisted canary source binding")
                validate_reference(label["canary"], label["text"])
        for edge in graph.edges.values():
            if (
                edge["from_node"] not in graph.nodes
                or edge["to_node"] not in graph.nodes
                or any(label not in graph.registry for label in edge["label_ids"])
                or edge["path_confidence"] is not None
                or edge["relation"]
                not in {
                    "candidate_content",
                    "context_exposure",
                    "tool_return",
                    "memory_restore",
                    "memory_persist",
                    "memory_append_preserved",
                }
                or edge["candidate"] is not (edge["relation"] == "candidate_content")
                or (
                    not edge["candidate"] and (edge["tier"] is not None or edge["evidence_score"] is not None)
                )
            ):
                raise ValueError("Dangling or invalid graph edge")
        for binding in graph.memory_bindings.values():
            if (
                binding["namespace"] != namespace
                or binding["node_id"] not in graph.nodes
                or binding["content_sha256"] != _content_hash(binding["content"])
                or type(binding["active"]) is not bool
                or type(binding["version"]) is not int
                or binding["version"] < 1
                or set(binding["paths"]) != set(binding["_nt_taint"])
            ):
                raise ValueError("Invalid memory binding")
            for label, path_edges in binding["paths"].items():
                if (
                    label not in graph.registry
                    or not path_edges
                    or any(edge not in graph.edges for edge in path_edges)
                ):
                    raise ValueError("Dangling memory lineage path")
                prior = graph.registry[label]["origin_node_id"]
                for edge_id in path_edges:
                    edge = graph.edges[edge_id]
                    if edge["from_node"] != prior or label not in edge["label_ids"]:
                        raise ValueError("Disconnected memory lineage path")
                    prior = edge["to_node"]
                if prior != binding["node_id"]:
                    raise ValueError("Memory lineage does not reach its binding")
        graph._budget()
        return graph
