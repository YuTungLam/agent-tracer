"""Bounded, offline comparison of caller-labelled two-session run pairs.

The exporter describes recorded actions and session-boundary evidence. It never
infers causal influence, hidden reasoning, maliciousness, or attack success.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
from urllib.parse import quote

import yaml

from agentdojo_lab.canary import validate_reference
from agentdojo_lab.html_report import collect_run_record
from agentdojo_lab.lineage import LIMITS as LINEAGE_LIMITS
from agentdojo_lab.lineage import METHOD as LINEAGE_METHOD
from agentdojo_lab.paired_report import compare_records

MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_RUN_INPUT_BYTES = 64 * 1024 * 1024
MAX_NATIVE_JSON_FILES = 128
MAX_NATIVE_ENTRIES = 512
MAX_PATH_EDGE_REFS = 200_000
SCOPE = (
    "Offline descriptive comparison of two ordered sessions per caller-labelled condition. "
    "Actions are aligned independently within session A and session B using the displayed "
    "edit rule. Event IDs, call IDs, episode IDs, and action indices remain local to their "
    "recorded run. Session-boundary fields report only direct identity, content-hash, native "
    "file, event, and lineage evidence. Missing evidence is unknown. Correspondence, lineage "
    "candidates, and clean/attacked differences do not establish causal influence, hidden "
    "reasoning, maliciousness, or attack success. Condition labels are supplied by the caller."
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def _validate_run_budget(path: Path, *, additional: tuple[Path, ...] = ()):
    if not path.is_dir():
        raise ValueError(f"Run directory does not exist: {path}")
    candidates = [
        path / name
        for name in (
            "manifest.json",
            "summary.json",
            "events.jsonl",
            "provenance.jsonl",
            "causal-online.jsonl",
            "causal-online-graph.json",
            "lineage-state.json",
            "lineage-initial-state.json",
            "final-environment.json",
            "native-memory.json",
        )
    ]
    additional = tuple(Path(candidate) for candidate in additional)
    candidates.extend(additional)
    native = []
    native_root = path / "native"
    if native_root.is_symlink():
        raise ValueError(f"Run native input must not be a symlink: {native_root}")
    if native_root.is_dir():
        stack = [native_root]
        entry_count = 0
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_NATIVE_ENTRIES:
                        raise ValueError(f"Run native tree has more than {MAX_NATIVE_ENTRIES} entries")
                    candidate = Path(entry.path)
                    if entry.is_symlink():
                        raise ValueError(f"Run native input contains a symlink: {candidate}")
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(candidate)
                    elif entry.is_file(follow_symlinks=False) and candidate.suffix == ".json":
                        native.append(candidate)
                        if len(native) > MAX_NATIVE_JSON_FILES:
                            raise ValueError(
                                f"Run has more than {MAX_NATIVE_JSON_FILES} native JSON artifacts"
                            )
    total = 0
    for candidate in [*candidates, *native]:
        if not candidate.exists():
            continue
        declared_additional = candidate in additional
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or not (
                candidate.resolve().is_relative_to(path)
                or (declared_additional and candidate.resolve() == candidate)
            )
        ):
            raise ValueError(f"Run input is not a regular in-source file: {candidate}")
        size = candidate.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise ValueError(f"Run input exceeds {MAX_ARTIFACT_BYTES} bytes: {candidate}")
        total += size
    if total > MAX_RUN_INPUT_BYTES:
        raise ValueError(f"Run inputs exceed the {MAX_RUN_INPUT_BYTES}-byte aggregate budget: {path}")


def _optional_json(path: Path, root: Path, consumed: dict[Path, str]):
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Optional boundary artifact is not a regular in-source file: {path}")
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"Optional boundary artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {path}")
    raw = path.read_bytes()
    consumed[path.resolve()] = hashlib.sha256(raw).hexdigest()

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON object key")
            value[key] = item
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Cannot parse optional boundary artifact: {path}") from exc


def _status_for_identity(values, *, local=False):
    if any(value is None for value in values):
        status = "unknown"
    elif values[0] != values[1]:
        status = "observed_distinct"
    else:
        status = "same_recorded_identifier"
    return {
        "status": status,
        "session_a": values[0],
        "session_b": values[1],
        **(
            {
                "scope": "run-local identifier; equality or difference does not establish process identity"
            }
            if local
            else {}
        ),
    }


def _episode_ids(record):
    return sorted(
        {
            event.get("episode_id")
            for event in record["events"]
            if isinstance(event.get("episode_id"), str)
        }
    )


def _event_run_ids(record):
    return sorted(
        {
            event.get("run_id")
            for event in record["events"]
            if isinstance(event.get("run_id"), str)
        }
    )


def _recorded_identity_values(record, key):
    values = {
        value
        for value in (record["summary"].get(key), record["manifest"].get(key))
        if isinstance(value, (str, int)) and not isinstance(value, bool)
    }
    values.update(
        event[key]
        for event in record["events"]
        if isinstance(event.get(key), (str, int)) and not isinstance(event.get(key), bool)
    )
    return sorted(values, key=str)


def _process_id(record):
    summary_pid = record["summary"].get("pid")
    manifest_pid = record["manifest"].get("pid")
    if summary_pid is not None and manifest_pid is not None and summary_pid != manifest_pid:
        return None, "mismatched_summary_and_manifest_pid"
    value = summary_pid if summary_pid is not None else manifest_pid
    return value, None


def _fresh_history(record):
    summary_flag = record["summary"].get("initial_history_empty")
    requests = sorted(
        (event for event in record["events"] if event.get("event_type") == "MODEL_REQUEST"),
        key=lambda event: (
            event.get("event_sequence")
            if isinstance(event.get("event_sequence"), int)
            else float("inf")
        ),
    )
    first = requests[0] if requests else None
    body = (first.get("data") or {}).get("body") if first else None
    messages = body.get("messages") if isinstance(body, dict) else None
    valid_messages = bool(
        isinstance(messages, list)
        and all(isinstance(message, dict) and isinstance(message.get("role"), str) for message in messages)
    )
    if not _recording_healthy(record) or not valid_messages:
        status = "unknown"
        roles = None
        derived_empty = None
    else:
        roles = [message.get("role") if isinstance(message, dict) else None for message in messages]
        derived_empty = all(role not in {"assistant", "tool"} for role in roles)
        if not isinstance(summary_flag, bool):
            status = "unknown"
        elif derived_empty != summary_flag:
            status = "mismatched_summary_and_first_request"
        else:
            status = "observed_empty" if derived_empty else "observed_not_empty"
    return {
        "status": status,
        "summary_initial_history_empty": summary_flag,
        "first_model_request_event_id": first.get("event_id") if first else None,
        "first_model_request_roles": roles,
        "derived_no_prior_assistant_or_tool_history": derived_empty,
        "contract": "first recorded model request contains no assistant or tool role",
    }


def _input_binding(
    *,
    name: str,
    artifact: Path,
    b_record: dict,
    b_spec: dict | None,
    spec_key: str,
    copied: Path | None,
    consumed: dict[Path, str],
):
    actual = consumed.get(artifact.resolve())
    recorded = (b_record["summary"].get("input_hashes") or {}).get(spec_key)
    spec_path = b_spec.get(spec_key) if isinstance(b_spec, dict) else None
    spec_resolves_to_a = None
    if isinstance(spec_path, str):
        spec_resolves_to_a = Path(spec_path).expanduser().resolve() == artifact.resolve()
    copied_hash = consumed.get(copied.resolve()) if copied is not None and copied.exists() else None
    contradictions = [
        actual is not None and recorded is not None and actual != recorded,
        spec_resolves_to_a is False,
        name == "lineage_checkpoint" and copied_hash is not None and actual is not None and copied_hash != actual,
    ]
    if any(contradictions):
        status = "mismatched"
    elif (
        actual is not None
        and recorded is not None
        and actual == recorded
        and spec_resolves_to_a is True
        and (name != "lineage_checkpoint" or copied_hash == actual)
    ):
        status = "observed_hash_bound"
    else:
        status = "unknown"
    return {
        "status": status,
        "a_artifact": artifact.name,
        "a_sha256": actual,
        "b_recorded_input_key": spec_key,
        "b_recorded_sha256": recorded,
        "b_spec_path": spec_path,
        "b_spec_resolves_to_a_artifact": spec_resolves_to_a,
        "b_copied_input_sha256": copied_hash,
    }


def _read_actions(session_comparison: dict, arm_index: int):
    return session_comparison["arms"][arm_index]["actions"]


def _read_ids(actions):
    reads = [
        {
            "action_index": index,
            "event_id": action.get("event_id"),
            "call_ref": action.get("call_ref"),
            "file_id": (action.get("arguments") or {}).get("file_id"),
            "execution_status": (action.get("execution") or {}).get("status"),
        }
        for index, action in enumerate(actions)
        if action.get("function") == "get_file_by_id"
    ]
    return reads


def _recording_healthy(record):
    return (record.get("audit") or {}).get("valid") is True and record["summary"].get(
        "recording", {}
    ).get("complete") is True


def _created_to_read(a_record, b_record, reads):
    created = a_record["summary"].get("created_file_id")
    ids = [row["file_id"] for row in reads if row["file_id"] is not None]
    successful = [row for row in reads if row["execution_status"] == "returned_successfully"]
    successful_ids = [row["file_id"] for row in successful if row["file_id"] is not None]
    if not created or not ids:
        proposal_status = "unknown"
    elif len(ids) != 1:
        proposal_status = "ambiguous_multiple_b_read_proposals"
    elif ids[0] == created:
        proposal_status = "proposal_argument_match"
    else:
        proposal_status = "proposal_argument_mismatch"
    healthy = _recording_healthy(b_record)
    if not created or not reads or not healthy:
        execution_status = "unknown"
    elif not successful_ids:
        execution_status = "none_observed"
    elif len(successful_ids) != 1:
        execution_status = "ambiguous_multiple_successful_b_reads"
    elif successful_ids[0] == created:
        execution_status = "observed_match"
    else:
        execution_status = "observed_mismatch"
    return {
        "status": execution_status,
        "proposal_argument_correspondence": proposal_status,
        "successful_execution_correspondence": execution_status,
        "a_created_file_id": created,
        "b_read_actions": reads,
    }


def _source_exposure(b_record, reads):
    read_refs = {row["call_ref"] for row in reads if row["call_ref"]}
    rows = [
        {
            "event_id": event.get("event_id"),
            "event_sequence": event.get("event_sequence"),
            "call_ref": event.get("call_ref"),
            "model_request_id": event.get("model_request_id"),
            "source_result_event_id": (event.get("data") or {}).get("source_result_event_id"),
            "semantics": (event.get("data") or {}).get("semantics"),
        }
        for event in b_record["events"]
        if event.get("event_type") == "TOOL_OUTPUT_EXPOSED" and event.get("call_ref") in read_refs
    ]
    healthy = _recording_healthy(b_record)
    status = "observed" if rows and healthy else "none_observed" if healthy and reads else "unknown"
    return {
        "status": status,
        "scope": "included_in_recorded_outbound_model_request; server receipt is not inferred",
        "events": rows,
    }


def _valid_content_hash(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _graph_id(namespace, kind, *parts):
    return f"{kind}:" + hashlib.sha256(_canonical([namespace, *parts])).hexdigest()


def _validated_graph(record, envelope=None):
    """Read-only subset of ``DCPG.load_state`` structural validation."""
    parsed_envelope = record.get("lineage_state")
    envelope = parsed_envelope if envelope is None else envelope

    def invalid(reason):
        return {"status": "invalid", "reason": reason}, None

    if not isinstance(envelope, dict) or not isinstance(envelope.get("state"), dict):
        return {"status": "unknown", "reason": "checkpoint_absent"}, None
    if envelope != parsed_envelope:
        return invalid("checkpoint_parse_mismatch")
    state = envelope["state"]
    try:
        if not (
            envelope.get("schema_version") == state.get("schema_version") == 1
            and type(envelope["schema_version"]) is type(state["schema_version"]) is int
            and state.get("method") == LINEAGE_METHOD
            and state.get("failed") is False
            and _valid_content_hash(envelope.get("state_sha256"))
            and hashlib.sha256(_canonical(state)).hexdigest() == envelope["state_sha256"]
        ):
            return invalid("schema_method_or_digest")
        namespace = state.get("namespace")
        metadata = state.get("metadata")
        manifest = record.get("manifest") or {}
        configured = manifest.get("config") or {}
        declared_metadata = (manifest.get("online_provenance") or {}).get("lineage")
        canary_enabled = configured.get("canary_enabled")
        if not (
            isinstance(namespace, str)
            and namespace.strip()
            and len(namespace) <= 256
            and _valid_content_hash(state.get("policy_sha256"))
            and isinstance(metadata, dict)
            and metadata.get("method") == LINEAGE_METHOD
            and metadata.get("namespace") == namespace
            and metadata.get("policy_sha256") == state.get("policy_sha256")
            and metadata.get("limits") == LINEAGE_LIMITS
            and metadata == declared_metadata
            and type(canary_enabled) is bool
            and ("canary_condition" in metadata) is canary_enabled
            and (metadata.get("memory_cascade") or {}).get("canary_enabled")
            is canary_enabled
            and (metadata.get("memory_cascade") or {}).get("model_inputs_modified")
            is canary_enabled
            and isinstance(state.get("memory_events"), list)
            and len(state["memory_events"]) <= LINEAGE_LIMITS["memory_events"]
        ):
            return invalid("metadata_or_memory_events")
        maps = {}
        for name, key in (
            ("nodes", "node_id"),
            ("edges", "edge_id"),
            ("registry", "label_id"),
            ("memory_bindings", "record_key"),
        ):
            values = state.get(name)
            if not isinstance(values, list) or len(values) > LINEAGE_LIMITS[name]:
                return invalid(f"{name}_collection")
            ids = [value.get(key) for value in values if isinstance(value, dict)]
            if len(ids) != len(values) or any(not isinstance(item, str) or not item for item in ids):
                return invalid(f"{name}_identity")
            maps[name] = dict(zip(ids, values, strict=True))
            if len(maps[name]) != len(values):
                return invalid(f"duplicate_{name}_identity")
        nodes, edges, labels, bindings = (
            maps[name] for name in ("nodes", "edges", "registry", "memory_bindings")
        )
        for node_id, node in nodes.items():
            kind = node.get("kind")
            if kind == "tool_step":
                expected = _graph_id(
                    namespace,
                    "step",
                    node.get("run_id"),
                    node.get("episode_id"),
                    node.get("proposal_event_id"),
                )
            elif kind == "tool_result":
                expected = _graph_id(
                    namespace,
                    "result",
                    node.get("run_id"),
                    node.get("episode_id"),
                    node.get("event_id"),
                )
            else:
                expected = node_id
            if node_id != expected:
                return invalid("content_derived_node_identity")
        if any(
            node.get("kind") not in {"tool_step", "tool_result", "memory_version"}
            or not isinstance(node.get("label_ids"), list)
            or any(label not in labels for label in node["label_ids"])
            for node in nodes.values()
        ):
            return invalid("node_or_node_label")
        if any(
            label_id != _graph_id(namespace, "label", label.get("source_id"))
            for label_id, label in labels.items()
        ):
            return invalid("content_derived_label_identity")
        if any(
            label.get("origin_node_id") not in nodes
            or label.get("origin_result_node_id") not in nodes
            or not isinstance(label.get("text"), str)
            or label.get("text_sha256")
            != hashlib.sha256(label["text"].encode("utf-8")).hexdigest()
            or label.get("policy_sha256") != state.get("policy_sha256")
            for label in labels.values()
        ):
            return invalid("registry_reference")
        for label in labels.values():
            if "canary" not in label:
                continue
            canary = label["canary"]
            if (
                not canary_enabled
                or not isinstance(canary, dict)
                or canary.get("source_result_event_id") != label.get("source_event_id")
                or canary.get("policy_sha256") != state.get("policy_sha256")
            ):
                return invalid("canary_binding")
            validate_reference(canary, label["text"])
        relations = {
            "candidate_content",
            "context_exposure",
            "tool_return",
            "memory_restore",
            "memory_persist",
            "memory_append_preserved",
        }
        if any(
            edge.get("from_node") not in nodes
            or edge.get("to_node") not in nodes
            or not isinstance(edge.get("label_ids"), list)
            or any(label not in labels for label in edge["label_ids"])
            or edge.get("relation") not in relations
            or edge.get("candidate") is not (edge.get("relation") == "candidate_content")
            or edge.get("path_confidence") is not None
            or (edge.get("relation") == "candidate_content"
                and (not isinstance(edge.get("evidence"), dict)
                     or edge["evidence"].get("matched") is not True))
            or (edge.get("relation") != "candidate_content"
                and (edge.get("tier") is not None or edge.get("evidence_score") is not None))
            for edge in edges.values()
        ):
            return invalid("edge_reference_or_type")
        edge_fields = (
            "from_node",
            "to_node",
            "relation",
            "label_ids",
            "event_id",
            "candidate",
            "path_confidence",
            "tier",
            "evidence_score",
            "evidence",
        )
        if any(
            edge_id
            != _graph_id(namespace, "edge", {key: edge.get(key) for key in edge_fields})
            for edge_id, edge in edges.items()
        ):
            return invalid("content_derived_edge_identity")
        for node_id, node in nodes.items():
            if node.get("kind") != "memory_version":
                continue
            events = {
                edge.get("event_id")
                for edge in edges.values()
                if edge.get("to_node") == node_id
                and edge.get("relation") in {"memory_persist", "memory_append_preserved"}
            }
            if not events or not any(
                node_id
                == _graph_id(
                    namespace,
                    "memory",
                    node.get("run_id"),
                    event_id,
                    node.get("record_key"),
                    node.get("version"),
                    node.get("content_sha256"),
                )
                for event_id in events
            ):
                return invalid("content_derived_memory_identity")
        path_refs = 0
        for binding in bindings.values():
            paths = binding.get("paths")
            node = nodes.get(binding.get("node_id"))
            content = binding.get("content")
            if not (
                binding.get("namespace") == state.get("namespace")
                and isinstance(content, str)
                and binding.get("content_sha256")
                == hashlib.sha256(content.encode("utf-8")).hexdigest()
                and type(binding.get("active")) is bool
                and type(binding.get("version")) is int
                and binding["version"] >= 1
                and isinstance(paths, dict)
                and isinstance(binding.get("_nt_taint"), list)
                and set(paths) == set(binding["_nt_taint"])
                and isinstance(node, dict)
                and node.get("kind") == "memory_version"
                and all(node.get(key) == binding.get(key) for key in (
                    "record_key", "version", "content_sha256", "run_id", "episode_id"
                ))
                and binding.get("node_id")
                == _graph_id(
                    namespace,
                    "memory",
                    binding.get("run_id"),
                    binding.get("confirmed_write_event_id"),
                    binding.get("record_key"),
                    binding.get("version"),
                    binding.get("content_sha256"),
                )
            ):
                return invalid("memory_binding")
            for label, route in paths.items():
                path_refs += len(route) if isinstance(route, list) else MAX_PATH_EDGE_REFS + 1
                if (
                    label not in labels
                    or not isinstance(route, list)
                    or not route
                    or path_refs > MAX_PATH_EDGE_REFS
                    or len(route) != len(set(route))
                ):
                    return invalid("memory_path")
                prior = labels[label]["origin_node_id"]
                for edge_id in route:
                    edge = edges.get(edge_id)
                    if not edge or edge["from_node"] != prior or label not in edge["label_ids"]:
                        return invalid("disconnected_memory_path")
                    prior = edge["to_node"]
                if prior != binding["node_id"]:
                    return invalid("memory_path_terminal")
        retained = sum(len(label["text"]) for label in labels.values())
        retained += sum(len(binding["content"]) for binding in bindings.values())
        if retained > LINEAGE_LIMITS["retained_text_codepoints"]:
            return invalid("retained_text_budget")
    except (KeyError, TypeError, ValueError):
        return invalid("malformed_checkpoint")
    graph = {"state": state, "state_sha256": envelope["state_sha256"], **maps}
    return {
        "status": "validated",
        "state_sha256": envelope["state_sha256"],
        "parent_checkpoint_sha256": state.get("parent_checkpoint_sha256"),
        "counts": {name: len(value) for name, value in maps.items()},
        "scope": "recorded graph structure; candidate_content remains detector correspondence",
    }, graph


def _walk(graph, label, route, terminal):
    if not isinstance(route, list) or not route or len(route) > MAX_PATH_EDGE_REFS:
        return False
    prior = graph["registry"].get(label, {}).get("origin_node_id")
    for edge_id in route:
        edge = graph["edges"].get(edge_id)
        if not edge or edge.get("from_node") != prior or label not in edge.get("label_ids", []):
            return False
        prior = edge["to_node"]
    return prior == terminal


def _graph_continuity(a_graph, b_graph):
    if not a_graph or not b_graph:
        return {"status": "unknown_or_invalid"}
    inherited = all(
        all(b_graph[name].get(identity) == value for identity, value in a_graph[name].items())
        for name in ("nodes", "edges", "registry")
    )
    parent = b_graph["state"].get("parent_checkpoint_sha256")
    valid = parent == a_graph["state_sha256"] and inherited
    return {"status": "validated" if valid else "mismatched",
            "a_state_sha256": a_graph["state_sha256"],
            "b_parent_checkpoint_sha256": parent,
            "inherited_graph": "validated_unchanged" if inherited else "mismatched"}


def _tool_message_text(event):
    message = (event.get("data") or {}).get("message") if isinstance(event, dict) else None
    if not isinstance(message, dict) or message.get("role") != "tool" or message.get("error") is not None:
        return None
    content = message.get("content")
    if isinstance(content, str):
        texts = [content]
    elif isinstance(content, list) and len(content) == 1:
        part = content[0]
        text = part.get("text", part.get("content")) if isinstance(part, dict) else None
        texts = [text] if isinstance(text, str) and part.get("type") == "text" else []
    else:
        texts = []
    if len(texts) != 1:
        return None
    return texts[0]


def _single_visible_tool_result_record(event):
    text = _tool_message_text(event)
    if text is None:
        return None
    try:
        value = yaml.safe_load(text)
    except (TypeError, yaml.YAMLError):
        return None
    return value if isinstance(value, dict) else None


def _memory_write(a_record, actions, graph_evidence, graph):
    created = a_record["summary"].get("created_file_id")
    successful_actions = {
        action.get("call_ref"): action
        for action in actions
        if action.get("function") == "create_file"
        and (action.get("execution") or {}).get("status") == "returned_successfully"
        and action.get("call_ref")
    }
    event_by_id = {
        event.get("event_id"): event for event in a_record["events"] if event.get("event_id")
    }
    checkpoint_integrity = graph_evidence["status"]
    all_bindings = list(graph["memory_bindings"].values()) if graph else []
    candidates = [
        row
        for row in all_bindings
        if isinstance(row, dict) and created and row.get("record_key") == created
    ]
    bindings = []
    malformed = []
    for row in candidates:
        confirmed = event_by_id.get(row.get("confirmed_write_event_id"))
        successful_action = (
            successful_actions.get(confirmed.get("call_ref")) if confirmed else None
        )
        runtime_return_refs = (successful_action or {}).get("execution", {}).get(
            "runtime_returns", []
        )
        runtime_returns = [
            event_by_id.get(reference.get("event_id")) for reference in runtime_return_refs
        ]
        runtime_return = runtime_returns[0] if len(runtime_returns) == 1 else None
        runtime_result = (
            (runtime_return.get("data") or {}).get("result")
            if isinstance(runtime_return, dict)
            else None
        )
        arguments = (successful_action or {}).get("arguments")
        proposal_event = (
            event_by_id.get(successful_action.get("event_id")) if successful_action else None
        )
        confirmed_call = (
            ((confirmed.get("data") or {}).get("message") or {}).get("tool_call")
            if confirmed
            else None
        )
        visible_record = _single_visible_tool_result_record(confirmed)
        confirmed_sequence = confirmed.get("event_sequence") if confirmed else None
        return_sequences = [
            returned.get("event_sequence")
            for returned in (successful_action or {}).get("execution", {}).get("runtime_returns", [])
        ]
        ordered_after_returns = bool(
            isinstance(confirmed_sequence, int)
            and return_sequences
            and all(
                isinstance(sequence, int) and sequence < confirmed_sequence
                for sequence in return_sequences
            )
        )
        content = row.get("content")
        content_hash_matches = bool(
            isinstance(content, str)
            and _valid_content_hash(row.get("content_sha256"))
            and hashlib.sha256(content.encode("utf-8")).hexdigest() == row["content_sha256"]
        )
        graph_row = graph["memory_bindings"].get(created) if graph and created else None
        routes = list((graph_row or {}).get("paths", {}).values())
        terminal_edges = [graph["edges"].get(route[-1]) for route in routes if route]
        step_ids = {edge.get("from_node") for edge in terminal_edges if edge}
        step = graph["nodes"].get(next(iter(step_ids))) if graph and len(step_ids) == 1 else None
        graph_returns = [
            edge
            for edge in (graph or {}).get("edges", {}).values()
            if step
            and edge.get("from_node") == step.get("node_id")
            and edge.get("relation") == "tool_return"
            and edge.get("event_id") == row.get("confirmed_write_event_id")
        ]
        graph_result = (
            graph["nodes"].get(graph_returns[0].get("to_node"))
            if graph and len(graph_returns) == 1
            else None
        )
        graph_bound = bool(
            graph_row == row
            and routes
            and len(terminal_edges) == len(routes)
            and all(
                edge
                and edge.get("relation") == "memory_persist"
                and edge.get("to_node") == row.get("node_id")
                and edge.get("event_id") == row.get("confirmed_write_event_id")
                for edge in terminal_edges
            )
            and isinstance(step, dict)
            and step.get("kind") == "tool_step"
            and step.get("function") == "create_file"
            and step.get("proposal_event_id") == (successful_action or {}).get("event_id")
            and step.get("proposal_sequence") == (proposal_event or {}).get("event_sequence")
            and step.get("run_id") == (proposal_event or {}).get("run_id")
            and step.get("episode_id") == (proposal_event or {}).get("episode_id")
            and step.get("call_ref") == (successful_action or {}).get("call_ref")
            and step.get("arguments") == arguments
            and step.get("outcome") == "success"
            and isinstance(graph_result, dict)
            and graph_result.get("kind") == "tool_result"
            and graph_result.get("event_id") == row.get("confirmed_write_event_id")
            and graph_result.get("run_id")
            == (confirmed or {}).get("run_id")
            == step.get("run_id")
            and graph_result.get("episode_id")
            == (confirmed or {}).get("episode_id")
            == step.get("episode_id")
            and graph_result.get("outcome") == "success"
        )
        valid = bool(
            row.get("active") is True
            and len(candidates) == 1
            and isinstance(row.get("version"), int)
            and not isinstance(row.get("version"), bool)
            and row["version"] > 0
            and content_hash_matches
            and isinstance(row.get("confirmed_write_event_id"), str)
            and isinstance(row.get("node_id"), str)
            and row.get("node_id")
            and confirmed
            and confirmed.get("event_type") == "TOOL_RESULT"
            and confirmed.get("call_ref") in successful_actions
            and ordered_after_returns
            and isinstance(arguments, dict)
            and isinstance(runtime_result, dict)
            and runtime_result.get("id_") == created == row.get("record_key")
            and runtime_result.get("content") == arguments.get("content") == content
            and runtime_result.get("filename") == arguments.get("filename")
            and isinstance(confirmed_call, dict)
            and confirmed_call.get("function") == "create_file"
            and confirmed_call.get("args") == arguments
            and isinstance(visible_record, dict)
            and visible_record.get("id_") == runtime_result.get("id_") == row.get("record_key")
            and visible_record.get("content") == runtime_result.get("content") == content
            and visible_record.get("filename") == runtime_result.get("filename")
            and isinstance(proposal_event, dict)
            and row.get("run_id") == proposal_event.get("run_id")
            and row.get("episode_id") == proposal_event.get("episode_id")
            and confirmed.get("run_id") == proposal_event.get("run_id")
            and confirmed.get("episode_id") == proposal_event.get("episode_id")
            and confirmed.get("model_request_id") == proposal_event.get("model_request_id")
            and runtime_return.get("run_id") == proposal_event.get("run_id")
            and runtime_return.get("episode_id") == proposal_event.get("episode_id")
            and runtime_return.get("call_ref") == proposal_event.get("call_ref")
            and runtime_return.get("model_request_id") == proposal_event.get("model_request_id")
            and successful_action.get("event_id") in confirmed.get("parent_event_ids", [])
            and runtime_return.get("event_id") in confirmed.get("parent_event_ids", [])
            and _recording_healthy(a_record)
            and graph_bound
        )
        selected = {
            key: row.get(key)
            for key in (
                "record_key",
                "version",
                "content_sha256",
                "confirmed_write_event_id",
                "run_id",
                "episode_id",
                "node_id",
                "active",
            )
        }
        selected["bound_successful_create_call_ref"] = (
            confirmed.get("call_ref")
            if confirmed and confirmed.get("call_ref") in successful_actions
            else None
        )
        selected["visible_tool_result_record"] = {
            key: visible_record.get(key) for key in ("id_", "content", "filename")
        } if isinstance(visible_record, dict) else None
        (bindings if valid else malformed).append(selected)
    if bindings and checkpoint_integrity == "validated":
        status = "canonical_digest_valid_event_bound_row_graph_validated"
    elif checkpoint_integrity not in {"validated", "unknown"} or malformed or (created and all_bindings):
        status = "mismatched_or_malformed"
    else:
        status = "unknown"
    return {
        "status": status,
        "checkpoint_integrity": checkpoint_integrity,
        "graph_connectivity": "validated_recorded_candidate_path" if bindings else "not_validated",
        "created_file_id": created,
        "bound_rows": bindings,
        "rejected_rows": malformed,
    }


def _restored_reads(b_record, reads):
    successful = {
        row["call_ref"]: row["file_id"]
        for row in reads
        if row["call_ref"]
        and row["file_id"] is not None
        and row["execution_status"] == "returned_successfully"
    }
    events = []
    recovered = []
    for row in b_record.get("provenance", []):
        call = row.get("call") if row.get("record_type") == "call_analysis" else None
        lineage = call.get("lineage") if isinstance(call, dict) else None
        if not isinstance(lineage, dict):
            continue
        for event in lineage.get("memory_events", []):
            if isinstance(event, dict) and event.get("status") == "lineage_restored":
                events.append(
                    {
                        key: event.get(key)
                        for key in (
                            "event_id",
                            "call_ref",
                            "record_key",
                            "version",
                            "run_id",
                            "episode_id",
                            "status",
                            "label_count",
                        )
                    }
                )
        for source in lineage.get("recovered_sources", []):
            if isinstance(source, dict):
                recovered.append(
                    {
                        key: source.get(key)
                        for key in (
                            "record_key",
                            "version",
                            "carrier_event_id",
                            "carrier_source_id",
                            "origin_source_id",
                            "content_sha256",
                            "path_edge_ids",
                        )
                    }
                )
    matching = [
        event
        for event in events
        if event["call_ref"] in successful and event["record_key"] == successful[event["call_ref"]]
    ]
    complete = b_record["summary"].get("online_provenance", {}).get("complete") is True
    healthy = _recording_healthy(b_record)
    if matching and complete and healthy:
        status = "observed"
    elif events and successful and complete and healthy:
        status = "mismatched_call_or_record_key"
    elif reads and complete and healthy:
        status = "none_observed"
    else:
        status = "unknown"
    return {
        "status": status,
        "restored_read_events": events,
        "events_matching_recorded_b_read_ids": matching,
        "recovered_lineage_candidates": recovered,
        "interpretation": "recorded restored ancestry candidates; causal influence is not assessed",
    }


def _b_spec_evidence(b_record, reads, artifacts):
    spec = artifacts["b_spec_value"]
    spec_path = artifacts["b_spec_path"]
    artifact_sha = artifacts["consumed"].get(spec_path.resolve())
    if not isinstance(spec, dict):
        return {"status": "unknown", "artifact": spec_path.name, "sha256": artifact_sha}
    content = spec.get("source_content")
    source_id = spec.get("source_id")
    content_sha = (
        hashlib.sha256(content.encode("utf-8")).hexdigest() if isinstance(content, str) else None
    )
    successful_refs = {
        row["call_ref"]
        for row in reads
        if row["call_ref"]
        and row["file_id"] == source_id
        and row["execution_status"] == "returned_successfully"
    }
    returns = [
        event
        for event in b_record["events"]
        if event.get("event_type") == "TOOL_RUNTIME_RETURNED"
        and event.get("call_ref") in successful_refs
    ]
    returned = [
        (event.get("data") or {}).get("result") for event in returns if isinstance((event.get("data") or {}).get("result"), dict)
    ]
    matching = [
        value
        for value in returned
        if value.get("id_") == source_id and value.get("content") == content
    ]
    if artifact_sha and matching and _recording_healthy(b_record):
        status = "observed_content_bound"
    elif returned and not matching:
        status = "mismatched"
    else:
        status = "unknown"
    return {
        "status": status,
        "artifact": spec_path.name,
        "sha256": artifact_sha,
        "stage": spec.get("stage"),
        "source_id": source_id,
        "source_content": content,
        "source_content_sha256": content_sha,
        "successful_read_return_event_ids": [event.get("event_id") for event in returns],
    }


def _a_entry_evidence(record, actions, graph, label_id, path):
    registry = graph["registry"].get(label_id)
    edges = [graph["edges"].get(edge_id) for edge_id in path]
    if not registry or any(edge is None for edge in edges) or len(edges) < 2:
        return None
    persist = edges[-1]
    candidates = [
        edge
        for edge in edges[:-1]
        if edge.get("relation") == "candidate_content"
        and edge.get("to_node") == persist.get("from_node")
    ]
    if len(candidates) != 1:
        return None
    candidate = candidates[0]
    candidate_evidence = candidate.get("evidence") or {}
    event_by_id = {
        event.get("event_id"): event for event in record["events"] if event.get("event_id")
    }
    action_by_id = {action.get("event_id"): action for action in actions}
    origin_step = graph["nodes"].get(registry.get("origin_node_id"))
    origin_result = graph["nodes"].get(registry.get("origin_result_node_id"))
    source_result = event_by_id.get(registry.get("source_event_id"))
    write_step = graph["nodes"].get(persist.get("from_node"))
    read_proposal = event_by_id.get((origin_step or {}).get("proposal_event_id"))
    write_proposal = event_by_id.get((write_step or {}).get("proposal_event_id"))
    read_action = action_by_id.get((origin_step or {}).get("proposal_event_id"))
    write_action = action_by_id.get((write_step or {}).get("proposal_event_id"))
    exposure = event_by_id.get(candidate_evidence.get("exposure_event_id"))
    read_starts = [
        event_by_id.get(reference.get("event_id"))
        for reference in (read_action or {}).get("execution", {}).get("runtime_starts", [])
    ]
    read_returns = [
        event_by_id.get(reference.get("event_id"))
        for reference in (read_action or {}).get("execution", {}).get("runtime_returns", [])
    ]
    read_start = read_starts[0] if len(read_starts) == 1 else None
    read_return = read_returns[0] if len(read_returns) == 1 else None
    runtime_result = (
        read_return.get("data", {}).get("result") if isinstance(read_return, dict) else None
    )
    visible_result = _single_visible_tool_result_record(source_result)
    calls = [
        row["call"]
        for row in record.get("provenance", [])
        if row.get("record_type") == "call_analysis"
        and isinstance(row.get("call"), dict)
        and row["call"].get("proposal_event_id") == (write_step or {}).get("proposal_event_id")
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    visible = [
        source
        for source in call.get("visible_sources", [])
        if source.get("source_id") == registry.get("source_id")
        and source.get("source_event_id") == registry.get("source_event_id")
        and source.get("exposure_event_id") == (exposure or {}).get("event_id")
        and source.get("text") == registry.get("text")
        and source.get("kind") == "tool"
        and source.get("policy", {}).get("eligible") is True
    ]
    candidate_occurrences = [
        {"argument_path": field.get("argument_path"), **pair}
        for field in call.get("fields", [])
        if field.get("cascade_scope", {}).get("sink", {}).get("selected") is True
        for pair in field.get("nt_style_cascade", [])
        if pair.get("matched") is True
    ]
    tool_returns = [
        edge
        for edge in graph["edges"].values()
        if edge.get("from_node") == registry.get("origin_node_id")
        and edge.get("to_node") == registry.get("origin_result_node_id")
        and edge.get("relation") == "tool_return"
        and edge.get("event_id") == registry.get("source_event_id")
    ]
    result_call = (
        (((source_result or {}).get("data") or {}).get("message") or {}).get("tool_call")
    )
    same_origin = all(
        item.get("run_id") == registry.get("run_id")
        and item.get("episode_id") == registry.get("episode_id")
        for item in (origin_step, origin_result, read_proposal, source_result, exposure)
        if isinstance(item, dict)
    )
    same_write = all(
        item.get("run_id") == call.get("run_id")
        and item.get("episode_id") == call.get("episode_id")
        for item in (write_step, write_proposal, exposure)
        if isinstance(item, dict)
    )
    valid = bool(
        isinstance(origin_step, dict)
        and origin_step.get("kind") == "tool_step"
        and isinstance(origin_result, dict)
        and origin_result.get("kind") == "tool_result"
        and origin_result.get("event_id") == registry.get("source_event_id")
        and origin_result.get("outcome") == "success"
        and len(tool_returns) == 1
        and isinstance(read_proposal, dict)
        and read_proposal.get("event_type") == "TOOL_CALL_PROPOSED"
        and read_proposal.get("event_sequence") == origin_step.get("proposal_sequence")
        and read_proposal.get("call_ref") == origin_step.get("call_ref")
        and read_proposal.get("data", {}).get("function")
        == origin_step.get("function")
        == registry.get("origin_tool")
        and read_proposal.get("data", {}).get("arguments") == origin_step.get("arguments")
        and isinstance(read_action, dict)
        and read_action.get("call_ref") == origin_step.get("call_ref")
        and read_action.get("function") == origin_step.get("function")
        and read_action.get("arguments") == origin_step.get("arguments")
        and read_action.get("execution", {}).get("status") == "returned_successfully"
        and isinstance(read_start, dict)
        and read_start.get("event_type") == "TOOL_RUNTIME_STARTED"
        and read_start.get("run_id") == read_proposal.get("run_id")
        and read_start.get("episode_id") == read_proposal.get("episode_id")
        and read_start.get("call_ref") == read_proposal.get("call_ref")
        and read_start.get("model_request_id") == read_proposal.get("model_request_id")
        and read_proposal.get("event_id") in read_start.get("parent_event_ids", [])
        and isinstance(read_return, dict)
        and read_return.get("event_type") == "TOOL_RUNTIME_RETURNED"
        and read_return.get("run_id") == read_proposal.get("run_id")
        and read_return.get("episode_id") == read_proposal.get("episode_id")
        and read_return.get("call_ref") == read_proposal.get("call_ref")
        and read_return.get("model_request_id") == read_proposal.get("model_request_id")
        and read_start.get("event_id") in read_return.get("parent_event_ids", [])
        and all(
            read_return.get("data", {}).get(key) is None
            for key in ("error", "raised_exception_type")
        )
        and isinstance(runtime_result, dict)
        and isinstance(source_result, dict)
        and source_result.get("event_type") == "TOOL_RESULT"
        and source_result.get("call_ref") == origin_step.get("call_ref")
        and source_result.get("model_request_id") == read_proposal.get("model_request_id")
        and read_proposal.get("event_id") in source_result.get("parent_event_ids", [])
        and read_return.get("event_id") in source_result.get("parent_event_ids", [])
        and _tool_message_text(source_result) == registry.get("text")
        and isinstance(visible_result, dict)
        and all(
            visible_result.get(key) == runtime_result.get(key)
            for key in ("id_", "content", "filename")
        )
        and isinstance(result_call, dict)
        and result_call.get("function") == origin_step.get("function")
        and result_call.get("args") == origin_step.get("arguments")
        and isinstance(exposure, dict)
        and exposure.get("event_type") == "TOOL_OUTPUT_EXPOSED"
        and exposure.get("call_ref") == source_result.get("call_ref")
        and exposure.get("data", {}).get("source_result_event_id")
        == source_result.get("event_id")
        and _tool_message_text(exposure) == registry.get("text")
        and source_result.get("event_sequence") < exposure.get("event_sequence")
        and isinstance(write_step, dict)
        and write_step.get("kind") == "tool_step"
        and write_step.get("outcome") == "success"
        and candidate.get("from_node") == registry.get("origin_node_id")
        and candidate.get("event_id") == write_step.get("proposal_event_id")
        and candidate_evidence.get("source_id") == registry.get("source_id")
        and candidate_evidence.get("source_event_id") == registry.get("source_event_id")
        and len(visible) == 1
        and visible[0].get("run_id") == registry.get("run_id")
        and visible[0].get("episode_id") == registry.get("episode_id")
        and visible[0].get("origin_tool") == registry.get("origin_tool")
        and candidate_evidence in candidate_occurrences
        and isinstance(write_proposal, dict)
        and write_proposal.get("event_type") == "TOOL_CALL_PROPOSED"
        and write_proposal.get("event_id") == candidate.get("event_id")
        and write_proposal.get("event_sequence")
        == write_step.get("proposal_sequence")
        == call.get("proposal_sequence")
        and write_proposal.get("model_request_id")
        == exposure.get("model_request_id")
        == call.get("model_request_id")
        and write_proposal.get("call_ref") == write_step.get("call_ref")
        and write_proposal.get("data", {}).get("function")
        == write_step.get("function")
        == call.get("function")
        == (write_action or {}).get("function")
        and write_proposal.get("data", {}).get("arguments")
        == write_step.get("arguments")
        == call.get("arguments")
        == (write_action or {}).get("arguments")
        and (write_action or {}).get("call_ref") == write_step.get("call_ref")
        and (write_action or {}).get("execution", {}).get("status")
        == "returned_successfully"
        and exposure.get("event_sequence") < write_proposal.get("event_sequence")
        and same_origin
        and same_write
        and _recording_healthy(record)
    )
    if not valid:
        return None
    return {
        "edge_ids": [candidate["edge_id"]],
        "event_ids": [
            source_result["event_id"],
            exposure["event_id"],
            write_proposal["event_id"],
        ],
    }


def _record_identity_consistent(record):
    _, pid_error = _process_id(record)
    return pid_error is None and len(_recorded_identity_values(record, "run_id")) == 1


SUPPORTED_NATIVE_SINKS = frozenset({"create_file", "send_email"})


def _email_attachments_match(arguments, runtime_result):
    requested = arguments.get("attachments")
    requested = [] if requested is None else requested
    observed = runtime_result.get("attachments")
    if not isinstance(requested, list) or not isinstance(observed, list):
        return False
    if len(requested) != len(observed):
        return False
    for supplied, stored in zip(requested, observed, strict=True):
        if not isinstance(supplied, dict):
            return False
        if supplied.get("type") == "file" or "file_id" in supplied:
            if not isinstance(supplied.get("file_id"), str) or stored != supplied["file_id"]:
                return False
            continue
        details = supplied.get("event_details")
        if not isinstance(details, dict) or not isinstance(stored, dict):
            return False
        if any(stored.get(key) != value for key, value in details.items()):
            return False
    return True


def _sink_runtime_result_matches(function, arguments, runtime_result):
    """Bind a supported native sink's arguments to its serialized return value."""
    if not isinstance(arguments, dict) or not isinstance(runtime_result, dict):
        return False
    if function == "create_file":
        return bool(
            isinstance(runtime_result.get("id_"), str)
            and runtime_result["id_"]
            and runtime_result.get("content") == arguments.get("content")
            and runtime_result.get("filename") == arguments.get("filename")
        )
    if function == "send_email":
        recipients = arguments.get("recipients")
        cc = arguments.get("cc")
        bcc = arguments.get("bcc")
        return bool(
            isinstance(runtime_result.get("id_"), str)
            and runtime_result["id_"]
            and isinstance(recipients, list)
            and recipients
            and all(isinstance(recipient, str) and recipient for recipient in recipients)
            and runtime_result.get("recipients") == recipients
            and runtime_result.get("cc") == ([] if cc is None else cc)
            and runtime_result.get("bcc") == ([] if bcc is None else bcc)
            and isinstance(arguments.get("subject"), str)
            and runtime_result.get("subject") == arguments["subject"]
            and isinstance(arguments.get("body"), str)
            and runtime_result.get("body") == arguments["body"]
            and runtime_result.get("status") == "sent"
            and runtime_result.get("read") is True
            and isinstance(runtime_result.get("sender"), str)
            and runtime_result["sender"]
            and isinstance(runtime_result.get("timestamp"), str)
            and runtime_result["timestamp"]
            and _email_attachments_match(arguments, runtime_result)
        )
    return False


def _sink_visible_result_matches(function, visible, runtime_result):
    if not isinstance(visible, dict) or not isinstance(runtime_result, dict):
        return False
    if function == "create_file":
        fields = ("id_", "content", "filename")
    elif function == "send_email":
        fields = (
            "id_",
            "sender",
            "recipients",
            "cc",
            "bcc",
            "subject",
            "body",
            "status",
            "read",
            "attachments",
            "timestamp",
        )
    else:
        return False
    def normalized(key, value):
        if key != "timestamp" or isinstance(value, str):
            return value
        isoformat = getattr(value, "isoformat", None)
        return isoformat() if callable(isoformat) else value

    return all(
        normalized(key, visible.get(key)) == normalized(key, runtime_result.get(key))
        for key in fields
    )


def _native_result_bound(record, function, arguments, runtime_result):
    if function not in SUPPORTED_NATIVE_SINKS:
        return False
    for item in record.get("native", []):
        trace = item.get("trace") if isinstance(item, dict) else None
        messages = trace.get("messages") if isinstance(trace, dict) else None
        for message in messages or []:
            tool_call = message.get("tool_call") if isinstance(message, dict) else None
            visible = _single_visible_tool_result_record({"data": {"message": message}})
            if (
                isinstance(tool_call, dict)
                and tool_call.get("function") == function
                and tool_call.get("args") == arguments
                and _sink_visible_result_matches(function, visible, runtime_result)
            ):
                return True
    return False


TERMINAL_SEGMENTS = (
    ("b_sink_runtime_success", "recorded_runtime"),
    ("b_sink_tool_result", "recorded_tool_result"),
    ("b_sink_native_state_change", "recorded_native_state"),
)


def _sink_execution_segments(
    record,
    action,
    proposal,
    final_environment,
    native_memory,
    *,
    graph=None,
    sink_node=None,
    require_graph_result=False,
):
    """Validate proposal-to-native-state evidence for one supported sink."""

    def segment(name, evidence_type, covered=False, **evidence):
        return {
            "segment": name,
            "coverage": "covered" if covered else "missing",
            "evidence_type": evidence_type,
            **evidence,
        }

    parts = {name: segment(name, evidence_type) for name, evidence_type in TERMINAL_SEGMENTS}
    function = action.get("function") if isinstance(action, dict) else None
    arguments = action.get("arguments") if isinstance(action, dict) else None
    if function not in SUPPORTED_NATIVE_SINKS:
        for name, evidence_type in TERMINAL_SEGMENTS:
            parts[name] = segment(
                name,
                evidence_type,
                reason="unsupported_sink_function",
                function=function,
            )
        return parts
    if not (
        isinstance(proposal, dict)
        and proposal.get("event_type") == "TOOL_CALL_PROPOSED"
        and proposal.get("event_id") == action.get("event_id")
        and proposal.get("call_ref") == action.get("call_ref")
        and proposal.get("data", {}).get("function") == function
        and proposal.get("data", {}).get("arguments") == arguments
    ):
        return parts

    events = {event.get("event_id"): event for event in record["events"]}
    execution = action.get("execution") or {}
    starts = [events.get(ref.get("event_id")) for ref in execution.get("runtime_starts", [])]
    returns = [events.get(ref.get("event_id")) for ref in execution.get("runtime_returns", [])]
    runtime_start = starts[0] if len(starts) == 1 else None
    runtime = returns[0] if len(returns) == 1 else None
    runtime_data = runtime.get("data") if isinstance(runtime, dict) else None
    runtime_result = runtime_data.get("result") if isinstance(runtime_data, dict) else None
    runtime_ok = bool(
        execution.get("status") == "returned_successfully"
        and isinstance(runtime_start, dict)
        and runtime_start.get("event_type") == "TOOL_RUNTIME_STARTED"
        and runtime_start.get("run_id") == proposal.get("run_id")
        and runtime_start.get("episode_id") == proposal.get("episode_id")
        and runtime_start.get("call_ref") == proposal.get("call_ref")
        and runtime_start.get("model_request_id") == proposal.get("model_request_id")
        and runtime_start.get("data", {}).get("function") == function
        and runtime_start.get("data", {}).get("runtime_input_args") == arguments
        and proposal.get("event_id") in runtime_start.get("parent_event_ids", [])
        and isinstance(runtime, dict)
        and runtime.get("event_type") == "TOOL_RUNTIME_RETURNED"
        and runtime.get("run_id") == proposal.get("run_id")
        and runtime.get("episode_id") == proposal.get("episode_id")
        and runtime.get("call_ref") == proposal.get("call_ref")
        and runtime.get("model_request_id") == proposal.get("model_request_id")
        and runtime_start.get("event_id") in runtime.get("parent_event_ids", [])
        and isinstance(runtime_data, dict)
        and {"error", "raised_exception_type"} <= runtime_data.keys()
        and runtime_data["error"] is None
        and runtime_data["raised_exception_type"] is None
        and _sink_runtime_result_matches(function, arguments, runtime_result)
    )
    if runtime_ok:
        parts["b_sink_runtime_success"] = segment(
            "b_sink_runtime_success",
            "recorded_runtime",
            True,
            function=function,
            event_ids=[proposal["event_id"], runtime_start["event_id"], runtime["event_id"]],
        )

    results = [
        event
        for event in record["events"]
        if runtime_ok
        and event.get("event_type") == "TOOL_RESULT"
        and event.get("run_id") == proposal.get("run_id")
        and event.get("episode_id") == proposal.get("episode_id")
        and event.get("call_ref") == proposal.get("call_ref")
        and event.get("model_request_id") == proposal.get("model_request_id")
        and proposal["event_id"] in event.get("parent_event_ids", [])
        and runtime["event_id"] in event.get("parent_event_ids", [])
        and event.get("data", {}).get("message", {}).get("error") is None
        and event.get("data", {}).get("message", {}).get("tool_call", {}).get("function")
        == function
        and event.get("data", {}).get("message", {}).get("tool_call", {}).get("args")
        == arguments
        and _sink_visible_result_matches(
            function, _single_visible_tool_result_record(event), runtime_result
        )
    ]
    graph_edge = None
    graph_result_ok = not require_graph_result
    if require_graph_result and graph and sink_node and len(results) == 1:
        graph_returns = [
            edge
            for edge in graph["edges"].values()
            if edge.get("from_node") == sink_node.get("node_id")
            and edge.get("relation") == "tool_return"
            and edge.get("event_id") == results[0].get("event_id")
        ]
        if len(graph_returns) == 1:
            result_node = graph["nodes"].get(graph_returns[0].get("to_node"))
            graph_result_ok = bool(
                isinstance(result_node, dict)
                and result_node.get("kind") == "tool_result"
                and result_node.get("event_id") == results[0].get("event_id")
                and result_node.get("run_id") == results[0].get("run_id")
                == sink_node.get("run_id")
                and result_node.get("episode_id") == results[0].get("episode_id")
                == sink_node.get("episode_id")
                and result_node.get("outcome") == "success"
                and sink_node.get("outcome") == "success"
            )
            graph_edge = graph_returns[0] if graph_result_ok else None
    result_ok = len(results) == 1 and graph_result_ok
    if result_ok:
        parts["b_sink_tool_result"] = segment(
            "b_sink_tool_result",
            "recorded_tool_result",
            True,
            function=function,
            edge_ids=[graph_edge["edge_id"]] if graph_edge else [],
            event_ids=[results[0]["event_id"]],
        )

    created = runtime_result.get("id_") if runtime_ok else None
    expected_path = (
        f"/cloud_drive/files/{created}"
        if function == "create_file" and created
        else f"/inbox/emails/{created}"
        if created
        else None
    )
    state_key = "cloud_drive" if function == "create_file" else "inbox"
    collection_key = "files" if function == "create_file" else "emails"
    observed_changes = execution.get("observed_environment_changes", [])
    change = observed_changes[0] if result_ok and len(observed_changes) == 1 else None
    change_event = events.get(change.get("event_id")) if isinstance(change, dict) else None
    before_values = (
        change_event.get("data", {}).get("before", {}).get(state_key, {}).get(collection_key)
        if isinstance(change_event, dict)
        else None
    )
    after_values = (
        change_event.get("data", {}).get("after", {}).get(state_key, {}).get(collection_key)
        if isinstance(change_event, dict)
        else None
    )
    final_values = (
        final_environment.get(state_key, {}).get(collection_key)
        if isinstance(final_environment, dict)
        else None
    )
    change_rows = change.get("changes") if isinstance(change, dict) else None
    base_change = {
        "path": expected_path,
        "before_present": False,
        "after_present": True,
        "before": None,
        "after": runtime_result,
    }
    change_shape_ok = bool(
        isinstance(change, dict)
        and change.get("bound_to_return")
        and change_rows == [base_change]
    )
    sent_before = sent_after = sent_final = None
    sent_path = None
    if function == "send_email" and isinstance(change_event, dict):
        sent_before = change_event.get("data", {}).get("before", {}).get("inbox", {}).get("sent")
        sent_after = change_event.get("data", {}).get("after", {}).get("inbox", {}).get("sent")
        sent_final = (
            final_environment.get("inbox", {}).get("sent")
            if isinstance(final_environment, dict)
            else None
        )
        sent_path = (
            f"/inbox/sent/{len(sent_before)}" if isinstance(sent_before, list) else None
        )
        expected_rows = {
            expected_path: base_change,
            sent_path: {
                "path": sent_path,
                "before_present": False,
                "after_present": True,
                "before": None,
                "after": runtime_result,
            },
        }
        indexed_rows = {
            row.get("path"): row
            for row in change_rows or []
            if isinstance(row, dict) and isinstance(row.get("path"), str)
        }
        change_shape_ok = bool(
            sent_path
            and isinstance(change_rows, list)
            and len(change_rows) == len(indexed_rows) == 2
            and indexed_rows == expected_rows
        )
    create_file_checkpoint_ok = True
    if function == "create_file":
        persisted_files = native_memory.get("files") if isinstance(native_memory, dict) else None
        persisted = [
            item
            for item in persisted_files or []
            if isinstance(item, dict) and item.get("id_") == created
        ]
        namespace = graph["state"].get("namespace") if graph else None
        create_file_checkpoint_ok = bool(
            isinstance(native_memory, dict)
            and native_memory.get("schema_version") == 1
            and isinstance(namespace, str)
            and native_memory.get("namespace") == namespace
            and len(persisted) == 1
            and persisted[0] == runtime_result
        )
    collection_state_ok = bool(
        isinstance(before_values, dict)
        and created not in before_values
        and isinstance(after_values, dict)
        and after_values == {**before_values, created: runtime_result}
        and isinstance(final_values, dict)
        and final_values == after_values
    )
    if function == "create_file":
        # Keep the exact-copy report's allowance for unrelated pre-existing/final
        # files while still binding the newly created record exactly.
        collection_state_ok = bool(
            isinstance(before_values, dict)
            and created not in before_values
            and isinstance(after_values, dict)
            and after_values.get(created) == runtime_result
            and isinstance(final_values, dict)
            and final_values.get(created) == runtime_result
        )
    sent_state_ok = function == "create_file" or bool(
        isinstance(sent_before, list)
        and sent_after == [*sent_before, runtime_result]
        and sent_final == sent_after
    )
    native_ok = bool(
        result_ok
        and change_shape_ok
        and isinstance(change_event, dict)
        and change_event.get("event_type") == "ENVIRONMENT_CHANGE"
        and change_event.get("run_id") == proposal.get("run_id")
        and change_event.get("episode_id") == proposal.get("episode_id")
        and change_event.get("call_ref") == proposal.get("call_ref")
        and change_event.get("model_request_id") == proposal.get("model_request_id")
        and runtime.get("event_id") in change_event.get("parent_event_ids", [])
        and collection_state_ok
        and sent_state_ok
        and create_file_checkpoint_ok
        and _native_result_bound(record, function, arguments, runtime_result)
    )
    if native_ok:
        parts["b_sink_native_state_change"] = segment(
            "b_sink_native_state_change",
            "recorded_native_state",
            True,
            function=function,
            state_path=expected_path,
            **({"sent_state_path": sent_path} if sent_path else {}),
            event_ids=[change_event["event_id"]],
        )
    return parts


OBSERVED_NATIVE_SEGMENTS = (
    ("a_write_to_memory", "recorded_storage"),
    ("a_checkpoint_to_b", "checkpoint_parent_and_inherited_graph"),
    ("b_memory_to_read_exposure", "recorded_read_and_exposure"),
    ("b_sink_proposal_after_exposure", "recorded_same_request_sequence"),
    *TERMINAL_SEGMENTS,
)


def _observed_a_storage(record, actions, native_memory, graph):
    created = record["summary"].get("created_file_id")
    events = {event.get("event_id"): event for event in record["events"]}
    matches = []
    for action in actions:
        if action.get("function") != "create_file":
            continue
        proposal = events.get(action.get("event_id"))
        changes = action.get("execution", {}).get("observed_environment_changes", [])
        change_event = events.get(changes[0].get("event_id")) if len(changes) == 1 else None
        final_environment = (
            change_event.get("data", {}).get("after")
            if isinstance(change_event, dict)
            else None
        )
        terminal = _sink_execution_segments(
            record, action, proposal, final_environment, native_memory, graph=graph
        )
        returns = action.get("execution", {}).get("runtime_returns", [])
        returned = events.get(returns[0].get("event_id")) if len(returns) == 1 else None
        runtime_result = returned.get("data", {}).get("result") if returned else None
        if (
            created
            and isinstance(runtime_result, dict)
            and runtime_result.get("id_") == created
            and all(row["coverage"] == "covered" for row in terminal.values())
        ):
            matches.append(
                {
                    "created_file_id": created,
                    "proposal_event_id": proposal.get("event_id"),
                    "runtime_return_event_id": returned.get("event_id"),
                    "native_state_path": terminal["b_sink_native_state_change"]["state_path"],
                    "stored_record": runtime_result,
                    "stored_record_sha256": hashlib.sha256(_canonical(runtime_result)).hexdigest(),
                }
            )
    return matches[0] if len(matches) == 1 and _recording_healthy(record) else None


def _observed_b_read_exposure(record, actions, stored_record, b_spec):
    if not isinstance(stored_record, dict) or b_spec.get("status") != "observed_content_bound":
        return None
    created = stored_record.get("id_")
    if not created:
        return None
    events = {event.get("event_id"): event for event in record["events"]}
    matches = []
    for action in actions:
        if (
            action.get("function") != "get_file_by_id"
            or (action.get("arguments") or {}).get("file_id") != created
            or action.get("execution", {}).get("status") != "returned_successfully"
        ):
            continue
        proposal = events.get(action.get("event_id"))
        starts = action.get("execution", {}).get("runtime_starts", [])
        returns = action.get("execution", {}).get("runtime_returns", [])
        start = events.get(starts[0].get("event_id")) if len(starts) == 1 else None
        returned = events.get(returns[0].get("event_id")) if len(returns) == 1 else None
        runtime_data = returned.get("data") if isinstance(returned, dict) else None
        runtime_result = runtime_data.get("result") if isinstance(runtime_data, dict) else None
        results = [
            event
            for event in record["events"]
            if isinstance(proposal, dict)
            and isinstance(returned, dict)
            and event.get("event_type") == "TOOL_RESULT"
            and event.get("run_id") == proposal.get("run_id")
            and event.get("episode_id") == proposal.get("episode_id")
            and event.get("call_ref") == proposal.get("call_ref")
            and event.get("model_request_id") == proposal.get("model_request_id")
            and proposal.get("event_id") in event.get("parent_event_ids", [])
            and returned.get("event_id") in event.get("parent_event_ids", [])
            and event.get("data", {}).get("message", {}).get("error") is None
            and event.get("data", {}).get("message", {}).get("tool_call", {}).get("function")
            == "get_file_by_id"
            and event.get("data", {}).get("message", {}).get("tool_call", {}).get("args")
            == action.get("arguments")
            and _sink_visible_result_matches(
                "create_file", _single_visible_tool_result_record(event), runtime_result
            )
        ]
        result = results[0] if len(results) == 1 else None
        exposures = [
            event
            for event in record["events"]
            if isinstance(result, dict)
            and event.get("event_type") == "TOOL_OUTPUT_EXPOSED"
            and event.get("run_id") == proposal.get("run_id")
            and event.get("episode_id") == proposal.get("episode_id")
            and event.get("call_ref") == proposal.get("call_ref")
            and event.get("data", {}).get("source_result_event_id") == result.get("event_id")
            and event.get("model_request_id")
            and _tool_message_text(event) == _tool_message_text(result)
            and result.get("event_sequence", -1) < event.get("event_sequence", -1)
            and any(
                later.get("event_id") == event.get("event_id")
                for later_action in actions
                if events.get(later_action.get("event_id"), {}).get("model_request_id")
                == event.get("model_request_id")
                and events.get(later_action.get("event_id"), {}).get("event_sequence", -1)
                > event.get("event_sequence", -1)
                for later in later_action.get("source_exposures_in_request", [])
            )
        ]
        exposure = exposures[0] if len(exposures) == 1 else None
        valid = bool(
            isinstance(proposal, dict)
            and proposal.get("event_type") == "TOOL_CALL_PROPOSED"
            and proposal.get("data", {}).get("function") == "get_file_by_id"
            and proposal.get("data", {}).get("arguments") == action.get("arguments")
            and isinstance(start, dict)
            and start.get("event_type") == "TOOL_RUNTIME_STARTED"
            and start.get("run_id") == proposal.get("run_id")
            and start.get("episode_id") == proposal.get("episode_id")
            and start.get("call_ref") == proposal.get("call_ref")
            and start.get("model_request_id") == proposal.get("model_request_id")
            and start.get("data", {}).get("function") == "get_file_by_id"
            and start.get("data", {}).get("runtime_input_args") == action.get("arguments")
            and proposal.get("event_id") in start.get("parent_event_ids", [])
            and isinstance(returned, dict)
            and returned.get("event_type") == "TOOL_RUNTIME_RETURNED"
            and returned.get("run_id") == proposal.get("run_id")
            and returned.get("episode_id") == proposal.get("episode_id")
            and returned.get("call_ref") == proposal.get("call_ref")
            and returned.get("model_request_id") == proposal.get("model_request_id")
            and start.get("event_id") in returned.get("parent_event_ids", [])
            and isinstance(runtime_data, dict)
            and {"error", "raised_exception_type"} <= runtime_data.keys()
            and runtime_data["error"] is None
            and runtime_data["raised_exception_type"] is None
            and isinstance(runtime_result, dict)
            and runtime_result == stored_record
            and runtime_result.get("id_") == created == b_spec.get("source_id")
            and runtime_result.get("content") == b_spec.get("source_content")
            and isinstance(result, dict)
            and isinstance(exposure, dict)
            and _recording_healthy(record)
        )
        if valid:
            matches.append(
                {
                    "proposal_event_id": proposal["event_id"],
                    "runtime_return_event_id": returned["event_id"],
                    "tool_result_event_id": result["event_id"],
                    "exposure_event_id": exposure["event_id"],
                    "model_request_id": exposure["model_request_id"],
                    "event_sequence": exposure["event_sequence"],
                }
            )
    return matches[0] if len(matches) == 1 else None


def _observed_native_path(
    a_record,
    a_actions,
    a_native_memory,
    b_record,
    b_actions,
    continuity,
    checkpoint_inputs,
    b_spec,
    fresh_history,
    final_environment,
    native_memory,
    a_graph,
    b_graph,
):
    def segment(name, evidence_type, covered=False, **evidence):
        return {
            "segment": name,
            "coverage": "covered" if covered else "missing",
            "evidence_type": evidence_type,
            **evidence,
        }

    parts = {
        name: segment(name, evidence_type) for name, evidence_type in OBSERVED_NATIVE_SEGMENTS
    }
    storage = _observed_a_storage(a_record, a_actions, a_native_memory, a_graph)
    if storage:
        parts["a_write_to_memory"] = segment(
            "a_write_to_memory", "recorded_storage", True, **storage
        )
    checkpoint_ok = bool(
        storage
        and continuity.get("status") == "validated"
        and checkpoint_inputs["native_state"]["status"] == "observed_hash_bound"
        and checkpoint_inputs["lineage_checkpoint"]["status"] == "observed_hash_bound"
        and b_spec.get("status") == "observed_content_bound"
        and fresh_history.get("status") == "observed_empty"
        and _record_identity_consistent(b_record)
    )
    if checkpoint_ok:
        parts["a_checkpoint_to_b"] = segment(
            "a_checkpoint_to_b",
            "checkpoint_parent_and_inherited_graph",
            True,
            created_file_id=storage["created_file_id"],
        )
    read = _observed_b_read_exposure(
        b_record, b_actions, storage["stored_record"] if storage else None, b_spec
    )
    if checkpoint_ok and read:
        parts["b_memory_to_read_exposure"] = segment(
            "b_memory_to_read_exposure",
            "recorded_read_and_exposure",
            True,
            event_ids=[
                read["proposal_event_id"],
                read["runtime_return_event_id"],
                read["tool_result_event_id"],
                read["exposure_event_id"],
            ],
        )
    events = {event.get("event_id"): event for event in b_record["events"]}
    later_actions = [
        action
        for action in b_actions
        if read
        and (proposal := events.get(action.get("event_id")))
        and proposal.get("model_request_id") == read["model_request_id"]
        and proposal.get("event_sequence", -1) > read["event_sequence"]
        and any(
            row.get("event_id") == read["exposure_event_id"]
            for row in action.get("source_exposures_in_request", [])
        )
    ]
    supported = [
        action for action in later_actions if action.get("function") in SUPPORTED_NATIVE_SINKS
    ]
    unsupported = sorted(
        {
            action.get("function")
            for action in later_actions
            if action.get("function") not in SUPPORTED_NATIVE_SINKS
            and isinstance(action.get("function"), str)
        }
    )
    if checkpoint_ok and read and len(supported) == 1:
        action = supported[0]
        proposal = events.get(action.get("event_id"))
        parts["b_sink_proposal_after_exposure"] = segment(
            "b_sink_proposal_after_exposure",
            "recorded_same_request_sequence",
            True,
            function=action.get("function"),
            event_ids=[read["exposure_event_id"], proposal["event_id"]],
            detector_candidate_correspondence="not_assessed",
        )
        parts.update(
            _sink_execution_segments(
                b_record,
                action,
                proposal,
                final_environment,
                native_memory,
                graph=b_graph,
            )
        )
    rows = list(parts.values())
    complete = all(row["coverage"] == "covered" for row in rows)
    return {
        "status": "all_native_observations_covered" if complete else "partial_or_missing",
        "segments": rows,
        "missing_segments": [
            row["segment"] for row in rows if row["coverage"] == "missing"
        ],
        "unsupported_sink_functions": unsupported,
        "scope": (
            "recorded native storage, checkpoint, read/exposure, same-request proposal, "
            "runtime, tool-result, and state evidence; detector correspondence is separate"
        ),
        "detector_candidate_correspondence": "not_assessed",
        "causal_influence": "not_assessed",
        "attack_success": "unknown",
    }


PATH_SEGMENTS = (
    ("a_source_to_write", "detector_candidate_correspondence"),
    ("a_write_to_memory", "recorded_storage"),
    ("a_checkpoint_to_b", "checkpoint_parent_and_inherited_graph"),
    ("b_memory_to_read_exposure", "recorded_read_and_exposure"),
    ("b_exposure_to_sink_proposal", "detector_candidate_correspondence"),
    ("b_sink_runtime_success", "recorded_runtime"),
    ("b_sink_tool_result", "recorded_tool_result"),
    ("b_sink_native_state_change", "recorded_native_state"),
)


def _complete_paths(
    a_graph,
    b_graph,
    continuity,
    a_record,
    a_actions,
    b_record,
    b_actions,
    memory,
    checkpoint_inputs,
    b_spec,
    fresh_history,
    final_environment,
    native_memory,
):
    def segment(name, evidence_type, covered=False, **evidence):
        return {"segment": name, "coverage": "covered" if covered else "missing",
                "evidence_type": evidence_type, **evidence}

    routes = []
    if not a_graph or not memory["bound_rows"]:
        return {"status": "no_validated_route", "routes": [],
                "missing_segments": [name for name, _ in PATH_SEGMENTS],
                "causal_influence": "not_assessed", "attack_success": "unknown"}
    binding = a_graph["memory_bindings"].get(memory["created_file_id"])
    events = {event.get("event_id"): event for event in b_record["events"]}
    actions = {action.get("event_id"): action for action in b_actions}
    calls = sorted(
        (row["call"] for row in b_record.get("provenance", [])
         if row.get("record_type") == "call_analysis" and isinstance(row.get("call"), dict)),
        key=lambda call: call.get("proposal_sequence", float("inf")),
    )
    parent_valid = bool(
        b_graph
        and continuity["status"] == "validated"
        and checkpoint_inputs["native_state"]["status"] == "observed_hash_bound"
        and checkpoint_inputs["lineage_checkpoint"]["status"] == "observed_hash_bound"
        and b_spec["status"] == "observed_content_bound"
        and fresh_history["status"] == "observed_empty"
        and _record_identity_consistent(b_record)
    )
    for label, a_path in (binding or {}).get("paths", {}).items():
        parts = {name: segment(name, evidence_type) for name, evidence_type in PATH_SEGMENTS}
        a_entry = _a_entry_evidence(a_record, a_actions, a_graph, label, a_path)
        if a_entry:
            parts["a_source_to_write"] = segment(
                "a_source_to_write", "detector_candidate_correspondence", True,
                evidence_strength="candidate_bound_to_recorded_source_and_write",
                **a_entry,
            )
        if memory["graph_connectivity"] == "validated_recorded_candidate_path":
            parts["a_write_to_memory"] = segment(
                "a_write_to_memory", "recorded_storage", True,
                evidence_strength="runtime_tool_result_and_checkpoint_binding",
                edge_ids=a_path[-1:], event_ids=[binding["confirmed_write_event_id"]])
        if parent_valid:
            parts["a_checkpoint_to_b"] = segment(
                "a_checkpoint_to_b", "checkpoint_parent_and_inherited_graph", True,
                state_sha256=a_graph["state_sha256"])
        else:
            rows = list(parts.values())
            routes.append(
                {
                    "label_id": label,
                    "segments": rows,
                    "covered_segments": sum(
                        row["coverage"] == "covered" for row in rows
                    ),
                }
            )
            continue

        restored_selected = None
        selected = None
        for call in calls:
            lineage = call.get("lineage") or {}
            for recovered in lineage.get("recovered_sources", []):
                recovered_path = recovered.get("path_edge_ids")
                if not (
                    recovered.get("label_id") == label
                    and recovered.get("origin_node_id")
                    == a_graph["registry"][label].get("origin_node_id")
                    and recovered.get("origin_source_id")
                    == a_graph["registry"][label].get("source_id")
                    and recovered.get("original_text")
                    == a_graph["registry"][label].get("text")
                    and recovered.get("original_text_sha256")
                    == a_graph["registry"][label].get("text_sha256")
                    and recovered.get("record_key") == binding["record_key"]
                    and recovered.get("version") == binding["version"]
                    and recovered.get("content_sha256") == binding["content_sha256"]
                    and isinstance(recovered_path, list)
                    and recovered_path[:-1] == a_path
                ):
                    continue
                restore = b_graph["edges"].get(recovered_path[-1]) if recovered_path else None
                read_step = b_graph["nodes"].get((restore or {}).get("to_node"))
                exposure = events.get((restore or {}).get("event_id"))
                carrier_result = events.get(recovered.get("carrier_event_id"))
                read_proposal = events.get((read_step or {}).get("proposal_event_id"))
                exposed_record = _single_visible_tool_result_record(exposure)
                carrier_record = _single_visible_tool_result_record(carrier_result)
                read = actions.get((read_step or {}).get("proposal_event_id"))
                read_runtime_returns = [
                    events.get(reference.get("event_id"))
                    for reference in (read or {}).get("execution", {}).get(
                        "runtime_returns", []
                    )
                ]
                read_runtime = (
                    read_runtime_returns[0] if len(read_runtime_returns) == 1 else None
                )
                read_runtime_result = (
                    read_runtime.get("data", {}).get("result")
                    if isinstance(read_runtime, dict)
                    else None
                )
                visible = [
                    source
                    for source in call.get("visible_sources", [])
                    if source.get("source_id") == recovered.get("carrier_source_id")
                    and source.get("source_event_id") == recovered.get("carrier_event_id")
                    and source.get("exposure_event_id") == (restore or {}).get("event_id")
                    and source.get("text") == _tool_message_text(exposure)
                    and source.get("kind") == "tool"
                    and source.get("policy", {}).get("eligible") is True
                ]
                restored = [
                    event
                    for event in lineage.get("memory_events", [])
                    if event.get("status") == "lineage_restored"
                    and event.get("event_id") == (restore or {}).get("event_id")
                    and event.get("call_ref") == (exposure or {}).get("call_ref")
                    and event.get("record_key") == binding["record_key"]
                    and event.get("version") == binding["version"]
                    and event.get("run_id") == (exposure or {}).get("run_id")
                    and event.get("episode_id") == (exposure or {}).get("episode_id")
                ]
                read_graph_returns = [
                    edge
                    for edge in b_graph["edges"].values()
                    if edge.get("from_node") == (read_step or {}).get("node_id")
                    and edge.get("relation") == "tool_return"
                    and edge.get("event_id") == recovered.get("carrier_event_id")
                ]
                read_result_node = (
                    b_graph["nodes"].get(read_graph_returns[0].get("to_node"))
                    if len(read_graph_returns) == 1
                    else None
                )
                carrier_call = (
                    (((carrier_result or {}).get("data") or {}).get("message") or {}).get(
                        "tool_call"
                    )
                )
                if not (
                    parent_valid and restore and restore.get("relation") == "memory_restore"
                    and restore.get("from_node") == binding["node_id"]
                    and restore.get("event_id") == (exposure or {}).get("event_id")
                    and label in restore.get("label_ids", [])
                    and isinstance(read_step, dict)
                    and read_step.get("kind") == "tool_step"
                    and read_step.get("node_id") == recovered.get("carrier_node_id")
                    and read_step.get("outcome") == "success"
                    and isinstance(read_proposal, dict)
                    and read_proposal.get("event_type") == "TOOL_CALL_PROPOSED"
                    and read_proposal.get("event_sequence")
                    == read_step.get("proposal_sequence")
                    and read_proposal.get("run_id") == read_step.get("run_id")
                    and read_proposal.get("episode_id") == read_step.get("episode_id")
                    and read_proposal.get("call_ref") == read_step.get("call_ref")
                    and read_proposal.get("data", {}).get("function")
                    == read_step.get("function")
                    == "get_file_by_id"
                    and read_proposal.get("data", {}).get("arguments")
                    == read_step.get("arguments")
                    and isinstance(read, dict)
                    and read.get("call_ref") == read_step.get("call_ref")
                    and read.get("function") == read_step.get("function")
                    and read.get("arguments") == read_step.get("arguments")
                    and (read.get("arguments") or {}).get("file_id") == binding["record_key"]
                    and read.get("execution", {}).get("status") == "returned_successfully"
                    and isinstance(read_runtime, dict)
                    and read_runtime.get("event_type") == "TOOL_RUNTIME_RETURNED"
                    and read_runtime.get("run_id") == read_step.get("run_id")
                    and read_runtime.get("episode_id") == read_step.get("episode_id")
                    and read_runtime.get("call_ref") == read_step.get("call_ref")
                    and read_runtime.get("model_request_id")
                    == read_proposal.get("model_request_id")
                    and all(
                        read_runtime.get("data", {}).get(key) is None
                        for key in ("error", "raised_exception_type")
                    )
                    and isinstance(read_runtime_result, dict)
                    and read_runtime_result.get("id_") == binding["record_key"]
                    and read_runtime_result.get("content") == binding["content"]
                    and isinstance(carrier_result, dict)
                    and carrier_result.get("event_type") == "TOOL_RESULT"
                    and carrier_result.get("run_id") == read_step.get("run_id")
                    and carrier_result.get("episode_id") == read_step.get("episode_id")
                    and carrier_result.get("call_ref") == read_step.get("call_ref")
                    and carrier_result.get("model_request_id")
                    == read_proposal.get("model_request_id")
                    and read_proposal.get("event_id")
                    in carrier_result.get("parent_event_ids", [])
                    and read_runtime.get("event_id")
                    in carrier_result.get("parent_event_ids", [])
                    and isinstance(carrier_call, dict)
                    and carrier_call.get("function") == read_step.get("function")
                    and carrier_call.get("args") == read_step.get("arguments")
                    and isinstance(read_result_node, dict)
                    and read_result_node.get("event_id") == carrier_result.get("event_id")
                    and read_result_node.get("run_id")
                    == carrier_result.get("run_id")
                    == read_step.get("run_id")
                    and read_result_node.get("episode_id")
                    == carrier_result.get("episode_id")
                    == read_step.get("episode_id")
                    and read_result_node.get("outcome") == "success"
                    and isinstance(carrier_record, dict)
                    and all(
                        carrier_record.get(key) == read_runtime_result.get(key)
                        for key in ("id_", "content", "filename")
                    )
                    and exposure and exposure.get("event_type") == "TOOL_OUTPUT_EXPOSED"
                    and exposure.get("run_id") == read_step.get("run_id") == call.get("run_id")
                    and exposure.get("episode_id")
                    == read_step.get("episode_id")
                    == call.get("episode_id")
                    and exposure.get("call_ref") == read_step.get("call_ref")
                    and exposure.get("data", {}).get("source_result_event_id")
                    == recovered.get("carrier_event_id")
                    and exposure.get("model_request_id") == call.get("model_request_id")
                    and call.get("proposal_sequence", -1) > exposure.get("event_sequence", -1)
                    and exposed_record
                    and exposed_record.get("id_") == binding["record_key"]
                    and exposed_record.get("content") == binding["content"]
                    and exposed_record.get("filename") == read_runtime_result.get("filename")
                    and len(visible) == len(restored) == 1
                    and visible[0].get("run_id") == exposure.get("run_id")
                    and visible[0].get("episode_id") == exposure.get("episode_id")
                    and visible[0].get("origin_tool") == read_step.get("function")
                    and _recording_healthy(b_record)
                    and _walk(b_graph, label, recovered_path, read_step["node_id"])
                ):
                    continue
                restored_selected = (restore, exposure)
                sink_route = next((path.get("edge_ids") for path in lineage.get("paths", []) if
                                   path.get("label_id") == label
                                   and isinstance(path.get("edge_ids"), list)
                                   and path["edge_ids"][:-1] == recovered_path), None)
                candidate = b_graph["edges"].get(sink_route[-1]) if sink_route else None
                sink = b_graph["nodes"].get((candidate or {}).get("to_node"))
                action = actions.get(call.get("proposal_event_id"))
                proposal = events.get(call.get("proposal_event_id"))
                argument_path = ((candidate or {}).get("evidence") or {}).get("argument_path")
                field_selected = any(field.get("argument_path") == argument_path
                                     and field.get("cascade_scope", {}).get("sink", {}).get("selected") is True
                                     for field in call.get("fields", []))
                comparison = (candidate or {}).get("evidence") in lineage.get("comparisons", [])
                if (
                    candidate and candidate.get("relation") == "candidate_content"
                    and candidate.get("evidence", {}).get("matched") is True
                    and candidate.get("from_node") == read_step["node_id"]
                    and label in candidate.get("label_ids", []) and sink
                    and sink.get("node_id") == lineage.get("node_id")
                    and sink.get("proposal_event_id") == call.get("proposal_event_id")
                    and sink.get("proposal_sequence") == call.get("proposal_sequence")
                    and sink.get("run_id") == call.get("run_id") == exposure.get("run_id")
                    and sink.get("episode_id")
                    == call.get("episode_id")
                    == exposure.get("episode_id")
                    and isinstance(proposal, dict)
                    and proposal.get("event_type") == "TOOL_CALL_PROPOSED"
                    and proposal.get("event_id") == candidate.get("event_id")
                    and proposal.get("event_sequence") == call.get("proposal_sequence")
                    and proposal.get("run_id") == sink.get("run_id")
                    and proposal.get("episode_id") == sink.get("episode_id")
                    and proposal.get("model_request_id")
                    == call.get("model_request_id")
                    == exposure.get("model_request_id")
                    and proposal.get("call_ref") == sink.get("call_ref")
                    and proposal.get("data", {}).get("function") == sink.get("function")
                    and proposal.get("data", {}).get("arguments") == sink.get("arguments")
                    and action and action.get("event_id") == proposal.get("event_id")
                    and action.get("call_ref") == sink.get("call_ref")
                    and action.get("function") == call.get("function") == sink.get("function")
                    and action.get("arguments") == call.get("arguments") == sink.get("arguments")
                    and field_selected and comparison
                    and _walk(b_graph, label, sink_route, sink["node_id"])
                ):
                    selected = (call, action, restore, exposure, candidate, sink, proposal)
                    break
            if selected:
                break
        if restored_selected:
            restore, exposure = restored_selected
            parts["b_memory_to_read_exposure"] = segment(
                "b_memory_to_read_exposure", "recorded_read_and_exposure", True,
                edge_ids=[restore["edge_id"]], event_ids=[exposure["event_id"]])
        if selected:
            call, action, restore, exposure, candidate, sink, proposal = selected
            parts["b_exposure_to_sink_proposal"] = segment(
                "b_exposure_to_sink_proposal", "detector_candidate_correspondence", True,
                evidence_strength="candidate_bound_to_recorded_proposal",
                edge_ids=[candidate["edge_id"]], event_ids=[proposal["event_id"]])
            parts.update(
                _sink_execution_segments(
                    b_record,
                    action,
                    proposal,
                    final_environment,
                    native_memory,
                    graph=b_graph,
                    sink_node=sink,
                    require_graph_result=True,
                )
            )
        rows = list(parts.values())
        routes.append({"label_id": label, "segments": rows,
                       "covered_segments": sum(row["coverage"] == "covered" for row in rows)})
    complete = bool(routes) and all(route["covered_segments"] == len(PATH_SEGMENTS) for route in routes)
    return {
        "status": "all_segments_covered" if complete else "partial_recorded_route",
        "routes": routes,
        "missing_segments": sorted({row["segment"] for route in routes for row in route["segments"]
                                    if row["coverage"] == "missing"}),
        "scope": "typed recorded and candidate coverage; no causal or attack-success inference",
        "causal_influence": "not_assessed", "attack_success": "unknown",
    }


def _boundary(
    a_record,
    b_record,
    session_comparisons,
    arm_index,
    artifacts,
):
    a_pid, a_pid_error = _process_id(a_record)
    b_pid, b_pid_error = _process_id(b_record)
    process = _status_for_identity([a_pid, b_pid])
    if a_pid_error or b_pid_error:
        process["status"] = "mismatched_recorded_pid_fields"
    process["field_errors"] = [error for error in (a_pid_error, b_pid_error) if error]
    a_actions = _read_actions(session_comparisons["A"], arm_index)
    b_actions = _read_actions(session_comparisons["B"], arm_index)
    reads = _read_ids(b_actions)
    a_graph_evidence, a_graph = _validated_graph(a_record, artifacts["a_lineage_value"])
    b_graph_evidence, b_graph = _validated_graph(b_record, artifacts["b_lineage_value"])
    continuity = _graph_continuity(a_graph, b_graph)
    memory = _memory_write(a_record, a_actions, a_graph_evidence, a_graph)
    episodes = _status_for_identity([_episode_ids(a_record) or None, _episode_ids(b_record) or None], local=True)
    episodes["global_session_identity"] = "unknown"
    fresh_history = _fresh_history(b_record)
    checkpoint_inputs = {
        "native_state": _input_binding(
            name="native_state",
            artifact=artifacts["a_native"],
            b_record=b_record,
            b_spec=artifacts["b_spec_value"],
            spec_key="native_input",
            copied=None,
            consumed=artifacts["consumed"],
        ),
        "lineage_checkpoint": _input_binding(
            name="lineage_checkpoint",
            artifact=artifacts["a_lineage"],
            b_record=b_record,
            b_spec=artifacts["b_spec_value"],
            spec_key="lineage_input",
            copied=artifacts["b_lineage_initial"],
            consumed=artifacts["consumed"],
        ),
    }
    b_spec = _b_spec_evidence(b_record, reads, artifacts)
    return {
        "identities": {
            "run": _status_for_identity(
                [_event_run_ids(a_record) or None, _event_run_ids(b_record) or None]
            ),
            "session": _status_for_identity(
                [
                    _recorded_identity_values(a_record, "session_id") or None,
                    _recorded_identity_values(b_record, "session_id") or None,
                ]
            ),
            "source_directory": _status_for_identity([a_record["run_id"], b_record["run_id"]]),
            "recorded_episode": episodes,
            "process": process,
            "fresh_b_history": fresh_history,
        },
        "checkpoint_inputs": checkpoint_inputs,
        "lineage_graph_validation": {
            "session_a": a_graph_evidence,
            "session_b": b_graph_evidence,
            "a_to_b": continuity,
        },
        "b_spec": b_spec,
        "consumed_boundary_hashes": {
            label: artifacts["consumed"].get(path.resolve())
            for label, path in artifacts["consumed_paths"].items()
            if artifacts["consumed"].get(path.resolve()) is not None
        },
        "created_file_id_to_b_read_id": _created_to_read(a_record, b_record, reads),
        "b_actual_source_exposure": _source_exposure(b_record, reads),
        "a_memory_write_and_version": memory,
        "b_restored_read": _restored_reads(b_record, reads),
        "observed_cross_session_native_path": _observed_native_path(
            a_record,
            a_actions,
            artifacts["a_native_value"],
            b_record,
            b_actions,
            continuity,
            checkpoint_inputs,
            b_spec,
            fresh_history,
            artifacts["b_final_environment_value"],
            artifacts["b_native_value"],
            a_graph,
            b_graph,
        ),
        "complete_propagation_path": _complete_paths(
            a_graph,
            b_graph,
            continuity,
            a_record,
            a_actions,
            b_record,
            b_actions,
            memory,
            checkpoint_inputs,
            b_spec,
            fresh_history,
            artifacts["b_final_environment_value"],
            artifacts["b_native_value"],
        ),
        "causal_influence": "not_assessed",
    }


def compare_cross_session_records(clean, attacked, *, labels=("clean", "attacked"), artifacts):
    """Compare ordered ``(session_a, session_b)`` records for two conditions."""
    if len(clean) != 2 or len(attacked) != 2 or len(labels) != 2:
        raise ValueError("Exactly two ordered sessions and two condition labels are required")
    if any(not isinstance(label, str) or not label or len(label) > 256 for label in labels):
        raise ValueError("Condition labels must be non-empty strings of at most 256 characters")
    if labels[0] == labels[1]:
        raise ValueError("Condition labels must be distinct")
    session_results = {
        "A": compare_records(clean[0], attacked[0]),
        "B": compare_records(clean[1], attacked[1]),
    }
    for comparison in session_results.values():
        for arm, label in zip(comparison["arms"], labels, strict=True):
            arm["condition"] = label
    boundaries = {
        labels[0]: _boundary(clean[0], clean[1], session_results, 0, artifacts[0]),
        labels[1]: _boundary(attacked[0], attacked[1], session_results, 1, artifacts[1]),
    }
    return {
        "schema_version": 2,
        "protocol": "offline-cross-session-propagation-v2",
        "scope": SCOPE,
        "condition_labels": list(labels),
        "session_order": ["A", "B"],
        "session_comparisons": session_results,
        "session_boundaries": boundaries,
        "causal_influence": "not_assessed",
        "attack_success": "unknown; use a separately declared native state oracle",
    }


def _page(result, records, output):
    esc = html.escape

    def dump(value):
        return "<pre>" + esc(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"

    def event_anchor(condition, stage, event_id):
        return f"{condition}-{stage}-{event_id}"

    def event_link(condition, stage, event_id, label=None):
        if not event_id:
            return "Absent"
        target = quote(event_anchor(condition, stage, event_id), safe="")
        return f'<a href="#{esc(target, quote=True)}">{esc(label or event_id)}</a>'

    boundary_links = []
    for condition in result["condition_labels"]:
        boundary = result["session_boundaries"][condition]
        links = []
        for binding in boundary["a_memory_write_and_version"]["bound_rows"]:
            graph_status = boundary["a_memory_write_and_version"]["graph_connectivity"]
            links.append(
                event_link(
                    condition,
                    "A",
                    binding["confirmed_write_event_id"],
                    f"A event-bound memory row [{graph_status}] "
                    + str(binding["confirmed_write_event_id"]),
                )
            )
        exposure_status = boundary["b_actual_source_exposure"]["status"]
        for exposure in boundary["b_actual_source_exposure"]["events"]:
            exposure_label = (
                "B observed exposure"
                if exposure_status == "observed"
                else f"Candidate B exposure [{exposure_status}]"
            )
            links.append(
                event_link(
                    condition,
                    "B",
                    exposure["event_id"],
                    exposure_label + " " + str(exposure["event_id"]),
                )
            )
            links.append(
                event_link(
                    condition,
                    "B",
                    exposure["source_result_event_id"],
                    exposure_label + " result " + str(exposure["source_result_event_id"]),
                )
            )
        restored_status = boundary["b_restored_read"]["status"]
        restored_rows = (
            boundary["b_restored_read"]["events_matching_recorded_b_read_ids"]
            if restored_status == "observed"
            else boundary["b_restored_read"]["restored_read_events"]
        )
        for restored in restored_rows:
            restored_label = (
                "B validated restored read"
                if restored_status == "observed"
                else f"Candidate B restored read [{restored_status}]"
            )
            links.append(
                event_link(
                    condition,
                    "B",
                    restored["event_id"],
                    restored_label + " " + str(restored["event_id"]),
                )
            )
        boundary_links.append(
            f"<p>{esc(condition)} boundary evidence: " + " · ".join(links or ["No linked events recorded."]) + "</p>"
        )

    sections = []
    for condition, pair in zip(result["condition_labels"], records, strict=True):
        for stage, record in zip(("A", "B"), pair, strict=True):
            report = Path(record["path"]) / "report.html"
            link = "Per-run report unavailable."
            if report.is_symlink():
                raise ValueError(f"Per-run report must not be a symlink: {report}")
            if report.exists() and not report.resolve().is_relative_to(Path(record["path"]).resolve()):
                raise ValueError(f"Per-run report resolves outside its source run: {report}")
            if report.is_file():
                href = quote(Path(os.path.relpath(report, output)).as_posix(), safe="/")
                link = f'<a href="{esc(href, quote=True)}">Open per-run report</a>'
            events = "".join(
                f'<details id="{esc(event_anchor(condition, stage, event["event_id"]), quote=True)}">'
                f'<summary>{esc(event["event_id"])} · {esc(event["event_type"])}</summary>{dump(event)}</details>'
                for event in record["events"]
                if event.get("event_id") and event.get("event_type") not in {"MODEL_REQUEST", "MODEL_RESPONSE"}
            )
            sections.append(
                f"<section><h2>{esc(condition)} session {stage}: {esc(record['run_id'])}</h2>"
                f"<p>{link}</p><h3>Recorded events</h3>{events}</section>"
            )
    alignments = []
    for stage in ("A", "B"):
        comparison = result["session_comparisons"][stage]
        rows = []
        for row in comparison["alignment"]["rows"]:
            refs = []
            for condition, key in zip(result["condition_labels"], ("clean_event_id", "attacked_event_id"), strict=True):
                event_id = row[key]
                refs.append(event_link(condition, stage, event_id))
            rows.append(
                f"<tr><td>{row['index']}</td><td>{esc(row['status'])}</td><td>{esc(str(row['function']))}</td>"
                f"<td>{refs[0]}</td><td>{refs[1]}</td><td>{dump(row['argument_changes'])}</td></tr>"
            )
        alignments.append(
            f"<h2>Session {stage} action alignment</h2><p>{esc(comparison['alignment']['rule'])}. "
            "An ambiguous alignment displays one equally optimal possibility.</p><div class=table><table><thead><tr>"
            f"<th>Row</th><th>Status</th><th>Tool</th><th>{esc(result['condition_labels'][0])}</th>"
            f"<th>{esc(result['condition_labels'][1])}</th><th>Argument changes</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
    overview = {
        "scope": result["scope"],
        "session_boundaries": result["session_boundaries"],
        "causal_influence": result["causal_influence"],
        "attack_success": result["attack_success"],
    }
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Cross-session trace comparison</title><style>body{{font:16px/1.5 system-ui;max-width:1200px;margin:32px auto;padding:0 20px}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border:1px solid #999;text-align:left;vertical-align:top}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere}}summary{{cursor:pointer}}details{{margin:10px 0}}.table{{overflow-x:auto}}</style></head>
<body><h1>Cross-session trace comparison</h1>{dump(overview)}{''.join(boundary_links)}{''.join(alignments)}{''.join(sections)}</body></html>"""


def export_cross_session_pair(
    clean_a: Path,
    clean_b: Path,
    attacked_a: Path,
    attacked_b: Path,
    output: Path,
    *,
    labels=("clean", "attacked"),
):
    """Export JSON and inert HTML without modifying the four source runs."""
    paths = [Path(path).expanduser().resolve() for path in (clean_a, clean_b, attacked_a, attacked_b)]
    output = Path(output).expanduser().resolve()
    if len(set(paths)) != 4:
        raise ValueError("The four ordered session run directories must be distinct")
    if output.exists():
        raise FileExistsError(output)
    if any(output == path or output.is_relative_to(path) for path in paths):
        raise ValueError("Report output must not be inside a source run directory")
    for index, path in enumerate(paths):
        additional = (path.parent / f"{path.name}-spec.json",) if index in (1, 3) else ()
        _validate_run_budget(path, additional=additional)
    records = [collect_run_record(path) for path in paths]
    consumed = {}
    artifacts = []
    for a_path, b_path in ((paths[0], paths[1]), (paths[2], paths[3])):
        branch_root = a_path.parent
        if b_path.parent != branch_root:
            branch_root = Path(os.path.commonpath((a_path, b_path)))
        branch_consumed = {}
        a_native = a_path / "native-memory.json"
        a_lineage = a_path / "lineage-state.json"
        b_initial = b_path / "lineage-initial-state.json"
        b_lineage = b_path / "lineage-state.json"
        b_final_environment = b_path / "final-environment.json"
        b_native = b_path / "native-memory.json"
        b_spec_path = b_path.parent / f"{b_path.name}-spec.json"
        a_native_value = _optional_json(a_native, branch_root, branch_consumed)
        a_lineage_value = _optional_json(a_lineage, branch_root, branch_consumed)
        _optional_json(b_initial, branch_root, branch_consumed)
        b_lineage_value = _optional_json(b_lineage, branch_root, branch_consumed)
        b_final_environment_value = _optional_json(
            b_final_environment, branch_root, branch_consumed
        )
        b_native_value = _optional_json(b_native, branch_root, branch_consumed)
        b_spec = _optional_json(b_spec_path, branch_root, branch_consumed)
        consumed.update(branch_consumed)
        artifacts.append(
            {
                "a_native": a_native,
                "a_native_value": a_native_value,
                "a_lineage": a_lineage,
                "a_lineage_value": a_lineage_value,
                "b_lineage_initial": b_initial,
                "b_lineage_value": b_lineage_value,
                "b_final_environment_value": b_final_environment_value,
                "b_native_value": b_native_value,
                "b_spec_path": b_spec_path,
                "b_spec_value": b_spec,
                "consumed": branch_consumed,
                "consumed_paths": {
                    "session_a/native-memory.json": a_native,
                    "session_a/lineage-state.json": a_lineage,
                    "session_b/lineage-initial-state.json": b_initial,
                    "session_b/lineage-state.json": b_lineage,
                    "session_b/final-environment.json": b_final_environment,
                    "session_b/native-memory.json": b_native,
                    f"session_b_spec/{b_spec_path.name}": b_spec_path,
                },
            }
        )
    for path, record in zip(paths, records, strict=True):
        for name, expected in record["source_hashes"].items():
            if _sha256(path / name) != expected:
                raise ValueError("Source changed while reading; preserve it before exporting")
    if any(_sha256(path) != expected for path, expected in consumed.items()):
        raise ValueError("Boundary source changed while reading; preserve it before exporting")
    result = compare_cross_session_records(
        (records[0], records[1]), (records[2], records[3]), labels=labels, artifacts=artifacts
    )
    for record, path in zip(records, paths, strict=True):
        record["path"] = str(path)
    for comparison in result["session_comparisons"].values():
        for arm, path in zip(comparison["arms"], (paths[0], paths[2]), strict=True):
            # Session B uses its own ordered paths.
            if comparison is result["session_comparisons"]["B"]:
                path = paths[1] if arm is comparison["arms"][0] else paths[3]
            arm["path"] = str(path)
    page = _page(result, ((records[0], records[1]), (records[2], records[3])), output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "cross-session.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    (output / "index.html").write_text(page, encoding="utf-8")
    return result
