"""Independent diagnostic placement of UUID canaries inside drive-file content.

This is a local placement experiment, separate from the canonical YAML-comment
intervention. A prepared assignment is only a plan; exposure is established by
the observation and provenance pipeline.
"""

from __future__ import annotations

import copy
import re
import uuid
from collections.abc import Mapping

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from agentdojo_lab.canary import (
    MAX_CODEPOINTS,
    MAX_CONTENT_PARTS,
    MAX_GENERATION_ATTEMPTS,
    MAX_SEEN_CALLS,
    METHOD,
    PLACEMENT_SCHEME,
    SCHEME,
    CanaryInjector,
    _canonical_token,
    _metadata,
    _native_texts,
    _sha,
    _span,
)
from agentdojo_lab.policy import ToolPolicy

PLACEMENTS = frozenset({"content_start", "content_middle", "content_end"})
MARKER_PREFIX = "# NT_CANARY: "
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_YAML_NODES = 4_096
_MAX_YAML_DEPTH = 32


def placement_metadata(placement: str | None = None) -> dict:
    """Describe the separate, explicitly selected local placement scheme."""
    metadata = _metadata()
    metadata.update(
        scheme=PLACEMENT_SCHEME,
        placement=placement or "inside_YAML_content_scalar",
        native_layout="one_type_text_content_string_block_with_flat_YAML_mapping",
        serialization="single_native_text_block; one_raw_insertion_inside_single_quoted_multiline_scalar",
        target_tool="get_file_by_id",
        target_field="/content",
        marker_line="# NT_CANARY: <canonical_UUIDv4>",
        middle_anchor="unique_Decisions_line",
        non_target_file_scheme=SCHEME,
        assumptions=[
            "Placement inside the parsed content scalar is a local diagnostic choice.",
            "The original content value remains an exact subsequence around one inserted marker line.",
            "The original YAML bytes remain in order; only one raw marker segment is inserted inside content.",
            "Unsupported scalar layouts are left unmodified and recorded as unknown.",
            "A valid compact reference still requires verified application and HTTP exposure.",
        ],
    )
    return metadata


def _parse_document(text: str) -> tuple[dict, list[int]]:
    """Accept only a bounded, unambiguous YAML mapping with a string content field."""
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError("Invalid YAML document") from error
    if not isinstance(node, MappingNode):
        raise ValueError("YAML document must be a mapping")
    seen_nodes: set[int] = set()
    count = 0

    def inspect(current, depth: int) -> None:
        nonlocal count
        count += 1
        if count > _MAX_YAML_NODES or depth > _MAX_YAML_DEPTH or id(current) in seen_nodes:
            raise ValueError("Unsupported YAML graph or budget")
        seen_nodes.add(id(current))
        if isinstance(current, MappingNode):
            keys: set[str] = set()
            for key, value in current.value:
                if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise ValueError("Unsupported YAML key")
                if key.value in keys:
                    raise ValueError("Duplicate YAML key")
                keys.add(key.value)
                inspect(key, depth + 1)
                inspect(value, depth + 1)
        elif isinstance(current, SequenceNode):
            for value in current.value:
                inspect(value, depth + 1)
        elif not isinstance(current, ScalarNode):
            raise ValueError("Unsupported YAML node")

    inspect(node, 0)
    content_entries = [(key, value) for key, value in node.value if key.value == "content"]
    if (
        node.flow_style
        or len(content_entries) != 1
        or not isinstance(content_entries[0][1], ScalarNode)
        or content_entries[0][1].tag != "tag:yaml.org,2002:str"
        or content_entries[0][1].style != "'"
    ):
        raise ValueError("YAML content must be a string scalar")
    key_node, content_node = content_entries[0]
    scalar_fragment = text[content_node.start_mark.index : content_node.end_mark.index]
    if (
        key_node.start_mark.column != 0
        or text[key_node.start_mark.index : content_node.start_mark.index] != "content: "
        or not scalar_fragment.startswith("'")
        or not scalar_fragment.endswith("'")
        or "\n" not in scalar_fragment
    ):
        raise ValueError("Unsupported YAML content scalar layout")
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError("Invalid YAML document") from error
    if type(document) is not dict or type(document.get("content")) is not str or not document["content"]:
        raise ValueError("YAML content must be a nonempty string")
    return document, [content_node.start_mark.index, content_node.end_mark.index]


def _tool_file_id(message) -> str | None:
    if not isinstance(message, dict):
        return None
    call = message.get("tool_call")
    arguments = call.get("args") if isinstance(call, dict) else getattr(call, "args", None)
    file_id = arguments.get("file_id") if isinstance(arguments, Mapping) else None
    return file_id if isinstance(file_id, str) and file_id else None


def _raw_insertion(
    original_text: str, scalar_span: list[int], content: str, placement: str, token: str
) -> tuple[int, str, int, str]:
    """Return raw offset/text and the exact parsed-content insertion they induce."""
    marker = MARKER_PREFIX + token
    start, end = scalar_span
    scalar = original_text[start:end]
    if placement == "content_start":
        return start + 1, marker + "\n\n", 0, marker + "\n"
    if placement == "content_end":
        return end - 1, "\n\n  " + marker, len(content), "\n" + marker
    if placement != "content_middle":
        raise ValueError("Unsupported content placement")
    raw_matches = list(re.finditer(r"(?m)^  Decisions:", scalar))
    parsed_matches = list(re.finditer(r"(?m)^Decisions:", content))
    if len(raw_matches) != 1 or len(parsed_matches) != 1:
        raise ValueError("Middle placement requires the unique Decisions line")
    return start + raw_matches[0].start(), "  " + marker + "\n\n", parsed_matches[0].start(), marker + "\n"


def validate_placement_assignment(audit: dict) -> dict:
    """Validate an in-content assignment without trusting its declared spans."""
    if (
        not isinstance(audit, dict)
        or type(audit.get("schema_version")) is not int
        or audit["schema_version"] != 1
        or audit.get("method") != METHOD
        or audit.get("scheme") != PLACEMENT_SCHEME
        or audit.get("status") != "assigned"
        or audit.get("application") != "planned_only"
        or audit.get("reason") != "eligible_successful_tool_output"
        or audit.get("function") != "get_file_by_id"
        or audit.get("target_file_id") != audit.get("observed_file_id")
    ):
        raise ValueError("Unsupported placement assignment schema or status")
    for key in ("run_id", "episode_id", "call_ref", "function"):
        if not isinstance(audit.get(key), str) or not 1 <= len(audit[key]) <= 1_024:
            raise ValueError("Invalid placement assignment identity")
    if not isinstance(audit.get("target_file_id"), str) or not 1 <= len(audit["target_file_id"]) <= 1_024:
        raise ValueError("Invalid placement target file identity")
    if not isinstance(audit.get("policy_sha256"), str) or not _SHA256.fullmatch(audit["policy_sha256"]):
        raise ValueError("Invalid placement policy fingerprint")
    token = _canonical_token(audit.get("token"))
    placement = audit.get("placement")
    if not isinstance(placement, str) or placement not in PLACEMENTS:
        raise ValueError("Invalid content placement")
    originals = _native_texts(audit.get("original_content"))
    marked = _native_texts(audit.get("marked_content"))
    if len(originals) != 1 or len(marked) != 1 or type(audit.get("selected_part_index")) is not int or audit["selected_part_index"] != 0:
        raise ValueError("Placement requires one selected native text block")
    original_text, marked_text = originals[0], marked[0]
    if token in original_text or marked_text.count(token) != 1:
        raise ValueError("Placement token must occur exactly once in the marked text")
    for key, value in (("original_text", original_text), ("marked_text", marked_text)):
        if audit.get(key) != value or audit.get(key + "_sha256") != _sha(value):
            raise ValueError("Placement text or hash does not match native content")
    original_doc, original_scalar_span = _parse_document(original_text)
    marked_doc, marked_parsed_span = _parse_document(marked_text)
    original_scalar = original_doc["content"]
    raw_offset, raw_insert, offset, inserted = _raw_insertion(
        original_text, original_scalar_span, original_scalar, placement, token
    )
    expected_scalar = original_scalar[:offset] + inserted + original_scalar[offset:]
    marked_scalar_span = [original_scalar_span[0], original_scalar_span[1] + len(raw_insert)]
    if (
        type(audit.get("content_insertion_offset")) is not int
        or audit["content_insertion_offset"] != offset
        or type(audit.get("insertion_offset")) is not int
        or audit["insertion_offset"] != offset
        or audit.get("inserted_text") != inserted
        or audit.get("suffix") != inserted
        or type(audit.get("raw_insertion_offset")) is not int
        or audit["raw_insertion_offset"] != raw_offset
        or type(audit.get("raw_insertion_byte_offset")) is not int
        or audit["raw_insertion_byte_offset"] != len(original_text[:raw_offset].encode("utf-8"))
        or audit.get("raw_inserted_text") != raw_insert
        or _span(audit.get("original_scalar_span"), length=len(original_text)) != original_scalar_span
        or _span(audit.get("marked_scalar_span"), length=len(marked_text)) != marked_scalar_span
        or marked_text != original_text[:raw_offset] + raw_insert + original_text[raw_offset:]
        or marked_parsed_span != marked_scalar_span
        or marked_doc["content"] != expected_scalar
        or {key: value for key, value in marked_doc.items() if key != "content"}
        != {key: value for key, value in original_doc.items() if key != "content"}
    ):
        raise ValueError("Placement changed content or metadata beyond the marker insertion")
    token_start = marked_text.find(token)
    token_span = [token_start, token_start + 36]
    if (
        _span(audit.get("part_token_span"), length=len(marked_text)) != token_span
        or _span(audit.get("joined_token_span"), length=len(marked_text)) != token_span
    ):
        raise ValueError("Invalid placement token span")
    attempts = audit.get("generation_attempts")
    if type(attempts) is not int or not 1 <= attempts <= MAX_GENERATION_ATTEMPTS:
        raise ValueError("Invalid placement generation attempt count")
    return copy.deepcopy(audit)


class PlacementCanaryInjector(CanaryInjector):
    """Plan a marker inside one eligible drive-file YAML content scalar."""

    def __init__(
        self,
        policy: ToolPolicy,
        placement: str = "content_start",
        uuid_factory=uuid.uuid4,
        *,
        target_file_id: str = "1",
    ):
        if not isinstance(placement, str) or placement not in PLACEMENTS:
            raise ValueError("placement must be content_start, content_middle, or content_end")
        if not isinstance(target_file_id, str) or not 1 <= len(target_file_id) <= 1_024:
            raise ValueError("target_file_id must be a nonempty file identifier")
        super().__init__(policy, uuid_factory)
        self.placement = placement
        self.target_file_id = target_file_id

    @property
    def metadata(self) -> dict:
        return {
            **placement_metadata(self.placement),
            "policy_sha256": self._policy_sha256,
            "target_file_id": self.target_file_id,
        }

    def status(self) -> dict:
        result = super().status()
        result["complete"] = result["complete"] and not self._counts["unknown"]
        result["unknown_count"] = self._counts["unknown"]
        return result

    def prepare(self, message, *, run_id, episode_id, call_ref, function, runtime_entered) -> dict:
        observed_file_id = _tool_file_id(message) if function == "get_file_by_id" else None
        if observed_file_id is not None and observed_file_id != self.target_file_id:
            return super().prepare(
                message,
                run_id=run_id,
                episode_id=episode_id,
                call_ref=call_ref,
                function=function,
                runtime_entered=runtime_entered,
            )
        self._counts["prepare_calls"] += 1
        audit = {
            "schema_version": 1,
            "method": METHOD,
            "scheme": PLACEMENT_SCHEME,
            "status": "skipped",
            "reason": None,
            "interpretation": "not_applicable",
            "run_id": run_id,
            "episode_id": episode_id,
            "call_ref": call_ref,
            "function": function,
            "policy_sha256": self._policy_sha256,
            "placement": self.placement,
            "target_file_id": self.target_file_id,
            "observed_file_id": observed_file_id,
            "original_content": None,
            "marked_content": None,
            "original_text": None,
            "marked_text": None,
            "original_text_sha256": None,
            "marked_text_sha256": None,
            "token": None,
            "selected_part_index": None,
            "insertion_offset": None,
            "content_insertion_offset": None,
            "inserted_text": None,
            "raw_insertion_offset": None,
            "raw_insertion_byte_offset": None,
            "raw_inserted_text": None,
            "original_scalar_span": None,
            "marked_scalar_span": None,
            "part_token_span": None,
            "joined_token_span": None,
            "suffix": None,
            "generation_attempts": 0,
            "application": "planned_only",
        }

        def skipped(reason: str, *, unknown: bool = False) -> dict:
            audit["reason"] = reason
            audit["interpretation"] = "unknown" if unknown else "not_applicable"
            self._counts["skipped"] += 1
            self._reasons[reason] += 1
            if unknown:
                self._counts["unknown"] += 1
            if reason == "budget_exceeded":
                self._counts["budget_exceeded"] += 1
            return audit

        try:
            if not self._active:
                return skipped("injector_disabled", unknown=True)
            if any(
                not isinstance(value, str) or not 1 <= len(value) <= 1_024
                for value in (run_id, episode_id, call_ref, function)
            ):
                raise ValueError("Invalid canary call identity")
            identity = (run_id, episode_id, call_ref)
            if identity in self._seen:
                return skipped("duplicate_call_identity")
            if len(self._seen) >= MAX_SEEN_CALLS:
                raise ValueError("Canary call registry budget exceeded")
            self._seen.add(identity)
            if not isinstance(message, dict) or message.get("role") != "tool":
                return skipped("unsupported_message_layout", unknown=True)
            if runtime_entered is not True:
                return skipped("runtime_not_entered")
            if message.get("error") is not None:
                return skipped("tool_error")
            decision = self.policy.source_decision("tool", function)
            if not decision["eligible"]:
                return skipped(decision["reason"])
            if function != "get_file_by_id":
                return skipped("tool_output_excluded_by_placement")
            if observed_file_id is None:
                return skipped("unknown_file_id", unknown=True)
            content = message.get("content")
            if isinstance(content, list) and len(content) > MAX_CONTENT_PARTS:
                return skipped("budget_exceeded")
            if (
                isinstance(content, list)
                and len(content) == 1
                and isinstance(content[0], dict)
                and set(content[0]) == {"type", "content"}
                and content[0]["type"] == "text"
                and isinstance(content[0]["content"], str)
                and len(content[0]["content"]) > MAX_CODEPOINTS
            ):
                return skipped("budget_exceeded")
            try:
                texts = _native_texts(content)
            except ValueError:
                return skipped("unsupported_content_layout", unknown=True)
            if len(texts) != 1:
                return skipped("unsupported_content_layout", unknown=True)
            original_text = texts[0]
            if len(original_text) > MAX_CODEPOINTS:
                return skipped("budget_exceeded")
            try:
                document, original_scalar_span = _parse_document(original_text)
            except ValueError:
                return skipped("unsupported_yaml_layout", unknown=True)
            original_scalar = document["content"]
            token = None
            for attempt in range(1, MAX_GENERATION_ATTEMPTS + 1):
                generated = self._uuid_factory()
                candidate = _canonical_token(
                    str(generated) if isinstance(generated, uuid.UUID) else generated
                )
                if candidate not in self._issued and candidate not in original_text:
                    token = candidate
                    break
            if token is None:
                raise ValueError("UUID uniqueness budget exhausted")
            try:
                raw_offset, raw_insert, offset, inserted = _raw_insertion(
                    original_text, original_scalar_span, original_scalar, self.placement, token
                )
            except ValueError:
                return skipped("unsupported_yaml_layout", unknown=True)
            marked_scalar_span = [original_scalar_span[0], original_scalar_span[1] + len(raw_insert)]
            marked_text = original_text[:raw_offset] + raw_insert + original_text[raw_offset:]
            if len(marked_text) > MAX_CODEPOINTS:
                return skipped("budget_exceeded")
            try:
                marked_doc, marked_parsed_span = _parse_document(marked_text)
            except ValueError:
                return skipped("unsupported_yaml_layout", unknown=True)
            if (
                marked_parsed_span != marked_scalar_span
                or marked_doc["content"] != original_scalar[:offset] + inserted + original_scalar[offset:]
                or {key: value for key, value in marked_doc.items() if key != "content"}
                != {key: value for key, value in document.items() if key != "content"}
            ):
                return skipped("unsupported_yaml_layout", unknown=True)
            token_start = marked_text.find(token)
            marked_content = [{"type": "text", "content": marked_text}]
            audit.update(
                status="assigned",
                reason="eligible_successful_tool_output",
                interpretation="assigned_plan_only",
                original_content=[dict(part) for part in content],
                marked_content=marked_content,
                original_text=original_text,
                marked_text=marked_text,
                original_text_sha256=_sha(original_text),
                marked_text_sha256=_sha(marked_text),
                token=token,
                selected_part_index=0,
                insertion_offset=offset,
                content_insertion_offset=offset,
                inserted_text=inserted,
                suffix=inserted,
                raw_insertion_offset=raw_offset,
                raw_insertion_byte_offset=len(original_text[:raw_offset].encode("utf-8")),
                raw_inserted_text=raw_insert,
                original_scalar_span=original_scalar_span,
                marked_scalar_span=marked_scalar_span,
                part_token_span=[token_start, token_start + 36],
                joined_token_span=[token_start, token_start + 36],
                generation_attempts=attempt,
            )
            validate_placement_assignment(audit)
            self._issued.add(token)
            self._counts["assigned"] += 1
            return audit
        except Exception as error:
            self.fail("prepare", error)
            self._counts["error"] += 1
            audit.update(
                status="error",
                reason="preparation_failed",
                interpretation="unknown",
                token=None,
                marked_content=None,
                marked_text=None,
                marked_text_sha256=None,
                inserted_text=None,
                part_token_span=None,
                joined_token_span=None,
                error_type=type(error).__name__,
            )
            return audit
