"""Explicit, frozen tool policy; observed content cannot change tool classifications."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from yaml.tokens import AliasToken, AnchorToken


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    rationale: str = Field(min_length=1)


class SourceRule(Rule):
    output_scope: Literal["visible_text"] = "visible_text"


class SinkRule(Rule):
    argument_paths: list[str] = Field(min_length=1)

    @field_validator("argument_paths")
    @classmethod
    def pointers(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Duplicate argument paths")
        for pointer in value:
            if pointer and not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
                raise ValueError(
                    "Argument selectors must be RFC 6901 pointers; the empty pointer selects all"
                )
        return value


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    policy_id: str = Field(min_length=1)
    suite: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    sources: dict[str, SourceRule]
    sinks: dict[str, SinkRule]
    neutral_tools: dict[str, Rule]

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("Policy schema_version must be the integer 1")
        return value

    @model_validator(mode="after")
    def rule_names(self):
        names = set(self.sources) | set(self.sinks) | set(self.neutral_tools)
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
            raise ValueError("Policy tool names must be exact native function identifiers")
        if set(self.neutral_tools) & (set(self.sources) | set(self.sinks)):
            raise ValueError("A neutral tool cannot also be a source or sink")
        return self


class ToolPolicy:
    """Keep an immutable-by-interface normalized policy and content fingerprint."""

    def __init__(self, document: dict, *, source_sha256: str | None = None):
        self._document = PolicyDocument.model_validate(copy.deepcopy(document)).model_dump()
        raw = json.dumps(self._document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self._sha256 = hashlib.sha256(raw).hexdigest()
        self._source_sha256 = source_sha256

    @classmethod
    def from_dict(cls, document: dict):
        return cls(document)

    @property
    def metadata(self):
        return copy.deepcopy(
            {
                "policy_id": self._document["policy_id"],
                "sha256": self._sha256,
                "source_file_sha256": self._source_sha256,
                "document": self._document,
                "selection": "exact_tool_name; JSON_Pointer_prefix; no_payload_or_label_based_policy_changes",
                "source_scope": "direct_visible_tool_results_only; no_transitive_lineage_or_memory_restoration",
                "unclassified_tools": "explicit_coverage_gap; never_assume_trusted_or_malicious",
                "parameter_paths": "local_extension; empty_pointer_selects_all_supplied_leaf_arguments",
            }
        )

    def validate_context(self, suite: str, benchmark_version: str, tool_names=None):
        if (suite, benchmark_version) != (self._document["suite"], self._document["benchmark_version"]):
            raise ValueError("Policy suite/benchmark does not match the run")
        if tool_names is not None:
            named = (
                set(self._document["sources"])
                | set(self._document["sinks"])
                | set(self._document["neutral_tools"])
            )
            if named - set(tool_names):
                raise ValueError("Policy names a tool that is absent from the native suite")

    def classify_tool(self, name: str | None) -> dict:
        source = name in self._document["sources"]
        sink = name in self._document["sinks"]
        neutral = name in self._document["neutral_tools"]
        classification = (
            "source_and_sink"
            if source and sink
            else "source"
            if source
            else "sink"
            if sink
            else "neutral"
            if neutral
            else "unclassified_tool"
        )
        return {
            "tool": name,
            "source": source,
            "sink": sink,
            "neutral": neutral,
            "classification": classification,
        }

    def source_decision(self, kind: str, origin_tool: str | None) -> dict:
        if kind != "tool":
            return {
                "eligible": False,
                "reason": "context_control_not_policy_source",
                "kind": kind,
                "origin_tool": None,
            }
        decision = self.classify_tool(origin_tool)
        return {
            **decision,
            "eligible": decision["source"],
            "reason": "declared_source"
            if decision["source"]
            else "unclassified_tool"
            if decision["classification"] == "unclassified_tool"
            else "tool_output_excluded_by_policy",
        }

    def sink_decision(self, name: str, path: str | None = None) -> dict:
        decision = self.classify_tool(name)
        selectors = self._document["sinks"].get(name, {}).get("argument_paths", [])
        selected = decision["sink"] and (
            path is None or any(path == prefix or path.startswith(prefix + "/") for prefix in selectors)
        )
        return {
            **decision,
            "selected": selected,
            "argument_path": path,
            "argument_selectors": list(selectors),
            "reason": "declared_sink"
            if selected
            else "argument_excluded_by_policy"
            if decision["sink"]
            else "unclassified_tool"
            if decision["classification"] == "unclassified_tool"
            else "not_a_policy_sink",
        }


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ValueError("Policy mappings require unique string keys")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_policy(path: Path) -> ToolPolicy:
    raw = Path(path).expanduser().read_bytes()
    if len(raw) > 65536:
        raise ValueError("Policy exceeds the 65536-byte configuration budget")
    try:
        text = raw.decode("utf-8")
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise ValueError("Policy aliases and anchors are unsupported")
        document = yaml.load(text, Loader=_UniqueLoader)
        return ToolPolicy(document, source_sha256=hashlib.sha256(raw).hexdigest())
    except (yaml.YAMLError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid policy YAML") from error
