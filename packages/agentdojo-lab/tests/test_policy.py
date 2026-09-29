"""Frozen policy configuration, selectors, and actual workspace tool coverage."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab.policy import ToolPolicy, load_policy


def document():
    return {
        "schema_version": 1,
        "policy_id": "local-test-policy-v1",
        "suite": "workspace",
        "benchmark_version": "v1.2.2",
        "sources": {"read_note": {"rationale": "Reads external note text."}},
        "sinks": {"update_note": {"rationale": "Changes a note.", "argument_paths": ["/text"]}},
        "neutral_tools": {"clock": {"rationale": "Returns the simulator clock."}},
    }


def write_policy(tmp_path, raw):
    path = tmp_path / "policy.yaml"
    path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
    return path


def test_normalized_fingerprint_is_deterministic_and_defaults_are_explicit():
    original = document()
    reordered = dict(reversed(list(original.items())))
    reordered["sources"] = {
        "read_note": {"output_scope": "visible_text", "rationale": "Reads external note text."}
    }
    first, second = ToolPolicy(original), ToolPolicy(reordered)
    assert first.metadata["sha256"] == second.metadata["sha256"]
    normalized = first.metadata["document"]
    assert normalized["sources"]["read_note"]["output_scope"] == "visible_text"
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert first.metadata["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert first.metadata["source_file_sha256"] is None
    changed = document()
    changed["sinks"]["update_note"]["argument_paths"] = ["/record"]
    assert ToolPolicy(changed).metadata["sha256"] != first.metadata["sha256"]


def test_json_yaml_and_comments_have_same_policy_hash_but_distinct_file_hashes(tmp_path):
    fingerprints, file_hashes = [], []
    raw_documents = [
        json.dumps(document()),
        yaml.safe_dump(document()),
        "# Local comment\n" + yaml.safe_dump(document()),
    ]
    for raw in raw_documents:
        policy = load_policy(write_policy(tmp_path, raw))
        fingerprints.append(policy.metadata["sha256"])
        file_hashes.append(policy.metadata["source_file_sha256"])
        assert file_hashes[-1] == hashlib.sha256(raw.encode()).hexdigest()
    assert len(set(fingerprints)) == 1
    assert len(set(file_hashes)) == 3


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None])
def test_schema_version_requires_exact_integer_one(version):
    config = document()
    config["schema_version"] = version
    with pytest.raises(ValueError):
        ToolPolicy(config)


@pytest.mark.parametrize("field", ["policy_id", "suite", "benchmark_version"])
@pytest.mark.parametrize("value", ["", 1, True, None])
def test_required_identity_fields_are_nonempty_strings(field, value):
    config = document()
    config[field] = value
    with pytest.raises(ValueError):
        ToolPolicy(config)


@pytest.mark.parametrize("location", ["document", "source", "sink", "neutral"])
def test_unknown_configuration_fields_are_rejected(location):
    config = document()
    target = {
        "document": config,
        "source": config["sources"]["read_note"],
        "sink": config["sinks"]["update_note"],
        "neutral": config["neutral_tools"]["clock"],
    }[location]
    target["automatic_classification"] = True
    with pytest.raises(ValueError):
        ToolPolicy(config)


@pytest.mark.parametrize("name", ["read*", "read-note", "read.note", "read note", "1read", "", "Read Note"])
def test_configured_tool_names_must_be_exact_function_identifiers(name):
    config = document()
    config["sources"] = {name: {"rationale": "Fixture."}}
    with pytest.raises(ValueError):
        ToolPolicy(config)


@pytest.mark.parametrize("name", [None, "READ_NOTE", "read", "read_note_extra", "read_note ", "read*"])
def test_runtime_classification_never_uses_case_folding_prefixes_or_wildcards(name):
    policy = ToolPolicy(document())
    assert policy.classify_tool(name)["classification"] == "unclassified_tool"
    assert policy.source_decision("tool", name)["eligible"] is False
    assert policy.source_decision("tool", name)["reason"] == "unclassified_tool"


def test_source_sink_overlap_is_allowed_and_neutral_overlap_is_rejected():
    config = document()
    config["sinks"]["read_note"] = {"rationale": "Reading also changes state.", "argument_paths": [""]}
    policy = ToolPolicy(config)
    assert policy.classify_tool("read_note")["classification"] == "source_and_sink"
    assert policy.source_decision("tool", "read_note")["eligible"] is True
    assert policy.sink_decision("read_note")["selected"] is True
    for name in ("read_note", "update_note"):
        invalid = copy.deepcopy(config)
        invalid["neutral_tools"][name] = {"rationale": "Conflicting classification."}
        with pytest.raises(ValueError):
            ToolPolicy(invalid)


@pytest.mark.parametrize("role", ["user", "system", "developer", "assistant", "unknown"])
def test_context_roles_cannot_become_policy_sources_by_claiming_a_tool_name(role):
    result = ToolPolicy(document()).source_decision(role, "read_note")
    assert result["eligible"] is False
    assert result["reason"] == "context_control_not_policy_source"
    assert result["origin_tool"] is None


def test_neutral_and_sink_only_outputs_are_explicit_policy_exclusions():
    policy = ToolPolicy(document())
    for name in ("clock", "update_note"):
        result = policy.source_decision("tool", name)
        assert result["eligible"] is False
        assert result["reason"] == "tool_output_excluded_by_policy"
    assert policy.sink_decision("read_note")["reason"] == "not_a_policy_sink"
    assert policy.sink_decision("missing")["reason"] == "unclassified_tool"


@pytest.mark.parametrize("selectors", [[], ["text"], ["/bad~"], ["/~2"], ["/text", "/text"], [1], "/text"])
def test_invalid_argument_selector_configuration_is_rejected(selectors):
    config = document()
    config["sinks"]["update_note"]["argument_paths"] = selectors
    with pytest.raises(ValueError):
        ToolPolicy(config)


@pytest.mark.parametrize(
    "path,selected",
    [
        ("/records", True),
        ("/records/0/id", True),
        ("/records/01/id", True),
        ("/records_extra", False),
        ("/records-extra/0", False),
        ("/records~1extra", False),
        ("/a~1b/~0key", True),
        ("/a~1b/~0key/child", True),
        ("/a/b/~0key", False),
        ("/a~1b/~0key_suffix", False),
        ("/literal/*", True),
        ("/literal/*/child", True),
        ("/literal/0", False),
        ("/literal/anything", False),
        ("/list/0", True),
        ("/list/0/name", True),
        ("/list/00", False),
        ("/list/1", False),
        ("", False),
    ],
)
def test_json_pointer_selection_preserves_components_escaping_numeric_tokens_and_literal_star(path, selected):
    config = document()
    config["sinks"]["update_note"]["argument_paths"] = ["/records", "/a~1b/~0key", "/literal/*", "/list/0"]
    decision = ToolPolicy(config).sink_decision("update_note", path)
    assert decision["selected"] is selected
    assert decision["reason"] == ("declared_sink" if selected else "argument_excluded_by_policy")


def test_root_selector_covers_all_supplied_leaf_paths_and_empty_named_key_is_distinct():
    config = document()
    config["sinks"]["update_note"]["argument_paths"] = [""]
    policy = ToolPolicy(config)
    for path in ("", "/text", "/0", "/nested/list/10/id", "/a~1b/~0key", "/"):
        assert policy.sink_decision("update_note", path)["selected"] is True
    config["sinks"]["update_note"]["argument_paths"] = ["/"]
    policy = ToolPolicy(config)
    assert policy.sink_decision("update_note", "/")["selected"] is True
    assert policy.sink_decision("update_note", "//nested")["selected"] is True
    assert policy.sink_decision("update_note", "/text")["selected"] is False
    assert policy.sink_decision("update_note", "")["selected"] is False


def test_input_documents_metadata_and_returned_selectors_cannot_mutate_policy():
    config = document()
    policy = ToolPolicy(config)
    original = policy.metadata
    config["sources"].clear()
    config["sinks"]["update_note"]["argument_paths"].append("")
    changed = policy.metadata
    changed["document"]["sources"].clear()
    changed["document"]["sinks"]["update_note"]["argument_paths"].append("")
    changed["sha256"] = "changed"
    decision = policy.sink_decision("update_note", "/text")
    decision["argument_selectors"].append("")
    assert policy.metadata == original
    assert policy.source_decision("tool", "read_note")["eligible"] is True
    assert policy.sink_decision("update_note", "/other")["selected"] is False


@pytest.mark.parametrize(
    "suite,version", [("banking", "v1.2.2"), ("workspace", "v1.2.1"), ("Workspace", "v1.2.2")]
)
def test_policy_context_must_match_suite_and_benchmark(suite, version):
    with pytest.raises(ValueError):
        ToolPolicy(document()).validate_context(suite, version)


def test_native_tool_inventory_catches_typos_but_keeps_unnamed_tools_unclassified():
    policy = ToolPolicy(document())
    policy.validate_context("workspace", "v1.2.2", ["read_note", "update_note", "clock", "unlisted"])
    assert policy.classify_tool("unlisted")["classification"] == "unclassified_tool"
    with pytest.raises(ValueError):
        policy.validate_context("workspace", "v1.2.2", ["read_notes", "update_note", "clock"])


@pytest.mark.parametrize(
    "raw",
    [
        "schema_version: 1\nschema_version: 1\n",
        '{"schema_version":1,"schema_version":1}',
        "sources:\n  read_note:\n    rationale: first\n    rationale: second\n",
        "sources:\n  1: value\n",
        "sources:\n  ? [one, two]\n  : value\n",
        "document: &policy {}\n",
        "document: &policy {}\ncopy: *policy\n",
        "*missing\n",
        "!custom {}\n",
        "!!python/tuple [1, 2]\n",
        "!!set {a: null}\n",
        "[one, two]\n",
        "null\n",
        "single string\n",
        "2026-09-08\n",
        ".nan\n",
        "schema_version: [\n",
        b"\xff\xfe",
    ],
)
def test_invalid_yaml_structures_duplicates_aliases_tags_and_non_json_values_are_rejected(tmp_path, raw):
    with pytest.raises(ValueError):
        load_policy(write_policy(tmp_path, raw))


def test_yaml_non_json_field_types_and_multiple_documents_are_rejected(tmp_path):
    valid = yaml.safe_dump(document())
    raw_documents = [
        valid.replace("local-test-policy-v1", "2026-09-08"),
        valid.replace("local-test-policy-v1", ".nan"),
        valid.replace("local-test-policy-v1", '!!binary "dGVzdA=="'),
        valid + "---\n" + valid,
    ]
    for raw in raw_documents:
        with pytest.raises(ValueError):
            load_policy(write_policy(tmp_path, raw))


def test_policy_byte_budget_accepts_boundary_and_rejects_oversize_before_parsing(tmp_path):
    valid = yaml.safe_dump(document()).encode()
    boundary = valid + b"#" + b" " * (65536 - len(valid) - 1)
    assert len(boundary) == 65536
    accepted = load_policy(write_policy(tmp_path, boundary))
    assert accepted.metadata["policy_id"] == "local-test-policy-v1"
    with pytest.raises(ValueError, match="65536-byte"):
        load_policy(write_policy(tmp_path, boundary + b" "))


def test_default_workspace_policy_covers_actual_suite_with_declared_overlap():
    path = Path(__file__).resolve().parents[1] / "configs" / "workspace_policy_v1.yaml"
    policy = load_policy(path)
    config = policy.metadata["document"]
    suite = get_suite(config["benchmark_version"], config["suite"])
    native_names = {tool.name for tool in suite.tools}
    declared_names = set(config["sources"]) | set(config["sinks"]) | set(config["neutral_tools"])
    assert len(config["sources"]) == 13
    assert len(config["sinks"]) == 11
    assert len(config["neutral_tools"]) == 1
    assert len(native_names) == len(declared_names) == 24
    assert declared_names == native_names
    assert set(config["sources"]) & set(config["sinks"]) == {"get_unread_emails"}
    policy.validate_context(config["suite"], config["benchmark_version"], native_names)
    assert policy.classify_tool("get_unread_emails")["classification"] == "source_and_sink"
    assert policy.classify_tool("get_current_day")["classification"] == "neutral"
    unread = next(tool for tool in suite.tools if tool.name == "get_unread_emails")
    assert unread.parameters.model_fields == {}
    assert policy.sink_decision("get_unread_emails")["selected"] is True
