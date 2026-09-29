"""Independent decoding examples and fail-closed scalar coordinate controls."""

import hashlib
import json

import pytest
import yaml
from yaml.nodes import ScalarNode, SequenceNode

from agentdojo_lab.span_scalars import LIMITS, decode_span_scalars


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_large_json_integer_keeps_lexical_text_without_numeric_conversion():
    text = "9" * 4301
    result = decode_span_scalars(text)
    assert result["complete"] is True
    assert result["scalars"][0]["decoded_text"] == text


def test_out_of_range_yaml_escape_is_unavailable():
    result = decode_span_scalars('value: "\\U00110000"')
    assert result["complete"] is False
    assert result["scalars"] == []
    assert result["reason"] == "invalid_scalar_escape"


def assert_complete(text, pointers, values):
    result = decode_span_scalars(text)
    assert result["complete"] is True
    assert result["status"] in {"parsed", "plain_text"}
    assert [item["scalar_pointer"] for item in result["scalars"]] == pointers
    assert [item["decoded_text"] for item in result["scalars"]] == values
    for item in result["scalars"]:
        start, end = item["wire_span"]
        assert 0 <= start <= end <= len(text)
        assert item["decoded_sha256"] == sha(item["decoded_text"])
        assert item["wire_token_sha256"] == sha(text[start:end])
    assert decode_span_scalars(text) == result
    assert json.loads(json.dumps(result, ensure_ascii=False)) == result
    return result


def test_nested_json_escapes_and_pointer_escaping():
    text = '{"a/b~c": [{"\\u006eame": "first\\nsecond\\t\\u0061"}, 13, true, null], "": "last"}'
    result = assert_complete(
        text,
        ["/a~1b~0c/0/name", "/a~1b~0c/1", "/a~1b~0c/2", "/a~1b~0c/3", "/"],
        ["first\nsecond\ta", "13", "true", "null", "last"],
    )
    first = result["scalars"][0]
    assert first["style"] == "double_quoted"
    start, end = first["wire_span"]
    assert text[start:end] == '"first\\nsecond\\t\\u0061"'
    assert end - start != len(first["decoded_text"])


def test_yaml_block_folded_and_single_quoted_scalars():
    text = "literal: |\n  first\n  second\nfolded: >-\n  one\n  two\nquoted: 'it''s exact'\n"
    result = assert_complete(
        text, ["/literal", "/folded", "/quoted"], ["first\nsecond\n", "one two", "it's exact"]
    )
    assert [item["style"] for item in result["scalars"]] == ["literal_block", "folded_block", "single_quoted"]
    first = result["scalars"][0]
    assert text[slice(*first["wire_span"])] == "|\n  first\n  second\n"


def test_unicode_codepoints_are_not_byte_or_grapheme_offsets():
    text = '{"emoji":"😀", "combining":"e\u0301", "case":"ABC abc"}'
    result = assert_complete(text, ["/emoji", "/combining", "/case"], ["😀", "e\u0301", "ABC abc"])
    emoji, combining, _ = result["scalars"]
    assert emoji["wire_span"][1] - emoji["wire_span"][0] == 3
    assert combining["wire_span"][1] - combining["wire_span"][0] == 4
    assert len(combining["decoded_text"]) == 2


def test_json_surrogate_pair_strings_and_keys_use_standard_decoder():
    text = '{"\\ud83d\\ude00/a": "\\ud83d\\ude00e\\u0301"}'
    result = assert_complete(text, ["/😀~1a"], ["😀e\u0301"])
    assert result["decode_mode"] == "json_string_tokens"
    scalar = result["scalars"][0]
    assert scalar["decode_mode"] == "json_string_tokens"
    assert text[slice(*scalar["wire_span"])] == '"\\ud83d\\ude00e\\u0301"'
    assert len(scalar["decoded_text"]) == 3


def test_yaml_flow_syntax_is_not_misrepresented_as_strict_json():
    result = assert_complete('{value: "text"}', ["/value"], ["text"])
    assert result["decode_mode"] == "yaml_baseloader"
    assert result["scalars"][0]["decode_mode"] == "yaml_baseloader"


@pytest.mark.parametrize(
    "text, decoded, token",
    [
        ("ordinary text", "ordinary text", "ordinary text"),
        ("  first\n  second  ", "first second", "first\n  second"),
        ("---\ntext\n...\n", "text", "text"),
    ],
)
def test_plain_root_uses_recorded_yaml_decoding(text, decoded, token):
    result = assert_complete(text, [""], [decoded])
    assert result["status"] == "plain_text"
    assert result["scalars"][0]["style"] == "plain"
    assert text[slice(*result["scalars"][0]["wire_span"])] == token


@pytest.mark.parametrize("text", ["", " \n\t", "# comment only\n", "[]", "{}"])
def test_documents_without_value_scalars(text):
    # A tab by itself is not valid YAML indentation, so it is not a fallback.
    if "\t" in text:
        assert decode_span_scalars(text)["complete"] is False
    else:
        assert_complete(text, [], [])


def test_empty_implicit_value_has_valid_empty_token():
    result = assert_complete("value:", ["/value"], [""])
    assert result["scalars"][0]["wire_span"] == [6, 6]


@pytest.mark.parametrize(
    "text",
    [
        "first: valid\na: 1\na: 2",
        '{"a": 1, "\\u0061": 2}',
        '{"😀": 1, "\\ud83d\\ude00": 2}',
        "outer:\n  same: first\n  same: second",
        "? [a, b]\n: value",
        "? {a: b}\n: value",
        "a: &identity value\nb: *identity",
        "a: &unused value",
        "a: *missing",
        "a: !!str value",
        "!custom [value]",
        "a: !<tag:example.org,2026:unsafe> value",
        "%YAML 1.1\n---\na: value",
        "---\none\n---\ntwo",
        "one\n...\ntwo",
        '{"a": "unterminated}',
        "[a, b",
        'value: "\\ud83d\\ude00"',
        '{"value": NaN}',
        '{"value": Infinity}',
        '"\\ud800"',
        "\ud800",
    ],
)
def test_unsupported_input_never_retains_partial_scalars(text):
    result = decode_span_scalars(text)
    assert result["status"] == "unsupported_structure"
    assert result["complete"] is False
    assert result["scalars"] == []
    assert result["reason"]


@pytest.mark.parametrize("value", [None, 1, True, b"text", ["text"], {"a": "text"}])
def test_type_invalid_inputs_are_explicitly_incomplete(value):
    result = decode_span_scalars(value)
    assert result["reason"] == "input_not_string"
    assert result["complete"] is False
    assert result["scalars"] == []


def test_codepoint_budget_before_parser(monkeypatch):
    monkeypatch.setattr(yaml, "scan", lambda *args, **kwargs: pytest.fail("Oversized input reached parser"))
    result = decode_span_scalars("x" * (LIMITS["max_codepoints"] + 1))
    assert result["status"] == "budget_exceeded"
    assert result["reason"] == "max_codepoints"
    assert result["scalars"] == []


def test_depth_budget_is_checked_before_compose(monkeypatch):
    text = "[" * 33 + "value" + "]" * 33
    monkeypatch.setattr(yaml, "compose", lambda *args, **kwargs: pytest.fail("Deep input reached composer"))
    result = decode_span_scalars(text)
    assert result["status"] == "budget_exceeded"
    assert result["reason"] == "max_depth"
    assert result["scalars"] == []


def test_node_budget_is_checked_before_compose(monkeypatch):
    text = "[" + ",".join("[]" for _ in range(4096)) + "]"
    monkeypatch.setattr(yaml, "compose", lambda *args, **kwargs: pytest.fail("Large input reached composer"))
    result = decode_span_scalars(text)
    assert result["status"] == "budget_exceeded"
    assert result["reason"] == "max_nodes"


def test_mapping_keys_count_toward_node_budget():
    text = "\n".join(f"key-{index}: []" for index in range(2048))
    result = decode_span_scalars(text)
    assert result["status"] == "budget_exceeded"
    assert result["reason"] == "max_nodes"


def test_scalar_budget_excludes_keys_but_rejects_partial_results():
    text = "\n".join(f"key-{index}: value" for index in range(512))
    assert len(decode_span_scalars(text)["scalars"]) == 512
    result = decode_span_scalars(text + "\nexcess: another")
    assert result["status"] == "budget_exceeded"
    assert result["reason"] == "max_scalars"
    assert result["complete"] is False
    assert result["scalars"] == []


def test_budget_boundaries_and_empty_containers():
    assert decode_span_scalars("x" * 65536)["complete"] is True
    assert decode_span_scalars("[" * 32 + "value" + "]" * 32)["complete"] is True
    assert decode_span_scalars("[" + ",".join("[]" for _ in range(4095)) + "]")["complete"] is True


def test_shared_nodes_rejected_even_if_scan_did_not_detect_alias(monkeypatch):
    root = yaml.compose("[value]", Loader=yaml.BaseLoader)
    root.value.append(root.value[0])
    monkeypatch.setattr(yaml, "compose", lambda *args, **kwargs: root)
    assert decode_span_scalars("[value]")["reason"] == "shared_node"


@pytest.mark.parametrize("alteration", ["negative", "past_end", "reversed", "tag", "style", "value"])
def test_invalid_composed_scalar_is_rejected(monkeypatch, alteration):
    root = yaml.compose("[value]", Loader=yaml.BaseLoader)
    node = root.value[0]
    assert isinstance(root, SequenceNode) and isinstance(node, ScalarNode)
    if alteration == "negative":
        node.start_mark.index = -1
    elif alteration == "past_end":
        node.end_mark.index = 100
    elif alteration == "reversed":
        node.start_mark.index = node.end_mark.index + 1
    elif alteration == "tag":
        node.tag = "tag:yaml.org,2002:int"
    elif alteration == "style":
        node.style = "unknown"
    else:
        node.value = 13
    monkeypatch.setattr(yaml, "compose", lambda *args, **kwargs: root)
    result = decode_span_scalars("[value]")
    assert result["complete"] is False
    assert result["scalars"] == []


def test_result_limits_are_not_shared_mutable_state():
    result = decode_span_scalars("value")
    result["limits"]["max_codepoints"] = 1
    assert decode_span_scalars("value")["limits"]["max_codepoints"] == 65536
