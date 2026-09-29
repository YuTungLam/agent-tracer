"""Bounded typography compatibility; no model calls or language accuracy claims."""

import copy
import hashlib
import json
import socket
from pathlib import Path

import httpx
import pytest
import test_causal_v2_audit as transport_fixtures
from test_causal_v2 import fixture, native_recorded_run
from test_causal_v2_audit import client_with, completion, read_results

from agentdojo_lab import causal_v2, counterfactual
from agentdojo_lab import causal_v2_audit as audit
from agentdojo_lab import judgment_formats as formats

FORMAT = formats.ENGLISH_PUNCTUATION_FORMAT
REASONING = "The agent’s choice—given both sources—is unchanged…\u00a0This is a prediction."


@pytest.fixture
def exported(tmp_path, monkeypatch):
    return transport_fixtures.exported.__wrapped__(tmp_path, monkeypatch)


def raw(reasoning=REASONING, **changes):
    return json.dumps(
        {"would_call_anyway": False, "confidence": 0.25, "reasoning": reasoning, **changes},
        ensure_ascii=False,
    )


def parse(value):
    return formats.parse_judgment(value, judgment_format=FORMAT)


@pytest.mark.parametrize("character", sorted(formats.TYPOGRAPHY))
def test_every_frozen_typography_character_is_preserved_and_old_parser_rejects(character):
    value = raw(f"English{character}reasoning.")
    assert parse(value) == {"status": "valid", "judgment": json.loads(value)}
    assert formats.parse_judgment(value) == counterfactual.parse_judgment(value)
    assert counterfactual.parse_judgment(value)["status"] == "invalid"


@pytest.mark.parametrize("codepoint", [0, 8, 11, 12, 27, 31, 127, 0x85, 0x200B, 0x200E, 0x202E,
                                     0x2066, 0xFEFF, 0x4E2D, 0x3002, 0x0410, 0x0627, 0x00E9, 0x1F600])
def test_controls_hidden_marks_other_scripts_and_unlisted_characters_fail_closed(codepoint):
    text = f"English{chr(codepoint)}reasoning."
    assert parse(raw(text))["status"] == "invalid"
    assert formats.contains_unsupported_characters(raw(text))
    assert formats.contains_unsupported_characters(json.dumps(json.loads(raw(text)), ensure_ascii=True))


@pytest.mark.parametrize("reasoning", ["", "\u00a0\u2009", "123—456", None, 5, [], {}])
def test_reasoning_requires_a_nonempty_string_and_ascii_letters(reasoning):
    assert parse(raw(reasoning))["status"] == "invalid"


def test_line_breaks_and_tabs_remain_valid_without_normalization():
    value = raw("An English line.\nAnother\tline.\rFinal line.")
    assert parse(value)["judgment"] == json.loads(value)


@pytest.mark.parametrize("change", [
    {"would_call_anyway": "false"}, {"would_call_anyway": 0}, {"would_call_anyway": None},
    {"confidence": True}, {"confidence": "0.5"}, {"confidence": -0.1}, {"confidence": 1.1},
    {"confidence": float("nan")}, {"confidence": float("inf")}, {"extra": 1},
])
def test_strict_schema_boolean_and_confidence_rules_remain(change):
    assert parse(raw(**change))["status"] == "invalid"


@pytest.mark.parametrize("value", [
    '{"would_call_anyway":false,"would_call_anyway":true,"confidence":0.5,"reasoning":"English."}',
    '{"would_call_anyway":false,"confidence":0.5}', '[]', 'null', '"English"',
    '```json\n{"would_call_anyway":false,"confidence":0.5,"reasoning":"English."}\n```',
])
def test_duplicate_missing_keys_and_non_json_wrappers_remain_invalid(value):
    assert parse(value)["status"] == "invalid"


@pytest.mark.parametrize("value", [None, {}, "x" * (counterfactual.LIMITS["judgment_codepoints"] + 1)])
def test_input_budget_and_type_are_retained(value):
    assert parse(value) == {"status": "invalid", "reason": "judgment_input_budget_or_type"}


def test_new_format_cannot_promote_or_mix_legacy_judgments():
    call, graph = fixture(second=True)
    plan = causal_v2.plan_joint_probes(call, graph)
    values = [True, True, False]
    current = [causal_v2.bind_judgment(p, raw(would_call_anyway=v), judgment_format=FORMAT)
               for p, v in zip(plan["probes"], values, strict=True)]
    summary = causal_v2.summarize_joint_results(plan, current, judgment_format=FORMAT)
    assert summary["complete"] is True
    assert summary["pairs"][0]["pattern"] == "predicted_redundant_OR_like"
    assert not causal_v2.summarize_joint_results(plan, current)["complete"]
    legacy = [causal_v2.bind_judgment(p, raw("ASCII English.", would_call_anyway=v))
              for p, v in zip(plan["probes"], values, strict=True)]
    assert causal_v2.summarize_joint_results(plan, legacy)["complete"] is True
    assert not causal_v2.summarize_joint_results(plan, legacy, judgment_format=FORMAT)["complete"]
    old_invalid = [causal_v2.bind_judgment(p, raw()) for p in plan["probes"]]
    assert all(row["status"] == "invalid" for row in old_invalid)
    assert not causal_v2.summarize_joint_results(plan, old_invalid, judgment_format=FORMAT)["complete"]
    changed = copy.deepcopy(current)
    changed[0]["binding_sha256"] = "0" * 64
    assert not causal_v2.summarize_joint_results(plan, changed, judgment_format=FORMAT)["complete"]


def test_old_default_request_and_judgment_shape_are_preserved():
    call, graph = fixture()
    probe = causal_v2.plan_joint_probes(call, graph)["probes"][0]
    body = audit.request_body(probe)
    assert body["messages"][0]["content"] == audit.SYSTEM_PROMPT
    assert "judgment_format" not in json.loads(body["messages"][1]["content"])
    bound = causal_v2.bind_judgment(probe, raw("ASCII English."))
    assert set(bound) == {"protocol", "probe_id", "binding_sha256", "status", "judgment"}
    assert audit._response_result(probe, completion(raw=raw()))["status"] == "invalid"
    assert audit._response_result(probe, completion(raw=raw()), judgment_format=FORMAT)["status"] == "valid"


def test_opt_in_transport_records_protocol_policy_exact_text_and_complete_pattern(exported):
    plans, source, output = exported
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=completion(raw=raw(would_call_anyway=len(calls) < 3)))

    with client_with(respond) as client:
        summary = audit.run_audit(plans, output, client=client, judgment_format=FORMAT)
    assert summary["protocol"] == audit.PUNCTUATION_PROTOCOL
    assert summary["schema_version"] == 3 and summary["judgment_format"] == FORMAT
    assert summary["valid_judgments"] == summary["request_count"] == 3
    assert summary["proposal_summaries"][0]["prediction_summary"]["complete"] is True
    assert summary["independent_causal_accuracy"] is None
    assert summary["source_files_unchanged"] is True
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["judgment_character_policy"] == formats.metadata()
    assert manifest["implementation_hashes"]["judgment_formats.py"] == hashlib.sha256(
        Path(formats.__file__).read_bytes()
    ).hexdigest()
    for request, row in zip(calls, read_results(output), strict=True):
        body = json.loads(request.content)
        assert body["messages"][0]["content"] == audit.PUNCTUATION_SYSTEM_PROMPT
        assert json.loads(body["messages"][1]["content"])["judgment_format"] == FORMAT
        assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(body)
        assert request.extensions["timeout"]["read"] == 60
        assert row["judgment_format"] == FORMAT and row["judgment"]["reasoning"] == REASONING
    assert "Joint counterfactual auditor v3" in (output / "index.html").read_text()


@pytest.mark.parametrize("reasoning", ["English with Cyrillic А.", "English with bidi \u202e.", "English with Han 中."])
def test_unsupported_response_text_is_quarantined_and_not_emitted_into_jsonl(exported, reasoning):
    plans, _, output = exported
    with client_with(lambda request: httpx.Response(200, json=completion(raw=raw(reasoning)))) as client:
        summary = audit.run_audit(plans, output, client=client, judgment_format=FORMAT, max_requests=1)
    assert summary["valid_judgments"] == 0 and summary["unknown_judgments"] == 3
    rows = read_results(output)
    assert rows[0]["status"] == "invalid" and rows[1]["status"] == "not_run"
    assert "response" not in rows[0]
    saved = (output / rows[0]["response_file"]).read_bytes()
    assert hashlib.sha256(saved).hexdigest() == rows[0]["response_sha256"]
    assert json.loads(json.loads(saved)["choices"][0]["message"]["content"])["reasoning"] == reasoning


def test_unknown_format_fails_before_output_or_client(exported):
    plans, _, output = exported
    with client_with(lambda request: pytest.fail("Unknown format must not make a request")) as client:
        with pytest.raises(ValueError, match="Unknown judgment format"):
            audit.run_audit(plans, output, client=client, judgment_format="auto")
    assert not output.exists()


def test_new_format_preserves_native_no_argument_prefix_bindings_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Network forbidden"))
    source = tmp_path / "native"
    before = native_recorded_run(source, no_arguments=True)
    plans, output = tmp_path / "plans", tmp_path / "audit"
    causal_v2.export_run(source, plans)
    with client_with(lambda request: httpx.Response(200, json=completion(raw=raw()))) as client:
        summary = audit.run_audit(plans, output, client=client, judgment_format=FORMAT)
    assert summary["request_count"] == summary["valid_judgments"] == 1
    assert summary["source_hashes_before"] == summary["source_hashes_after"] == before
    request = json.loads((output / "requests.jsonl").read_text())
    body = json.loads(request["body"]["messages"][1]["content"])
    assert body["sink"]["function"] == "get_unread_emails" and body["sink"]["arguments"] == {}
