"""Four-candidate selection, repeat, transport, and unknown-preservation contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest
from agentdojo.functions_runtime import FunctionsRuntime

import agentdojo_lab.scout_multi_repeat_judge as repeat_module
from agentdojo_lab.scout_multi_repeat_judge import (
    TOTAL_REQUESTS,
    TerminationRequested,
    run_multi_repeat,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/scout_multi_repeat_judge_v1.json"


class Response:
    def __init__(self, value):
        self.value = value

    def model_dump(self, mode="json"):
        assert mode == "json"
        return copy.deepcopy(self.value)


class Completions:
    def __init__(self, owner, role, replies=None):
        self.owner = owner
        self.role = role
        self.replies = iter(replies or [])

    def create(self, **body):
        assert body.pop("timeout") == 180.0
        self.owner.calls.append(copy.deepcopy(body))
        if self.role == "judge":
            value = next(self.replies, False)
            content = (
                json.dumps(
                    {
                        "would_call_anyway": value,
                        "confidence": 0.8,
                        "reasoning": "The frozen neutralization removes the trigger.",
                    }
                )
                if type(value) is bool
                else "not valid judgment JSON"
            )
            return Response(
                {
                    "model": "llama-4-scout-local",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": content},
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                }
            )
        neutralized = "Neutral reference information." in json.dumps(body["messages"])
        message = (
            {"role": "assistant", "content": "No sink call after neutralization."}
            if neutralized
            else {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-fixture",
                        "type": "function",
                        "function": {"name": "get_unread_emails", "arguments": "{}"},
                    }
                ],
            }
        )
        return Response(
            {
                "model": "llama-4-scout-local",
                "choices": [
                    {
                        "finish_reason": "stop" if neutralized else "tool_calls",
                        "message": message,
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )


class Client:
    max_retries = 0
    api_key = "fixture-key"

    def __init__(self, role, replies=None):
        self.calls = []
        self.closed = False
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(self, role, replies)

    def close(self):
        self.closed = True


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_plan_only_freezes_identical_requests_and_preserves_unknowns(tmp_path, monkeypatch):
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args, **kwargs: pytest.fail("Plan-only must not use a socket"),
    )
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("The follow-up must not execute tools"),
    )
    output = tmp_path / "plan-only"

    summary = run_multi_repeat(output, config_path=CONFIG)

    assert summary["status"] == "plan_only_complete"
    assert summary["request_count"] == summary["native_tool_executions"] == 0
    assert summary["unknown_operation_slots"] == TOTAL_REQUESTS == 36
    assert summary["identical_request_bodies_verified"] is True
    assert summary["analysis"]["pooled_paired_comparisons"] == 0
    assert summary["analysis"]["research_gap_status"] == (
        "not_established_construction_scoped_second_task_family_needed"
    )
    operations = rows(output / "operation-plan.jsonl")
    assert len(operations) == 36
    assert all(row["body"]["model"] == "llama-4-scout-local" for row in operations)
    assert all(row["body"]["temperature"] == 0.0 for row in operations)
    assert all(row["body"]["max_completion_tokens"] == 2048 for row in operations)
    assert all("reasoning_effort" not in row["body"] for row in operations)
    for operation_type in ("sham_replay", "neutralized_replay", "isolated_judge"):
        selected = [row for row in operations if row["operation_type"] == operation_type]
        assert len(selected) == 12
        for candidate_id in {row["candidate_id"] for row in selected}:
            candidate_rows = [row for row in selected if row["candidate_id"] == candidate_id]
            assert len(candidate_rows) == 3
            assert len({row["request_body_sha256"] for row in candidate_rows}) == 1
            assert len({json.dumps(row["body"], sort_keys=True) for row in candidate_rows}) == 1
    judges = [row for row in operations if row["operation_type"] == "isolated_judge"]
    assert all(
        not {"tools", "tool_choice", "functions", "function_call"}.intersection(row["body"])
        for row in judges
    )
    assert (output / "requests.jsonl").read_bytes() == b""
    assert all(row["reason"] == "live_not_enabled" for row in rows(output / "results.jsonl"))
    assert json.loads((output / "plan.sealed").read_text())["sealed_before_transport"] is True
    runtime_hashes = json.loads((output / "plan.json").read_text())["implementation_hashes"]
    expected_runtime_paths = {
        "src/agentdojo_lab/__init__.py",
        "src/agentdojo_lab/profiles.py",
        "src/agentdojo_lab/inspection.py",
        "src/agentdojo_lab/html_report.py",
        "scripts/run_scout_multi_repeat_judge.py",
        "protocol_config",
    }
    assert expected_runtime_paths <= set(runtime_hashes)
    for relative in expected_runtime_paths - {"protocol_config"}:
        assert runtime_hashes[relative] == hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    assert runtime_hashes["protocol_config"] == hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    assert (output / "index.html").is_file()


def test_mocked_repetitions_compare_judge_with_observed_replay_without_tools(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("A returned proposal must never execute"),
    )
    replay = Client("replay")
    judge = Client("judge", replies=[False] * 12)
    output = tmp_path / "complete"

    summary = run_multi_repeat(
        output,
        config_path=CONFIG,
        replay_client=replay,
        judge_client=judge,
    )

    assert summary["status"] == "completed"
    assert summary["request_count"] == 36
    assert summary["unknown_operation_slots"] == 0
    assert summary["native_tool_executions"] == 0
    assert len(replay.calls) == 24 and len(judge.calls) == 12
    assert all("tools" in body for body in replay.calls)
    assert all("tools" not in body for body in judge.calls)
    assert len({json.dumps(body, sort_keys=True) for body in judge.calls}) == 4
    comparisons = rows(output / "comparisons.jsonl")
    assert [row["sham_reproduced_sink"] for row in comparisons] == [True] * 12
    assert [row["observed_replay_would_call_anyway"] for row in comparisons] == [False] * 12
    assert [row["judge_predicted_would_call_anyway"] for row in comparisons] == [False] * 12
    assert [row["agreement"] for row in comparisons] == [True] * 12
    assert all(
        item["judge_variability"]["status"] == "unanimous"
        and item["replay_variability"]["status"] == "unanimous"
        for item in summary["analysis"]["per_candidate"]
    )


def test_invalid_judgment_remains_unknown_and_is_not_replaced(tmp_path):
    replay = Client("replay")
    judge = Client("judge", replies=[False, "invalid", True])
    output = tmp_path / "unknown"

    summary = run_multi_repeat(
        output,
        config_path=CONFIG,
        replay_client=replay,
        judge_client=judge,
    )

    assert summary["status"] == "completed_with_unknowns"
    assert summary["request_count"] == 36
    assert summary["unknown_operation_slots"] == 1
    assert len(judge.calls) == 12
    comparisons = rows(output / "comparisons.jsonl")
    assert [row["status"] for row in comparisons].count("unknown") == 1
    invalid = next(row for row in comparisons if row["status"] == "unknown")
    assert invalid["judge_predicted_would_call_anyway"] is None
    assert any(
        item["judge_variability"]["status"] == "unknowns_present"
        for item in summary["analysis"]["per_candidate"]
    )
    assert summary["analysis"]["research_gap_status"] == (
        "not_established_construction_scoped_second_task_family_needed"
    )


def test_started_termination_gets_incremental_terminal_result_and_no_replacement(tmp_path):
    replay = Client("replay")
    judge = Client("judge", replies=[False] * 12)

    def terminate(**_body):
        raise TerminationRequested("fixture TERM")

    replay.chat.completions.create = terminate
    output = tmp_path / "terminated"

    summary = run_multi_repeat(
        output,
        config_path=CONFIG,
        replay_client=replay,
        judge_client=judge,
    )

    results = rows(output / "results.jsonl")
    assert len(results) == 36
    assert results[0]["request_attempted"] is True
    assert results[0]["status"] == "unknown"
    assert results[0]["reason"] == "request_interrupted_after_start"
    assert all(row["reason"] == "execution_interrupted" for row in results[1:])
    assert summary["termination_requested"] is True
    assert summary["request_count"] == 1
    assert summary["silent_retries_or_replacements"] == 0


def test_tampered_plan_seal_blocks_later_transport(tmp_path):
    replay = Client("replay")
    judge = Client("judge", replies=[False] * 12)
    output = tmp_path / "tampered-seal"
    original = replay.chat.completions.create

    def tamper(**body):
        response = original(**body)
        (output / "plan.sealed").write_text("{}\n")
        return response

    replay.chat.completions.create = tamper

    summary = run_multi_repeat(
        output,
        config_path=CONFIG,
        replay_client=replay,
        judge_client=judge,
    )

    results = rows(output / "results.jsonl")
    assert summary["request_count"] == 1
    assert summary["input_plan_and_implementation_unchanged"] is False
    assert all(
        row["reason"] == "input_plan_or_implementation_changed" for row in results[1:]
    )


def test_selection_is_complete_and_outcome_independent():
    config = json.loads(CONFIG.read_text())
    assert len(config["sources"]) == 4
    assert {row["run_id"] for row in config["sources"]} == {
        "conditional_action-r01-both",
        "conditional_action-r02-both",
    }
    assert all("outcome" not in key and "judgment" not in key for key in config["sources"][0])
    assert "without reference to archived or prospective" in config["selection_rule"]
    assert set(config["support"]) == {
        "conditional_action-r01-both",
        "conditional_action-r02-both",
    }
    assert all(set(value) == {"judge", "replay"} for value in config["support"].values())


@pytest.mark.parametrize("mutation", ["duplicate_candidate", "outcome_field", "support_hash"])
def test_candidate_or_support_mutations_fail_closed(tmp_path, mutation):
    config = json.loads(CONFIG.read_text())
    if mutation == "duplicate_candidate":
        config["sources"][3] = copy.deepcopy(config["sources"][2])
    elif mutation == "outcome_field":
        config["sources"][0]["archived_judgment"] = True
    else:
        config["support"]["conditional_action-r01-both"]["judge"]["sha256"] = "0" * 64
    path = tmp_path / "mutated.json"
    path.write_text(json.dumps(config))

    with pytest.raises(ValueError):
        run_multi_repeat(tmp_path / "output", config_path=path)


def test_live_clients_disable_environment_proxies_and_redirects(tmp_path, monkeypatch):
    transports = []
    clients = [Client("replay"), Client("judge", replies=[True] * 12)]
    openai_calls = []

    class Transport:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            transports.append(self)

        def close(self):
            self.closed = True

    def openai_client(**kwargs):
        openai_calls.append(kwargs)
        return clients[len(openai_calls) - 1]

    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-fixture-key")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:9999")
    monkeypatch.setattr(repeat_module.httpx, "Client", Transport)
    monkeypatch.setattr(repeat_module.openai, "OpenAI", openai_client)

    output = tmp_path / "live-policy"
    summary = run_multi_repeat(output, config_path=CONFIG, live=True)

    assert summary["status"] == "completed"
    assert len(transports) == len(openai_calls) == 2
    assert all(
        transport.kwargs
        == {"trust_env": False, "follow_redirects": False, "timeout": 180.0}
        for transport in transports
    )
    assert all(call["http_client"] is transport for call, transport in zip(openai_calls, transports))
    assert all(call["base_url"] == "http://127.0.0.1:8000/v1" for call in openai_calls)
    assert all(call["max_retries"] == 0 for call in openai_calls)
    assert all(client.closed for client in clients)
    assert all(transport.closed for transport in transports)
    plan = json.loads((output / "plan.json").read_text())
    assert plan["transport"]["trust_env"] is False
    assert plan["transport"]["follow_redirects"] is False
    assert summary["analysis"]["systematic_pattern_status"] == (
        "systematic_opposite_judge_replay_direction_observed"
    )
    assert summary["analysis"]["standalone_gap_claim_permitted"] is False
