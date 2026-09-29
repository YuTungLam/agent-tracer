"""Frozen content-composition argument intervention contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
from collections import Counter
from pathlib import Path

import pytest
from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_lab.scout_content_composition_argument import (
    COMBINATION_REQUIREMENT,
    EXPECTED_SINK,
    ITEM_13_STATUS,
    TOTAL_REQUESTS,
    TerminationRequested,
    run_content_composition_argument,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/scout_content_composition_argument_v1.json"


class Response:
    def __init__(self, value):
        self.value = value

    def model_dump(self, mode="json"):
        assert mode == "json"
        return copy.deepcopy(self.value)


class Completions:
    def __init__(
        self,
        owner,
        role,
        *,
        invalid_judgment=False,
        sham_fails=False,
        change_filename_after_intervention=False,
    ):
        self.owner = owner
        self.role = role
        self.invalid_judgment = invalid_judgment
        self.sham_fails = sham_fails
        self.change_filename_after_intervention = change_filename_after_intervention

    def create(self, **body):
        assert body.pop("timeout") == 180.0
        self.owner.calls.append(copy.deepcopy(body))
        if self.role == "judge":
            payload = json.loads(body["messages"][1]["content"])
            if self.invalid_judgment:
                self.invalid_judgment = False
                content = "not judgment JSON"
            else:
                content = json.dumps(
                    {
                        "would_preserve_content": payload["intervention_arm"] in {"a", "b"},
                        "confidence": 0.8,
                        "reasoning": "The frozen carrier removal determines this prediction.",
                    }
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
        contents = [message.get("content") for message in body["messages"] if message.get("role") == "tool"]
        neutral_count = sum(
            isinstance(value, str) and ("NEUTRAL-SRC-A---" in value or "NEUTR-B-" in value)
            for value in contents
        )
        propose = neutral_count < 2 and not (self.sham_fails and neutral_count == 0)
        arguments = copy.deepcopy(EXPECTED_SINK["arguments"])
        if self.change_filename_after_intervention and neutral_count:
            arguments["filename"] = "changed-filename.txt"
        message = (
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-fixture",
                        "type": "function",
                        "function": {
                            "name": "create_file",
                            "arguments": json.dumps(arguments),
                        },
                    }
                ],
            }
            if propose
            else {"role": "assistant", "content": "No exact create-file proposal."}
        )
        return Response(
            {
                "model": "llama-4-scout-local",
                "choices": [
                    {
                        "finish_reason": "tool_calls" if propose else "stop",
                        "message": message,
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )


class Client:
    max_retries = 0
    api_key = "fixture-key"

    def __init__(self, role, **kwargs):
        self.calls = []
        self.closed = False
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(self, role, **kwargs)

    def close(self):
        self.closed = True


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_plan_only_is_request_free_and_freezes_complete_argument_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args, **kwargs: pytest.fail("Plan construction must not use a socket"),
    )
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("The protocol never executes returned tools"),
    )
    output = tmp_path / "plan-only"

    summary = run_content_composition_argument(output, config_path=CONFIG)

    assert summary["status"] == "plan_only_complete"
    assert summary["request_count"] == summary["native_tool_executions"] == 0
    assert summary["all_slots_terminal"] is False
    assert summary["scientific_complete"] is False
    assert summary["unknown_operation_slots"] == TOTAL_REQUESTS == 42
    assert summary["analysis"]["item_13_status"] == ITEM_13_STATUS
    assert summary["analysis"]["combination_requirement"] == COMBINATION_REQUIREMENT
    assert summary["analysis"]["standalone_item_13_claim_permitted"] is False
    operations = rows(output / "operation-plan.jsonl")
    assert len(operations) == 42
    assert Counter((row["operation_type"], row["arm"]) for row in operations) == {
        ("sham_replay", "sham"): 6,
        ("neutralized_replay", "a"): 6,
        ("neutralized_replay", "b"): 6,
        ("neutralized_replay", "both"): 6,
        ("isolated_judge", "a"): 6,
        ("isolated_judge", "b"): 6,
        ("isolated_judge", "both"): 6,
    }
    assert [row["global_sequence"] for row in operations] == list(range(1, 43))
    assert all(row["body"]["model"] == "llama-4-scout-local" for row in operations)
    assert all(row["body"]["temperature"] == 0.0 for row in operations)
    judges = [row for row in operations if row["operation_type"] == "isolated_judge"]
    assert len(judges) == 18
    assert all(
        not {"tools", "tool_choice", "functions", "function_call"}.intersection(row["body"]) for row in judges
    )
    plan = json.loads((output / "plan.json").read_text())
    assert plan["standalone_item_13_claim_permitted"] is False
    assert [len(candidate["source_files"]) for candidate in plan["candidates"]] == [21, 21]
    assert all(
        source["source_hashes"] == candidate["source_files"]
        for source, candidate in zip(plan["source_inputs"], plan["candidates"], strict=True)
    )
    for candidate_id, probes in plan["probes"].items():
        assert set(probes) == {"a", "b", "both"}
        assert len(probes["a"]["replacements"]) == 1
        assert len(probes["b"]["replacements"]) == 1
        assert len(probes["both"]["replacements"]) == 2
        for probe in probes.values():
            assert probe["target_argument_path"] == "/content"
            assert probe["non_target_argument_paths"] == ["/filename"]
            assert all(
                replacement["all_fragment_occurrences_replaced_in_every_frozen_carrier"] is True
                and replacement["surrounding_carrier_text_preserved"] is True
                and replacement["replacement_length_preserved"] is True
                and replacement["carrier_occurrence_count"] == 1
                and replacement["fragment_occurrence_count"] == 1
                for replacement in probe["replacements"]
            )
            for replacement in probe["replacements"]:
                pointer = replacement["request_pointers"][0]
                index = int(pointer.split("/")[4])
                before = probe["context_a"][index]["content"]
                after = probe["context_b"][index]["content"]
                assert after == before.replace(replacement["fragment"], replacement["fragment_replacement"])
                assert "Expense count:" in after
                assert before.split("filename:", 1)[1] == after.split("filename:", 1)[1]
        assert candidate_id in {"r01-both", "r02-both"}
    assert (output / "requests.jsonl").read_bytes() == b""
    assert all(row["reason"] == "live_not_enabled" for row in rows(output / "results.jsonl"))
    assert json.loads((output / "plan.sealed").read_text())["sealed_before_transport"] is True


def test_mocked_replays_and_judges_compare_all_18_pairs_without_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("A returned proposal must never execute"),
    )
    replay, judge = Client("replay"), Client("judge")
    output = tmp_path / "complete"

    summary = run_content_composition_argument(
        output, config_path=CONFIG, replay_client=replay, judge_client=judge
    )

    assert summary["status"] == "completed"
    assert summary["request_count"] == 42
    assert summary["unknown_operation_slots"] == 0
    assert summary["all_slots_terminal"] is True
    assert summary["scientific_complete"] is False
    assert summary["analysis"]["diagnostic_checks"]["transport_direct_literal_loopback"] is False
    assert summary["native_tool_executions"] == 0
    assert len(replay.calls) == 24 and len(judge.calls) == 18
    assert all("tools" in body for body in replay.calls)
    assert all("tools" not in body for body in judge.calls)
    comparisons = rows(output / "comparisons.jsonl")
    assert len(comparisons) == 18
    assert all(row["sham_reproduced_exact_call"] is True for row in comparisons)
    assert all(row["status"] == "compared" and row["agreement"] is True for row in comparisons)
    assert all(row["observed_content_would_persist"] is (row["arm"] in {"a", "b"}) for row in comparisons)
    assert summary["analysis"]["pooled_paired_comparisons"] == 18
    assert summary["analysis"]["item_13_status"] == ITEM_13_STATUS
    assert summary["analysis"]["standalone_item_13_claim_permitted"] is False


def test_filename_change_does_not_create_false_content_effect(tmp_path):
    replay = Client("replay", change_filename_after_intervention=True)
    judge = Client("judge")
    output = tmp_path / "filename-change"

    summary = run_content_composition_argument(
        output, config_path=CONFIG, replay_client=replay, judge_client=judge
    )

    assert summary["status"] == "completed"
    comparisons = rows(output / "comparisons.jsonl")
    single_source = [row for row in comparisons if row["arm"] in {"a", "b"}]
    assert all(row["observed_content_would_persist"] is True for row in single_source)
    assert all(row["observed_content_effect"] is False for row in single_source)
    assert all(row["intervention_filename_argument_proposed"] is False for row in single_source)
    assert all(row["intervention_exact_call_proposed"] is False for row in single_source)
    assert all(row["agreement"] is True for row in single_source)
    replay_results = [
        row
        for row in rows(output / "results.jsonl")
        if row["operation_type"] == "neutralized_replay" and row["arm"] in {"a", "b"}
    ]
    assert all(row["content_argument_proposed"] is True for row in replay_results)
    assert all(row["filename_argument_proposed"] is False for row in replay_results)
    assert all(row["exact_sink_proposed"] is False for row in replay_results)


def test_invalid_judgment_is_preserved_as_one_unknown_without_replacement(tmp_path):
    replay, judge = Client("replay"), Client("judge", invalid_judgment=True)
    output = tmp_path / "invalid"

    summary = run_content_composition_argument(
        output, config_path=CONFIG, replay_client=replay, judge_client=judge
    )

    assert summary["status"] == "completed_with_unknowns"
    assert summary["request_count"] == 42
    assert summary["unknown_operation_slots"] == 1
    assert summary["all_slots_terminal"] is True
    assert summary["scientific_complete"] is False
    assert len(judge.calls) == 18
    comparisons = rows(output / "comparisons.jsonl")
    assert sum(row["status"] == "unknown" for row in comparisons) == 1
    assert (
        next(row for row in comparisons if row["status"] == "unknown")[
            "judge_predicted_content_would_persist"
        ]
        is None
    )


def test_failed_sham_blocks_all_directional_comparisons_but_keeps_raw_results(tmp_path):
    replay, judge = Client("replay", sham_fails=True), Client("judge")
    output = tmp_path / "sham-failed"

    summary = run_content_composition_argument(
        output, config_path=CONFIG, replay_client=replay, judge_client=judge
    )

    comparisons = rows(output / "comparisons.jsonl")
    assert len(comparisons) == 18
    assert all(row["sham_reproduced_exact_call"] is False for row in comparisons)
    assert all(row["observed_content_would_persist"] is None for row in comparisons)
    assert all(row["status"] == "unknown" for row in comparisons)
    assert all("sham_did_not_reproduce_exact_archived_call" in row["unknown_reasons"] for row in comparisons)
    assert summary["unknown_paired_comparisons"] == 18


def test_started_termination_finalizes_every_slot_without_retry(tmp_path):
    replay, judge = Client("replay"), Client("judge")

    def terminate(**_body):
        raise TerminationRequested("fixture TERM")

    replay.chat.completions.create = terminate
    output = tmp_path / "terminated"

    summary = run_content_composition_argument(
        output, config_path=CONFIG, replay_client=replay, judge_client=judge
    )

    results = rows(output / "results.jsonl")
    assert summary["termination_requested"] is True
    assert summary["request_count"] == 1
    assert len(results) == 42
    assert results[0]["status"] == "unknown"
    assert results[0]["reason"] == "request_interrupted_after_start"
    assert all(row["reason"] == "execution_interrupted" for row in results[1:])
    assert summary["silent_retries_or_replacements"] == 0


def test_tier_binding_or_archive_hash_change_fails_before_output(tmp_path):
    config = json.loads(CONFIG.read_text())
    config["candidates"][0]["sources"][0]["lcs_length"] = 18
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(config))

    with pytest.raises(ValueError, match="Tier-2"):
        run_content_composition_argument(tmp_path / "out", config_path=changed)
    assert not (tmp_path / "out").exists()


def test_runtime_source_and_config_hashes_are_frozen(tmp_path):
    output = tmp_path / "plan"
    run_content_composition_argument(output, config_path=CONFIG)
    hashes = json.loads((output / "plan.json").read_text())["implementation_hashes"]
    expected = {
        "src/agentdojo_lab/scout_content_composition_argument.py",
        "src/agentdojo_lab/counterfactual.py",
        "src/agentdojo_lab/causal_replay.py",
        "scripts/run_scout_content_composition_argument.py",
        "protocol_config",
    }
    assert expected <= set(hashes)
    for relative in expected - {"protocol_config"}:
        assert hashes[relative] == hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    assert hashes["protocol_config"] == hashlib.sha256(CONFIG.read_bytes()).hexdigest()
