"""Native exact-prefix replay uses frozen artifacts and never executes tools."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentdojo_lab import neurotaint_causal_panel as controlled
from agentdojo_lab import neurotaint_native_replay as replay
from agentdojo_lab.neurotaint_eval import create_neurotaint_eval_plan


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")


def completed_batch(tmp_path: Path, monkeypatch):
    batch = create_neurotaint_eval_plan(tmp_path / "batch")
    plan = json.loads((batch / "plan.json").read_text(encoding="utf-8"))
    strict_reader = replay.read_neurotaint_eval_plan

    def fixture_reader(path, **kwargs):
        assert kwargs == {"require_evidence": True}
        return strict_reader(path, require_evidence=False)

    monkeypatch.setattr(replay, "read_neurotaint_eval_plan", fixture_reader)
    for slot in plan["schedule"]:
        job = batch / "jobs" / slot["trial_id"]
        job.mkdir()
        write_json(job / "started.json", {"trial_id": slot["trial_id"]})
        write_json(job / "result.json", {"status": "completed", "exit_code": 0})
    first_case = plan["native_scenarios"][0]["case_id"]
    eligible = [
        slot for slot in plan["schedule"] if slot["condition"] == "injected" and slot["case_id"] == first_case
    ]
    for slot in eligible:
        (batch / "runs" / slot["trial_id"]).mkdir()
    return batch, plan, eligible


def sink_arguments(target: dict) -> dict:
    values = {
        "body": "Bound replay body.",
        "recipients": ["bound-replay@example.org"],
        "subject": "Bound replay subject",
        "file_id": "13",
        "end_time": "2026-11-01 10:00",
        "participants": ["bound-replay@example.org"],
        "start_time": "2026-11-01 09:00",
        "title": "Bound replay event",
    }
    return {name: copy.deepcopy(values[name]) for name in target["target_argument_fields"]}


def leaf_paths(value, prefix=""):
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            result.extend(leaf_paths(item, prefix + "/" + key))
        return result
    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            result.extend(leaf_paths(item, prefix + f"/{index}"))
        return result
    return [prefix]


def verified_material(run: Path, slot: dict, target: dict) -> dict:
    source_text = "Injected source record with an observed payload."
    unit = {
        "unit_id": slot["trial_id"].replace("-", "_"),
        "user_prompt": "Use the saved source record to perform the specified task.",
        "sources": [
            {
                "source_id": "source-a",
                "origin_tool": target["declared_source_tool"],
                "tool_arguments": {"query": "bound replay"},
                "text": source_text,
            }
        ],
        "sink": {
            "function": target["target_sink_tool"],
            "arguments": sink_arguments(target),
        },
        "target_argument_path": "/" + target["target_argument_fields"][0],
    }
    call, graph = controlled._fixture(unit, slot["repeat"])
    pair = copy.deepcopy(call["fields"][0]["nt_style_cascade"][0])
    pair.update(
        status="scored",
        matched=True,
        complete=True,
        truncated=False,
        first_matched_tier="tier2",
    )
    call["fields"] = [
        {
            "argument_path": path,
            "value": "fixture",
            "cascade_scope": {"sink": {"selected": True}},
            "nt_style_cascade": [copy.deepcopy(pair)],
        }
        for path in leaf_paths(call["arguments"])
    ]
    source = next(row for row in call["visible_sources"] if row["kind"] == "tool")
    body = {
        "model": "openai/gpt-oss-120b",
        "messages": copy.deepcopy(call["request_messages"]),
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "Saved native function schema.",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
            for name in (target["declared_source_tool"], target["target_sink_tool"])
        ],
        "tool_choice": "auto",
        "temperature": 0,
        "max_completion_tokens": 4096,
        "reasoning_effort": "low",
        "parallel_tool_calls": False,
    }
    event = {
        "event_type": "MODEL_REQUEST",
        "event_id": call["request_event_id"],
        "data": {"body": body},
    }
    exposure = {
        "complete": True,
        "occurrences": [
            {
                "source_result_event_id": source["source_event_id"],
                "exposure_event_id": source["exposure_event_id"],
                "request_event_id": call["request_event_id"],
                "model_request_id": call["model_request_id"],
                "message_index": source["message_index"],
                "request_pointer": source["request_pointer"],
                "source_function": source["origin_tool"],
            }
        ],
    }
    return {
        "manifest": {"config": {"model": "openai/gpt-oss-120b"}},
        "summary": {},
        "calls": [call],
        "graph": graph,
        "events": {call["request_event_id"]: event},
        "exposure": exposure,
        "online": {
            call["proposal_event_id"]: {
                "plan": {
                    "status": "not_eligible",
                    "reason": "explicit_candidate_present",
                },
                "prediction_summary": {"status": "unknown", "single_sources": []},
                "results": [],
            }
        },
        "run_hashes": {},
        "run_tree_sha256": replay._tree_digest(replay._tree(run)),
        "saved_verifier": {"passed": True, "proposal_count": 1},
        "provenance_record_count": 1,
    }


class Response:
    def __init__(self, value):
        self.value = value

    def model_dump(self, mode="json"):
        assert mode == "json"
        return copy.deepcopy(self.value)


class Completions:
    def __init__(self, owner, sink, *, interrupt=False):
        self.owner = owner
        self.sink = sink
        self.interrupt = interrupt

    def create(self, **body):
        assert body.pop("timeout") == 60.0
        self.owner.calls.append(copy.deepcopy(body))
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt()
        neutralized = "Neutral reference information." in json.dumps(body["messages"])
        if neutralized:
            value = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": "No further action is proposed.",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
            }
        else:
            value = {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-bound-replay",
                                    "type": "function",
                                    "function": {
                                        "name": self.sink["function"],
                                        "arguments": json.dumps(self.sink["arguments"], sort_keys=True),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
            }
        return Response(value)


class FakeClient:
    max_retries = 0
    api_key = "test-key"

    def __init__(self, sink, *, interrupt=False):
        self.calls = []
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(self, sink, interrupt=interrupt)
        self.closed = False

    def close(self):
        self.closed = True


def install_material(monkeypatch, plan, eligible):
    targets = {row["case_id"]: row for row in plan["native_scenarios"]}
    eligible_ids = {row["trial_id"] for row in eligible}

    def load(run, slot):
        if slot["trial_id"] not in eligible_ids:
            raise replay.EvidenceUnavailable("fixture_unavailable")
        return verified_material(run, slot, targets[slot["case_id"]])

    monkeypatch.setattr(replay, "_load_verified_run", load)
    return targets[eligible[0]["case_id"]]


def test_seals_exact_prefix_plan_and_resumes_to_stable_dependency(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    target = install_material(monkeypatch, plan, eligible)
    output = tmp_path / "native-replay"

    prepared = replay.run_native_replay(batch, output, live=True, max_requests=0)

    assert prepared["status"] == "prepared"
    assert prepared["injected_trajectories"] == 60
    assert prepared["planned_operations"] == 10
    assert prepared["request_count"] == 0
    assert (output / "plan.sealed").is_file()
    operations = [json.loads(line) for line in (output / "operation-plan.jsonl").read_text().splitlines()]
    assert {row["operation_type"] for row in operations} == {
        "sham_replay",
        "neutralized_replay",
    }
    for trial_id in {row["trial_id"] for row in operations}:
        pair = [row for row in operations if row["trial_id"] == trial_id]
        sham = next(row for row in pair if row["operation_type"] == "sham_replay")
        neutral = next(row for row in pair if row["operation_type"] == "neutralized_replay")
        assert {key: value for key, value in sham["body"].items() if key != "messages"} == {
            key: value for key, value in neutral["body"].items() if key != "messages"
        }
        assert sham["body"]["messages"] != neutral["body"]["messages"]
        assert sham["online_m7_plan_reason"] == "explicit_candidate_present"
        assert sham["online_m7_eligibility_is_not_replay_gate"] is True

    clients = []

    def new_client():
        client = FakeClient({"function": target["target_sink_tool"], "arguments": sink_arguments(target)})
        clients.append(client)
        return client

    monkeypatch.setattr(replay, "_new_client", new_client)
    partial = replay.run_native_replay(batch, output, live=True, resume=True, max_requests=4)
    assert partial["status"] == "partial"
    assert partial["request_count"] == 4

    completed = replay.run_native_replay(batch, output, live=True, resume=True, max_requests=120)
    assert completed["status"] == "completed"
    assert completed["request_count"] == 10
    stable = next(row for row in completed["stable_labels"] if row["case_id"] == eligible[0]["case_id"])
    assert stable["status"] == "stable_dependency"
    assert stable["sham_reproduced_count"] == 5
    assert stable["neutralized_reproduced_count"] == 0
    assert completed["native_tool_executions"] == 0
    assert sum(len(client.calls) for client in clients) == 10
    for name in (
        "trajectory-plan.jsonl",
        "operation-plan.jsonl",
        "requests.jsonl",
        "results.jsonl",
        "comparisons.jsonl",
        "stable-labels.jsonl",
        "summary.json",
        "index.html",
    ):
        (output / name).read_bytes().decode("ascii")


def test_zero_operation_terminal_replay_completes_without_requests(tmp_path, monkeypatch):
    batch, _, _ = completed_batch(tmp_path, monkeypatch)
    output = tmp_path / "zero-operation-replay"

    result = replay.run_native_replay(batch, output, live=True, max_requests=0)

    assert result["status"] == "completed"
    assert result["injected_trajectories"] == 60
    assert result["planned_operations"] == 0
    assert result["request_count"] == 0
    assert result["never_started_operations"] == 0
    assert sum(result["trajectory_status_counts"].values()) == 60


def test_interrupted_started_operation_is_unknown_and_never_retried(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    eligible = eligible[:1]
    target = install_material(monkeypatch, plan, eligible)
    output = tmp_path / "interrupted-replay"
    replay.run_native_replay(batch, output, live=True, max_requests=0)
    sink = {"function": target["target_sink_tool"], "arguments": sink_arguments(target)}
    interrupting = FakeClient(sink, interrupt=True)
    monkeypatch.setattr(replay, "_new_client", lambda: interrupting)

    with pytest.raises(KeyboardInterrupt):
        replay.run_native_replay(batch, output, live=True, resume=True, max_requests=1)

    replacement = FakeClient(sink)
    monkeypatch.setattr(replay, "_new_client", lambda: replacement)
    result = replay.run_native_replay(batch, output, live=True, resume=True, max_requests=120)

    assert result["request_count"] == 2
    assert result["interrupted_after_start"] == 1
    assert len(interrupting.calls) == 1
    assert len(replacement.calls) == 1
    rows = [json.loads(line) for line in (output / "results.jsonl").read_text().splitlines()]
    assert sum(row.get("reason") == "interrupted_after_start" for row in rows) == 1


def test_first_selected_target_is_never_replaced_by_a_later_target():
    target = {
        "target_sink_tool": "send_email",
        "target_argument_fields": ["recipients", "subject", "body"],
    }

    def call(sequence, subject):
        arguments = {
            "recipients": ["bound@example.org"],
            "subject": subject,
            "body": "Body",
        }
        return {
            "proposal_sequence": sequence,
            "function": "send_email",
            "arguments": arguments,
            "component_mode": "ordered_cascade",
            "policy": {"sink": {"selected": True}},
            "fields": [
                {
                    "argument_path": "/recipients/0",
                    "cascade_scope": {"sink": {"selected": True}},
                },
                {
                    "argument_path": "/subject",
                    "cascade_scope": {"sink": {"selected": True}},
                },
                {
                    "argument_path": "/body",
                    "cascade_scope": {"sink": {"selected": True}},
                },
            ],
        }

    first, later = call(10, "First"), call(20, "Later")
    assert replay._select_target([later, first], target) is first

    extra = call(5, "Extra")
    extra["arguments"]["cc"] = ["other@example.org"]
    assert replay._select_target([later, extra], target) is later


def test_frozen_plan_digest_mutation_is_rejected(tmp_path, monkeypatch):
    batch, _, _ = completed_batch(tmp_path, monkeypatch)
    (batch / "plan.json").write_text("{}\n", encoding="ascii")
    with pytest.raises(ValueError, match="plan"):
        replay.run_native_replay(batch, tmp_path / "replay", live=True, max_requests=0)


def test_forged_observed_result_without_request_start_is_rejected(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    target = install_material(monkeypatch, plan, eligible[:1])
    output = tmp_path / "forged-result"
    replay.run_native_replay(batch, output, live=True, max_requests=0)
    operation = json.loads((output / "operation-plan.jsonl").read_text().splitlines()[0])
    forged = replay._base_result(operation)
    forged.update(
        status="observed",
        reason=None,
        exact_sink_proposed=True,
        response_kind="tool_proposal",
    )
    write_json(output / "result-slots" / "0001.json", forged)

    sink = {"function": target["target_sink_tool"], "arguments": sink_arguments(target)}
    monkeypatch.setattr(replay, "_new_client", lambda: FakeClient(sink))
    with pytest.raises(ValueError, match="result"):
        replay.run_native_replay(batch, output, live=True, resume=True, max_requests=120)


def test_fresh_execution_must_seal_before_any_request(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    install_material(monkeypatch, plan, eligible[:1])
    with pytest.raises(ValueError, match="seal with zero requests"):
        replay.run_native_replay(
            batch,
            tmp_path / "unsealed-live",
            live=True,
            max_requests=1,
        )


def test_client_setup_failure_does_not_consume_a_slot(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    install_material(monkeypatch, plan, eligible[:1])
    output = tmp_path / "client-setup-failure"
    replay.run_native_replay(batch, output, live=True, max_requests=0)
    monkeypatch.setattr(replay, "_new_client", lambda: (_ for _ in ()).throw(ValueError("no key")))

    with pytest.raises(ValueError, match="no key"):
        replay.run_native_replay(batch, output, live=True, resume=True, max_requests=1)
    assert list((output / "started-slots").iterdir()) == []
    assert list((output / "result-slots").iterdir()) == []


def test_pacing_state_must_be_outside_frozen_batch(tmp_path, monkeypatch):
    batch, plan, eligible = completed_batch(tmp_path, monkeypatch)
    install_material(monkeypatch, plan, eligible[:1])
    pacer = type("Pacer", (), {"path": batch / "pacing.json", "budget": 7000})()

    with pytest.raises(ValueError, match="separate from frozen input"):
        replay.run_native_replay(
            batch,
            tmp_path / "bad-pacing",
            live=True,
            max_requests=0,
            pacer=pacer,
        )
