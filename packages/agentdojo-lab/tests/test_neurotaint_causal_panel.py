"""Offline and mock-transport checks for the prospective controlled causal panel."""

import hashlib
import json
import socket
from collections import Counter, deque
from pathlib import Path

import httpx
import openai
import pytest
from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_lab import causal_v2_audit
from agentdojo_lab.neurotaint_causal_panel import (
    CATEGORIES,
    PROTOCOL,
    _canonical,
    _stable_metrics,
    compile_causal_panel,
    load_causal_panel_config,
    run_causal_panel,
)

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "configs" / "neurotaint_causal_panel_v1.json"


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def client_with(handler):
    return openai.OpenAI(
        api_key="fixture-private-key",
        base_url="https://controlled-causal.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def completion(operation: dict, *, malformed: bool = False) -> dict:
    if operation["operation_type"] == "isolated_judge":
        content = (
            '{"would_call_anyway":true,"would_call_anyway":false,'
            '"confidence":0.9,"reasoning":"Duplicate."}'
            if malformed
            else json.dumps(
                {
                    "would_call_anyway": operation[
                        "construction_reference_would_call_anyway"
                    ],
                    "confidence": 0.9,
                    "reasoning": "Controlled mock prediction from the frozen category.",
                },
                separators=(",", ":"),
            )
        )
        message = {"role": "assistant", "content": content}
        finish = "stop"
    else:
        propose = operation["operation_type"] == "sham_replay" or operation[
            "construction_reference_would_call_anyway"
        ]
        if propose:
            arguments = (
                '{"duplicate":1,"duplicate":2}'
                if malformed
                else json.dumps(operation["sink"]["arguments"], separators=(",", ":"))
            )
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "controlled-proposal",
                        "type": "function",
                        "function": {
                            "name": operation["sink"]["function"],
                            "arguments": arguments,
                        },
                    }
                ],
            }
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "No action proposed."}
            finish = "stop"
    return {
        "id": f"mock-{operation['operation_sequence']:04d}",
        "object": "chat.completion",
        "created": 0,
        "model": operation["body"]["model"],
        "choices": [
            {
                "index": 0,
                "finish_reason": finish,
                "message": message,
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
    }


@pytest.fixture(scope="module")
def compiled():
    config, _ = load_causal_panel_config(CONFIG)
    return config, compile_causal_panel(config)


def test_frozen_inventory_has_all_categories_domains_repetitions_and_m7_plans(compiled):
    config, panel = compiled
    assert len(panel["references"]) == 12
    assert Counter(row["category"] for row in panel["references"]) == {
        "single_dependent": 3,
        "single_independent": 3,
        "joint_conjunctive": 3,
        "redundant_or": 3,
    }
    assert Counter(row["domain"] for row in panel["references"]) == {
        "calendar": 4,
        "email": 4,
        "file": 4,
    }
    assert len(panel["plans"]) == 60 and len(panel["probes"]) == 120
    assert len(panel["operations"]) == config["limits"]["planned_total_requests"] == 360
    assert Counter(row["operation_type"] for row in panel["operations"]) == {
        "sham_replay": 120,
        "neutralized_replay": 120,
        "isolated_judge": 120,
    }
    assert all(
        row["m7_plan"]["status"] == "eligible" and row["m7_plan"]["complete"] is True
        for row in panel["plans"]
    )
    assert all(
        count == 1
        for count in Counter(
            (row["unit_id"], row["repetition"]) for row in panel["plans"]
        ).values()
    )
    assert all(row["hidden_model_causality"] == "not_labeled" for row in panel["references"])


def test_stable_accuracy_claim_gate_requires_twelve_balanced_unit_source_sets(compiled):
    _, panel = compiled
    rows_11 = [
        {"prediction": value, "reference": value, "probability": 0.9 if value else 0.1}
        for value in ([True] * 6 + [False] * 5)
    ]
    blocked = _stable_metrics(rows_11, "prediction", "reference", probability="probability")
    assert blocked["evaluated"] == 11
    assert blocked["accuracy"] is None and blocked["balanced_accuracy"] is None
    assert blocked["claim_gate"]["passed"] is False
    assert blocked["calibration"]["reason"] == "stable_unit_claim_gate_not_met"

    rows_12 = rows_11 + [{"prediction": False, "reference": False, "probability": 0.1}]
    eligible = _stable_metrics(rows_12, "prediction", "reference", probability="probability")
    assert eligible["claim_gate"]["passed"] is True
    assert eligible["accuracy"] == eligible["balanced_accuracy"] == 1.0
    assert eligible["calibration"]["brier_score"] == pytest.approx(0.01)
    assert all(row["source_set_references"] == CATEGORIES[row["category"]]["references"] for row in panel["references"])


def test_operations_bind_same_prefix_replays_and_tool_free_judges(compiled):
    _, panel = compiled
    by_group = {}
    for operation in panel["operations"]:
        by_group.setdefault(operation["group_id"], {})[operation["operation_type"]] = operation
        assert operation["request_body_sha256"] == hashlib.sha256(
            _canonical(operation["body"])
        ).hexdigest()
        binding = {
            key: value
            for key, value in operation.items()
            if key not in {"body", "binding_sha256", "operation_id"}
        }
        assert operation["binding_sha256"] == hashlib.sha256(_canonical(binding)).hexdigest()
        assert operation["operation_id"] == "causal-panel:" + operation["binding_sha256"]
    assert len(by_group) == 120
    for group_id, operations in by_group.items():
        sham = operations["sham_replay"]
        neutral = operations["neutralized_replay"]
        judge = operations["isolated_judge"]
        probe = panel["probes"][group_id]
        assert sham["body"]["messages"] == probe["context_a"]
        assert neutral["body"]["messages"] == probe["context_b"]
        assert {key: value for key, value in sham["body"].items() if key != "messages"} == {
            key: value for key, value in neutral["body"].items() if key != "messages"
        }
        assert sham["context_a_sha256"] == neutral["context_a_sha256"]
        assert sham["probe_binding_sha256"] == neutral["probe_binding_sha256"]
        assert sham["sink"] == neutral["sink"]
        assert sham["body"]["tools"] and neutral["body"]["tools"]
        assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(
            judge["body"]
        )
        judged = json.loads(judge["body"]["messages"][1]["content"])
        assert judged["probe_id"] == probe["probe_id"]
        assert judged["context_a"] == probe["context_a"]
        assert judged["context_b"] == probe["context_b"]
    for repetition in range(1, 6):
        example = next(
            group
            for group in by_group.values()
            if next(iter(group.values()))["repetition"] == repetition
        )
        ordered = [
            item[0]
            for item in sorted(
                (
                    (operation["operation_type"], operation["operation_sequence"])
                    for operation in example.values()
                ),
                key=lambda pair: pair[1],
            )
        ]
        assert ordered == (
            ["sham_replay", "neutralized_replay", "isolated_judge"]
            if repetition % 2
            else ["neutralized_replay", "sham_replay", "isolated_judge"]
        )


def test_plan_only_is_offline_retains_unknowns_and_executes_no_tools(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        causal_v2_audit,
        "_new_client",
        lambda: pytest.fail("Plan-only must not construct a client"),
    )
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args, **kwargs: pytest.fail("Plan-only must not use a socket"),
    )
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("Controlled replay must not execute a tool"),
    )
    output = tmp_path / "plan-only"
    summary = run_causal_panel(output, config_path=CONFIG)
    assert summary["status"] == "plan_only_complete" and summary["mode"] == "plan_only"
    assert summary["request_count"] == summary["native_tool_executions"] == 0
    assert summary["result_operations"] == 360
    assert summary["unknown_replay_operations"] == 240
    assert summary["unknown_judgments"] == 120
    assert summary["unknown_observed_replay_labels"] == 120
    assert summary["judge_vs_observed_replay"]["evaluated"] == 0
    assert summary["judge_vs_observed_replay"]["accuracy"] is None
    assert summary["judge_vs_observed_replay"]["claim_gate"]["passed"] is False
    assert summary["judge_vs_observed_replay"]["calibration"]["status"] == "unavailable"
    assert (output / "requests.jsonl").read_bytes() == b""
    assert all(row["reason"] == "live_not_enabled" for row in rows(output / "results.jsonl"))
    assert (output / "panel-config.json").read_bytes() == CONFIG.read_bytes()
    for path in output.iterdir():
        if path.is_file():
            path.read_bytes().decode("ascii")


def test_full_mock_panel_observes_frozen_patterns_without_tool_execution(
    tmp_path, monkeypatch, compiled
):
    _, panel = compiled
    pending = deque(panel["operations"])
    attempted = []

    def handler(request):
        operation = pending.popleft()
        attempted.append(operation["operation_id"])
        assert (output / "plan.sealed").is_file()
        seal = json.loads((output / "plan.sealed").read_text(encoding="ascii"))
        assert seal["sealed_before_transport"] is True
        assert hashlib.sha256((output / "plan.json").read_bytes()).hexdigest() == seal[
            "frozen_files"
        ]["plan.json"]
        assert json.loads(request.content) == operation["body"]
        assert request.extensions["timeout"]["read"] == 60.0
        return httpx.Response(200, json=completion(operation))

    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *args, **kwargs: pytest.fail("Mock transport must not use a socket"),
    )
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("A returned proposal must never execute"),
    )
    output = tmp_path / "mock-complete"
    with client_with(handler) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=360,
        )
    assert not pending and len(attempted) == len(set(attempted)) == 360
    assert summary["status"] == "completed" and summary["mode"] == "injected_client"
    assert summary["request_count"] == 360 and summary["native_tool_executions"] == 0
    assert summary["observed_replay_operations"] == 240
    assert summary["valid_judgments"] == 120
    assert summary["observed_replay_labels"] == 120
    assert summary["stable_observed_labels"] == 24 and summary["unknown_stable_labels"] == 0
    assert summary["judge_vs_observed_replay"]["accuracy"] == 1.0
    assert summary["judge_vs_observed_replay"]["balanced_accuracy"] == 1.0
    assert summary["observed_replay_vs_construction"]["accuracy"] == 1.0
    assert summary["judge_vs_construction"]["accuracy"] == 1.0
    assert summary["observed_replay_vs_construction"]["tp"] == 9
    assert summary["observed_replay_vs_construction"]["tn"] == 15
    assert summary["observed_replay_vs_construction"]["evaluated"] == 24
    gate = summary["judge_vs_observed_replay"]["claim_gate"]
    assert gate == {
        "passed": True,
        "definitive_unit_source_sets": 24,
        "would_call_anyway_unit_source_sets": 9,
        "dependency_unit_source_sets": 15,
        "minimum_definitive": 12,
        "minimum_would_call_anyway": 6,
        "minimum_dependency": 6,
    }
    assert summary["judge_vs_observed_replay"]["calibration"]["status"] == "available"
    assert summary["judge_vs_observed_replay"]["calibration"]["brier_score"] == pytest.approx(0.01)
    assert summary["repetition_level_diagnostics"]["observed_replay_vs_construction"]["tp"] == 45
    assert summary["repetition_level_diagnostics"]["observed_replay_vs_construction"]["tn"] == 75
    assert "accuracy" not in summary["repetition_level_diagnostics"]["judge_vs_observed_replay"]
    assert summary["reported_usage"]["total_tokens"]["known_sum"] == 360 * 14
    assert all(row["protocol"] == PROTOCOL for row in rows(output / "results.jsonl"))
    assert all(
        row["hidden_model_causality"] == "not_labeled"
        for row in rows(output / "comparisons.jsonl")
    )
    manifest = json.loads((output / "manifest.json").read_text(encoding="ascii"))
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest


def test_one_attempt_budget_has_no_retry_or_replacement(tmp_path, compiled):
    _, panel = compiled
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(200, json=completion(panel["operations"][0], malformed=True))

    output = tmp_path / "one-attempt"
    with client_with(handler) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=1,
        )
    result_rows = rows(output / "results.jsonl")
    assert len(attempts) == summary["request_count"] == 1
    assert summary["status"] == "partial"
    assert summary["invocation_request_count"] == 1
    assert summary["never_started_operations"] == 359
    assert len(result_rows) == 1 and sum(row["request_attempted"] for row in result_rows) == 1
    assert result_rows[0]["status"] == "invalid"
    assert len(rows(output / "requests.jsonl")) == 1
    assert len(list((output / "started-slots").glob("*.json"))) == 1
    assert len(list((output / "result-slots").glob("*.json"))) == 1


def test_strict_judge_schema_failure_stays_explicit_unknown(tmp_path, compiled):
    _, panel = compiled
    judge_index = next(
        index
        for index, operation in enumerate(panel["operations"])
        if operation["operation_type"] == "isolated_judge"
    )
    pending = deque(panel["operations"][: judge_index + 1])

    def handler(request):
        operation = pending.popleft()
        return httpx.Response(
            200,
            json=completion(
                operation,
                malformed=operation["operation_type"] == "isolated_judge",
            ),
        )

    output = tmp_path / "invalid-judge"
    with client_with(handler) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=judge_index + 1,
        )
    first_judge = next(
        row for row in rows(output / "results.jsonl") if row["operation_type"] == "isolated_judge"
    )
    assert first_judge["status"] == "invalid"
    assert first_judge["reason"] == "invalid_judgment_schema"
    assert summary["valid_judgments"] == 0 and summary["unknown_judgments"] == 120


def test_unsupported_response_text_is_quarantined_from_english_jsonl(tmp_path, compiled):
    _, panel = compiled

    def handler(request):
        response = completion(panel["operations"][0])
        response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json.dumps(
            {"value": "\u041f\u0440\u0438\u0432\u0435\u0442"}, ensure_ascii=False
        )
        return httpx.Response(200, json=response)

    output = tmp_path / "unsupported-response"
    with client_with(handler) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=1,
        )
    first = rows(output / "results.jsonl")[0]
    assert first["status"] == "invalid" and first["reason"] == "non_english_response"
    assert "response" not in first and (output / first["response_file"]).is_file()
    assert summary["request_count"] == 1 and summary["observed_replay_operations"] == 0
    for path in output.iterdir():
        if path.is_file():
            path.read_bytes().decode("ascii")
    for path in output.rglob("*.json"):
        path.read_bytes().decode("ascii")


def test_retry_enabled_client_and_invalid_budgets_fail_before_output(tmp_path):
    with client_with(lambda request: pytest.fail("Rejected client must not be used")) as client:
        client.max_retries = 1
        output = tmp_path / "retry-client"
        with pytest.raises(ValueError, match="disable SDK retries"):
            run_causal_panel(output, config_path=CONFIG, client=client, max_requests=1)
        assert not output.exists()
    for index, limit in enumerate((-1, 361, True, 1.5)):
        output = tmp_path / f"bad-budget-{index}"
        with pytest.raises(ValueError, match="zero through 360"):
            run_causal_panel(output, config_path=CONFIG, max_requests=limit)
        assert not output.exists()


def test_frozen_plan_mutation_after_pacing_stops_before_transport(tmp_path):
    output = tmp_path / "mutated-after-freeze"

    class MutatingPacer:
        def before_request(self, messages, tools):
            assert messages and tools
            (output / "plan.json").write_text("{}\n", encoding="ascii")
            return "ticket", 0.0

    with client_with(lambda request: pytest.fail("Changed frozen plan must stop transport")) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=360,
            pacer=MutatingPacer(),
        )
    result_rows = rows(output / "results.jsonl")
    assert summary["request_count"] == 0 and summary["status"] == "invalidated_inputs"
    assert summary["integrity"]["frozen_inputs_unchanged"] is False
    assert result_rows == []
    assert summary["never_started_operations"] == 360


def test_pacing_state_must_stay_outside_fresh_output(tmp_path):
    output = tmp_path / "panel"

    class Pacer:
        path = output / "pacing.json"

    with pytest.raises(ValueError, match="Pacing state"):
        run_causal_panel(output, config_path=CONFIG, pacer=Pacer())
    assert not output.exists()


def test_config_rejects_changed_frozen_limits_before_output(tmp_path):
    config = json.loads(CONFIG.read_text(encoding="ascii"))
    config["limits"]["planned_total_requests"] = 359
    config_dir = tmp_path / "input"
    config_dir.mkdir()
    changed = config_dir / "panel.json"
    changed.write_text(json.dumps(config), encoding="ascii")
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="limits differ"):
        run_causal_panel(output, config_path=changed)
    assert not output.exists()


def test_live_prepared_plan_resumes_only_never_started_slots(tmp_path, compiled):
    _, panel = compiled
    output = tmp_path / "prepared"
    with client_with(lambda request: pytest.fail("Zero-cap preparation must not call transport")) as client:
        prepared = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=0,
        )
    assert prepared["status"] == "live_prepared"
    assert prepared["request_count"] == prepared["result_operations"] == 0
    assert prepared["never_started_operations"] == 360
    assert (output / "plan.sealed").is_file()
    assert list((output / "started-slots").glob("*.json")) == []
    assert rows(output / "results.jsonl") == []

    expected = deque(panel["operations"][:2])
    first_ids = []

    def first_handler(request):
        operation = expected.popleft()
        first_ids.append(operation["operation_id"])
        assert json.loads(request.content) == operation["body"]
        return httpx.Response(200, json=completion(operation))

    with client_with(first_handler) as client:
        first = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=2,
            resume=True,
        )
    assert not expected
    assert first["status"] == "partial"
    assert first["starts_before_invocation"] == 0
    assert first["invocation_request_count"] == first["request_count"] == 2
    assert first["never_started_operations"] == 358

    next_operation = panel["operations"][2]
    second_ids = []

    def second_handler(request):
        second_ids.append(next_operation["operation_id"])
        assert json.loads(request.content) == next_operation["body"]
        return httpx.Response(200, json=completion(next_operation))

    with client_with(second_handler) as client:
        second = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=1,
            resume=True,
        )
    assert first_ids == [operation["operation_id"] for operation in panel["operations"][:2]]
    assert second_ids == [next_operation["operation_id"]]
    assert not set(first_ids).intersection(second_ids)
    assert second["starts_before_invocation"] == 2
    assert second["invocation_request_count"] == 1
    assert second["request_count"] == 3
    assert second["never_started_operations"] == 357
    assert len({row["operation_id"] for row in rows(output / "requests.jsonl")}) == 3


def test_interrupted_started_slot_is_never_retried_and_resume_finishes(
    tmp_path, compiled, monkeypatch
):
    _, panel = compiled
    output = tmp_path / "interrupted"
    initial = deque(panel["operations"][:3])
    initial_ids = []
    monkeypatch.setattr(
        FunctionsRuntime,
        "run_function",
        lambda *args, **kwargs: pytest.fail("Resume must never execute returned tool proposals"),
    )

    def interrupting_handler(request):
        operation = initial.popleft()
        initial_ids.append(operation["operation_id"])
        if not initial:
            raise KeyboardInterrupt
        return httpx.Response(200, json=completion(operation))

    with client_with(interrupting_handler) as client, pytest.raises(KeyboardInterrupt):
        run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=360,
        )
    assert initial_ids == [operation["operation_id"] for operation in panel["operations"][:3]]
    assert len(list((output / "started-slots").glob("*.json"))) == 3
    assert len(list((output / "result-slots").glob("*.json"))) == 2

    remaining = deque(panel["operations"][3:])
    resumed_ids = []

    def resumed_handler(request):
        operation = remaining.popleft()
        resumed_ids.append(operation["operation_id"])
        assert json.loads(request.content) == operation["body"]
        return httpx.Response(200, json=completion(operation))

    with client_with(resumed_handler) as client:
        summary = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=360,
            resume=True,
        )
    assert not remaining
    assert not set(initial_ids).intersection(resumed_ids)
    assert len(initial_ids) + len(resumed_ids) == 360
    assert summary["status"] == "completed_with_unknowns"
    assert summary["starts_before_invocation"] == 3
    assert summary["invocation_request_count"] == 357
    assert summary["request_count"] == 360
    assert summary["interrupted_after_start"] == 1
    result_rows = rows(output / "results.jsonl")
    assert len(result_rows) == 360
    assert result_rows[2]["status"] == "unknown"
    assert result_rows[2]["reason"] == "interrupted_after_start"
    assert len({row["operation_id"] for row in rows(output / "requests.jsonl")}) == 360

    with client_with(lambda request: pytest.fail("Completed slots must never be retried")) as client:
        repeated = run_causal_panel(
            output,
            config_path=CONFIG,
            client=client,
            max_requests=10,
            resume=True,
        )
    assert repeated["invocation_request_count"] == 0
    assert repeated["request_count"] == 360


def test_resume_rejects_frozen_hash_or_runtime_drift_before_transport(tmp_path):
    output = tmp_path / "drift"
    with client_with(lambda request: pytest.fail("Preparation must not call transport")) as client:
        run_causal_panel(output, config_path=CONFIG, client=client, max_requests=0)
    (output / "plan.json").write_text("{}\n", encoding="ascii")
    attempts = []
    with client_with(lambda request: attempts.append(request)) as client:
        with pytest.raises(ValueError, match="frozen plan or runtime changed"):
            run_causal_panel(
                output,
                config_path=CONFIG,
                client=client,
                max_requests=1,
                resume=True,
            )
    assert attempts == []
    assert list((output / "started-slots").glob("*.json")) == []

    runtime_output = tmp_path / "runtime-drift"
    with client_with(lambda request: pytest.fail("Preparation must not call transport")) as client:
        run_causal_panel(runtime_output, config_path=CONFIG, client=client, max_requests=0)
    with openai.OpenAI(
        api_key="fixture-private-key",
        base_url="https://different-controlled-causal.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda request: pytest.fail("Drift must stop transport"))
        ),
    ) as changed_client:
        with pytest.raises(ValueError, match="frozen plan or runtime changed"):
            run_causal_panel(
                runtime_output,
                config_path=CONFIG,
                client=changed_client,
                max_requests=1,
                resume=True,
            )
    assert list((runtime_output / "started-slots").glob("*.json")) == []
