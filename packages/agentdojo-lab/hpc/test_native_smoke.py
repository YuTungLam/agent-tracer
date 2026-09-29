"""Native smoke contracts with real simulated tools and in-process HTTP responses."""

import json
import socket

import httpx
import native_smoke
import pytest
import smoke
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab import runner

BASE_URL = "http://127.0.0.1:8123/v1"
SECRET = "native-smoke-fixture-secret"


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("Unexpected socket"))
    monkeypatch.setattr(runner, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("SLURM_JOB_ID", "smoke-fixture-job")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", SECRET)
    monkeypatch.setenv("GROQ_API_KEY", "must-never-be-used")
    for mode_name, directory_name in native_smoke.FROZEN_CASE_BINDINGS:
        monkeypatch.delenv(mode_name, raising=False)
        monkeypatch.delenv(directory_name, raising=False)


@pytest.fixture
def serving(tmp_path):
    preflight = tmp_path / "preflight.json"
    preflight.write_text(json.dumps({
        "slurm_job_id": "smoke-fixture-job", "model": {
            "model_id": "meta-llama/Llama-4-Scout-17B-16E-Instruct", "declared_revision": "fixture-pin",
        }, "template": {"sha256": "template-fixture"}, "container": {"sha256": "container-fixture"},
    }))
    (tmp_path / "smoke.json").write_text(json.dumps({
        "status": "passed", "requests_started": 4, "requests": [
            {"status": "passed", "request": {"model": smoke.MODEL}, "response": {"model": smoke.MODEL}}
            for _ in range(4)
        ],
    }))
    (tmp_path / "server-command.txt").write_text(
        "apptainer exec /fixture.sif vllm serve /fixture/model --served-model-name llama-4-scout-local "
        "--host 127.0.0.1 --port 8123 --max-model-len 8192\n"
    )
    return dict(base_url=BASE_URL, serving_receipt=preflight,
                output=tmp_path / "native-smoke.json", run_dir=tmp_path / "native-run")


def install_mock(monkeypatch, mode="success"):
    received = []
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_0"]
    calls = task.ground_truth(suite.load_and_inject_default_environment({}))

    def handler(request):
        assert str(request.url) == BASE_URL + "/chat/completions"
        assert request.headers["Authorization"] == "Bearer " + SECRET
        body = json.loads(request.content)
        received.append(body)
        assert body["model"] == smoke.MODEL
        assert body["max_completion_tokens"] == 2048
        assert "reasoning_effort" not in body
        if mode == "api_error":
            return httpx.Response(500, json={"error": {"message": "Rejected " + SECRET}})
        tool_turn = mode == "exhaust" or (len(received) == 1 and mode != "answer_only")
        message = (
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"native-{len(received)}-{i}", "type": "function", "function": {
                    "name": call.function if mode != "unknown_tool" else "missing_function",
                    "arguments": json.dumps(call.args),
                }} for i, call in enumerate(calls)
            ]} if tool_turn else {"role": "assistant", "content": task.GROUND_TRUTH_OUTPUT}
        )
        return httpx.Response(200, json={
            "id": "mock-completion", "object": "chat.completion", "created": 0, "model": smoke.MODEL,
            "choices": [{"index": 0, "finish_reason": "tool_calls" if tool_turn else "stop",
                         "message": message}],
            "usage": {"prompt_tokens": 4591, "completion_tokens": 30, "total_tokens": 4621},
        })

    original = httpx.Client

    class LocalMock(original):
        def __init__(self, **kwargs):
            assert kwargs == {"trust_env": False, "follow_redirects": False}
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(native_smoke.httpx, "Client", LocalMock)
    return received


def test_native_clean_round_trip_and_pinned_receipt(monkeypatch, serving):
    received = install_mock(monkeypatch)
    result = native_smoke.run_native(**serving)
    assert result["status"] == "passed"
    assert all(result["checks"].values())
    assert len(received) == result["native_requests_started"] == 2
    assert result["event_audit"]["event_count"] == 15
    assert result["native_summary"]["task_success_count"] == 1
    assert len(result["native_tool_round_trips"]) == 1
    assert result["serving"]["model"]["declared_revision"] == "fixture-pin"
    assert result["serving"]["preflight"]["sha256"]
    assert set(result["artifacts"]) == {
        "manifest.json", "summary.json", "events.jsonl", "events.audit.json", "report.html",
    }
    manifest = json.loads((serving["run_dir"] / "manifest.json").read_text())
    assert manifest["mode"] == "live-openai-compatible"
    assert manifest["sdk_max_retries"] == 0
    assert manifest["attack"] is None
    assert not manifest["online_provenance"]["enabled"]
    assert not manifest["online_causal_audit"]["enabled"]
    assert "causal_endpoint" not in manifest["config"]
    assert SECRET not in serving["output"].read_text()
    assert runner.GroqLLM is not native_smoke.BudgetedSmokeLLM


def test_global_cap_includes_native_continuations_and_retains_failure(monkeypatch, serving):
    received = install_mock(monkeypatch, "exhaust")
    result = native_smoke.run_native(**serving)
    assert result["status"] == "failed"
    assert len(received) == result["native_requests_started"] == 4
    assert "summary.json" in result["artifacts"]
    assert result["native_summary"]["status"] != "completed"


@pytest.mark.parametrize("mode, expected_requests", [("answer_only", 1), ("unknown_tool", 2), ("api_error", 1)])
def test_native_false_pass_and_transport_failure_are_retained(monkeypatch, serving, mode, expected_requests):
    received = install_mock(monkeypatch, mode)
    result = native_smoke.run_native(**serving)
    assert result["status"] == "failed"
    assert len(received) == result["native_requests_started"] == expected_requests
    assert "summary.json" in result["artifacts"]
    assert not result.get("checks", {}).get("native_tool_round_trip", False)
    for path in serving["run_dir"].rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text()
    assert SECRET not in serving["output"].read_text()


@pytest.mark.parametrize("change", ["port", "model", "job", "missing_key", "prior_run", "prior_receipt"])
def test_preconditions_block_without_network_and_preserve_fresh_failure(monkeypatch, serving, change):
    monkeypatch.setattr(native_smoke, "run_clean", lambda *a, **k: pytest.fail("Native execution started"))
    if change == "port":
        serving["base_url"] = "http://127.0.0.1:8124/v1"
    elif change == "model":
        path = serving["serving_receipt"].parent / "smoke.json"
        value = json.loads(path.read_text())
        value["requests"][0]["response"]["model"] = "wrong-model"
        path.write_text(json.dumps(value))
    elif change == "job":
        monkeypatch.setenv("SLURM_JOB_ID", "different-job")
    elif change == "missing_key":
        monkeypatch.delenv("LOCAL_LLM_API_KEY")
    elif change == "prior_run":
        serving["run_dir"].mkdir()
        (serving["run_dir"] / "summary.json").write_text('{"usage":{"request_count":99}}')
    else:
        serving["output"].write_text("prior-receipt")
        with pytest.raises(FileExistsError):
            native_smoke.run_native(**serving)
        assert serving["output"].read_text() == "prior-receipt"
        return
    result = native_smoke.run_native(**serving)
    assert result["status"] == "failed"
    assert result["native_requests_started"] == 0
    assert result["artifacts"] == {}
    assert "native_summary" not in result
    assert json.loads(serving["output"].read_text())["status"] == "failed"
    if change == "prior_run":
        assert (serving["run_dir"] / "summary.json").read_text() == '{"usage":{"request_count":99}}'
    else:
        assert not serving["run_dir"].exists()
