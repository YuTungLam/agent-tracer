import copy
import json
from types import SimpleNamespace

import httpx
import openai
from agentdojo.functions_runtime import FunctionsRuntime

from agentdojo_lab import pacing
from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.pacing import RequestPacer


def test_pacer_shares_reported_usage_waits_and_stores_no_text(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(
        pacing,
        "time",
        SimpleNamespace(
            time=lambda: clock[0],
            monotonic=lambda: clock[0],
            sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ),
    )
    path = tmp_path / "pacing.json"
    first = RequestPacer(7000, path)
    messages = [{"role": "user", "content": "private-fixture-content"}]
    before = copy.deepcopy(messages)
    ticket, waited = first.before_request(messages, [])
    assert waited == 0
    first.after_response(ticket, 6500)
    second = RequestPacer(7000, path)
    _, waited = second.before_request(messages, [])
    assert waited == 65.0
    assert messages == before
    assert "private-fixture-content" not in path.read_text()
    assert len(json.loads(path.read_text())) == 1


def test_pacing_changes_neither_sdk_payload_nor_number_of_requests():
    payloads = []

    def handler(request):
        payloads.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "fixture",
                "object": "chat.completion",
                "created": 0,
                "model": "fixture",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "Done"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 4, "total_tokens": 104},
            },
        )

    messages = [{"role": "user", "content": [{"type": "text", "content": "Read a normal note"}]}]
    with openai.OpenAI(
        api_key="fixture",
        base_url="https://fixture.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        plain = GroqLLM(client, "openai/gpt-oss-120b")
        paced = GroqLLM(client, "openai/gpt-oss-120b", pacer=RequestPacer(7000))
        a = plain.query("Read a normal note", FunctionsRuntime(), messages=messages)
        b = paced.query("Read a normal note", FunctionsRuntime(), messages=messages)
    assert payloads[0] == payloads[1]
    assert a[3] == b[3]
    assert plain.stats["request_count"] == paced.stats["request_count"] == 1
    assert paced.stats["pacing_wait_seconds"] >= 0


def test_failed_call_reservation_remains_without_a_retry(tmp_path):
    pacer = RequestPacer(7000, tmp_path / "state.json")
    ticket, _ = pacer.before_request([], [])
    # No after_response call: the failed request retains its estimate.
    pacer._load()
    assert pacer.entries[0]["id"] == ticket and pacer.entries[0]["tokens"] > 0
