"""DeepSeek Flash wire tests with the real SDK and an in-process HTTP mock."""

import json

import httpx
import openai
import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import text_content_block_from_string

from agentdojo_lab.deepseek_adapter import DEEPSEEK_FLASH_MODEL, DeepSeekLLM

BASE_URL = "https://api.deepseek.com"


def completion(message, *, prompt_tokens=10, completion_tokens=4):
    return {
        "id": "deepseek-offline-completion",
        "object": "chat.completion",
        "created": 1,
        "model": DEEPSEEK_FLASH_MODEL,
        "system_fingerprint": "test-fingerprint",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
                "message": message,
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


@pytest.fixture
def client_factory():
    clients = []

    def make(handler, *, key="offline-test-key"):
        client = openai.OpenAI(
            api_key=key,
            base_url=BASE_URL,
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


def test_native_tool_loop_uses_deepseek_wire_contract_without_reasoning_replay(client_factory):
    requests = []
    executed = []
    tool_output = "  Original result: café\nsecond line\n"

    def handler(request):
        assert request.method == "POST"
        assert str(request.url) == BASE_URL + "/chat/completions"
        assert request.headers["authorization"] == "Bearer offline-test-key"
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            message = {
                "role": "assistant",
                "content": None,
                # A disabled-thinking response should omit this field. Include
                # it to prove the next request does not require or replay it.
                "reasoning_content": "must-not-appear-in-next-request",
                "tool_calls": [
                    {
                        "id": "call-deepseek-1",
                        "type": "function",
                        "function": {"name": "read_note", "arguments": '{"note_id":"note-1"}'},
                    }
                ],
            }
        else:
            assert all("reasoning_content" not in item for item in body["messages"])
            message = {"role": "assistant", "content": "The note was read."}
        return httpx.Response(200, json=completion(message))

    runtime = FunctionsRuntime()

    @runtime.register_function
    def read_note(note_id: str) -> str:
        """Read a synthetic note.

        :param note_id: Identifier of the synthetic note.
        """
        executed.append(note_id)
        return tool_output

    llm = DeepSeekLLM(client_factory(handler), max_tokens=1234)
    pipeline = AgentPipeline(
        [
            SystemMessage("Read the requested note."),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=2),
        ]
    )
    _, returned_runtime, _, messages, _ = pipeline.query("Read note-1.", runtime)

    assert returned_runtime is runtime
    assert executed == ["note-1"]
    assert len(requests) == 2
    for body in requests:
        assert body["model"] == DEEPSEEK_FLASH_MODEL
        assert body["messages"][0] == {"role": "system", "content": "Read the requested note."}
        assert body["thinking"] == {"type": "disabled"}
        assert body["max_tokens"] == 1234
        assert body["temperature"] == 0.0
        assert body["tool_choice"] == "auto"
        assert body["tools"][0]["function"]["name"] == "read_note"
        assert "max_completion_tokens" not in body
        assert "reasoning_effort" not in body
        assert all("name" not in item for item in body["messages"])
    assert requests[1]["messages"][-2]["tool_calls"][0]["id"] == "call-deepseek-1"
    assert requests[1]["messages"][-1] == {
        "role": "tool",
        "tool_call_id": "call-deepseek-1",
        "content": tool_output,
    }
    assert messages[-1] == {
        "role": "assistant",
        "content": [text_content_block_from_string("The note was read.")],
        "tool_calls": None,
    }
    assert llm.name == "deepseek_deepseek-flash"
    assert llm.stats == {"request_count": 2, "prompt_tokens": 20, "completion_tokens": 8}


def test_no_tool_request_preserves_observer_pacer_and_native_return_shape(client_factory):
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=completion({"role": "assistant", "content": "Done."}))

    class Observer:
        def __init__(self):
            self.events = []

        def begin_model_call(self, messages):
            self.events.append(("begin", len(messages)))

        def model_parsed(self, output):
            self.events.append(("parsed", output["role"]))

        def model_failed(self, exc):
            self.events.append(("failed", type(exc).__name__))

    class Pacer:
        def __init__(self):
            self.before = []
            self.after = []

        def before_request(self, messages, tools):
            self.before.append((messages, tools))
            return "ticket-1", 0.25

        def after_response(self, ticket, tokens):
            self.after.append((ticket, tokens))

    observer = Observer()
    pacer = Pacer()
    llm = DeepSeekLLM(client_factory(handler), observer=observer, pacer=pacer)
    runtime = FunctionsRuntime()
    history = [{"role": "user", "content": [text_content_block_from_string("Hello.")]}]
    extra_args = {"trace_id": "test-1"}
    query, returned_runtime, _, output, returned_args = llm.query(
        "Hello.", runtime, messages=history, extra_args=extra_args
    )

    assert query == "Hello."
    assert returned_runtime is runtime
    assert output[:-1] == history
    assert returned_args is extra_args
    assert requests[0]["messages"] == [{"role": "user", "content": "Hello."}]
    assert requests[0]["thinking"] == {"type": "disabled"}
    assert "tools" not in requests[0] and "tool_choice" not in requests[0]
    assert observer.events == [("begin", 1), ("parsed", "assistant")]
    assert pacer.before == [([{"role": "user", "content": "Hello."}], [])]
    assert pacer.after == [("ticket-1", 14)]
    assert llm.stats == {
        "request_count": 1,
        "prompt_tokens": 10,
        "completion_tokens": 4,
        "pacing_wait_seconds": 0.25,
    }


def test_api_error_redacts_key_without_retry(client_factory):
    requests = []
    secret = "fixture-private-key"

    def handler(request):
        requests.append(request)
        return httpx.Response(400, json={"error": {"message": "rejected " + secret}})

    llm = DeepSeekLLM(client_factory(handler, key=secret))
    with pytest.raises(openai.BadRequestError) as raised:
        llm.query("Hello.", FunctionsRuntime())
    assert len(requests) == 1
    assert secret not in str(raised.value)
    assert "[REDACTED]" in str(raised.value)
    assert llm.stats == {"request_count": 1, "prompt_tokens": 0, "completion_tokens": 0}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"model": "deepseek-v4-flash"},
        {"temperature": -0.1},
        {"temperature": True},
        {"max_tokens": 0},
        {"max_tokens": True},
    ],
)
def test_invalid_settings_stop_before_request(client_factory, kwargs):
    def handler(request):
        pytest.fail("Invalid configuration must not send a request")

    with pytest.raises(ValueError):
        DeepSeekLLM(client_factory(handler), **kwargs)
