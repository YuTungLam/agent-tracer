"""Offline Groq wire-contract tests using the real OpenAI SDK and native runtime."""

import json
from copy import deepcopy

import httpx
import openai
import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentdojo.types import text_content_block_from_string

from agentdojo_lab.groq_adapter import GroqLLM

MODEL = "openai/gpt-oss-20b"


def completion(message, *, prompt_tokens=10, completion_tokens=4):
    return {
        "id": "offline-completion",
        "object": "chat.completion",
        "created": 1,
        "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


@pytest.fixture
def client_factory():
    clients = []

    def make(handler):
        client = openai.OpenAI(
            api_key="offline-test-key",
            base_url="https://api.groq.com/openai/v1",
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


def test_native_pipeline_executes_tool_and_sends_compatible_second_request(client_factory):
    requests = []
    tool_calls = []
    tool_output = "  Original result: café\nsecond line\n"

    def handler(request):
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-read-01",
                        "type": "function",
                        "function": {"name": "read_note", "arguments": '{"note_id":"note-1"}'},
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": "The note was read."}
        return httpx.Response(200, json=completion(message))

    runtime = FunctionsRuntime()

    @runtime.register_function
    def read_note(note_id: str) -> str:
        """Read a synthetic note.

        :param note_id: Identifier of the synthetic note.
        """
        tool_calls.append(note_id)
        return tool_output

    llm = GroqLLM(client_factory(handler), MODEL, max_completion_tokens=1234, reasoning_effort="low")
    pipeline = AgentPipeline(
        [
            SystemMessage("Read the requested note."),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=2),
        ]
    )
    initial_history = []
    _, returned_runtime, _, messages, _ = pipeline.query("Read note-1.", runtime, messages=initial_history)

    assert initial_history == []
    assert returned_runtime is runtime
    assert tool_calls == ["note-1"]
    assert len(requests) == 2
    for body in requests:
        assert body["messages"][0] == {"role": "system", "content": "Read the requested note."}
        assert all("name" not in message for message in body["messages"])
        assert body["max_completion_tokens"] == 1234
        assert body["reasoning_effort"] == "low"
        assert body["temperature"] == 0.0
        assert body["tool_choice"] == "auto"
        assert body["tools"][0]["function"]["name"] == "read_note"
    assert requests[1]["messages"][-1] == {
        "role": "tool",
        "tool_call_id": "call-read-01",
        "content": tool_output,
    }
    assert requests[1]["messages"][-2]["tool_calls"][0]["id"] == "call-read-01"
    assert messages[-1] == {
        "role": "assistant",
        "content": [text_content_block_from_string("The note was read.")],
        "tool_calls": None,
    }
    assert llm.name == "groq_openai/gpt-oss-20b"
    assert llm.stats == {"request_count": 2, "prompt_tokens": 20, "completion_tokens": 8}


def test_message_conversion_preserves_history_call_ids_and_each_text_block(client_factory):
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=completion({"role": "assistant", "content": "Done."}))

    call = FunctionCall(function="read_note", args={"note_id": "note-1"}, id="call-9")
    history = [
        {"role": "system", "content": [text_content_block_from_string("System\n")]},
        {
            "role": "user",
            "content": [
                text_content_block_from_string("  first"),
                text_content_block_from_string("second  "),
            ],
        },
        {"role": "assistant", "content": None, "tool_calls": [call]},
        {
            "role": "tool",
            "content": [text_content_block_from_string("A\n"), text_content_block_from_string(" B")],
            "tool_call_id": "call-9",
            "tool_call": call,
            "error": None,
        },
    ]
    original = deepcopy(history)
    extra_args = {"trace_id": "offline-1"}
    env = EmptyEnv()
    llm = GroqLLM(client_factory(handler), MODEL)
    _, _, returned_env, output, returned_args = llm.query(
        "Read note-1.", FunctionsRuntime(), env, history, extra_args
    )

    assert history == original
    assert output is not history
    assert output[:-1] == original
    assert returned_env is env
    assert returned_args is extra_args
    wire = requests[0]["messages"]
    assert wire[0] == {"role": "system", "content": "System\n"}
    assert wire[1]["content"] == "  first\nsecond  "
    assert wire[2]["content"] is None
    assert json.loads(wire[2]["tool_calls"][0]["function"]["arguments"]) == call.args
    assert wire[3] == {"role": "tool", "content": "A\n\n B", "tool_call_id": "call-9"}
    assert "tools" not in requests[0]
    assert "tool_choice" not in requests[0]
    assert "reasoning_effort" not in requests[0]


def test_tool_errors_follow_native_serializer_without_mutation(client_factory):
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=completion({"role": "assistant", "content": "Failed."}))

    call = FunctionCall(function="read_note", args={}, id="call-error")
    history = [
        {
            "role": "tool",
            "content": [text_content_block_from_string("None")],
            "tool_call_id": "call-error",
            "tool_call": call,
            "error": "  Note unavailable\n",
        }
    ]
    original = deepcopy(history)
    GroqLLM(client_factory(handler), MODEL).query("Read.", FunctionsRuntime(), messages=history)
    assert requests[0]["messages"][0]["content"] == "  Note unavailable\n"
    assert "name" not in requests[0]["messages"][0]
    assert history == original


def test_api_failure_is_propagated_once_without_adapter_retry(client_factory):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            503, json={"error": {"message": "offline provider failure", "type": "server_error"}}
        )

    llm = GroqLLM(client_factory(handler), MODEL)
    with pytest.raises(openai.InternalServerError, match="offline provider failure"):
        llm.query("Hello.", FunctionsRuntime())
    assert len(requests) == 1
    assert llm.stats == {"request_count": 1, "prompt_tokens": 0, "completion_tokens": 0}


def test_missing_usage_is_not_invented(client_factory):
    def handler(request):
        payload = completion({"role": "assistant", "content": "Hello."})
        payload.pop("usage")
        return httpx.Response(200, json=payload)

    llm = GroqLLM(client_factory(handler), MODEL)
    llm.query("Hello.", FunctionsRuntime())
    assert llm.stats == {"request_count": 1, "prompt_tokens": 0, "completion_tokens": 0}


@pytest.mark.parametrize(
    "overrides",
    [
        {"model": " "},
        {"temperature": -0.1},
        {"max_completion_tokens": 0},
        {"max_completion_tokens": True},
        {"reasoning_effort": "unknown"},
    ],
)
def test_invalid_configuration_is_rejected_before_request(client_factory, overrides):
    def handler(request):
        pytest.fail("Invalid configuration must not send an HTTP request")

    arguments = {"model": MODEL, **overrides}
    with pytest.raises(ValueError):
        GroqLLM(client_factory(handler), **arguments)
