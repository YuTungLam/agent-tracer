"""Observer contracts against the native pipeline and real SDK mock transport.

These deterministic, benign fixtures test instrumentation, not model capability.
"""

import json
from copy import deepcopy
from typing import Annotated

import httpx
import openai
import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import Depends, EmptyEnv, FunctionsRuntime, TaskEnvironment
from pydantic import BaseModel, Field

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.recording import EventRecorder

MODEL = "openai/gpt-oss-20b"


class Note(BaseModel):
    text: str = "Original note."


class NoteEnv(TaskEnvironment):
    note: Note = Field(default_factory=Note)


def completion(message):
    return {
        "id": "synthetic-completion",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
        "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
    }


def tool_call(name, arguments, call_id="provider-id-reused"):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def tool_message(*calls):
    return {"role": "assistant", "content": None, "tool_calls": list(calls)}


def final_message():
    return {"role": "assistant", "content": "Done."}


def events_at(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def of_type(events, event_type):
    return [event for event in events if event["event_type"] == event_type]


def native_pipeline(llm):
    return AgentPipeline(
        [
            SystemMessage("Use the requested note tools."),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=3),
        ]
    )


def note_runtime(executed):
    runtime = FunctionsRuntime()

    @runtime.register_function
    def read_note(labels: list[str], note: Annotated[Note, Depends("note")]) -> Note:
        """Read a note with the supplied labels.

        :param labels: Labels supplied for this read.
        """
        executed.append(("read_note", deepcopy(labels)))
        return note

    @runtime.register_function
    def update_note(text: str, note: Annotated[Note, Depends("note")]) -> str:
        """Update the text of the note.

        :param text: Replacement note text.
        """
        executed.append(("update_note", text))
        note.text = text
        return "Updated."

    @runtime.register_function
    def unavailable_note(note_id: str) -> str:
        """Read a note that is unavailable in this fixture.

        :param note_id: Identifier of the requested note.
        """
        executed.append(("unavailable_note", note_id))
        raise ValueError("Synthetic note unavailable.")

    return runtime


def run_script(tmp_path, script, *, observed, query_count=1, observer_fault_event=None):
    requests = []
    executed = []
    runtime = note_runtime(executed)
    env = NoteEnv()
    initial_history = []
    extra_args = {"fixture": "same-object"}
    event_path = tmp_path / "events.jsonl"
    recorder = EventRecorder(event_path, "test") if observed else None
    observer = ObservationSession(recorder) if recorder is not None else None
    if observer is not None and observer_fault_event is not None:
        original_emit = observer.emit
        failed = False

        def emit_with_one_failure(event_type, *args, **kwargs):
            nonlocal failed
            if event_type == observer_fault_event and not failed:
                failed = True
                # Raise inside a decorated observer method, outside the
                # recorder's own I/O safeguards, to exercise its separate guard.
                raise OSError("Synthetic instrumentation failure.")
            return original_emit(event_type, *args, **kwargs)

        observer.emit = emit_with_one_failure

    def respond(request):
        requests.append(json.loads(request.content))
        assert len(requests) <= len(script), "Observer must not add model requests"
        return httpx.Response(200, json=completion(deepcopy(script[len(requests) - 1])))

    client = openai.OpenAI(
        api_key="synthetic-observation-key",
        base_url="https://observation.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    if observer is not None:
        observer.attach(client)
    llm = GroqLLM(client, MODEL, observer=observer)
    pipeline = native_pipeline(llm)
    if observer is not None:
        pipeline = observe_pipeline(pipeline, observer)
    outputs = []
    try:
        with client:
            for _ in range(query_count):
                result = pipeline.query("Use the note tools.", runtime, env, initial_history, extra_args)
                assert result[0] == "Use the note tools."
                assert result[1] is runtime
                assert result[2] is env
                assert result[4] is extra_args
                outputs.append(deepcopy(result[3]))
    finally:
        if recorder is not None:
            recorder.close()
    assert initial_history == []
    assert extra_args == {"fixture": "same-object"}
    return {
        "requests": requests,
        "executed": executed,
        "messages": outputs,
        "env": env.model_dump(),
        "stats": llm.stats,
        "events": events_at(event_path) if observed else [],
        "recording_status": observer.status() if observer is not None else None,
    }


def test_observer_preserves_native_semantics_and_captures_mutable_raw_results(tmp_path):
    script = [
        tool_message(
            tool_call("read_note", {"labels": "['alpha', 'beta']"}),
            tool_call("update_note", {"text": "Changed after read."}),
        ),
        final_message(),
    ]
    baseline = run_script(tmp_path, script, observed=False)
    observed = run_script(tmp_path, script, observed=True)
    for key in ("requests", "executed", "messages", "env", "stats"):
        assert observed[key] == baseline[key], key
    assert observed["executed"] == [
        ("read_note", ["alpha", "beta"]),
        ("update_note", "Changed after read."),
    ]
    assert observed["env"]["note"]["text"] == "Changed after read."

    events = observed["events"]
    requests = of_type(events, "MODEL_REQUEST")
    assert [event["data"]["body"] for event in requests] == observed["requests"]
    assert len(of_type(events, "MODEL_RESPONSE")) == 2
    assert len(of_type(events, "MODEL_PARSED")) == 2
    proposed = of_type(events, "TOOL_CALL_PROPOSED")
    starts = of_type(events, "TOOL_RUNTIME_STARTED")
    returned = of_type(events, "TOOL_RUNTIME_RETURNED")
    results = of_type(events, "TOOL_RESULT")
    assert len(proposed) == len(starts) == len(returned) == len(results) == 2
    assert proposed[0]["data"]["arguments"] == {"labels": "['alpha', 'beta']"}
    assert starts[0]["data"]["runtime_input_args"] == {"labels": ["alpha", "beta"]}
    assert returned[0]["data"]["result"] == {"text": "Original note."}
    assert returned[0]["data"]["error"] is None
    assert len(of_type(events, "ENVIRONMENT_CHANGE")) >= 1

    # Provider IDs need not be unique even within one assistant response.
    assert proposed[0]["tool_call_id"] == proposed[1]["tool_call_id"] == "provider-id-reused"
    refs = [event["call_ref"] for event in proposed]
    assert all(refs) and refs[0] != refs[1]
    assert [event["call_ref"] for event in starts] == refs
    assert [event["call_ref"] for event in returned] == refs
    assert [event["call_ref"] for event in results] == refs
    assert {event["model_request_id"] for event in proposed} == {requests[0]["model_request_id"]}

    exposed = of_type(events, "TOOL_OUTPUT_EXPOSED")
    assert len(exposed) == 2
    assert [event["call_ref"] for event in exposed] == refs
    assert {event["model_request_id"] for event in exposed} == {requests[1]["model_request_id"]}
    wire_results = [message for message in observed["requests"][1]["messages"] if message["role"] == "tool"]
    assert [event["data"]["message"] for event in exposed] == wire_results


def test_unknown_and_failing_tools_have_distinct_execution_records(tmp_path):
    observed = run_script(
        tmp_path,
        [
            tool_message(
                tool_call("unknown_note_tool", {}, "unknown"),
                tool_call("unavailable_note", {"note_id": "note-1"}, "unavailable"),
            ),
            final_message(),
        ],
        observed=True,
    )
    events = observed["events"]
    proposed = of_type(events, "TOOL_CALL_PROPOSED")
    assert len(proposed) == 2
    unknown_ref, failure_ref = [event["call_ref"] for event in proposed]
    starts = of_type(events, "TOOL_RUNTIME_STARTED")
    returned = of_type(events, "TOOL_RUNTIME_RETURNED")
    assert [event["call_ref"] for event in starts] == [failure_ref]
    assert [event["call_ref"] for event in returned] == [failure_ref]
    assert returned[0]["data"]["result"] == ""
    assert returned[0]["data"]["error"] == "ValueError: Synthetic note unavailable."
    results = of_type(events, "TOOL_RESULT")
    assert [event["call_ref"] for event in results] == [unknown_ref, failure_ref]
    assert "Invalid tool" in results[0]["data"]["message"]["error"]
    assert results[1]["data"]["message"]["error"] == "ValueError: Synthetic note unavailable."
    exposed = of_type(events, "TOOL_OUTPUT_EXPOSED")
    assert [event["call_ref"] for event in exposed] == [unknown_ref, failure_ref]
    assert exposed[1]["data"]["message"]["content"] == "ValueError: Synthetic note unavailable."
    assert observed["executed"] == [("unavailable_note", "note-1")]


def test_http_failure_records_response_and_preserves_original_error_without_retry(tmp_path):
    def run(observed):
        requests = []
        event_path = tmp_path / "http-error.jsonl"
        recorder = EventRecorder(event_path, "test") if observed else None
        observer = ObservationSession(recorder) if recorder is not None else None

        def respond(request):
            requests.append(json.loads(request.content))
            return httpx.Response(
                503, json={"error": {"message": "Synthetic provider failure.", "type": "server_error"}}
            )

        client = openai.OpenAI(
            api_key="synthetic-observation-key",
            base_url="https://observation.invalid/v1",
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(respond)),
        )
        if observer is not None:
            observer.attach(client)
        llm = GroqLLM(client, MODEL, observer=observer)
        pipeline = native_pipeline(llm)
        if observer is not None:
            pipeline = observe_pipeline(pipeline, observer)
        try:
            with client, pytest.raises(openai.InternalServerError) as failure:
                pipeline.query("Read the note.", FunctionsRuntime(), EmptyEnv())
        finally:
            if recorder is not None:
                recorder.close()
        return requests, failure.value, llm.stats, events_at(event_path) if observed else []

    baseline_requests, baseline_error, baseline_stats, _ = run(False)
    requests, error, stats, events = run(True)
    assert len(requests) == 1
    assert requests == baseline_requests
    assert type(error) is type(baseline_error)
    assert str(error) == str(baseline_error)
    assert error.status_code == 503
    assert stats == baseline_stats == {"request_count": 1, "prompt_tokens": 0, "completion_tokens": 0}
    assert len(of_type(events, "MODEL_REQUEST")) == 1
    assert len(of_type(events, "MODEL_RESPONSE")) == 1
    assert len(of_type(events, "MODEL_ERROR")) == 1
    assert not of_type(events, "MODEL_PARSED")
    assert not of_type(events, "TOOL_RUNTIME_STARTED")


def test_multiple_pipeline_queries_keep_episodes_and_call_refs_separate(tmp_path):
    first = tool_message(tool_call("update_note", {"text": "First episode."}))
    second = tool_message(tool_call("update_note", {"text": "Second episode."}))
    observed = run_script(
        tmp_path, [first, final_message(), second, final_message()], observed=True, query_count=2
    )
    events = observed["events"]
    started = of_type(events, "EPISODE_STARTED")
    ended = of_type(events, "EPISODE_ENDED")
    assert len(started) == len(ended) == 2
    episode_ids = [event["episode_id"] for event in started]
    assert all(episode_ids) and episode_ids[0] != episode_ids[1]
    assert [event["episode_id"] for event in ended] == episode_ids
    proposed = of_type(events, "TOOL_CALL_PROPOSED")
    assert [event["episode_id"] for event in proposed] == episode_ids
    assert proposed[0]["call_ref"] != proposed[1]["call_ref"]
    requests = of_type(events, "MODEL_REQUEST")
    assert len({event["model_request_id"] for event in requests}) == 4
    assert [event["episode_id"] for event in requests] == [episode_ids[0]] * 2 + [episode_ids[1]] * 2
    assert [message["role"] for message in observed["requests"][2]["messages"]] == ["system", "user"]
    assert observed["env"]["note"]["text"] == "Second episode."


@pytest.mark.parametrize(
    "failed_event",
    [
        "EPISODE_STARTED",
        "MODEL_REQUEST",
        "MODEL_RESPONSE",
        "MODEL_PARSED",
        "TOOL_RUNTIME_STARTED",
        "TOOL_RUNTIME_RETURNED",
        "TOOL_RESULT",
        "TOOL_OUTPUT_EXPOSED",
        "EPISODE_ENDED",
    ],
)
def test_internal_observer_errors_do_not_change_agent_execution(tmp_path, failed_event):
    script = [
        tool_message(
            tool_call("read_note", {"labels": "['alpha']"}),
            tool_call("update_note", {"text": "Changed despite recorder failure."}),
        ),
        final_message(),
    ]
    baseline = run_script(tmp_path, script, observed=False)
    observed = run_script(tmp_path, script, observed=True, observer_fault_event=failed_event)

    # run_script also checks returned runtime, env and extra_args identities.
    # Exact wire equality includes the later request with both tool results.
    for key in ("requests", "executed", "messages", "env", "stats"):
        assert observed[key] == baseline[key], key
    assert len(observed["requests"]) == 2
    assert len(observed["executed"]) == 2
    assert observed["env"]["note"]["text"] == "Changed despite recorder failure."
    assert observed["messages"][0][-1]["role"] == "assistant"
    assert not of_type(observed["events"], "MODEL_ERROR")
    status = observed["recording_status"]
    assert status["complete"] is False
    assert len(status["observer_errors"]) == 1
    assert "OSError" in status["observer_errors"][0]


@pytest.mark.parametrize("transport_error", [httpx.ReadTimeout, httpx.ReadError])
def test_response_body_read_failure_preserves_sdk_exception_and_cause(tmp_path, transport_error):
    """Reading the response for observation must not swallow transport failures."""

    class BrokenBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"id":'
            raise transport_error("Synthetic response-body read failure.")

    def run(observed):
        requests = []
        event_path = tmp_path / "body-read-failure.jsonl"
        recorder = EventRecorder(event_path, "test") if observed else None
        observer = ObservationSession(recorder) if recorder is not None else None

        def respond(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200, headers={"content-type": "application/json"}, stream=BrokenBody())

        client = openai.OpenAI(
            api_key="synthetic-observation-key",
            base_url="https://observation.invalid/v1",
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(respond)),
        )
        if observer is not None:
            observer.attach(client)
        llm = GroqLLM(client, MODEL, observer=observer)
        pipeline = native_pipeline(llm)
        if observer is not None:
            pipeline = observe_pipeline(pipeline, observer)
        try:
            with client, pytest.raises(openai.APIConnectionError) as failure:
                pipeline.query("Read the note.", FunctionsRuntime(), EmptyEnv())
        finally:
            if recorder is not None:
                recorder.close()
        return requests, failure.value, llm.stats, events_at(event_path) if observed else []

    baseline_requests, baseline_error, baseline_stats, _ = run(False)
    requests, error, stats, events = run(True)
    assert len(requests) == 1
    assert requests == baseline_requests
    assert type(error) is type(baseline_error)
    assert str(error) == str(baseline_error)
    assert type(error.__cause__) is type(baseline_error.__cause__) is transport_error
    assert str(error.__cause__) == str(baseline_error.__cause__)
    assert stats == baseline_stats == {"request_count": 1, "prompt_tokens": 0, "completion_tokens": 0}
    assert len(of_type(events, "MODEL_REQUEST")) == 1
    assert len(of_type(events, "MODEL_ERROR")) == 1
    assert not of_type(events, "MODEL_PARSED")
    assert not of_type(events, "TOOL_RUNTIME_STARTED")
