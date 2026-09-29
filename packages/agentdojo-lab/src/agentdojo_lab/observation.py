"""Passive observations at the HTTP, native pipeline and top-level runtime boundaries.

An outbound request is observable; server receipt/model attention is not. Runtime
arguments are captured before the runtime's own validation/defaults/dependencies.
Nested runtime calls are outside this initial recorder's scope.
"""

import copy
import hashlib
import json
from functools import wraps

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv
from agentdojo.logging import Logger

from agentdojo_lab.recording import EventRecorder


def observational(method):
    """Instrumentation must never turn a recording error into a new agent error."""

    @wraps(method)
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as exc:
            self.errors.append(f"{method.__name__}: {type(exc).__name__}")
            return None

    return guarded


class ObservationSession:
    def __init__(self, recorder: EventRecorder, *, canary=None):
        self.recorder = recorder
        self.errors = []
        self.canary = canary
        self.task_id = None
        self.episode_id = None
        self.episode_event = None
        self.request_id = None
        self.request_event = None
        self.response_event = None
        self.input_messages = ()
        self.calls = {}
        self.tool_messages = {}
        self.attached_clients = []

    def emit(self, event_type, data, *, entry=None, parents=()):
        entry = entry or {}
        return self.recorder.emit(
            event_type,
            data,
            task_id=self.task_id,
            episode_id=self.episode_id,
            model_request_id=entry.get("model_request_id", self.request_id),
            tool_call_id=entry.get("tool_call_id"),
            call_ref=entry.get("call_ref"),
            parent_event_ids=[p for p in parents if p is not None],
        )

    def status(self):
        status = self.recorder.status()
        return {
            **status,
            "complete": status["complete"]
            and not self.errors
            and (self.canary is None or self.canary.status()["complete"]),
            "observer_errors": list(self.errors),
            **({"canary": self.canary.status()} if self.canary is not None else {}),
        }

    @observational
    def attach(self, client):
        # The pinned OpenAI SDK exposes its injected HTTPX client here. Tests
        # exercise actual serialized bodies, including the second tool round.
        if client in self.attached_clients:
            return
        client._client.event_hooks["request"].append(self.on_request)
        client._client.event_hooks["response"].append(self.on_response)
        self.attached_clients.append(client)

    @observational
    def start_episode(self, env, messages):
        context = getattr(Logger.get(), "context", {})
        # Only identity metadata; never pull evaluator results into online data.
        self.task_id = context.get("user_task_id")
        self.episode_id = self.recorder.new_id("episode")
        self.request_id = self.request_event = self.response_event = None
        self.calls = {}
        self.tool_messages = {}
        self.episode_event = self.emit(
            "EPISODE_STARTED",
            {
                "suite": context.get("suite_name"),
                "initial_history_length": len(messages),
                "environment": env,
            },
        )

    @observational
    def end_episode(self, error=None):
        self.emit(
            "EPISODE_ENDED",
            {
                "status": "error" if error else "returned",
                "error_type": type(error).__name__ if error else None,
            },
            parents=[self.episode_event],
        )

    @observational
    def begin_model_call(self, messages):
        self.request_id = self.recorder.new_id("request")
        self.request_event = self.response_event = None
        self.input_messages = messages

    @observational
    def on_request(self, request):
        raw = request.content
        body = json.loads(raw)
        self.request_event = self.emit(
            "MODEL_REQUEST",
            {
                "body": body,
                "body_sha256": hashlib.sha256(raw).hexdigest(),
                "body_bytes": len(raw),
                "method": request.method,
                "path": request.url.path,
            },
            parents=[self.episode_event],
        )
        for index, message in enumerate(body.get("messages", [])):
            if message.get("role") != "tool":
                continue
            native_message = self.input_messages[index]
            record = self.tool_messages.get(id(native_message), {})
            entry = {**record.get("entry", {}), "model_request_id": self.request_id}
            self.emit(
                "TOOL_OUTPUT_EXPOSED",
                {
                    "message_index": index,
                    "message": message,
                    "semantics": "included_in_outbound_request; server receipt is not asserted",
                    "source_result_event_id": record.get("event_id"),
                },
                entry=entry,
                parents=[self.request_event, record.get("event_id")],
            )

    def on_response(self, response):
        # HTTPX also reads here immediately after hooks for these nonstreaming
        # requests. Preserve transport failures for the SDK's normal wrapping;
        # swallowing one would make its next read raise StreamConsumed instead.
        raw = response.read()
        self.record_response(response, raw)

    @observational
    def record_response(self, response, raw):
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            body = {"non_json_body": raw.decode("utf-8", errors="replace")}
        self.response_event = self.emit(
            "MODEL_RESPONSE",
            {
                "status_code": response.status_code,
                "body": body,
                "body_sha256": hashlib.sha256(raw).hexdigest(),
                "body_bytes": len(raw),
            },
            parents=[self.request_event],
        )

    @observational
    def model_parsed(self, output):
        calls = output.get("tool_calls") or []
        parsed = self.emit("MODEL_PARSED", {"tool_call_count": len(calls)}, parents=[self.response_event])
        for index, call in enumerate(calls):
            entry = {
                "call_ref": self.recorder.new_id("call"),
                "tool_call_id": call.id,
                "model_request_id": self.request_id,
            }
            event_id = self.emit(
                "TOOL_CALL_PROPOSED",
                {
                    "call_index": index,
                    "function": call.function,
                    "arguments": call.args,
                },
                entry=entry,
                parents=[parsed, self.request_event],
            )
            # Keep the object alive so an id cannot be reused within the episode.
            self.calls[id(call)] = {"object": call, "entry": entry, "proposal_event": event_id}

    @observational
    def model_failed(self, error):
        self.emit(
            "MODEL_ERROR",
            {"error_type": type(error).__name__},
            parents=[self.request_event, self.response_event],
        )

    @observational
    def before_runtime(self, call, env, function, args):
        record = self.calls.get(id(call), {})
        event_id = self.emit(
            "TOOL_RUNTIME_STARTED",
            {
                "function": function,
                "runtime_input_args": args,
                "boundary": "top-level FunctionsRuntime.run_function; before internal validation",
            },
            entry=record.get("entry"),
            parents=[record.get("proposal_event")],
        )
        before = env.model_dump(mode="json")
        return {**record, "start_event": event_id, "before": before}

    @observational
    def after_runtime(self, call, record, env, *, result=None, error=None, raised=None):
        record = record or self.calls.get(id(call), {})
        event_id = self.emit(
            "TOOL_RUNTIME_RETURNED",
            {
                "result": result,
                "error": error,
                "raised_exception_type": type(raised).__name__ if raised else None,
            },
            entry=record.get("entry"),
            parents=[record.get("start_event")],
        )
        # Serialize the raw result before any later call can mutate its objects.
        if id(call) in self.calls:
            self.calls[id(call)]["runtime_return_event"] = event_id
        after = env.model_dump(mode="json")
        before = record.get("before")
        if before != after:
            self.emit(
                "ENVIRONMENT_CHANGE",
                {"before": before, "after": after},
                entry=record.get("entry"),
                parents=[event_id],
            )

    @observational
    def tool_result(self, message, intervention_event_id=None):
        record = self.calls.get(id(message["tool_call"]), {})
        event_id = self.emit(
            "TOOL_RESULT",
            {
                "message": message,
                "runtime_entered": "runtime_return_event" in record,
                **({"intervention_event_id": intervention_event_id} if self.canary is not None else {}),
            },
            entry=record.get("entry"),
            parents=[record.get("proposal_event"), record.get("runtime_return_event"), intervention_event_id],
        )
        self.tool_messages[id(message)] = {
            "object": message,
            "entry": record.get("entry", {}),
            "event_id": event_id,
        }

    @observational
    def prepare_tool_result(self, message):
        """Apply an explicitly configured, audited source-text intervention once."""
        if self.canary is None:
            return message, None
        call = message["tool_call"]
        record = self.calls.get(id(call), {})
        audit = self.canary.prepare(
            message,
            run_id=self.recorder.run_id,
            episode_id=self.episode_id,
            call_ref=record.get("entry", {}).get("call_ref"),
            function=call.function,
            runtime_entered="runtime_return_event" in record,
        )
        event_id = self.emit(
            "TOOL_OUTPUT_INTERVENTION",
            audit,
            entry=record.get("entry"),
            parents=[record.get("proposal_event"), record.get("runtime_return_event")],
        )
        if event_id is None:
            self.canary.fail("audit", RuntimeError("Intervention audit was not persisted"))
            return message, None
        if audit["status"] == "assigned":
            # Preserve the original call object so all runtime links retain identity.
            message = {**message, "content": copy.deepcopy(audit["marked_content"])}
        return message, event_id


class _RuntimeView:
    """Delegate all native behavior; observe only external runtime entry calls."""

    def __init__(self, runtime, observer, calls):
        self.original = runtime
        self.observer = observer
        self.calls = iter(calls)

    def __getattr__(self, name):
        return getattr(self.original, name)

    def run_function(self, env, function, args, *rest, **kwargs):
        call = next(self.calls)
        record = self.observer.before_runtime(call, env, function, args)
        try:
            result, error = self.original.run_function(env, function, args, *rest, **kwargs)
        except BaseException as exc:
            self.observer.after_runtime(call, record, env, raised=exc)
            raise
        self.observer.after_runtime(call, record, env, result=result, error=error)
        return result, error


class ObservedToolsExecutor(BasePipelineElement):
    def __init__(self, executor, observer):
        self.executor = executor
        self.observer = observer

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        calls = (messages[-1].get("tool_calls") or []) if messages else []
        # Native executor only enters runtime for registered, nonempty names.
        names = {tool.name for tool in runtime.functions.values()}
        valid = [call for call in calls if call.function in names and call.function != EMPTY_FUNCTION_NAME]
        view = _RuntimeView(runtime, self.observer, valid)
        output = self.executor.query(query, view, env, messages, extra_args if extra_args is not None else {})
        observed_messages = list(output[3]) if self.observer.canary is not None else output[3]
        for index in range(len(messages), len(observed_messages)):
            message = observed_messages[index]
            if message["role"] == "tool":
                if self.observer.canary is not None:
                    prepared = self.observer.prepare_tool_result(message)
                    message, intervention_id = prepared if prepared is not None else (message, None)
                    observed_messages[index] = message
                    self.observer.tool_result(message, intervention_id)
                else:
                    self.observer.tool_result(message)
        # Downstream consumers receive the original runtime object, not the proxy.
        return output[0], runtime, output[2], observed_messages, output[4]


class ObservedPipeline(BasePipelineElement):
    def __init__(self, pipeline, observer):
        self.pipeline = pipeline
        self.observer = observer
        self.name = pipeline.name

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        self.observer.start_episode(env, messages)
        try:
            result = self.pipeline.query(
                query, runtime, env, messages, extra_args if extra_args is not None else {}
            )
        except BaseException as exc:
            self.observer.end_episode(error=exc)
            raise
        self.observer.end_episode()
        return result


def observe_pipeline(pipeline, observer):
    """Instrument a freshly constructed pipeline without editing upstream code."""
    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.elements = [
                ObservedToolsExecutor(child, observer) if isinstance(child, ToolsExecutor) else child
                for child in element.elements
            ]
    return ObservedPipeline(pipeline, observer)
