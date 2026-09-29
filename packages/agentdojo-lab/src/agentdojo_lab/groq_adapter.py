"""Groq transport for AgentDojo's native pipeline and tool runtime.

The private serializers imported below intentionally match AgentDojo commit
089ed468cf3ed0322acc66b0211f26d9d90dbf60. Recheck this adapter and its wire-format
tests before changing that pin. Groq's compatibility contract is documented at
https://console.groq.com/docs/openai.
"""

from collections.abc import Sequence
from typing import Literal, cast

import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from openai._types import NOT_GIVEN
from openai.types.chat import ChatCompletionMessageParam

from agentdojo_lab.observation import ObservationSession
from agentdojo_lab.pacing import RequestPacer
from agentdojo_lab.providers import Provider

ReasoningEffort = Literal["low", "medium", "high"]


def _message_to_groq(message: ChatMessage, model: str) -> ChatCompletionMessageParam:
    """Adapt a newly serialized message without modifying native history.

    Text blocks use AgentDojo's plain-text convention: a newline between blocks,
    with each block's text preserved verbatim. Tool errors retain the upstream
    serializer's error-content handling. No tool output is filtered or rewritten.
    """
    serialized = dict(_message_to_openai(message, model))
    # Groq rejects messages[].name, including names on tool result messages.
    serialized.pop("name", None)
    if serialized["role"] == "developer":
        serialized["role"] = "system"
    content = serialized.get("content")
    if isinstance(content, list):
        serialized["content"] = "\n".join(block["text"] for block in content)
    return cast(ChatCompletionMessageParam, serialized)


class GroqLLM(BasePipelineElement):
    """One Groq completion per query, with retries/timeouts owned by the client.

    ``stats.request_count`` (stored as a dictionary key) counts SDK invocations,
    including failed attempts. Token totals include only API-reported usage.
    This class adds no retry loop; pass ``max_retries=0`` to the OpenAI client
    when one HTTP attempt per query is required.
    """

    def __init__(
        self,
        client: openai.OpenAI,
        model: str,
        temperature: float = 0.0,
        max_completion_tokens: int = 4096,
        reasoning_effort: ReasoningEffort | None = None,
        observer: ObservationSession | None = None,
        pacer: RequestPacer | None = None,
        provider: Provider = "groq",
    ) -> None:
        if not model or not model.strip():
            raise ValueError("model must be a non-empty Groq model ID")
        if not 0.0 <= temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if isinstance(max_completion_tokens, bool) or not isinstance(max_completion_tokens, int):
            raise ValueError("max_completion_tokens must be a positive integer")
        if max_completion_tokens < 1:
            raise ValueError("max_completion_tokens must be a positive integer")
        if reasoning_effort not in (None, "low", "medium", "high"):
            raise ValueError("reasoning_effort must be low, medium, high, or None")
        self.client = client
        self.model = model
        self.temperature = temperature
        self.max_completion_tokens = max_completion_tokens
        self.reasoning_effort = reasoning_effort
        self.observer = observer
        self.pacer = pacer
        if provider not in ("groq", "openai_compatible"):
            raise ValueError("Unsupported completion provider")
        self.provider = provider
        self.name = f"{provider}_{model}"
        self.stats = {"request_count": 0, "prompt_tokens": 0, "completion_tokens": 0}
        if pacer is not None:
            self.stats["pacing_wait_seconds"] = 0.0

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        groq_messages = [_message_to_groq(message, self.model) for message in messages]
        groq_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        ticket = None
        if self.pacer is not None:
            ticket, waited = self.pacer.before_request(groq_messages, groq_tools)
            self.stats["pacing_wait_seconds"] += waited
        self.stats["request_count"] += 1
        if self.observer is not None:
            self.observer.begin_model_call(messages)
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=groq_messages,
                tools=groq_tools or NOT_GIVEN,
                tool_choice="auto" if groq_tools else NOT_GIVEN,
                temperature=self.temperature,
                max_completion_tokens=self.max_completion_tokens,
                reasoning_effort=self.reasoning_effort or NOT_GIVEN,
            )
            if completion.usage is not None:
                self.stats["prompt_tokens"] += completion.usage.prompt_tokens
                self.stats["completion_tokens"] += completion.usage.completion_tokens
            if self.pacer is not None:
                self.pacer.after_response(ticket, completion.usage.total_tokens if completion.usage else None)
            if not completion.choices:
                raise ValueError("Groq returned no completion choices")
            output = _openai_to_assistant_message(completion.choices[0].message)
        except BaseException as exc:
            # Native AgentDojo can persist str(APIError). A local service's error
            # response must not copy the configured bearer key into that log.
            key = getattr(self.client, "api_key", "")
            if self.provider == "openai_compatible" and isinstance(exc, openai.APIError) and key:
                exc.message = str(exc).replace(key, "[REDACTED]")
                exc.args = (exc.message,)
            if self.observer is not None:
                self.observer.model_failed(exc)
            raise
        if self.observer is not None:
            self.observer.model_parsed(output)
        return query, runtime, env, [*messages, output], extra_args if extra_args is not None else {}
