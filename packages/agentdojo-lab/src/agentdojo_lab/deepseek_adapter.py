"""DeepSeek Flash transport for AgentDojo's native tool execution pipeline.

This adapter uses DeepSeek's OpenAI-compatible Chat Completions API. Thinking is
explicitly disabled because the pinned AgentDojo message type does not retain
``reasoning_content`` for the next tool round, which DeepSeek requires when
thinking and tools are combined.
"""

from collections.abc import Sequence
from typing import cast

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

DEEPSEEK_FLASH_MODEL = "deepseek-flash"


def _message_to_deepseek(message: ChatMessage) -> ChatCompletionMessageParam:
    """Reuse pinned AgentDojo conversion and adapt its wire roles/content."""
    serialized = dict(_message_to_openai(message, DEEPSEEK_FLASH_MODEL))
    # DeepSeek Chat Completions accepts system, user, assistant and tool roles.
    if serialized["role"] == "developer":
        serialized["role"] = "system"
    # The native tool serializer adds `name`, which DeepSeek does not list for
    # tool messages. The call ID already identifies the matching tool output.
    if serialized["role"] == "tool":
        serialized.pop("name", None)
    content = serialized.get("content")
    if isinstance(content, list):
        serialized["content"] = "\n".join(block["text"] for block in content)
    return cast(ChatCompletionMessageParam, serialized)


class DeepSeekLLM(BasePipelineElement):
    """One DeepSeek API request per query, without adapter-level retries."""

    def __init__(
        self,
        client: openai.OpenAI,
        model: str = DEEPSEEK_FLASH_MODEL,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        observer: ObservationSession | None = None,
        pacer: RequestPacer | None = None,
    ) -> None:
        if model != DEEPSEEK_FLASH_MODEL:
            raise ValueError(f"DeepSeekLLM requires model {DEEPSEEK_FLASH_MODEL}")
        if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
            raise ValueError("temperature must be a number between 0 and 2")
        if not 0.0 <= temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        self.client = client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.observer = observer
        self.pacer = pacer
        self.name = f"deepseek_{model}"
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
        deepseek_messages = [_message_to_deepseek(message) for message in messages]
        deepseek_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        ticket = None
        if self.pacer is not None:
            ticket, waited = self.pacer.before_request(deepseek_messages, deepseek_tools)
            self.stats["pacing_wait_seconds"] += waited
        self.stats["request_count"] += 1
        if self.observer is not None:
            self.observer.begin_model_call(messages)
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=deepseek_messages,
                tools=deepseek_tools or NOT_GIVEN,
                tool_choice="auto" if deepseek_tools else NOT_GIVEN,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                extra_body={"thinking": {"type": "disabled"}},
            )
            if completion.usage is not None:
                self.stats["prompt_tokens"] += completion.usage.prompt_tokens
                self.stats["completion_tokens"] += completion.usage.completion_tokens
            if self.pacer is not None:
                self.pacer.after_response(ticket, completion.usage.total_tokens if completion.usage else None)
            if not completion.choices:
                raise ValueError("DeepSeek returned no completion choices")
            output = _openai_to_assistant_message(completion.choices[0].message)
        except BaseException as exc:
            key = getattr(self.client, "api_key", "")
            if isinstance(exc, openai.APIError) and key:
                exc.message = str(exc).replace(key, "[REDACTED]")
                exc.args = (exc.message,)
            if self.observer is not None:
                self.observer.model_failed(exc)
            raise
        if self.observer is not None:
            self.observer.model_parsed(output)
        return query, runtime, env, [*messages, output], extra_args if extra_args is not None else {}
