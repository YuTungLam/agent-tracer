"""Groq Chat Completions adapter for the controlled two-stage agent pilot."""

from __future__ import annotations

import json
import os
import time
from importlib import metadata as package_metadata
from typing import Any, Callable, Mapping

from .domain import ModelCallMetadata, PreparedToolCall
from .llm import (
    BackendDecision,
    DEFAULT_SIMULATED_SINK_IDS,
    LLMBackendError,
    LLMRequest,
    MalformedModelResponse,
    PreludeRequest,
    SINK_FUNCTION_NAME,
    safe_backend_error,
    serialize_provider_context,
    sink_function_schema,
    source_function_schema,
    validated_provider_context,
)
from .utils import canonical_json, sha256_text, stable_identifier

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_PACKAGE = "groq"
PINNED_GROQ_VERSION = "1.6.0"
GROQ_API_VERSION = "openai/v1/chat/completions"
DEFAULT_GROQ_MIN_REQUEST_INTERVAL_SECONDS = 2.1
GROQ_TEMPERATURE = 1e-8
GROQ_TOOL_RESULT_FIELDS = (
    "confidential_token",
    "document_id",
    "operator_note",
    "public_answer",
)


def _openai_function_schema(
    schema: Mapping[str, Any],
) -> Mapping[str, Any]:
    required = {"type", "name", "description", "parameters"}
    if set(schema) != required or schema.get("type") != "function":
        raise ValueError("Unexpected provider-neutral function schema")
    return {
        "type": "function",
        "function": {
            "name": schema["name"],
            "description": schema["description"],
            "parameters": schema["parameters"],
        },
    }


def _groq_sink_function_schema(
    available_sink_ids: tuple[str, ...],
) -> Mapping[str, Any]:
    """Expose the same source-field constraint enforced by the local policy."""

    schema = sink_function_schema(available_sink_ids)
    parameters = schema["parameters"]
    properties = parameters["properties"]
    source_field = properties["source_field"]
    source_field["description"] = (
        "The exact document-tool result key from which value was copied."
    )
    source_field["enum"] = list(GROQ_TOOL_RESULT_FIELDS)
    return schema


def _groq_model_tool_schema_hash(
    available_sink_ids: tuple[str, ...],
) -> str:
    """Hash the exact OpenAI-compatible schemas visible to Groq."""

    return sha256_text(
        canonical_json(
            {
                "sink": _openai_function_schema(
                    _groq_sink_function_schema(available_sink_ids)
                ),
                "source_template": _openai_function_schema(
                    source_function_schema(
                        "synthetic_document_lookup",
                        {"query": "<matched-task-query>"},
                    )
                ),
            }
        )
    )


class GroqConfigurationError(ValueError):
    """The live adapter cannot be constructed safely."""


class _DuplicateJSONKey(ValueError):
    """A provider argument object contains an ambiguous duplicate key."""


class GroqBackend:
    """Use Groq local function calling without automatic tool execution."""

    provider_id = "groq"
    sdk_name = GROQ_PACKAGE
    api_version = GROQ_API_VERSION
    is_real_model = True
    sampling_parameters: Mapping[str, Any] = {
        "disable_tool_validation": False,
        "http_max_attempts_including_initial": 1,
        "parallel_tool_calls": False,
        "post_tool_max_completion_tokens": 1_024,
        "post_tool_tool_choice": "auto_sink_only",
        "pre_tool_max_completion_tokens": 512,
        "pre_tool_tool_choice": "required_specific_source",
        "request_min_interval_seconds": (
            DEFAULT_GROQ_MIN_REQUEST_INTERVAL_SECONDS
        ),
        "request_interval_cooldown_on_exit": True,
        "seed_determinism": "provider_best_effort",
        "seed_source": "matched_phase_seeds",
        "store_request": False,
        "provider_retention_guarantee": "not_asserted",
        "temperature": GROQ_TEMPERATURE,
        "timeout_seconds": 60.0,
    }
    model_tool_schema_hash = _groq_model_tool_schema_hash(
        DEFAULT_SIMULATED_SINK_IDS
    )

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_GROQ_MODEL,
        client: Any | None = None,
        api_key: str | None = None,
        sdk_version: str | None = None,
        min_request_interval_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not model_id.strip():
            raise GroqConfigurationError("Groq model ID must not be empty")
        if model_id.endswith("-latest") or model_id.endswith("/latest"):
            raise GroqConfigurationError(
                "Use a stable Groq model ID, not a moving latest alias"
            )
        self.model_id = model_id
        self.model_version: str | None = model_id
        self._secrets: tuple[str, ...] = ()
        resolved_interval = (
            (
                0.0
                if client is not None
                else DEFAULT_GROQ_MIN_REQUEST_INTERVAL_SECONDS
            )
            if min_request_interval_seconds is None
            else min_request_interval_seconds
        )
        if (
            isinstance(resolved_interval, bool)
            or not isinstance(resolved_interval, (int, float))
            or not 0 <= float(resolved_interval) <= 60
        ):
            raise GroqConfigurationError(
                "Groq minimum request interval must be between 0 and 60 seconds"
            )
        self._min_request_interval_seconds = float(resolved_interval)
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._last_request_started_at: float | None = None
        self._post_fingerprints_by_matched_set: dict[str, str] = {}
        self.sampling_parameters = {
            **type(self).sampling_parameters,
            "request_min_interval_seconds": (
                self._min_request_interval_seconds
            ),
        }

        if client is not None:
            self._client = client
            self.sdk_version = sdk_version or self._installed_sdk_version(
                fallback="injected-client"
            )
            if api_key:
                self._secrets = (api_key,)
            return

        resolved_key = api_key or os.environ.get("GROQ_API_KEY")
        if not resolved_key:
            raise GroqConfigurationError(
                "GROQ_API_KEY is not set; no live Groq request was made"
            )
        try:
            from groq import Groq
        except ImportError as exc:
            raise GroqConfigurationError(
                "Groq support is not installed; install the 'groq' extra"
            ) from exc

        installed_version = self._installed_sdk_version()
        if installed_version != PINNED_GROQ_VERSION:
            raise GroqConfigurationError(
                "Groq SDK version mismatch: expected "
                f"{PINNED_GROQ_VERSION}, found {installed_version}"
            )
        self._secrets = (resolved_key,)
        self.sdk_version = installed_version
        client_error: str | None = None
        try:
            self._client = Groq(
                api_key=resolved_key,
                max_retries=0,
                timeout=60.0,
            )
        except Exception as exc:
            client_error = safe_backend_error(
                exc,
                secrets=self._secrets,
            )
        if client_error is not None:
            raise GroqConfigurationError(client_error)

    @staticmethod
    def _installed_sdk_version(*, fallback: str | None = None) -> str:
        try:
            return package_metadata.version(GROQ_PACKAGE)
        except package_metadata.PackageNotFoundError:
            if fallback is not None:
                return fallback
            raise GroqConfigurationError(
                "Groq support is not installed; install the 'groq' extra"
            ) from None

    def _wait_for_request_slot(self) -> None:
        """Pace request starts without retrying any provider call."""

        now = self._monotonic()
        if self._last_request_started_at is not None:
            remaining = (
                self._min_request_interval_seconds
                - (now - self._last_request_started_at)
            )
            if remaining > 0:
                self._sleeper(remaining)
                now = self._monotonic()
        self._last_request_started_at = now

    def finish_request_schedule(self) -> None:
        """Leave one full interval after the last call for the next process."""

        if self._last_request_started_at is None:
            return
        remaining = (
            self._min_request_interval_seconds
            - (self._monotonic() - self._last_request_started_at)
        )
        if remaining > 0:
            self._sleeper(remaining)

    @staticmethod
    def model_tool_schema_hash_for(
        available_sink_ids: tuple[str, ...],
    ) -> str:
        return _groq_model_tool_schema_hash(available_sink_ids)

    def prepare_tool_call(
        self,
        request: PreludeRequest,
    ) -> PreparedToolCall:
        self._wait_for_request_slot()
        started_ns = time.perf_counter_ns()
        provider_error: str | None = None
        try:
            completion = self._client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {
                        "role": "system",
                        "content": request.system_instruction,
                    },
                    {
                        "role": "user",
                        "content": request.user_prompt,
                    },
                ],
                tools=[
                    _openai_function_schema(
                        request.source_tool_schema()
                    )
                ],
                tool_choice=self._specific_tool_choice(
                    request.source_tool_name
                ),
                disable_tool_validation=False,
                parallel_tool_calls=False,
                store=False,
                temperature=GROQ_TEMPERATURE,
                seed=request.seed,
                max_completion_tokens=self.sampling_parameters[
                    "pre_tool_max_completion_tokens"
                ],
            )
        except Exception as exc:
            provider_error = safe_backend_error(
                exc,
                secrets=self._secrets,
            )
        if provider_error is not None:
            raise LLMBackendError(provider_error)
        latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        return self._parse_prelude(
            completion,
            request=request,
            latency_ms=latency_ms,
        )

    def complete(
        self,
        request: LLMRequest,
        prepared: PreparedToolCall,
    ) -> BackendDecision:
        self._validate_branch_context(request, prepared)
        if request.sink_tool_choice_mode not in {"any", "validated"}:
            raise MalformedModelResponse(
                "Groq post-tool choice mode must be 'any' or 'validated'"
            )
        tool_choice: str | Mapping[str, Any] = (
            self._specific_tool_choice(SINK_FUNCTION_NAME)
            if request.sink_tool_choice_mode == "any"
            else "auto"
        )
        self._wait_for_request_slot()
        started_ns = time.perf_counter_ns()
        provider_error: str | None = None
        try:
            completion = self._client.chat.completions.create(
                model=self.model_id,
                messages=self._branch_messages(request, prepared),
                tools=[
                    _openai_function_schema(
                        _groq_sink_function_schema(
                            request.available_sink_ids
                        )
                    )
                ],
                tool_choice=tool_choice,
                disable_tool_validation=False,
                parallel_tool_calls=False,
                store=False,
                temperature=GROQ_TEMPERATURE,
                seed=request.seed,
                max_completion_tokens=self.sampling_parameters[
                    "post_tool_max_completion_tokens"
                ],
            )
        except Exception as exc:
            provider_error = safe_backend_error(
                exc,
                secrets=self._secrets,
            )
        if provider_error is not None:
            raise LLMBackendError(provider_error)
        latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        decision = self._parse_completion(
            completion,
            latency_ms=latency_ms,
            sink_action_required=(
                request.sink_tool_choice_mode == "any"
            ),
        )
        observed_fingerprint = decision.metadata.system_fingerprint
        if observed_fingerprint is None:
            raise MalformedModelResponse(
                "Groq post-tool response has no system fingerprint"
            )
        expected_fingerprint = self._post_fingerprints_by_matched_set.setdefault(
            request.matched_set_id,
            observed_fingerprint,
        )
        if observed_fingerprint != expected_fingerprint:
            raise MalformedModelResponse(
                "Groq post-tool system fingerprint changed within the matched set"
            )
        return decision

    def _parse_prelude(
        self,
        completion: Any,
        *,
        request: PreludeRequest,
        latency_ms: float,
    ) -> PreparedToolCall:
        choice = self._single_choice(completion, phase="prelude")
        message = getattr(choice, "message", None)
        if message is None:
            raise MalformedModelResponse(
                "Groq prelude response has no assistant message"
            )
        if self._message_text(message):
            raise MalformedModelResponse(
                "Groq prelude mixed answer text with its source-tool call"
            )
        tool_calls = list(getattr(message, "tool_calls", None) or ())
        if len(tool_calls) != 1:
            raise MalformedModelResponse(
                "Groq prelude must return exactly one source-tool call"
            )
        if self._optional_string(
            getattr(choice, "finish_reason", None)
        ) != "tool_calls":
            raise MalformedModelResponse(
                "Groq prelude did not finish with tool_calls"
            )
        call_id, function_name, arguments, raw_arguments = (
            self._parse_tool_call(
                tool_calls[0],
                phase="prelude source-tool",
            )
        )
        if function_name != request.source_tool_name:
            raise MalformedModelResponse(
                "Groq prelude selected an unexpected source tool"
            )
        if arguments != dict(request.source_tool_arguments):
            raise MalformedModelResponse(
                "Groq prelude changed the frozen source-tool arguments"
            )

        cache_key = request.cache_key(self)
        source_schema_hash = sha256_text(
            canonical_json(request.source_tool_schema())
        )
        provider_steps = (
            {
                "type": "function_call",
                "id": call_id,
                "name": function_name,
                "arguments": arguments,
                "arguments_json": raw_arguments,
            },
        )
        provider_context = (
            dict(request.user_input_step()),
            *provider_steps,
        )
        provider_context_json, provider_context_sha256 = (
            serialize_provider_context(provider_context)
        )
        model_call = self._model_call_metadata(
            completion,
            choice=choice,
            latency_ms=latency_ms,
        )
        if model_call.system_fingerprint is None:
            raise MalformedModelResponse(
                "Groq prelude response has no system fingerprint"
            )
        return PreparedToolCall(
            prelude_id=stable_identifier(
                "prelude",
                request.matched_set_id,
                cache_key,
                length=24,
            ),
            cache_key=cache_key,
            matched_set_id=request.matched_set_id,
            user_prompt_sha256=sha256_text(request.user_prompt),
            tool_name=request.source_tool_name,
            tool_arguments=arguments,
            arguments_sha256=sha256_text(canonical_json(arguments)),
            provider_call_id=call_id,
            source_tool_schema_hash=source_schema_hash,
            model_call=model_call,
            step_types=("function_call",),
            provider_context_json=provider_context_json,
            provider_context_sha256=provider_context_sha256,
            store=False,
        )

    def _parse_completion(
        self,
        completion: Any,
        *,
        latency_ms: float,
        sink_action_required: bool,
    ) -> BackendDecision:
        choice = self._single_choice(completion, phase="post-tool")
        message = getattr(choice, "message", None)
        if message is None:
            raise MalformedModelResponse(
                "Groq post-tool response has no assistant message"
            )
        text_answer = self._message_text(message)
        tool_calls = list(getattr(message, "tool_calls", None) or ())
        if len(tool_calls) > 1:
            raise MalformedModelResponse(
                "Groq returned more than one function call in a one-step policy"
            )
        finish_reason = self._optional_string(
            getattr(choice, "finish_reason", None)
        )
        sink_action: Mapping[str, Any] | None = None

        if tool_calls:
            if finish_reason != "tool_calls":
                raise MalformedModelResponse(
                    "Groq function call did not finish with tool_calls"
                )
            _, function_name, raw_arguments, _ = self._parse_tool_call(
                tool_calls[0],
                phase="post-tool sink",
            )
            if function_name != SINK_FUNCTION_NAME:
                raise MalformedModelResponse(
                    "Groq returned an unexpected function name"
                )
            required = {
                "final_answer",
                "sink_id",
                "source_field",
                "value",
            }
            missing = sorted(required - set(raw_arguments))
            unknown = sorted(set(raw_arguments) - required)
            if missing:
                raise MalformedModelResponse(
                    "Groq function call is missing fields: "
                    f"{', '.join(missing)}"
                )
            if unknown:
                raise MalformedModelResponse(
                    "Groq function call has unknown fields: "
                    f"{', '.join(unknown)}"
                )
            function_answer = raw_arguments["final_answer"]
            if (
                not isinstance(function_answer, str)
                or not function_answer.strip()
            ):
                raise MalformedModelResponse(
                    "Groq function call final_answer must be a non-empty string"
                )
            answer = function_answer.strip()
            if text_answer and text_answer != answer:
                raise MalformedModelResponse(
                    "Groq returned conflicting text and function-call answers"
                )
            sink_action = {
                "sink_id": raw_arguments["sink_id"],
                "operation": SINK_FUNCTION_NAME,
                "source_field": raw_arguments["source_field"],
                "value": raw_arguments["value"],
            }
        else:
            if sink_action_required:
                raise MalformedModelResponse(
                    "Groq required sink tool choice returned no function call"
                )
            if finish_reason != "stop":
                raise MalformedModelResponse(
                    "Groq text response did not finish normally"
                )
            if not text_answer:
                raise MalformedModelResponse(
                    "Groq returned neither answer text nor a function call"
                )
            answer = text_answer

        return BackendDecision(
            answer=answer,
            sink_action=sink_action,
            metadata=self._model_call_metadata(
                completion,
                choice=choice,
                latency_ms=latency_ms,
            ),
        )

    def _validate_branch_context(
        self,
        request: LLMRequest,
        prepared: PreparedToolCall,
    ) -> None:
        if prepared.store:
            raise MalformedModelResponse(
                "Groq branch context must use store=False"
            )
        if prepared.model_call.system_fingerprint is None:
            raise MalformedModelResponse(
                "Groq prepared context has no system fingerprint"
            )
        if request.matched_set_id != prepared.matched_set_id:
            raise MalformedModelResponse(
                "Groq branch changed the matched-set identity"
            )
        if sha256_text(request.user_prompt) != prepared.user_prompt_sha256:
            raise MalformedModelResponse(
                "Groq branch changed the matched-set user prompt"
            )
        if request.source_tool_name != prepared.tool_name:
            raise MalformedModelResponse(
                "Groq branch changed the source tool name"
            )
        if (
            dict(request.source_tool_arguments)
            != dict(prepared.tool_arguments)
        ):
            raise MalformedModelResponse(
                "Groq branch changed the source-tool arguments"
            )
        if request.source_tool_call_id != prepared.provider_call_id:
            raise MalformedModelResponse(
                "Groq branch changed the provider source-tool call ID"
            )
        expected_schema_hash = sha256_text(
            canonical_json(
                source_function_schema(
                    prepared.tool_name,
                    prepared.tool_arguments,
                )
            )
        )
        if prepared.source_tool_schema_hash != expected_schema_hash:
            raise MalformedModelResponse(
                "Groq branch changed the source-tool schema"
            )
        validated_provider_context(
            prepared,
            expected_user_prompt=request.user_prompt,
        )

    def _branch_messages(
        self,
        request: LLMRequest,
        prepared: PreparedToolCall,
    ) -> list[Mapping[str, Any]]:
        context = validated_provider_context(
            prepared,
            expected_user_prompt=request.user_prompt,
        )
        function_call = context[-1]
        raw_arguments = function_call.get("arguments_json")
        if not isinstance(raw_arguments, str) or not raw_arguments:
            raise MalformedModelResponse(
                "Groq prelude context omitted native argument JSON"
            )
        parsed_arguments = self._parse_arguments_json(
            raw_arguments,
            phase="stored source-tool",
        )
        if parsed_arguments != dict(prepared.tool_arguments):
            raise MalformedModelResponse(
                "Groq stored source-tool arguments changed"
            )
        return [
            {
                "role": "system",
                "content": request.system_instruction,
            },
            {
                "role": "user",
                "content": request.user_prompt,
            },
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": prepared.provider_call_id,
                        "type": "function",
                        "function": {
                            "name": prepared.tool_name,
                            "arguments": raw_arguments,
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": prepared.provider_call_id,
                "name": prepared.tool_name,
                "content": canonical_json(dict(request.tool_payload)),
            },
        ]

    def _model_call_metadata(
        self,
        completion: Any,
        *,
        choice: Any,
        latency_ms: float,
    ) -> ModelCallMetadata:
        observed_model = self._optional_string(
            getattr(completion, "model", None)
        )
        if observed_model is not None and observed_model != self.model_id:
            raise MalformedModelResponse(
                "Groq response model differs from the configured model ID"
            )
        usage = getattr(completion, "usage", None)
        completion_details = (
            getattr(usage, "completion_tokens_details", None)
            if usage is not None
            else None
        )
        prompt_details = (
            getattr(usage, "prompt_tokens_details", None)
            if usage is not None
            else None
        )
        return ModelCallMetadata(
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=observed_model or self.model_version,
            sdk_name=self.sdk_name,
            sdk_version=self.sdk_version,
            api_version=self.api_version,
            response_id=self._optional_string(
                getattr(completion, "id", None)
            ),
            response_status="completed",
            finish_reason=self._optional_string(
                getattr(choice, "finish_reason", None)
            ),
            latency_ms=latency_ms,
            input_tokens=self._usage_value(usage, "prompt_tokens"),
            output_tokens=self._usage_value(usage, "completion_tokens"),
            thought_tokens=self._usage_value(
                completion_details,
                "reasoning_tokens",
            ),
            cached_tokens=self._usage_value(
                prompt_details,
                "cached_tokens",
            ),
            total_tokens=self._usage_value(usage, "total_tokens"),
            system_fingerprint=self._optional_string(
                getattr(completion, "system_fingerprint", None)
            ),
        )

    @staticmethod
    def _single_choice(completion: Any, *, phase: str) -> Any:
        choices = list(getattr(completion, "choices", None) or ())
        if len(choices) != 1:
            raise MalformedModelResponse(
                f"Groq {phase} response must contain exactly one choice"
            )
        return choices[0]

    @classmethod
    def _parse_tool_call(
        cls,
        tool_call: Any,
        *,
        phase: str,
    ) -> tuple[str, str, Mapping[str, Any], str]:
        call_id = cls._optional_string(getattr(tool_call, "id", None))
        if call_id is None:
            raise MalformedModelResponse(
                f"Groq {phase} call has no call ID"
            )
        call_type = cls._optional_string(
            getattr(tool_call, "type", None)
        )
        if call_type is not None and call_type != "function":
            raise MalformedModelResponse(
                f"Groq {phase} returned a non-function tool call"
            )
        function = getattr(tool_call, "function", None)
        if function is None:
            raise MalformedModelResponse(
                f"Groq {phase} call has no function object"
            )
        name = cls._optional_string(getattr(function, "name", None))
        if name is None:
            raise MalformedModelResponse(
                f"Groq {phase} call has no function name"
            )
        raw_arguments = getattr(function, "arguments", None)
        if not isinstance(raw_arguments, str) or not raw_arguments:
            raise MalformedModelResponse(
                f"Groq {phase} arguments must be a JSON string"
            )
        arguments = cls._parse_arguments_json(
            raw_arguments,
            phase=phase,
        )
        return call_id, name, arguments, raw_arguments

    @staticmethod
    def _parse_arguments_json(
        raw_arguments: str,
        *,
        phase: str,
    ) -> Mapping[str, Any]:
        def reject_duplicates(
            pairs: list[tuple[str, Any]],
        ) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise _DuplicateJSONKey(key)
                value[key] = item
            return value

        try:
            value = json.loads(
                raw_arguments,
                object_pairs_hook=reject_duplicates,
            )
        except (_DuplicateJSONKey, json.JSONDecodeError, TypeError):
            raise MalformedModelResponse(
                f"Groq {phase} arguments are not an unambiguous JSON object"
            ) from None
        if not isinstance(value, dict):
            raise MalformedModelResponse(
                f"Groq {phase} arguments must decode to an object"
            )
        return value

    @staticmethod
    def _specific_tool_choice(name: str) -> Mapping[str, Any]:
        return {
            "type": "function",
            "function": {"name": name},
        }

    @staticmethod
    def _message_text(message: Any) -> str:
        content = getattr(message, "content", None)
        return content.strip() if isinstance(content, str) else ""

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _usage_value(usage: object, field: str) -> int | None:
        if usage is None:
            return None
        value = getattr(usage, field, None)
        return value if isinstance(value, int) and value >= 0 else None
