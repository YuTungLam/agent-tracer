"""Google Gemini adapter for the controlled two-stage agent pilot."""

from __future__ import annotations

import os
import time
from importlib import metadata as package_metadata
from typing import Any, Callable, Mapping

from .domain import ModelCallMetadata, PreparedToolCall
from .llm import (
    ActionDecision,
    ActionRequest,
    BackendDecision,
    DEFAULT_SIMULATED_SINK_IDS,
    LLMRequest,
    MalformedModelResponse,
    PreludeRequest,
    ProviderRequestError,
    SINK_FUNCTION_NAME,
    safe_backend_error,
    serialize_provider_context,
    sink_function_schema,
    source_function_schema,
    validate_action_arguments,
    validate_action_prepared_context,
    validated_action_decision,
    validated_action_function_schema,
    validated_provider_context,
)
from .utils import canonical_json, sha256_text, stable_identifier

DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"
GOOGLE_GENAI_PACKAGE = "google-genai"
PINNED_GOOGLE_GENAI_VERSION = "2.13.0"
GEMINI_API_VERSION = "v1"
TERMINAL_INTERACTION_STATUSES = {"completed", "requires_action"}
DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS = 13.0


class GeminiConfigurationError(ValueError):
    """The live adapter cannot be constructed safely."""


class GeminiBackend:
    """Use Gemini Interactions without automatic or external tool execution."""

    provider_id = "google-gemini"
    sdk_name = GOOGLE_GENAI_PACKAGE
    api_version = GEMINI_API_VERSION
    is_real_model = True
    is_empirical_backend = True
    sampling_parameters: Mapping[str, Any] = {
        "http_max_attempts_including_initial": 1,
        "post_tool_max_output_tokens": 1_024,
        "post_tool_thinking_level": "medium",
        "post_tool_tool_choice": "validated_sink_only",
        "pre_tool_max_output_tokens": 512,
        "pre_tool_thinking_level": "medium",
        "pre_tool_tool_choice": "any_source_only",
        "request_min_interval_seconds": (
            DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS
        ),
        "request_interval_cooldown_on_exit": True,
        "seed_source": "matched_phase_seeds",
        "store": False,
    }
    model_tool_schema_hash = sha256_text(
        canonical_json(
            {
                "sink": sink_function_schema(
                    DEFAULT_SIMULATED_SINK_IDS
                ),
                "source_template": source_function_schema(
                    "synthetic_document_lookup",
                    {"query": "<matched-task-query>"},
                ),
            }
        )
    )

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_GEMINI_MODEL,
        client: Any | None = None,
        api_key: str | None = None,
        sdk_version: str | None = None,
        min_request_interval_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not model_id.strip():
            raise GeminiConfigurationError("Gemini model ID must not be empty")
        if model_id.endswith("-latest") or model_id.endswith("/latest"):
            raise GeminiConfigurationError(
                "Use a stable Gemini model ID, not a moving latest alias"
            )
        self.model_id = model_id
        self.model_version: str | None = model_id
        self._secrets: tuple[str, ...] = ()
        self.real_provider_invoked = False
        self.provider_invocation_count = 0
        self.provider_request_attempt_count = 0
        self.is_empirical_backend = False
        self.is_real_model = False
        resolved_interval = (
            (
                0.0
                if client is not None
                else DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS
            )
            if min_request_interval_seconds is None
            else min_request_interval_seconds
        )
        if (
            isinstance(resolved_interval, bool)
            or not isinstance(resolved_interval, (int, float))
            or not 0 <= float(resolved_interval) <= 60
        ):
            raise GeminiConfigurationError(
                "Gemini minimum request interval must be between 0 and 60 seconds"
            )
        self._min_request_interval_seconds = float(resolved_interval)
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._last_request_started_at: float | None = None
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

        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise GeminiConfigurationError(
                "GEMINI_API_KEY is not set; no live Gemini request was made"
            )
        try:
            from google import genai
        except ImportError as exc:
            raise GeminiConfigurationError(
                "Gemini support is not installed; install the 'gemini' extra"
            ) from exc

        installed_version = self._installed_sdk_version()
        if installed_version != PINNED_GOOGLE_GENAI_VERSION:
            raise GeminiConfigurationError(
                "Gemini SDK version mismatch: expected "
                f"{PINNED_GOOGLE_GENAI_VERSION}, found {installed_version}"
            )
        self._secrets = (resolved_key,)
        self.sdk_version = installed_version
        client_error: str | None = None
        try:
            client_factory = genai.Client
            self._client = client_factory(
                api_key=resolved_key,
                http_options={
                    "api_version": self.api_version,
                    "retry_options": {"attempts": 1},
                    "timeout": 120_000,
                },
            )
        except Exception as exc:
            client_error = safe_backend_error(exc, secrets=self._secrets)
        if client_error is not None:
            raise GeminiConfigurationError(client_error)
        self.is_empirical_backend = (
            isinstance(client_factory, type)
            and isinstance(self._client, client_factory)
        )
        self.is_real_model = self.is_empirical_backend

    @staticmethod
    def _installed_sdk_version(*, fallback: str | None = None) -> str:
        try:
            return package_metadata.version(GOOGLE_GENAI_PACKAGE)
        except package_metadata.PackageNotFoundError:
            if fallback is not None:
                return fallback
            raise GeminiConfigurationError(
                "Gemini support is not installed; install the 'gemini' extra"
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

    def _record_successful_provider_invocation(self) -> None:
        """Record only a returned live-SDK request, never an attempted call."""

        if self.is_empirical_backend:
            self.provider_invocation_count += 1
            self.real_provider_invoked = True

    def _record_provider_request_attempt(self) -> None:
        """Count each SDK request once, including a failed initial attempt."""

        self.provider_request_attempt_count += 1

    @staticmethod
    def _provider_status_code(error: BaseException) -> int | None:
        """Extract a status code without retaining the provider exception."""

        candidates = (
            getattr(error, "status_code", None),
            getattr(error, "code", None),
            getattr(getattr(error, "response", None), "status_code", None),
        )
        for value in candidates:
            if isinstance(value, bool):
                continue
            if isinstance(value, int) and 100 <= value <= 599:
                return value
            if isinstance(value, str) and value.isdigit():
                parsed = int(value)
                if 100 <= parsed <= 599:
                    return parsed
        return None

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
        return sha256_text(
            canonical_json(
                {
                    "sink": sink_function_schema(available_sink_ids),
                    "source_template": source_function_schema(
                        "synthetic_document_lookup",
                        {"query": "<matched-task-query>"},
                    ),
                }
            )
        )

    def prepare_tool_call(
        self,
        request: PreludeRequest,
    ) -> PreparedToolCall:
        self._wait_for_request_slot()
        started_ns = time.perf_counter_ns()
        provider_error: str | None = None
        provider_status_code: int | None = None
        self._record_provider_request_attempt()
        try:
            interaction = self._client.interactions.create(
                model=self.model_id,
                input=[request.user_input_step()],
                system_instruction=request.system_instruction,
                store=False,
                tools=[request.source_tool_schema()],
                generation_config={
                    "max_output_tokens": self.sampling_parameters[
                        "pre_tool_max_output_tokens"
                    ],
                    "seed": request.seed,
                    "thinking_level": self.sampling_parameters[
                        "pre_tool_thinking_level"
                    ],
                    "tool_choice": {
                        "allowed_tools": {
                            "mode": "any",
                            "tools": [request.source_tool_name],
                        }
                    },
                },
            )
            self._record_successful_provider_invocation()
        except Exception as exc:
            provider_error = safe_backend_error(exc, secrets=self._secrets)
            provider_status_code = self._provider_status_code(exc)
        if provider_error is not None:
            raise ProviderRequestError(
                provider_error,
                status_code=provider_status_code,
            )
        latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        return self._parse_prelude(
            interaction,
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
                "Gemini post-tool choice mode must be 'any' or 'validated'"
            )
        source_schema = source_function_schema(
            prepared.tool_name,
            prepared.tool_arguments,
        )
        self._wait_for_request_slot()
        started_ns = time.perf_counter_ns()
        provider_error: str | None = None
        provider_status_code: int | None = None
        self._record_provider_request_attempt()
        try:
            interaction = self._client.interactions.create(
                model=self.model_id,
                input=request.interaction_input(prepared),
                system_instruction=request.system_instruction,
                store=False,
                tools=[
                    source_schema,
                    sink_function_schema(request.available_sink_ids),
                ],
                generation_config={
                    "max_output_tokens": self.sampling_parameters[
                        "post_tool_max_output_tokens"
                    ],
                    "seed": request.seed,
                    "thinking_level": self.sampling_parameters[
                        "post_tool_thinking_level"
                    ],
                    "tool_choice": {
                        "allowed_tools": {
                            "mode": request.sink_tool_choice_mode,
                            "tools": [SINK_FUNCTION_NAME],
                        }
                    },
                },
            )
            self._record_successful_provider_invocation()
        except Exception as exc:
            provider_error = safe_backend_error(exc, secrets=self._secrets)
            provider_status_code = self._provider_status_code(exc)
        if provider_error is not None:
            raise ProviderRequestError(
                provider_error,
                status_code=provider_status_code,
            )
        latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        return self._parse_interaction(
            interaction,
            latency_ms=latency_ms,
            sink_action_required=(
                request.sink_tool_choice_mode == "any"
            ),
        )

    def complete_action(
        self,
        request: ActionRequest,
        prepared: PreparedToolCall,
    ) -> ActionDecision:
        """Return a generic structured proposal without executing any tool."""

        validate_action_prepared_context(request, prepared, self)
        action_schema = validated_action_function_schema(
            request.action_tool_schema
        )
        action_name = request.action_name
        source_schema = source_function_schema(
            prepared.tool_name,
            prepared.tool_arguments,
        )
        generation_config: dict[str, Any] = {
            "max_output_tokens": self.sampling_parameters[
                "post_tool_max_output_tokens"
            ],
            "seed": request.seed,
            "thinking_level": self.sampling_parameters[
                "post_tool_thinking_level"
            ],
        }
        if request.action_choice_mode == "required":
            generation_config["tool_choice"] = {
                "allowed_tools": {
                    "mode": "any",
                    "tools": [action_name],
                }
            }
        self._wait_for_request_slot()
        started_ns = time.perf_counter_ns()
        provider_error: str | None = None
        provider_status_code: int | None = None
        self._record_provider_request_attempt()
        try:
            interaction = self._client.interactions.create(
                model=self.model_id,
                input=request.interaction_input(prepared),
                system_instruction=request.system_instruction,
                store=False,
                tools=[source_schema, action_schema],
                generation_config=generation_config,
            )
            self._record_successful_provider_invocation()
        except Exception as exc:
            provider_error = safe_backend_error(exc, secrets=self._secrets)
            provider_status_code = self._provider_status_code(exc)
        if provider_error is not None:
            raise ProviderRequestError(
                provider_error,
                status_code=provider_status_code,
            )
        latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        return self._parse_action_interaction(
            interaction,
            request=request,
            latency_ms=latency_ms,
        )

    def _parse_prelude(
        self,
        interaction: Any,
        *,
        request: PreludeRequest,
        latency_ms: float,
    ) -> PreparedToolCall:
        status = self._terminal_status(interaction)
        steps = list(getattr(interaction, "steps", None) or ())
        function_calls = [
            step
            for step in steps
            if getattr(step, "type", None) == "function_call"
        ]
        if len(function_calls) != 1:
            raise MalformedModelResponse(
                "Gemini prelude must return exactly one source-tool call"
            )
        call = function_calls[0]
        call_id = self._optional_string(getattr(call, "id", None))
        if call_id is None:
            raise MalformedModelResponse(
                "Gemini prelude source-tool call has no call ID"
            )
        if getattr(call, "name", None) != request.source_tool_name:
            raise MalformedModelResponse(
                "Gemini prelude selected an unexpected source tool"
            )
        raw_arguments = getattr(call, "arguments", None)
        if not isinstance(raw_arguments, Mapping):
            raise MalformedModelResponse(
                "Gemini prelude source-tool arguments must be an object"
            )
        arguments = dict(raw_arguments)
        if arguments != dict(request.source_tool_arguments):
            raise MalformedModelResponse(
                "Gemini prelude changed the frozen source-tool arguments"
            )

        serialized_steps = tuple(self._step_mapping(step) for step in steps)
        unexpected_step_types = sorted(
            {
                str(step.get("type"))
                for step in serialized_steps
                if step.get("type") not in {"function_call", "thought"}
            }
        )
        if unexpected_step_types:
            raise MalformedModelResponse(
                "Gemini prelude returned unexpected step types: "
                f"{', '.join(unexpected_step_types)}"
            )
        if any(step.get("type") == "function_result" for step in serialized_steps):
            raise MalformedModelResponse(
                "Gemini prelude unexpectedly contained a function result"
            )
        cache_key = request.cache_key(self)
        source_schema_hash = sha256_text(
            canonical_json(request.source_tool_schema())
        )
        metadata = self._model_call_metadata(
            interaction,
            status=status,
            finish_reason="function_call",
            latency_ms=latency_ms,
        )
        provider_context = (
            dict(request.user_input_step()),
            *serialized_steps,
        )
        provider_context_json, provider_context_sha256 = (
            serialize_provider_context(provider_context)
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
            model_call=metadata,
            step_types=tuple(
                str(step.get("type", "")) for step in serialized_steps
            ),
            provider_context_json=provider_context_json,
            provider_context_sha256=provider_context_sha256,
            store=False,
        )

    def _validate_branch_context(
        self,
        request: LLMRequest,
        prepared: PreparedToolCall,
    ) -> None:
        if prepared.store:
            raise MalformedModelResponse(
                "Gemini branch context must use store=False"
            )
        if request.matched_set_id != prepared.matched_set_id:
            raise MalformedModelResponse(
                "Gemini branch changed the matched-set identity"
            )
        if sha256_text(request.user_prompt) != prepared.user_prompt_sha256:
            raise MalformedModelResponse(
                "Gemini branch changed the matched-set user prompt"
            )
        if request.source_tool_name != prepared.tool_name:
            raise MalformedModelResponse(
                "Gemini branch changed the source tool name"
            )
        if (
            dict(request.source_tool_arguments)
            != dict(prepared.tool_arguments)
        ):
            raise MalformedModelResponse(
                "Gemini branch changed the source-tool arguments"
            )
        if request.source_tool_call_id != prepared.provider_call_id:
            raise MalformedModelResponse(
                "Gemini branch changed the provider source-tool call ID"
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
                "Gemini branch changed the source-tool schema"
            )
        validated_provider_context(
            prepared,
            expected_user_prompt=request.user_prompt,
        )

    def _parse_action_interaction(
        self,
        interaction: Any,
        *,
        request: ActionRequest,
        latency_ms: float,
    ) -> ActionDecision:
        status = self._terminal_status(interaction)
        serialized_steps = tuple(
            self._step_mapping(step)
            for step in (getattr(interaction, "steps", None) or ())
        )
        unexpected_step_types = sorted(
            {
                str(step.get("type"))
                for step in serialized_steps
                if step.get("type")
                not in {"function_call", "model_output", "thought"}
            }
        )
        if unexpected_step_types:
            raise MalformedModelResponse(
                "Gemini action response returned unexpected step types: "
                f"{', '.join(unexpected_step_types)}"
            )
        function_calls = [
            step
            for step in serialized_steps
            if step.get("type") == "function_call"
        ]
        if len(function_calls) > 1:
            raise MalformedModelResponse(
                "Gemini returned more than one function call at an action boundary"
            )
        if function_calls and any(
            step.get("type") == "model_output"
            for step in serialized_steps
        ):
            raise MalformedModelResponse(
                "Gemini mixed a model_output step with a structured action proposal"
            )

        output_text = getattr(interaction, "output_text", None)
        text = output_text.strip() if isinstance(output_text, str) else ""
        action_name: str | None = None
        action_arguments: Mapping[str, Any] | None = None
        finish_reason: str

        if function_calls:
            call = function_calls[0]
            if self._optional_string(call.get("id")) is None:
                raise MalformedModelResponse(
                    "Gemini action function call has no call ID"
                )
            if call.get("name") != request.action_name:
                raise MalformedModelResponse(
                    "Gemini returned an undeclared action function name"
                )
            if text:
                raise MalformedModelResponse(
                    "Gemini mixed answer text with a structured action proposal"
                )
            action_name = request.action_name
            action_arguments = validate_action_arguments(
                call.get("arguments"),
                request.action_tool_schema,
            )
            finish_reason = "function_call"
        else:
            if request.action_choice_mode == "required":
                raise MalformedModelResponse(
                    "Gemini required action tool choice returned no function call"
                )
            if status == "requires_action":
                raise MalformedModelResponse(
                    "Gemini requires_action response has no function call"
                )
            if not text:
                raise MalformedModelResponse(
                    "Gemini returned neither text nor a structured action proposal"
                )
            if len(text) > 2_000:
                raise MalformedModelResponse(
                    "Gemini action-boundary text exceeds 2,000 characters"
                )
            finish_reason = "text"

        metadata = self._model_call_metadata(
            interaction,
            status=status,
            finish_reason=finish_reason,
            latency_ms=latency_ms,
        )
        return validated_action_decision(
            ActionDecision(
                text=text or None,
                action_name=action_name,
                action_arguments=action_arguments,
                metadata=metadata,
            ),
            request,
        )

    def _parse_interaction(
        self,
        interaction: Any,
        *,
        latency_ms: float,
        sink_action_required: bool = False,
    ) -> BackendDecision:
        status = self._terminal_status(interaction)

        serialized_steps = tuple(
            self._step_mapping(step)
            for step in (getattr(interaction, "steps", None) or ())
        )
        unexpected_step_types = sorted(
            {
                str(step.get("type"))
                for step in serialized_steps
                if step.get("type")
                not in {"function_call", "model_output", "thought"}
            }
        )
        if unexpected_step_types:
            raise MalformedModelResponse(
                "Gemini post-tool response returned unexpected step types: "
                f"{', '.join(unexpected_step_types)}"
            )

        # Current Interactions responses may surface a function call under either
        # terminal status, so classify the observed steps instead of inferring
        # the function-call shape from status alone. A text-only response is
        # complete, however, and must not remain in requires_action.
        function_calls = [
            step
            for step in serialized_steps
            if step.get("type") == "function_call"
        ]
        if len(function_calls) > 1:
            raise MalformedModelResponse(
                "Gemini returned more than one function call in a one-step policy"
            )

        output_text = getattr(interaction, "output_text", None)
        text_answer = output_text.strip() if isinstance(output_text, str) else ""
        sink_action: Mapping[str, Any] | None = None
        finish_reason: str

        if function_calls:
            call = function_calls[0]
            call_id = self._optional_string(call.get("id"))
            if call_id is None:
                raise MalformedModelResponse(
                    "Gemini sink function call has no call ID"
                )
            if call.get("name") != SINK_FUNCTION_NAME:
                raise MalformedModelResponse(
                    "Gemini returned an unexpected function name"
                )
            raw_arguments = call.get("arguments")
            if not isinstance(raw_arguments, Mapping):
                raise MalformedModelResponse(
                    "Gemini function arguments must be an object"
                )
            required = {"final_answer", "sink_id", "source_field", "value"}
            missing = sorted(required - set(raw_arguments))
            unknown = sorted(set(raw_arguments) - required)
            if missing:
                raise MalformedModelResponse(
                    f"Gemini function call is missing fields: {', '.join(missing)}"
                )
            if unknown:
                raise MalformedModelResponse(
                    f"Gemini function call has unknown fields: {', '.join(unknown)}"
                )
            function_answer = raw_arguments["final_answer"]
            if not isinstance(function_answer, str) or not function_answer.strip():
                raise MalformedModelResponse(
                    "Gemini function call final_answer must be a non-empty string"
                )
            answer = function_answer.strip()
            if text_answer and text_answer != answer:
                raise MalformedModelResponse(
                    "Gemini returned conflicting text and function-call answers"
                )
            sink_action = {
                "sink_id": raw_arguments["sink_id"],
                "operation": SINK_FUNCTION_NAME,
                "source_field": raw_arguments["source_field"],
                "value": raw_arguments["value"],
            }
            finish_reason = "function_call"
        else:
            if sink_action_required:
                raise MalformedModelResponse(
                    "Gemini required sink tool choice returned no function call"
                )
            if status == "requires_action":
                raise MalformedModelResponse(
                    "Gemini requires_action response has no function call"
                )
            if not text_answer:
                raise MalformedModelResponse(
                    "Gemini returned neither answer text nor a function call"
                )
            answer = text_answer
            finish_reason = "text"

        metadata = self._model_call_metadata(
            interaction,
            status=status,
            finish_reason=finish_reason,
            latency_ms=latency_ms,
        )
        return BackendDecision(
            answer=answer,
            sink_action=sink_action,
            metadata=metadata,
        )

    def _terminal_status(self, interaction: Any) -> str:
        status = self._optional_string(getattr(interaction, "status", None))
        if status not in TERMINAL_INTERACTION_STATUSES:
            raise MalformedModelResponse(
                f"Gemini interaction ended with non-terminal status {status!r}"
            )
        return status

    def _model_call_metadata(
        self,
        interaction: Any,
        *,
        status: str,
        finish_reason: str,
        latency_ms: float,
    ) -> ModelCallMetadata:
        usage = getattr(interaction, "usage", None)
        observed_model = self._optional_string(
            getattr(interaction, "model", None)
        )
        if observed_model is not None and observed_model != self.model_id:
            raise MalformedModelResponse(
                "Gemini response model differs from the configured model ID"
            )
        return ModelCallMetadata(
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=observed_model or self.model_version,
            sdk_name=self.sdk_name,
            sdk_version=self.sdk_version,
            api_version=self.api_version,
            response_id=self._optional_string(
                getattr(interaction, "id", None)
            ),
            response_status=status,
            finish_reason=finish_reason,
            latency_ms=latency_ms,
            input_tokens=self._usage_value(usage, "total_input_tokens"),
            output_tokens=self._usage_value(usage, "total_output_tokens"),
            thought_tokens=self._usage_value(usage, "total_thought_tokens"),
            tool_use_tokens=self._usage_value(usage, "total_tool_use_tokens"),
            cached_tokens=self._usage_value(usage, "total_cached_tokens"),
            total_tokens=self._usage_value(usage, "total_tokens"),
        )

    @staticmethod
    def _step_mapping(step: object) -> Mapping[str, Any]:
        if isinstance(step, Mapping):
            return dict(step)
        model_dump = getattr(step, "model_dump", None)
        if callable(model_dump):
            value = model_dump(mode="json", exclude_none=True)
            if isinstance(value, Mapping):
                return dict(value)
        fields = (
            "arguments",
            "content",
            "id",
            "name",
            "signature",
            "summary",
            "type",
        )
        value = {
            field: getattr(step, field)
            for field in fields
            if getattr(step, field, None) is not None
        }
        if "type" not in value:
            raise MalformedModelResponse(
                "Gemini prelude step cannot be serialized"
            )
        return value

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _usage_value(usage: object, field: str) -> int | None:
        if usage is None:
            return None
        value = getattr(usage, field, None)
        return value if isinstance(value, int) and value >= 0 else None
