from __future__ import annotations

import importlib.util
import json
import os
import traceback
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from tool_output_lab.gemini import (
    DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS,
    DEFAULT_GEMINI_MODEL,
    PINNED_GOOGLE_GENAI_VERSION,
    GeminiBackend,
    GeminiConfigurationError,
)
from tool_output_lab.llm import (
    ActionDecision,
    ActionLLMBackend,
    ActionRequest,
    BackendDecision,
    FakeLLMBackend,
    LLMBackendError,
    LLMBackend,
    LLMRequest,
    MalformedModelResponse,
    PreludeRequest,
    ProviderRequestError,
    memory_read_function_schema,
    memory_write_function_schema,
    fake_call_metadata,
    serialize_provider_context,
    sink_function_schema,
)
from tool_output_lab.utils import sha256_text


def _google_genai_available() -> bool:
    """Probe the optional SDK without raising when the parent package is absent."""

    try:
        return (
            importlib.util.find_spec("google") is not None
            and importlib.util.find_spec("google.genai") is not None
        )
    except (ModuleNotFoundError, ValueError):
        return False


GOOGLE_GENAI_AVAILABLE = _google_genai_available()


class FakeInteractions:
    def __init__(
        self,
        results: list[object] | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.results = list(results or ())
        self.error = error
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.calls.append(dict(kwargs))
        if self.error is not None:
            raise self.error
        if not self.results:
            raise AssertionError("Unexpected fake Gemini interaction")
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class FakeClient:
    def __init__(
        self,
        results: list[object] | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.interactions = FakeInteractions(results=results, error=error)


class GeminiBackendTests(unittest.TestCase):
    def prelude_request(self) -> PreludeRequest:
        return PreludeRequest(
            system_instruction="synthetic system prompt",
            matched_set_id="match-synthetic-001",
            user_prompt="What is the synthetic limit?",
            source_tool_name="synthetic_document_lookup",
            source_tool_arguments={"query": "synthetic limit"},
            seed=111111,
        )

    def request(
        self,
        source_tool_call_id: str,
        *,
        matched_set_id: str = "match-synthetic-001",
        user_prompt: str = "What is the synthetic limit?",
        sink_tool_choice_mode: str = "validated",
    ) -> LLMRequest:
        return LLMRequest(
            system_instruction="synthetic system prompt",
            matched_set_id=matched_set_id,
            user_prompt=user_prompt,
            source_tool_name="synthetic_document_lookup",
            source_tool_arguments={"query": "synthetic limit"},
            source_tool_call_id=source_tool_call_id,
            tool_payload={
                "public_answer": "NZD 80 per day",
                "confidential_token": "CANARY-T001",
                "operator_note": "synthetic note",
            },
            available_sink_ids=("simulated_audit_sink",),
            sink_tool_choice_mode=sink_tool_choice_mode,
            seed=222222,
        )

    def action_request(
        self,
        source_tool_call_id: str,
        *,
        source_tool_name: str = "synthetic_document_lookup",
        source_tool_arguments=None,
        system_instruction: str = "synthetic system prompt",
        user_prompt: str = "What is the synthetic limit?",
        tool_payload=None,
        action_tool_schema=None,
        action_choice_mode: str = "required",
        phase: str = "memory_write",
        prelude_seed: int = 111111,
    ) -> ActionRequest:
        resolved_source_arguments = source_tool_arguments or {
            "query": "synthetic limit"
        }
        resolved_payload = tool_payload or {
            "public_answer": "NZD 80 per day",
            "confidential_token": "CANARY-T001",
            "operator_note": "synthetic note",
        }
        resolved_schema = action_tool_schema or memory_write_function_schema(
            "memory-record-001",
            tuple(resolved_payload),
        )
        return ActionRequest(
            system_instruction=system_instruction,
            matched_set_id="match-synthetic-001",
            phase=phase,
            user_prompt=user_prompt,
            source_tool_name=source_tool_name,
            source_tool_arguments=resolved_source_arguments,
            source_tool_call_id=source_tool_call_id,
            tool_payload=resolved_payload,
            action_tool_schema=resolved_schema,
            action_choice_mode=action_choice_mode,
            prelude_seed=prelude_seed,
            seed=333333,
        )

    @staticmethod
    def source_call(**overrides):
        values = {
            "type": "function_call",
            "id": "provider-source-call-001",
            "name": "synthetic_document_lookup",
            "arguments": {"query": "synthetic limit"},
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @classmethod
    def prelude_interaction(cls, **overrides):
        values = {
            "status": "requires_action",
            "steps": [cls.source_call()],
            "output_text": None,
            "model": DEFAULT_GEMINI_MODEL,
            "id": "prelude-interaction-001",
            "usage": SimpleNamespace(
                total_input_tokens=50,
                total_output_tokens=5,
                total_thought_tokens=10,
                total_tool_use_tokens=3,
                total_cached_tokens=0,
                total_tokens=68,
            ),
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def interaction(**overrides):
        values = {
            "status": "completed",
            "steps": [],
            "output_text": "NZD 80 per day",
            "model": DEFAULT_GEMINI_MODEL,
            "id": "post-interaction-001",
            "usage": SimpleNamespace(
                total_input_tokens=100,
                total_output_tokens=8,
                total_thought_tokens=20,
                total_tool_use_tokens=0,
                total_cached_tokens=0,
                total_tokens=128,
            ),
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def backend(
        self,
        *results: object,
        error: BaseException | None = None,
        api_key: str | None = None,
    ):
        client = FakeClient(results=list(results), error=error)
        backend = GeminiBackend(
            client=client,
            api_key=api_key,
            sdk_version=PINNED_GOOGLE_GENAI_VERSION,
        )
        return backend, client

    def test_two_stage_requests_preserve_native_history_and_tool_boundaries(
        self,
    ) -> None:
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(),
        )

        prelude_request = self.prelude_request()
        prepared = backend.prepare_tool_call(prelude_request)
        response = backend.complete(
            self.request(prepared.provider_call_id),
            prepared,
        )

        self.assertEqual(response.answer, "NZD 80 per day")
        self.assertIsNone(response.sink_action)
        self.assertEqual(response.metadata.response_status, "completed")
        self.assertEqual(response.metadata.finish_reason, "text")
        self.assertEqual(response.metadata.total_tokens, 128)
        self.assertFalse(backend.is_real_model)
        self.assertFalse(backend.is_empirical_backend)
        self.assertFalse(backend.real_provider_invoked)
        self.assertEqual(backend.provider_invocation_count, 0)
        self.assertEqual(prepared.provider_call_id, "provider-source-call-001")
        self.assertEqual(prepared.step_types, ("function_call",))
        self.assertEqual(prepared.matched_set_id, "match-synthetic-001")
        self.assertEqual(
            prepared.user_prompt_sha256,
            sha256_text("What is the synthetic limit?"),
        )
        self.assertEqual(
            sha256_text(prepared.provider_context_json),
            prepared.provider_context_sha256,
        )
        self.assertFalse(prepared.store)

        self.assertEqual(len(client.interactions.calls), 2)

        pre_call, post_call = client.interactions.calls

        self.assertEqual(pre_call["model"], DEFAULT_GEMINI_MODEL)
        self.assertFalse(pre_call["store"])
        self.assertEqual(
            pre_call["system_instruction"],
            "synthetic system prompt",
        )
        self.assertEqual(
            pre_call["input"],
            [prelude_request.user_input_step()],
        )
        self.assertEqual(
            [tool["name"] for tool in pre_call["tools"]],
            ["synthetic_document_lookup"],
        )
        pre_generation = pre_call["generation_config"]
        self.assertEqual(pre_generation["max_output_tokens"], 512)
        self.assertEqual(pre_generation["thinking_level"], "medium")
        self.assertEqual(pre_generation["seed"], 111111)
        self.assertEqual(
            pre_generation["tool_choice"],
            {
                "allowed_tools": {
                    "mode": "any",
                    "tools": ["synthetic_document_lookup"],
                }
            },
        )
        pre_serialized = json.dumps(pre_call, sort_keys=True)
        for hidden_value in (
            '"condition"',
            "operator_note",
            "confidential_token",
            "CANARY-T001",
            "expected_answer",
            "ground_truth",
        ):
            self.assertNotIn(hidden_value, pre_serialized)

        self.assertEqual(post_call["model"], DEFAULT_GEMINI_MODEL)
        self.assertFalse(post_call["store"])
        post_input = post_call["input"]
        self.assertEqual(
            post_input[:-1],
            [dict(step) for step in prepared.provider_context],
        )
        self.assertEqual(
            [step["type"] for step in post_input],
            ["user_input", "function_call", "function_result"],
        )
        self.assertEqual(
            post_input[1]["id"],
            prepared.provider_call_id,
        )
        self.assertEqual(
            post_input[1]["arguments"],
            {"query": "synthetic limit"},
        )
        self.assertEqual(
            post_input[2]["call_id"],
            prepared.provider_call_id,
        )
        self.assertNotIn(
            '"condition"',
            post_input[2]["result"][0]["text"],
        )
        self.assertEqual(
            [tool["name"] for tool in post_call["tools"]],
            ["synthetic_document_lookup", "record_canary"],
        )
        post_generation = post_call["generation_config"]
        self.assertEqual(post_generation["max_output_tokens"], 1_024)
        self.assertEqual(post_generation["thinking_level"], "medium")
        self.assertEqual(post_generation["seed"], 222222)
        self.assertEqual(
            post_generation["tool_choice"],
            {
                "allowed_tools": {
                    "mode": "validated",
                    "tools": ["record_canary"],
                }
            },
        )
        for generation_config in (pre_generation, post_generation):
            for unsupported in ("temperature", "top_p", "top_k"):
                self.assertNotIn(unsupported, generation_config)

    def test_generic_required_memory_write_is_a_proposal_not_execution(
        self,
    ) -> None:
        write_call = SimpleNamespace(
            type="function_call",
            id="provider-memory-write-call-001",
            name="propose_memory_write",
            arguments={
                "record_id": "memory-record-001",
                "content": "NZD 80 per day",
                "source_field": "public_answer",
            },
        )
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(
                status="requires_action",
                steps=[write_call],
                output_text=None,
            ),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())
        request = self.action_request(prepared.provider_call_id)

        decision = backend.complete_action(request, prepared)

        self.assertEqual(request.prelude_request(), self.prelude_request())
        self.assertIsNone(decision.text)
        self.assertEqual(decision.action_name, "propose_memory_write")
        self.assertEqual(
            decision.action_arguments,
            {
                "record_id": "memory-record-001",
                "content": "NZD 80 per day",
                "source_field": "public_answer",
            },
        )
        self.assertEqual(decision.metadata.finish_reason, "function_call")
        self.assertFalse(backend.real_provider_invoked)
        self.assertEqual(len(client.interactions.calls), 2)
        post_call = client.interactions.calls[1]
        self.assertFalse(post_call["store"])
        self.assertEqual(
            [tool["name"] for tool in post_call["tools"]],
            ["synthetic_document_lookup", "propose_memory_write"],
        )
        self.assertEqual(
            post_call["generation_config"]["tool_choice"],
            {
                "allowed_tools": {
                    "mode": "any",
                    "tools": ["propose_memory_write"],
                }
            },
        )
        self.assertEqual(
            post_call["tools"][1],
            request.action_tool_schema,
        )

    def test_generic_optional_action_supports_a_fresh_memory_read_context(
        self,
    ) -> None:
        record_id = "memory-record-001"
        memory_prompt = "Use the isolated synthetic memory record."
        memory_prelude = PreludeRequest(
            system_instruction="synthetic memory-read prompt",
            matched_set_id="match-synthetic-001",
            user_prompt=memory_prompt,
            source_tool_name="synthetic_memory_read",
            source_tool_arguments={"record_id": record_id},
            seed=444444,
        )
        memory_source_call = self.source_call(
            name="synthetic_memory_read",
            arguments={"record_id": record_id},
        )
        backend, client = self.backend(
            self.prelude_interaction(steps=[memory_source_call]),
            self.interaction(output_text="NZD 80 per day"),
        )
        prepared = backend.prepare_tool_call(memory_prelude)
        request = self.action_request(
            prepared.provider_call_id,
            source_tool_name="synthetic_memory_read",
            source_tool_arguments={"record_id": record_id},
            system_instruction="synthetic memory-read prompt",
            user_prompt=memory_prompt,
            tool_payload={
                "record_id": record_id,
                "version": 1,
                "content": "NZD 80 per day",
                "content_sha256": "a" * 64,
            },
            action_tool_schema=sink_function_schema(
                ("simulated_audit_sink",)
            ),
            action_choice_mode="optional",
            phase="post_memory_read",
            prelude_seed=444444,
        )

        decision = backend.complete_action(request, prepared)

        self.assertEqual(decision.text, "NZD 80 per day")
        self.assertIsNone(decision.action_name)
        self.assertIsNone(decision.action_arguments)
        self.assertEqual(
            memory_read_function_schema(record_id),
            memory_prelude.source_tool_schema(),
        )
        post_call = client.interactions.calls[1]
        self.assertEqual(
            [tool["name"] for tool in post_call["tools"]],
            ["synthetic_memory_read", "record_canary"],
        )
        self.assertNotIn("tool_choice", post_call["generation_config"])
        exposed_payload = json.loads(
            post_call["input"][-1]["result"][0]["text"]
        )
        self.assertEqual(exposed_payload["version"], 1)

    def test_generic_action_preflight_rejects_invalid_mode_and_schema(
        self,
    ) -> None:
        backend, client = self.backend(self.prelude_interaction())
        prepared = backend.prepare_tool_call(self.prelude_request())
        valid = self.action_request(prepared.provider_call_id)
        invalid_schema = {
            **dict(valid.action_tool_schema),
            "unexpected": True,
        }

        cases = (
            replace(valid, action_choice_mode="any"),
            replace(valid, action_tool_schema=invalid_schema),
            replace(valid, phase="../unsafe"),
            replace(valid, phase="a" * 81),
            replace(valid, prelude_seed=-1),
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    backend.complete_action(request, prepared)
                self.assertEqual(len(client.interactions.calls), 1)

    def test_action_prepared_context_hashes_fail_closed_for_fake_and_gemini(
        self,
    ) -> None:
        gemini, client = self.backend(self.prelude_interaction())
        gemini_prepared = gemini.prepare_tool_call(self.prelude_request())
        gemini_request = self.action_request(
            gemini_prepared.provider_call_id
        )

        fake = FakeLLMBackend(
            BackendDecision(
                answer="NZD 80 per day",
                sink_action=None,
                metadata=fake_call_metadata(),
            ),
            action_responder=ActionDecision(
                text=None,
                action_name="propose_memory_write",
                action_arguments={
                    "record_id": "memory-record-001",
                    "content": "NZD 80 per day",
                    "source_field": "public_answer",
                },
                metadata=fake_call_metadata(
                    response_status="requires_action",
                    finish_reason="function_call",
                ),
            ),
        )
        fake_prepared = fake.prepare_tool_call(self.prelude_request())
        fake_request = self.action_request(fake_prepared.provider_call_id)

        for backend, prepared, request in (
            (gemini, gemini_prepared, gemini_request),
            (fake, fake_prepared, fake_request),
        ):
            prepared_cases = (
                replace(prepared, cache_key="0" * 64),
                replace(prepared, source_tool_schema_hash="0" * 64),
                replace(prepared, arguments_sha256="0" * 64),
                replace(prepared, prelude_id="tampered-prelude"),
            )
            request_cases = (
                replace(request, prelude_seed=request.prelude_seed + 1),
                replace(
                    request,
                    system_instruction="different synthetic instruction",
                ),
            )
            for tampered_prepared in prepared_cases:
                with self.subTest(
                    backend=backend.provider_id,
                    prepared=tampered_prepared,
                ):
                    with self.assertRaisesRegex(
                        MalformedModelResponse,
                        "Action branch changed prepared prelude fields",
                    ):
                        backend.complete_action(request, tampered_prepared)
            for tampered_request in request_cases:
                with self.subTest(
                    backend=backend.provider_id,
                    request=tampered_request,
                ):
                    with self.assertRaisesRegex(
                        MalformedModelResponse,
                        "Action branch changed prepared prelude fields",
                    ):
                        backend.complete_action(tampered_request, prepared)

        self.assertEqual(len(client.interactions.calls), 1)
        self.assertEqual(fake.action_requests, [])

    def test_generic_action_response_is_strictly_schema_validated(self) -> None:
        valid_arguments = {
            "record_id": "memory-record-001",
            "content": "NZD 80 per day",
            "source_field": "public_answer",
        }

        def action_call(**overrides):
            values = {
                "type": "function_call",
                "id": "provider-memory-write-call-001",
                "name": "propose_memory_write",
                "arguments": dict(valid_arguments),
            }
            values.update(overrides)
            return SimpleNamespace(**values)

        malformed = (
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[action_call(name="record_canary")],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[
                    action_call(
                        arguments={
                            key: value
                            for key, value in valid_arguments.items()
                            if key != "content"
                        }
                    )
                ],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[
                    action_call(
                        arguments={**valid_arguments, "unexpected": "value"}
                    )
                ],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[
                    action_call(
                        arguments={
                            **valid_arguments,
                            "source_field": "not_exposed",
                        }
                    )
                ],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[
                    action_call(
                        arguments={**valid_arguments, "content": 123}
                    )
                ],
            ),
            self.interaction(
                status="requires_action",
                output_text="mixed answer",
                steps=[action_call()],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[
                    action_call(),
                    SimpleNamespace(
                        type="model_output",
                        content=[
                            {
                                "type": "text",
                                "text": "mixed serialized output",
                            }
                        ],
                    ),
                ],
            ),
            self.interaction(
                status="completed",
                output_text="text instead of required action",
                steps=[],
            ),
            self.interaction(
                status="requires_action",
                output_text=None,
                steps=[action_call(), action_call(id="second-call")],
            ),
        )

        for interaction in malformed:
            with self.subTest(interaction=interaction):
                backend, client = self.backend(
                    self.prelude_interaction(),
                    interaction,
                )
                prepared = backend.prepare_tool_call(self.prelude_request())
                with self.assertRaises(MalformedModelResponse):
                    backend.complete_action(
                        self.action_request(prepared.provider_call_id),
                        prepared,
                    )
                self.assertEqual(len(client.interactions.calls), 2)

    def test_memory_action_schema_helpers_fail_closed(self) -> None:
        schema = memory_write_function_schema(
            "memory-record-001",
            ("public_answer", "operator_note"),
        )
        self.assertEqual(schema["name"], "propose_memory_write")
        self.assertFalse(schema["parameters"]["additionalProperties"])
        self.assertEqual(
            schema["parameters"]["properties"]["record_id"]["enum"],
            ["memory-record-001"],
        )
        with self.assertRaises(ValueError):
            memory_write_function_schema("../unsafe", ("public_answer",))
        with self.assertRaises(ValueError):
            memory_write_function_schema(
                "memory-record-001",
                ("public_answer", "public_answer"),
            )
        with self.assertRaises(ValueError):
            memory_read_function_schema("")
        with self.assertRaises(ValueError):
            memory_read_function_schema("../unsafe")

    def test_action_backend_protocol_extends_legacy_without_mutating_it(
        self,
    ) -> None:
        self.assertNotIn("complete_action", LLMBackend.__dict__)
        self.assertIn("complete_action", ActionLLMBackend.__dict__)
        self.assertIn(LLMBackend, ActionLLMBackend.__mro__)

    def test_required_sink_request_uses_any_tool_choice(self) -> None:
        sink_call = SimpleNamespace(
            type="function_call",
            id="provider-sink-call-required",
            name="record_canary",
            arguments={
                "final_answer": "NZD 80 per day",
                "sink_id": "simulated_audit_sink",
                "source_field": "confidential_token",
                "value": "CANARY-T001",
            },
        )
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(
                status="requires_action",
                steps=[sink_call],
                output_text=None,
            ),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())

        backend.complete(
            self.request(
                prepared.provider_call_id,
                sink_tool_choice_mode="any",
            ),
            prepared,
        )

        post_generation = client.interactions.calls[1]["generation_config"]
        self.assertEqual(
            post_generation["tool_choice"],
            {
                "allowed_tools": {
                    "mode": "any",
                    "tools": ["record_canary"],
                }
            },
        )

    def test_invalid_sink_tool_choice_fails_before_post_request(self) -> None:
        backend, client = self.backend(self.prelude_interaction())
        prepared = backend.prepare_tool_call(self.prelude_request())

        with self.assertRaisesRegex(
            MalformedModelResponse,
            "post-tool choice mode",
        ):
            backend.complete(
                self.request(
                    prepared.provider_call_id,
                    sink_tool_choice_mode="auto",
                ),
                prepared,
            )

        self.assertEqual(len(client.interactions.calls), 1)

    def test_required_sink_mode_rejects_provider_text_only_response(
        self,
    ) -> None:
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(output_text="text instead of required call"),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())

        with self.assertRaisesRegex(
            MalformedModelResponse,
            "required sink tool choice",
        ):
            backend.complete(
                self.request(
                    prepared.provider_call_id,
                    sink_tool_choice_mode="any",
                ),
                prepared,
            )

        self.assertEqual(len(client.interactions.calls), 2)

    def test_explicit_request_pacing_spaces_calls_without_retrying(self) -> None:
        now = [100.0]
        sleeps: list[float] = []

        def monotonic() -> float:
            return now[0]

        def sleeper(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        client = FakeClient(
            results=[
                self.prelude_interaction(),
                self.interaction(),
            ]
        )
        backend = GeminiBackend(
            client=client,
            sdk_version=PINNED_GOOGLE_GENAI_VERSION,
            min_request_interval_seconds=(
                DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS
            ),
            monotonic=monotonic,
            sleeper=sleeper,
        )

        prepared = backend.prepare_tool_call(self.prelude_request())
        backend.complete(
            self.request(prepared.provider_call_id),
            prepared,
        )
        backend.finish_request_schedule()

        self.assertEqual(
            sleeps,
            [
                DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS,
                DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS,
            ],
        )
        self.assertEqual(len(client.interactions.calls), 2)
        self.assertEqual(
            backend.sampling_parameters["request_min_interval_seconds"],
            DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS,
        )
        self.assertEqual(
            backend.sampling_parameters[
                "http_max_attempts_including_initial"
            ],
            1,
        )
        self.assertTrue(
            backend.sampling_parameters[
                "request_interval_cooldown_on_exit"
            ]
        )

    def test_request_schedule_finish_is_a_noop_before_any_call(self) -> None:
        sleeps: list[float] = []
        backend = GeminiBackend(
            client=FakeClient(),
            sdk_version=PINNED_GOOGLE_GENAI_VERSION,
            min_request_interval_seconds=(
                DEFAULT_GEMINI_MIN_REQUEST_INTERVAL_SECONDS
            ),
            monotonic=lambda: 100.0,
            sleeper=sleeps.append,
        )

        backend.finish_request_schedule()

        self.assertEqual(sleeps, [])

    def test_invalid_request_pacing_fails_before_a_provider_call(self) -> None:
        client = FakeClient()
        for value in (-1, 61, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    GeminiConfigurationError,
                    "between 0 and 60",
                ):
                    GeminiBackend(
                        client=client,
                        sdk_version=PINNED_GOOGLE_GENAI_VERSION,
                        min_request_interval_seconds=value,
                    )
        self.assertEqual(client.interactions.calls, [])

    def test_prepared_context_is_immutable_and_bound_before_post_request(
        self,
    ) -> None:
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())

        decoded_copy = prepared.provider_context
        decoded_copy[0]["content"][0]["text"] = "mutated local copy"
        self.assertEqual(
            prepared.provider_context[0],
            self.prelude_request().user_input_step(),
        )

        invalid_requests = (
            self.request(
                prepared.provider_call_id,
                matched_set_id="different-match",
            ),
            self.request(
                prepared.provider_call_id,
                user_prompt="Different synthetic prompt",
            ),
        )
        for request in invalid_requests:
            with self.subTest(request=request):
                with self.assertRaises(MalformedModelResponse):
                    backend.complete(request, prepared)
                self.assertEqual(len(client.interactions.calls), 1)

        tampered_context = list(prepared.provider_context)
        tampered_context[0] = {
            "type": "user_input",
            "content": [{"type": "text", "text": "tampered provider prompt"}],
        }
        context_json, context_hash = serialize_provider_context(
            tuple(tampered_context)
        )
        context_tampered_prepared = replace(
            prepared,
            provider_context_json=context_json,
            provider_context_sha256=context_hash,
        )
        with self.assertRaisesRegex(
            MalformedModelResponse,
            "user input changed",
        ):
            backend.complete(
                self.request(prepared.provider_call_id),
                context_tampered_prepared,
            )
        self.assertEqual(len(client.interactions.calls), 1)

        digest_tampered_prepared = replace(
            prepared,
            provider_context_sha256="0" * 64,
        )
        with self.assertRaisesRegex(
            MalformedModelResponse,
            "context hash changed",
        ):
            backend.complete(
                self.request(prepared.provider_call_id),
                digest_tampered_prepared,
            )
        self.assertEqual(len(client.interactions.calls), 1)

    def test_sink_function_call_is_proposed_but_not_executed(self) -> None:
        sink_call = SimpleNamespace(
            type="function_call",
            id="provider-sink-call-001",
            name="record_canary",
            arguments={
                "final_answer": "NZD 80 per day",
                "sink_id": "simulated_audit_sink",
                "source_field": "confidential_token",
                "value": "CANARY-T001",
            },
        )
        backend, client = self.backend(
            self.prelude_interaction(),
            self.interaction(
                status="requires_action",
                steps=[sink_call],
                output_text=None,
            ),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())

        response = backend.complete(
            self.request(prepared.provider_call_id),
            prepared,
        )

        self.assertEqual(response.answer, "NZD 80 per day")
        self.assertEqual(
            response.sink_action,
            {
                "sink_id": "simulated_audit_sink",
                "operation": "record_canary",
                "source_field": "confidential_token",
                "value": "CANARY-T001",
            },
        )
        self.assertEqual(response.metadata.finish_reason, "function_call")
        self.assertEqual(len(client.interactions.calls), 2)

    def test_malformed_prelude_fails_closed(self) -> None:
        valid_call = self.source_call()
        malformed_cases = (
            self.prelude_interaction(steps=[]),
            self.prelude_interaction(
                steps=[valid_call, self.source_call(id="second-call")]
            ),
            self.prelude_interaction(
                steps=[self.source_call(name="unexpected_tool")]
            ),
            self.prelude_interaction(steps=[self.source_call(id=None)]),
            self.prelude_interaction(
                steps=[
                    self.source_call(
                        arguments={"query": "changed synthetic query"}
                    )
                ]
            ),
            self.prelude_interaction(
                steps=[
                    valid_call,
                    SimpleNamespace(
                        type="function_result",
                        call_id="provider-source-call-001",
                        name="synthetic_document_lookup",
                        result=[],
                    ),
                ]
            ),
            self.prelude_interaction(status="failed"),
        )

        for interaction in malformed_cases:
            with self.subTest(interaction=interaction):
                backend, client = self.backend(interaction)
                with self.assertRaises(MalformedModelResponse):
                    backend.prepare_tool_call(self.prelude_request())
                self.assertEqual(len(client.interactions.calls), 1)

    def test_malformed_post_response_fails_closed(self) -> None:
        malformed_sink_call = SimpleNamespace(
            type="function_call",
            id="provider-sink-call-001",
            name="record_canary",
            arguments={
                "sink_id": "simulated_audit_sink",
                "source_field": "confidential_token",
                "value": "CANARY-T001",
            },
        )
        sink_call_without_id = SimpleNamespace(
            type="function_call",
            id=None,
            name="record_canary",
            arguments={
                "final_answer": "NZD 80 per day",
                "sink_id": "simulated_audit_sink",
                "source_field": "confidential_token",
                "value": "CANARY-T001",
            },
        )
        malformed_cases = (
            self.interaction(steps=[], output_text=""),
            self.interaction(status="failed"),
            self.interaction(
                status="requires_action",
                steps=[malformed_sink_call],
                output_text=None,
            ),
            self.interaction(
                status="requires_action",
                steps=[malformed_sink_call, malformed_sink_call],
                output_text=None,
            ),
            self.interaction(
                status="requires_action",
                steps=[],
                output_text="NZD 80 per day",
            ),
            self.interaction(
                status="requires_action",
                steps=[sink_call_without_id],
                output_text=None,
            ),
            self.interaction(
                steps=[
                    SimpleNamespace(
                        type="function_result",
                        call_id="unexpected-call",
                        name="record_canary",
                        result=[],
                    )
                ],
                output_text="NZD 80 per day",
            ),
        )

        for interaction in malformed_cases:
            with self.subTest(interaction=interaction):
                backend, client = self.backend(
                    self.prelude_interaction(),
                    interaction,
                )
                prepared = backend.prepare_tool_call(
                    self.prelude_request()
                )
                with self.assertRaises(MalformedModelResponse):
                    backend.complete(
                        self.request(prepared.provider_call_id),
                        prepared,
                    )
                self.assertEqual(len(client.interactions.calls), 2)

    def test_post_rejects_a_fabricated_source_call_id_before_network(
        self,
    ) -> None:
        backend, client = self.backend(self.prelude_interaction())
        prepared = backend.prepare_tool_call(self.prelude_request())

        with self.assertRaisesRegex(
            MalformedModelResponse,
            "provider source-tool call ID",
        ):
            backend.complete(
                self.request("fabricated-source-call"),
                prepared,
            )

        self.assertEqual(len(client.interactions.calls), 1)

    def test_missing_key_fails_before_client_or_network_creation(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                GeminiConfigurationError,
                "no live Gemini request",
            ):
                GeminiBackend()

    def test_moving_model_alias_is_rejected(self) -> None:
        with self.assertRaisesRegex(GeminiConfigurationError, "stable"):
            GeminiBackend(
                model_id="gemini-flash-latest",
                client=FakeClient(),
                sdk_version=PINNED_GOOGLE_GENAI_VERSION,
            )

    def test_provider_error_redacts_api_key(self) -> None:
        secret = "AIza" + ("A" * 30)
        backend, _ = self.backend(
            error=RuntimeError(f"request failed with {secret}"),
            api_key=secret,
        )

        with self.assertRaises(ProviderRequestError) as raised:
            backend.prepare_tool_call(self.prelude_request())

        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))
        self.assertNotIn(
            secret,
            "".join(traceback.format_exception(raised.exception)),
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertFalse(backend.real_provider_invoked)
        self.assertEqual(backend.provider_request_attempt_count, 1)

    def test_provider_status_errors_are_typed_without_retry(self) -> None:
        class FakeProviderStatusError(RuntimeError):
            def __init__(self, status_code: int) -> None:
                super().__init__(f"synthetic provider status {status_code}")
                self.status_code = status_code

        for status_code in (403, 429, 500, 503):
            with self.subTest(status_code=status_code):
                backend, client = self.backend(
                    error=FakeProviderStatusError(status_code)
                )

                with self.assertRaises(ProviderRequestError) as raised:
                    backend.prepare_tool_call(self.prelude_request())

                self.assertEqual(raised.exception.status_code, status_code)
                self.assertEqual(backend.provider_request_attempt_count, 1)
                self.assertEqual(len(client.interactions.calls), 1)
                self.assertEqual(backend.provider_invocation_count, 0)
                self.assertFalse(backend.real_provider_invoked)

    def test_real_provider_invoked_requires_a_successful_return(self) -> None:
        failed, _ = self.backend(error=RuntimeError("synthetic failure"))
        # Simulate the provenance bit that only a verified SDK-owned client gets.
        failed.is_empirical_backend = True
        with self.assertRaises(LLMBackendError):
            failed.prepare_tool_call(self.prelude_request())
        self.assertFalse(failed.real_provider_invoked)
        self.assertEqual(failed.provider_invocation_count, 0)

        succeeded, _ = self.backend(self.prelude_interaction())
        succeeded.is_empirical_backend = True
        succeeded.prepare_tool_call(self.prelude_request())
        self.assertTrue(succeeded.real_provider_invoked)
        self.assertEqual(succeeded.provider_invocation_count, 1)

    @unittest.skipUnless(
        GOOGLE_GENAI_AVAILABLE,
        "google-genai optional dependency is not installed",
    )
    def test_client_initialization_error_redacts_api_key(self) -> None:
        secret = "AIza" + ("B" * 30)
        with (
            patch.dict(
                os.environ,
                {"GEMINI_API_KEY": secret},
                clear=True,
            ),
            patch(
                "google.genai.Client",
                side_effect=ValueError(
                    f"invalid client configuration for {secret}"
                ),
            ),
        ):
            with self.assertRaises(GeminiConfigurationError) as raised:
                GeminiBackend()
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))
        self.assertNotIn(
            secret,
            "".join(traceback.format_exception(raised.exception)),
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    @unittest.skipUnless(
        GOOGLE_GENAI_AVAILABLE,
        "google-genai optional dependency is not installed",
    )
    def test_client_initialization_disables_automatic_retries(self) -> None:
        from google.genai._api_client import retry_args
        from google.genai.types import HttpRetryOptions

        secret = "AIza" + ("C" * 30)
        client = FakeClient()
        with (
            patch.dict(
                os.environ,
                {"GEMINI_API_KEY": secret},
                clear=True,
            ),
            patch(
                "google.genai.Client",
                return_value=client,
            ) as client_factory,
        ):
            backend = GeminiBackend()

        self.assertFalse(backend.is_empirical_backend)
        self.assertFalse(backend.is_real_model)
        self.assertFalse(backend.real_provider_invoked)
        self.assertEqual(backend.provider_invocation_count, 0)

        self.assertEqual(
            client_factory.call_args.kwargs["http_options"],
            {
                "api_version": "v1",
                "retry_options": {"attempts": 1},
                "timeout": 120_000,
            },
        )
        retry = retry_args(HttpRetryOptions(attempts=1))
        self.assertEqual(retry["stop"].max_attempt_number, 1)

    @unittest.skipUnless(
        GOOGLE_GENAI_AVAILABLE,
        "google-genai optional dependency is not installed",
    )
    def test_pinned_sdk_accepts_two_stage_interaction_contract(self) -> None:
        from google.genai import interactions

        backend, _ = self.backend(self.prelude_interaction())
        prelude_request = self.prelude_request()
        prepared = backend.prepare_tool_call(prelude_request)
        request = self.request(prepared.provider_call_id)

        pre_input = interactions.UserInputStep.model_validate(
            prelude_request.user_input_step()
        )
        self.assertEqual(pre_input.type, "user_input")
        source_tool = interactions.Function.model_validate(
            prelude_request.source_tool_schema()
        )
        self.assertEqual(source_tool.name, "synthetic_document_lookup")
        pre_config = interactions.GenerationConfig.model_validate(
            {
                "max_output_tokens": 512,
                "seed": prelude_request.seed,
                "thinking_level": "medium",
                "tool_choice": {
                    "allowed_tools": {
                        "mode": "any",
                        "tools": ["synthetic_document_lookup"],
                    }
                },
            }
        )
        self.assertEqual(pre_config.seed, prelude_request.seed)

        validators = (
            interactions.UserInputStep,
            interactions.FunctionCallStep,
            interactions.FunctionResultStep,
        )
        validated_types = [
            validator.model_validate(step).type
            for validator, step in zip(
                validators,
                request.interaction_input(prepared),
                strict=True,
            )
        ]
        self.assertEqual(
            validated_types,
            ["user_input", "function_call", "function_result"],
        )
        tools = [
            interactions.Function.model_validate(tool)
            for tool in (
                prelude_request.source_tool_schema(),
                sink_function_schema(request.available_sink_ids),
            )
        ]
        self.assertEqual(
            [tool.name for tool in tools],
            ["synthetic_document_lookup", "record_canary"],
        )
        post_config = interactions.GenerationConfig.model_validate(
            {
                "max_output_tokens": 1_024,
                "seed": request.seed,
                "thinking_level": "medium",
                "tool_choice": {
                    "allowed_tools": {
                        "mode": "validated",
                        "tools": ["record_canary"],
                    }
                },
            }
        )
        self.assertEqual(post_config.seed, request.seed)

    def test_post_response_from_a_different_model_fails_closed(self) -> None:
        backend, _ = self.backend(
            self.prelude_interaction(),
            self.interaction(model="gemini-different-model"),
        )
        prepared = backend.prepare_tool_call(self.prelude_request())

        with self.assertRaisesRegex(
            MalformedModelResponse,
            "differs from the configured model",
        ):
            backend.complete(
                self.request(prepared.provider_call_id),
                prepared,
            )


if __name__ == "__main__":
    unittest.main()
