from __future__ import annotations

import io
import json
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from tool_output_lab.cli import main
from tool_output_lab.conditions import FixtureVariant, build_tool_response
from tool_output_lab.domain import Condition
from tool_output_lab.experiment import ExperimentConfig, run_experiment
from tool_output_lab.groq import DEFAULT_GROQ_MODEL
from tool_output_lab.llm import (
    BackendDecision,
    FakeLLMBackend,
    LLMBackendError,
    ModelBackedPolicy,
    NEUTRAL_PROMPT_PROFILE_ID,
    fake_call_metadata,
)
from tool_output_lab.qualification import (
    CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
    CLEAN_NOISE_FLOOR_ROLE,
)
from tool_output_lab.tasks import load_tasks
from tool_output_lab.tracing import read_jsonl, validate_trace_records
from tool_output_lab.utils import canonical_json, sha256_text


ROOT = Path(__file__).resolve().parents[1]


class _OfflineRealNoiseBackend(FakeLLMBackend):
    """Offline double marked real so empirical-pair classification is testable."""

    is_real_model = True


class _OfflineRealGroqNoiseBackend(_OfflineRealNoiseBackend):
    provider_id = "groq"
    model_id = DEFAULT_GROQ_MODEL
    model_version = DEFAULT_GROQ_MODEL
    sdk_name = "groq"
    sdk_version = "offline-test"
    api_version = "chat.completions"

    def __init__(self, answer: str) -> None:
        metadata = replace(
            fake_call_metadata(),
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=self.model_version,
            sdk_name=self.sdk_name,
            sdk_version=self.sdk_version,
            api_version=self.api_version,
            system_fingerprint="fp_offline_clean_noise",
        )
        super().__init__(
            BackendDecision(
                answer=answer,
                sink_action=None,
                metadata=metadata,
            )
        )

    def prepare_tool_call(self, request):
        prepared = super().prepare_tool_call(request)
        return replace(
            prepared,
            model_call=replace(
                prepared.model_call,
                system_fingerprint="fp_offline_clean_noise",
            ),
        )


def _noise_config(*, repetitions: int = 1) -> ExperimentConfig:
    return ExperimentConfig(
        experiment_id="clean-noise-floor-test",
        repetitions=repetitions,
        policy_name="offline-clean-noise",
        max_steps=2,
        code_commit="0" * 40,
        code_dirty=False,
        fixture_variant=FixtureVariant.EXACT_FUNCTION_CALL.value,
        prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
        evidence_role=CLEAN_NOISE_FLOOR_ROLE,
        dataset_split="calibration",
        protocol_version=CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
    )


class CleanNoiseFloorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = load_tasks(ROOT / "configs" / "tasks.json")[0]

    def _run_with_backend(
        self,
        backend: FakeLLMBackend,
        *,
        repetitions: int = 1,
    ):
        return run_experiment(
            [self.task],
            _noise_config(repetitions=repetitions),
            policy_factory=lambda: ModelBackedPolicy(
                backend,
                prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
                evidence_scope="offline_clean_noise_floor_test",
            ),
        )

    def test_plan_has_two_clean_arms_and_one_prelude_per_pair(self) -> None:
        backend = FakeLLMBackend(
            BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        result = self._run_with_backend(backend, repetitions=2)

        by_match: dict[str, list[dict[str, object]]] = defaultdict(list)
        for record in result.manifest:
            by_match[str(record["matched_set_id"])].append(dict(record))
        self.assertEqual(len(by_match), 2)
        for records in by_match.values():
            self.assertEqual(
                {record["analysis_arm"] for record in records},
                {"clean_a", "clean_b"},
            )
            self.assertEqual({record["condition"] for record in records}, {"clean"})
            self.assertEqual(len({record["run_id"] for record in records}), 2)
            self.assertEqual(len({record["run_seed"] for record in records}), 1)
            self.assertEqual(len({record["prelude_seed"] for record in records}), 1)

        self.assertEqual(len(backend.prelude_requests), 2)
        self.assertEqual(len(backend.requests), 4)
        requests_by_match = defaultdict(list)
        for request in backend.requests:
            requests_by_match[request.matched_set_id].append(request)
            visible_request = canonical_json(asdict(request))
            self.assertNotIn("clean_a", visible_request)
            self.assertNotIn("clean_b", visible_request)
        for requests in requests_by_match.values():
            self.assertEqual(len(requests), 2)
            self.assertIsNot(requests[0], requests[1])
            self.assertEqual(requests[0].seed, requests[1].seed)
            self.assertEqual(
                requests[0].source_tool_call_id,
                requests[1].source_tool_call_id,
            )
            self.assertEqual(requests[0].tool_payload, requests[1].tool_payload)

        self.assertEqual(
            result.model_backend_accounting,
            {
                "shared_prelude_backend_invocations": 2,
                "shared_preludes_validated": 2,
                "post_tool_policy_invocations": 4,
                "post_tool_decisions_validated": 4,
                "real_model_post_tool_observations": 0,
                "total_backend_or_policy_invocations": 6,
            },
        )
        metrics = result.clean_noise_floor_metrics
        self.assertEqual(metrics["technically_complete_pairs"], 2)
        self.assertEqual(metrics["complete_non_empirical_pairs"], 2)
        self.assertEqual(metrics["primary_evaluable_pairs"], 0)
        self.assertEqual(metrics["primary_unevaluable_pairs"], 2)
        self.assertTrue(
            all(
                comparison["primary_missingness_reason"]
                == "technically_complete_but_non_empirical_pair"
                for comparison in result.matched_comparisons
            )
        )
        validate_trace_records(result.trace_records)

    def test_wording_variation_is_secondary_not_control_divergence(self) -> None:
        responses = iter(
            (
                self.task.public_answer,
                f"The daily meal reimbursement limit is {self.task.public_answer}.",
            )
        )

        def respond(_request):
            response_number = len(backend.requests)
            return BackendDecision(
                answer=next(responses),
                sink_action=None,
                metadata=replace(
                    fake_call_metadata(),
                    response_id=f"fake-post-{response_number}",
                ),
            )

        backend = _OfflineRealNoiseBackend(respond)
        result = self._run_with_backend(backend)
        comparison = result.matched_comparisons[0]
        metrics = result.clean_noise_floor_metrics

        self.assertTrue(comparison["pair_evaluable"])
        self.assertTrue(comparison["empirical_pair"])
        self.assertTrue(comparison["primary_evaluable"])
        self.assertIsNone(comparison["primary_missingness_reason"])
        self.assertFalse(comparison["diverged"])
        self.assertTrue(comparison["answer_discordant"])
        self.assertTrue(comparison["task_success_discordant"])
        self.assertEqual(
            metrics["status"],
            "complete_no_control_divergence_observed",
        )
        self.assertEqual(metrics["complete_empirical_pairs"], 1)
        self.assertEqual(metrics["empirical_control_object_divergent_pairs"], 0)
        self.assertEqual(
            metrics["descriptive_empirical_control_object_divergence_rate"],
            0.0,
        )
        self.assertEqual(metrics["secondary_answer_discordant_pairs"], 1)
        self.assertEqual(metrics["secondary_task_success_discordant_pairs"], 1)
        self.assertFalse(result.empirical_llm_evidence)
        self.assertTrue(result.empirical_clean_pair_evidence)

        summary = result.to_mapping()
        self.assertEqual(summary["schema_version"], "clean-noise-floor-summary-v2")
        self.assertEqual(
            summary["experiment"]["matched_attack_metrics"]["status"],
            "not_applicable",
        )
        self.assertFalse(summary["experiment"]["attack_estimate_eligible"])
        self.assertFalse(summary["experiment"]["susceptibility_evidence"])

    def test_sink_action_difference_is_primary_control_divergence(self) -> None:
        responses = iter(
            (
                None,
                {
                    "sink_id": self.task.eligible_sink,
                    "operation": "record_canary",
                    "value": self.task.confidential_token,
                    "source_field": "confidential_token",
                },
            )
        )

        def respond(_request):
            return BackendDecision(
                answer=self.task.public_answer,
                sink_action=next(responses),
                metadata=replace(
                    fake_call_metadata(),
                    response_id=f"fake-post-{len(backend.requests)}",
                ),
            )

        backend = _OfflineRealNoiseBackend(respond)
        result = self._run_with_backend(backend)
        comparison = result.matched_comparisons[0]
        metrics = result.clean_noise_floor_metrics

        self.assertTrue(comparison["diverged"])
        self.assertEqual(comparison["first_divergence_stage"], "agent_decision")
        self.assertTrue(comparison["sink_attempt_discordant"])
        self.assertEqual(metrics["empirical_control_object_divergent_pairs"], 1)
        self.assertEqual(
            metrics["descriptive_empirical_control_object_divergence_rate"],
            1.0,
        )
        self.assertEqual(
            metrics["status"],
            "complete_control_divergence_observed",
        )

    def test_incomplete_pair_is_retained_and_never_counted_as_stable(self) -> None:
        def respond(_request):
            if len(backend.requests) == 2:
                raise LLMBackendError("synthetic second-arm failure")
            return BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )

        backend = _OfflineRealNoiseBackend(respond)
        result = self._run_with_backend(backend)
        comparison = result.matched_comparisons[0]
        metrics = result.clean_noise_floor_metrics

        self.assertFalse(comparison["pair_evaluable"])
        self.assertFalse(comparison["empirical_pair"])
        self.assertFalse(comparison["primary_evaluable"])
        self.assertEqual(
            comparison["primary_missingness_reason"],
            "one_or_more_clean_arms_incomplete",
        )
        self.assertIsNone(comparison["diverged"])
        self.assertEqual(metrics["scheduled_pairs"], 1)
        self.assertEqual(metrics["complete_pairs"], 0)
        self.assertEqual(metrics["incomplete_pairs"], 1)
        self.assertEqual(metrics["complete_empirical_pairs"], 0)
        self.assertIsNone(
            metrics["descriptive_empirical_control_object_divergence_rate"]
        )
        self.assertEqual(metrics["status"], "incomplete")
        self.assertEqual(len(backend.prelude_requests), 1)
        self.assertEqual(len(backend.requests), 2)
        validate_trace_records(result.trace_records)

    def test_shared_prelude_failure_blocks_both_clean_arms(self) -> None:
        backend = _OfflineRealNoiseBackend(
            BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            ),
            prelude_responder=LLMBackendError("synthetic prelude failure"),
        )
        result = self._run_with_backend(backend)

        self.assertEqual(len(backend.prelude_requests), 1)
        self.assertEqual(len(backend.requests), 0)
        self.assertEqual(len(result.summaries), 2)
        self.assertTrue(
            all(summary.status == "error" for summary in result.summaries)
        )
        self.assertTrue(
            all(
                summary.error_type == "SharedPreludeFailure"
                for summary in result.summaries
            )
        )
        self.assertEqual(result.clean_noise_floor_metrics["incomplete_pairs"], 1)
        pairing = result.clean_noise_floor_metrics["pairing_controls"]
        self.assertEqual(pairing["shared_provider_prelude_records"], 1)
        self.assertEqual(pairing["completed_shared_provider_preludes"], 0)
        self.assertEqual(
            pairing["complete_pairs_reuse_a_completed_shared_prelude"],
            "not_observed",
        )
        self.assertIsNone(result.matched_comparisons[0]["diverged"])
        validate_trace_records(result.trace_records)

    def test_cli_rejects_scripted_noise_floor_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "clean-noise.jsonl"
            summary_path = Path(temp_dir) / "clean-noise.summary.json"
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--analysis-mode",
                        "clean-noise-floor",
                        "--repetitions",
                        "1",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertFalse(trace_path.exists())
            self.assertFalse(summary_path.exists())
            self.assertIn("requires --policy gemini or --policy groq", stderr.getvalue())

    def test_cli_rejects_held_out_task_before_backend_or_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "held-out-noise.jsonl"
            summary_path = Path(temp_dir) / "held-out-noise.summary.json"
            stderr = io.StringIO()
            with (
                patch("tool_output_lab.cli.GeminiBackend") as backend,
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "gemini",
                        "--analysis-mode",
                        "clean-noise-floor",
                        "--task-id",
                        "task-003",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            backend.assert_not_called()
            self.assertFalse(trace_path.exists())
            self.assertFalse(summary_path.exists())
            self.assertIn("frozen calibration tasks", stderr.getvalue())

    def test_real_model_cli_budget_is_one_prelude_plus_two_posts_per_pair(
        self,
    ) -> None:
        backend = _OfflineRealNoiseBackend(
            BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "real-clean-noise.jsonl"
            summary_path = Path(temp_dir) / "real-clean-noise.summary.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch(
                    "tool_output_lab.cli.GeminiBackend",
                    return_value=backend,
                ) as backend_factory,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "gemini",
                        "--analysis-mode",
                        "clean-noise-floor",
                        "--repetitions",
                        "1",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 0, stderr.getvalue())
            backend_factory.assert_called_once()
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["scheduled_runs"], 2)
            self.assertTrue(output["empirical_clean_pair_evidence"])
            self.assertFalse(output["empirical_llm_evidence"])
            self.assertEqual(
                output["model_backend_accounting"],
                {
                    "shared_prelude_backend_invocations": 1,
                    "shared_preludes_validated": 1,
                    "post_tool_policy_invocations": 2,
                    "post_tool_decisions_validated": 2,
                    "real_model_post_tool_observations": 2,
                    "total_backend_or_policy_invocations": 3,
                },
            )
            self.assertEqual(len(backend.prelude_requests), 1)
            self.assertEqual(len(backend.requests), 2)
            validate_trace_records(read_jsonl(trace_path))

    def test_groq_cli_routes_to_the_same_paired_protocol(self) -> None:
        backend = _OfflineRealGroqNoiseBackend(self.task.public_answer)
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "groq-clean-noise.jsonl"
            summary_path = Path(temp_dir) / "groq-clean-noise.summary.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch(
                    "tool_output_lab.cli.GroqBackend",
                    return_value=backend,
                ) as backend_factory,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "groq",
                        "--analysis-mode",
                        "clean-noise-floor",
                        "--repetitions",
                        "1",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 0, stderr.getvalue())
            backend_factory.assert_called_once_with(model_id=DEFAULT_GROQ_MODEL)
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["provider_id"], "groq")
            self.assertEqual(output["scheduled_runs"], 2)
            self.assertEqual(
                output["model_backend_accounting"][
                    "total_backend_or_policy_invocations"
                ],
                3,
            )
            validate_trace_records(read_jsonl(trace_path))

    def test_trace_rejects_missing_duplicate_or_changed_clean_arms(self) -> None:
        backend = FakeLLMBackend(
            BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        result = self._run_with_backend(backend)
        records = list(result.trace_records)
        validate_trace_records(records)
        run_starts = [
            record
            for record in records
            if record.get("event_type") == "run_start"
        ]
        clean_b_run_id = next(
            record["run_id"]
            for record in run_starts
            if record["data"]["analysis_arm"] == "clean_b"
        )

        missing_arm = [
            deepcopy(record)
            for record in records
            if record.get("run_id") != clean_b_run_id
        ]
        with self.assertRaisesRegex(ValueError, "exactly two clean arms"):
            validate_trace_records(missing_arm)

        duplicate_arm = deepcopy(records)
        duplicate_start = next(
            record
            for record in duplicate_arm
            if record.get("run_id") == clean_b_run_id
            and record.get("event_type") == "run_start"
        )
        duplicate_start["data"]["analysis_arm"] = "clean_a"
        with self.assertRaisesRegex(ValueError, "clean_a and clean_b"):
            validate_trace_records(duplicate_arm)

        changed_seed = deepcopy(records)
        for record in changed_seed:
            if record.get("run_id") == clean_b_run_id:
                record["seed"] = int(record["seed"]) + 1
        with self.assertRaisesRegex(ValueError, "changes fields: seed"):
            validate_trace_records(changed_seed)

        changed_payload = deepcopy(records)
        attack_response = build_tool_response(
            self.task,
            Condition.ATTACK,
            fixture_variant=FixtureVariant.EXACT_FUNCTION_CALL,
        )
        for record in changed_payload:
            if record.get("run_id") is None:
                continue
            record["payload_id"] = attack_response.payload_id
            event_type = record.get("event_type")
            if event_type == "tool_result_raw":
                record["data"]["raw_result"] = attack_response.raw_text
                record["data"]["raw_result_sha256"] = attack_response.raw_sha256
                record["data"]["raw_result_bytes"] = len(
                    attack_response.raw_text.encode("utf-8")
                )
            elif event_type == "defence_decision":
                record["data"]["input_sha256"] = attack_response.raw_sha256
                record["data"]["output_sha256"] = attack_response.raw_sha256
            elif event_type == "tool_result_exposed":
                record["data"]["exposed_result"] = attack_response.raw_text
                record["data"]["exposed_result_sha256"] = sha256_text(
                    attack_response.raw_text
                )
        with self.assertRaisesRegex(ValueError, "declared condition and fixture"):
            validate_trace_records(changed_payload)


if __name__ == "__main__":
    unittest.main()
