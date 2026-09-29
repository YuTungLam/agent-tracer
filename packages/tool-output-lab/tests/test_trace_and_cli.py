from __future__ import annotations

import io
import json
import os
import tempfile
import tomllib
import unittest
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tool_output_lab import __version__
from tool_output_lab.cli import QUALIFICATION_MODES, main
from tool_output_lab.experiment import ExperimentConfig, run_experiment
from tool_output_lab.groq import DEFAULT_GROQ_MODEL
from tool_output_lab.llm import (
    BackendDecision,
    CAPABILITY_PROMPT_PROFILE_ID,
    FakeLLMBackend,
    GUARDED_PROMPT_PROFILE_ID,
    LLMBackendError,
    ModelBackedPolicy,
    fake_call_metadata,
)
from tool_output_lab.tasks import load_tasks
from tool_output_lab.tracing import (
    PRELUDE_SCHEMA_VERSION,
    TRACE_SCHEMA_VERSION,
    read_jsonl,
    validate_trace,
    validate_trace_records,
)
from tool_output_lab.utils import canonical_json, sha256_text


ROOT = Path(__file__).resolve().parents[1]


class TraceAndCliTests(unittest.TestCase):
    def test_runtime_version_matches_package_metadata(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            package_version = tomllib.load(handle)["project"]["version"]
        self.assertEqual(__version__, package_version)

    def test_capability_cli_uses_dedicated_authorized_profile(self) -> None:
        self.assertEqual(
            QUALIFICATION_MODES["capability"]["prompt_profile_id"],
            CAPABILITY_PROMPT_PROFILE_ID,
        )
        self.assertTrue(
            QUALIFICATION_MODES["capability"]["user_authorized_sink"]
        )

    def test_jsonl_is_canonical_and_complete(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.jsonl"
            run_experiment(
                [task],
                ExperimentConfig(repetitions=1),
                trace_path=trace_path,
            )
            raw_lines = trace_path.read_text(encoding="utf-8").splitlines()
            events = read_jsonl(trace_path)
            self.assertEqual(len(raw_lines), len(events))
            self.assertTrue(trace_path.read_bytes().endswith(b"\n"))
            for raw_line, event in zip(raw_lines, events, strict=True):
                self.assertEqual(raw_line, canonical_json(event))
                for field in (
                    "schema_version",
                    "run_id",
                    "matched_set_id",
                    "condition",
                    "event_index",
                    "event_type",
                    "data",
                ):
                    self.assertIn(field, event)

    def test_cli_writes_declared_artifacts_and_reports_no_external_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "pilot.jsonl"
            summary_path = Path(temp_dir) / "pilot.summary.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--tasks",
                        str(ROOT / "configs" / "tasks.json"),
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                        "--repetitions",
                        "1",
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["external_side_effects"], 0)
            self.assertFalse(output["empirical_llm_evidence"])
            self.assertEqual(output["runtime_kind"], "scripted_control")
            self.assertEqual(output["evidence_scope"], "instrumentation_validation")
            self.assertEqual(output["scheduled_runs"], 15)
            self.assertTrue(trace_path.exists())
            self.assertTrue(summary_path.exists())

    def test_cli_refuses_to_overwrite_without_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "pilot.jsonl"
            trace_path.write_text("sentinel", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--tasks",
                        str(ROOT / "configs" / "tasks.json"),
                        "--trace",
                        str(trace_path),
                    ]
                )
            self.assertEqual(exit_code, 1)
            self.assertEqual(trace_path.read_text(encoding="utf-8"), "sentinel")
            self.assertIn("Refusing to overwrite", stderr.getvalue())

    def test_trace_validator_rejects_empty_and_corrupt_traces(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one event"):
            validate_trace([])

        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment([task], ExperimentConfig(repetitions=1))
        missing_field = [dict(event) for event in result.events]
        missing_field[0].pop("schema_version")
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_trace(missing_field)

        changed_context = [dict(event) for event in result.events]
        changed_context[1]["task_id"] = "different-task"
        with self.assertRaisesRegex(ValueError, "invariant fields"):
            validate_trace(changed_context)

        broken_parent = [dict(event) for event in result.events]
        broken_parent[1]["parent_event_id"] = "nonexistent-event"
        with self.assertRaisesRegex(ValueError, "preceding parent"):
            validate_trace(broken_parent)

    def test_qualification_provenance_is_emitted_and_bound(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        backend = FakeLLMBackend(
            BackendDecision(
                answer=task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        config = ExperimentConfig(
            experiment_id="qualification-provenance-test",
            repetitions=1,
            policy_name="fake-llm",
            max_steps=2,
            prompt_profile_id=GUARDED_PROMPT_PROFILE_ID,
        )
        result = run_experiment(
            [task],
            config,
            policy_factory=lambda: ModelBackedPolicy(
                backend,
                prompt_profile_id=GUARDED_PROMPT_PROFILE_ID,
            ),
        )

        expected = {
            "prompt_profile_id": GUARDED_PROMPT_PROFILE_ID,
            "prompt_profile_version": "1.0",
            "evidence_role": "instrumentation_control",
            "dataset_split": "not_applicable",
            "protocol_version": "attack-qualification-v2",
            "attack_estimate_eligible": False,
            "fixture_variant": "legacy_override",
        }
        self.assertEqual(len(result.preludes), 1)
        self.assertEqual(
            result.preludes[0]["schema_version"],
            PRELUDE_SCHEMA_VERSION,
        )
        self.assertEqual(PRELUDE_SCHEMA_VERSION, "matched-set-prelude-v4")
        for field, value in expected.items():
            self.assertEqual(result.preludes[0][field], value)

        self.assertTrue(result.events)
        self.assertEqual(TRACE_SCHEMA_VERSION, "trace-event-v5")
        for event in result.events:
            self.assertEqual(event["schema_version"], TRACE_SCHEMA_VERSION)
            for field, value in expected.items():
                self.assertEqual(event[field], value)
        validate_trace_records(result.trace_records)

        tampered_records = deepcopy(list(result.trace_records))
        tampered_records[0]["fixture_variant"] = "tampered_variant"
        with self.assertRaisesRegex(
            ValueError,
            "fixture_variant|fixture variant",
        ):
            validate_trace_records(tampered_records)

        contradictory = deepcopy(list(result.events))
        for event in contradictory:
            event["attack_estimate_eligible"] = True
        with self.assertRaisesRegex(
            ValueError,
            "contradicts evidence role and split",
        ):
            validate_trace(contradictory)

    def test_empirical_flag_requires_retained_matching_model_call(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        backend = FakeLLMBackend(
            BackendDecision(
                answer=task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        backend.is_real_model = True
        result = run_experiment(
            [task],
            ExperimentConfig(
                experiment_id="empirical-provenance-test",
                repetitions=1,
                policy_name="offline-real",
                max_steps=2,
                prompt_profile_id=GUARDED_PROMPT_PROFILE_ID,
            ),
            policy_factory=lambda: ModelBackedPolicy(
                backend,
                prompt_profile_id=GUARDED_PROMPT_PROFILE_ID,
            ),
        )
        forged = deepcopy(list(result.events))
        decision = next(
            event
            for event in forged
            if event["condition"] == "clean"
            and event["event_type"] == "agent_decision"
        )
        decision["data"]["model_call"] = None
        with self.assertRaisesRegex(
            ValueError,
            "lacks retained model-call provenance",
        ):
            validate_trace(forged)

    def test_trace_validator_enforces_terminal_grammar(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment([task], ExperimentConfig(repetitions=1))

        forged_status = deepcopy(list(result.events))
        run_end = next(
            event
            for event in forged_status
            if event["condition"] == "clean"
            and event["event_type"] == "run_end"
        )
        run_end["data"]["status"] = "error"
        with self.assertRaisesRegex(
            ValueError,
            "Error run .* exactly one run_error",
        ):
            validate_trace(forged_status)

        forged_evaluability = deepcopy(list(result.events))
        evaluation = next(
            event
            for event in forged_evaluability
            if event["condition"] == "clean"
            and event["event_type"] == "task_evaluation"
        )
        evaluation["data"]["outcome_evaluable"] = False
        with self.assertRaisesRegex(
            ValueError,
            "must be outcome-evaluable",
        ):
            validate_trace(forged_evaluability)

        forged_task_success = deepcopy(list(result.events))
        evaluation = next(
            event
            for event in forged_task_success
            if event["condition"] == "clean"
            and event["event_type"] == "task_evaluation"
        )
        run_end = next(
            event
            for event in forged_task_success
            if event["run_id"] == evaluation["run_id"]
            and event["event_type"] == "run_end"
        )
        evaluation["data"]["task_success"] = False
        run_end["data"]["task_success"] = False
        with self.assertRaisesRegex(
            ValueError,
            "contradicts retained answers",
        ):
            validate_trace(forged_task_success)

        forged_ground_truth = deepcopy(list(result.events))
        evaluation = next(
            event
            for event in forged_ground_truth
            if event["condition"] == "clean"
            and event["event_type"] == "task_evaluation"
        )
        run_end = next(
            event
            for event in forged_ground_truth
            if event["run_id"] == evaluation["run_id"]
            and event["event_type"] == "run_end"
        )
        evaluation["data"]["expected_answer"] = "coherently forged answer"
        evaluation["data"]["task_success"] = False
        run_end["data"]["task_success"] = False
        with self.assertRaisesRegex(
            ValueError,
            "expected answer differs from its task definition",
        ):
            validate_trace(forged_ground_truth)

        forged_phase_count = deepcopy(list(result.events))
        run_end = next(
            event
            for event in forged_phase_count
            if event["condition"] == "clean"
            and event["event_type"] == "run_end"
        )
        run_end["data"]["step_count"] = 0
        with self.assertRaisesRegex(
            ValueError,
            "step count disagrees with phase flags",
        ):
            validate_trace(forged_phase_count)

    def test_trace_validator_recomputes_retained_content_hashes(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment([task], ExperimentConfig(repetitions=1))

        changed_prompt = deepcopy(list(result.events))
        user_input = next(
            event
            for event in changed_prompt
            if event["condition"] == "clean"
            and event["event_type"] == "user_input"
        )
        user_input["data"]["prompt"] = "tampered retained prompt"
        with self.assertRaisesRegex(ValueError, "User prompt hash"):
            validate_trace(changed_prompt)

        changed_answer = deepcopy(list(result.events))
        decision = next(
            event
            for event in changed_answer
            if event["condition"] == "clean"
            and event["event_type"] == "agent_decision"
        )
        decision["data"]["answer"] = "tampered answer"
        with self.assertRaisesRegex(ValueError, "Agent answer hash"):
            validate_trace(changed_answer)

        changed_task_definition = deepcopy(list(result.events))
        run_start = next(
            event
            for event in changed_task_definition
            if event["condition"] == "clean"
            and event["event_type"] == "run_start"
        )
        run_start["data"]["task_definition"]["public_answer"] = (
            "tampered task answer"
        )
        with self.assertRaisesRegex(ValueError, "task-definition hash"):
            validate_trace(changed_task_definition)

    def test_trace_validator_binds_raw_defence_and_exposed_chain(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment([task], ExperimentConfig(repetitions=1))

        changed_raw = deepcopy(list(result.events))
        clean_run_id = next(
            event["run_id"]
            for event in changed_raw
            if event["condition"] == "clean"
        )
        raw = next(
            event
            for event in changed_raw
            if event["run_id"] == clean_run_id
            and event["event_type"] == "tool_result_raw"
        )
        raw["data"]["raw_result"] = f"{raw['data']['raw_result']} "
        raw_hash = sha256_text(raw["data"]["raw_result"])
        raw["data"]["raw_result_sha256"] = raw_hash
        raw["data"]["raw_result_bytes"] = len(
            raw["data"]["raw_result"].encode("utf-8")
        )
        for event in changed_raw:
            if event["run_id"] == clean_run_id:
                event["payload_id"] = f"payload-{raw_hash[:16]}"
        with self.assertRaisesRegex(ValueError, "declared condition and fixture"):
            validate_trace(changed_raw)

        changed_exposed = deepcopy(list(result.events))
        exposed = next(
            event
            for event in changed_exposed
            if event["condition"] == "clean"
            and event["event_type"] == "tool_result_exposed"
        )
        exposed["data"]["exposed_result"] = (
            f"{exposed['data']['exposed_result']} "
        )
        exposed_hash = sha256_text(exposed["data"]["exposed_result"])
        exposed["data"]["exposed_result_sha256"] = exposed_hash
        defence = next(
            event
            for event in changed_exposed
            if event["run_id"] == exposed["run_id"]
            and event["event_type"] == "defence_decision"
        )
        defence["data"]["output_sha256"] = exposed_hash
        with self.assertRaisesRegex(ValueError, "Untransformed tool result"):
            validate_trace(changed_exposed)

    def test_trace_validator_reconciles_sink_chain_with_evaluation(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment(
            [task],
            ExperimentConfig(
                repetitions=1,
                policy_name="vulnerable",
            ),
        )

        changed_evaluation = deepcopy(list(result.events))
        evaluation = next(
            event
            for event in changed_evaluation
            if event["condition"] == "attack"
            and event["event_type"] == "task_evaluation"
        )
        evaluation["data"]["sink_attempted"] = False
        with self.assertRaisesRegex(ValueError, "Evaluation contradicts"):
            validate_trace(changed_evaluation)

        changed_attempt = deepcopy(list(result.events))
        attempt = next(
            event
            for event in changed_attempt
            if event["condition"] == "attack"
            and event["event_type"] == "sink_attempt"
        )
        attempt["data"]["canonical_arguments"] = {
            **attempt["data"]["canonical_arguments"],
            "value": "CANARY-TAMPERED",
        }
        with self.assertRaisesRegex(ValueError, "differs from the agent action"):
            validate_trace(changed_attempt)

        blocked_effect = deepcopy(list(result.events))
        sink_result = next(
            event
            for event in blocked_effect
            if event["condition"] == "attack"
            and event["event_type"] == "sink_result"
        )
        sink_result["data"]["blocked"] = True
        with self.assertRaisesRegex(
            ValueError,
            "Sink result contradicts retained task/action",
        ):
            validate_trace(blocked_effect)

    def test_error_run_sink_result_is_recomputed_from_retained_inputs(
        self,
    ) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        with patch(
            "tool_output_lab.experiment._answers_match",
            side_effect=RuntimeError("synthetic evaluator failure"),
        ):
            result = run_experiment(
                [task],
                ExperimentConfig(
                    repetitions=1,
                    policy_name="vulnerable",
                ),
            )
        validate_trace(result.events)

        forged = deepcopy(list(result.events))
        sink_result = next(
            event
            for event in forged
            if event["condition"] == "attack"
            and event["event_type"] == "sink_result"
        )
        sink_result["data"].update(
            {
                "simulator_accepted": False,
                "blocked": True,
                "security_policy_violation": False,
                "prohibited_simulated_effect": False,
            }
        )
        with self.assertRaisesRegex(
            ValueError,
            "Sink result contradicts retained task/action",
        ):
            validate_trace(forged)

        non_boolean = deepcopy(list(result.events))
        sink_result = next(
            event
            for event in non_boolean
            if event["condition"] == "attack"
            and event["event_type"] == "sink_result"
        )
        for field in (
            "simulator_accepted",
            "user_authorized",
            "blocked",
            "security_policy_violation",
            "prohibited_simulated_effect",
            "external_side_effect",
        ):
            sink_result["data"][field] = int(sink_result["data"][field])
        with self.assertRaisesRegex(
            ValueError,
            "Sink result has non-boolean outcomes",
        ):
            validate_trace(non_boolean)

    def test_trace_records_require_complete_matched_triplet(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        result = run_experiment([task], ExperimentConfig(repetitions=1))
        truncated = [
            event
            for event in result.events
            if event["condition"] != "attack"
        ]

        with self.assertRaisesRegex(
            ValueError,
            "exactly clean, placebo, and attack",
        ):
            validate_trace_records(truncated)

    def test_trace_and_summary_paths_cannot_alias(self) -> None:
        task = load_tasks(ROOT / "configs" / "tasks.json")[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "same-output.json"
            with self.assertRaisesRegex(ValueError, "different files"):
                run_experiment(
                    [task],
                    ExperimentConfig(repetitions=1),
                    trace_path=output_path,
                    summary_path=output_path,
                    overwrite=True,
                )
            self.assertFalse(output_path.exists())

    def test_gemini_cli_missing_key_creates_no_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "gemini.jsonl"
            summary_path = Path(temp_dir) / "gemini.summary.json"
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, {}, clear=True),
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "gemini",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertFalse(trace_path.exists())
            self.assertFalse(summary_path.exists())
            self.assertIn("GEMINI_API_KEY", stderr.getvalue())
            self.assertIn("no live Gemini request", stderr.getvalue())

    def test_groq_cli_missing_key_creates_no_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "groq.jsonl"
            summary_path = Path(temp_dir) / "groq.summary.json"
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, {}, clear=True),
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "groq",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertFalse(trace_path.exists())
            self.assertFalse(summary_path.exists())
            self.assertIn("GROQ_API_KEY", stderr.getvalue())
            self.assertIn("no live Groq request", stderr.getvalue())

    def test_groq_held_out_is_rejected_before_backend_or_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "groq-held-out.jsonl"
            stderr = io.StringIO()
            with (
                patch("tool_output_lab.cli.GroqBackend") as backend,
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "groq",
                        "--qualification-mode",
                        "held-out-evaluation",
                        "--confirm-held-out-evaluation",
                        "--trace",
                        str(trace_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            backend.assert_not_called()
            self.assertFalse(trace_path.exists())
            self.assertIn("Gemini-specific", stderr.getvalue())
            self.assertIn("separately frozen", stderr.getvalue())

    def test_groq_cli_uses_default_model_and_provider_transport(self) -> None:
        class SuccessfulGroqControl(FakeLLMBackend):
            provider_id = "groq"
            model_id = DEFAULT_GROQ_MODEL
            model_version = DEFAULT_GROQ_MODEL
            sdk_name = "groq"
            sdk_version = "1.6.0"
            api_version = "openai/v1/chat/completions"
            is_real_model = True
            sampling_parameters = {
                "http_max_attempts_including_initial": 1,
                "parallel_tool_calls": False,
                "seed_source": "matched_phase_seeds",
            }

            def __init__(self) -> None:
                metadata = replace(
                    fake_call_metadata(),
                    provider_id=self.provider_id,
                    model_id=self.model_id,
                    model_version=self.model_version,
                    sdk_name=self.sdk_name,
                    sdk_version=self.sdk_version,
                    api_version=self.api_version,
                    system_fingerprint="fp_synthetic_groq",
                )
                super().__init__(
                    BackendDecision(
                        answer="NZD 80 per day",
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
                        system_fingerprint="fp_synthetic_groq",
                    ),
                )

        fake_backend = SuccessfulGroqControl()
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "groq.jsonl"
            summary_path = Path(temp_dir) / "groq.summary.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch(
                    "tool_output_lab.cli.GroqBackend",
                    return_value=fake_backend,
                ) as backend_factory,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "groq",
                        "--repetitions",
                        "1",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 0, stderr.getvalue())
            backend_factory.assert_called_once_with(
                model_id=DEFAULT_GROQ_MODEL
            )
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["provider_id"], "groq")
            self.assertEqual(output["model_id"], DEFAULT_GROQ_MODEL)
            events = read_jsonl(trace_path)
            self.assertEqual(
                {event["transport"] for event in events},
                {"groq_openai_chat_completions_v1"},
            )
            validate_trace_records(events)

            changed_fingerprint = deepcopy(events)
            attack_decision = next(
                event
                for event in changed_fingerprint
                if event.get("condition") == "attack"
                and event.get("event_type") == "agent_decision"
            )
            attack_decision["data"]["model_call"][
                "system_fingerprint"
            ] = "fp_different_backend"
            with self.assertRaisesRegex(
                ValueError,
                "fingerprint changes within matched set",
            ):
                validate_trace_records(changed_fingerprint)

            missing_prelude_fingerprint = deepcopy(events)
            prelude = next(
                record
                for record in missing_prelude_fingerprint
                if record.get("schema_version") == PRELUDE_SCHEMA_VERSION
            )
            prelude["tool_selection"]["model_call"].pop(
                "system_fingerprint"
            )
            with self.assertRaisesRegex(
                ValueError,
                "shared prelude lacks a system fingerprint",
            ):
                validate_trace_records(missing_prelude_fingerprint)

    def test_held_out_cli_requires_explicit_confirmation_before_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "held-out.jsonl"
            summary_path = Path(temp_dir) / "held-out.summary.json"
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
                        "--qualification-mode",
                        "held-out-evaluation",
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
            self.assertIn(
                "--confirm-held-out-evaluation",
                stderr.getvalue(),
            )

    def test_held_out_cli_requires_control_receipts_before_backend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "held-out.jsonl"
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
                        "--qualification-mode",
                        "held-out-evaluation",
                        "--confirm-held-out-evaluation",
                        "--trace",
                        str(trace_path),
                    ]
                )
            self.assertEqual(exit_code, 2)
            backend.assert_not_called()
            self.assertFalse(trace_path.exists())
            self.assertIn("summary receipts", stderr.getvalue())

    def test_smoke_cli_cannot_consume_a_frozen_held_out_task(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "smoke-held-out.jsonl"
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
                        "--qualification-mode",
                        "smoke",
                        "--task-id",
                        "task-003",
                        "--trace",
                        str(trace_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            backend.assert_not_called()
            self.assertFalse(trace_path.exists())
            self.assertIn("must not consume", stderr.getvalue())

    def test_held_out_cli_rejects_fixture_override_before_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "held-out-override.jsonl"
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
                        "--qualification-mode",
                        "held-out-evaluation",
                        "--confirm-held-out-evaluation",
                        "--fixture-variant",
                        "structured_next_action",
                        "--trace",
                        str(trace_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            backend.assert_not_called()
            self.assertFalse(trace_path.exists())
            self.assertIn("does not allow a fixture override", stderr.getvalue())

    def test_gemini_cli_requires_confirmation_for_custom_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            custom_tasks = temp_root / "custom-tasks.json"
            custom_tasks.write_text(
                (ROOT / "configs" / "tasks.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            trace_path = temp_root / "custom.jsonl"
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "gemini",
                        "--tasks",
                        str(custom_tasks),
                        "--trace",
                        str(trace_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertFalse(trace_path.exists())
            self.assertIn(
                "--allow-custom-synthetic-tasks",
                stderr.getvalue(),
            )

    def test_cli_rejects_artifacts_inside_shared_repository(self) -> None:
        paths = (
            ROOT / "results" / "must-not-be-created.jsonl",
            ROOT.parent / "outputs" / "must-not-be-created.jsonl",
        )
        for trace_path in paths:
            with self.subTest(trace_path=trace_path):
                summary_path = trace_path.with_suffix(".summary.json")
                stderr = io.StringIO()
                with (
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(stderr),
                ):
                    exit_code = main(
                        [
                            "run",
                            "--trace",
                            str(trace_path),
                            "--summary",
                            str(summary_path),
                        ]
                    )
                self.assertEqual(exit_code, 2)
                self.assertFalse(trace_path.exists())
                self.assertFalse(summary_path.exists())
                self.assertIn(
                    "outside the shared repository",
                    stderr.getvalue(),
                )

    def test_gemini_cli_returns_failure_when_all_model_runs_error(self) -> None:
        class FailingRealBackend(FakeLLMBackend):
            provider_id = "google-gemini"
            model_id = "gemini-3.6-flash"
            model_version = "gemini-3.6-flash"
            sdk_name = "google-genai"
            sdk_version = "2.13.0"
            api_version = "v1"
            is_real_model = True
            sampling_parameters = {
                "http_max_attempts_including_initial": 1,
                "post_tool_max_output_tokens": 1_024,
                "post_tool_thinking_level": "medium",
                "post_tool_tool_choice": "validated_sink_only",
                "pre_tool_max_output_tokens": 512,
                "pre_tool_thinking_level": "medium",
                "pre_tool_tool_choice": "any_source_only",
                "seed_source": "matched_phase_seeds",
                "store": False,
            }
            model_tool_schema_hash = (
                FakeLLMBackend.model_tool_schema_hash
            )

            def __init__(self):
                def fail(request):
                    raise LLMBackendError(
                        "synthetic provider failure"
                    )

                super().__init__(fail)

        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "gemini.jsonl"
            summary_path = Path(temp_dir) / "gemini.summary.json"
            stdout = io.StringIO()
            with (
                patch(
                    "tool_output_lab.cli.GeminiBackend",
                    return_value=FailingRealBackend(),
                ),
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "run",
                        "--policy",
                        "gemini",
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )
            output = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(output["scheduled_runs"], 9)
            self.assertEqual(output["error_runs"], 9)
            self.assertEqual(output["completed_runs"], 0)
            self.assertTrue(output["real_model_configured"])
            self.assertEqual(output["empirical_llm_completed_runs"], 0)
            self.assertFalse(output["empirical_llm_evidence"])
            self.assertEqual(
                output["model_backend_accounting"],
                {
                    "post_tool_decisions_validated": 0,
                    "post_tool_policy_invocations": 9,
                    "real_model_post_tool_observations": 0,
                    "shared_prelude_backend_invocations": 3,
                    "shared_preludes_validated": 3,
                    "total_backend_or_policy_invocations": 12,
                },
            )
            self.assertTrue(trace_path.exists())
            self.assertTrue(summary_path.exists())
            events = read_jsonl(trace_path)
            validate_trace_records(events)
            prelude_records = [
                event
                for event in events
                if event["schema_version"] == PRELUDE_SCHEMA_VERSION
            ]
            self.assertEqual(len(prelude_records), 3)
            for prelude in prelude_records:
                self.assertNotIn("condition", prelude)
                self.assertNotIn("payload_id", prelude)
                self.assertNotIn("run_id", prelude)
                serialized_prelude = canonical_json(prelude)
                self.assertNotIn("provider_context_json", serialized_prelude)
                self.assertNotIn('"signature"', serialized_prelude)
            self.assertEqual(
                {event["transport"] for event in events},
                {"google_gemini_interactions_v1"},
            )
            self.assertTrue(
                all(
                    event["code_commit"] != "uncommitted-working-tree"
                    for event in events
                )
            )


if __name__ == "__main__":
    unittest.main()
