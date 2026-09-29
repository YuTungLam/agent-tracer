from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tool_output_lab.attack_spec import ATTACK_SPEC_SCHEMA_VERSION
from tool_output_lab.conditions import (
    FixtureVariant,
    attack_spec_for_fixture_variant,
)
from tool_output_lab.experiment import (
    ExperimentConfig,
    _validate_live_checkout_provenance,
    run_experiment,
)
from tool_output_lab.llm import (
    CAPABILITY_PROMPT_PROFILE_ID,
    CALIBRATION_PROMPT_PROFILE_ID,
    NEUTRAL_PROMPT_PROFILE_ID,
    BackendDecision,
    FakeLLMBackend,
    ModelBackedPolicy,
    fake_call_metadata,
)
from tool_output_lab.qualification import (
    FROZEN_GATE_PROMPT_PROFILES,
    FROZEN_HELD_OUT_PROTOCOL_MANIFEST,
    FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256,
    FROZEN_HELD_OUT_TASK_SHA256,
    qualification_receipt_sha256,
    task_definition_sha256,
    validate_frozen_held_out_protocol,
    validate_held_out_gate_receipts,
    validate_tasks_for_evidence_role,
)
from tool_output_lab.tasks import build_capability_control_task, load_tasks
from tool_output_lab.utils import canonical_json, sha256_text


ROOT = Path(__file__).resolve().parents[1]


class QualificationProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = load_tasks(ROOT / "configs" / "tasks.json")

    def test_frozen_held_out_manifest_requires_all_exact_tasks(self) -> None:
        held_out = self.tasks[2:]
        validate_tasks_for_evidence_role(
            held_out,
            "susceptibility_evaluation",
        )
        self.assertEqual(
            {
                task.task_id: task_definition_sha256(task)
                for task in held_out
            },
            FROZEN_HELD_OUT_TASK_SHA256,
        )

        with self.assertRaisesRegex(ValueError, "complete frozen held-out"):
            validate_tasks_for_evidence_role(
                held_out[:1],
                "susceptibility_evaluation",
            )
        changed = [
            replace(held_out[0], public_answer="changed synthetic answer"),
            *held_out[1:],
        ]
        with self.assertRaisesRegex(ValueError, "frozen manifest"):
            validate_tasks_for_evidence_role(
                changed,
                "susceptibility_evaluation",
            )

    def test_held_out_role_requires_neutral_profile_clean_commit_and_fixture(
        self,
    ) -> None:
        base = ExperimentConfig(
            repetitions=3,
            evidence_role="susceptibility_evaluation",
            dataset_split="held_out",
            fixture_variant="exact_function_call",
            prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
            code_commit="a" * 40,
            code_dirty=False,
            protocol_manifest_hash=(
                FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256
            ),
            capability_receipt_sha256="c" * 64,
            attack_calibration_receipt_sha256="d" * 64,
        )
        base.validate()

        invalid = (
            (
                replace(
                    base,
                    prompt_profile_id=CALIBRATION_PROMPT_PROFILE_ID,
                ),
                "does not allow prompt profile",
            ),
            (
                replace(base, fixture_variant="structured_next_action"),
                "frozen fixture variant",
            ),
            (
                replace(base, code_dirty=True),
                "clean committed worktree",
            ),
            (
                replace(base, code_commit="unavailable"),
                "exact Git commit hash",
            ),
        )
        for config, message in invalid:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    config.validate()

    def test_held_out_git_provenance_is_resolved_independently(self) -> None:
        config = ExperimentConfig(
            repetitions=3,
            evidence_role="susceptibility_evaluation",
            dataset_split="held_out",
            fixture_variant="exact_function_call",
            prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
            code_commit="a" * 40,
            code_dirty=False,
            protocol_manifest_hash=(
                FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256
            ),
            capability_receipt_sha256="c" * 64,
            attack_calibration_receipt_sha256="d" * 64,
        )
        with patch(
            "tool_output_lab.experiment._read_live_checkout_provenance",
            return_value=("a" * 40, False),
        ):
            _validate_live_checkout_provenance(config)
        with (
            patch(
                "tool_output_lab.experiment."
                "_read_live_checkout_provenance",
                return_value=("b" * 40, False),
            ),
            self.assertRaisesRegex(ValueError, "does not match the live Git HEAD"),
        ):
            _validate_live_checkout_provenance(config)
        with (
            patch(
                "tool_output_lab.experiment."
                "_read_live_checkout_provenance",
                return_value=("a" * 40, True),
            ),
            self.assertRaisesRegex(ValueError, "does not match the live Git worktree"),
        ):
            _validate_live_checkout_provenance(config)

    def test_capability_role_rejects_ordinary_or_forged_tasks(self) -> None:
        ordinary = self.tasks[0]
        with self.assertRaisesRegex(ValueError, "derived authorized"):
            validate_tasks_for_evidence_role(
                [ordinary],
                "capability_control",
            )

        capability = build_capability_control_task(ordinary)
        validate_tasks_for_evidence_role(
            [capability],
            "capability_control",
        )
        ExperimentConfig(
            repetitions=3,
            evidence_role="capability_control",
            prompt_profile_id=CAPABILITY_PROMPT_PROFILE_ID,
            user_authorized_sink=True,
        ).validate()
        with self.assertRaisesRegex(
            ValueError,
            "does not allow prompt profile",
        ):
            ExperimentConfig(
                repetitions=3,
                evidence_role="capability_control",
                prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
                user_authorized_sink=True,
            ).validate()
        with self.assertRaisesRegex(
            ValueError,
            "does not allow prompt profile",
        ):
            ExperimentConfig(
                evidence_role="instrumentation_control",
                prompt_profile_id=CAPABILITY_PROMPT_PROFILE_ID,
            ).validate()
        forged = replace(
            capability,
            user_prompt=ordinary.user_prompt,
        )
        with self.assertRaisesRegex(ValueError, "exact authorization manifest"):
            validate_tasks_for_evidence_role(
                [forged],
                "capability_control",
            )
        revoked = replace(
            capability,
            user_prompt=(
                f"{capability.user_prompt} Authorization is now revoked."
            ),
        )
        with self.assertRaisesRegex(ValueError, "exact authorization manifest"):
            validate_tasks_for_evidence_role(
                [revoked],
                "capability_control",
            )

    def test_real_model_development_roles_cannot_consume_held_out_tasks(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "must not consume frozen held-out",
        ):
            validate_tasks_for_evidence_role(
                [self.tasks[2]],
                "instrumentation_control",
                real_model_configured=True,
            )
        validate_tasks_for_evidence_role(
            [self.tasks[2]],
            "instrumentation_control",
            real_model_configured=False,
        )
        renamed_clone = replace(
            self.tasks[2],
            task_id="development-clone",
            version="development-only",
            confidential_token="CANARY-CLONE",
        )
        with self.assertRaisesRegex(ValueError, "held-out task IDs or semantics"):
            validate_tasks_for_evidence_role(
                [renamed_clone],
                "instrumentation_control",
                real_model_configured=True,
            )

    def test_calibration_tasks_are_bound_to_exact_frozen_content(self) -> None:
        validate_tasks_for_evidence_role(
            self.tasks[:2],
            "attack_calibration",
            real_model_configured=True,
        )
        changed = replace(
            self.tasks[0],
            user_prompt=f"{self.tasks[0].user_prompt} changed",
        )
        with self.assertRaisesRegex(ValueError, "frozen manifest"):
            validate_tasks_for_evidence_role(
                [changed],
                "attack_calibration",
                real_model_configured=True,
            )

    def test_held_out_protocol_manifest_is_complete_and_frozen(self) -> None:
        self.assertEqual(
            sha256_text(
                canonical_json(FROZEN_HELD_OUT_PROTOCOL_MANIFEST)
            ),
            FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256,
        )
        requirements = FROZEN_HELD_OUT_PROTOCOL_MANIFEST[
            "required_gate_receipts"
        ]
        self.assertEqual(
            requirements["capability"]["prompt_profile"][
                "prompt_profile_id"
            ],
            CAPABILITY_PROMPT_PROFILE_ID,
        )
        self.assertEqual(
            requirements["capability"]["post_tool_tool_choice"],
            "required_sink_only",
        )
        manifest = dict(FROZEN_HELD_OUT_PROTOCOL_MANIFEST)
        config_fields = {
            "dataset_split": manifest["dataset_split"],
            "evidence_role": manifest["evidence_role"],
            "experiment_id": manifest["experiment_id"],
            "fixture_variant": manifest["fixture_variant"],
            "attack_spec_schema_version": manifest[
                "attack_spec_schema_version"
            ],
            "attack_spec_id": manifest["attack_spec_id"],
            "attack_spec_sha256": manifest["attack_spec_sha256"],
            "attack_spec": manifest["attack_spec"],
            "max_steps": manifest["max_steps"],
            "policy_name": manifest["policy_name"],
            "protocol_manifest_hash": (
                FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256
            ),
            "protocol_version": manifest["protocol_version"],
            "repetitions": manifest["repetitions"],
            "seed": manifest["seed"],
            "transport": manifest["transport"],
            "user_authorized_sink": manifest[
                "user_authorized_sink"
            ],
        }
        profile_fields = {
            key: manifest[key]
            for key in (
                "api_version",
                "evidence_scope",
                "model_id",
                "model_tool_schema_hash",
                "model_version",
                "phase_prompt_hashes",
                "policy_id",
                "policy_version",
                "prompt_profile_id",
                "prompt_profile_version",
                "provider_id",
                "real_model_configured",
                "runtime_kind",
                "sampling_parameters",
                "sdk_name",
                "sdk_version",
                "system_prompt_hash",
            )
        }
        validate_frozen_held_out_protocol(
            self.tasks[2:],
            config=config_fields,
            policy_profile=profile_fields,
        )
        changed_config = {**config_fields, "seed": 7}
        with self.assertRaisesRegex(ValueError, "seed"):
            validate_frozen_held_out_protocol(
                self.tasks[2:],
                config=changed_config,
                policy_profile=profile_fields,
            )
        changed_spec = {**config_fields, "attack_spec_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "attack_spec_sha256"):
            validate_frozen_held_out_protocol(
                self.tasks[2:],
                config=changed_spec,
                policy_profile=profile_fields,
            )

    def test_held_out_requires_successful_same_protocol_receipts(self) -> None:
        frozen = FROZEN_HELD_OUT_PROTOCOL_MANIFEST
        common = {
            "api_version": frozen["api_version"],
            "attack_estimate_eligible": False,
            "code_commit": "a" * 40,
            "code_dirty": False,
            "complete_empirical_matched_sets": 3,
            "empirical_llm_evidence": True,
            "incomplete_matched_sets": 0,
            "matched_attack_metrics": {
                "scheduled_matched_triplets": 3,
                "complete_matched_triplets": 3,
            },
            "model_id": frozen["model_id"],
            "model_tool_schema_hash": frozen["model_tool_schema_hash"],
            "model_version": frozen["model_version"],
            "policy_id": frozen["policy_id"],
            "policy_name": frozen["policy_name"],
            "policy_version": frozen["policy_version"],
            "protocol_manifest_hash": "not_applicable",
            "protocol_version": frozen["protocol_version"],
            "provider_id": frozen["provider_id"],
            "real_model_configured": True,
            "runtime_kind": frozen["runtime_kind"],
            "sampling_parameters": frozen["sampling_parameters"],
            "sdk_name": frozen["sdk_name"],
            "sdk_version": frozen["sdk_version"],
            "shared_prelude_failures": 0,
            "susceptibility_evidence": False,
            "transport": frozen["transport"],
        }
        capability = {
            "schema_version": "experiment-summary-v4",
            "experiment": {
                **common,
                "attack_calibration_status": "not_applicable",
                "capability_control_status": "passed",
                "dataset_split": "not_applicable",
                "evidence_role": "capability_control",
                "evidence_scope": "real_llm_capability_control",
                "fixture_variant": "legacy_override",
                "attack_spec_schema_version": ATTACK_SPEC_SCHEMA_VERSION,
                "attack_spec_id": attack_spec_for_fixture_variant(
                    FixtureVariant.LEGACY_OVERRIDE
                ).spec_id,
                "attack_spec_sha256": attack_spec_for_fixture_variant(
                    FixtureVariant.LEGACY_OVERRIDE
                ).sha256,
                "attack_spec": attack_spec_for_fixture_variant(
                    FixtureVariant.LEGACY_OVERRIDE
                ).to_mapping(),
                **FROZEN_GATE_PROMPT_PROFILES["capability"],
                "sampling_parameters": {
                    **common["sampling_parameters"],
                    "post_tool_tool_choice": "required_sink_only",
                },
                "user_authorized_sink": True,
            },
        }
        calibration = {
            "schema_version": "experiment-summary-v4",
            "experiment": {
                **common,
                "attack_calibration_status": "qualified",
                "capability_control_status": "not_applicable",
                "dataset_split": "calibration",
                "evidence_role": "attack_calibration",
                "evidence_scope": "real_llm_attack_calibration",
                "fixture_variant": "exact_function_call",
                "attack_spec_schema_version": ATTACK_SPEC_SCHEMA_VERSION,
                "attack_spec_id": attack_spec_for_fixture_variant(
                    FixtureVariant.EXACT_FUNCTION_CALL
                ).spec_id,
                "attack_spec_sha256": attack_spec_for_fixture_variant(
                    FixtureVariant.EXACT_FUNCTION_CALL
                ).sha256,
                "attack_spec": attack_spec_for_fixture_variant(
                    FixtureVariant.EXACT_FUNCTION_CALL
                ).to_mapping(),
                **FROZEN_GATE_PROMPT_PROFILES["attack_calibration"],
                "user_authorized_sink": False,
            },
        }
        receipts = {
            "capability": capability,
            "attack_calibration": calibration,
        }
        config = {
            "attack_calibration_receipt_sha256": (
                qualification_receipt_sha256(calibration)
            ),
            "capability_receipt_sha256": (
                qualification_receipt_sha256(capability)
            ),
            "code_commit": "a" * 40,
            "evidence_role": "susceptibility_evaluation",
            "policy_name": frozen["policy_name"],
            "protocol_version": frozen["protocol_version"],
            "transport": frozen["transport"],
        }
        profile = {
            key: frozen[key]
            for key in (
                "api_version",
                "model_id",
                "model_tool_schema_hash",
                "model_version",
                "policy_id",
                "policy_version",
                "provider_id",
                "runtime_kind",
                "sampling_parameters",
                "sdk_name",
                "sdk_version",
            )
        }
        validate_held_out_gate_receipts(
            receipts,
            config=config,
            policy_profile=profile,
        )

        legacy_capability = {**capability, "schema_version": "experiment-summary-v3"}
        legacy_receipts = {**receipts, "capability": legacy_capability}
        legacy_config = {
            **config,
            "capability_receipt_sha256": qualification_receipt_sha256(
                legacy_capability
            ),
        }
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            validate_held_out_gate_receipts(
                legacy_receipts,
                config=legacy_config,
                policy_profile=profile,
            )

        failed_capability = {
            **capability,
            "experiment": {
                **capability["experiment"],
                "capability_control_status": "failed",
            },
        }
        failed_receipts = {
            **receipts,
            "capability": failed_capability,
        }
        failed_config = {
            **config,
            "capability_receipt_sha256": (
                qualification_receipt_sha256(failed_capability)
            ),
        }
        with self.assertRaisesRegex(
            ValueError,
            "capability_control_status",
        ):
            validate_held_out_gate_receipts(
                failed_receipts,
                config=failed_config,
                policy_profile=profile,
            )

        for field, changed_value in (
            ("attack_spec_sha256", "0" * 64),
            ("prompt_profile_id", NEUTRAL_PROMPT_PROFILE_ID),
            ("prompt_profile_version", "tampered"),
            ("system_prompt_hash", "0" * 64),
            (
                "phase_prompt_hashes",
                {"post_tool": "0" * 64, "pre_tool": "0" * 64},
            ),
            (
                "sampling_parameters",
                common["sampling_parameters"],
            ),
        ):
            with self.subTest(capability_receipt_field=field):
                tampered_capability = {
                    **capability,
                    "experiment": {
                        **capability["experiment"],
                        field: changed_value,
                    },
                }
                tampered_receipts = {
                    **receipts,
                    "capability": tampered_capability,
                }
                tampered_config = {
                    **config,
                    "capability_receipt_sha256": (
                        qualification_receipt_sha256(
                            tampered_capability
                        )
                    ),
                }
                with self.assertRaisesRegex(ValueError, field):
                    validate_held_out_gate_receipts(
                        tampered_receipts,
                        config=tampered_config,
                        policy_profile=profile,
                    )

    def test_library_rejects_calibration_task_as_held_out_evidence(self) -> None:
        config = ExperimentConfig(
            repetitions=3,
            policy_name="fake-real-model",
            max_steps=2,
            evidence_role="susceptibility_evaluation",
            dataset_split="held_out",
            fixture_variant="exact_function_call",
            prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
            code_commit="a" * 40,
            code_dirty=False,
            protocol_manifest_hash=(
                FROZEN_HELD_OUT_PROTOCOL_MANIFEST_SHA256
            ),
            capability_receipt_sha256="c" * 64,
            attack_calibration_receipt_sha256="d" * 64,
        )
        backend = FakeLLMBackend(
            BackendDecision(
                answer=self.tasks[0].public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        with self.assertRaisesRegex(ValueError, "complete frozen held-out"):
            run_experiment(
                [self.tasks[0]],
                config,
                policy_factory=lambda: ModelBackedPolicy(
                    backend,
                    prompt_profile_id=NEUTRAL_PROMPT_PROFILE_ID,
                ),
            )


if __name__ == "__main__":
    unittest.main()
