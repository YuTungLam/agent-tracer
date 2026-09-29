from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from tool_output_lab.conditions import FixtureVariant
from tool_output_lab.qualification import (
    CALIBRATION_PROMPT_PROFILE_ID,
    CALIBRATION_ROLE,
    CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
    CLEAN_NOISE_FLOOR_ROLE,
    EVIDENCE_ROLES,
    NEUTRAL_PROMPT_PROFILE_ID,
    NOT_APPLICABLE_GATE_RECEIPT_HASH,
    NOT_APPLICABLE_PROMPT_PROFILE_ID,
    NOT_APPLICABLE_PROTOCOL_MANIFEST_HASH,
    PROMPT_PROFILE_VERSIONS,
    QUALIFICATION_PROTOCOL_VERSION,
    ROLE_ALLOWED_PROMPT_PROFILES,
    ROLE_SPLITS,
    validate_qualification_provenance,
    validate_tasks_for_evidence_role,
)
from tool_output_lab.tasks import load_tasks


ROOT = Path(__file__).resolve().parents[1]


class CleanNoiseFloorQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = load_tasks(ROOT / "configs" / "tasks.json")

    @staticmethod
    def provenance(
        *,
        evidence_role: str = CLEAN_NOISE_FLOOR_ROLE,
        dataset_split: str = "calibration",
        protocol_version: str = CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
        prompt_profile_id: str = NEUTRAL_PROMPT_PROFILE_ID,
        fixture_variant: str = FixtureVariant.EXACT_FUNCTION_CALL.value,
        attack_estimate_eligible: bool = False,
        protocol_manifest_hash: str = NOT_APPLICABLE_PROTOCOL_MANIFEST_HASH,
        capability_receipt_sha256: str = NOT_APPLICABLE_GATE_RECEIPT_HASH,
        attack_calibration_receipt_sha256: str = (
            NOT_APPLICABLE_GATE_RECEIPT_HASH
        ),
    ) -> dict[str, object]:
        return {
            "evidence_role": evidence_role,
            "dataset_split": dataset_split,
            "protocol_version": protocol_version,
            "prompt_profile_id": prompt_profile_id,
            "prompt_profile_version": PROMPT_PROFILE_VERSIONS[
                prompt_profile_id
            ],
            "fixture_variant": fixture_variant,
            "attack_estimate_eligible": attack_estimate_eligible,
            "code_commit": "uncommitted-working-tree",
            "code_dirty": True,
            "protocol_manifest_hash": protocol_manifest_hash,
            "capability_receipt_sha256": capability_receipt_sha256,
            "attack_calibration_receipt_sha256": (
                attack_calibration_receipt_sha256
            ),
        }

    def test_role_has_frozen_split_and_prompt_profiles(self) -> None:
        self.assertIn(CLEAN_NOISE_FLOOR_ROLE, EVIDENCE_ROLES)
        self.assertEqual(ROLE_SPLITS[CLEAN_NOISE_FLOOR_ROLE], "calibration")
        self.assertEqual(
            ROLE_ALLOWED_PROMPT_PROFILES[CLEAN_NOISE_FLOOR_ROLE],
            {
                NEUTRAL_PROMPT_PROFILE_ID,
                NOT_APPLICABLE_PROMPT_PROFILE_ID,
            },
        )

        for prompt_profile_id in (
            NEUTRAL_PROMPT_PROFILE_ID,
            NOT_APPLICABLE_PROMPT_PROFILE_ID,
        ):
            with self.subTest(prompt_profile_id=prompt_profile_id):
                validate_qualification_provenance(
                    **self.provenance(prompt_profile_id=prompt_profile_id)
                )

        with self.assertRaisesRegex(ValueError, "does not allow prompt profile"):
            validate_qualification_provenance(
                **self.provenance(
                    prompt_profile_id=CALIBRATION_PROMPT_PROFILE_ID
                )
            )

    def test_role_requires_its_own_protocol_and_calibration_split(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
        ):
            validate_qualification_provenance(
                **self.provenance(
                    protocol_version=QUALIFICATION_PROTOCOL_VERSION
                )
            )
        with self.assertRaisesRegex(ValueError, "dataset_split='calibration'"):
            validate_qualification_provenance(
                **self.provenance(dataset_split="not_applicable")
            )

        attack_calibration = self.provenance(
            evidence_role=CALIBRATION_ROLE,
            protocol_version=QUALIFICATION_PROTOCOL_VERSION,
            prompt_profile_id=CALIBRATION_PROMPT_PROFILE_ID,
        )
        validate_qualification_provenance(**attack_calibration)
        with self.assertRaisesRegex(
            ValueError,
            QUALIFICATION_PROTOCOL_VERSION,
        ):
            validate_qualification_provenance(
                **{
                    **attack_calibration,
                    "protocol_version": CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
                }
            )

    def test_role_is_never_attack_estimate_eligible(self) -> None:
        validate_qualification_provenance(**self.provenance())
        with self.assertRaisesRegex(
            ValueError,
            "attack_estimate_eligible contradicts",
        ):
            validate_qualification_provenance(
                **self.provenance(attack_estimate_eligible=True)
            )

    def test_role_requires_the_frozen_exact_function_fixture(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "requires the frozen exact_function_call fixture",
        ):
            validate_qualification_provenance(
                **self.provenance(
                    fixture_variant=FixtureVariant.LEGACY_OVERRIDE.value
                )
            )

    def test_role_cannot_claim_held_out_manifest_or_receipts(self) -> None:
        invalid = (
            {
                "protocol_manifest_hash": "a" * 64,
            },
            {
                "capability_receipt_sha256": "b" * 64,
            },
            {
                "attack_calibration_receipt_sha256": "c" * 64,
            },
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, "Non-held-out evidence"):
                    validate_qualification_provenance(
                        **self.provenance(**changes)
                    )

    def test_role_uses_exact_frozen_calibration_tasks(self) -> None:
        validate_tasks_for_evidence_role(
            self.tasks[:2],
            CLEAN_NOISE_FLOOR_ROLE,
            real_model_configured=True,
        )

        changed = replace(
            self.tasks[0],
            public_answer="changed synthetic answer",
        )
        with self.assertRaisesRegex(ValueError, "frozen manifest"):
            validate_tasks_for_evidence_role(
                [changed],
                CLEAN_NOISE_FLOOR_ROLE,
                real_model_configured=True,
            )

        with self.assertRaisesRegex(
            ValueError,
            "held-out task IDs or semantics",
        ):
            validate_tasks_for_evidence_role(
                [self.tasks[2]],
                CLEAN_NOISE_FLOOR_ROLE,
                real_model_configured=True,
            )

        renamed_held_out_clone = replace(
            self.tasks[2],
            task_id="noise-floor-clone",
            version="noise-floor-development-only",
            confidential_token="CANARY-NOISE-FLOOR-CLONE",
        )
        with self.assertRaisesRegex(
            ValueError,
            "held-out task IDs or semantics",
        ):
            validate_tasks_for_evidence_role(
                [renamed_held_out_clone],
                CLEAN_NOISE_FLOOR_ROLE,
                real_model_configured=True,
            )

        with self.assertRaisesRegex(
            ValueError,
            "only frozen calibration task IDs",
        ):
            validate_tasks_for_evidence_role(
                [self.tasks[2]],
                CLEAN_NOISE_FLOOR_ROLE,
                real_model_configured=False,
            )


if __name__ == "__main__":
    unittest.main()
