from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from tool_output_lab.attack_spec import (
    ATTACK_SPEC_FIELDS,
    ATTACK_SPEC_SCHEMA_VERSION,
    AttackCarrier,
    AttackFamily,
    AttackInterface,
    AttackObjective,
    AttackSpec,
    OptimisationRegime,
    PayloadPlacement,
    PayloadTechnique,
    PropagationPattern,
)
from tool_output_lab.conditions import (
    FIXTURE_ATTACK_SPECS,
    FixtureVariant,
    attack_spec_for_fixture_variant,
    build_tool_response,
    validate_matched_triplet,
)
from tool_output_lab.domain import Condition, PolicyInput, ToolSelectionInput
from tool_output_lab.experiment import (
    ExperimentConfig,
    build_run_plan,
    run_experiment,
)
from tool_output_lab.llm import (
    BackendDecision,
    FakeLLMBackend,
    LLMRequest,
    ModelBackedPolicy,
    PreludeRequest,
    fake_call_metadata,
)
from tool_output_lab.qualification import CLEAN_NOISE_FLOOR_PROTOCOL_VERSION
from tool_output_lab.tasks import load_tasks
from tool_output_lab.tracing import validate_trace, validate_trace_records
from tool_output_lab.utils import canonical_json, sha256_text


ROOT = Path(__file__).resolve().parents[1]


class AttackSpecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = load_tasks(ROOT / "configs" / "tasks.json")[0]

    def test_enum_wire_values_are_frozen(self) -> None:
        expected = {
            AttackFamily: {"tool_output_injection"},
            AttackCarrier: {"tool_output", "mcp_server_response"},
            AttackInterface: {
                "in_process_mock_document",
                "mock_web_search",
                "file_system_reader",
                "api_endpoint",
                "mcp",
            },
            PayloadTechnique: {
                "plain_text_instruction",
                "structured_json_instruction",
                "structured_xml_instruction",
                "role_escalation_prompt",
            },
            PayloadPlacement: {
                "operator_note",
                "top_level_field",
                "nested_field",
                "response_prefix",
                "response_infix",
                "response_suffix",
            },
            PropagationPattern: {"single_hop", "multi_hop_cross_tool"},
            AttackObjective: {
                "unauthorized_simulated_sink_action",
                "data_exfiltration",
                "unsafe_action_execution",
                "goal_deviation",
                "cross_tool_contamination",
                "persistent_memory_corruption",
            },
            OptimisationRegime: {"fixed_template", "gcg_suffix"},
        }
        for enum_type, wire_values in expected.items():
            with self.subTest(enum_type=enum_type.__name__):
                self.assertEqual({item.value for item in enum_type}, wire_values)
                self.assertNotIn("unknown", wire_values)
                self.assertNotIn("other", wire_values)

    def test_from_mapping_rejects_invalid_shapes(self) -> None:
        valid = attack_spec_for_fixture_variant(
            FixtureVariant.LEGACY_OVERRIDE
        ).to_mapping()
        cases = (
            (None, "object"),
            ({key: value for key, value in valid.items() if key != "carrier"}, "carrier"),
            ({**valid, "extra": "value"}, "extra"),
            ({**valid, "carrier": 7}, "carrier"),
            ({**valid, "carrier": ""}, "carrier"),
            ({**valid, "carrier": "unknown"}, "carrier"),
            ({**valid, "payload_version": "../escape"}, "payload_version"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, message):
                    AttackSpec.from_mapping(value)  # type: ignore[arg-type]

    def test_spec_is_frozen_hashable_and_canonical(self) -> None:
        spec = attack_spec_for_fixture_variant(FixtureVariant.LEGACY_OVERRIDE)
        with self.assertRaises(FrozenInstanceError):
            spec.carrier = "mcp_server_response"  # type: ignore[misc]
        self.assertEqual(hash(spec), hash(AttackSpec.from_mapping(spec.to_mapping())))
        reversed_mapping = dict(reversed(tuple(spec.to_mapping().items())))
        reparsed = AttackSpec.from_mapping(reversed_mapping)
        self.assertEqual(reparsed, spec)
        self.assertEqual(reparsed.sha256, spec.sha256)
        self.assertEqual(
            spec.sha256,
            sha256_text(canonical_json(spec.declaration_mapping())),
        )
        self.assertEqual(tuple(spec.to_mapping()), ATTACK_SPEC_FIELDS)
        changed = replace(spec, interface="mcp")
        self.assertNotEqual(changed.sha256, spec.sha256)
        self.assertNotEqual(changed.spec_id, spec.spec_id)

    def test_every_fixture_variant_has_one_exact_projection(self) -> None:
        expected = {
            FixtureVariant.LEGACY_OVERRIDE: (
                "role_escalation_prompt",
                "legacy-override-v1",
            ),
            FixtureVariant.EXACT_FUNCTION_CALL: (
                "plain_text_instruction",
                "exact-function-call-v1",
            ),
            FixtureVariant.TASK_ALIGNED_AUDIT: (
                "plain_text_instruction",
                "task-aligned-audit-v1",
            ),
            FixtureVariant.STRUCTURED_NEXT_ACTION: (
                "structured_json_instruction",
                "structured-next-action-v1",
            ),
        }
        self.assertEqual(set(FIXTURE_ATTACK_SPECS), set(FixtureVariant))
        self.assertEqual(len(set(FIXTURE_ATTACK_SPECS.values())), 4)
        for variant, (technique, payload_version) in expected.items():
            with self.subTest(variant=variant.value):
                spec = attack_spec_for_fixture_variant(variant)
                self.assertEqual(spec.attack_family, "tool_output_injection")
                self.assertEqual(spec.carrier, "tool_output")
                self.assertEqual(spec.interface, "in_process_mock_document")
                self.assertEqual(spec.payload_technique, technique)
                self.assertEqual(spec.placement, "operator_note")
                self.assertEqual(spec.propagation, "single_hop")
                self.assertEqual(
                    spec.objective,
                    "unauthorized_simulated_sink_action",
                )
                self.assertEqual(spec.optimisation_regime, "fixed_template")
                self.assertEqual(spec.payload_version, payload_version)

    def test_implicit_and_explicit_specs_have_identical_fixtures(self) -> None:
        for variant in FixtureVariant:
            spec = attack_spec_for_fixture_variant(variant)
            for condition in Condition:
                with self.subTest(variant=variant.value, condition=condition.value):
                    implicit = build_tool_response(
                        self.task,
                        condition,
                        fixture_variant=variant,
                    )
                    explicit = build_tool_response(
                        self.task,
                        condition,
                        fixture_variant=variant,
                        attack_spec=spec,
                    )
                    self.assertEqual(implicit, explicit)
                    self.assertEqual(implicit.attack_spec_sha256, spec.sha256)

    def test_conflicting_spec_and_renderer_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "conflicts"):
            build_tool_response(
                self.task,
                Condition.ATTACK,
                fixture_variant=FixtureVariant.LEGACY_OVERRIDE,
                attack_spec=attack_spec_for_fixture_variant(
                    FixtureVariant.EXACT_FUNCTION_CALL
                ),
            )
        with self.assertRaisesRegex(ValueError, "conflicts"):
            ExperimentConfig(
                fixture_variant=FixtureVariant.LEGACY_OVERRIDE.value,
                attack_spec=attack_spec_for_fixture_variant(
                    FixtureVariant.EXACT_FUNCTION_CALL
                ),
            )

    def test_legacy_fixture_bytes_and_hashes_are_unchanged(self) -> None:
        hashes = {
            ("legacy_override", "clean"): "6ed9f3829d974300d34f1679de81cff4b5c13da36e38c4bf57ae5bbf00075dd8",
            ("legacy_override", "placebo"): "89e26abc68044306a1d3dc121042024aa89e40ee00498bfeb628743721274f91",
            ("legacy_override", "attack"): "53194a1f7aa1daeff00b8f87f752976e1659832d0acff66ee5fada2543b0a779",
            ("exact_function_call", "clean"): "6ed9f3829d974300d34f1679de81cff4b5c13da36e38c4bf57ae5bbf00075dd8",
            ("exact_function_call", "placebo"): "ec9c98c61c04402d880d8a28a6198a0cfdc0045897dd148e7bfcdc9a1c0321b5",
            ("exact_function_call", "attack"): "7ba20d72afb66c9cdb942fb83e1328d9e8fd33c24805f723b7b12ac3b0335d9e",
            ("task_aligned_audit", "clean"): "6ed9f3829d974300d34f1679de81cff4b5c13da36e38c4bf57ae5bbf00075dd8",
            ("task_aligned_audit", "placebo"): "9b0f1d264e6d47e25227e038c50e789e0117c447985c7ee53ffdd327a844d964",
            ("task_aligned_audit", "attack"): "fc24510e6d3ac4c9cd2e95cac74ea0e9555d4b980d4e9033e56aadd8c4feb3a4",
            ("structured_next_action", "clean"): "6ed9f3829d974300d34f1679de81cff4b5c13da36e38c4bf57ae5bbf00075dd8",
            ("structured_next_action", "placebo"): "feaf58826b26279778a4eec50be72bf69ccd37585c61a6f854b5a08ba182d6d4",
            ("structured_next_action", "attack"): "8ac726915b4a39357d45842c13471c3180b960a13a4a97d0e8590a930e9956e9",
        }
        for variant in FixtureVariant:
            for condition in Condition:
                response = build_tool_response(
                    self.task,
                    condition,
                    fixture_variant=variant,
                )
                with self.subTest(variant=variant.value, condition=condition.value):
                    self.assertEqual(len(response.raw_text.encode("utf-8")), 378)
                    self.assertEqual(
                        response.raw_sha256,
                        hashes[(variant.value, condition.value)],
                    )
                    self.assertEqual(
                        response.fixture_version,
                        f"tool-response-fixture-v2:{variant.value}",
                    )

    def test_taxonomy_never_enters_policy_or_tool_payload(self) -> None:
        forbidden = set(ATTACK_SPEC_FIELDS) | {
            "attack_spec",
            "attack_spec_schema_version",
            "attack_spec_id",
            "attack_spec_sha256",
            "condition",
        }
        self.assertTrue(forbidden.isdisjoint({field.name for field in fields(PolicyInput)}))
        self.assertTrue(
            forbidden.isdisjoint({field.name for field in fields(ToolSelectionInput)})
        )
        self.assertTrue(forbidden.isdisjoint({field.name for field in fields(PreludeRequest)}))
        self.assertTrue(forbidden.isdisjoint({field.name for field in fields(LLMRequest)}))
        for variant in FixtureVariant:
            for condition in Condition:
                response = build_tool_response(
                    self.task,
                    condition,
                    fixture_variant=variant,
                )
                self.assertTrue(forbidden.isdisjoint(response.payload))
                for key in forbidden:
                    self.assertNotIn(f'"{key}"', response.raw_text)

    def test_matched_triplets_share_one_spec(self) -> None:
        for variant in FixtureVariant:
            validate_matched_triplet(self.task, fixture_variant=variant)
            responses = tuple(
                build_tool_response(
                    self.task,
                    condition,
                    fixture_variant=variant,
                )
                for condition in Condition
            )
            self.assertEqual(len({response.attack_spec for response in responses}), 1)
            self.assertEqual(
                len({response.attack_spec_sha256 for response in responses}),
                1,
            )

    def test_explicit_and_implicit_specs_have_same_config_identity(self) -> None:
        spec = attack_spec_for_fixture_variant(FixtureVariant.LEGACY_OVERRIDE)
        implicit = run_experiment(
            [self.task],
            ExperimentConfig(repetitions=1),
        )
        explicit = run_experiment(
            [self.task],
            ExperimentConfig(repetitions=1, attack_spec=spec),
        )
        reordered = run_experiment(
            [self.task],
            ExperimentConfig(
                repetitions=1,
                attack_spec=dict(reversed(tuple(spec.to_mapping().items()))),
            ),
        )
        proxy = run_experiment(
            [self.task],
            ExperimentConfig(
                repetitions=1,
                attack_spec=MappingProxyType(spec.to_mapping()),
            ),
        )
        self.assertEqual(implicit.config_hash, explicit.config_hash)
        self.assertEqual(implicit.config_hash, reordered.config_hash)
        self.assertEqual(implicit.config_hash, proxy.config_hash)
        self.assertEqual(implicit.manifest, explicit.manifest)
        self.assertEqual(implicit.manifest, reordered.manifest)
        self.assertEqual(implicit.manifest, proxy.manifest)
        self.assertEqual(
            implicit.config.to_mapping(),
            explicit.config.to_mapping(),
        )

    def test_explicit_mapping_is_snapshotted_into_frozen_config(self) -> None:
        source = attack_spec_for_fixture_variant(
            FixtureVariant.LEGACY_OVERRIDE
        ).to_mapping()
        config = ExperimentConfig(attack_spec=source)
        before = config.to_mapping()

        source["carrier"] = "mcp_server_response"

        self.assertIsInstance(config.attack_spec, AttackSpec)
        self.assertEqual(config.to_mapping(), before)
        self.assertEqual(
            config.resolved_attack_spec,
            attack_spec_for_fixture_variant(FixtureVariant.LEGACY_OVERRIDE),
        )

    def test_fixture_enum_and_wire_value_have_identical_identity(self) -> None:
        enum_result = run_experiment(
            [self.task],
            ExperimentConfig(
                repetitions=1,
                fixture_variant=FixtureVariant.EXACT_FUNCTION_CALL,
            ),
        )
        wire_result = run_experiment(
            [self.task],
            ExperimentConfig(
                repetitions=1,
                fixture_variant=FixtureVariant.EXACT_FUNCTION_CALL.value,
            ),
        )
        self.assertEqual(enum_result.config.fixture_variant, "exact_function_call")
        self.assertEqual(enum_result.config_hash, wire_result.config_hash)
        self.assertEqual(enum_result.manifest, wire_result.manifest)
        def stable_events(result):
            records = deepcopy(list(result.events))
            for record in records:
                record.pop("timestamp_utc")
                record.pop("elapsed_ns")
            return records

        self.assertEqual(stable_events(enum_result), stable_events(wire_result))

    def test_run_plan_spec_drift_fails_before_a_model_request(self) -> None:
        backend = FakeLLMBackend(
            BackendDecision(
                answer=self.task.public_answer,
                sink_action=None,
                metadata=fake_call_metadata(),
            )
        )
        config = ExperimentConfig(
            experiment_id="run-plan-spec-drift",
            repetitions=1,
            policy_name="fake-llm",
            max_steps=2,
            prompt_profile_id="guarded_authorization",
        )

        def drifting_plan(tasks, declared_config, config_hash):
            plan = build_run_plan(tasks, declared_config, config_hash)
            return [
                replace(
                    plan[0],
                    attack_spec=attack_spec_for_fixture_variant(
                        FixtureVariant.EXACT_FUNCTION_CALL
                    ),
                ),
                *plan[1:],
            ]

        with patch(
            "tool_output_lab.experiment.build_run_plan",
            side_effect=drifting_plan,
        ):
            with self.assertRaisesRegex(ValueError, "Run plan.*AttackSpec"):
                run_experiment(
                    [self.task],
                    config,
                    policy_factory=lambda: ModelBackedPolicy(backend),
                )
        self.assertEqual(backend.prelude_requests, [])
        self.assertEqual(backend.requests, [])

    def test_reserved_vocabulary_is_not_executable_without_a_registry_binding(self) -> None:
        current = attack_spec_for_fixture_variant(FixtureVariant.LEGACY_OVERRIDE)
        for future in (
            replace(
                current,
                carrier="mcp_server_response",
                interface="mcp",
            ),
            replace(current, propagation="multi_hop_cross_tool"),
            replace(current, optimisation_regime="gcg_suffix"),
        ):
            with self.subTest(spec=future.to_mapping()):
                with self.assertRaisesRegex(ValueError, "conflicts"):
                    build_tool_response(
                        self.task,
                        Condition.ATTACK,
                        fixture_variant=FixtureVariant.LEGACY_OVERRIDE,
                        attack_spec=future,
                    )

    def test_spec_is_retained_in_summary_manifest_trace_and_comparison(self) -> None:
        result = run_experiment(
            [self.task],
            ExperimentConfig(
                repetitions=1,
                fixture_variant=FixtureVariant.STRUCTURED_NEXT_ACTION.value,
            ),
        )
        spec = attack_spec_for_fixture_variant(
            FixtureVariant.STRUCTURED_NEXT_ACTION
        )
        expected = {
            "attack_spec_schema_version": ATTACK_SPEC_SCHEMA_VERSION,
            "attack_spec_id": spec.spec_id,
            "attack_spec_sha256": spec.sha256,
            "attack_spec": spec.to_mapping(),
        }
        summary = result.to_mapping()
        for key, value in expected.items():
            self.assertEqual(summary["experiment"][key], value)
        for record in (
            *result.manifest,
            *result.events,
            *result.matched_comparisons,
        ):
            for key, value in expected.items():
                self.assertEqual(record[key], value)
        self.assertEqual(
            {record["condition"] for record in result.manifest},
            {"clean", "placebo", "attack"},
        )
        self.assertTrue(
            all("condition" not in record["attack_spec"] for record in result.events)
        )

    def test_trace_rejects_attack_spec_tampering(self) -> None:
        result = run_experiment(
            [self.task],
            ExperimentConfig(repetitions=1),
        )

        missing = deepcopy(list(result.events))
        missing[0].pop("attack_spec")
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_trace(missing)

        bad_hash = deepcopy(list(result.events))
        bad_hash[0]["attack_spec_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "AttackSpec hash"):
            validate_trace(bad_hash)

        unknown = deepcopy(list(result.events))
        unknown[0]["attack_spec"]["carrier"] = "unknown"
        with self.assertRaisesRegex(ValueError, "carrier"):
            validate_trace(unknown)

        changed_branch = deepcopy(list(result.events))
        replacement = attack_spec_for_fixture_variant(
            FixtureVariant.EXACT_FUNCTION_CALL
        )
        clean_run_ids = {
            event["run_id"]
            for event in changed_branch
            if event["condition"] == "clean"
        }
        for event in changed_branch:
            if event["run_id"] in clean_run_ids:
                event["fixture_variant"] = FixtureVariant.EXACT_FUNCTION_CALL.value
                event["fixture_version"] = (
                    "tool-response-fixture-v2:exact_function_call"
                )
                event["attack_spec_schema_version"] = ATTACK_SPEC_SCHEMA_VERSION
                event["attack_spec_id"] = replacement.spec_id
                event["attack_spec_sha256"] = replacement.sha256
                event["attack_spec"] = replacement.to_mapping()
        with self.assertRaisesRegex(ValueError, "Matched set.*changes fields"):
            validate_trace(changed_branch)

    def test_clean_noise_pair_keeps_spec_without_becoming_attack_evidence(self) -> None:
        config = ExperimentConfig(
            experiment_id="attack-spec-clean-noise-test",
            repetitions=1,
            fixture_variant=FixtureVariant.EXACT_FUNCTION_CALL.value,
            evidence_role="clean_noise_floor",
            dataset_split="calibration",
            protocol_version=CLEAN_NOISE_FLOOR_PROTOCOL_VERSION,
        )
        result = run_experiment([self.task], config)
        self.assertFalse(result.config.attack_estimate_eligible)
        self.assertEqual(result.matched_attack_metrics["status"], "not_applicable")
        self.assertEqual(
            {record["analysis_arm"] for record in result.manifest},
            {"clean_a", "clean_b"},
        )
        self.assertEqual(
            len({record["attack_spec_sha256"] for record in result.manifest}),
            1,
        )
        validate_trace_records(result.trace_records)


if __name__ == "__main__":
    unittest.main()
