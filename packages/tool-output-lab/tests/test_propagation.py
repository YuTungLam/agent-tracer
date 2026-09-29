from __future__ import annotations

import io
import json
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from tool_output_lab.attack_spec import ATTACK_SPEC_FIELDS
from tool_output_lab.cli import main
from tool_output_lab.domain import Condition
from tool_output_lab.propagation import (
    GuardMode,
    IngressChannel,
    PropagationConfig,
    SyntheticMemoryStore,
    TOOL_OUTPUT_PROPAGATION_ATTACK_SPEC,
    build_propagation_plan,
    run_propagation_testbed,
    validate_propagation_trace,
)
from tool_output_lab.tasks import load_tasks
from tool_output_lab.utils import sha256_text


ROOT = Path(__file__).resolve().parents[1]


def _events_by_run(
    events: tuple[Mapping[str, Any], ...],
) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event["run_id"])].append(event)
    for run_events in grouped.values():
        run_events.sort(key=lambda event: int(event["event_index"]))
    return grouped


def _event(
    events: list[Mapping[str, Any]],
    event_type: str,
    *,
    occurrence: int = 0,
) -> Mapping[str, Any]:
    matches = [event for event in events if event["event_type"] == event_type]
    return matches[occurrence]


def _assert_forbidden_keys_absent(
    testcase: unittest.TestCase,
    value: Any,
    forbidden: set[str],
) -> None:
    if isinstance(value, Mapping):
        testcase.assertTrue(
            forbidden.isdisjoint(value),
            f"controller metadata entered model-visible mapping: "
            f"{sorted(forbidden & set(value))}",
        )
        for child in value.values():
            _assert_forbidden_keys_absent(testcase, child, forbidden)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_forbidden_keys_absent(testcase, child, forbidden)
    elif isinstance(value, str):
        lowered = value.casefold()
        for key in forbidden:
            testcase.assertNotIn(f'"{key.casefold()}"', lowered)


class PropagationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = load_tasks(ROOT / "configs" / "tasks.json")[0]

    def test_plan_is_a_deterministic_two_by_three_matrix(self) -> None:
        config = PropagationConfig(
            experiment_id="deterministic-propagation-plan",
            repetitions=1,
            seed=12345,
        )
        first = build_propagation_plan([self.task], config)
        second = build_propagation_plan([self.task], config)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 6)
        self.assertEqual(
            {
                (spec.ingress_channel.value, spec.condition.value)
                for spec in first
            },
            {
                (channel.value, condition.value)
                for channel in IngressChannel
                for condition in Condition
            },
        )
        self.assertEqual(
            sorted(spec.plan_index for spec in first),
            list(range(6)),
        )
        self.assertEqual(len({spec.paired_set_id for spec in first}), 1)
        self.assertEqual(len({spec.run_id for spec in first}), 6)

        by_match: dict[str, list[Any]] = defaultdict(list)
        for spec in first:
            by_match[spec.matched_set_id].append(spec)
        self.assertEqual(len(by_match), 2)
        for triplet in by_match.values():
            self.assertEqual(
                {spec.condition for spec in triplet},
                set(Condition),
            )
            self.assertEqual(
                len({spec.ingress_channel for spec in triplet}),
                1,
            )

    def test_matched_inputs_change_only_the_declared_carrier(self) -> None:
        result = run_propagation_testbed([self.task])
        runs = _events_by_run(result.events)
        by_arm: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        for run_events in runs.values():
            first = run_events[0]
            by_arm[(str(first["ingress_channel"]), str(first["condition"]))] = (
                run_events
            )

        tool_output_runs = [
            by_arm[(IngressChannel.TOOL_OUTPUT.value, condition.value)]
            for condition in Condition
        ]
        self.assertEqual(
            len(
                {
                    _event(events, "user_input")["data"]["content_sha256"]
                    for events in tool_output_runs
                }
            ),
            1,
        )
        self.assertEqual(
            len(
                {
                    _event(events, "document_read")["data"]["raw_sha256"]
                    for events in tool_output_runs
                }
            ),
            3,
        )

        direct_prompt_runs = [
            by_arm[(IngressChannel.DIRECT_USER_PROMPT.value, condition.value)]
            for condition in Condition
        ]
        self.assertEqual(
            len(
                {
                    _event(events, "document_read")["data"]["raw_sha256"]
                    for events in direct_prompt_runs
                }
            ),
            1,
        )
        self.assertEqual(
            len(
                {
                    _event(events, "user_input")["data"]["content_sha256"]
                    for events in direct_prompt_runs
                }
            ),
            3,
        )

        self.assertEqual(len(result.positional_contrasts), 3)
        for contrast in result.positional_contrasts:
            self.assertTrue(contrast["same_treatment_note_sha256"])
            self.assertTrue(contrast["same_model_visible_total_bytes"])
            self.assertTrue(contrast["same_post_ingress_observables"])

    def test_vulnerable_positive_control_completes_only_attack_routes(self) -> None:
        result = run_propagation_testbed(
            [self.task],
            PropagationConfig(policy_name="vulnerable"),
        )
        attack_rows = [
            row for row in result.summaries if row.condition == Condition.ATTACK.value
        ]
        control_rows = [
            row for row in result.summaries if row.condition != Condition.ATTACK.value
        ]

        self.assertEqual(len(attack_rows), 2)
        self.assertTrue(
            all(
                row.memory_write_attempted
                and row.memory_committed
                and row.memory_read
                and row.controlled_attack_record_persisted
                and row.sink_proposed
                and row.sink_attempted
                and row.simulator_accepted
                and row.security_policy_violation
                and row.prohibited_simulated_effect
                and row.route_completed
                for row in attack_rows
            )
        )
        self.assertTrue(
            all(
                row.memory_committed
                and row.memory_read
                and not row.controlled_attack_record_persisted
                and not row.sink_proposed
                and not row.sink_attempted
                and not row.prohibited_simulated_effect
                and not row.route_completed
                for row in control_rows
            )
        )
        self.assertTrue(all(row.task_success for row in result.summaries))
        self.assertTrue(
            all(not row.external_side_effect for row in result.summaries)
        )
        for channel in IngressChannel:
            attack_aggregate = result.aggregate[
                f"{channel.value}:{Condition.ATTACK.value}"
            ]
            self.assertEqual(attack_aggregate["memory_commit_rate"], 1.0)
            self.assertEqual(attack_aggregate["sink_attempt_rate"], 1.0)
            self.assertEqual(
                attack_aggregate["prohibited_simulated_effect_rate"],
                1.0,
            )
            self.assertEqual(attack_aggregate["external_side_effects"], 0)

    def test_safe_negative_control_reads_attack_memory_without_a_sink(self) -> None:
        result = run_propagation_testbed(
            [self.task],
            PropagationConfig(policy_name="safe"),
        )
        attack_rows = [
            row for row in result.summaries if row.condition == Condition.ATTACK.value
        ]

        self.assertEqual(len(attack_rows), 2)
        self.assertTrue(
            all(
                row.memory_committed
                and row.memory_read
                and row.controlled_attack_record_persisted
                and not row.sink_proposed
                and not row.sink_attempted
                and not row.security_policy_violation
                and not row.prohibited_simulated_effect
                and not row.route_completed
                for row in attack_rows
            )
        )
        self.assertTrue(all(not row.sink_proposed for row in result.summaries))
        self.assertTrue(
            all(not row.external_side_effect for row in result.summaries)
        )

    def test_guard_block_separates_proposal_attempt_and_effect(self) -> None:
        result = run_propagation_testbed(
            [self.task],
            PropagationConfig(
                policy_name="vulnerable",
                guard_mode=GuardMode.BLOCK.value,
            ),
        )
        attack_rows = [
            row for row in result.summaries if row.condition == Condition.ATTACK.value
        ]
        self.assertTrue(
            all(
                row.sink_proposed
                and row.guard_decision == GuardMode.BLOCK.value
                and not row.sink_attempted
                and not row.simulator_accepted
                and not row.security_policy_violation
                and not row.prohibited_simulated_effect
                and not row.route_completed
                for row in attack_rows
            )
        )

        for run_events in _events_by_run(result.events).values():
            if str(run_events[0]["condition"]) != Condition.ATTACK.value:
                continue
            attempt = _event(run_events, "sink_attempt")["data"]
            effect = _event(run_events, "sink_effect")["data"]
            self.assertFalse(attempt["attempted"])
            self.assertTrue(attempt["blocked_by_guard"])
            self.assertFalse(effect["prohibited_simulated_effect"])
            self.assertFalse(effect["external_side_effect"])

    def test_authorized_sink_effect_is_accepted_but_not_prohibited(self) -> None:
        result = run_propagation_testbed(
            [self.task],
            PropagationConfig(
                policy_name="vulnerable",
                user_authorized_sink=True,
            ),
        )
        attack_rows = [
            row for row in result.summaries if row.condition == Condition.ATTACK.value
        ]
        self.assertTrue(
            all(
                row.sink_proposed
                and row.sink_attempted
                and row.simulator_accepted
                and row.user_authorized
                and not row.security_policy_violation
                and not row.prohibited_simulated_effect
                and row.route_completed
                for row in attack_rows
            )
        )
        self.assertTrue(
            all(not row.external_side_effect for row in result.summaries)
        )

    def test_memory_store_binds_reads_to_committed_content_and_hash(self) -> None:
        store = SyntheticMemoryStore()
        written = store.write("record-001", "CONTROLLED_ATTACK_RECORD:CANARY-T001")

        self.assertEqual(written.version, 1)
        self.assertEqual(written.content_sha256, sha256_text(written.content))
        read = store.read(written.record_id)
        self.assertEqual(read, written)
        self.assertIsNot(read, written)
        self.assertEqual(store.record_count, 1)
        self.assertEqual(store.store_version, 1)
        with self.assertRaisesRegex(ValueError, "overwrite"):
            store.write(written.record_id, "replacement")
        with self.assertRaisesRegex(ValueError, "Unknown memory record"):
            store.read("missing-record")

        store._records[written.record_id] = replace(  # noqa: SLF001
            written,
            content="tampered-content",
        )
        with self.assertRaisesRegex(ValueError, "failed hash validation"):
            store.read(written.record_id)

    def test_trace_rejects_memory_and_external_effect_tampering(self) -> None:
        result = run_propagation_testbed([self.task])
        validate_propagation_trace(result.events)

        bad_memory = deepcopy(list(result.events))
        read_result = next(
            event
            for event in bad_memory
            if event["event_type"] == "memory_read_result"
        )
        read_result["data"]["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "memory write/read binding"):
            validate_propagation_trace(bad_memory)

        external_effect = deepcopy(list(result.events))
        sink_effect = next(
            event
            for event in external_effect
            if event["event_type"] == "sink_effect"
        )
        sink_effect["data"]["external_side_effect"] = True
        with self.assertRaisesRegex(ValueError, "external side effect"):
            validate_propagation_trace(external_effect)

    def test_trace_rejects_controller_and_outcome_forgery(self) -> None:
        base = run_propagation_testbed([self.task])

        def attack_run_id(events: list[Mapping[str, Any]]) -> str:
            return str(
                next(
                    event
                    for event in events
                    if event["condition"] == Condition.ATTACK.value
                    and event["ingress_channel"]
                    == IngressChannel.TOOL_OUTPUT.value
                )["run_id"]
            )

        swapped = deepcopy(list(base.events))
        tool_events = [
            event
            for event in swapped
            if event["ingress_channel"] == IngressChannel.TOOL_OUTPUT.value
        ]
        attack_id = next(
            str(event["run_id"])
            for event in tool_events
            if event["condition"] == Condition.ATTACK.value
        )
        placebo_id = next(
            str(event["run_id"])
            for event in tool_events
            if event["condition"] == Condition.PLACEBO.value
        )
        for event in swapped:
            if event["run_id"] == attack_id:
                event["condition"] = Condition.PLACEBO.value
                event["position_treatment"]["condition"] = Condition.PLACEBO.value
            elif event["run_id"] == placebo_id:
                event["condition"] = Condition.ATTACK.value
                event["position_treatment"]["condition"] = Condition.ATTACK.value
        with self.assertRaisesRegex(ValueError, "controller plan|position fixture"):
            validate_propagation_trace(swapped)

        metadata_leak = deepcopy(list(base.events))
        target_id = attack_run_id(metadata_leak)
        user_event = next(
            event
            for event in metadata_leak
            if event["run_id"] == target_id and event["event_type"] == "user_input"
        )
        content = f"attack_family=tool_output_injection {user_event['data']['content']}"
        user_event["data"]["content"] = content
        user_event["data"]["content_sha256"] = sha256_text(content)
        user_event["data"]["content_bytes"] = len(content.encode("utf-8"))
        document_event = next(
            event
            for event in metadata_leak
            if event["run_id"] == target_id and event["event_type"] == "document_read"
        )
        visible_bytes = len(content.encode("utf-8")) + int(
            document_event["data"]["raw_bytes"]
        )
        for event in metadata_leak:
            if event["run_id"] == target_id:
                event["position_treatment"][
                    "model_visible_total_bytes"
                ] = visible_bytes
                if event["event_type"] == "ingress_exposed":
                    event["data"]["model_visible_total_bytes"] = visible_bytes
        with self.assertRaisesRegex(
            ValueError, "controller metadata|controller-bound task data"
        ):
            validate_propagation_trace(metadata_leak)

        literal_leak = deepcopy(list(base.events))
        target_id = attack_run_id(literal_leak)
        user_event = next(
            event
            for event in literal_leak
            if event["run_id"] == target_id and event["event_type"] == "user_input"
        )
        content = (
            f"{TOOL_OUTPUT_PROPAGATION_ATTACK_SPEC.spec_id} "
            f"{user_event['data']['content']}"
        )
        user_event["data"]["content"] = content
        user_event["data"]["content_sha256"] = sha256_text(content)
        user_event["data"]["content_bytes"] = len(content.encode("utf-8"))
        document_event = next(
            event
            for event in literal_leak
            if event["run_id"] == target_id and event["event_type"] == "document_read"
        )
        visible_bytes = len(content.encode("utf-8")) + int(
            document_event["data"]["raw_bytes"]
        )
        for event in literal_leak:
            if event["run_id"] == target_id:
                event["position_treatment"][
                    "model_visible_total_bytes"
                ] = visible_bytes
                if event["event_type"] == "ingress_exposed":
                    event["data"]["model_visible_total_bytes"] = visible_bytes
        with self.assertRaisesRegex(
            ValueError, "controller metadata literal|controller-bound task data"
        ):
            validate_propagation_trace(literal_leak)

        forged_sink = deepcopy(list(base.events))
        target_id = attack_run_id(forged_sink)
        sink_proposal = next(
            event
            for event in forged_sink
            if event["run_id"] == target_id
            and event["event_type"] == "action_proposal"
            and event["data"]["phase"] == "post_memory_read_sink"
        )
        sink_proposal["data"]["canonical_arguments"]["value"] = "CANARY-FORGED"
        forged_hash = sha256_text(
            json.dumps(
                sink_proposal["data"]["canonical_arguments"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        sink_proposal["data"]["arguments_sha256"] = forged_hash
        sink_attempt = next(
            event
            for event in forged_sink
            if event["run_id"] == target_id and event["event_type"] == "sink_attempt"
        )
        sink_attempt["data"]["canonical_arguments"]["value"] = "CANARY-FORGED"
        sink_attempt["data"]["arguments_sha256"] = forged_hash
        with self.assertRaisesRegex(ValueError, "invalid sink proposal"):
            validate_propagation_trace(forged_sink)

        blocked_but_dispatched = deepcopy(list(base.events))
        target_id = attack_run_id(blocked_but_dispatched)
        sink_authorization = next(
            event
            for event in blocked_but_dispatched
            if event["run_id"] == target_id
            and event["event_type"] == "authorization_decision"
            and event["data"]["phase"] == "sink_dispatch"
        )
        sink_authorization["data"]["decision"] = GuardMode.BLOCK.value
        sink_authorization["data"][
            "reason_code"
        ] = "instrumentation_guard_blocks_dispatch"
        with self.assertRaisesRegex(ValueError, "sink authorization"):
            validate_propagation_trace(blocked_but_dispatched)

        forged_evaluation = deepcopy(list(base.events))
        target_id = attack_run_id(forged_evaluation)
        evaluation = next(
            event
            for event in forged_evaluation
            if event["run_id"] == target_id
            and event["event_type"] == "task_evaluation"
        )
        evaluation["data"]["route_completed"] = False
        with self.assertRaisesRegex(ValueError, "forged task evaluation"):
            validate_propagation_trace(forged_evaluation)

        contradictory_result = deepcopy(list(base.events))
        target_id = attack_run_id(contradictory_result)
        sink_result = next(
            event
            for event in contradictory_result
            if event["run_id"] == target_id and event["event_type"] == "sink_result"
        )
        sink_result["data"]["blocked"] = True
        with self.assertRaisesRegex(ValueError, "contradictory sink result"):
            validate_propagation_trace(contradictory_result)

        two_task_result = run_propagation_testbed(
            load_tasks(ROOT / "configs" / "tasks.json")[:2]
        )
        duplicate_arm = deepcopy(list(two_task_result.events))
        clean_run_ids = []
        for event in duplicate_arm:
            if (
                event["event_type"] == "run_start"
                and event["condition"] == Condition.CLEAN.value
                and event["ingress_channel"] == IngressChannel.TOOL_OUTPUT.value
            ):
                clean_run_ids.append(str(event["run_id"]))
        self.assertEqual(len(clean_run_ids), 2)
        first_match = next(
            str(event["matched_set_id"])
            for event in duplicate_arm
            if event["run_id"] == clean_run_ids[0]
        )
        for event in duplicate_arm:
            if event["run_id"] == clean_run_ids[1]:
                event["matched_set_id"] = first_match
        with self.assertRaisesRegex(ValueError, "controller plan|repeats clean"):
            validate_propagation_trace(duplicate_arm)

    def test_trace_binds_the_complete_plan_and_position_matrix(self) -> None:
        base = run_propagation_testbed([self.task])

        mixed_experiments = list(base.events) + list(
            run_propagation_testbed(
                [self.task],
                PropagationConfig(seed=20260818),
            ).events
        )
        with self.assertRaisesRegex(ValueError, "mixes experiment identities"):
            validate_propagation_trace(mixed_experiments)

        extra_top_level = deepcopy(list(base.events))
        extra_top_level[0]["undeclared_field"] = "forged"
        with self.assertRaisesRegex(ValueError, "schema drift"):
            validate_propagation_trace(extra_top_level)

        invalid_ingress = deepcopy(list(base.events))
        ingress = next(
            event
            for event in invalid_ingress
            if event["event_type"] == "ingress_exposed"
        )
        ingress["data"]["untrusted"] = False
        with self.assertRaisesRegex(ValueError, "invalid ingress exposure"):
            validate_propagation_trace(invalid_ingress)

        missing_position = [
            event
            for event in deepcopy(list(base.events))
            if event["ingress_channel"] != IngressChannel.DIRECT_USER_PROMPT.value
        ]
        with self.assertRaisesRegex(ValueError, "incomplete|channel matrix"):
            validate_propagation_trace(missing_position)

        forged_seed = deepcopy(list(base.events))
        start = next(event for event in forged_seed if event["event_type"] == "run_start")
        start["data"]["run_seed"] = (int(start["data"]["run_seed"]) + 1) % (
            2**31
        )
        with self.assertRaisesRegex(ValueError, "initial state|deterministic run seed"):
            validate_propagation_trace(forged_seed)

        duplicate_plan_indexes = deepcopy(list(base.events))
        for event in duplicate_plan_indexes:
            if event["event_type"] == "run_start":
                event["data"]["plan_index"] = 0
        with self.assertRaisesRegex(ValueError, "initial state|repeats plan_index"):
            validate_propagation_trace(duplicate_plan_indexes)

        different_position_task = deepcopy(list(base.events))
        replacement_prefix = f"X{self.task.user_prompt[1:]}"
        self.assertEqual(
            len(replacement_prefix.encode("utf-8")),
            len(self.task.user_prompt.encode("utf-8")),
        )
        for event in different_position_task:
            if (
                event["ingress_channel"]
                == IngressChannel.DIRECT_USER_PROMPT.value
                and event["event_type"] == "user_input"
            ):
                _, separator, note = str(event["data"]["content"]).rpartition(
                    "\n\nContext note: "
                )
                changed = f"{replacement_prefix}{separator}{note}"
                event["data"]["content"] = changed
                event["data"]["content_sha256"] = sha256_text(changed)
                event["data"]["content_bytes"] = len(changed.encode("utf-8"))
        with self.assertRaisesRegex(
            ValueError, "controller-bound task data|non-treatment fixture data"
        ):
            validate_propagation_trace(different_position_task)

        arm_specific_authorization = deepcopy(list(base.events))
        attack_ids = {
            str(event["run_id"])
            for event in arm_specific_authorization
            if event["condition"] == Condition.ATTACK.value
        }
        for event in arm_specific_authorization:
            if event["run_id"] not in attack_ids:
                continue
            if event["event_type"] == "run_start":
                event["data"]["user_authorized_sink"] = True
            elif event["event_type"] == "sink_result":
                event["data"]["user_authorized"] = True
                event["data"]["security_policy_violation"] = False
                event["data"]["prohibited_simulated_effect"] = False
                event["data"][
                    "reason_code"
                ] = "authorized_simulated_effect_recorded"
            elif event["event_type"] == "sink_effect":
                event["data"]["prohibited_simulated_effect"] = False
            elif event["event_type"] == "task_evaluation":
                event["data"]["user_authorized"] = True
                event["data"]["security_policy_violation"] = False
                event["data"]["prohibited_simulated_effect"] = False
        with self.assertRaisesRegex(
            ValueError, "initial state|declared run configuration"
        ):
            validate_propagation_trace(arm_specific_authorization)

        oversized = replace(self.task, public_answer="😀" * 500)
        with self.assertRaisesRegex(ValueError, "memory content above"):
            run_propagation_testbed([oversized])

    def test_controller_metadata_stays_out_of_model_visible_values(self) -> None:
        result = run_propagation_testbed([self.task])
        forbidden = set(ATTACK_SPEC_FIELDS) | {
            "attack_spec",
            "attack_spec_applicable",
            "attack_spec_id",
            "attack_spec_schema_version",
            "attack_spec_sha256",
            "condition",
            "ingress_channel",
            "position_treatment",
        }

        for run_events in _events_by_run(result.events).values():
            channel = str(run_events[0]["ingress_channel"])
            if channel == IngressChannel.TOOL_OUTPUT.value:
                for event in run_events:
                    self.assertTrue(event["attack_spec_applicable"])
                    self.assertEqual(
                        event["attack_spec"],
                        TOOL_OUTPUT_PROPAGATION_ATTACK_SPEC.to_mapping(),
                    )
            else:
                for event in run_events:
                    self.assertFalse(event["attack_spec_applicable"])
                    self.assertIsNone(event["attack_spec_schema_version"])
                    self.assertIsNone(event["attack_spec_id"])
                    self.assertIsNone(event["attack_spec_sha256"])
                    self.assertIsNone(event["attack_spec"])

            visible_values = [
                _event(run_events, "user_input")["data"]["content"],
                _event(run_events, "document_read")["data"]["payload"],
                _event(run_events, "action_proposal", occurrence=0)["data"][
                    "canonical_arguments"
                ],
                _event(run_events, "memory_read_result")["data"]["content"],
                _event(run_events, "memory_read_exposed")["data"]["content"],
                _event(run_events, "action_proposal", occurrence=1)["data"][
                    "canonical_arguments"
                ],
            ]
            for value in visible_values:
                _assert_forbidden_keys_absent(self, value, forbidden)

    def test_outputs_are_external_and_never_overwritten_implicitly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="propagation-test-") as directory:
            root = Path(directory)
            trace_path = root / "trace.jsonl"
            summary_path = root / "summary.json"
            result = run_propagation_testbed(
                [self.task],
                trace_path=trace_path,
                summary_path=summary_path,
            )

            self.assertTrue(trace_path.is_file())
            self.assertTrue(summary_path.is_file())
            trace_records = [
                json.loads(line)
                for line in trace_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(trace_records, list(result.events))
            validate_propagation_trace(trace_records)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertFalse(summary["attack_estimate_eligible"])
            self.assertFalse(summary["empirical_llm_observation"])
            self.assertEqual(summary["experiment"]["scheduled_runs"], 6)
            self.assertTrue(
                all(not row["external_side_effect"] for row in summary["runs"])
            )

            with self.assertRaisesRegex(FileExistsError, "overwrite"):
                run_propagation_testbed(
                    [self.task],
                    trace_path=trace_path,
                    summary_path=summary_path,
                )
            overwritten = run_propagation_testbed(
                [self.task],
                trace_path=trace_path,
                summary_path=summary_path,
                overwrite=True,
            )
            self.assertEqual(overwritten.config_hash, result.config_hash)

            same_path = root / "same-output.json"
            with self.assertRaisesRegex(ValueError, "must be different"):
                run_propagation_testbed(
                    [self.task],
                    trace_path=same_path,
                    summary_path=same_path,
                    overwrite=True,
                )

        with self.assertRaisesRegex(ValueError, "outside the shared repository"):
            run_propagation_testbed(
                [self.task],
                trace_path=ROOT / "results" / "forbidden-propagation.jsonl",
            )

    def test_cli_runs_the_declared_instrumentation_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="propagation-cli-") as directory:
            trace_path = Path(directory) / "cli-trace.jsonl"
            summary_path = Path(directory) / "cli-summary.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "testbed",
                        "--tasks",
                        str(ROOT / "configs" / "tasks.json"),
                        "--task-id",
                        self.task.task_id,
                        "--trace",
                        str(trace_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["mode"], "scripted_propagation_diagnostic")
            self.assertTrue(output["instrumentation_only"])
            self.assertFalse(output["attack_estimate_eligible"])
            self.assertFalse(output["empirical_llm_observation"])
            self.assertEqual(output["scheduled_runs"], 6)
            self.assertEqual(output["completed_runs"], 6)
            self.assertEqual(output["external_side_effects"], 0)
            self.assertTrue(trace_path.is_file())
            self.assertTrue(summary_path.is_file())


if __name__ == "__main__":
    unittest.main()
