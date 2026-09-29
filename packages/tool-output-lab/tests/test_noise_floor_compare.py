from __future__ import annotations

import unittest
from typing import Any

from tool_output_lab.compare import (
    CONTROL_OBJECT_COMPARATOR_VERSION,
    compare_control_object_events,
    compare_privileged_events,
)


def event(
    event_id: str,
    event_type: str,
    data: dict[str, Any],
    *,
    component: str = "agent",
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "component": component,
        "data": data,
    }


class ControlObjectComparatorTests(unittest.TestCase):
    def test_ignores_answer_task_evaluation_and_unselected_metadata(self) -> None:
        left = [
            event(
                "left-tool",
                "tool_call",
                {
                    "tool_name": "lookup_policy",
                    "canonical_arguments": {"account_id": "A-1", "region": "NZ"},
                    "latency_ms": 4,
                },
                component="left-component",
            ),
            event(
                "left-decision",
                "agent_decision",
                {
                    "answer": "The limit is NZD 80 per day.",
                    "sink_action": None,
                    "termination_decision": "answer",
                    "model_call": {"response_id": "left-response"},
                },
            ),
            event(
                "left-evaluation",
                "task_evaluation",
                {"task_success": True, "sink_attempted": False},
            ),
        ]
        right = [
            event(
                "right-tool",
                "tool_call",
                {
                    "tool_name": "lookup_policy",
                    "canonical_arguments": {"region": "NZ", "account_id": "A-1"},
                    "latency_ms": 999,
                },
                component="right-component",
            ),
            event(
                "right-decision",
                "agent_decision",
                {
                    "answer": "NZD 80/day",
                    "sink_action": None,
                    "termination_decision": "answer",
                    "model_call": {"response_id": "right-response"},
                },
            ),
            event(
                "right-evaluation",
                "task_evaluation",
                {"task_success": False, "sink_attempted": True},
            ),
        ]

        comparison = compare_control_object_events(left, right)

        self.assertEqual(
            comparison,
            {
                "comparator_version": CONTROL_OBJECT_COMPARATOR_VERSION,
                "diverged": False,
                "first_divergence_position": None,
                "first_divergence_stage": None,
                "left_event_id": None,
                "left_event_type": None,
                "right_event_id": None,
                "right_event_type": None,
                "left_control_object_event_count": 2,
                "right_control_object_event_count": 2,
            },
        )

    def test_reports_first_control_object_divergence(self) -> None:
        left = [
            event(
                "left-tool",
                "tool_call",
                {
                    "tool_name": "lookup_policy",
                    "canonical_arguments": {"region": "NZ"},
                },
            ),
            event(
                "left-decision",
                "agent_decision",
                {
                    "answer": "Ignored left wording",
                    "sink_action": "send_email",
                    "termination_decision": "continue",
                },
            ),
        ]
        right = [
            event(
                "right-tool",
                "tool_call",
                {
                    "tool_name": "lookup_policy",
                    "canonical_arguments": {"region": "AU"},
                },
            ),
            event(
                "right-decision",
                "agent_decision",
                {
                    "answer": "Ignored right wording",
                    "sink_action": None,
                    "termination_decision": "answer",
                },
            ),
        ]

        comparison = compare_control_object_events(left, right)

        self.assertTrue(comparison["diverged"])
        self.assertEqual(comparison["first_divergence_position"], 0)
        self.assertEqual(comparison["first_divergence_stage"], "tool_call")
        self.assertEqual(comparison["left_event_id"], "left-tool")
        self.assertEqual(comparison["left_event_type"], "tool_call")
        self.assertEqual(comparison["right_event_id"], "right-tool")
        self.assertEqual(comparison["right_event_type"], "tool_call")
        self.assertEqual(comparison["left_control_object_event_count"], 2)
        self.assertEqual(comparison["right_control_object_event_count"], 2)

    def test_reports_stage_when_one_side_lacks_a_control_event(self) -> None:
        shared = event(
            "shared-tool",
            "tool_call",
            {
                "tool_name": "lookup_policy",
                "canonical_arguments": {"region": "NZ"},
            },
        )
        left = [
            shared,
            event(
                "left-attempt",
                "sink_attempt",
                {
                    "sink_id": "email",
                    "operation": "send",
                    "canonical_arguments": {"to": "test@example.invalid"},
                    "attempted": True,
                },
            ),
        ]

        comparison = compare_control_object_events(left, [shared])

        self.assertTrue(comparison["diverged"])
        self.assertEqual(comparison["first_divergence_position"], 1)
        self.assertEqual(comparison["first_divergence_stage"], "sink_attempt")
        self.assertEqual(comparison["left_event_id"], "left-attempt")
        self.assertEqual(comparison["left_event_type"], "sink_attempt")
        self.assertIsNone(comparison["right_event_id"])
        self.assertIsNone(comparison["right_event_type"])
        self.assertEqual(comparison["left_control_object_event_count"], 2)
        self.assertEqual(comparison["right_control_object_event_count"], 1)

    def test_sink_result_fields_are_part_of_the_control_signature(self) -> None:
        left = event(
            "left-result",
            "sink_result",
            {
                "simulator_accepted": False,
                "user_authorized": False,
                "blocked": True,
                "security_policy_violation": True,
                "prohibited_simulated_effect": False,
            },
        )
        right = event(
            "right-result",
            "sink_result",
            {
                "simulator_accepted": True,
                "user_authorized": False,
                "blocked": False,
                "security_policy_violation": True,
                "prohibited_simulated_effect": False,
            },
        )

        comparison = compare_control_object_events([left], [right])

        self.assertTrue(comparison["diverged"])
        self.assertEqual(comparison["first_divergence_stage"], "sink_result")

    def test_existing_comparator_still_treats_answer_as_observable(self) -> None:
        left = event(
            "left-decision",
            "agent_decision",
            {
                "answer": "Long-form answer",
                "sink_action": None,
                "termination_decision": "answer",
            },
        )
        right = event(
            "right-decision",
            "agent_decision",
            {
                "answer": "Short answer",
                "sink_action": None,
                "termination_decision": "answer",
            },
        )

        self.assertFalse(compare_control_object_events([left], [right])["diverged"])
        self.assertTrue(compare_privileged_events([left], [right])["diverged"])


if __name__ == "__main__":
    unittest.main()
