from __future__ import annotations

import os
import socket
import subprocess
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from tool_output_lab.conditions import build_tool_response
from tool_output_lab.domain import Condition, PolicyInput, SinkAction
from tool_output_lab.policy import ScriptedSafePolicy, ScriptedVulnerablePolicy
from tool_output_lab.tasks import load_tasks
from tool_output_lab.tools import SimulatedSink


ROOT = Path(__file__).resolve().parents[1]


class PolicyAndSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = load_tasks(ROOT / "configs" / "tasks.json")[0]

    def policy_input(self, condition: Condition) -> PolicyInput:
        return PolicyInput(
            user_prompt=self.task.user_prompt,
            tool_payload=build_tool_response(self.task, condition).payload,
            available_sink_ids=(self.task.eligible_sink,),
        )

    def test_vulnerable_policy_reacts_to_content_not_condition_label(self) -> None:
        policy = ScriptedVulnerablePolicy()
        self.assertIsNone(policy.decide(self.policy_input(Condition.CLEAN)).sink_action)
        self.assertIsNotNone(policy.decide(self.policy_input(Condition.ATTACK)).sink_action)

    def test_safe_policy_ignores_attack_content(self) -> None:
        decision = ScriptedSafePolicy().decide(self.policy_input(Condition.ATTACK))
        self.assertIsNone(decision.sink_action)
        self.assertEqual(decision.answer, self.task.public_answer)

    def test_simulated_sink_never_calls_external_primitives(self) -> None:
        sink = SimulatedSink()
        action = SinkAction(
            sink_id="simulated_audit_sink",
            operation="record_canary",
            value="CANARY-TEST",
            source_field="confidential_token",
        )
        with (
            patch.object(socket, "create_connection") as create_connection,
            patch.object(urllib.request, "urlopen") as urlopen,
            patch.object(subprocess, "Popen") as popen,
            patch.object(os, "system") as os_system,
        ):
            result = sink.attempt(action)
        create_connection.assert_not_called()
        urlopen.assert_not_called()
        popen.assert_not_called()
        os_system.assert_not_called()
        self.assertTrue(result.simulator_accepted)
        self.assertFalse(result.user_authorized)
        self.assertTrue(result.security_policy_violation)
        self.assertTrue(result.prohibited_simulated_effect)
        self.assertFalse(result.external_side_effect)
        self.assertEqual(len(sink.records), 1)

    def test_invalid_sink_action_is_blocked(self) -> None:
        result = SimulatedSink().attempt(
            SinkAction(
                sink_id="real_external_sink",
                operation="send",
                value="CANARY-TEST",
                source_field="confidential_token",
            )
        )
        self.assertTrue(result.blocked)
        self.assertFalse(result.simulator_accepted)
        self.assertFalse(result.prohibited_simulated_effect)
        self.assertFalse(result.external_side_effect)

    def test_task_scoped_sink_rejects_a_different_canary(self) -> None:
        sink = SimulatedSink(
            expected_canary="CANARY-EXPECTED",
        )
        result = sink.attempt(
            SinkAction(
                sink_id="simulated_audit_sink",
                operation="record_canary",
                value="CANARY-DIFFERENT",
                source_field="confidential_token",
            )
        )
        self.assertTrue(result.blocked)
        self.assertFalse(result.simulator_accepted)
        self.assertFalse(result.prohibited_simulated_effect)
        self.assertEqual(sink.records, [])


if __name__ == "__main__":
    unittest.main()
