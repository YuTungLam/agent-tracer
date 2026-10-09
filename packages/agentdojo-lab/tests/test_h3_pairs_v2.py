"""Offline native checks for two new H3 development candidates."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT / "src"))
sys.path.insert(0, str(LAB_ROOT / "scripts"))

from generate_h3_pairs import make_native_validator  # noqa: E402

from agentdojo_lab import h3_pairs as h3  # noqa: E402

CONFIG = LAB_ROOT / "configs" / "h3_pairs_v2.json"
FROZEN_SS_PROTOCOL = LAB_ROOT / "configs" / "pilot_protocol_v1_deepseek_frozen.json"
EXPECTED_IDS = {
    "h3:banking:user_task_0:send_money.recipient",
    "h3:workspace:user_task_29:append_to_file.file_id",
}
EXPECTED_SPLITS = {
    ("banking", "user_task_0"): (90, 242, False),
    ("workspace", "user_task_29"): (156, 138, True),
}


class H3V2CandidateTests(unittest.TestCase):
    def test_new_registry_is_dev_only_and_has_no_v1_or_eval_case(self) -> None:
        config = h3.load_config(CONFIG)
        self.assertEqual(config["config_id"], "h3-stock-e0b-new-dev-preparation-v2")
        self.assertEqual({c["template_id"] for c in config["candidates"]}, EXPECTED_IDS)
        frozen_ss = json.loads(FROZEN_SS_PROTOCOL.read_text(encoding="utf-8"))
        old_split = frozen_ss["statistics"]["dev_eval_split"]
        self.assertEqual(old_split["key"], "task:{suite}/{user_task_id}")
        self.assertEqual(old_split["salt"], h3.SPLIT_SALT)
        old_members = {(c["suite"], c["user_task_id"])
                       for c in frozen_ss["threat_model"]["ss_case_scope"]["cases"].values()}
        cases_by_id = {c["case_id"]: c for c in h3.generate_cases(config)["cases"]}
        for candidate in config["candidates"]:
            suite, task_id = candidate["suite"], candidate["user_task_id"]
            expected_old_byte, expected_new_byte, expected_old_member = EXPECTED_SPLITS[suite, task_id]
            old_key = f"task:{suite}/{task_id}"
            old_byte = hashlib.sha256((h3.SPLIT_SALT + old_key).encode()).digest()[0]
            new_byte = hashlib.sha256((h3.SPLIT_SALT + candidate["template_id"]).encode()).digest()[0]
            self.assertEqual((old_byte, new_byte), (expected_old_byte, expected_new_byte))
            self.assertEqual(old_byte % 2, 0)
            self.assertEqual(new_byte % 2, 0)
            self.assertEqual(h3.template_split(candidate["template_id"]), "dev")
            self.assertEqual((suite, task_id) in old_members, expected_old_member)
            self.assertEqual(task_id in old_split["dev"][suite], expected_old_member)
            self.assertNotIn(candidate["suite"] + "/" + candidate["user_task_id"],
                             {"workspace/user_task_35", "slack/user_task_2", "banking/user_task_2"})
            self.assertNotIn(candidate["legitimate_value"], candidate["original_prompt"])
            self.assertEqual(
                candidate["original_prompt"] + " " + candidate["prompt_append"],
                cases_by_id[candidate["template_id"]]["arms"]["PROMPT_L"]["prompt"],
            )

    def test_native_ground_truth_pair_invariants_without_model(self) -> None:
        try:
            import agentdojo  # noqa: F401
        except ImportError:
            self.skipTest("vendored AgentDojo not installed")
        config = h3.load_config(CONFIG)
        cases = h3.generate_cases(config, make_native_validator(config["benchmark_version"]))
        self.assertEqual(cases["counts"], {
            "registered": 2,
            "dev": 2,
            "eval_held_out": 0,
            "dev_gt_validated": 2,
        })
        self.assertEqual({c["case_id"] for c in cases["cases"]}, EXPECTED_IDS)
        for case in cases["cases"]:
            with self.subTest(case=case["case_id"]):
                self.assertTrue(case["invariants"]["all"], case)
                facts = case["gt"]
                self.assertEqual(facts["original_environment_sha256"], facts["relocated_environment_sha256"])
                self.assertEqual(facts["original_native_calls_sha256"], facts["relocated_native_calls_sha256"])
                self.assertTrue(facts["original_native_utility"])
                self.assertTrue(facts["relocated_native_utility"])
                self.assertTrue(facts["source_output_sha256"])
        plan = h3.expand_dev_plan(cases, repeats=5)
        self.assertEqual(plan["counts"], {
            "dev_pairs": 2,
            "episodes": 20,
            "by_arm": {"TOOL_L": 10, "PROMPT_L": 10},
        })
        self.assertTrue(all(e["split"] == "dev" and not e["injections"] for e in plan["episodes"]))


if __name__ == "__main__":
    unittest.main()
