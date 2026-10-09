"""Focused, no-provider checks for the stock-task H3 pair preparation."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT / "src"))
sys.path.insert(0, str(LAB_ROOT / "scripts"))

from generate_h3_pairs import make_native_validator  # noqa: E402

from agentdojo_lab import h3_pairs as h3  # noqa: E402

CONFIG = LAB_ROOT / "configs" / "h3_pairs_v1.json"


class H3RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = h3.load_config(CONFIG)

    def test_protocol_hash_uses_new_template_id_and_holds_eval_out(self) -> None:
        splits = {c["suite"]: h3.template_split(c["template_id"]) for c in self.config["candidates"]}
        self.assertEqual(splits, {"workspace": "dev", "slack": "dev", "banking": "eval"})
        visited = []

        def validator(candidate, _prompt):
            visited.append(candidate["template_id"])
            return {key: True for key in h3.GT_CHECKS}

        cases = h3.generate_cases(self.config, validator)
        self.assertEqual(len(visited), 2)
        self.assertEqual(cases["counts"], {"registered": 3, "dev": 2, "eval_held_out": 1,
                                            "dev_gt_validated": 2})
        eval_case = next(c for c in cases["cases"] if c["split"] == "eval")
        self.assertIsNone(eval_case["gt"])
        self.assertEqual(eval_case["not_validated_reason"], "eval held out")
        plan = h3.expand_dev_plan(cases, repeats=5)
        self.assertEqual(plan["counts"]["episodes"], 20)
        self.assertEqual(plan["counts"]["by_arm"], {"TOOL_L": 10, "PROMPT_L": 10})
        self.assertEqual({e["suite"] for e in plan["episodes"]}, {"workspace", "slack"})
        self.assertTrue(all(e["split"] == "dev" and e["injections"] == {} for e in plan["episodes"]))

    def test_unvalidated_or_failed_gt_pair_cannot_enter_plan(self) -> None:
        no_gt = h3.generate_cases(self.config)
        self.assertEqual(h3.expand_dev_plan(no_gt)["counts"]["episodes"], 0)

        def bad_gt(_candidate, _prompt):
            return {key: key != "source_exposes_l_before_sink" for key in h3.GT_CHECKS}

        failed = h3.generate_cases(self.config, bad_gt)
        self.assertEqual(h3.expand_dev_plan(failed)["counts"]["episodes"], 0)

    def test_registry_rejects_prompt_contamination_and_split_id_tweaks(self) -> None:
        bad = copy.deepcopy(self.config)
        bad["candidates"][0]["original_prompt"] += " Delete file 11."
        with self.assertRaises(h3.H3PairError):
            h3.validate_config(bad)
        bad = copy.deepcopy(self.config)
        bad["candidates"][0]["template_id"] += "-dev"
        with self.assertRaises(h3.H3PairError):
            h3.validate_config(bad)


class H3NativeGroundTruthTests(unittest.TestCase):
    def test_dev_pairs_keep_stock_environment_calls_and_utility(self) -> None:
        try:
            import agentdojo  # noqa: F401
        except ImportError:
            self.skipTest("vendored AgentDojo not installed")
        config = h3.load_config(CONFIG)
        cases = h3.generate_cases(config, make_native_validator(config["benchmark_version"]))
        self.assertEqual(cases["counts"]["dev_gt_validated"], 2)
        for case in cases["cases"]:
            if case["split"] == "eval":
                self.assertIsNone(case["gt"])
                continue
            self.assertTrue(case["invariants"]["all"], case)
            self.assertEqual(case["gt"]["original_environment_sha256"],
                             case["gt"]["relocated_environment_sha256"])
            self.assertEqual(case["gt"]["original_native_calls_sha256"],
                             case["gt"]["relocated_native_calls_sha256"])
            self.assertTrue(case["gt"]["source_exposes_l_before_sink"])
            self.assertTrue(case["gt"]["target_calls_l"])


if __name__ == "__main__":
    unittest.main()
