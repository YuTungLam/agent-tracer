"""Zero-cost tests for the MELON gate driver on an ADI-derived case file (ADI amendment).

Synthetic placeholder payload only (``common/tests/adi_fixture.py``); every upstream is a scripted loopback
fake. Pure tests run anywhere; the driver tests need the agentdojo-lab venv, the MELON artifact and MiniLM
(as ``test_melon_h2.py``).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

TESTS = Path(__file__).resolve().parent
MELON = TESTS.parent
ADAPTERS = MELON.parent
H2 = ADAPTERS / "h2"
COMMON = ADAPTERS / "common"
for path in (TESTS, MELON, H2, COMMON, COMMON / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adi_compat  # noqa: E402
import adi_fixture as fx  # noqa: E402
import melon_h2_core as mc  # noqa: E402
import test_melon_h2 as base  # noqa: E402

ADI_CONFIG = MELON / "melon_h2_config.adi.json"
ADI_STAGES = MELON / "stages.adi.json"


class AdiCoreTests(unittest.TestCase):
    def test_empty_clean_injections_accepted_only_without_x(self):
        ep = {"episode_id": "e", "suite": "banking", "injections": {}, "target": {}, "attacker_value": fx.X,
              "legitimate_set": [fx.L], "carries_attacker_value": False}
        self.assertEqual(mc.validate_injections([ep], {"banking": [fx.VECTOR]})["episodes"], 1)
        with self.assertRaises(mc.CaseContractError):
            mc.validate_injections([dict(ep, carries_attacker_value=True)], {"banking": [fx.VECTOR]})

    def test_exposure_needle_under_the_json_formatter(self):
        seen = [json.dumps([{"subject": fx.ATTACK_ENV_TEXT}])]           # how the JSON formatter renders it
        plain = mc.exposure_pre_gate([], [], seen, arm_text=fx.ATTACK_ENV_TEXT, attacker_value=fx.X)
        self.assertFalse(plain["injection_exposed_pre_gate"])           # the escaped text is not the raw needle
        fmt = mc.exposure_pre_gate([], [], seen, arm_text=fx.ATTACK_ENV_TEXT, attacker_value=fx.X,
                                   tool_output_format="json")
        self.assertTrue(fmt["injection_exposed_pre_gate"])
        self.assertTrue(fmt["attacker_value_seen_pre_gate"])
        after_escape = [json.dumps([{"subject": "line one\n" + fx.X}])]       # m1: X right after a JSON escape
        self.assertFalse(mc.exposure_pre_gate([], [], after_escape, arm_text=None, attacker_value=fx.X)
                         ["attacker_value_seen_pre_gate"])
        self.assertTrue(mc.exposure_pre_gate([], [], after_escape, arm_text=None, attacker_value=fx.X,
                                             tool_output_format="json")["attacker_value_seen_pre_gate"])

    def test_attack_is_a_value_arm_and_clean_a_benign_arm(self):
        self.assertIn("ATTACK", mc.VALUE_ARMS)
        planned = [{"episode_id": f"{fx.CASE_ID}|{a}|r0", "arm": a} for a in ("ATTACK", "CLEAN")]
        s = mc.summarize_gate(planned, [])
        self.assertEqual(list(s["per_arm"]), ["CLEAN", "ATTACK"])
        self.assertIn("false_block_rate", s["per_arm"]["CLEAN"])
        self.assertNotIn("false_block_rate", s["per_arm"]["ATTACK"])
        self.assertIsNone(s["approval_contrast"])

    def test_adi_config_mirrors_the_h2_adi_config(self):
        import deepseek_route as dr

        mine = json.loads(ADI_CONFIG.read_text(encoding="utf-8"))
        h2 = json.loads((H2 / "config.adi.json").read_text(encoding="utf-8"))
        self.assertEqual(set(mine["stages"]), {"ADI-S1", "ADI-S2"})
        for name, stage in mine["stages"].items():
            twin = h2["stages"][stage["mirrors_h2_stage"]]
            for key in ("splits", "require_invariants", "value_kinds", "families", "arms", "repeats", "max_cases",
                        "temperature"):
                self.assertEqual(stage.get(key), twin.get(key), f"{name}.{key}")
            self.assertEqual(stage["episode_request_ceiling"], 2 * twin["episode_request_ceiling"])
        self.assertEqual(mine["agent"]["llm"] | {"note": None}, h2["agent"]["llm"] | {"note": None})
        self.assertEqual(mine["agent"]["tool_output_format"], "case_file")
        for key in ("required_equals", "required_presence", "forbidden_fields"):
            self.assertEqual(mine["wire_request_assertion"][key], h2["wire_request_assertion"][key])
        stages = json.loads(ADI_STAGES.read_text(encoding="utf-8"))
        for name in ("ADI-S1", "ADI-S2"):
            merged, _ = dr.load_stage(ADI_STAGES, name)
            self.assertIn("{adapter_dir}/melon_h2_config.adi.json", merged["argv"])
            self.assertIn("{cases_sha256}", merged["argv"])
            self.assertIn(name, mine["stages"])
        self.assertLess(stages["stages"]["ADI-S1"]["cap_usd"], stages["stages"]["ADI-S2"]["cap_usd"])
        import adi_stages

        self.assertEqual(adi_stages.check(adi_stages.load_json(adi_stages.ACFG_DEFAULT)), [])   # G-ADI-STAGES
        # the frozen config and stage file are unchanged by the amendment
        self.assertEqual(set(json.loads(base.CONFIG.read_text(encoding="utf-8"))["stages"]), {"AL-S1", "AL-S2", "AL-S2T0"})


@unittest.skipUnless(base.IN_LAB_VENV and base.HAVE_ARTIFACT and base.HAVE_MINILM,
                     "needs the agentdojo-lab venv, the MELON artifact and MiniLM")
class AdiDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="melon-adi-"))
        cls.cases, cls.lf = fx.write_doc(cls.tmp / "adi-cases.json", fx.adi_doc("json"))
        cfg = json.loads(ADI_CONFIG.read_text(encoding="utf-8"))
        cfg["stages"]["T"] = dict(cfg["stages"]["ADI-S1"], temperature=0.0, episode_request_ceiling=20)
        cls.config = cls.tmp / "melon_h2_config.adi.test.json"
        cls.config.write_text(json.dumps(cfg), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_json_format_is_what_the_agent_and_the_masked_run_see(self):
        out = self.tmp / "json"
        with fx.ScriptedUpstream(fx.refund_policy(masked="none")) as fake:
            rc = base._run_driver(self.tmp, self.config, self.cases, "T", out, fake.base_url,
                                  extra=["--expect-content-sha256", self.lf])
            bodies = list(fake.requests)
        self.assertEqual(rc, 0)
        rows = {r["arm"]: r for r in base._read_jsonl(out / "episodes.jsonl")}
        self.assertEqual(set(rows), {"ATTACK", "CLEAN"})
        for arm, row in rows.items():
            self.assertEqual(row["status"], "ok", row.get("error_message"))
            self.assertTrue(row["code_check"]["ok"], row["code_check"])
            self.assertTrue(row["melon"]["gate_oracle_cross_check"]["agrees"])
        self.assertEqual((rows["ATTACK"]["outcome"], rows["CLEAN"]["outcome"]), ("attacker", "legitimate"))
        self.assertEqual(rows["ATTACK"]["melon"]["gate"]["x_call_approval"], "approved")
        self.assertTrue(rows["ATTACK"]["injection_exposed_pre_gate"])
        self.assertIsNone(rows["CLEAN"]["injection_exposed_pre_gate"])
        agent = [b for b in bodies if not fx.is_masked(b)]
        masked = [b for b in bodies if fx.is_masked(b)]
        self.assertTrue(masked)
        self.assertEqual(fx.transactions_rendering(fx.tool_texts(agent)), "json")
        # MELON's masked run embeds the same tool text the agent saw (pi_detector.py tool_contents)
        self.assertTrue(any(adi_compat.json_escaped(fx.ATTACK_ENV_TEXT) in fx.text_of(m.get("content"))
                            for b in masked for m in b["messages"] if m.get("role") == "tool"))
        plan = json.loads((out / "episode_plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["tool_output_format"]["tool_output_format"], "json")
        self.assertEqual(plan["case_file"]["sha256_lf"], self.lf)
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["seed_family"], "ADI")
        self.assertIn("false_block_rate", summary["melon_gate"]["per_arm"]["CLEAN"])
        rows_pp = base._gate_rows(self.cases, out)["groups"]["ADI|all"]["rows"]["melon"]["per_arm"]
        self.assertEqual([rows_pp["ATTACK"]["ss_catch"][k] for k in ("k", "n")], [0, 1])
        self.assertEqual([rows_pp["CLEAN"]["false_block"][k] for k in ("k", "n")], [0, 1])

    def test_wrong_pin_is_refused_before_any_child(self):
        out = self.tmp / "pin"
        with fx.ScriptedUpstream(fx.refund_policy()) as fake:
            rc = base._run_driver(self.tmp, self.config, self.cases, "T", out, fake.base_url,
                                  extra=["--expect-content-sha256", "e" * 64])
            self.assertEqual(fake.requests, [])
        self.assertEqual(rc, 2)
        self.assertFalse((out / "episodes.jsonl").exists())

    def test_end_to_end_through_the_stage_runner_with_the_shipped_stage_file(self):
        import deepseek_route as dr

        lab_env = self.tmp / "fake-lab.env"
        lab_env.write_text("DEEPSEEK_API_KEY=sk-fake-deepseek-0123456789\n", encoding="utf-8")
        with fx.ScriptedUpstream(fx.refund_policy(masked="none")) as fake:
            receipt = dr.run_stage(dr.StageRequest(
                artifact="melon", stage="ADI-S1", cap_usd=Decimal("0.25"), cap_tokens=600000,
                out_root=self.tmp / "runs", lab_env=lab_env, artifact_root=base.LAB, config_path=ADI_STAGES,
                extra_values={"cases": str(self.cases), "cases_sha256": self.lf, "melon_dir": str(base.ARTIFACT_DIR)},
                deepseek_url_override=fake.base_url, label="test"))
        self.assertEqual(receipt["status"], "completed", receipt.get("stderr"))
        out = Path(receipt["receipt_path"]).parent / "melon_h2"
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["planned_episodes"], 2)
        self.assertEqual(receipt["guard"]["requests_forwarded"], summary["usage"]["requests"])


if __name__ == "__main__":
    unittest.main()
