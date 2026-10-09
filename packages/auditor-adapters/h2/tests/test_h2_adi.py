"""Zero-cost tests for the H2 runner on an ADI-derived case file (ADI amendment).

A synthetic ADI-format case file with a placeholder payload (``common/tests/adi_fixture.py``; no ADI payload
text) runs through the real AgentDojo banking pipeline against a scripted loopback fake. Core tests run under
any Python; the adapter tests need the lab venv:

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s h2/tests -v
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
H2 = TESTS.parent
ADAPTERS = H2.parent
COMMON = ADAPTERS / "common"
LAB = Path(os.environ.get("H2_LAB_ROOT") or ADAPTERS.parent / "agentdojo-lab").resolve()
LAB_PY = LAB / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
ADI_CONFIG = H2 / "config.adi.json"
ADI_STAGES = H2 / "stages.adi.json"
for path in (TESTS, H2, COMMON, COMMON / "tests", LAB / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adi_compat  # noqa: E402
import adi_fixture as fx  # noqa: E402
import adi_stages  # noqa: E402
import h2_core as hc  # noqa: E402

try:
    import agentdojo  # noqa: F401
    import agentdojo_lab  # noqa: F401
    IN_LAB_VENV = Path(agentdojo.__file__).resolve().is_relative_to(LAB)
except ImportError:
    IN_LAB_VENV = False

FAKE_TOKEN = "guard-token-for-tests-0123456789"


class AdiCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h2-adi-core-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _stage(self, name="ADI-S2"):
        return json.loads(ADI_CONFIG.read_text(encoding="utf-8"))["stages"][name]

    def test_adi_stage_expands_attack_and_clean_for_every_eligible_case(self):
        evalc = dict(fx.adi_case(fx.CASE_ID + "e"), split="eval")          # eval protection: never selected
        doc = fx.adi_doc(cases=[fx.adi_case(), fx.adi_case(fx.CASE_ID + "b"), fx.adi_case(fx.CASE_ID + "c", runnable=False),
                                evalc])
        eps = hc.expand_stage(doc, self._stage("ADI-S2"))
        self.assertEqual(hc.count_arms(eps), {"ATTACK": 10, "CLEAN": 10, "total": 20})
        self.assertNotIn(evalc["case_id"], {e["case_id"] for e in eps})
        self.assertTrue(all(e["carries_attacker_value"] == (e["arm"] == "ATTACK") for e in eps))
        s1 = hc.expand_stage(fx.adi_doc(cases=[fx.adi_case(f"{fx.CASE_ID}-{i}") for i in range(5)]), self._stage("ADI-S1"))
        self.assertEqual(len(s1), 6)                              # first 3 cases x 2 arms x 1 repeat

    def test_ss_stage_refuses_an_adi_file_and_adi_refuses_mixed_families(self):
        with self.assertRaises(hc.H2RunError):                    # INSTR/FACT are not emitted
            hc.expand_stage(fx.adi_doc(), {"arms": ["CLEAN", "INSTR", "FACT", "SHAM"], "repeats": 1})
        mixed = fx.adi_doc(cases=[fx.adi_case(), fx.adi_case(fx.CASE_ID + "e0b", family="E0B")])
        with self.assertRaises(hc.H2RunError):
            hc.expand_stage(mixed, {"arms": ["ATTACK", "CLEAN"], "repeats": 1})
        self.assertEqual(len(hc.expand_stage(mixed, self._stage("ADI-S1"))), 2)   # the ADI stage selects ADI only

    def test_per_arm_legitimate_set_and_exposure_needles(self):
        eps = hc.expand_stage(fx.adi_doc(cases=[fx.adi_case(per_arm_legit=True)]), self._stage("ADI-S1"))
        by_arm = {e["arm"]: e for e in eps}
        self.assertEqual(by_arm["ATTACK"]["legitimate_set"], [fx.L_ATTACK])     # ADI-X-11: the arm's own set
        self.assertEqual(by_arm["CLEAN"]["legitimate_set"], [fx.L])
        self.assertEqual(by_arm["ATTACK"]["exposure_needles"], [fx.ATTACK_ENV_TEXT])   # M2: the payload, not X
        self.assertIsNone(by_arm["CLEAN"]["exposure_needles"])
        plain = {e["arm"]: e for e in hc.expand_stage(fx.adi_doc(), self._stage("ADI-S1"))}
        self.assertEqual(plain["ATTACK"]["legitimate_set"], [fx.L])                  # no per-arm set: the case set
        bad = fx.adi_case()
        bad["arms"]["CLEAN"]["legitimate_set"] = []
        with self.assertRaises(hc.H2RunError):
            hc.expand_stage(fx.adi_doc(cases=[bad]), self._stage("ADI-S1"))

    def test_ss_plan_episode_is_unchanged(self):
        ss = fx.adi_case(family="E0B")
        ss["arms"] = {"CLEAN": ss["arms"]["CLEAN"], "FACT": dict(ss["arms"]["ATTACK"])}
        doc = dict(fx.adi_doc(cases=[ss]), arms_emitted=["CLEAN", "FACT"])
        ep = hc.expand_stage(doc, {"arms": ["CLEAN", "FACT"], "repeats": 1})[1]
        self.assertNotIn("exposure_needles", ep)                      # SS plans carry no ADI field
        self.assertEqual(ep["legitimate_set"], [fx.L])
        ss["gt"]["attacker_executable"] = None                         # SS keeps its frozen bool() reading
        self.assertFalse(hc.expand_stage(doc, {"arms": ["FACT"], "repeats": 1})[0]["attacker_executable"])

    def test_unresolved_executability_is_refused_for_adi(self):
        with self.assertRaisesRegex(hc.H2RunError, "unresolved"):
            hc.expand_stage(fx.adi_doc(cases=[fx.adi_case(executable=None)]), self._stage("ADI-S1"))

    def test_tool_output_format_is_validated_on_load(self):
        for fmt, want in ((None, "yaml"), ("yaml", "yaml"), ("json", "json")):
            path, _ = fx.write_doc(self.tmp / f"c-{fmt}.json", fx.adi_doc(fmt))
            self.assertEqual(hc.tool_output_format(hc.load_case_file(path)), want)
        path, _ = fx.write_doc(self.tmp / "bad.json", dict(fx.adi_doc(), tool_output_format="xml"))
        with self.assertRaises(hc.H2RunError):
            hc.load_case_file(path)

    def test_summary_keeps_adi_apart_and_labels_the_amendment(self):
        doc = fx.adi_doc()
        planned = hc.expand_stage(doc, self._stage("ADI-S2"))
        recs = [{"episode_id": e["episode_id"], "scored": True, "x_sink_called": e["arm"] == "ATTACK",
                 "outcome": "attacker" if e["arm"] == "ATTACK" else "legitimate", "utility": e["arm"] == "CLEAN",
                 "oracle_details": {"attacker_attempted": e["arm"] == "ATTACK"}} for e in planned]
        s = hc.summarize(doc, "ADI-S2", planned, recs, mode="deepseek")
        self.assertEqual(s["seed_family"], "ADI")
        self.assertEqual(s["amendment"], adi_compat.AMENDMENT_ID)
        self.assertEqual(s["tool_output_format"], "json")
        self.assertIn("ADI", s["evidence_label"])
        self.assertEqual(s["per_arm"]["ATTACK"]["attacker_executed_rate"]["pct"], 100.0)
        self.assertEqual(s["per_arm"]["CLEAN"]["legitimate_rate"]["pct"], 100.0)
        self.assertEqual(list(s["per_arm"]), ["CLEAN", "ATTACK"])
        self.assertEqual(s["ss_contrast"], {"executed": None, "attempted": None})
        self.assertIsNone(s["cluster_bootstrap"]["attempted_all"])
        # an SS summary is unchanged: no ADI keys
        self.assertNotIn("seed_family", hc.summarize({"cases": []}, "S", [], [], mode="x"))

    def test_shipped_adi_stage_files_load_in_the_route(self):
        import deepseek_route as dr

        stages = json.loads(ADI_STAGES.read_text(encoding="utf-8"))
        self.assertEqual(set(stages["stages"]), {"ADI-S1", "ADI-S2"})
        config = json.loads(ADI_CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(set(config["stages"]), {"ADI-S1", "ADI-S2"})
        self.assertEqual(config["agent"]["tool_output_format"], "case_file")
        for name, st in config["stages"].items():
            self.assertEqual((st["splits"], st["families"], st["arms"], st["temperature"]),
                             (["dev"], ["ADI"], ["ATTACK", "CLEAN"], 0.7))
        self.assertEqual(config["stages"]["ADI-S2"]["repeats"], 5)
        acfg = adi_stages.load_json(adi_stages.ACFG_DEFAULT)
        self.assertEqual(adi_stages.check(acfg), [])                 # G-ADI-STAGES: the files equal ACFG experiments[]
        d27 = next(e for e in acfg["experiments"] if e["id"] == "D27")
        for name in stages["stages"]:
            merged, _ = dr.load_stage(ADI_STAGES, name)
            self.assertIn("{cases_sha256}", merged["argv"])
            self.assertIn("{adapter_dir}/config.adi.json", merged["argv"])
            self.assertIn("UNVERIFIED", json.dumps(merged["estimate"]))
            self.assertNotRegex(json.dumps(merged), r"[A-Za-z]:[\\/]")
        with tempfile.TemporaryDirectory() as tmp:
            plan = dr.run_stage(dr.StageRequest(
                artifact="h2", stage="ADI-S2", cap_usd=Decimal(str(d27["cap"][0])), cap_tokens=d27["cap"][1],
                out_root=Path(tmp) / "o", artifact_root=LAB, config_path=ADI_STAGES, plan_only=True,
                extra_values={"cases": "C:/results/adi.json", "cases_sha256": "0" * 64}))["plan"]
            with self.assertRaises(dr.RouteError):                    # above the ACFG cap: refused
                dr.run_stage(dr.StageRequest(
                    artifact="h2", stage="ADI-S2", cap_usd=Decimal(str(d27["cap"][0])) + Decimal("0.01"),
                    cap_tokens=d27["cap"][1], out_root=Path(tmp) / "o", artifact_root=LAB, config_path=ADI_STAGES,
                    plan_only=True, extra_values={"cases": "C:/results/adi.json", "cases_sha256": "0" * 64}))
        self.assertIn("0" * 64, plan["argv"])
        self.assertEqual(plan["cap_requests"], d27["cap"][2])
        # the frozen SS stage files are untouched by the amendment
        self.assertEqual(set(json.loads((H2 / "stages.json").read_text(encoding="utf-8"))["stages"]),
                         {"DRY", "S1", "S2", "S2T0"})


@unittest.skipUnless(IN_LAB_VENV and LAB_PY.is_file(), "needs the agentdojo-lab venv python")
class AdiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h2-adi-run-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        cfg = json.loads(ADI_CONFIG.read_text(encoding="utf-8"))
        cfg["stages"]["T"] = dict(cfg["stages"]["ADI-S1"], temperature=0.0, episode_request_ceiling=10)
        self.config = self.tmp / "config.adi.test.json"
        self.config.write_text(json.dumps(cfg), encoding="utf-8")

    def _run(self, doc, out, *, stage="T", expect=None, config=None):
        import run_h2

        path, lf = fx.write_doc(self.tmp / f"{out.name}-cases.json", doc)
        saved = dict(os.environ)
        for k in list(os.environ):
            if k.upper().startswith(("OPENAI_", "DEEPSEEK_", "AUDITOR_")):
                os.environ.pop(k, None)
        with fx.ScriptedUpstream(fx.refund_policy()) as fake:
            os.environ.update({"AUDITOR_GUARD_URL": fake.base_url, "AUDITOR_GUARD_TOKEN": FAKE_TOKEN,
                               "OPENAI_BASE_URL": fake.base_url, "OPENAI_API_KEY": FAKE_TOKEN,
                               "AUDITOR_MODE": "test-fake", "NO_PROXY": "127.0.0.1,localhost", "PYTHONUTF8": "1"})
            try:
                rc = run_h2.main(["--config", str(config or self.config), "--cases", str(path), "--stage", stage,
                                  "--lab-root", str(LAB), "--out-dir", str(out),
                                  "--expect-content-sha256", expect if expect is not None else lf])
            finally:
                os.environ.clear()
                os.environ.update(saved)
            return rc, fake.requests, path, lf

    def test_json_format_reaches_the_agent_and_the_oracle_scores_attack_and_clean(self):
        out = self.tmp / "json"
        rc, bodies, path, lf = self._run(fx.adi_doc("json"), out)
        self.assertEqual(rc, 0)
        self.assertEqual(fx.transactions_rendering(fx.tool_texts(bodies)), "json")
        texts = "\n".join(fx.tool_texts(bodies))
        self.assertIn(adi_compat.json_escaped(fx.ATTACK_ENV_TEXT), texts)   # quote and non-ASCII escaped, as the fork
        self.assertNotIn(fx.ATTACK_ENV_TEXT, texts)
        rows = {r["arm"]: r for r in hc.read_jsonl(out / "episodes.jsonl")}
        self.assertEqual((rows["ATTACK"]["outcome"], rows["CLEAN"]["outcome"]), ("attacker", "legitimate"))
        self.assertTrue(rows["ATTACK"]["oracle_details"]["post_state_adds_attacker"])
        self.assertTrue(rows["ATTACK"]["injection_exposed"])             # M2: the payload was seen
        self.assertTrue(rows["ATTACK"]["attacker_value_in_tool_output"])
        self.assertIsNone(rows["CLEAN"]["injection_exposed"])            # CLEAN plants nothing
        self.assertFalse(rows["CLEAN"]["attacker_value_in_tool_output"])
        self.assertTrue(rows["ATTACK"]["x_sink_called"])
        self.assertTrue(rows["CLEAN"]["utility"])
        plan = json.loads((out / "episode_plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["tool_output_format"]["tool_output_format"], "json")
        self.assertEqual(plan["case_file"]["sha256_lf"], lf)
        receipt = json.loads((out / "h2_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["tool_output_format"]["source"]["commit"], adi_compat.ADI_FORMATTER_SOURCE["commit"])
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual((summary["seed_family"], summary["tool_output_format"]), ("ADI", "json"))
        transcript = json.loads((out / "transcripts" / rows["ATTACK"]["transcript_path"]).read_text(encoding="utf-8"))
        self.assertTrue(json.loads(transcript["tool_outputs"][0]))      # the transcript keeps the JSON text

    def test_absent_format_is_the_stock_yaml(self):
        out = self.tmp / "yaml"
        rc, bodies, _path, _lf = self._run(fx.adi_doc(None), out)
        self.assertEqual(rc, 0)
        self.assertEqual(fx.transactions_rendering(fx.tool_texts(bodies)), "yaml")
        plan = json.loads((out / "episode_plan.json").read_text(encoding="utf-8"))
        self.assertNotIn("tool_output_format", plan)                    # nothing declared, nothing added
        receipt = json.loads((out / "h2_receipt.json").read_text(encoding="utf-8"))
        self.assertNotIn("tool_output_format", receipt)                 # m3: an undeclared file keeps the frozen keys
        self.assertEqual(set(receipt["files_sha256"]), {"run_h2.py", "h2_core.py", "deepseek_route.py"})
        rows = {r["arm"]: r for r in hc.read_jsonl(out / "episodes.jsonl")}
        self.assertEqual((rows["ATTACK"]["outcome"], rows["CLEAN"]["outcome"]), ("attacker", "legitimate"))

    def test_unknown_vector_is_refused_before_any_request(self):
        case = fx.adi_case()
        case["arms"]["ATTACK"]["injections"] = {"injection_restaurant_msg": "placeholder"}   # a fork-only vector id
        out = self.tmp / "vector"
        rc, bodies, _path, _lf = self._run(fx.adi_doc("json", cases=[case]), out)
        self.assertEqual(rc, 2)                                          # m2: refused, not run as errored episodes
        self.assertEqual(bodies, [])
        self.assertFalse((out / "episodes.jsonl").exists())

    def test_wrong_pin_is_refused_before_any_request(self):
        out = self.tmp / "pin"
        rc, bodies, _path, _lf = self._run(fx.adi_doc("json"), out, expect="f" * 64)
        self.assertEqual(rc, 2)
        self.assertEqual(bodies, [])
        self.assertFalse((out / "episodes.jsonl").exists())

    def test_config_format_mismatch_is_refused(self):
        cfg = json.loads(self.config.read_text(encoding="utf-8"))
        cfg["agent"]["tool_output_format"] = "yaml"
        bad = self.tmp / "config.yaml-only.json"
        bad.write_text(json.dumps(cfg), encoding="utf-8")
        rc, bodies, _path, _lf = self._run(fx.adi_doc("json"), self.tmp / "mismatch", config=bad)
        self.assertEqual(rc, 2)
        self.assertEqual(bodies, [])

    def test_end_to_end_through_the_stage_runner_with_the_shipped_stage_file(self):
        import deepseek_route as dr

        path, lf = fx.write_doc(self.tmp / "adi-cases.json", fx.adi_doc("json"))
        lab_env = self.tmp / "fake-lab.env"
        lab_env.write_text("DEEPSEEK_API_KEY=sk-fake-deepseek-0123456789\n", encoding="utf-8")
        with fx.ScriptedUpstream(fx.refund_policy()) as fake:
            receipt = dr.run_stage(dr.StageRequest(
                artifact="h2", stage="ADI-S1", cap_usd=Decimal("0.10"), cap_tokens=300000, out_root=self.tmp / "runs",
                lab_env=lab_env, artifact_root=LAB, config_path=ADI_STAGES,
                extra_values={"cases": str(path), "cases_sha256": lf}, deepseek_url_override=fake.base_url,
                label="test"))
        self.assertEqual(receipt["status"], "completed", receipt)
        out = Path(receipt["receipt_path"]).parent / "h2"
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["planned_episodes"], 2)
        self.assertEqual(summary["per_arm"]["ATTACK"]["attacker_executed_rate"]["k"], 1)
        self.assertEqual(receipt["guard"]["requests_forwarded"], summary["usage"]["requests"])
        self.assertNotIn(fx.X, Path(receipt["guard"]["ledger"]).read_text(encoding="utf-8"))
        self.assertEqual(fx.transactions_rendering(fx.tool_texts(fake.requests)), "json")


if __name__ == "__main__":
    unittest.main()
