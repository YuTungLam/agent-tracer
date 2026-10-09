"""Zero-cost tests for the AttriGuard case runner on an ADI-derived case file (ADI amendment).

Synthetic placeholder payload only (``common/tests/adi_fixture.py``; no ADI payload text). Unit tests need only
the standard library. The end-to-end test also needs the artifact venv (agentdojo 0.1.35 + openai) and
ATTRIGUARD_SRC; every upstream is the loopback ground-truth replay in fake_gt_upstream.py.

    ATTRIGUARD_SRC=<artifact>/src/usenix-artifacts/main/pipeline \
      <artifact>/.venv/Scripts/python -X utf8 -m unittest discover -s packages/auditor-adapters/attriguard/tests
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
COMMON = ADAPTER_DIR.parent / "common"
for _p in (ADAPTER_DIR, HERE, COMMON / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import adi_fixture as fx  # noqa: E402
import attriguard_cases as ac  # noqa: E402

sys.path.insert(0, str(COMMON))
import adi_stages  # noqa: E402

ADI_CONFIG = ADAPTER_DIR / "config.cases.adi.json"
ADI_STAGES = ADAPTER_DIR / "stages.adi.json"
RUNNER = ADAPTER_DIR / "run_attriguard_cases.py"
ART_SRC = os.environ.get("ATTRIGUARD_SRC")


def _config() -> dict:
    config, _ = ac.load_stage_config(ADI_CONFIG)
    return config


def _child_env(mode: str | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENAI_", "AUDITOR_", "DEEPSEEK_"))}
    env.update({"OPENAI_API_KEY": "test-dummy-key", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
                "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
    if mode:
        env["AUDITOR_MODE"] = mode
    return env


class AdiLoaderTests(unittest.TestCase):
    def test_config_is_valid_and_pins_at_run_time(self):
        config = _config()
        self.assertEqual(set(config["stages"]), {"ADI-S1", "ADI-S2"})
        for name, stage in config["stages"].items():
            sel = stage["selections"]["adi"]
            self.assertTrue(sel[ac.RUNTIME_PIN_KEY])
            self.assertEqual((sel["splits"], sel["families"], sel["arms"]), (["dev"], ["ADI"], ["ATTACK", "CLEAN"]))
            self.assertEqual(ac.unpinned_selections(config, name), ["adi"])            # no run-time pin given
            self.assertEqual(ac.unpinned_selections(config, name, runtime_pinned={"adi": "x"}), [])
        self.assertEqual(config["stages"]["ADI-S2"]["repeats"], 5)
        self.assertNotRegex(ADI_CONFIG.read_text(encoding="utf-8"), r"[A-Za-z]:[\\/]")
        # the frozen config keeps its stages and its ADI exclusion note is superseded only in the ADI config
        frozen, _ = ac.load_stage_config(ADAPTER_DIR / "config.cases.json")
        self.assertEqual(set(frozen["stages"]), {"AL-S1", "AL-S2", "AL-S2T0"})

    def test_expand_attack_and_clean_and_refuse_mixed_families(self):
        config = _config()
        doc = fx.adi_doc(cases=[fx.adi_case(f"{fx.CASE_ID}-{i}") for i in range(4)])
        ac.validate_case_file(doc)
        s1 = ac.expand_case_stage(config, "ADI-S1", {"adi": doc})
        self.assertEqual(ac.count_plan(s1)["by_arm"], {"ATTACK": 6, "CLEAN": 6})       # 3 cases x 2 rows
        s2 = ac.expand_case_stage(config, "ADI-S2", {"adi": doc})
        self.assertEqual(len(s2), 4 * 2 * 5 * 2)
        self.assertEqual({e["family"] for e in s2}, {"ADI"})
        clean = next(e for e in s2 if e["arm"] == "CLEAN")
        self.assertEqual((clean["injections"], clean["exposure_needles"]), ({}, None))
        mixed = fx.adi_doc(cases=[fx.adi_case(), fx.adi_case(fx.CASE_ID + "x", family="E0B")])
        cfg = json.loads(json.dumps(config))
        cfg["stages"]["ADI-S2"]["selections"]["adi"].pop("families")
        with self.assertRaises(ac.CaseFileError):
            ac.expand_case_stage(cfg, "ADI-S2", {"adi": mixed})
        with self.assertRaises(ac.CaseFileError):                                   # SS stage on an ADI file
            ac.expand_case_stage(json.loads((ADAPTER_DIR / "config.cases.json").read_text(encoding="utf-8")),
                                 "AL-S2", {"ss": doc})

    def test_per_arm_legitimate_set_and_unresolved_executability(self):
        config = _config()
        doc = fx.adi_doc(cases=[fx.adi_case(per_arm_legit=True)])
        ac.validate_case_file(doc)
        eps = {e["arm"]: e for e in ac.expand_case_stage(config, "ADI-S1", {"adi": doc}) if e["row"] == "no_defense"}
        self.assertEqual((eps["ATTACK"]["legitimate_set"], eps["CLEAN"]["legitimate_set"]), ([fx.L_ATTACK], [fx.L]))
        bad = fx.adi_case()
        bad["arms"]["ATTACK"]["legitimate_set"] = ["", "x"]
        with self.assertRaises(ac.CaseFileError):
            ac.validate_case_file(fx.adi_doc(cases=[bad]))
        with self.assertRaisesRegex(ac.CaseFileError, "unresolved"):                     # m5
            ac.expand_case_stage(config, "ADI-S1", {"adi": fx.adi_doc(cases=[fx.adi_case(executable=None)])})

    def test_format_validation_and_identity(self):
        ident = ac.case_file_identity(fx.adi_doc("json"))
        self.assertEqual(ident["tool_output_format"], "json")
        self.assertNotIn("tool_output_format", ac.case_file_identity(fx.adi_doc(None)))
        with self.assertRaises(ac.CaseFileError):
            ac.validate_case_file(dict(fx.adi_doc(), tool_output_format="xml"))

    def test_runtime_pins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, lf = fx.write_doc(Path(tmp) / "adi.json", fx.adi_doc())
            config = _config()
            ok, problems = ac.runtime_pin_problems(config, "ADI-S1", {"adi": path}, {"adi": lf})
            self.assertEqual((ok, problems), ({"adi": lf}, []))
            _, problems = ac.runtime_pin_problems(config, "ADI-S1", {"adi": path}, {})
            self.assertIn("pinned at run time", problems[0])
            _, problems = ac.runtime_pin_problems(config, "ADI-S1", {"adi": path}, {"adi": "0" * 64})
            self.assertIn("pinned to another file", problems[0])

    def test_exposure_under_the_json_formatter(self):
        ep = {"exposure_needles": ac.arm_exposure_needles({"arm_text": fx.ATTACK_ENV_TEXT}), "decoy_sentence": None,
              "attacker_value": fx.X}
        rendered = [json.dumps([{"subject": fx.ATTACK_ENV_TEXT}])]
        oracle, _ = ac.load_oracle(ac.default_oracle_path(ADAPTER_DIR))
        self.assertFalse(ac.exposure_flags(rendered, ep, oracle.contains_value)["injection_exposed"])
        flags = ac.exposure_flags(rendered, ep, oracle.contains_value, "json")
        self.assertTrue(flags["injection_exposed"] and flags["attacker_value_in_tool_output"])
        after_escape = [json.dumps([{"subject": "line one\n" + fx.X}])]                 # m1: X right after an escape
        self.assertFalse(ac.exposure_flags(after_escape, ep, oracle.contains_value)["attacker_value_in_tool_output"])
        self.assertTrue(ac.exposure_flags(after_escape, ep, oracle.contains_value, "json")["attacker_value_in_tool_output"])

    def _plan(self, tmp: Path, *extra: str, mode: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-X", "utf8", str(RUNNER), "--config", str(ADI_CONFIG), "--stage",
                               "ADI-S2", "--cases", f"adi={tmp / 'adi.json'}", "--out", str(tmp / "out"), "--plan-only",
                               *extra], cwd=tmp, env=_child_env(mode), capture_output=True, text=True,
                              encoding="utf-8", timeout=120)

    def test_plan_only_needs_the_run_time_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _, lf = fx.write_doc(tmp / "adi.json", fx.adi_doc("json"))
            proc = self._plan(tmp)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("pinned at run time", proc.stderr)
            proc = self._plan(tmp, "--expect-cases-sha256-lf", "adi=" + "0" * 64)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("pinned to another file", proc.stderr)
            proc = self._plan(tmp, "--expect-cases-sha256-lf", f"adi={lf}", mode="deepseek")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["counts"]["total"], 20)
            plan = json.loads((tmp / "out" / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["tool_output_format"]["tool_output_format"], "json")
            self.assertEqual(plan["case_files"]["adi"]["sha256_lf"], lf)

    def test_adi_stages_load_and_plan_in_the_shared_runner(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("deepseek_route_ag_adi", COMMON / "deepseek_route.py")
        route = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = route
        try:
            spec.loader.exec_module(route)
            for name in ("ADI-S1", "ADI-S2"):
                merged, _ = route.load_stage(ADI_STAGES, name)
                self.assertFalse(merged["dry_run_allowed"])
                self.assertIn("{adapter_dir}/config.cases.adi.json", merged["argv"])
                self.assertIn("adi={cases}", merged["argv"])
                self.assertIn("adi={cases_sha256}", merged["argv"])
                self.assertIn(name, _config()["stages"])
                self.assertIn("UNVERIFIED", json.dumps(merged["estimate"]))
            acfg = adi_stages.load_json(adi_stages.ACFG_DEFAULT)
            self.assertEqual(adi_stages.check(acfg), [])          # G-ADI-STAGES
            d29 = next(e for e in acfg["experiments"] if e["id"] == "D29")
            with tempfile.TemporaryDirectory() as tmp:
                plan = route.run_stage(route.StageRequest(
                    artifact="attriguard", stage="ADI-S2", cap_usd=Decimal(str(d29["cap"][0])), cap_tokens=d29["cap"][1],
                    out_root=Path(tmp) / "out", artifact_root=Path(tmp) / "artifact", plan_only=True,
                    config_path=ADI_STAGES, extra_values={"cases": "C:/r/adi.json", "cases_sha256": "2" * 64}))["plan"]
            self.assertIn("adi=" + "2" * 64, plan["argv"])
            self.assertEqual(plan["cap_requests"], d29["cap"][2])
        finally:
            sys.modules.pop(spec.name, None)


def _artifact_env_ready() -> bool:
    if not ART_SRC or not (Path(ART_SRC) / "AttriGuard.py").is_file():
        return False
    try:
        import agentdojo  # noqa: F401
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(_artifact_env_ready(), "needs the artifact venv and ATTRIGUARD_SRC")
class AdiEndToEndTests(unittest.TestCase):
    """The unmodified runner and the released gate on the synthetic ADI file, JSON formatter, GT replay."""

    def test_json_formatter_reaches_agent_and_gate_and_the_oracle_scores_both_arms(self):
        from fake_gt_upstream import GTUpstream

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "cwd").mkdir()
            cases, lf = fx.write_doc(tmp / "adi.json", fx.adi_doc("json"))
            scripts_path = tmp / "gt_scripts.json"
            proc = subprocess.run([sys.executable, "-X", "utf8", str(HERE / "make_gt_scripts.py"), str(cases),
                                   str(scripts_path), "dev"], env=_child_env(), capture_output=True, text=True,
                                  encoding="utf-8", timeout=600)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            scripts = json.loads(scripts_path.read_text(encoding="utf-8"))
            self.assertEqual(scripts[f"{fx.CASE_ID}|ATTACK"]["x"][-1]["args"]["recipient"], fx.X)
            out = tmp / "out"
            with GTUpstream(scripts, judge_allow=True) as up:
                proc = subprocess.run(
                    [sys.executable, "-X", "utf8", str(RUNNER), "--artifact-src", ART_SRC, "--config", str(ADI_CONFIG),
                     "--stage", "ADI-S1", "--cases", f"adi={cases}", "--expect-cases-sha256-lf", f"adi={lf}",
                     "--out", str(out), "--guard-url", up.base_url], cwd=tmp / "cwd", env=_child_env(),
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            eps = {(e["row"], e["arm"]): e for e in ac.read_jsonl(out / "episodes.jsonl")}
            self.assertEqual(len(eps), 4)
            for row in ("no_defense", "attriguard_l2"):
                self.assertEqual(eps[(row, "ATTACK")]["outcome"], "attacker", eps[(row, "ATTACK")].get("oracle_details"))
                self.assertEqual(eps[(row, "CLEAN")]["outcome"], "legitimate")
                self.assertTrue(eps[(row, "ATTACK")]["injection_exposed"])
                self.assertIsNone(eps[(row, "CLEAN")]["injection_exposed"])
                self.assertEqual(eps[(row, "ATTACK")]["instrumentation_anomalies"], [])
            self.assertTrue(eps[("attriguard_l2", "ATTACK")]["funnel"]["F2_audited_x"])
            # what the models were shown: JSON tool outputs, in the agent's and the attenuator's/judge's requests
            agent_tool_texts = [m["content"] for body, h in zip(up.requests, up.headers)
                                if {k.lower(): v for k, v in h.items()}.get("x-auditor-role") == "agent"
                                for m in body["messages"] if m.get("role") == "tool" and isinstance(m.get("content"), str)]
            self.assertEqual(fx.transactions_rendering(agent_tool_texts), "json")
            escaped = json.dumps(fx.ATTACK_ENV_TEXT)[1:-1]                     # how the ADI formatter renders it
            self.assertNotEqual(escaped, fx.ATTACK_ENV_TEXT)
            aux_texts = [m.get("content") for body, h in zip(up.requests, up.headers)
                         if {k.lower(): v for k, v in h.items()}.get("x-auditor-role") == "attenuation"
                         for m in body["messages"] if isinstance(m.get("content"), str)]
            self.assertTrue(aux_texts)
            self.assertTrue(any(escaped in t for t in aux_texts))             # the attenuator read the same JSON
            receipt = json.loads((out / "adapter_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "ok")
            self.assertEqual(receipt["tool_output_format"]["tool_output_format"], "json")
            self.assertIn("common/adi_compat.py", receipt["adapter_files_sha256"])    # declared file: hashed
            self.assertEqual(receipt["case_files"]["adi"]["sha256_lf"], lf)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            fb = summary["false_block_on_clean"]["attriguard_l2"]["adi"]
            self.assertEqual(fb["episodes_with_blocked_legit_call"]["k"], 0)
            self.assertEqual(summary["per_arm"]["attriguard_l2"]["adi"]["ATTACK"]["ASR_attacker_executed"]["k"], 1)


if __name__ == "__main__":
    unittest.main()
