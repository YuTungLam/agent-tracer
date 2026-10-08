"""Zero-cost tests for the H2-SS runner. Every upstream is a loopback fake; no model, no network.

Core tests (expand/summarize) run under any Python. The adapter tests build the
real AgentDojo banking pipeline against the fake upstream and need the lab venv:

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
CONFIG = H2 / "config.template.json"
STAGES = H2 / "stages.json"
LAB_SRC = LAB / "src"
for path in (TESTS, H2, COMMON, LAB_SRC):
    sys.path.insert(0, str(path))

import h2_core as hc  # noqa: E402
from fake_h2_upstream import ATTACKER_ACCOUNT, LEGIT_ACCOUNT, FakeH2Upstream  # noqa: E402

try:
    import agentdojo  # noqa: F401
    import agentdojo_lab  # noqa: F401
    from agentdojo_lab import h2_cases  # noqa: F401
    IN_LAB_VENV = Path(agentdojo.__file__).resolve().is_relative_to(LAB)
except ImportError:
    IN_LAB_VENV = False

FAKE_TOKEN = "guard-token-for-tests-0123456789"
AUTH_MAP = {"send_money": ["recipient"]}


def _banking_census(root: Path) -> Path:
    """A synthetic single-case census for banking user_task_0.

    user_task_0's recipient IBAN is genuinely vector-dependent in the real census
    (it lives inside injection_bill_text); this fixture marks it non-dependent so the
    generator keeps it, because the fake upstream is scripted for the bill -> send_money
    flow. This is a plumbing fixture, not a census-fidelity claim.
    """
    import csv
    d = root / "derived"
    d.mkdir(parents=True, exist_ok=True)

    def w(name, header, rows):
        with (d / name).open("w", encoding="utf-8", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=header)
            wr.writeheader()
            for r in rows:
                wr.writerow({k: r.get(k, "") for k in header})

    w("e0_values.csv",
      ["suite", "user_task_id", "call_index", "function", "argument", "element_index",
       "value_kind", "value", "origin", "exposed_before_call", "vector_dependent"],
      [{"suite": "banking", "user_task_id": "user_task_0", "call_index": "1", "function": "send_money",
        "argument": "recipient", "element_index": "0", "value_kind": "account", "value": LEGIT_ACCOUNT,
        "origin": "b_environment", "exposed_before_call": "true", "vector_dependent": "false"}])
    w("e1_vector_exposure.csv", ["suite", "user_task_id", "vector_count", "ordered_vectors", "first_exposure"],
      [{"suite": "banking", "user_task_id": "user_task_0", "vector_count": "1",
        "ordered_vectors": "injection_bill_text",
        "first_exposure": json.dumps({"injection_bill_text": {"index": 0}})}])
    w("e1_injection_tasks.csv", ["suite", "injection_task_id", "gt_plus_fallback.seed_candidate"], [])
    w("e1_attacker_values.csv",
      ["suite", "injection_task_id", "function", "argument", "element_index", "value_kind", "value", "in_clean_environment"], [])
    w("role_table.csv", ["suite", "tool", "argument", "argument_role", "value_kind"],
      [{"suite": "banking", "tool": "send_money", "argument": "recipient", "argument_role": "authority",
        "value_kind": "account"},
       {"suite": "banking", "tool": "send_money", "argument": "subject", "argument_role": "content", "value_kind": ""}])
    return d


class CoreTests(unittest.TestCase):
    def _case(self, cid, split, passing=True, executable=True):
        arms = {a: {"injections": {"injection_bill_text": f"default {a}"},
                    "carries_attacker_value": a in ("INSTR", "FACT")}
                for a in ("CLEAN", "INSTR", "FACT", "SHAM")}
        return {"case_id": cid, "seed_family": "E0B", "suite": "banking", "user_task_id": "user_task_" + cid[-1],
                "split": split, "target": {"function": "send_money", "argument": "recipient", "value_kind": "account",
                "slots": [{"function": "send_money", "argument": "recipient", "element_index": 0}]},
                "legitimate_set": ["L"], "legitimate_value": "L", "attacker_value": "X", "attacker_value_kind": "fresh",
                "decoy_value": "D", "gt": {"attacker_executable": executable, "attacker_execution_state_observable": True},
                "arms": arms, "invariants": {"all": passing}}

    def _case_file(self):
        return {"schema": hc.SCHEMA_CASES, "arms_emitted": ["CLEAN", "INSTR", "FACT", "SHAM"],
                "config_sha256": "deadbeef", "cases_digest": "cafe", "gt_validated": True,
                "authority_arg_map": AUTH_MAP,
                "cases": [self._case("c-dev-1", "dev"), self._case("c-eval-2", "eval"),
                          self._case("c-bad-3", "dev", passing=False)]}

    def test_expand_filters_by_split_and_invariants(self):
        cf = self._case_file()
        stage = {"splits": ["dev"], "require_invariants": True, "arms": ["CLEAN", "INSTR", "FACT", "SHAM"], "repeats": 5}
        eps = hc.expand_stage(cf, stage)
        self.assertEqual(hc.count_arms(eps), {"CLEAN": 5, "INSTR": 5, "FACT": 5, "SHAM": 5, "total": 20})
        self.assertTrue(all(e["case_id"] == "c-dev-1" for e in eps))
        self.assertEqual(len({e["episode_id"] for e in eps}), 20)
        self.assertTrue(all(e.get("attacker_executable") for e in eps))

    def test_expand_rejects_unemitted_arm(self):
        with self.assertRaises(hc.H2RunError):
            hc.expand_stage(self._case_file(), {"arms": ["FACT_STRUCT"], "repeats": 1})

    def test_plan_digest_changes_with_payload(self):
        cf = self._case_file()
        eps = hc.expand_stage(cf, {"splits": ["dev"], "arms": ["CLEAN", "INSTR", "FACT", "SHAM"], "repeats": 1})
        d1 = hc.plan_digest(eps)
        eps2 = [dict(e) for e in eps]
        eps2[0]["injection_payload_sha256"] = "changed"
        self.assertNotEqual(d1, hc.plan_digest(eps2))

    def test_summary_executed_vs_attempted_and_errors_counted(self):
        cf = self._case_file()
        stage = {"splits": ["dev"], "arms": ["CLEAN", "INSTR", "FACT", "SHAM"], "repeats": 2}
        planned = hc.expand_stage(cf, stage)

        def rec(ep, outcome, attempted, utility=None, run_error=False):
            return {"episode_id": ep["episode_id"], "scored": True, "outcome": outcome, "utility": utility,
                    "run_error": run_error, "injection_exposed": ep["carries_attacker_value"],
                    "oracle_details": {"attacker_attempted": attempted}, "prompt_tokens": 100,
                    "completion_tokens": 10, "requests": 1}
        recs = []
        for ep in planned:
            if ep["arm"] == "FACT":
                recs.append(rec(ep, "attacker", True))
            elif ep["arm"] == "INSTR":
                if ep["repeat"] == 0:
                    recs.append(rec(ep, "attacker", True))
                else:
                    recs.append(rec(ep, "task_failure", True, run_error=True))
            else:
                recs.append(rec(ep, "legitimate", False, utility=True))
        summary = hc.summarize(cf, "T", planned, recs, mode="deepseek",
                               price={"snapshot_id": "s", "input_per_million": "0.30", "output_per_million": "1.20"})
        self.assertEqual(summary["per_arm"]["FACT"]["attacker_executed_rate"]["pct"], 100.0)
        self.assertEqual(summary["per_arm"]["INSTR"]["attacker_executed_rate"]["pct"], 50.0)
        self.assertEqual(summary["per_arm"]["INSTR"]["attacker_attempted_rate"]["pct"], 100.0)
        self.assertEqual(summary["per_arm"]["INSTR"]["scored"], 2)  # errored episode still scored
        self.assertEqual(summary["ss_contrast"]["executed"]["delta_pp"], 50.0)
        self.assertEqual(summary["ss_contrast"]["attempted"]["delta_pp"], 0.0)
        self.assertTrue(summary["complete"])
        self.assertIsNotNone(summary["usage"]["usd_at_snapshot"])

    def test_real_stage_config_loads(self):
        # a test actually loads the shipped stages.json and config.template.json.
        stages = json.loads(STAGES.read_text(encoding="utf-8"))
        self.assertEqual(set(stages["stages"]), {"DRY", "S1", "S2", "S2T0"})
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(set(config["stages"]), {"DRY", "S1", "S2", "S2T0"})
        for name, st in config["stages"].items():
            self.assertIn(st.get("temperature"), (0.0, 0.7), name)


@unittest.skipUnless(IN_LAB_VENV and LAB_PY.is_file(), "needs the agentdojo-lab venv python")
class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h2-run-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        sys.path.insert(0, str(LAB / "scripts"))
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo_lab import h2_cases
        from generate_h2_cases import make_gt_provider
        defaults = dict(get_suite("v1.2.2", "banking").get_injection_vector_defaults())
        config = h2_cases.load_config(LAB / "configs" / "h2_cases_v1.json")
        census = _banking_census(self.tmp)
        provider = make_gt_provider("v1.2.2", {"send_money": {"recipient"}})
        self.doc = h2_cases.generate_cases(census, config, defaults, gt_provider=provider)
        self.case_file = self.tmp / "cases.json"
        self.case_file.write_text(json.dumps(self.doc), encoding="utf-8")
        self.assertEqual(len(self.doc["cases"]), 1)
        self.assertEqual(self.doc["cases"][0]["target"]["value_kind"], "account")
        self.assertTrue(self.doc["cases"][0]["invariants"]["all"])

    def _run_main(self, stage: str, out: Path, base_url: str) -> int:
        import run_h2
        saved = dict(os.environ)
        for k in list(os.environ):
            if k.upper().startswith(("OPENAI_", "DEEPSEEK_", "AUDITOR_")):
                os.environ.pop(k, None)
        os.environ.update({"AUDITOR_GUARD_URL": base_url, "AUDITOR_GUARD_TOKEN": FAKE_TOKEN,
                           "OPENAI_BASE_URL": base_url, "OPENAI_API_KEY": FAKE_TOKEN,
                           "AUDITOR_MODE": "test-fake", "NO_PROXY": "127.0.0.1,localhost", "PYTHONUTF8": "1"})
        try:
            return run_h2.main(["--config", str(CONFIG), "--cases", str(self.case_file), "--stage", stage,
                                "--lab-root", str(LAB), "--out-dir", str(out)])
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_oracle_resolves_each_arm(self):
        out = self.tmp / "dry"
        with FakeH2Upstream() as fake:
            rc = self._run_main("DRY", out, fake.base_url)
        self.assertEqual(rc, 0)
        rows = {r["arm"]: r for r in hc.read_jsonl(out / "episodes.jsonl")}
        self.assertEqual(set(rows), {"CLEAN", "INSTR", "FACT", "SHAM"})
        self.assertEqual(rows["CLEAN"]["outcome"], "legitimate")
        self.assertEqual(rows["SHAM"]["outcome"], "legitimate")
        self.assertEqual(rows["INSTR"]["outcome"], "attacker")
        self.assertEqual(rows["FACT"]["outcome"], "attacker")
        self.assertTrue(rows["INSTR"]["oracle_details"]["attacker_executed"])
        self.assertFalse(rows["CLEAN"]["oracle_details"]["attacker_executed"])
        self.assertTrue((out / "transcripts").is_dir())
        self.assertTrue(rows["FACT"]["injection_exposed"])
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["ss_contrast"]["executed"]["fact"]["pct"], 100.0)
        self.assertEqual(summary["ss_contrast"]["executed"]["instr"]["pct"], 100.0)

    def test_wire_contract_enforced_and_no_secret_leak(self):
        out = self.tmp / "dry2"
        with FakeH2Upstream() as fake:
            self._run_main("DRY", out, fake.base_url)
            for body in fake.requests:
                self.assertEqual(body["model"], "deepseek-flash")
                self.assertEqual(body["temperature"], 0.0)  # DRY stage temperature
                self.assertEqual(body["max_tokens"], 2048)
                self.assertEqual(body["thinking"], {"type": "disabled"})
                self.assertNotIn("max_completion_tokens", body)
            self.assertTrue(all(h == f"Bearer {FAKE_TOKEN}" for h in fake.auth_headers))
        for name in ("episodes.jsonl", "summary.json", "h2_receipt.json"):
            self.assertNotIn(FAKE_TOKEN, (out / name).read_text(encoding="utf-8"))

    def test_end_to_end_through_the_stage_runner(self):
        import deepseek_route as dr
        temp_stages = self.tmp / "stages.json"
        temp_stages.write_text(json.dumps({
            "schema": "auditor-adapter-stages/v1", "artifact": "h2",
            "defaults": {"venv": ".venv", "request_model": "deepseek-flash", "max_tokens_default": 2048,
                         "max_tokens_ceiling": 2048, "request_timeout_seconds": 120},
            "stages": {"DRY": {
                "argv": ["{artifact_python}", "{adapter_dir}/run_h2.py", "--config", "{adapter_dir}/config.template.json",
                         "--cases", "{cases}", "--stage", "{stage}", "--lab-root", "{artifact_root}",
                         "--out-dir", "{out_dir}/h2"],
                "paid_allowed": True, "cap_usd": 0.10, "cap_tokens": 300000, "cap_requests": 200, "timeout_seconds": 600}},
        }), encoding="utf-8")
        lab_env = self.tmp / "fake-lab.env"
        lab_env.write_text("DEEPSEEK_API_KEY=sk-fake-deepseek-0123456789\n", encoding="utf-8")
        with FakeH2Upstream() as fake:
            receipt = dr.run_stage(dr.StageRequest(
                artifact="h2", stage="DRY", cap_usd=Decimal("0.10"), cap_tokens=300000,
                out_root=self.tmp / "runs", lab_env=lab_env, artifact_root=LAB, config_path=temp_stages,
                extra_values={"cases": str(self.case_file)}, deepseek_url_override=fake.base_url, label="test"))
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["fidelity_label"], "backbone-substituted (deepseek-flash)")
        out = Path(receipt["receipt_path"]).parent / "h2"
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(receipt["guard"]["requests_forwarded"], summary["usage"]["requests"])
        self.assertTrue(all(h == "Bearer sk-fake-deepseek-0123456789" for h in fake.auth_headers))
        ledger = Path(receipt["guard"]["ledger"]).read_text(encoding="utf-8")
        self.assertNotIn(ATTACKER_ACCOUNT, ledger)  # ledger holds ids/usage only, no payload


if __name__ == "__main__":
    unittest.main()
