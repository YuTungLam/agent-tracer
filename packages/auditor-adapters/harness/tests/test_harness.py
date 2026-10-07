"""Zero-cost tests for the no-defense harness adapter.  Every upstream is a loopback fake.

Run from packages/auditor-adapters with the LAB venv python (the integration
tests import AgentDojo and are skipped under any other interpreter):

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s harness/tests -v
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

TESTS = Path(__file__).resolve().parent
HARNESS = TESTS.parent
ADAPTERS = HARNESS.parent
COMMON = ADAPTERS / "common"
LAB = Path(os.environ.get("HARNESS_LAB_ROOT") or ADAPTERS.parent / "agentdojo-lab").resolve()
LAB_PY = LAB / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
CONFIG = HARNESS / "config.template.json"
for path in (TESTS, HARNESS, COMMON):
    sys.path.insert(0, str(path))

import harness_core as hc  # noqa: E402
from fake_agent_upstream import FakeAgentUpstream  # noqa: E402

try:  # the integration tests need the lab venv (vendored AgentDojo + agentdojo_lab)
    import agentdojo  # noqa: F401
    import agentdojo_lab  # noqa: F401

    IN_LAB_VENV = Path(agentdojo.__file__).resolve().is_relative_to(LAB)
except ImportError:
    IN_LAB_VENV = False

FAKE_TOKEN = "guard-token-for-tests-0123456789"
INDEX = {
    "banking": {"user_tasks": [f"user_task_{i}" for i in range(16)],
                "injection_tasks": [f"injection_task_{i}" for i in range(9)]},
    "slack": {"user_tasks": [f"user_task_{i}" for i in range(21)],
              "injection_tasks": [f"injection_task_{i}" for i in range(1, 6)]},
    "workspace": {"user_tasks": [f"user_task_{i}" for i in range(40)],
                  "injection_tasks": [f"injection_task_{i}" for i in range(14)]},
    "travel": {"user_tasks": [f"user_task_{i}" for i in range(20)],
               "injection_tasks": [f"injection_task_{i}" for i in range(7)]},
}


def _config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


class CoreTests(unittest.TestCase):
    def test_template_is_valid(self):
        hc.validate_config(_config())

    def test_frozen_agent_settings_are_enforced(self):
        for path, value in (
            (("agent", "llm", "temperature"), 0.7),
            (("agent", "llm", "max_tokens"), 4096),
            (("agent", "llm", "model"), "gpt-4o-mini"),
            (("agent", "llm", "thinking"), {"type": "enabled"}),
            (("agent", "tools_execution_loop_max_iters"), 10),
            (("attack", "name"), "tool_knowledge"),
            (("benchmark", "benchmark_version"), "v1.2.1"),
        ):
            config = _config()
            node = config
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            with self.assertRaises(hc.HarnessConfigError, msg=str(path)):
                hc.validate_config(config)
        config = _config()
        config["defense"] = "melon"
        with self.assertRaises(hc.HarnessConfigError):
            hc.validate_config(config)

    def test_stage_expansion_counts_and_order(self):
        config = _config()
        s2 = hc.expand_stage(config, "S2", INDEX)
        self.assertEqual(hc.count_kinds(s2), {"benign": 37, "injection_as_user": 14, "attacked": 249, "total": 300})
        self.assertEqual(s2[0]["episode_id"], "benign:banking:user_task_0:-")
        self.assertEqual(s2[16]["episode_id"], "injection_as_user:banking:-:injection_task_0")
        self.assertEqual(s2[25]["episode_id"], "attacked:banking:user_task_0:injection_task_0")
        # numeric, not lexical, task order
        self.assertEqual(s2[2]["user_task"], "user_task_2")
        self.assertEqual([e["seq"] for e in s2], list(range(300)))
        s3 = hc.expand_stage(config, "S3", INDEX)
        self.assertEqual(hc.count_kinds(s3)["attacked"], 949)
        self.assertEqual(hc.count_kinds(s3)["benign"], 97)
        s1 = hc.expand_stage(config, "S1", INDEX)
        self.assertEqual(len(s1), 4)
        self.assertNotEqual(hc.plan_digest(s1), hc.plan_digest(s2))

    def test_explicit_episodes_are_checked_against_the_suites(self):
        config = _config()
        config["stages"]["S1"]["episodes"][1]["injection_task"] = "injection_task_99"
        with self.assertRaises(hc.HarnessConfigError):
            hc.expand_stage(config, "S1", INDEX)
        config = _config()
        config["stages"]["S1"]["episodes"].append(copy.deepcopy(config["stages"]["S1"]["episodes"][0]))
        with self.assertRaises(hc.HarnessConfigError):
            hc.expand_stage(config, "S1", INDEX)
        config = _config()
        config["stages"]["S2"]["expected_episode_counts"]["attacked"] = 250
        with self.assertRaises(hc.HarnessConfigError):
            hc.expand_stage(config, "S2", INDEX)

    def test_wilson(self):
        self.assertIsNone(hc.wilson(0, 0))
        low, high = hc.wilson(5, 10)
        self.assertAlmostEqual(low, 0.2366, places=3)
        self.assertAlmostEqual(high, 0.7634, places=3)
        low, high = hc.wilson(0, 37)
        self.assertEqual(low, 0.0)
        self.assertAlmostEqual(high, 0.0942, places=3)

    def test_summary_denominators_and_comparison(self):
        config = _config()
        planned = hc.expand_stage(config, "S1", INDEX)
        records = [
            {"episode_id": planned[0]["episode_id"], "kind": "benign", "scored": True, "utility": True,
             "security": True, "requests": 3, "prompt_tokens": 4000, "completion_tokens": 100, "pipeline_attempts": 1},
            {"episode_id": planned[1]["episode_id"], "kind": "attacked", "scored": True, "utility": False,
             "security": True, "requests": 2, "prompt_tokens": 3000, "completion_tokens": 50, "pipeline_attempts": 1,
             "stock_logged_error": "context_length_exceeded"},
            {"episode_id": planned[3]["episode_id"], "kind": "attacked", "scored": False,
             "error_type": "APIConnectionError", "requests": 1, "prompt_tokens": 0, "completion_tokens": 0,
             "pipeline_attempts": 1},
        ]
        summary = hc.summarize(config, "S1", planned, records, mode="deepseek")
        attacked = summary["overall"]["attacked"]
        self.assertEqual((attacked["planned"], attacked["started"], attacked["scored"], attacked["errored"]), (2, 2, 1, 1))
        self.assertEqual(attacked["asr"]["k"], 1)
        self.assertEqual(attacked["asr"]["n"], 1)
        self.assertEqual(attacked["asr_excluding_stock_errors"]["n"], 0)
        self.assertEqual(summary["overall"]["benign"]["not_started"], 1)
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["usage"]["usd_at_snapshot"], "0.002280")
        comp = summary["comparison"]
        self.assertFalse(comp["same_suite_scope"])
        self.assertFalse(comp["numeric_comparison_allowed"])
        self.assertEqual(comp["target"]["asr_pct"], 42.68)


def _run_adapter(stage: str, out_dir: Path, base_url: str, *extra: str, plan_only: bool = False) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENAI_", "DEEPSEEK_", "AUDITOR_"))}
    if not plan_only:
        env.update({"AUDITOR_GUARD_URL": base_url, "AUDITOR_GUARD_TOKEN": FAKE_TOKEN, "OPENAI_BASE_URL": base_url,
                    "OPENAI_API_KEY": FAKE_TOKEN, "AUDITOR_MODE": "test-fake", "NO_PROXY": "127.0.0.1,localhost"})
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
    argv = [str(LAB_PY), str(HARNESS / "run_harness.py"), "--config", str(CONFIG), "--stage", stage,
            "--lab-root", str(LAB), "--out-dir", str(out_dir), *extra]
    if plan_only:
        argv.append("--plan-only")
    return subprocess.run(argv, cwd=out_dir.parent, env=env, capture_output=True, text=True, timeout=600, check=False)


@unittest.skipUnless(IN_LAB_VENV and LAB_PY.is_file(), "needs the agentdojo-lab venv python")
class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="harness-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_plan_only_needs_no_guard(self):
        result = _run_adapter("S2", self.tmp / "plan", "", plan_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads((self.tmp / "plan" / "episode_plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["counts"]["total"], 300)

    def test_refuses_without_guard(self):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENAI_", "AUDITOR_"))}
        result = subprocess.run(
            [str(LAB_PY), str(HARNESS / "run_harness.py"), "--config", str(CONFIG), "--stage", "DRY",
             "--lab-root", str(LAB), "--out-dir", str(self.tmp / "noguard")],
            cwd=self.tmp, env=env, capture_output=True, text=True, timeout=600, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("auditor guard", result.stderr)
        self.assertFalse((self.tmp / "noguard" / "episodes.jsonl").exists())

    def test_dry_episode_scores_with_stock_oracles(self):
        out = self.tmp / "dry"
        with FakeAgentUpstream() as fake:
            result = _run_adapter("DRY", out, fake.base_url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = hc.read_jsonl(out / "episodes.jsonl")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["scored"])
        self.assertTrue(row["utility"])  # paid the bill
        self.assertTrue(row["security"])  # attacker transfer with the streaming service
        self.assertEqual(row["requests"], 3)
        self.assertEqual(row["pipeline_attempts"], 1)
        self.assertEqual(row["request_bodies_checked"], 3)
        self.assertEqual(len(fake.requests), 3)
        for body in fake.requests:
            self.assertEqual(body["model"], "deepseek-flash")
            self.assertEqual(body["temperature"], 0.0)
            self.assertEqual(body["max_tokens"], 2048)
            self.assertEqual(body["thinking"], {"type": "disabled"})
            self.assertEqual(body["tool_choice"], "auto")
            self.assertNotIn("max_completion_tokens", body)
            self.assertEqual(body["messages"][0]["role"], "system")
            self.assertTrue(all(m.get("role") != "developer" for m in body["messages"]))
            self.assertTrue(all("name" not in m for m in body["messages"] if m.get("role") == "tool"))
        payload = fake.requests[1]["messages"][-1]["content"]
        self.assertIn("to you, DeepSeek", payload)
        self.assertIn("Emma Johnson", payload)
        self.assertTrue(all(h == f"Bearer {FAKE_TOKEN}" for h in fake.auth_headers))
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["overall"]["attacked"]["asr"]["k"], 1)
        self.assertTrue(summary["complete"])
        log = json.loads((out / "agentdojo_logs" / row["log_path"]).read_text(encoding="utf-8"))
        self.assertTrue(log["security"])
        self.assertTrue(list((out / "request_bodies").glob("*.jsonl")))
        receipt = json.loads((out / "harness_receipt.json").read_text(encoding="utf-8"))
        self.assertTrue(receipt["lab"]["pin_matches"])
        self.assertEqual(receipt["attack"]["model_name"], "DeepSeek")
        self.assertNotIn(FAKE_TOKEN, (out / "episodes.jsonl").read_text(encoding="utf-8"))
        self.assertNotIn(FAKE_TOKEN, (out / "harness_receipt.json").read_text(encoding="utf-8"))

    def test_guard_refusal_stops_the_stage(self):
        out = self.tmp / "halt"
        with FakeAgentUpstream(status=402) as fake:
            result = _run_adapter("S1", out, fake.base_url)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        rows = hc.read_jsonl(out / "episodes.jsonl")
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["scored"])
        self.assertEqual(rows[0]["error_status_code"], 402)
        self.assertEqual(len(fake.requests), 1)
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["started_episodes"], 1)
        receipt = json.loads((out / "harness_receipt.json").read_text(encoding="utf-8"))
        self.assertIn("402", receipt["stop_reason"])

    def test_resume_skips_started_episodes(self):
        first, second = self.tmp / "first", self.tmp / "second"
        with FakeAgentUpstream() as fake:
            self.assertEqual(_run_adapter("DRY", first, fake.base_url).returncode, 0)
            sent = len(fake.requests)
            result = _run_adapter("DRY", second, fake.base_url, "--resume-from", str(first))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(fake.requests), sent)
        receipt = json.loads((second / "harness_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["skipped_as_started_before"], 1)
        summary = json.loads((second / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        # a different stage's run cannot be used to resume
        result = _run_adapter("S1", self.tmp / "third", "http://127.0.0.1:9/v1", "--resume-from", str(first))
        self.assertEqual(result.returncode, 2)

    def test_wire_violation_is_never_sent(self):
        import openai
        import run_harness as rh

        config = hc.load_config(CONFIG)
        with FakeAgentUpstream() as fake:
            ctx = rh._Context()
            rt = rh.build_runtime(config, config["stages"]["S1"], base_url=fake.base_url, token=FAKE_TOKEN,
                                  out_dir=self.tmp / "wire", ctx=ctx)
            tools = [{"type": "function", "function": {"name": "noop", "description": "x",
                                                       "parameters": {"type": "object", "properties": {}}}}]
            with self.assertRaises(openai.APIConnectionError) as caught:
                rt["client"].chat.completions.create(
                    model="deepseek-flash", messages=[{"role": "user", "content": "x"}], tools=tools,
                    tool_choice="auto", temperature=0.5, max_tokens=2048,
                    extra_body={"thinking": {"type": "disabled"}},
                )
            self.assertIsInstance(caught.exception.__cause__, rh.WireAssertionError)
            self.assertEqual(fake.requests, [])
            rt["http_client"].close()

    def test_s1_end_to_end_through_the_stage_runner(self):
        import deepseek_route as dr

        lab_env = self.tmp / "fake-lab.env"
        lab_env.write_text("GROQ_API_KEY=not-read-by-the-runner\nDEEPSEEK_API_KEY=sk-fake-deepseek-0123456789\n",
                           encoding="utf-8")
        with FakeAgentUpstream() as fake:
            receipt = dr.run_stage(dr.StageRequest(
                artifact="harness", stage="S1", cap_usd=Decimal("0.10"), cap_tokens=300000,
                out_root=self.tmp / "runs", lab_env=lab_env, artifact_root=LAB,
                deepseek_url_override=fake.base_url, label="test",
            ))
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["fidelity_label"], "backbone-substituted (deepseek-flash)")
        out = Path(receipt["receipt_path"]).parent / "harness"
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["started_episodes"], 4)
        self.assertTrue(summary["complete"])
        self.assertEqual(receipt["guard"]["requests_forwarded"], len(fake.requests))
        self.assertEqual(receipt["guard"]["requests_forwarded"], summary["usage"]["requests"])
        self.assertEqual(receipt["guard"]["prompt_tokens"], summary["usage"]["prompt_tokens"])
        self.assertTrue(all(h == "Bearer sk-fake-deepseek-0123456789" for h in fake.auth_headers))
        ledger = Path(receipt["guard"]["ledger"]).read_text(encoding="utf-8")
        self.assertNotIn("bill-december", ledger)
        self.assertNotIn("INFORMATION", ledger)
        for name in ("episodes.jsonl", "harness_receipt.json", "summary.json"):
            text = (out / name).read_text(encoding="utf-8")
            self.assertNotIn("sk-fake-deepseek", text)
        child_env_stripped = receipt["child_env_stripped"]
        self.assertIsInstance(child_env_stripped, list)


if __name__ == "__main__":
    unittest.main()
