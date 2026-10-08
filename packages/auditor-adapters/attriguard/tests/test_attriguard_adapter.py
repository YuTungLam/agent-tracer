"""Zero-cost tests for the AttriGuard DeepSeek adapter.

Unit tests need only the standard library. The end-to-end test additionally needs the artifact's venv
(agentdojo 0.1.35 + openai) and ATTRIGUARD_SRC; it drives one real AgentDojo banking episode through the
released gate against a scripted loopback upstream, so it makes no model call.

    python -m unittest discover -s packages/auditor-adapters/attriguard/tests -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))
sys.path.insert(0, str(HERE))

import attriguard_deepseek as ad  # noqa: E402


class NotGiven:  # same type name as openai._types.NotGiven
    pass


class FakeCompletions:
    def __init__(self, completion=None, exc=None):
        self.completion = completion
        self.exc = exc
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return self.completion


def _completion(prompt=100, completion=20, finish="stop", logprobs=None):
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion),
        choices=[SimpleNamespace(finish_reason=finish, logprobs=logprobs)],
    )


class WireTests(unittest.TestCase):
    def test_normalize_messages(self):
        msgs = [
            {"role": "developer", "content": [{"type": "text", "text": "sys"}]},
            {"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1"}]},
            {"role": "tool", "content": [{"type": "text", "text": "out"}], "tool_call_id": "1", "name": "read_file"},
            {"role": "tool", "content": "error text", "tool_call_id": "2", "name": "x"},
        ]
        out = ad.normalize_messages(msgs)
        self.assertEqual(out[0], {"role": "system", "content": "sys"})
        self.assertEqual(out[1]["content"], "a\nb")
        self.assertIsNone(out[2]["content"])
        self.assertNotIn("name", out[3])
        self.assertEqual(out[3]["content"], "out")
        self.assertEqual(out[4]["content"], "error text")
        self.assertIn("name", msgs[3], "input must not be mutated")

    def test_build_wire_params(self):
        params = {
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "tools": NotGiven(),
            "temperature": 0.2,
            "top_p": 0.9,
            "reasoning_effort": "low",
            "max_completion_tokens": 10,
            "logprobs": True,
            "top_logprobs": 5,
        }
        wire, report = ad.build_wire_params(params, max_tokens=2048, allow_logprobs=True)
        self.assertNotIn("tools", wire)
        self.assertNotIn("reasoning_effort", wire)
        self.assertNotIn("max_completion_tokens", wire)
        self.assertEqual(wire["max_tokens"], 2048)
        self.assertEqual(wire["extra_body"], {"thinking": {"type": "disabled"}})
        self.assertEqual(wire["messages"][0]["content"], "hi")
        self.assertTrue(wire["logprobs"])
        self.assertEqual(sorted(report.dropped_fields), ["max_completion_tokens", "reasoning_effort"])
        wire2, report2 = ad.build_wire_params(params, allow_logprobs=False)
        self.assertNotIn("logprobs", wire2)
        self.assertNotIn("top_logprobs", wire2)
        self.assertTrue(report2.stripped_logprobs)

    def test_wrong_model_refused(self):
        with self.assertRaises(ValueError):
            ad.build_wire_params({"model": "gpt-4.1-mini", "messages": []})

    def test_loopback_only(self):
        self.assertEqual(ad.require_loopback_base_url("http://127.0.0.1:8899/v1/"), "http://127.0.0.1:8899/v1")
        self.assertEqual(ad.require_loopback_base_url("http://localhost:1/v1"), "http://localhost:1/v1")
        for bad in ("https://api.deepseek.com", "http://10.0.0.5:8000/v1", "", None, "ftp://127.0.0.1/"):
            with self.assertRaises(ad.AdapterRefusal):
                ad.require_loopback_base_url(bad)

    def test_redact(self):
        text = "Authentication failed for key sk-abcdef1234567890 and mysecretvalue99"
        out = ad.redact(text, ["mysecretvalue99"])
        self.assertNotIn("sk-abcdef1234567890", out)
        self.assertNotIn("mysecretvalue99", out)


class ClientAndProbeTests(unittest.TestCase):
    def test_routed_client_meters_and_tags(self):
        meter, ctx = ad.UsageMeter(), ad.RunContext(episode_id="row/banking/user_task_0/injection_task_0")
        fake = FakeCompletions(_completion(100, 20, finish="length"))
        client = ad.RoutedClient(SimpleNamespace(chat=SimpleNamespace(completions=fake)), "attenuation", meter, ctx)
        client.chat.completions.create(model="deepseek-flash", messages=[{"role": "user", "content": "x"}])
        sent = fake.calls[0]
        self.assertEqual(sent["extra_headers"]["X-Auditor-Role"], "attenuation")
        self.assertEqual(sent["extra_headers"]["X-Auditor-Episode"], ctx.episode_id)
        snap = meter.snapshot()
        self.assertEqual(snap["total"]["attenuation"]["prompt_tokens"], 100)
        self.assertEqual(snap["episode"]["attenuation"]["finish_length"], 1)
        self.assertEqual(ad.UsageMeter.tokens(snap["total"]), 120)
        meter.begin_episode()
        self.assertEqual(ad.UsageMeter.tokens(meter.snapshot()["episode"]), 0)

    def test_routed_client_counts_errors(self):
        meter, ctx = ad.UsageMeter(), ad.RunContext()
        fake = FakeCompletions(exc=RuntimeError("boom"))
        client = ad.RoutedClient(SimpleNamespace(chat=SimpleNamespace(completions=fake)), "agent", meter, ctx)
        with self.assertRaises(RuntimeError):
            client.chat.completions.create(model="deepseek-flash", messages=[])
        self.assertEqual(meter.snapshot()["total"]["agent"]["errors"], 1)

    def test_judge_probe_translates_logprobs_rejection(self):
        class Rejection(Exception):
            status_code = 400

        class Inner:
            def __init__(self):
                self.seen = []

            def query(self, query, runtime, env, messages, extra_args):
                self.seen.append(dict(extra_args))
                if extra_args.get("logprobs"):
                    raise Rejection("Error code: 400 - logprobs is not supported for this model")
                return query, runtime, env, [*messages, {"role": "assistant", "content": [{"content": '{"survive": true}'}]}], {}

        ctx = ad.RunContext()
        probe = ad.JudgeProbe(Inner(), ctx)
        with self.assertRaises(ad.LogprobsUnsupported) as caught:
            probe.query("", None, None, [], {"logprobs": True, "top_logprobs": 5})
        # The released fallback condition, verbatim from AttriGuard._fuzzy_survive:
        err = caught.exception
        self.assertTrue("logprobs" in str(err) and "unsupported" in str(err).lower())
        self.assertTrue(ctx.logprobs_disabled)
        probe.query("", None, None, [], {})
        probe.query("", None, None, [], {"logprobs": True, "top_logprobs": 5})  # sticky: stripped now
        self.assertEqual(probe.inner.seen[-1], {})
        self.assertEqual(probe.last_raw, '{"survive": true}')
        self.assertEqual(probe.calls, 3)

    def test_judge_probe_off_mode(self):
        class Inner:
            def query(self, query, runtime, env, messages, extra_args):
                assert "logprobs" not in extra_args
                return query, runtime, env, [], {"logprobs": None}

        probe = ad.JudgeProbe(Inner(), ad.RunContext(logprobs_mode="off"))
        probe.query("", None, None, [], {"logprobs": True, "top_logprobs": 5})
        self.assertFalse(probe.last_logprobs_present)

    def test_other_errors_propagate(self):
        class Inner:
            def query(self, *a):
                raise ValueError("budget exhausted")

        with self.assertRaises(ValueError):
            ad.JudgeProbe(Inner(), ad.RunContext()).query("", None, None, [], {"logprobs": True})


class RouteTests(unittest.TestCase):
    def kw(self, **over):
        base = dict(exact=False, same_function=True, has_judge=True, judged=True, raw="", logprobs_present=False,
                    survived=False)
        base.update(over)
        return base

    def test_routes(self):
        c = ad.classify_route
        self.assertEqual(c(**self.kw(exact=True, survived=True)), "exact_fastpath")
        self.assertEqual(c(**self.kw(same_function=False, judged=False)), "name_mismatch_block")
        self.assertEqual(c(**self.kw(raw='{"survive": false}')), "judge_json_block")
        self.assertEqual(c(**self.kw(raw='{"survive": true}', survived=True)), "judge_json_allow")
        self.assertEqual(c(**self.kw(raw="it is not true", survived=True)), "judge_parse_fallback_allow")
        self.assertEqual(c(**self.kw(raw='{"survive": false}', logprobs_present=True, survived=True)),
                         "judge_json_allow_logprob_override")
        self.assertEqual(c(**self.kw(has_judge=False, judged=False)), "exact_only_block")


def _catalog():
    return {
        "banking": {"user_tasks": [f"user_task_{i}" for i in range(16)],
                    "injection_tasks": [f"injection_task_{i}" for i in range(9)]},
        "slack": {"user_tasks": [f"user_task_{i}" for i in range(21)],
                  "injection_tasks": [f"injection_task_{i}" for i in range(1, 6)]},
    }


class PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads((ADAPTER_DIR / "config.template.json").read_text(encoding="utf-8"))

    def test_s2_counts_match_table4_arithmetic(self):
        eps = ad.expand_stage(self.config, "S2", _catalog())
        self.assertEqual(len(eps), 528)
        for row in ("no_defense", "attriguard_l2"):
            mine = [e for e in eps if e["row"] == row]
            self.assertEqual(sum(e["injection_task"] is None for e in mine), 34)
            self.assertEqual(sum(e["injection_task"] is not None for e in mine), 230)
            self.assertEqual(sum(e["suite"] == "banking" and e["injection_task"] is not None for e in mine), 135)
        self.assertFalse(any(e["user_task"] == "user_task_12" and e["suite"] == "banking" for e in eps))
        self.assertTrue(any(e["suite"] == "slack" and e["injection_task"] == "injection_task_5" for e in eps))
        # rows interleave per pair: a capped partial run stays paired
        self.assertEqual([e["row"] for e in eps[:4]], ["no_defense", "attriguard_l2", "no_defense", "attriguard_l2"])
        self.assertEqual(len({e["episode_id"] for e in eps}), len(eps))

    def test_s1_and_dry(self):
        s1 = ad.expand_stage(self.config, "S1", _catalog())
        self.assertEqual([(e["suite"], e["user_task"], e["injection_task"]) for e in s1],
                         [("banking", "user_task_0", "injection_task_0"), ("slack", "user_task_0", "injection_task_3")])
        self.assertEqual(len(ad.expand_stage(self.config, "DRY", _catalog())), 1)

    def test_unknown_ids_rejected(self):
        bad = json.loads(json.dumps(self.config))
        bad["stages"]["S1"]["suites"]["banking"]["pairs"] = [["user_task_99", "injection_task_0"]]
        with self.assertRaises(ValueError):
            ad.expand_stage(bad, "S1", _catalog())

    def test_config_has_no_absolute_paths(self):
        for name in ("config.template.json", "config.cases.json"):
            text = (ADAPTER_DIR / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"[A-Za-z]:[\\/]", name)
            self.assertNotIn("/home/", text, name)

    def test_stage_names_match_runner_config(self):
        """Every stages.json stage runs a runner whose config defines it: run_attriguard.py with
        config.template.json (DRY/S1/S2), run_attriguard_cases.py with config.cases.json (AL-*)."""
        stages = json.loads((ADAPTER_DIR / "stages.json").read_text(encoding="utf-8"))
        cases_config = json.loads((ADAPTER_DIR / "config.cases.json").read_text(encoding="utf-8"))
        self.assertEqual(set(stages["stages"]), set(self.config["stages"]) | set(cases_config["stages"]))
        self.assertFalse(set(self.config["stages"]) & set(cases_config["stages"]))
        default_argv = stages["defaults"]["argv"]
        for name, stage in stages["stages"].items():
            argv = stage.get("argv", default_argv)
            if name in cases_config["stages"]:
                self.assertIn("{adapter_dir}/run_attriguard_cases.py", argv, name)
                self.assertIn("{adapter_dir}/config.cases.json", argv, name)
            else:
                self.assertIn("{adapter_dir}/run_attriguard.py", argv, name)
                self.assertIn("{adapter_dir}/config.template.json", argv, name)
        self.assertNotRegex((ADAPTER_DIR / "stages.json").read_text(encoding="utf-8"), r"[A-Za-z]:[\\/]")

    def test_stages_json_accepted_by_common_runner(self):
        common = ADAPTER_DIR.parent / "common" / "deepseek_route.py"
        if not common.is_file():
            self.skipTest("common/deepseek_route.py not present")
        import importlib.util
        from decimal import Decimal

        spec = importlib.util.spec_from_file_location("deepseek_route_under_test", common)
        route = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = route
        spec.loader.exec_module(route)
        for stage in ("DRY", "S1", "S2"):
            merged, _ = route.load_stage(ADAPTER_DIR / "stages.json", stage)
            self.assertGreater(merged["cap_usd"], 0)
        with tempfile.TemporaryDirectory() as tmp:
            plan = route.run_stage(route.StageRequest(
                artifact="attriguard", stage="S1", cap_usd=Decimal("0.10"), cap_tokens=100000,
                out_root=Path(tmp) / "out", artifact_root=Path(tmp) / "artifact", plan_only=True,
            ))["plan"]
        argv = plan["argv"]
        self.assertTrue(argv[0].endswith(("python.exe", "python")))
        self.assertTrue(argv[1].endswith("run_attriguard.py"))
        self.assertIn("S1", argv)
        self.assertTrue(any(a.endswith(str(Path("src/usenix-artifacts/main/pipeline"))) or
                            a.endswith("src/usenix-artifacts/main/pipeline") for a in argv))

    def test_summary(self):
        recs = [
            {"status": "done", "row": "r", "suite": "banking", "injection_task": None, "utility": True, "security": False,
             "episode_tokens": 10},
            {"status": "done", "row": "r", "suite": "banking", "injection_task": "i0", "utility": False, "security": True,
             "episode_tokens": 30},
            {"status": "error", "row": "r", "suite": "banking", "injection_task": "i1"},
        ]
        s = ad.summarize_episodes(recs)["r"]
        self.assertEqual(s["BU"], "1/1 = 100.00%")
        self.assertEqual(s["ASR"], "1/1 = 100.00%")
        self.assertEqual(s["tokens_per_episode"], 20.0)


def _artifact_env_ready() -> bool:
    src = os.environ.get("ATTRIGUARD_SRC")
    if not src or not (Path(src) / "AttriGuard.py").is_file():
        return False
    try:
        import agentdojo  # noqa: F401
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(_artifact_env_ready(), "needs the artifact venv and ATTRIGUARD_SRC")
class EndToEndFakeUpstreamTest(unittest.TestCase):
    """One real AgentDojo banking episode through the released gate, scripted loopback upstream."""

    def test_dry_stage_against_fake_upstream(self):
        from fake_upstream import ATTENUATED_TEXT, FakeUpstream

        with tempfile.TemporaryDirectory() as tmp, FakeUpstream(reject_logprobs=True) as upstream:
            scratch, out = Path(tmp) / "cwd", Path(tmp) / "out"
            scratch.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI_", "AUDITOR_"))}
            env.update({"OPENAI_API_KEY": "test-dummy-key", "PYTHONIOENCODING": "utf-8"})
            proc = subprocess.run(
                [sys.executable, str(ADAPTER_DIR / "run_attriguard.py"), "--artifact-src", os.environ["ATTRIGUARD_SRC"],
                 "--stage", "DRY", "--out", str(out), "--guard-url", upstream.base_url],
                cwd=scratch, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            episodes = [json.loads(x) for x in (out / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(episodes), 1)
            ep = episodes[0]
            self.assertEqual(ep["status"], "done")
            self.assertGreater(ep["usage"]["attenuation"]["requests"], 0)
            self.assertGreater(ep["usage"]["judge"]["requests"], 0)
            gates = [json.loads(x) for x in (out / "gate_decisions.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertIn("judge_json_block", [g["route"] for g in gates])
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["judge"]["logprobs_rejections"], 1)
            self.assertTrue(summary["judge"]["logprobs_disabled_after_rejection"])
            # Wire format on every request.
            for body in upstream.requests:
                self.assertEqual(body["model"], "deepseek-flash")
                self.assertEqual(body["thinking"], {"type": "disabled"})
                self.assertEqual(body["max_tokens"], 2048)
                self.assertNotIn("max_completion_tokens", body)
                self.assertNotIn("reasoning_effort", body)
                for m in body["messages"]:
                    self.assertNotIsInstance(m.get("content"), list)
                    if m["role"] == "tool":
                        self.assertNotIn("name", m)
            roles = [h.get("X-Auditor-Role") for h in upstream.headers]
            self.assertEqual(set(roles), {"agent", "attenuation", "judge"})
            # The shadow saw the attenuated observation, never the raw bill.
            self.assertTrue(any(ATTENUATED_TEXT in json.dumps(b["messages"]) for b in upstream.requests if b.get("tools")))
            self.assertNotIn("test-dummy-key", proc.stdout + proc.stderr)
            receipt = json.loads((out / "adapter_receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "ok")

            # Resume: a second invocation carries the finished episode over and makes no request.
            n_before = len(upstream.requests)
            out2 = Path(tmp) / "out2"
            proc2 = subprocess.run(
                [sys.executable, str(ADAPTER_DIR / "run_attriguard.py"), "--artifact-src", os.environ["ATTRIGUARD_SRC"],
                 "--stage", "DRY", "--out", str(out2), "--guard-url", upstream.base_url, "--resume-from", str(out)],
                cwd=scratch, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
            )
            self.assertEqual(proc2.returncode, 0, proc2.stderr[-3000:])
            self.assertEqual(len(upstream.requests), n_before)
            summary2 = json.loads((out2 / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual((summary2["carried_episodes"], summary2["done_episodes"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
