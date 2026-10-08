"""Zero-cost tests for the NeuroTaint judge stage child and the reference stage files.

The judge talks only to a loopback fake (``fake_judge_upstream``); the guard
environment is simulated the way ``h2/tests`` does. ``deepseek_route.load_stage`` is
used read-only to validate ``stages.json`` (no run-stage, no lock file, no key).

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s reference/tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

import helpers as h  # noqa: E402

try:
    import yaml  # noqa: F401
    import pydantic  # noqa: F401
    IN_LAB = True
except ImportError:
    IN_LAB = False

from fake_judge_upstream import FakeJudgeUpstream  # noqa: E402
from ref_common import COMMON, read_json, read_jsonl  # noqa: E402

FAKE_TOKEN = "guard-token-for-tests-0123456789"
STAGES = h.REF / "stages.json"
OFFLINE = h.REF / "offline_stages.json"


@contextmanager
def guarded_env(base_url: str | None):
    saved = dict(os.environ)
    for k in list(os.environ):
        if k.upper().startswith(("OPENAI_", "DEEPSEEK_", "AUDITOR_")):
            os.environ.pop(k, None)
    if base_url:
        os.environ.update({"AUDITOR_GUARD_URL": base_url, "AUDITOR_GUARD_TOKEN": FAKE_TOKEN, "OPENAI_BASE_URL": base_url,
                           "OPENAI_API_KEY": FAKE_TOKEN, "AUDITOR_MODE": "test-fake", "AUDITOR_STAGE": "NTJ-S1",
                           "NO_PROXY": "127.0.0.1,localhost"})
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


@unittest.skipUnless(IN_LAB, "needs the agentdojo-lab venv")
class JudgeTests(unittest.TestCase):
    def setUp(self):
        import neurotaint_offline as nt
        from agentdojo_lab.cascade import CascadeMatcher
        from ref_common import LAB, load_config
        from test_neurotaint_offline import FakeEncoder, ws_trace
        from agentdojo_lab.semantic import SemanticMatcher

        self.tmp = Path(tempfile.mkdtemp(prefix="ref-judge-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.config = load_config()
        census = read_json(LAB / "configs" / "authority_census_v2.json")
        policy = nt.policy_for_suite("workspace", self.config, census)
        trace = ws_trace(body="Kickoff planning notes attached.", recipient="eve@example.com",
                         source_text="subject: kickoff\nbody: Agenda for the kickoff planning.\n")
        m = CascadeMatcher(SemanticMatcher(FakeEncoder([("eve@", (0.0, 1.0))])), profile="ordinary")
        analysis = nt.analyse_trace(trace, matcher=m, policy=policy, authority_args=h.AUTH)[0]
        plan = nt.plan_probes(analysis, trace, config=self.config, scope="all")
        self.assertEqual(len(plan["probes"]), 1)
        self.probes = self.tmp / "probes.jsonl"
        self.probes.write_text("".join(json.dumps(p) + "\n" for p in plan["probes"]), encoding="utf-8")
        from test_neurotaint_offline import ws_spec
        ss_plan = nt.plan_probes(analysis, trace, config=self.config, spec=ws_spec(stratum="SS"), include_ss=True)
        self.ss_probes = self.tmp / "ss_probes.jsonl"
        self.ss_probes.write_text("".join(json.dumps(p) + "\n" for p in ss_plan["probes"]), encoding="utf-8")

    def run_judge(self, base_url, *extra):
        import neurotaint_judge
        with guarded_env(base_url):
            return neurotaint_judge.main(["--probes", str(self.probes), "--out-dir", str(self.tmp / "out"), *extra])

    def test_sends_the_frozen_request_and_writes_bound_records(self):
        from agentdojo_lab import counterfactual_audit
        with FakeJudgeUpstream() as fake:
            rc = self.run_judge(fake.base_url)
        self.assertEqual(rc, 0)
        self.assertEqual(len(fake.requests), 1)
        body = fake.requests[0]
        self.assertEqual((body["model"], body["temperature"], body["max_completion_tokens"]), ("deepseek-flash", 0, 1024))
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual(body["messages"][0], {"role": "system", "content": counterfactual_audit.SYSTEM_PROMPT})
        self.assertNotIn("tools", body)
        self.assertEqual(fake.auth_headers, [f"Bearer {FAKE_TOKEN}"])
        rows = read_jsonl(self.tmp / "out" / "judgments.jsonl")
        probe = read_jsonl(self.probes)[0]
        self.assertEqual((rows[0]["probe_id"], rows[0]["binding_sha256"]), (probe["probe_id"], probe["binding_sha256"]))
        receipt = read_json(self.tmp / "out" / "judge_receipt.json")
        self.assertEqual((receipt["sent"], receipt["ok"], receipt["exit_code"]), (1, 1, 0))
        for name in ("judgments.jsonl", "judge_receipt.json", "judge_plan.json"):
            self.assertNotIn(FAKE_TOKEN, (self.tmp / "out" / name).read_text(encoding="utf-8"))

    def test_refuses_without_the_guard(self):
        with FakeJudgeUpstream() as fake:
            rc = self.run_judge(None)
        self.assertEqual(rc, 2)
        self.assertEqual(fake.requests, [])

    def test_plan_only_sends_nothing(self):
        with FakeJudgeUpstream() as fake:
            rc = self.run_judge(fake.base_url, "--plan-only")
        self.assertEqual((rc, fake.requests), (0, []))
        plan = read_json(self.tmp / "out" / "judge_plan.json")
        self.assertEqual(plan["to_send"], 1)
        self.assertGreater(plan["estimate"]["prompt_tokens_bytes_over_4"], 0)

    def test_stops_when_the_guard_refuses(self):
        with FakeJudgeUpstream(status=402) as fake:
            rc = self.run_judge(fake.base_url)
        self.assertEqual(rc, 3)
        self.assertEqual(read_json(self.tmp / "out" / "judge_receipt.json")["stop_reason"],
                         "guard or provider refused with HTTP 402")

    def test_refuses_a_tampered_probe(self):
        probe = read_jsonl(self.probes)[0]
        probe["context_b"][0]["content"] = "changed"
        self.probes.write_text(json.dumps(probe) + "\n", encoding="utf-8")
        with FakeJudgeUpstream() as fake:
            rc = self.run_judge(fake.base_url)
        self.assertEqual((rc, fake.requests), (2, []))

    def test_through_an_in_process_budget_guard(self):
        # The real guard (no run-stage, so no lock file in common/) in front of the loopback fake.
        import sys
        from decimal import Decimal
        sys.path.insert(0, str(COMMON))
        import deepseek_route as dr
        with FakeJudgeUpstream() as fake:
            guard = dr.BudgetGuard(dr.GuardConfig(
                stage_id="reference/NTJ-S1-test", ledger_path=self.tmp / "ledger.jsonl", cap_usd=Decimal("0.10"),
                cap_tokens=400000, cap_requests=12, upstream_base_url=fake.base_url, api_key="sk-fake-0123456789",
                client_token=FAKE_TOKEN, max_tokens_default=1024, max_tokens_ceiling=1024))
            with guard:  # __enter__ starts the loopback proxy
                rc = self.run_judge(guard.base_url)
            summary = guard.summary()
        self.assertEqual(rc, 0)
        upstream = fake.requests[0]
        self.assertEqual(upstream["max_tokens"], 1024)
        self.assertNotIn("max_completion_tokens", upstream)
        self.assertEqual(upstream["thinking"], {"type": "disabled"})
        self.assertEqual(upstream["response_format"], {"type": "json_object"})
        self.assertEqual(fake.auth_headers, ["Bearer sk-fake-0123456789"])
        self.assertEqual(summary["requests_forwarded"], 1)
        ledger = (self.tmp / "ledger.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("Neutral reference information", ledger)  # ids and usage only
        self.assertEqual(read_jsonl(self.tmp / "out" / "judgments.jsonl")[0]["http_status"], 200)

    def test_resume_skips_judged_probes(self):
        with FakeJudgeUpstream() as fake:
            self.run_judge(fake.base_url)
            first = self.tmp / "out"
            import neurotaint_judge
            with guarded_env(fake.base_url):
                rc = neurotaint_judge.main(["--probes", str(self.probes), "--out-dir", str(self.tmp / "out2"),
                                            "--resume-from", str(first)])
        self.assertEqual(rc, 0)
        self.assertEqual(len(fake.requests), 1)

    def test_resume_retries_errored_probes(self):
        import neurotaint_judge
        with FakeJudgeUpstream(status=500) as bad:
            self.run_judge(bad.base_url)
        rows = read_jsonl(self.tmp / "out" / "judgments.jsonl")
        self.assertEqual((len(rows), rows[0]["http_status"], rows[0]["raw_content"]), (1, 500, None))
        with FakeJudgeUpstream() as good:
            with guarded_env(good.base_url):
                rc = neurotaint_judge.main(["--probes", str(self.probes), "--out-dir", str(self.tmp / "out2"),
                                            "--resume-from", str(self.tmp / "out")])
        self.assertEqual((rc, len(good.requests)), (0, 1))  # the errored probe is sent again
        self.assertEqual(read_json(self.tmp / "out2" / "judge_plan.json")["skipped_as_done"], 0)

    def test_refuses_ss_and_inexact_probes_unless_overridden(self):
        import neurotaint_judge
        with FakeJudgeUpstream() as fake:
            with guarded_env(fake.base_url):
                rc = neurotaint_judge.main(["--probes", str(self.ss_probes), "--out-dir", str(self.tmp / "ss")])
            self.assertEqual((rc, fake.requests), (2, []))
            with guarded_env(fake.base_url):
                rc = neurotaint_judge.main(["--probes", str(self.ss_probes), "--out-dir", str(self.tmp / "ss2"),
                                            "--allow-ss", "--plan-only"])
            self.assertEqual((rc, fake.requests), (0, []))
        probe = read_jsonl(self.probes)[0]
        import neurotaint_offline as nt
        probe["prefix_exact"] = False
        probe["binding_sha256"] = nt._binding(probe)
        probe["probe_id"] = "ref-nt-probe-v1:" + probe["binding_sha256"]
        inexact = self.tmp / "inexact.jsonl"
        inexact.write_text(json.dumps(probe) + "\n", encoding="utf-8")
        with FakeJudgeUpstream() as fake:
            with guarded_env(fake.base_url):
                rc = neurotaint_judge.main(["--probes", str(inexact), "--out-dir", str(self.tmp / "inexact")])
        self.assertEqual((rc, fake.requests), (2, []))


class StageFileTests(unittest.TestCase):
    def test_route_stage_file_validates(self):
        import sys
        sys.path.insert(0, str(COMMON))
        import deepseek_route as dr
        config = read_json(STAGES)
        self.assertEqual(set(config["stages"]), {"NTJ-S1", "NTJ-S2"})
        for name in config["stages"]:
            stage, _ = dr.load_stage(STAGES, name)
            self.assertEqual(stage["_ignored_keys"], [])  # every key is a route key; nothing silently ignored
            self.assertGreater(stage["cap_usd"], 0)
            self.assertEqual(stage["max_tokens_ceiling"], 1024)
            self.assertIn("{artifact_python}", stage["argv"])
            self.assertIn("{probes}", stage["argv"])
            self.assertFalse(stage["dry_run_allowed"])

    def test_offline_stages_make_no_model_calls_and_have_no_caps(self):
        offline = read_json(OFFLINE)
        for name, stage in offline["stages"].items():
            self.assertEqual(stage["model_requests"], 0, name)
            self.assertFalse({k for k in stage if k.startswith("cap_")}, name)
            self.assertTrue((h.REF / stage["argv"][1]).is_file(), name)


if __name__ == "__main__":
    unittest.main()
