"""Zero-cost tests for the reference rows on an ADI-derived case file (ADI amendment; lab venv).

Synthetic placeholder payload only (``common/tests/adi_fixture.py``; no ADI payload text). Ground truth and a
scripted loopback fake only; no model.

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s reference/tests -v
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import helpers as h  # noqa: E402,F401  (puts reference/ on sys.path)

TESTS = Path(__file__).resolve().parent
ADAPTERS = TESTS.parents[1]
for _p in (ADAPTERS / "common", ADAPTERS / "common" / "tests", ADAPTERS / "h2", ADAPTERS / "h2" / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import adi_fixture as fx  # noqa: E402

try:
    import agentdojo  # noqa: F401
    from ref_common import LAB
    IN_LAB = Path(agentdojo.__file__).resolve().is_relative_to(LAB)
except ImportError:
    IN_LAB = False


@unittest.skipUnless(IN_LAB, "needs the agentdojo-lab venv with the vendored AgentDojo")
class AdiReferenceTests(unittest.TestCase):
    def test_spec_carries_the_adi_stratum_and_format(self):
        import ref_trace as rt
        spec = rt.case_arm_spec(fx.adi_doc("json"), fx.CASE_ID, "ATTACK")
        self.assertEqual((spec["design"]["stratum"], spec["tool_output_format"], spec["seed_family"]),
                         ("ADI", "json", "ADI"))
        self.assertEqual(spec["design"]["steering_texts"], [fx.ATTACK_ENV_TEXT])
        plain = fx.adi_case(family="E0B")
        plain.pop("stratum")
        ss = rt.case_arm_spec(fx.adi_doc(None, cases=[plain]), fx.CASE_ID, "CLEAN")
        self.assertEqual(ss["design"]["stratum"], "SS")                      # unchanged default
        self.assertNotIn("tool_output_format", ss)
        with tempfile.TemporaryDirectory() as tmp:
            bad, _ = fx.write_doc(Path(tmp) / "bad.json", dict(fx.adi_doc(), tool_output_format="xml"))
            from ref_common import ReferenceError
            with self.assertRaises(ReferenceError):
                rt.load_case_file(bad)

    def test_spec_reads_the_per_arm_legitimate_set(self):
        import ref_trace as rt
        doc = fx.adi_doc("json", cases=[fx.adi_case(per_arm_legit=True)])
        self.assertEqual(rt.case_arm_spec(doc, fx.CASE_ID, "ATTACK")["oracle"]["legitimate_set"], [fx.L_ATTACK])
        self.assertEqual(rt.case_arm_spec(doc, fx.CASE_ID, "CLEAN")["oracle"]["legitimate_set"], [fx.L])
        self.assertEqual(rt.case_arm_spec(fx.adi_doc("json"), fx.CASE_ID, "ATTACK")["oracle"]["legitimate_set"], [fx.L])

    def test_scripted_traces_render_json_and_score_both_arms(self):
        import native_replay as nr
        import ref_trace as rt
        import run_reference
        doc = fx.adi_doc("json")
        attack, clean = (rt.case_arm_spec(doc, fx.CASE_ID, arm) for arm in ("ATTACK", "CLEAN"))
        sub, changed = nr.substitute_attacker(attack, nr.ground_truth_calls(attack))
        self.assertTrue(changed)
        trace, facts = nr.scripted_trace(attack, sub, trace_id="adi-x")
        self.assertTrue(facts["post_state_adds_attacker"])
        tool_texts = [m["text"] for m in trace["messages"] if m["role"] == "tool"]
        self.assertEqual(fx.transactions_rendering(tool_texts), "json")
        self.assertTrue(any(json.dumps(fx.ATTACK_ENV_TEXT)[1:-1] in t for t in tool_texts))
        self.assertEqual(run_reference.undefended_outcome(trace, attack, nr.replay_post_state)["outcome"], "attacker")
        ctrace, cfacts = nr.scripted_trace(clean, nr.ground_truth_calls(clean), trace_id="adi-l")
        self.assertTrue(cfacts["utility"])
        self.assertEqual(run_reference.undefended_outcome(ctrace, clean, nr.replay_post_state)["outcome"], "legitimate")
        # the same spec without a declared format renders the stock YAML (SS behaviour)
        ytrace, _ = nr.scripted_trace(rt.case_arm_spec(fx.adi_doc(None), fx.CASE_ID, "CLEAN"),
                                      nr.ground_truth_calls(clean), trace_id="adi-y")
        self.assertEqual(fx.transactions_rendering([m["text"] for m in ytrace["messages"] if m["role"] == "tool"]),
                         "yaml")

    def test_reference_rows_on_a_real_h2_adi_run(self):
        import run_reference
        import test_h2_adi as th
        from ref_common import read_json, read_jsonl

        t = th.AdiAdapterTests("test_json_format_reaches_the_agent_and_the_oracle_scores_attack_and_clean")
        t.setUp()
        self.addCleanup(t.doCleanups)
        run = t.tmp / "adi-run"
        rc, _bodies, cases, _lf = t._run(fx.adi_doc("json"), run)
        self.assertEqual(rc, 0)
        out = t.tmp / "ref-out"
        rc = run_reference.main(["--case-file", str(cases), "--h2-run", str(run), "--out-dir", str(out),
                                 "--auditors", "origin,join,neurotaint"])
        self.assertEqual(rc, 0)
        eps = {e["arm"]: e for e in read_jsonl(out / "episodes.jsonl")}
        self.assertEqual(set(eps), {"ATTACK", "CLEAN"})
        self.assertEqual({e["stratum"] for e in eps.values()}, {"ADI"})
        self.assertEqual((eps["ATTACK"]["undefended"]["outcome"], eps["CLEAN"]["undefended"]["outcome"]),
                         ("attacker", "legitimate"))
        summary = read_json(out / "summary.json")
        self.assertEqual(summary["stimulus_binding"]["h2_episodes_verified"], 2)
        common = ADAPTERS / "common"
        if str(common) not in sys.path:
            sys.path.insert(0, str(common))
        import postprocess_gate_rows as pp
        dest = t.tmp / "gate_rows.json"
        self.assertEqual(pp.main(["--adapter", "reference", "--cases", str(cases), "--run", str(out), "--out",
                                  str(dest), "--bootstrap-b", "50"]), 0)
        doc = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(sorted({g.split("|")[0] for g in doc["groups"]}), ["ADI"])
        und = doc["groups"]["ADI|all"]["rows"]["undefended"]["per_arm"]
        self.assertEqual([und["ATTACK"]["F4_attacker_over_scored"][k] for k in ("k", "n")], [1, 1])
        self.assertIn("adi_family", doc["definitions"])


if __name__ == "__main__":
    unittest.main()
