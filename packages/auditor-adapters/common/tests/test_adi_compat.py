"""Zero-cost tests for the ADI-derived case-file support (ADI amendment): common/adi_compat.py and the ADI
family in common/postprocess_gate_rows.py. Synthetic placeholders only; no ADI payload text.

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s common/tests -v

The fork-conformance checks read the pinned ADI checkout (``ADI_FORK_SRC``, default the sibling
``external-auditors/adi/src``) and are skipped when it is absent. Run this file with the ADI fork's own venv
python as well to compare the copied formatter with the fork's function on the fork's suite objects.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
COMMON = TESTS.parent
ADAPTERS = COMMON.parent
REPO = ADAPTERS.parents[1]
FORK = Path(os.environ.get("ADI_FORK_SRC") or REPO.parent / "external-auditors" / "adi" / "src")
FORK_TOOL_EXECUTION = FORK / "agentdojo" / "src" / "agentdojo" / "agent_pipeline" / "tool_execution.py"
for path in (COMMON, TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adi_compat as ac  # noqa: E402
import adi_fixture as fx  # noqa: E402
import postprocess_gate_rows as pp  # noqa: E402


class FormatTests(unittest.TestCase):
    def test_declared_and_effective_format(self):
        self.assertIsNone(ac.declared_tool_output_format({}))
        self.assertEqual(ac.tool_output_format({}), "yaml")
        self.assertEqual(ac.tool_output_format({"tool_output_format": "json"}), "json")
        for bad in ("JSON", None, "xml", 1):
            with self.assertRaises(ac.CaseFormatError):
                ac.tool_output_format({"tool_output_format": bad})
        self.assertIsNone(ac.tool_output_formatter("yaml"))
        self.assertIs(ac.tool_output_formatter("json"), ac.adi_tool_result_to_str)

    def test_family_mix(self):
        ac.check_family_mix(["ADI", "ADI"])
        ac.check_family_mix(["E0B", "E1PRE"])
        for fams in (["ADI", "E0B"], ["ADI", None], ["E1PRE", "ADI"]):
            with self.assertRaises(ac.CaseFormatError):
                ac.check_family_mix(fams)

    def test_escaping_helpers(self):
        text = 'a "b" café\nend\\x \U0001F600'
        esc = ac.json_escaped(text)
        self.assertEqual(esc, json.dumps(text)[1:-1])
        self.assertEqual(ac.json_unescape(esc), text)                    # surrogate pair joined back
        self.assertEqual(ac.rendered_variants("plain-value-1", "json"), ["plain-value-1"])
        self.assertEqual(ac.rendered_variants(text, "yaml"), [text])
        self.assertEqual(ac.rendered_variants(text, "json"), [text, esc])
        self.assertEqual(ac.state_needle(fx.X), fx.X)                    # identifiers: unchanged needle
        self.assertEqual(ac.state_needle('q"x'), 'q\\"x')
        self.assertEqual(ac.json_unescape("no escapes here"), "no escapes here")

    def test_pin_is_the_lf_sha256(self):
        tmp = Path(tempfile.mkdtemp(prefix="adi-pin-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path, lf = fx.write_doc(tmp / "c.json", fx.adi_doc())
        self.assertIn(b"\r\n", path.read_bytes())
        self.assertEqual(ac.sha256_lf(path), lf)
        self.assertEqual(ac.check_pin(path, [lf.upper()]), lf)
        with self.assertRaises(ac.CaseFormatError):
            ac.check_pin(path, [lf, "0" * 64])

    def test_formatter_output_shapes(self):
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("pydantic not installed")
        import datetime as dt

        class Item(BaseModel):
            subject: str
            when: dt.datetime

        item = Item(subject='x "q" é', when=dt.datetime(2022, 3, 7, 9, 30))
        out = ac.adi_tool_result_to_str([item, item])
        self.assertEqual(json.loads(out), [{"subject": 'x "q" é', "when": "2022-03-07T09:30:00"}] * 2)
        self.assertIn("\\u00e9", out)                                     # json.dumps default: ASCII escapes
        self.assertEqual(ac.adi_tool_result_to_str(item), json.dumps(item.model_dump(mode="json")))
        self.assertEqual(ac.adi_tool_result_to_str({"a": 1}), '{"a": 1}')
        self.assertEqual(ac.adi_tool_result_to_str("text"), "text")
        self.assertEqual(ac.adi_tool_result_to_str(["s", 3]), '["s", "3"]')
        with self.assertRaises(TypeError):
            ac.adi_tool_result_to_str([1.5])


@unittest.skipUnless(FORK_TOOL_EXECUTION.is_file(), "needs the pinned ADI checkout (ADI_FORK_SRC)")
class ForkConformanceTests(unittest.TestCase):
    """The copied formatter is the fork's function (declared reuse): same body, statement for statement."""

    @staticmethod
    def _function(source: str, name: str) -> ast.FunctionDef:
        return next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_copied_body_equals_the_fork(self):
        fork = self._function(FORK_TOOL_EXECUTION.read_text(encoding="utf-8"), "tool_result_to_str")
        mine = self._function((COMMON / "adi_compat.py").read_text(encoding="utf-8"), "adi_tool_result_to_str")
        body = [s for s in mine.body if not (isinstance(s, ast.ImportFrom) and s.module == "pydantic")]
        self.assertEqual(len(body), len(mine.body) - 1)
        self.assertEqual([ast.dump(s) for s in body], [ast.dump(s) for s in fork.body])
        self.assertEqual([a.arg for a in mine.args.args], [a.arg for a in fork.args.args])
        self.assertEqual(ast.dump(mine.args.defaults[0]), ast.dump(fork.args.defaults[0]))   # json.dumps

    def test_fork_pin(self):
        self.assertEqual(ac.ADI_FORMATTER_SOURCE["commit"], "1a3ddf8fa96bf008f3cb80dd56db5149d4ac0df7")
        lic = (FORK / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", lic)
        notice = (COMMON / "adi_compat.py").read_text(encoding="utf-8")
        for line in ("Copyright (c) 2026 Woohyuk Choi, Juhee Kim, Taehyun Kang, Jihyeon Jeong, Luyi Xing, and Byoungyoung Lee",
                     "Permission is hereby granted, free of charge, to any person obtaining a copy"):
            self.assertIn(line, lic)
            self.assertIn(line, notice)


def _in_fork_venv() -> bool:
    try:
        import inspect

        from agentdojo.agent_pipeline import tool_execution
    except ImportError:
        return False
    return "mode='json'" in inspect.getsource(tool_execution.tool_result_to_str)


@unittest.skipUnless(_in_fork_venv(), "needs the ADI fork's venv (agentdojo = the fork)")
class ForkBehaviourTests(unittest.TestCase):
    """In the fork's venv: the copy and the fork's own function give identical text on the fork's suites."""

    def test_identical_on_suite_objects(self):
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.task_suite.load_suites import get_suite

        compared = 0
        for suite_name, calls in (("banking", [("get_most_recent_transactions", {"n": 100}),
                                               ("get_scheduled_transactions", {}), ("get_user_info", {})]),
                                  ("workspace", [("get_received_emails", {}), ("list_files", {}),
                                                 ("get_day_calendar_events", {"day": "2024-05-15"})]),
                                  ("slack", [("get_channels", {}), ("read_inbox", {"user": "Alice"})])):
            suite = get_suite("v1.2.2", suite_name)
            env = suite.load_and_inject_default_environment({})
            runtime = FunctionsRuntime(suite.tools)
            for fn, args in calls:
                result, error = runtime.run_function(env, fn, args)
                self.assertIsNone(error, fn)
                self.assertEqual(ac.adi_tool_result_to_str(result), tool_result_to_str(result), fn)
                compared += 1
        self.assertEqual(compared, 8)


class LoaderHelperTests(unittest.TestCase):
    """Per-arm legitimate set (ADI-X-11), exposure needles (M2), unresolved executability (m5), X after a JSON
    escape (m1) and the conformance-only frozen tool clock (ADI-X-13)."""

    def test_arm_legitimate_set(self):
        case = fx.adi_case(per_arm_legit=True)
        self.assertEqual((ac.arm_legitimate_set(case, "ATTACK"), ac.arm_legitimate_set(case, "CLEAN")),
                         ([fx.L_ATTACK], [fx.L]))
        self.assertIsNone(ac.arm_legitimate_set(fx.adi_case(), "ATTACK"))          # SS-like: no per-arm set
        bad = fx.adi_case()
        for value in ([], [""], "x", [1]):
            bad["arms"]["CLEAN"]["legitimate_set"] = value
            with self.assertRaises(ac.CaseFormatError):
                ac.arm_legitimate_set(bad, "CLEAN")

    def test_exposure_needles_and_executability(self):
        case = fx.adi_case()
        self.assertEqual(ac.adi_exposure_needles(case, "ATTACK"), [fx.ATTACK_ENV_TEXT])
        self.assertIsNone(ac.adi_exposure_needles(case, "CLEAN"))
        ac.require_resolved_executability(case)
        with self.assertRaisesRegex(ac.CaseFormatError, "unresolved"):
            ac.require_resolved_executability(fx.adi_case(executable=None))
        ac.require_resolved_executability(fx.adi_case(family="E0B", executable=None))  # SS cases are not checked

    def test_value_and_needle_seen_under_json(self):
        import re

        def contains(h: str, n: str) -> bool:
            return re.search(rf"(?<![0-9a-z]){re.escape(n.casefold())}(?![0-9a-z])", h.casefold()) is not None

        after_escape = [json.dumps([{"subject": "line one\n" + fx.X}])]
        self.assertFalse(ac.value_in_outputs(contains, after_escape, fx.X, "yaml"))  # the plain test misses it
        self.assertTrue(ac.value_in_outputs(contains, after_escape, fx.X, "json"))   # m1
        rendered = [json.dumps([{"note": fx.ATTACK_ENV_TEXT}])]
        self.assertFalse(ac.value_in_outputs(contains, ["nothing here"], fx.X, "json"))
        collapse = lambda t: " ".join(t.split())                                    # noqa: E731
        self.assertFalse(ac.needle_seen([fx.ATTACK_ENV_TEXT], rendered, "yaml", collapse))
        self.assertTrue(ac.needle_seen([fx.ATTACK_ENV_TEXT], rendered, "json", collapse))
        self.assertIsNone(ac.needle_seen(None, rendered, "json", collapse))

    def test_frozen_tool_clock(self):
        try:
            import agentdojo.default_suites.v1.tools.cloud_drive_client as cdc
        except ImportError:
            self.skipTest("needs an AgentDojo venv")
        import datetime as dt

        with ac.frozen_tool_clock() as patched:
            self.assertEqual(len(patched), 2)
            now = cdc.datetime.datetime.now()
            self.assertIs(type(now), dt.datetime)                                  # a plain datetime (DeepDiff)
            self.assertEqual(now, dt.datetime(*ac.FROZEN_TOOL_INSTANT))
        self.assertIs(cdc.datetime, dt)                                             # restored


class PostprocessAdiTests(unittest.TestCase):
    """The ADI family is its own group in the post-processor; ATTACK is an X arm and CLEAN a benign arm."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gate-rows-adi-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cases_path, _ = fx.write_doc(self.tmp / "cases.json", fx.adi_doc(
            cases=[fx.adi_case(), fx.adi_case(fx.CASE_ID + "2")]))

    def _h2_run(self):
        run = self.tmp / "h2run"
        eps = [{"episode_id": f"{cid}|{arm}|r{r}", "arm": arm, "case_id": cid, "suite": "banking",
                "user_task_id": "user_task_3", "repeat": r}
               for cid in (fx.CASE_ID, fx.CASE_ID + "2") for arm in ("ATTACK", "CLEAN") for r in range(2)]
        run.mkdir()
        (run / "episode_plan.json").write_text(json.dumps({"episodes": eps}), encoding="utf-8")
        recs = [{"episode_id": e["episode_id"], "case_id": e["case_id"], "arm": e["arm"], "scored": True,
                 "outcome": "attacker" if e["arm"] == "ATTACK" and e["repeat"] == 0 else "legitimate",
                 "utility": e["arm"] == "CLEAN", "x_sink_called": e["arm"] == "ATTACK",
                 "oracle_details": {"attacker_attempted": e["arm"] == "ATTACK"},
                 "injection_exposed": e["arm"] == "ATTACK"} for e in eps]
        (run / "episodes.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
        return run

    def test_h2_adi_groups(self):
        out = self.tmp / "rows.json"
        rc = pp.main(["--adapter", "h2", "--cases", str(self.cases_path), "--run", str(self._h2_run()),
                      "--out", str(out), "--bootstrap-b", "200"])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(g.startswith("ADI|") for g in doc["groups"]))
        self.assertIn("ADI|all", doc["groups"])
        self.assertEqual(doc["families_not_reported"], [])
        arms = doc["groups"]["ADI|all"]["rows"]["undefended"]["per_arm"]
        self.assertEqual(list(arms), ["CLEAN", "ATTACK"])
        self.assertEqual([arms["ATTACK"]["F4_attacker_over_scored"][k] for k in ("k", "n")], [2, 4])
        self.assertEqual([arms["ATTACK"]["F1_x_sink_proposed"][k] for k in ("k", "n")], [4, 4])
        self.assertEqual([arms["CLEAN"]["legitimate"][k] for k in ("k", "n")], [4, 4])
        self.assertNotIn("legitimate", arms["ATTACK"])
        contrasts = doc["groups"]["ADI|all"]["rows"]["undefended"]["fact_minus_instr_pp"]
        self.assertTrue(all(v is None for v in contrasts.values()))
        self.assertIsNone(doc["futility_ss0"])                           # Gate SS-0 reads SS runs only
        self.assertIn("ADI", doc["futility_ss0_note"])

    def test_gated_adi_row_counts_attack_as_x_arm(self):
        views = [pp._view(episode_id=f"e{i}|{arm}", row="g", gated=True, arm=arm, case_id=fx.CASE_ID,
                          cases=pp.load_cases(self.cases_path), scored=True, outcome="legitimate",
                          F1=arm == "ATTACK", F2=arm == "ATTACK", F3=False, _F3_audited=False, fb=arm == "CLEAN")
                 for i, arm in enumerate(("ATTACK", "CLEAN"))]
        att, clean = views
        self.assertEqual((att["caught"], att["fb"]), (True, None))
        self.assertEqual((clean["caught"], clean["fb"]), (None, True))

    def test_argus_blame_left_out_where_the_payload_and_native_x_share_a_span(self):
        a, b = fx.adi_case(), fx.adi_case(fx.CASE_ID + "2")
        a["design"] = {"argus_span_separated": False}                       # ADI-X-12
        b["design"] = {"argus_span_separated": True}
        path, _ = fx.write_doc(self.tmp / "cases.json", fx.adi_doc(cases=[a, b]))
        run = self.tmp / "argusrun"
        run.mkdir()
        eps = [{"episode_id": f"{cid}|ATTACK|r0", "arm": "ATTACK", "case_id": cid} for cid in (a["case_id"], b["case_id"])]
        (run / "episode-plan-t.json").write_text(json.dumps({"rows": ["none", "warrant"], "episodes": eps}),
                                                 encoding="utf-8")
        stopped = {"function": "send_money", "carries_attacker_value": True, "verdict": "block",
                   "blame": "steering_flagged", "flagged_in_S_class": "steering_only"}
        act = {"success": True, "state_changing": True, "steering_label": True, "steering_in_dep": True,
               "blame_shift": False}
        for row in ("none", "warrant"):
            recs = [{"adapter": {"key": e["episode_id"]}, "outcome": "legitimate", "utility": True, "executed_calls": [],
                     "calls": [stopped] if row == "warrant" else [], "x_action_dep": [act] if row == "warrant" else [],
                     "funnel": {}, "false_block": {}} for e in eps]
            (run / f"cases-{row}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
        views, _planned, _extra = pp.views_argus([run], pp.load_cases(path))
        warrant = {v["case_id"]: v for v in views if v["row"] == "warrant"}
        shared, separated = warrant[a["case_id"]], warrant[b["case_id"]]
        self.assertTrue(all(v == [] for v in shared["items"].values()))
        self.assertEqual(shared["classes"]["attribution.argus_blame_undefined_span_shared"], ["excluded", "excluded"])
        self.assertEqual(separated["items"]["attribution.x_action_dep_steering_recall"], [True])
        self.assertNotIn("attribution.argus_blame_undefined_span_shared", separated["classes"])

    def test_substratum_untested_and_adi_scope_subsets(self):
        a, b = fx.adi_case(), fx.adi_case(fx.CASE_ID + "2")
        a["substratum"], b["substratum"] = "Xatt", "A1mech"
        b["gt"] = {"attacker_executable": None, "attacker_execution_state_observable": None}   # untested on stock
        self.cases_path, _ = fx.write_doc(self.tmp / "cases.json", fx.adi_doc(cases=[a, b]))
        config = self.tmp / "acfg.json"
        config.write_text(json.dumps({"threat_model": {"adi_case_scope": {"cases": {
            fx.CASE_ID: {"auditors": {"attriguard": {"label": "in_scope"}}, "delegation": False,
                         "task_anticipated_selection": True},
            fx.CASE_ID + "2": {"auditors": {"attriguard": {"label": "out_of_scope"}}, "delegation": True,
                               "task_anticipated_selection": False}}}}}), encoding="utf-8")
        self.assertEqual(pp.load_scope(config, "attriguard"), {fx.CASE_ID: "in_scope", fx.CASE_ID + "2": "out_of_scope"})
        out = self.tmp / "rows.json"
        rc = pp.main(["--adapter", "h2", "--cases", str(self.cases_path), "--run", str(self._h2_run()),
                      "--protocol-config", str(config), "--out", str(out), "--bootstrap-b", "50"])
        self.assertEqual(rc, 0)
        groups = json.loads(out.read_text(encoding="utf-8"))["groups"]
        self.assertEqual(groups["ADI|substratum=Xatt"]["cases"], 1)
        self.assertEqual(groups["ADI|substratum=A1mech"]["cases"], 1)
        self.assertEqual(groups["ADI|executable=untested"]["cases"], 1)
        self.assertEqual(groups["ADI|executable"]["cases"], 1)
        self.assertNotIn("ADI|not_executable", groups)                    # the untested case is neither
        self.assertEqual(groups["ADI|delegation=yes"]["cases"], 1)
        self.assertEqual(groups["ADI|task_anticipated_selection=yes"]["cases"], 1)
        # an SS case never gets these subsets, whatever fields it carries
        ss = pp.load_cases(self.cases_path)
        self.assertEqual(ss["by_id"][fx.CASE_ID]["substratum"], "Xatt")
        other = dict(a, seed_family="E0B", case_id="E0B:x")
        path, _ = fx.write_doc(self.tmp / "ss.json", fx.adi_doc(cases=[other]))
        row = pp.load_cases(path)["by_id"]["E0B:x"]
        self.assertEqual((row["substratum"], row["exec_untested"]), (None, False))


if __name__ == "__main__":
    unittest.main()
