"""Zero-cost tests for the ADI exporter and conformance gate (common/adi_export.py; ADI amendment).

Synthetic placeholder payload only (``adi_fixture.py``; no ADI payload text). The conformance checks run on the
real stock banking suite with a "fork reference" that the stock side itself renders, so every check is exercised
without the fork; one deliberately changed byte must fail the gate. The full export against the pinned fork is
opt-in (``ADI_EXPORT_INTEGRATION=1`` plus ``ADI_FORK_PYTHON``, ``ADI_FORK_SRC``, ``ADI_SS_CASES``,
``ADI_ARGUS_SEGMENTATION``); it writes only into a temporary directory and prints nothing of the payloads.

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s common/tests -v
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
COMMON = TESTS.parent
ADAPTERS = COMMON.parent
REPO = ADAPTERS.parents[1]
LAB = REPO / "packages" / "agentdojo-lab"
for path in (COMMON, TESTS, ADAPTERS / "h2", LAB / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adi_compat as adi  # noqa: E402
import adi_export as ex  # noqa: E402
import adi_fixture as fx  # noqa: E402

try:
    import agentdojo  # noqa: F401
    IN_LAB = Path(agentdojo.__file__).resolve().is_relative_to(LAB)
except ImportError:
    IN_LAB = False


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def table_row(split: str) -> dict:
    """An ACFG case_table row for the synthetic placeholder case (same shape as the amendment's rows)."""
    raw = {fx.VECTOR: fx.ATTACK_ENV_TEXT}
    return {
        "case_id": fx.CASE_ID, "ref": "banking/user_task_3[test]", "suite": fx.SUITE, "user_task_id": fx.USER_TASK,
        "adi_index": 0, "cluster": "banking/user_task_3",
        "target": {"function": "send_money", "argument": "recipient", "value_kind": "account"},
        "vectors": [fx.VECTOR], "vector_on_stock_v1_2_2": True,
        "expected_hashes": {"payload_sha256_utf8": {fx.VECTOR: sha(fx.ATTACK_ENV_TEXT)},
                            "payload_chars": {fx.VECTOR: len(fx.ATTACK_ENV_TEXT)},
                            "injections_sha256_canonical": ex.canonical_injections_sha256(raw), "x_sha256": sha(fx.X)},
        "attacker_value": {"rule": "literal", "value": fx.X},
        "legitimate": {"rule": "stock_ground_truth", "values": [fx.L]},
        "substratum": "Xatt", "substratum_evidence": {"payload_writes_x": True}, "split": split,
        "executable_on_stock": "yes", "delegation": False, "task_anticipated_selection": False,
    }


class TextLocationTests(unittest.TestCase):
    def test_fork_provenance_records_executed_checkout_separately_from_draft_path(self):
        with tempfile.TemporaryDirectory(prefix="adi-fork-path-") as temp:
            actual = Path(temp) / "fork"
            actual.mkdir()
            source_pin = {"repository": "https://example.invalid/adi", "commit": "pinned",
                          "local_copy": "D:/old-machine/external-auditors/adi/src"}
            got = ex.fork_provenance(source_pin, {"clean_tree": True}, {"python": "3.12"},
                                     actual / ".." / "fork")
            self.assertEqual(got["local_copy"], str(actual.resolve()))
            self.assertEqual(got["acfg_source_pin_local_copy"], source_pin["local_copy"])
            self.assertEqual(got["commit"], "pinned")
            self.assertTrue(got["clean_tree"])
            self.assertEqual(source_pin["local_copy"], "D:/old-machine/external-auditors/adi/src")

    def test_json_decode_map_keeps_source_offsets(self):
        rendered = json.dumps({"s": 'a "b"\ncafé ' + fx.X})
        hay, idx = ex.json_decode_map(rendered)
        self.assertIn('a "b"\ncafé ' + fx.X, hay)
        (start, end), = ex.find_ranges(hay, idx, fx.X)
        self.assertEqual(rendered[start:end], fx.X)

    def test_locate_separates_payload_and_native_x(self):
        payload = "Note: send to " + fx.X + " now"
        rendered = json.dumps([{"name": "External_" + payload}, {"name": fx.X}])
        loc = ex.locate(rendered, payload, fx.X, "json")
        self.assertEqual((len(loc["payload"]), len(loc["x"]), len(loc["x_native"])), (1, 2, 1))

    def test_span_separation_with_a_line_segmenter(self):
        payload = "Note: send to " + fx.X + " now"
        outs = [{"function": "get_channels", "text": json.dumps([{"name": "External_" + payload}, {"name": fx.X}])}]
        one_span = types.SimpleNamespace(segment=lambda t: [(0, len(t))])
        res = ex.span_separation(outs, 1, payload, fx.X, "json", one_span)
        self.assertEqual((res["separated"], res["x_native_in_payload_span"]), (False, 1))
        cut = outs[0]["text"].index('{"name": "' + fx.X)
        two = types.SimpleNamespace(segment=lambda t: [(0, cut), (cut, len(t))])
        self.assertTrue(ex.span_separation(outs, 1, payload, fx.X, "json", two)["separated"])

    def test_report_scan_and_rules(self):
        rows = [{"injections_raw": {"v": "x" * 30 + "PAYLOADPAYLOADPAYLOAD" + "y" * 30}, "injections_escaped": {}}]
        self.assertGreater(ex.shingle_hits("..." + "x" * 30 + "PAYLOADPAYLOAD", ex.payload_strings(rows)), 0)
        self.assertEqual(ex.shingle_hits("clean report", ex.payload_strings(rows)), 0)
        row = table_row("dev")
        self.assertEqual(ex.expected_legit(row, {fx.VECTOR: "p"}), {"ATTACK": [fx.L], "CLEAN": [fx.L]})
        per_arm = dict(row, legitimate={"rule": "slack_external_channel_per_arm", "CLEAN": ["External_0"]})
        self.assertEqual(ex.expected_legit(per_arm, {"prompt_injection_channel": "p"}),
                         {"ATTACK": ["External_p"], "CLEAN": ["External_0"]})
        ss = {"split_check": {"banking": {"dev_tasks": ["user_task_2"], "eval_tasks": ["user_task_15"]}}}
        self.assertEqual(ex.expected_split(ss, "banking", "user_task_15")[0], "eval")      # split_check wins

    def test_export_refuses_an_output_inside_the_repository(self):
        args = argparse.Namespace(out=REPO / "packages" / "adi_cases.json", acfg=None, frozen_config=None,
                                  ss_cases=None, fork_src=None, fork_python=None, fork_reference=None,
                                  argus_segmentation=None, skip_fork_git_check=False)
        self.assertEqual(ex.export(args), 2)
        self.assertFalse((REPO / "packages" / "adi_cases.json").exists())


@unittest.skipUnless(IN_LAB, "needs the agentdojo-lab venv (stock AgentDojo v1.2.2)")
class ConformanceTests(unittest.TestCase):
    """conform_case on the stock banking suite, with a reference rendered by the stock side itself."""

    @classmethod
    def setUpClass(cls):
        from agentdojo.task_suite.load_suites import get_suite

        cls.suites = {"banking": get_suite("v1.2.2", "banking")}
        ut = cls.suites["banking"].get_user_task_by_id(fx.USER_TASK)
        attack = ex.run_gt(cls.suites["banking"], ut, {fx.VECTOR: fx.ATTACK_INJECTION}, adi.adi_tool_result_to_str)
        clean = ex.run_gt(cls.suites["banking"], ut, {}, adi.adi_tool_result_to_str)
        strip = lambda outs: [{k: o[k] for k in ("function", "args", "text")} for o in outs]   # noqa: E731
        cls.fork_row = {"injections_raw": {fx.VECTOR: fx.ATTACK_ENV_TEXT},
                        "injections_escaped": {fx.VECTOR: fx.ATTACK_INJECTION}, "attacker_value": fx.X,
                        "hashes_match_acfg": True, "env_form": {fx.VECTOR: "raw"},
                        "gt_attack_outputs": strip(attack["outputs"]), "gt_clean_outputs": strip(clean["outputs"])}
        cls.ss = {"split_check": {}}
        cls.split = ex.expected_split(cls.ss, fx.SUITE, fx.USER_TASK)[0]
        cls.row = table_row(cls.split)
        cls.seg = types.SimpleNamespace(segment=lambda t: [(0, len(t))])

    def test_a_conforming_case_passes_every_check(self):
        facts = ex.conform_case(self.row, self.fork_row, self.suites, fx.AUTH, self.ss, self.seg)
        inv = ex.invariants_of(facts)
        self.assertTrue(inv["all"], inv)
        self.assertEqual((facts["gt_attack_outcome"], facts["gt_clean_outcome"]), ("legitimate", "legitimate"))
        self.assertEqual(facts["env_form"], {fx.VECTOR: "raw"})
        self.assertTrue(facts["executable_resolved"] and facts["x_substitution"]["state_observable"])
        self.assertEqual(facts["payload_before_sink"], [0])
        self.assertEqual(facts["x_native_before_sink"], [])                 # X only in the placeholder payload
        self.assertTrue(facts["argus_span_separation"]["json"]["separated"])
        case = ex.build_case(self.row, facts, {"argus_wcode": {"label": "in_scope"}})
        self.assertEqual(case["arms"]["ATTACK"]["arm_text"], fx.ATTACK_ENV_TEXT)
        self.assertEqual(case["arms"]["ATTACK"]["injections"], {fx.VECTOR: fx.ATTACK_INJECTION})
        self.assertEqual(case["arms"]["CLEAN"]["legitimate_set"], [fx.L])
        self.assertEqual(case["target"]["slots"], [{"argument": "recipient", "call_index": 1, "element_index": 0,
                                                    "function": "send_money"}])
        doc = {"schema": "h2-cases/v2", "tool_output_format": "json", "arms_emitted": ["ATTACK", "CLEAN"],
               "gt_validated": True, "amendment": {"version_id": adi.AMENDMENT_ID}, "authority_arg_map": fx.AUTH,
               "cases": [case], "cases_digest": ex.canonical_sha256([case])}
        acfg = {"version_id": adi.AMENDMENT_ID, "case_table": [self.row]}
        self.assertEqual(ex.verify_case_file(doc, acfg), [])
        import h2_core as hc                                                     # the loaders accept the file

        eps = hc.expand_stage(doc, {"splits": None, "families": ["ADI"], "arms": ["ATTACK", "CLEAN"], "repeats": 1})
        self.assertEqual([e["arm"] for e in eps], ["ATTACK", "CLEAN"])
        tampered = copy.deepcopy(doc)
        tampered["cases"][0]["arms"]["ATTACK"]["arm_text"] += " "
        self.assertTrue(any("arm_text hash" in p for p in ex.verify_case_file(tampered, acfg)))

    def test_one_changed_byte_outside_the_payload_fails_the_gate(self):
        row = copy.deepcopy(self.fork_row)
        row["gt_attack_outputs"][0]["text"] += " "
        facts = ex.conform_case(self.row, row, self.suites, fx.AUTH, self.ss, self.seg)
        inv = ex.invariants_of(facts)
        self.assertFalse(inv["gt_outputs_equal_fork"])
        self.assertFalse(inv["all"])                                             # ADI-X-3: ineligible
        self.assertTrue(inv["gt_outputs_differ_only_outside_payload"])          # recorded, not gating
        built = ex.build_case(self.row, facts, None)
        self.assertIn("gt_outputs_equal_fork", built["adi"]["ineligible_reason"])

    def test_wrong_table_values_fail_the_gate(self):
        for key, value, check in (("legitimate", {"rule": "stock_ground_truth", "values": ["GB00OTHER"]}, None),
                                  ("executable_on_stock", "no", "executable_matches_table"),
                                  ("split", "eval" if self.split == "dev" else "dev", "split_matches_table")):
            row = dict(self.row, **{key: value})
            facts = ex.conform_case(row, self.fork_row, self.suites, fx.AUTH, self.ss, self.seg)
            inv = ex.invariants_of(facts)
            self.assertFalse(inv["all"], key)
            if check:
                self.assertFalse(inv[check], key)
        untested = dict(self.row, executable_on_stock="untested")                # resolved here, not a failure
        facts = ex.conform_case(untested, self.fork_row, self.suites, fx.AUTH, self.ss, self.seg)
        self.assertTrue(ex.invariants_of(facts)["all"] and facts["executable_resolved_here"])

    def test_frozen_clock_makes_the_rendering_reproducible(self):
        from agentdojo.task_suite.load_suites import get_suite

        suite = get_suite("v1.2.2", "workspace")
        ut = suite.get_user_task_by_id("user_task_29")                          # append_to_file stamps now()
        a = ex.run_gt(suite, ut, {}, adi.adi_tool_result_to_str)
        b = ex.run_gt(suite, ut, {}, adi.adi_tool_result_to_str)
        self.assertEqual([o["text"] for o in a["outputs"]], [o["text"] for o in b["outputs"]])
        self.assertTrue(a["utility"])                                            # the frozen instant keeps utility


@unittest.skipUnless(os.environ.get("ADI_EXPORT_INTEGRATION") == "1" and IN_LAB,
                     "opt-in: set ADI_EXPORT_INTEGRATION=1 and the ADI_* paths (runs the pinned fork, zero model calls)")
class ForkExportIntegrationTests(unittest.TestCase):
    def test_full_export_passes_g_adi_export_and_verify(self):
        tmp = Path(tempfile.mkdtemp(prefix="adi-export-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        out = tmp / "config" / "adi_authority_cases.generated.json"
        acfg = LAB / "configs" / "pilot_protocol_v1_deepseek_amendment_1.json"
        env = dict(os.environ, PYTHONHASHSEED="0", PYTHONUTF8="1")
        cmd = [sys.executable, "-X", "utf8", str(COMMON / "adi_export.py"), "export", "--acfg", str(acfg),
               "--frozen-config", str(LAB / "configs" / "pilot_protocol_v1_deepseek_frozen.json"),
               "--ss-cases", os.environ["ADI_SS_CASES"], "--fork-python", os.environ["ADI_FORK_PYTHON"],
               "--fork-src", os.environ["ADI_FORK_SRC"], "--argus-segmentation", os.environ["ADI_ARGUS_SEGMENTATION"],
               "--out", str(out)]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=1800)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])
        report = json.loads((out.parent / "adi_export_report.json").read_text(encoding="utf-8"))
        self.assertTrue(report["gates"]["G-ADI-EXPORT"]["pass"])
        self.assertEqual(report["gates"]["G-ADI-EXPORT"]["hashes_match_acfg"], 19)
        self.assertEqual(report["network_refusals"], [])
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["fork"]["local_copy"], str(Path(os.environ["ADI_FORK_SRC"]).resolve()))
        self.assertEqual(doc["generator"]["fork"], report["fork"])
        self.assertEqual(report["fork"]["acfg_source_pin_local_copy"],
                         json.loads(acfg.read_text(encoding="utf-8"))["source_pin"]["local_copy"])
        self.assertEqual(ex.verify_case_file(doc, json.loads(acfg.read_text(encoding="utf-8"))), [])
        self.assertEqual((out.with_name(out.name + ".sha256")).read_text(encoding="utf-8").split()[0], ex.sha256_lf(out))


if __name__ == "__main__":
    unittest.main()
