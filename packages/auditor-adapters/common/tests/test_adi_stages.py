"""G-ADI-STAGES (ADI amendment): the ADI stage files equal the amendment config's experiments[] (zero cost).

    <agentdojo-lab>/.venv/Scripts/python.exe -m unittest discover -s common/tests -v
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
COMMON = TESTS.parent
ADAPTERS = COMMON.parent
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import adi_stages as st  # noqa: E402

FILES = ("h2/stages.adi.json", "h2/config.adi.json", "melon/stages.adi.json", "melon/melon_h2_config.adi.json",
         "attriguard/stages.adi.json", "attriguard/config.cases.adi.json", "argus/stages.adi.json",
         "argus/stages.json", "paa/stages.adi.json", "paa/paa_agentdojo.py")


class StageFileTests(unittest.TestCase):
    def setUp(self):
        self.acfg = st.load_json(st.ACFG_DEFAULT)

    def test_shipped_files_equal_the_amendment_config(self):
        self.assertEqual(st.check(self.acfg), [])
        ids = [e["id"] for e in st.experiments(self.acfg)]
        self.assertEqual(ids, [f"D{n}" for n in range(23, 33)])
        total = sum(e["cap"][0] for e in st.experiments(self.acfg))
        self.assertAlmostEqual(total, self.acfg["budget"]["adi_total_caps_proposed"], places=6)   # $24.15

    def test_every_difference_is_reported(self):
        acfg = copy.deepcopy(self.acfg)
        exp = {e["id"]: e for e in acfg["experiments"]}
        exp["D27"]["cap"][0] = 2.0
        exp["D29"]["run"]["repeats"] = 4
        exp["D30"]["run"]["repeats"] = 5
        exp["D32"]["run"]["max_units"] = 100
        problems = "\n".join(st.check(acfg))
        for needle in ("D27 h2/ADI-S2: cap", "D29 attriguard/ADI-S2: repeats", "D30 argus/ADI-S2: argv --repeats",
                       "D32 paa/ADI-S2: argv --max-units", "D32 paa/ADI-S2: max_units x requests_per_unit"):
            self.assertIn(needle, problems)

    def test_write_regenerates_the_files_from_the_config(self):
        tmp = Path(tempfile.mkdtemp(prefix="adi-stages-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for rel in FILES:
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ADAPTERS / rel, tmp / rel)
        argus = json.loads((tmp / "argus/stages.adi.json").read_text(encoding="utf-8"))
        s2 = argus["stages"]["ADI-S2"]
        s2["cap_usd"] = 7.0
        s2["argv"] = st._set_argv(s2["argv"], "--agent-temperature", ["0.7"])
        s2["argv"] = st._set_argv(s2["argv"], "--repeats", ["5"])
        (tmp / "argus/stages.adi.json").write_text(json.dumps(argus, indent=2) + "\n", encoding="utf-8")
        problems = st.check(self.acfg, tmp)
        self.assertTrue(any("--agent-temperature" in p for p in problems))
        self.assertTrue(any("exceeds the frozen AL-S2-ADI ceiling" in p for p in problems))
        self.assertEqual(st.write(self.acfg, tmp), ["argus/stages.adi.json"])
        self.assertEqual(st.check(self.acfg, tmp), [])
        self.assertEqual(st.write(self.acfg, tmp), [])                                  # idempotent

    def test_frozen_argus_adi_placeholder_stays_blocked(self):
        frozen = st.load_json(ADAPTERS / "argus" / "stages.json")["stages"]["AL-S2-ADI"]
        self.assertIs(frozen["paid_allowed"], False)
        self.assertIs(frozen["dry_run_allowed"], False)

    def test_every_stage_resolves_plan_only_at_the_config_caps(self):
        results = st.plan(self.acfg)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(r["rc"] == 0 for r in results), results)
        caps = {e["id"]: e["cap"][2] for e in st.experiments(self.acfg)}
        self.assertTrue(all(r["cap_requests"] == caps[r["id"]] for r in results))


if __name__ == "__main__":
    unittest.main()
