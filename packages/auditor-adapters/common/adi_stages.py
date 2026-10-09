"""G-ADI-STAGES: the ADI stage files are derived from, and checked against, the amendment config's ``experiments[]``.

Versioned amendment ``authority-auditor-pilot-v1-deepseek.1``. The amendment config (ACFG,
``packages/agentdojo-lab/configs/pilot_protocol_v1_deepseek_amendment_1.json``) is the single source: each paid ADI
experiment D23-D32 carries its cap ``[USD, tokens, requests]`` and a ``run`` block (splits, families, arms, repeats,
max_cases, agent temperature, rows, PAA unit and request caps). This module

* ``check``: lists every difference between ACFG and the stage files and runner configs (``<adapter>/stages.adi.json``,
  ``h2/config.adi.json``, ``melon/melon_h2_config.adi.json``, ``attriguard/config.cases.adi.json``, the ARGUS and PAA
  stage argv, ``paa/paa_agentdojo.py`` STAGES) and checks that the frozen ``argus/stages.json`` AL-S2-ADI stays
  ``paid_allowed: false`` with the ADI-S2 ceiling at or below it. Empty = G-ADI-STAGES holds for the files;
* ``write``: rewrites the caps, repeats, max_cases and the PAA unit/request caps of those files from ACFG (run it
  again whenever the user signs another figure in U3, then ``check``);
* ``plan``: resolves every ADI stage through ``deepseek_route.run_stage(plan_only=True)`` at the ACFG caps (no guard,
  no key, no model request) and reports each return.

Standard library only (``deepseek_route`` is imported for ``plan``). No model request, no network.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent          # packages/auditor-adapters/common
ADAPT = HERE.parent
REPO_ROOT = ADAPT.parents[1]
ACFG_DEFAULT = REPO_ROOT / "packages" / "agentdojo-lab" / "configs" / "pilot_protocol_v1_deepseek_amendment_1.json"
ADAPTERS = ("h2", "melon", "attriguard", "argus", "paa")
RUNNER_CONFIG = {"h2": "h2/config.adi.json", "melon": "melon/melon_h2_config.adi.json",
                 "attriguard": "attriguard/config.cases.adi.json"}
FROZEN_ARGUS_ADI = "AL-S2-ADI"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump_like(path: Path, doc: Mapping[str, Any]) -> bool:
    """Write ``doc`` in the file's own JSON layout (indent and ASCII mode detected); True if the bytes changed."""
    raw = Path(path).read_text(encoding="utf-8")
    old = json.loads(raw)
    layout = next(((ind, ea) for ind in (2, 1) for ea in (False, True)
                   if json.dumps(old, indent=ind, ensure_ascii=ea) + "\n" == raw), (2, False))
    text = json.dumps(doc, indent=layout[0], ensure_ascii=layout[1]) + "\n"
    if text == raw:
        return False
    Path(path).write_text(text, encoding="utf-8", newline="\n")
    return True


def experiments(acfg: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The paid ADI experiments (adapter, stage, cap, run) of ACFG."""
    out = []
    for e in acfg.get("experiments") or []:
        if e.get("adapter") in ADAPTERS and e.get("stage") and e.get("stage_file"):
            if not isinstance(e.get("run"), Mapping):
                raise ValueError(f"ACFG experiment {e.get('id')} has no run block")
            out.append(e)
    return out


def _argv_values(argv: Sequence[str], flag: str) -> list[str] | None:
    """Values that follow ``flag`` in an argv (up to the next ``--option``); None when the flag is absent."""
    if flag not in argv:
        return None
    i = argv.index(flag) + 1
    vals = []
    while i < len(argv) and not str(argv[i]).startswith("--"):
        vals.append(str(argv[i]))
        i += 1
    return vals


def _caps(stage: Mapping[str, Any]) -> list[Any]:
    return [float(stage.get("cap_usd")), int(stage.get("cap_tokens")), int(stage.get("cap_requests"))]


def _usd(value: Any) -> str:
    return f"{Decimal(str(value)):.2f}"


def check(acfg: Mapping[str, Any], adapt: Path = ADAPT) -> list[str]:
    """Every G-ADI-STAGES difference between ACFG experiments[] and the shipped files (empty = equal)."""
    problems: list[str] = []
    for e in experiments(acfg):
        a, sname, run, cap = e["adapter"], e["stage"], e["run"], list(e["cap"])
        where = f"{e['id']} {a}/{sname}"
        sf = load_json(adapt / a / "stages.adi.json")
        st = (sf.get("stages") or {}).get(sname)
        if st is None:
            problems.append(f"{where}: no stage in {a}/stages.adi.json")
            continue
        if _caps(st) != [float(cap[0]), int(cap[1]), int(cap[2])]:
            problems.append(f"{where}: cap {_caps(st)} != ACFG {cap}")
        if st.get("paid_allowed", (sf.get("defaults") or {}).get("paid_allowed", True)) is not True:
            problems.append(f"{where}: paid_allowed is not true")
        argv = [str(x) for x in st.get("argv") or []]
        if a in RUNNER_CONFIG:
            rc = load_json(adapt / RUNNER_CONFIG[a])
            rs = (rc.get("stages") or {}).get(sname) or {}
            if a == "attriguard":
                sel = (rs.get("selections") or {}).get("adi") or {}
                got = {"splits": sel.get("splits"), "families": sel.get("families"), "arms": sel.get("arms"),
                       "repeats": rs.get("repeats"), "max_cases": sel.get("max_cases"), "rows": rs.get("rows"),
                       "temperature": rs.get("agent_temperature", (rc.get("backbone") or {}).get("agent_temperature"))}
                if not sel.get("expect_sha256_lf_at_run_time") or "adi={cases_sha256}" not in argv:
                    problems.append(f"{where}: the selection is not pinned at run time by {{cases_sha256}}")
            else:
                got = {"splits": rs.get("splits"), "families": rs.get("families"), "arms": rs.get("arms"),
                       "repeats": rs.get("repeats"), "max_cases": rs.get("max_cases"),
                       "temperature": rs.get("temperature")}
                if "{cases_sha256}" not in argv or _argv_values(argv, "--expect-content-sha256") != ["{cases_sha256}"]:
                    problems.append(f"{where}: argv does not pin the case file by {{cases_sha256}}")
                if not rs.get("require_invariants", False):
                    problems.append(f"{where}: require_invariants is not true")
            want = {k: run.get(k) for k in got}
            for k in got:
                if got[k] != want[k]:
                    problems.append(f"{where}: {k} {got[k]!r} != ACFG {want[k]!r}")
        elif a == "argus":
            want = {"--splits": run["splits"], "--families": run["families"], "--arms": run["arms"],
                    "--repeats": [str(run["repeats"])], "--rows": run["rows"],
                    "--max-cases": None if run.get("max_cases") is None else [str(run["max_cases"])]}
            for flag, value in want.items():
                if _argv_values(argv, flag) != value:
                    problems.append(f"{where}: argv {flag} {_argv_values(argv, flag)!r} != ACFG {value!r}")
            if "--agent-temperature" in argv:
                problems.append(f"{where}: argv passes --agent-temperature (ADI-X-8: the artifact's temperature)")
            if run.get("temperature") != "artifact":
                problems.append(f"{where}: ACFG temperature must be 'artifact' for ARGUS (ADI-X-8)")
            if _argv_values(argv, "--expect-content-sha256") != ["{cases_sha256}"]:
                problems.append(f"{where}: argv does not pin the case file by {{cases_sha256}}")
            frozen = load_json(adapt / "argus" / "stages.json")["stages"].get(FROZEN_ARGUS_ADI) or {}
            if frozen.get("paid_allowed") is not False:
                problems.append(f"frozen argus/stages.json {FROZEN_ARGUS_ADI} paid_allowed is not false")
            if frozen and any(x > y for x, y in zip(_caps(st), _caps(frozen))):
                problems.append(f"{where}: cap {_caps(st)} exceeds the frozen {FROZEN_ARGUS_ADI} ceiling {_caps(frozen)}")
        elif a == "paa":
            want = {"--strata": [",".join(run["strata"])], "--cap-usd": [_usd(cap[0])], "--cap-tokens": [str(cap[1])],
                    "--max-requests": [str(cap[2])], "--max-units": [str(run["max_units"])],
                    "--expect-cases-sha256": ["{cases_sha256}"]}
            for flag, value in want.items():
                if _argv_values(argv, flag) != value:
                    problems.append(f"{where}: argv {flag} {_argv_values(argv, flag)!r} != ACFG {value!r}")
            if int(run["max_units"]) * int(run.get("requests_per_unit", 6)) != int(cap[2]):
                problems.append(f"{where}: max_units x requests_per_unit != the request cap")
            defaults = _paa_stage_defaults(adapt).get(sname)
            if defaults != {"max_units": int(run["max_units"]), "max_requests": int(cap[2])}:
                problems.append(f"{where}: paa_agentdojo.STAGES[{sname}] {defaults} != ACFG")
    return problems


def _paa_stage_defaults(adapt: Path) -> dict[str, dict[str, int]]:
    """``STAGES`` of ``paa/paa_agentdojo.py`` read from the source (the module needs the PAA artifact to import)."""
    src = (adapt / "paa" / "paa_agentdojo.py").read_text(encoding="utf-8")
    out = {}
    for m in re.finditer(r'"(ADI-S\d)":\s*\{"max_units":\s*(\d+),\s*"max_requests":\s*(\d+)', src):
        out[m.group(1)] = {"max_units": int(m.group(2)), "max_requests": int(m.group(3))}
    return out


def _set_argv(argv: list[Any], flag: str, values: Sequence[str] | None) -> list[Any]:
    """Replace (or drop, for None) a flag and its values in an argv."""
    out = list(argv)
    if flag in out:
        i = out.index(flag)
        j = i + 1
        while j < len(out) and not str(out[j]).startswith("--"):
            j += 1
        del out[i:j]
        if values is not None:
            out[i:i] = [flag, *values]
    elif values is not None:
        k = out.index("--out") if "--out" in out else len(out)
        out[k:k] = [flag, *values]
    return out


def write(acfg: Mapping[str, Any], adapt: Path = ADAPT) -> list[str]:
    """Rewrite caps, repeats, max_cases and PAA unit/request caps from ACFG; returns the files that changed."""
    changed: set[str] = set()
    for e in experiments(acfg):
        a, sname, run, cap = e["adapter"], e["stage"], e["run"], list(e["cap"])
        path = adapt / a / "stages.adi.json"
        sf = load_json(path)
        st = sf["stages"][sname]
        st["cap_usd"], st["cap_tokens"], st["cap_requests"] = float(cap[0]), int(cap[1]), int(cap[2])
        if a == "argus":
            argv = list(st["argv"])
            argv = _set_argv(argv, "--agent-temperature", None)
            argv = _set_argv(argv, "--repeats", [str(run["repeats"])])
            argv = _set_argv(argv, "--max-cases", None if run.get("max_cases") is None else [str(run["max_cases"])])
            st["argv"] = argv
        if a == "paa":
            argv = list(st["argv"])
            for flag, value in (("--cap-usd", _usd(cap[0])), ("--cap-tokens", str(cap[1])),
                                ("--max-requests", str(cap[2])), ("--max-units", str(run["max_units"]))):
                argv = _set_argv(argv, flag, [value])
            st["argv"] = argv
        if dump_like(path, sf):
            changed.add(path.relative_to(adapt).as_posix())
        if a in RUNNER_CONFIG:
            rpath = adapt / RUNNER_CONFIG[a]
            rc = load_json(rpath)
            rs = rc["stages"][sname]
            rs["repeats"] = int(run["repeats"])
            if a == "attriguard":
                sel = rs["selections"]["adi"]
                if run.get("max_cases") is None:
                    sel.pop("max_cases", None)
                else:
                    sel["max_cases"] = int(run["max_cases"])
            else:
                rs["max_cases"] = run.get("max_cases")
            if dump_like(rpath, rc):
                changed.add(rpath.relative_to(adapt).as_posix())
    return sorted(changed)


def plan(acfg: Mapping[str, Any], out_root: Path | None = None) -> list[dict[str, Any]]:
    """Each ADI stage resolved by the route with ``plan_only`` at the ACFG caps (zero cost; nothing is started)."""
    sys.path.insert(0, str(HERE))
    import deepseek_route as dr

    results = []
    with tempfile.TemporaryDirectory(prefix="adi-stage-plan-") as tmp:
        root = Path(out_root) if out_root is not None else Path(tmp)
        for e in experiments(acfg):
            cap = list(e["cap"])
            req = dr.StageRequest(
                artifact=e["adapter"], stage=e["stage"], cap_usd=Decimal(str(cap[0])), cap_tokens=int(cap[1]),
                cap_requests=int(cap[2]), out_root=root, artifact_root=root / "artifact",
                config_path=ADAPT / e["adapter"] / "stages.adi.json", plan_only=True,
                extra_values={"cases": "<ADICASES>", "cases_sha256": "<ADISHA>", "units": "<ADIUNITS>",
                              "melon_dir": "<EXT>/melon"})
            try:
                got = dr.run_stage(req)
                results.append({"id": e["id"], "adapter": e["adapter"], "stage": e["stage"], "rc": 0,
                                "cap_requests": got["plan"]["cap_requests"]})
            except dr.RouteError as exc:
                results.append({"id": e["id"], "adapter": e["adapter"], "stage": e["stage"], "rc": 2, "error": str(exc)})
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=["check", "write", "plan"])
    ap.add_argument("--acfg", type=Path, default=ACFG_DEFAULT)
    args = ap.parse_args(argv)
    acfg = load_json(args.acfg)
    if args.cmd == "write":
        print(json.dumps({"changed": write(acfg)}))
    if args.cmd == "plan":
        res = plan(acfg)
        print(json.dumps(res, indent=1))
        return 0 if all(r["rc"] == 0 for r in res) else 3
    problems = check(acfg)
    print(json.dumps({"G-ADI-STAGES": "PASS" if not problems else "FAIL", "problems": problems}, indent=1))
    return 0 if not problems else 3


if __name__ == "__main__":
    raise SystemExit(main())
