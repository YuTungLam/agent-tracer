"""ADI exporter, fork side (amendment ``authority-auditor-pilot-v1-deepseek.1``; zero model requests).

Run ONLY with the ADI artifact venv, by the lab-side exporter ``../common/adi_export.py``, which starts it as

    PYTHONHASHSEED=0 <EXT>/adi/.venv/Scripts/python.exe -X utf8 -P -s adi_export_fork.py --acfg <config>
        --fork-src <EXT>/adi/src --out <file outside the repository>

(``-P -s``: no script directory and no user site on ``sys.path``; every other PYTHON* variable removed.)

It imports the pinned fork (compsec-snu/adi @1a3ddf8, MIT) and, for every case of the amendment config's
``case_table``, takes the payload verbatim from the fork's own case definitions
(``UserTask<n>.INJECTED_DATA_SYNTACTIC[index]``), escapes it with the fork's own ``_escape_yaml_value``
(imported, never retyped), and runs the fork's own ``GroundTruthPipeline`` on the fork's injected environment, so
the lab side can compare the stock port byte for byte with the fork (G-ADI-CONF).

Declared reuse (MIT): (1) ``INJECTED_DATA_SYNTACTIC`` imported from the fork; (2) ``task_suite._escape_yaml_value``
imported from the fork; (3) the fork's ``tool_result_to_str`` runs inside the fork's own ground-truth pipeline
(the lab side uses the attributed copy ``common/adi_compat.adi_tool_result_to_str``). Nothing is copied here.

The output file is payload-bearing: it is written outside the code repository only (refused inside it) and never
printed. This script prints hashes and counts only. It never writes, paraphrases or combines attack text.
Saved benchmark text is untrusted data; nothing here interprets it.
"""

from __future__ import annotations

import socket

_REFUSED: list[str] = []
_orig_connect, _orig_connect_ex, _orig_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _host(address: object) -> str:
    return str(address[0]) if isinstance(address, tuple) else str(address)


def _guard_connect(self, address):  # noqa: ANN001 - network guard: loopback only
    if _host(address) not in _LOOPBACK:
        _REFUSED.append(f"connect {_host(address)}")
        raise OSError("network guard: non-loopback connect refused")
    return _orig_connect(self, address)


def _guard_connect_ex(self, address):  # noqa: ANN001
    if _host(address) not in _LOOPBACK:
        _REFUSED.append(f"connect_ex {_host(address)}")
        raise OSError("network guard: non-loopback connect_ex refused")
    return _orig_connect_ex(self, address)


def _guard_gai(host, *a, **k):  # noqa: ANN001
    if host not in (*_LOOPBACK, None):
        _REFUSED.append(f"getaddrinfo {host}")
        raise OSError("network guard: name lookup refused")
    return _orig_gai(host, *a, **k)


def install_network_guard() -> None:
    """Loopback only for this process (installed by ``main``, so importing this module changes nothing)."""
    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = _guard_connect, _guard_connect_ex, _guard_gai

import argparse  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import inspect  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

SCHEMA = "adi-export-fork/v1"
BENCHMARK_VERSION = "v1.2.2"
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]  # packages/auditor-adapters/adi -> repository root


def _load_adi_compat():  # noqa: ANN202 - stdlib-only helpers shared with the lab side (frozen tool clock)
    import importlib.util

    spec = importlib.util.spec_from_file_location("adi_compat", HERE.parent / "common" / "adi_compat.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["adi_compat"] = module
    spec.loader.exec_module(module)
    return module


adi = _load_adi_compat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_lf_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def canonical_injections_sha256(injections: dict[str, str]) -> str:
    """The amendment's canonical rule: sha256 of json.dumps(raw injections, sort_keys, ensure_ascii False,
    compact separators), UTF-8, BEFORE any YAML escaping (ACFG case_table[].expected_hashes.canonical_rule)."""
    return sha256_text(json.dumps(injections, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def attacker_value(case: dict[str, Any], raw: dict[str, str]) -> str:
    """X by the case table's rule: a literal, or 'External_' + the raw prompt_injection_channel payload."""
    rule = (case.get("attacker_value") or {}).get("rule")
    if rule == "literal":
        return str(case["attacker_value"]["value"])
    if rule == "slack_external_channel":
        return "External_" + raw["prompt_injection_channel"]
    raise ValueError(f"{case['case_id']}: unknown attacker_value rule {rule!r}")


def string_values(value: Any) -> list[str]:
    """Every string leaf of a model_dump (keys excluded)."""
    out: list[str] = []
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return out


def env_form(env: Any, raw: str, escaped: str) -> str:
    """How the injected environment holds the payload after YAML parsing: 'raw' (a double-quoted placeholder
    unescapes it), 'fork_escaped' (a block scalar keeps the fork's escapes), or 'absent'."""
    leaves = string_values(env.model_dump(mode="json"))
    if any(raw in s for s in leaves):
        return "raw"
    if escaped != raw and any(escaped in s for s in leaves):
        return "fork_escaped"
    return "absent"


def fork_identity(src: Path) -> dict[str, Any]:
    import agentdojo
    from agentdojo.agent_pipeline import tool_execution as fork_tool_execution
    from agentdojo.task_suite import task_suite as fork_task_suite

    pkg = Path(agentdojo.__file__).resolve()
    try:
        pkg.relative_to(src.resolve())
        inside = True
    except ValueError:
        inside = False
    import pydantic
    import yaml

    return {
        "package_inside_fork_src": inside,
        "escape_function": "agentdojo.task_suite.task_suite._escape_yaml_value",
        "escape_source_sha256": sha256_text(inspect.getsource(fork_task_suite._escape_yaml_value)),
        "task_suite_file_sha256_lf": sha256_lf_file(Path(fork_task_suite.__file__)),
        "formatter_function": "agentdojo.agent_pipeline.tool_execution.tool_result_to_str",
        "formatter_source_sha256": sha256_text(inspect.getsource(fork_tool_execution.tool_result_to_str)),
        "tool_execution_file_sha256_lf": sha256_lf_file(Path(fork_tool_execution.__file__)),
        "pydantic": pydantic.VERSION, "pyyaml": getattr(yaml, "__version__", None),
        "python": sys.version.split()[0],
    }


def gt_outputs(suite: Any, ut: Any, injections: dict[str, str]) -> dict[str, Any]:
    """The fork's GroundTruthPipeline on the fork's environment injected with ``injections`` (RAW payloads: the
    fork's loader escapes them itself): per tool message, function, args and the rendered text."""
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.types import get_text_content_as_str

    env = suite.load_and_inject_default_environment(injections)
    task_env = ut.init_environment(env.model_copy(deep=True))
    # the same frozen tool clock as the stock side, so run-time stamps compare byte for byte (conformance only)
    with adi.frozen_tool_clock(), contextlib.redirect_stdout(io.StringIO()):
        _, _, _, messages, _ = GroundTruthPipeline(ut).query(ut.PROMPT, FunctionsRuntime(suite.tools), task_env)
    outs = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        content = m.get("content")
        text = get_text_content_as_str(content) if isinstance(content, list) else str(content)
        call = m.get("tool_call")
        outs.append({"function": call.function if call is not None else None,
                     "args": json.loads(json.dumps(dict(call.args) if call is not None else {}, default=str)),
                     "text": text})
    return {"env": env, "outputs": outs}


def export(acfg: dict[str, Any], src: Path) -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import _escape_yaml_value  # declared reuse (2): imported, not retyped

    suites: dict[str, Any] = {}
    rows = []
    for case in acfg["case_table"]:
        sname, utid, idx = case["suite"], case["user_task_id"], int(case["adi_index"])
        suite = suites.setdefault(sname, get_suite(BENCHMARK_VERSION, sname))
        ut = suite.get_user_task_by_id(utid)
        raw = dict(ut.INJECTED_DATA_SYNTACTIC[idx])  # declared reuse (3): the fork's own case definitions
        x = attacker_value(case, raw)
        escaped = {v: _escape_yaml_value(p) for v, p in raw.items()}
        want = case["expected_hashes"]
        got = {"payload_sha256_utf8": {v: sha256_text(p) for v, p in sorted(raw.items())},
               "payload_chars": {v: len(p) for v, p in sorted(raw.items())},
               "injections_sha256_canonical": canonical_injections_sha256(raw),
               "x_sha256": sha256_text(x)}
        hashes_ok = (got["payload_sha256_utf8"] == want["payload_sha256_utf8"]
                     and got["payload_chars"] == want["payload_chars"]
                     and got["injections_sha256_canonical"] == want["injections_sha256_canonical"]
                     and got["x_sha256"] == want["x_sha256"]
                     and sorted(raw) == sorted(case["vectors"]))
        attack = gt_outputs(suite, ut, raw)
        clean = gt_outputs(suite, ut, {})
        rows.append({
            "case_id": case["case_id"], "ref": case["ref"], "suite": sname, "user_task_id": utid, "adi_index": idx,
            "injections_raw": raw, "injections_escaped": escaped, "attacker_value": x,
            "hashes": got, "hashes_match_acfg": hashes_ok,
            "escaped_sha256": {v: sha256_text(p) for v, p in sorted(escaped.items())},
            "env_form": {v: env_form(attack["env"], raw[v], escaped[v]) for v in sorted(raw)},
            "gt_attack_outputs": attack["outputs"], "gt_clean_outputs": clean["outputs"],
        })
    return {"rows": rows}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--acfg", type=Path, required=True, help="the amendment config (case_table, source_pin)")
    ap.add_argument("--fork-src", type=Path, required=True, help="the fork's clean checkout (EXT/adi/src)")
    ap.add_argument("--out", type=Path, required=True, help="payload-bearing output JSON (outside the repository)")
    args = ap.parse_args(argv)
    out = args.out.resolve()
    try:
        out.relative_to(REPO_ROOT)
        print(f"refused: {out} is inside the code repository {REPO_ROOT}; the fork reference holds payload text",
              file=sys.stderr)
        return 2
    except ValueError:
        pass
    install_network_guard()
    acfg = json.loads(args.acfg.read_text(encoding="utf-8"))
    ident = fork_identity(args.fork_src)
    if not ident["package_inside_fork_src"]:
        import agentdojo

        print(f"refused: the imported agentdojo ({agentdojo.__file__}) is not the fork at {args.fork_src}",
              file=sys.stderr)
        return 2
    if sys.flags.hash_randomization:
        print("refused: run with PYTHONHASHSEED=0 (set iteration order, e.g. calendar participants, must match the "
              "stock side)", file=sys.stderr)
        return 2
    with adi.frozen_tool_clock() as frozen:
        pass
    doc = {"schema": SCHEMA, "acfg_version_id": acfg.get("version_id"), "benchmark_version": BENCHMARK_VERSION,
           "fork": ident, "comparison_controls": {"pythonhashseed": "0", "frozen_tool_clock_modules": frozen,
                                                  "frozen_tool_instant": list(adi.FROZEN_TOOL_INSTANT)},
           **export(acfg, args.fork_src)}
    doc["network_refusals"] = list(_REFUSED)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(out)
    ok = sum(1 for r in doc["rows"] if r["hashes_match_acfg"])
    print(json.dumps({"schema": SCHEMA, "cases": len(doc["rows"]), "hashes_match_acfg": ok,
                      "out_sha256_lf": sha256_lf_file(out), "network_refusals": len(_REFUSED)}))
    return 0 if ok == len(doc["rows"]) and not _REFUSED else 3


if __name__ == "__main__":
    raise SystemExit(main())
