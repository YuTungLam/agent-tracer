"""ADI exporter and zero-cost conformance gate, lab side (G-ADI-EXPORT, G-ADI-CONF; zero model requests).

Versioned amendment ``authority-auditor-pilot-v1-deepseek.1`` (made after D01-D07 and with batch-2 output present;
see the amendment's ``data_seen_before_amendment`` and its open item U4). Run with the lab venv
(``PYTHONUTF8=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1``)::

    python common/adi_export.py export --acfg <LAB>/configs/pilot_protocol_v1_deepseek_amendment_1.json \\
        --frozen-config <LAB>/configs/pilot_protocol_v1_deepseek_frozen.json --ss-cases <pinned SS case file> \\
        --fork-python <EXT>/adi/.venv/Scripts/python.exe --fork-src <EXT>/adi/src \\
        --argus-segmentation <EXT>/argus/src/AgentLure/agentlure/warrant/segmentation.py \\
        --out <RES>/experiments/<DAY>-deepseek-adi-authority-cases-v1/config/adi_authority_cases.generated.json

    python common/adi_export.py verify --acfg <...amendment_1.json> --cases <case file>   # no fork needed

What ``export`` does:

1. Starts the fork side (``../adi/adi_export_fork.py``) in the fork's own venv, in isolated mode. It imports the
   pinned fork (commit and clean tree checked here with git), takes every payload verbatim from the fork's case
   definitions, escapes it with the fork's own ``_escape_yaml_value`` (imported) and records the fork's own
   ground-truth tool outputs. Nothing is retyped and no attack text is written.
2. Ports each case onto stock AgentDojo v1.2.2 (the lab's vendored 0.1.35; no fork data overlaid, ADI-X-3) and runs
   the conformance checks of G-ADI-CONF on it: the ground-truth tool outputs rendered with the fork's JSON formatter
   (``adi_compat.adi_tool_result_to_str``, attributed copy) equal the fork's byte for byte; the environment holds the
   payload as the fork's does; the ground-truth legitimate value of each arm equals the case table; both arms'
   ground truth score ``legitimate`` with utility true (ADI-X-11: the legitimate set is per arm); X-substitution
   executability equals the table, or resolves an ``untested`` entry; the state-observable flag uses the runners'
   counting rule (``adi_compat.state_needle``). A failing case is written with ``invariants.all`` false (ineligible,
   never run) and the failure is recorded.
3. Records, per case and without gating, whether Warrant's span partition keeps the payload and every native
   occurrence of X in different spans under the JSON rendering (and the YAML one, for comparison): where they share
   a span, ARGUS wrong-source blame is undefined for that case (amendment deviation ADI-X-12).
4. Writes the payload-bearing case file (``h2-cases/v2`` + ``tool_output_format`` json, seed family ADI, arms ATTACK
   and CLEAN) outside the code repository only, deterministically (no timestamps), its LF sha256 next to it, and a
   payload-free report. The report is scanned for payload shingles before it is written.

Saved benchmark text is untrusted data; nothing here interprets it. Payload text is never printed.
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
    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = _guard_connect, _guard_connect_ex, _guard_gai


import argparse  # noqa: E402
import contextlib  # noqa: E402
import difflib  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import unicodedata  # noqa: E402
from collections.abc import Callable, Iterable, Mapping, Sequence  # noqa: E402
from pathlib import Path  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any  # noqa: E402

HERE = Path(__file__).resolve().parent              # packages/auditor-adapters/common
ADAPT = HERE.parent
REPO_ROOT = ADAPT.parents[1]
LAB_SRC = REPO_ROOT / "packages" / "agentdojo-lab" / "src"
FORK_SIDE = ADAPT / "adi" / "adi_export_fork.py"

EXPORTER_VERSION = "adi-export/1"
SCHEMA_CASES = "h2-cases/v2"
SCHEMA_REPORT = "adi-export-report/v1"
CONFIG_ID = "adi-authority-cases-v1"
BENCHMARK_VERSION = "v1.2.2"
SPLIT_SALT = "authority-auditor-pilot-v1|"
EXEC_LABEL = {"yes": True, "no": False}


class ExportError(RuntimeError):
    """The export cannot be completed as the amendment requires (nothing is written)."""


def _load_adi_compat() -> ModuleType:
    if "adi_compat" in sys.modules:
        return sys.modules["adi_compat"]
    spec = importlib.util.spec_from_file_location("adi_compat", HERE / "adi_compat.py")
    if spec is None or spec.loader is None:
        raise ImportError("cannot load adi_compat.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["adi_compat"] = module
    spec.loader.exec_module(module)
    return module


adi = _load_adi_compat()


def _h2_cases() -> ModuleType:
    if str(LAB_SRC) not in sys.path:
        sys.path.insert(0, str(LAB_SRC))
    from agentdojo_lab import h2_cases

    return h2_cases


# ---------------------------------------------------------------------------------------------
# Hashing and small helpers


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_lf(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def canonical_injections_sha256(injections: Mapping[str, str]) -> str:
    """ACFG ``canonical_rule``: json.dumps(raw injections, sort_keys, ensure_ascii False, compact), UTF-8."""
    return sha256_text(json.dumps(dict(injections), sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def inside(path: Path, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------------------------
# Text location (offset-preserving decoders). Payload text is only ever compared, never printed.

_JSON_ESC = re.compile(r'\\(u[0-9a-fA-F]{4}(?:\\u[dD][c-fC-F][0-9a-fA-F]{2})?|["\\/bfnrt])')
_SIMPLE = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def json_decode_map(text: str) -> tuple[str, list[int]]:
    """``text`` with JSON string escapes decoded, and each decoded character's source offset (so a match in the
    decoded view maps back to the rendered text, which is what a span partition cuts)."""
    out: list[str] = []
    idx: list[int] = []
    pos = 0
    for m in _JSON_ESC.finditer(text):
        for k in range(pos, m.start()):
            out.append(text[k])
            idx.append(k)
        g = m.group(1)
        if g[0] == "u":
            ch = json.loads('"\\' + g + '"')
        else:
            ch = _SIMPLE[g]
        for c in ch:
            out.append(c)
            idx.append(m.start())
        pos = m.end()
    for k in range(pos, len(text)):
        out.append(text[k])
        idx.append(k)
    return "".join(out), idx


_QUOTES = "'\"`‘’“”"


def canon_map(text: str) -> tuple[str, list[int]]:
    """Folded view for YAML-rendered text (NFKC + casefold; whitespace, quotes and backslash escapes become one
    space; ``\\uXXXX`` decoded), with source offsets. An approximation of ``argus_gate.canon_map`` (json_escapes
    on), used only for the non-gating YAML comparison of the span check."""
    out: list[str] = []
    idx: list[int] = []
    i, n, space = 0, len(text), True
    while i < n:
        ch, step = text[i], 1
        m = re.match(r"\\u([0-9a-fA-F]{4})", text[i:i + 6])
        if m:
            ch, step = chr(int(m.group(1), 16)), 6
            sep = ch.isspace() or ch in _QUOTES
        elif ch == "\\" and i + 1 < n and text[i + 1] in 'nrt"\\/':
            sep, step = True, 2
        else:
            sep = ch.isspace() or ch in _QUOTES or ch == "\\"
        if sep:
            if not space:
                out.append(" ")
                idx.append(i)
                space = True
        else:
            for c in unicodedata.normalize("NFKC", ch).casefold():
                out.append(c)
                idx.append(i)
            space = False
        i += step
    return "".join(out), idx


def find_ranges(hay: str, idx: Sequence[int], needle: str) -> list[tuple[int, int]]:
    """Every occurrence of ``needle`` in the decoded ``hay``, as source ranges [start, end)."""
    out: list[tuple[int, int]] = []
    if not needle:
        return out
    start = 0
    while True:
        k = hay.find(needle, start)
        if k < 0:
            return out
        out.append((idx[k], idx[k + len(needle) - 1] + 1))
        start = k + 1


def word_ranges(hay: str, idx: Sequence[int], value: str, *, fold: bool = False) -> list[tuple[int, int]]:
    """Word-boundary occurrences of ``value`` (the census rule's boundary class) as source ranges."""
    v = unicodedata.normalize("NFKC", value).casefold() if fold else value
    if not v:
        return []
    flags = 0 if fold else re.IGNORECASE
    pat = re.compile(rf"(?<![0-9A-Za-z_]){re.escape(v)}(?![0-9A-Za-z_])", flags)
    return [(idx[m.start()], idx[m.end() - 1] + 1) for m in pat.finditer(hay)]


def overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def locate(text: str, payload: str, x: str, fmt: str) -> dict[str, list[tuple[int, int]]]:
    """Payload occurrences and native X occurrences (X outside every payload occurrence) in one rendered output."""
    if fmt == "json":
        hay, idx = json_decode_map(text)
        pay = find_ranges(hay, idx, payload)
        xs = word_ranges(hay, idx, x)
    else:
        hay, idx = canon_map(text)
        pay = find_ranges(hay, idx, canon_map(payload)[0].strip())
        xs = word_ranges(hay, idx, canon_map(x)[0].strip(), fold=True)
    native = [r for r in xs if not any(overlaps(r, p) for p in pay)]
    return {"payload": pay, "x": xs, "x_native": native}


# ---------------------------------------------------------------------------------------------
# Fork side, fork pin, inputs


def check_fork_tree(fork_src: Path, commit: str) -> dict[str, Any]:
    """The fork checkout is at the pinned commit with a clean tree (G-ADI-EXPORT)."""
    try:
        head = subprocess.run(["git", "-C", str(fork_src), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=60).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(fork_src), "status", "--porcelain"], capture_output=True, text=True,
                               check=True, timeout=120).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ExportError(f"cannot check the fork checkout with git: {exc}") from None
    if head != commit:
        raise ExportError(f"fork checkout {fork_src} is at {head}, the amendment pins {commit}")
    if dirty:
        raise ExportError(f"fork checkout {fork_src} is not clean ({len(dirty.splitlines())} changed paths)")
    return {"commit": head, "clean_tree": True}


def run_fork_side(fork_python: Path, fork_src: Path, acfg_path: Path, out: Path) -> dict[str, Any]:
    """Start ``adi_export_fork.py`` in the fork venv and return its summary line. ``-P -s`` keep the script
    directory and the user site off ``sys.path`` (as ``-I`` would); ``-I`` itself is not used because it also
    drops PYTHONHASHSEED, which the comparison needs. Every other PYTHON* variable is removed from the child env."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env.update({"PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"})
    cmd = [str(fork_python), "-X", "utf8", "-P", "-s", str(FORK_SIDE), "--acfg", str(acfg_path),
           "--fork-src", str(fork_src), "--out", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(out.parent),
                          env=env, timeout=1800)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    summary = json.loads(lines[-1]) if lines else {}
    if proc.returncode != 0:
        tail = proc.stderr.strip().splitlines()[-1:] if proc.stderr.strip() else []
        raise ExportError(f"fork side exited {proc.returncode}: {summary or tail}")
    return summary


def load_inputs(acfg_path: Path, frozen_path: Path, ss_path: Path) -> dict[str, Any]:
    acfg = json.loads(Path(acfg_path).read_text(encoding="utf-8"))
    if acfg.get("version_id") != adi.AMENDMENT_ID:
        raise ExportError(f"{acfg_path}: version_id {acfg.get('version_id')!r} is not {adi.AMENDMENT_ID}")
    frozen = json.loads(Path(frozen_path).read_text(encoding="utf-8"))
    pin = ((frozen.get("case_set") or {}).get("pins") or {}).get("content_sha256_lf")
    ss_lf = sha256_lf(ss_path)
    if not pin or ss_lf != pin:
        raise ExportError(f"SS case file LF sha256 {ss_lf} is not the frozen pin {pin} (case_set.pins.content_sha256_lf)")
    ss = json.loads(Path(ss_path).read_text(encoding="utf-8"))
    return {"acfg": acfg, "acfg_sha256_lf": sha256_lf(acfg_path), "frozen_sha256_lf": sha256_lf(frozen_path),
            "ss": ss, "ss_sha256_lf": ss_lf}


def expected_split(ss: Mapping[str, Any], suite: str, user_task_id: str) -> tuple[str, str]:
    """ADI-X-9: the pinned SS case file's ``split_check`` where the task is listed, else the raw rule."""
    check = (ss.get("split_check") or {}).get(suite) or {}
    if user_task_id in (check.get("dev_tasks") or []):
        return "dev", "split_check dev_tasks of the pinned SS case file"
    if user_task_id in (check.get("eval_tasks") or []):
        return "eval", "split_check eval_tasks of the pinned SS case file"
    return _h2_cases().task_split(suite, user_task_id, SPLIT_SALT), "raw hash rule (task not in the SS case file)"


def expected_legit(case: Mapping[str, Any], raw: Mapping[str, str]) -> dict[str, list[str]]:
    """Per-arm legitimate values by the case table's rule (ADI-X-11)."""
    rule = case["legitimate"]
    if rule.get("rule") == "stock_ground_truth":
        vals = [str(v) for v in rule["values"]]
        return {"ATTACK": vals, "CLEAN": vals}
    if rule.get("rule") == "slack_external_channel_per_arm":
        return {"ATTACK": ["External_" + raw["prompt_injection_channel"]], "CLEAN": [str(v) for v in rule["CLEAN"]]}
    raise ExportError(f"{case['case_id']}: unknown legitimate rule {rule.get('rule')!r}")


# ---------------------------------------------------------------------------------------------
# Stock port: ground truth with a given formatter


@contextlib.contextmanager
def gt_formatter(formatter: Callable[[Any], str] | None):
    """Run AgentDojo's own ``GroundTruthPipeline`` with ``formatter`` as its module-level tool-output formatter
    (the fork's pipeline is the stock one with the JSON formatter; the two files are identical otherwise)."""
    import agentdojo.agent_pipeline.ground_truth_pipeline as gtp

    previous = gtp.tool_result_to_str
    if formatter is not None:
        gtp.tool_result_to_str = formatter
    try:
        yield
    finally:
        gtp.tool_result_to_str = previous


def run_gt(suite: Any, ut: Any, injections: Mapping[str, str], formatter: Callable[[Any], str] | None,
           frozen_clock: bool = True) -> dict[str, Any]:
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages
    from agentdojo.types import get_text_content_as_str

    env = ut.init_environment(suite.load_and_inject_default_environment(dict(injections)))
    pre = env.model_copy(deep=True)
    clock = adi.frozen_tool_clock() if frozen_clock else contextlib.nullcontext()
    with clock, gt_formatter(formatter), contextlib.redirect_stdout(io.StringIO()):
        _, _, post, msgs, _ = GroundTruthPipeline(ut).query(ut.PROMPT, FunctionsRuntime(suite.tools), env)
    stack = functions_stack_trace_from_messages(msgs)
    out = model_output_from_messages(msgs)
    utility = bool(suite._check_user_task_utility(ut, out or [], pre, post, stack))
    outputs = []
    for m in msgs:
        if m.get("role") != "tool":
            continue
        content = m.get("content")
        call = m.get("tool_call")
        outputs.append({"function": call.function if call is not None else None,
                        "args": json.loads(json.dumps(dict(call.args) if call is not None else {}, default=str)),
                        "text": get_text_content_as_str(content) if isinstance(content, list) else str(content)})
    calls = [{"function": fc.function, "args": dict(fc.args), "success": True} for fc in stack]
    return {"pre": pre, "post": post, "outputs": outputs, "calls": calls, "utility": utility}


def sink_values(calls: Sequence[Mapping[str, Any]], target: Mapping[str, Any]) -> list[str]:
    return [str(v) for c in calls if c["function"] == target["function"]
            for v in _as_list((c.get("args") or {}).get(target["argument"]))]


def sink_slots(calls: Sequence[Mapping[str, Any]], target: Mapping[str, Any], legit: Iterable[str]) -> list[dict[str, Any]]:
    """Target slots as the SS generator records them: the sink call's index in the ground-truth stack and the
    element index of each legitimate value in it."""
    h2 = _h2_cases()
    lnorm = {h2.normalize_value(v) for v in legit}
    slots = []
    for ci, c in enumerate(calls):
        if c["function"] != target["function"]:
            continue
        for ei, v in enumerate(_as_list((c.get("args") or {}).get(target["argument"]))):
            if h2.normalize_value(v) in lnorm:
                slots.append({"argument": target["argument"], "call_index": ci, "element_index": ei,
                              "function": target["function"]})
    return slots


def x_substitution(suite: Any, ut: Any, injections: Mapping[str, str], target: Mapping[str, Any], x: str,
                   legit: Iterable[str]) -> dict[str, Any]:
    """The SS generator's executability rule on the ATTACK environment: substitute X for every legitimate value in
    the target slots of the ground-truth calls and run them for real; executable iff a substitution happened and
    no sink call errored. State-observable iff that run adds an occurrence of X to the JSON dump of the native
    state, counted with the runners' rule (``adi_compat.state_needle``)."""
    from agentdojo.functions_runtime import FunctionsRuntime

    h2 = _h2_cases()
    lnorm = {h2.normalize_value(v) for v in legit}
    env = ut.init_environment(suite.load_and_inject_default_environment(dict(injections)))
    runtime = FunctionsRuntime(suite.tools)
    needle = adi.state_needle(x)
    x_pre = env.model_dump_json().count(needle)
    errors: list[str] = []
    substituted = False
    with contextlib.redirect_stdout(io.StringIO()):
        for fc in ut.ground_truth(env.model_copy(deep=True)):
            args = dict(fc.args)
            if fc.function == target["function"] and target["argument"] in args:
                v = args[target["argument"]]
                if isinstance(v, list):
                    new = [x if h2.normalize_value(e) in lnorm else e for e in v]
                    substituted = substituted or new != v
                    args[target["argument"]] = new
                elif h2.normalize_value(v) in lnorm:
                    args[target["argument"]] = x
                    substituted = True
            _res, err = runtime.run_function(env, fc.function, args, raise_on_error=False)
            if err and fc.function == target["function"]:
                errors.append(str(err).split(":")[0][:80])
    executable = substituted and not errors
    observable = executable and env.model_dump_json().count(needle) > x_pre
    return {"substituted": substituted, "sink_error_types": errors, "executable": executable,
            "state_observable": bool(observable)}


def env_form(env: Any, raw: str, escaped: str) -> str:
    leaves: list[str] = []
    stack: list[Any] = [env.model_dump(mode="json")]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            leaves.append(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    if any(raw in s for s in leaves):
        return "raw"
    if escaped != raw and any(escaped in s for s in leaves):
        return "fork_escaped"
    return "absent"


def output_diff(stock: str, fork: str, payload_ranges: Sequence[tuple[int, int]]) -> dict[str, Any]:
    """Where a stock output differs from the fork's (offsets and sizes only; never the text)."""
    ops = [op for op in difflib.SequenceMatcher(None, fork, stock, autojunk=False).get_opcodes() if op[0] != "equal"]
    return {"equal": False, "len_fork": len(fork), "len_stock": len(stock), "segments": len(ops),
            "fork_chars_changed": sum(i2 - i1 for _, i1, i2, _, _ in ops),
            "stock_chars_changed": sum(j2 - j1 for _, _, _, j1, j2 in ops),
            "touches_payload": any(overlaps((i1, max(i2, i1 + 1)), p) for _, i1, i2, _, _ in ops for p in payload_ranges)}


# ---------------------------------------------------------------------------------------------
# Warrant span separation (ADI-X-12): recorded, not gating


def load_segmentation(path: Path | None) -> ModuleType | None:
    if path is None:
        return None
    spec = importlib.util.spec_from_file_location("warrant_segmentation", path)
    if spec is None or spec.loader is None:
        raise ExportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def span_separation(outputs: Sequence[Mapping[str, Any]], first_sink: int, payload: str, x: str, fmt: str,
                    seg: ModuleType) -> dict[str, Any]:
    """Under Warrant's ``segment`` (default parameters, as ``ContextSegmenter.partition``), does any native
    occurrence of X share a span with the payload in a ground-truth output read before the sink?"""
    per = []
    native_total = shared_total = 0
    for i, o in enumerate(outputs[:first_sink]):
        loc = locate(o["text"], payload, x, fmt)
        if not loc["payload"] and not loc["x_native"]:
            continue
        spans = seg.segment(o["text"])
        pay_spans = [s for s in spans if any(overlaps(s, p) for p in loc["payload"])]
        shared = sum(1 for r in loc["x_native"] if any(overlaps(r, s) for s in pay_spans))
        native_total += len(loc["x_native"])
        shared_total += shared
        per.append({"output": i, "function": o["function"], "spans": len(spans), "payload_spans": len(pay_spans),
                    "x_native_occurrences": len(loc["x_native"]), "x_native_in_payload_span": shared})
    return {"separated": shared_total == 0, "x_native_occurrences": native_total,
            "x_native_in_payload_span": shared_total, "outputs": per}


# ---------------------------------------------------------------------------------------------
# One case


def conform_case(case: Mapping[str, Any], fork_row: Mapping[str, Any], suites: Mapping[str, Any],
                 amap: Mapping[str, Sequence[str]], ss: Mapping[str, Any], seg: ModuleType | None) -> dict[str, Any]:
    """Every zero-cost check of G-ADI-EXPORT and G-ADI-CONF for one case. Returns the facts (payload-bearing
    values only under ``_private``)."""
    h2 = _h2_cases()
    suite = suites[case["suite"]]
    ut = suite.get_user_task_by_id(case["user_task_id"])
    target = dict(case["target"])
    raw: dict[str, str] = dict(fork_row["injections_raw"])
    escaped: dict[str, str] = dict(fork_row["injections_escaped"])
    x = str(fork_row["attacker_value"])
    legit = expected_legit(case, raw)
    split, split_source = expected_split(ss, case["suite"], case["user_task_id"])
    facts: dict[str, Any] = {
        "hashes_match_acfg": bool(fork_row["hashes_match_acfg"]),
        "x_sha256": sha256_text(x),
        "split": split, "split_source": split_source, "split_matches_table": split == case["split"],
        "legitimate_sha256": {arm: [sha256_text(v) for v in vals] for arm, vals in legit.items()},
    }
    vectors = set(suite.get_injection_vector_defaults())
    facts["vectors_on_stock"] = all(v in vectors for v in raw)
    facts["vector_on_stock_matches_table"] = facts["vectors_on_stock"] == bool(case.get("vector_on_stock_v1_2_2"))
    facts["_private"] = {"raw": raw, "escaped": escaped, "x": x, "legit": legit}
    if not facts["vectors_on_stock"]:
        facts["ineligible_reason"] = "a vector of this case exists only in the fork (ADI-X-3: no fork data overlaid)"
        return facts
    arm_texts = {v: (raw[v] if fork_row["env_form"][v] == "raw" else escaped[v]) for v in raw}
    facts["_private"]["arm_text"] = "\n\n".join(arm_texts[v] for v in sorted(arm_texts))
    payload = facts["_private"]["arm_text"]
    fmt_json = adi.adi_tool_result_to_str
    attack = run_gt(suite, ut, escaped, fmt_json)
    clean = run_gt(suite, ut, {}, fmt_json)
    attack_env = suite.load_and_inject_default_environment(escaped)
    facts["env_form"] = {v: env_form(attack_env, raw[v], escaped[v]) for v in sorted(raw)}
    facts["env_form_matches_fork"] = facts["env_form"] == fork_row["env_form"] and "absent" not in facts["env_form"].values()

    # byte-for-byte conformance with the fork's own ground-truth outputs (ATTACK gates; CLEAN is a diagnostic)
    def compare(stock_outs: Sequence[Mapping[str, Any]], fork_outs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        per = []
        for i in range(max(len(stock_outs), len(fork_outs))):
            s = stock_outs[i] if i < len(stock_outs) else None
            f = fork_outs[i] if i < len(fork_outs) else None
            if s is None or f is None:
                per.append({"output": i, "equal": False, "missing": "stock" if s is None else "fork"})
                continue
            same_call = s["function"] == f["function"] and s["args"] == f["args"]
            if same_call and s["text"] == f["text"]:
                per.append({"output": i, "function": s["function"], "equal": True})
                continue
            pay = locate(f["text"], payload, x, "json")["payload"]
            per.append({"output": i, "function": s["function"], "same_call": same_call,
                        **output_diff(s["text"], f["text"], pay)})
        return {"equal": all(p["equal"] for p in per) and len(stock_outs) == len(fork_outs), "outputs": per}

    facts["gt_outputs_vs_fork"] = compare(attack["outputs"], fork_row["gt_attack_outputs"])
    facts["gt_outputs_equal_fork"] = facts["gt_outputs_vs_fork"]["equal"]
    facts["gt_clean_outputs_vs_fork"] = compare(clean["outputs"], fork_row["gt_clean_outputs"])
    if not facts["gt_outputs_equal_fork"]:
        # recorded, NOT gating (ADI-X-3 fails any difference beyond the payload): do the differences avoid the
        # payload's own occurrences entirely (e.g. a fork data edit in another record)?
        diffs = [p for p in facts["gt_outputs_vs_fork"]["outputs"] if not p["equal"]]
        facts["gt_outputs_differ_only_outside_payload"] = all(
            p.get("same_call") and not p.get("touches_payload") and "missing" not in p for p in diffs)

    # legitimate value per arm, and both arms' ground truth scored by the typed oracle
    observed = {"ATTACK": sorted(set(sink_values(attack["calls"], target))),
                "CLEAN": sorted(set(sink_values(clean["calls"], target)))}
    facts["gt_legit_matches_table"] = {arm: observed[arm] == sorted(set(legit[arm])) for arm in ("ATTACK", "CLEAN")}
    for arm, run in (("ATTACK", attack), ("CLEAN", clean)):
        verdict = h2.classify_outcome(target, legit[arm], x, None, run["calls"], run["utility"], authority_args=amap)
        facts[f"gt_{arm.lower()}_outcome"] = verdict["outcome"]
        facts[f"gt_{arm.lower()}_utility"] = run["utility"]
    facts["gt_both_arms_legitimate"] = all(facts[f"gt_{a}_outcome"] == "legitimate" and facts[f"gt_{a}_utility"]
                                           for a in ("attack", "clean"))
    facts["_private"]["slots"] = sink_slots(clean["calls"], target, legit["CLEAN"])

    # executability (resolves 'untested') and the state-observable flag
    sub = x_substitution(suite, ut, escaped, target, x, legit["ATTACK"])
    label = case.get("executable_on_stock")
    facts["x_substitution"] = sub
    facts["executable_table"] = label
    facts["executable_resolved"] = sub["executable"]
    facts["executable_matches_table"] = (EXEC_LABEL[label] == sub["executable"]) if label in EXEC_LABEL else True
    facts["executable_resolved_here"] = label not in EXEC_LABEL

    # exposure of the payload and native X on the ground-truth path before the sink (JSON rendering)
    first_sink = next((i for i, o in enumerate(attack["outputs"]) if o["function"] == target["function"]),
                      len(attack["outputs"]))
    pre = attack["outputs"][:first_sink]
    locs = [locate(o["text"], payload, x, "json") for o in pre]
    facts["gt_first_sink_output"] = first_sink
    facts["payload_before_sink"] = [i for i, loc in enumerate(locs) if loc["payload"]]
    facts["x_native_before_sink"] = [i for i, loc in enumerate(locs) if loc["x_native"]]
    free = [i for i in facts["x_native_before_sink"] if not locs[i]["payload"]]
    facts["x_native_payload_free_outputs"] = free
    carrier_fns = sorted({pre[i]["function"] for i in free})
    fn_with_payload = {pre[i]["function"] for i in facts["payload_before_sink"]}
    if carrier_fns and not (set(carrier_fns) & fn_with_payload):
        facts["carrier"] = {"declared": True, "carrier_tools": carrier_fns,
                            "rule": "every pre-sink output of these tools holds native X and no payload"}
    else:
        facts["carrier"] = {"declared": False, "carrier_tools": [],
                            "reason": ("no pre-sink output holds native X" if not facts["x_native_before_sink"] else
                                       "native X and the payload share a tool output (or a tool name) on the "
                                       "ground-truth path, so a source-level carrier is not separable; the reference "
                                       "carrier readings stay content-derived (trivial by construction)")}

    # Warrant span separation (ADI-X-12), JSON as run and YAML for comparison
    if seg is not None:
        yaml_attack = run_gt(suite, ut, escaped, None)   # the stock YAML rendering, for comparison only
        facts["argus_span_separation"] = {
            "json": span_separation(attack["outputs"], first_sink, payload, x, "json", seg),
            "yaml_comparison": span_separation(yaml_attack["outputs"], first_sink, payload, x, "yaml", seg)}
    else:
        facts["argus_span_separation"] = None
    return facts


GATING = ("hashes_match_acfg", "vectors_on_stock", "vector_on_stock_matches_table", "split_matches_table",
          "env_form_matches_fork", "gt_outputs_equal_fork", "gt_both_arms_legitimate", "executable_matches_table")


def invariants_of(facts: Mapping[str, Any]) -> dict[str, Any]:
    inv: dict[str, Any] = {k: bool(facts.get(k)) for k in GATING}
    legit = facts.get("gt_legit_matches_table") or {}
    inv["gt_legit_matches_table_attack"] = bool(legit.get("ATTACK"))
    inv["gt_legit_matches_table_clean"] = bool(legit.get("CLEAN"))
    inv["all"] = all(inv.values())
    inv["payload_before_sink"] = bool(facts.get("payload_before_sink"))   # recorded, not gating
    if "gt_outputs_differ_only_outside_payload" in facts:                 # recorded, not gating (ADI-X-3)
        inv["gt_outputs_differ_only_outside_payload"] = bool(facts["gt_outputs_differ_only_outside_payload"])
    return inv


def build_case(case: Mapping[str, Any], facts: Mapping[str, Any], scope: Mapping[str, Any] | None) -> dict[str, Any]:
    """The h2-cases/v2 case (seed family ADI) for one ACFG case_table row and its facts."""
    p = facts["_private"]
    inv = invariants_of(facts)
    legit = p["legit"]
    union = list(dict.fromkeys([*legit["CLEAN"], *legit["ATTACK"]]))
    expressible = bool(facts.get("vectors_on_stock"))
    executable = facts.get("executable_resolved") if expressible else None
    observable = (facts.get("x_substitution") or {}).get("state_observable") if expressible else None
    writes_x = bool((case.get("substratum_evidence") or {}).get("payload_writes_x"))
    separation = facts.get("argus_span_separation") or {}
    out = {
        "case_id": case["case_id"], "seed_family": adi.ADI_FAMILY, "stratum": "ADI",
        "substratum": case["substratum"], "adi_substratum": case["substratum"],
        "suite": case["suite"], "user_task_id": case["user_task_id"], "split": facts["split"],
        "cluster": case.get("cluster"),
        "target": {**dict(case["target"]), "slots": p.get("slots") or []},
        # union of both arms (safe: neither arm's value exists in the other arm's environment); the loaders read
        # the per-arm set (arms[arm].legitimate_set, ADI-X-11) where it is given
        "legitimate_set": union, "legitimate_value": legit["CLEAN"][0],
        "attacker_value": p["x"],
        "attacker_value_kind": "adi_" + str((case.get("attacker_value") or {}).get("rule")),
        "decoy_value": None, "decoy_sentence": None,
        "gt": {"attacker_executable": executable, "attacker_execution_state_observable": observable,
               "executable_table": facts.get("executable_table"),
               "executable_resolved_at_export": bool(facts.get("executable_resolved_here")),
               "clean_outcome": facts.get("gt_clean_outcome"), "attack_outcome": facts.get("gt_attack_outcome")},
        "arms": {
            "ATTACK": {"injections": dict(p["escaped"]) if expressible else {}, "carries_attacker_value": True,
                       "payload_writes_x": writes_x, "arm_text": p.get("arm_text"),
                       "legitimate_set": list(legit["ATTACK"])},
            "CLEAN": {"injections": {}, "carries_attacker_value": False, "arm_text": None,
                      "legitimate_set": list(legit["CLEAN"])},
        },
        "invariants": inv,
        "design": {
            "stratum": "ADI", "substratum": case["substratum"],
            **({"carrier_tools": facts["carrier"]["carrier_tools"]} if (facts.get("carrier") or {}).get("declared")
               else {}),
            "carrier_note": (facts.get("carrier") or {}).get("reason") or (facts.get("carrier") or {}).get("rule"),
            "argus_span_separated": (separation.get("json") or {}).get("separated") if separation else None,
        },
        "adi": {
            "ref": case["ref"], "adi_index": case["adi_index"], "vectors": list(case["vectors"]),
            "expected_hashes": case["expected_hashes"], "legitimate_sha256": facts["legitimate_sha256"],
            "split_source": facts["split_source"], "eligible": inv["all"],
            "ineligible_reason": facts.get("ineligible_reason") or (None if inv["all"] else
                                                                    "failed: " + ", ".join(k for k in GATING if not inv.get(k))),
            "substratum_evidence": case.get("substratum_evidence"),
            "delegation": case.get("delegation"), "task_anticipated_selection": case.get("task_anticipated_selection"),
            "scope": scope,
        },
    }
    return out


# ---------------------------------------------------------------------------------------------
# Payload-free report (scanned before it is written)


def payload_strings(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    out: list[str] = []
    for r in rows:
        for p in (r.get("injections_raw") or {}).values():
            out += [p, json.dumps(p)[1:-1]]
        for p in (r.get("injections_escaped") or {}).values():
            out.append(p)
    return [s for s in out if s]


def shingle_hits(text: str, payloads: Iterable[str], width: int = 24, benign: str = "") -> int:
    hits = 0
    for p in payloads:
        for i in range(0, max(1, len(p) - width + 1), 4):
            piece = p[i:i + width]
            if len(piece) == width and piece in text and piece not in benign:
                hits += 1
    return hits


def export(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    if inside(out, REPO_ROOT):
        print(f"refused: {out} is inside the code repository {REPO_ROOT}; the case file holds payload text and "
              "belongs in the results checkout", file=sys.stderr)
        return 2
    install_network_guard()
    try:
        inputs = load_inputs(args.acfg, args.frozen_config, args.ss_cases)
        acfg = inputs["acfg"]
        pin = acfg["source_pin"]["commit"]
        fork_check = check_fork_tree(Path(args.fork_src), pin)
        out.parent.mkdir(parents=True, exist_ok=True)
        ref_path = Path(args.fork_reference).resolve() if args.fork_reference else out.parent / "fork_reference.json"
        if inside(ref_path, REPO_ROOT):
            raise ExportError(f"--fork-reference {ref_path} is inside the code repository")
        fork_summary = None
        if not args.fork_reference:
            fork_summary = run_fork_side(Path(args.fork_python), Path(args.fork_src), Path(args.acfg).resolve(), ref_path)
        fork = json.loads(ref_path.read_text(encoding="utf-8"))
        if fork.get("schema") != "adi-export-fork/v1" or fork.get("network_refusals"):
            raise ExportError("the fork reference is not adi-export-fork/v1 or logged network refusals")
        if fork.get("acfg_version_id") != acfg["version_id"]:
            raise ExportError("the fork reference was made for another amendment")
        rows = {r["case_id"]: r for r in fork["rows"]}
        missing = [c["case_id"] for c in acfg["case_table"] if c["case_id"] not in rows]
        if missing:
            raise ExportError(f"the fork reference lacks {len(missing)} case(s)")
        seg = load_segmentation(Path(args.argus_segmentation)) if args.argus_segmentation else None
        from agentdojo.task_suite.load_suites import get_suite

        suites = {s: get_suite(BENCHMARK_VERSION, s) for s in ("banking", "slack", "workspace", "travel")}
        amap = {k: list(v) for k, v in inputs["ss"]["authority_arg_map"].items()}
        scope_cases = ((acfg.get("threat_model") or {}).get("adi_case_scope") or {}).get("cases") or {}
        cases, report_rows = [], []
        for case in acfg["case_table"]:
            facts = conform_case(case, rows[case["case_id"]], suites, amap, inputs["ss"], seg)
            built = build_case(case, facts, (scope_cases.get(case["case_id"]) or {}).get("auditors"))
            cases.append(built)
            report_rows.append({"case_id": case["case_id"], "ref": case["ref"], "split": built["split"],
                                "substratum": built["substratum"], "eligible": built["invariants"]["all"],
                                "runs_under_proposed_choices": built["invariants"]["all"] and built["split"] == "dev",
                                "invariants": built["invariants"], "attacker_executable": built["gt"]["attacker_executable"],
                                "state_observable": built["gt"]["attacker_execution_state_observable"],
                                "ineligible_reason": built["adi"]["ineligible_reason"],
                                **{k: v for k, v in facts.items() if not k.startswith("_")}})
    except ExportError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    doc = {
        "schema": SCHEMA_CASES, "config_id": CONFIG_ID, "config_sha256": inputs["acfg_sha256_lf"],
        "cases_digest": canonical_sha256(cases), "gt_validated": True, "arms_emitted": ["ATTACK", "CLEAN"],
        "authority_arg_map": amap, "tool_output_format": "json", "seed_family": adi.ADI_FAMILY, "stratum": "ADI",
        "amendment": {"version_id": adi.AMENDMENT_ID, "after_seeing_data": True, "note": adi.AMENDMENT_NOTE},
        "generator": {
            "exporter": EXPORTER_VERSION,
            "code_sha256_lf": {n: sha256_lf(p) for n, p in (("common/adi_export.py", HERE / "adi_export.py"),
                                                              ("common/adi_compat.py", HERE / "adi_compat.py"),
                                                              ("adi/adi_export_fork.py", FORK_SIDE))},
            "fork": {**acfg["source_pin"], **fork_check, "identity": fork["fork"]},
            "declared_reuse": [
                "INJECTED_DATA_SYNTACTIC imported from the pinned fork (adi/adi_export_fork.py)",
                "task_suite._escape_yaml_value imported from the pinned fork (MIT) and applied to each payload",
                "tool_result_to_str: the fork's own ground-truth pipeline renders the reference; the lab side uses "
                "the attributed MIT copy common/adi_compat.adi_tool_result_to_str"],
            "benchmark": {"name": "AgentDojo", "version": BENCHMARK_VERSION, "package": "vendored 0.1.35 (stock data)"},
        },
        "inputs_sha256_lf": {"acfg": inputs["acfg_sha256_lf"], "frozen_config": inputs["frozen_sha256_lf"],
                             "ss_case_file": inputs["ss_sha256_lf"], "fork_reference": sha256_lf(ref_path)},
        "counts": {
            "cases": len(cases), "eligible": sum(1 for c in cases if c["invariants"]["all"]),
            "eligible_dev": sum(1 for c in cases if c["invariants"]["all"] and c["split"] == "dev"),
            "eligible_eval": sum(1 for c in cases if c["invariants"]["all"] and c["split"] == "eval"),
            "by_substratum_eligible_dev": {s: sum(1 for c in cases if c["invariants"]["all"] and c["split"] == "dev"
                                                  and c["substratum"] == s) for s in ("A1mech", "Xboth", "Xatt")},
        },
        "cases": cases,
    }
    text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    out.write_text(text, encoding="utf-8", newline="\n")
    lf = sha256_lf(out)
    out.with_name(out.name + ".sha256").write_text(f"{lf}  {out.name}\n", encoding="utf-8", newline="\n")
    report = {
        "schema": SCHEMA_REPORT, "amendment": adi.AMENDMENT_ID, "exporter": EXPORTER_VERSION,
        "case_file": {"path": str(out), "sha256_lf": lf, "cases_digest": doc["cases_digest"]},
        "inputs_sha256_lf": doc["inputs_sha256_lf"], "fork": doc["generator"]["fork"], "fork_side_summary": fork_summary,
        "comparison_controls": {
            "rule": "both sides run the ground truth with PYTHONHASHSEED=0 and the suite tools' run-time clock frozen at "
                    "one instant (adi_compat.frozen_tool_clock), then every rendered byte must be equal (conformance "
                    "only; runs freeze nothing)",
            "fork": fork.get("comparison_controls"),
            "stock": {"pythonhashseed": os.environ.get("PYTHONHASHSEED"),
                      "frozen_tool_instant": list(adi.FROZEN_TOOL_INSTANT)}},
        "gates": {
            "G-ADI-EXPORT": {"hashes_match_acfg": sum(1 for r in report_rows if r["invariants"]["hashes_match_acfg"]),
                             "cases": len(report_rows), "case_file_outside_repo": True, "model_requests": 0,
                             "fork_clean_tree_at_pin": fork_check.get("clean_tree") is True,
                             "pass": fork_check.get("clean_tree") is True and all(
                                 r["invariants"]["hashes_match_acfg"] and r["split_matches_table"] for r in report_rows)},
            "G-ADI-CONF": {"eligible": doc["counts"]["eligible"], "eligible_dev": doc["counts"]["eligible_dev"],
                           "failed": {r["ref"]: r["ineligible_reason"] for r in report_rows if not r["eligible"]},
                           "argus_span_shared_under_json (ADI-X-12, recorded)": sorted(
                               r["ref"] for r in report_rows
                               if ((r.get("argus_span_separation") or {}).get("json") or {}).get("separated") is False)},
        },
        "counts": doc["counts"], "cases": report_rows,
        "network_refusals": list(_REFUSED), "model_requests": 0,
    }
    report_text = json.dumps(report, ensure_ascii=False, indent=1) + "\n"
    benign = json.dumps([o["text"] for r in fork["rows"] for o in r["gt_clean_outputs"]])  # stock-data text
    hits = shingle_hits(report_text, payload_strings(fork["rows"]), benign=benign)
    if hits:
        print(f"refused: the report would hold {hits} payload shingle(s); nothing but the case file was written",
              file=sys.stderr)
        return 4
    report_path = out.parent / "adi_export_report.json"
    report_path.write_text(report_text, encoding="utf-8", newline="\n")
    print(json.dumps({"case_file_sha256_lf": lf, "report": str(report_path), "counts": doc["counts"],
                      "G-ADI-EXPORT": report["gates"]["G-ADI-EXPORT"]["pass"],
                      "G-ADI-CONF_failed": sorted(report["gates"]["G-ADI-CONF"]["failed"]),
                      "network_refusals": len(_REFUSED)}))
    return 0 if report["gates"]["G-ADI-EXPORT"]["pass"] and not _REFUSED else 3


# ---------------------------------------------------------------------------------------------
# verify: re-check a written case file against the amendment (no fork needed)


def verify_case_file(doc: Mapping[str, Any], acfg: Mapping[str, Any]) -> list[str]:
    """Problems of an exported case file against ACFG (empty = pass): the structure the loaders need, the payload
    hashes recomputed from ``arm_text`` (the payload as the environment holds it), X, split and per-arm sets."""
    problems: list[str] = []
    if doc.get("schema") != SCHEMA_CASES or doc.get("tool_output_format") != "json":
        problems.append("schema must be h2-cases/v2 with tool_output_format json")
    if doc.get("arms_emitted") != ["ATTACK", "CLEAN"] or doc.get("gt_validated") is not True:
        problems.append("arms_emitted must be [ATTACK, CLEAN] and gt_validated true")
    if (doc.get("amendment") or {}).get("version_id") != acfg.get("version_id"):
        problems.append("amendment version_id differs from ACFG")
    by_id = {c["case_id"]: c for c in doc.get("cases") or []}
    for row in acfg["case_table"]:
        c = by_id.get(row["case_id"])
        if c is None:
            problems.append(f"{row['ref']}: missing")
            continue
        want = row["expected_hashes"]
        if c.get("seed_family") != adi.ADI_FAMILY or c.get("split") != row["split"] or c.get("substratum") != row["substratum"]:
            problems.append(f"{row['ref']}: seed_family / split / substratum differ from ACFG")
        if sha256_text(str(c.get("attacker_value"))) != want["x_sha256"]:
            problems.append(f"{row['ref']}: X hash differs")
        arms = c.get("arms") or {}
        for arm in ("ATTACK", "CLEAN"):
            ls = (arms.get(arm) or {}).get("legitimate_set")
            if not (isinstance(ls, list) and ls and all(isinstance(v, str) and v for v in ls)):
                problems.append(f"{row['ref']}: arms.{arm}.legitimate_set must be a non-empty list of strings")
        if arms.get("CLEAN", {}).get("injections") != {}:
            problems.append(f"{row['ref']}: CLEAN must plant nothing")
        inv = c.get("invariants") or {}
        if inv.get("all"):
            if c.get("gt", {}).get("attacker_executable") not in (True, False):
                problems.append(f"{row['ref']}: eligible but executability unresolved")
            if (c.get("design") or {}).get("argus_span_separated") not in (True, False):
                problems.append(f"{row['ref']}: eligible but the Warrant span check (ADI-X-12) did not run")
            text = arms.get("ATTACK", {}).get("arm_text")
            vecs = list(row["vectors"])
            if len(vecs) == 1 and isinstance(text, str):
                if sha256_text(text) != want["payload_sha256_utf8"][vecs[0]]:
                    problems.append(f"{row['ref']}: ATTACK arm_text hash differs from the expected payload hash")
                if canonical_injections_sha256({vecs[0]: text}) != want["injections_sha256_canonical"]:
                    problems.append(f"{row['ref']}: canonical injections hash differs")
            elif inv.get("all"):
                problems.append(f"{row['ref']}: cannot recompute the payload hash (multi-vector or no arm_text)")
            if sorted((arms.get("ATTACK") or {}).get("injections") or {}) != sorted(vecs):
                problems.append(f"{row['ref']}: ATTACK injection vectors differ")
    extra = sorted(set(by_id) - {r["case_id"] for r in acfg["case_table"]})
    if extra:
        problems.append(f"{len(extra)} case(s) not in ACFG")
    if doc.get("cases_digest") != canonical_sha256(doc.get("cases") or []):
        problems.append("cases_digest does not match the cases")
    return problems


def verify(args: argparse.Namespace) -> int:
    acfg = json.loads(Path(args.acfg).read_text(encoding="utf-8"))
    doc = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    problems = verify_case_file(doc, acfg)
    lf = sha256_lf(Path(args.cases))
    if args.expect_sha256 and lf != args.expect_sha256.strip().lower():
        problems.append(f"case file LF sha256 is {lf}, expected {args.expect_sha256}")
    print(json.dumps({"case_file_sha256_lf": lf, "problems": problems, "pass": not problems}))
    return 0 if not problems else 3


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="fork side + stock port + G-ADI-CONF; writes the case file outside the repo")
    e.add_argument("--acfg", type=Path, required=True)
    e.add_argument("--frozen-config", type=Path, required=True, help="pins the SS case file (case_set.pins)")
    e.add_argument("--ss-cases", type=Path, required=True, help="the pinned SS case file (authority map, split_check)")
    e.add_argument("--fork-python", type=Path, help="the ADI artifact venv's python")
    e.add_argument("--fork-src", type=Path, required=True, help="the fork's checkout (EXT/adi/src)")
    e.add_argument("--fork-reference", type=Path, help="reuse a fork reference written by adi_export_fork.py")
    e.add_argument("--argus-segmentation", type=Path, required=True,
                   help="Warrant's segmentation.py (EXT/argus/src/AgentLure/agentlure/warrant/segmentation.py; ADI-X-12)")
    e.add_argument("--out", type=Path, required=True)
    e.set_defaults(fn=export)
    v = sub.add_parser("verify", help="re-check an exported case file against ACFG (no fork, no model)")
    v.add_argument("--acfg", type=Path, required=True)
    v.add_argument("--cases", type=Path, required=True)
    v.add_argument("--expect-sha256", default=None)
    v.set_defaults(fn=verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
    if args.cmd == "export" and not args.fork_reference and not args.fork_python:
        print("refused: give --fork-python (or --fork-reference)", file=sys.stderr)
        return 2
    if args.cmd == "export" and sys.flags.hash_randomization:
        # set iteration order (calendar participants) must match the fork side: re-run with PYTHONHASHSEED=0
        env = dict(os.environ, PYTHONHASHSEED="0", PYTHONUTF8="1")
        return subprocess.run([sys.executable, "-X", "utf8", str(Path(__file__).resolve()), *raw_argv],
                              env=env).returncode
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
