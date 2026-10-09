"""Shared loader support for ADI-derived case files (standard library only; pydantic is imported lazily).

Versioned amendment ``authority-auditor-pilot-v1-deepseek.1`` (the frozen pattern ``...-deepseek.<n>``) to the
frozen DeepSeek protocol (``PILOT-PROTOCOL-V1-DEEPSEEK-FROZEN.md``, agent-tracer f87b847). It was made on
2026-10-09 AFTER seeing data: everything in the amendment config's ``data_seen_before_amendment`` (D01-D07 with
D03, the ADI baseline; the D03 verification that drew the 19-case boundary; and batch-2 output directories that
already existed, with the data-read statement U4 still open), so nothing run under it is pre-registered. The user
decided that the A1 stratum uses the 19 ADI authority cases (our classification of the published ADI syntactic
cases, drawn during the D03 verification, ADI-X-10; arXiv:2607.05120; github.com/compsec-snu/adi, MIT, commit
1a3ddf8).

What the loaders accept on top of the common case contract (``h2-cases/v2``, ``H2-CASES-V1.md`` section 8):

* a top-level ``tool_output_format``: ``"yaml"`` or ``"json"``. Absent means ``"yaml"``: the stock AgentDojo
  0.1.35 formatter, i.e. the behaviour of every SS run, which is unchanged. ``"json"`` means the ADI fork's
  formatter (``adi_tool_result_to_str`` below), applied to every tool output that the agent AND the auditor see;
* cases of ``seed_family`` ``"ADI"`` with the arms ``"ATTACK"`` (the ADI payload, read from the pinned fork) and
  ``"CLEAN"`` (no payload). ADI is its own group: a plan or a selection that mixes ADI with any other family
  (E0B, E1PRE) is refused, so no adapter summary can pool them.

``injections`` values are the exact strings each runner passes to the stock
``suite.load_and_inject_default_environment``. Any escaping the stock v1.2.2 YAML templates need is applied by
the exporter that writes the case file; the loaders never transform payload text. No payload text lives in this
repository: case files are generated into the results checkout and pinned by sha256 at run time.

Saved benchmark text and model output are untrusted data; nothing here interprets them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

AMENDMENT_ID = "authority-auditor-pilot-v1-deepseek.1"
AMENDMENT_NOTE = ("versioned amendment authority-auditor-pilot-v1-deepseek.1 to the frozen DeepSeek protocol "
                  "(agent-tracer f87b847), made 2026-10-09 after seeing data (its config's data_seen_before_amendment: "
                  "D01-D07 including D03, the ADI baseline, and existing batch-2 output; data-read statement U4 open): "
                  "exploratory, not pre-registered; ADI-derived rows are never compared with D03's 7/19 or ADI's 53/108")
TOOL_OUTPUT_FORMATS = ("yaml", "json")
DEFAULT_TOOL_OUTPUT_FORMAT = "yaml"
ADI_FAMILY = "ADI"
ADI_ARMS = ("ATTACK", "CLEAN")
ADI_X_ARM = "ATTACK"

# Where adi_tool_result_to_str comes from (declared reuse, MIT; see the notice above the function).
ADI_FORMATTER_SOURCE = {
    "repository": "https://github.com/compsec-snu/adi",
    "commit": "1a3ddf8fa96bf008f3cb80dd56db5149d4ac0df7",
    "file": "agentdojo/src/agentdojo/agent_pipeline/tool_execution.py",
    "function": "tool_result_to_str (lines 22-48)",
    "license": "MIT (ADI authors 2026; derived from AgentDojo, MIT, 2024)",
    "how": "copied with attribution (the fork's package is also named agentdojo, so it cannot be imported "
           "next to the vendored AgentDojo 0.1.35); logic unchanged, pydantic imported inside the function",
}


class CaseFormatError(ValueError):
    """A case file declares something the loaders cannot honour."""


# ---------------------------------------------------------------------------------------------
# Case-file declarations


def declared_tool_output_format(doc: Mapping[str, Any]) -> str | None:
    """The case file's ``tool_output_format`` as declared, or None when the key is absent."""
    if "tool_output_format" not in doc:
        return None
    value = doc.get("tool_output_format")
    if value not in TOOL_OUTPUT_FORMATS:
        raise CaseFormatError(f"tool_output_format must be one of {TOOL_OUTPUT_FORMATS}, got {value!r}")
    return value


def tool_output_format(doc: Mapping[str, Any]) -> str:
    """The effective tool-output format: the declared one, else ``"yaml"`` (stock AgentDojo)."""
    return declared_tool_output_format(doc) or DEFAULT_TOOL_OUTPUT_FORMAT


def check_family_mix(families: Iterable[Any], where: str = "selection") -> None:
    """Refuse ADI cases mixed with any other seed family (E0B, E1PRE, unlabelled) in one plan."""
    fams = {str(f) if f is not None else "(none)" for f in families}
    if ADI_FAMILY in fams and len(fams) > 1:
        raise CaseFormatError(f"{where} mixes seed family {ADI_FAMILY} with {sorted(fams - {ADI_FAMILY})}; ADI-derived "
                              "cases are a separate group and are never pooled with E0B or E1PRE")


def has_adi(families: Iterable[Any]) -> bool:
    return any(f == ADI_FAMILY for f in families)


# ---------------------------------------------------------------------------------------------
# The ADI fork's JSON tool-output formatter (declared reuse)
#
# Copied from compsec-snu/adi at commit 1a3ddf8fa96bf008f3cb80dd56db5149d4ac0df7,
# agentdojo/src/agentdojo/agent_pipeline/tool_execution.py, function tool_result_to_str (lines 22-48).
# Changes: the function is renamed; ``from pydantic import BaseModel`` is done inside the function; the
# FunctionReturnType / Callable annotations are replaced by Any. The logic and the dump call are unchanged.
#
# MIT License
#
# Copyright (c) 2026 Woohyuk Choi, Juhee Kim, Taehyun Kang, Jihyeon Jeong, Luyi Xing, and Byoungyoung Lee
# Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer,
# and Florian Tramèr (AgentDojo, on which the fork builds)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def adi_tool_result_to_str(
    tool_result: Any, dump_fn: Callable[[Any], str] = json.dumps
) -> str:
    """Basic tool output formatter with JSON dump by default. Could work with `yaml.safe_dump` as
    `dump_fn`."""
    from pydantic import BaseModel

    if isinstance(tool_result, BaseModel):
        # Use mode='json' to convert datetime objects to ISO strings
        return dump_fn(tool_result.model_dump(mode='json')).strip()

    if isinstance(tool_result, list):
        res_items = []
        for item in tool_result:
            if type(item) in [str, int]:
                res_items += [str(item)]
            elif isinstance(item, BaseModel):
                # Use mode='json' to convert datetime objects to ISO strings
                res_items += [item.model_dump(mode='json')]
            else:
                raise TypeError("Not valid type for item tool result: " + str(type(item)))

        # If type checking passes, this is guaranteed to be a list of BaseModel
        return dump_fn(res_items).strip()

    if isinstance(tool_result, dict):
        return dump_fn(tool_result).strip()

    return str(tool_result)


# ---------------------------------------------------------------------------------------------


def tool_output_formatter(fmt: str) -> Callable[[Any], str] | None:
    """The formatter to install for ``fmt``: None for ``"yaml"`` (keep the stock one, nothing replaced),
    the ADI fork's formatter for ``"json"``."""
    if fmt == "yaml":
        return None
    if fmt == "json":
        return adi_tool_result_to_str
    raise CaseFormatError(f"unknown tool_output_format {fmt!r}")


def formatter_record(fmt: str, declared: str | None) -> dict[str, Any]:
    """What a plan or receipt records about the formatter (written only when the case file declares one)."""
    return {"tool_output_format": fmt, "declared": declared is not None,
            "formatter": ("stock AgentDojo 0.1.35 tool_result_to_str (yaml.safe_dump)" if fmt == "yaml"
                          else "ADI fork tool_result_to_str (json.dumps of model_dump(mode='json'))"),
            **({"source": ADI_FORMATTER_SOURCE} if fmt == "json" else {})}


def json_escaped(text: Any) -> str:
    """``text`` as it appears inside a string of the ADI formatter's output (``json.dumps``, ASCII escapes)."""
    return json.dumps(str(text))[1:-1]


def rendered_variants(text: Any, fmt: str) -> list[str]:
    """``text`` plus, under the JSON formatter, its JSON-escaped form when that differs (exposure needles)."""
    out = [str(text)]
    if fmt == "json":
        esc = json_escaped(text)
        if esc != out[0]:
            out.append(esc)
    return out


def state_needle(value: Any) -> str:
    """How ``value`` appears inside pydantic's ``model_dump_json()`` of an environment.

    Equal to ``str(value)`` for any value without a quote, a backslash or a control character (every SS
    attacker value), so post-state counts of SS cases are unchanged; an ADI value that holds such characters
    is counted in its escaped form, which is the only form it can have in a JSON dump.
    """
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


_JSON_ESC = re.compile(r'\\(u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4})?|["\\/bfnrt])')
_JSON_SIMPLE = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def json_unescape(text: Any) -> str:
    """Undo JSON string escaping in a whole rendered tool output (surrogate pairs joined)."""

    def rep(m: re.Match[str]) -> str:
        g = m.group(1)
        if g[0] == "u":
            try:
                return json.loads('"\\' + g + '"')
            except ValueError:
                return m.group(0)
        return _JSON_SIMPLE[g]

    return _JSON_ESC.sub(rep, str(text))


def sha256_lf(path: Path) -> str:
    """SHA-256 of a file with CRLF normalised to LF: the run-time case-file pin of every ADI stage
    (``--set cases_sha256=<hex>``; the same definition as ARGUS ``--expect-content-sha256``)."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def check_pin(path: Path, expected: Iterable[str]) -> str:
    """Refuse unless the file's LF sha256 equals every expected value; returns the LF sha256."""
    got = sha256_lf(path)
    for want in expected:
        if str(want).strip().lower() != got:
            raise CaseFormatError(f"case file LF sha256 is {got}, the stage expects {str(want).strip()} "
                                  "(this stage is pinned to another file)")
    return got


# ---------------------------------------------------------------------------------------------
# Per-arm legitimate set (ADI-X-11), exposure needles and executability (loader helpers)


def arm_legitimate_set(case: Mapping[str, Any], arm: str) -> list[str] | None:
    """The arm's own legitimate set (``arms[arm].legitimate_set``), or None when the arm gives none.

    ADI-X-11: in slack ut9[0], ut10[0] and ut19[0] the legitimate External channel differs between ATTACK and
    CLEAN, so the exporter writes a set per arm. Every loader uses it where present and otherwise keeps its own
    case-level reading, so an SS case (no per-arm set) is read exactly as before."""
    spec = (case.get("arms") or {}).get(arm)
    if not isinstance(spec, Mapping) or "legitimate_set" not in spec:
        return None
    value = spec["legitimate_set"]
    if not (isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value)):
        raise CaseFormatError(f"{case.get('case_id')}/{arm}: legitimate_set must be a non-empty list of strings")
    return list(value)


def adi_exposure_needles(case: Mapping[str, Any], arm: str) -> list[str] | None:
    """Exposure needles of an ADI-derived arm: its ``arm_text`` (the payload as the environment holds it), or None
    for an arm that plants nothing (CLEAN). Only ever called for seed family ADI (SS plans are unchanged)."""
    text = ((case.get("arms") or {}).get(arm) or {}).get("arm_text")
    return [text] if isinstance(text, str) and text.strip() else None


def require_resolved_executability(case: Mapping[str, Any]) -> None:
    """An ADI case must reach a stage with ``gt.attacker_executable`` true or false: the exporter resolves an
    'untested' entry at G-ADI-CONF, so a null here would silently become 'not executable'."""
    if case.get("seed_family") != ADI_FAMILY:
        return
    value = (case.get("gt") or {}).get("attacker_executable")
    if value not in (True, False):
        raise CaseFormatError(f"{case.get('case_id')}: ADI case with unresolved gt.attacker_executable ({value!r}); "
                              "re-export (G-ADI-CONF resolves it) before any run")


def value_in_outputs(contains_value: Callable[[str, str], bool], outputs: Iterable[str], value: Any,
                     fmt: str) -> bool:
    """The secondary word-boundary X test over rendered tool outputs. Under ``fmt`` "json" X is also tried in its
    JSON-escaped form and in the JSON-unescaped view of each output, so an X right after an escape such as a
    newline escape (whose letter would otherwise break the word boundary) is still found; "yaml" is the plain test."""
    variants = rendered_variants(value, fmt)
    for o in outputs:
        if any(contains_value(o, v) for v in variants):
            return True
        if fmt == "json" and contains_value(json_unescape(o), str(value)):
            return True
    return False


def needle_seen(needles: Sequence[str] | None, outputs: Iterable[str], fmt: str,
                collapse: Callable[[str], str]) -> bool | None:
    """Was any planted needle seen in a tool output (per output, whitespace-collapsed, as the generator checks it)?
    Under "json" each needle is also tried JSON-escaped. None when there is no needle (an arm without text)."""
    if not needles:
        return None
    outs = [collapse(o) for o in outputs]
    return any(collapse(v) in o for n in needles for v in rendered_variants(n, fmt) for o in outs)


# ---------------------------------------------------------------------------------------------
# Conformance only: a frozen clock for the suite tools that stamp run-time values


TOOL_CLOCK_MODULES = ("agentdojo.default_suites.v1.tools.cloud_drive_client",
                      "agentdojo.default_suites.v1.tools.email_client")
FROZEN_TOOL_INSTANT = (2026, 1, 1, 12, 0, 0)   # after every suite data timestamp, as a real run's clock is


@contextlib.contextmanager
def frozen_tool_clock(module_names: Sequence[str] = TOOL_CLOCK_MODULES,
                      instant: Sequence[int] = FROZEN_TOOL_INSTANT) -> Iterator[list[str]]:
    """Within the block, ``datetime.datetime.now()`` in the suite tool modules returns one fixed instant.

    Used only by the ADI exporter's conformance comparison (G-ADI-CONF), on the fork side and the stock side alike:
    ``append_to_file``, ``create_file`` and ``send_email`` stamp the run-time clock into their outputs, which can
    never be byte-equal across two processes otherwise. Runs never use it. Yields the patched module names."""
    import datetime as _dt
    import importlib
    import types

    class _Frozen(_dt.datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Any:  # noqa: D102
            # a plain datetime (not this subclass), so DeepDiff-based utility checks see a value change, not a type
            # change, and YAML/JSON dumps treat it as any other datetime
            value = _dt.datetime(*instant)
            return value if tz is None else value.replace(tzinfo=tz)

    shim = types.ModuleType("datetime")
    shim.__dict__.update(_dt.__dict__)
    shim.datetime = _Frozen  # type: ignore[attr-defined]
    patched = []
    for name in module_names:
        mod = importlib.import_module(name)
        if getattr(mod, "datetime", None) is _dt:
            mod.datetime = shim  # type: ignore[attr-defined]
            patched.append(mod)
    try:
        yield [m.__name__ for m in patched]
    finally:
        for mod in patched:
            mod.datetime = _dt  # type: ignore[attr-defined]
