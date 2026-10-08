"""PACT/SIEVE-style origin-admission rule over recorded traces (zero model calls).

For every proposed call of a role-table function, each authority value element is
admitted iff it originates from an admissible source: the user prompt (or another
trusted origin of the reading) or a tool result whose trust level reaches the role
minimum. Origins are found by exact structural match first, then by the reading's
declared normalisation (``reference_config.json`` origin_rule). The call is allowed
iff every element is admitted (PACT Alg. 1).

Labellings: ``native`` is the reading's own trust table with no carrier override
(the faithful row, protocol 4.6); ``carrier_untrusted`` / ``carrier_trusted`` move
the case's carrier sources to the reading's lowest / admissible level. A carrier
labelling is only meaningful when the case declares its carrier (A1); on a
content-derived carrier (SS) its rows are tagged ``trivial_on_SS`` and kept out of
the summaries (``ref_trace.carrier_scope``).

This is a reference row: scored on D1 approval only and never described as
"defeated" (protocol 2.5 / 3.2). Standard library plus the lab helpers; the
structural stage uses PyYAML when present (lab venv).
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ref_common import SCHEMA_CALL, ReferenceError
from ref_trace import (
    authority_values,
    carrier_scope,
    carrier_source_ids,
    match_stage,
    proposals,
    sources_before,
    value_role,
)

AUDITOR = "origin_rule"
LABELLINGS = ("native", "carrier_untrusted", "carrier_trusted")
CARRIER_LABELLINGS = ("carrier_untrusted", "carrier_trusted")


def labelling_tags(labelling: str, spec: Mapping[str, Any] | None) -> dict[str, Any]:
    """``carrier_scope`` and ``trivial_on_SS`` of one (labelling, case) row."""
    scope = carrier_scope(spec) if labelling in CARRIER_LABELLINGS else None
    return {"carrier_scope": scope, "trivial_on_SS": scope == "content_derived"}


def resolve_reading(config: Mapping[str, Any], name: str) -> dict[str, Any]:
    readings = config["origin_rule"]["readings"]
    if name not in readings:
        raise ReferenceError(f"unknown origin-rule reading {name!r}")
    reading = copy.deepcopy(readings[name])
    parent = reading.pop("inherits", None)
    if parent:
        base = resolve_reading(config, parent)
        base.update(reading)
        reading = base
    lattice = reading["lattice"]
    levels = [*reading["origin_levels"].values(), reading["tool_default"], *reading["tool_levels"].values(),
              *reading["role_min"].values(), reading["carrier_trusted_level"], reading["carrier_untrusted_level"]]
    unknown = sorted({lv for lv in levels if lv not in lattice})
    if unknown:
        raise ReferenceError(f"reading {name}: levels {unknown} not in lattice {lattice}")
    if reading["multi_match"] not in ("any", "min_with_origin_precedence"):
        raise ReferenceError(f"reading {name}: unknown multi_match {reading['multi_match']!r}")
    reading["name"] = name
    return reading


def _rank(reading: Mapping[str, Any], level: str) -> int:
    return reading["lattice"].index(level)


def source_level(source: Mapping[str, Any], reading: Mapping[str, Any], *, carriers: set[str],
                 labelling: str) -> str:
    if source["kind"] == "user":
        return reading["origin_levels"]["user_prompt"]
    if source["kind"] == "system":
        return reading["origin_levels"]["system_prompt"]
    if source.get("error"):
        return reading["lattice"][0]  # never reached by admit_value (error texts are not origins)
    if labelling in CARRIER_LABELLINGS and source["source_id"] in carriers:
        return reading["carrier_trusted_level"] if labelling == "carrier_trusted" else reading["carrier_untrusted_level"]
    return reading["tool_levels"].get(source.get("tool"), reading["tool_default"])


def admit_value(value: str, kind: str | None, sources: Sequence[Mapping[str, Any]], reading: Mapping[str, Any], *,
                carriers: set[str], labelling: str) -> dict[str, Any]:
    """Admission of one authority value element; returns the decision and its evidence."""
    role_min = reading["role_min"].get(kind or "", reading["role_min"]["default"])
    min_rank = _rank(reading, role_min)
    structural_only = set(reading.get("structural_only_tools") or [])
    seen: list[dict[str, Any]] = []
    for stage in reading["stages"]:
        hits = []
        for s in sources:
            if s.get("error"):
                continue  # an error text echoes the agent's own argument back; it is not an origin
            ev = match_stage(value, kind, s["text"], stage, structured=s["kind"] == "tool")
            if ev is None:
                continue
            if s["kind"] == "tool" and s.get("tool") in structural_only and ev["evidence"] != "structured_scalar_equal":
                continue  # typed-contract Field binding needs structural equality
            level = source_level(s, reading, carriers=carriers, labelling=labelling)
            hits.append({"source_id": s["source_id"], "kind": s["kind"], "tool": s.get("tool"), "stage": stage,
                         "level": level, "evidence": ev["evidence"], "carrier": s["source_id"] in carriers})
        if not hits:
            continue
        seen.extend(hits)
        ranks = [_rank(reading, h["level"]) for h in hits]
        if reading["multi_match"] == "any":
            # Existential containment: any admissible occurrence at any stage admits.
            if max(ranks) >= min_rank:
                return {"admitted": True, "stage": stage, "role_min": role_min, "matches": seen,
                        "basis": "some matching source reaches the role minimum", "route": f"admit_{stage}"}
            continue
        origin_ok = [h for h in hits if h["kind"] in ("user", "system") and _rank(reading, h["level"]) >= min_rank]
        if origin_ok:
            admitted, basis = True, "trusted-origin precedence (PACT Alg. 2 step 1)"
        else:
            admitted = min(ranks) >= min_rank
            basis = ("all matching tool fields reach the role minimum" if admitted
                     else "ambiguous or low-trust provenance -> conservative label (PACT Alg. 2)")
        # PACT Alg. 2: the first stage that finds any provenance decides.
        return {"admitted": admitted, "stage": stage, "role_min": role_min, "basis": basis, "matches": hits,
                "route": f"admit_{stage}" if admitted else f"deny_{stage}"}
    if seen:
        return {"admitted": False, "stage": seen[-1]["stage"], "role_min": role_min, "matches": seen,
                "basis": "no matching source reaches the role minimum", "route": "deny_low_trust"}
    return {"admitted": False, "stage": None, "role_min": role_min, "matches": [],
            "basis": "no origin found at any stage -> conservative low trust", "route": "deny_no_origin"}


def evaluate_trace(trace: Mapping[str, Any], *, config: Mapping[str, Any], reading_name: str, labelling: str,
                   authority_args: Mapping[str, Sequence[str]], kinds: Mapping[str, Mapping[str, str]],
                   spec: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Call decisions (with per-element records) for every role-table proposal in a trace."""
    if labelling not in LABELLINGS:
        raise ReferenceError(f"unknown labelling {labelling!r}")
    reading = resolve_reading(config, reading_name)
    tags = labelling_tags(labelling, spec)
    out = []
    for p in proposals(trace):
        if p["function"] not in authority_args:
            continue
        values = authority_values(p["function"], p["args"], authority_args)
        sources = sources_before(trace, p["msg_index"])
        carriers = carrier_source_ids(sources, spec) if labelling in CARRIER_LABELLINGS else set()
        elements = []
        for v in values:
            kind = (kinds.get(p["function"]) or {}).get(v["argument"])
            decision = admit_value(v["value"], kind, sources, reading, carriers=carriers, labelling=labelling)
            elements.append({**v, "value_kind": kind, "value_role": value_role(v["value"], spec), **decision})
        allowed = all(e["admitted"] for e in elements)
        out.append({
            "schema": SCHEMA_CALL, "auditor": AUDITOR, "reading": reading_name, "labelling": labelling,
            "trace_id": trace["trace_id"], "proposal_id": p["proposal_id"], "msg_index": p["msg_index"],
            "position": p["position"], "function": p["function"], "executed": p["executed"], "success": p["success"],
            "verdict": "pass" if allowed else "block",
            "route": "no_authority_values" if not elements else ("admit_all" if allowed else "deny_some"),
            "elements": elements, "carrier_source_ids": sorted(carriers), **tags,
            "visible_tool_sources": sum(1 for s in sources if s["kind"] == "tool"),
            "prefix_exact": trace.get("prefix_exact"),
            "reported_value_sources": sorted({m["source_id"] for e in elements for m in e["matches"]}),
            "reported_steering_sources": "NOT_REPORTED",
        })
    return out
