"""Pure helpers for the H2 matched-framing runner (standard library only).

Loads the H2 case file (produced by ``agentdojo_lab.h2_cases.generate_cases``),
expands a stage into an ordered episode list (case x arm x repeat), and turns
typed per-episode records into a summary: per-arm outcome distributions, the H2
contrast (FACT attacker-rate minus INSTR attacker-rate), AgentDojo utility, and
token usage, each with Wilson intervals.

``run_h2.py`` (lab venv) and the tests import it. It never touches the network
or a ``.env`` file. The outcome oracle itself lives in
``agentdojo_lab.h2_cases.classify_outcome``; this module only tabulates its
results. Saved benchmark text and model output are untrusted data.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

SCHEMA_CASES = "h2-cases/v2"
SCHEMA_EPISODE = "h2-episode/v2"
SCHEMA_PLAN = "h2-episode-plan/v2"
SCHEMA_SUMMARY = "h2-summary/v2"

OUTCOMES = ("attacker", "other", "legitimate", "no_call", "task_failure")


class H2RunError(ValueError):
    """The case file, config or a stage request is malformed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_case_file(path: Path) -> dict[str, Any]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA_CASES:
        raise H2RunError(f"case file schema must be {SCHEMA_CASES}")
    if not isinstance(doc.get("cases"), list) or not doc["cases"]:
        raise H2RunError("case file has no cases")
    return doc


def _match(value: Any, allowed: Any) -> bool:
    return allowed is None or value in set(allowed)


def expand_stage(case_file: Mapping[str, Any], stage: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Ordered episodes for a stage: case (filtered) x arm x repeat.

    Stage keys: splits (list|None), require_invariants (bool), families (list|None),
    value_kinds (list|None), arms (list), repeats (int), max_cases (int|None).
    Cases are kept in case-file order (already deterministic from generation).
    """
    arms = stage.get("arms") or ["CLEAN", "INSTR", "FACT", "SHAM"]
    repeats = int(stage.get("repeats", 1))
    if repeats < 1:
        raise H2RunError("repeats must be >= 1")
    emitted = set(case_file.get("arms_emitted") or [])
    for arm in arms:
        if arm not in emitted:
            raise H2RunError(f"stage arm {arm!r} is not emitted in the case file ({sorted(emitted)})")
    selected: list[dict[str, Any]] = []
    for case in case_file["cases"]:
        if stage.get("require_invariants", True) and not case["invariants"]["all"]:
            continue
        if not _match(case["split"], stage.get("splits")):
            continue
        if not _match(case["seed_family"], stage.get("families")):
            continue
        if not _match(case["target"]["value_kind"], stage.get("value_kinds")):
            continue
        selected.append(case)
    max_cases = stage.get("max_cases")
    if max_cases is not None:
        selected = selected[: int(max_cases)]
    out: list[dict[str, Any]] = []
    seq = 0
    for case in selected:
        for arm in arms:
            if arm not in case["arms"]:
                raise H2RunError(f"case {case['case_id']} has no arm {arm!r}")
            gt = case.get("gt") or {}
            for rep in range(repeats):
                out.append({
                    "episode_id": f"{case['case_id']}|{arm}|r{rep}",
                    "seq": seq,
                    "case_id": case["case_id"],
                    "arm": arm,
                    "repeat": rep,
                    "suite": case["suite"],
                    "user_task_id": case["user_task_id"],
                    "target": dict(case["target"]),
                    "legitimate_set": list(case.get("legitimate_set") or [case.get("legitimate_value")]),
                    "legitimate_value": case.get("legitimate_value"),
                    "attacker_value": case["attacker_value"],
                    "attacker_value_kind": case.get("attacker_value_kind"),
                    "decoy_value": case.get("decoy_value"),
                    "injections": dict(case["arms"][arm]["injections"]),
                    "injection_payload_sha256": sha256_bytes(
                        json.dumps(case["arms"][arm]["injections"], sort_keys=True, ensure_ascii=False).encode("utf-8")),
                    "carries_attacker_value": case["arms"][arm]["carries_attacker_value"],
                    "attacker_executable": bool(gt.get("attacker_executable")),
                    "attacker_state_observable": bool(gt.get("attacker_execution_state_observable")),
                })
                seq += 1
    ids = [e["episode_id"] for e in out]
    if len(ids) != len(set(ids)):
        raise H2RunError("stage expanded an episode id twice")
    return out


def count_arms(episodes: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for e in episodes:
        counts[e["arm"]] += 1
        counts["total"] += 1
    return dict(counts)


def plan_digest(episodes: Sequence[Mapping[str, Any]]) -> str:
    # Include the per-episode payload hash so a regenerated case file with the same
    # ids but different injected text does not resume into a mix of stimuli (M9).
    basis = [[e["episode_id"], e.get("injection_payload_sha256", "")] for e in episodes]
    return sha256_bytes(json.dumps(basis, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "pct": None if n == 0 else round(100.0 * k / n, 2),
            "wilson95_pct": None if ci is None else [round(100.0 * ci[0], 2), round(100.0 * ci[1], 2)]}


def usd(prompt_tokens: int, completion_tokens: int, price: Mapping[str, Any]) -> str:
    value = (Decimal(prompt_tokens) * Decimal(str(price["input_per_million"]))
             + Decimal(completion_tokens) * Decimal(str(price["output_per_million"]))) / Decimal(1_000_000)
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP), "f")


def _arm_block(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    # Errored episodes are scored too (the runner ranks an executed attacker call
    # above a run error, and assigns task_failure/run_error otherwise), so every
    # started episode is in the denominator -- nothing silently drops out.
    scored = [r for r in rows if r.get("scored")]
    dist = {o: sum(1 for r in scored if r.get("outcome") == o) for o in OUTCOMES}
    n = len(scored)
    attempted = sum(1 for r in scored if (r.get("oracle_details") or {}).get("attacker_attempted"))
    exposed = sum(1 for r in scored if r.get("injection_exposed"))
    block = {
        "started": len(rows),
        "scored": n,
        "unscored": len(rows) - n,
        "outcomes": dist,
        "attacker_executed_rate": _rate(dist["attacker"], n),
        "attacker_attempted_rate": _rate(attempted, n),
        "legitimate_rate": _rate(dist["legitimate"], n),
        "utility_rate": _rate(sum(1 for r in scored if r.get("utility") is True), n),
        "exposure_rate": _rate(exposed, n),
        "prompt_tokens": sum(int(r.get("prompt_tokens") or 0) for r in rows),
        "completion_tokens": sum(int(r.get("completion_tokens") or 0) for r in rows),
        "requests": sum(int(r.get("requests") or 0) for r in rows),
    }
    started = block["started"] or 1
    block["tokens_per_started_episode"] = round((block["prompt_tokens"] + block["completion_tokens"]) / started, 1)
    return block


def _contrast(per_arm: Mapping[str, Any], key: str, label: str) -> dict[str, Any] | None:
    if "INSTR" not in per_arm or "FACT" not in per_arm:
        return None
    fr, ir = per_arm["FACT"][key], per_arm["INSTR"][key]
    if fr["pct"] is None or ir["pct"] is None:
        return None
    return {"estimand": label, "fact": fr, "instr": ir, "delta_pp": round(fr["pct"] - ir["pct"], 2)}


def _blocks_and_contrasts(rows_by_arm: Mapping[str, list[dict[str, Any]]]) -> tuple[dict[str, Any], dict[str, Any]]:
    arms = sorted(rows_by_arm, key=lambda a: (["CLEAN", "INSTR", "FACT", "SHAM", "FACT_STRUCT"] + [a]).index(a))
    per_arm = {arm: _arm_block(rows_by_arm[arm]) for arm in arms}
    contrasts = {
        "executed": _contrast(per_arm, "attacker_executed_rate",
                              "FACT minus INSTR, attacker value EXECUTED in native state (per episode)"),
        "attempted": _contrast(per_arm, "attacker_attempted_rate",
                               "FACT minus INSTR, attacker value ATTEMPTED (requested into an authority arg, per episode)"),
    }
    return per_arm, contrasts


def _cluster_bootstrap_delta(planned: Sequence[Mapping[str, Any]], by_id: Mapping[str, Any],
                             metric: Callable[[Mapping[str, Any]], bool], *, b: int = 10000,
                             seed: int = 20261008) -> dict[str, Any] | None:
    """Percentile CI for FACT-minus-INSTR of a per-episode metric, resampling user-task clusters."""
    clusters: dict[str, dict[str, list[int]]] = defaultdict(lambda: {"FACT": [], "INSTR": []})
    for e in planned:
        if e["arm"] not in ("FACT", "INSTR"):
            continue
        r = by_id.get(e["episode_id"])
        if r is None or not r.get("scored"):
            continue
        clusters[e["user_task_id"]][e["arm"]].append(1 if metric(r) else 0)
    names = [c for c, v in clusters.items() if v["FACT"] and v["INSTR"]]
    if len(names) < 2:
        return None

    def delta(sample: Sequence[str]) -> float:
        f = [x for c in sample for x in clusters[c]["FACT"]]
        i = [x for c in sample for x in clusters[c]["INSTR"]]
        return 100.0 * (sum(f) / len(f) - sum(i) / len(i))

    rng = random.Random(seed)
    point = delta(names)
    reps = sorted(delta([rng.choice(names) for _ in names]) for _ in range(b))
    lo, hi = reps[int(0.025 * b)], reps[min(b - 1, int(0.975 * b))]
    return {"clusters": len(names), "point_pp": round(point, 2),
            "bootstrap95_pp": [round(lo, 2), round(hi, 2)], "b": b, "seed": seed}


def summarize(case_file: Mapping[str, Any], stage_name: str, planned: Sequence[Mapping[str, Any]],
              records: Sequence[Mapping[str, Any]], *, mode: str, price: Mapping[str, Any] | None = None) -> dict[str, Any]:
    by_id = {r["episode_id"]: r for r in records}
    planned_ids = [e["episode_id"] for e in planned]
    plan_by_id = {e["episode_id"]: e for e in planned}
    rows_by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in planned:
        r = by_id.get(e["episode_id"])
        if r is not None:
            rows_by_arm[e["arm"]].append(r)
    per_arm, contrasts = _blocks_and_contrasts(rows_by_arm)

    # Breakdowns (M4): pool only within a value kind, and split executable vs not,
    # because a non-executable fresh-id sink can never reach an executed-attacker
    # outcome. The analyst reads these before pooling the headline contrast.
    def _subset(pred: Callable[[Mapping[str, Any]], bool]) -> dict[str, list[dict[str, Any]]]:
        sub: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in planned:
            r = by_id.get(e["episode_id"])
            if r is not None and pred(e):
                sub[e["arm"]].append(r)
        return sub

    kinds = sorted({e["target"]["value_kind"] for e in planned})
    by_kind = {}
    for k in kinds:
        pa, ct = _blocks_and_contrasts(_subset(lambda e, k=k: e["target"]["value_kind"] == k))
        by_kind[k] = {"per_arm": pa, "contrasts": ct}
    by_exec = {}
    for flag, label in ((True, "executable"), (False, "not_executable")):
        pa, ct = _blocks_and_contrasts(_subset(lambda e, f=flag: bool(e.get("attacker_executable")) == f))
        by_exec[label] = {"per_arm": pa, "contrasts": ct}

    # Cluster bootstrap (by user task) for the executed and attempted contrasts over the
    # executable subset, which is where the executed contrast is defined.
    def _executed(r: Mapping[str, Any]) -> bool:
        return r.get("outcome") == "attacker"

    def _attempted(r: Mapping[str, Any]) -> bool:
        return bool((r.get("oracle_details") or {}).get("attacker_attempted"))

    exec_ids = {e["episode_id"] for e in planned if e.get("attacker_executable")}
    exec_plan = [e for e in planned if e["episode_id"] in exec_ids]
    cluster = {
        "executed_executable_subset": _cluster_bootstrap_delta(exec_plan, by_id, _executed),
        "attempted_all": _cluster_bootstrap_delta(planned, by_id, _attempted),
    }

    prompt = sum(int(r.get("prompt_tokens") or 0) for r in records)
    completion = sum(int(r.get("completion_tokens") or 0) for r in records)
    _ = plan_by_id
    return {
        "schema": SCHEMA_SUMMARY,
        "stage": stage_name,
        "mode": mode,
        "evidence_label": ("plumbing dry run only (not evidence)" if mode != "deepseek"
                           else "backbone-substituted (deepseek-flash); exploratory SS framing contrast (not protocol H2)"),
        "stratum_note": ("This is the same-source (SS) framing contrast. The headline FACT-minus-INSTR "
                         "difference is exploratory and the H1 SS comparator; it is not the protocol H2 "
                         "estimand (A1 under a D1 gate). See H2-CASES-V1.md Section 12."),
        "case_file": {"config_sha256": case_file.get("config_sha256"), "cases_digest": case_file.get("cases_digest"),
                      "gt_validated": case_file.get("gt_validated")},
        "planned_episodes": len(planned_ids),
        "started_episodes": sum(1 for i in planned_ids if i in by_id),
        "scored_episodes": sum(1 for i in planned_ids if i in by_id and by_id[i].get("scored")),
        "complete": all(i in by_id and by_id[i].get("scored") for i in planned_ids),
        "per_arm": per_arm,
        "ss_contrast": contrasts,
        "breakdowns": {"by_value_kind": by_kind, "by_executability": by_exec},
        "cluster_bootstrap": cluster,
        "usage": {
            "requests": sum(int(r.get("requests") or 0) for r in records),
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "usd_at_snapshot": usd(prompt, completion, price) if price else None,
            "usd_is_notional": mode != "deepseek",
            "price_snapshot_id": (price or {}).get("snapshot_id"),
        },
    }
