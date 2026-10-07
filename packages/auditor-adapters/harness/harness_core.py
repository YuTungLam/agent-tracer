"""Pure helpers for the no-defense harness check (standard library only).

This module holds everything that does not need AgentDojo: loading and
validating the frozen config, expanding a stage into an ordered episode list,
Wilson intervals, and turning ``episodes.jsonl`` into a summary with the
SIEVE F0 side-by-side block.  ``run_harness.py`` (lab venv) and the tests
import it; it never touches the network or a ``.env`` file.

Saved benchmark text and model output are untrusted data; nothing here
interprets them.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

SCHEMA_CONFIG = "auditor-harness-config/v1"
SCHEMA_EPISODE = "harness-episode/v1"
SCHEMA_PLAN = "harness-episode-plan/v1"
SCHEMA_SUMMARY = "harness-summary/v1"

KINDS = ("benign", "injection_as_user", "attacked")
SUITES_ALL = ("workspace", "travel", "banking", "slack")

# Frozen agent settings the adapter refuses to deviate from.  They mirror the
# lab DeepSeek wire contract (agentdojo-lab/configs/cross_model_pilot_v2.json
# providers[deepseek].wire_request_assertion).
FROZEN_AGENT = {
    "model": "deepseek-flash",
    "temperature": 0.0,
    "max_tokens": 2048,
    "thinking": {"type": "disabled"},
    "tool_choice": "auto",
    "sdk_max_retries": 0,
}


class HarnessConfigError(ValueError):
    """The frozen config or a stage request is malformed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HarnessConfigError(f"config not found: {path}") from None
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    if config.get("schema") != SCHEMA_CONFIG:
        raise HarnessConfigError(f"config schema must be {SCHEMA_CONFIG}")
    bench = config.get("benchmark") or {}
    if bench.get("benchmark_version") != "v1.2.2":
        raise HarnessConfigError("benchmark_version must be v1.2.2")
    attack = config.get("attack") or {}
    if attack.get("name") != "important_instructions":
        raise HarnessConfigError("attack.name must be important_instructions")
    if config.get("defense") is not None:
        raise HarnessConfigError("this harness is the no-defense check; defense must be null")
    llm = (config.get("agent") or {}).get("llm") or {}
    for key, value in FROZEN_AGENT.items():
        if llm.get(key) != value:
            raise HarnessConfigError(f"agent.llm.{key} must be {value!r} (frozen lab wire contract)")
    agent = config.get("agent") or {}
    if agent.get("tools_execution_loop_max_iters") != 15:
        raise HarnessConfigError("agent.tools_execution_loop_max_iters must be 15 (AgentDojo default)")
    stages = config.get("stages")
    if not isinstance(stages, dict) or not stages:
        raise HarnessConfigError("config needs a stages object")
    for name, stage in stages.items():
        _validate_stage(name, stage)


def _validate_stage(name: str, stage: Mapping[str, Any]) -> None:
    episodes = stage.get("episodes")
    suites = stage.get("suites")
    if (episodes is None) == (suites is None):
        raise HarnessConfigError(f"stage {name}: give exactly one of episodes or suites")
    if episodes is not None:
        if not isinstance(episodes, list) or not episodes:
            raise HarnessConfigError(f"stage {name}: episodes must be a non-empty list")
        for item in episodes:
            _validate_episode_ref(name, item)
    else:
        if not isinstance(suites, list) or not suites or any(s not in SUITES_ALL for s in suites):
            raise HarnessConfigError(f"stage {name}: suites must be a non-empty subset of {SUITES_ALL}")
        kinds = stage.get("kinds")
        if not isinstance(kinds, list) or not kinds or any(k not in KINDS for k in kinds):
            raise HarnessConfigError(f"stage {name}: kinds must be a non-empty subset of {KINDS}")
    ceiling = stage.get("episode_request_ceiling", 48)
    if not isinstance(ceiling, int) or isinstance(ceiling, bool) or not 1 <= ceiling <= 48:
        raise HarnessConfigError(f"stage {name}: episode_request_ceiling must be an int in 1..48")


def _validate_episode_ref(stage: str, item: Any) -> None:
    if not isinstance(item, dict):
        raise HarnessConfigError(f"stage {stage}: each episode must be an object")
    kind = item.get("kind")
    if kind not in KINDS:
        raise HarnessConfigError(f"stage {stage}: unknown episode kind {kind!r}")
    if item.get("suite") not in SUITES_ALL:
        raise HarnessConfigError(f"stage {stage}: unknown suite {item.get('suite')!r}")
    if kind == "attacked":
        if not item.get("user_task") or not item.get("injection_task"):
            raise HarnessConfigError(f"stage {stage}: attacked episodes need user_task and injection_task")
    elif kind == "benign":
        if not item.get("user_task") or item.get("injection_task"):
            raise HarnessConfigError(f"stage {stage}: benign episodes need user_task and no injection_task")
    else:
        if item.get("user_task") or not item.get("injection_task"):
            raise HarnessConfigError(f"stage {stage}: injection_as_user episodes need injection_task only")


def episode_id(kind: str, suite: str, user_task: str | None, injection_task: str | None) -> str:
    return f"{kind}:{suite}:{user_task or '-'}:{injection_task or '-'}"


def _episode(kind: str, suite: str, user_task: str | None, injection_task: str | None) -> dict[str, Any]:
    return {
        "episode_id": episode_id(kind, suite, user_task, injection_task),
        "kind": kind,
        "suite": suite,
        "user_task": user_task,
        "injection_task": injection_task,
        "attack": "important_instructions" if kind == "attacked" else None,
    }


def _task_sort_key(task_id: str) -> tuple[str, int]:
    prefix, _, number = task_id.rpartition("_")
    return (prefix, int(number)) if number.isdigit() else (task_id, -1)


def expand_stage(
    config: Mapping[str, Any],
    stage_name: str,
    task_index: Mapping[str, Mapping[str, Sequence[str]]],
) -> list[dict[str, Any]]:
    """Ordered episode list for a stage.

    ``task_index`` maps suite -> {"user_tasks": [...], "injection_tasks": [...]}
    as loaded from the pinned suites.  Explicit episode lists are checked
    against it; suite stages are expanded per suite in the order benign,
    injection_as_user, attacked (user task major, injection task minor), with
    task ids in numeric order.  The order is part of the frozen plan.
    """
    stages = config.get("stages") or {}
    if stage_name not in stages:
        raise HarnessConfigError(f"unknown stage {stage_name!r}; known: {sorted(stages)}")
    stage = stages[stage_name]
    out: list[dict[str, Any]] = []
    if stage.get("episodes") is not None:
        for item in stage["episodes"]:
            suite = item["suite"]
            index = task_index.get(suite)
            if index is None:
                raise HarnessConfigError(f"suite {suite} not loaded")
            if item.get("user_task") and item["user_task"] not in index["user_tasks"]:
                raise HarnessConfigError(f"{suite}/{item['user_task']} is not a v1.2.2 user task")
            if item.get("injection_task") and item["injection_task"] not in index["injection_tasks"]:
                raise HarnessConfigError(f"{suite}/{item['injection_task']} is not a v1.2.2 injection task")
            out.append(_episode(item["kind"], suite, item.get("user_task"), item.get("injection_task")))
    else:
        for suite in stage["suites"]:
            index = task_index.get(suite)
            if index is None:
                raise HarnessConfigError(f"suite {suite} not loaded")
            users = sorted(index["user_tasks"], key=_task_sort_key)
            injections = sorted(index["injection_tasks"], key=_task_sort_key)
            if "benign" in stage["kinds"]:
                out.extend(_episode("benign", suite, ut, None) for ut in users)
            if "injection_as_user" in stage["kinds"]:
                out.extend(_episode("injection_as_user", suite, None, it) for it in injections)
            if "attacked" in stage["kinds"]:
                out.extend(_episode("attacked", suite, ut, it) for ut in users for it in injections)
    ids = [e["episode_id"] for e in out]
    if len(ids) != len(set(ids)):
        raise HarnessConfigError(f"stage {stage_name} lists an episode twice")
    for seq, episode in enumerate(out):
        episode["seq"] = seq
    expected = stage.get("expected_episode_counts")
    if expected:
        counts = count_kinds(out)
        for kind, value in expected.items():
            if counts.get(kind, 0) != value:
                raise HarnessConfigError(
                    f"stage {stage_name}: expected {value} {kind} episodes, expanded {counts.get(kind, 0)}"
                )
    return out


def count_kinds(episodes: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for episode in episodes:
        counts[episode["kind"]] += 1
        counts["total"] += 1
    return dict(counts)


def plan_digest(episodes: Sequence[Mapping[str, Any]]) -> str:
    ids = [e["episode_id"] for e in episodes]
    return sha256_bytes(json.dumps(ids, separators=(",", ":")).encode("utf-8"))


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    """Wilson score interval for k successes out of n, or None when n == 0."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "pct": None if n == 0 else round(100.0 * k / n, 2),
        "wilson95_pct": None if ci is None else [round(100.0 * ci[0], 2), round(100.0 * ci[1], 2)],
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def usd(prompt_tokens: int, completion_tokens: int, price: Mapping[str, Any]) -> str:
    value = (
        Decimal(prompt_tokens) * Decimal(str(price["input_per_million"]))
        + Decimal(completion_tokens) * Decimal(str(price["output_per_million"]))
    ) / Decimal(1_000_000)
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP), "f")


def summarize(
    config: Mapping[str, Any],
    stage_name: str,
    planned: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
    *,
    mode: str,
) -> dict[str, Any]:
    """Aggregate episode records into stock AgentDojo rates plus diagnostics.

    Rates use *scored* episodes: those where AgentDojo returned utility and
    security (this includes the stock context-length mapping utility=False,
    security=True, which is flagged separately).  Episodes that raised an
    unhandled error are reported as ``errored`` and excluded from denominators;
    the stock harness would have aborted the whole run on them.
    """
    price = config.get("price_snapshot") or {}
    by_id = {r["episode_id"]: r for r in records}
    planned_ids = [e["episode_id"] for e in planned]
    suites = sorted({e["suite"] for e in planned}, key=SUITES_ALL.index)

    def block(selection: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for kind in KINDS:
            eps = [e for e in selection if e["kind"] == kind]
            if not eps:
                continue
            rows = [by_id[e["episode_id"]] for e in eps if e["episode_id"] in by_id]
            scored = [r for r in rows if r.get("scored")]
            errored = [r for r in rows if not r.get("scored")]
            entry: dict[str, Any] = {
                "planned": len(eps),
                "started": len(rows),
                "scored": len(scored),
                "errored": len(errored),
                "not_started": len(eps) - len(rows),
                "stock_error_logged": sum(1 for r in scored if r.get("stock_logged_error")),
                "utility": _rate(sum(1 for r in scored if r.get("utility") is True), len(scored)),
            }
            if kind == "attacked":
                entry["asr"] = _rate(sum(1 for r in scored if r.get("security") is True), len(scored))
                clean = [r for r in scored if not r.get("stock_logged_error")]
                entry["asr_excluding_stock_errors"] = _rate(
                    sum(1 for r in clean if r.get("security") is True), len(clean)
                )
            entry["requests"] = sum(int(r.get("requests") or 0) for r in rows)
            entry["prompt_tokens"] = sum(int(r.get("prompt_tokens") or 0) for r in rows)
            entry["completion_tokens"] = sum(int(r.get("completion_tokens") or 0) for r in rows)
            entry["tokens_per_started_episode"] = (
                None if not rows else round((entry["prompt_tokens"] + entry["completion_tokens"]) / len(rows), 1)
            )
            entry["pipeline_attempts_gt1"] = sum(1 for r in rows if int(r.get("pipeline_attempts") or 0) > 1)
            out[kind] = entry
        return out

    per_suite = {suite: block([e for e in planned if e["suite"] == suite]) for suite in suites}
    overall = block(list(planned))
    per_injection: dict[str, dict[str, Any]] = {}
    for e in planned:
        if e["kind"] != "attacked":
            continue
        r = by_id.get(e["episode_id"])
        key = f"{e['suite']}/{e['injection_task']}"
        slot = per_injection.setdefault(key, {"k": 0, "n": 0})
        if r and r.get("scored"):
            slot["n"] += 1
            slot["k"] += 1 if r.get("security") is True else 0
    for key, slot in per_injection.items():
        per_injection[key] = _rate(slot["k"], slot["n"])

    prompt = sum(int(r.get("prompt_tokens") or 0) for r in records)
    completion = sum(int(r.get("completion_tokens") or 0) for r in records)
    summary = {
        "schema": SCHEMA_SUMMARY,
        "config_id": config.get("config_id"),
        "stage": stage_name,
        "mode": mode,
        "evidence_label": (
            "plumbing dry run only (not evidence)" if mode != "deepseek"
            else "backbone-substituted (deepseek-flash); exploratory; not an exact reproduction"
        ),
        "planned_episodes": len(planned_ids),
        "started_episodes": sum(1 for i in planned_ids if i in by_id),
        "complete": all(i in by_id and by_id[i].get("scored") for i in planned_ids),
        "per_suite": per_suite,
        "overall": overall,
        "per_injection_task_asr": per_injection,
        "usage": {
            "requests": sum(int(r.get("requests") or 0) for r in records),
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "usd_at_snapshot": usd(prompt, completion, price) if price else None,
            "usd_is_notional": mode != "deepseek",
            "price_snapshot_id": price.get("snapshot_id"),
        },
        "comparison": comparison_block(config, overall, suites),
    }
    return summary


def comparison_block(
    config: Mapping[str, Any], overall: Mapping[str, Any], suites: Sequence[str]
) -> dict[str, Any]:
    target = (config.get("comparison") or {}).get("sieve_f0") or {}
    ours = {
        "asr_pct": ((overall.get("attacked") or {}).get("asr") or {}).get("pct"),
        "ua_pct": ((overall.get("attacked") or {}).get("utility") or {}).get("pct"),
        "uc_pct": ((overall.get("benign") or {}).get("utility") or {}).get("pct"),
        "suites": list(suites),
    }
    same_scope = sorted(suites) == sorted(target.get("suites") or [])
    return {
        "target": {k: target.get(k) for k in ("source", "backbone", "asr_pct", "ua_pct", "uc_pct", "suites", "n_attacked", "n_benign")},
        "ours": ours,
        "same_suite_scope": same_scope,
        "numeric_comparison_allowed": False,
        "why_not": target.get("not_comparable_because") or [],
        "note": (
            "Side by side only. The backbone, thinking mode and temperature differ or are unknown, so no pass band "
            "applies even when the suite scope matches."
            if same_scope else
            "Different suite scope: the SIEVE F0 numbers pool all four suites (workspace is 560/949 attacked "
            "pairs), so a Banking+Slack rate cannot be checked against them."
        ),
    }
