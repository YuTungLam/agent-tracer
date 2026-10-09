"""Pure, offline registration and planning for the protocol H3 benign pairs.

The two arms differ only by a sentence that states the legitimate authority
value in the trusted user prompt. Both use the same stock AgentDojo task,
environment, tool data, sink, and native utility. This module cannot call a
provider. Its output is a preparation artifact, not an H3 result: the 10 pp
undefended-utility precondition and auditor false-block contrast need live runs.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = "h3-pairs-config/v1"
CASES_SCHEMA = "h3-pairs/v1"
PLAN_SCHEMA = "h3-plan/v1"
SPLIT_SALT = "authority-auditor-pilot-v1|"
ARMS = ("TOOL_L", "PROMPT_L")
GT_CHECKS = (
    "original_prompt_matches_native",
    "same_environment",
    "same_native_calls",
    "same_utility_implementation",
    "same_native_utility",
    "native_utility_true",
    "source_exposes_l_before_sink",
    "target_calls_l",
)


class H3PairError(ValueError):
    """A proposed benign pair fails the frozen H3 registration contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _contains(haystack: str, value: Any) -> bool:
    needle = str(value)
    return re.search(rf"(?<![0-9A-Za-z]){re.escape(needle)}(?![0-9A-Za-z])", haystack, re.I) is not None


def template_split(template_id: str) -> str:
    """Protocol §8.4: split by the *new template id*, not an old SS task label."""
    first_byte = hashlib.sha256((SPLIT_SALT + template_id).encode("utf-8")).digest()[0]
    return "dev" if first_byte % 2 == 0 else "eval"


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    if config.get("schema") != CONFIG_SCHEMA or config.get("split_salt") != SPLIT_SALT:
        raise H3PairError("wrong H3 schema or §8.4 split salt")
    if config.get("benchmark_version") != "v1.2.2":
        raise H3PairError("H3 stock task candidates require AgentDojo v1.2.2")
    candidates = config.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise H3PairError("candidates must be a non-empty list")
    ids: set[str] = set()
    for c in candidates:
        if not isinstance(c, Mapping):
            raise H3PairError("candidate must be an object")
        target = c.get("target")
        if not isinstance(target, Mapping):
            raise H3PairError("candidate target is missing")
        expected_id = (f"h3:{c.get('suite')}:{c.get('user_task_id')}:"
                       f"{target.get('function')}.{target.get('argument')}")
        if c.get("template_id") != expected_id or expected_id in ids:
            raise H3PairError(f"template id must be unique and canonical: {expected_id}")
        ids.add(expected_id)
        if c.get("suite") not in {"workspace", "slack", "banking", "travel"}:
            raise H3PairError(f"unknown suite for {expected_id}")
        original, addition, value = c.get("original_prompt"), c.get("prompt_append"), c.get("legitimate_value")
        if not isinstance(original, str) or not isinstance(addition, str) or value is None:
            raise H3PairError(f"prompt or legitimate value missing for {expected_id}")
        if not original.strip() or addition != addition.strip() or "\n" in addition:
            raise H3PairError(f"invalid prompt append for {expected_id}")
        if _contains(original, value) or not _contains(addition, value):
            raise H3PairError(f"L must be absent from the original and present in the appended sentence: {expected_id}")
        if not c.get("source_function") or not target.get("function") or not target.get("argument"):
            raise H3PairError(f"source/sink is incomplete for {expected_id}")


def generate_cases(
    config: Mapping[str, Any],
    native_validator: Callable[[Mapping[str, Any], str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Register all candidates; validate only dev cases with a local GT callback.

    Eval tasks are recorded by hash but their environments are not built or
    probed here. No case is runnable without all native checks passing.
    """
    validate_config(config)
    cases: list[dict[str, Any]] = []
    for c in config["candidates"]:
        split = template_split(c["template_id"])
        relocated = c["original_prompt"] + " " + c["prompt_append"]
        case: dict[str, Any] = {
            "template_id": c["template_id"], "case_id": c["template_id"],
            "split": split, "suite": c["suite"], "user_task_id": c["user_task_id"],
            "target": dict(c["target"]), "source_function": c["source_function"],
            "legitimate_value": c["legitimate_value"],
            "arms": {
                "TOOL_L": {"prompt": c["original_prompt"], "prompt_sha256": _sha(c["original_prompt"].encode()),
                           "injections": {}},
                "PROMPT_L": {"prompt": relocated, "prompt_sha256": _sha(relocated.encode()),
                             "injections": {}},
            },
        }
        if split == "dev" and native_validator is not None:
            facts = dict(native_validator(c, relocated))
            checks = {k: facts.get(k) is True for k in GT_CHECKS}
            case["gt"] = facts
            case["invariants"] = checks | {"all": all(checks.values())}
        else:
            case["gt"] = None
            case["invariants"] = {"all": False}
            case["not_validated_reason"] = "eval held out" if split == "eval" else "native validator unavailable"
        cases.append(case)
    runnable = [c for c in cases if c["split"] == "dev" and c["invariants"]["all"]]
    return {
        "schema": CASES_SCHEMA, "config_id": config["config_id"],
        "config_sha256": _sha(_canonical(config)),
        "benchmark_version": config["benchmark_version"],
        "split_salt": SPLIT_SALT,
        "counts": {"registered": len(cases), "dev": sum(c["split"] == "dev" for c in cases),
                   "eval_held_out": sum(c["split"] == "eval" for c in cases),
                   "dev_gt_validated": len(runnable)},
        "cases": cases,
    }


def expand_dev_plan(case_file: Mapping[str, Any], *, repeats: int = 5) -> dict[str, Any]:
    """Make a machine-readable, dev-only no-provider episode plan."""
    if case_file.get("schema") != CASES_SCHEMA or repeats < 1:
        raise H3PairError("invalid H3 case file or repeat count")
    episodes: list[dict[str, Any]] = []
    for case in case_file["cases"]:
        if case["split"] != "dev" or not case["invariants"]["all"]:
            continue
        if any(case["arms"][a]["injections"] != {} for a in ARMS):
            raise H3PairError("H3 benign pairs cannot contain attacker injections")
        for arm in ARMS:
            for rep in range(repeats):
                episodes.append({
                    "episode_id": f"{case['case_id']}|{arm}|r{rep}",
                    "seq": len(episodes), "case_id": case["case_id"], "split": "dev",
                    "arm": arm, "repeat": rep, "suite": case["suite"],
                    "user_task_id": case["user_task_id"], "prompt_override": case["arms"][arm]["prompt"],
                    "prompt_sha256": case["arms"][arm]["prompt_sha256"],
                    "injections": {}, "target": case["target"],
                    "legitimate_value": case["legitimate_value"],
                })
    return {
        "schema": PLAN_SCHEMA, "case_config_sha256": case_file["config_sha256"],
        "benchmark_version": case_file["benchmark_version"],
        "repeats": repeats, "episodes": episodes,
        "counts": {"dev_pairs": len(episodes) // (len(ARMS) * repeats), "episodes": len(episodes),
                   "by_arm": {arm: sum(e["arm"] == arm for e in episodes) for arm in ARMS}},
        "plan_sha256": _sha(_canonical([[e["episode_id"], e["prompt_sha256"]] for e in episodes])),
    }
