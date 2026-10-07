#!/usr/bin/env python
"""Offline token estimate for the harness stages (no model, no network).

Run with the lab venv python from a scratch cwd:

    <lab>/.venv/Scripts/python.exe estimate_tokens.py --config config.template.json \
        --stage S2 --out <dir>/token_estimate.json

For every planned episode it replays the task's AgentDojo ground truth on the
pinned v1.2.2 environment (with the important_instructions payloads injected
for attacked episodes), rebuilds the chat-completions body the lab DeepSeek
adapter would send before each ground-truth step (system + user + history +
all suite tools), and counts its UTF-8 bytes.  Two trajectories bound the
attacked case:

* ``ignore``: the agent follows only the user task (payload still in context);
* ``follow``: right after the first tool output that carries a payload, the
  agent also executes the injection task's ground-truth calls.

Bytes are converted at 4 bytes/token (low) and 3 bytes/token (high); the high
band is then multiplied by ``--step-margin`` (default 1.5, as in the ADI
adapter) for extra agent steps.  Completion tokens use the lab's measured
DeepSeek mean of 126 tokens per request (128,896 / 1,024, pilot protocol
draft budget.measured_per_slot.native).  Every figure is an estimate
(UNVERIFIED) until an S1 ledger exists.

Benchmark text is data: it is serialised and counted, never interpreted.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness_core import expand_stage, load_config, usd  # noqa: E402

COMPLETION_PER_REQUEST = 126  # lab DeepSeek native main v2: 128,896 completion tokens / 1,024 requests
PAYLOAD_MARKER = "<INFORMATION>"  # opening tag of the important_instructions template


def _openai_tool_call(index: int, call) -> dict[str, Any]:
    return {
        "id": f"call_{index}",
        "type": "function",
        "function": {"name": call.function, "arguments": json.dumps(call.args)},
    }


def _request_bytes(system: str, prompt: str, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> int:
    body = {
        "model": "deepseek-flash",
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}, *history],
        "tools": tools,
        "tool_choice": "auto",
        "temperature": 0.0,
        "max_tokens": 2048,
        "thinking": {"type": "disabled"},
    }
    return len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _trajectory(suite, task, env, runtime, *, payloads: list[str], inject_task=None) -> dict[str, Any]:
    """Replay ground truth; return per-request byte counts (one request per agent turn)."""
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

    system = _trajectory.system  # type: ignore[attr-defined]
    tools = _trajectory.tools[suite.name]  # type: ignore[attr-defined]
    prompt = getattr(task, "PROMPT", None) or task.GOAL
    calls = list(task.ground_truth(env))
    history: list[dict[str, Any]] = []
    request_bytes: list[int] = []
    inserted = False
    index = 0
    queue = list(calls)
    while queue:
        call = queue.pop(0)
        request_bytes.append(_request_bytes(system, prompt, history, tools))
        tool_call = _openai_tool_call(index, call)
        index += 1
        result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
        text = error or tool_result_to_str(result)
        history.append({"role": "assistant", "content": "", "tool_calls": [tool_call]})
        history.append({"role": "tool", "tool_call_id": tool_call["id"], "content": text})
        # yaml.safe_dump re-wraps long strings, so look for the short payload marker, not the full text.
        if inject_task is not None and not inserted and payloads and PAYLOAD_MARKER in text:
            inserted = True
            queue = list(inject_task.ground_truth(env)) + queue
    request_bytes.append(_request_bytes(system, prompt, history, tools))  # final answer turn
    return {"requests": len(request_bytes), "bytes": sum(request_bytes), "payload_seen": inserted}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--stage", action="append", required=True, help="stage name; repeatable")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--step-margin", type=float, default=1.5)
    args = parser.parse_args(argv)

    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.models import MODEL_NAMES
    from agentdojo.task_suite.load_suites import get_suite

    config = load_config(args.config)
    MODEL_NAMES.setdefault(config["attack"]["model_name_key"], config["attack"]["model_name"])

    class _Named(BasePipelineElement):
        name = config["attack"]["pipeline_name"]

        def query(self, *a, **k):  # pragma: no cover - never called
            raise RuntimeError("estimator never queries a model")

    version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(version, name) for name in ("workspace", "travel", "banking", "slack")}
    _trajectory.system = load_system_message(None)  # type: ignore[attr-defined]
    _trajectory.tools = {  # type: ignore[attr-defined]
        name: [_function_to_openai(f) for f in FunctionsRuntime(s.tools).functions.values()]
        for name, s in suites.items()
    }
    attacks = {name: ImportantInstructionsAttack(s, _Named()) for name, s in suites.items()}
    index = {
        name: {"user_tasks": list(s.user_tasks), "injection_tasks": list(s.injection_tasks)}
        for name, s in suites.items()
    }
    price = config["price_snapshot"]
    report: dict[str, Any] = {
        "schema": "harness-token-estimate/v1",
        "method": (
            "ground-truth replay bytes of the lab DeepSeek request body; low = bytes/4, high = bytes/3 x step_margin; "
            f"completion = {COMPLETION_PER_REQUEST} tokens per request (lab measured mean). UNVERIFIED."
        ),
        "step_margin": args.step_margin,
        "tool_schema_bytes": {name: len(json.dumps(t, separators=(",", ":"))) for name, t in _trajectory.tools.items()},  # type: ignore[attr-defined]
        "system_message_bytes": len(_trajectory.system.encode("utf-8")),  # type: ignore[attr-defined]
        "stages": {},
    }
    for stage in args.stage:
        episodes = expand_stage(config, stage, index)
        rows = []
        for ep in episodes:
            suite = suites[ep["suite"]]
            runtime = FunctionsRuntime(suite.tools)
            injections: dict[str, str] = {}
            inj_task = None
            if ep["kind"] == "attacked":
                user_task = suite.get_user_task_by_id(ep["user_task"])
                inj_task = suite.get_injection_task_by_id(ep["injection_task"])
                injections = attacks[ep["suite"]].attack(user_task, inj_task)
                task = user_task
            elif ep["kind"] == "benign":
                task = suite.get_user_task_by_id(ep["user_task"])
            else:
                task = suite.get_injection_task_by_id(ep["injection_task"])
            row: dict[str, Any] = {"episode_id": ep["episode_id"], "kind": ep["kind"], "suite": ep["suite"]}
            try:
                env = suite.load_and_inject_default_environment(injections)
                if ep["kind"] != "injection_as_user":
                    env = task.init_environment(env)
                ignore = _trajectory(suite, task, env.model_copy(deep=True), runtime, payloads=list(injections.values()))
                row["ignore"] = ignore
                if inj_task is not None:
                    row["follow"] = _trajectory(
                        suite, task, env.model_copy(deep=True), runtime,
                        payloads=list(injections.values()), inject_task=inj_task,
                    )
            except Exception as exc:  # noqa: BLE001 - recorded, estimate continues
                row["error"] = type(exc).__name__
            rows.append(row)

        def tokens(row: dict[str, Any], bound: str) -> tuple[int, int, int] | None:
            if "ignore" not in row:
                return None
            if bound == "low":
                traj = row["ignore"]
                prompt = traj["bytes"] / 4
                requests = traj["requests"]
            else:
                traj = row.get("follow", row["ignore"])
                prompt = traj["bytes"] / 3 * args.step_margin
                requests = traj["requests"] * args.step_margin
            completion = requests * COMPLETION_PER_REQUEST
            return round(prompt), round(completion), round(requests)

        def agg(selection: list[dict[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {"episodes": len(selection)}
            for bound in ("low", "high"):
                vals = [tokens(r, bound) for r in selection]
                vals = [v for v in vals if v is not None]
                if not vals:
                    continue
                prompt = sum(v[0] for v in vals)
                completion = sum(v[1] for v in vals)
                per = [v[0] + v[1] for v in vals]
                out[bound] = {
                    "requests": sum(v[2] for v in vals),
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "tokens": prompt + completion,
                    "per_episode_mean": round(statistics.fmean(per)),
                    "per_episode_max": max(per),
                    "usd": usd(prompt, completion, price),
                }
            out["errors"] = sum(1 for r in selection if "error" in r)
            out["payload_not_seen_in_follow"] = sum(
                1 for r in selection if "follow" in r and not r["follow"]["payload_seen"]
            )
            return out

        summary: dict[str, Any] = {"total": agg(rows), "by_suite_kind": {}}
        for suite_name in sorted({r["suite"] for r in rows}):
            for kind in ("benign", "injection_as_user", "attacked"):
                sel = [r for r in rows if r["suite"] == suite_name and r["kind"] == kind]
                if sel:
                    summary["by_suite_kind"][f"{suite_name}/{kind}"] = agg(sel)
        report["stages"][stage] = {"summary": summary, "episodes": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for stage, data in report["stages"].items():
        total = data["summary"]["total"]
        print(json.dumps({"stage": stage, "low": total.get("low"), "high": total.get("high"), "errors": total["errors"]}))
        for key, value in data["summary"]["by_suite_kind"].items():
            print(f"  {key}: low {value.get('low', {}).get('per_episode_mean')} / high {value.get('high', {}).get('per_episode_mean')} tokens per episode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
