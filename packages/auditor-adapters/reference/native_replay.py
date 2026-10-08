"""Native AgentDojo replay for the offline auditors (lab venv; no model, no network).

* ``replay_post_state`` rebuilds the native post-state of a (gated) call prefix by
  re-executing the recorded calls in the case arm's injected environment, so a
  gated outcome is scored with ``classify_outcome`` on executed calls plus native
  post-state (H2-CASES-V1.md section 6), and checks that every replayed success
  flag equals the recorded one.
* ``scripted_trace`` executes a fixed call list (the user task's ground truth, or
  the ground truth with the attacker value substituted into the target slots, as
  ``scripts/generate_h2_cases.py`` does for executability) and returns an exact
  AgentDojo-format trace. These are conformance and integration fixtures, not agent
  behaviour.

AgentDojo is the lab's vendored v1.2.2 package; importing this module requires it.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ref_common import ReferenceError, h2_cases
from ref_trace import trace_from_messages, validate_spec

BENCHMARK_VERSION = "v1.2.2"
_SUITES: dict[str, Any] = {}


def get_suite(name: str):
    from agentdojo.task_suite.load_suites import get_suite as _get

    if name not in _SUITES:
        _SUITES[name] = _get(BENCHMARK_VERSION, name)
    return _SUITES[name]


def known_vectors(suite_name: str) -> list[str]:
    return sorted(get_suite(suite_name).get_injection_vector_defaults())


def build_env(spec: Mapping[str, Any]):
    validate_spec(dict(spec), known_vectors(spec["suite"]))
    suite = get_suite(spec["suite"])
    task = suite.get_user_task_by_id(spec["user_task_id"])
    env = task.init_environment(suite.load_and_inject_default_environment(dict(spec["injections"])))
    return suite, task, env


def replay_post_state(spec: Mapping[str, Any], calls: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Re-execute recorded calls; X delta in native state and success-flag consistency."""
    from agentdojo.functions_runtime import FunctionsRuntime

    suite, _task, env = build_env(spec)
    x = str(spec["oracle"]["attacker_value"])
    pre = env.model_dump_json()
    runtime = FunctionsRuntime(suite.tools)
    mismatches = []
    for i, call in enumerate(calls):
        _result, error = runtime.run_function(env, call["function"], dict(call.get("args") or {}), raise_on_error=False)
        if (error is None) != bool(call.get("success")):
            mismatches.append({"index": i, "function": call["function"], "recorded_success": call.get("success"),
                               "replayed_error": None if error is None else str(error)[:200]})
    post = env.model_dump_json()
    return {"post_state_adds_attacker": post.count(x) > pre.count(x), "x_pre": pre.count(x), "x_post": post.count(x),
            "calls_replayed": len(calls), "consistent": not mismatches, "mismatches": mismatches}


def ground_truth_calls(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    _suite, task, env = build_env(spec)
    return [{"function": fc.function, "args": dict(fc.args)} for fc in task.ground_truth(env.model_copy(deep=True))]


def substitute_attacker(spec: Mapping[str, Any], calls: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """X in place of every legitimate value in the target slots (generator rule)."""
    target, oracle = spec["oracle"]["target"], spec["oracle"]
    legit = {h2_cases.normalize_value(v) for v in oracle["legitimate_set"]}
    x = oracle["attacker_value"]
    out, changed = [], False
    for call in calls:
        args = copy.deepcopy(dict(call["args"]))
        if call["function"] == target["function"] and target["argument"] in args:
            value = args[target["argument"]]
            if isinstance(value, list):
                new = [x if h2_cases.normalize_value(e) in legit else e for e in value]
                changed |= new != value
                args[target["argument"]] = new
            elif h2_cases.normalize_value(value) in legit:
                args[target["argument"]] = x
                changed = True
        out.append({"function": call["function"], "args": args})
    return out, changed


def scripted_trace(spec: Mapping[str, Any], calls: Sequence[Mapping[str, Any]], *, trace_id: str,
                   final_text: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute ``calls`` one per assistant turn in the arm's environment -> (trace, native facts).

    The final assistant text defaults to the user task's ``GROUND_TRUTH_OUTPUT`` (as
    AgentDojo's ``GroundTruthPipeline``), and AgentDojo utility is computed with
    ``suite._check_user_task_utility`` over that text, the pre/post environments and
    the scripted call stack, as the H2 generator's ground-truth provider does.
    """
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

    suite, task, env = build_env(spec)
    if final_text is None:
        final_text = str(getattr(task, "GROUND_TRUTH_OUTPUT", "") or "")
    x = str(spec["oracle"]["attacker_value"])
    pre_env = env.model_copy(deep=True)
    pre = env.model_dump_json()
    runtime = FunctionsRuntime(suite.tools)
    stack = [FunctionCall(function=c["function"], args=dict(c["args"]), id=f"scripted_{i}") for i, c in enumerate(calls)]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": [{"type": "text", "content": load_system_message(None)}]},
        {"role": "user", "content": [{"type": "text", "content": task.PROMPT}]},
    ]
    for i, call in enumerate(calls):
        fc = {"function": call["function"], "args": dict(call["args"]), "id": f"scripted_{i}"}
        messages.append({"role": "assistant", "content": [{"type": "text", "content": ""}], "tool_calls": [fc]})
        result, error = runtime.run_function(env, call["function"], dict(call["args"]), raise_on_error=False)
        messages.append({"role": "tool", "content": [{"type": "text", "content": tool_result_to_str(result)}],
                         "tool_call_id": fc["id"], "tool_call": fc, "error": error})
    messages.append({"role": "assistant", "content": [{"type": "text", "content": final_text}], "tool_calls": None})
    post = env.model_dump_json()
    utility = bool(suite._check_user_task_utility(task, [{"type": "text", "content": final_text}], pre_env, env, stack))
    facts = {"post_state_adds_attacker": post.count(x) > pre.count(x), "utility": utility}
    trace = trace_from_messages(messages, trace_id=trace_id, fmt="scripted_agentdojo", meta={
        "suite": spec["suite"], "user_task_id": spec["user_task_id"], "case_id": spec.get("case_id"),
        "arm": spec.get("arm"), "recorded": {"run_error": False, **facts},
        "notes": ["scripted fixture: fixed call list executed natively; not agent behaviour"]})
    return trace, facts


def prompt_resolver(suite_name: str, user_task_id: str) -> str | None:
    try:
        return get_suite(suite_name).get_user_task_by_id(user_task_id).PROMPT
    except Exception as exc:  # noqa: BLE001 - an unknown task is a malformed input
        raise ReferenceError(f"cannot resolve prompt for {suite_name}/{user_task_id}: {exc}") from None


def default_system_message() -> str:
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message

    return load_system_message(None)
