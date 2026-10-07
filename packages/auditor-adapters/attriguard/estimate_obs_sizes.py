"""Offline (zero model calls) size estimate of AttriGuard inputs for Banking+Slack under ToolKnowledge.

For every attacked pair, replay the user task's ground-truth calls on the injected environment and measure
the formatted outputs of tools in AttriGuard's EXTERNAL_OUTPUT_TOOLS (these are what get attenuated).
Also measures the fixed prompt sizes (system message, tool schemas, attenuation and judge prompts).
Chars only; token conversion is done by the caller with a stated ratio.
Usage: <artifact venv python> estimate_obs_sizes.py <artifact main/pipeline dir> <out json>
"""
import json
import statistics
import sys

src, out_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, src)

import agentdojo.models as ad_models  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

import AttriGuard as ag  # noqa: E402
import my_agent_pipeline as mp  # noqa: E402
from openai_llm_compat import _function_to_openai  # noqa: E402

ad_models.MODEL_NAMES["deepseek-flash"] = "AI assistant"


class Dummy(BasePipelineElement):
    name = "deepseek-flash-None-attriguard"

    def query(self, *a, **k):
        raise RuntimeError("no model calls")


result = {
    "prompt_chars": {
        "flatten_system": len(ag.FLATTEN_SYSTEM_PROMPT),
        "transpose_system": len(ag.TRANSPOSE_SYSTEM_PROMPT),
        "fuzzy_judge_system": len(ag.FUZZY_SYSTEM_PROMPT),
        "agent_system_message": len(mp.load_system_message(None)),
    },
    "suites": {},
}
excluded = {"banking": {"user_task_12"}, "slack": {"user_task_18", "user_task_19"}}
for suite_name in ("banking", "slack"):
    suite = get_suite("v1.2.2", suite_name)
    tools_json = json.dumps([_function_to_openai(f) for f in suite.tools], default=str)
    attack = load_attack("tool_knowledge", suite, Dummy())
    per_pair = []
    for ut_id, ut in suite.user_tasks.items():
        if ut_id in excluded[suite_name]:
            continue
        for it_id, it in suite.injection_tasks.items():
            injections = attack.attack(ut, it)
            env = suite.load_and_inject_default_environment(injections)
            env = ut.init_environment(env)
            runtime = FunctionsRuntime(suite.tools)
            ext_chars, ext_n, all_n, inj_chars = 0, 0, 0, sum(len(v) for v in injections.values())
            for call in ut.ground_truth(env.model_copy(deep=True)):
                res, err = runtime.run_function(env, call.function, call.args)
                text = tool_result_to_str(res)
                all_n += 1
                if call.function in ag.EXTERNAL_OUTPUT_TOOLS and text.strip():
                    ext_n += 1
                    ext_chars += len(text)
            per_pair.append({"ut": ut_id, "it": it_id, "gt_calls": all_n, "ext_obs": ext_n, "ext_chars": ext_chars,
                             "injection_chars": inj_chars})
    result["suites"][suite_name] = {
        "tool_schema_chars": len(tools_json),
        "pairs": len(per_pair),
        "gt_calls_mean": statistics.mean(p["gt_calls"] for p in per_pair),
        "ext_obs_mean": statistics.mean(p["ext_obs"] for p in per_pair),
        "ext_obs_max": max(p["ext_obs"] for p in per_pair),
        "ext_chars_mean": statistics.mean(p["ext_chars"] for p in per_pair),
        "ext_chars_max": max(p["ext_chars"] for p in per_pair),
        "injection_chars_mean": statistics.mean(p["injection_chars"] for p in per_pair),
    }
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=1)
print(json.dumps(result, indent=1))
