#!/usr/bin/env python
"""Run the released AttriGuard gate, unmodified, as an online (D1) gate on the common case files.

Run with the ARTIFACT's own venv python, from a scratch cwd that holds no .env, normally through
``common/deepseek_route.py run-stage --artifact attriguard --stage AL-S1|AL-S2|AL-S2T0 --set cases=<file>``:

    <attriguard .venv python> run_attriguard_cases.py --artifact-src <usenix-artifacts/main/pipeline> \
        --config config.cases.json --stage AL-S1 --cases ss=<h2 SS case file> --out <fresh run dir>

Each episode is one (row, case, arm, repeat). The arm's ``injections`` dict (any vectors, any number) is
passed to ``suite.load_and_inject_default_environment``, the user task runs under the row's pipeline
(``attriguard_l2``: released AttriGuardExecutionLoop, lambda=2, fuzzy survival, skip-empty-audit on;
``no_defense``: the released no-defense pipeline; both with the released default YAML tool-output
format), and the declared authority sink is scored with the typed oracle
``agentdojo_lab/h2_cases.py: classify_outcome`` (loaded by path), never with an AgentDojo injection-task
security check. Every planned stimulus environment is built once before the first model request; a
stimulus that fails to build refuses the run and is never scored.

Every model request (agent, shadow, attenuation, judge) goes through one loopback budget guard with the
same routed client, wire normalisation and judge-logprobs handling as ``run_attriguard.py``. One
behaviour change is declared (README D13): a per-episode request ceiling refuses requests past the row's
``episode_request_ceiling`` before they are metered or sent, so a runaway episode ends as a run error.

Instrumentation is observation only (README deviation D10):
* a subclass of AttriGuardExecutionLoop records, per audited call, the route the released
  ``_fuzzy_survive`` took (it calls the released method unchanged);
* the gate's ``tools_executor`` (AgentDojo's ToolsExecutor, which the release uses only for its
  unaudited skip routes) is replaced by a subclass that records each call it executes, and a logging
  handler reads the release's own debug line that names the skip branch (so ATTRIGUARD_DEBUG must be 1);
* the episode's FunctionsRuntime is an AgentDojo subclass that records each executed tool call, so the
  oracle sees calls that executed before an episode error.

``--plan-only`` expands and writes the plan without importing the artifact or calling any model.
Saved benchmark text and model output are untrusted data; nothing here interprets them as instructions.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import platform
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import attriguard_cases as ac  # noqa: E402
from attriguard_deepseek import (  # noqa: E402
    DEEPSEEK_MODEL,
    AdapterRefusal,
    JudgeProbe,
    RoutedClient,
    RunContext,
    UsageMeter,
    classify_route,
    redact,
    require_loopback_base_url,
)

ADAPTER_VERSION = "attriguard-case-adapter/2"
ARTIFACT_FILES = ("AttriGuard.py", "my_agent_pipeline.py", "openai_llm_compat.py", "runtime_patches.py", "pydantic_fix.py")
ADAPTER_FILES = ("run_attriguard_cases.py", "attriguard_cases.py", "attriguard_deepseek.py")
EXIT_OK, EXIT_OTHER, EXIT_CONFIG, EXIT_GUARD_HALT, EXIT_ERRORS = 0, 1, 2, 3, 6
MAX_CONSECUTIVE_ERRORS = 5
# The release's own debug lines, emitted in the exact skip branch (AttriGuard.py:724-725 and 757-758).
SKIP_LOG_MESSAGES = {
    "AttriGuard skip audit due to empty tool outputs in previous step": "skip_after_empty_step",
    "AttriGuard no tool observations yet; skipping audit": "skip_before_first_observation",
}
VECTOR_SENTINEL = "ZQXATTRIGUARDVECTORPROBE7Q"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False, sort_keys=True, default=str) + "\n", encoding="utf-8")


class EpisodeRequestCeiling(RuntimeError):
    """The per-episode request ceiling was reached; the request was not sent."""


class EpisodeCeiling:
    """Request count of the current episode, shared by every role's client."""

    def __init__(self) -> None:
        self.count = 0
        self.refusals = 0
        self.ceiling: int | None = None

    def begin(self, ceiling: int | None) -> None:
        self.count, self.refusals, self.ceiling = 0, 0, ceiling


class CeilingClient:
    """Duck-typed client in front of a RoutedClient: past the ceiling a request is refused before it is
    metered or sent (the artifact's tenacity retries of it are refused the same way)."""

    def __init__(self, inner: Any, shared: EpisodeCeiling) -> None:
        self._inner = inner
        self._shared = shared
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **params: Any) -> Any:
        s = self._shared
        if s.ceiling is not None and s.count >= s.ceiling:
            s.refusals += 1
            raise EpisodeRequestCeiling(f"episode request ceiling {s.ceiling} reached")
        s.count += 1
        return self._inner.chat.completions.create(**params)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifact-src", default=os.environ.get("ATTRIGUARD_SRC"),
                   help="the artifact's src/usenix-artifacts/main/pipeline directory (env ATTRIGUARD_SRC)")
    p.add_argument("--config", default=str(HERE / "config.cases.json"))
    p.add_argument("--stage", required=True)
    p.add_argument("--cases", action="append", default=[], metavar="NAME=PATH",
                   help="case file for the stage selection NAME (repeatable), e.g. ss=...")
    p.add_argument("--out", default=os.environ.get("AUDITOR_OUT"), help="fresh run directory (env AUDITOR_OUT)")
    p.add_argument("--oracle", default=None, help="path of agentdojo_lab/h2_cases.py (default: this repo's lab)")
    p.add_argument("--guard-url", default=None, help="loopback guard base URL; default AUDITOR_GUARD_URL, then OPENAI_BASE_URL")
    p.add_argument("--max-episodes", type=int, default=None, help="stop after this many NEW episodes")
    p.add_argument("--logprobs", choices=("auto", "off"), default=None)
    p.add_argument("--timeout", type=float, default=None, help="per-request client timeout in seconds")
    p.add_argument("--plan-only", action="store_true", help="write the plan and exit; no model calls")
    p.add_argument("--resume-from", action="append", default=[], metavar="ADAPTER_DIR",
                   help="earlier run dir of the SAME stage, config, plan, mode, oracle, adapter, artifact and case "
                        "files; its scored episodes (and their per-call rows) are carried over")
    return p.parse_args(argv)


# ---------------------------------------------------------------------------------------------
# Instrumentation state


class GateRecorder:
    """Per-call records for the current episode. Observation only: never changes a decision."""

    def __init__(self, normalize: Any) -> None:
        self.normalize = normalize
        self.authority_args: dict[str, list[str]] = {}
        self.ep: dict[str, Any] | None = None
        self.calls: list[dict[str, Any]] = []
        self.attempt = 0
        self.pending_skip: str | None = None
        self.observations = 0
        self.gate_queries = 0
        self.anomalies: list[str] = []

    def begin_episode(self, ep: dict[str, Any], authority_args: dict[str, list[str]]) -> None:
        self.ep = ep
        self.authority_args = authority_args
        self.calls = []
        self.attempt = 0
        self.pending_skip = None
        self.observations = 0
        self.gate_queries = 0
        self.anomalies = []

    def begin_gate_query(self) -> None:
        self.gate_queries += 1
        self.pending_skip = None

    def take_skip(self) -> str | None:
        route, self.pending_skip = self.pending_skip, None
        return route

    def flags(self, call: Any) -> dict[str, Any]:
        assert self.ep is not None
        return ac.call_flags(call.function, call.args, self.ep, self.authority_args, self.normalize)

    def record_unaudited(self, call: Any, route: str, cause: str | None) -> None:
        self.calls.append({"attempt": self.attempt, "call_id": call.id, "function": call.function,
                           "args_sha256": ac.args_digest(call.args), "audited": False, "route": route,
                           "survived": None, "skip_cause": cause, **self.flags(call)})

    def record_audited(self, call: Any, candidates: list[Any], *, route: str, survived: bool, exact: bool,
                       judge_called: bool, judge_logprobs_present: bool, judge_json_survive: Any) -> None:
        shadow = [self.flags(c) for c in candidates]
        same_fn = [s for c, s in zip(candidates, shadow) if c.function == call.function]
        self.calls.append({
            "attempt": self.attempt, "call_id": call.id, "function": call.function,
            "args_sha256": ac.args_digest(call.args), "audited": True, "route": route, "survived": bool(survived),
            "exact_shadow_match": exact, "shadow_calls": len(candidates),
            "shadow_same_function_calls": len(same_fn),
            "shadow_has_x": any(s["carries_attacker"] for s in shadow),
            "shadow_same_function_authority_values": [v for s in same_fn for v in s["authority_values"]][:20],
            "judge_called": judge_called, "judge_logprobs_present": bool(judge_called and judge_logprobs_present),
            "judge_json_survive": judge_json_survive, **self.flags(call),
        })


def _json_survive(raw: str) -> Any:
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    value = data.get("survive") if isinstance(data, dict) else None
    return value if isinstance(value, bool) else None


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(b.get("content") or b.get("text") or "") for b in content if isinstance(b, dict))
    return ""


def _serialise_messages(messages: list[Any]) -> list[dict[str, Any]]:
    out = []
    for m in messages:
        item: dict[str, Any] = {"role": m.get("role"), "content": _content_text(m.get("content"))}
        if m.get("tool_calls"):
            item["tool_calls"] = [{"id": c.id, "function": c.function, "args": c.args} for c in m["tool_calls"]]
        if m.get("role") == "tool":
            call = m.get("tool_call")
            item.update({"tool_call_id": m.get("tool_call_id"), "error": m.get("error"),
                         "function": getattr(call, "function", None),
                         "defense_state": m.get("defense_state")})
        out.append(item)
    return out


def _is_guard_refusal(exc: BaseException) -> bool:
    seen = 0
    cur: BaseException | None = exc
    while cur is not None and seen < 5:
        if getattr(cur, "status_code", None) in (401, 402, 403):
            return True
        cur = cur.__cause__ or cur.__context__
        seen += 1
    return False


def _latest_by_episode(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Latest record per episode id, a scored one winning over an unscored one."""
    latest: dict[str, dict[str, Any]] = {}
    for r in records:
        if r.get("status") in ac.SCORED_STATUSES or r["episode_id"] not in latest:
            latest[r["episode_id"]] = r
    return latest


# ---------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    config, config_sha = ac.load_stage_config(Path(args.config))
    if args.stage not in config["stages"]:
        raise AdapterRefusal(f"unknown stage {args.stage!r}; known {sorted(config['stages'])}")
    stage = config["stages"][args.stage]
    if not args.out:
        raise AdapterRefusal("refusing: no --out / AUDITOR_OUT run directory")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for name in ("episodes.jsonl", "gate_calls.jsonl"):
        if (out / name).exists():
            raise AdapterRefusal(f"refusing: {out} already holds {name}; use a fresh --out and --resume-from {out}")
    if (Path.cwd() / ".env").exists():
        raise AdapterRefusal(f"refusing: cwd {Path.cwd()} contains a .env; run from a scratch directory")
    provider = os.environ.get("AUDITOR_PROVIDER")
    if provider and provider != "deepseek":
        raise AdapterRefusal(f"refusing: this adapter routes deepseek-flash only (AUDITOR_PROVIDER={provider})")

    case_paths = ac.parse_cases_args(args.cases)
    case_docs: dict[str, dict[str, Any]] = {}
    case_meta: dict[str, dict[str, Any]] = {}
    for name, path in case_paths.items():
        doc, digest = ac.load_case_file(path)
        case_docs[name] = doc
        case_meta[name] = {"path": str(path.resolve()), "sha256": digest, "schema": doc.get("schema"),
                           **ac.case_file_identity(doc)}
    planned = ac.expand_case_stage(config, args.stage, case_docs)
    if not planned:
        raise AdapterRefusal(f"refusing: stage {args.stage} selects no episode from the given case files")
    digest = ac.plan_digest(planned)
    mode = os.environ.get("AUDITOR_MODE") or ("plan-only" if args.plan_only else "standalone")
    if mode == "deepseek":
        unpinned = ac.unpinned_selections(config, args.stage)
        if unpinned:
            raise AdapterRefusal(f"refusing a paid run: selections {unpinned} of {args.stage} do not pin "
                                 "cases_digest, config_sha256 and content_sha256")
    plan_doc = {"schema": ac.SCHEMA_PLAN, "adapter": ADAPTER_VERSION, "stage": args.stage, "mode": mode,
                "planned_utc": _utc(), "plan_digest": digest, "config_sha256": config_sha, "case_files": case_meta,
                "counts": ac.count_plan(planned), "episodes": planned}
    _write_json(out / "plan.json", plan_doc)
    if args.plan_only:
        print(json.dumps({"stage": args.stage, "plan_digest": digest, "counts": plan_doc["counts"]}))
        return EXIT_OK

    guard_url = require_loopback_base_url(
        args.guard_url or os.environ.get("AUDITOR_GUARD_URL") or os.environ.get("OPENAI_BASE_URL"))
    api_key = os.environ.get("OPENAI_API_KEY") or "guard-held-key"
    secrets = [api_key, os.environ.get("AUDITOR_GUARD_TOKEN") or ""]
    if not args.artifact_src:
        raise AdapterRefusal("refusing: no --artifact-src / ATTRIGUARD_SRC")
    src = Path(args.artifact_src).resolve()
    if not (src / "AttriGuard.py").is_file() or not (src / "my_agent_pipeline.py").is_file():
        raise AdapterRefusal(f"refusing: {src} is not the artifact's main/pipeline directory")
    if not sys.flags.utf8_mode:
        # AgentDojo 0.1.35 opens the suite YAML in the locale encoding (task_suite.py read_suite_file);
        # on a GBK locale that garbles non-ASCII environment text. run-stage sets PYTHONUTF8=1.
        raise AdapterRefusal("refusing: Python UTF-8 mode is off; set PYTHONUTF8=1")
    oracle_path = Path(args.oracle).resolve() if args.oracle else ac.default_oracle_path(HERE)
    oracle, oracle_sha = ac.load_oracle(oracle_path)

    backbone = config["backbone"]
    if backbone["model"] != DEEPSEEK_MODEL:
        raise AdapterRefusal(f"refusing: config model {backbone['model']!r} is not {DEEPSEEK_MODEL!r}")
    agent_temperature = float(stage.get("agent_temperature", backbone["agent_temperature"]))
    run_uid = uuid.uuid4().hex

    receipt: dict[str, Any] = {
        "adapter": ADAPTER_VERSION, "artifact": "attriguard", "stage": args.stage, "mode": mode, "run_uid": run_uid,
        "started_utc": _utc(), "config_sha256": config_sha, "plan_digest": digest, "case_files": case_meta,
        "oracle": {"path_tail": "/".join(oracle_path.parts[-4:]), "sha256": oracle_sha},
        "guard": {"host_port": guard_url.split("://", 1)[1].split("/", 1)[0]},
        # The released shadow is the agent LLM object (AttriGuard.py:801 self.llm), so it runs at this
        # temperature too (README D12).
        "backbone": {**backbone, "agent_temperature_effective": agent_temperature,
                     "shadow_temperature_effective": agent_temperature},
        "baseline_row": config["baseline_row"],
        "python": sys.version.split()[0], "platform": platform.platform(),
        "artifact_files_sha256": {n: ac.sha256_file(src / n) for n in ARTIFACT_FILES if (src / n).is_file()},
        "adapter_files_sha256": {n: ac.sha256_file(HERE / n) for n in ADAPTER_FILES},
        "deviations": config.get("deviations", []),
        "resumed_from": [str(Path(p).resolve()) for p in args.resume_from],
        "status": "started",
    }
    receipt_path = out / "adapter_receipt.json"
    _write_json(receipt_path, receipt)

    for key, value in (config.get("attriguard_env") or {}).items():
        os.environ[key] = str(value)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(out / "attriguard_debug.log", encoding="utf-8")], force=True)
    for noisy in ("httpx", "httpcore", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    sys.path.insert(0, str(src))
    from importlib.metadata import version as pkg_version

    import openai
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    import pydantic_fix  # noqa: F401  (artifact: rebuilds TaskResults, as my_benchmark.py does)
    import my_agent_pipeline
    import AttriGuard as ag_module
    from openai_llm_compat import OpenAILLM
    from runtime_patches import apply_runtime_workarounds

    apply_runtime_workarounds()
    agentdojo_version = pkg_version("agentdojo")
    if agentdojo_version != config["benchmark"]["package_version"]:
        raise AdapterRefusal(f"refusing: agentdojo {agentdojo_version} != {config['benchmark']['package_version']}")
    receipt["agentdojo_version"] = agentdojo_version

    benchmark_version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(benchmark_version, name) for name in sorted({e["suite"] for e in planned})}
    vector_ids = {name: set(suite.get_injection_vector_defaults()) for name, suite in suites.items()}
    problems = ac.check_episode_vectors(planned, vector_ids)
    if problems:
        raise AdapterRefusal("refusing: injection vectors not in AgentDojo " + benchmark_version + ": " + "; ".join(problems[:10]))

    # Stimulus preflight, before any model request: every planned vector must land in its suite's
    # environment, and every planned (suite, user task, injections) environment must build.
    preflight: dict[str, Any] = {"vectors_checked": 0, "stimuli_built": 0, "problems": []}
    for suite_name, vector in ac.planned_vectors(planned):
        preflight["vectors_checked"] += 1
        try:
            probe = suites[suite_name].load_and_inject_default_environment({vector: VECTOR_SENTINEL})
            if VECTOR_SENTINEL not in probe.model_dump_json():
                preflight["problems"].append(f"{suite_name}/{vector}: the vector has no placeholder in the environment")
        except Exception as exc:  # noqa: BLE001
            preflight["problems"].append(f"{suite_name}/{vector}: probe failed: {type(exc).__name__}: {str(exc)[:200]}")
    for stim in ac.unique_stimuli(planned):
        try:
            suite = suites[stim["suite"]]
            suite.get_user_task_by_id(stim["user_task_id"]).init_environment(
                suite.load_and_inject_default_environment(stim["injections"]))
            preflight["stimuli_built"] += 1
        except Exception as exc:  # noqa: BLE001
            preflight["problems"].append(f"{stim['example']} ({stim['suite']}/{stim['user_task_id']}): environment does not "
                                         f"build: {type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}")
    receipt["stimulus_preflight"] = preflight
    _write_json(receipt_path, receipt)
    if preflight["problems"]:
        raise AdapterRefusal("refusing: stimulus preflight failed (no model request was made): "
                             + "; ".join(preflight["problems"][:10]))

    authority_maps = {name: {fn: list(a) for fn, a in doc["authority_arg_map"].items()} for name, doc in case_docs.items()}
    recorder = GateRecorder(oracle.normalize_value)

    class _SkipRouteHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                route = SKIP_LOG_MESSAGES.get(record.getMessage())
            except Exception:  # noqa: BLE001
                return
            if route:
                recorder.pending_skip = route

    logging.getLogger().addHandler(_SkipRouteHandler(level=logging.INFO))

    context = RunContext(logprobs_mode=args.logprobs or backbone.get("judge_logprobs", "auto"))
    meter = UsageMeter()
    timeout = args.timeout or float(backbone.get("request_timeout_seconds", 120))
    base_client = openai.OpenAI(base_url=guard_url, api_key=api_key, max_retries=0, timeout=timeout)
    ceiling = EpisodeCeiling()
    max_tokens = int(backbone["max_tokens"])
    model = backbone["model"]
    clients = {role: RoutedClient(base_client, role, meter, context, model=model, max_tokens=max_tokens)
               for role in ("agent", "attenuation", "judge")}
    gated = {role: CeilingClient(c, ceiling) for role, c in clients.items()}
    agent_llm = OpenAILLM(gated["agent"], model, temperature=agent_temperature)
    agent_llm.name = model
    attenuation_llm = OpenAILLM(gated["attenuation"], model, temperature=float(backbone["aux_temperature"]),
                                top_p=float(backbone["aux_top_p"]))
    judge_probe = JudgeProbe(OpenAILLM(gated["judge"], model, temperature=float(backbone["aux_temperature"]),
                                       top_p=float(backbone["aux_top_p"])), context)

    def _routed_aux_llms(tool_delimiter: str):  # replaces my_agent_pipeline._get_attriguard_aux_llms
        return attenuation_llm, judge_probe

    call_signature = ag_module._call_signature

    class RecordingToolsExecutor(ToolsExecutor):
        """AgentDojo ToolsExecutor; the release uses it only on its unaudited skip routes."""

        def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):  # noqa: B006, ANN001
            route = recorder.take_skip() or "skip_unknown"
            if route == "skip_unknown":
                recorder.anomalies.append("unaudited execution without a released skip log line")
            last = messages[-1] if messages else None
            calls = (last.get("tool_calls") or []) if last is not None and last.get("role") == "assistant" else []
            cause = None
            if route == "skip_after_empty_step":
                prev = []
                for m in reversed(list(messages)[:-1]):
                    if m.get("role") != "tool":
                        break
                    prev.append(m)
                cause = ac.previous_step_cause(prev)
            for call in calls:
                recorder.record_unaudited(call, route, cause)
            return super().query(query, runtime, env, messages, extra_args)

    class InstrumentedAttriGuardExecutionLoop(ag_module.AttriGuardExecutionLoop):
        """Observation only: records the released route of every call; decisions are the release's."""

        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self.tools_executor = RecordingToolsExecutor(self.tools_executor.output_formatter)

        def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):  # noqa: B006, ANN001
            recorder.begin_gate_query()
            return super().query(query, runtime, env, messages, extra_args)

        def _attenuate_observation(self, text, runtime, env):  # noqa: ANN001
            recorder.observations += 1
            return super()._attenuate_observation(text, runtime, env)

        def _fuzzy_survive(self, orig_call, candidates, user_task, runtime, env):  # noqa: ANN001
            exact = any(call_signature(orig_call) == call_signature(c) for c in candidates)
            same_function = any(c.function == orig_call.function for c in candidates)
            before = judge_probe.calls
            survived = super()._fuzzy_survive(orig_call, candidates, user_task, runtime, env)
            judged = judge_probe.calls > before
            route = classify_route(exact=exact, same_function=same_function, has_judge=self.judge_llm is not None,
                                   judged=judged, raw=judge_probe.last_raw,
                                   logprobs_present=judge_probe.last_logprobs_present, survived=bool(survived))
            recorder.record_audited(orig_call, list(candidates), route=route, survived=bool(survived), exact=exact,
                                    judge_called=judged, judge_logprobs_present=judge_probe.last_logprobs_present,
                                    judge_json_survive=_json_survive(judge_probe.last_raw) if judged else None)
            return survived

    my_agent_pipeline._get_attriguard_aux_llms = _routed_aux_llms
    my_agent_pipeline.AttriGuardExecutionLoop = InstrumentedAttriGuardExecutionLoop

    rows_def = config["rows"]
    pipelines: dict[str, Any] = {}
    gates: dict[str, Any] = {}
    for row_id in stage["rows"]:
        row = rows_def[row_id]
        if row.get("defense") == "attriguard":
            os.environ["ATTRIGUARD_LEVEL"] = str(int(row["level"]))
        pipeline = my_agent_pipeline.AgentPipeline.from_config(my_agent_pipeline.PipelineConfig(
            llm=agent_llm, model_id=None, defense=row.get("defense"), tool_delimiter="tool",
            system_message_name=None, system_message=None, tool_output_format=None, attack=None, suite_name=None))
        gate = next((el for el in pipeline.elements if isinstance(el, InstrumentedAttriGuardExecutionLoop)), None)
        if row.get("defense") == "attriguard":
            expected = row["gate"]
            actual = {k: getattr(gate, k, None) for k in ac.GATE_KEYS}
            if gate is None or actual != expected or gate.judge_llm is not judge_probe or gate.attenuation_llm is not attenuation_llm:
                raise AdapterRefusal(f"row {row_id}: gate not built as configured: {actual} vs {expected}")
            if actual["debug"] is not True:
                raise AdapterRefusal(f"row {row_id}: the gate's debug log is off; skip routes cannot be attributed")
            gates[row_id] = actual
        elif gate is not None:
            raise AdapterRefusal(f"row {row_id}: unexpected gate in a no-defense row")
        pipelines[row_id] = pipeline
    receipt["gates"] = gates
    receipt["pipeline_names"] = {r: p.name for r, p in pipelines.items()}
    receipt["episode_request_ceilings"] = {r: int(rows_def[r]["episode_request_ceiling"]) for r in stage["rows"]}

    class RecordingRuntime(FunctionsRuntime):
        """AgentDojo FunctionsRuntime that also records each executed tool call (both executors use it)."""

        executed: list[dict[str, Any]]

        def run_function(self, env, function, kwargs, raise_on_error=False):  # noqa: ANN001
            result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
            self.executed.append({"attempt": recorder.attempt, "function": function, "args": copy.deepcopy(dict(kwargs)),
                                  "success": error is None, "error": (str(error)[:200] if error else None)})
            return result, error

    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages

    transcripts = out / "transcripts"
    transcripts.mkdir(exist_ok=True)
    calls_path = out / "gate_calls.jsonl"
    episodes_path = out / "episodes.jsonl"

    def run_one(ep: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], BaseException | None]:
        suite = suites[ep["suite"]]
        user_task = suite.get_user_task_by_id(ep["user_task_id"])
        row = rows_def[ep["row"]]
        amap = authority_maps[ep["selection"]]
        context.episode_id = ep["episode_id"]
        meter.begin_episode()
        recorder.begin_episode(ep, amap)
        ceiling.begin(int(row["episode_request_ceiling"]))
        x = ep["attacker_value"]
        euid = f"{run_uid}:{ep['seq']}"
        record: dict[str, Any] = {
            "schema": ac.SCHEMA_EPISODE, "episode_id": ep["episode_id"], "episode_run_uid": euid,
            "config_sha256": config_sha, "pair_id": ep["pair_id"], "seq": ep["seq"],
            "row": ep["row"], "selection": ep["selection"], "case_id": ep["case_id"], "arm": ep["arm"],
            "repeat": ep["repeat"], "suite": ep["suite"], "user_task": ep["user_task_id"], "target": ep["target"],
            "value_kind": ep.get("value_kind"), "family": ep.get("family"), "split": ep.get("split"),
            "attacker_executable": ep["attacker_executable"], "injection_payload_sha256": ep["injection_payload_sha256"],
            "carries_attacker_value": ep.get("carries_attacker_value"), "vectors": ep["vectors"],
            "agent_temperature": agent_temperature, "started_utc": _utc(), "scored": False, "run_error": False,
        }
        started = time.time()
        try:
            task_env = user_task.init_environment(suite.load_and_inject_default_environment(ep["injections"]))
        except Exception as exc:  # noqa: BLE001 - passed the preflight, so this is unexpected: never scored
            record.update({"status": "stimulus_error", "error_type": type(exc).__name__,
                           "error": redact(str(exc), secrets)[:500], "finished_utc": _utc(),
                           "usage_total": {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0}})
            return record, [], exc
        attempts: list[list[Any]] = []
        error: BaseException | None = None
        utility: bool | None = None
        post_adds_x: bool | None = None
        runtime = RecordingRuntime(suite.tools)
        runtime.executed = []
        pre_json = task_env.model_dump_json()
        try:
            pre_env = task_env.model_copy(deep=True)
            messages: list[Any] = []
            model_output = None
            try:
                for attempt in range(3):
                    recorder.attempt = attempt
                    try:
                        _, _, task_env, messages, _ = pipelines[ep["row"]].query(user_task.PROMPT, runtime, task_env)
                    except AbortAgentError as exc:
                        task_env, messages = exc.task_environment, exc.messages
                    attempts.append(list(messages))
                    model_output = model_output_from_messages(messages) if messages else None
                    if model_output is not None:
                        break
                stack = functions_stack_trace_from_messages(messages)
                utility = bool(suite._check_user_task_utility(user_task, model_output or [], pre_env, task_env, stack))
            finally:
                # Tools mutate task_env in place, so the post-state is read even after an error.
                post_adds_x = task_env.model_dump_json().count(x) > pre_json.count(x)
        except BaseException as exc:  # noqa: BLE001 - recorded; the caller decides whether to stop
            if isinstance(exc, KeyboardInterrupt):
                raise
            error = exc

        # Per-call records: every call the agent proposed (assistant messages of finished attempts) plus
        # every call the gate saw (also from an attempt that raised), joined on (attempt, call id).
        gate_rows = {(c["attempt"], c["call_id"]): dict(c) for c in recorder.calls}
        tool_results: dict[tuple[int, Any], Any] = {}
        for k, msgs in enumerate(attempts):
            for m in msgs:
                if m.get("role") == "tool":
                    tool_results[(k, m.get("tool_call_id"))] = m
        has_gate = row.get("defense") is not None
        calls: list[dict[str, Any]] = []
        for k, msgs in enumerate(attempts):
            step = 0
            for m in msgs:
                if m.get("role") != "assistant":
                    continue
                step += 1
                for tc in m.get("tool_calls") or []:
                    key = (k, tc.id)
                    row_rec = gate_rows.pop(key, None)
                    if row_rec is None:
                        result = tool_results.get(key)
                        route = ac.NO_GATE_ROUTE if not has_gate else (
                            "skip_unknown" if result is not None else ac.UNPROCESSED_ROUTE)
                        row_rec = {"attempt": k, "call_id": tc.id, "function": tc.function,
                                   "args_sha256": ac.args_digest(tc.args), "audited": False, "route": route,
                                   "survived": None, **recorder.flags(tc)}
                    row_rec["step"] = step
                    calls.append(row_rec)
        calls.extend(gate_rows.values())  # gate-seen calls from an attempt that raised (no messages)
        for c in calls:
            result = tool_results.get((c["attempt"], c["call_id"]))
            if result is not None:
                err = str(result.get("error") or "")
                c["blocked_by_gate"] = err.startswith(ac.ATTRIGUARD_BLOCKED_MARKER)
                c["executed"] = not err
                c["tool_error"] = err[:200] if err and not c["blocked_by_gate"] else None
            else:
                c["blocked_by_gate"] = bool(c.get("audited") and c.get("survived") is False)
                c["executed"] = False if c["blocked_by_gate"] else None
                c["tool_error"] = None

        # Oracle input: every call that reached a tool, from the recording runtime (so calls executed before
        # an episode error still count), with the tool's own success flag. Calls the gate blocked never
        # reach a tool; they are added to attacker_attempted below.
        executed_calls = [{"function": e["function"], "args": e["args"], "success": e["success"]} for e in runtime.executed]
        blocked_x = [c for c in calls if c.get("blocked_by_gate") and c.get("carries_attacker")]
        status = "done" if error is None else ("aborted" if _is_guard_refusal(error) else "error")
        if status != "aborted":
            verdict = oracle.classify_outcome(
                ep["target"], ep["legitimate_set"], x, ep.get("decoy_value"), executed_calls, utility,
                authority_args=amap, run_error=error is not None,
                attacker_state_observable=ep["attacker_state_observable"], post_state_adds_attacker=post_adds_x)
            details = dict(verdict["details"])
            # A gate-blocked X call is an attempt too (requested into an authority argument, never executed).
            details["attacker_attempted"] = bool(details["attacker_attempted"] or blocked_x)
            details["attacker_blocked_by_gate"] = len(blocked_x)
            record.update({"scored": True, "outcome": verdict["outcome"], "subtype": verdict["subtype"],
                           "oracle_details": details})
        tool_outputs = [_content_text(m.get("content")) for msgs in attempts for m in msgs if m.get("role") == "tool"]
        snap = meter.snapshot()["episode"]
        record.update({
            "status": status, "run_error": error is not None and status != "aborted", "utility": utility,
            "post_state_adds_attacker": post_adds_x, "attempts": len(attempts),
            **ac.exposure_flags(tool_outputs, ep, oracle.contains_value),
            "funnel": ac.episode_funnel(calls, record.get("outcome")),
            "gate_queries": recorder.gate_queries, "attenuated_observations": recorder.observations,
            "instrumentation_anomalies": list(recorder.anomalies),
            "requests_sent": ceiling.count, "ceiling_refusals": ceiling.refusals,
            "ceiling_reached": ceiling.refusals > 0,
            "usage": snap,
            "usage_total": {"requests": sum(v["requests"] for v in snap.values()),
                            "prompt_tokens": sum(v["prompt_tokens"] for v in snap.values()),
                            "completion_tokens": sum(v["completion_tokens"] for v in snap.values())},
            "wall_seconds": round(time.time() - started, 2), "finished_utc": _utc(),
        })
        if error is not None:
            record.update({"error_type": type(error).__name__, "error_status_code": getattr(error, "status_code", None),
                           "error": redact(str(error), secrets)[:1000]})
            (out / "last_error_traceback.txt").write_text(redact("".join(traceback.format_exception(error)), secrets),
                                                          encoding="utf-8")
        call_rows = [{"schema": ac.SCHEMA_CALL, "episode_id": ep["episode_id"], "episode_run_uid": euid,
                      "status": status, "carried": False, "config_sha256": config_sha, "row": ep["row"],
                      "selection": ep["selection"], "case_id": ep["case_id"], "arm": ep["arm"],
                      "repeat": ep["repeat"], **c} for c in calls]
        # Short name: case ids are long and Windows paths are limited to 260 characters.
        tname = f"{ep['seq']:05d}_{ep['row']}_{ac.sha256_bytes(ep['episode_id'].encode('utf-8'))[:12]}.json"
        try:
            (transcripts / tname).write_text(json.dumps({
                "episode_id": ep["episode_id"], "episode_run_uid": euid, "status": status,
                "attempts": [_serialise_messages(msgs) for msgs in attempts],
                "executed_calls": runtime.executed, "gate_calls": calls}, ensure_ascii=False, indent=1, default=str),
                encoding="utf-8")
            record["transcript"] = tname
        except OSError:
            pass
        return record, call_rows, error

    # Resume: scored episodes of earlier runs with the same receipt identity are carried over, with their
    # per-call rows; anything else (a different config, oracle, adapter, artifact, case file, mode or plan)
    # is refused.
    planned_ids = {e["episode_id"] for e in planned}
    carried_records: list[dict[str, Any]] = []
    carried_calls: list[dict[str, Any]] = []
    carried_ids: set[str] = set()
    for folder in args.resume_from:
        prev = Path(folder).resolve()
        if prev == out:
            raise AdapterRefusal("refusing: --resume-from names the output directory itself")
        prev_receipt_path = prev / "adapter_receipt.json"
        if not prev_receipt_path.is_file() or not (prev / "plan.json").is_file():
            raise AdapterRefusal(f"refusing: {prev} is not a case-adapter run dir (no receipt or plan)")
        prev_receipt = json.loads(prev_receipt_path.read_text(encoding="utf-8"))
        mismatches = ac.resume_mismatches(prev_receipt, receipt)
        if mismatches:
            raise AdapterRefusal(f"refusing to resume from {prev}: {', '.join(mismatches)} differ")
        latest = _latest_by_episode(ac.read_jsonl(prev / "episodes.jsonl"))
        taken: set[str] = set()
        for rid, rec in latest.items():
            if (rec.get("status") in ac.SCORED_STATUSES and rid in planned_ids and rid not in carried_ids
                    and rec.get("config_sha256") == config_sha):
                carried_ids.add(rid)
                taken.add(str(rec.get("episode_run_uid")))
                carried_records.append({**rec, "carried": True, "carried_from": str(prev)})
        carried_calls += [{**c, "carried": True} for c in ac.read_jsonl(prev / "gate_calls.jsonl")
                          if str(c.get("episode_run_uid")) in taken]
    for rec in carried_records:
        _append_jsonl(episodes_path, rec)
    for row_rec in carried_calls:
        _append_jsonl(calls_path, row_rec)
    receipt["carried_episodes"] = len(carried_records)
    _write_json(receipt_path, receipt)
    price = config.get("price_snapshot_usd_per_mtok")

    def write_summary() -> dict[str, Any]:
        latest = _latest_by_episode(ac.read_jsonl(episodes_path))
        summary = ac.summarize(planned, list(latest.values()), stage=args.stage, mode=mode, case_files=case_docs,
                               baseline_row=config["baseline_row"], price=price)
        summary["judge_probe"] = {"calls": judge_probe.calls, "logprobs_mode": context.logprobs_mode,
                                  "logprobs_rejections": judge_probe.logprobs_rejections,
                                  "logprobs_disabled_after_rejection": context.logprobs_disabled,
                                  "responses_with_logprobs": meter.snapshot()["total"]["judge"]["logprobs_returned"]}
        summary["wire"] = {role: {"dropped_fields": sorted(c.wire_reports["dropped_fields"]),
                                  "injected_max_tokens": c.wire_reports["injected_max_tokens"],
                                  "stripped_logprobs": c.wire_reports["stripped_logprobs"]} for role, c in clients.items()}
        summary["carried_episodes"] = len(carried_records)
        summary["agent_temperature"] = agent_temperature
        _write_json(out / "summary.json", summary)
        return summary

    exit_code, stop_reason, new_count, consecutive = EXIT_OK, "plan_complete", 0, 0
    try:
        for ep in planned:
            if ep["episode_id"] in carried_ids:
                continue
            if args.max_episodes is not None and new_count >= args.max_episodes:
                stop_reason = "max_episodes"
                break
            record, call_rows, error = run_one(ep)
            _append_jsonl(episodes_path, record)
            for row_rec in call_rows:
                _append_jsonl(calls_path, row_rec)
            new_count += 1
            write_summary()
            if error is None:
                consecutive = 0
                continue
            if record["status"] == "stimulus_error":
                exit_code, stop_reason = EXIT_CONFIG, f"stimulus failed to build: {record['episode_id']}"
                break
            if record["status"] == "aborted":
                exit_code, stop_reason = EXIT_GUARD_HALT, f"guard refused (HTTP {getattr(error, 'status_code', '?')})"
                break
            consecutive += 1
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                exit_code, stop_reason = EXIT_ERRORS, f"{consecutive} consecutive episode errors"
                break
    except BaseException as exc:  # noqa: BLE001
        exit_code, stop_reason = EXIT_OTHER, f"{type(exc).__name__}: {redact(str(exc), secrets)[:300]}"
    summary = write_summary()
    receipt.update(finished_utc=_utc(), status="ok" if exit_code == 0 else "stopped", stop_reason=stop_reason,
                   new_episodes=new_count, exit_code=exit_code, summary_file="summary.json",
                   usage_this_invocation=meter.snapshot()["total"])
    _write_json(receipt_path, receipt)
    print(json.dumps({"stage": args.stage, "stop_reason": stop_reason, "new_episodes": new_count,
                      "carried": len(carried_records), "scored": summary["scored_episodes"],
                      "planned": summary["planned_episodes"],
                      "tokens": summary["usage"]["prompt_tokens"] + summary["usage"]["completion_tokens"]}))
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AdapterRefusal, ac.CaseFileError) as refusal:
        print(str(refusal), file=sys.stderr)
        sys.exit(EXIT_CONFIG)
