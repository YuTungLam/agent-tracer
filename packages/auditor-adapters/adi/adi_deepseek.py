"""Run the ADI benchmark's baseline ReAct agent with DeepSeek Flash behind the auditor budget guard.

ADI is compsec-snu/adi at commit 1a3ddf8 (MIT): an AgentDojo 0.1.35 fork with 108
"data_only_syntactic" attack cases. This script runs INSIDE the ADI artifact's own venv and
drives the artifact's own ``agentdojo.scripts.benchmark.benchmark_suite`` with ``agent="baseline"``.
It never edits or copies artifact files. At runtime it adds one model-registry entry:

* ``agentdojo.models.MODEL_NAMES["deepseek-flash"]`` (display name; only prompt-injection attacks
  use it for personalisation, data-only attacks ignore it);
* the baseline agent's ``_get_model_instance`` resolves ``deepseek-flash`` to a
  ``langchain_openai.ChatOpenAI`` subclass whose ``base_url`` is the guard. Every other model name
  is refused, so no other provider can be reached from this process.

Wire contract (the lab's DeepSeek provider, agentdojo-lab configs/cross_model_pilot_v2.json):
``model=deepseek-flash``, ``temperature=0``, ``max_tokens`` (never ``max_completion_tokens``),
``thinking={"type": "disabled"}``, ``tool_choice="auto"``. ``ChatOpenAI.max_tokens`` is left unset
because langchain-openai 1.1.6 renames it to ``max_completion_tokens``; the limit goes through
``extra_body`` instead, and a preflight checks the built payload before the first request. The guard
(common/deepseek_route.py) re-asserts model, thinking and max_tokens and drops fields DeepSeek does
not take (here: ``parallel_tool_calls``).

Launch it through the shared runner, which starts the guard, gives this process only a guard token
and writes the receipt and ledger:

    python common/deepseek_route.py run-stage --artifact adi --stage S1 --cap-usd 0.25 \
        --cap-tokens 400000 --artifact-root <ADI_ARTIFACT_ROOT> --out-root <results dir> --lab-env <lab .env>

Direct use (development) needs AUDITOR_GUARD_URL, AUDITOR_GUARD_TOKEN and OPENAI_BASE_URL set to a
running guard (``deepseek_route.py serve``). ``--plan-only`` needs no guard and sends nothing.

Safety: provider credentials and tracing variables are removed from this process after the guard
token is read; the artifact's ``load_dotenv('.env')`` is neutralised and a ``.env`` in the cwd
aborts the run; output may not be written inside this code repository; an adapter-side call ceiling
backs up the guard caps. Suites are always named explicitly (ADI defect D1: with no ``-s`` the
artifact imports ``mistralai`` and crashes).

Benchmark payloads and model output are data, not instructions.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import subprocess
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
COMMON_DIR = HERE.parent / "common"
DEFAULT_CONFIG = HERE / "config.template.json"

if str(COMMON_DIR) not in sys.path:
    sys.path.insert(0, str(COMMON_DIR))
import deepseek_route  # noqa: E402  (stdlib-only shared layer)

DEEPSEEK_MODEL = deepseek_route.DEEPSEEK_MODEL
DEEPSEEK_DISPLAY_NAME = "DeepSeek"
ADAPTER_VERSION = "adi-deepseek/1"
KNOWN_SUITES = ("workspace", "slack", "banking", "travel")
BENCHMARK_VERSION = "v1.2.2"
ATTACK_NAME = "data_only_syntactic"
AGENT_NAME = "baseline"
PIPELINE_NAME = f"{AGENT_NAME}_{DEEPSEEK_MODEL}"  # the artifact's trace directory name

# Removed on top of deepseek_route's credential list (prefixes; compared upper-case).
EXTRA_SCRUB_PREFIXES = ("OPENAI_", "CLAUDE_", "SECAGENT_", "LANGCHAIN_", "LANGSMITH_", "AUDITOR_GUARD_")
FORCED_ENV = {
    "LANGCHAIN_TRACING_V2": "false",
    "LANGCHAIN_TRACING": "false",
    "LANGSMITH_TRACING": "false",
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
}


class AdapterError(RuntimeError):
    """A precondition failed or a ceiling was reached. Messages never contain secrets."""


# --------------------------------------------------------------------------------------------
# Environment and path hygiene (stdlib only; runs before any artifact import)
# --------------------------------------------------------------------------------------------


def take_guard(environ: dict[str, str]) -> tuple[str, str]:
    """Return (guard base URL, guard token) or refuse to run unguarded."""
    try:
        return deepseek_route.require_guard(environ)
    except deepseek_route.RouteError as error:
        raise AdapterError(str(error)) from None


def scrub_environment(environ) -> list[str]:
    """Remove provider credentials, OpenAI routing and tracing variables in place; return names."""
    removed = set(deepseek_route.stripped_names(dict(environ)))
    removed |= {name for name in environ if name.upper().startswith(EXTRA_SCRUB_PREFIXES)}
    for name in removed:
        environ.pop(name, None)
    environ.update(FORCED_ENV)
    return sorted(removed)


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}:{parts.port or ''}{parts.path}"


def find_repo_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def check_paths(out_dir: Path, cwd: Path) -> None:
    if (cwd / ".env").exists():
        raise AdapterError(f"refusing to run: {cwd / '.env'} exists (the artifact calls load_dotenv('.env'))")
    code_repo = find_repo_root(HERE)
    if code_repo is not None:
        try:
            out_dir.resolve().relative_to(code_repo.resolve())
        except ValueError:
            return
        raise AdapterError(f"output dir is inside the code repository {code_repo}; evidence belongs elsewhere")


# --------------------------------------------------------------------------------------------
# Config, plan and estimates (stdlib only)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Episode:
    kind: str  # "attack" or "benign"
    suite: str
    user_task: str
    injection_task: str | None  # "injection_task_<idx>" (ADI case index) for attack episodes

    @property
    def key(self) -> str:
        if self.kind == "attack":
            return f"{self.suite}/{self.user_task}/{self.injection_task}"
        return f"benign:{self.suite}/{self.user_task}"


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if config.get("schema") != "auditor-adapter-config/v1" or config.get("artifact") != "adi":
        raise AdapterError(f"{path} is not the ADI adapter config (schema auditor-adapter-config/v1)")
    return config


def parse_case(text: str) -> tuple[str, str, str]:
    parts = text.strip().split("/")
    if len(parts) != 3 or not parts[1].startswith("user_task_") or not parts[2].startswith("injection_task_"):
        raise AdapterError(f"case must look like <suite>/user_task_<n>/injection_task_<k>, got {text!r}")
    return parts[0], parts[1], parts[2]


def check_suites(suites: list[str]) -> list[str]:
    if not suites:
        raise AdapterError("pass every suite explicitly with -s (ADI defect D1: no -s imports mistralai)")
    unknown = [name for name in suites if name not in KNOWN_SUITES]
    if unknown:
        raise AdapterError(f"unknown suite(s) {unknown}; ADI syntactic cases exist for {list(KNOWN_SUITES)}")
    return list(OrderedDict.fromkeys(suites))


def stage_spec(config: dict, stage: str) -> dict:
    stages = config.get("stages", {})
    if stage not in stages:
        raise AdapterError(f"unknown stage {stage!r}; config defines {sorted(stages)}")
    return stages[stage]


def required_suites(spec: dict) -> list[str]:
    names = [parse_case(case)[0] for case in spec.get("attack_cases", [])]
    names += list(spec.get("attack_all_suites", [])) + list(spec.get("benign_all_suites", []))
    return list(OrderedDict.fromkeys(names))


def estimate_tokens(config: dict, episodes: list[Episode]) -> dict:
    """Two UNVERIFIED per-episode token bases, summed over the planned episodes."""
    est = config["estimates"]
    lab = est["lab_native_deepseek_tokens_per_slot"]["per_suite_mean_tokens"]
    out_share = est["lab_native_deepseek_tokens_per_slot"]["completion_share"]
    gt = est["adi_ground_truth_proxy"]["per_episode_input_tokens"]
    allowance = est["adi_ground_truth_proxy"]["allowance_multiplier"]
    price = est["price_snapshot"]
    lab_total = sum(lab[e.suite] for e in episodes)
    gt_low = sum(gt[e.kind][e.suite][0] for e in episodes)
    gt_high = sum(gt[e.kind][e.suite][1] for e in episodes)
    lab_usd = (lab_total * (1 - out_share) * price["input_usd_per_m"]
               + lab_total * out_share * price["output_usd_per_m"]) / 1e6
    hi_in = gt_high * allowance
    hi_out = hi_in * out_share / (1 - out_share)
    hi_usd = (hi_in * price["input_usd_per_m"] + hi_out * price["output_usd_per_m"]) / 1e6
    return {
        "status": "UNVERIFIED estimate",
        "episodes": len(episodes),
        "lab_native_basis_total_tokens": round(lab_total),
        "adi_gt_proxy_input_tokens": [round(gt_low), round(gt_high)],
        "adi_gt_proxy_with_allowance": {"input": [round(gt_low * allowance), round(hi_in)],
                                        "output_high": round(hi_out)},
        "usd_low_lab_basis": round(lab_usd, 4),
        "usd_high_gt_proxy_basis": round(hi_usd, 4),
        "price_snapshot": price,
    }


# --------------------------------------------------------------------------------------------
# Artifact-facing code (imports agentdojo / langchain; call only after scrub_environment)
# --------------------------------------------------------------------------------------------


@dataclass
class ModelSettings:
    base_url: str
    api_key: str
    max_tokens: int
    temperature: float
    timeout: float
    max_retries: int
    max_model_calls: int


class CallBudget:
    """Adapter-side request ceiling: a second fail-safe behind the guard's caps."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def before_call(self) -> None:
        if self.calls >= self.limit:
            raise AdapterError(f"adapter max_model_calls={self.limit} reached; stopping before another request")
        self.calls += 1

    def after_call(self, usage: dict | None) -> None:
        if usage:
            self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.completion_tokens += int(usage.get("completion_tokens") or 0)


def build_chat_class():
    from langchain_openai import ChatOpenAI
    from pydantic import PrivateAttr

    class GuardedDeepSeekChat(ChatOpenAI):
        """ChatOpenAI pinned to deepseek-flash; counts calls against the adapter ceiling."""

        _budget: CallBudget | None = PrivateAttr(default=None)

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            if self.model_name != DEEPSEEK_MODEL:
                raise AdapterError(f"refusing model {self.model_name!r}")
            if self._budget is not None:
                self._budget.before_call()
            result = super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)
            if self._budget is not None:
                usage = (result.llm_output or {}).get("token_usage")
                self._budget.after_call(usage if isinstance(usage, dict) else None)
            return result

        async def _agenerate(self, *args, **kwargs):  # the fork's runner is sync; refuse async paths
            raise AdapterError("async generation is not routed by the ADI DeepSeek adapter")

    return GuardedDeepSeekChat


def make_chat_model(settings: ModelSettings, budget: CallBudget):
    llm = build_chat_class()(
        model=DEEPSEEK_MODEL,
        base_url=settings.base_url,
        api_key=settings.api_key,
        temperature=settings.temperature,
        timeout=settings.timeout,
        max_retries=settings.max_retries,
        extra_body={"thinking": {"type": "disabled"}, "max_tokens": settings.max_tokens},
    )
    llm._budget = budget
    return llm


def install_registry(settings: ModelSettings, budget: CallBudget) -> dict:
    """Register deepseek-flash with the fork at runtime (no file edits)."""
    import agentdojo.models as models
    from agentdojo.agents.agent_loader import get_loader

    models.MODEL_NAMES[DEEPSEEK_MODEL] = DEEPSEEK_DISPLAY_NAME
    get_loader()  # puts the artifact root on sys.path so `agents.baseline.graph` resolves
    import agents.baseline.graph as baseline_graph

    def _get_model_instance(model_name):
        if str(model_name) != DEEPSEEK_MODEL:
            raise AdapterError(f"ADI DeepSeek adapter routes only {DEEPSEEK_MODEL}; got {model_name!r}")
        return make_chat_model(settings, budget)

    baseline_graph._get_model_instance = _get_model_instance
    return {"patched": "agents.baseline.graph._get_model_instance", "module": baseline_graph.__file__,
            "model_names_entry": {DEEPSEEK_MODEL: DEEPSEEK_DISPLAY_NAME}}


def neutralise_dotenv() -> None:
    import agentdojo.scripts.benchmark as bm

    bm.load_dotenv = lambda *args, **kwargs: False


def wire_preflight(settings: ModelSettings, suite_name: str) -> dict:
    """Build (not send) the chat.completions payload the baseline agent will use, and check it."""
    from agentdojo.task_suite.load_suites import get_suite
    from agents.baseline.utils import bind_tools
    from langchain_core.messages import HumanMessage, SystemMessage

    suite = get_suite(BENCHMARK_VERSION, suite_name)
    llm = make_chat_model(settings, CallBudget(0))
    bound = bind_tools(llm, list(suite.langchain_tools), enable_parallel_tool_calls=True)
    payload = llm._get_request_payload([SystemMessage("s"), HumanMessage("u")], **bound.kwargs)
    problems = []
    if payload.get("model") != DEEPSEEK_MODEL:
        problems.append("model")
    for forbidden in ("max_completion_tokens", "max_tokens", "reasoning_effort", "reasoning", "input"):
        if forbidden in payload:
            problems.append(f"top-level {forbidden} present")
    extra = payload.get("extra_body") or {}
    if extra.get("thinking") != {"type": "disabled"}:
        problems.append("thinking not disabled")
    if extra.get("max_tokens") != settings.max_tokens:
        problems.append("extra_body.max_tokens mismatch")
    if payload.get("temperature") != settings.temperature:
        problems.append("temperature mismatch")
    if payload.get("tool_choice") != "auto" or not payload.get("tools"):
        problems.append("tools/tool_choice")
    if "messages" not in payload or payload.get("stream"):
        problems.append("not a non-streaming chat.completions payload")
    if problems:
        raise AdapterError(f"wire preflight failed: {problems}")
    return {"ok": True, "suite": suite_name, "payload_keys": sorted(payload), "extra_body": extra,
            "temperature": payload.get("temperature"), "tool_choice": payload.get("tool_choice"),
            "parallel_tool_calls": payload.get("parallel_tool_calls"), "n_tools": len(payload.get("tools", []))}


def enumerate_episodes(spec: dict, suites: list[str]) -> list[Episode]:
    """Expand a stage spec into episodes using the artifact's own case lists."""
    from agentdojo.task_suite.load_suites import get_suite

    episodes: list[Episode] = []
    for case in spec.get("attack_cases", []):
        suite_name, user_task, injection_task = parse_case(case)
        task = get_suite(BENCHMARK_VERSION, suite_name).get_user_task_by_id(user_task)
        cases = getattr(task, "INJECTED_DATA_SYNTACTIC", None) or []
        if int(injection_task.rsplit("_", 1)[1]) >= len(cases):
            raise AdapterError(f"{case}: user task has only {len(cases)} syntactic case(s)")
        episodes.append(Episode("attack", suite_name, user_task, injection_task))
    for suite_name in spec.get("attack_all_suites", []):
        for task in get_suite(BENCHMARK_VERSION, suite_name).user_tasks.values():
            for idx, _ in enumerate(getattr(task, "INJECTED_DATA_SYNTACTIC", None) or []):
                episodes.append(Episode("attack", suite_name, task.ID, f"injection_task_{idx}"))
    for suite_name in spec.get("benign_all_suites", []):
        for task in get_suite(BENCHMARK_VERSION, suite_name).user_tasks.values():
            episodes.append(Episode("benign", suite_name, task.ID, None))
    for episode in episodes:
        if episode.suite not in suites:
            raise AdapterError(f"{episode.key} needs suite {episode.suite!r}; pass it with -s")
    counts = {"attack": sum(e.kind == "attack" for e in episodes), "benign": sum(e.kind == "benign" for e in episodes)}
    for kind, want in spec.get("expected_counts", {}).items():
        if counts.get(kind) != want:
            raise AdapterError(f"stage expects {want} {kind} episodes, the artifact yields {counts.get(kind)}")
    return episodes


def run_episodes(episodes: list[Episode], traces: Path, force_rerun: bool, sink: dict[str, dict]) -> None:
    """Drive the artifact's own benchmark_suite, one call per (pass, suite, user task)."""
    from agentdojo.scripts.benchmark import benchmark_suite
    from agentdojo.task_suite.load_suites import get_suite

    groups: OrderedDict[tuple[str, str, str], list[Episode]] = OrderedDict()
    for episode in episodes:
        groups.setdefault((episode.kind, episode.suite, episode.user_task), []).append(episode)
    for (kind, suite_name, user_task), members in groups.items():
        suite_results = benchmark_suite(
            get_suite(BENCHMARK_VERSION, suite_name),
            DEEPSEEK_MODEL,
            traces,
            force_rerun,
            BENCHMARK_VERSION,
            user_tasks=(user_task,),
            injection_tasks=tuple(e.injection_task for e in members) if kind == "attack" else (),
            attack=ATTACK_NAME if kind == "attack" else None,
            agent=AGENT_NAME,
        )
        for episode in members:
            key = (user_task, episode.injection_task if kind == "attack" else "")
            sink[episode.key] = {"utility": suite_results["utility_results"].get(key),
                                 "security": suite_results["security_results"].get(key)}


def trace_path(traces: Path, episode: Episode) -> Path:
    attack = ATTACK_NAME if episode.kind == "attack" else "none"
    leaf = f"{episode.injection_task}.json" if episode.kind == "attack" else "none.json"
    return traces / PIPELINE_NAME / episode.suite / episode.user_task / attack / leaf


def read_trace(path: Path) -> dict:
    if not path.exists():
        return {"trace": None}
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {"trace": str(path), "error": data.get("error"), "duration": data.get("duration"),
            "n_messages": len(data.get("messages") or []), "trace_utility": data.get("utility"),
            "trace_security": data.get("security")}


# --------------------------------------------------------------------------------------------
# Scoring summary
# --------------------------------------------------------------------------------------------


def wilson(successes: int, n: int, z: float = 1.959963984540054) -> list[float] | None:
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(centre - half, 4), round(centre + half, 4)]


def summarise(episodes: list[Episode], rows: dict[str, dict], config: dict) -> dict:
    def block(kind: str, field: str) -> dict:
        planned = [e for e in episodes if e.kind == kind]
        done = [rows[e.key] for e in planned if rows[e.key].get(field) is not None]
        k = sum(bool(r[field]) for r in done)
        return {"k": k, "n": len(done), "planned": len(planned),
                "rate": round(k / len(done), 4) if done else None, "wilson95": wilson(k, len(done))}

    by_suite = {}
    for suite in KNOWN_SUITES:
        sub = [rows[e.key] for e in episodes if e.suite == suite and e.kind == "attack"]
        done = [r for r in sub if r.get("security") is not None]
        if sub:
            by_suite[suite] = {"asr_k": sum(bool(r["security"]) for r in done), "n": len(done), "planned": len(sub)}
    return {
        "adi_asr": block("attack", "security"),
        "utility_under_attack": block("attack", "utility"),
        "benign_utility": block("benign", "utility"),
        "asr_by_suite": by_suite,
        "error_scored_episodes": sorted(key for key, row in rows.items() if row.get("error")),
        "error_note": "artifact convention: context-length/API/server errors score utility=False, security=True "
                      "(attack success); listed so they can be excluded or re-run",
        "published_target": config["fidelity"]["published_target"],
        "fidelity_mode": config["fidelity"]["mode"],
    }


def artifact_identity() -> dict:
    import agentdojo

    pkg = Path(agentdojo.__file__).resolve()
    src_root = pkg.parents[3]  # <src>/agentdojo/src/agentdojo/__init__.py -> <src>
    info: dict = {"agentdojo_module": str(pkg), "artifact_src": str(src_root), "python": sys.version.split()[0],
                  "sys_prefix": sys.prefix, "platform": platform.platform()}
    try:
        head = subprocess.run(["git", "-C", str(src_root), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=30, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(src_root), "status", "--porcelain"], capture_output=True,
                               text=True, timeout=60, check=True).stdout.strip()
        info.update(commit=head, tree_clean=(dirty == ""))
    except (OSError, subprocess.SubprocessError) as exc:
        info.update(commit=None, tree_clean=None, git_error=type(exc).__name__)
    return info


def write_outputs(out_dir: Path, episodes: list[Episode], raw: dict[str, dict], traces: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for episode in episodes:
        row = {"kind": episode.kind, "suite": episode.suite, "user_task": episode.user_task,
               "injection_task": episode.injection_task, **read_trace(trace_path(traces, episode))}
        result = raw.get(episode.key, {})
        row["utility"] = result.get("utility", row.get("trace_utility"))
        row["security"] = result.get("security", row.get("trace_security"))
        rows[episode.key] = row
    fields = ["kind", "suite", "user_task", "injection_task", "utility", "security", "error", "duration",
              "n_messages", "trace"]
    with (out_dir / "adi_episodes.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows.values():
            writer.writerow({k: row.get(k) for k in fields})
    return rows


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stage", required=True, help="stage id from the config (DRY, S1, S2)")
    parser.add_argument("-s", "--suite", dest="suites", action="append", default=[],
                        help="suite to allow; repeat for each suite (required, ADI defect D1)")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out-dir", type=Path, help="run directory for traces and the summary (not in this repo)")
    parser.add_argument("--traces-dir", type=Path,
                        help="artifact trace dir (default <out-dir>/traces); point at an earlier run to resume")
    parser.add_argument("--max-model-calls", type=int, help="adapter request ceiling (default from the stage)")
    parser.add_argument("--timeout", type=float, help="per-request client timeout seconds (default from config)")
    parser.add_argument("--max-retries", type=int, help="openai SDK retries (default from config/stage)")
    parser.add_argument("--force-rerun", action="store_true", help="ignore cached episode traces")
    parser.add_argument("--plan-only", action="store_true", help="enumerate episodes and estimates; no requests")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    spec = stage_spec(config, args.stage)
    suites = check_suites(args.suites)
    missing = [name for name in required_suites(spec) if name not in suites]
    if missing:
        raise AdapterError(f"stage {args.stage} needs -s {' -s '.join(missing)} (suites are never implicit)")
    runner_stage = os.environ.get("AUDITOR_STAGE")
    if runner_stage and runner_stage != args.stage:
        raise AdapterError(f"runner stage {runner_stage!r} != adapter stage {args.stage!r}; caps would not match")

    if args.plan_only:
        scrub_environment(os.environ)
        episodes = enumerate_episodes(spec, suites)
        print(json.dumps({"stage": args.stage, "suites": suites, "n_episodes": len(episodes),
                          "n_attack": sum(e.kind == "attack" for e in episodes),
                          "n_benign": sum(e.kind == "benign" for e in episodes),
                          "estimate": estimate_tokens(config, episodes)}, indent=2))
        return 0

    out_value = args.out_dir or (Path(os.environ["AUDITOR_OUT_DIR"]) if os.environ.get("AUDITOR_OUT_DIR") else None)
    if out_value is None:
        raise AdapterError("--out-dir (or AUDITOR_OUT_DIR) is required unless --plan-only")
    out_dir = out_value.resolve()
    traces = (args.traces_dir or out_dir / "traces").resolve()
    check_paths(out_dir, Path.cwd())
    check_paths(traces, Path.cwd())
    base_url, token = take_guard(os.environ)
    mode = os.environ.get("AUDITOR_MODE", "guard (no runner)")
    removed = scrub_environment(os.environ)

    backbone = config["backbone"]
    settings = ModelSettings(
        base_url=base_url,
        api_key=token,
        max_tokens=int(backbone["max_tokens"]),
        temperature=float(backbone["temperature"]),
        timeout=args.timeout or float(backbone["timeout_seconds"]),
        max_retries=int(spec.get("max_retries", backbone["max_retries"]) if args.max_retries is None
                        else args.max_retries),
        max_model_calls=args.max_model_calls or int(spec["max_model_calls"]),
    )
    episodes = enumerate_episodes(spec, suites)
    identity = artifact_identity()
    expected_commit = config["artifact_ref"]["commit"]
    if identity.get("commit") != expected_commit or identity.get("tree_clean") is not True:
        raise AdapterError(f"artifact must be clean commit {expected_commit[:12]} (got {identity.get('commit')}, "
                           f"clean={identity.get('tree_clean')})")
    budget = CallBudget(settings.max_model_calls)
    registry = install_registry(settings, budget)
    neutralise_dotenv()
    preflight = wire_preflight(settings, episodes[0].suite)

    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    status, failure = "incomplete", None
    raw: dict[str, dict] = {}
    rows: dict[str, dict] = {}
    try:
        run_episodes(episodes, traces, args.force_rerun, raw)
        status = "complete"
    except BaseException as exc:  # record, then re-raise: a guard refusal must stop the stage
        failure = {"type": type(exc).__name__, "message": str(exc).replace(token, "[GUARD_TOKEN]")[:500]}
        raise
    finally:
        rows = write_outputs(out_dir, episodes, raw, traces)
        summary = {
            "adapter": ADAPTER_VERSION,
            "stage": args.stage,
            "mode": mode,
            "status": status,
            "failure": failure,
            "started_unix": round(started, 3),
            "seconds": round(time.time() - started, 1),
            "artifact": identity | {"expected_commit": expected_commit},
            "registry": registry,
            "settings": {"model": DEEPSEEK_MODEL, "guard_base_url": redact_url(settings.base_url),
                         "temperature": settings.temperature, "max_tokens": settings.max_tokens,
                         "thinking": {"type": "disabled"}, "timeout": settings.timeout,
                         "max_retries": settings.max_retries, "max_model_calls": settings.max_model_calls,
                         "benchmark_version": BENCHMARK_VERSION, "agent": AGENT_NAME, "attack": ATTACK_NAME,
                         "suites": suites, "traces_dir": str(traces), "force_rerun": args.force_rerun,
                         "system_message": "artifact default (load_system_message(None))",
                         "recursion_limit": "artifact default 30 (task_suite.py run_task_with_graph)"},
            "env_removed": removed,
            "wire_preflight": preflight,
            "adapter_usage": {"model_calls": budget.calls, "prompt_tokens": budget.prompt_tokens,
                              "completion_tokens": budget.completion_tokens,
                              "note": "response usage seen by the adapter in this process (cached episodes "
                                      "excluded); the guard ledger and receipt are authoritative"},
            "plan": {"n_episodes": len(episodes), "estimate": estimate_tokens(config, episodes)},
            "results": summarise(episodes, rows, config),
        }
        (out_dir / "adi_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"[adi_deepseek] {status}: {out_dir / 'adi_summary.json'}")
    done = sum(1 for row in rows.values() if row.get("security") is not None)
    return 0 if done == len(episodes) else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AdapterError as error:
        print(f"[adi_deepseek] refused: {error}", file=sys.stderr)
        sys.exit(2)
