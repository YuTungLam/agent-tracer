"""Run native AgentDojo tasks, retaining its trace format and clean default behavior."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
import tomllib
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from uuid import uuid4

import openai as openai  # Compatibility export used by existing callers and mock transports.
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.benchmark import benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite, get_suites
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.html_report import export_run_html
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.offline import make_offline_client
from agentdojo_lab.pacing import RequestPacer
from agentdojo_lab.providers import GROQ_BASE_URL as GROQ_BASE_URL
from agentdojo_lab.providers import EndpointSettings, Provider
from agentdojo_lab.recording import EventRecorder

if TYPE_CHECKING:
    from agentdojo_lab.evaluation_runner import EvaluationTrial

ROOT = Path(__file__).resolve().parents[2]


class RunExecutionError(RuntimeError):
    """A failed run whose partial results were persisted at a known location."""

    def __init__(self, summary_path: Path, cause: Exception):
        self.summary_path = summary_path
        super().__init__(f"Run failed ({type(cause).__name__}). Details: {summary_path}")


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    provider: Provider = "groq"
    model: str = "openai/gpt-oss-120b"
    base_url: str | None = Field(default=None, exclude_if=lambda value: value is None)
    api_key_env: str | None = Field(default=None, exclude_if=lambda value: value is None)
    causal_endpoint: EndpointSettings | None = Field(default=None, exclude_if=lambda value: value is None)
    benchmark_version: str = "v1.2.2"
    suite: str = "workspace"
    user_tasks: list[str] = Field(default_factory=lambda: ["user_task_0"], min_length=1)
    temperature: float = Field(default=0.0, ge=0, le=2)
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    max_completion_tokens: int = Field(default=4096, gt=0, le=65536)
    max_tool_rounds: int = Field(default=8, ge=1, le=100)
    request_timeout_seconds: float = Field(default=60.0, gt=0)
    record_events: bool = True
    online_provenance: bool = False
    online_causal_audit: bool = Field(default=False, exclude_if=lambda value: value is False)
    provenance_policy: str | None = None
    cascade_profile: Literal["ordinary", "implicit_string", "safe_control"] = Field(
        default="ordinary", exclude_if=lambda value: value == "ordinary"
    )
    lineage_namespace: str | None = None
    canary_enabled: bool = False
    semantic_model: str | None = None
    semantic_revision: str | None = None
    causal_model: str = Field(
        default="openai/gpt-oss-120b", exclude_if=lambda value: value == "openai/gpt-oss-120b"
    )
    causal_max_requests: int = Field(default=8, ge=0, le=32, exclude_if=lambda value: value == 8)
    causal_max_sources: int = Field(default=8, ge=1, le=8, exclude_if=lambda value: value == 8)
    causal_max_pairs: int = Field(default=12, ge=0, le=28, exclude_if=lambda value: value == 12)
    causal_request_timeout_seconds: float = Field(
        default=60.0, gt=0, exclude_if=lambda value: value == 60.0
    )
    pacing_tokens_per_minute: int | None = Field(default=None, ge=1000, le=1000000)

    @model_validator(mode="after")
    def attribution_configuration(self):
        self.primary_endpoint()
        if self.provider == "openai_compatible":
            if "model" not in self.model_fields_set:
                raise ValueError("openai_compatible requires an explicit served model name")
            if self.reasoning_effort is not None:
                raise ValueError("openai_compatible currently requires reasoning_effort to be omitted")
            if self.online_causal_audit and self.causal_endpoint is None:
                raise ValueError("A local primary with online causal auditing requires explicit causal_endpoint")
        if self.causal_endpoint is not None and self.causal_model != "openai/gpt-oss-120b":
            raise ValueError("Use causal_endpoint.model instead of causal_model when selecting an endpoint")
        if self.cascade_profile != "ordinary" and not self.provenance_policy:
            raise ValueError("A nonordinary cascade profile requires a frozen provenance policy")
        if self.canary_enabled and (not self.provenance_policy or len(self.user_tasks) != 1):
            raise ValueError("Canary intervention requires a frozen policy and one native task per run")
        if self.lineage_namespace is not None and (
            not self.lineage_namespace.strip() or not self.provenance_policy or len(self.user_tasks) != 1
        ):
            raise ValueError(
                "Lineage requires a nonempty namespace, a frozen policy and one native task per run"
            )
        if self.online_provenance and not self.record_events:
            raise ValueError("Online provenance requires event recording")
        if self.online_causal_audit and (
            not self.online_provenance
            or not self.provenance_policy
            or not self.lineage_namespace
            or not self.semantic_model
            or not self.semantic_revision
        ):
            raise ValueError(
                "Online causal audit requires online_provenance, a frozen policy, lineage, "
                "and a pinned semantic model"
            )
        if self.provenance_policy is not None and (
            not self.online_provenance or not self.provenance_policy.strip()
        ):
            raise ValueError("A provenance policy requires online_provenance and a nonempty path")
        if bool(self.semantic_model) != bool(self.semantic_revision):
            raise ValueError("Use semantic_model and semantic_revision together")
        if (self.semantic_model is not None or self.semantic_revision is not None) and (
            not self.online_provenance or not self.semantic_model or not self.semantic_revision
        ):
            raise ValueError("Semantic model settings require online_provenance and nonempty values")
        return self

    def primary_endpoint(self) -> EndpointSettings:
        return EndpointSettings(
            provider=self.provider, model=self.model, base_url=self.base_url, api_key_env=self.api_key_env
        )

    def judge_endpoint(self) -> EndpointSettings:
        return self.causal_endpoint or EndpointSettings(provider="groq", model=self.causal_model)

    @field_validator("model", "suite", "benchmark_version", "causal_model")
    @classmethod
    def nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("user_tasks")
    @classmethod
    def unique_tasks(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(not task.strip() for task in value):
            raise ValueError("user_tasks must be nonempty, unique task IDs")
        return value


def load_config(path: Path) -> RunConfig:
    return RunConfig.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))


def upstream_status() -> dict:
    expected = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    vendor = ROOT / "vendor" / "agentdojo"
    actual = subprocess.check_output(["git", "-C", str(vendor), "rev-parse", "HEAD"], text=True).strip()
    changes = subprocess.check_output(["git", "-C", str(vendor), "status", "--porcelain"], text=True).strip()
    return {
        **expected,
        "actual_commit": actual,
        "modified": bool(changes),
        "pin_matches": actual == expected["commit"] and not changes,
    }


def require_upstream() -> dict:
    status = upstream_status()
    if not status["pin_matches"]:
        raise ValueError("Upstream checkout differs from upstream.json or has changes; restore it first.")
    return status


def configured_key() -> str:
    load_dotenv(ROOT / ".env", override=False)
    return os.environ.get("GROQ_API_KEY", "").strip()


def doctor(config: RunConfig | None = None) -> dict:
    status = upstream_status()
    suites = get_suites(status["benchmark_version"])
    has_key = bool(configured_key())
    result = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "upstream": status,
        "packages": {name: version(name) for name in ("agentdojo", "openai", "pydantic", "httpx")},
        "suites": {
            name: {"user_tasks": len(suite.user_tasks), "tools": len(suite.tools)}
            for name, suite in suites.items()
        },
        "offline_ready": status["pin_matches"],
        "groq_api_key_configured": has_key,
        "live_prerequisites_ready": has_key and status["pin_matches"],
        "live_connectivity_verified": False,
        "env_file": str(ROOT / ".env"),
    }
    if config is not None:
        endpoint = config.primary_endpoint()
        primary_ready = bool(endpoint.configured_key())
        judge = config.judge_endpoint() if config.online_causal_audit else None
        judge_ready = judge is None or config.causal_max_requests == 0 or bool(judge.configured_key())
        result.update(
            endpoint=endpoint.model_dump(),
            api_key_configured=primary_ready,
            causal_endpoint=judge.model_dump() if judge is not None else None,
            causal_api_key_configured=bool(judge.configured_key()) if judge is not None else None,
            live_prerequisites_ready=status["pin_matches"] and primary_ready and judge_ready,
        )
    return result


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def new_output_dir(mode: str, output: Path | None) -> Path:
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = ROOT / "runs" / f"{stamp}-{mode}-{uuid4().hex[:8]}"
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    return output


def build_pipeline(
    llm: GroqLLM, config: RunConfig, observer: ObservationSession | None = None
) -> BasePipelineElement:
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )
    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.max_iters = config.max_tool_rounds
    return observe_pipeline(pipeline, observer) if observer is not None else pipeline


def run_clean(
    config: RunConfig,
    *,
    offline: bool = False,
    output: Path | None = None,
    pacing_state: Path | None = None,
    evaluation: EvaluationTrial | None = None,
    causal_client=None,
) -> dict:
    upstream = require_upstream()
    suites = get_suites(config.benchmark_version)
    if config.suite not in suites:
        raise ValueError(f"Unknown suite/version: {config.suite}/{config.benchmark_version}")
    suite = get_suite(config.benchmark_version, config.suite)
    for task in config.user_tasks:
        if task not in suite.user_tasks:
            raise ValueError(f"Unknown task {task} in {config.suite}")
    if evaluation is not None:
        from agentdojo_lab.evaluation_runner import validate_evaluation

        validate_evaluation(config, evaluation, suite)
    if offline and (
        config.suite != "workspace"
        or config.benchmark_version != "v1.2.2"
        or config.user_tasks != ["user_task_0"]
    ):
        raise ValueError("Offline smoke supports only workspace v1.2.2 user_task_0.")
    if causal_client is not None and not config.online_causal_audit:
        raise ValueError("An injected causal client requires online_causal_audit")

    endpoint = config.primary_endpoint()
    judge_endpoint = config.judge_endpoint()
    if not offline:
        load_dotenv(ROOT / ".env", override=False)
    key = "" if offline else (
        configured_key() if endpoint.key_variable == "GROQ_API_KEY" else endpoint.configured_key()
    )
    if not offline and not key:
        raise ValueError(f"Set {endpoint.key_variable} in {ROOT / '.env'} before a live run.")
    judge_key = ""
    if config.online_causal_audit and not offline and config.causal_max_requests:
        if causal_client is None:
            judge_key = key if judge_endpoint.key_variable == endpoint.key_variable else judge_endpoint.require_key()
        else:
            judge_key = getattr(causal_client, "api_key", "")
    redactions = tuple(sorted({value for value in (key, judge_key) if value}, key=len, reverse=True))

    policy = None
    if config.provenance_policy is not None:
        from agentdojo_lab.policy import load_policy

        policy = load_policy(Path(config.provenance_policy))
        policy.validate_context(config.suite, config.benchmark_version, [tool.name for tool in suite.tools])

    # Load and verify optional local weights before executing any agent request.
    # Runtime attribution errors are fail-open; invalid setup fails preflight.
    matcher = None
    if config.semantic_model:
        from agentdojo_lab.profiles import get_profile
        from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

        thresholds = get_profile(config.cascade_profile)
        matcher = SemanticMatcher(
            LocalMiniLMEncoder(Path(config.semantic_model).expanduser(), revision=config.semantic_revision),
            semantic_threshold=thresholds.semantic_threshold,
            coverage_threshold=thresholds.coverage_threshold,
        )

    lineage = None
    if config.lineage_namespace is not None:
        from agentdojo_lab.lineage import DCPG

        lineage = DCPG(
            config.lineage_namespace, policy, semantic_matcher=matcher, canary_enabled=config.canary_enabled
        )

    canary = None
    if config.canary_enabled:
        from agentdojo_lab.canary import CanaryInjector

        canary = CanaryInjector(policy)

    mode = "offline-fixture" if offline else f"live-{config.provider.replace('_', '-')}"
    pacer = (
        RequestPacer(config.pacing_tokens_per_minute, pacing_state)
        if config.pacing_tokens_per_minute
        else None
    )
    run_dir = new_output_dir(mode, output)
    lock_hash = hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "mode": mode,
        "real_llm": not offline,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config": config.model_dump(),
        "upstream": upstream,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "uv_lock_sha256": lock_hash,
        "endpoint": "in-process mock transport" if offline else endpoint.url,
        "sdk_max_retries": 0,
        "request_pacing": {
            "enabled": pacer is not None,
            "tokens_per_minute": config.pacing_tokens_per_minute,
            "window_seconds": RequestPacer.window_seconds if pacer else None,
        },
        "adapter": "groq-text-v1" if config.provider == "groq" else "openai-compatible-text-v1",
        "event_recording": {"enabled": config.record_events, "schema_version": 1},
        "input_condition": "canary_intervention" if canary is not None else "passive",
        "online_provenance": {
            "enabled": config.online_provenance,
            "mode": "synchronous_observation; ordered_cascade"
            if policy
            else "synchronous_observation; independent_all_pairs",
            "semantic": matcher.metadata if matcher is not None else None,
            "policy": policy.metadata if policy is not None else None,
            "implementation_sha256": {
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in (
                    "recording.py",
                    "observation.py",
                    "online.py",
                    "provenance.py",
                    "lexical.py",
                    "semantic.py",
                    "cascade.py",
                    "profiles.py",
                    "policy.py",
                )
            }
            if config.online_provenance
            else {},
            "timing_scope": "Model loading excluded; callback compute and flush add latency; no hard deadline",
        },
        "online_causal_audit": {
            "enabled": config.online_causal_audit,
            "mode": (
                "injected_client"
                if causal_client is not None
                else "plan_only"
                if offline or config.causal_max_requests == 0
                else f"isolated_{judge_endpoint.provider}"
            ),
            "model": judge_endpoint.model,
            "max_requests": config.causal_max_requests,
            "max_sources": config.causal_max_sources,
            "max_pairs": config.causal_max_pairs,
            "request_timeout_seconds": config.causal_request_timeout_seconds,
            "sdk_max_retries": 0,
            "transport_isolation": "separate_unobserved_client; no_tools",
            "execution": "synchronous_before_native_tool_runtime; observational_only",
            "action_enforcement": False,
            "model_parameter_updates": 0,
            "implementation_sha256": {
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in (
                    "online_causal.py",
                    "causal_v2.py",
                    "causal_v2_audit.py",
                    "paper_audit.py",
                    "judgment_formats.py",
                )
            }
            if config.online_causal_audit
            else {},
        },
        "attack": None,
        "defense": None,
        "notes": [
            "Offline fixture results validate plumbing only, not model capability."
            if offline
            else "Clean tasks using the native AgentDojo pipeline and evaluator.",
            "Native suite runner may execute a pipeline up to three times total if no final text is returned.",
            "events.jsonl captures outbound HTTP JSON and top-level runtime boundaries when enabled.",
            "Recording observes execution; it does not establish source attribution or causality.",
        ],
    }
    if config.causal_endpoint is not None:
        manifest["online_causal_audit"]["endpoint"] = judge_endpoint.model_dump()
    if lineage is not None:
        manifest["online_provenance"]["lineage"] = lineage.metadata
        manifest["online_provenance"]["implementation_sha256"]["lineage.py"] = hashlib.sha256(
            Path(__file__).with_name("lineage.py").read_bytes()
        ).hexdigest()
    if canary is not None:
        manifest["canary"] = canary.metadata
        manifest["online_provenance"]["implementation_sha256"]["canary.py"] = hashlib.sha256(
            Path(__file__).with_name("canary.py").read_bytes()
        ).hexdigest()
    if evaluation is not None:
        from agentdojo_lab.evaluation_runner import InputComparisonTrial, MatrixEvaluationTrial
        from agentdojo_lab.heldout_runner import HeldoutTrial

        manifest["evaluation"] = evaluation.model_dump()
        manifest["attack"] = {
            "name": "native_direct_evaluation",
            "condition": evaluation.condition,
            "injection_task_id": evaluation.injection_task_id,
            "vector_id": evaluation.vector_id,
            "injection_assigned": evaluation.condition == "injected",
            "payload_sha256": hashlib.sha256(evaluation.payload.encode()).hexdigest(),
        }
        manifest["notes"][0] = (
            "Frozen held-out native clean/injected evaluation; both arms use passive inputs."
            if isinstance(evaluation, HeldoutTrial)
            else "Frozen NT-AgentDojo matrix evaluation; both arms use passive inputs with online causal auditing."
            if isinstance(evaluation, MatrixEvaluationTrial)
            else "Frozen native injected-only input comparison; this run uses "
            + ("canary intervention." if config.canary_enabled else "passive input.")
            if isinstance(evaluation, InputComparisonTrial)
            else "Frozen native clean/injected evaluation; both arms use canary intervention."
        )
        manifest["notes"].extend(
            [
                "Every comparison run receives the same native injection assignment; no clean arm is included."
                if isinstance(evaluation, InputComparisonTrial)
                else "The same native attack-goal evaluator is also run in clean controls; its raw boolean is not ASR.",
                "The global primary SDK request limit spans all native suite query attempts.",
            ]
        )
    write_json(run_dir / "manifest.json", manifest)
    started = time.monotonic()
    llm = None
    recorder = None
    observer = None
    attribution = None
    attribution_status = {}
    causal_auditor = None
    owned_causal_client = None
    results = None
    summary = {"mode": mode, "real_llm": not offline, "run_dir": str(run_dir), "status": "running"}
    try:
        if config.record_events:
            if config.online_provenance:
                from agentdojo_lab.online import OnlineProvenance

                if config.online_causal_audit:
                    from agentdojo_lab import judgment_formats
                    from agentdojo_lab.online_causal import OnlineCausalAuditor

                    judge_client = causal_client
                    if judge_client is None and not offline and config.causal_max_requests:
                        owned_causal_client = judge_endpoint.client(
                            key=judge_key, timeout=config.causal_request_timeout_seconds
                        )
                        judge_client = owned_causal_client
                    causal_auditor = OnlineCausalAuditor(
                        run_dir / "causal-online.jsonl",
                        client=judge_client,
                        max_requests=config.causal_max_requests,
                        canary_enabled=config.canary_enabled,
                        max_sources=config.causal_max_sources,
                        max_pairs=config.causal_max_pairs,
                        judgment_format=judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
                        request_timeout_seconds=config.causal_request_timeout_seconds,
                        model=judge_endpoint.model,
                        **({"reasoning_effort": None} if judge_endpoint.provider == "openai_compatible" else {}),
                    )

                attribution = OnlineProvenance(
                    run_dir / "provenance.jsonl",
                    semantic_matcher=matcher,
                    policy=policy,
                    **({"lineage": lineage} if lineage is not None else {}),
                    **({"canary_enabled": True} if canary is not None else {}),
                    **(
                        {"cascade_profile": config.cascade_profile}
                        if config.cascade_profile != "ordinary"
                        else {}
                    ),
                    **({"causal_auditor": causal_auditor} if causal_auditor is not None else {}),
                )
            recorder = EventRecorder(
                run_dir / "events.jsonl",
                run_dir.name,
                redactions=redactions,
                on_event=attribution.consume if attribution is not None else None,
            )
            recorder.emit("RUN_STARTED", {"mode": mode, "config": config.model_dump()})
            observer = ObservationSession(recorder, **({"canary": canary} if canary is not None else {}))
        client = (
            make_offline_client(suite, suite.user_tasks["user_task_0"], config.model)
            if offline
            else endpoint.client(key=key, timeout=config.request_timeout_seconds)
        )
        with client:
            if observer is not None:
                observer.attach(client)
            llm_type = GroqLLM
            llm_extra = {}
            if evaluation is not None:
                from agentdojo_lab.evaluation_runner import EvaluationGroqLLM

                llm_type = EvaluationGroqLLM
                llm_extra["request_limit"] = evaluation.request_limit
            llm = llm_type(
                client,
                config.model,
                temperature=config.temperature,
                max_completion_tokens=config.max_completion_tokens,
                reasoning_effort=config.reasoning_effort,
                observer=observer,
                pacer=pacer,
                **({"provider": config.provider} if config.provider != "groq" else {}),
                **llm_extra,
            )
            if offline:
                llm.name = "offline_fixture"
            pipeline = build_pipeline(llm, config, observer)
            native_dir = run_dir / "native"
            with OutputLogger(str(native_dir)):
                if evaluation is not None:
                    from agentdojo_lab.evaluation_runner import run_native_evaluation

                    results = run_native_evaluation(
                        pipeline, suite, suite.user_tasks[evaluation.user_task_id], evaluation, native_dir
                    )
                else:
                    results = benchmark_suite_without_injections(
                        pipeline,
                        suite,
                        logdir=native_dir,
                        force_rerun=False,
                        user_tasks=config.user_tasks,
                        benchmark_version=config.benchmark_version,
                    )
        tasks = []
        for path in sorted(native_dir.rglob("*.json")):
            trace = json.loads(path.read_text(encoding="utf-8"))
            messages = trace.get("messages", [])
            calls = [call for m in messages if m["role"] == "assistant" for call in m.get("tool_calls") or []]
            tool_results = [m for m in messages if m["role"] == "tool"]
            pending = bool(messages and messages[-1].get("tool_calls"))
            task_status = "error" if trace.get("error") else "incomplete" if pending else "evaluated"
            if evaluation is not None:
                from agentdojo_lab.evaluation_runner import has_final_text

                if task_status == "evaluated" and not has_final_text(messages):
                    task_status = "incomplete"
            tasks.append(
                {
                    "task": trace["user_task_id"],
                    "status": task_status,
                    "utility": trace.get("utility"),
                    "proposed_tool_calls": len(calls),
                    "tool_results": len(tool_results),
                    "tool_errors": sum(bool(m.get("error")) for m in tool_results),
                    "final_tool_calls_pending": pending,
                    "trace": str(path.relative_to(run_dir)),
                    "error": trace.get("error"),
                }
            )
        utilities = list(results["utility_results"].values())
        evaluated = [task for task in tasks if task["status"] == "evaluated"]
        error_count = sum(task["status"] == "error" for task in tasks)
        incomplete_count = sum(task["status"] == "incomplete" for task in tasks)
        summary.update(
            status="completed" if len(evaluated) == len(utilities) else "completed_with_issues",
            tasks=tasks,
            task_count=len(utilities),
            task_success_count=sum(utilities),
            task_success_rate=sum(utilities) / len(utilities),
            error_task_count=error_count,
            incomplete_task_count=incomplete_count,
            evaluable_task_count=len(evaluated),
            evaluable_success_rate=(
                sum(bool(task["utility"]) for task in evaluated) / len(evaluated) if evaluated else None
            ),
        )
        if evaluation is not None and not results["evaluation_completed"]:
            summary["task_success_count"] = None
            summary["task_success_rate"] = None
    except BaseException as exc:
        # Persist a useful failure record without serializing clients or credentials.
        detail = str(exc)
        for secret in redactions:
            detail = detail.replace(secret, "[REDACTED]")
        summary.update(status="failed", error_type=type(exc).__name__, error=detail[:2000])
        if isinstance(exc, Exception):
            raise RunExecutionError(run_dir / "summary.json", exc) from exc
        raise
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary["usage"] = dict(llm.stats) if llm is not None else {}
        if recorder is not None:
            recorder.emit("RUN_END", {"status": summary["status"]})
            recorder.close()
            recording_status = observer.status() if observer is not None else recorder.status()
            try:
                audit = inspect_events(run_dir / "events.jsonl")
                write_json(run_dir / "events.audit.json", audit)
            except Exception as exc:
                audit = {"valid": False, "errors": [f"inspection: {type(exc).__name__}"]}
            summary["recording"] = {
                "enabled": True,
                **recording_status,
                "complete": recording_status["complete"] and audit["valid"],
                "audit": audit,
                "events_path": str(run_dir / "events.jsonl"),
            }
        else:
            summary["recording"] = {"enabled": False}
        if canary is not None:
            summary["canary"] = {**canary.status(), "input_condition": "canary_intervention"}
        if attribution is not None:
            attribution.close()
            subscriber_status = recorder.subscriber_status() if recorder is not None else {"complete": False}
            if lineage is not None:
                summary["lineage_state"] = (
                    attribution.save_state(run_dir / "lineage-state.json")
                    if summary["recording"].get("complete", False) and subscriber_status["complete"]
                    else {"status": "not_saved", "reason": "recording_or_subscriber_incomplete"}
                )
            attribution_status = attribution.status()
            summary["online_provenance"] = {
                **attribution_status,
                "enabled": True,
                "complete": attribution_status["complete"]
                and subscriber_status["complete"]
                and summary["recording"].get("complete", False),
                "subscriber": subscriber_status,
                "path": str(run_dir / "provenance.jsonl"),
            }
        else:
            summary["online_provenance"] = (
                {"enabled": config.online_provenance, "complete": False}
                if config.online_provenance
                else {"enabled": False}
            )
        if causal_auditor is not None:
            final_graph = lineage.snapshot() if lineage is not None else None
            causal_auditor.close(final_graph=final_graph)
            causal_status = causal_auditor.status()
            subscriber_status = recorder.subscriber_status() if recorder is not None else {"complete": False}
            summary["online_causal_audit"] = {
                **causal_status,
                "enabled": True,
                "complete": causal_status["complete"]
                and not attribution_status.get("causal_bridge_error_count", 0)
                and subscriber_status["complete"]
                and summary["recording"].get("complete", False),
                "path": str(run_dir / "causal-online.jsonl"),
                "derived_graph_path": str(run_dir / "causal-online-graph.json"),
            }
        else:
            summary["online_causal_audit"] = (
                {"enabled": True, "complete": False}
                if config.online_causal_audit
                else {"enabled": False}
            )
        if owned_causal_client is not None:
            try:
                owned_causal_client.close()
            except Exception:
                pass
        if evaluation is not None:
            from agentdojo_lab.evaluation_runner import build_evaluation_summary, payload_exposure_audit

            exposure = payload_exposure_audit(run_dir / "events.jsonl", evaluation)
            write_json(run_dir / "payload-exposure.json", exposure)
            summary["evaluation"] = build_evaluation_summary(evaluation, summary, results, exposure)
        write_json(run_dir / "summary.json", summary)
        # Reporting happens after execution and recording are complete. Its
        # failures must not replace an agent error or change evaluator results.
        try:
            report_status = export_run_html(run_dir, redactions=redactions)
        except Exception as exc:
            report_status = {"status": "failed", "error_type": type(exc).__name__}
        try:
            write_json(run_dir / "html-report-status.json", report_status)
        except OSError:
            pass  # A full disk must not replace the original execution outcome.
    return summary
