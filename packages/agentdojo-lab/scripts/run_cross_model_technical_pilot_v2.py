"""Execute the frozen 32-slot cross-model technical pilot.

The live path is deliberately fail closed: both provider credentials, an exact
committed Agent Tracer revision, unchanged runtime sources, and every captured
wire assertion are checked before or during execution.  Offline mode uses an
in-process HTTP mock and is transport evidence only, never model evidence.

Started slots are immutable and are never replaced.  A checkpoint/resume can
therefore start only schedule slots for which no durable ``started`` ledger row
exists.  Formatting repair calls are disabled and count zero by construction.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any

import httpx
import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.logging import OutputLogger, TraceLogger
from agentdojo.task_suite.load_suites import get_suite
from dotenv import dotenv_values
from pydantic import BaseModel

from agentdojo_lab import cross_model_pilot_v2, native_carrier_main_v2, pilot_acceptance
from agentdojo_lab.deepseek_adapter import DeepSeekLLM
from agentdojo_lab.evaluation_runner import PrimaryRequestLimitError, has_final_text
from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.recording import EventRecorder
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_VERSION = "v1.2.2"
TASK_TIMEOUT_SECONDS = 900
PAUSE_STATUS_CODES = {401, 402, 403, 429}
SEMANTIC_MODEL = native_carrier_main_v2.SEMANTIC_MODEL
SEMANTIC_REVISION = native_carrier_main_v2.SEMANTIC_REVISION
RUNTIME_PATHS = (
    "scripts/run_cross_model_technical_pilot_v2.py",
    "scripts/run_deepseek_native_main_v2.py",
    "configs/cross_model_pilot_v2.json",
    "src/agentdojo_lab/cross_model_pilot_v2.py",
    "src/agentdojo_lab/pilot_acceptance.py",
    "src/agentdojo_lab/native_carrier_main_v2.py",
    "src/agentdojo_lab/deepseek_adapter.py",
    "src/agentdojo_lab/groq_adapter.py",
    "src/agentdojo_lab/evaluation_runner.py",
    "src/agentdojo_lab/inspection.py",
    "src/agentdojo_lab/observation.py",
    "src/agentdojo_lab/recording.py",
    "src/agentdojo_lab/semantic.py",
    "src/agentdojo_lab/model_pins/minilm-v1.json",
    "pyproject.toml",
    "upstream.json",
    "uv.lock",
)
PRICING_SNAPSHOTS = {
    "deepseek": {
        "snapshot_id": "deepseek-2026-09-30-conservative-peak-uncached",
        "provider": "deepseek",
        "model": "deepseek-flash",
        "currency": "USD",
        "unit_tokens": 1_000_000,
        "input_per_unit": "0.30",
        "output_per_unit": "1.20",
        "basis": "conservative peak uncached input and peak output prices",
        "snapshot_date": "2026-09-30",
        "source_url": "https://api-docs.deepseek.com/quick_start/pricing/",
    },
    "groq": {
        "snapshot_id": "groq-2026-09-30-gpt-oss-120b",
        "provider": "groq",
        "model": "openai/gpt-oss-120b",
        "currency": "USD",
        "unit_tokens": 1_000_000,
        "input_per_unit": "0.15",
        "output_per_unit": "0.60",
        "basis": "published input and output prices",
        "snapshot_date": "2026-09-30",
        "source_url": "https://console.groq.com/docs/model/openai/gpt-oss-120b",
    },
}


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _write_new(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False, default=_json_default)
        stream.write("\n")


def _write_atomic(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False, default=_json_default) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def _append_jsonl(stream, value: Any) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False, default=_json_default) + "\n")
    stream.flush()


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSONL object: {path}")
            rows.append(value)
    return rows


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _exact_commit(value: str | None) -> str:
    commit = value or _git("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", commit or "") is None:
        raise ValueError("--agent-tracer-commit must be a full lowercase 40-hex commit")
    return commit


def _source_hashes() -> dict[str, str]:
    missing = [name for name in RUNTIME_PATHS if not (ROOT / name).is_file()]
    if missing:
        raise ValueError(f"Runtime source files are missing: {missing!r}")
    return {name: _file_sha(ROOT / name) for name in RUNTIME_PATHS}


def _assert_source_hashes(manifest: Mapping[str, Any]) -> None:
    hashes = manifest.get("source_hashes")
    if not isinstance(hashes, Mapping) or hashes != _source_hashes():
        raise ValueError("Runtime source hashes differ from the saved run manifest")


def _verify_live_revision(commit: str) -> None:
    head = _git("rev-parse", "HEAD")
    if head != commit:
        raise ValueError("Live pilot commit does not equal the current HEAD")
    status = _git("status", "--porcelain", "--untracked-files=all")
    if status:
        raise ValueError("Live pilot worktree must be committed and unchanged")
    vendor = ROOT / "vendor" / "agentdojo"
    expected = cross_model_pilot_v2.UPSTREAM["commit"]
    vendor_head = subprocess.run(
        ["git", "-C", str(vendor), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    vendor_status = subprocess.run(
        ["git", "-C", str(vendor), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if vendor_head != expected or vendor_status:
        raise ValueError("Vendored AgentDojo must be at the frozen clean upstream commit")
    imported_source = Path(inspect.getfile(__import__("agentdojo"))).resolve()
    expected_source = (vendor / "src" / "agentdojo").resolve()
    if expected_source not in imported_source.parents:
        raise ValueError("Imported AgentDojo is not the frozen vendored checkout")
    if importlib.metadata.version("agentdojo") != cross_model_pilot_v2.UPSTREAM["package_version"]:
        raise ValueError("Imported AgentDojo package version differs from the frozen version")


def _portable_semantic_identity(metadata: Mapping[str, Any]) -> dict[str, Any]:
    identity = copy.deepcopy(dict(metadata))
    identity["model_path"] = SEMANTIC_MODEL
    return identity


def _verified_semantic_identity() -> dict[str, Any]:
    encoder = LocalMiniLMEncoder(ROOT / SEMANTIC_MODEL, revision=SEMANTIC_REVISION)
    return _portable_semantic_identity(encoder.metadata)


def _credentials(*, live: bool, env_file: Path | None = None) -> dict[str, str]:
    if not live:
        return {
            "DEEPSEEK_API_KEY": "offline-deepseek-synthetic-key",
            "GROQ_API_KEY": "offline-groq-synthetic-key",
        }
    file_values: Mapping[str, Any] = {}
    if env_file is not None:
        if not env_file.is_file():
            raise ValueError(f"Credential env file does not exist: {env_file}")
        file_values = dotenv_values(env_file)
    values = {
        name: str(os.environ.get(name) or file_values.get(name) or "").strip()
        for name in ("DEEPSEEK_API_KEY", "GROQ_API_KEY")
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ValueError(
            "Live pilot requires both DEEPSEEK_API_KEY and GROQ_API_KEY before output creation; "
            f"missing {', '.join(missing)}"
        )
    return values


def build_run_manifest(
    agent_tracer_commit: str,
    *,
    live: bool,
    semantic_identity: Mapping[str, Any] | None = None,
    config_path: Path | str = cross_model_pilot_v2.CONFIG_PATH,
) -> dict[str, Any]:
    """Bind the static protocol to runtime code, prices, timeouts and mode."""
    protocol_manifest = cross_model_pilot_v2.build_manifest(agent_tracer_commit, config_path)
    if live and semantic_identity is None:
        semantic_identity = _verified_semantic_identity()
    manifest = {
        "schema_version": 1,
        "protocol": cross_model_pilot_v2.PROTOCOL,
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_tracer_commit": agent_tracer_commit,
        "protocol_manifest": protocol_manifest,
        "frozen_config_sha256": protocol_manifest["frozen_config_sha256"],
        "source_hashes": _source_hashes(),
        "runtime": {
            "real_llm": live,
            "repair_enabled": False,
            "request_limit_per_run": 10,
            "request_attempt_ceiling": 320,
            "task_timeout_seconds": TASK_TIMEOUT_SECONDS,
            "sdk_max_retries": 0,
            "execution": "sequential_fixed_schedule_no_replacement",
        },
        "request_timeouts_seconds": {
            row["provider_id"]: row["request_timeout_seconds"]
            for row in protocol_manifest["config"]["providers"]
        },
        "pricing_snapshots": copy.deepcopy(PRICING_SNAPSHOTS),
        "semantic_scoring": {
            "model_path": SEMANTIC_MODEL,
            "revision": SEMANTIC_REVISION,
            "stages": ["tier3", "tier4"],
            "source_view": "fixture_declared_passage",
            "model_available_at_manifest_creation": (ROOT / SEMANTIC_MODEL).is_dir(),
            "identity_verified_and_loadable": live,
            "identity": copy.deepcopy(dict(semantic_identity)) if semantic_identity is not None else None,
            "missing_model_policy": (
                "eligible pairs remain eligible with scored=false; acceptance fails rather than "
                "substituting native utility or another metric"
            ),
        },
        "credentials": {
            "required_for_live": ["DEEPSEEK_API_KEY", "GROQ_API_KEY"],
            "values_persisted": False,
        },
        "interpretation": (
            "technical acceptance only; offline mode is transport evidence, and this manifest "
            "does not define a cross-model research comparison"
        ),
    }
    return validate_run_manifest(manifest)


def validate_run_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != 1 or manifest.get("protocol") != cross_model_pilot_v2.PROTOCOL:
        raise ValueError("Wrong cross-model runner manifest schema or protocol")
    commit = manifest.get("agent_tracer_commit")
    if re.fullmatch(r"[0-9a-f]{40}", commit or "") is None:
        raise ValueError("Run manifest requires a full Agent Tracer commit")
    protocol_manifest = cross_model_pilot_v2.validate_manifest(
        copy.deepcopy(manifest.get("protocol_manifest", {}))
    )
    if protocol_manifest.get("agent_tracer_commit") != commit:
        raise ValueError("Protocol and runner commits differ")
    if manifest.get("frozen_config_sha256") != protocol_manifest["frozen_config_sha256"]:
        raise ValueError("Frozen config digest differs")
    expected_runtime = {
        "real_llm": manifest.get("runtime", {}).get("real_llm"),
        "repair_enabled": False,
        "request_limit_per_run": 10,
        "request_attempt_ceiling": 320,
        "task_timeout_seconds": TASK_TIMEOUT_SECONDS,
        "sdk_max_retries": 0,
        "execution": "sequential_fixed_schedule_no_replacement",
    }
    if expected_runtime["real_llm"] not in (True, False) or manifest.get("runtime") != expected_runtime:
        raise ValueError("Runner mode, timeout, or request budget changed")
    expected_timeouts = {
        row["provider_id"]: row["request_timeout_seconds"] for row in protocol_manifest["config"]["providers"]
    }
    if manifest.get("request_timeouts_seconds") != expected_timeouts:
        raise ValueError("Provider request timeouts changed")
    if manifest.get("pricing_snapshots") != PRICING_SNAPSHOTS:
        raise ValueError("Pricing snapshots changed")
    semantic = manifest.get("semantic_scoring", {})
    if semantic.get("model_path") != SEMANTIC_MODEL or semantic.get("revision") != SEMANTIC_REVISION:
        raise ValueError("Semantic scorer is not the pinned MiniLM revision")
    if manifest["runtime"]["real_llm"]:
        identity = semantic.get("identity")
        if semantic.get("identity_verified_and_loadable") is not True or not isinstance(identity, Mapping):
            raise ValueError("Live manifest lacks a verified loadable semantic identity")
        if identity.get("model_id") != cross_model_pilot_v2.SCORING["model"]["id"]:
            raise ValueError("Live semantic model identity differs from the frozen model")
        if identity.get("revision") != SEMANTIC_REVISION:
            raise ValueError("Live semantic revision differs from the frozen revision")
        if not isinstance(identity.get("versions"), Mapping):
            raise ValueError("Live semantic identity lacks package versions")
    elif semantic.get("identity_verified_and_loadable") is not False:
        raise ValueError("Offline manifest must not claim live semantic verification")
    hashes = manifest.get("source_hashes")
    if not isinstance(hashes, dict) or set(hashes) != set(RUNTIME_PATHS):
        raise ValueError("Run manifest has incomplete runtime source hashes")
    if any(re.fullmatch(r"[0-9a-f]{64}", value or "") is None for value in hashes.values()):
        raise ValueError("Run manifest has an invalid runtime source digest")
    return manifest


@cache
def _native_runner():
    """Load only the already reviewed native evidence helpers from the script."""
    path = ROOT / "scripts/run_deepseek_native_main_v2.py"
    name = "_agent_tracer_native_main_v2_runner_helpers"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load native runner evidence helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


class RequestBudget:
    """One counted SDK invocation per permit; the eleventh is rejected."""

    def __init__(self, limit: int = 10):
        if isinstance(limit, bool) or limit != 10:
            raise ValueError("The frozen request limit is exactly 10")
        self.limit = limit

    def permit(self, stats: dict[str, Any]) -> None:
        if stats.get("request_count", 0) >= self.limit:
            stats["request_budget_exhausted"] = True
            raise PrimaryRequestLimitError(
                "Primary request budget reached; trial retained without repair or retry"
            )


class BudgetedDeepSeekLLM(DeepSeekLLM):
    def __init__(self, *args, request_limit: int, **kwargs):
        super().__init__(*args, **kwargs)
        self._budget = RequestBudget(request_limit)
        self.stats.update(
            request_limit=request_limit,
            request_budget_exhausted=False,
            repair_request_count=0,
        )

    def query(self, *args, **kwargs):
        self._budget.permit(self.stats)
        return super().query(*args, **kwargs)


class BudgetedGroqLLM(GroqLLM):
    def __init__(self, *args, request_limit: int, **kwargs):
        super().__init__(*args, **kwargs)
        self._budget = RequestBudget(request_limit)
        self.stats.update(
            request_limit=request_limit,
            request_budget_exhausted=False,
            repair_request_count=0,
        )

    def query(self, *args, **kwargs):
        self._budget.permit(self.stats)
        return super().query(*args, **kwargs)


def _offline_completion(message: dict[str, Any], index: int, model: str) -> dict[str, Any]:
    reply = copy.deepcopy(message)
    finish_reason = reply.pop("__finish_reason__", None)
    return {
        "id": f"cross-model-transport-fixture-{index}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "system_fingerprint": "offline-transport-only",
        "choices": [
            {
                "index": 0,
                "message": reply,
                "finish_reason": finish_reason or ("tool_calls" if reply.get("tool_calls") else "stop"),
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
    }


def _reservation(*, request_id: str, ordinal: int, raw_bytes: int, provider_id: str) -> dict[str, Any]:
    snapshot = PRICING_SNAPSHOTS[provider_id]
    prompt_upper = raw_bytes
    output_upper = 2048
    upper_cost = (
        prompt_upper * float(snapshot["input_per_unit"]) + output_upper * float(snapshot["output_per_unit"])
    ) / snapshot["unit_tokens"]
    return {
        "reservation_id": f"reservation:{ordinal + 1:08d}",
        "model_request_id": request_id,
        "ordinal": ordinal,
        "prompt_token_upper_bound": prompt_upper,
        "output_token_upper_bound": output_upper,
        "reserved_tokens": prompt_upper + output_upper,
        "estimated_cost_upper_bound_usd": format(upper_cost, ".12f").rstrip("0").rstrip("."),
        "pricing_snapshot_id": snapshot["snapshot_id"],
        "basis": "request body UTF-8 bytes plus frozen output-token cap",
    }


def make_client(
    manifest: dict[str, Any],
    slot: dict[str, Any],
    observer: ObservationSession,
    captures: list[dict[str, Any]],
    reservations: list[dict[str, Any]],
    request_stream,
    reservation_stream,
    *,
    api_key: str,
):
    """Return an OpenAI-compatible client with fail-closed pre-send capture."""
    profile = slot["provider_config"]
    provider_id = slot["provider_id"]
    config = manifest["protocol_manifest"]["config"]

    def capture(request: httpx.Request) -> None:
        raw = bytes(request.content)
        if api_key and api_key.encode("utf-8") in raw:
            raise ValueError("API credential appeared in the request body")
        body = json.loads(raw)
        cross_model_pilot_v2.assert_frozen_outbound_request(config, provider_id, body)
        request_id = observer.request_id
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("Captured request has no observer request ID")
        ordinal = len(captures)
        row = {
            "ordinal": ordinal,
            "model_request_id": request_id,
            "body": body,
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_bytes": len(raw),
        }
        reserve = _reservation(
            request_id=request_id,
            ordinal=ordinal,
            raw_bytes=len(raw),
            provider_id=provider_id,
        )
        captures.append(row)
        reservations.append(reserve)
        _append_jsonl(request_stream, row)
        _append_jsonl(reservation_stream, reserve)

    kwargs = {
        "api_key": api_key,
        "base_url": profile["endpoint"],
        "max_retries": profile["sdk_max_retries"],
        "timeout": profile["request_timeout_seconds"],
    }
    if manifest["runtime"]["real_llm"]:
        return openai.OpenAI(
            **kwargs,
            http_client=httpx.Client(
                timeout=profile["request_timeout_seconds"],
                event_hooks={"request": [capture]},
            ),
        )

    replies = copy.deepcopy(slot.get("offline_responses") or [])
    if not replies:
        replies = [{"role": "assistant", "content": "Offline transport complete."}]

    def respond(_request: httpx.Request) -> httpx.Response:
        index = len(captures) - 1
        if index < 0 or index >= len(replies):
            raise AssertionError("Offline response fixture exhausted")
        return httpx.Response(
            200,
            json=_offline_completion(replies[index], index, profile["model"]),
        )

    return openai.OpenAI(
        **{**kwargs, "base_url": "https://cross-model-transport.invalid"},
        http_client=httpx.Client(
            transport=httpx.MockTransport(respond),
            timeout=profile["request_timeout_seconds"],
            event_hooks={"request": [capture]},
        ),
    )


def make_llm(client, slot: dict[str, Any], observer: ObservationSession):
    profile = slot["provider_config"]
    common = {
        "temperature": 0.0,
        "observer": observer,
        "request_limit": slot["request_limit"],
    }
    if slot["provider_id"] == "deepseek":
        return BudgetedDeepSeekLLM(
            client,
            profile["model"],
            max_tokens=2048,
            **common,
        )
    if slot["provider_id"] == "groq":
        return BudgetedGroqLLM(
            client,
            profile["model"],
            max_completion_tokens=2048,
            reasoning_effort="low",
            **common,
        )
    raise ValueError(f"Unknown provider: {slot['provider_id']}")


def provider_acceptance_config(slot: Mapping[str, Any]) -> dict[str, Any]:
    provider = slot["provider_id"]
    profile = slot["provider_config"]
    return {
        "provider": provider,
        "model": profile["model"],
        "request_limit": 10,
        "output_token_limit": 2048,
        "output_token_field": "max_tokens" if provider == "deepseek" else "max_completion_tokens",
        "reasoning_effort": "low" if provider == "groq" else None,
        "thinking": {"type": "disabled"} if provider == "deepseek" else None,
        "repair_enabled": False,
    }


def _message_text(message: Any) -> str | None:
    if not isinstance(message, Mapping):
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    parts = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, Mapping):
            text = block.get("text", block.get("content"))
            if not isinstance(text, str):
                return None
            parts.append(text)
        else:
            return None
    return "\n".join(parts)


def build_source_bindings(
    events: Sequence[Mapping[str, Any]], slot: Mapping[str, Any]
) -> list[dict[str, Any]]:
    by_id = {
        event.get("event_id"): event
        for event in events
        if isinstance(event.get("event_id"), str) and event.get("event_id")
    }
    declarations = slot["base_fixture_slot"]["carrier_declarations"]
    rows = []
    for exposure in events:
        if exposure.get("event_type") != "TOOL_OUTPUT_EXPOSED":
            continue
        data = exposure.get("data") if isinstance(exposure.get("data"), Mapping) else {}
        message = data.get("message")
        text = _message_text(message)
        source_id = data.get("source_result_event_id")
        source = by_id.get(source_id)
        verified = bool(
            source
            and source.get("event_type") == "TOOL_RESULT"
            and source.get("call_ref") == exposure.get("call_ref")
            and source.get("tool_call_id") == exposure.get("tool_call_id")
            and source.get("event_sequence", 10**30) < exposure.get("event_sequence", -1)
        )
        for declaration in declarations:
            passage = declaration["carrier_text"]
            if not isinstance(text, str) or passage not in text:
                continue
            rows.append(
                {
                    "exposure_event_id": exposure.get("event_id"),
                    "source_id": declaration["source_id"],
                    "model_request_id": exposure.get("model_request_id"),
                    "source_result_event_id": source_id,
                    "message_index": data.get("message_index"),
                    "message_sha256": _sha(message),
                    "verified": verified,
                }
            )
    return rows


def _pointer(value: Any, path: str) -> Any:
    for raw in path.lstrip("/").split("/"):
        if not raw:
            continue
        part = raw.replace("~1", "/").replace("~0", "~")
        try:
            value = value[int(part)] if isinstance(value, list) else value[part]
        except (IndexError, KeyError, TypeError, ValueError):
            return None
    return value


def emit_state_oracle_events(
    recorder: EventRecorder,
    events: list[dict[str, Any]],
    slot: Mapping[str, Any],
    scoring: Mapping[str, Any] | None,
) -> None:
    sink_name = slot["base_fixture_slot"]["sink_call"]["function"]
    proposals = [
        event
        for event in events
        if event.get("event_type") == "TOOL_CALL_PROPOSED"
        and isinstance(event.get("data"), Mapping)
        and event["data"].get("function") == sink_name
    ]
    for proposal in proposals:
        recorder.emit(
            "STATE_ORACLE_EVALUATED",
            {
                "oracle_id": slot["state_oracle"]["oracle_id"],
                "implementation": slot["state_oracle"]["implementation"],
                "argument_executed": (scoring or {}).get("argument_executed") is True,
                "state_change_confirmed": (scoring or {}).get("state_change_confirmed") is True,
                "state_confirmed": (scoring or {}).get("state_confirmed") is True,
                "successful_sink_calls": (scoring or {}).get("successful_sink_calls"),
            },
            call_ref=proposal.get("call_ref"),
            model_request_id=proposal.get("model_request_id"),
            tool_call_id=proposal.get("tool_call_id"),
            parent_event_ids=[proposal.get("event_id")],
        )


def build_sink_records(
    events: Sequence[Mapping[str, Any]],
    slot: Mapping[str, Any],
    scoring: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    sink = slot["base_fixture_slot"]["sink_call"]
    proposals = [
        event
        for event in events
        if event.get("event_type") == "TOOL_CALL_PROPOSED"
        and isinstance(event.get("data"), Mapping)
        and event["data"].get("function") == sink["function"]
    ]
    rows = []
    for index, proposal in enumerate(proposals):
        call_ref = proposal.get("call_ref")
        returned = next(
            (
                event
                for event in events
                if event.get("event_type") == "TOOL_RUNTIME_RETURNED" and event.get("call_ref") == call_ref
            ),
            None,
        )
        result = next(
            (
                event
                for event in events
                if event.get("event_type") == "TOOL_RESULT" and event.get("call_ref") == call_ref
            ),
            None,
        )
        state = next(
            (
                event
                for event in events
                if event.get("event_type") == "STATE_ORACLE_EVALUATED" and event.get("call_ref") == call_ref
            ),
            None,
        )
        arguments = proposal["data"].get("arguments")
        returned_data = returned.get("data", {}) if isinstance(returned, Mapping) else {}
        state_data = state.get("data", {}) if isinstance(state, Mapping) else {}
        rows.append(
            {
                "sink_id": f"{slot['run_id']}:sink:{index + 1}",
                "call_ref": call_ref,
                "proposal_event_id": proposal.get("event_id"),
                "runtime_return_event_id": returned.get("event_id") if returned else None,
                "result_event_id": result.get("event_id") if result else None,
                "state_evidence_event_id": state.get("event_id") if state else None,
                "tool_name": sink["function"],
                "argument_path": sink["argument_path"],
                "actual_value": _pointer(arguments, sink["argument_path"]),
                "oracle_id": slot["state_oracle"]["oracle_id"],
                "state_confirmed": state_data.get("state_confirmed"),
                "state_change_confirmed": state_data.get("state_change_confirmed"),
                "argument_executed": state_data.get("argument_executed"),
                "arguments_verified": isinstance(arguments, Mapping),
                "result_verified": bool(
                    returned
                    and result
                    and "error" in returned_data
                    and "raised_exception_type" in returned_data
                ),
                "state_verified": bool(
                    state
                    and scoring is not None
                    and isinstance(state_data.get("state_confirmed"), bool)
                    and isinstance(state_data.get("state_change_confirmed"), bool)
                    and isinstance(state_data.get("argument_executed"), bool)
                    and state_data.get("state_confirmed") is scoring.get("state_confirmed")
                    and state_data.get("state_change_confirmed") is scoring.get("state_change_confirmed")
                    and state_data.get("argument_executed") is scoring.get("argument_executed")
                ),
            }
        )
    return rows


def _semantic_matcher() -> tuple[SemanticMatcher | None, str | None]:
    path = ROOT / SEMANTIC_MODEL
    if not path.is_dir():
        return None, "PinnedSemanticModelMissing"
    try:
        return SemanticMatcher(LocalMiniLMEncoder(path, revision=SEMANTIC_REVISION)), None
    except Exception as error:
        return None, type(error).__name__


def build_scoring_records(
    events: Sequence[Mapping[str, Any]],
    slot: Mapping[str, Any],
    source_bindings: Sequence[Mapping[str, Any]],
    sink_records: Sequence[Mapping[str, Any]],
    matcher: SemanticMatcher | None,
    *,
    setup_error: str | None,
) -> list[dict[str, Any]]:
    declarations = {row["source_id"]: row for row in slot["base_fixture_slot"]["carrier_declarations"]}
    indexed_events = list(enumerate(events))
    by_id = {
        event.get("event_id"): (index, event)
        for index, event in indexed_events
        if isinstance(event.get("event_id"), str) and event.get("event_id")
    }
    sink = slot["base_fixture_slot"]["sink_call"]
    executed_proposal_ids = {
        row.get("proposal_event_id")
        for row in sink_records
        if row.get("argument_executed") is True
        and row.get("arguments_verified") is True
        and row.get("result_verified") is True
        and row.get("state_verified") is True
    }
    targets = [
        (index, event)
        for index, event in indexed_events
        if event.get("event_type") == "TOOL_CALL_PROPOSED"
        and isinstance(event.get("data"), Mapping)
        and event["data"].get("function") == sink["function"]
        and event.get("event_id") in executed_proposal_ids
    ]
    rows = []
    for binding in source_bindings:
        if binding.get("verified") is not True:
            continue
        exposure_entry = by_id.get(binding.get("exposure_event_id"))
        declaration = declarations.get(binding.get("source_id"))
        if exposure_entry is None or declaration is None:
            continue
        exposure_index, exposure = exposure_entry
        exposure_order = exposure.get("event_sequence", exposure_index)
        passage = declaration["carrier_text"]
        for proposal_index, proposal in targets:
            proposal_order = proposal.get("event_sequence", proposal_index)
            if exposure_order >= proposal_order:
                continue
            arguments = proposal["data"].get("arguments")
            target = _pointer(arguments, sink["argument_path"])
            if not isinstance(target, str) or not target:
                continue
            for stage in ("tier3", "tier4"):
                input_id = pilot_acceptance.scoring_input_id(
                    exposure["event_id"],
                    declaration["source_id"],
                    proposal["event_id"],
                    stage,
                )
                row = {
                    "input_id": input_id,
                    "tier": stage,
                    "exposure_event_id": exposure["event_id"],
                    "source_id": declaration["source_id"],
                    "proposal_event_id": proposal["event_id"],
                    "complete": True,
                    "truncated": False,
                    "eligible": True,
                    "status": "scoring_error",
                    "scored": False,
                    "score": None,
                    "source_sha256": _sha(passage),
                    "target_sha256": _sha(target),
                    "source_length": len(passage),
                    "target_length": len(target),
                }
                if matcher is None:
                    row["scoring_error_type"] = setup_error or "SemanticMatcherUnavailable"
                    rows.append(row)
                    continue
                result = getattr(matcher, f"compare_{stage}")(passage, target)
                metadata = result.get("metadata") if isinstance(result.get("metadata"), Mapping) else {}
                encoder = metadata.get("encoder") if isinstance(metadata.get("encoder"), Mapping) else {}
                row["scorer"] = {
                    "method": result.get("method"),
                    "model_id": encoder.get("model_id"),
                    "revision": encoder.get("revision"),
                    "model_manifest_sha256": encoder.get("manifest_sha256"),
                    "package_versions": encoder.get("versions"),
                    "semantic_threshold": result.get("semantic_threshold"),
                    "coverage_threshold": result.get("coverage_threshold") if stage == "tier4" else None,
                }
                if result.get("status") != "scored":
                    row["scoring_error_type"] = (
                        result.get("metadata", {}).get("unscored_reason")
                        or result.get("status")
                        or "SemanticScoringFailed"
                    )
                    rows.append(row)
                    continue
                complete = result.get("complete") is True
                truncated = result.get("truncated") is True
                eligible = complete and not truncated
                row.update(
                    complete=complete,
                    truncated=truncated,
                    eligible=eligible,
                    status="completed",
                    scored=isinstance(result.get("score"), (int, float)),
                    score=result.get("score"),
                    matched=result.get("matched"),
                )
                if not eligible:
                    reason = (
                        "incomplete_and_truncated"
                        if not complete and truncated
                        else "incomplete"
                        if not complete
                        else "truncated"
                    )
                    row["eligibility_reason"] = reason
                if stage == "tier4":
                    row.update(
                        coverage=result.get("coverage"),
                        chunks=result.get("chunks", []),
                        matched_visible_spans=result.get("matched_visible_spans", []),
                    )
                rows.append(row)
    return rows


def build_stop_record(
    events: Sequence[Mapping[str, Any]],
    stats: Mapping[str, Any],
    *,
    failure: str | None,
    final_text_present: bool,
) -> dict[str, Any]:
    length_ids = []
    parse_ids = []
    for event in events:
        request_id = event.get("model_request_id")
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        if event.get("event_type") == "MODEL_RESPONSE":
            body = data.get("body") if isinstance(data.get("body"), Mapping) else {}
            choices = body.get("choices") if isinstance(body.get("choices"), list) else []
            if any(
                isinstance(choice, Mapping) and choice.get("finish_reason") == "length" for choice in choices
            ):
                length_ids.append(request_id)
        elif event.get("event_type") == "MODEL_ERROR":
            text = json.dumps(data, ensure_ascii=False).lower()
            if "parse" in text or "jsondecode" in text or "json_decode" in text:
                parse_ids.append(request_id)
    request_limit = bool(
        stats.get("request_budget_exhausted") is True
        or failure == "PrimaryRequestLimitError"
        or (stats.get("request_count") == 10 and not final_text_present)
    )
    failure_reason = None
    if failure and failure != "PrimaryRequestLimitError":
        lowered = failure.lower()
        failure_reason = (
            "parse_error"
            if "parse" in lowered or "jsondecode" in lowered
            else "network_error"
            if any(token in lowered for token in ("connection", "timeout", "network"))
            else "provider_error"
            if any(token in lowered for token in ("api", "rate", "authentication", "badrequest"))
            else "runtime_error"
        )
    secondary = []
    if length_ids:
        primary = {
            "reason": "output_limit_triggered",
            "model_request_id": length_ids[0],
        }
        for request_id in parse_ids:
            if request_id in length_ids:
                secondary.append(
                    {
                        "reason": "parse_error",
                        "model_request_id": request_id,
                        "caused_by": "output_limit_triggered",
                    }
                )
        if request_limit:
            secondary.append(
                {
                    "reason": "request_limit_triggered",
                    "caused_by": "output_limit_triggered",
                }
            )
        if failure_reason and failure_reason != "parse_error":
            secondary.append({"reason": failure_reason, "caused_by": "output_limit_triggered"})
    elif failure_reason:
        primary = {"reason": failure_reason}
        if request_limit:
            secondary.append(
                {
                    "reason": "request_limit_triggered",
                    "caused_by": failure_reason,
                }
            )
    elif request_limit:
        primary = {"reason": "request_limit_triggered"}
    else:
        primary = {"reason": "completed"}
    return {
        "primary": primary,
        "secondary": secondary,
        "output_limit_triggered": bool(length_ids),
        "request_limit_triggered": request_limit,
    }


def _native_plan_and_slot(slot: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    base = copy.deepcopy(slot["base_fixture_slot"])
    base["offline_responses"] = copy.deepcopy(slot["offline_responses"])
    return {"protocol": native_carrier_main_v2.PROTOCOL, "slots": [base]}, base


def run_trial(spec_path: Path) -> dict[str, Any]:
    spec = _read_json(spec_path)
    manifest_reference = Path(spec["manifest_path"])
    if manifest_reference.is_absolute() or ".." in manifest_reference.parts:
        raise ValueError("Session manifest path must be relative to the batch root")
    batch_root = spec_path.parent.parent.resolve()
    manifest_path = (batch_root / manifest_reference).resolve()
    if manifest_path.parent != batch_root:
        raise ValueError("Session manifest path escapes the batch root")
    manifest = validate_run_manifest(_read_json(manifest_path))
    if _file_sha(manifest_path) != spec.get("manifest_sha256"):
        raise ValueError("Trial is not bound to the saved run manifest")
    _assert_source_hashes(manifest)
    slot = spec.get("slot")
    slots = manifest["protocol_manifest"]["slots"]
    if slot not in slots:
        raise ValueError("Trial slot is outside the frozen 32-run schedule")
    if manifest["runtime"]["real_llm"]:
        _verify_live_revision(manifest["agent_tracer_commit"])
        credentials = _credentials(live=True)
    else:
        credentials = _credentials(live=False)

    output = manifest_path.parent / "runs" / slot["run_id"]
    output.mkdir(parents=True, exist_ok=False)
    environment = cross_model_pilot_v2.make_environment(manifest["protocol_manifest"], slot)
    before_env = environment.model_copy(deep=True)
    if (
        cross_model_pilot_v2.canonical_sha256(before_env.model_dump(mode="json"))
        != slot["initial_environment_sha256"]
    ):
        raise ValueError("Actual initial environment differs from the frozen SHA-256")
    _write_new(output / "initial-environment.json", before_env.model_dump(mode="json"))

    suite = get_suite(BENCHMARK_VERSION, slot["suite"])
    task = suite.user_tasks[slot["task_id"]]
    native_plan, native_slot = _native_plan_and_slot(slot)
    actions: list[dict[str, Any]] = []
    runtime = _native_runner().RecordingRuntime(suite.tools, actions)
    captured: list[dict[str, Any]] = []
    reservations: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    redactions = tuple(credentials.values())
    recorder = EventRecorder(
        output / "events.jsonl", slot["run_id"], redactions=redactions, on_event=events.append
    )
    observer = ObservationSession(recorder)
    messages: Sequence[Any] = []
    failure: str | None = None
    status_code: int | None = None
    llm = None
    native_utility = None
    utility_error = None
    scoring = None
    scoring_error = None
    recorder.emit(
        "RUN_STARTED",
        {
            "protocol": manifest["protocol"],
            "run_id": slot["run_id"],
            "provider_id": slot["provider_id"],
            "real_llm": manifest["runtime"]["real_llm"],
        },
    )
    with (
        (output / "requests.jsonl").open("x", encoding="utf-8", newline="\n") as request_stream,
        (output / "reservations.jsonl").open("x", encoding="utf-8", newline="\n") as reservation_stream,
    ):
        try:
            key = credentials[slot["provider_config"]["api_key_env"]]
            with make_client(
                manifest,
                slot,
                observer,
                captured,
                reservations,
                request_stream,
                reservation_stream,
                api_key=key,
            ) as client:
                observer.attach(client)
                if observer.errors:
                    raise RuntimeError("Observer attachment failed before the first request")
                llm = make_llm(client, slot, observer)
                pipeline = AgentPipeline.from_config(
                    PipelineConfig(
                        llm=llm,
                        model_id=None,
                        defense=None,
                        system_message_name=None,
                        system_message=load_system_message(None),
                    )
                )
                for element in pipeline.elements:
                    if hasattr(element, "max_iters"):
                        element.max_iters = slot["request_limit"]
                pipeline = observe_pipeline(pipeline, observer)
                delegate = OutputLogger(str(output / "native"))
                with TraceLogger(
                    delegate=delegate,
                    suite_name=suite.name,
                    user_task_id=task.ID,
                    injection_task_id=None,
                    injections={native_slot["vector_id"]: native_slot["vector_payload"]},
                    attack_type="cross_model_technical_pilot_" + native_slot["condition"],
                    pipeline_name=pipeline.name,
                    benchmark_version=BENCHMARK_VERSION,
                    evaluation_condition=native_slot["condition"],
                    evaluation_completed=False,
                ) as logger:
                    try:
                        messages = pipeline.query(task.PROMPT, runtime, environment, [], {})[3]
                    except Exception as error:
                        failure = type(error).__name__
                        status_code = getattr(error, "status_code", None)
                        logger.log_error(failure)
                        messages = list(logger.messages)
                    native_utility, utility_error = _native_runner().native_utility(
                        suite, task, before_env, environment, messages
                    )
                    logger.set_contextarg("native_utility", native_utility)
                    logger.set_contextarg("utility_error_type", utility_error)
                    logger.set_contextarg(
                        "evaluation_completed", failure is None and has_final_text(messages)
                    )
        except Exception as error:
            failure = failure or type(error).__name__
            status_code = status_code or getattr(error, "status_code", None)

        final_text = _native_runner()._final_text(messages)  # noqa: SLF001 - reviewed helper
        try:
            scoring = native_carrier_main_v2.score_trajectory(
                native_plan,
                native_slot,
                actions,
                before_env,
                environment,
                final_text,
            )
        except Exception as error:
            scoring_error = type(error).__name__
        emit_state_oracle_events(recorder, events, slot, scoring)
        recorder.emit("RUN_END", {"status": "completed" if failure is None else "failed"})
        recorder.close()

    event_audit = inspect_events(output / "events.jsonl")
    source_reads, sink = _native_runner().source_and_sink_evidence(events, native_slot, scoring or {})
    source_bindings = build_source_bindings(events, slot)
    sink_records = build_sink_records(events, slot, scoring)
    matcher, matcher_error = _semantic_matcher()
    scoring_records = build_scoring_records(
        events,
        slot,
        source_bindings,
        sink_records,
        matcher,
        setup_error=matcher_error,
    )
    stats = (
        dict(llm.stats)
        if llm is not None
        else {
            "request_count": 0,
            "request_limit": 10,
            "request_budget_exhausted": False,
            "repair_request_count": 0,
        }
    )
    stats.setdefault("repair_request_count", 0)
    stop = build_stop_record(
        events,
        stats,
        failure=failure,
        final_text_present=has_final_text(messages),
    )
    acceptance = pilot_acceptance.audit_pilot_run(
        provider_config=provider_acceptance_config(slot),
        pilot_slot=slot,
        sdk_stats=stats,
        captured_requests=captured,
        events=events,
        source_bindings=source_bindings,
        sink_records=sink_records,
        scoring_records=scoring_records,
        reservations=reservations,
        pricing_snapshot=PRICING_SNAPSHOTS[slot["provider_id"]],
        stop_record=stop,
        scoring_contract=manifest["semantic_scoring"],
    )
    complete = bool(
        failure is None
        and scoring_error is None
        and has_final_text(messages)
        and observer.status()["complete"]
        and event_audit["valid"]
    )
    summary = {
        "schema_version": 1,
        "protocol": manifest["protocol"],
        "run_id": slot["run_id"],
        "sequence": slot["sequence"],
        "provider_id": slot["provider_id"],
        "model": slot["provider_config"]["model"],
        "real_llm": manifest["runtime"]["real_llm"],
        "status": "completed" if complete else "failed",
        "complete": complete,
        "error_type": failure,
        "error_status_code": status_code,
        "scoring_error_type": scoring_error,
        "semantic_matcher_error_type": matcher_error,
        "native_utility": native_utility,
        "native_utility_error_type": utility_error,
        "native_scoring": scoring,
        "stats": stats,
        "stop": stop,
        "acceptance": acceptance["acceptance"],
        "acceptance_valid": acceptance["valid"],
        "initial_environment_sha256": slot["initial_environment_sha256"],
        "final_environment_sha256": cross_model_pilot_v2.canonical_sha256(
            environment.model_dump(mode="json")
        ),
        "recording": {**observer.status(), "audit": event_audit},
        "interpretation": (
            "live technical acceptance"
            if manifest["runtime"]["real_llm"]
            else "offline transport control only; not model evidence"
        ),
    }
    artifacts = (
        ("requests.json", captured),
        ("reservations.json", reservations),
        ("actions.json", actions),
        ("messages.json", messages),
        ("final-environment.json", environment.model_dump(mode="json")),
        ("native-scoring.json", scoring),
        ("source-reads.json", source_reads),
        ("source-bindings.json", source_bindings),
        ("sink-records.json", sink_records),
        ("scoring-records.json", scoring_records),
        ("stop-record.json", stop),
        ("acceptance.json", acceptance),
        ("summary.json", summary),
    )
    for name, value in artifacts:
        _write_new(output / name, value)
    return summary


def _slot_item(slot: Mapping[str, Any], output: Path) -> dict[str, Any]:
    return {
        "sequence": slot["sequence"],
        "run_id": slot["run_id"],
        "configuration_task_pair_id": slot["configuration_task_pair_id"],
        "provider_id": slot["provider_id"],
        "suite": slot["suite"],
        "task_id": slot["task_id"],
        "condition": slot["condition"],
        "process_status": "not_started",
        "returncode": None,
        "run_path": (Path("runs") / slot["run_id"]).as_posix(),
        "error_type": None,
        "error_status_code": None,
        "recorded_request_count": 0,
        "summary": None,
    }


def dispatch(
    manifest: dict[str, Any],
    slot: dict[str, Any],
    output: Path,
    manifest_hash: str,
    credentials: Mapping[str, str],
) -> dict[str, Any]:
    spec_path = output / "specs" / f"{slot['run_id']}.json"
    _write_new(
        spec_path,
        {
            "manifest_path": "manifest.json",
            "manifest_sha256": manifest_hash,
            "slot": slot,
        },
    )
    item = _slot_item(slot, output)
    item["process_status"] = "failed"
    log_path = output / "processes" / f"{slot['run_id']}.log"
    with log_path.open("x", encoding="utf-8", newline="\n") as log:
        try:
            process = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--session-spec", str(spec_path)],
                stdout=log,
                stderr=log,
                timeout=manifest["runtime"]["task_timeout_seconds"],
                check=False,
                env={**os.environ, **credentials, "PYTHONUTF8": "1"},
            )
            item["returncode"] = process.returncode
        except subprocess.TimeoutExpired:
            item["error_type"] = "TaskTimeout"
            item["process_status"] = "failed"
        except OSError as error:
            item["error_type"] = type(error).__name__
    run_path = output / "runs" / slot["run_id"]
    summary_path = run_path / "summary.json"
    if summary_path.is_file():
        try:
            summary = _read_json(summary_path)
            item["summary"] = summary
            item["error_type"] = summary.get("error_type") or summary.get("scoring_error_type")
            item["error_status_code"] = summary.get("error_status_code")
            if item["returncode"] == 0:
                item["process_status"] = "completed"
        except (OSError, ValueError, json.JSONDecodeError) as error:
            item["error_type"] = type(error).__name__
    capture_path = run_path / "requests.jsonl"
    if capture_path.is_file():
        item["recorded_request_count"] = len(_jsonl(capture_path))
    return item


def _summary(
    manifest: Mapping[str, Any],
    output: Path,
    ledger: Sequence[Mapping[str, Any]],
    *,
    paused: bool,
    pause_kind: str | None,
    resume_count: int,
) -> dict[str, Any]:
    latest = {row["run_id"]: row for row in ledger if row.get("run_id")}
    slots = []
    for slot in manifest["protocol_manifest"]["slots"]:
        slots.append(copy.deepcopy(latest.get(slot["run_id"], _slot_item(slot, output))))
    requests = sum(int(item.get("recorded_request_count") or 0) for item in slots)
    if requests > manifest["runtime"]["request_attempt_ceiling"]:
        raise ValueError("Captured request count exceeds the frozen global ceiling")
    status_counts: dict[str, int] = {"pass": 0, "fail": 0, "not_covered": 0}
    for item in slots:
        decisions = ((item.get("summary") or {}).get("acceptance") or {}).values()
        for decision in decisions:
            status = decision.get("status") if isinstance(decision, Mapping) else None
            if status in status_counts:
                status_counts[status] += 1
    return {
        "schema_version": 1,
        "protocol": manifest["protocol"],
        "real_llm": manifest["runtime"]["real_llm"],
        "planned_runs": 32,
        "started_runs": sum(item["process_status"] != "not_started" for item in slots),
        "completed_runs": sum(item["process_status"] == "completed" for item in slots),
        "failed_runs": sum(item["process_status"] == "failed" for item in slots),
        "not_started_runs": sum(item["process_status"] == "not_started" for item in slots),
        "captured_request_attempts": requests,
        "request_attempt_ceiling": 320,
        "acceptance_status_counts": status_counts,
        "paused": paused,
        "pause_kind": pause_kind,
        "resume_count": resume_count,
        "slots": slots,
        "interpretation": (
            "technical acceptance only; offline runs are not model evidence and pass/fail/not_covered are retained independently"
        ),
    }


def _write_progress(output: Path, summary: Mapping[str, Any]) -> None:
    _write_atomic(
        output / "progress.json",
        {
            key: summary[key]
            for key in (
                "protocol",
                "planned_runs",
                "started_runs",
                "completed_runs",
                "failed_runs",
                "not_started_runs",
                "captured_request_attempts",
                "paused",
                "pause_kind",
                "resume_count",
            )
        }
        | {"updated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
    )


def run_slots(
    output: Path,
    manifest: dict[str, Any],
    manifest_hash: str,
    pending: Sequence[dict[str, Any]],
    prior: Sequence[dict[str, Any]],
    credentials: Mapping[str, str],
    *,
    resume_count: int,
    max_started_slots: int | None,
) -> dict[str, Any]:
    ledger_rows = list(prior)
    newly_started = 0
    paused = False
    pause_kind = None
    with (output / "slots.jsonl").open("a", encoding="utf-8", newline="\n") as ledger:
        for index, slot in enumerate(pending):
            if max_started_slots is not None and newly_started >= max_started_slots:
                paused = True
                pause_kind = "planned_checkpoint"
                _write_atomic(
                    output / "checkpoint.json",
                    {
                        "reason": "planned_start_limit",
                        "remaining_run_ids": [row["run_id"] for row in pending[index:]],
                    },
                )
                break
            started = _slot_item(slot, output)
            started["process_status"] = "started"
            _append_jsonl(ledger, started)
            ledger_rows.append(started)
            newly_started += 1
            item = dispatch(manifest, slot, output, manifest_hash, credentials)
            _append_jsonl(ledger, item)
            ledger_rows.append(item)
            interim = _summary(
                manifest,
                output,
                ledger_rows,
                paused=False,
                pause_kind=None,
                resume_count=resume_count,
            )
            _write_progress(output, interim)
            print(
                json.dumps(
                    {
                        "sequence": slot["sequence"],
                        "run_id": slot["run_id"],
                        "status": item["process_status"],
                    }
                ),
                flush=True,
            )
            if item.get("error_status_code") in PAUSE_STATUS_CODES:
                paused = True
                pause_kind = "provider_service"
                _write_atomic(
                    output / "service-pause.json",
                    {
                        "run_id": slot["run_id"],
                        "status_code": item["error_status_code"],
                        "remaining_run_ids": [row["run_id"] for row in pending[index + 1 :]],
                    },
                )
                break
    result = _summary(
        manifest,
        output,
        ledger_rows,
        paused=paused,
        pause_kind=pause_kind,
        resume_count=resume_count,
    )
    _write_atomic(output / "summary.json", result)
    _write_progress(output, result)
    return result


def run_batch(
    output: Path,
    *,
    agent_tracer_commit: str | None = None,
    live: bool = False,
    env_file: Path | None = None,
    max_started_slots: int | None = None,
    config_path: Path | str = cross_model_pilot_v2.CONFIG_PATH,
) -> dict[str, Any]:
    if max_started_slots is not None and max_started_slots < 1:
        raise ValueError("max_started_slots must be positive")
    if output.exists():
        raise FileExistsError(output)
    # Credential and revision checks intentionally precede output.mkdir().
    credentials = _credentials(live=live, env_file=env_file)
    commit = _exact_commit(agent_tracer_commit)
    semantic_identity = None
    if live:
        _verify_live_revision(commit)
        semantic_identity = _verified_semantic_identity()
    manifest = build_run_manifest(
        commit,
        live=live,
        semantic_identity=semantic_identity,
        config_path=config_path,
    )
    output.mkdir(parents=True, exist_ok=False)
    _write_new(output / "manifest.json", manifest)
    manifest_hash = _file_sha(output / "manifest.json")
    _write_new(
        output / "preflight.json",
        {
            "protocol": manifest["protocol"],
            "agent_tracer_commit": commit,
            "manifest_sha256": manifest_hash,
            "both_live_credentials_present": live,
            "credential_values_persisted": False,
            "live_revision_verified": live,
            "source_hashes_verified": True,
            "semantic_model_available": (ROOT / SEMANTIC_MODEL).is_dir(),
            "semantic_identity_verified_and_loadable": live,
            "real_llm": live,
        },
    )
    (output / "runs").mkdir()
    (output / "specs").mkdir()
    (output / "processes").mkdir()
    (output / "slots.jsonl").touch(exist_ok=False)
    return run_slots(
        output,
        manifest,
        manifest_hash,
        manifest["protocol_manifest"]["slots"],
        [],
        credentials,
        resume_count=0,
        max_started_slots=max_started_slots,
    )


def resume_batch(
    output: Path,
    *,
    env_file: Path | None = None,
    max_started_slots: int | None = None,
) -> dict[str, Any]:
    if max_started_slots is not None and max_started_slots < 1:
        raise ValueError("max_started_slots must be positive")
    manifest_path = output / "manifest.json"
    manifest = validate_run_manifest(_read_json(manifest_path))
    _assert_source_hashes(manifest)
    live = manifest["runtime"]["real_llm"]
    credentials = _credentials(live=live, env_file=env_file)
    if live:
        _verify_live_revision(manifest["agent_tracer_commit"])
        if _verified_semantic_identity() != manifest["semantic_scoring"]["identity"]:
            raise ValueError("Semantic model identity differs from the saved live manifest")
    pause_paths = [
        path for path in (output / "checkpoint.json", output / "service-pause.json") if path.is_file()
    ]
    if len(pause_paths) != 1:
        raise ValueError("Resume requires exactly one planned checkpoint or service pause")
    previous = _read_json(output / "summary.json")
    if previous.get("paused") is not True:
        raise ValueError("Saved batch is not paused")
    rows = _jsonl(output / "slots.jsonl")
    started_ids = {
        row["run_id"] for row in rows if row.get("process_status") in {"started", "completed", "failed"}
    }
    pending = [slot for slot in manifest["protocol_manifest"]["slots"] if slot["run_id"] not in started_ids]
    for slot in pending:
        if (output / "runs" / slot["run_id"]).exists():
            raise ValueError("Untouched slot has a run directory and cannot be resumed")
    generation = int(previous.get("resume_count", 0)) + 1
    pause_paths[0].rename(output / f"{pause_paths[0].stem}.before-resume-{generation}.json")
    return run_slots(
        output,
        manifest,
        _file_sha(manifest_path),
        pending,
        rows,
        credentials,
        resume_count=generation,
        max_started_slots=max_started_slots,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--agent-tracer-commit")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-started-slots", type=int)
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.session_spec:
        result = run_trial(args.session_spec.resolve())
        print(json.dumps({"run_id": result["run_id"], "status": result["status"]}))
        return 0
    if args.output is None:
        parser.error("--output is required")
    if args.resume:
        if args.live or args.agent_tracer_commit:
            parser.error("--resume derives mode and commit from the saved manifest")
        result = resume_batch(
            args.output.resolve(),
            env_file=args.env_file.resolve() if args.env_file else None,
            max_started_slots=args.max_started_slots,
        )
    else:
        result = run_batch(
            args.output.resolve(),
            agent_tracer_commit=args.agent_tracer_commit,
            live=args.live,
            env_file=args.env_file.resolve() if args.env_file else None,
            max_started_slots=args.max_started_slots,
        )
    print(
        json.dumps(
            {key: result[key] for key in ("completed_runs", "failed_runs", "not_started_runs", "paused")}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
