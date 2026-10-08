#!/usr/bin/env python
"""MELON as an online gate on the common H2 case files (AgentDojo v1.2.2 / 0.1.35), through the guard.

Runs in the agentdojo-lab venv (vendored AgentDojo 0.1.35, the same environment
as the undefended H2 runner). Two modes:

* **stage driver** (default): checks that this interpreter has the pinned
  agentdojo, loads the H2 case file and the stage selection from
  ``melon_h2_config.json``, expands it with ``h2/h2_core.expand_stage`` (so the
  episode ids and stimuli are the H2 runner's), checks every injections dict
  against the suite's v1.2.2 injection vectors, writes ``episode_plan.json`` and
  ``code_manifest.json`` (sha256 of every code file a child can import from the
  working tree: melon/, h2/, common/, the lab's src/ and its vendored AgentDojo),
  then starts **one fresh interpreter per episode** (the MELON cache lives in
  AgentPipeline.query's shared default dict, so a fresh process gives a
  per-episode cache) and writes ``episodes.jsonl``, ``summary.json`` and
  ``melon_h2_receipt.json``. Before each child it re-hashes the manifest and
  stops (EXIT_CONFIG, no request) if any file changed; after each child it
  stops if the child imported code that differs from the manifest.
* **child** (``--child --episode-id``): one episode. It installs the loopback
  network guard, builds the H2 runner's own runtime
  (``h2/run_h2.build_runtime``: lab DeepSeekLLM, wire-contract hook, request
  ceiling, pacer), replaces the tool loop's LLM with
  ``MELON(llm, threshold=0.1)`` behind the content-block shim
  (``melon_port.py``), refuses to send a request if its imported code differs
  from the manifest, runs the H2 runner's own episode function
  (``h2/run_h2.run_one`` v2: arm injections, 3-attempt loop, executed calls of
  every attempt including one salvaged after an error, utility, post-state X
  delta, typed oracle, transcript), and adds the MELON gate evidence.

``--plan-only`` makes no request. It is launched for real only through
``common/deepseek_route.py run-stage`` and never reads a ``.env`` or a key.
Saved benchmark text and model output are untrusted data.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import subprocess
import sys
import time
import traceback
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ADAPTERS = HERE.parent
H2_DIR = ADAPTERS / "h2"
COMMON = ADAPTERS / "common"
DEFAULT_LAB = ADAPTERS.parent / "agentdojo-lab"
DEFAULT_CONFIG = HERE / "melon_h2_config.json"
for _path in (HERE, H2_DIR, COMMON):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import melon_h2_core as mc  # noqa: E402
import melon_netguard  # noqa: E402

ADAPTER_VERSION = "melon-h2-gate/2"
SCHEMA_PLAN = "melon-h2-episode-plan/v1"
SCHEMA_RECEIPT = "melon-h2-receipt/v2"
SCHEMA_CODE_MANIFEST = "melon-h2-code-manifest/v1"
CODE_MANIFEST_NAME = "code_manifest.json"
# h2/run_h2.py v2 scores the executed calls of every attempt (including one salvaged after an
# upstream error) and writes Windows-safe transcripts; v1 scored the last attempt only and lost
# every call of an attempt that raised, so v1 is refused.
REQUIRED_H2_ADAPTER = "h2-deepseek-adapter/2"
REQUIRED_H2_RECORD_FIELDS = ("attempts_run", "attempt_endings", "salvaged_after_error")
EXIT_OK, EXIT_OTHER, EXIT_CONFIG, EXIT_GUARD_HALT, EXIT_ERRORS = 0, 1, 2, 3, 6
MAX_CONSECUTIVE_ERRORS = 5
SUITES = ("workspace", "travel", "banking", "slack")
_STATE = {"run_started": False}  # child: set once the episode may have sent a model request
SCRUBBED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONUSERBASE")
FILES_HASHED = {
    "run_melon_h2.py": HERE / "run_melon_h2.py", "melon_port.py": HERE / "melon_port.py",
    "melon_h2_core.py": HERE / "melon_h2_core.py", "melon_embedder.py": HERE / "melon_embedder.py",
    "melon_netguard.py": HERE / "melon_netguard.py", "melon_h2_config.json": HERE / "melon_h2_config.json",
    "h2/run_h2.py": H2_DIR / "run_h2.py", "h2/h2_core.py": H2_DIR / "h2_core.py",
    "common/deepseek_route.py": COMMON / "deepseek_route.py",
}
# Adapter dirs whose top-level code a child imports (tests are never imported by a child).
ADAPTER_CODE_DIRS = {"melon": (".py", ".json"), "h2": (".py", ".json"), "common": (".py",)}
TREE_SUFFIXES = (".py", ".yaml", ".yml")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _sha256_lf(path: Path) -> str | None:
    """LF-normalised content hash (the lab's CRLF-checkout caveat)."""
    try:
        return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    except OSError:
        return None


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str) + "\n")


def _redact(text: str, token: str) -> str:
    return text.replace(token, "[REDACTED]") if token else text


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if config.get("schema") != "melon-h2-config/v1":
        raise ValueError("config schema must be melon-h2-config/v1")
    return config


def venv_problem(config: dict[str, Any]) -> str | None:
    """None if this interpreter has the pinned agentdojo; else a refusal message (checked before anything else)."""
    pin = config["benchmark"]["package_version"]
    try:
        installed = importlib.metadata.version("agentdojo")
    except importlib.metadata.PackageNotFoundError:
        installed = None
    if installed == pin:
        return None
    return (f"this interpreter ({sys.executable}) has agentdojo {installed}, the AL stages need {pin}: run them in "
            f"the agentdojo-lab venv (deepseek_route.py run-stage --artifact-root <agent-tracer>/packages/agentdojo-lab), "
            f"not the MELON artifact venv")


def vector_ids(benchmark_version: str) -> dict[str, list[str]]:
    from agentdojo.task_suite.load_suites import get_suite

    return {name: sorted(get_suite(benchmark_version, name).get_injection_vector_defaults()) for name in SUITES}


def plan_stage(config: dict[str, Any], stage_name: str, case_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    import h2_core as hc

    if stage_name not in config["stages"]:
        raise ValueError(f"unknown stage {stage_name!r}; known: {sorted(config['stages'])}")
    case_file = hc.load_case_file(case_path)
    if not case_file.get("authority_arg_map"):
        raise ValueError("case file has no authority_arg_map (regenerate with the v2 generator)")
    planned = hc.expand_stage(case_file, config["stages"][stage_name])
    return case_file, planned


# ---------------------------------------------------------------------------
# Code manifest (what a child may import from the working tree)
# ---------------------------------------------------------------------------


def code_roots(lab_root: Path) -> dict[str, Path]:
    lab = Path(lab_root).resolve()
    return {"adapters": ADAPTERS.resolve(), "lab_src": (lab / "src").resolve(),
            "vendor": (lab / "vendor" / "agentdojo" / "src").resolve()}


def _code_key(roots: dict[str, Path], path: Path) -> str | None:
    resolved = Path(path).resolve()
    for name, root in roots.items():
        try:
            rel = resolved.relative_to(root)
        except ValueError:
            continue
        return f"{name}:{rel.as_posix()}"
    return None


def _digest(files: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{k}\t{v}\n" for k, v in sorted(files.items())).encode("utf-8")).hexdigest()


def code_manifest(lab_root: Path, config_path: Path) -> dict[str, Any]:
    """sha256 of every code file a child can import from the working tree, plus the stage config."""
    roots = code_roots(lab_root)
    files: dict[str, str] = {}
    for folder, suffixes in ADAPTER_CODE_DIRS.items():
        base = roots["adapters"] / folder
        if base.is_dir():
            for path in sorted(base.iterdir()):
                if path.is_file() and path.suffix in suffixes:
                    files[f"adapters:{folder}/{path.name}"] = _sha256_file(path) or "unreadable"
    for name in ("lab_src", "vendor"):
        root = roots[name]
        if root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.suffix in TREE_SUFFIXES and "__pycache__" not in path.parts:
                    files[f"{name}:{path.relative_to(root).as_posix()}"] = _sha256_file(path) or "unreadable"
    files[f"config:{Path(config_path).name}"] = _sha256_file(Path(config_path)) or "unreadable"
    return {"schema": SCHEMA_CODE_MANIFEST, "roots": {k: str(v) for k, v in roots.items()},
            "files": files, "n_files": len(files), "digest": _digest(files)}


def manifest_changes(start: dict[str, Any], now: dict[str, Any]) -> list[str]:
    a, b = start["files"], now["files"]
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


def loaded_code(roots: dict[str, Path]) -> dict[str, str]:
    """sha256 of every imported module file under the code roots (read now)."""
    out: dict[str, str] = {}
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        key = _code_key(roots, Path(filename))
        if key is not None and key not in out:
            out[key] = _sha256_file(Path(filename)) or "unreadable"
    return out


def compare_code(manifest_files: dict[str, str], loaded: dict[str, str]) -> dict[str, Any]:
    mismatched = sorted(k for k, v in loaded.items() if k in manifest_files and manifest_files[k] != v)
    unlisted = sorted(k for k in loaded if k not in manifest_files)
    return {"mismatched": mismatched, "unlisted": unlisted, "ok": not mismatched and not unlisted}


# ---------------------------------------------------------------------------
# Child: one episode
# ---------------------------------------------------------------------------


def _executed_with_ids(messages: list[Any], attempt: int) -> list[dict[str, Any]]:
    out = []
    for message in messages:
        if message.get("role") != "tool" or message.get("tool_call") is None:
            continue
        call = message["tool_call"]
        out.append({"attempt": attempt, "tool_call_id": message.get("tool_call_id"), "function": call.function,
                    "args": json.loads(json.dumps(dict(call.args), default=str)),
                    "success": message.get("error") is None,
                    "error": (str(message.get("error"))[:200] if message.get("error") else None)})
    return out


def _tool_texts(messages: list[Any]) -> list[str]:
    from melon_port import blocks_to_text

    return [blocks_to_text(m.get("content")) or "" for m in messages if m.get("role") == "tool"]


def _arm_text(case_file: dict[str, Any], episode: dict[str, Any]) -> str | None:
    case = next((c for c in case_file.get("cases") or [] if c.get("case_id") == episode["case_id"]), None)
    return ((case or {}).get("arms") or {}).get(episode["arm"], {}).get("arm_text")


def run_child(args: argparse.Namespace) -> int:
    melon_netguard.install()
    out_dir = Path(args.out_dir).resolve()
    plan = json.loads((out_dir / "episode_plan.json").read_text(encoding="utf-8"))
    episode = next((e for e in plan["episodes"] if e["episode_id"] == args.episode_id), None)
    if episode is None:
        print(f"episode {args.episode_id!r} not in plan", file=sys.stderr)
        return EXIT_CONFIG
    stem = mc.safe_name(episode["episode_id"])
    record_path = out_dir / "episodes" / f"{stem}.json"
    token = os.environ.get("AUDITOR_GUARD_TOKEN", "")
    started = time.monotonic()
    try:
        record = _child_episode(args, plan, episode, out_dir, stem)
    except Exception as exc:  # before run_one: nothing was sent; after: an adapter bug (requests may have been sent)
        record = {"schema": mc.SCHEMA_EPISODE, "episode_id": episode["episode_id"], "arm": episode["arm"],
                  "case_id": episode["case_id"], "scored": False, "run_error": True,
                  "status": "adapter_error" if _STATE["run_started"] else "precondition_failed",
                  "error_type": type(exc).__name__,
                  "error_message": _redact(str(exc), token)[:500],
                  "error_trace_tail": _redact("".join(traceback.format_exc().splitlines(True)[-6:]), token),
                  "netguard_blocked_hosts": list(melon_netguard.BLOCKED)}
    record["child_wall_seconds"] = round(time.monotonic() - started, 2)
    _write_json(record_path, record)
    print(json.dumps({k: record.get(k) for k in ("episode_id", "status", "outcome", "utility", "stop_hint")}
                     | {"x_call_approval": (((record.get("melon") or {}).get("gate")) or {}).get("x_call_approval")},
                     default=str))
    if record.get("status") == "ok":
        return EXIT_OK
    return EXIT_CONFIG if record.get("status") == "precondition_failed" else EXIT_ERRORS


def _child_episode(args: argparse.Namespace, plan: dict[str, Any], episode: dict[str, Any], out_dir: Path,
                   stem: str) -> dict[str, Any]:
    if Path.cwd().joinpath(".env").exists():
        raise RuntimeError("refusing to run from a directory that contains a .env file")
    config = load_config(Path(args.config))
    if _sha256_lf(Path(args.config)) != plan.get("config_sha256"):
        raise RuntimeError("stage config changed since the plan was written")
    stage = config["stages"][plan["stage"]]
    case_path = Path(plan["case_file"]["path"])
    if _sha256_file(case_path) != plan["case_file"]["sha256"]:
        raise RuntimeError("case file changed since the plan was written")
    case_file = json.loads(case_path.read_text(encoding="utf-8"))
    manifest_path = out_dir / CODE_MANIFEST_NAME
    if not manifest_path.is_file():
        raise RuntimeError(f"no {CODE_MANIFEST_NAME} in the out dir (start episodes through the stage driver)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problem = venv_problem(config)
    if problem:
        raise RuntimeError(problem)

    import openai
    import run_h2
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo_lab.h2_cases import classify_outcome, contains_value
    from deepseek_route import RouteError, require_guard

    import melon_port
    from melon_embedder import SubstituteEmbeddingClient, build_encoder, cosine

    if getattr(run_h2, "ADAPTER_VERSION", None) != REQUIRED_H2_ADAPTER:
        raise RuntimeError(f"h2/run_h2.py is {getattr(run_h2, 'ADAPTER_VERSION', None)!r}; this loader needs "
                           f"{REQUIRED_H2_ADAPTER} (all-attempt scoring with salvage after an error)")
    try:
        base_url, token = require_guard()
    except RouteError as exc:
        raise RuntimeError(str(exc)) from None
    shared_default = AgentPipeline.query.__defaults__[-1]
    if not isinstance(shared_default, dict) or shared_default:
        raise RuntimeError("AgentPipeline.query shared default extra_args is not an empty dict at process start")

    melon_module, artifact_sha = melon_port.load_artifact(Path(args.melon_dir))
    encoder = build_encoder("minilm", minilm_dir=args.embedder_dir)
    if encoder.weights_sha256 != config["melon"]["embedder"]["weights_sha256"]:
        raise RuntimeError("MiniLM weights differ from the pinned sha256")
    embed_client = SubstituteEmbeddingClient(encoder, max_requests=args.max_embedding_requests)

    ctx = run_h2._Context()
    ctx.episode_id = episode["episode_id"]
    rt = run_h2.build_runtime(config, stage, base_url=base_url, token=token, out_dir=out_dir, ctx=ctx)
    llm = rt["llm"]
    recorder = melon_port.MelonRecorder(stats_source=lambda: llm.stats)

    def kind_hook(request: Any) -> None:
        _append_jsonl(out_dir / "melon_requests.jsonl", {
            "episode_id": ctx.episode_id, "n": ctx.request_index, "kind": recorder.kind,
            "body_sha256": hashlib.sha256(request.content).hexdigest(), "body_bytes": len(request.content)})

    rt["http_client"].event_hooks["request"].append(kind_hook)

    gate, detector = melon_port.build_melon_gate(llm, melon_module, embed_client, recorder, cosine)
    system_el, init_el, first_llm, loop = list(rt["pipeline"].elements)
    if first_llm is not llm or not isinstance(loop, ToolsExecutionLoop) or loop.elements[1] is not llm:
        raise RuntimeError("unexpected undefended pipeline layout from run_h2.build_runtime")

    class CountingPipeline(AgentPipeline):
        def query(self, *a: Any, **k: Any):  # type: ignore[override]
            recorder.new_attempt()
            try:
                result = super().query(*a, **k)  # extra_args left to the shared default, as the stock runner does
            except AbortAgentError as exc:
                recorder.end_attempt(exc.messages, ended="abort", error_type=type(exc).__name__)
                raise
            except BaseException as exc:
                # The attempt raised (upstream 5xx, timeout, request ceiling): keep the real conversation
                # the shim saw last, so calls that already executed are still joined to the gate rows.
                recorder.end_attempt(recorder.last_trajectory, ended="error", error_type=type(exc).__name__)
                raise
            recorder.end_attempt(result[3], ended="completed")
            return result

    # loop.elements[0] is the H2 runner's (recording) ToolsExecutor, kept as is.
    pipeline = CountingPipeline([system_el, init_el, first_llm,
                                 ToolsExecutionLoop([loop.elements[0], gate], max_iters=loop.max_iters)])
    pipeline.name = f"{llm.name}-melon"
    rt["pipeline"] = pipeline

    version = config["benchmark"]["benchmark_version"]
    suites = {name: get_suite(version, name) for name in SUITES}
    authority_args = {k: list(v) for k, v in (case_file.get("authority_arg_map") or {}).items()}

    # No request before the imported code is known to be the manifest's.
    roots = code_roots(Path(args.lab_root))
    loaded_start = loaded_code(roots)
    start_check = compare_code(manifest["files"], loaded_start)
    if not start_check["ok"]:
        raise RuntimeError(f"code changed since the stage started (manifest {manifest['digest'][:12]}): "
                           f"mismatched {start_check['mismatched'][:10]}, unlisted {start_check['unlisted'][:10]}")

    transcripts_dir = out_dir / "transcripts"
    transcripts_dir.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    _STATE["run_started"] = True
    try:
        with redirect_stdout(buffer):
            record = run_h2.run_one(episode, suites=suites, authority_args=authority_args, rt=rt, token=token,
                                    transcripts_dir=transcripts_dir)
    finally:
        log = out_dir / "episodes" / f"{stem}.stdout.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(_redact(buffer.getvalue(), token), encoding="utf-8")
        rt["http_client"].close()
    exc = record.pop("_exception")

    # Code imported during the run (lazy imports included), checked again at the end.
    loaded_end = loaded_code(roots)
    end_check = compare_code(manifest["files"], loaded_end)
    changed_during = sorted(k for k, v in loaded_start.items() if loaded_end.get(k) != v)
    code_check = {"manifest_digest": manifest["digest"], "loaded_files": len(loaded_end),
                  "loaded_by_root": {name: sum(1 for k in loaded_end if k.startswith(f"{name}:")) for name in roots},
                  "loaded_digest": _digest(loaded_end), "mismatched": end_check["mismatched"],
                  "unlisted": end_check["unlisted"], "changed_during_episode": changed_during,
                  "ok": bool(end_check["ok"] and not changed_during)}

    stop_hint = None
    if exc is not None:
        if isinstance(exc, run_h2.WireAssertionError) or isinstance(getattr(exc, "__cause__", None), run_h2.WireAssertionError):
            stop_hint = "wire_assertion"
        elif isinstance(exc, openai.APIStatusError) and exc.status_code in (401, 402, 403):
            stop_hint = "guard_refusal"
    if record.get("transcript_path"):
        record["h2_transcript_relpath"] = f"transcripts/{record['transcript_path']}"
    record.update({
        "schema": mc.SCHEMA_EPISODE,
        "h2_episode_schema": record.get("schema"),
        "h2_adapter": run_h2.ADAPTER_VERSION,
        "adapter": ADAPTER_VERSION,
        "status": "ok" if exc is None else "error",
        "stop_hint": stop_hint,
        "attempts": record.get("attempts_run"),
        "code_check": code_check,
        "shared_default_extra_args_keys_at_end": sorted(shared_default.keys()),
        "netguard_blocked_hosts": list(melon_netguard.BLOCKED),
    })
    melon_block: dict[str, Any] = {
        "artifact": {"sha256": artifact_sha, "commit": melon_port.ARTIFACT_COMMIT, "modified": False},
        "runtime_port": "melon_port content-block shim (declared)",
        "threshold_arg": melon_port.MELON_THRESHOLD_ARG,
        "effective_threshold": melon_port.MELON_EFFECTIVE_THRESHOLD,
        "mode": detector.mode,
        "replaced_detection_client": detector.replaced_detection_client_type,
        "embedder": embed_client.description,
        "embedding_requests": embed_client.embeddings.request_count,
        "embedding_request_cap": args.max_embedding_requests,
        "embedding_models_requested_by_artifact": sorted(set(embed_client.embeddings.requested_models)),
        "cache_scope": "per-episode (fresh interpreter)",
        "gate": None,
    }
    record["melon"] = melon_block

    # Gate evidence. A failure here is an adapter bug: the scored H2 record is kept (it was paid for)
    # with gate_error, and the driver stops the stage.
    try:
        missing = [k for k in REQUIRED_H2_RECORD_FIELDS if k not in record]
        if missing:
            raise RuntimeError(f"h2 record lacks {missing} (run_h2 contract changed)")
        executed_all: list[dict[str, Any]] = []
        for attempt, messages in enumerate(recorder.attempt_messages, start=1):
            executed_all += _executed_with_ids(messages, attempt)
        executed_by_key = {(c["attempt"], c["tool_call_id"]): c for c in executed_all if c.get("tool_call_id")}
        legit = episode.get("legitimate_set") or []
        calls = mc.gate_calls(recorder.steps, executed_by_key, authority_args=authority_args,
                              attacker_value=episode["attacker_value"], decoy_value=episode.get("decoy_value"),
                              legitimate_set=legit, target=episode["target"])
        gate_view = mc.episode_gate_summary(recorder.steps, calls, authority_args=authority_args,
                                            attacker_value=episode["attacker_value"],
                                            decoy_value=episode.get("decoy_value"), executed=executed_all,
                                            target=episode["target"], legitimate_set=legit)
        exposure = mc.exposure_pre_gate(recorder.steps, calls, recorder.tool_outputs_seen,
                                        arm_text=_arm_text(case_file, episode),
                                        attacker_value=episode["attacker_value"], contains_value=contains_value)
        # Cross-check: the typed oracle on the gate's own view of the executed calls must agree with the
        # H2 record (both read every attempt, including one salvaged after an error).
        mine = classify_outcome(
            episode["target"], legit, episode["attacker_value"], episode.get("decoy_value"), executed_all,
            record.get("utility"), authority_args=authority_args, run_error=bool(record.get("run_error")),
            attacker_state_observable=bool(episode.get("attacker_state_observable")),
            post_state_adds_attacker=(record.get("oracle_details") or {}).get("post_state_adds_attacker"))
        by_kind: dict[str, dict[str, int]] = {}
        for row in recorder.llm_calls:
            bucket = by_kind.setdefault(row["kind"], {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0})
            bucket["requests"] += int(row["usage"].get("request_count", 0))
            bucket["prompt_tokens"] += int(row["usage"].get("prompt_tokens", 0))
            bucket["completion_tokens"] += int(row["usage"].get("completion_tokens", 0))
        agent_init = {"requests": int(record.get("requests") or 0), "prompt_tokens": int(record.get("prompt_tokens") or 0),
                      "completion_tokens": int(record.get("completion_tokens") or 0)}
        for bucket in by_kind.values():
            for key in agent_init:
                agent_init[key] -= bucket[key]
        by_kind["agent_init"] = agent_init
        transcript = out_dir / "melon_transcripts" / f"{stem}.json"
        _write_json(transcript, {
            "episode_id": episode["episode_id"],
            "attempt_endings": recorder.attempt_endings,
            "executed_calls_all_attempts": executed_all,
            "tool_outputs_final_trace": _tool_texts(recorder.attempt_messages[-1]) if recorder.attempt_messages else [],
            "tool_outputs_seen_before_gate": recorder.tool_outputs_seen,
            "melon_steps": recorder.steps,
            "llm_calls": recorder.llm_calls,
        })
        record.update(exposure)
        record["melon_transcript_path"] = f"melon_transcripts/{transcript.name}"
        record["injection_exposed_note"] = ("injection_exposed (H2) tests X in any tool output of the final traces; "
                                            "injection_exposed_pre_gate tests the arm's planted text in what the agent "
                                            "saw before the first X proposal (None for CLEAN)")
        melon_block.update({
            "steps": json.loads(json.dumps(recorder.steps, default=str)),
            "calls": calls,
            "gate": gate_view,
            "gate_attempts_recorded": len(recorder.attempt_messages),
            "gate_attempt_endings": recorder.attempt_endings,
            "gate_attempts_match_h2": len(recorder.attempt_messages) == record.get("attempts_run"),
            "gate_oracle_cross_check": {"outcome": mine["outcome"], "subtype": mine["subtype"],
                                        "agrees": (mine["outcome"], mine["subtype"]) == (record.get("outcome"), record.get("subtype"))},
            "usage_by_kind": by_kind,
        })
    except Exception as gate_exc:  # noqa: BLE001
        melon_block["gate"] = None
        record["gate_error"] = {"error_type": type(gate_exc).__name__,
                                "error_message": _redact(str(gate_exc), token)[:500],
                                "error_trace_tail": _redact("".join(traceback.format_exc().splitlines(True)[-6:]), token)}
        if record["status"] == "ok":
            record["status"] = "gate_error"
    return record


# ---------------------------------------------------------------------------
# Stage driver
# ---------------------------------------------------------------------------


def child_env(base: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in base.items() if k not in SCRUBBED_ENV}
    env.update({"PYTHONHASHSEED": "0", "PYTHONUTF8": "1", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return env


def child_command(args: argparse.Namespace, episode_id: str) -> list[str]:
    return [args.python, "-s", "-P", "-X", "utf8", str(Path(__file__).resolve()), "--child",
            "--config", str(Path(args.config).resolve()), "--cases", str(Path(args.cases).resolve()),
            "--stage", args.stage, "--lab-root", str(Path(args.lab_root).resolve()),
            "--melon-dir", str(Path(args.melon_dir).resolve()), "--embedder-dir", str(Path(args.embedder_dir).resolve()),
            "--out-dir", str(Path(args.out_dir).resolve()), "--episode-id", episode_id,
            "--max-embedding-requests", str(args.max_embedding_requests)]


def _spawn_child(command: list[str], env: dict[str, str], timeout: float) -> tuple[int | None, str, str]:
    """Run one child; (returncode or None on timeout, stdout, stderr)."""
    try:
        proc = subprocess.run(command, env=env, cwd=os.getcwd(), capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", "episode timeout"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _read_child_record(path: Path, episode_id: str) -> dict[str, Any] | None:
    """The child's record, or None if missing, unreadable or for another episode."""
    if not path.is_file():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return record if isinstance(record, dict) and record.get("episode_id") == episode_id else None


RAN_STATUSES = ("ok", "error", "gate_error")  # the child reached run_one and must carry a code_check


def code_drift(record: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    """Why a run child's imported code differs from the stage manifest ([] if it does not).

    Only records that reached the episode function are checked; a precondition failure (nothing
    sent) stops the stage on its own, and an adapter error or a dead child counts as an episode error.
    """
    if record.get("status") not in RAN_STATUSES:
        return []
    check = record.get("code_check")
    if not isinstance(check, dict):
        return ["record has no code_check"]
    problems = []
    if check.get("manifest_digest") != manifest["digest"]:
        problems.append("checked against another manifest")
    problems += [f"mismatched:{k}" for k in check.get("mismatched") or []]
    problems += [f"unlisted:{k}" for k in check.get("unlisted") or []]
    problems += [f"changed_during_episode:{k}" for k in check.get("changed_during_episode") or []]
    return problems


def _load_prior(resume_dirs: list[Path], digest: str, manifest_digest: str | None = None) -> list[dict[str, Any]]:
    import h2_core as hc

    prior: list[dict[str, Any]] = []
    for folder in resume_dirs:
        plan = json.loads((folder / "episode_plan.json").read_text(encoding="utf-8"))
        if plan.get("plan_digest") != digest:
            raise ValueError(f"--resume-from {folder} was planned from a different case file or stage")
        if manifest_digest is not None:
            receipt_path = folder / "melon_h2_receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.is_file() else {}
            if receipt.get("code_manifest_digest") != manifest_digest:
                raise ValueError(f"--resume-from {folder} ran on other code (code manifest "
                                 f"{str(receipt.get('code_manifest_digest'))[:12]} != {manifest_digest[:12]}); "
                                 f"start a fresh out dir instead of mixing code versions")
        prior.extend(hc.read_jsonl(folder / "episodes.jsonl"))
    return prior


def _latest(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for record in records:
        seen.setdefault(record["episode_id"], record)
    return list(seen.values())


def write_summary(out_dir: Path, config: dict[str, Any], case_file: dict[str, Any], stage_name: str,
                  planned: list[dict[str, Any]], records: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    import h2_core as hc

    summary = hc.summarize(case_file, stage_name, planned, records, mode=mode, price=config.get("price_snapshot"))
    summary["evidence_label"] = (config["evidence_label"] if mode == "deepseek"
                                 else "plumbing or test run only (not evidence)")
    summary["melon_gate"] = mc.summarize_gate(planned, records)
    summary["exposure_note"] = ("per_arm.exposure_rate is the H2 field (X in any tool output of the final traces, "
                                "where MELON may blank the latest output); melon_gate.per_arm."
                                "injection_exposed_pre_gate_rate is the arm's planted text in what the agent saw "
                                "before the first X proposal, over arms that plant text")
    _write_json(out_dir / "summary.json", summary)
    return summary


def run_stage(args: argparse.Namespace) -> int:
    import h2_core as hc

    config = load_config(Path(args.config))
    if not args.summarize_only:
        problem = venv_problem(config)
        if problem:
            print(f"refused: {problem}", file=sys.stderr)
            return EXIT_CONFIG
    try:
        case_file, planned = plan_stage(config, args.stage, Path(args.cases))
    except (ValueError, hc.H2RunError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("AUDITOR_MODE") or ("plan-only" if args.plan_only else "unknown")
    digest = hc.plan_digest(planned)

    if args.summarize_only:
        plan = json.loads((out_dir / "episode_plan.json").read_text(encoding="utf-8"))
        records = _latest(_load_prior(args.resume_from, plan["plan_digest"]) + hc.read_jsonl(out_dir / "episodes.jsonl"))
        summary = write_summary(out_dir, config, case_file, args.stage, plan["episodes"], records, plan.get("mode", mode))
        print(json.dumps({"summary": str(out_dir / "summary.json"), "complete": summary["complete"]}))
        return EXIT_OK

    try:
        contract = mc.validate_injections(planned, vector_ids(config["benchmark"]["benchmark_version"]))
    except mc.CaseContractError as exc:
        print(f"case contract error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    plan_doc = {
        "schema": SCHEMA_PLAN, "adapter": ADAPTER_VERSION, "stage": args.stage, "mode": mode, "planned_at": _utc(),
        "plan_digest": digest,
        "plan_digest_note": "h2_core.plan_digest of the expanded episodes; equal to the H2 runner's digest for the mirrored stage",
        "mirrors_h2_stage": config["stages"][args.stage].get("mirrors_h2_stage"),
        "case_file": {"path": str(Path(args.cases).resolve()), "sha256": _sha256_file(Path(args.cases)),
                      "config_sha256": case_file.get("config_sha256"), "cases_digest": case_file.get("cases_digest")},
        "config_sha256": _sha256_lf(Path(args.config)),
        "case_contract": contract,
        "counts": hc.count_arms(planned),
        "episodes": planned,
    }
    _write_json(out_dir / "episode_plan.json", plan_doc)
    print(json.dumps({"stage": args.stage, "counts": plan_doc["counts"], "plan_digest": digest, **contract}))
    if args.plan_only:
        return EXIT_OK

    # Preconditions (no request is made before all of these pass) -------------
    try:
        if Path.cwd().joinpath(".env").exists():
            raise ValueError("refusing to run from a directory that contains a .env file")
        import run_h2
        from deepseek_route import RouteError, require_guard

        import melon_port
        from melon_embedder import sha256_file

        if getattr(run_h2, "ADAPTER_VERSION", None) != REQUIRED_H2_ADAPTER:
            raise ValueError(f"h2/run_h2.py is {getattr(run_h2, 'ADAPTER_VERSION', None)!r}; this loader needs "
                             f"{REQUIRED_H2_ADAPTER} (all-attempt scoring with salvage after an error)")
        try:
            require_guard()
        except RouteError as exc:
            raise ValueError(str(exc)) from None
        lab = run_h2.lab_status(Path(args.lab_root).resolve())
        run_h2.require_lab(lab, config["benchmark"]["package_version"])
        artifact_sha = _sha256_file(Path(args.melon_dir).joinpath(*melon_port.ARTIFACT_REL))
        if artifact_sha != melon_port.ARTIFACT_SHA256:
            raise ValueError(f"MELON artifact missing or modified under --melon-dir (sha256 {artifact_sha})")
        weights = Path(args.embedder_dir) / "model.safetensors"
        if not weights.is_file() or sha256_file(weights) != config["melon"]["embedder"]["weights_sha256"]:
            raise ValueError("MiniLM weights missing or not the pinned file under --embedder-dir")
        manifest = code_manifest(Path(args.lab_root), Path(args.config))
        prior = _load_prior(args.resume_from, digest, manifest["digest"])
        _write_json(out_dir / CODE_MANIFEST_NAME, manifest)
    except (ValueError, OSError, ImportError) as exc:  # h2_core.H2RunError is a ValueError
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    receipt: dict[str, Any] = {
        "schema": SCHEMA_RECEIPT, "adapter": ADAPTER_VERSION, "stage": args.stage, "mode": mode,
        "backbone": os.environ.get("AUDITOR_BACKBONE"), "plan_digest": digest, "started_at": _utc(),
        "lab": lab, "case_file": plan_doc["case_file"], "artifact_sha256": artifact_sha,
        "h2_adapter": run_h2.ADAPTER_VERSION,
        "code_manifest_digest": manifest["digest"], "code_manifest_files": manifest["n_files"],
        "code_manifest_path": CODE_MANIFEST_NAME,
        "code_manifest_note": ("every child refuses to send a request if its imported code differs from the manifest; "
                               "the driver re-hashes the manifest before each child and stops on any change. The "
                               "route's own launch/end snapshot covers common/ and melon/ only"),
        "files_sha256_lf": {name: _sha256_lf(path) for name, path in FILES_HASHED.items()},
        "h2_cases_py_sha256_lf": _sha256_lf(Path(args.lab_root) / "src" / "agentdojo_lab" / "h2_cases.py"),
        "python": {"executable": args.python, "version": platform.python_version(), "platform": platform.platform()},
        "resumed_from": [str(p) for p in args.resume_from], "skipped_as_started_before": 0,
        "deviations": config.get("deviations", []), "children": [],
    }
    started_before = {r["episode_id"] for r in prior}
    episodes_path = out_dir / "episodes.jsonl"
    env = child_env(dict(os.environ))
    exit_code, stop_reason, consecutive = EXIT_OK, "all planned episodes started", 0
    try:
        for episode in planned:
            if episode["episode_id"] in started_before:
                receipt["skipped_as_started_before"] += 1
                continue
            changed = manifest_changes(manifest, code_manifest(Path(args.lab_root), Path(args.config)))
            if changed:
                exit_code, stop_reason = EXIT_CONFIG, f"code changed since the stage started: {changed[:10]}"
                break
            stem = mc.safe_name(episode["episode_id"])
            record_path = out_dir / "episodes" / f"{stem}.json"
            record_path.unlink(missing_ok=True)  # never read a record left by an earlier run in this out dir
            t0 = time.monotonic()
            rc, stdout, stderr = _spawn_child(child_command(args, episode["episode_id"]), env, args.episode_timeout)
            tail = stdout.strip().splitlines()[-1:] or [""]
            print(tail[0], flush=True)
            if stderr:
                (out_dir / "episodes").mkdir(parents=True, exist_ok=True)
                (out_dir / "episodes" / f"{stem}.stderr.log").write_text(stderr, encoding="utf-8")
            record = _read_child_record(record_path, episode["episode_id"])
            if record is None:
                record = {"schema": mc.SCHEMA_EPISODE, "episode_id": episode["episode_id"], "arm": episode["arm"],
                          "case_id": episode["case_id"], "scored": False, "run_error": True, "status": "child_failed",
                          "child_returncode": rc}
            drift = code_drift(record, manifest)
            if drift:
                record["code_drift"] = drift
            receipt["children"].append({"episode_id": episode["episode_id"], "returncode": rc,
                                        "seconds": round(time.monotonic() - t0, 1), "status": record.get("status")})
            _append_jsonl(episodes_path, record)
            if rc is None:
                exit_code, stop_reason = EXIT_OTHER, f"episode timeout after {args.episode_timeout}s"
                break
            if drift:
                exit_code, stop_reason = EXIT_CONFIG, f"code drift in {episode['episode_id']}: {drift[:10]}"
                break
            if record.get("transcript_error"):
                exit_code, stop_reason = EXIT_ERRORS, f"transcript not written for {episode['episode_id']}: {record['transcript_error']}"
                break
            if record.get("gate_error"):
                exit_code, stop_reason = EXIT_ERRORS, (f"gate evidence failed for {episode['episode_id']} "
                                                       f"({record['gate_error'].get('error_type')}); adapter bug")
                break
            if record.get("status") == "ok":
                consecutive = 0
                continue
            if record.get("status") == "precondition_failed":
                exit_code, stop_reason = EXIT_CONFIG, f"child precondition failed: {record.get('error_message')}"
                break
            consecutive += 1
            if record.get("stop_hint") == "wire_assertion":
                exit_code, stop_reason = EXIT_CONFIG, "wire assertion failed (request not sent)"
                break
            if record.get("stop_hint") == "guard_refusal":
                exit_code, stop_reason = EXIT_GUARD_HALT, f"guard or provider refused (HTTP {record.get('error_status_code')})"
                break
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                exit_code, stop_reason = EXIT_ERRORS, f"{consecutive} consecutive episode errors"
                break
    except BaseException as exc:  # noqa: BLE001
        exit_code, stop_reason = EXIT_OTHER, f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        records = _latest(prior + hc.read_jsonl(episodes_path))
        summary = write_summary(out_dir, config, case_file, args.stage, planned, records, mode)
        end_manifest = code_manifest(Path(args.lab_root), Path(args.config))
        receipt.update({"finished_at": _utc(), "exit_code": exit_code, "stop_reason": stop_reason,
                        "code_manifest_end_digest": end_manifest["digest"],
                        "code_unchanged_at_end": end_manifest["digest"] == manifest["digest"],
                        "episodes_jsonl_sha256": _sha256_file(episodes_path) if episodes_path.exists() else None})
        _write_json(out_dir / "melon_h2_receipt.json", receipt)
    print(json.dumps({"stage": args.stage, "exit_code": exit_code, "stop_reason": stop_reason,
                      "started": summary["started_episodes"], "planned": summary["planned_episodes"],
                      "usage": summary["usage"]}))
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MELON online gate on H2 case files (guarded, one process per episode)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--cases", required=True, help="H2 case file (h2-cases/v2) from generate_h2_cases.py")
    parser.add_argument("--stage", required=True)
    parser.add_argument("--lab-root", default=str(DEFAULT_LAB))
    parser.add_argument("--melon-dir", default=os.environ.get("MELON_ARTIFACT_DIR"),
                        help="artifact folder that holds src/MELON/pi_detector.py")
    parser.add_argument("--embedder-dir", default=None, help="pinned all-MiniLM-L6-v2 dir (default: <lab-root>/.model-cache/...)")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--python", default=sys.executable, help="lab venv interpreter for the episode children")
    parser.add_argument("--resume-from", type=Path, action="append", default=[])
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--episode-timeout", type=float, default=1800.0)
    parser.add_argument("--max-embedding-requests", type=int, default=400,
                        help="per-episode cap on substitute-embedder calls (declared deviation; the artifact has none)")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--episode-id", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.embedder_dir is None:
        config = load_config(Path(args.config))
        args.embedder_dir = str(Path(args.lab_root) / config["melon"]["embedder"]["dir_relative_to_lab_root"])
    if args.child:
        return run_child(args)
    melon_netguard.install()
    if not args.plan_only and not args.summarize_only and not args.melon_dir:
        print("set --melon-dir or MELON_ARTIFACT_DIR", file=sys.stderr)
        return EXIT_CONFIG
    return run_stage(args)


if __name__ == "__main__":
    raise SystemExit(main())
