"""Frozen ten-slot native evaluation; only never-started slots may be resumed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab.file_lock import acquire_exclusive_nonblocking
from agentdojo_lab.runner import ROOT, RunConfig, require_upstream


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _runtime():
    return {
        "python": sys.version,
        "packages": {
            name: version(name) for name in ("agentdojo", "openai", "httpx", "sentence-transformers", "torch")
        },
    }


def _write_new(path: Path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def _stop_process(process):
    """Reap a timed-out child even if it exits between wait and group cleanup."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait()


def _implementation_hashes():
    paths = {ROOT / name for name in ("uv.lock", "upstream.json", "EVALUATION.md", "pyproject.toml")}
    for directory in ("src/agentdojo_lab", "tests", "scripts", "configs"):
        paths.update(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file() and path.suffix in {".py", ".html", ".js", ".svg", ".json", ".yaml", ".toml"}
        )
    return {str(path.relative_to(ROOT)): _sha(path) for path in sorted(paths)}


def schedule(config: dict) -> list[dict]:
    from agentdojo_lab.evaluation_runner import EvaluationTrial

    if config.get("schema_version") != 1 or config.get("repetitions") != 5:
        raise ValueError("Protocol v1 requires exactly five repetitions")
    if config.get("request_limit") != 4 or config.get("task_timeout_seconds") != 600:
        raise ValueError("Protocol v1 requires four primary requests and 600 seconds per slot")
    if config.get("auditor_max_probes") != 1:
        raise ValueError("Protocol v1 permits at most one auditor probe per slot")
    run = RunConfig.model_validate(config["run"])
    expected_run = RunConfig(
        provider="groq",
        model="openai/gpt-oss-120b",
        benchmark_version="v1.2.2",
        suite="workspace",
        user_tasks=["user_task_29"],
        temperature=0.0,
        reasoning_effort="low",
        max_completion_tokens=4096,
        max_tool_rounds=4,
        request_timeout_seconds=60.0,
        record_events=True,
        online_provenance=True,
        provenance_policy="configs/workspace_policy_v1.yaml",
        lineage_namespace="workspace-file29-evaluation-v1",
        canary_enabled=True,
        semantic_model=".model-cache/all-MiniLM-L6-v2-1110a243",
        semantic_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        pacing_tokens_per_minute=7000,
    )
    if run != expected_run:
        raise ValueError("Protocol v1 requires its fixed model, policy, tracing and request settings")
    result = []
    for repeat in range(1, 6):
        for condition in ("clean", "injected") if repeat % 2 else ("injected", "clean"):
            spec = EvaluationTrial(
                trial_id=f"r{repeat:02d}-{condition}",
                case_id=config["case_id"],
                repeat=repeat,
                condition=condition,
                user_task_id=config["user_task_id"],
                injection_task_id=config["injection_task_id"],
                vector_id=config["vector_id"],
                payload=config["payload"],
                request_limit=config["request_limit"],
            )
            result.append(spec.model_dump())
    return result


def create_evaluation_plan(output: Path, config_path: Path | None = None) -> Path:
    from agentdojo_lab.evaluation_runner import EvaluationTrial, validate_evaluation

    path = config_path or ROOT / "configs/evaluation_pilot_v1.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    trials = schedule(config)
    run = RunConfig.model_validate(config["run"])
    upstream = require_upstream()
    suite = get_suite(run.benchmark_version, run.suite)
    validate_evaluation(run, EvaluationTrial.model_validate(trials[0]), suite)
    destination = Path(output).expanduser().resolve()
    if destination == ROOT or destination in ROOT.parents:
        raise ValueError("The batch requires a new dedicated output directory")
    destination.mkdir(parents=True, exist_ok=False)
    for name in ("runs", "jobs", "audits"):
        (destination / name).mkdir()
    (destination / "config.json").write_bytes(path.read_bytes())
    (destination / "protocol.md").write_bytes((ROOT / "EVALUATION.md").read_bytes())
    plan = {
        "schema_version": 1,
        "protocol": "native-file-attribution-pilot-v1",
        "created_at": _now(),
        "batch_id": destination.name,
        "config": config,
        "schedule": trials,
        "source_hashes": _implementation_hashes(),
        "upstream": upstream,
        "frozen_files": {name: _sha(destination / name) for name in ("config.json", "protocol.md")},
        "runtime": _runtime(),
        "primary_request_ceiling": 40,
        "auditor_request_ceiling": 10,
        "independent_labels": "pending_human_review",
        "accuracy_metrics": None,
        "task_prompt": suite.user_tasks[run.user_tasks[0]].PROMPT,
        "native_attack_goal": suite.injection_tasks[config["injection_task_id"]].GOAL,
        "commands": [
            f"{sys.executable} -m agentdojo_lab.evaluation_batch trial --batch {destination} --trial {item['trial_id']}"
            for item in trials
        ],
    }
    _write_new(destination / "plan.json", plan)
    (destination / "plan.sha256").write_text(_sha(destination / "plan.json") + "\n")
    return destination


def read_evaluation_plan(batch: Path, *, check_implementation=True) -> dict:
    batch = Path(batch).resolve()
    if _sha(batch / "plan.json") != (batch / "plan.sha256").read_text().strip():
        raise ValueError("Frozen evaluation plan changed")
    plan = json.loads((batch / "plan.json").read_text())
    if plan.get("schema_version") != 1 or plan.get("schedule") != schedule(plan["config"]):
        raise ValueError("Frozen trial order changed")
    for name, digest in plan["frozen_files"].items():
        if name not in ("config.json", "protocol.md") or _sha(batch / name) != digest:
            raise ValueError("Frozen evaluation input changed")
    if check_implementation and plan["source_hashes"] != _implementation_hashes():
        raise ValueError("Implementation changed; use the frozen version to resume unstarted slots")
    if check_implementation and plan["runtime"] != _runtime():
        raise ValueError("Runtime changed; use the frozen runtime to resume unstarted slots")
    if require_upstream() != plan["upstream"]:
        raise ValueError("Pinned native checkout changed")
    return plan


def execute_trial(batch: Path, trial_id: str) -> int:
    """Worker: one primary episode plus an optional independent deferred auditor."""
    from agentdojo_lab.counterfactual_audit import GroqCounterfactualJudge, audit_run
    from agentdojo_lab.evaluation_runner import EvaluationTrial, run_evaluation_trial
    from agentdojo_lab.pacing import RequestPacer
    from agentdojo_lab.runner import RunExecutionError

    plan = read_evaluation_plan(batch)
    matches = [item for item in plan["schedule"] if item["trial_id"] == trial_id]
    if len(matches) != 1:
        raise ValueError("Unknown trial ID")
    spec = EvaluationTrial.model_validate(matches[0])
    job = batch / "jobs" / trial_id
    if (
        not (job / "started.json").is_file()
        or (job / "worker-result.json").exists()
        or (job / "result.json").exists()
    ):
        raise ValueError("Worker requires a fresh started slot")
    _write_new(job / "worker-started.json", {"trial_id": trial_id, "claimed_at": _now()})
    run_dir = batch / "runs" / trial_id
    config = RunConfig.model_validate(plan["config"]["run"])
    primary_error = None
    try:
        summary = run_evaluation_trial(config, spec, output=run_dir, pacing_state=batch / "pacing.json")
    except RunExecutionError as exc:
        primary_error = type(exc).__name__
        summary = json.loads((run_dir / "summary.json").read_text())
    auditor = {"status": "unavailable", "reason": "incomplete_source_artifacts"}
    if (
        summary.get("online_provenance", {}).get("complete") is True
        and (run_dir / "lineage-state.json").is_file()
    ):
        try:
            auditor = audit_run(
                run_dir,
                batch / "audits" / trial_id,
                judge=GroqCounterfactualJudge(pacer=RequestPacer(7000, batch / "pacing.json")),
                max_probes=plan["config"]["auditor_max_probes"],
            )
        except Exception as exc:
            auditor = {"status": "error", "error_type": type(exc).__name__}
    result = {
        "trial_id": trial_id,
        "primary_status": summary.get("status"),
        "primary_error": primary_error,
        "evaluation": summary.get("evaluation"),
        "primary_usage": summary.get("usage"),
        "auditor": auditor,
        "finished_at": _now(),
    }
    _write_new(job / "worker-result.json", result)
    print(
        json.dumps(
            {
                "trial_id": trial_id,
                "primary_status": summary.get("status"),
                "evaluation": summary.get("evaluation"),
            },
            ensure_ascii=False,
        )
    )
    return 0 if summary.get("evaluation", {}).get("evaluation_completed") is True else 2


def execute_evaluation_batch(batch: Path) -> dict:
    return execute_frozen_batch(
        batch, read_plan=read_evaluation_plan, worker_module="agentdojo_lab.evaluation_batch"
    )


def execute_frozen_batch(batch: Path, *, read_plan, worker_module: str) -> dict:
    """Shared serial supervisor; claims and timeouts apply to each frozen protocol."""
    batch = Path(batch).expanduser().resolve()
    with (batch / ".lock").open("a") as lock:
        try:
            acquire_exclusive_nonblocking(lock)
        except BlockingIOError as exc:
            raise ValueError("Evaluation batch is already running") from exc
        plan = read_plan(batch)
        with (batch / "execution.jsonl").open("a", encoding="utf-8") as journal:

            def emit(kind, **values):
                row = {"schema_version": 1, "event_type": kind, "time_utc": _now(), **values}
                journal.write(json.dumps(row, ensure_ascii=False) + "\n")
                journal.flush()
                print(json.dumps(row, ensure_ascii=False), flush=True)

            for item in plan["schedule"]:
                read_plan(batch)
                trial_id = item["trial_id"]
                job = batch / "jobs" / trial_id
                if job.exists():
                    # Even a partially written start marker consumes the planned slot.
                    continue
                job.mkdir()
                command = [
                    sys.executable,
                    "-m",
                    worker_module,
                    "trial",
                    "--batch",
                    str(batch),
                    "--trial",
                    trial_id,
                ]
                _write_new(
                    job / "started.json", {"trial_id": trial_id, "started_at": _now(), "command": command}
                )
                emit(
                    "trial_started", trial_id=trial_id, condition=item["condition"], repeat=item["repeat"],
                    **({"input_condition": item["input_condition"]} if "input_condition" in item else {}),
                )
                tick = time.monotonic()
                status, returncode = "failed", None
                with (job / "console.log").open("x") as log:
                    process = None
                    try:
                        process = subprocess.Popen(
                            command,
                            cwd=ROOT,
                            stdin=subprocess.DEVNULL,
                            stdout=log,
                            stderr=subprocess.STDOUT,
                            start_new_session=True,
                            env={
                                **os.environ,
                                "HF_HUB_OFFLINE": "1",
                                "PYTHONDONTWRITEBYTECODE": "1",
                                "TOKENIZERS_PARALLELISM": "false",
                            },
                        )
                        _write_new(job / "process.json", {"pid": process.pid, "started_at": _now()})
                        returncode = process.wait(timeout=plan["config"]["task_timeout_seconds"])
                        status = "completed" if returncode == 0 else "failed"
                    except subprocess.TimeoutExpired:
                        emit(
                            "trial_timeout",
                            trial_id=trial_id,
                            timeout_seconds=plan["config"]["task_timeout_seconds"],
                        )
                        returncode = _stop_process(process)
                        status = "timeout"
                    except BaseException:
                        if process is not None and process.poll() is None:
                            returncode = _stop_process(process)
                        _write_new(
                            job / "result.json",
                            {
                                "status": "interrupted",
                                "exit_code": returncode,
                                "elapsed_seconds": time.monotonic() - tick,
                                "finished_at": _now(),
                            },
                        )
                        raise
                result = {
                    "status": status,
                    "exit_code": returncode,
                    "elapsed_seconds": time.monotonic() - tick,
                    "finished_at": _now(),
                }
                _write_new(job / "result.json", result)
                emit("trial_finished", trial_id=trial_id, **result)
    results = [json.loads(path.read_text()) for path in (batch / "jobs").glob("*/result.json")]
    return {
        "batch_dir": str(batch),
        "planned": len(plan["schedule"]),
        "finished": len(results),
        "completed": sum(row["status"] == "completed" for row in results),
        "failed_or_interrupted": sum(row["status"] != "completed" for row in results),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    trial = sub.add_parser("trial")
    trial.add_argument("--batch", type=Path, required=True)
    trial.add_argument("--trial", required=True)
    args = parser.parse_args()
    try:
        code = execute_trial(args.batch.resolve(), args.trial)
    except Exception as exc:
        print(json.dumps({"status": "worker_error", "error_type": type(exc).__name__}), file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
