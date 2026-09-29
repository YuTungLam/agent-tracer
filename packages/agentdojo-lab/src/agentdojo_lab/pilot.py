"""Frozen, sequential clean-task pilot batches with one process and run per trial."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from agentdojo.task_suite.load_suites import get_suite
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentdojo_lab.file_lock import acquire_exclusive_nonblocking, release
from agentdojo_lab.runner import ROOT, RunConfig, configured_key, require_upstream


class PilotSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = "clean-pilot-v1"
    repetitions: int = Field(default=3, ge=1, le=3)
    task_timeout_seconds: int = Field(default=300, ge=10, le=1800)
    interval_seconds: float = Field(default=15, ge=0, le=300)


class TaskSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^user_task_[0-9]+$")
    label: str
    area: str
    expected_tools: list[str] = Field(min_length=1)
    rationale: str


class PilotConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pilot: PilotSettings
    run: RunConfig
    tasks: list[TaskSpec] = Field(min_length=1)

    @field_validator("tasks")
    @classmethod
    def unique(cls, tasks):
        if len({task.id for task in tasks}) != len(tasks):
            raise ValueError("Pilot task IDs must be unique")
        return tasks


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: Path, data: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def source_hashes() -> dict:
    paths = [ROOT / "uv.lock", *sorted((ROOT / "src/agentdojo_lab").rglob("*.py"))]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def create_plan(config_path: Path, output: Path | None = None) -> Path:
    config = PilotConfig.model_validate(tomllib.loads(config_path.read_text()))
    ids = [task.id for task in config.tasks]
    if ids != config.run.user_tasks or not config.run.record_events:
        raise ValueError("Pilot requires matching ordered task lists and record_events=true")
    upstream = require_upstream()
    suite = get_suite(config.run.benchmark_version, config.run.suite)
    tool_names = {tool.name for tool in suite.tools}
    for task in config.tasks:
        if task.id not in suite.user_tasks or any(tool not in tool_names for tool in task.expected_tools):
            raise ValueError(f"Unknown native task or expected tool: {task.id}")
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = ROOT / "runs" / f"{stamp}-clean-pilot-{uuid4().hex[:8]}"
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "runs").mkdir()
    (output / "jobs").mkdir()
    (output / "pilot-config.toml").write_bytes(config_path.read_bytes())
    (output / "protocol.md").write_bytes((ROOT / "protocol.md").read_bytes())
    # RunConfig is flat; JSON scalars/lists are valid TOML values here.
    frozen_config = "\n".join(
        f"{key} = {json.dumps(value, ensure_ascii=False)}"
        for key, value in config.run.model_dump().items()
        if value is not None
    )
    (output / "run-config.toml").write_text(frozen_config + "\n", encoding="utf-8")
    tasks = [{**task.model_dump(), "prompt": suite.user_tasks[task.id].PROMPT} for task in config.tasks]
    plan = {
        "schema_version": 1,
        "batch_id": output.name,
        "created_at": utc_now(),
        "settings": config.pilot.model_dump(),
        "run_config": config.run.model_dump(),
        "upstream": upstream,
        "source_hashes": source_hashes(),
        "frozen_file_hashes": {
            name: digest(output / name) for name in ("pilot-config.toml", "run-config.toml", "protocol.md")
        },
        "tasks": tasks,
        "schedule": [
            {"id": f"r{repeat:02d}-{task.id}", "task_id": task.id, "repeat": repeat}
            for repeat in range(1, config.pilot.repetitions + 1)
            for task in config.tasks
        ],
    }
    atomic_json(output / "plan.json", plan)
    (output / "plan.sha256").write_text(digest(output / "plan.json") + "\n")
    return output


def read_plan(batch: Path) -> dict:
    if digest(batch / "plan.json") != (batch / "plan.sha256").read_text().strip():
        raise ValueError("Frozen pilot plan changed")
    plan = json.loads((batch / "plan.json").read_text())
    config = PilotConfig.model_validate(
        {
            "pilot": plan["settings"],
            "run": plan["run_config"],
            "tasks": [{k: v for k, v in task.items() if k != "prompt"} for task in plan["tasks"]],
        }
    )
    expected = [
        {"id": f"r{repeat:02d}-{task.id}", "task_id": task.id, "repeat": repeat}
        for repeat in range(1, config.pilot.repetitions + 1)
        for task in config.tasks
    ]
    if plan.get("schema_version") != 1 or plan["schedule"] != expected:
        raise ValueError("Invalid pilot schedule")
    for name in ("pilot-config.toml", "run-config.toml", "protocol.md"):
        if digest(batch / name) != plan["frozen_file_hashes"][name]:
            raise ValueError(f"Frozen pilot file changed: {name}")
    return plan


@contextmanager
def batch_lock(batch: Path):
    with (batch / ".batch.lock").open("a") as stream:
        try:
            acquire_exclusive_nonblocking(stream)
        except BlockingIOError as exc:
            raise ValueError("This pilot batch is already running") from exc
        try:
            yield
        finally:
            release(stream)


def execute_trial(command: list[str], job_dir: Path, timeout: int, progress: Callable) -> dict:
    """Persist process identity; a killed/interrupted trial is never retried."""
    started = time.monotonic()
    with (job_dir / "console.log").open("x") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        outcome = "finished"
        previous_handler = signal.getsignal(signal.SIGTERM)

        def interrupted(signum, frame):
            raise KeyboardInterrupt

        try:
            signal.signal(signal.SIGTERM, interrupted)
            atomic_json(job_dir / "process.json", {"pid": process.pid, "started_at": utc_now()})
            try:
                code = process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                outcome = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted"
                progress({"trial": job_dir.name, "status": outcome, "action": "stopping child process"})
                stop_child(process)
                code = process.returncode
                if outcome == "interrupted":
                    atomic_json(
                        job_dir / "execution.json",
                        {
                            "status": outcome,
                            "exit_code": code,
                            "ended_at": utc_now(),
                            "wall_seconds": time.monotonic() - started,
                        },
                    )
                    raise
        finally:
            stop_child(process)
            signal.signal(signal.SIGTERM, previous_handler)
    return {
        "status": outcome,
        "exit_code": code,
        "ended_at": utc_now(),
        "wall_seconds": time.monotonic() - started,
    }


def stop_child(process) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def reject_active_children(batch: Path) -> None:
    for job in (batch / "jobs").iterdir():
        path = job / "process.json"
        if (job / "execution.json").is_file() or not path.is_file():
            continue
        pid = json.loads(path.read_text()).get("pid")
        if type(pid) is not int or pid <= 0:
            raise ValueError(f"Cannot determine previous process state for {job.name}")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            pass
        raise ValueError(f"Previous trial process may still be active: {job.name}; wait before resuming")


def run_pilot(
    *,
    config_path: Path | None = None,
    output: Path | None = None,
    resume: Path | None = None,
    through_repeat: int = 1,
    plan_only: bool = False,
    progress: Callable | None = None,
) -> dict:
    from agentdojo_lab.pilot_report import export_pilot_report

    if resume is not None and (config_path is not None or output is not None):
        raise ValueError("Resume uses its frozen plan; do not supply a config or output")
    if not 1 <= through_repeat <= 3:
        raise ValueError("through_repeat must be between 1 and 3")
    if not plan_only and not configured_key():
        raise ValueError("Set GROQ_API_KEY locally before running a pilot")
    batch = (
        resume.expanduser().resolve()
        if resume
        else create_plan(config_path or ROOT / "configs/pilot_clean.toml", output)
    )
    notify = progress or (lambda data: print(json.dumps(data, ensure_ascii=False), flush=True))
    with batch_lock(batch):
        plan = read_plan(batch)
        if through_repeat > plan["settings"]["repetitions"]:
            raise ValueError("Requested repetition exceeds the frozen plan")
        if not plan_only:
            reject_active_children(batch)
            if source_hashes() != plan["source_hashes"]:
                raise ValueError(
                    "Code or dependency lock changed; use a new batch to preserve reproducibility"
                )
            if require_upstream()["actual_commit"] != plan["upstream"]["actual_commit"]:
                raise ValueError("Upstream changed since this batch was frozen")
        atomic_json(
            batch / "state.json",
            {
                "status": "planned" if plan_only else "running",
                "through_repeat": through_repeat,
                "updated_at": utc_now(),
            },
        )
        try:
            if not plan_only:
                for entry in plan["schedule"]:
                    if entry["repeat"] > through_repeat:
                        continue
                    job_dir = batch / "jobs" / entry["id"]
                    # Reserving a trial consumes its slot, even if it crashes before
                    # summary creation. Resuming only executes never-started slots.
                    if job_dir.exists():
                        continue
                    job_dir.mkdir()
                    command = [
                        sys.executable,
                        "-m",
                        "agentdojo_lab",
                        "run",
                        "--config",
                        str(batch / "run-config.toml"),
                        "--task",
                        entry["task_id"],
                        "--output",
                        str(batch / "runs" / entry["id"]),
                    ]
                    if plan["run_config"].get("pacing_tokens_per_minute"):
                        command.extend(["--pacing-state", str(batch / "pacing-state.json")])
                    atomic_json(
                        job_dir / "started.json", {**entry, "started_at": utc_now(), "command": command}
                    )
                    notify({"batch": batch.name, "trial": entry["id"], "status": "started"})
                    try:
                        result = execute_trial(
                            command, job_dir, plan["settings"]["task_timeout_seconds"], notify
                        )
                    except Exception as exc:
                        result = {
                            "status": "launch_error",
                            "error_type": type(exc).__name__,
                            "ended_at": utc_now(),
                        }
                    atomic_json(job_dir / "execution.json", result)
                    report = export_pilot_report(batch)
                    row = next(row for row in report["rows"] if row["trial_id"] == entry["id"])
                    notify(
                        {
                            "trial": entry["id"],
                            "status": row["status"],
                            "utility": row["utility"],
                            "recording_complete": row["recording_complete"],
                            "model_requests": row["model_requests"],
                        }
                    )
                    # Distinct planned trials remain in the schedule after errors.
                    # No retries of an SDK request or a completed trial are added.
                    if set(row["http_error_codes"]) & {401, 403, 429}:
                        atomic_json(
                            batch / "service-pause.json",
                            {
                                "trial": entry["id"],
                                "http_error_codes": row["http_error_codes"],
                                "time": utc_now(),
                                "reason": "Provider access or quota requires attention; no retry added",
                            },
                        )
                        notify({"status": "paused_service_error", "trial": entry["id"]})
                        break
                    time.sleep(plan["settings"]["interval_seconds"])
        finally:
            atomic_json(
                batch / "state.json",
                {"status": "idle", "through_repeat": through_repeat, "updated_at": utc_now()},
            )
            report = export_pilot_report(batch)
    return {"batch_dir": str(batch), "html_report": str(batch / "index.html"), **report["totals"]}
