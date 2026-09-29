"""Prospectively frozen passive clean/injected native case, with no replaced slots."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab import evaluation_batch
from agentdojo_lab.evaluation_batch import _now, _runtime, _sha, _write_new
from agentdojo_lab.evaluation_review import _canonical, _local, _read, _strict
from agentdojo_lab.heldout_runner import (
    CASE_ID,
    INJECTION_TASK,
    PAYLOAD,
    PROTOCOL,
    USER_TASK,
    VECTOR,
    HeldoutTrial,
    expected_run,
    validate_heldout,
)
from agentdojo_lab.runner import ROOT, RunConfig, require_upstream

PROTOCOL_FILE = "HELDOUT.md"
SELECTION_SHA = "7bbf12572f84040940a9697cae10d9128c750d6a2413212d37c29ff47a0d0471"


def _implementation_hashes():
    return {
        **evaluation_batch._implementation_hashes(),
        **{name: _sha(ROOT / name) for name in (PROTOCOL_FILE, "HELDOUT-SELECTION.md")},
    }


def schedule(config: dict) -> list[dict]:
    prescribed = {
        "schema_version": 1,
        "name": PROTOCOL,
        "case_id": CASE_ID,
        "user_task_id": USER_TASK,
        "injection_task_id": INJECTION_TASK,
        "vector_id": VECTOR,
        "payload": PAYLOAD,
        "repetitions": 5,
        "request_limit": 4,
        "task_timeout_seconds": 600,
        "auditor_max_probes": 1,
        "auditor_request_ceiling": 0,
        "run": expected_run().model_dump(),
    }
    if _canonical(config) != _canonical(prescribed):
        raise ValueError("Held-out protocol requires its exact fixed case, model and resource settings")
    return [
        HeldoutTrial(trial_id=f"r{repeat:02d}-{condition}", repeat=repeat, condition=condition).model_dump()
        for repeat in range(1, 6)
        for condition in (("clean", "injected") if repeat % 2 else ("injected", "clean"))
    ]


def create_heldout_plan(output: Path, config_path: Path | None = None) -> Path:
    path = _local(config_path or ROOT / "configs/heldout_passive_v1.json")
    config = _strict(_read(path))
    trials = schedule(config)
    run = RunConfig.model_validate(config["run"])
    upstream = require_upstream()
    suite = get_suite(run.benchmark_version, run.suite)
    for trial in trials:
        validate_heldout(run, HeldoutTrial.model_validate(trial), suite)
    destination = _local(output)
    if destination == ROOT or destination in ROOT.parents:
        raise ValueError("Use a new dedicated held-out batch directory")
    selection_path = ROOT / "configs/heldout_selection_v1.json"
    selection = _strict(_read(selection_path))
    if (
        _sha(selection_path) != SELECTION_SHA
        or selection.get("selected", {}).get("user_task_id") != USER_TASK
    ):
        raise ValueError("Static case-selection audit differs from protocol")
    destination.mkdir(parents=True, exist_ok=False)
    for name in ("runs", "jobs", "audits"):
        (destination / name).mkdir()
    for source, name in (
        (path, "config.json"),
        (ROOT / PROTOCOL_FILE, "protocol.md"),
        (selection_path, "selection.json"),
    ):
        (destination / name).write_bytes(_read(source))
    plan = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "created_at": _now(),
        "batch_id": destination.name,
        "config": config,
        "schedule": trials,
        "source_hashes": _implementation_hashes(),
        "upstream": upstream,
        "runtime": _runtime(),
        "frozen_files": {
            name: _sha(destination / name) for name in ("config.json", "protocol.md", "selection.json")
        },
        "primary_request_ceiling": 40,
        "auditor_request_ceiling": 0,
        "independent_labels": "unavailable; prior assisted labels are development only",
        "accuracy_metrics": None,
        "held_out_unit": "native legitimate operation/case family; source object, carrier, model, tools and attack goal may recur",
        "task_prompt": suite.user_tasks[USER_TASK].PROMPT,
        "native_attack_goal": suite.injection_tasks[INJECTION_TASK].GOAL,
        "commands": [
            shlex.join(
                [
                    sys.executable,
                    "-m",
                    "agentdojo_lab.heldout",
                    "trial",
                    "--batch",
                    str(destination),
                    "--trial",
                    item["trial_id"],
                ]
            )
            for item in trials
        ],
    }
    _write_new(destination / "plan.json", plan)
    (destination / "plan.sha256").write_text(_sha(destination / "plan.json") + "\n")
    return destination


def read_heldout_plan(batch: Path, *, check_implementation=True) -> dict:
    batch = _local(batch)
    if _sha(batch / "plan.json") != (batch / "plan.sha256").read_text().strip():
        raise ValueError("Frozen held-out plan changed")
    plan = _strict(_read(batch / "plan.json"))
    if (
        type(plan.get("schema_version")) is not int
        or plan["schema_version"] != 1
        or plan.get("protocol") != PROTOCOL
        or _canonical(plan.get("schedule")) != _canonical(schedule(plan["config"]))
        or type(plan.get("primary_request_ceiling")) is not int
        or plan["primary_request_ceiling"] != 40
        or type(plan.get("auditor_request_ceiling")) is not int
        or plan["auditor_request_ceiling"] != 0
    ):
        raise ValueError("Frozen held-out protocol, order or request limits changed")
    expected_files = {name: _sha(batch / name) for name in ("config.json", "protocol.md", "selection.json")}
    if plan.get("frozen_files") != expected_files or _canonical(
        _strict(_read(batch / "config.json"))
    ) != _canonical(plan["config"]):
        raise ValueError("Frozen held-out input changed")
    if (
        _sha(batch / "selection.json") != SELECTION_SHA
        or _strict(_read(batch / "selection.json")).get("selected", {}).get("user_task_id") != USER_TASK
    ):
        raise ValueError("Frozen held-out case-selection binding changed")
    if check_implementation and plan["source_hashes"] != _implementation_hashes():
        raise ValueError("Implementation changed; only original frozen code can resume never-started slots")
    if check_implementation and plan["runtime"] != _runtime():
        raise ValueError("Runtime changed; use the frozen runtime")
    if require_upstream() != plan["upstream"]:
        raise ValueError("Pinned native checkout changed")
    return plan


def execute_heldout_trial(batch: Path, trial_id: str) -> int:
    from agentdojo_lab.counterfactual_audit import audit_run
    from agentdojo_lab.evaluation_runner import run_evaluation_trial
    from agentdojo_lab.runner import RunExecutionError

    batch = _local(batch)
    plan = read_heldout_plan(batch)
    matches = [item for item in plan["schedule"] if item["trial_id"] == trial_id]
    if len(matches) != 1:
        raise ValueError("Unknown held-out trial")
    spec = HeldoutTrial.model_validate(matches[0])
    job = batch / "jobs" / trial_id
    if not (job / "started.json").is_file() or any(
        (job / name).exists() for name in ("worker-result.json", "result.json")
    ):
        raise ValueError("Worker requires a fresh started slot")
    _write_new(job / "worker-started.json", {"trial_id": trial_id, "claimed_at": _now()})
    run_dir = batch / "runs" / trial_id
    config = RunConfig.model_validate(plan["config"]["run"])
    primary_error = None
    try:
        summary = run_evaluation_trial(config, spec, output=run_dir, pacing_state=batch / "pacing.json")
    except RunExecutionError as error:
        primary_error = type(error).__name__
        summary = _strict(_read(run_dir / "summary.json"))
    auditor = {"status": "unavailable", "request_count": 0, "reason": "incomplete_source_artifacts"}
    if (
        summary.get("online_provenance", {}).get("complete") is True
        and (run_dir / "lineage-state.json").is_file()
    ):
        try:
            # Passive Tier 1 is disabled. This writes an eligibility report only.
            # No auditor/client is constructed, even if later validation fails.
            audit = audit_run(run_dir, batch / "audits" / trial_id, judge=None, max_probes=1)
            if audit.get("counts", {}).get("request", 0) != 0:
                raise ValueError("Passive held-out protocol permits no auditor requests")
            auditor = {**audit, "request_count": 0}
        except Exception as error:
            auditor = {"status": "error", "request_count": 0, "error_type": type(error).__name__}
    result = {
        "trial_id": trial_id,
        "input_condition": "passive",
        "primary_status": summary.get("status"),
        "primary_error": primary_error,
        "evaluation": summary.get("evaluation"),
        "primary_usage": summary.get("usage"),
        "auditor": auditor,
        "finished_at": _now(),
    }
    _write_new(job / "worker-result.json", result)
    print(json.dumps({key: result[key] for key in ("trial_id", "primary_status", "evaluation")}))
    return 0 if summary.get("evaluation", {}).get("evaluation_completed") is True else 2


def execute_heldout_batch(batch: Path) -> dict:
    return evaluation_batch.execute_frozen_batch(
        batch, read_plan=read_heldout_plan, worker_module="agentdojo_lab.heldout"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    trial = sub.add_parser("trial")
    trial.add_argument("--batch", type=Path, required=True)
    trial.add_argument("--trial", required=True)
    args = parser.parse_args()
    try:
        code = execute_heldout_trial(args.batch, args.trial)
    except Exception as error:
        print(json.dumps({"status": "worker_error", "error_type": type(error).__name__}), file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
