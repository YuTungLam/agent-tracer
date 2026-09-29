"""Frozen injected-only passive/Canary comparison with ten fresh primary trials."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab import evaluation_batch
from agentdojo_lab.evaluation_batch import _now, _runtime, _sha, _write_new
from agentdojo_lab.evaluation_runner import InputComparisonTrial, validate_evaluation
from agentdojo_lab.runner import ROOT, RunConfig, require_upstream

PROTOCOL = "native-injected-input-comparison-v1"
PROTOCOL_FILE = "INPUT-COMPARISON.md"


def _implementation_hashes():
    return {
        **evaluation_batch._implementation_hashes(),
        PROTOCOL_FILE: _sha(ROOT / PROTOCOL_FILE),
    }


def _expected_run() -> RunConfig:
    return RunConfig(
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
        lineage_namespace="workspace-file29-input-comparison-v1",
        canary_enabled=True,
        semantic_model=".model-cache/all-MiniLM-L6-v2-1110a243",
        semantic_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        pacing_tokens_per_minute=7000,
    )


def schedule(config: dict) -> list[dict]:
    """The exact attack and paired input order are fixed before any model request."""
    if not isinstance(config, dict) or set(config) != {
        "schema_version",
        "name",
        "case_id",
        "user_task_id",
        "injection_task_id",
        "vector_id",
        "payload",
        "repetitions",
        "request_limit",
        "task_timeout_seconds",
        "auditor_max_probes",
        "run",
    }:
        raise ValueError("Comparison requires its exact protocol configuration fields")
    for key, expected in {
        "schema_version": 1,
        "repetitions": 5,
        "request_limit": 4,
        "task_timeout_seconds": 600,
        "auditor_max_probes": 1,
    }.items():
        if type(config[key]) is not int or config[key] != expected:
            raise ValueError("Comparison requires five repeats, four requests and 600 seconds per slot")
    if config["name"] != PROTOCOL or config["case_id"] != "workspace-file29-delete13":
        raise ValueError("Comparison requires its fixed protocol and native case identity")
    if RunConfig.model_validate(config["run"]) != _expected_run():
        raise ValueError("Comparison requires its fixed model, policy, tracing and request settings")
    result = []
    for repeat in range(1, 6):
        order = ("passive", "canary") if repeat % 2 else ("canary", "passive")
        for input_condition in order:
            spec = InputComparisonTrial(
                trial_id=f"r{repeat:02d}-{input_condition}",
                case_id=config["case_id"],
                repeat=repeat,
                input_condition=input_condition,
                user_task_id=config["user_task_id"],
                injection_task_id=config["injection_task_id"],
                vector_id=config["vector_id"],
                payload=config["payload"],
                request_limit=config["request_limit"],
            )
            result.append(spec.model_dump())
    return result


def trial_config(config: dict, spec: InputComparisonTrial) -> RunConfig:
    """Only the assigned Canary flag changes between the two primary conditions."""
    return RunConfig.model_validate({**config["run"], "canary_enabled": spec.input_condition == "canary"})


def create_input_comparison_plan(output: Path, config_path: Path | None = None) -> Path:
    path = config_path or ROOT / "configs/input_comparison_v1.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    trials = schedule(config)
    upstream = require_upstream()
    run = RunConfig.model_validate(config["run"])
    suite = get_suite(run.benchmark_version, run.suite)
    for row in trials:
        spec = InputComparisonTrial.model_validate(row)
        validate_evaluation(trial_config(config, spec), spec, suite)
    destination = Path(output).expanduser().resolve()
    if destination == ROOT or destination in ROOT.parents:
        raise ValueError("The comparison requires a new dedicated output directory")
    destination.mkdir(parents=True, exist_ok=False)
    for name in ("runs", "jobs", "audits"):
        (destination / name).mkdir()
    (destination / "config.json").write_bytes(path.read_bytes())
    (destination / "protocol.md").write_bytes((ROOT / PROTOCOL_FILE).read_bytes())
    plan = {
        "schema_version": 1,
        "protocol": PROTOCOL,
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
            shlex.join(
                [
                    sys.executable,
                    "-m",
                    "agentdojo_lab.input_comparison",
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


def read_input_comparison_plan(batch: Path, *, check_implementation=True) -> dict:
    batch = Path(batch).resolve()
    if _sha(batch / "plan.json") != (batch / "plan.sha256").read_text().strip():
        raise ValueError("Frozen comparison plan changed")
    plan = json.loads((batch / "plan.json").read_text())
    if (
        type(plan.get("schema_version")) is not int
        or plan.get("schema_version") != 1
        or plan.get("protocol") != PROTOCOL
        or plan.get("schedule") != schedule(plan["config"])
        or plan.get("primary_request_ceiling") != 40
        or plan.get("auditor_request_ceiling") != 10
    ):
        raise ValueError("Frozen comparison identity or order changed")
    expected_files = {name: _sha(batch / name) for name in ("config.json", "protocol.md")}
    if (
        plan.get("frozen_files") != expected_files
        or json.loads((batch / "config.json").read_text()) != plan["config"]
    ):
        raise ValueError("Frozen comparison input changed")
    if check_implementation and plan["source_hashes"] != _implementation_hashes():
        raise ValueError("Implementation changed; use the frozen version to resume unstarted slots")
    if check_implementation and plan["runtime"] != _runtime():
        raise ValueError("Runtime changed; use the frozen runtime to resume unstarted slots")
    if require_upstream() != plan["upstream"]:
        raise ValueError("Pinned native checkout changed")
    return plan


def execute_input_comparison_trial(batch: Path, trial_id: str) -> int:
    """One fresh primary recording and a separate unchanged gate-7 deferred audit."""
    from agentdojo_lab.counterfactual_audit import GroqCounterfactualJudge, audit_run
    from agentdojo_lab.evaluation_runner import run_evaluation_trial
    from agentdojo_lab.pacing import RequestPacer
    from agentdojo_lab.runner import RunExecutionError

    batch = Path(batch).resolve()
    plan = read_input_comparison_plan(batch)
    matches = [item for item in plan["schedule"] if item["trial_id"] == trial_id]
    if len(matches) != 1:
        raise ValueError("Unknown trial ID")
    spec = InputComparisonTrial.model_validate(matches[0])
    job = batch / "jobs" / trial_id
    if (
        not (job / "started.json").is_file()
        or (job / "worker-result.json").exists()
        or (job / "result.json").exists()
    ):
        raise ValueError("Worker requires a fresh started slot")
    _write_new(job / "worker-started.json", {"trial_id": trial_id, "claimed_at": _now()})
    run_dir = batch / "runs" / trial_id
    config = trial_config(plan["config"], spec)
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
        "input_condition": spec.input_condition,
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
            {key: result[key] for key in ("trial_id", "input_condition", "primary_status", "evaluation")},
            ensure_ascii=False,
        )
    )
    return 0 if summary.get("evaluation", {}).get("evaluation_completed") is True else 2


def execute_input_comparison_batch(batch: Path) -> dict:
    return evaluation_batch.execute_frozen_batch(
        batch,
        read_plan=read_input_comparison_plan,
        worker_module="agentdojo_lab.input_comparison",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    trial = sub.add_parser("trial")
    trial.add_argument("--batch", type=Path, required=True)
    trial.add_argument("--trial", required=True)
    args = parser.parse_args()
    try:
        code = execute_input_comparison_trial(args.batch.resolve(), args.trial)
    except Exception as exc:
        print(json.dumps({"status": "worker_error", "error_type": type(exc).__name__}), file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
