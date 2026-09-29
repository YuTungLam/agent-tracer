"""Offline tests for the immutable Scout content-argument batch boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import content_composition_argument_batch as batch
import pytest

from agentdojo_lab.scout_content_composition_argument import (
    TerminationRequested,
    run_content_composition_argument,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/scout_content_composition_argument_v1.json"


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def build_bundle(tmp_path: Path) -> tuple[Path, Path]:
    bundle = tmp_path / "bundle"
    for relative in batch.required_bundle_files(ROOT):
        source = ROOT / relative
        target = bundle / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    config = json.loads(CONFIG.read_text())
    directories = {Path(candidate["source_run"]) for candidate in config["candidates"]}
    for relative in directories:
        shutil.copytree(ROOT / relative, bundle / relative, dirs_exist_ok=True)
    entries = batch.snapshot(bundle)
    manifest = bundle / "submission-sha256.txt"
    manifest.write_text("".join(f"{value}  {key}\n" for key, value in entries.items()), encoding="utf-8")
    return bundle, manifest


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        ("src/agentdojo_lab/runner.py", "native-smoke dependency closure"),
        (
            "vendor/agentdojo/src/agentdojo/data/suites/workspace/environment.yaml",
            "pinned AgentDojo runtime source tree",
        ),
    ],
)
def test_job_9135588_bundle_rejects_incomplete_native_smoke_closure(
    tmp_path, relative, message
):
    bundle, manifest = build_bundle(tmp_path)
    (bundle / relative).unlink()
    entries = batch.snapshot(bundle)
    entries.pop("submission-sha256.txt")
    manifest.write_text(
        "".join(f"{value}  {key}\n" for key, value in entries.items()), encoding="utf-8"
    )

    with pytest.raises(ValueError, match=message):
        batch.validate_bundle(bundle, manifest, batch.digest(manifest))


def run_copied_plan(bundle: Path, output: Path) -> None:
    environment = dict(os.environ)
    environment.pop("LOCAL_LLM_API_KEY", None)
    environment["PYTHONPATH"] = str(bundle / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(
        [
            sys.executable,
            str(bundle / "scripts/run_scout_content_composition_argument.py"),
            "--config",
            str(bundle / "configs/scout_content_composition_argument_v1.json"),
            "--output",
            str(output),
        ],
        cwd=bundle,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def test_bundle_plan_and_post_smoke_mutation_gate(tmp_path):
    bundle, manifest = build_bundle(tmp_path)
    plan_dir = tmp_path / "plan"
    run_copied_plan(bundle, plan_dir)
    site = tmp_path / "site.env"
    site.write_text("PRIVATE_SITE_FIXTURE=1\n")
    smoke, live = tmp_path / "smoke", tmp_path / "live"
    pre_path = Path(str(smoke) + batch.PROTOCOL_SIDECAR_SUFFIXES["pre_smoke"])
    stdout, stderr = tmp_path / "job.out", tmp_path / "job.err"

    def scheduler_io(job_id, expected_stdout, expected_stderr):
        return {
            "source": "scontrol_show_job_-o",
            "reported_job_id": job_id,
            "stdout": str(expected_stdout),
            "stderr": str(expected_stderr),
            "submission_requirement": "explicit_sbatch_--output_and_--error",
        }

    pre = batch.validate_before_smoke(
        pre_path,
        bundle=bundle,
        manifest=manifest,
        manifest_sha256=batch.digest(manifest),
        site=site,
        site_sha256=batch.digest(site),
        executed_wrapper=bundle / "hpc/scout-smoke-content-composition-argument.sbatch",
        plan_dir=plan_dir,
        smoke_dir=smoke,
        live_dir=live,
        runner=bundle / "scripts/run_scout_content_composition_argument.py",
        config=bundle / "configs/scout_content_composition_argument_v1.json",
        job_id="123",
        expected_stdout=stdout,
        expected_stderr=stderr,
        scheduler_io_probe=scheduler_io,
    )
    assert pre["status"] == "prepared_inputs_validated_before_smoke"
    assert pre["limits"]["total_generation_requests"] == 50
    assert pre["scheduler_io"]["stdout"] == str(stdout)

    config_path = bundle / "configs/scout_content_composition_argument_v1.json"
    config_path.write_bytes(config_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="bundle"):
        batch.reserve_phase(
            tmp_path / "phase.json",
            pre_smoke=pre_path,
            bundle=bundle,
            manifest=manifest,
            manifest_sha256=batch.digest(manifest),
            job_id="123",
            reported_job_id="123",
            remaining="02:20:00",
            time_limit="03:30:00",
            server_pid=1234,
        )


@pytest.mark.parametrize("nested_destination", ["smoke", "live", "stdout", "pre_smoke"])
def test_pre_smoke_rejects_any_output_nested_under_immutable_bundle(tmp_path, nested_destination):
    bundle, manifest = build_bundle(tmp_path)
    plan_dir = tmp_path / "plan"
    run_copied_plan(bundle, plan_dir)
    site = tmp_path / "site.env"
    site.write_text("PRIVATE_SITE_FIXTURE=1\n")
    smoke, live = tmp_path / "smoke", tmp_path / "live"
    stdout, stderr = tmp_path / "job.out", tmp_path / "job.err"
    if nested_destination == "smoke":
        smoke = bundle / "new-smoke"
    elif nested_destination == "live":
        live = bundle / "new-live"
    elif nested_destination == "stdout":
        stdout = bundle / "new-job.out"
    pre_path = Path(str(smoke) + batch.PROTOCOL_SIDECAR_SUFFIXES["pre_smoke"])
    if nested_destination == "pre_smoke":
        pre_path = bundle / "new-pre-smoke.json"

    def scheduler_io(job_id, expected_stdout, expected_stderr):
        return {
            "source": "scontrol_show_job_-o",
            "reported_job_id": job_id,
            "stdout": str(expected_stdout),
            "stderr": str(expected_stderr),
            "submission_requirement": "explicit_sbatch_--output_and_--error",
        }

    with pytest.raises(ValueError, match="overlap|sidecar"):
        batch.validate_before_smoke(
            pre_path,
            bundle=bundle,
            manifest=manifest,
            manifest_sha256=batch.digest(manifest),
            site=site,
            site_sha256=batch.digest(site),
            executed_wrapper=bundle / "hpc/scout-smoke-content-composition-argument.sbatch",
            plan_dir=plan_dir,
            smoke_dir=smoke,
            live_dir=live,
            runner=bundle / "scripts/run_scout_content_composition_argument.py",
            config=bundle / "configs/scout_content_composition_argument_v1.json",
            job_id="123",
            expected_stdout=stdout,
            expected_stderr=stderr,
            scheduler_io_probe=scheduler_io,
        )


@pytest.mark.parametrize(
    ("remaining", "time_limit", "expected"),
    [
        ("02:20:00", "03:30:00", "reserved_before_repeat_judge_calls"),
        ("02:19:59", "03:30:00", "unstarted_insufficient_remaining_time"),
        ("02:20:00", "03:30:01", "unstarted_walltime_limit_exceeded"),
    ],
)
def test_fixed_scheduler_gate(remaining, time_limit, expected):
    result = batch.scheduler_decision("42", "42", remaining, time_limit)
    assert result["status"] == expected


def test_authoritative_scheduler_output_paths_must_match_explicit_submission(tmp_path):
    stdout, stderr = tmp_path / "job.out", tmp_path / "job.err"

    class Result:
        returncode = 0

        def __init__(self, line):
            self.stdout = line

    def run(command, **kwargs):
        assert command == ["scontrol", "show", "job", "-o", "42"]
        assert kwargs["check"] is False
        return Result(f"JobId=42 JobState=RUNNING StdOut={stdout} StdErr={stderr}\n")

    value = batch.scheduler_output_identity("42", stdout, stderr, run=run)

    assert value["stdout"] == str(stdout)
    assert value["stderr"] == str(stderr)
    assert value["submission_requirement"] == "explicit_sbatch_--output_and_--error"
    with pytest.raises(ValueError, match="differ"):
        batch.scheduler_output_identity("42", stdout, tmp_path / "other.err", run=run)


def test_loopback_same_allocation_server_check(tmp_path, monkeypatch):
    monkeypatch.setenv("SLURM_JOB_ID", "42")
    monkeypatch.setenv("SCOUT_SERVER_PID", "1234")

    def identity(pid):
        return {
            "pid": pid,
            "start_ticks": pid,
            "boot_id": "boot",
            "hostname": "node",
            "uid": 1,
            "cmdline_sha256": str(pid),
            "cgroup_sha256": "scope",
        }

    output = tmp_path / "server.json"
    result = batch.server_check(
        output,
        base_url=batch.ENDPOINT,
        key="secret",
        server_pid=1234,
        job_id="42",
        identity_probe=identity,
        scheduler_probe=lambda job: {"reported_job_id": job, "state": "RUNNING"},
        auth_probe=lambda url, key: {
            "endpoint": url + "/models",
            "generation_requests_started": 0,
            "checks": {"correct_key": {"expected_model_present": bool(key)}},
        },
    )
    assert result["status"] == "passed"
    assert result["endpoint"] == "http://127.0.0.1:8000/v1"
    with pytest.raises(ValueError):
        batch.local_url("https://127.0.0.1:8000/v1")


class Response:
    def __init__(self, value):
        self.value = value

    def model_dump(self, mode="json"):
        assert mode == "json"
        return copy.deepcopy(self.value)


class Completions:
    def __init__(self, role, terminate=False, invalid=False):
        self.role = role
        self.terminate = terminate
        self.invalid = invalid

    def create(self, **body):
        body.pop("timeout")
        if self.terminate:
            self.terminate = False
            raise TerminationRequested("fixture")
        if self.role == "judge":
            if self.invalid:
                self.invalid = False
                content = "invalid judgment"
            else:
                content = json.dumps({"would_preserve_content": False, "confidence": 0.8, "reasoning": "No."})
            message = {
                "role": "assistant",
                "content": content,
            }
            finish = "stop"
        elif any(marker in json.dumps(body["messages"]) for marker in ("NEUTRAL-SRC-A---", "NEUTR-B-")):
            message, finish = {"role": "assistant", "content": "No call."}, "stop"
        else:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "create_file",
                            "arguments": json.dumps(
                                {
                                    "content": "NTFLOW-7e92f5a1-64bd39c8",
                                    "filename": "expense-reconciliation.txt",
                                }
                            ),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        return Response(
            {
                "model": batch.MODEL,
                "choices": [{"finish_reason": finish, "message": message}],
                "usage": {"total_tokens": 1},
            }
        )


class Client:
    max_retries = 0
    api_key = "fixture"

    def __init__(self, role, terminate=False, invalid=False):
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(role, terminate=terminate, invalid=invalid)


def binding(mode: str) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "launcher": "/bundle/scripts/run_scout_content_composition_argument.py",
        "launcher_sha256": "a" * 64,
        "config": "/bundle/configs/scout_content_composition_argument_v1.json",
        "config_sha256": "b" * 64,
        "python_executable": "/venv/bin/python",
        "python_version": "3.12.0",
        "working_directory": "/bundle",
        "local_key_variable": "LOCAL_LLM_API_KEY",
        "local_key_status": "configured" if mode == "live" else "missing",
        "credential_value_recorded": False,
        "sigterm_policy": "finalize_started_slot_as_unknown_and_leave_remaining_slots_unstarted",
    }


def regenerate_manifest(folder: Path) -> None:
    values = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(folder.iterdir())
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    write_json(folder / "artifact-manifest.json", values)


def make_runs(tmp_path: Path, *, interrupted=False, invalid_judge=False) -> tuple[Path, Path]:
    plan_only, live = tmp_path / "plan-only", tmp_path / "live"
    run_content_composition_argument(plan_only, config_path=CONFIG, wrapper_binding=binding("plan_only"))
    run_content_composition_argument(
        live,
        config_path=CONFIG,
        replay_client=Client("replay", terminate=interrupted),
        judge_client=Client("judge", invalid=invalid_judge),
        wrapper_binding=binding("live"),
    )
    summary_path = live / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["mode"] = "live_openai_compatible"
    summary["analysis"]["diagnostic_checks"]["transport_direct_literal_loopback"] = True
    summary["scientific_complete"] = not interrupted and not invalid_judge
    if not interrupted and not invalid_judge:
        summary["analysis"]["panel_pattern_status"] = "stable_judge_replay_agreement_observed"
    write_json(summary_path, summary)
    regenerate_manifest(live)
    return plan_only, live


def terminal_inputs(tmp_path: Path, plan_only: Path, live: Path, exit_code: int) -> dict:
    bundle, manifest = build_bundle(tmp_path / "terminal-binding")
    pre = tmp_path / "pre.json"
    scheduler_io = {
        "source": "scontrol_show_job_-o",
        "reported_job_id": "42",
        "stdout": str(tmp_path / "job.out"),
        "stderr": str(tmp_path / "job.err"),
        "submission_requirement": "explicit_sbatch_--output_and_--error",
    }
    write_json(pre, {"protocol": batch.PROTOCOL, "scheduler_io": scheduler_io})
    phase = tmp_path / "phase.json"
    write_json(
        phase,
        {
            "protocol": batch.PROTOCOL,
            "status": "reserved_before_repeat_judge_calls",
            "slurm_job_id": "42",
            "server_pid": 1234,
            "pre_smoke": batch.receipt(pre),
            "bundle": batch.validate_bundle(bundle, manifest, batch.digest(manifest)),
            "runtime": batch.runtime_identity(bundle),
            "scheduler_io": scheduler_io,
            "plan_only": {"folder": str(plan_only), "tree": batch.snapshot(plan_only)},
            "limits": batch.fixed_limits(),
        },
    )
    smoke = tmp_path / "smoke.json"
    native = tmp_path / "native.json"
    server = tmp_path / "server.json"
    cleanup = tmp_path / "cleanup.json"
    exit_path = tmp_path / "exit.txt"
    write_json(smoke, {"protocol": batch.SMOKE_PROTOCOL, "status": "passed", "requests_started": 4})
    write_json(
        native,
        {
            "protocol": batch.NATIVE_PROTOCOL,
            "status": "passed",
            "native_requests_started": 4,
            "checks": {"no_online_auditors": True},
        },
    )
    write_json(
        server,
        {
            "protocol": batch.PROTOCOL,
            "status": "passed",
            "endpoint": batch.ENDPOINT,
            "server_pid": 1234,
            "slurm_job_id": "42",
            "model": batch.MODEL,
            "created_unix_ns": 1,
            "process_identity": {
                "pid": 1234,
                "start_ticks": 55,
                "boot_id": "boot-id",
                "hostname": "node01",
                "uid": 1000,
                "cmdline_sha256": "a" * 64,
                "cgroup_sha256": "b" * 64,
            },
            "scheduler": {
                "reported_job_id": "42",
                "state": "RUNNING",
                "batch_host": "node01.cluster",
            },
            "models_auth": {
                "endpoint": batch.ENDPOINT + "/models",
                "generation_requests_started": 0,
                "checks": {
                    "correct_key": {"status_code": 200, "expected_model_present": True},
                    "missing_key": {"status_code": 401, "rejected": True},
                    "wrong_key": {"status_code": 403, "rejected": True},
                },
            },
        },
    )
    write_json(
        cleanup,
        {
            "protocol": batch.PROTOCOL,
            "status": "cleanup_complete",
            "slurm_job_id": "42",
            "server": {"pid": 1234, "stopped": True},
            "runner": {"pid": 5678, "stopped": True},
        },
    )
    exit_path.write_text(f"{exit_code}\n")
    return {
        "phase_path": phase,
        "pre_smoke_path": pre,
        "smoke_path": smoke,
        "native_path": native,
        "server_check_path": server,
        "cleanup_path": cleanup,
        "runner_exit_path": exit_path,
        "live_dir": live,
        "job_id": "42",
        "expected_stdout": Path(scheduler_io["stdout"]),
        "expected_stderr": Path(scheduler_io["stderr"]),
        "scheduler_io_probe": lambda job_id, stdout, stderr: scheduler_io,
    }


def test_complete_and_sigterm_terminal_semantics(tmp_path):
    complete_root, term_root = tmp_path / "complete", tmp_path / "term"
    complete_root.mkdir()
    term_root.mkdir()
    plan, live = make_runs(complete_root)
    complete = batch.finalize(
        complete_root / "final.json",
        **terminal_inputs(complete_root, plan, live, 0),
    )
    assert complete["status"] == "complete_all_repeat_judge_slots_terminal"
    assert complete["requests"] == {
        "synthetic": 4,
        "native": 4,
        "repeat": 42,
        "total": 50,
        "limit": 50,
    }
    assert complete["artifacts"]["server_check"] == batch.receipt(complete_root / "server.json")
    assert complete["item_13_status"] == "not_established_by_this_protocol_alone"
    assert complete["standalone_item_13_claim_permitted"] is False
    assert complete["scientific_outcome"]["standalone_item_13_claim_permitted"] is False
    assert complete["scientific_outcome"]["all_slots_terminal"] is True
    assert complete["scientific_outcome"]["complete"] is True
    assert complete["authoritative_scheduler_io"]["source"] == "scontrol_show_job_-o"

    plan, live = make_runs(term_root, interrupted=True)
    interrupted = batch.finalize(
        term_root / "final.json",
        **terminal_inputs(term_root, plan, live, 143),
    )
    assert interrupted["status"] == "terminal_graceful_interruption_preserved"
    assert interrupted["repeat_judge"]["result_count"] == 42
    assert interrupted["requests"]["repeat"] == 1
    assert interrupted["scientific_outcome"]["standalone_item_13_claim_permitted"] is False
    assert interrupted["scientific_outcome"]["all_slots_terminal"] is False
    assert interrupted["scientific_outcome"]["complete"] is False


def test_all_42_terminal_slots_with_one_invalid_judge_are_not_scientifically_complete(tmp_path):
    plan, live = make_runs(tmp_path, invalid_judge=True)

    terminal = batch.finalize(
        tmp_path / "unknown-final.json",
        **terminal_inputs(tmp_path, plan, live, 0),
    )

    assert terminal["status"] == "complete_all_repeat_judge_slots_terminal"
    assert terminal["requests"]["repeat"] == 42
    assert terminal["repeat_judge"]["all_slots_terminal"] is True
    assert terminal["repeat_judge"]["scientific_complete"] is False
    assert terminal["scientific_outcome"]["all_slots_terminal"] is True
    assert terminal["scientific_outcome"]["complete"] is False
    assert terminal["scientific_outcome"]["unknown_operation_slots"] == 1
    assert terminal["scientific_outcome"]["unknown_paired_comparisons"] == 1
    assert terminal["scientific_outcome"]["standalone_item_13_claim_permitted"] is False


def test_abrupt_partial_ledger_is_preserved_without_claiming_completion(tmp_path):
    plan, live = make_runs(tmp_path)
    requests = (live / "requests.jsonl").read_text().splitlines()
    results = (live / "results.jsonl").read_text().splitlines()
    (live / "requests.jsonl").write_text(requests[0] + "\n")
    (live / "results.jsonl").write_text(results[0] + "\n")
    for name in ("summary.json", "artifact-manifest.json", "comparisons.jsonl", "index.html"):
        (live / name).unlink()
    final = batch.finalize(
        tmp_path / "final.json",
        **terminal_inputs(tmp_path, plan, live, 137),
    )
    assert final["status"] == "terminal_partial_ledgers_preserved"
    assert final["scientific_outcome"]["complete"] is False
    assert final["scientific_outcome"]["all_slots_terminal"] is False
    assert final["scientific_outcome"]["unknown_operation_slots"] == 41
    assert final["scientific_outcome"]["unknown_paired_comparisons"] == 18
    assert final["requests"]["repeat"] == 1


def test_abrupt_zero_row_ledger_counts_all_42_slots_unknown(tmp_path):
    plan, live = make_runs(tmp_path)
    (live / "requests.jsonl").write_bytes(b"")
    (live / "results.jsonl").write_bytes(b"")
    for name in ("summary.json", "artifact-manifest.json", "comparisons.jsonl", "index.html"):
        (live / name).unlink()

    final = batch.finalize(
        tmp_path / "zero-row-final.json",
        **terminal_inputs(tmp_path, plan, live, 137),
    )

    assert final["status"] == "terminal_partial_ledgers_preserved"
    assert final["scientific_outcome"]["unknown_operation_slots"] == 42
    assert final["scientific_outcome"]["unknown_paired_comparisons"] == 18


def test_abrupt_partial_cannot_accept_zero_runner_exit(tmp_path):
    plan, live = make_runs(tmp_path)
    (live / "requests.jsonl").write_text((live / "requests.jsonl").read_text().splitlines()[0] + "\n")
    (live / "results.jsonl").write_text((live / "results.jsonl").read_text().splitlines()[0] + "\n")
    for name in ("summary.json", "artifact-manifest.json", "comparisons.jsonl", "index.html"):
        (live / name).unlink()

    final = batch.finalize(
        tmp_path / "zero-exit-partial-final.json",
        **terminal_inputs(tmp_path, plan, live, 0),
    )

    assert final["status"] == "incomplete"
    assert final["failure"]["stage"] == "server_and_live_ledgers"
    assert "exit code" in final["failure"]["message"]


def test_terminal_recomputes_analysis_instead_of_trusting_summary(tmp_path):
    plan, live = make_runs(tmp_path)
    summary_path = live / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["analysis"]["pooled_disagreements"] = 18
    write_json(summary_path, summary)
    regenerate_manifest(live)

    final = batch.finalize(
        tmp_path / "final.json",
        **terminal_inputs(tmp_path, plan, live, 0),
    )

    assert final["status"] == "incomplete"
    assert final["failure"]["stage"] == "server_and_live_ledgers"
    assert "analysis differs" in final["failure"]["message"]


def test_terminal_rejects_result_identity_tamper(tmp_path):
    plan, live = make_runs(tmp_path)
    rows = [json.loads(line) for line in (live / "results.jsonl").read_text().splitlines()]
    rows[0]["candidate_id"] = "r02-both"
    (live / "results.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    regenerate_manifest(live)

    final = batch.finalize(
        tmp_path / "identity-tamper-final.json",
        **terminal_inputs(tmp_path, plan, live, 0),
    )

    assert final["status"] == "incomplete"
    assert final["failure"]["stage"] == "server_and_live_ledgers"
    assert "frozen operation" in final["failure"]["message"]


def test_early_smoke_failure_still_writes_claim_bounded_authoritative_receipt(tmp_path):
    scheduler_io = {
        "source": "scontrol_show_job_-o",
        "reported_job_id": "42",
        "stdout": str(tmp_path / "job.out"),
        "stderr": str(tmp_path / "job.err"),
        "submission_requirement": "explicit_sbatch_--output_and_--error",
    }

    result = batch.finalize(
        tmp_path / "early-final.json",
        phase_path=tmp_path / "missing-phase.json",
        pre_smoke_path=tmp_path / "missing-pre.json",
        smoke_path=tmp_path / "missing-smoke.json",
        native_path=tmp_path / "missing-native.json",
        server_check_path=tmp_path / "missing-server.json",
        cleanup_path=tmp_path / "missing-cleanup.json",
        runner_exit_path=tmp_path / "missing-exit.txt",
        live_dir=tmp_path / "missing-live",
        job_id="42",
        expected_stdout=Path(scheduler_io["stdout"]),
        expected_stderr=Path(scheduler_io["stderr"]),
        scheduler_io_probe=lambda job_id, stdout, stderr: scheduler_io,
    )

    assert result["status"] == "incomplete"
    assert result["failure"]["stage"] == "inputs"
    assert result["authoritative_scheduler_io"] == scheduler_io
    assert result["item_13_status"] == "not_established_by_this_protocol_alone"
    assert result["standalone_item_13_claim_permitted"] is False
    assert result["scientific_outcome"]["complete"] is False
    assert result["scientific_outcome"]["combination_requirement"] == batch.COMBINATION_REQUIREMENT


@pytest.mark.parametrize(
    ("protocol", "repeat_limit", "total_limit", "content_argument"),
    [
        ("nesi-scout-smoke-repeat-judge-v1", 9, 17, False),
        ("nesi-scout-smoke-multi-repeat-judge-v1", 36, 44, False),
        ("nesi-scout-smoke-content-composition-argument-v1", 42, 50, True),
    ],
)
def test_shared_pre_phase_terminal_records_native_import_failure_without_missing_phase(
    tmp_path, protocol, repeat_limit, total_limit, content_argument
):
    smoke = tmp_path / "smoke.json"
    write_json(
        smoke,
        {
            "protocol": "nesi-scout-smoke-v1",
            "status": "passed",
            "requests_started": 4,
            "requests": [{"status": "passed"} for _ in range(4)],
        },
    )
    pre_smoke = tmp_path / "pre-smoke.json"
    cleanup = tmp_path / "cleanup.json"
    exit_path = tmp_path / "wrapper-exit.txt"
    write_json(pre_smoke, {"status": "prepared_inputs_validated_before_smoke"})
    write_json(cleanup, {"status": "cleanup_complete"})
    exit_path.write_text("1\n", encoding="utf-8")
    output = tmp_path / "terminal.json"
    helper = ROOT / "hpc/scout-smoke-content-composition-base.bash"
    command = """
set -euo pipefail
SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY=1
source "$1"
unset SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY
SCOUT_LAB_PYTHON="$2"
write_pre_phase_terminal "$3" "$4" native_smoke 1 "$5" "$6" "$7" "$8" "$9" \
    "${10}" "${11}" "${12}" 42 "${13}" "${14}"
"""
    stdout = tmp_path / "job.out"
    stderr = tmp_path / "job.err"
    result = subprocess.run(
        [
            "bash",
            "-c",
            command,
            "bash",
            str(helper),
            sys.executable,
            str(output),
            protocol,
            str(smoke),
            str(tmp_path / "missing-native.json"),
            str(pre_smoke),
            str(cleanup),
            str(exit_path),
            str(repeat_limit),
            str(total_limit),
            str(content_argument).lower(),
            str(stdout),
            str(stderr),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    terminal = json.loads(output.read_text(encoding="utf-8"))
    assert terminal["status"] == "terminal_before_repeat_judge_phase"
    assert terminal["failure"] == {
        "stage": "native_smoke",
        "error_type": "WrapperStageFailure",
        "message": "Wrapper exited during native_smoke before repeat/judge phase reservation",
    }
    assert terminal["requests"] == {
        "synthetic": 4,
        "native": 0,
        "repeat": 0,
        "total": 4,
        "limit": total_limit,
        "accounting_complete": True,
    }
    assert "phase" not in terminal["artifacts"]
    assert terminal["scientific_outcome"]["started"] is False
    assert ("item_13_status" in terminal) is content_argument


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("model",), "other-model"),
        (("process_identity", "cmdline_sha256"), None),
        (("scheduler", "state"), "PENDING"),
        (("models_auth", "checks", "wrong_key", "rejected"), False),
        (("models_auth", "checks", "missing_key"), "__delete__"),
    ],
)
def test_terminal_rejects_mutated_or_missing_server_evidence(tmp_path, path, value):
    plan, live = make_runs(tmp_path)
    inputs = terminal_inputs(tmp_path, plan, live, 0)
    server_path = inputs["server_check_path"]
    server = json.loads(server_path.read_text())
    target = server
    for key in path[:-1]:
        target = target[key]
    if value == "__delete__":
        del target[path[-1]]
    else:
        target[path[-1]] = value
    write_json(server_path, server)

    final = batch.finalize(tmp_path / "mutated-final.json", **inputs)

    assert final["status"] == "incomplete"
    assert final["failure"]["stage"] == "server_and_live_ledgers"
    assert "server receipt" in final["failure"]["message"]


def test_wrapper_static_resource_reserve_watchdog_and_request_arithmetic():
    wrapper = (ROOT / "hpc/scout-smoke-content-composition-argument.sbatch").read_text()
    helper = (ROOT / "hpc/scout-smoke-content-composition-base.bash").read_text()
    generic = (ROOT / "hpc/scout-smoke.sbatch").read_bytes()
    assert "#SBATCH --time=03:30:00" in wrapper
    assert "#SBATCH --gpus-per-node=a100:4" in wrapper
    assert "#SBATCH --cpus-per-task=48" in wrapper
    assert "#SBATCH --mem=320G" in wrapper
    assert "at least 8,400 seconds remaining" in wrapper
    assert "sleep 7800" in wrapper
    assert "--expected-stdout" in wrapper and "--expected-stderr" in wrapper
    assert "#SBATCH --error=scout-content-arg-%j.err" in wrapper
    helper_source = 'source "$CCA_HPC_DIR/scout-smoke-content-composition-base.bash"'
    definition_source_position = wrapper.index(helper_source)
    source_position = wrapper.rindex(helper_source)
    trap_position = wrapper.index("trap terminal_cleanup EXIT")
    plan_position = wrapper.index("# Generate and validate the exact request plan")
    unset_pid_position = wrapper.index("unset SCOUT_SERVER_PID")
    cleared_pid_position = wrapper.index("SCOUT_SERVER_PID=''", wrapper.index("CCA_PRE_SMOKE="))
    exported_pid_position = wrapper.index("export SCOUT_SERVER_PID")
    assert unset_pid_position < cleared_pid_position
    assert definition_source_position < trap_position < plan_position < source_position < exported_pid_position
    assert "export SCOUT_PROTOCOL_PARENT_OWNS_TRAPS=1" in wrapper
    assert "[[ ${SCOUT_PROTOCOL_PARENT_OWNS_TRAPS:-0} == 1 ]]" in helper
    assert "SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY" in helper
    assert "declare -F terminal_cleanup >/dev/null || exit 2" in helper
    assert "trap cleanup EXIT" not in helper
    assert "SCOUT_SMOKE_STAGE=native_smoke" in helper
    assert "write_pre_phase_terminal" in helper
    assert (
        'export PYTHONPATH="$CCA_BUNDLE_ROOT/vendor/agentdojo/src:'
        '$CCA_BUNDLE_ROOT/src:$CCA_BUNDLE_ROOT/scripts"'
    ) in wrapper
    assert wrapper.count("for _ in {1..10}; do") >= 4
    assert "local killer=" not in wrapper
    assert hashlib.sha256(generic).hexdigest() == (
        "1e2caa7bd21310f7ce04af46607ad0e077abb56f2ba117691f5ee466a584ee1a"
    )
    assert wrapper.index('for sidecar in "$CCA_PRE_SMOKE"') < trap_position
    assert '[[ ! -e "$sidecar" && ! -L "$sidecar" ]] || exit 2' in wrapper
    output_paths = re.search(r"CCA_OUTPUT_PATHS=\(.*?\n\)", wrapper, flags=re.DOTALL)
    assert output_paths is not None
    for name in (
        "$CCA_BUNDLE_ROOT",
        "$SCOUT_RUN_DIR",
        "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR",
        "$SCOUT_CONTENT_ARGUMENT_OUTPUT",
        "$CCA_FINAL",
        "$SCOUT_CONTENT_ARGUMENT_STDOUT",
        "$SCOUT_CONTENT_ARGUMENT_STDERR",
    ):
        assert name in output_paths.group(0)
    assert 'paths_overlap "${CCA_OUTPUT_PATHS[left_index]}"' in wrapper
    limits = batch.fixed_limits()
    assert limits == {
        "walltime_seconds": 12600,
        "minimum_remaining_seconds": 8400,
        "command_timeout_seconds": 7800,
        "synthetic_requests": 4,
        "native_requests": 4,
        "repeat_judge_requests": 42,
        "total_generation_requests": 50,
        "sdk_retries": 0,
        "native_tool_executions_by_repeat_runner": 0,
    }
    assert limits["minimum_remaining_seconds"] >= 42 * 180 + 14 * 60
    assert limits["command_timeout_seconds"] >= 42 * 180 + 4 * 60
    assert limits["walltime_seconds"] > limits["minimum_remaining_seconds"]


def test_wrapper_rejects_path_overlap_and_stale_or_symlink_sidecars(tmp_path):
    wrapper = (ROOT / "hpc/scout-smoke-content-composition-argument.sbatch").read_text()
    function = re.search(r"paths_overlap\(\) \{.*?^\}", wrapper, flags=re.DOTALL | re.MULTILINE)
    assert function is not None
    command = function.group(0) + '\npaths_overlap "$1" "$2"'

    overlap = subprocess.run(
        ["bash", "-c", command, "bash", "/evidence/final.json", "/evidence/final.json/plan"],
        check=False,
    )
    distinct = subprocess.run(
        ["bash", "-c", command, "bash", "/evidence/final.json", "/evidence/plan"],
        check=False,
    )
    assert overlap.returncode == 0
    assert distinct.returncode != 0

    stale = tmp_path / "stale.json"
    stale.write_text("old")
    link = tmp_path / "stale-link.json"
    link.symlink_to(stale)
    predicate = 'sidecar=$1; [[ ! -e "$sidecar" && ! -L "$sidecar" ]]'
    assert subprocess.run(["bash", "-c", predicate, "bash", str(tmp_path / "new.json")]).returncode == 0
    assert subprocess.run(["bash", "-c", predicate, "bash", str(stale)]).returncode != 0
    assert subprocess.run(["bash", "-c", predicate, "bash", str(link)]).returncode != 0
