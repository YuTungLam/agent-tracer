"""Offline tests for the immutable Scout multi-candidate repeat/judge boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import multi_repeat_judge_batch as batch
import pytest

from agentdojo_lab.scout_multi_repeat_judge import TerminationRequested, run_multi_repeat

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/scout_multi_repeat_judge_v1.json"


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
    directories = {
        Path(value)
        for candidate in config["sources"]
        for value in (candidate["plan_export"], candidate["source_run"])
    }
    for relative in directories:
        shutil.copytree(ROOT / relative, bundle / relative, dirs_exist_ok=True)
    for roles in config["support"].values():
        for item in roles.values():
            relative = Path(item["path"])
            target = bundle / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
    entries = batch.snapshot(bundle)
    manifest = bundle / "submission-sha256.txt"
    manifest.write_text(
        "".join(f"{value}  {key}\n" for key, value in entries.items()), encoding="utf-8"
    )
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
def test_job_9129940_bundle_rejects_incomplete_native_smoke_closure(
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
            str(bundle / "scripts/run_scout_multi_repeat_judge.py"),
            "--config",
            str(bundle / "configs/scout_multi_repeat_judge_v1.json"),
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
    pre_path = tmp_path / "pre.json"

    pre = batch.validate_before_smoke(
        pre_path,
        bundle=bundle,
        manifest=manifest,
        manifest_sha256=batch.digest(manifest),
        site=site,
        site_sha256=batch.digest(site),
        executed_wrapper=bundle / "hpc/scout-smoke-multi-repeat-judge.sbatch",
        plan_dir=plan_dir,
        smoke_dir=smoke,
        live_dir=live,
        runner=bundle / "scripts/run_scout_multi_repeat_judge.py",
        config=bundle / "configs/scout_multi_repeat_judge_v1.json",
    )
    assert pre["status"] == "prepared_inputs_validated_before_smoke"
    assert pre["limits"]["total_generation_requests"] == 44

    config_path = bundle / "configs/scout_multi_repeat_judge_v1.json"
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
            remaining="02:10:00",
            time_limit="03:30:00",
            server_pid=1234,
        )


@pytest.mark.parametrize(
    ("remaining", "time_limit", "expected"),
    [
        ("02:10:00", "03:30:00", "reserved_before_repeat_judge_calls"),
        ("02:09:59", "03:30:00", "unstarted_insufficient_remaining_time"),
        ("02:10:00", "03:30:01", "unstarted_walltime_limit_exceeded"),
    ],
)
def test_fixed_scheduler_gate(remaining, time_limit, expected):
    result = batch.scheduler_decision("42", "42", remaining, time_limit)
    assert result["status"] == expected


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
    def __init__(self, role, terminate=False):
        self.role = role
        self.terminate = terminate

    def create(self, **body):
        body.pop("timeout")
        if self.terminate:
            self.terminate = False
            raise TerminationRequested("fixture")
        if self.role == "judge":
            message = {
                "role": "assistant",
                "content": json.dumps(
                    {"would_call_anyway": False, "confidence": 0.8, "reasoning": "No."}
                ),
            }
            finish = "stop"
        elif "Neutral reference information." in json.dumps(body["messages"]):
            message, finish = {"role": "assistant", "content": "No call."}, "stop"
        else:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "get_unread_emails", "arguments": "{}"},
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

    def __init__(self, role, terminate=False):
        self.chat = type("Chat", (), {})()
        self.chat.completions = Completions(role, terminate=terminate)


def binding(mode: str) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "launcher": "/bundle/scripts/run_scout_multi_repeat_judge.py",
        "launcher_sha256": "a" * 64,
        "config": "/bundle/configs/scout_multi_repeat_judge_v1.json",
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


def make_runs(tmp_path: Path, *, interrupted=False) -> tuple[Path, Path]:
    plan_only, live = tmp_path / "plan-only", tmp_path / "live"
    run_multi_repeat(plan_only, config_path=CONFIG, wrapper_binding=binding("plan_only"))
    run_multi_repeat(
        live,
        config_path=CONFIG,
        replay_client=Client("replay", terminate=interrupted),
        judge_client=Client("judge"),
        wrapper_binding=binding("live"),
    )
    summary_path = live / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["mode"] = "live_openai_compatible"
    summary["analysis"]["diagnostic_checks"]["transport_direct_literal_loopback"] = True
    if not interrupted:
        summary["analysis"]["systematic_pattern_status"] = (
            "systematic_judge_replay_agreement_observed"
        )
    write_json(summary_path, summary)
    regenerate_manifest(live)
    return plan_only, live


def terminal_inputs(tmp_path: Path, plan_only: Path, live: Path, exit_code: int) -> dict:
    bundle, manifest = build_bundle(tmp_path / "terminal-binding")
    pre = tmp_path / "pre.json"
    write_json(pre, {"protocol": batch.PROTOCOL})
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
        "repeat": 36,
        "total": 44,
        "limit": 44,
    }
    assert complete["artifacts"]["server_check"] == batch.receipt(
        complete_root / "server.json"
    )

    plan, live = make_runs(term_root, interrupted=True)
    interrupted = batch.finalize(
        term_root / "final.json",
        **terminal_inputs(term_root, plan, live, 143),
    )
    assert interrupted["status"] == "terminal_graceful_interruption_preserved"
    assert interrupted["repeat_judge"]["result_count"] == 36
    assert interrupted["requests"]["repeat"] == 1


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
    assert final["requests"]["repeat"] == 1


def test_terminal_recomputes_analysis_instead_of_trusting_summary(tmp_path):
    plan, live = make_runs(tmp_path)
    summary_path = live / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["analysis"]["pooled_disagreements"] = 12
    write_json(summary_path, summary)
    regenerate_manifest(live)

    final = batch.finalize(
        tmp_path / "final.json",
        **terminal_inputs(tmp_path, plan, live, 0),
    )

    assert final["status"] == "incomplete"
    assert final["failure"]["stage"] == "server_and_live_ledgers"
    assert "analysis differs" in final["failure"]["message"]


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
    wrapper = (ROOT / "hpc/scout-smoke-multi-repeat-judge.sbatch").read_text()
    assert "#SBATCH --time=03:30:00" in wrapper
    assert "#SBATCH --gpus-per-node=a100:4" in wrapper
    assert "#SBATCH --cpus-per-task=48" in wrapper
    assert "#SBATCH --mem=320G" in wrapper
    assert "at least 7,800 seconds remaining" in wrapper
    assert "sleep 7200" in wrapper
    helper_source = 'source "$MRJ_HPC_DIR/scout-smoke-content-composition-base.bash"'
    definition_source_position = wrapper.index(helper_source)
    execution_source_position = wrapper.rindex(helper_source)
    trap_position = wrapper.index("trap terminal_cleanup EXIT")
    assert (
        'export PYTHONPATH="$MRJ_BUNDLE_ROOT/vendor/agentdojo/src:'
        '$MRJ_BUNDLE_ROOT/src:$MRJ_BUNDLE_ROOT/scripts"'
    ) in wrapper
    assert wrapper.count(helper_source) == 2
    assert definition_source_position < trap_position < execution_source_position
    assert "export SCOUT_PROTOCOL_PARENT_OWNS_TRAPS=1" in wrapper
    assert 'if [[ -e "$MRJ_PHASE" ]]; then' in wrapper
    assert 'else\n            write_pre_phase_terminal "$MRJ_FINAL"' in wrapper
    assert wrapper.count("for _ in {1..10}; do") >= 4
    assert "local killer=" not in wrapper
    assert "hpc/scout-smoke-content-composition-base.bash" in batch.REQUIRED_BUNDLE_FILES
    limits = batch.fixed_limits()
    assert limits == {
        "walltime_seconds": 12600,
        "minimum_remaining_seconds": 7800,
        "command_timeout_seconds": 7200,
        "synthetic_requests": 4,
        "native_requests": 4,
        "repeat_judge_requests": 36,
        "total_generation_requests": 44,
        "sdk_retries": 0,
        "native_tool_executions_by_repeat_runner": 0,
    }
    assert limits["minimum_remaining_seconds"] >= 36 * 180 + 20 * 60
    assert limits["command_timeout_seconds"] >= 36 * 180 + 10 * 60
    assert limits["walltime_seconds"] > limits["minimum_remaining_seconds"]
