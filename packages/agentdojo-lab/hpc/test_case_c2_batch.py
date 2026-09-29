"""Offline checks for the separately named smoke-plus-Case-C2 batch protocol."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import case_c2_batch
import pytest

HPC = Path(__file__).resolve().parent


def test_real_cli_preparation_matches_batch_plan_contract(tmp_path):
    case_dir = tmp_path / "real-prepared"
    runner = HPC.parent / "scripts/run_case_c2_scout.py"
    completed = subprocess.run(
        [sys.executable, str(runner), "prepare", str(case_dir)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    plan = case_c2_batch.validate_plan_shape(case_dir, runner, run_verifier=False)
    assert plan["config"]["online_causal_audit"] is False


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def prepared(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    bundle = tmp_path / "bundle"
    sources = {}
    for key in case_c2_batch.REQUIRED_RUNTIME_KEYS:
        path = bundle / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{key}\n", encoding="utf-8")
        sources[key] = path.resolve()
    runner = sources["scripts/run_case_c2_scout.py"]
    source_hashes = {key: case_c2_batch.receipt(path)["sha256"] for key, path in sources.items()}
    full_source = bundle / "src/agentdojo_lab/full_source.py"
    full_source.parent.mkdir(parents=True, exist_ok=True)
    full_source.write_text("# plan-bound source outside the launch manifest\n", encoding="utf-8")
    source_hashes["src/agentdojo_lab/full_source.py"] = case_c2_batch.receipt(full_source)["sha256"]
    plan = {
        "protocol": case_c2_batch.CASE_PROTOCOL,
        "status": "prepared_design_only",
        "real_llm_requests_started": 0,
        "conditions": list(case_c2_batch.CONDITIONS),
        "session_order": list(case_c2_batch.SESSION_ORDER),
        "slots": [
            {
                "slot_id": slot_id,
                "condition": condition,
                "stage": stage,
                "order": order,
            }
            for order, (slot_id, (condition, stage)) in enumerate(
                zip(case_c2_batch.SLOT_IDS, case_c2_batch.SLOTS, strict=True), 1
            )
        ],
        "execution_binding": {"status": "pending_same_allocation_serving_receipt"},
        "limits": {
            "sdk_attempts_per_session": 4,
            "primary_sdk_attempts_total": 16,
            "completion_tokens_per_request": 2048,
            "context_tokens": 8192,
            "online_auditor_requests": 0,
            "sdk_max_retries": 0,
            "request_pacing": False,
            "worker_processes": 4,
            "session_timeout_seconds": 900,
        },
        "config": {
            "provider": "openai_compatible",
            "model": "llama-4-scout-local",
            "base_url": "http://127.0.0.1:8000/v1",
            "api_key_env": "LOCAL_LLM_API_KEY",
            "benchmark_version": "v1.2.2",
            "suite": "workspace",
            "user_tasks": ["case_c2_fixed_target_memory"],
            "temperature": 0.0,
            "max_completion_tokens": 2048,
            "max_tool_rounds": 4,
            "request_timeout_seconds": 180.0,
            "online_causal_audit": False,
            "reasoning_effort": None,
            "pacing_tokens_per_minute": None,
            "record_events": True,
            "online_provenance": True,
            "canary_enabled": False,
            "lineage_namespace": case_c2_batch.CASE_PROTOCOL,
            "provenance_policy": "configs/workspace_policy_v1.yaml",
            "semantic_model": "/models/all-MiniLM-L6-v2-1110a243",
            "semantic_revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        },
        "endpoint_identity": {
            "settings": {
                "provider": "openai_compatible",
                "model": "llama-4-scout-local",
                "base_url": "http://127.0.0.1:8000/v1",
                "api_key_env": "LOCAL_LLM_API_KEY",
            },
            "literal_loopback_required": True,
            "credentials": "environment_variable_only",
            "fallback": None,
        },
        "schema_version": 2,
        "memory": {
            "selection_contract": "prospectively_named_native_identity",
            "file_id": "2",
            "filename": "session-memory-c2.txt",
            "initial_content": "",
            "initial_content_sha256": hashlib.sha256(b"").hexdigest(),
            "native_and_dcpg_checkpoints": "separate",
            "session_b_native_checkpoint_scope": "only_the_bound_persisted_artifact",
        },
        "session_isolation": {
            "distinct_worker_processes": True,
            "distinct_run_and_session_ids": True,
            "empty_message_history_at_each_session_start": True,
            "session_b_model_visible_native_files": ["2"],
            "session_b_receives_source_file": False,
            "observer_checkpoint_restored_separately": True,
        },
        "fixture_contract": {
            "label": "scripted_repeated_read_and_write_fixed_target_oracle_fixture",
            "research_result": False,
            "source_reads": 2,
            "target_appends": 2,
        },
        "tools": {
            "A": [
                {"function": {"name": "get_file_by_id"}},
                {"function": {"name": "append_to_file"}},
            ],
            "B": [
                {"function": {"name": "get_file_by_id"}},
                {"function": {"name": "send_email"}},
            ],
        },
        "source_hashes": source_hashes,
    }
    dump(case_dir / "plan.json", plan)
    dump(
        case_dir / "preparation.json",
        {
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "status": "prepared_not_executed",
            "real_llm_requests_started": 0,
            "plan": case_c2_batch.receipt(case_dir / "plan.json"),
        },
    )
    manifest = bundle / "submission-sha256.txt"
    manifest.write_text(
        "".join(f"{case_c2_batch.receipt(path)['sha256']}  {key}\n" for key, path in sources.items()),
        encoding="utf-8",
    )
    site = tmp_path / "case-c2-site.env"
    site.write_text("# frozen private site fixture\n", encoding="utf-8")
    executed = tmp_path / "slurm_script"
    executed.write_bytes(sources["hpc/scout-smoke-case-c2.sbatch"].read_bytes())
    submission = {
        "site_path": site,
        "site_sha256": case_c2_batch.receipt(site)["sha256"],
        "manifest_path": manifest,
        "manifest_sha256": case_c2_batch.receipt(manifest)["sha256"],
        "executed_wrapper_path": executed,
    }
    return case_dir, runner, sources, plan, submission


def full_plan_verifier(runner: Path):
    bundle = runner.parents[1]

    def verify(case_dir: Path):
        plan = json.loads((case_dir / "plan.json").read_text(encoding="utf-8"))
        current = {}
        for key in plan["source_hashes"]:
            path = bundle / key
            if not path.is_file():
                raise ValueError("Missing plan-bound Case C2 source")
            current[key] = case_c2_batch.receipt(path)["sha256"]
        if current != plan["source_hashes"]:
            raise ValueError("Changed plan-bound Case C2 source")
        return plan

    return verify


def write_wrapper_checksums(output: Path, sources: dict[str, Path], submission: dict) -> None:
    paths = [
        submission["executed_wrapper_path"],
        submission["site_path"],
        submission["manifest_path"],
        *sources.values(),
    ]
    unique = {str(path.resolve()): path for path in paths}
    output.write_text(
        "".join(f"{case_c2_batch.receipt(path)['sha256']}  {path.resolve()}\n" for path in unique.values()),
        encoding="utf-8",
    )


def pre_smoke_fixture(tmp_path: Path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    smoke_dir = tmp_path / "smoke"
    pre_smoke = tmp_path / "smoke.case-c2-pre-smoke.json"
    case_c2_batch.validate_before_smoke(
        pre_smoke,
        case_dir,
        smoke_dir,
        runner,
        sources,
        **submission,
        verifier=lambda _path: plan,
    )
    smoke_dir.mkdir()
    write_wrapper_checksums(smoke_dir / "case-c2-wrapper-sha256.txt", sources, submission)
    return case_dir, runner, sources, plan, smoke_dir, pre_smoke


def reserve(tmp_path: Path, **changes):
    case_dir, runner, sources, plan, smoke_dir, pre_smoke = pre_smoke_fixture(tmp_path)
    values = {
        "job_id": "42",
        "reported_job_id": "42",
        "remaining": "01:05:00",
        "time_limit": "02:00:00",
        "case_dir": case_dir,
        "pre_smoke_path": pre_smoke,
        "runner_path": runner,
        "runtime_sources": sources,
        "wrapper_sha256_path": smoke_dir / "case-c2-wrapper-sha256.txt",
        "server_pid": 500,
        "verifier": lambda _path: plan,
    }
    values.update(changes)
    phase = case_c2_batch.reserve_phase(smoke_dir / "case-c2-phase.json", **values)
    return case_dir, runner, sources, plan, smoke_dir, pre_smoke, phase


def test_pre_smoke_requires_pristine_preparation_and_every_launch_hash(tmp_path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    output = tmp_path / "smoke.case-c2-pre-smoke.json"
    result = case_c2_batch.validate_before_smoke(
        output,
        case_dir,
        tmp_path / "smoke",
        runner,
        sources,
        **submission,
        verifier=lambda _path: plan,
    )
    assert result["verification"] == {
        "request_free_runner_verify": True,
        "real_llm_requests_started": 0,
    }
    assert set(result["runtime_sources"]) == set(case_c2_batch.REQUIRED_RUNTIME_KEYS)

    changed = sources["hpc/case_c2_batch.py"]
    changed.write_text("drift\n", encoding="utf-8")
    with pytest.raises(ValueError, match="launch source|manifest"):
        case_c2_batch.validate_before_smoke(
            tmp_path / "other-smoke.case-c2-pre-smoke.json",
            case_dir,
            tmp_path / "other-smoke",
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )


def test_pre_smoke_rejects_prior_case_output_existing_smoke_and_missing_mapping(tmp_path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    (case_dir / "execution.json").write_text("prior output", encoding="utf-8")
    with pytest.raises(ValueError, match="only plan"):
        case_c2_batch.validate_before_smoke(
            tmp_path / "smoke.case-c2-pre-smoke.json",
            case_dir,
            tmp_path / "smoke",
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )
    (case_dir / "execution.json").unlink()
    smoke = tmp_path / "smoke"
    smoke.mkdir()
    with pytest.raises(FileExistsError, match="fresh"):
        case_c2_batch.validate_before_smoke(
            tmp_path / "smoke.case-c2-pre-smoke.json",
            case_dir,
            smoke,
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )
    incomplete = dict(sources)
    incomplete.pop("hpc/smoke.py")
    with pytest.raises(ValueError, match="incomplete"):
        case_c2_batch.validate_runtime_sources(plan, incomplete)


def test_parse_runtime_sources_requires_exact_absolute_unique_mapping(tmp_path):
    _, _, sources, _, _ = prepared(tmp_path)
    rows = [[key, str(path)] for key, path in sources.items()]
    assert case_c2_batch.parse_runtime_sources(rows) == sources
    with pytest.raises(ValueError, match="Duplicate"):
        case_c2_batch.parse_runtime_sources(rows + [rows[0]])
    with pytest.raises(ValueError, match="incomplete"):
        case_c2_batch.parse_runtime_sources(rows[:-1])
    linked = tmp_path / "linked-runner.py"
    linked.symlink_to(sources["scripts/run_case_c2_scout.py"])
    changed = [list(row) for row in rows]
    runner_index = next(
        index for index, row in enumerate(changed) if row[0] == "scripts/run_case_c2_scout.py"
    )
    changed[runner_index][1] = str(linked)
    with pytest.raises(ValueError, match="Invalid"):
        case_c2_batch.parse_runtime_sources(changed)


def test_pre_smoke_rejects_symlinked_preparation_before_verification(tmp_path):
    case_dir, runner, sources, _plan, submission = prepared(tmp_path)
    linked_case = tmp_path / "linked-case"
    linked_case.symlink_to(case_dir, target_is_directory=True)
    verifier_called = False

    def verifier(_path):
        nonlocal verifier_called
        verifier_called = True
        raise AssertionError("verification must not start for an aliased preparation")

    with pytest.raises(ValueError, match="physical canonical directory"):
        case_c2_batch.validate_before_smoke(
            tmp_path / "smoke.case-c2-pre-smoke.json",
            linked_case,
            tmp_path / "smoke",
            runner,
            sources,
            **submission,
            verifier=verifier,
        )
    assert verifier_called is False


@pytest.mark.parametrize("name", ["plan.json", "preparation.json"])
def test_pre_smoke_rejects_symlinked_preparation_file(tmp_path, name):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    original = case_dir / name
    external = tmp_path / f"external-{name}"
    original.replace(external)
    original.symlink_to(external)

    with pytest.raises(ValueError, match="physical canonical file"):
        case_c2_batch.validate_before_smoke(
            tmp_path / "smoke.case-c2-pre-smoke.json",
            case_dir,
            tmp_path / "smoke",
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )


@pytest.mark.parametrize("name", ["plan.json", "preparation.json"])
def test_reserve_rejects_preparation_file_replaced_by_symlink(tmp_path, name):
    case_dir, runner, sources, plan, smoke_dir, pre_smoke = pre_smoke_fixture(tmp_path)
    original = case_dir / name
    external = tmp_path / f"external-{name}"
    original.replace(external)
    original.symlink_to(external)

    with pytest.raises(ValueError, match="physical canonical file"):
        case_c2_batch.reserve_phase(
            smoke_dir / "case-c2-phase.json",
            job_id="42",
            reported_job_id="42",
            remaining="01:05:00",
            time_limit="02:00:00",
            case_dir=case_dir,
            pre_smoke_path=pre_smoke,
            runner_path=runner,
            runtime_sources=sources,
            wrapper_sha256_path=smoke_dir / "case-c2-wrapper-sha256.txt",
            server_pid=500,
            verifier=lambda _path: plan,
        )


def test_runtime_source_validation_rejects_symlink_alias(tmp_path):
    _case_dir, _runner, sources, plan, _submission = prepared(tmp_path)
    linked_runner = tmp_path / "linked-runtime-runner.py"
    linked_runner.symlink_to(sources["scripts/run_case_c2_scout.py"])
    changed = dict(sources)
    changed["scripts/run_case_c2_scout.py"] = linked_runner
    with pytest.raises(ValueError, match="physical canonical file"):
        case_c2_batch.validate_runtime_sources(plan, changed)


def test_request_free_verifier_subprocess_receives_no_credentials(tmp_path, monkeypatch):
    case_dir, runner, _sources, plan, _submission = prepared(tmp_path)
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-secret")
    monkeypatch.setenv("GROQ_API_KEY", "remote-secret")
    seen = {}

    def run(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(case_c2_batch.subprocess, "run", run)
    assert case_c2_batch.validate_plan_shape(case_dir, runner, run_verifier=True) == plan
    assert seen["command"] == [
        case_c2_batch.sys.executable,
        str(runner),
        "verify",
        str(case_dir),
    ]
    assert seen["kwargs"]["stdin"] is case_c2_batch.subprocess.DEVNULL
    assert seen["kwargs"]["env"]["HF_HUB_OFFLINE"] == "1"
    assert seen["kwargs"]["env"]["PYTHONPATH"].split(case_c2_batch.os.pathsep) == [
        str(runner.parents[1] / "vendor/agentdojo/src"),
        str(runner.parents[1] / "src"),
        str(runner.parents[1] / "scripts"),
    ]
    assert "LOCAL_LLM_API_KEY" not in seen["kwargs"]["env"]
    assert "GROQ_API_KEY" not in seen["kwargs"]["env"]


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("01:05:00", 3900), ("59:00", 3540), ("0-02:00:00", 7200), ("1-00:00:00", 86400)],
)
def test_parse_slurm_duration(raw, seconds):
    assert case_c2_batch.parse_slurm_duration(raw) == seconds


@pytest.mark.parametrize("raw", ["", " 01:00", "01:60", "x", "1-24:00:00"])
def test_parse_slurm_duration_rejects_malformed_values(raw):
    with pytest.raises(ValueError):
        case_c2_batch.parse_slurm_duration(raw)


def test_scheduler_gate_reserves_boundary_and_hashes_all_runtime_inputs(tmp_path):
    *_, phase = reserve(tmp_path)
    assert phase["status"] == "reserved_before_case_calls"
    assert phase["server_pid"] == 500
    assert phase["time_decision"]["remaining_seconds"] == 3900
    assert phase["limits"] == {
        "walltime_seconds": 7200,
        "minimum_remaining_seconds": 3900,
        "case_command_timeout_seconds": 3600,
        "synthetic_requests": 4,
        "native_requests": 4,
        "case_requests": 16,
        "total_generation_requests": 24,
        "online_auditor_requests": 0,
        "sdk_retries": 0,
    }
    assert set(phase["runtime_sources"]) == set(case_c2_batch.REQUIRED_RUNTIME_KEYS)


@pytest.mark.parametrize("server_pid", [True, 1, 0, -1])
def test_scheduler_gate_rejects_invalid_server_pid(tmp_path, server_pid):
    with pytest.raises(ValueError, match="server PID"):
        reserve(tmp_path, server_pid=server_pid)


@pytest.mark.parametrize(
    ("changes", "status"),
    [
        ({"remaining": "01:04:59"}, "unstarted_insufficient_remaining_time"),
        ({"time_limit": "02:00:01"}, "unstarted_walltime_limit_exceeded"),
        ({"reported_job_id": "99"}, "unstarted_invalid_current_job_time_evidence"),
        ({"remaining": "invalid"}, "unstarted_invalid_current_job_time_evidence"),
        ({"remaining": "02:00:01"}, "unstarted_invalid_current_job_time_evidence"),
    ],
)
def test_scheduler_gate_fails_closed(tmp_path, changes, status):
    *_, phase = reserve(tmp_path, **changes)
    assert phase["status"] == status


def terminal_fixture(tmp_path: Path, *, remaining="01:05:00", wrapper_exit=0, counts=(1, 2, 3, 4)):
    case_dir, runner, _sources, plan, smoke_dir, pre_smoke, phase = reserve(tmp_path, remaining=remaining)
    job_id = "42"
    smoke_limits, enclosing_limits = case_c2_batch.expected_preflight_limits()
    dump(
        smoke_dir / "preflight.json",
        {
            "protocol": case_c2_batch.SMOKE_PROTOCOL,
            "slurm_job_id": job_id,
            "limits": smoke_limits,
            "enclosing_case_c_limits": enclosing_limits,
        },
    )
    dump(
        smoke_dir / "smoke.json",
        {"protocol": case_c2_batch.SMOKE_PROTOCOL, "status": "passed", "requests_started": 4},
    )
    dump(
        smoke_dir / "native-smoke.json",
        {
            "protocol": case_c2_batch.NATIVE_PROTOCOL,
            "status": "passed",
            "slurm_job_id": job_id,
            "native_requests_started": 3,
            "checks": {"no_online_auditors": True},
        },
    )
    dump(
        smoke_dir / "case-c2-cleanup.json",
        {
            "protocol": case_c2_batch.PROTOCOL,
            "status": "server_stopped",
            "slurm_job_id": job_id,
            "server_pid": 500,
            "case_process": {
                "pid": 0 if phase["status"].startswith("unstarted_") else 600,
                "term_sent": False,
                "kill_sent": False,
                "stopped": True,
            },
        },
    )
    (smoke_dir / "case-c2-wrapper-exit-code.txt").write_text(f"{wrapper_exit}\n", encoding="utf-8")
    paths = {
        "phase_path": smoke_dir / "case-c2-phase.json",
        "pre_smoke_path": pre_smoke,
        "runner_path": runner,
        "preflight_path": smoke_dir / "preflight.json",
        "smoke_path": smoke_dir / "smoke.json",
        "native_path": smoke_dir / "native-smoke.json",
        "case_summary_path": case_dir / "case-summary.json",
        "case_plan_path": case_dir / "plan.json",
        "execution_path": case_dir / "execution.json",
        "wrapper_exit_path": smoke_dir / "case-c2-wrapper-exit-code.txt",
        "wrapper_sha256_path": smoke_dir / "case-c2-wrapper-sha256.txt",
        "server_check_path": smoke_dir / "case-a-server-check.json",
        "cleanup_path": smoke_dir / "case-c2-cleanup.json",
        "plan_verifier": full_plan_verifier(runner),
    }
    if phase["status"].startswith("unstarted_"):
        paths["smoke_binding_validator"] = lambda _preflight, _url: {
            "status": "bound_before_case_calls",
            "slurm_job_id": job_id,
        }
        return smoke_dir, paths

    binding = {"status": "bound_before_case_calls", "slurm_job_id": job_id, "evidence": {}}
    dump(
        paths["server_check_path"],
        {
            "protocol": case_c2_batch.SERVER_CHECK_PROTOCOL,
            "status": "passed",
            "slurm_job_id": job_id,
            "endpoint": plan["config"]["base_url"],
            "server_pid": 500,
        },
    )
    dump(
        paths["execution_path"],
        {
            "schema_version": 1,
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "mode": "live_scout",
            "plan": case_c2_batch.receipt(case_dir / "plan.json"),
            "serving": binding,
            "preflight": case_c2_batch.receipt(paths["preflight_path"]),
            "status": "reserved_before_workers",
            "fixed_slot_order": list(case_c2_batch.SLOT_IDS),
        },
    )
    slots = []
    worker_pids = [101, 102, 103, 104]
    plan_receipt = case_c2_batch.receipt(case_dir / "plan.json")
    terminals = {}
    handoffs = {}
    for condition in case_c2_batch.CONDITIONS:
        a_index = list(case_c2_batch.SLOTS).index((condition, "A"))
        b_index = list(case_c2_batch.SLOTS).index((condition, "B"))
        memory_id = "2"
        memory_content = f"transformed memory for {condition}"
        a_run_id = f"{case_c2_batch.CASE_PROTOCOL}-{condition}-A"
        a_outcome = {
            "transformation_confirmed": True,
            "condition": condition,
            "session_a_tool_scope": {
                "conformant": True,
                "off_contract_source_reads": [],
                "off_contract_memory_writes": [],
            },
            "source_read_chains": [{"arguments": {"file_id": "1"}}],
            "actual_source_exposure": {"binding_verified": True},
            "memory_write_chains": [
                {"arguments": {"file_id": "2", "content": memory_content}}
            ],
            "memory_write_selection": {
                "status": "selected_by_prospective_identity",
                "observed_target_write_count": 1,
                "post_inference_candidate_choice": False,
            },
            "memory_write_binding": {"confirmed": True},
            "observed_memory_write_summary": {"all_target_writes_bound": True},
        }
        a_terminal = {
            "schema_version": 1,
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "condition": condition,
            "stage": "A",
            "slot_id": f"{condition}/A",
            "run_id": a_run_id,
            "session_id": a_run_id,
            "status": "completed",
            "pid": worker_pids[a_index],
            "primary_trajectory_complete": True,
            "outcome_analysis_complete": True,
            "real_llm": True,
            "evidence_class": "live_scout_research",
            "fixture_is_research_result": None,
            "source_snapshot_unchanged_after_calls": True,
            "input_hashes_unchanged": True,
            "created_file_id": memory_id,
            "created_content": memory_content,
            "outcome": a_outcome,
            "dcpg_candidate_evidence": {"complete": True},
        }
        a_root = case_dir / condition / "A"
        a_root.mkdir(parents=True)
        dump(a_root / "summary.json", a_terminal)
        dump(a_root / "case-c-outcome.json", a_outcome)
        dump(a_root / "native-memory.json", {"files": [{"id_": memory_id}]})
        dump(a_root / "lineage-state.json", {"status": "saved"})
        dump(
            a_root / "session-b-native.json",
            {
                "schema_version": 1,
                "namespace": f"{case_c2_batch.CASE_PROTOCOL}-{condition}",
                "account_email": "user@example.com",
                "files": [
                    {
                        "id_": memory_id,
                        "filename": "session-memory-c2.txt",
                        "content": memory_content,
                    }
                ],
            },
        )
        dump(case_dir / f"{condition}-A-terminal.json", a_terminal)
        handoff = {
            "schema_version": 2,
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "condition": condition,
            "status": "ready_for_session_b",
            "advancement_basis": "prospectively_bound_target_final_native_state_only",
            "post_inference_candidate_choice": False,
            "dcpg_candidate_match_can_advance": False,
            "plan": plan_receipt,
            "session_a": {
                "worker_pid": worker_pids[a_index],
                "run_id": a_run_id,
                "summary": case_c2_batch.receipt(a_root / "summary.json"),
                "outcome": case_c2_batch.receipt(a_root / "case-c-outcome.json"),
            },
            "native_state": case_c2_batch.receipt(a_root / "session-b-native.json"),
            "native_state_scope": "only_the_bound_persisted_artifact",
            "source_file_excluded_from_session_b": True,
            "dcpg_state": case_c2_batch.receipt(a_root / "lineage-state.json"),
            "memory": {
                "file_id": memory_id,
                "filename": "session-memory-c2.txt",
                "content": memory_content,
                "content_sha256": hashlib.sha256(memory_content.encode()).hexdigest(),
            },
            "checkpoint_hashes_distinctly_bound": True,
        }
        dump(case_dir / condition / "handoff.json", handoff)
        handoffs[condition] = handoff

        b_run_id = f"{case_c2_batch.CASE_PROTOCOL}-{condition}-B"
        b_outcome = {"observed_end_to_end_sink": True, "condition": condition}
        b_terminal = {
            "schema_version": 1,
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "condition": condition,
            "stage": "B",
            "slot_id": f"{condition}/B",
            "run_id": b_run_id,
            "session_id": b_run_id,
            "status": "completed",
            "pid": worker_pids[b_index],
            "primary_trajectory_complete": True,
            "outcome_analysis_complete": True,
            "real_llm": True,
            "evidence_class": "live_scout_research",
            "fixture_is_research_result": None,
            "source_snapshot_unchanged_after_calls": True,
            "input_hashes_unchanged": True,
            "source_id": memory_id,
            "source_content": memory_content,
            "input_hashes": {
                "handoff": case_c2_batch.receipt(case_dir / condition / "handoff.json")["sha256"],
                "native_input": handoff["native_state"]["sha256"],
                "lineage_input": handoff["dcpg_state"]["sha256"],
            },
            "outcome": b_outcome,
            "dcpg_candidate_evidence": {"complete": True},
        }
        dump(case_dir / f"{condition}-B-terminal.json", b_terminal)
        terminals[(condition, "A")] = a_terminal
        terminals[(condition, "B")] = b_terminal

    for (condition, stage), count, worker_pid in zip(
        case_c2_batch.SLOTS, counts, worker_pids, strict=True
    ):
        attempts = case_dir / condition / stage / "sdk-attempts.jsonl"
        attempts.parent.mkdir(parents=True, exist_ok=True)
        attempts.write_text(
            "".join(json.dumps({"sdk_attempt": index}) + "\n" for index in range(1, count + 1)),
            encoding="utf-8",
        )
        slots.append(
            {
                "slot_id": f"{condition}/{stage}",
                "condition": condition,
                "stage": stage,
                "terminal": terminals[(condition, stage)],
                "captured_sdk_attempts": count,
                "worker_pid": worker_pid,
                "process_identity_verified": True,
                "process_status": "terminal",
                "returncode": 0,
                "replacement_attempted": False,
            }
        )

    report_root = case_dir / "cross-session-c2-report"
    report_root.mkdir()
    dump(report_root / "cross-session-c2.json", {"status": "fixture"})
    (report_root / "index.html").write_text("<html></html>", encoding="utf-8")
    outcomes = {row["slot_id"]: row["terminal"]["outcome"] for row in slots}
    candidates = {
        row["slot_id"]: row["terminal"]["dcpg_candidate_evidence"] for row in slots
    }
    run_ids = [row["terminal"]["run_id"] for row in slots]
    cross_session = {
        "status": "exported_request_free",
        "model_requests_started": 0,
        "observed_native_path_complete": True,
        "observed_native_path_status": {
            condition: "all_native_observations_covered"
            for condition in case_c2_batch.CONDITIONS
        },
        "native_oracle_affected": False,
        "cross_session_json": case_c2_batch.receipt(report_root / "cross-session-c2.json"),
        "index_html": case_c2_batch.receipt(report_root / "index.html"),
    }
    dump(
        paths["case_summary_path"],
        {
            "schema_version": 1,
            "protocol": case_c2_batch.CASE_PROTOCOL,
            "status": "completed",
            "mode": "live_scout",
            "evidence_class": "live_scout_research",
            "real_llm": True,
            "fixture_is_research_result": None,
            "fixture_validation_complete": None,
            "research_outcome": "inspect_observed_native_evidence",
            "plan": plan_receipt,
            "fixed_slot_order": list(case_c2_batch.SLOT_IDS),
            "slots": slots,
            "all_assignments_accounted": True,
            "all_workers_terminal_successfully": True,
            "all_primary_trajectories_complete": True,
            "all_outcome_analyses_determinate": True,
            "all_worker_processes_distinct": True,
            "all_recorded_run_ids_distinct": True,
            "worker_pids": worker_pids,
            "run_ids": run_ids,
            "handoffs": handoffs,
            "handoffs_ready_from_observed_native_writes": True,
            "captured_primary_sdk_attempts": sum(counts),
            "primary_sdk_attempt_ceiling": 16,
            "request_bound_respected": True,
            "protocol_execution_complete": True,
            "research_experiment_complete": True,
            "end_to_end_native_report_complete": True,
            "observed_native_outcomes": outcomes,
            "dcpg_candidate_reporting": candidates,
            "cross_session_export": cross_session,
            "cross_session_export_is_native_oracle": False,
            "source_snapshot_unchanged": True,
            "failures_replaced": False,
        },
    )
    paths["binding_validator"] = lambda _preflight, _url: binding
    return smoke_dir, paths


def test_final_receipt_accounts_for_all_three_request_sources(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path)
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "complete_all_slots_terminal"
    assert result["requests"] == {
        "synthetic": 4,
        "native": 3,
        "case": 10,
        "total": 17,
        "limit": 24,
        "per_case_session": {
            "clean/A": 1,
            "clean/B": 2,
            "attacked/A": 3,
            "attacked/B": 4,
        },
    }
    with pytest.raises(FileExistsError):
        case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)


def test_final_receipt_rejects_per_arm_request_overrun(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path)
    attempts = paths["case_plan_path"].parent / "clean" / "A" / "sdk-attempts.jsonl"
    attempts.write_text(
        "".join(json.dumps({"sdk_attempt": index}) + "\n" for index in range(1, 6)),
        encoding="utf-8",
    )
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_nonzero_wrapper_exit_preserves_determinate_terminal_failure(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, wrapper_exit=1)
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "terminal_case_runner_failed"
    assert result["wrapper_exit_code"] == 1
    assert result["requests"]["total"] == 17


@pytest.mark.parametrize(
    "mutation",
    [
        "phase_limits",
        "phase_server_pid",
        "runtime_source",
        "server_protocol",
        "server_check_pid",
        "summary_count",
        "cleanup_pid",
    ],
)
def test_final_receipt_rejects_mutated_launch_and_terminal_chain(tmp_path, mutation):
    smoke_dir, paths = terminal_fixture(tmp_path)
    if mutation == "phase_limits":
        value = json.loads(paths["phase_path"].read_text(encoding="utf-8"))
        value["limits"]["case_requests"] = 17
        dump(paths["phase_path"], value)
    elif mutation == "phase_server_pid":
        value = json.loads(paths["phase_path"].read_text(encoding="utf-8"))
        value["server_pid"] = 501
        dump(paths["phase_path"], value)
    elif mutation == "runtime_source":
        phase = json.loads(paths["phase_path"].read_text(encoding="utf-8"))
        source = Path(phase["runtime_sources"]["hpc/case_c2_batch.py"]["path"])
        source.write_text("changed after phase reservation\n", encoding="utf-8")
    elif mutation == "server_protocol":
        value = json.loads(paths["server_check_path"].read_text(encoding="utf-8"))
        value["protocol"] = "forged"
        dump(paths["server_check_path"], value)
    elif mutation == "server_check_pid":
        value = json.loads(paths["server_check_path"].read_text(encoding="utf-8"))
        value["server_pid"] = 501
        dump(paths["server_check_path"], value)
    elif mutation == "summary_count":
        value = json.loads(paths["case_summary_path"].read_text(encoding="utf-8"))
        value["captured_primary_sdk_attempts"] = 16
        dump(paths["case_summary_path"], value)
    else:
        value = json.loads(paths["cleanup_path"].read_text(encoding="utf-8"))
        value["server_pid"] = 999
        dump(paths["cleanup_path"], value)
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


@pytest.mark.parametrize(
    ("remaining", "wrapper_exit"),
    [("01:05:00", 0), ("01:04:59", 3)],
)
def test_terminal_receipt_rejects_non_manifest_plan_source_drift(tmp_path, remaining, wrapper_exit):
    smoke_dir, paths = terminal_fixture(tmp_path, remaining=remaining, wrapper_exit=wrapper_exit)
    runner = paths["runner_path"]
    source = runner.parents[1] / "src/agentdojo_lab/full_source.py"
    source.write_text("# changed after phase reservation\n", encoding="utf-8")
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_unstarted_terminal_rejects_cleanup_server_pid_mismatch(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, remaining="01:04:59", wrapper_exit=3)
    cleanup = json.loads(paths["cleanup_path"].read_text(encoding="utf-8"))
    cleanup["server_pid"] = 501
    dump(paths["cleanup_path"], cleanup)
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_unstarted_terminal_records_smoke_without_server_or_case_calls(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, remaining="01:04:59", wrapper_exit=3)
    result = case_c2_batch.finalize(smoke_dir / "case-c2-batch-summary.json", **paths)
    assert result["status"] == "terminal_case_unstarted"
    assert result["requests"] == {
        "synthetic": 4,
        "native": 3,
        "case": 0,
        "total": 7,
        "limit": 24,
    }
    assert result["scientific_outcome"] == {
        "case_started": False,
        "reason": "unstarted_insufficient_remaining_time",
    }


def test_wrapper_uses_canonical_site_helpers_and_binds_slurm_spool_copy():
    wrapper = (HPC / "scout-smoke-case-c2.sbatch").read_text(encoding="utf-8")
    source_site = 'source "$CASE_C2_SITE_FILE"'
    canonicalize = 'CASE_C2_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")'
    compare = 'cmp --silent -- "$CASE_C2_EXECUTED_WRAPPER" "$CASE_C2_CANONICAL_WRAPPER"'
    helper_check = "for helper in scout-smoke-case-c2.sbatch scout-smoke.sbatch case_c2_batch.py"
    assert wrapper.index(source_site) < wrapper.index(canonicalize) < wrapper.index(compare)
    assert wrapper.index(compare) < wrapper.index(helper_check)
    assert '$(dirname -- "${BASH_SOURCE[0]}")' not in wrapper
    assert ': "${SCOUT_HPC_DIR:?' in wrapper
    for fragment in (
        '"${SCOUT_SITE_SHA256:?',
        '"${SCOUT_HPC_MANIFEST_SHA256:?',
        "sha256sum --check --strict --status submission-sha256.txt",
        '[[ "$(realpath -e -- "$SCOUT_HPC_DIR")" == "$SCOUT_HPC_DIR" ]]',
        '[[ -d "$directory" && ! -L "$directory" ]]',
        '[[ "$(realpath -e -- "$directory")" == "$directory" ]]',
        '[[ "$(realpath -e -- "$SCOUT_CASE_C2_DIR")" == "$SCOUT_CASE_C2_DIR" ]]',
        '[[ "$SCOUT_CASE_C2_RUNNER" == "$CASE_C2_RUNNER"',
        '[[ "$SCOUT_CHAT_TEMPLATE" == "$CASE_C2_CHAT_TEMPLATE"',
        'export SCOUT_CHAT_TEMPLATE="$CASE_C2_CHAT_TEMPLATE"',
        '"$CASE_C2_BUNDLE_ROOT/configs/local_scout.toml"',
        '--runtime-source configs/local_scout.toml',
        '--executed-wrapper-path "$CASE_C2_EXECUTED_WRAPPER"',
        '--wrapper-sha256-path "$CASE_C2_WRAPPER_SHA256"',
        '--server-pid "$SCOUT_SERVER_PID"',
        'export PYTHONPATH="$CASE_C2_BUNDLE_ROOT/vendor/agentdojo/src:$CASE_C2_BUNDLE_ROOT/src:$CASE_C2_BUNDLE_ROOT/scripts"',
    ):
        assert fragment in wrapper


def test_wrapper_is_bounded_same_allocation_and_uses_shared_server_check():
    wrapper = (HPC / "scout-smoke-case-c2.sbatch").read_text(encoding="utf-8")
    for fragment in (
        "#SBATCH --time=02:00:00",
        "#SBATCH --gpus-per-node=a100:4",
        "export SCOUT_NATIVE_SMOKE=1",
            "export SCOUT_CASE_C_MODE=1",
            "export SCOUT_CASE_C2_MODE=1",
        "export SCOUT_CASE_C2_DIR",
        'source "$CASE_C2_HPC_DIR/scout-smoke.sbatch"',
        "export SCOUT_SERVER_PID",
        "squeue -h -j \"$SLURM_JOB_ID\" -o '%i|%L|%l'",
        '"$CASE_C2_HPC_DIR/case_a_batch.py" server-check',
        "case-a-server-check.json",
        "sleep 3600",
        'kill -TERM -- "-$CASE_C2_PROCESS_PID"',
        'kill -KILL -- "-$CASE_C2_PROCESS_PID"',
        "case-c2-cleanup.json",
        "case-c2-wrapper-exit-code.txt",
        "case-c2-batch-summary.json",
        "job-exit-code.txt",
        "unset SCOUT_SITE_FILE",
        "(( SCOUT_SERVER_PID <= 1 ))",
        "(( CASE_C2_PROCESS_PID > 1 ))",
        "valid_server_pid=true",
    ):
        assert fragment in wrapper
    old_pid_guard = "[[ ${SCOUT_SERVER_PID:-} =~ ^[1-9][0-9]*$ ]] || exit 2"
    pid_guard = "if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then"
    smoke_source = 'source "$CASE_C2_HPC_DIR/scout-smoke.sbatch"'
    post_smoke_guard = '[[ "$SCOUT_HPC_DIR" == "$CASE_C2_HPC_DIR"'
    assert old_pid_guard not in wrapper
    assert wrapper.index(smoke_source) < wrapper.index(pid_guard) < wrapper.index(post_smoke_guard)
    assert wrapper.index("SCOUT_SERVER_PID=''") < wrapper.index("exit 2", wrapper.index(pid_guard))
    assert (
        wrapper.index('source "$CASE_C2_HPC_DIR/scout-smoke.sbatch"')
        < wrapper.index('"$CASE_C2_HPC_DIR/case_a_batch.py" server-check')
        < wrapper.index('"$SCOUT_CASE_C2_RUNNER" run')
    )
    assert case_c2_batch.TOTAL_REQUEST_LIMIT == 24
    assert case_c2_batch.CASE_REQUEST_LIMIT == 16
    assert case_c2_batch.CASE_SLOT_REQUEST_LIMIT == 4


def test_case_c2_source_inventory_names_every_live_runtime_input():
    script = (HPC.parent / "scripts" / "run_case_c2_scout.py").read_text(encoding="utf-8")
    for key in ("CASE-C2-SCOUT-V1.md", "case_c2_scout_v1.toml"):
        assert key in script
    assert "scripts/run_case_c2_scout.py" in case_c2_batch.REQUIRED_RUNTIME_KEYS
    assert hashlib.sha256((HPC / "scout-smoke.sbatch").read_bytes()).hexdigest() == (
        "1e2caa7bd21310f7ce04af46607ad0e077abb56f2ba117691f5ee466a584ee1a"
    )
