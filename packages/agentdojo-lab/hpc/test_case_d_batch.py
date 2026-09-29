"""Offline checks for the separately named smoke-plus-Case-D batch protocol."""

import hashlib
import json
from pathlib import Path

import case_d_batch
import native_smoke
import preflight
import pytest

HPC = Path(__file__).resolve().parent


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def prepared(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    bundle = tmp_path / "bundle"
    sources = {}
    for key in case_d_batch.REQUIRED_RUNTIME_KEYS:
        path = bundle / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{key}\n", encoding="utf-8")
        sources[key] = path.resolve()
    runner = sources["scripts/run_case_d_scout.py"]
    source_hashes = {key: case_d_batch.receipt(path)["sha256"] for key, path in sources.items()}
    full_source = bundle / "src/agentdojo_lab/full_source.py"
    full_source.parent.mkdir(parents=True, exist_ok=True)
    full_source.write_text("# plan-bound source outside the launch manifest\n", encoding="utf-8")
    source_hashes["src/agentdojo_lab/full_source.py"] = case_d_batch.receipt(full_source)["sha256"]
    plan = {
        "protocol": case_d_batch.CASE_PROTOCOL,
        "scientific_protocol": case_d_batch.SCIENTIFIC_PROTOCOL,
        "scientific_design_sha256": "0" * 64,
        "status": "prepared_design_only",
        "real_llm_requests_started": 0,
        "conditions": list(case_d_batch.CONDITIONS),
        "slots": [
            {
                "slot_id": f"case-d-r01-{arm}",
                "family": "redundant_source",
                "arm": arm,
                "repetition": 1,
            }
            for arm in case_d_batch.CONDITIONS
        ],
        "target_filename": "expense-reconciliation.txt",
        "target_content": "NTFLOW-7e92f5a1-64bd39c8",
        "redundancy_hypothesis": {
            "carrier_ids": case_d_batch.EXPECTED_CARRIERS,
            "prospective_target_outcomes": case_d_batch.EXPECTED_OUTCOMES,
        },
        "source_content_sha256": {
            arm: {"1": "1" * 64, "2": "2" * 64} for arm in case_d_batch.CONDITIONS
        },
        "limits": {
            "sdk_attempts_per_slot": 4,
            "primary_sdk_attempts_total": 16,
            "context_tokens": 8192,
            "completion_tokens_per_request": 2048,
            "worker_processes": 4,
            "online_auditor_requests": 0,
            "sdk_max_retries": 0,
        },
        "config": {
            "provider": "openai_compatible",
            "model": "llama-4-scout-local",
            "base_url": "http://127.0.0.1:8000/v1",
            "api_key_env": "LOCAL_LLM_API_KEY",
            "user_tasks": ["case_d_redundant_source"],
            "temperature": 0.0,
            "max_completion_tokens": 2048,
            "max_tool_rounds": 4,
            "online_provenance": True,
            "online_causal_audit": False,
        },
        "endpoint_identity": {
            "settings": {
                "provider": "openai_compatible",
                "model": "llama-4-scout-local",
                "base_url": "http://127.0.0.1:8000/v1",
                "api_key_env": "LOCAL_LLM_API_KEY",
            },
            "fallback": None,
        },
        "source_hashes": source_hashes,
    }
    dump(case_dir / "plan.json", plan)
    dump(
        case_dir / "preparation.json",
        {
            "protocol": case_d_batch.CASE_PROTOCOL,
            "status": "prepared_not_executed",
            "real_llm_requests_started": 0,
            "plan": case_d_batch.receipt(case_dir / "plan.json"),
        },
    )
    manifest = bundle / "submission-sha256.txt"
    manifest.write_text(
        "".join(f"{case_d_batch.receipt(path)['sha256']}  {key}\n" for key, path in sources.items()),
        encoding="utf-8",
    )
    site = tmp_path / "case-d-site.env"
    site.write_text("# frozen private site fixture\n", encoding="utf-8")
    executed = tmp_path / "slurm_script"
    executed.write_bytes(sources["hpc/scout-smoke-case-d.sbatch"].read_bytes())
    submission = {
        "site_path": site,
        "site_sha256": case_d_batch.receipt(site)["sha256"],
        "manifest_path": manifest,
        "manifest_sha256": case_d_batch.receipt(manifest)["sha256"],
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
                raise ValueError("Missing plan-bound Case D source")
            current[key] = case_d_batch.receipt(path)["sha256"]
        if current != plan["source_hashes"]:
            raise ValueError("Changed plan-bound Case D source")
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
        "".join(f"{case_d_batch.receipt(path)['sha256']}  {path.resolve()}\n" for path in unique.values()),
        encoding="utf-8",
    )


def pre_smoke_fixture(tmp_path: Path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    smoke_dir = tmp_path / "smoke"
    pre_smoke = tmp_path / "smoke.case-d-pre-smoke.json"
    case_d_batch.validate_before_smoke(
        pre_smoke,
        case_dir,
        smoke_dir,
        runner,
        sources,
        **submission,
        verifier=lambda _path: plan,
    )
    smoke_dir.mkdir()
    write_wrapper_checksums(smoke_dir / "case-d-wrapper-sha256.txt", sources, submission)
    return case_dir, runner, sources, plan, smoke_dir, pre_smoke


def reserve(tmp_path: Path, *, symlink_case_input=None, **changes):
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
        "wrapper_sha256_path": smoke_dir / "case-d-wrapper-sha256.txt",
        "server_pid": 500,
        "verifier": lambda _path: plan,
    }
    if symlink_case_input is not None:
        detached = tmp_path / f"detached-{symlink_case_input}"
        (case_dir / symlink_case_input).replace(detached)
        (case_dir / symlink_case_input).symlink_to(detached)
    values.update(changes)
    phase = case_d_batch.reserve_phase(smoke_dir / "case-d-phase.json", **values)
    return case_dir, runner, sources, plan, smoke_dir, pre_smoke, phase


def test_pre_smoke_requires_pristine_preparation_and_every_launch_hash(tmp_path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    output = tmp_path / "smoke.case-d-pre-smoke.json"
    result = case_d_batch.validate_before_smoke(
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
    assert set(result["runtime_sources"]) == set(case_d_batch.REQUIRED_RUNTIME_KEYS)

    changed = sources["hpc/case_d_batch.py"]
    changed.write_text("drift\n", encoding="utf-8")
    with pytest.raises(ValueError, match="launch source"):
        case_d_batch.validate_before_smoke(
            tmp_path / "other-smoke.case-d-pre-smoke.json",
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
        case_d_batch.validate_before_smoke(
            tmp_path / "smoke.case-d-pre-smoke.json",
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
        case_d_batch.validate_before_smoke(
            tmp_path / "smoke.case-d-pre-smoke.json",
            case_dir,
            smoke,
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )
    incomplete = dict(sources)
    incomplete.pop("configs/local_scout.toml")
    with pytest.raises(ValueError, match="incomplete"):
        case_d_batch.validate_runtime_sources(plan, incomplete)


def test_missing_native_config_fails_before_smoke_or_pre_smoke_receipt(tmp_path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    sources.pop("configs/local_scout.toml")
    output = tmp_path / "smoke.case-d-pre-smoke.json"
    smoke_dir = tmp_path / "smoke"

    with pytest.raises(ValueError, match="incomplete"):
        case_d_batch.validate_before_smoke(
            output,
            case_dir,
            smoke_dir,
            runner,
            sources,
            **submission,
            verifier=lambda _path: plan,
        )

    assert not output.exists()
    assert not smoke_dir.exists()


def test_parse_runtime_sources_requires_exact_absolute_unique_mapping(tmp_path):
    _, _, sources, _, _ = prepared(tmp_path)
    rows = [[key, str(path)] for key, path in sources.items()]
    assert case_d_batch.parse_runtime_sources(rows) == sources
    with pytest.raises(ValueError, match="Duplicate"):
        case_d_batch.parse_runtime_sources(rows + [rows[0]])
    with pytest.raises(ValueError, match="incomplete"):
        case_d_batch.parse_runtime_sources(rows[:-1])


def test_validation_rejects_symlinked_launch_inputs_before_verification(tmp_path):
    case_dir, runner, sources, plan, submission = prepared(tmp_path)
    config_alias = tmp_path / "local-scout-alias.toml"
    config_alias.symlink_to(sources["configs/local_scout.toml"])
    aliased_sources = dict(sources)
    aliased_sources["configs/local_scout.toml"] = config_alias
    rows = [[key, str(path)] for key, path in aliased_sources.items()]
    with pytest.raises(ValueError, match="Invalid Case D runtime source"):
        case_d_batch.parse_runtime_sources(rows)
    with pytest.raises(ValueError, match="physical and canonical"):
        case_d_batch.validate_runtime_sources(plan, aliased_sources)

    runner_alias = tmp_path / "run-case-d-alias.py"
    runner_alias.symlink_to(runner)
    with pytest.raises(ValueError, match="runner must be.*physical canonical"):
        case_d_batch.validate_plan_shape(case_dir, runner_alias, run_verifier=False)

    case_alias = tmp_path / "case-alias"
    case_alias.symlink_to(case_dir, target_is_directory=True)
    verifier_calls = []
    with pytest.raises(ValueError, match="directory must be physical and canonical"):
        case_d_batch.validate_before_smoke(
            tmp_path / "smoke.case-d-pre-smoke.json",
            case_alias,
            tmp_path / "smoke",
            runner,
            sources,
            **submission,
            verifier=lambda path: verifier_calls.append(path) or plan,
        )
    assert verifier_calls == []


@pytest.mark.parametrize("filename", ["plan.json", "preparation.json"])
def test_validate_cli_rejects_symlinked_preparation_input(tmp_path, filename):
    case_dir, runner, sources, _plan, submission = prepared(tmp_path)
    detached = tmp_path / f"detached-{filename}"
    (case_dir / filename).replace(detached)
    (case_dir / filename).symlink_to(detached)
    output = tmp_path / "smoke.case-d-pre-smoke.json"
    arguments = [
        "validate",
        "--output",
        str(output),
        "--case-dir",
        str(case_dir),
        "--smoke-dir",
        str(tmp_path / "smoke"),
        "--runner-path",
        str(runner),
        "--site-path",
        str(submission["site_path"]),
        "--site-sha256",
        submission["site_sha256"],
        "--manifest-path",
        str(submission["manifest_path"]),
        "--manifest-sha256",
        submission["manifest_sha256"],
        "--executed-wrapper-path",
        str(submission["executed_wrapper_path"]),
    ]
    for key, path in sources.items():
        arguments.extend(("--runtime-source", key, str(path)))
    with pytest.raises(ValueError, match="non-symlink regular files"):
        case_d_batch.main(arguments)
    assert not output.exists()


def test_request_free_verifier_subprocess_receives_no_credentials(tmp_path, monkeypatch):
    case_dir, runner, _sources, plan, _submission = prepared(tmp_path)
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-secret")
    monkeypatch.setenv("GROQ_API_KEY", "remote-secret")
    seen = {}

    def run(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(case_d_batch.subprocess, "run", run)
    assert case_d_batch.validate_plan_shape(case_dir, runner, run_verifier=True) == plan
    assert seen["command"] == [
        case_d_batch.sys.executable,
        str(runner),
        "verify",
        str(case_dir),
    ]
    assert seen["kwargs"]["stdin"] is case_d_batch.subprocess.DEVNULL
    assert seen["kwargs"]["env"]["HF_HUB_OFFLINE"] == "1"
    assert seen["kwargs"]["env"]["PYTHONPATH"].split(case_d_batch.os.pathsep) == [
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
    assert case_d_batch.parse_slurm_duration(raw) == seconds


@pytest.mark.parametrize("raw", ["", " 01:00", "01:60", "x", "1-24:00:00"])
def test_parse_slurm_duration_rejects_malformed_values(raw):
    with pytest.raises(ValueError):
        case_d_batch.parse_slurm_duration(raw)


def test_shared_smoke_helpers_bind_case_d_without_aliasing_another_case():
    records = preflight.limit_records(native=True, case_a_mode=False, case_d_mode=True)
    assert records["enclosing_case_d_limits"] == case_d_batch.expected_preflight_limits()[1]
    assert not any(key.startswith("enclosing_case_") and key != "enclosing_case_d_limits" for key in records)
    assert ("SCOUT_CASE_D_MODE", "SCOUT_CASE_D_DIR") in native_smoke.FROZEN_CASE_BINDINGS
    with pytest.raises(ValueError, match="more than one case"):
        preflight.limit_records(
            native=True,
            case_a_mode=False,
            case_b_mode=True,
            case_d_mode=True,
        )


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
    assert set(phase["runtime_sources"]) == set(case_d_batch.REQUIRED_RUNTIME_KEYS)


@pytest.mark.parametrize("filename", ["plan.json", "preparation.json"])
def test_scheduler_gate_rejects_symlinked_preparation_input(tmp_path, filename):
    with pytest.raises(ValueError, match="non-symlink regular files"):
        reserve(tmp_path, symlink_case_input=filename)
    assert not (tmp_path / "smoke" / "case-d-phase.json").exists()


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
    smoke_limits, enclosing_limits = case_d_batch.expected_preflight_limits()
    dump(
        smoke_dir / "preflight.json",
        {
            "protocol": case_d_batch.SMOKE_PROTOCOL,
            "slurm_job_id": job_id,
            "limits": smoke_limits,
            "enclosing_case_d_limits": enclosing_limits,
        },
    )
    dump(
        smoke_dir / "smoke.json",
        {"protocol": case_d_batch.SMOKE_PROTOCOL, "status": "passed", "requests_started": 4},
    )
    dump(
        smoke_dir / "native-smoke.json",
        {
            "protocol": case_d_batch.NATIVE_PROTOCOL,
            "status": "passed",
            "slurm_job_id": job_id,
            "native_requests_started": 3,
            "checks": {"no_online_auditors": True},
        },
    )
    dump(
        smoke_dir / "case-d-cleanup.json",
        {
            "protocol": case_d_batch.PROTOCOL,
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
    (smoke_dir / "case-d-wrapper-exit-code.txt").write_text(f"{wrapper_exit}\n", encoding="utf-8")
    paths = {
        "phase_path": smoke_dir / "case-d-phase.json",
        "pre_smoke_path": pre_smoke,
        "runner_path": runner,
        "preflight_path": smoke_dir / "preflight.json",
        "smoke_path": smoke_dir / "smoke.json",
        "native_path": smoke_dir / "native-smoke.json",
        "case_summary_path": case_dir / "case-summary.json",
        "case_plan_path": case_dir / "plan.json",
        "execution_path": case_dir / "execution.json",
        "wrapper_exit_path": smoke_dir / "case-d-wrapper-exit-code.txt",
        "wrapper_sha256_path": smoke_dir / "case-d-wrapper-sha256.txt",
        "server_check_path": smoke_dir / "case-a-server-check.json",
        "cleanup_path": smoke_dir / "case-d-cleanup.json",
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
            "protocol": case_d_batch.SERVER_CHECK_PROTOCOL,
            "status": "passed",
            "slurm_job_id": job_id,
            "endpoint": plan["config"]["base_url"],
            "server_pid": 500,
        },
    )
    dump(
        paths["execution_path"],
        {
            "protocol": case_d_batch.CASE_PROTOCOL,
            "mode": "live_scout",
            "plan": case_d_batch.receipt(case_dir / "plan.json"),
            "serving": binding,
            "status": "reserved_before_workers",
        },
    )
    slots = []
    worker_pids = [101, 102, 103, 104]
    for condition, count, worker_pid in zip(case_d_batch.CONDITIONS, counts, worker_pids, strict=True):
        expected = case_d_batch.EXPECTED_OUTCOMES[condition]
        carriers = case_d_batch.EXPECTED_CARRIERS[condition]
        outcome = {
            "case_protocol": case_d_batch.CASE_PROTOCOL,
            "scientific_protocol": case_d_batch.SCIENTIFIC_PROTOCOL,
            "analysis_status": "determinate",
            "assigned_carrier_ids": case_d_batch.EXPECTED_CARRIERS[condition],
            "observed_target_outcome": expected,
            "source_exposure": [
                {
                    "file_id": file_id,
                    "binding_verified": True,
                    "expected_content_exposed": True,
                }
                for file_id in ("1", "2")
            ],
            "expected_source_ids_exposed": ["1", "2"],
            "both_source_outputs_exposed": True,
            "native_create_state_binding": {
                "confirmed": expected,
                "multiplicity_valid": expected,
                "matching_exact_creation_count": 1 if expected else 0,
                "exact_target_proposal_count": 1 if expected else 0,
            },
            "target_proposals": (
                [
                    {
                        "exact_target_arguments": True,
                        "executed_successfully": True,
                        "pre_sink_carrier_witness_ids": carriers,
                    }
                ]
                if expected
                else []
            ),
            "utility": {"evaluable": True, "passed": True},
        }
        terminal = {
            "protocol": case_d_batch.CASE_PROTOCOL,
            "condition": condition,
            "status": "completed",
            "pid": worker_pid,
            "primary_trajectory_complete": True,
            "outcome_analysis_complete": True,
            "outcome": outcome,
        }
        dump(case_dir / f"{condition}-terminal.json", terminal)
        attempts = case_dir / "runs" / condition / "sdk-attempts.jsonl"
        attempts.parent.mkdir(parents=True)
        dump(attempts.parent / "case-d-outcome.json", outcome)
        (attempts.parent / "report.html").write_text(
            f"<!doctype html><title>Case D {condition}</title>", encoding="utf-8"
        )
        attempts.write_text(
            "".join(json.dumps({"sdk_attempt": index}) + "\n" for index in range(1, count + 1)),
            encoding="utf-8",
        )
        slots.append(
            {
                "condition": condition,
                "terminal": terminal,
                "captured_sdk_attempts": count,
                "worker_pid": worker_pid,
                "process_identity_status": "verified_distinct_worker",
                "process_status": "terminal",
                "returncode": 0,
                "causal_v2": {
                    "status": "exported_request_free",
                    "model_requests": 0,
                },
            }
        )
    dump(
        paths["case_summary_path"],
        {
            "protocol": case_d_batch.CASE_PROTOCOL,
            "scientific_protocol": case_d_batch.SCIENTIFIC_PROTOCOL,
            "status": "completed",
            "real_llm": True,
            "plan": case_d_batch.receipt(case_dir / "plan.json"),
            "conditions": list(case_d_batch.CONDITIONS),
            "slots": slots,
            "all_assignments_accounted": True,
            "all_assigned_processes_terminal": True,
            "planned_slots": 4,
            "terminal_slots": 4,
            "primary_trajectory_batch_complete": True,
            "worker_processing_complete": True,
            "completed_primary_trajectories": 4,
            "determinate_outcome_analyses": 4,
            "successful_request_free_causal_exports": 4,
            "captured_primary_sdk_attempts": sum(counts),
            "primary_sdk_attempt_ceiling": 16,
            "scientific_batch_complete": True,
            "worker_pids": worker_pids,
            "actual_worker_processes": 4,
            "verified_worker_identities": 4,
            "distinct_worker_processes": 4,
            "all_worker_processes_distinct": True,
            "joint_pattern": {
                "prospective_outcomes": case_d_batch.EXPECTED_OUTCOMES,
                "arm_outcomes": case_d_batch.EXPECTED_OUTCOMES,
                "pattern_matches": True,
                "redundancy_pattern_interpretation_eligible": True,
                "interpretation_blocks": [],
                "all_arms_distinct_verified_workers": True,
                "status": "observed_pattern_consistent_with_redundant_sufficiency",
                "arm_source_exposure": {
                    arm: {"observed_source_ids": ["1", "2"], "balanced": True}
                    for arm in case_d_batch.CONDITIONS
                },
                "arm_utility": {
                    arm: {"evaluable": True, "passed": True}
                    for arm in case_d_batch.CONDITIONS
                },
                "pre_sink_carrier_witnesses": {
                    arm: {
                        "required_carrier_ids": case_d_batch.EXPECTED_CARRIERS[arm],
                        "observed_carrier_ids": case_d_batch.EXPECTED_CARRIERS[arm],
                        "complete": True,
                    }
                    for arm in case_d_batch.CONDITIONS
                },
            },
        },
    )
    (case_dir / "index.html").write_text(
        "<!doctype html><h1>Scout Case D: redundant sources</h1>", encoding="utf-8"
    )
    paths["binding_validator"] = lambda _preflight, _url: binding
    return smoke_dir, paths


def test_final_receipt_accounts_for_all_three_request_sources(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "complete_all_slots_terminal"
    assert result["requests"] == {
        "synthetic": 4,
        "native": 3,
        "case": 10,
        "total": 17,
        "limit": 24,
        "per_case_slot": {"both": 1, "a_only": 2, "b_only": 3, "neither": 4},
    }
    with pytest.raises(FileExistsError):
        case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)


def test_final_receipt_rejects_per_arm_request_overrun(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path)
    attempts = paths["case_plan_path"].parent / "runs" / "both" / "sdk-attempts.jsonl"
    attempts.write_text(
        "".join(json.dumps({"sdk_attempt": index}) + "\n" for index in range(1, 6)),
        encoding="utf-8",
    )
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_nonzero_wrapper_exit_preserves_determinate_terminal_failure(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, wrapper_exit=1)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "terminal_case_runner_failed"
    assert result["wrapper_exit_code"] == 1
    assert result["requests"]["total"] == 17


def test_partial_arm_failure_preserves_terminal_counts_and_unknown(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, wrapper_exit=1)
    summary = json.loads(paths["case_summary_path"].read_text(encoding="utf-8"))
    failed = next(row for row in summary["slots"] if row["condition"] == "b_only")
    terminal = {
        "protocol": case_d_batch.CASE_PROTOCOL,
        "condition": "b_only",
        "status": "failed",
        "pid": failed["worker_pid"],
        "primary_trajectory_complete": False,
        "outcome_analysis_complete": False,
        "outcome": {
            "case_protocol": case_d_batch.CASE_PROTOCOL,
            "scientific_protocol": case_d_batch.SCIENTIFIC_PROTOCOL,
            "analysis_status": "unknown",
            "observed_target_outcome": None,
        },
    }
    failed["terminal"] = terminal
    dump(paths["case_plan_path"].parent / "b_only-terminal.json", terminal)
    summary.update(
        status="failed",
        primary_trajectory_batch_complete=False,
        completed_primary_trajectories=3,
        determinate_outcome_analyses=3,
        scientific_batch_complete=False,
    )
    dump(paths["case_summary_path"], summary)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "terminal_case_runner_failed"
    assert result["requests"]["per_case_slot"]["b_only"] == 3
    assert result["scientific_outcome"]["case_started"] is True


@pytest.mark.parametrize(
    "mutation",
    (
        "false_both",
        "utility_false",
        "absent_exposure",
        "native_target_gap",
        "carrier_witness_gap",
        "pattern_eligibility_gap",
    ),
)
def test_terminal_completion_rejects_missing_redundancy_evidence(tmp_path, mutation):
    smoke_dir, paths = terminal_fixture(tmp_path)
    case_root = paths["case_plan_path"].parent
    summary = json.loads(paths["case_summary_path"].read_text(encoding="utf-8"))
    condition = "both" if mutation == "false_both" else "a_only"
    row = next(item for item in summary["slots"] if item["condition"] == condition)
    outcome = row["terminal"]["outcome"]
    joint = summary["joint_pattern"]
    if mutation == "false_both":
        outcome["observed_target_outcome"] = False
        outcome["native_create_state_binding"].update(
            confirmed=False,
            multiplicity_valid=False,
            matching_exact_creation_count=0,
            exact_target_proposal_count=0,
        )
        outcome["target_proposals"] = []
        joint["arm_outcomes"]["both"] = False
        joint["pattern_matches"] = False
    elif mutation == "utility_false":
        outcome["utility"]["passed"] = False
        joint["arm_utility"][condition]["passed"] = False
    elif mutation == "absent_exposure":
        outcome["source_exposure"] = outcome["source_exposure"][:1]
        outcome["expected_source_ids_exposed"] = ["1"]
        outcome["both_source_outputs_exposed"] = False
        joint["arm_source_exposure"][condition] = {
            "observed_source_ids": ["1"],
            "balanced": False,
        }
    elif mutation == "native_target_gap":
        outcome["native_create_state_binding"]["confirmed"] = False
        outcome["native_create_state_binding"]["multiplicity_valid"] = False
        outcome["native_create_state_binding"]["matching_exact_creation_count"] = 0
    elif mutation == "carrier_witness_gap":
        outcome["target_proposals"][0]["pre_sink_carrier_witness_ids"] = []
        joint["pre_sink_carrier_witnesses"][condition].update(
            observed_carrier_ids=[], complete=False
        )
    joint["redundancy_pattern_interpretation_eligible"] = False
    joint["interpretation_blocks"] = [mutation]
    joint["status"] = "outcome_pattern_recorded_redundancy_interpretation_withheld"
    dump(case_root / f"{condition}-terminal.json", row["terminal"])
    dump(case_root / f"runs/{condition}/case-d-outcome.json", outcome)
    dump(paths["case_summary_path"], summary)

    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "terminal_case_runner_failed"
    acceptance = result["scientific_outcome"]["terminal_acceptance"]
    assert acceptance["eligible"] is False
    assert acceptance["blocking_conditions"]


@pytest.mark.parametrize("mutation", ["aggregate_report", "arm_report", "arm_outcome", "pattern"])
def test_started_case_validates_case_d_outcomes_and_html(tmp_path, mutation):
    smoke_dir, paths = terminal_fixture(tmp_path)
    case_root = paths["case_plan_path"].parent
    if mutation == "aggregate_report":
        (case_root / "index.html").write_text("foreign report", encoding="utf-8")
    elif mutation == "arm_report":
        (case_root / "runs/a_only/report.html").unlink()
    elif mutation == "arm_outcome":
        value = json.loads((case_root / "runs/b_only/case-d-outcome.json").read_text(encoding="utf-8"))
        value["assigned_carrier_ids"] = ["1"]
        dump(case_root / "runs/b_only/case-d-outcome.json", value)
    else:
        value = json.loads(paths["case_summary_path"].read_text(encoding="utf-8"))
        value["joint_pattern"]["prospective_outcomes"]["neither"] = True
        dump(paths["case_summary_path"], value)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


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
        source = Path(phase["runtime_sources"]["hpc/case_d_batch.py"]["path"])
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
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
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
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_unstarted_terminal_rejects_cleanup_server_pid_mismatch(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, remaining="01:04:59", wrapper_exit=3)
    cleanup = json.loads(paths["cleanup_path"].read_text(encoding="utf-8"))
    cleanup["server_pid"] = 501
    dump(paths["cleanup_path"], cleanup)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
    assert result["status"] == "incomplete"
    assert result["error_type"] == "ValueError"


def test_unstarted_terminal_records_smoke_without_server_or_case_calls(tmp_path):
    smoke_dir, paths = terminal_fixture(tmp_path, remaining="01:04:59", wrapper_exit=3)
    result = case_d_batch.finalize(smoke_dir / "case-d-batch-summary.json", **paths)
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
    wrapper = (HPC / "scout-smoke-case-d.sbatch").read_text(encoding="utf-8")
    source_site = 'source "$CASE_D_SITE_FILE"'
    canonicalize = 'CASE_D_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")'
    compare = 'cmp --silent -- "$CASE_D_EXECUTED_WRAPPER" "$CASE_D_CANONICAL_WRAPPER"'
    helper_check = "for helper in scout-smoke-case-d.sbatch scout-smoke.sbatch case_d_batch.py"
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
        'CASE_D_RUNNER="$CASE_D_BUNDLE_ROOT/scripts/run_case_d_scout.py"',
        'CASE_D_CHAT_TEMPLATE="$CASE_D_HPC_DIR/tool_chat_template_llama4_pythonic_typed_v1.jinja"',
        '[[ "$SCOUT_CASE_D_RUNNER" == "$CASE_D_RUNNER" && -f "$CASE_D_RUNNER"',
        '[[ "$SCOUT_CHAT_TEMPLATE" == "$CASE_D_CHAT_TEMPLATE" && -f "$CASE_D_CHAT_TEMPLATE"',
        '[[ -d "$SCOUT_CASE_D_DIR" && ! -L "$SCOUT_CASE_D_DIR"',
        "export SCOUT_CASE_D_DIR",
        'export SCOUT_CHAT_TEMPLATE="$CASE_D_CHAT_TEMPLATE"',
        '--executed-wrapper-path "$CASE_D_EXECUTED_WRAPPER"',
        '--wrapper-sha256-path "$CASE_D_WRAPPER_SHA256"',
        '--server-pid "$SCOUT_SERVER_PID"',
        'export PYTHONPATH="$CASE_D_BUNDLE_ROOT/vendor/agentdojo/src:$CASE_D_BUNDLE_ROOT/src:$CASE_D_BUNDLE_ROOT/scripts"',
        '--runtime-source configs/local_scout.toml "$CASE_D_BUNDLE_ROOT/configs/local_scout.toml"',
        '"$CASE_D_BUNDLE_ROOT/configs/local_scout.toml"',
    ):
        assert fragment in wrapper
    native_config = '--runtime-source configs/local_scout.toml'
    pre_smoke_validation = '"$CASE_D_HPC_DIR/case_d_batch.py" validate'
    server_start = 'source "$CASE_D_HPC_DIR/scout-smoke.sbatch"'
    assert (
        wrapper.index(native_config)
        < wrapper.index(pre_smoke_validation)
        < wrapper.index(server_start)
    )


def test_wrapper_is_bounded_same_allocation_and_uses_shared_server_check():
    wrapper = (HPC / "scout-smoke-case-d.sbatch").read_text(encoding="utf-8")
    for fragment in (
        "#SBATCH --time=02:00:00",
        "#SBATCH --gpus-per-node=a100:4",
        "export SCOUT_NATIVE_SMOKE=1",
        "export SCOUT_CASE_D_MODE=1",
        'source "$CASE_D_HPC_DIR/scout-smoke.sbatch"',
        "export SCOUT_SERVER_PID",
        "squeue -h -j \"$SLURM_JOB_ID\" -o '%i|%L|%l'",
        '"$CASE_D_HPC_DIR/case_a_batch.py" server-check',
        "case-a-server-check.json",
        "sleep 3600",
        'kill -TERM -- "-$CASE_D_PROCESS_PID"',
        'kill -KILL -- "-$CASE_D_PROCESS_PID"',
        "case-d-cleanup.json",
        "case-d-wrapper-exit-code.txt",
        "case-d-batch-summary.json",
        "job-exit-code.txt",
        "unset SCOUT_SITE_FILE",
        "(( SCOUT_SERVER_PID <= 1 ))",
        "(( CASE_D_PROCESS_PID > 1 ))",
        "valid_server_pid=true",
    ):
        assert fragment in wrapper
    old_pid_guard = "[[ ${SCOUT_SERVER_PID:-} =~ ^[1-9][0-9]*$ ]] || exit 2"
    pid_guard = "if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then"
    smoke_source = 'source "$CASE_D_HPC_DIR/scout-smoke.sbatch"'
    post_smoke_guard = '[[ "$SCOUT_HPC_DIR" == "$CASE_D_HPC_DIR"'
    assert old_pid_guard not in wrapper
    assert wrapper.index(smoke_source) < wrapper.index(pid_guard) < wrapper.index(post_smoke_guard)
    assert wrapper.index("SCOUT_SERVER_PID=''") < wrapper.index("exit 2", wrapper.index(pid_guard))
    assert (
        wrapper.index('source "$CASE_D_HPC_DIR/scout-smoke.sbatch"')
        < wrapper.index('"$CASE_D_HPC_DIR/case_a_batch.py" server-check')
        < wrapper.index('"$CASE_D_RUNNER" run')
    )
    assert '"$SCOUT_CASE_D_RUNNER" run' not in wrapper
    assert (
        wrapper.index("export SCOUT_CASE_D_DIR")
        < wrapper.index('source "$CASE_D_HPC_DIR/scout-smoke.sbatch"')
    )
    assert case_d_batch.TOTAL_REQUEST_LIMIT == 24
    assert case_d_batch.CASE_REQUEST_LIMIT == 16
    assert case_d_batch.CASE_SLOT_REQUEST_LIMIT == 4


def test_case_d_source_inventory_names_every_live_runtime_input():
    script = (HPC.parent / "scripts" / "run_case_d_scout.py").read_text(encoding="utf-8")
    wrapper = (HPC / "scout-smoke-case-d.sbatch").read_text(encoding="utf-8")
    for key in case_d_batch.REQUIRED_RUNTIME_KEYS:
        assert key in wrapper
    for name in (
        "CASE-D-SCOUT-V1.md",
        "case_d_scout_v1.toml",
        "case_d_batch.py",
        "scout-smoke-case-d.sbatch",
    ):
        assert name in script
    assert hashlib.sha256((HPC / "scout-smoke.sbatch").read_bytes()).hexdigest() == (
        "1e2caa7bd21310f7ce04af46607ad0e077abb56f2ba117691f5ee466a584ee1a"
    )
