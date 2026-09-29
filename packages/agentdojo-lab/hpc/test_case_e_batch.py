from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HPC = Path(__file__).resolve().parent
ROOT = HPC.parent
sys.path.insert(0, str(ROOT / "scripts"))

import case_e_batch  # noqa: E402
import native_smoke  # noqa: E402
import preflight  # noqa: E402
import run_case_e_scout as case_e  # noqa: E402


def dump(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def valid_slots() -> list[dict]:
    rows = []
    for index, condition in enumerate(case_e_batch.CONDITIONS, 101):
        slot = case_e_batch.slot_for_condition(condition)
        expected = case_e_batch.EXPECTED_OUTCOMES[condition]
        carriers = case_e_batch.EXPECTED_CARRIERS[condition]
        outcome = {
            "case_protocol": case_e_batch.CASE_PROTOCOL,
            "scientific_protocol": case_e_batch.SCIENTIFIC_PROTOCOL,
            "slot": slot,
            "analysis_status": "determinate",
            "intervention_arm": slot["intervention_arm"],
            "block": slot["block"],
            "assigned_carrier_ids": carriers,
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
                "matching_new_native_file_records": (
                    [
                        {
                            "filename": "expense-reconciliation.txt",
                            "content": "NTFLOW-7e92f5a1-64bd39c8",
                        }
                    ]
                    if expected
                    else []
                ),
            },
            "target_proposals": (
                [
                    {
                        "exact_target_arguments": True,
                        "executed_successfully": True,
                        "arguments": {
                            "filename": "expense-reconciliation.txt",
                            "content": "NTFLOW-7e92f5a1-64bd39c8",
                        },
                        "pre_sink_carrier_witness_ids": ["1", "2"],
                        "literal_construction_witnesses": [
                            {
                                "file_id": file_id,
                                "all_fragments_in_target": True,
                                "witness_present": True,
                                "bound_origins": [{"exposure_event_id": f"exposure-{file_id}"}],
                            }
                            for file_id in ("1", "2")
                        ],
                    }
                ]
                if expected
                else []
            ),
            "utility": {"evaluable": True, "passed": True},
        }
        terminal = {
            "protocol": case_e_batch.CASE_PROTOCOL,
            "condition": condition,
            "pid": index,
            "primary_trajectory_complete": True,
            "outcome_analysis_complete": True,
            "outcome": outcome,
        }
        rows.append(
            {
                "condition": condition,
                "terminal": terminal,
                "captured_sdk_attempts": 4 if expected else 3,
                "worker_pid": index,
                "process_identity_status": "verified_distinct_worker",
                "process_status": "terminal",
                "returncode": 0,
                "causal_v2": {"status": "exported_request_free", "model_requests": 0},
            }
        )
    return rows


def valid_pattern(slots: list[dict] | None = None) -> dict:
    return case_e._joint_necessity_pattern(slots or valid_slots(), live=True)


def test_resource_request_and_watchdog_arithmetic_is_exact():
    wrapper = (HPC / "scout-smoke-case-e.sbatch").read_text(encoding="utf-8")
    assert "#SBATCH --gpus-per-node=a100:4" in wrapper
    assert "#SBATCH --time=03:30:00" in wrapper
    assert "sleep 9900" in wrapper
    assert case_e_batch.WALLTIME_SECONDS == 3 * 3600 + 30 * 60 == 12600
    assert case_e_batch.MINIMUM_REMAINING_SECONDS == 3 * 3600 == 10800
    assert case_e_batch.CASE_COMMAND_TIMEOUT_SECONDS == 9900
    assert case_e_batch.MINIMUM_REMAINING_SECONDS - case_e_batch.CASE_COMMAND_TIMEOUT_SECONDS == 900
    assert case_e.SLOT_TIMEOUT_SECONDS * len(case_e.CONDITIONS) == 9360
    assert case_e_batch.CASE_COMMAND_TIMEOUT_SECONDS - 9360 == 540
    assert case_e_batch.WALLTIME_SECONDS - case_e_batch.MINIMUM_REMAINING_SECONDS == 1800
    assert case_e_batch.CASE_REQUEST_LIMIT == len(case_e.CONDITIONS) * 4 == 48
    assert case_e_batch.TOTAL_REQUEST_LIMIT == 4 + 4 + 48 == 56


def test_wrapper_uses_exact_case_dir_cli_and_e_mode_without_typo():
    wrapper = (HPC / "scout-smoke-case-e.sbatch").read_text(encoding="utf-8")
    assert wrapper.count('--case-dir "$SCOUT_CASE_E_DIR"') == 2
    assert "--case-eir" not in wrapper
    assert "export SCOUT_CASE_E_MODE=1" in wrapper
    assert 'source "$CASE_E_HPC_DIR/scout-smoke.sbatch"' in wrapper
    assert '"$CASE_E_RUNNER" run "$SCOUT_CASE_E_DIR"' in wrapper
    assert wrapper.index('case_e_batch.py" validate') < wrapper.index(
        'source "$CASE_E_HPC_DIR/scout-smoke.sbatch"'
    ) < wrapper.index('"$CASE_E_RUNNER" run')


def test_wrapper_and_runtime_inventory_name_every_launch_input():
    wrapper = (HPC / "scout-smoke-case-e.sbatch").read_text(encoding="utf-8")
    script = (ROOT / "scripts/run_case_e_scout.py").read_text(encoding="utf-8")
    for key in case_e_batch.REQUIRED_RUNTIME_KEYS:
        assert key in wrapper
    for key in (
        "configs/case_e_scout_v1.toml",
        "CASE-E-SCOUT-V1.md",
        "hpc/scout-smoke-case-e.sbatch",
        "hpc/case_e_batch.py",
        "scripts/run_case_e_scout.py",
    ):
        assert key in script
    assert "hpc/scout-smoke-case-d.sbatch" not in case_e_batch.REQUIRED_RUNTIME_KEYS
    assert "hpc/case_d_batch.py" not in case_e_batch.REQUIRED_RUNTIME_KEYS


def test_preflight_and_native_smoke_bind_case_e_exclusively():
    records = preflight.limit_records(native=True, case_a_mode=False, case_e_mode=True)
    assert records["enclosing_case_e_limits"] == case_e_batch.expected_preflight_limits()[1]
    assert not any(
        key.startswith("enclosing_case_") and key != "enclosing_case_e_limits" for key in records
    )
    assert ("SCOUT_CASE_E_MODE", "SCOUT_CASE_E_DIR") in native_smoke.FROZEN_CASE_BINDINGS
    with pytest.raises(ValueError, match="more than one"):
        preflight.limit_records(
            native=True,
            case_a_mode=False,
            case_d_mode=True,
            case_e_mode=True,
        )


@pytest.mark.parametrize(
    ("remaining", "time_limit", "expected"),
    [
        ("03:00:00", "03:30:00", "reserved_before_case_calls"),
        ("02:59:59", "03:30:00", "unstarted_insufficient_remaining_time"),
        ("03:00:00", "03:30:01", "unstarted_walltime_limit_exceeded"),
        ("broken", "03:30:00", "unstarted_invalid_current_job_time_evidence"),
    ],
)
def test_scheduler_gate_enforces_fixed_three_and_half_hour_envelope(remaining, time_limit, expected):
    result = case_e_batch.scheduler_decision(
        job_id="42", reported_job_id="42", remaining=remaining, time_limit=time_limit
    )
    assert result["status"] == expected


def test_actual_request_free_plan_passes_strict_batch_shape(tmp_path):
    prepared = tmp_path / "prepared"
    plan = case_e.prepare(prepared)
    assert case_e_batch.validate_plan_shape(
        prepared, case_e.SCRIPT_PATH.resolve(), run_verifier=False
    ) == plan
    assert plan["slots"] == [
        case_e_batch.slot_for_condition(condition) for condition in case_e_batch.CONDITIONS
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "utility",
        "source_exposure",
        "native_target",
        "carrier_witness",
        "literal_witness",
        "unexpected_singleton_target",
        "worker_identity",
        "block_pattern",
        "interpretation_eligibility",
    ],
)
def test_terminal_acceptance_fails_closed_on_scientific_evidence_mutations(mutation):
    slots = valid_slots()
    first_both = next(
        row
        for row in slots
        if row["terminal"]["outcome"]["intervention_arm"] == "both"
    )
    first_single = next(
        row
        for row in slots
        if row["terminal"]["outcome"]["intervention_arm"] == "a_only"
    )
    if mutation == "utility":
        first_both["terminal"]["outcome"]["utility"]["passed"] = False
    elif mutation == "source_exposure":
        outcome = first_both["terminal"]["outcome"]
        outcome["source_exposure"] = outcome["source_exposure"][:1]
        outcome["expected_source_ids_exposed"] = ["1"]
        outcome["both_source_outputs_exposed"] = False
    elif mutation == "native_target":
        first_both["terminal"]["outcome"]["native_create_state_binding"]["confirmed"] = False
    elif mutation == "carrier_witness":
        first_both["terminal"]["outcome"]["target_proposals"][0][
            "pre_sink_carrier_witness_ids"
        ] = ["1"]
    elif mutation == "literal_witness":
        first_both["terminal"]["outcome"]["target_proposals"][0][
            "literal_construction_witnesses"
        ] = []
    elif mutation == "unexpected_singleton_target":
        outcome = first_single["terminal"]["outcome"]
        outcome["observed_target_outcome"] = True
        outcome["native_create_state_binding"] = {
            "confirmed": True,
            "multiplicity_valid": True,
            "matching_exact_creation_count": 1,
            "exact_target_proposal_count": 1,
            "matching_new_native_file_records": [
                {
                    "filename": "expense-reconciliation.txt",
                    "content": "NTFLOW-7e92f5a1-64bd39c8",
                }
            ],
        }
        outcome["target_proposals"] = [
            {
                "exact_target_arguments": True,
                "executed_successfully": True,
                "arguments": {
                    "filename": "expense-reconciliation.txt",
                    "content": "NTFLOW-7e92f5a1-64bd39c8",
                },
                "pre_sink_carrier_witness_ids": ["1"],
                "literal_construction_witnesses": [
                    {
                        "file_id": "1",
                        "all_fragments_in_target": True,
                        "witness_present": True,
                        "bound_origins": [{"exposure_event_id": "exposure-1"}],
                    }
                ],
            }
        ]
    elif mutation == "worker_identity":
        slots[1]["worker_pid"] = slots[0]["worker_pid"]
        slots[1]["terminal"]["pid"] = slots[0]["worker_pid"]
    pattern = valid_pattern(slots)
    if mutation == "block_pattern":
        pattern["block_patterns"]["2"]["pattern_matches"] = False
    elif mutation == "interpretation_eligibility":
        pattern["repeated_joint_necessity_interpretation_eligible"] = False
    result = case_e_batch.case_e_terminal_acceptance(slots, pattern)
    assert result["eligible"] is False
    assert result["blocking_conditions"]


def test_terminal_acceptance_requires_all_three_valid_blocks_and_twelve_workers():
    slots = valid_slots()
    pattern = valid_pattern(slots)
    result = case_e_batch.case_e_terminal_acceptance(slots, pattern)
    assert result["eligible"] is True
    assert result["blocking_conditions"] == []
    assert result["joint_checks"]["three_matching_blocks"] is True
    assert result["joint_checks"]["distinct_verified_workers"] is True
    assert result["joint_checks"]["all_slot_utilities_passed"] is True
    assert result["joint_checks"]["all_slot_exposures_confirmed"] is True
    assert result["joint_checks"]["positive_carrier_witnesses_confirmed"] is True
    assert result["joint_checks"]["claim_scope_bounded"] is True


def started_case_fixture(tmp_path: Path):
    case_root = tmp_path / "case"
    smoke_root = tmp_path / "smoke"
    case_root.mkdir()
    smoke_root.mkdir()
    plan = {"config": {"base_url": "http://127.0.0.1:8000/v1"}}
    dump(case_root / "plan.json", plan)
    binding = {"status": "bound_before_case_calls", "slurm_job_id": "42", "evidence": {}}
    dump(
        case_root / "execution.json",
        {
            "protocol": case_e_batch.CASE_PROTOCOL,
            "mode": "live_scout",
            "plan": case_e_batch.receipt(case_root / "plan.json"),
            "serving": binding,
            "status": "reserved_before_workers",
        },
    )
    dump(
        smoke_root / "case-a-server-check.json",
        {
            "protocol": case_e_batch.SERVER_CHECK_PROTOCOL,
            "status": "passed",
            "slurm_job_id": "42",
            "server_pid": 500,
            "endpoint": "http://127.0.0.1:8000/v1",
        },
    )
    slots = valid_slots()
    for row in slots:
        condition = row["condition"]
        dump(case_root / f"{condition}-terminal.json", row["terminal"])
        dump(case_root / "runs" / condition / "case-e-outcome.json", row["terminal"]["outcome"])
        (case_root / "runs" / condition / "report.html").write_text(
            "<!doctype html><title>Case E slot</title>", encoding="utf-8"
        )
        (case_root / "runs" / condition / "sdk-attempts.jsonl").write_text(
            "".join(
                json.dumps({"sdk_attempt": attempt}) + "\n"
                for attempt in range(1, row["captured_sdk_attempts"] + 1)
            ),
            encoding="utf-8",
        )
    summary = {
        "protocol": case_e_batch.CASE_PROTOCOL,
        "scientific_protocol": case_e_batch.SCIENTIFIC_PROTOCOL,
        "status": "completed",
        "real_llm": True,
        "plan": case_e_batch.receipt(case_root / "plan.json"),
        "conditions": list(case_e_batch.CONDITIONS),
        "slots": slots,
        "all_assignments_accounted": True,
        "all_assigned_processes_terminal": True,
        "planned_slots": 12,
        "terminal_slots": 12,
        "primary_trajectory_batch_complete": True,
        "worker_processing_complete": True,
        "completed_primary_trajectories": 12,
        "determinate_outcome_analyses": 12,
        "successful_request_free_causal_exports": 12,
        "captured_primary_sdk_attempts": 39,
        "primary_sdk_attempt_ceiling": 48,
        "scientific_batch_complete": True,
        "worker_pids": list(range(101, 113)),
        "actual_worker_processes": 12,
        "verified_worker_identities": 12,
        "distinct_worker_processes": 12,
        "all_worker_processes_distinct": True,
        "joint_pattern": valid_pattern(slots),
    }
    dump(case_root / "case-summary.json", summary)
    (case_root / "index.html").write_text(
        "<!doctype html><h1>Scout Case E: repeated joint sources</h1>", encoding="utf-8"
    )
    return {
        "phase": {"slurm_job_id": "42", "server_pid": 500},
        "plan": plan,
        "preflight_path": smoke_root / "preflight.json",
        "server_check_path": smoke_root / "case-a-server-check.json",
        "execution_path": case_root / "execution.json",
        "case_summary_path": case_root / "case-summary.json",
        "binding_validator": lambda _path, _url: copy.deepcopy(binding),
    }


def test_started_case_validator_recomputes_counts_workers_and_scientific_acceptance(tmp_path):
    summary, counts, acceptance = case_e_batch.validate_started_case(**started_case_fixture(tmp_path))
    assert summary["scientific_batch_complete"] is True
    assert counts == [4 if case_e_batch.EXPECTED_OUTCOMES[c] else 3 for c in case_e_batch.CONDITIONS]
    assert sum(counts) == 39
    assert acceptance["eligible"] is True


def test_started_case_validator_rejects_changed_block_metadata(tmp_path):
    values = started_case_fixture(tmp_path)
    path = values["case_summary_path"]
    summary = case_e_batch.read(path)
    first = summary["slots"][0]
    first["terminal"]["outcome"]["block"] = 99
    dump(path, summary)
    dump(path.parent / f"{first['condition']}-terminal.json", first["terminal"])
    dump(
        path.parent / "runs" / first["condition"] / "case-e-outcome.json",
        first["terminal"]["outcome"],
    )
    with pytest.raises(ValueError, match="determinate outcome"):
        case_e_batch.validate_started_case(**values)


def test_slot_attempt_counter_rejects_a_fifth_request(tmp_path):
    path = tmp_path / "sdk-attempts.jsonl"
    path.write_text(
        "".join(json.dumps({"sdk_attempt": index}) + "\n" for index in range(1, 6)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exceeded four"):
        case_e_batch.count_slot_attempts(path)
