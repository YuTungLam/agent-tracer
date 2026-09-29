"""Deterministic controls for the frozen method-conformance evidence runner."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from agentdojo_lab import neurotaint_conformance as conformance


def result(
    *,
    exit_code=0,
    stdout=b"",
    stderr=b"",
    elapsed_ms=1,
    error_type=None,
    timed_out=False,
):
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_ms": elapsed_ms,
        "error_type": error_type,
        "timed_out": timed_out,
    }


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def test_frozen_matrix_maps_m1_through_m7_to_exact_unique_nodes():
    config, raw = conformance.load_config()
    cases = conformance.validate_config(config)
    assert raw.isascii()
    assert [milestone["id"] for milestone in config["milestones"]] == [
        "M1",
        "M2",
        "M3",
        "M4",
        "M5",
        "M6",
        "M7",
    ]
    assert len(cases) == 62
    assert len({case["id"] for case in cases}) == len(cases)
    assert len({case["node_id"] for case in cases}) == len(cases)
    assert all("::test_" in case["node_id"] for case in cases)
    assert all((conformance.ROOT / case["node_id"].split("::", 1)[0]).is_file() for case in cases)
    branches = {branch for case in cases for branch in case["branches"]}
    for required in {
        "tier1_disabled",
        "tier2_positive",
        "tier3_positive",
        "tier4_evaluated",
        "encoder_error",
        "source_budget_exceeded",
        "restored_memory_path",
        "single_source",
        "source_pair",
        "judge_yes",
        "judge_no",
        "judge_error",
        "judge_budget_exhausted",
        "before_runtime",
        "non_enforcing_sidecar",
        "artifact_tamper",
    }:
        assert required in branches
    assert all(case["live_judge_evidence"] is False for case in cases)
    assert config["live_judge_coverage"] == {
        "status": "not_evaluated_by_deterministic_conformance",
        "claimed": False,
        "required_for_deterministic_pass": False,
        "known_observation": (
            "The retained live M7 run reached an explicit Tier-2 hit and made zero eligible "
            "causal-judge requests."
        ),
        "next_evidence": (
            "A separate authorized live run must reach an eligible sink and produce a real "
            "isolated-judge receipt."
        ),
    }


def test_mocked_complete_run_records_every_exact_case_and_ascii_hashes(tmp_path):
    calls = []
    private_output = b"private-fixture-value"

    def fake(command, *, cwd, env, timeout_seconds):
        calls.append(tuple(command))
        assert cwd == conformance.ROOT
        assert timeout_seconds == 120
        assert Path(env["PYTHONPATH"].split(os.pathsep, 1)[0], "sitecustomize.py").is_file()
        assert not any(
            marker in name.upper()
            for name in env
            for marker in ("API_KEY", "SECRET", "PASSWORD", "CREDENTIAL")
        )
        node_id = command[-1]
        if "--collect-only" in command:
            return result(
                stdout=(node_id + "\n1 test collected in 0.01s\n").encode("ascii"),
                stderr=private_output,
            )
        return result(stdout=b"1 passed in 0.01s\n", stderr=private_output)

    output = tmp_path / "evidence"
    summary = conformance.run_conformance(output, process_runner=fake)
    rows = read_rows(output / "conformance-results.jsonl")
    assert summary["passed"] is False
    assert summary["status"] == "test_only"
    assert summary["execution_runner"] == "injected_test_runner"
    assert summary["counts"] == {"failed": 0, "passed": 62, "unknown": 0}
    assert len(rows) == len(calls) // 2 == 62
    assert all(row["collection"]["requested_node_collected"] for row in rows)
    assert all(row["execution"]["requested_node_executed"] for row in rows)
    assert all(row["collection"]["exit_code"] == row["execution"]["exit_code"] == 0 for row in rows)
    assert all(group["status"] == "passed" for group in summary["groups"])
    assert all(group["all_required_nodes_collected"] for group in summary["groups"])
    assert all(group["all_required_nodes_executed"] for group in summary["groups"])
    assert all(summary["source_integrity"].values())
    assert [row["sequence"] for row in rows] == list(range(1, 63))
    assert len({row["config_sha256"] for row in rows}) == 1
    assert len({row["implementation_manifest_sha256"] for row in rows}) == 1
    assert len({row["test_manifest_sha256"] for row in rows}) == 1

    for path in output.iterdir():
        assert path.read_bytes().isascii()
        assert private_output not in path.read_bytes()
    artifacts = json.loads((output / "artifact-hashes.json").read_text(encoding="ascii"))
    for name, digest in artifacts["artifacts"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    with pytest.raises(ValueError, match="real subprocess"):
        conformance.verify_conformance_bundle(output)
    with pytest.raises(FileExistsError, match="fresh"):
        conformance.run_conformance(output, process_runner=fake)

    with (output / "conformance-summary.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ValueError, match="manifest"):
        conformance.verify_conformance_bundle(output)


def test_contradictory_rehashed_pass_row_is_rejected(tmp_path):
    def fake(command, *, cwd, env, timeout_seconds):
        node_id = command[-1]
        if "--collect-only" in command:
            return result(stdout=(node_id + "\n1 test collected\n").encode("ascii"))
        return result(stdout=b"1 passed\n")

    output = tmp_path / "evidence"
    conformance.run_conformance(output, process_runner=fake)
    plan = json.loads((output / "conformance-plan.json").read_text(encoding="ascii"))
    plan["execution_runner"] = "real_subprocess"
    (output / "conformance-plan.json").write_bytes(conformance._pretty(plan))
    rows = read_rows(output / "conformance-results.jsonl")
    for row in rows:
        row["execution_runner"] = "real_subprocess"
    rows[0]["collection"]["status"] = "not_collected"
    results_raw = b"".join(conformance._canonical(row) + b"\n" for row in rows)
    (output / "conformance-results.jsonl").write_bytes(results_raw)
    summary = json.loads((output / "conformance-summary.json").read_text(encoding="ascii"))
    summary["execution_runner"] = "real_subprocess"
    summary["passed"] = True
    summary["status"] = "passed"
    summary["hashes"]["plan_sha256"] = hashlib.sha256(
        (output / "conformance-plan.json").read_bytes()
    ).hexdigest()
    summary["hashes"]["results_sha256"] = hashlib.sha256(results_raw).hexdigest()
    (output / "conformance-summary.json").write_bytes(conformance._pretty(summary))
    manifest = json.loads((output / "artifact-hashes.json").read_text(encoding="ascii"))
    for name in manifest["artifacts"]:
        manifest["artifacts"][name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    (output / "artifact-hashes.json").write_bytes(conformance._pretty(manifest))

    with pytest.raises(ValueError, match="result inventory"):
        conformance.verify_conformance_bundle(output)


def test_missing_collection_and_failed_execution_remain_explicit(tmp_path):
    calls = []
    missing = "tests/test_provenance.py::test_missing_tool_exposure_prevents_analysis_of_proposal"
    failing = "tests/test_causal_v2_audit.py::test_budget_exhaustion_keeps_unrequested_slots_unknown"

    def fake(command, *, cwd, env, timeout_seconds):
        calls.append(tuple(command))
        node_id = command[-1]
        if "--collect-only" in command:
            if node_id == missing:
                return result(exit_code=5, stdout=b"no tests collected\n")
            return result(stdout=(node_id + "\n1 test collected\n").encode("ascii"))
        if node_id == failing:
            return result(exit_code=1, stdout=b"1 failed\n", stderr=b"private failure details")
        return result(stdout=b"1 passed\n")

    output = tmp_path / "evidence"
    summary = conformance.run_conformance(output, process_runner=fake)
    rows = {row["node_id"]: row for row in read_rows(output / "conformance-results.jsonl")}
    assert summary["passed"] is False
    assert summary["counts"] == {"failed": 1, "passed": 60, "unknown": 1}
    assert rows[missing]["status"] == "unknown"
    assert rows[missing]["failure_reason"] == "exact_node_not_collected"
    assert rows[missing]["collection"]["exit_code"] == 5
    assert rows[missing]["execution"]["status"] == "not_run"
    assert rows[missing]["execution"]["requested_node_executed"] is False
    assert sum(command[-1] == missing for command in calls) == 1
    assert rows[failing]["status"] == "failed"
    assert rows[failing]["failure_reason"] == "pytest_execution_failed"
    assert rows[failing]["execution"]["exit_code"] == 1
    assert rows[failing]["execution"]["requested_node_executed"] is True
    assert {group["milestone_id"] for group in summary["groups"] if group["status"] == "failed"} == {
        "M1",
        "M4",
    }
    assert b"private failure details" not in (output / "conformance-results.jsonl").read_bytes()


def test_config_rejects_duplicate_nodes_and_live_coverage_claims():
    config, _ = conformance.load_config()
    duplicate = copy.deepcopy(config)
    duplicate["milestones"][0]["cases"][1]["node_id"] = duplicate["milestones"][0]["cases"][0][
        "node_id"
    ]
    with pytest.raises(ValueError, match="duplicate pytest node"):
        conformance.validate_config(duplicate)

    live_claim = copy.deepcopy(config)
    live_claim["live_judge_coverage"]["claimed"] = True
    with pytest.raises(ValueError, match="cannot claim"):
        conformance.validate_config(live_claim)


def test_one_real_frozen_node_collects_and_executes_offline():
    case = {
        "node_id": (
            "tests/test_policy.py::"
            "test_default_workspace_policy_covers_actual_suite_with_declared_overlap"
        )
    }
    with conformance.offline_environment() as env:
        evaluated = conformance.evaluate_case(
            case,
            root=conformance.ROOT,
            python=sys.executable,
            env=env,
            timeout_seconds=30,
        )
    assert evaluated["status"] == "passed"
    assert evaluated["collection"]["collected_node_ids"] == [case["node_id"]]
    assert evaluated["collection"]["requested_node_collected"] is True
    assert evaluated["execution"]["requested_node_executed"] is True
    assert evaluated["execution"]["exit_code"] == 0
