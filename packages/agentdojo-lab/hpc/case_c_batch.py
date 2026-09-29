"""Fail-closed gates and terminal receipts for the Scout smoke-plus-Case-C job."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROTOCOL = "nesi-scout-smoke-case-c-v1"
SERVER_CHECK_PROTOCOL = "nesi-scout-smoke-case-a-v1"
CASE_PROTOCOL = "scout-case-c-transformed-memory-v1"
SMOKE_PROTOCOL = "nesi-scout-smoke-v1"
NATIVE_PROTOCOL = "nesi-scout-native-clean-smoke-v1"
WALLTIME_SECONDS = 7200
MINIMUM_REMAINING_SECONDS = 3900
CASE_COMMAND_TIMEOUT_SECONDS = 3600
SYNTHETIC_REQUEST_LIMIT = 4
NATIVE_REQUEST_LIMIT = 4
CASE_REQUEST_LIMIT = 16
CASE_SLOT_REQUEST_LIMIT = 4
TOTAL_REQUEST_LIMIT = 24
CONDITIONS = ("clean", "attacked")
SESSION_ORDER = ("A", "B")
SLOTS = tuple((condition, stage) for condition in CONDITIONS for stage in SESSION_ORDER)
SLOT_IDS = tuple(f"{condition}/{stage}" for condition, stage in SLOTS)
REQUIRED_RUNTIME_KEYS = (
    "configs/local_scout.toml",
    "hpc/scout-smoke-case-c.sbatch",
    "hpc/scout-smoke.sbatch",
    "hpc/case_c_batch.py",
    "hpc/case_a_batch.py",
    "hpc/preflight.py",
    "hpc/smoke.py",
    "hpc/native_smoke.py",
    "hpc/tool_chat_template_llama4_pythonic_typed_v1.jinja",
    "scripts/run_case_c_scout.py",
)
UNSTARTED_STATUSES = {
    "unstarted_walltime_limit_exceeded",
    "unstarted_insufficient_remaining_time",
    "unstarted_invalid_current_job_time_evidence",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def expected_limits() -> dict:
    return {
        "walltime_seconds": WALLTIME_SECONDS,
        "minimum_remaining_seconds": MINIMUM_REMAINING_SECONDS,
        "case_command_timeout_seconds": CASE_COMMAND_TIMEOUT_SECONDS,
        "synthetic_requests": SYNTHETIC_REQUEST_LIMIT,
        "native_requests": NATIVE_REQUEST_LIMIT,
        "case_requests": CASE_REQUEST_LIMIT,
        "total_generation_requests": TOTAL_REQUEST_LIMIT,
        "online_auditor_requests": 0,
        "sdk_retries": 0,
    }


def expected_preflight_limits() -> tuple[dict, dict]:
    smoke = {
        "scope": "smoke_phase_only",
        "gpus": 4,
        "intended_walltime_minutes": 60,
        "ready_seconds": 1500,
        "generative_requests": 8,
        "synthetic_requests": 4,
        "synthetic_request_timeout_seconds": 120,
        "synthetic_max_completion_tokens_per_request": 512,
        "native_requests": 4,
        "native_request_timeout_seconds": 180,
        "native_max_completion_tokens_per_request": 2048,
    }
    enclosing = {
        "scope": "smoke_plus_case_c_job",
        "walltime_seconds": WALLTIME_SECONDS,
        "total_generation_requests": TOTAL_REQUEST_LIMIT,
        "case_requests": CASE_REQUEST_LIMIT,
        "case_sessions": len(SLOTS),
        "requests_per_case_session": CASE_SLOT_REQUEST_LIMIT,
        "online_auditor_requests": 0,
    }
    return smoke, enclosing


def receipt(path: Path) -> dict:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object receipt")
    return value


def write_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def parse_runtime_sources(rows: list[list[str]]) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for key, raw_path in rows:
        if key in sources:
            raise ValueError("Duplicate Case C runtime source key")
        path = Path(raw_path)
        if (
            key not in REQUIRED_RUNTIME_KEYS
            or not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or path.resolve() != path
        ):
            raise ValueError("Invalid Case C runtime source mapping")
        sources[key] = path
    if tuple(sorted(sources)) != tuple(sorted(REQUIRED_RUNTIME_KEYS)):
        raise ValueError("Case C runtime source mapping is incomplete")
    return sources


def validate_runtime_sources(plan: dict, sources: dict[str, Path]) -> dict[str, dict]:
    if set(sources) != set(REQUIRED_RUNTIME_KEYS):
        raise ValueError("Case C runtime source mapping is incomplete")
    for path in sources.values():
        require_absolute_regular(path, "Case C runtime source")
    hashes = plan.get("source_hashes", {})
    values = {key: receipt(path) for key, path in sources.items()}
    if any(hashes.get(key) != value["sha256"] for key, value in values.items()):
        raise ValueError("Case C launch source differs from its prepared source hash")
    return values


def require_absolute_regular(path: Path, label: str) -> Path:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve() != path
    ):
        raise ValueError(f"{label} must be an absolute, physical canonical file")
    return path


def require_absolute_directory(path: Path, label: str) -> Path:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve() != path
    ):
        raise ValueError(f"{label} must be an absolute, physical canonical directory")
    return path


def manifest_entries(path: Path, runtime: dict[str, dict]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", line)
        if match is None or match.group(2) in entries:
            raise ValueError("Malformed or duplicate Case C checksum manifest entry")
        entries[match.group(2)] = match.group(1)
    expected = {key: item["sha256"] for key, item in runtime.items()}
    if entries != expected:
        raise ValueError("Case C checksum manifest does not exactly bind every launch payload")
    return entries


def submission_binding(
    *,
    site_path: Path,
    site_sha256: str,
    manifest_path: Path,
    manifest_sha256: str,
    executed_wrapper_path: Path,
    runtime: dict[str, dict],
) -> dict:
    if not SHA256_RE.fullmatch(site_sha256) or not SHA256_RE.fullmatch(manifest_sha256):
        raise ValueError("Case C submission hashes must be lowercase SHA-256 values")
    site = require_absolute_regular(site_path, "Case C site file")
    manifest = require_absolute_regular(manifest_path, "Case C manifest")
    executed = require_absolute_regular(executed_wrapper_path, "Executed Case C wrapper")
    canonical = require_absolute_regular(
        Path(runtime["hpc/scout-smoke-case-c.sbatch"]["path"]),
        "Canonical Case C wrapper",
    )
    bundle_root = canonical.parent.parent
    if manifest != bundle_root / "submission-sha256.txt" or any(
        Path(item["path"]) != bundle_root / key for key, item in runtime.items()
    ):
        raise ValueError("Case C launch payloads must use their frozen bundle paths")
    site_receipt = receipt(site)
    manifest_receipt = receipt(manifest)
    executed_receipt = receipt(executed)
    canonical_receipt = receipt(canonical)
    if (
        site_receipt["sha256"] != site_sha256
        or manifest_receipt["sha256"] != manifest_sha256
        or executed_receipt["sha256"] != canonical_receipt["sha256"]
        or canonical_receipt != runtime["hpc/scout-smoke-case-c.sbatch"]
    ):
        raise ValueError("Case C submitted site, manifest, or spool wrapper differs")
    manifest_entries(manifest, runtime)
    return {
        "site": site_receipt,
        "site_sha256_at_submission": site_sha256,
        "manifest": manifest_receipt,
        "manifest_sha256_at_submission": manifest_sha256,
        "executed_wrapper": executed_receipt,
        "canonical_wrapper": canonical_receipt,
        "executed_wrapper_matches_canonical": True,
    }


def validate_recorded_submission(binding: dict, runtime: dict[str, dict]) -> None:
    required = {
        "site",
        "site_sha256_at_submission",
        "manifest",
        "manifest_sha256_at_submission",
        "executed_wrapper",
        "canonical_wrapper",
        "executed_wrapper_matches_canonical",
    }
    if set(binding) != required:
        raise ValueError("Recorded Case C submission binding has unexpected fields")
    for name in ("site", "manifest", "executed_wrapper", "canonical_wrapper"):
        if receipt(Path(binding[name]["path"])) != binding[name]:
            raise ValueError("A submission-bound Case C file changed")
    canonical = runtime["hpc/scout-smoke-case-c.sbatch"]
    if (
        binding["site"]["sha256"] != binding["site_sha256_at_submission"]
        or binding["manifest"]["sha256"] != binding["manifest_sha256_at_submission"]
        or binding["canonical_wrapper"] != canonical
        or binding["executed_wrapper"]["sha256"] != canonical["sha256"]
        or binding["executed_wrapper_matches_canonical"] is not True
    ):
        raise ValueError("Recorded Case C submission hashes are inconsistent")
    manifest_entries(Path(binding["manifest"]["path"]), runtime)


def validate_wrapper_checksums(path: Path, binding: dict, runtime: dict[str, dict]) -> None:
    recorded: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (/.+)", line)
        if match is None:
            raise ValueError("Malformed Case C wrapper checksum entry")
        resolved = str(Path(match.group(2)).resolve())
        if resolved in recorded:
            raise ValueError("Duplicate Case C wrapper checksum path")
        recorded[resolved] = match.group(1)
    expected = {
        item["path"]: item["sha256"]
        for item in (
            binding["executed_wrapper"],
            binding["site"],
            binding["manifest"],
            *runtime.values(),
        )
    }
    if recorded != expected:
        raise ValueError("Case C wrapper checksum record differs from bound inputs")


def validate_plan_shape(case_dir: Path, runner_path: Path, *, run_verifier: bool) -> dict:
    plan_path = require_absolute_regular(case_dir / "plan.json", "Case C plan")
    preparation_path = require_absolute_regular(
        case_dir / "preparation.json", "Case C preparation receipt"
    )
    preparation = read(preparation_path)
    if (
        preparation.get("protocol") != CASE_PROTOCOL
        or preparation.get("status") != "prepared_not_executed"
        or preparation.get("real_llm_requests_started") != 0
        or preparation.get("plan") != receipt(plan_path)
        or Path(preparation.get("plan", {}).get("path", "")).resolve() != plan_path.resolve()
    ):
        raise ValueError("Invalid Case C preparation receipt")
    plan = read(plan_path)
    limits = plan.get("limits", {})
    config = plan.get("config", {})
    endpoint = plan.get("endpoint_identity", {})
    semantic_model = config.get("semantic_model")
    semantic_model_valid = (
        isinstance(semantic_model, str)
        and Path(semantic_model).is_absolute()
        and Path(semantic_model).name == "all-MiniLM-L6-v2-1110a243"
    )
    expected_slots = [
        {"slot_id": slot_id, "condition": condition, "stage": stage, "order": order}
        for order, (slot_id, (condition, stage)) in enumerate(zip(SLOT_IDS, SLOTS, strict=True), 1)
    ]
    expected_endpoint = {
        "settings": {
            "provider": "openai_compatible",
            "model": "llama-4-scout-local",
            "base_url": "http://127.0.0.1:8000/v1",
            "api_key_env": "LOCAL_LLM_API_KEY",
        },
        "literal_loopback_required": True,
        "credentials": "environment_variable_only",
        "fallback": None,
    }
    if (
        plan.get("protocol") != CASE_PROTOCOL
        or plan.get("status") != "prepared_design_only"
        or plan.get("real_llm_requests_started") != 0
        or plan.get("conditions") != list(CONDITIONS)
        or plan.get("session_order") != list(SESSION_ORDER)
        or plan.get("slots") != expected_slots
        or plan.get("execution_binding")
        != {"status": "pending_same_allocation_serving_receipt"}
        or limits.get("sdk_attempts_per_session") != CASE_SLOT_REQUEST_LIMIT
        or limits.get("primary_sdk_attempts_total") != CASE_REQUEST_LIMIT
        or limits.get("completion_tokens_per_request") != 2048
        or limits.get("context_tokens") != 8192
        or limits.get("online_auditor_requests") != 0
        or limits.get("sdk_max_retries") != 0
        or limits.get("request_pacing") is not False
        or limits.get("worker_processes") != len(SLOTS)
        or limits.get("session_timeout_seconds") != 900
        or config.get("provider") != "openai_compatible"
        or config.get("model") != "llama-4-scout-local"
        or config.get("base_url") != "http://127.0.0.1:8000/v1"
        or config.get("api_key_env") != "LOCAL_LLM_API_KEY"
        or config.get("benchmark_version") != "v1.2.2"
        or config.get("suite") != "workspace"
        or config.get("user_tasks") != ["case_c_transformed_memory"]
        or config.get("temperature") != 0.0
        or config.get("max_completion_tokens") != 2048
        or config.get("max_tool_rounds") != CASE_SLOT_REQUEST_LIMIT
        or config.get("request_timeout_seconds") != 180.0
        or config.get("online_causal_audit") is not False
        or config.get("reasoning_effort") is not None
        or config.get("pacing_tokens_per_minute") is not None
        or config.get("record_events") is not True
        or config.get("online_provenance") is not True
        or config.get("canary_enabled") is not False
        or config.get("lineage_namespace") != CASE_PROTOCOL
        or config.get("provenance_policy") != "configs/workspace_policy_v1.yaml"
        or not semantic_model_valid
        or config.get("semantic_revision") != "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
        or endpoint != expected_endpoint
    ):
        raise ValueError("Prepared plan violates the fixed local Case C schedule or request bounds")
    runner_path = require_absolute_regular(runner_path, "Case C runner")
    expected_runner = plan.get("source_hashes", {}).get("scripts/run_case_c_scout.py")
    if receipt(runner_path)["sha256"] != expected_runner:
        raise ValueError("Case C runner differs from its prepared source hash")
    if run_verifier:
        verification_env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "LOCAL_LLM_API_KEY",
                "GROQ_API_KEY",
                "HF_TOKEN",
                "HUGGING_FACE_HUB_TOKEN",
            }
        }
        verification_env.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
        bundle_root = runner_path.resolve().parents[1]
        verification_env["PYTHONPATH"] = os.pathsep.join(
            (
                str(bundle_root / "vendor/agentdojo/src"),
                str(bundle_root / "src"),
                str(bundle_root / "scripts"),
            )
        )
        checked = subprocess.run(
            [sys.executable, str(runner_path), "verify", str(case_dir)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
            env=verification_env,
        )
        if checked.returncode != 0:
            raise ValueError("Case C request-free plan verification failed")
    return plan


def validate_before_smoke(
    output: Path,
    case_dir: Path,
    smoke_dir: Path,
    runner_path: Path,
    runtime_sources: dict[str, Path],
    site_path: Path,
    site_sha256: str,
    manifest_path: Path,
    manifest_sha256: str,
    executed_wrapper_path: Path,
    *,
    verifier=None,
) -> dict:
    """Verify a pristine preparation and every launch byte before starting vLLM."""
    if not all(path.is_absolute() for path in (output, case_dir, smoke_dir, runner_path)):
        raise ValueError("Case C launch paths must be absolute")
    case_dir = require_absolute_directory(case_dir, "Prepared Case C directory")
    if smoke_dir.is_symlink() or smoke_dir.resolve() != smoke_dir:
        raise ValueError("Case C smoke path must be physical and canonical")
    if case_dir == smoke_dir or case_dir.is_relative_to(smoke_dir) or smoke_dir.is_relative_to(case_dir):
        raise ValueError("Case C and smoke evidence directories must be separate")
    if output.resolve() != Path(str(smoke_dir) + ".case-c-pre-smoke.json"):
        raise ValueError("Pre-smoke receipt must be the fresh smoke directory sibling")
    if {path.name for path in case_dir.iterdir()} != {"plan.json", "preparation.json"}:
        raise ValueError("Prepared Case C directory must contain only plan.json and preparation.json")
    if smoke_dir.exists():
        raise FileExistsError("Smoke evidence directory must be fresh")
    plan = (
        verifier(case_dir)
        if verifier is not None
        else validate_plan_shape(case_dir, runner_path, run_verifier=True)
    )
    if verifier is not None:
        validate_plan_shape(case_dir, runner_path, run_verifier=False)
    runtime = validate_runtime_sources(plan, runtime_sources)
    submission = submission_binding(
        site_path=site_path,
        site_sha256=site_sha256,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        executed_wrapper_path=executed_wrapper_path,
        runtime=runtime,
    )
    value = {
        "protocol": PROTOCOL,
        "status": "prepared_inputs_validated_before_smoke",
        "case_dir": str(case_dir),
        "smoke_dir": str(smoke_dir),
        "plan": receipt(case_dir / "plan.json"),
        "runner": receipt(runner_path),
        "runtime_sources": runtime,
        "submission_binding": submission,
        "verification": {
            "request_free_runner_verify": True,
            "real_llm_requests_started": 0,
        },
    }
    write_exclusive(output, value)
    return value


def parse_slurm_duration(value: str) -> int:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("Missing Slurm duration")
    day_text, clock = value.split("-", 1) if "-" in value else ("0", value)
    parts = clock.split(":")
    if len(parts) == 2:
        parts.insert(0, "0")
    if len(parts) != 3 or not day_text.isdigit() or any(not part.isdigit() for part in parts):
        raise ValueError("Invalid Slurm duration")
    days, hours, minutes, seconds = (int(day_text), *(int(part) for part in parts))
    if (days and hours > 23) or minutes > 59 or seconds > 59:
        raise ValueError("Invalid Slurm duration fields")
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def scheduler_decision(*, job_id: str, reported_job_id: str, remaining: str, time_limit: str) -> dict:
    status = "reserved_before_case_calls"
    error_type = None
    try:
        if not job_id or reported_job_id != job_id:
            raise ValueError("Slurm time record belongs to another job")
        remaining_seconds = parse_slurm_duration(remaining)
        time_limit_seconds = parse_slurm_duration(time_limit)
        if time_limit_seconds <= 0 or remaining_seconds > time_limit_seconds:
            raise ValueError("Slurm remaining time is inconsistent with its time limit")
        if time_limit_seconds > WALLTIME_SECONDS:
            status = "unstarted_walltime_limit_exceeded"
        elif remaining_seconds < MINIMUM_REMAINING_SECONDS:
            status = "unstarted_insufficient_remaining_time"
    except ValueError as error:
        status = "unstarted_invalid_current_job_time_evidence"
        error_type = type(error).__name__
        remaining_seconds = None
        time_limit_seconds = None
    result = {
        "status": status,
        "time_decision": {
            "source": "squeue_current_job_%i_%L_%l",
            "reported_job_id": reported_job_id,
            "remaining_raw": remaining,
            "time_limit_raw": time_limit,
            "remaining_seconds": remaining_seconds,
            "time_limit_seconds": time_limit_seconds,
        },
    }
    if error_type:
        result["error_type"] = error_type
    return result


def validate_scheduler_decision(phase: dict) -> None:
    recorded = phase.get("time_decision", {})
    expected = scheduler_decision(
        job_id=phase.get("slurm_job_id", ""),
        reported_job_id=recorded.get("reported_job_id", ""),
        remaining=recorded.get("remaining_raw", ""),
        time_limit=recorded.get("time_limit_raw", ""),
    )
    if (
        phase.get("status") != expected["status"]
        or recorded != expected["time_decision"]
        or phase.get("error_type") != expected.get("error_type")
        or ("error_type" in phase) != ("error_type" in expected)
    ):
        raise ValueError("Recorded Case C scheduler decision is inconsistent")


def reserve_phase(
    output: Path,
    *,
    job_id: str,
    reported_job_id: str,
    remaining: str,
    time_limit: str,
    case_dir: Path,
    pre_smoke_path: Path,
    runner_path: Path,
    runtime_sources: dict[str, Path],
    wrapper_sha256_path: Path,
    server_pid: int,
    verifier=None,
) -> dict:
    if not all(
        path.is_absolute() for path in (output, case_dir, pre_smoke_path, runner_path, wrapper_sha256_path)
    ):
        raise ValueError("Case C phase paths must be absolute")
    case_dir = require_absolute_directory(case_dir, "Prepared Case C directory")
    if output.name != "case-c-phase.json" or output.parent.resolve() == case_dir.resolve():
        raise ValueError("Case C phase must be in its separate smoke directory")
    if type(server_pid) is not int or server_pid <= 1:
        raise ValueError("Case C server PID must identify the live smoke server")
    decision = scheduler_decision(
        job_id=job_id,
        reported_job_id=reported_job_id,
        remaining=remaining,
        time_limit=time_limit,
    )
    plan = (
        verifier(case_dir)
        if verifier is not None
        else validate_plan_shape(case_dir, runner_path, run_verifier=True)
    )
    if verifier is not None:
        validate_plan_shape(case_dir, runner_path, run_verifier=False)
    runtime = validate_runtime_sources(plan, runtime_sources)
    pre_smoke = read(pre_smoke_path)
    if output.parent.resolve() != Path(pre_smoke.get("smoke_dir", "")).resolve():
        raise ValueError("Case C phase path differs from the pre-smoke binding")
    binding = pre_smoke.get("submission_binding")
    if not isinstance(binding, dict):
        raise ValueError("Missing Case C submission binding")
    validate_recorded_submission(binding, runtime)
    require_path(wrapper_sha256_path, output.parent, "case-c-wrapper-sha256.txt")
    validate_wrapper_checksums(wrapper_sha256_path, binding, runtime)
    expected_pre_smoke = {
        "protocol": PROTOCOL,
        "status": "prepared_inputs_validated_before_smoke",
        "case_dir": str(case_dir.resolve()),
        "smoke_dir": str(output.parent.resolve()),
        "plan": receipt(case_dir / "plan.json"),
        "runner": receipt(runner_path),
        "runtime_sources": runtime,
        "submission_binding": binding,
        "verification": {
            "request_free_runner_verify": True,
            "real_llm_requests_started": 0,
        },
    }
    if pre_smoke != expected_pre_smoke:
        raise ValueError("Pre-smoke Case C binding changed before phase reservation")
    value = {
        "protocol": PROTOCOL,
        "status": decision["status"],
        "slurm_job_id": job_id,
        "server_pid": server_pid,
        "time_decision": decision["time_decision"],
        "case_dir": str(case_dir.resolve()),
        "plan": receipt(case_dir / "plan.json"),
        "runner": receipt(runner_path),
        "pre_smoke": receipt(pre_smoke_path),
        "runtime_sources": runtime,
        "submission_binding": binding,
        "wrapper_checksums": receipt(wrapper_sha256_path),
        "limits": expected_limits(),
    }
    if "error_type" in decision:
        value["error_type"] = decision["error_type"]
    write_exclusive(output, value)
    return value


def record_cleanup(
    output: Path,
    *,
    server_pid: int,
    term_sent: bool,
    kill_sent: bool,
    stopped: bool,
    case_pid: int,
    case_term_sent: bool,
    case_kill_sent: bool,
    case_stopped: bool,
    job_id: str,
) -> dict:
    if type(server_pid) is not int or server_pid <= 1 or type(case_pid) is not int or case_pid < 0:
        raise ValueError("Case C cleanup process identities are invalid")
    value = {
        "protocol": PROTOCOL,
        "slurm_job_id": job_id,
        "status": "server_stopped" if stopped else "server_cleanup_unconfirmed",
        "server_pid": server_pid,
        "term_sent": term_sent,
        "kill_sent": kill_sent,
        "case_process": {
            "pid": case_pid,
            "term_sent": case_term_sent,
            "kill_sent": case_kill_sent,
            "stopped": case_stopped,
        },
    }
    write_exclusive(output, value)
    return value


def require_path(path: Path, parent: Path, name: str) -> None:
    if path.resolve() != parent.resolve() / name:
        raise ValueError(f"Expected {name} in the bound evidence directory")


def count_slot_attempts(path: Path) -> int:
    if not path.is_file():
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > CASE_SLOT_REQUEST_LIMIT:
        raise ValueError("Case C slot exceeded four SDK attempts")
    for expected, line in enumerate(lines, 1):
        row = json.loads(line)
        if (
            not isinstance(row, dict)
            or type(row.get("sdk_attempt")) is not int
            or row["sdk_attempt"] != expected
        ):
            raise ValueError("Case C SDK attempts must be sequential JSON objects")
    return len(lines)


def validate_common_chain(
    *,
    phase: dict,
    pre_smoke_path: Path,
    runner_path: Path,
    preflight_path: Path,
    smoke_path: Path,
    native_path: Path,
    cleanup_path: Path,
    case_plan_path: Path,
    wrapper_sha256_path: Path,
    plan_verifier=None,
) -> tuple[dict, dict, dict, dict, dict]:
    smoke_root = smoke_path.parent.resolve()
    if pre_smoke_path.resolve() != Path(str(smoke_root) + ".case-c-pre-smoke.json"):
        raise ValueError("Pre-smoke receipt path differs from the bound smoke directory")
    for path, name in (
        (preflight_path, "preflight.json"),
        (smoke_path, "smoke.json"),
        (native_path, "native-smoke.json"),
        (cleanup_path, "case-c-cleanup.json"),
    ):
        require_path(path, smoke_root, name)
    case_root = case_plan_path.parent.resolve()
    require_path(case_plan_path, case_root, "plan.json")
    if (
        case_root == smoke_root
        or case_root.is_relative_to(smoke_root)
        or smoke_root.is_relative_to(case_root)
    ):
        raise ValueError("Case C and smoke terminal evidence paths must be separate")
    plan = read(case_plan_path)
    verified_plan = (
        plan_verifier(case_root)
        if plan_verifier is not None
        else validate_plan_shape(case_root, runner_path, run_verifier=True)
    )
    if plan_verifier is not None:
        validate_plan_shape(case_root, runner_path, run_verifier=False)
    if verified_plan != plan:
        raise ValueError("Terminal Case C request-free plan verification differs")
    plan_receipt = receipt(case_plan_path)
    runner_receipt = receipt(runner_path)
    pre_smoke = read(pre_smoke_path)
    if (
        phase.get("protocol") != PROTOCOL
        or type(phase.get("server_pid")) is not int
        or phase["server_pid"] <= 1
        or phase.get("case_dir") != str(case_root)
        or phase.get("plan") != plan_receipt
        or phase.get("runner") != runner_receipt
        or phase.get("pre_smoke") != receipt(pre_smoke_path)
        or pre_smoke.get("protocol") != PROTOCOL
        or pre_smoke.get("status") != "prepared_inputs_validated_before_smoke"
        or pre_smoke.get("case_dir") != str(case_root)
        or pre_smoke.get("smoke_dir") != str(smoke_root)
        or pre_smoke.get("plan") != plan_receipt
        or pre_smoke.get("runner") != runner_receipt
        or pre_smoke.get("runtime_sources") != phase.get("runtime_sources")
        or pre_smoke.get("submission_binding") != phase.get("submission_binding")
        or pre_smoke.get("verification")
        != {"request_free_runner_verify": True, "real_llm_requests_started": 0}
        or phase.get("limits") != expected_limits()
        or plan.get("protocol") != CASE_PROTOCOL
        or plan.get("source_hashes", {}).get("scripts/run_case_c_scout.py") != runner_receipt["sha256"]
    ):
        raise ValueError("Case C pre-call source, plan, or path binding differs")
    for key, bound in phase.get("runtime_sources", {}).items():
        if key not in REQUIRED_RUNTIME_KEYS or receipt(Path(bound.get("path", ""))) != bound:
            raise ValueError("Case C launch source changed after phase reservation")
        if plan.get("source_hashes", {}).get(key) != bound.get("sha256"):
            raise ValueError("Case C plan no longer binds a launch source")
    if set(phase.get("runtime_sources", {})) != set(REQUIRED_RUNTIME_KEYS):
        raise ValueError("Case C terminal runtime source inventory is incomplete")
    binding = phase.get("submission_binding")
    if not isinstance(binding, dict):
        raise ValueError("Case C terminal submission binding is missing")
    validate_recorded_submission(binding, phase["runtime_sources"])
    require_path(wrapper_sha256_path, smoke_root, "case-c-wrapper-sha256.txt")
    if phase.get("wrapper_checksums") != receipt(wrapper_sha256_path):
        raise ValueError("Case C wrapper checksum receipt changed")
    validate_wrapper_checksums(wrapper_sha256_path, binding, phase["runtime_sources"])
    preflight = read(preflight_path)
    smoke = read(smoke_path)
    native = read(native_path)
    cleanup = read(cleanup_path)
    job_id = phase.get("slurm_job_id")
    smoke_limits, enclosing_limits = expected_preflight_limits()
    if (
        preflight.get("protocol") != SMOKE_PROTOCOL
        or preflight.get("slurm_job_id") != job_id
        or preflight.get("limits") != smoke_limits
        or preflight.get("enclosing_case_c_limits") != enclosing_limits
        or "enclosing_case_a_limits" in preflight
        or smoke.get("protocol") != SMOKE_PROTOCOL
        or native.get("protocol") != NATIVE_PROTOCOL
        or native.get("slurm_job_id") != job_id
        or cleanup.get("protocol") != PROTOCOL
        or cleanup.get("slurm_job_id") != job_id
        or cleanup.get("server_pid") != phase.get("server_pid")
    ):
        raise ValueError("Case C smoke, cleanup, or allocation binding differs")
    return plan, preflight, smoke, native, cleanup


def validate_started_case(
    *,
    phase: dict,
    plan: dict,
    preflight_path: Path,
    server_check_path: Path,
    execution_path: Path,
    case_summary_path: Path,
    binding_validator=None,
) -> tuple[dict, list[int]]:
    smoke_root = preflight_path.parent.resolve()
    require_path(server_check_path, smoke_root, "case-a-server-check.json")
    case_root = case_summary_path.parent.resolve()
    require_path(execution_path, case_root, "execution.json")
    require_path(case_summary_path, case_root, "case-summary.json")
    server_check = read(server_check_path)
    job_id = phase.get("slurm_job_id")
    if (
        server_check.get("protocol") != SERVER_CHECK_PROTOCOL
        or server_check.get("status") != "passed"
        or server_check.get("slurm_job_id") != job_id
        or server_check.get("server_pid") != phase.get("server_pid")
        or server_check.get("endpoint") != plan.get("config", {}).get("base_url")
    ):
        raise ValueError("Case C server check differs from its shared checked receipt")
    if binding_validator is None:
        from agentdojo_lab.case_a_scout import recorded_serving_binding

        binding_validator = recorded_serving_binding
    binding = binding_validator(preflight_path, plan["config"]["base_url"])
    if binding.get("status") != "bound_before_case_calls" or binding.get("slurm_job_id") != job_id:
        raise ValueError("Recomputed Case C serving binding differs")
    plan_receipt = receipt(case_root / "plan.json")
    execution = read(execution_path)
    if execution != {
        "schema_version": 1,
        "protocol": CASE_PROTOCOL,
        "mode": "live_scout",
        "plan": plan_receipt,
        "serving": binding,
        "preflight": receipt(preflight_path),
        "status": "reserved_before_workers",
        "fixed_slot_order": list(SLOT_IDS),
    }:
        raise ValueError("Case C execution receipt differs from its serving binding")
    summary = read(case_summary_path)
    slots = summary.get("slots", [])
    if (
        summary.get("schema_version") != 1
        or summary.get("protocol") != CASE_PROTOCOL
        or summary.get("mode") != "live_scout"
        or summary.get("evidence_class") != "live_scout_research"
        or summary.get("real_llm") is not True
        or summary.get("fixture_is_research_result") is not None
        or summary.get("fixture_validation_complete") is not None
        or summary.get("research_outcome") != "inspect_observed_native_evidence"
        or summary.get("plan") != plan_receipt
        or summary.get("fixed_slot_order") != list(SLOT_IDS)
        or len(slots) != len(SLOTS)
        or [row.get("slot_id") for row in slots] != list(SLOT_IDS)
        or [(row.get("condition"), row.get("stage")) for row in slots] != list(SLOTS)
        or summary.get("source_snapshot_unchanged") is not True
        or summary.get("failures_replaced") is not False
        or summary.get("cross_session_export_is_native_oracle") is not False
    ):
        raise ValueError("Case C terminal summary protocol, plan, or schedule differs")
    counts = []
    for (condition, stage), row in zip(SLOTS, slots, strict=True):
        terminal_path = case_root / f"{condition}-{stage}-terminal.json"
        if not terminal_path.is_file():
            raise ValueError("Case C worker terminal receipt is missing")
        terminal = read(terminal_path)
        if (
            row.get("terminal") != terminal
            or terminal.get("protocol") != CASE_PROTOCOL
            or row.get("replacement_attempted") is not False
        ):
            raise ValueError("Case C embedded and on-disk terminal evidence differs")
        if terminal.get("status") == "completed" and (
            terminal.get("schema_version") != 1
            or terminal.get("condition") != condition
            or terminal.get("stage") != stage
            or terminal.get("slot_id") != f"{condition}/{stage}"
            or terminal.get("run_id") != f"{CASE_PROTOCOL}-{condition}-{stage}"
            or terminal.get("session_id") != terminal.get("run_id")
            or terminal.get("real_llm") is not True
            or terminal.get("evidence_class") != "live_scout_research"
            or terminal.get("fixture_is_research_result") is not None
            or terminal.get("source_snapshot_unchanged_after_calls") is not True
            or terminal.get("input_hashes_unchanged") is not True
        ):
            raise ValueError("Completed Case C terminal is not bound to its exact session")
        count = count_slot_attempts(case_root / condition / stage / "sdk-attempts.jsonl")
        if row.get("captured_sdk_attempts") != count:
            raise ValueError("Case C summary SDK count differs from its attempt ledger")
        counts.append(count)
    if summary.get("captured_primary_sdk_attempts") != sum(counts):
        raise ValueError("Case C total SDK count differs from its slot ledgers")
    verified_pids = []
    for row in slots:
        pid = row.get("worker_pid")
        identity_verified = bool(
            type(pid) is int and pid > 1 and row.get("terminal", {}).get("pid") == pid
        )
        if row.get("process_identity_verified") is not identity_verified:
            raise ValueError("Case C process identity flag differs from terminal evidence")
        if identity_verified:
            verified_pids.append(pid)
    run_ids = [row.get("terminal", {}).get("run_id") for row in slots]
    all_distinct = len(verified_pids) == len(SLOTS) and len(set(verified_pids)) == len(SLOTS)
    distinct_runs = all(isinstance(value, str) and value for value in run_ids) and len(
        set(run_ids)
    ) == len(SLOTS)
    all_terminal = all(
        row.get("process_status") == "terminal" and row.get("returncode") == 0 for row in slots
    )
    all_primary = all(
        row.get("terminal", {}).get("primary_trajectory_complete") is True for row in slots
    )
    all_analyses = all(
        row.get("terminal", {}).get("outcome_analysis_complete") is True for row in slots
    )
    handoffs = summary.get("handoffs")
    if not isinstance(handoffs, dict) or set(handoffs) != set(CONDITIONS):
        raise ValueError("Case C summary lacks the two branch handoff receipts")
    handoffs_ready = True
    for condition in CONDITIONS:
        handoff_path = case_root / condition / "handoff.json"
        handoff = read(handoff_path)
        if handoffs.get(condition) != handoff:
            raise ValueError("Case C embedded handoff differs from its on-disk receipt")
        if handoff.get("status") != "ready_for_session_b":
            handoffs_ready = False
            continue
        a_terminal = slots[list(SLOTS).index((condition, "A"))]["terminal"]
        b_terminal = slots[list(SLOTS).index((condition, "B"))]["terminal"]
        a_root = case_root / condition / "A"
        session_a = handoff.get("session_a", {})
        memory = handoff.get("memory", {})
        expected_files = {
            "summary": a_root / "summary.json",
            "outcome": a_root / "case-c-outcome.json",
            "native_state": a_root / "native-memory.json",
            "dcpg_state": a_root / "lineage-state.json",
        }
        if (
            handoff.get("schema_version") != 1
            or handoff.get("protocol") != CASE_PROTOCOL
            or handoff.get("condition") != condition
            or handoff.get("advancement_basis")
            != "observed_successful_native_memory_write_only"
            or handoff.get("dcpg_candidate_match_can_advance") is not False
            or handoff.get("plan") != plan_receipt
            or handoff.get("checkpoint_hashes_distinctly_bound") is not True
            or session_a.get("worker_pid") != a_terminal.get("pid")
            or session_a.get("run_id") != a_terminal.get("run_id")
            or session_a.get("summary") != receipt(expected_files["summary"])
            or session_a.get("outcome") != receipt(expected_files["outcome"])
            or handoff.get("native_state") != receipt(expected_files["native_state"])
            or handoff.get("dcpg_state") != receipt(expected_files["dcpg_state"])
            or handoff.get("native_state") == handoff.get("dcpg_state")
            or read(expected_files["summary"]) != a_terminal
            or read(expected_files["outcome"]) != a_terminal.get("outcome")
            or memory.get("file_id") != a_terminal.get("created_file_id")
            or memory.get("content") != a_terminal.get("created_content")
            or not isinstance(memory.get("content"), str)
            or hashlib.sha256(memory["content"].encode()).hexdigest()
            != memory.get("content_sha256")
            or b_terminal.get("source_id") != memory.get("file_id")
            or b_terminal.get("source_content") != memory.get("content")
            or b_terminal.get("input_hashes")
            != {
                "handoff": receipt(handoff_path)["sha256"],
                "native_input": handoff["native_state"]["sha256"],
                "lineage_input": handoff["dcpg_state"]["sha256"],
            }
        ):
            raise ValueError("Case C ready handoff is not bound to the exact A and B evidence")
    request_bound = sum(counts) <= CASE_REQUEST_LIMIT and all(
        count <= CASE_SLOT_REQUEST_LIMIT for count in counts
    )
    protocol_complete = bool(
        all_terminal
        and all_primary
        and all_analyses
        and all_distinct
        and distinct_runs
        and request_bound
        and handoffs_ready
    )
    cross_session = summary.get("cross_session_export")
    if not isinstance(cross_session, dict) or cross_session.get("model_requests_started") != 0:
        raise ValueError("Case C cross-session export is not request-free")
    report_native_complete = cross_session.get("observed_native_path_complete") is True
    if cross_session.get("status") == "exported_request_free":
        native_status = cross_session.get("observed_native_path_status")
        if (
            cross_session.get("native_oracle_affected") is not False
            or native_status
            != {condition: "all_native_observations_covered" for condition in CONDITIONS}
            or report_native_complete is not True
            or cross_session.get("cross_session_json")
            != receipt(case_root / "cross-session-report/cross-session.json")
            or cross_session.get("index_html")
            != receipt(case_root / "cross-session-report/index.html")
        ):
            raise ValueError("Case C request-free export lacks both complete observed native paths")
    elif report_native_complete:
        raise ValueError("A failed Case C export cannot claim a complete native path")
    outcomes = {row["slot_id"]: row["terminal"].get("outcome") for row in slots}
    candidates = {
        row["slot_id"]: row["terminal"].get("dcpg_candidate_evidence") for row in slots
    }
    research_complete = protocol_complete and report_native_complete
    derived = {
        "all_assignments_accounted": True,
        "all_workers_terminal_successfully": all_terminal,
        "all_primary_trajectories_complete": all_primary,
        "all_outcome_analyses_determinate": all_analyses,
        "all_worker_processes_distinct": all_distinct,
        "all_recorded_run_ids_distinct": distinct_runs,
        "worker_pids": verified_pids,
        "run_ids": run_ids,
        "handoffs_ready_from_observed_native_writes": handoffs_ready,
        "primary_sdk_attempt_ceiling": CASE_REQUEST_LIMIT,
        "request_bound_respected": request_bound,
        "protocol_execution_complete": protocol_complete,
        "research_experiment_complete": research_complete,
        "end_to_end_native_report_complete": report_native_complete,
        "observed_native_outcomes": outcomes,
        "dcpg_candidate_reporting": candidates,
    }
    if any(summary.get(key) != expected for key, expected in derived.items()):
        raise ValueError("Case C summary disagrees with its worker evidence")
    if summary.get("status") != ("completed" if research_complete else "failed"):
        raise ValueError("Case C summary status disagrees with its derived completion")
    return summary, counts


def finalize(
    output: Path,
    *,
    phase_path: Path,
    pre_smoke_path: Path,
    runner_path: Path,
    preflight_path: Path,
    smoke_path: Path,
    native_path: Path,
    case_summary_path: Path,
    case_plan_path: Path,
    execution_path: Path,
    wrapper_exit_path: Path,
    wrapper_sha256_path: Path,
    server_check_path: Path,
    cleanup_path: Path,
    binding_validator=None,
    smoke_binding_validator=None,
    plan_verifier=None,
) -> dict:
    """Write one exclusive terminal receipt while preserving scientific failures."""
    value: dict = {
        "protocol": PROTOCOL,
        "status": "incomplete",
        "input_paths": {
            name: str(path.resolve())
            for name, path in {
                "phase": phase_path,
                "pre_smoke": pre_smoke_path,
                "runner": runner_path,
                "preflight": preflight_path,
                "smoke": smoke_path,
                "native_smoke": native_path,
                "case_summary": case_summary_path,
                "case_plan": case_plan_path,
                "execution": execution_path,
                "wrapper_exit": wrapper_exit_path,
                "wrapper_checksums": wrapper_sha256_path,
                "server_check": server_check_path,
                "cleanup": cleanup_path,
            }.items()
        },
    }
    try:
        smoke_root = smoke_path.parent.resolve()
        require_path(output, smoke_root, "case-c-batch-summary.json")
        require_path(phase_path, smoke_root, "case-c-phase.json")
        require_path(wrapper_exit_path, smoke_root, "case-c-wrapper-exit-code.txt")
        phase = read(phase_path)
        validate_scheduler_decision(phase)
        plan, preflight, smoke, native, cleanup = validate_common_chain(
            phase=phase,
            pre_smoke_path=pre_smoke_path,
            runner_path=runner_path,
            preflight_path=preflight_path,
            smoke_path=smoke_path,
            native_path=native_path,
            cleanup_path=cleanup_path,
            case_plan_path=case_plan_path,
            wrapper_sha256_path=wrapper_sha256_path,
            plan_verifier=plan_verifier,
        )
        wrapper_exit = int(wrapper_exit_path.read_text(encoding="utf-8").strip())
        if not 0 <= wrapper_exit <= 255:
            raise ValueError("Case C wrapper exit code is invalid")
        synthetic_count = smoke.get("requests_started")
        native_count = native.get("native_requests_started")
        cleanup_case = cleanup.get("case_process", {})
        common_valid = (
            smoke.get("status") == "passed"
            and synthetic_count == SYNTHETIC_REQUEST_LIMIT
            and native.get("status") == "passed"
            and type(native_count) is int
            and 0 <= native_count <= NATIVE_REQUEST_LIMIT
            and native.get("checks", {}).get("no_online_auditors") is True
            and cleanup.get("status") == "server_stopped"
            and type(cleanup.get("server_pid")) is int
            and cleanup["server_pid"] > 1
            and cleanup_case.get("stopped") is True
        )
        value.update(
            phase=receipt(phase_path),
            pre_smoke=receipt(pre_smoke_path),
            wrapper_exit=receipt(wrapper_exit_path),
            wrapper_checksums=receipt(wrapper_sha256_path),
            cleanup=receipt(cleanup_path),
            terminal_plan_verification={
                "request_free_runner_verify": True,
                "real_llm_requests_started": 0,
            },
        )
        if phase.get("status") in UNSTARTED_STATUSES:
            if smoke_binding_validator is None:
                from agentdojo_lab.case_a_scout import recorded_smoke_binding

                smoke_binding_validator = recorded_smoke_binding
            smoke_binding = smoke_binding_validator(preflight_path, plan["config"]["base_url"])
            if (
                not common_valid
                or wrapper_exit != 3
                or server_check_path.exists()
                or smoke_binding.get("status") != "bound_before_case_calls"
                or smoke_binding.get("slurm_job_id") != phase.get("slurm_job_id")
                or cleanup_case != {"pid": 0, "term_sent": False, "kill_sent": False, "stopped": True}
            ):
                raise ValueError("Unstarted Case C terminal evidence is inconsistent")
            value.update(
                status="terminal_case_unstarted",
                framework_status="case_not_started_after_smoke",
                wrapper_exit_code=wrapper_exit,
                requests={
                    "synthetic": synthetic_count,
                    "native": native_count,
                    "case": 0,
                    "total": synthetic_count + native_count,
                    "limit": TOTAL_REQUEST_LIMIT,
                },
                scientific_outcome={"case_started": False, "reason": phase["status"]},
                artifacts={
                    "preflight": receipt(preflight_path),
                    "smoke": receipt(smoke_path),
                    "native_smoke": receipt(native_path),
                    "plan": receipt(case_plan_path),
                    "runner": receipt(runner_path),
                },
            )
            write_exclusive(output, value)
            return value
        if phase.get("status") != "reserved_before_case_calls":
            raise ValueError("Unknown Case C phase status")
        summary, slot_counts = validate_started_case(
            phase=phase,
            plan=plan,
            preflight_path=preflight_path,
            server_check_path=server_check_path,
            execution_path=execution_path,
            case_summary_path=case_summary_path,
            binding_validator=binding_validator,
        )
        if (
            type(cleanup_case.get("pid")) is not int
            or cleanup_case["pid"] <= 1
            or read(server_check_path).get("server_pid") != phase.get("server_pid")
            or cleanup.get("server_pid") != phase.get("server_pid")
        ):
            raise ValueError("Case C cleanup process identities differ from the launch evidence")
        case_count = sum(slot_counts)
        total = synthetic_count + native_count + case_count
        if not common_valid or case_count > CASE_REQUEST_LIMIT or total > TOTAL_REQUEST_LIMIT:
            raise ValueError("Smoke-plus-Case-C evidence exceeds its fixed request bounds")
        complete = (
            wrapper_exit == 0
            and summary.get("status") == "completed"
            and summary.get("protocol_execution_complete") is True
            and summary.get("end_to_end_native_report_complete") is True
            and summary.get("research_experiment_complete") is True
            and summary.get("all_worker_processes_distinct") is True
            and summary.get("all_recorded_run_ids_distinct") is True
            and summary.get("request_bound_respected") is True
            and summary.get("primary_sdk_attempt_ceiling") == CASE_REQUEST_LIMIT
            and plan.get("limits", {}).get("online_auditor_requests") == 0
            and plan.get("limits", {}).get("sdk_max_retries") == 0
            and plan.get("limits", {}).get("request_pacing") is False
        )
        value.update(
            status="complete_all_slots_terminal" if complete else "terminal_case_runner_failed",
            framework_status=(
                "case_runner_all_slots_terminal"
                if complete
                else "case_runner_returned_failure_or_incomplete_summary"
            ),
            wrapper_exit_code=wrapper_exit,
            requests={
                "synthetic": synthetic_count,
                "native": native_count,
                "case": case_count,
                "total": total,
                "limit": TOTAL_REQUEST_LIMIT,
                "per_case_session": dict(zip(SLOT_IDS, slot_counts, strict=True)),
            },
            artifacts={
                "preflight": receipt(preflight_path),
                "smoke": receipt(smoke_path),
                "native_smoke": receipt(native_path),
                "server_check": receipt(server_check_path),
                "execution": receipt(execution_path),
                "case_summary": receipt(case_summary_path),
                "case_plan": receipt(case_plan_path),
            },
            scientific_outcome={
                "case_started": True,
                "case_summary": receipt(case_summary_path),
                "interpretation": (
                    "Use the four observed-native transformed-memory outcomes and keep the "
                    "request-free DCPG candidate report separate from the native oracle."
                ),
            },
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        value["error_type"] = type(error).__name__
    write_exclusive(output, value)
    return value


def add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--runtime-source",
        nargs=2,
        action="append",
        default=[],
        metavar=("PLAN_KEY", "ABSOLUTE_PATH"),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--output", type=Path, required=True)
    validate.add_argument("--case-dir", type=Path, required=True)
    validate.add_argument("--smoke-dir", type=Path, required=True)
    validate.add_argument("--runner-path", type=Path, required=True)
    validate.add_argument("--site-path", type=Path, required=True)
    validate.add_argument("--site-sha256", required=True)
    validate.add_argument("--manifest-path", type=Path, required=True)
    validate.add_argument("--manifest-sha256", required=True)
    validate.add_argument("--executed-wrapper-path", type=Path, required=True)
    add_runtime_arguments(validate)
    reserve = commands.add_parser("reserve")
    reserve.add_argument("--output", type=Path, required=True)
    reserve.add_argument("--job-id", required=True)
    reserve.add_argument("--reported-job-id", required=True)
    reserve.add_argument("--remaining", required=True)
    reserve.add_argument("--time-limit", required=True)
    reserve.add_argument("--server-pid", type=int, required=True)
    reserve.add_argument("--case-dir", type=Path, required=True)
    reserve.add_argument("--pre-smoke-path", type=Path, required=True)
    reserve.add_argument("--runner-path", type=Path, required=True)
    reserve.add_argument("--wrapper-sha256-path", type=Path, required=True)
    add_runtime_arguments(reserve)
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--output", type=Path, required=True)
    cleanup.add_argument("--server-pid", type=int, required=True)
    cleanup.add_argument("--term-sent", choices=("true", "false"), required=True)
    cleanup.add_argument("--kill-sent", choices=("true", "false"), required=True)
    cleanup.add_argument("--stopped", choices=("true", "false"), required=True)
    cleanup.add_argument("--case-pid", type=int, required=True)
    cleanup.add_argument("--case-term-sent", choices=("true", "false"), required=True)
    cleanup.add_argument("--case-kill-sent", choices=("true", "false"), required=True)
    cleanup.add_argument("--case-stopped", choices=("true", "false"), required=True)
    cleanup.add_argument("--job-id", required=True)
    finish = commands.add_parser("finalize")
    for name in (
        "output",
        "phase-path",
        "pre-smoke-path",
        "runner-path",
        "preflight-path",
        "smoke-path",
        "native-path",
        "case-summary-path",
        "case-plan-path",
        "execution-path",
        "wrapper-exit-path",
        "wrapper-sha256-path",
        "server-check-path",
        "cleanup-path",
    ):
        finish.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "validate":
        validate_before_smoke(
            args.output,
            args.case_dir,
            args.smoke_dir,
            args.runner_path,
            parse_runtime_sources(args.runtime_source),
            args.site_path,
            args.site_sha256,
            args.manifest_path,
            args.manifest_sha256,
            args.executed_wrapper_path,
        )
        return 0
    if args.command == "reserve":
        result = reserve_phase(
            args.output,
            job_id=args.job_id,
            reported_job_id=args.reported_job_id,
            remaining=args.remaining,
            time_limit=args.time_limit,
            case_dir=args.case_dir,
            pre_smoke_path=args.pre_smoke_path,
            runner_path=args.runner_path,
            runtime_sources=parse_runtime_sources(args.runtime_source),
            wrapper_sha256_path=args.wrapper_sha256_path,
            server_pid=args.server_pid,
        )
        return 0 if result["status"] == "reserved_before_case_calls" else 3
    if args.command == "cleanup":
        result = record_cleanup(
            args.output,
            server_pid=args.server_pid,
            term_sent=args.term_sent == "true",
            kill_sent=args.kill_sent == "true",
            stopped=args.stopped == "true",
            case_pid=args.case_pid,
            case_term_sent=args.case_term_sent == "true",
            case_kill_sent=args.case_kill_sent == "true",
            case_stopped=args.case_stopped == "true",
            job_id=args.job_id,
        )
        return 0 if result["status"] == "server_stopped" else 1
    result = finalize(
        args.output,
        phase_path=args.phase_path,
        pre_smoke_path=args.pre_smoke_path,
        runner_path=args.runner_path,
        preflight_path=args.preflight_path,
        smoke_path=args.smoke_path,
        native_path=args.native_path,
        case_summary_path=args.case_summary_path,
        case_plan_path=args.case_plan_path,
        execution_path=args.execution_path,
        wrapper_exit_path=args.wrapper_exit_path,
        wrapper_sha256_path=args.wrapper_sha256_path,
        server_check_path=args.server_check_path,
        cleanup_path=args.cleanup_path,
    )
    return 0 if result["status"] in {"complete_all_slots_terminal", "terminal_case_unstarted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
