"""Immutable gates and terminal accounting for Scout multi-candidate repeat/judge execution."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

PROTOCOL = "nesi-scout-smoke-multi-repeat-judge-v1"
REPEAT_PROTOCOL = "scout-multi-candidate-identical-judge-replay-v1"
SMOKE_PROTOCOL = "nesi-scout-smoke-v1"
NATIVE_PROTOCOL = "nesi-scout-native-clean-smoke-v1"
MODEL = "llama-4-scout-local"
ENDPOINT = "http://127.0.0.1:8000/v1"
WALLTIME_SECONDS = 12600
MINIMUM_REMAINING_SECONDS = 7800
COMMAND_TIMEOUT_SECONDS = 7200
SYNTHETIC_REQUEST_LIMIT = 4
NATIVE_REQUEST_LIMIT = 4
REPEAT_REQUEST_LIMIT = 36
TOTAL_REQUEST_LIMIT = 44
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_MODELS_RESPONSE_BYTES = 1024 * 1024
NATIVE_SMOKE_LOCAL_DEPENDENCIES = frozenset(
    {
        "src/agentdojo_lab/groq_adapter.py",
        "src/agentdojo_lab/html_report.py",
        "src/agentdojo_lab/inspection.py",
        "src/agentdojo_lab/observation.py",
        "src/agentdojo_lab/offline.py",
        "src/agentdojo_lab/pacing.py",
        "src/agentdojo_lab/providers.py",
        "src/agentdojo_lab/recording.py",
        "src/agentdojo_lab/runner.py",
        "src/agentdojo_lab/templates/agent_flow.js",
        "src/agentdojo_lab/templates/agent_flow.svg",
        "src/agentdojo_lab/templates/run_report.html",
        "upstream.json",
        "vendor/agentdojo/pyproject.toml",
        "vendor/agentdojo/src/agentdojo/__init__.py",
    }
)
PINNED_AGENTDOJO_RUNTIME_FILE_COUNT = 113
PINNED_AGENTDOJO_RUNTIME_TREE_SHA256 = (
    "4c58924aeb917f1daf29a4fcb11d79e716af8baf7266b73c592b39aa93a4edd7"
)
PANEL_IMPLEMENTATION_FILES = frozenset(
    {
        "scripts/run_scout_multi_repeat_judge.py",
        "src/agentdojo_lab/__init__.py",
        "src/agentdojo_lab/causal_replay.py",
        "src/agentdojo_lab/causal_v2.py",
        "src/agentdojo_lab/causal_v2_audit.py",
        "src/agentdojo_lab/counterfactual.py",
        "src/agentdojo_lab/counterfactual_audit.py",
        "src/agentdojo_lab/evaluation_review.py",
        "src/agentdojo_lab/html_report.py",
        "src/agentdojo_lab/inspection.py",
        "src/agentdojo_lab/judgment_formats.py",
        "src/agentdojo_lab/profiles.py",
        "src/agentdojo_lab/providers.py",
        "src/agentdojo_lab/scout_multi_repeat_judge.py",
        "src/agentdojo_lab/scout_repeat_judge.py",
    }
)
REQUIRED_BUNDLE_FILES = {
    "configs/local_scout.toml",
    "configs/scout_multi_repeat_judge_v1.json",
    "hpc/native_smoke.py",
    "hpc/preflight.py",
    "hpc/multi_repeat_judge_batch.py",
    "hpc/scout-smoke-content-composition-base.bash",
    "hpc/scout-smoke-multi-repeat-judge.sbatch",
    "hpc/scout-smoke.sbatch",
    "hpc/smoke.py",
    "hpc/tool_chat_template_llama4_pythonic_typed_v1.jinja",
    "pyproject.toml",
    "scripts/run_scout_multi_repeat_judge.py",
    "src/agentdojo_lab/__init__.py",
    "src/agentdojo_lab/causal_replay.py",
    "src/agentdojo_lab/causal_v2.py",
    "src/agentdojo_lab/causal_v2_audit.py",
    "src/agentdojo_lab/counterfactual.py",
    "src/agentdojo_lab/counterfactual_audit.py",
    "src/agentdojo_lab/evaluation_review.py",
    "src/agentdojo_lab/html_report.py",
    "src/agentdojo_lab/inspection.py",
    "src/agentdojo_lab/judgment_formats.py",
    "src/agentdojo_lab/profiles.py",
    "src/agentdojo_lab/providers.py",
    "src/agentdojo_lab/scout_repeat_judge.py",
    "src/agentdojo_lab/scout_multi_repeat_judge.py",
    "uv.lock",
} | NATIVE_SMOKE_LOCAL_DEPENDENCIES


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path.name}")
    return value


def read_jsonl(path: Path, *, maximum: int) -> list[dict]:
    if not path.is_file():
        return []
    values = []
    for raw in path.read_bytes().splitlines():
        if not raw.strip():
            continue
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError(f"Expected JSON objects in {path.name}")
        values.append(value)
    if len(values) > maximum:
        raise ValueError(f"{path.name} exceeds its fixed row budget")
    return values


def receipt(path: Path) -> dict:
    path = physical_file(path, path.name)
    return {"path": str(path), "sha256": digest(path)}


def write_exclusive(path: Path, value: dict) -> None:
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def physical_file(path: Path, label: str) -> Path:
    path = path.absolute()
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise ValueError(f"{label} must be a physical canonical file")
    return path


def physical_directory(path: Path, label: str) -> Path:
    path = path.absolute()
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise ValueError(f"{label} must be a physical canonical directory")
    return path


def snapshot(root: Path) -> dict[str, str]:
    root = physical_directory(root, "snapshot root")
    files = sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())
    result = {}
    for path in files:
        physical_file(path, "snapshot input")
        result[str(path.relative_to(root))] = digest(path)
    return result


def parse_manifest(path: Path) -> dict[str, str]:
    path = physical_file(path, "submission manifest")
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None or match.group(2) in entries:
            raise ValueError("Malformed or duplicate submission manifest entry")
        relative = Path(match.group(2))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Submission manifest paths must be bundle-relative")
        entries[match.group(2)] = match.group(1)
    return entries


def native_smoke_dependency_files(root: Path) -> frozenset[str]:
    """Return the complete frozen source closure needed by native_smoke.py."""
    root = physical_directory(root, "native-smoke bundle root")
    missing_local = {
        relative
        for relative in NATIVE_SMOKE_LOCAL_DEPENDENCIES
        if not (root / relative).is_file()
    }
    if missing_local:
        raise ValueError(
            "Submission bundle lacks the complete native-smoke dependency closure: "
            f"{sorted(missing_local)!r}"
        )

    vendor_root = root / "vendor/agentdojo/src/agentdojo"
    metadata = root / "vendor/agentdojo/pyproject.toml"
    vendor_files = [
        metadata,
        *sorted(
            path
            for path in vendor_root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix in {".py", ".txt", ".yaml"}
        ),
    ]
    vendor_receipts = {
        str(physical_file(path, "pinned AgentDojo runtime source").relative_to(root)): digest(path)
        for path in vendor_files
    }
    runtime_tree_sha256 = hashlib.sha256(canonical(vendor_receipts)).hexdigest()
    if (
        len(vendor_receipts) != PINNED_AGENTDOJO_RUNTIME_FILE_COUNT
        or runtime_tree_sha256 != PINNED_AGENTDOJO_RUNTIME_TREE_SHA256
    ):
        raise ValueError(
            "Submission bundle lacks the complete pinned AgentDojo runtime source tree"
        )
    return NATIVE_SMOKE_LOCAL_DEPENDENCIES | frozenset(vendor_receipts)


def required_bundle_files(root: Path) -> frozenset[str]:
    """Return every protocol and native-smoke source required when freezing a bundle."""
    return frozenset(REQUIRED_BUNDLE_FILES) | native_smoke_dependency_files(root)


def validate_bundle(bundle: Path, manifest: Path, manifest_sha256: str) -> dict:
    bundle = physical_directory(bundle, "submission bundle")
    manifest = physical_file(manifest, "submission manifest")
    if manifest != bundle / "submission-sha256.txt":
        raise ValueError("Submission manifest must be at the bundle root")
    if not SHA256_RE.fullmatch(manifest_sha256) or digest(manifest) != manifest_sha256:
        raise ValueError("Submission manifest hash mismatch")
    entries = parse_manifest(manifest)
    actual = snapshot(bundle)
    actual.pop("submission-sha256.txt", None)
    if entries != actual:
        raise ValueError("Submission manifest does not exactly bind the copied bundle")
    missing = required_bundle_files(bundle) - set(entries)
    if missing:
        raise ValueError(f"Submission bundle lacks required runtime files: {sorted(missing)!r}")
    return {
        "bundle": str(bundle),
        "manifest": receipt(manifest),
        "entry_count": len(entries),
        "entries_sha256": hashlib.sha256(canonical(entries)).hexdigest(),
    }


def validate_artifact_manifest(folder: Path) -> dict:
    recorded = read_json(folder / "artifact-manifest.json")
    actual = {
        path.name: digest(path)
        for path in sorted(folder.iterdir())
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    if recorded != actual:
        raise ValueError("Repeat/judge artifact manifest mismatch")
    return receipt(folder / "artifact-manifest.json")


def runtime_identity(bundle: Path) -> dict:
    """Bind the lab interpreter and transport/parser distributions to the lock."""
    names = ("agentdojo-lab", "agentdojo", "httpx", "openai", "pydantic")
    versions = {name: importlib.metadata.version(name) for name in names}
    lock = tomllib.loads((bundle / "uv.lock").read_text(encoding="utf-8"))
    locked = {
        row.get("name"): row.get("version")
        for row in lock.get("package", [])
        if isinstance(row, dict) and row.get("name") in names
    }
    if locked != versions:
        raise ValueError("Installed repeat/judge runtime differs from uv.lock")
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "packages": versions,
        "uv_lock": receipt(bundle / "uv.lock"),
        "pyproject": receipt(bundle / "pyproject.toml"),
    }


def validate_plan_only(folder: Path, bundle: Path, runner: Path, config: Path) -> dict:
    folder = physical_directory(folder, "plan-only output")
    bundle = physical_directory(bundle, "submission bundle")
    runner = physical_file(runner, "repeat/judge runner")
    config = physical_file(config, "repeat/judge config")
    if runner != bundle / "scripts/run_scout_multi_repeat_judge.py":
        raise ValueError("Runner escaped the frozen bundle")
    if config != bundle / "configs/scout_multi_repeat_judge_v1.json":
        raise ValueError("Protocol config escaped the frozen bundle")
    summary = read_json(folder / "summary.json")
    plan = read_json(folder / "plan.json")
    operations = read_jsonl(folder / "operation-plan.jsonl", maximum=REPEAT_REQUEST_LIMIT)
    results = read_jsonl(folder / "results.jsonl", maximum=REPEAT_REQUEST_LIMIT)
    if (
        summary.get("protocol") != REPEAT_PROTOCOL
        or summary.get("status") != "plan_only_complete"
        or summary.get("mode") != "plan_only"
        or summary.get("request_count") != 0
        or summary.get("planned_requests") != REPEAT_REQUEST_LIMIT
        or summary.get("native_tool_executions") != 0
        or summary.get("sdk_max_retries") != 0
        or summary.get("silent_retries_or_replacements") != 0
        or len(operations) != REPEAT_REQUEST_LIMIT
        or len(results) != REPEAT_REQUEST_LIMIT
        or (folder / "requests.jsonl").read_bytes() != b""
        or any(row.get("request_attempted") is not False for row in results)
    ):
        raise ValueError("Plan-only output violates the fixed request-free protocol")
    limits = plan.get("limits", {})
    if (
        plan.get("protocol") != REPEAT_PROTOCOL
        or limits.get("total_requests") != REPEAT_REQUEST_LIMIT
        or limits.get("sdk_max_retries") != 0
        or limits.get("native_tool_executions") != 0
        or limits.get("silent_retries_or_replacements") != 0
    ):
        raise ValueError("Plan-only manifest violates the fixed limits")
    if plan.get("transport") != {
        "http_client": "httpx.Client",
        "trust_env": False,
        "follow_redirects": False,
        "httpx_version": importlib.metadata.version("httpx"),
        "openai_version": importlib.metadata.version("openai"),
    }:
        raise ValueError("Plan-only transport policy is not the frozen direct loopback policy")
    implementation = plan.get("implementation_hashes", {})
    expected_implementation = {key: digest(bundle / key) for key in PANEL_IMPLEMENTATION_FILES}
    expected_implementation["protocol_config"] = digest(config)
    if implementation != expected_implementation:
        raise ValueError("Runner implementation inventory differs from the copied bundle")
    protocol_config = read_json(config)
    if (
        plan.get("sources") != protocol_config.get("sources")
        or plan.get("selection_rule") != protocol_config.get("selection_rule")
        or plan.get("selection_checks")
        != {
            "inclusion_independent_of_outcomes": True,
            "complete_structural_inventory": True,
            "source_exposure_structurally_bound": True,
            "neutralization_structurally_bound": True,
        }
    ):
        raise ValueError("Frozen multi-candidate selection differs from its config")
    source_inputs = plan.get("source_inputs")
    if not isinstance(source_inputs, list) or len(source_inputs) != 2:
        raise ValueError("Both archived source/plan snapshots must be recorded")
    by_run = {row.get("run_id"): row for row in source_inputs if isinstance(row, dict)}
    config_by_run = {}
    for candidate in protocol_config.get("sources", []):
        config_by_run.setdefault(candidate.get("run_id"), candidate)
    if set(by_run) != set(config_by_run) or len(config_by_run) != 2:
        raise ValueError("Source snapshot run inventory differs from the config")
    for run_id, candidate in config_by_run.items():
        recorded = by_run[run_id]
        plan_export = physical_directory(bundle / candidate["plan_export"], "plan export")
        source_run = physical_directory(bundle / candidate["source_run"], "source run")
        if (
            recorded.get("plan_export") != str(plan_export)
            or recorded.get("source_run") != str(source_run)
            or recorded.get("plan_export_hashes") != snapshot(plan_export)
            or recorded.get("source_hashes") != snapshot(source_run)
        ):
            raise ValueError("An archived plan/source full snapshot differs")
    if plan.get("support_inputs") != protocol_config.get("support"):
        raise ValueError("Archived support bindings differ from the frozen config")
    for roles in protocol_config.get("support", {}).values():
        for item in roles.values():
            path = bundle / item.get("path", "")
            if digest(physical_file(path, "support artifact")) != item.get("sha256"):
                raise ValueError("Archived support artifact differs")
    candidate_ids = [row.get("candidate_id") for row in operations]
    if (
        len(set(candidate_ids)) != 4
        or any(candidate_ids.count(candidate_id) != 9 for candidate_id in set(candidate_ids))
        or [row.get("global_sequence") for row in operations] != list(range(1, 37))
    ):
        raise ValueError("Plan-only operation inventory is not four candidates by nine slots")
    wrapper = plan.get("wrapper_binding", {})
    if (
        wrapper.get("mode") != "plan_only"
        or wrapper.get("launcher") != str(runner)
        or wrapper.get("launcher_sha256") != digest(runner)
        or wrapper.get("config") != str(config)
        or wrapper.get("config_sha256") != digest(config)
        or wrapper.get("local_key_status") != "missing"
        or wrapper.get("credential_value_recorded") is not False
    ):
        raise ValueError("Plan-only launcher binding differs")
    return {
        "folder": str(folder),
        "tree": snapshot(folder),
        "summary": receipt(folder / "summary.json"),
        "plan": receipt(folder / "plan.json"),
        "artifact_manifest": validate_artifact_manifest(folder),
    }


def validate_before_smoke(
    output: Path,
    *,
    bundle: Path,
    manifest: Path,
    manifest_sha256: str,
    site: Path,
    site_sha256: str,
    executed_wrapper: Path,
    plan_dir: Path,
    smoke_dir: Path,
    live_dir: Path,
    runner: Path,
    config: Path,
) -> dict:
    bundle = physical_directory(bundle, "submission bundle")
    site = physical_file(site, "private site file")
    executed_wrapper = physical_file(executed_wrapper, "executed wrapper")
    canonical_wrapper = physical_file(
        bundle / "hpc/scout-smoke-multi-repeat-judge.sbatch", "canonical wrapper"
    )
    if not SHA256_RE.fullmatch(site_sha256) or digest(site) != site_sha256:
        raise ValueError("Private site file hash mismatch")
    if digest(executed_wrapper) != digest(canonical_wrapper):
        raise ValueError("Slurm-spooled wrapper differs from the frozen canonical wrapper")
    for path, label in ((smoke_dir, "smoke"), (live_dir, "live repeat/judge")):
        path = path.absolute()
        if path.exists() or path.is_symlink():
            raise ValueError(f"{label} output must be fresh")
    value = {
        "protocol": PROTOCOL,
        "status": "prepared_inputs_validated_before_smoke",
        "bundle": validate_bundle(bundle, manifest, manifest_sha256),
        "site": receipt(site),
        "executed_wrapper": receipt(executed_wrapper),
        "canonical_wrapper": receipt(canonical_wrapper),
        "plan_only": validate_plan_only(plan_dir, bundle, runner, config),
        "runtime": runtime_identity(bundle),
        "smoke_dir": str(smoke_dir.absolute()),
        "live_dir": str(live_dir.absolute()),
        "limits": fixed_limits(),
    }
    write_exclusive(output, value)
    return value


def fixed_limits() -> dict:
    return {
        "walltime_seconds": WALLTIME_SECONDS,
        "minimum_remaining_seconds": MINIMUM_REMAINING_SECONDS,
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        "synthetic_requests": SYNTHETIC_REQUEST_LIMIT,
        "native_requests": NATIVE_REQUEST_LIMIT,
        "repeat_judge_requests": REPEAT_REQUEST_LIMIT,
        "total_generation_requests": TOTAL_REQUEST_LIMIT,
        "sdk_retries": 0,
        "native_tool_executions_by_repeat_runner": 0,
    }


def parse_slurm_duration(value: str) -> int:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("Missing Slurm duration")
    day_text, clock = (value.split("-", 1) if "-" in value else ("0", value))
    parts = clock.split(":")
    if len(parts) == 2:
        parts.insert(0, "0")
    if len(parts) != 3 or not day_text.isdigit() or any(not item.isdigit() for item in parts):
        raise ValueError("Invalid Slurm duration")
    days, hours, minutes, seconds = (int(day_text), *(int(item) for item in parts))
    if (days and hours > 23) or minutes > 59 or seconds > 59:
        raise ValueError("Invalid Slurm duration fields")
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def scheduler_decision(job_id: str, reported_job_id: str, remaining: str, time_limit: str) -> dict:
    status = "reserved_before_repeat_judge_calls"
    try:
        if not job_id or reported_job_id != job_id:
            raise ValueError("Slurm record belongs to another job")
        remaining_seconds = parse_slurm_duration(remaining)
        time_limit_seconds = parse_slurm_duration(time_limit)
        if time_limit_seconds <= 0 or remaining_seconds > time_limit_seconds:
            raise ValueError("Slurm time evidence is inconsistent")
        if time_limit_seconds > WALLTIME_SECONDS:
            status = "unstarted_walltime_limit_exceeded"
        elif remaining_seconds < MINIMUM_REMAINING_SECONDS:
            status = "unstarted_insufficient_remaining_time"
        error_type = None
    except ValueError as error:
        status = "unstarted_invalid_current_job_time_evidence"
        remaining_seconds = time_limit_seconds = None
        error_type = type(error).__name__
    result = {
        "status": status,
        "source": "squeue_current_job_%i_%L_%l",
        "reported_job_id": reported_job_id,
        "remaining_raw": remaining,
        "time_limit_raw": time_limit,
        "remaining_seconds": remaining_seconds,
        "time_limit_seconds": time_limit_seconds,
    }
    if error_type:
        result["error_type"] = error_type
    return result


def reserve_phase(
    output: Path,
    *,
    pre_smoke: Path,
    bundle: Path,
    manifest: Path,
    manifest_sha256: str,
    job_id: str,
    reported_job_id: str,
    remaining: str,
    time_limit: str,
    server_pid: int,
) -> dict:
    if type(server_pid) is not int or server_pid <= 1:
        raise ValueError("A live server PID is required")
    previous = read_json(pre_smoke)
    current_bundle = validate_bundle(bundle, manifest, manifest_sha256)
    plan_dir = Path(previous.get("plan_only", {}).get("folder", ""))
    if (
        previous.get("protocol") != PROTOCOL
        or previous.get("status") != "prepared_inputs_validated_before_smoke"
        or previous.get("bundle") != current_bundle
        or previous.get("plan_only", {}).get("tree") != snapshot(plan_dir)
        or previous.get("runtime") != runtime_identity(bundle)
    ):
        raise ValueError("Frozen inputs changed after pre-smoke validation")
    decision = scheduler_decision(job_id, reported_job_id, remaining, time_limit)
    value = {
        "protocol": PROTOCOL,
        "status": decision["status"],
        "slurm_job_id": job_id,
        "server_pid": server_pid,
        "time_decision": decision,
        "pre_smoke": receipt(pre_smoke),
        "bundle": current_bundle,
        "plan_only": previous["plan_only"],
        "runtime": previous["runtime"],
        "limits": fixed_limits(),
    }
    write_exclusive(output, value)
    return value


def local_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 8000
        or parsed.path != "/v1"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Expected the literal authenticated loopback Scout endpoint")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def models_auth_check(base_url: str, key: str, *, opener=None) -> dict:
    endpoint = local_url(base_url) + "/models"
    if not key or any(character in key for character in "\r\n"):
        raise ValueError("Missing local server key")
    wrong = "repeat-judge-intentionally-wrong-key"
    if wrong == key:
        wrong += "-2"
    client = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    checks = {}
    for name, authorization in (
        ("correct_key", "Bearer " + key),
        ("missing_key", None),
        ("wrong_key", "Bearer " + wrong),
    ):
        headers = {"Accept": "application/json"}
        if authorization:
            headers["Authorization"] = authorization
        request = urllib.request.Request(endpoint, headers=headers, method="GET")
        try:
            response = client.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(MAX_MODELS_RESPONSE_BYTES + 1)
            status, response_url = int(response.status), response.geturl()
        if len(body) > MAX_MODELS_RESPONSE_BYTES or response_url != endpoint:
            raise ValueError("Invalid or redirected /models response")
        if name == "correct_key":
            payload = json.loads(body)
            models = payload.get("data", []) if isinstance(payload, dict) else []
            if status != 200 or not any(
                isinstance(item, dict) and item.get("id") == MODEL for item in models
            ):
                raise ValueError("Correct key did not authorize the expected model")
            checks[name] = {"status_code": status, "expected_model_present": True}
        elif status not in {401, 403}:
            raise ValueError("Server accepted an absent or incorrect key")
        else:
            checks[name] = {"status_code": status, "rejected": True}
    return {"endpoint": endpoint, "generation_requests_started": 0, "checks": checks}


def process_identity(pid: int) -> dict:
    if type(pid) is not int or pid <= 1:
        raise ValueError("Invalid process PID")
    os.kill(pid, 0)
    proc = Path("/proc") / str(pid)
    stat = (proc / "stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
    if len(stat) < 20 or stat[0] in {"Z", "X", "x"}:
        raise ValueError("Process is not live")
    cmdline, cgroup = (proc / "cmdline").read_bytes(), (proc / "cgroup").read_bytes()
    if not cmdline or not cgroup:
        raise ValueError("Process identity is incomplete")
    return {
        "pid": pid,
        "start_ticks": int(stat[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "hostname": socket.gethostname(),
        "uid": proc.stat().st_uid,
        "cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
        "cgroup_sha256": hashlib.sha256(cgroup).hexdigest(),
    }


def scheduler_identity(job_id: str, *, run=subprocess.run) -> dict:
    result = run(
        ["squeue", "-h", "-j", job_id, "-o", "%i|%T|%B"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    lines = result.stdout.splitlines() if result.returncode == 0 else []
    if len(lines) != 1:
        raise ValueError("Slurm did not return one current job record")
    fields = lines[0].split("|")
    if (
        len(fields) != 3
        or fields[0] != job_id
        or fields[1] != "RUNNING"
        or fields[2].split(".", 1)[0] != socket.gethostname().split(".", 1)[0]
    ):
        raise ValueError("Slurm job is not running on this host")
    return {"reported_job_id": fields[0], "state": fields[1], "batch_host": fields[2]}


def server_check(
    output: Path,
    *,
    base_url: str,
    key: str,
    server_pid: int,
    job_id: str,
    identity_probe=None,
    scheduler_probe=None,
    auth_probe=None,
) -> dict:
    value = {
        "protocol": PROTOCOL,
        "status": "failed",
        "endpoint": base_url,
        "server_pid": server_pid,
        "slurm_job_id": job_id,
    }
    try:
        local_url(base_url)
        if os.environ.get("SLURM_JOB_ID") != job_id:
            raise ValueError("Server check is outside the recorded Slurm job")
        if os.environ.get("SCOUT_SERVER_PID") != str(server_pid):
            raise ValueError("Server PID environment binding differs")
        identity_probe = identity_probe or process_identity
        server, caller = identity_probe(server_pid), identity_probe(os.getpid())
        for field in ("boot_id", "hostname", "uid", "cgroup_sha256"):
            if server[field] != caller[field]:
                raise ValueError("Server is outside the allocation process scope")
        scheduler = (scheduler_probe or scheduler_identity)(job_id)
        auth = (auth_probe or models_auth_check)(base_url, key)
        if identity_probe(server_pid) != server:
            raise ValueError("Server identity changed during authentication")
        value.update(
            status="passed",
            model=MODEL,
            created_unix_ns=time.time_ns(),
            process_identity=server,
            scheduler=scheduler,
            models_auth=auth,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        value["error_type"] = type(error).__name__
    write_exclusive(output, value)
    return value


def record_cleanup(
    output: Path,
    *,
    job_id: str,
    server_pid: int,
    server_term: bool,
    server_kill: bool,
    server_stopped: bool,
    runner_pid: int,
    runner_term: bool,
    runner_kill: bool,
    runner_stopped: bool,
) -> dict:
    value = {
        "protocol": PROTOCOL,
        "slurm_job_id": job_id,
        "status": "cleanup_complete" if server_stopped and runner_stopped else "cleanup_unconfirmed",
        "server": {
            "pid": server_pid,
            "term_sent": server_term,
            "kill_sent": server_kill,
            "stopped": server_stopped,
        },
        "runner": {
            "pid": runner_pid,
            "term_sent": runner_term,
            "kill_sent": runner_kill,
            "stopped": runner_stopped,
        },
    }
    write_exclusive(output, value)
    return value


def _variability(comparisons: list[dict], field: str) -> dict:
    values = [row.get(field) for row in comparisons if type(row.get(field)) is bool]
    return {
        "definitive_repetitions": len(values),
        "unknown_repetitions": 3 - len(values),
        "true": sum(values),
        "false": len(values) - sum(values),
        "distinct_definitive_values": len(set(values)),
        "status": (
            "unknowns_present"
            if len(values) < 3
            else "disagreement"
            if len(set(values)) > 1
            else "unanimous"
        ),
    }


def validate_scientific_analysis(summary: dict, comparisons: list[dict], results: list[dict]) -> None:
    """Recompute every terminal comparison and pooled scientific claim."""
    candidate_ids = list(dict.fromkeys(row.get("candidate_id") for row in results))
    expected_per_candidate = []
    for candidate_id in candidate_ids:
        candidate_comparisons = [
            row for row in comparisons if row.get("candidate_id") == candidate_id
        ]
        if (
            len(candidate_comparisons) != 3
            or {row.get("repetition") for row in candidate_comparisons} != {1, 2, 3}
        ):
            raise ValueError("A candidate lacks its three frozen paired comparisons")
        for comparison in candidate_comparisons:
            repetition = comparison["repetition"]
            rows = {
                row.get("operation_type"): row
                for row in results
                if row.get("candidate_id") == candidate_id
                and row.get("repetition") == repetition
            }
            if set(rows) != {"sham_replay", "neutralized_replay", "isolated_judge"}:
                raise ValueError("A paired comparison lacks its three operation results")
            sham, neutralized, judge = (
                rows["sham_replay"],
                rows["neutralized_replay"],
                rows["isolated_judge"],
            )
            sham_value = (
                sham.get("exact_sink_proposed") if sham.get("status") == "observed" else None
            )
            replay_value = (
                neutralized.get("exact_sink_proposed")
                if sham_value is True and neutralized.get("status") == "observed"
                else None
            )
            prediction = (
                judge.get("judgment", {}).get("would_call_anyway")
                if judge.get("status") == "valid"
                else None
            )
            expected = {
                "run_id": sham.get("run_id"),
                "probe_id": sham.get("probe_id"),
                "sham_reproduced_sink": sham_value,
                "intervention_exact_sink_proposed": (
                    neutralized.get("exact_sink_proposed")
                    if neutralized.get("status") == "observed"
                    else None
                ),
                "observed_replay_would_call_anyway": replay_value,
                "observed_replay_effect": (
                    (not replay_value) if type(replay_value) is bool else None
                ),
                "judge_predicted_would_call_anyway": prediction,
                "agreement": (
                    prediction == replay_value
                    if type(prediction) is bool and type(replay_value) is bool
                    else None
                ),
                "status": (
                    "compared"
                    if type(prediction) is bool and type(replay_value) is bool
                    else "unknown"
                ),
            }
            if any(comparison.get(key) != value for key, value in expected.items()):
                raise ValueError("A paired comparison differs from its operation results")
        definitive = [row for row in candidate_comparisons if row.get("status") == "compared"]
        disagreements = sum(row.get("agreement") is False for row in definitive)
        expected_per_candidate.append(
            {
                "candidate_id": candidate_id,
                "probe_id": candidate_comparisons[0].get("probe_id"),
                "judge_variability": _variability(
                    candidate_comparisons, "judge_predicted_would_call_anyway"
                ),
                "replay_variability": _variability(
                    candidate_comparisons, "observed_replay_would_call_anyway"
                ),
                "paired_comparisons": len(definitive),
                "agreements": len(definitive) - disagreements,
                "disagreements": disagreements,
            }
        )
    definitive = [row for row in comparisons if row.get("status") == "compared"]
    disagreements = sum(row.get("agreement") is False for row in definitive)
    parser_complete = all(row.get("status") in {"observed", "valid"} for row in results)
    diagnostics = {
        "transport_direct_literal_loopback": True,
        "response_models_and_parsers_complete": parser_complete,
        "source_exposure_structurally_bound": True,
        "neutralization_structurally_bound": True,
        "input_plan_and_implementation_unchanged": True,
    }
    stable_complete = (
        len(definitive) == 12
        and all(diagnostics.values())
        and all(
            row["judge_variability"]["status"] == "unanimous"
            and row["replay_variability"]["status"] == "unanimous"
            for row in expected_per_candidate
        )
    )
    if stable_complete and disagreements == len(definitive):
        systematic = "systematic_opposite_judge_replay_direction_observed"
    elif stable_complete and disagreements == 0:
        systematic = "systematic_judge_replay_agreement_observed"
    elif stable_complete:
        systematic = "stable_but_mixed_candidate_relations_observed"
    else:
        systematic = "incomplete_or_within_candidate_variable_evidence"
    expected_analysis = {
        "predeclared_candidate_count": 4,
        "per_candidate": expected_per_candidate,
        "pooled_paired_comparisons": len(definitive),
        "pooled_agreements": len(definitive) - disagreements,
        "pooled_disagreements": disagreements,
        "diagnostic_checks": diagnostics,
        "systematic_pattern_status": systematic,
        "research_gap_status": "not_established_construction_scoped_second_task_family_needed",
        "standalone_gap_claim_permitted": False,
    }
    if summary.get("analysis") != expected_analysis:
        raise ValueError("Pooled or per-candidate analysis differs from terminal results")
    if summary.get("unknown_paired_comparisons") != 12 - len(definitive):
        raise ValueError("Unknown paired-comparison count differs from terminal results")


def validate_live_ledgers(folder: Path, plan_only_folder: Path) -> dict:
    folder = physical_directory(folder, "live repeat/judge output")
    plan_only_folder = physical_directory(plan_only_folder, "bound plan-only output")
    plan = read_json(folder / "plan.json")
    reference = read_json(plan_only_folder / "plan.json")
    operations = read_jsonl(folder / "operation-plan.jsonl", maximum=REPEAT_REQUEST_LIMIT)
    requests = read_jsonl(folder / "requests.jsonl", maximum=REPEAT_REQUEST_LIMIT)
    results = read_jsonl(folder / "results.jsonl", maximum=REPEAT_REQUEST_LIMIT)
    if plan.get("protocol") != REPEAT_PROTOCOL or len(operations) != REPEAT_REQUEST_LIMIT:
        raise ValueError("Live operation plan is not the fixed 36-slot protocol")
    bound_keys = {
        "schema_version",
        "protocol",
        "scope",
        "selection_rule",
        "sources",
        "selection_checks",
        "candidate_model",
        "model_change_is_new_protocol",
        "source_inputs",
        "support_inputs",
        "implementation_hashes",
        "endpoints",
        "request_settings",
        "limits",
        "transport",
        "ordering",
        "operation_ids",
        "identical_body_hashes",
    }
    if any(plan.get(key) != reference.get(key) for key in bound_keys) or (
        (folder / "operation-plan.jsonl").read_bytes()
        != (plan_only_folder / "operation-plan.jsonl").read_bytes()
    ):
        raise ValueError("Live plan differs from the request-free bound plan")
    live_wrapper = plan.get("wrapper_binding", {})
    reference_wrapper = reference.get("wrapper_binding", {})
    if (
        live_wrapper.get("mode") != "live"
        or live_wrapper.get("local_key_status") != "configured"
        or live_wrapper.get("credential_value_recorded") is not False
        or any(
            live_wrapper.get(key) != reference_wrapper.get(key)
            for key in (
                "launcher",
                "launcher_sha256",
                "config",
                "config_sha256",
                "python_executable",
                "python_version",
                "working_directory",
                "local_key_variable",
                "sigterm_policy",
            )
        )
    ):
        raise ValueError("Live launcher/runtime binding differs from plan-only preflight")
    limits = plan.get("limits", {})
    if (
        limits.get("total_requests") != REPEAT_REQUEST_LIMIT
        or limits.get("sdk_max_retries") != 0
        or limits.get("native_tool_executions") != 0
        or limits.get("silent_retries_or_replacements") != 0
    ):
        raise ValueError("Live plan violates request or tool-execution bounds")
    operation_ids = [row.get("operation_id") for row in operations]
    candidate_ids = [row.get("candidate_id") for row in operations]
    if (
        len(set(operation_ids)) != REPEAT_REQUEST_LIMIT
        or len(set(candidate_ids)) != 4
        or any(candidate_ids.count(candidate_id) != 9 for candidate_id in set(candidate_ids))
        or [row.get("global_sequence") for row in operations] != list(range(1, 37))
    ):
        raise ValueError("Live operation IDs are missing or duplicated")
    request_ids = [row.get("operation_id") for row in requests]
    result_ids = [row.get("operation_id") for row in results]
    if (
        request_ids != operation_ids[: len(request_ids)]
        or result_ids != operation_ids[: len(result_ids)]
        or len(request_ids) < sum(row.get("request_attempted") is True for row in results)
        or any(
            row.get("request_attempted") is True and row.get("operation_id") not in request_ids
            for row in results
        )
    ):
        raise ValueError("Incremental request/result ledgers violate slot order or attempt binding")
    for request, operation in zip(requests, operations, strict=False):
        if (
            request.get("binding_sha256") != operation.get("binding_sha256")
            or request.get("body_sha256") != operation.get("request_body_sha256")
            or request.get("body") != operation.get("body")
        ):
            raise ValueError("A request ledger row differs from its frozen operation")
    for result, operation in zip(results, operations, strict=False):
        expected_binding = (
            operation.get("probe_binding_sha256")
            if operation.get("operation_type") == "isolated_judge"
            and result.get("status") == "valid"
            else operation.get("binding_sha256")
        )
        if (
            result.get("binding_sha256") != expected_binding
            or result.get("request_body_sha256") != operation.get("request_body_sha256")
            or result.get("probe_binding_sha256") != operation.get("probe_binding_sha256")
        ):
            raise ValueError("A result ledger row differs from its frozen operation")
    summary_path = folder / "summary.json"
    if summary_path.is_file():
        summary = read_json(summary_path)
        comparisons = read_jsonl(folder / "comparisons.jsonl", maximum=12)
        status_counts = dict(Counter(row.get("status") for row in results))
        unknowns = sum(row.get("status") not in {"observed", "valid"} for row in results)
        if (
            len(results) != REPEAT_REQUEST_LIMIT
            or len(comparisons) != 12
            or summary.get("protocol") != REPEAT_PROTOCOL
            or summary.get("mode") != "live_openai_compatible"
            or summary.get("status") not in {"completed", "completed_with_unknowns"}
            or summary.get("planned_requests") != REPEAT_REQUEST_LIMIT
            or summary.get("candidate_count") != 4
            or summary.get("repetitions_per_candidate") != 3
            or summary.get("request_count") != len(requests)
            or summary.get("request_count")
            != sum(row.get("request_attempted") is True for row in results)
            or summary.get("status_counts") != status_counts
            or summary.get("unknown_operation_slots") != unknowns
            or summary.get("native_tool_executions") != 0
            or summary.get("sdk_max_retries") != 0
            or summary.get("silent_retries_or_replacements") != 0
            or summary.get("input_plan_and_implementation_unchanged") is not True
            or summary.get("identical_request_bodies_verified") is not True
            or summary.get("analysis", {}).get("standalone_gap_claim_permitted") is not False
            or summary.get("analysis", {}).get("research_gap_status")
            != "not_established_construction_scoped_second_task_family_needed"
        ):
            raise ValueError("Live summary differs from its complete ledgers")
        validate_scientific_analysis(summary, comparisons, results)
        validate_artifact_manifest(folder)
        state = "graceful_interrupted" if summary.get("termination_requested") is True else "complete"
    else:
        summary = None
        state = "abrupt_partial"
    return {
        "state": state,
        "folder": str(folder),
        "request_count": len(requests),
        "result_count": len(results),
        "unresolved_started_requests": len(requests)
        - sum(row.get("request_attempted") is True for row in results),
        "tree": snapshot(folder),
        "summary": receipt(summary_path) if summary is not None else None,
    }


def validate_server_receipt(server: dict, phase: dict) -> None:
    """Revalidate every allocation, process, model, and authentication claim."""
    expected_top = {
        "protocol",
        "status",
        "endpoint",
        "server_pid",
        "slurm_job_id",
        "model",
        "created_unix_ns",
        "process_identity",
        "scheduler",
        "models_auth",
    }
    identity = server.get("process_identity", {})
    scheduler = server.get("scheduler", {})
    auth = server.get("models_auth", {})
    checks = auth.get("checks", {})
    if (
        set(server) != expected_top
        or server.get("protocol") != PROTOCOL
        or server.get("status") != "passed"
        or server.get("endpoint") != ENDPOINT
        or server.get("model") != MODEL
        or server.get("server_pid") != phase.get("server_pid")
        or server.get("slurm_job_id") != phase.get("slurm_job_id")
        or type(server.get("created_unix_ns")) is not int
        or server["created_unix_ns"] <= 0
        or set(identity)
        != {
            "pid",
            "start_ticks",
            "boot_id",
            "hostname",
            "uid",
            "cmdline_sha256",
            "cgroup_sha256",
        }
        or identity.get("pid") != phase.get("server_pid")
        or type(identity.get("start_ticks")) is not int
        or identity["start_ticks"] < 0
        or type(identity.get("uid")) is not int
        or identity["uid"] < 0
        or any(
            not isinstance(identity.get(key), str) or not identity[key]
            for key in ("boot_id", "hostname")
        )
        or any(
            not isinstance(identity.get(key), str) or not SHA256_RE.fullmatch(identity[key])
            for key in ("cmdline_sha256", "cgroup_sha256")
        )
        or set(scheduler) != {"reported_job_id", "state", "batch_host"}
        or scheduler.get("reported_job_id") != phase.get("slurm_job_id")
        or scheduler.get("state") != "RUNNING"
        or not isinstance(scheduler.get("batch_host"), str)
        or scheduler["batch_host"].split(".", 1)[0]
        != identity["hostname"].split(".", 1)[0]
        or set(auth) != {"endpoint", "generation_requests_started", "checks"}
        or auth.get("endpoint") != ENDPOINT + "/models"
        or auth.get("generation_requests_started") != 0
        or set(checks) != {"correct_key", "missing_key", "wrong_key"}
        or checks.get("correct_key")
        != {"status_code": 200, "expected_model_present": True}
        or any(
            set(checks.get(name, {})) != {"status_code", "rejected"}
            or checks[name].get("status_code") not in {401, 403}
            or checks[name].get("rejected") is not True
            for name in ("missing_key", "wrong_key")
        )
    ):
        raise ValueError("Same-allocation server receipt has missing or inconsistent fields")


def finalize(
    output: Path,
    *,
    phase_path: Path,
    pre_smoke_path: Path,
    smoke_path: Path,
    native_path: Path,
    server_check_path: Path,
    cleanup_path: Path,
    runner_exit_path: Path,
    live_dir: Path,
) -> dict:
    value = {"protocol": PROTOCOL, "status": "incomplete", "limits": fixed_limits()}
    stage = "inputs"
    try:
        phase = read_json(phase_path)
        pre_smoke = read_json(pre_smoke_path)
        smoke = read_json(smoke_path)
        native = read_json(native_path)
        cleanup = read_json(cleanup_path)
        runner_exit = int(runner_exit_path.read_text(encoding="utf-8").strip())
        stage = "fixed_receipts"
        bundle_binding = phase.get("bundle", {})
        manifest_binding = bundle_binding.get("manifest", {})
        current_bundle = validate_bundle(
            Path(bundle_binding.get("bundle", "")),
            Path(manifest_binding.get("path", "")),
            manifest_binding.get("sha256", ""),
        )
        if (
            phase.get("protocol") != PROTOCOL
            or pre_smoke.get("protocol") != PROTOCOL
            or phase.get("pre_smoke") != receipt(pre_smoke_path)
            or phase.get("limits") != fixed_limits()
            or smoke.get("protocol") != SMOKE_PROTOCOL
            or smoke.get("status") != "passed"
            or smoke.get("requests_started") != SYNTHETIC_REQUEST_LIMIT
            or native.get("protocol") != NATIVE_PROTOCOL
            or native.get("status") != "passed"
            or type(native.get("native_requests_started")) is not int
            or not 0 <= native["native_requests_started"] <= NATIVE_REQUEST_LIMIT
            or native.get("checks", {}).get("no_online_auditors") is not True
            or cleanup.get("protocol") != PROTOCOL
            or cleanup.get("status") != "cleanup_complete"
            or cleanup.get("slurm_job_id") != phase.get("slurm_job_id")
            or cleanup.get("server", {}).get("pid") != phase.get("server_pid")
            or cleanup.get("server", {}).get("stopped") is not True
            or cleanup.get("runner", {}).get("stopped") is not True
            or current_bundle != bundle_binding
            or phase.get("runtime") != runtime_identity(Path(bundle_binding["bundle"]))
            or phase.get("plan_only", {}).get("tree")
            != snapshot(Path(phase.get("plan_only", {}).get("folder", "")))
        ):
            raise ValueError("Smoke, phase, or cleanup terminal evidence is invalid")
        base = smoke["requests_started"] + native["native_requests_started"]
        if str(phase.get("status", "")).startswith("unstarted_"):
            if runner_exit != 3 or live_dir.exists():
                raise ValueError("Unstarted phase unexpectedly launched repeat/judge inference")
            value.update(
                status="terminal_repeat_judge_unstarted",
                wrapper_exit_code=runner_exit,
                requests={"synthetic": 4, "native": native["native_requests_started"], "repeat": 0,
                          "total": base, "limit": TOTAL_REQUEST_LIMIT},
                scientific_outcome={"started": False, "reason": phase["status"]},
            )
        else:
            stage = "server_and_live_ledgers"
            server = read_json(server_check_path)
            validate_server_receipt(server, phase)
            if (
                phase.get("status") != "reserved_before_repeat_judge_calls"
                or type(cleanup.get("runner", {}).get("pid")) is not int
                or cleanup["runner"]["pid"] <= 1
            ):
                raise ValueError("Same-allocation loopback server evidence is invalid")
            ledger = validate_live_ledgers(
                live_dir, Path(phase.get("plan_only", {}).get("folder", ""))
            )
            total = base + ledger["request_count"]
            if total > TOTAL_REQUEST_LIMIT:
                raise ValueError("Combined request count exceeds the 44-call ceiling")
            expected_exit = {"complete": 0, "graceful_interrupted": 143}.get(ledger["state"])
            if expected_exit is not None and runner_exit != expected_exit:
                raise ValueError("Runner exit code disagrees with its terminal summary")
            value.update(
                status={
                    "complete": "complete_all_repeat_judge_slots_terminal",
                    "graceful_interrupted": "terminal_graceful_interruption_preserved",
                    "abrupt_partial": "terminal_partial_ledgers_preserved",
                }[ledger["state"]],
                wrapper_exit_code=runner_exit,
                requests={"synthetic": 4, "native": native["native_requests_started"],
                          "repeat": ledger["request_count"], "total": total,
                          "limit": TOTAL_REQUEST_LIMIT},
                repeat_judge=ledger,
                scientific_outcome={
                    "started": True,
                    "complete": ledger["state"] == "complete",
                    "interpretation": "Use only complete paired comparisons; unresolved slots remain unknown.",
                },
            )
        value["artifacts"] = {
            "phase": receipt(phase_path),
            "pre_smoke": receipt(pre_smoke_path),
            "smoke": receipt(smoke_path),
            "native": receipt(native_path),
            "cleanup": receipt(cleanup_path),
            "runner_exit": receipt(runner_exit_path),
        }
        if server_check_path.is_file():
            value["artifacts"]["server_check"] = receipt(server_check_path)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        value.update(
            error_type=type(error).__name__,
            failure={"stage": stage, "error_type": type(error).__name__, "message": str(error)},
        )
    write_exclusive(output, value)
    return value


def boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("Expected true or false")
    return value == "true"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    for name in ("output", "bundle", "manifest", "site", "executed-wrapper", "plan-dir",
                 "smoke-dir", "live-dir", "runner", "config"):
        validate.add_argument("--" + name, type=Path, required=True)
    validate.add_argument("--manifest-sha256", required=True)
    validate.add_argument("--site-sha256", required=True)
    reserve = commands.add_parser("reserve")
    for name in ("output", "pre-smoke", "bundle", "manifest"):
        reserve.add_argument("--" + name, type=Path, required=True)
    reserve.add_argument("--manifest-sha256", required=True)
    reserve.add_argument("--job-id", required=True)
    reserve.add_argument("--reported-job-id", required=True)
    reserve.add_argument("--remaining", required=True)
    reserve.add_argument("--time-limit", required=True)
    reserve.add_argument("--server-pid", type=int, required=True)
    server = commands.add_parser("server-check")
    server.add_argument("--output", type=Path, required=True)
    server.add_argument("--base-url", required=True)
    server.add_argument("--server-pid", type=int, required=True)
    server.add_argument("--job-id", required=True)
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--output", type=Path, required=True)
    cleanup.add_argument("--job-id", required=True)
    cleanup.add_argument("--server-pid", type=int, required=True)
    cleanup.add_argument("--runner-pid", type=int, required=True)
    for name in ("server-term", "server-kill", "server-stopped", "runner-term", "runner-kill",
                 "runner-stopped"):
        cleanup.add_argument("--" + name, choices=("true", "false"), required=True)
    finish = commands.add_parser("finalize")
    for name in ("output", "phase-path", "pre-smoke-path", "smoke-path", "native-path",
                 "server-check-path", "cleanup-path", "runner-exit-path", "live-dir"):
        finish.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "validate":
        validate_before_smoke(
            args.output, bundle=args.bundle, manifest=args.manifest,
            manifest_sha256=args.manifest_sha256, site=args.site,
            site_sha256=args.site_sha256, executed_wrapper=args.executed_wrapper,
            plan_dir=args.plan_dir, smoke_dir=args.smoke_dir, live_dir=args.live_dir,
            runner=args.runner, config=args.config,
        )
        return 0
    if args.command == "reserve":
        result = reserve_phase(
            args.output, pre_smoke=args.pre_smoke, bundle=args.bundle,
            manifest=args.manifest, manifest_sha256=args.manifest_sha256,
            job_id=args.job_id, reported_job_id=args.reported_job_id,
            remaining=args.remaining, time_limit=args.time_limit, server_pid=args.server_pid,
        )
        return 0 if result["status"] == "reserved_before_repeat_judge_calls" else 3
    if args.command == "server-check":
        result = server_check(
            args.output, base_url=args.base_url,
            key=os.environ.get("LOCAL_LLM_API_KEY", ""), server_pid=args.server_pid,
            job_id=args.job_id,
        )
        return 0 if result["status"] == "passed" else 1
    if args.command == "cleanup":
        result = record_cleanup(
            args.output, job_id=args.job_id, server_pid=args.server_pid,
            server_term=boolean(args.server_term), server_kill=boolean(args.server_kill),
            server_stopped=boolean(args.server_stopped), runner_pid=args.runner_pid,
            runner_term=boolean(args.runner_term), runner_kill=boolean(args.runner_kill),
            runner_stopped=boolean(args.runner_stopped),
        )
        return 0 if result["status"] == "cleanup_complete" else 1
    result = finalize(
        args.output, phase_path=args.phase_path, pre_smoke_path=args.pre_smoke_path,
        smoke_path=args.smoke_path, native_path=args.native_path,
        server_check_path=args.server_check_path, cleanup_path=args.cleanup_path,
        runner_exit_path=args.runner_exit_path, live_dir=args.live_dir,
    )
    return 0 if result["status"] != "incomplete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
