"""Offline, frozen pytest evidence runner for NT-AgentDojo method conformance.

The runner treats pytest node IDs as evidence selectors.  It first collects each
exact frozen node and only executes it when collection returns that node alone.
Subprocess output is never copied into the evidence bundle; only exit status,
byte counts, and SHA-256 digests are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "configs" / "neurotaint_conformance_v1.json"
PROTOCOL = "NT-AgentDojo-Conformance-v1"
EVIDENCE_PROTOCOL = "NT-AgentDojo-Conformance-Evidence-v1"
MILESTONE_IDS = tuple(f"M{number}" for number in range(1, 8))
EVIDENCE_FILES = (
    "config.json",
    "conformance-plan.json",
    "conformance-results.jsonl",
    "conformance-summary.json",
    "artifact-hashes.json",
)
MAX_CONFIG_BYTES = 2 * 1024 * 1024
FIXED_EXECUTION_CONTRACT = {
    "collection_mode": "collect_exact_node_then_execute_exact_node",
    "network_access": "disabled",
    "model_requests": "disabled",
    "case_timeout_seconds": 120,
    "stdout_stderr_storage": "sha256_and_byte_count_only",
}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "protocol",
    "execution_contract",
    "milestones",
    "live_judge_coverage",
}
MILESTONE_FIELDS = {"id", "title", "scope", "cases"}
CASE_FIELDS = {"id", "node_id", "branches", "invariants", "live_judge_evidence"}
LIVE_FIELDS = {
    "status",
    "claimed",
    "required_for_deterministic_pass",
    "known_observation",
    "next_evidence",
}
CASE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,79}$")
NODE_ID_PATTERN = re.compile(
    r"^tests/test_[a-z0-9_]+\.py::test_[A-Za-z0-9_]+(?:\[[\x20-\x7e]+\])?$"
)
SENSITIVE_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
SENSITIVE_ENV_NAMES = {
    "AUTHORIZATION",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
}
ProcessRunner = Callable[..., Mapping[str, Any]]
RUNTIME_PACKAGES = (
    "agentdojo",
    "httpx",
    "jinja2",
    "numpy",
    "openai",
    "pydantic",
    "pytest",
    "PyYAML",
    "sentence-transformers",
    "tokenizers",
    "torch",
    "transformers",
)


def _runtime_identity() -> dict[str, Any]:
    packages = {}
    for name in RUNTIME_PACKAGES:
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "unavailable"
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_full_version": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "pytest_invocation": "python -m pytest",
        "packages": packages,
    }


def _upstream_identity() -> dict[str, Any]:
    from agentdojo_lab.runner import require_upstream

    return require_upstream()


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON constant: {value}")


def _strict_json(raw: bytes) -> Any:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Conformance configuration exceeds its byte budget")
    if not raw.isascii():
        raise ValueError("Conformance configuration must contain ASCII bytes only")
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid conformance JSON") from exc


def _regular_file(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} must be a regular non-symlink file")
    return path


def _ascii_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError(f"{field} must be a nonempty ASCII string")
    return value


def _ascii_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a nonempty list")
    result = [_ascii_text(item, field) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{field} contains duplicates")
    return result


def load_config(path: Path | str = DEFAULT_CONFIG) -> tuple[dict[str, Any], bytes]:
    """Load and validate the frozen matrix without collecting or executing tests."""

    config_path = _regular_file(Path(path), "Conformance configuration")
    raw = config_path.read_bytes()
    config = _strict_json(raw)
    validate_config(config)
    return config, raw


def validate_config(config: Any, *, root: Path = ROOT) -> tuple[dict[str, Any], ...]:
    """Validate the matrix and return its cases in frozen execution order."""

    if not isinstance(config, dict) or set(config) != TOP_LEVEL_FIELDS:
        raise ValueError("Conformance configuration has unexpected top-level fields")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("Conformance schema_version must be integer one")
    if config["protocol"] != PROTOCOL:
        raise ValueError("Unexpected conformance protocol")
    if config["execution_contract"] != FIXED_EXECUTION_CONTRACT:
        raise ValueError("The offline execution contract is not the frozen v1 contract")

    live = config["live_judge_coverage"]
    if not isinstance(live, dict) or set(live) != LIVE_FIELDS:
        raise ValueError("Invalid live judge coverage declaration")
    if live["status"] != "not_evaluated_by_deterministic_conformance":
        raise ValueError("Live judge coverage must remain separate from deterministic conformance")
    if live["claimed"] is not False or live["required_for_deterministic_pass"] is not False:
        raise ValueError("Deterministic conformance cannot claim or require live judge evidence")
    _ascii_text(live["known_observation"], "live_judge_coverage.known_observation")
    _ascii_text(live["next_evidence"], "live_judge_coverage.next_evidence")

    milestones = config["milestones"]
    if not isinstance(milestones, list) or [item.get("id") for item in milestones if isinstance(item, dict)] != list(
        MILESTONE_IDS
    ):
        raise ValueError("Conformance milestones must be ordered exactly M1 through M7")

    case_ids: set[str] = set()
    node_ids: set[str] = set()
    ordered: list[dict[str, Any]] = []
    for milestone in milestones:
        if not isinstance(milestone, dict) or set(milestone) != MILESTONE_FIELDS:
            raise ValueError("Conformance milestone has unexpected fields")
        milestone_id = _ascii_text(milestone["id"], "milestone.id")
        _ascii_text(milestone["title"], f"{milestone_id}.title")
        _ascii_text(milestone["scope"], f"{milestone_id}.scope")
        cases = milestone["cases"]
        if not isinstance(cases, list) or not cases:
            raise ValueError(f"{milestone_id} must contain at least one frozen case")
        for case in cases:
            if not isinstance(case, dict) or set(case) != CASE_FIELDS:
                raise ValueError(f"{milestone_id} case has unexpected fields")
            case_id = _ascii_text(case["id"], "case.id")
            if not CASE_ID_PATTERN.fullmatch(case_id) or case_id in case_ids:
                raise ValueError(f"Invalid or duplicate case id: {case_id}")
            case_ids.add(case_id)
            node_id = _ascii_text(case["node_id"], f"{case_id}.node_id")
            if not NODE_ID_PATTERN.fullmatch(node_id) or node_id in node_ids:
                raise ValueError(f"Invalid or duplicate pytest node id: {node_id}")
            node_ids.add(node_id)
            relative_test = node_id.split("::", 1)[0]
            _regular_file(root / relative_test, f"Frozen test for {case_id}")
            _ascii_list(case["branches"], f"{case_id}.branches")
            _ascii_list(case["invariants"], f"{case_id}.invariants")
            if case["live_judge_evidence"] is not False:
                raise ValueError("Frozen deterministic cases cannot claim live judge evidence")
            ordered.append({"milestone_id": milestone_id, **case})
    return tuple(ordered)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _pretty(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2) + "\n"
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash_files(paths: Sequence[Path], *, root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(set(paths)):
        _regular_file(path, "Hashed evidence input")
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("Implementation evidence must stay inside the project root") from exc
        result[name] = _sha(path.read_bytes())
    return result


def _implementation_hashes(root: Path) -> dict[str, str]:
    package = root / "src" / "agentdojo_lab"
    paths = list(package.rglob("*.py"))
    paths.extend(
        path
        for path in (
            root / "scripts" / "verify_online_run.py",
            root / "scripts" / "verify_online_causal.py",
            root / "scripts" / "run_neurotaint_conformance.py",
        )
        if path.exists()
    )
    return _hash_files(paths, root=root)


def _test_hashes(cases: Sequence[Mapping[str, Any]], root: Path) -> dict[str, str]:
    paths = {root / case["node_id"].split("::", 1)[0] for case in cases}
    return _hash_files(list(paths), root=root)


def _environment_hashes(root: Path) -> dict[str, str]:
    paths = [root / name for name in ("pyproject.toml", "uv.lock", "upstream.json")]
    return _hash_files([path for path in paths if path.exists()], root=root)


def _manifest_hash(values: Mapping[str, str]) -> str:
    return _sha(_canonical(dict(values)))


def _sensitive_environment_name(name: str) -> bool:
    upper = name.upper()
    return name in SENSITIVE_ENV_NAMES or any(marker in upper for marker in SENSITIVE_ENV_MARKERS)


_SITECUSTOMIZE = """\
import socket

def _conformance_network_block(*_args, **_kwargs):
    raise OSError("Network access is disabled by the conformance runner")

socket.create_connection = _conformance_network_block
socket.getaddrinfo = _conformance_network_block
for _method in ("connect", "connect_ex", "sendto", "sendmsg"):
    if hasattr(socket.socket, _method):
        setattr(socket.socket, _method, _conformance_network_block)
"""


@contextmanager
def offline_environment() -> Iterator[dict[str, str]]:
    """Yield a credential-free environment with socket operations blocked at import."""

    with tempfile.TemporaryDirectory(prefix="nt-conformance-offline-") as directory:
        guard = Path(directory)
        (guard / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="ascii")
        environment = {
            name: value
            for name, value in os.environ.items()
            if not _sensitive_environment_name(name)
        }
        prior_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = str(guard) + (os.pathsep + prior_pythonpath if prior_pythonpath else "")
        environment.update(
            {
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "HF_HUB_OFFLINE": "1",
                "PIP_NO_INDEX": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "TOKENIZERS_PARALLELISM": "false",
                "TRANSFORMERS_OFFLINE": "1",
            }
        )
        yield environment


def run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run one bounded command and retain bytes only in the in-memory result."""

    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "elapsed_ms": (time.perf_counter_ns() - started) // 1_000_000,
            "error_type": None,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": None,
            "stdout": exc.stdout if isinstance(exc.stdout, bytes) else b"",
            "stderr": exc.stderr if isinstance(exc.stderr, bytes) else b"",
            "elapsed_ms": (time.perf_counter_ns() - started) // 1_000_000,
            "error_type": type(exc).__name__,
            "timed_out": True,
        }
    except (OSError, ValueError) as exc:
        return {
            "exit_code": None,
            "stdout": b"",
            "stderr": b"",
            "elapsed_ms": (time.perf_counter_ns() - started) // 1_000_000,
            "error_type": type(exc).__name__,
            "timed_out": False,
        }


def _process_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout", b"")
    stderr = result.get("stderr", b"")
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise ValueError("Process runners must return byte stdout and stderr")
    exit_code = result.get("exit_code")
    if exit_code is not None and type(exit_code) is not int:
        raise ValueError("Process exit_code must be an integer or null")
    elapsed_ms = result.get("elapsed_ms")
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        raise ValueError("Process elapsed_ms must be a nonnegative integer")
    error_type = result.get("error_type")
    if error_type is not None:
        _ascii_text(error_type, "process.error_type")
    timed_out = result.get("timed_out")
    if type(timed_out) is not bool:
        raise ValueError("Process timed_out must be a boolean")
    return {
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "stdout_sha256": _sha(stdout),
        "stdout_bytes": len(stdout),
        "stderr_sha256": _sha(stderr),
        "stderr_bytes": len(stderr),
        "error_type": error_type,
        "timed_out": timed_out,
    }


def _collected_nodes(stdout: bytes) -> list[str]:
    lines = stdout.decode("utf-8", errors="replace").splitlines()
    nodes: list[str] = []
    for line in lines:
        candidate = line.strip()
        if candidate.startswith("tests/") and "::" in candidate:
            nodes.append(candidate)
    return nodes


def evaluate_case(
    case: Mapping[str, Any],
    *,
    root: Path = ROOT,
    python: str | Path = sys.executable,
    env: Mapping[str, str],
    timeout_seconds: int = 120,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    """Collect and execute one exact frozen case under an already offline environment."""

    runner = process_runner or run_process
    node_id = case["node_id"]
    collect_command = [
        str(python),
        "-m",
        "pytest",
        "--collect-only",
        "-q",
        "-p",
        "no:cacheprovider",
        node_id,
    ]
    collected = runner(
        collect_command,
        cwd=root,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    collection = _process_evidence(collected)
    nodes = _collected_nodes(collected.get("stdout", b""))
    exact = collection["exit_code"] == 0 and nodes == [node_id]
    collection.update(
        {
            "status": "collected" if exact else "timeout" if collection["timed_out"] else "not_collected",
            "collected_node_ids": nodes,
            "requested_node_collected": exact,
        }
    )

    if not exact:
        execution = {
            "status": "not_run",
            "exit_code": None,
            "elapsed_ms": 0,
            "stdout_sha256": _sha(b""),
            "stdout_bytes": 0,
            "stderr_sha256": _sha(b""),
            "stderr_bytes": 0,
            "error_type": None,
            "timed_out": False,
            "requested_node_executed": False,
        }
        return {
            "collection": collection,
            "execution": execution,
            "status": "unknown",
            "failure_reason": "exact_node_not_collected",
        }

    execute_command = [
        str(python),
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--disable-warnings",
        node_id,
    ]
    executed = runner(
        execute_command,
        cwd=root,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    execution = _process_evidence(executed)
    execution_started = execution["exit_code"] is not None or execution["timed_out"]
    execution.update(
        {
            "status": (
                "passed"
                if execution["exit_code"] == 0
                else "timeout"
                if execution["timed_out"]
                else "failed"
                if execution_started
                else "not_started"
            ),
            "requested_node_executed": execution_started,
        }
    )
    passed = execution["exit_code"] == 0
    return {
        "collection": collection,
        "execution": execution,
        "status": "passed" if passed else "failed" if execution_started else "unknown",
        "failure_reason": (
            None
            if passed
            else "pytest_execution_failed"
            if execution_started
            else "pytest_process_not_started"
        ),
    }


def _exclusive_write(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run_conformance(
    output: Path | str,
    config_path: Path | str = DEFAULT_CONFIG,
    *,
    root: Path = ROOT,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    """Create a fresh deterministic conformance evidence bundle."""

    config, config_raw = load_config(config_path)
    cases = validate_config(config, root=root)
    execution_runner = "real_subprocess" if process_runner is None else "injected_test_runner"
    runtime_identity = _runtime_identity()
    upstream_identity = _upstream_identity()
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Conformance output must be a fresh path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()

    config_sha256 = _sha(config_raw)
    implementation_hashes = _implementation_hashes(root)
    test_hashes = _test_hashes(cases, root)
    environment_hashes = _environment_hashes(root)
    implementation_manifest_sha256 = _manifest_hash(implementation_hashes)
    test_manifest_sha256 = _manifest_hash(test_hashes)

    frozen_cases = [
        {
            "sequence": sequence,
            "milestone_id": case["milestone_id"],
            "case_id": case["id"],
            "node_id": case["node_id"],
            "branches": case["branches"],
            "invariants": case["invariants"],
            "live_judge_evidence": False,
        }
        for sequence, case in enumerate(cases, 1)
    ]
    plan = {
        "schema_version": 1,
        "protocol": EVIDENCE_PROTOCOL,
        "record_type": "conformance_plan",
        "created_at_utc": _utc_now(),
        "source_protocol": PROTOCOL,
        "case_count": len(cases),
        "milestone_ids": list(MILESTONE_IDS),
        "cases": frozen_cases,
        "execution_contract": config["execution_contract"],
        "execution_runner": execution_runner,
        "live_judge_coverage": config["live_judge_coverage"],
        "upstream": upstream_identity,
        "hashes": {
            "config_sha256": config_sha256,
            "implementation_manifest_sha256": implementation_manifest_sha256,
            "implementation_files": implementation_hashes,
            "test_manifest_sha256": test_manifest_sha256,
            "test_files": test_hashes,
            "environment_files": environment_hashes,
        },
        "runtime": runtime_identity,
    }
    _exclusive_write(destination / "config.json", config_raw)
    _exclusive_write(destination / "conformance-plan.json", _pretty(plan))

    results_path = destination / "conformance-results.jsonl"
    rows: list[dict[str, Any]] = []
    timeout_seconds = config["execution_contract"]["case_timeout_seconds"]
    with offline_environment() as env, results_path.open("xb") as handle:
        for frozen, case in zip(frozen_cases, cases, strict=True):
            evaluated = evaluate_case(
                case,
                root=root,
                env=env,
                timeout_seconds=timeout_seconds,
                process_runner=process_runner,
            )
            row = {
                "schema_version": 1,
                "protocol": EVIDENCE_PROTOCOL,
                "record_type": "conformance_case_result",
                **frozen,
                "config_sha256": config_sha256,
                "implementation_manifest_sha256": implementation_manifest_sha256,
                "test_manifest_sha256": test_manifest_sha256,
                "execution_runner": execution_runner,
                **evaluated,
            }
            raw = _canonical(row) + b"\n"
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            rows.append(row)

    groups = []
    for milestone in config["milestones"]:
        selected = [row for row in rows if row["milestone_id"] == milestone["id"]]
        counts = {
            status: sum(row["status"] == status for row in selected)
            for status in ("passed", "failed", "unknown")
        }
        all_collected = all(row["collection"]["requested_node_collected"] for row in selected)
        all_executed = all(row["execution"]["requested_node_executed"] for row in selected)
        passed = counts["passed"] == len(selected) and all_collected and all_executed
        groups.append(
            {
                "milestone_id": milestone["id"],
                "title": milestone["title"],
                "case_count": len(selected),
                "counts": counts,
                "all_required_nodes_collected": all_collected,
                "all_required_nodes_executed": all_executed,
                "status": "passed" if passed else "failed",
            }
        )
    final_implementation_hashes = _implementation_hashes(root)
    final_test_hashes = _test_hashes(cases, root)
    final_environment_hashes = _environment_hashes(root)
    final_runtime_identity = _runtime_identity()
    final_upstream_identity = _upstream_identity()
    config_source_unchanged = (
        _sha(_regular_file(Path(config_path), "Conformance configuration").read_bytes())
        == config_sha256
    )
    source_integrity = {
        "config_source_unchanged": config_source_unchanged,
        "implementation_files_unchanged": final_implementation_hashes == implementation_hashes,
        "test_files_unchanged": final_test_hashes == test_hashes,
        "environment_files_unchanged": final_environment_hashes == environment_hashes,
        "runtime_unchanged": final_runtime_identity == runtime_identity,
        "upstream_checkout_unchanged": final_upstream_identity == upstream_identity,
    }
    overall_passed = (
        execution_runner == "real_subprocess"
        and all(group["status"] == "passed" for group in groups)
        and all(source_integrity.values())
    )
    summary = {
        "schema_version": 1,
        "protocol": EVIDENCE_PROTOCOL,
        "record_type": "conformance_summary",
        "completed_at_utc": _utc_now(),
        "passed": overall_passed,
        "status": (
            "passed"
            if overall_passed
            else "test_only"
            if execution_runner == "injected_test_runner"
            else "failed"
        ),
        "execution_runner": execution_runner,
        "runtime": runtime_identity,
        "upstream": upstream_identity,
        "case_count": len(rows),
        "counts": {
            status: sum(row["status"] == status for row in rows)
            for status in ("passed", "failed", "unknown")
        },
        "groups": groups,
        "source_integrity": source_integrity,
        "hashes": {
            "config_sha256": config_sha256,
            "implementation_manifest_sha256": implementation_manifest_sha256,
            "test_manifest_sha256": test_manifest_sha256,
            "plan_sha256": _sha((destination / "conformance-plan.json").read_bytes()),
            "results_sha256": _sha(results_path.read_bytes()),
        },
        "live_judge_coverage": config["live_judge_coverage"],
        "interpretation": (
            "Passing requires real subprocess collection and execution for every frozen pytest node. "
            "It does not establish live judge coverage, causal ground truth, attack efficacy, or model accuracy."
        ),
    }
    _exclusive_write(destination / "conformance-summary.json", _pretty(summary))
    artifacts = {
        name: _sha((destination / name).read_bytes())
        for name in (
            "config.json",
            "conformance-plan.json",
            "conformance-results.jsonl",
            "conformance-summary.json",
        )
    }
    _exclusive_write(
        destination / "artifact-hashes.json",
        _pretty(
            {
                "schema_version": 1,
                "protocol": EVIDENCE_PROTOCOL,
                "record_type": "artifact_hashes",
                "artifacts": artifacts,
            }
        ),
    )
    return summary


def verify_conformance_bundle(
    directory: Path | str,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Verify a completed receipt against the current implementation and tests.

    The returned object contains only portable identities.  It is suitable for
    copying into a later frozen evaluation plan; absolute source paths are not
    part of the receipt identity.
    """

    evidence = Path(directory)
    if evidence.is_symlink() or not evidence.is_dir():
        raise ValueError("Conformance evidence must be a regular directory")
    files = {
        name: _regular_file(evidence / name, f"Conformance artifact {name}")
        for name in EVIDENCE_FILES
    }
    raw = {name: path.read_bytes() for name, path in files.items()}
    digests = {name: _sha(value) for name, value in raw.items()}

    try:
        artifact_manifest = _strict_json(raw["artifact-hashes.json"])
        plan = _strict_json(raw["conformance-plan.json"])
        summary = _strict_json(raw["conformance-summary.json"])
    except ValueError as exc:
        raise ValueError("Conformance evidence contains invalid JSON") from exc
    expected_artifacts = {
        name: digests[name]
        for name in EVIDENCE_FILES
        if name != "artifact-hashes.json"
    }
    if artifact_manifest != {
        "schema_version": 1,
        "protocol": EVIDENCE_PROTOCOL,
        "record_type": "artifact_hashes",
        "artifacts": expected_artifacts,
    }:
        raise ValueError("Conformance artifact manifest does not match exact file bytes")
    if (
        not isinstance(plan, dict)
        or plan.get("execution_runner") != "real_subprocess"
        or not isinstance(summary, dict)
        or summary.get("execution_runner") != "real_subprocess"
    ):
        raise ValueError("Conformance evidence requires real subprocess execution")

    config = _strict_json(raw["config.json"])
    registered_config = root / "configs" / "neurotaint_conformance_v1.json"
    if raw["config.json"] != _regular_file(
        registered_config, "Registered conformance configuration"
    ).read_bytes():
        raise ValueError("Conformance evidence does not use the registered exact matrix")
    cases = validate_config(config, root=root)
    config_sha256 = digests["config.json"]
    implementation_hashes = _implementation_hashes(root)
    test_hashes = _test_hashes(cases, root)
    environment_hashes = _environment_hashes(root)
    runtime_identity = _runtime_identity()
    upstream_identity = _upstream_identity()
    expected_plan_hashes = {
        "config_sha256": config_sha256,
        "implementation_manifest_sha256": _manifest_hash(implementation_hashes),
        "implementation_files": implementation_hashes,
        "test_manifest_sha256": _manifest_hash(test_hashes),
        "test_files": test_hashes,
        "environment_files": environment_hashes,
    }
    expected_frozen_cases = [
        {
            "sequence": sequence,
            "milestone_id": case["milestone_id"],
            "case_id": case["id"],
            "node_id": case["node_id"],
            "branches": case["branches"],
            "invariants": case["invariants"],
            "live_judge_evidence": False,
        }
        for sequence, case in enumerate(cases, 1)
    ]
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != 1
        or plan.get("protocol") != EVIDENCE_PROTOCOL
        or plan.get("record_type") != "conformance_plan"
        or plan.get("source_protocol") != PROTOCOL
        or plan.get("case_count") != len(cases)
        or plan.get("milestone_ids") != list(MILESTONE_IDS)
        or plan.get("cases") != expected_frozen_cases
        or plan.get("execution_contract") != FIXED_EXECUTION_CONTRACT
        or plan.get("execution_runner") != "real_subprocess"
        or plan.get("upstream") != upstream_identity
        or plan.get("hashes") != expected_plan_hashes
        or plan.get("runtime") != runtime_identity
    ):
        raise ValueError("Conformance plan is stale or inconsistent with the current codebase")

    result_rows = []
    for line in raw["conformance-results.jsonl"].splitlines():
        if not line:
            continue
        row = _strict_json(line)
        if not isinstance(row, dict):
            raise ValueError("Conformance result rows must be JSON objects")
        result_rows.append(row)
    expected_case_ids = [case["id"] for case in cases]
    if (
        len(result_rows) != len(cases)
        or [row.get("case_id") for row in result_rows] != expected_case_ids
        or [row.get("sequence") for row in result_rows] != list(range(1, len(cases) + 1))
        or any(row.get("status") != "passed" for row in result_rows)
        or any(
            row.get("schema_version") != 1
            or row.get("protocol") != EVIDENCE_PROTOCOL
            or row.get("record_type") != "conformance_case_result"
            or any(row.get(key) != frozen[key] for key in frozen)
            or not isinstance(row.get("collection"), dict)
            or row["collection"].get("status") != "collected"
            or row["collection"].get("exit_code") != 0
            or row["collection"].get("timed_out") is not False
            or row["collection"].get("error_type") is not None
            or row["collection"].get("requested_node_collected") is not True
            or row["collection"].get("collected_node_ids") != [frozen["node_id"]]
            or not isinstance(row.get("execution"), dict)
            or row["execution"].get("status") != "passed"
            or row["execution"].get("requested_node_executed") is not True
            or row["execution"].get("exit_code") != 0
            or row["execution"].get("timed_out") is not False
            or row["execution"].get("error_type") is not None
            or row.get("failure_reason") is not None
            or row.get("implementation_manifest_sha256")
            != expected_plan_hashes["implementation_manifest_sha256"]
            or row.get("test_manifest_sha256")
            != expected_plan_hashes["test_manifest_sha256"]
            or row.get("config_sha256") != config_sha256
            or row.get("execution_runner") != "real_subprocess"
            for row, frozen in zip(result_rows, expected_frozen_cases, strict=True)
        )
    ):
        raise ValueError("Conformance result inventory is incomplete or failed")

    expected_summary_hashes = {
        "config_sha256": config_sha256,
        "implementation_manifest_sha256": expected_plan_hashes[
            "implementation_manifest_sha256"
        ],
        "test_manifest_sha256": expected_plan_hashes["test_manifest_sha256"],
        "plan_sha256": digests["conformance-plan.json"],
        "results_sha256": digests["conformance-results.jsonl"],
    }
    groups = summary.get("groups") if isinstance(summary, dict) else None
    expected_group_sizes = {
        milestone["id"]: len(milestone["cases"]) for milestone in config["milestones"]
    }
    if (
        not isinstance(summary, dict)
        or summary.get("schema_version") != 1
        or summary.get("protocol") != EVIDENCE_PROTOCOL
        or summary.get("record_type") != "conformance_summary"
        or summary.get("passed") is not True
        or summary.get("status") != "passed"
        or summary.get("execution_runner") != "real_subprocess"
        or summary.get("runtime") != runtime_identity
        or summary.get("upstream") != upstream_identity
        or summary.get("case_count") != len(cases)
        or summary.get("counts")
        != {"passed": len(cases), "failed": 0, "unknown": 0}
        or not isinstance(groups, list)
        or [group.get("milestone_id") for group in groups if isinstance(group, dict)]
        != list(MILESTONE_IDS)
        or any(
            not isinstance(group, dict)
            or group.get("status") != "passed"
            or group.get("all_required_nodes_collected") is not True
            or group.get("all_required_nodes_executed") is not True
            or group.get("case_count") != expected_group_sizes.get(group.get("milestone_id"))
            or group.get("counts")
            != {
                "passed": expected_group_sizes.get(group.get("milestone_id")),
                "failed": 0,
                "unknown": 0,
            }
            for group in groups
        )
        or summary.get("source_integrity")
        != {
            "config_source_unchanged": True,
            "implementation_files_unchanged": True,
            "test_files_unchanged": True,
            "environment_files_unchanged": True,
            "runtime_unchanged": True,
            "upstream_checkout_unchanged": True,
        }
        or summary.get("hashes") != expected_summary_hashes
    ):
        raise ValueError("Conformance summary does not prove a complete current-code pass")

    return {
        "status": "passed",
        "protocol": EVIDENCE_PROTOCOL,
        "source_protocol": PROTOCOL,
        "case_count": len(cases),
        "milestone_ids": list(MILESTONE_IDS),
        "files": digests,
        "bundle_identity_sha256": _manifest_hash(digests),
        "implementation_manifest_sha256": expected_plan_hashes[
            "implementation_manifest_sha256"
        ],
        "test_manifest_sha256": expected_plan_hashes["test_manifest_sha256"],
        "runtime": runtime_identity,
        "upstream": upstream_identity,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run frozen offline NT-AgentDojo conformance cases.")
    parser.add_argument("--output", required=True, type=Path, help="Fresh evidence output directory.")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Frozen conformance matrix JSON.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_conformance(args.output, args.config)
    except (FileExistsError, OSError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "protocol": EVIDENCE_PROTOCOL,
                    "status": "error",
                    "error_type": type(exc).__name__,
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
