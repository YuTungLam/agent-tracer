"""Validate already downloaded smoke-job inputs. No network or GPU imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

CASE_A_WALLTIME_SECONDS = 7200
CASE_A_REQUEST_LIMIT = 16
CASE_A_TOTAL_REQUEST_LIMIT = 24
CASE_B_WALLTIME_SECONDS = 7200
CASE_B_REQUEST_LIMIT = 16
CASE_B_TOTAL_REQUEST_LIMIT = 24
CASE_C_WALLTIME_SECONDS = 7200
CASE_C_REQUEST_LIMIT = 16
CASE_C_TOTAL_REQUEST_LIMIT = 24
CASE_D_WALLTIME_SECONDS = 7200
CASE_D_REQUEST_LIMIT = 16
CASE_D_TOTAL_REQUEST_LIMIT = 24
CASE_E_WALLTIME_SECONDS = 12600
CASE_E_REQUEST_LIMIT = 48
CASE_E_TOTAL_REQUEST_LIMIT = 56


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def checked_file(path: Path, expected: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected a previously recorded SHA-256")
    if not path.is_file() or path.stat().st_size == 0 or sha256(path) != expected:
        raise ValueError("Local file missing, empty, or different from its frozen SHA-256")
    return {"path": str(path.resolve()), "sha256": expected, "bytes": path.stat().st_size}


def inspect_snapshot(snapshot: Path, revision: str) -> dict:
    if not snapshot.is_absolute() or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("An absolute local snapshot and exact commit revision are required")
    snapshot = snapshot.resolve(strict=True)
    names = {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"}
    index_path = snapshot / "model.safetensors.index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    weight_map = index.get("weight_map")
    if not isinstance(weight_map, dict) or not weight_map:
        raise ValueError("Missing safetensors weight inventory")
    shards = set(weight_map.values())
    if any(not isinstance(name, str) or not name.endswith(".safetensors") for name in shards):
        raise ValueError("Invalid safetensors shard names")
    names.update(shards)
    rows = []
    for name in sorted(names):
        candidate = snapshot / name
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(snapshot) or not resolved.is_file() or resolved.stat().st_size == 0:
            raise ValueError("Snapshot must be complete and materialized within its model directory")
        rows.append({"name": name, "bytes": resolved.stat().st_size,
                     "sha256": None if name in shards else sha256(resolved)})
    config = json.loads((snapshot / "config.json").read_text(encoding="utf-8"))
    if config.get("model_type") != "llama4" or config.get("quantization_config"):
        raise ValueError("This smoke protocol requires unquantized Llama 4 weights")
    text = config.get("text_config", {})
    if text.get("num_local_experts") != 16:
        raise ValueError("This smoke protocol requires Scout's sixteen experts")
    return {"path": str(snapshot), "declared_revision": revision,
            "model_id": "meta-llama/Llama-4-Scout-17B-16E-Instruct", "files": rows,
            "weight_integrity": "sizes measured; existence/nonempty checked; full hashes require download receipt"}


def verify_download_receipt(path: Path, model: dict) -> dict:
    """Bind the successful CPU hash pass to the exact local inventory being served."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if (data.get("status") != "all_selected_files_verified"
            or data.get("model_id") != model["model_id"]
            or data.get("revision") != model["declared_revision"]
            or Path(data.get("snapshot", "")).resolve() != Path(model["path"]).resolve()):
        raise ValueError("A completed matching model integrity receipt is required")
    rows = data.get("files", [])
    inventory = {row["path"]: row for row in rows}
    if len(inventory) != len(rows):
        raise ValueError("Duplicate download inventory entry")
    for file in model["files"]:
        row = inventory.get(file["name"], {})
        algorithm = row.get("algorithm")
        width = 64 if algorithm == "sha256" else 40 if algorithm == "git-blob-sha1" else 0
        if (row.get("verified") is not True or row.get("bytes") != file["bytes"]
                or width == 0 or not re.fullmatch(r"[0-9a-f]{%d}" % width, row.get("expected", ""))
                or (file["name"].endswith(".safetensors") and algorithm != "sha256")):
            raise ValueError("Download receipt does not verify the complete serving inventory")
        if not file["name"].endswith(".safetensors"):
            candidate = Path(model["path"]) / file["name"]
            if algorithm == "sha256":
                current = sha256(candidate)
            else:
                current = hashlib.sha1(
                    f"blob {candidate.stat().st_size}\0".encode() + candidate.read_bytes()
                ).hexdigest()
            if current != row["expected"]:
                raise ValueError("Serving metadata differs from its pinned download checksum")
    return {"path": str(path.resolve()), "sha256": sha256(path), "status": data["status"],
            "weight_hashes_rechecked_in_gpu_job": False}


def limit_records(
    *,
    native: bool,
    case_a_mode: bool,
    case_b_mode: bool = False,
    case_c_mode: bool = False,
    case_d_mode: bool = False,
    case_e_mode: bool = False,
) -> dict:
    """Describe smoke separately from an optional enclosing case-study job."""
    if sum((case_a_mode, case_b_mode, case_c_mode, case_d_mode, case_e_mode)) > 1:
        raise ValueError("A smoke job cannot enclose more than one case study")
    records = {
        "limits": {
            "scope": "smoke_phase_only",
            "gpus": 4,
            "intended_walltime_minutes": 60 if native else 45,
            "ready_seconds": 1500,
            "generative_requests": 8 if native else 4,
            "synthetic_requests": 4,
            "synthetic_request_timeout_seconds": 120,
            "synthetic_max_completion_tokens_per_request": 512,
            "native_requests": 4 if native else 0,
            "native_request_timeout_seconds": 180 if native else None,
            "native_max_completion_tokens_per_request": 2048 if native else None,
        }
    }
    if case_a_mode:
        records["enclosing_case_a_limits"] = {
            "scope": "smoke_plus_case_a_job",
            "walltime_seconds": CASE_A_WALLTIME_SECONDS,
            "total_generation_requests": CASE_A_TOTAL_REQUEST_LIMIT,
            "case_requests": CASE_A_REQUEST_LIMIT,
            "online_auditor_requests": 0,
        }
    if case_b_mode:
        records["enclosing_case_b_limits"] = {
            "scope": "smoke_plus_case_b_job",
            "walltime_seconds": CASE_B_WALLTIME_SECONDS,
            "total_generation_requests": CASE_B_TOTAL_REQUEST_LIMIT,
            "case_requests": CASE_B_REQUEST_LIMIT,
            "case_slots": 4,
            "requests_per_case_slot": 4,
            "online_auditor_requests": 0,
        }
    if case_c_mode:
        records["enclosing_case_c_limits"] = {
            "scope": "smoke_plus_case_c_job",
            "walltime_seconds": CASE_C_WALLTIME_SECONDS,
            "total_generation_requests": CASE_C_TOTAL_REQUEST_LIMIT,
            "case_requests": CASE_C_REQUEST_LIMIT,
            "case_sessions": 4,
            "requests_per_case_session": 4,
            "online_auditor_requests": 0,
        }
    if case_d_mode:
        records["enclosing_case_d_limits"] = {
            "scope": "smoke_plus_case_d_job",
            "walltime_seconds": CASE_D_WALLTIME_SECONDS,
            "total_generation_requests": CASE_D_TOTAL_REQUEST_LIMIT,
            "case_requests": CASE_D_REQUEST_LIMIT,
            "case_slots": 4,
            "requests_per_case_slot": 4,
            "online_auditor_requests": 0,
        }
    if case_e_mode:
        records["enclosing_case_e_limits"] = {
            "scope": "smoke_plus_case_e_job",
            "walltime_seconds": CASE_E_WALLTIME_SECONDS,
            "total_generation_requests": CASE_E_TOTAL_REQUEST_LIMIT,
            "case_requests": CASE_E_REQUEST_LIMIT,
            "case_slots": 12,
            "requests_per_case_slot": 4,
            "online_auditor_requests": 0,
        }
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        # Absolute paths avoid Apptainer treating a registry URI as a pull request.
        for variable in ("SCOUT_SNAPSHOT", "SCOUT_CHAT_TEMPLATE", "VLLM_SIF"):
            value = os.environ.get(variable, "")
            if not value.startswith("/") or any(ch in value for ch in "\n\r,:"):
                raise ValueError("Set absolute local paths without bind delimiters")
        native = os.environ.get("SCOUT_NATIVE_SMOKE", "0") == "1"
        case_a_mode = os.environ.get("SCOUT_CASE_A_MODE", "0") == "1"
        case_b_mode = os.environ.get("SCOUT_CASE_B_MODE", "0") == "1"
        case_c_mode = os.environ.get("SCOUT_CASE_C_MODE", "0") == "1"
        case_d_mode = os.environ.get("SCOUT_CASE_D_MODE", "0") == "1"
        case_e_mode = os.environ.get("SCOUT_CASE_E_MODE", "0") == "1"
        model = inspect_snapshot(Path(os.environ["SCOUT_SNAPSHOT"]), os.environ["SCOUT_REVISION"])
        receipt = {
            "protocol": "nesi-scout-smoke-v1",
            "model": model,
            "download_integrity": verify_download_receipt(Path(os.environ["SCOUT_MODEL_INTEGRITY"]), model),
            "template": checked_file(Path(os.environ["SCOUT_CHAT_TEMPLATE"]),
                                     os.environ["SCOUT_TEMPLATE_SHA256"]),
            "container": checked_file(Path(os.environ["VLLM_SIF"]), os.environ["VLLM_SIF_SHA256"]),
            "slurm_job_id": os.environ.get("SLURM_JOB_ID"),
            **limit_records(
                native=native,
                case_a_mode=case_a_mode,
                case_b_mode=case_b_mode,
                case_c_mode=case_c_mode,
                case_d_mode=case_d_mode,
                case_e_mode=case_e_mode,
            ),
        }
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Preflight failed ({type(error).__name__}); check local paths, snapshot and hashes.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
