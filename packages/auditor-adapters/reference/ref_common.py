"""Shared plumbing for the offline reference auditors (standard library only).

Locates the lab source tree, imports the frozen lab helpers this package reuses
(the census matching rule, the H2 typed outcome oracle, the lexical tier), and
provides hashing, JSONL and Wilson-interval helpers.

Nothing here touches the network, a model, or a ``.env`` file. Saved benchmark
text and model output are untrusted data and are never interpreted as
instructions.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ADAPTERS = HERE.parent
COMMON = ADAPTERS / "common"
LAB = Path(os.environ.get("REFERENCE_LAB_ROOT") or ADAPTERS.parent / "agentdojo-lab").resolve()
LAB_SRC = LAB / "src"
CONFIG_PATH = HERE / "reference_config.json"

if str(LAB_SRC) not in sys.path:
    sys.path.insert(0, str(LAB_SRC))

# Frozen lab helpers (standard library only at import time).
from agentdojo_lab import authority_census as census  # noqa: E402,F401  (re-exported)
from agentdojo_lab import h2_cases  # noqa: E402,F401  (re-exported)

SCHEMA_RECORD = "reference-argument-record/v1"
SCHEMA_CALL = "reference-call-decision/v1"
SCHEMA_EPISODE = "reference-episode/v1"
SCHEMA_SUMMARY = "reference-summary/v1"


class ReferenceError(ValueError):
    """A trace, case, or config input is malformed (never silently repaired)."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def sha256_text_lf(path: Path) -> str:
    """SHA-256 of a text file with CRLF normalised to LF (CRLF-checkout stable)."""
    return sha256_bytes(Path(path).read_bytes().replace(b"\r\n", b"\n"))


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            count += 1
    return count


def load_config(path: Path | None = None) -> dict[str, Any]:
    config = read_json(path or CONFIG_PATH)
    if config.get("schema") != "reference-auditors-config/v1":
        raise ReferenceError("reference config schema must be reference-auditors-config/v1")
    return config


def wilson(k: int, n: int, z: float = 1.959963984540054) -> dict[str, Any]:
    """Two-sided 95% Wilson interval; n = 0 gives an empty record (no rate)."""
    if n <= 0:
        return {"k": k, "n": n, "rate": None, "lo": None, "hi": None}
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {"k": k, "n": n, "rate": round(p, 6), "lo": round(max(0.0, centre - half), 6),
            "hi": round(min(1.0, centre + half), 6)}


def code_hashes(paths: Iterable[Path]) -> dict[str, str]:
    """LF-normalised hashes of the code files that produced an output."""
    return {Path(p).name: sha256_text_lf(Path(p)) for p in paths if Path(p).is_file()}


# Lab files the reference results depend on (imported unchanged), hashed into every receipt.
LAB_FILES = tuple(f"src/agentdojo_lab/{name}" for name in (
    "authority_census.py", "h2_cases.py", "cascade.py", "lexical.py", "semantic.py", "profiles.py",
    "causal_v2.py", "counterfactual.py", "counterfactual_audit.py", "judgment_formats.py",
    "provenance.py", "policy.py", "neurotaint_lcs_sensitivity.py", "model_pins/minilm-v1.json",
)) + ("configs/workspace_policy_v1.yaml", "configs/authority_census_v2.json")


def lab_code_hashes(lab: Path | None = None) -> dict[str, str | None]:
    """LF-normalised hashes of ``LAB_FILES`` keyed by their lab-relative path (None if absent)."""
    root = Path(lab or LAB)
    return {rel: (sha256_text_lf(root / rel) if (root / rel).is_file() else None) for rel in LAB_FILES}


def injections_sha256(injections: Mapping[str, Any]) -> str:
    """The H2 runner's ``injection_payload_sha256`` rule (``h2_core.expand_stage``)."""
    return sha256_bytes(json.dumps(dict(injections), sort_keys=True, ensure_ascii=False).encode("utf-8"))
