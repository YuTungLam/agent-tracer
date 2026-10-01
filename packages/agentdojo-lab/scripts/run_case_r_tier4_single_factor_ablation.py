"""Frozen, request-free Case R Tier-4 single-factor ablation (offline v1).

Verifies the frozen protocol, audit input packet, LF-normalized scorer and the
pinned local MiniLM; runs Gate 0 parity on the 11 original pairs and stops with a
failure receipt on any mismatch; then scores every primary cell and wrong-target
control with the unchanged scorer and writes deterministic JSON. No agent,
provider or network request is made; saved source texts are data only.

After a completed run it renders ``reports/index.html`` from the saved JSON and
writes the bundle index (``README.md``, ``manifest.json``, ``checksums.sha256``).
``--render-only`` rewrites those four files from the existing ``config/``,
``derived/`` and ``logs/`` files (verified against the receipt's hashes) without
loading the encoder or rescoring anything.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import json
import os
import platform
import re
import socket
import subprocess
import sys
import traceback
from pathlib import Path

from agentdojo_lab import tier4_single_factor_ablation as ab
from agentdojo_lab import tier4_single_factor_ablation_html as report_html
from agentdojo_lab.semantic import ASSUMPTIONS, LocalMiniLMEncoder, SemanticMatcher, local_minilm_identity

OFFLINE_FLAGS = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY")
for _flag in OFFLINE_FLAGS:
    os.environ[_flag] = "1"

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
LAB_PREFIX = ROOT.relative_to(REPO_ROOT).as_posix()
CODE_FILES = (
    "src/agentdojo_lab/tier4_single_factor_ablation.py",
    "src/agentdojo_lab/tier4_single_factor_ablation_html.py",
    "scripts/run_case_r_tier4_single_factor_ablation.py",
    "tests/test_tier4_single_factor_ablation.py",
)
OUTPUT_FILES = (
    "config/frozen-config.json",
    "derived/packet.json",
    "derived/summary.json",
    "logs/parity.json",
    "logs/receipt.json",
)
PACKAGES = (
    "sentence-transformers", "transformers", "tokenizers", "torch", "huggingface-hub", "safetensors", "numpy",
)
DIRECTION_RULE = (
    "raised if delta > 1e-6; lowered if delta < -1e-6; otherwise unchanged within the protocol tolerance 1e-6"
)
LIMITS = [
    "Every edited text is a synthetic offline edit of a saved output; none is added to the original "
    "46-relation, 13 versus 13 denominators.",
    "The scores measure scorer sensitivity to specific strings and edits, not model reliance, injection "
    "success or a defence bypass.",
    "There is no statistical inference: each row is one deterministic text; distinct texts are counted once.",
    "For F2 and F3 the delta compares two targets within the same base text.",
    "Whole-source T4 can be decided by a chunk that does not contain the scored target.",
    "Tier 3 encodes the whole source; for sources over 256 tokens the unchanged scorer scores only the "
    "encoded view and reports it as truncated. Such rows are flagged; no T4 encoding was truncated.",
]


class GateFailure(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


class OfflineGuard:
    """Refuse and count any Python socket connection or DNS lookup during the run."""

    def __init__(self) -> None:
        self.attempts = 0
        self._saved: tuple = ()

    def _blocked(self, *args, **kwargs):
        self.attempts += 1
        raise OSError("network access refused by the offline protocol guard")

    def __enter__(self) -> OfflineGuard:
        self._saved = (socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo)
        socket.socket.connect = self._blocked
        socket.socket.connect_ex = self._blocked
        socket.create_connection = self._blocked
        socket.getaddrinfo = self._blocked
        return self

    def __exit__(self, *exc) -> None:
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = self._saved


class CountingEncoder:
    """Pass-through wrapper counting local encoder calls (never a remote request)."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls = 0
        self.texts = 0

    @property
    def metadata(self) -> dict:
        return self._inner.metadata

    def encode(self, texts):
        self.calls += 1
        self.texts += len(texts)
        return self._inner.encode(texts)


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True, encoding="utf-8").strip()


def git_bytes(cwd: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=cwd)


def file_hashes(path: Path) -> dict:
    data = path.read_bytes()
    return {"raw_sha256": ab.sha256_bytes(data), "lf_normalized_sha256": ab.lf_normalized_sha256(data)}


class Paths:
    def __init__(self, results_root: Path, output: Path):
        self.results_root = results_root
        self.output = output
        self.model = (ROOT / ab.MODEL_CACHE).resolve()
        self.replacements = []
        for absolute, relative in (
            (self.model, ab.MODEL_CACHE),
            (output, "<results>/" + output.relative_to(results_root).as_posix()),
            (results_root, "<results>"),
            (ROOT, "<agent-tracer>/" + LAB_PREFIX),
            (REPO_ROOT, "<agent-tracer>"),
            (Path.home(), "<home>"),
        ):
            for form in (str(absolute), absolute.as_posix()):
                self.replacements.append((form, relative))

    def scrub(self, value):
        if isinstance(value, dict):
            return {key: self.scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.scrub(item) for item in value]
        if isinstance(value, str):
            for old, new in self.replacements:
                value = value.replace(old, new)
            return value
        return value

    def check_no_absolute(self, text: str, name: str) -> None:
        lowered = text.lower()
        for old, _ in self.replacements:
            if old.lower() in lowered or old.lower().replace("\\", "\\\\") in lowered:
                raise ValueError(f"Absolute machine path would be written to {name}")
        if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:(?:\\\\|\\|/)", text):
            raise ValueError(f"Drive-letter path would be written to {name}")

    def write_json(self, relative: str, payload: dict) -> str:
        text = json.dumps(self.scrub(payload), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
        self.check_no_absolute(text, relative)
        target = self.output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = text.encode("utf-8")
        target.write_bytes(data)
        return ab.sha256_bytes(data)


def verify_inputs(paths: Paths) -> dict:
    protocol_path = ROOT / ab.PROTOCOL_FILE
    protocol_hashes = file_hashes(protocol_path)
    if ab.PROTOCOL_SHA256 not in protocol_hashes.values():
        raise ValueError("Frozen protocol hash mismatch")
    protocol_method = "raw_bytes" if protocol_hashes["raw_sha256"] == ab.PROTOCOL_SHA256 else "lf_normalized"
    criteria = ab.parse_hypotheses(protocol_path.read_text(encoding="utf-8"))

    packet_path = paths.results_root / ab.INPUT_PACKET
    packet_bytes = packet_path.read_bytes()
    if ab.sha256_bytes(packet_bytes) != ab.INPUT_PACKET_SHA256:
        raise ValueError("Frozen audit input packet hash mismatch")
    committed = git_bytes(paths.results_root, "show", f"{ab.RESULTS_COMMIT}:{ab.INPUT_PACKET}")
    if ab.sha256_bytes(committed) != ab.INPUT_PACKET_SHA256:
        raise ValueError("Audit input packet differs at the frozen results commit")
    packet = json.loads(packet_bytes.decode("utf-8"))

    crossover_path = paths.results_root / ab.CROSSOVER_PACKET
    crossover_bytes = crossover_path.read_bytes()
    crossover_sha = ab.sha256_bytes(crossover_bytes)
    if crossover_sha != packet["input_sha256"]["crossover"]:
        raise ValueError("Crossover packet differs from the hash recorded by the audit packet")
    crossover = json.loads(crossover_bytes.decode("utf-8"))

    scorer_path = ROOT / ab.SCORER
    scorer_hashes = file_hashes(scorer_path)
    if scorer_hashes["lf_normalized_sha256"] != ab.SCORER_LF_SHA256:
        raise ValueError("Scorer differs from the frozen blob beyond CRLF conversion")
    blob_sha = ab.sha256_bytes(git_bytes(ROOT, "show", f"HEAD:./{ab.SCORER}"))
    if blob_sha != ab.SCORER_LF_SHA256:
        raise ValueError("Committed scorer blob hash mismatch")

    identity = local_minilm_identity(paths.model, revision=ab.MODEL_REVISION)
    if (
        identity["model_id"] != ab.MODEL_ID
        or identity["revision"] != ab.MODEL_REVISION
        or identity["revision_verification"] != "pinned_manifest_verified"
    ):
        raise ValueError("Pinned MiniLM identity was not verified")
    return {
        "protocol_hashes": protocol_hashes,
        "protocol_method": protocol_method,
        "criteria": criteria,
        "packet": packet,
        "crossover": crossover,
        "crossover_sha256": crossover_sha,
        "scorer_hashes": scorer_hashes,
        "scorer_blob_sha256": blob_sha,
        "scorer_commit": git(ROOT, "log", "-1", "--format=%H", "--", ab.SCORER),
        "identity": identity,
        "pin_hashes": file_hashes(ROOT / ab.MODEL_PIN),
    }


def frozen_config(inputs: dict, bases: dict, cells: list[dict], controls: list[dict]) -> dict:
    return {
        "protocol": {
            "id": ab.PROTOCOL_ID,
            "file": ab.PROTOCOL_FILE,
            "file_base": "agent-tracer/" + LAB_PREFIX,
            "sha256": ab.PROTOCOL_SHA256,
            "sha256_verified_on": inputs["protocol_method"],
            "frozen_at": ab.PROTOCOL_FROZEN_AT,
        },
        "evidence_id": ab.EVIDENCE_ID,
        "inputs": {
            "results_commit": ab.RESULTS_COMMIT,
            "audit_packet": {"path": ab.INPUT_PACKET, "path_base": "agent-tracer-results", "sha256": ab.INPUT_PACKET_SHA256},
            "crossover_packet": {
                "path": ab.CROSSOVER_PACKET,
                "path_base": "agent-tracer-results",
                "sha256": inputs["crossover_sha256"],
                "use": "parity confirmation for byte-identical F2 texts only",
            },
        },
        "scorer": {
            "path": ab.SCORER,
            "lf_normalized_sha256": ab.SCORER_LF_SHA256,
            "semantic_threshold": ab.SEMANTIC_THRESHOLD,
            "coverage_threshold": ab.COVERAGE_THRESHOLD,
            "chunking": {"chunk_sentences": 3, "step_sentences": 2},
            "assumptions": ASSUMPTIONS,
            "calls": "SemanticMatcher.compare_tier3 and compare_tier4, independently",
        },
        "model": {
            "id": ab.MODEL_ID,
            "revision": ab.MODEL_REVISION,
            "cache": ab.MODEL_CACHE,
            "pin": ab.MODEL_PIN,
            "pin_sha256": inputs["pin_hashes"]["raw_sha256"],
            "manifest_sha256": inputs["identity"]["manifest_sha256"],
        },
        "tolerance": ab.TOLERANCE,
        "direction_rule": DIRECTION_RULE,
        "primary_measure": "localized T4: max cosine over chunks whose encoded visible text contains the complete scored target",
        "delta_labels": ab.DELTA_LABELS,
        "bases": [
            {
                "id": base.id,
                "label": base.label,
                "role": base.role,
                "target": base.target,
                "source_sha256": bases[base.id]["pair"]["source_sha256"],
                "source_codepoints": len(bases[base.id]["text"]),
                "f6_anchor": base.f6_anchor,
            }
            for base in ab.BASES
        ],
        "edit_strings": {
            "F1": {"old": ab.F1_OLD, "new": ab.F1_NEW, "contexts": ab.F1_CONTEXTS},
            "F1+": {"old": ab.ATTACKER, "new": ab.F1PLUS_NEW},
            "F2": "replace the target with the other original value",
            "F3": {"neutral_by_codepoint_length": {str(k): v for k, v in ab.NEUTRAL_BY_LENGTH.items()}},
            "F4": {key: {"old": old, "new": new} for key, (old, new) in ab.F4_EDITS.items()},
            "F5": {"delete_from_marker_to_end": ab.F5_MARKER},
            "F6": {"inserts": ab.F6_INSERTS},
            "F7": {"item": ab.F7_ITEM, "insert_before": ab.F7_MARKER, "k": list(ab.F7_KS)},
        },
        "variant_bases": {key: list(value) for key, value in ab.VARIANT_BASES.items()},
        "f2_exclusions": ab.F2_EXCLUDED,
        "cells": [
            {key: cell[key] for key in (
                "id", "factor", "factor_name", "variant", "base_id", "target", "target_role", "delta_comparison",
                "edits", "reversal_check", "neutral_check", "source_sha256", "source_codepoints",
                "designated_target_span", "wrong_target_controls",
            )}
            for cell in cells
        ],
        "wrong_target_controls": controls,
        "hypotheses": inputs["criteria"],
        "outputs": list(OUTPUT_FILES),
        "code_files": {path: file_hashes(ROOT / path) for path in CODE_FILES},
    }


def prior_attempts(output: Path) -> list[dict]:
    """Earlier stopped attempts preserved byte-for-byte under logs/attempt-*/."""
    attempts = []
    for folder in sorted((output / "logs").glob("attempt-*")):
        files = {
            path.relative_to(output).as_posix(): ab.sha256_bytes(path.read_bytes())
            for path in sorted(folder.rglob("*")) if path.is_file()
        }
        receipt_path = folder / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.is_file() else {}
        attempts.append({
            "folder": folder.relative_to(output).as_posix(),
            "files_sha256": files,
            "status": receipt.get("status"),
            "error": receipt.get("error"),
            "started_at_utc": receipt.get("started_at_utc"),
            "requests": receipt.get("requests"),
            "results_written": False,
            "note": (
                "Stopped by the runner's own validator, which had required every Tier-3 result to be "
                "untruncated; Tier 3 for the longest F7 texts exceeds 256 tokens. No score was written or "
                "inspected. The validator now accepts the scorer's flagged truncated Tier-3 view and still "
                "requires complete Tier-4 encodings. Cells, strings, thresholds and hypotheses are unchanged."
            ) if (receipt.get("error") or {}).get("message", "").startswith("Unscored or incomplete tier3") else None,
        })
    return attempts


def gate0(matcher: SemanticMatcher, pairs: list[dict]) -> tuple[dict, dict]:
    entries, rows = [], {}
    for pair in pairs:
        key = ab.pair_key(pair)
        row = ab.score_pair(
            matcher, pair_id=f"gate0:{key}", source=pair["source_text"], target=pair["target_text"],
            kind="gate0_original_pair",
        )
        differences = ab.compare_to_stored(pair, row)
        try:
            maxima = ab.max_abs_differences(pair, row)
        except TypeError:
            maxima = None
        entries.append({
            "id": key,
            "group": pair["group"],
            "occurrences": pair["occurrences"],
            "source_sha256": pair["source_sha256"],
            "target_text": pair["target_text"],
            "passed": not differences,
            "differences": differences,
            "max_abs_difference": maxima,
            "current": {
                "tier3_score": row["tier3"]["score"],
                "tier3_matched": row["tier3"]["matched"],
                "tier4_best_score": row["tier4"]["score"],
                "tier4_coverage": row["tier4"]["coverage"],
                "tier4_matched": row["tier4"]["matched"],
                "chunk_scores": [chunk.get("score") for chunk in row["tier4"]["chunks"]],
                "chunk_matched": [chunk.get("matched") for chunk in row["tier4"]["chunks"]],
            },
            "stored": {
                "tier3_score": pair["tier3_score"],
                "tier3_matched": pair["tier3_matched"],
                "tier4_best_score": pair["tier4_best_score"],
                "tier4_coverage": pair["tier4_coverage"],
                "tier4_matched": pair["tier4_matched"],
                "chunk_scores": [chunk["score"] for chunk in pair["chunks"]],
                "chunk_matched": [chunk["matched"] for chunk in pair["chunks"]],
            },
        })
        rows[(pair["source_sha256"], pair["target_text"])] = row
    overall = max(
        (value for entry in entries if entry["max_abs_difference"] for value in entry["max_abs_difference"].values()),
        default=None,
    )
    return {
        "status": "passed" if all(entry["passed"] for entry in entries) else "failed",
        "rule": "every T3 score, T4 best score, T4 coverage and per-chunk T4 score within 1e-6; every decision exact",
        "tolerance": ab.TOLERANCE,
        "pairs_compared": len(entries),
        "pairs_passed": sum(entry["passed"] for entry in entries),
        "max_abs_difference_overall": overall,
        "pairs": entries,
    }, rows


def measured(row: dict, base_localized: float | None, cell: dict | None) -> dict:
    row["localized"] = ab.localized_measure(row)
    row["whole_source"] = ab.whole_source_measure(row)
    if cell is not None:
        value = ab.delta(row["localized"]["score"], base_localized)
        row["delta"] = {
            "comparison": cell["delta_comparison"],
            "label": ab.DELTA_LABELS[cell["delta_comparison"]],
            "base_localized": base_localized,
            "edited_localized": row["localized"]["score"],
            "delta": value,
            "direction": ab.change_direction(value),
        }
    return row


def crossover_parity(crossover: dict, cell_rows: list[dict], base_rows: list[dict]) -> dict:
    rows = crossover["crossover"]["rows"]
    entries = []
    for row in [*base_rows, *cell_rows]:
        for other in rows:
            if other["source_text"] != row["source_text"]:
                continue
            same_target = other["target_text"] == row["target_text"]
            differences = ab.compare_to_crossover(row, other) if same_target else None
            entries.append({
                "row_id": row["id"],
                "crossover_cell_id": other["id"],
                "source_sha256": row["source_sha256"],
                "byte_identical_text": True,
                "same_target": same_target,
                "required_by_protocol": row["id"].startswith("F2:") and same_target,
                "passed": (not differences) if same_target else None,
                "differences": differences,
                "current": {"t3": row["tier3"]["score"], "t4": row["tier4"]["score"], "coverage": row["tier4"]["coverage"]},
                "crossover": {
                    "t3": other["tier3"]["score"], "t4": other["tier4"]["score"], "coverage": other["tier4"]["coverage"],
                },
            })
    required = [entry for entry in entries if entry["required_by_protocol"]]
    return {
        "rule": "an F2 text byte-identical to a scored crossover cell must reproduce that cell within 1e-6",
        "f2_byte_identical_cells": [entry["row_id"] for entry in required],
        "status": (
            "not_applicable_no_byte_identical_f2_text" if not required
            else "passed" if all(entry["passed"] for entry in required) else "failed"
        ),
        "required_comparisons": len(required),
        "entries": entries,
    }


def table_row(row: dict, cell: dict) -> dict:
    local, whole = row["localized"], row["whole_source"]
    return {
        "cell_id": cell["id"],
        "factor": cell["factor"],
        "variant": cell["variant"],
        "base_id": cell["base_id"],
        "target": cell["target"],
        "target_role": cell["target_role"],
        "delta_comparison": cell["delta_comparison"],
        "source_sha256": row["source_sha256"],
        "source_codepoints": row["source_codepoints"],
        "base_localized": row["delta"]["base_localized"],
        "localized": local["score"],
        "delta": row["delta"]["delta"],
        "direction": row["delta"]["direction"],
        "localized_chunk_index": local["chunk_index"],
        "localized_chunk_codepoints": local["chunk"]["codepoints"],
        "localized_chunk_span": local["chunk"]["span"],
        "localized_threshold_hit": local["threshold_hit"],
        "t4_best_score": whole["t4_best_score"],
        "t4_best_chunk_index": whole["t4_best_chunk_index"],
        "t4_best_chunk_contains_target": whole["t4_best_chunk_contains_target"],
        "t4_coverage": whole["t4_coverage"],
        "t4_decision": whole["t4_decision"],
        "t3_score": whole["t3_score"],
        "t3_decision": whole["t3_decision"],
        "t3_truncated": whole["t3_truncated"],
        "t3_source_input_tokens": whole["t3_source_input_tokens"],
        "exact_matched": row["exact"]["matched"],
    }


def run(paths: Paths, receipt: dict, guard: OfflineGuard) -> int:
    inputs = verify_inputs(paths)
    receipt["verification"] = {
        "protocol_sha256": ab.PROTOCOL_SHA256,
        "protocol_file_hashes": inputs["protocol_hashes"],
        "audit_packet_sha256": ab.INPUT_PACKET_SHA256,
        "audit_packet_verified_at_results_commit": ab.RESULTS_COMMIT,
        "crossover_packet_sha256": inputs["crossover_sha256"],
        "scorer_working_copy": inputs["scorer_hashes"],
        "scorer_committed_blob_sha256": inputs["scorer_blob_sha256"],
        "scorer_lf_sha256_expected": ab.SCORER_LF_SHA256,
        "scorer_commit": inputs["scorer_commit"],
        "model_pin": {"path": ab.MODEL_PIN, **inputs["pin_hashes"]},
    }
    receipt["model_identity"] = inputs["identity"]

    bases = ab.load_bases(inputs["packet"])
    pairs = ab.original_pairs(inputs["packet"])
    cells = ab.build_cells({key: value["text"] for key, value in bases.items()})
    controls = ab.build_controls(cells)
    receipt["outputs"]["config/frozen-config.json"] = paths.write_json(
        "config/frozen-config.json", frozen_config(inputs, bases, cells, controls)
    )

    encoder = CountingEncoder(LocalMiniLMEncoder(paths.model, revision=ab.MODEL_REVISION))
    matcher = SemanticMatcher(
        encoder, semantic_threshold=ab.SEMANTIC_THRESHOLD, coverage_threshold=ab.COVERAGE_THRESHOLD
    )
    if matcher.metadata["encoder"]["revision"] != ab.MODEL_REVISION:
        raise ValueError("Pinned MiniLM revision mismatch")
    receipt["encoder"] = encoder

    parity, gate_rows = gate0(matcher, pairs)
    parity_log = {"protocol": ab.PROTOCOL_ID, "gate0": parity, "crossover_parity": None}
    if parity["status"] != "passed":
        parity_log["note"] = "Gate 0 failed; no ablated text was scored."
        receipt["outputs"]["logs/parity.json"] = paths.write_json("logs/parity.json", parity_log)
        raise GateFailure("stopped_gate0_parity_failed", "Gate 0 environment parity failed")
    parity_log["note"] = "Gate 0 passed; crossover parity is added after the primary cells are scored."
    receipt["outputs"]["logs/parity.json"] = paths.write_json("logs/parity.json", parity_log)

    base_rows = []
    for base in ab.BASES:
        row = gate_rows[(bases[base.id]["pair"]["source_sha256"], base.target)]
        row = {**row, "id": f"base:{base.id}", "kind": "base_original_pair", "base_id": base.id,
               "base_label": base.label, "base_role": base.role}
        ab.validate_scored(row, primary=True)
        base_rows.append(measured(row, None, None))
    base_localized = {row["base_id"]: row["localized"]["score"] for row in base_rows}

    by_cell = {cell["id"]: cell for cell in cells}
    cell_rows = []
    for cell in cells:
        row = ab.score_pair(matcher, pair_id=cell["id"], source=cell["source"], target=cell["target"],
                            kind="primary_cell")
        if row["source_sha256"] != cell["source_sha256"]:
            raise ValueError(f"Scored text differs from the constructed cell: {cell['id']}")
        ab.validate_scored(row, primary=True)
        row.update({key: cell[key] for key in (
            "factor", "factor_name", "variant", "base_id", "base_label", "base_role", "base_source_sha256",
            "base_target", "target_role", "delta_comparison", "edits", "reversal_check", "neutral_check",
            "designated_target_span", "wrong_target_controls",
        )})
        row["cell_id"] = cell["id"]
        cell_rows.append(measured(row, base_localized[cell["base_id"]], cell))

    control_rows = []
    for control in controls:
        cell = by_cell[control["cell_id"]]
        row = ab.score_pair(matcher, pair_id=control["id"], source=cell["source"], target=control["target"],
                            kind="wrong_target_control")
        ab.validate_scored(row, primary=False)
        row.update({"cell_id": cell["id"], "variant": cell["variant"], "base_id": cell["base_id"],
                    "target_role": control["target_role"]})
        row["whole_source"] = ab.whole_source_measure(row)
        row["false_correspondence_candidate"] = row["tier3"]["matched"] is True or row["tier4"]["matched"] is True
        control_rows.append(row)

    cross = crossover_parity(inputs["crossover"], cell_rows, base_rows)
    parity_log["crossover_parity"] = cross
    parity_log.pop("note")
    if cross["status"] == "failed":
        parity_log["note"] = "Crossover parity failed; derived results were not written."
        receipt["outputs"]["logs/parity.json"] = paths.write_json("logs/parity.json", parity_log)
        raise GateFailure("stopped_crossover_parity_failed", "F2 crossover parity failed")

    table = {row["cell_id"]: {
        "base_localized": row["delta"]["base_localized"],
        "localized": row["localized"]["score"],
        "delta": row["delta"]["delta"],
    } for row in cell_rows}
    premises = {row["base_id"]: ab.metadata_premises(row) for row in base_rows}
    f7_rows = {row["cell_id"]: row["whole_source"] for row in cell_rows if row["factor"] == "F7"}
    hypotheses = ab.evaluate_hypotheses(table, premises, f7_rows, inputs["criteria"])

    delta_table = [table_row(row, by_cell[row["cell_id"]]) for row in cell_rows]
    control_table = [{
        "id": row["id"],
        "cell_id": row["cell_id"],
        "base_id": row["base_id"],
        "variant": row["variant"],
        "target": row["target_text"],
        "source_sha256": row["source_sha256"],
        "t3_score": row["tier3"]["score"],
        "t3_decision": row["tier3"]["matched"],
        "t4_best_score": row["tier4"]["score"],
        "t4_coverage": row["tier4"]["coverage"],
        "t4_decision": row["tier4"]["matched"],
        "t3_truncated": row["tier3"]["truncated"],
        "exact_matched": row["exact"]["matched"],
        "false_correspondence_candidate": row["false_correspondence_candidate"],
    } for row in control_rows]
    base_table = [{
        "base_id": row["base_id"],
        "label": row["base_label"],
        "role": row["base_role"],
        "target": row["target_text"],
        "source_sha256": row["source_sha256"],
        "source_codepoints": row["source_codepoints"],
        "localized": row["localized"]["score"],
        "localized_chunk_index": row["localized"]["chunk_index"],
        "localized_chunk_codepoints": row["localized"]["chunk"]["codepoints"],
        "localized_chunk_text": row["localized"]["chunk"]["text"],
        "t4_best_score": row["whole_source"]["t4_best_score"],
        "t4_best_chunk_index": row["whole_source"]["t4_best_chunk_index"],
        "t4_coverage": row["whole_source"]["t4_coverage"],
        "t4_decision": row["whole_source"]["t4_decision"],
        "t3_score": row["whole_source"]["t3_score"],
        "t3_decision": row["whole_source"]["t3_decision"],
        "t3_truncated": row["whole_source"]["t3_truncated"],
        "h4_premises": premises[row["base_id"]],
    } for row in base_rows]
    counts = {
        "bases": len(base_rows),
        "primary_cells": len(cell_rows),
        "distinct_primary_texts": len({row["source_sha256"] for row in cell_rows}),
        "wrong_target_controls": len(control_rows),
        "gate0_pairs": parity["pairs_compared"],
        "primary_localized_threshold_hits": sum(row["localized"]["threshold_hit"] is True for row in cell_rows),
        "primary_t4_whole_source_hits": sum(row["tier4"]["matched"] is True for row in cell_rows),
        "primary_t3_hits": sum(row["tier3"]["matched"] is True for row in cell_rows),
        "control_t3_positives": sum(row["tier3"]["matched"] is True for row in control_rows),
        "control_t4_positives": sum(row["tier4"]["matched"] is True for row in control_rows),
        "primary_t3_truncated": sum(row["tier3"]["truncated"] is True for row in cell_rows),
        "control_t3_truncated": sum(row["tier3"]["truncated"] is True for row in control_rows),
        "tier4_truncated_rows": sum(
            row["tier4"]["truncated"] is True for row in [*base_rows, *cell_rows, *control_rows]
        ),
    }
    common = {
        "protocol": ab.PROTOCOL_ID,
        "evidence_id": ab.EVIDENCE_ID,
        "status": "scored",
        "requests": {"agent": 0, "provider": 0, "network_connection_attempts": guard.attempts},
        "statistical_inference": "none; every row is one deterministic text and distinct texts are counted once",
    }
    packet = {
        **common,
        "boundary": LIMITS,
        "gate0_rows": list(gate_rows.values()),
        "base_rows": base_rows,
        "primary_rows": cell_rows,
        "wrong_target_rows": control_rows,
        "counts": counts,
    }
    summary = {
        **common,
        "tolerance": ab.TOLERANCE,
        "direction_rule": DIRECTION_RULE,
        "delta_labels": ab.DELTA_LABELS,
        "counts": counts,
        "base_table": base_table,
        "delta_table": delta_table,
        "f2_exclusions": ab.F2_EXCLUDED,
        "wrong_target_controls": {
            "rule": "each edited text paired with each original value that has zero literal occurrences in it; "
                    "never folded into primary rows",
            "count": len(control_rows),
            "t3_positives": counts["control_t3_positives"],
            "t4_positives": counts["control_t4_positives"],
            "false_correspondence_candidates": [row["id"] for row in control_rows if row["false_correspondence_candidate"]],
            "rows": control_table,
        },
        "t3_truncation": {
            "rule": "the unchanged scorer encodes at most 256 tokens; a longer Tier-3 source is scored on its "
                    "encoded view and flagged truncated (complete=false)",
            "primary_rows": [row["id"] for row in cell_rows if row["tier3"]["truncated"]],
            "control_rows": [row["id"] for row in control_rows if row["tier3"]["truncated"]],
        },
        "prior_attempts": receipt["prior_attempts"],
        "hypotheses": hypotheses,
        "hypothesis_outcomes": {key: value["outcome"] for key, value in hypotheses.items()},
        "gate0": {key: parity[key] for key in ("status", "pairs_compared", "pairs_passed", "max_abs_difference_overall")},
        "crossover_parity": {key: cross[key] for key in ("status", "required_comparisons", "f2_byte_identical_cells")},
        "limits": LIMITS,
    }
    receipt["outputs"]["derived/packet.json"] = paths.write_json("derived/packet.json", packet)
    receipt["outputs"]["derived/summary.json"] = paths.write_json("derived/summary.json", summary)
    receipt["outputs"]["logs/parity.json"] = paths.write_json("logs/parity.json", parity_log)
    receipt["rows_scored"] = {
        "gate0_pairs": len(pairs), "base_rows_reused_from_gate0": len(base_rows),
        "primary_cells": len(cell_rows), "wrong_target_controls": len(control_rows),
    }
    receipt["hypothesis_outcomes"] = summary["hypothesis_outcomes"]
    return 0


BUNDLE_FILES = ("README.md", "manifest.json", "checksums.sha256")
FILE_ROLES = {
    "README.md": "readme",
    "config/frozen-config.json": "frozen_configuration",
    "derived/packet.json": "derived_rows_with_full_chunk_detail",
    "derived/summary.json": "derived_summary_delta_table_and_hypothesis_outcomes",
    "logs/parity.json": "gate0_and_crossover_parity_log",
    "logs/receipt.json": "run_receipt_environment_packages_model_identity",
    "reports/index.html": "graphical_report",
}
BUNDLE_ROLES = {"manifest.json": "file_manifest", "checksums.sha256": "sha256_checksums"}
CREDENTIAL_PATTERNS = (
    r"gsk_[A-Za-z0-9]{20,}", r"\bsk-[A-Za-z0-9_-]{20,}", r"\bhf_[A-Za-z0-9]{20,}", r"\bAKIA[0-9A-Z]{16}\b",
    r"\bghp_[A-Za-z0-9]{20,}", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)


def bundle_paths(output: Path, exclude: tuple[str, ...]) -> list[str]:
    return sorted(
        path.relative_to(output).as_posix() for path in output.rglob("*")
        if path.is_file() and path.relative_to(output).as_posix() not in exclude
    )


def file_role(relative: str) -> str:
    if relative in FILE_ROLES:
        return FILE_ROLES[relative]
    if relative in BUNDLE_ROLES:
        return BUNDLE_ROLES[relative]
    if relative.startswith("logs/attempt-"):
        return "stopped_attempt_record_preserved_byte_for_byte"
    return "other"


def credential_scan(output: Path, names: list[str]) -> None:
    for relative in names:
        text = (output / relative).read_bytes().decode("utf-8", errors="replace")
        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, text):
                raise ValueError(f"Credential-like string matched {pattern!r} in {relative}")


def readme_text(m: dict, report: dict) -> str:
    summary, receipt, config = m["summary"], m["receipt"], m["config"]
    gate, counts = summary["gate0"], summary["counts"]
    breakdown = report_html.count_breakdown(m)
    identity = report_html.code_identity(m)
    protocol = config.get("protocol") or {}
    model = config.get("model") or {}
    inputs = config.get("inputs") or {}
    verification = receipt.get("verification") or {}
    attempts = summary.get("prior_attempts") or []
    requests = receipt.get("requests") or {}
    outward = sum((r.get("agent_requests") or 0) + (r.get("provider_requests") or 0)
                  + (r.get("network_connection_attempts") or 0)
                  for r in [requests, *[a.get("requests") or {} for a in attempts]])
    runs = "the final run" + (f" and {len(attempts)} earlier attempt{'' if len(attempts) == 1 else 's'}"
                              if attempts else "")
    hypotheses = "\n".join(
        f"| {key} {result['title']} | {result['outcome']} | {result['sub_claims_holding']} of "
        f"{result['sub_claims_total']} |" for key, result in summary["hypotheses"].items()
    )
    names = sorted(set(bundle_paths(m["output"], ())) | set(BUNDLE_FILES))
    files = "\n".join(f"| `{name}` | {file_role(name)} |" for name in names)
    code = "\n".join(f"  - {role}: `{path}`, `{digest}`" for role, path, digest in identity["files"]) or "  - none"
    attempt_lines = []
    for attempt in attempts:
        req = attempt.get("requests") or {}
        diff = report_html.attempt_config_diff(m, attempt.get("folder"))
        attempt_lines.append(
            f"  - `{attempt.get('folder')}`: {attempt.get('status')} "
            f"({(attempt.get('error') or {}).get('message')}). {req.get('local_encoder_calls')} local encoder "
            f"calls over {req.get('local_encoder_texts')} texts; {req.get('network_connection_attempts')} network "
            f"connection attempts; {(req.get('agent_requests') or 0) + (req.get('provider_requests') or 0)} agent "
            "or provider requests; "
            + ("results written" if attempt.get("results_written") else "no score written")
            + (f"; {diff}" if diff else "") + "."
        )
    untracked = report_html.and_join(identity["untracked_roles"])
    tree = (f"- agent-tracer at `{identity['head']}`, working tree {'dirty' if identity['dirty'] else 'clean'} "
            "when scored" + (f"; the {untracked} were untracked, so the scored code is identified by the hashes "
                             "above, not by a commit" if untracked else "")
            + ". The report renderer is not part of the scored code.")

    def unedited(cells: list, label: str) -> str:
        return f"; {len(cells)} {'is' if len(cells) == 1 else 'are'} {label}" if cells else ""

    lines = [
        "# Case R Tier-4 single-factor ablation (offline v1)",
        "",
        f"Status: scored offline, Gate 0 {gate['status']}, report rendered. Evidence ID `{summary['evidence_id']}`.",
        "",
        f"Protocol `{protocol.get('id')}`: `{protocol.get('file_base')}/{protocol.get('file')}`, SHA-256 "
        f"`{protocol.get('sha256')}`, frozen {protocol.get('frozen_at')}.",
        "",
        "## Question",
        "",
        "Which declared text features of the five saved Case R carrier outputs move the fixed scorer's Tier-4 "
        "score when they are changed one at a time? The answer is at the scorer level only.",
        "",
        "## Boundary",
        "",
        f"- Agent, provider and network requests: {outward} across {runs}. Scoring used only the local "
        f"`{model.get('id')}` revision `{model.get('revision')}`.",
        "- Every edited text is a synthetic single edit of a saved output. None enters the original "
        "46-relation, 13 versus 13 denominators.",
        "- The scores measure scorer sensitivity, not model reliance, injection success, attacker evasion or a "
        "defence result.",
        "- Saved texts in `derived/packet.json` are untrusted experiment data, never instructions.",
        "",
        "## Result",
        "",
        f"- Gate 0: {gate['status']}, {gate['pairs_passed']}/{gate['pairs_compared']} original pairs, max absolute "
        f"deviation {report_html.sci(gate['max_abs_difference_overall'])} (tolerance "
        f"{report_html.sci(summary['tolerance'])}).",
        f"- {counts['primary_cells']} primary cells ({counts['distinct_primary_texts']} distinct texts) on "
        f"{counts['bases']} bases; {counts['wrong_target_controls']} wrong-target controls.",
        "- Cell counts, not rates (each cell is one synthetic text; not comparable with the original 13 versus 13 "
        "split):",
        f"  - localized T4 at or above 0.60: {counts['primary_localized_threshold_hits']} cells, "
        f"{breakdown['local_distinct']} distinct chunk texts"
        + unedited(breakdown["local_unedited"], breakdown["local_unedited_label"]) + ";",
        f"  - whole-source T4 hits: {counts['primary_t4_whole_source_hits']} cells, {breakdown['whole_distinct']} "
        "distinct winning chunks" + unedited(breakdown["whole_unedited"], breakdown["whole_unedited_label"]) + ";",
        f"  - wrong-target controls: {counts['control_t4_positives']} T4 positives from "
        f"{breakdown['control_distinct']} chunk texts, {counts['control_t3_positives']} T3 positives.",
        "",
        "| Hypothesis | Recorded outcome | Sub-claims holding |",
        "| --- | --- | --- |",
        hypotheses,
        "",
        "The runner supplied the supported / mixed / not supported aggregation rule; the frozen protocol names "
        "the labels but does not define how clauses combine. `reports/index.html` shows every sub-claim, the "
        "adjudicated reading and the over-read warnings.",
        "",
        "## Files",
        "",
        "| Path | Role |",
        "| --- | --- |",
        files,
        "",
        "`manifest.json` lists every file except itself and `checksums.sha256`, with its size and SHA-256. "
        "`checksums.sha256` covers every file except itself.",
        "",
        "## Provenance",
        "",
        f"- Frozen inputs at agent-tracer-results commit `{inputs.get('results_commit')}`; audit packet SHA-256 "
        f"`{(inputs.get('audit_packet') or {}).get('sha256')}`.",
        f"- Scorer `semantic.py` LF-normalized SHA-256 "
        f"`{(verification.get('scorer_working_copy') or {}).get('lf_normalized_sha256')}` (committed blob "
        f"`{verification.get('scorer_committed_blob_sha256')}`).",
        "- Scored code, from `config/frozen-config.json` `code_files` (LF-normalized SHA-256):",
        code,
        tree,
        "- Earlier attempts:",
        "\n".join(attempt_lines) or "  - none",
        f"- Report: `{report['report']}`, rendered by `{report['renderer']}`, SHA-256 `{report['sha256']}`.",
        "",
        "## Re-render without rescoring",
        "",
        "```text",
        "cd agent-tracer/packages/agentdojo-lab",
        "PYTHONUTF8=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 python "
        "scripts/run_case_r_tier4_single_factor_ablation.py --results-root <RESULTS_ROOT> --output "
        f"<RESULTS_ROOT>/experiments/{summary['evidence_id']} --render-only",
        "```",
        "",
        "This verifies the saved JSON against `logs/receipt.json`, loads no encoder, and rewrites "
        "`reports/index.html`, `README.md`, `manifest.json` and `checksums.sha256`.",
    ]
    return "\n".join(lines) + "\n"


def write_bundle_files(paths: Paths, report: dict) -> dict:
    """Write README.md, manifest.json and checksums.sha256 from the saved files (deterministic)."""
    output = paths.output
    m = report_html.prepare(report_html.load_inputs(output))
    m["output"] = output
    summary, receipt, config = m["summary"], m["receipt"], m["config"]
    readme = readme_text(m, report)
    paths.check_no_absolute(readme, "README.md")
    (output / "README.md").write_bytes(readme.encode("utf-8"))
    listed = bundle_paths(output, ("manifest.json", "checksums.sha256"))
    credential_scan(output, listed)
    files = []
    for relative in listed:
        data = (output / relative).read_bytes()
        files.append({"path": relative, "role": file_role(relative), "bytes": len(data),
                      "sha256": ab.sha256_bytes(data)})
    requests = receipt.get("requests") or {}
    tracer = receipt.get("agent_tracer") or {}
    manifest = {
        "schema_version": 1,
        "experiment_id": summary["evidence_id"],
        "status": "scored_and_rendered",
        "experiment_type": "offline_single_factor_scorer_ablation",
        "protocol": config.get("protocol"),
        "scoring_run": {"started_at_utc": receipt.get("started_at_utc"),
                        "finished_at_utc": receipt.get("finished_at_utc"), "status": receipt.get("status")},
        "execution": {
            "mode": "offline_local_semantic_scoring",
            "agent_requests": requests.get("agent_requests"),
            "provider_requests": requests.get("provider_requests"),
            "network_connection_attempts": requests.get("network_connection_attempts"),
            "local_encoder_calls": requests.get("local_encoder_calls"),
            "local_encoder_texts": requests.get("local_encoder_texts"),
            "request_free": True,
        },
        "prior_attempts": [
            {key: attempt.get(key) for key in ("folder", "status", "results_written", "requests", "files_sha256")}
            for attempt in summary.get("prior_attempts") or []
        ],
        "agent_tracer": {
            "head_at_scoring": tracer.get("head"),
            "dirty_at_scoring": tracer.get("dirty"),
            "status_porcelain_at_scoring": tracer.get("status_porcelain"),
            "scored_code_files": config.get("code_files"),
            "render_code_files": {path: file_hashes(ROOT / path) for path in (
                "src/agentdojo_lab/tier4_single_factor_ablation_html.py",
                "scripts/run_case_r_tier4_single_factor_ablation.py",
            )},
        },
        "agent_tracer_results": receipt.get("agent_tracer_results"),
        "inputs": config.get("inputs"),
        "model": config.get("model"),
        "report": {"path": report["report"], "renderer": report["renderer"], "sha256": report["sha256"]},
        "gate0": {key: summary["gate0"].get(key) for key in (
            "status", "pairs_compared", "pairs_passed", "max_abs_difference_overall")},
        "hypothesis_outcomes": summary.get("hypothesis_outcomes"),
        "counts": summary.get("counts"),
        "access_classification": "private_access_controlled_research_evidence",
        "retention_policy": "append_only; corrections require a new experiment ID",
        "integrity": {
            "checksums_path": "checksums.sha256",
            "checksum_format": "lowercase SHA-256, two spaces, forward-slash relative path",
            "checksum_scope": "every file except checksums.sha256 itself",
            "manifest_files_scope": "every file except manifest.json and checksums.sha256",
        },
        "validation": {"machine_path_scan": "pass", "credential_pattern_scan": "pass"},
        "files": files,
    }
    manifest_digest = paths.write_json("manifest.json", manifest)
    names = bundle_paths(output, ("checksums.sha256",))
    credential_scan(output, ["manifest.json"])
    lines = "".join(f"{ab.sha256_bytes((output / name).read_bytes())}  {name}\n" for name in names)
    paths.check_no_absolute(lines, "checksums.sha256")
    (output / "checksums.sha256").write_bytes(lines.encode("utf-8"))
    return {
        "readme_sha256": ab.sha256_bytes(readme.encode("utf-8")),
        "manifest_sha256": manifest_digest,
        "checksums_sha256": ab.sha256_bytes(lines.encode("utf-8")),
        "checksummed_files": len(names),
    }


def render(paths: Paths) -> dict:
    """Render reports/index.html and the bundle index from the saved JSON only (no encoder, no rescoring)."""
    with OfflineGuard() as guard:
        result = report_html.render_report(paths.output, check=paths.check_no_absolute)
        bundle = write_bundle_files(paths, result)
    if guard.attempts:
        raise RuntimeError("The report renderer attempted a network connection")
    return {
        "protocol": ab.PROTOCOL_ID,
        "mode": "render",
        "output": "<results>/" + paths.output.relative_to(paths.results_root).as_posix(),
        **result,
        "bundle": bundle,
        "network_connection_attempts": guard.attempts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True, help="agent-tracer-results checkout")
    parser.add_argument("--output", type=Path, required=True, help="experiment directory inside the results root")
    parser.add_argument(
        "--render-only", action="store_true",
        help="only re-render reports/index.html and the bundle index from the saved JSON; nothing is rescored",
    )
    args = parser.parse_args(argv)
    results_root = args.results_root.resolve()
    output = args.output.resolve()
    if not output.is_relative_to(results_root / "experiments") or output == results_root / "experiments":
        raise SystemExit("--output must be a directory under <results-root>/experiments")
    if args.render_only:
        try:
            result = render(Paths(results_root, output))
        except report_html.ReportInputError as failure:
            print(json.dumps({"protocol": ab.PROTOCOL_ID, "mode": "render_only", "status": "refused",
                              "error": str(failure)}, indent=2))
            return 4
        print(json.dumps({**result, "mode": "render_only", "status": "rendered"}, ensure_ascii=False, indent=2))
        return 0
    existing = [name for name in OUTPUT_FILES if (output / name).exists()]
    if existing:
        raise SystemExit(f"Refusing to overwrite existing outputs: {existing}")
    paths = Paths(results_root, output)
    guard = OfflineGuard()
    receipt: dict = {
        "protocol": ab.PROTOCOL_ID,
        "evidence_id": ab.EVIDENCE_ID,
        "started_at_utc": utc_now(),
        "command": (
            f"{LAB_PREFIX}/scripts/run_case_r_tier4_single_factor_ablation.py --results-root <results> "
            f"--output <results>/{output.relative_to(results_root).as_posix()}"
        ),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": Path(sys.executable).resolve().relative_to(ROOT).as_posix()
            if Path(sys.executable).resolve().is_relative_to(ROOT) else "outside the lab directory",
        },
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "packages": {},
        "environment_flags": {flag: os.environ.get(flag) for flag in OFFLINE_FLAGS},
        "agent_tracer": {
            "head": git(REPO_ROOT, "rev-parse", "HEAD"),
            "status_porcelain": git(REPO_ROOT, "status", "--porcelain").splitlines(),
        },
        "agent_tracer_results": {
            "head": git(results_root, "rev-parse", "HEAD"),
            "frozen_input_commit": ab.RESULTS_COMMIT,
        },
        "protocol_sha256": ab.PROTOCOL_SHA256,
        "prior_attempts": prior_attempts(output),
        "outputs": {},
    }
    receipt["agent_tracer"]["dirty"] = bool(receipt["agent_tracer"]["status_porcelain"])
    for package in PACKAGES:
        try:
            receipt["packages"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            receipt["packages"][package] = "unavailable"
    status, code, error = "completed", 0, None
    try:
        with guard:
            code = run(paths, receipt, guard)
    except GateFailure as failure:
        status, code = failure.status, 1
        error = {"type": type(failure).__name__, "message": str(failure)}
    except Exception as failure:
        traceback.print_exc()
        status, code = "stopped_with_error", 2
        error = {"type": type(failure).__name__, "message": str(failure)}
    encoder = receipt.pop("encoder", None)
    receipt.update({
        "status": status,
        "error": error,
        "finished_at_utc": utc_now(),
        "requests": {
            "agent_requests": 0,
            "provider_requests": 0,
            "network_connection_attempts": guard.attempts,
            "local_encoder_calls": encoder.calls if encoder else 0,
            "local_encoder_texts": encoder.texts if encoder else 0,
        },
    })
    paths.write_json("logs/receipt.json", receipt)
    print(json.dumps(paths.scrub({
        "protocol": ab.PROTOCOL_ID,
        "status": status,
        "error": error,
        "output": "<results>/" + output.relative_to(results_root).as_posix(),
        "hypothesis_outcomes": receipt.get("hypothesis_outcomes"),
        "requests": receipt["requests"],
    }), ensure_ascii=False, indent=2))
    if status == "completed":
        try:
            print(json.dumps({**render(paths), "status": "rendered"}, ensure_ascii=False, indent=2))
        except Exception:
            traceback.print_exc()
            code = code or 3
    return code


if __name__ == "__main__":
    raise SystemExit(main())
