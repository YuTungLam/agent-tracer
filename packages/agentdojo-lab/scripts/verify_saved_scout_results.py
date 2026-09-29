"""Audit saved Scout files only; no model, network, tool execution, or job submission.

Run with the lab environment. This checks file integrity, event structure and
request accounting. It does not validate scientific or causal conclusions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentdojo_lab.inspection import inspect_events

CASES = {
    "A": ("scout-case-a-prepared-v5", ("clean", "attacked")),
    "B": ("scout-case-b-prepared-v3", ("runs/both", "runs/a_only", "runs/b_only", "runs/neither")),
    "C": ("scout-case-c-prepared-v2", ("clean/A", "attacked/A")),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path.name}")
    return value


def audit(lab: Path) -> dict:
    result = {
        "protocol": "scout-saved-evidence-review-v1",
        "scope": "File integrity, fresh event-structure checks and SDK ledger accounting only",
        "new_model_requests": 0,
        "cases": {},
        "source_files": [],
        "terminal_hash_checks": [],
        "issues": [],
    }
    for case, (dirname, sessions) in CASES.items():
        base = lab / "runs" / dirname
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise ValueError("Saved evidence must not contain symlinks")
            if path.is_file():
                result["source_files"].append({
                    "path": str(path.relative_to(lab)),
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                })
        records = []
        for session in sessions:
            directory = base / session
            events = directory / "events.jsonl"
            fresh = inspect_events(events)
            saved = load(directory / "events.audit.json")
            ledger = [json.loads(row) for row in (directory / "sdk-attempts.jsonl").read_text().splitlines()]
            sequence = [row.get("sdk_attempt") for row in ledger]
            sequential = sequence == list(range(1, len(ledger) + 1))
            match = fresh == saved
            checks = {
                "event_structure_valid": fresh.get("valid") is True,
                "fresh_audit_matches_saved": match,
                "sdk_attempt_sequence_valid": sequential,
                "sdk_attempt_count_equals_event_requests": len(ledger) == fresh.get("model_requests"),
            }
            records.append({
                "session": session,
                "requests": len(ledger),
                "checks": checks,
                "fresh_event_audit": fresh,
            })
            for key, valid in checks.items():
                if not valid:
                    result["issues"].append(f"{case}/{session}: {key}")
        for terminal in sorted(base.glob("*-terminal.json")):
            for name, receipt in load(terminal).get("artifacts", {}).items():
                if not isinstance(receipt, dict) or not {"path", "sha256"} <= receipt.keys():
                    continue
                # Terminal paths were written on NeSI. Bind the relative suffix
                # to this checkout so an archive can be checked on another host.
                raw = receipt["path"]
                marker = "/codebase/agentdojo-lab/"
                relative = raw.split(marker, 1)[1] if marker in raw else raw
                path = (lab / relative).resolve()
                if not path.is_relative_to(base.resolve()):
                    raise ValueError("Artifact receipt escapes its case directory")
                valid = path.is_file() and digest(path) == receipt["sha256"]
                result["terminal_hash_checks"].append({
                    "terminal": str(terminal.relative_to(lab)),
                    "artifact": name,
                    "path": str(path.relative_to(lab)),
                    "expected_sha256": receipt["sha256"],
                    "matches": valid,
                })
                if not valid:
                    result["issues"].append(f"{case}: terminal hash mismatch {name}")
        result["cases"][case] = {"sessions": records, "requests": sum(r["requests"] for r in records)}
    result["research_requests"] = sum(c["requests"] for c in result["cases"].values())
    result["executed_sessions"] = sum(len(c["sessions"]) for c in result["cases"].values())
    result["status"] = "passed" if not result["issues"] else "issues_found"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    lab = args.lab.resolve()
    target = args.output.resolve()
    if any(target.is_relative_to(lab / "runs" / spec[0]) for spec in CASES.values()):
        raise ValueError("Review output must be separate from original case evidence")
    result = audit(lab)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "research_requests", "executed_sessions", "issues")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
