"""Run the frozen six-slot Case R intentional-recipient probe.

The original Case R transport and native-state scorer are reused without
altering their code. Only this named protocol supplies the three frozen arms.
The default mode is a scripted transport control with zero model requests.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import run_case_r_groq as transport

from agentdojo_lab import case_r_intentional_probe as probe

ROOT = Path(__file__).resolve().parents[1]
_ORIGINAL_RUNTIME_FILES = transport.runtime_files


def runtime_files() -> list[Path]:
    return [
        *_ORIGINAL_RUNTIME_FILES(),
        ROOT / "src/agentdojo_lab/case_r_intentional_probe.py",
        Path(__file__).resolve(),
    ]


def dispatch(plan: dict, slot: dict, output: Path, plan_hash: str, log_dir: Path) -> dict:
    """Use this wrapper in each fresh trial process, retaining Case R's ledger."""
    run_path = output / "runs" / slot["slot_id"]
    spec_path = output / "specs" / (slot["slot_id"] + ".json")
    transport.write_json(
        spec_path,
        {
            "slot": slot,
            "plan_path": str(output / "plan.json"),
            "plan_sha256": plan_hash,
            "pacing_state": str(output / "pacing.json"),
        },
    )
    item = transport._slot_item(slot, output)
    item["process_status"] = "failed"
    with (log_dir / (slot["slot_id"] + ".log")).open("x", encoding="utf-8") as log:
        try:
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--session-spec", str(spec_path)],
                stdout=log,
                stderr=log,
                timeout=plan["task_timeout_seconds"],
                check=False,
                env={**os.environ, "PYTHONUTF8": "1"},
            )
            item["returncode"] = completed.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            item["error_type"] = type(exc).__name__
    try:
        result = transport.read(run_path / "summary.json") if (run_path / "summary.json").is_file() else None
        item["summary"] = result
        if result:
            item["error_type"] = result.get("error_type")
            item["error_status_code"] = result.get("error_status_code")
        if item["returncode"] == 0 and result and result["status"] == "completed" and result["complete"]:
            item["process_status"] = "completed"
    except (ValueError, OSError) as exc:
        item["error_type"] = type(exc).__name__
    capture = run_path / "requests.jsonl"
    item["recorded_request_count"] = (
        sum(bool(line.strip()) for line in capture.read_bytes().splitlines()) if capture.exists() else 0
    )
    item["usage_available"] = bool(item["summary"] and item["summary"].get("stats") is not None)
    return item


def configure_transport() -> None:
    """Bind the new protocol in this isolated process, including child trials."""
    transport.case_r = probe
    transport.runtime_files = runtime_files
    transport._dispatch = dispatch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--session-spec", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    configure_transport()
    try:
        if args.preflight:
            if args.output or args.live or args.resume or args.session_spec:
                parser.error("--preflight cannot be combined with run options")
            receipt = probe.preflight()
            receipt["runner_sha256"] = transport.digest(Path(__file__))
            receipt["protocol_module_sha256"] = transport.digest(ROOT / "src/agentdojo_lab/case_r_intentional_probe.py")
            receipt["runtime_file_count"] = len(runtime_files())
            print(json.dumps(receipt, sort_keys=True))
            return 0
        if args.session_spec:
            outcome = transport.run_trial(args.session_spec.resolve())
            return 0 if outcome["complete"] else 1
        if not args.output:
            parser.error("--output is required")
        if args.resume and args.live:
            parser.error("--resume reads the frozen live mode from the existing plan")
        probe.preflight()
        outcome = (
            transport.resume_batch(args.output.resolve())
            if args.resume
            else transport.run_batch(args.output.resolve(), protocol_name=probe.PROTOCOL, live=args.live)
        )
        if outcome["planned_slots"] != 6 or outcome["reported_primary_requests"] > 36:
            raise RuntimeError("Frozen batch budget was violated")
        print(json.dumps({
            key: outcome[key]
            for key in (
                "completed_slots", "planned_slots", "not_started_slots", "paused",
                "reported_primary_requests", "reported_primary_tokens",
            )
        }))
        return 1 if outcome["paused"] else 0
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "detail": str(exc)[:300]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
