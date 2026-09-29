"""Freeze or run the Scout content-composition argument intervention protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import sys
from pathlib import Path

from agentdojo_lab.scout_content_composition_argument import (
    TerminationRequested,
    run_content_composition_argument,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wrapper_binding(config: Path, *, live: bool) -> dict:
    """Bind the launcher, config, interpreter, and credential presence."""
    script = Path(__file__).resolve()
    config = config.absolute().resolve()
    return {
        "schema_version": 1,
        "mode": "live" if live else "plan_only",
        "launcher": str(script),
        "launcher_sha256": _sha(script),
        "config": str(config),
        "config_sha256": _sha(config),
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "working_directory": str(Path.cwd().resolve()),
        "local_key_variable": "LOCAL_LLM_API_KEY",
        "local_key_status": ("configured" if os.environ.get("LOCAL_LLM_API_KEY", "").strip() else "missing"),
        "credential_value_recorded": False,
        "sigterm_policy": "finalize_started_slot_as_unknown_and_leave_remaining_slots_unstarted",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Fresh output directory")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/scout_content_composition_argument_v1.json"),
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Start the 42 frozen local endpoint requests; otherwise freeze plan only",
    )
    args = parser.parse_args()
    binding = wrapper_binding(args.config, live=args.live)

    def terminate(_signum, _frame):
        raise TerminationRequested("SIGTERM")

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        summary = run_content_composition_argument(
            args.output,
            config_path=args.config,
            live=args.live,
            wrapper_binding=binding,
        )
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "status",
                    "mode",
                    "request_count",
                    "unknown_operation_slots",
                    "native_tool_executions",
                )
            },
            indent=2,
            sort_keys=True,
        )
    )
    if summary["termination_requested"]:
        return 128 + signal.SIGTERM
    return (
        0
        if summary["status"]
        in {
            "plan_only_complete",
            "completed",
            "completed_with_unknowns",
        }
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
