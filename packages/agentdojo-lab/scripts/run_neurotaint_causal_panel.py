"""Freeze or explicitly run the NT-AgentDojo controlled causal panel."""

import argparse
import json
from pathlib import Path

from agentdojo_lab.neurotaint_causal_panel import MAX_REQUESTS, run_causal_panel
from agentdojo_lab.pacing import RequestPacer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="Fresh panel output directory.")
    destination.add_argument(
        "--resume",
        type=Path,
        metavar="PATH",
        help="Resume an existing sealed live panel and start only never-started slots.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/neurotaint_causal_panel_v1.json"),
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Prepare or run Groq transport; --resume implies live mode.",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=0,
        choices=range(MAX_REQUESTS + 1),
        metavar="0..360",
        help="Per-invocation cap on newly started slots; default 0.",
    )
    parser.add_argument(
        "--pacing-state",
        type=Path,
        help="Optional persistent Groq pacing state file outside the output directory.",
    )
    parser.add_argument("--tokens-per-minute", type=int, default=7000)
    args = parser.parse_args()
    resuming = args.resume is not None
    if not args.live and not resuming and args.max_requests:
        parser.error("--max-requests above zero requires explicit --live")
    if args.tokens_per_minute <= 0:
        parser.error("--tokens-per-minute must be positive")
    live = args.live or resuming
    pacer = (
        RequestPacer(args.tokens_per_minute, args.pacing_state)
        if live
        else None
    )
    summary = run_causal_panel(
        args.resume if resuming else args.output,
        config_path=args.config,
        live=live,
        max_requests=args.max_requests,
        pacer=pacer,
        resume=resuming,
    )
    print(
        json.dumps(
            {
                "status": summary["status"],
                "mode": summary["mode"],
                "request_count": summary["request_count"],
                "invocation_request_count": summary["invocation_request_count"],
                "never_started_operations": summary["never_started_operations"],
                "max_requests": summary["max_requests"],
                "observed_replay_labels": summary["observed_replay_labels"],
                "valid_judgments": summary["valid_judgments"],
                "native_tool_executions": summary["native_tool_executions"],
                "plan_sha256": summary["plan_sha256"],
                "integrity": summary["integrity"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return (
        0
        if summary["status"]
        in {
            "plan_only_complete",
            "live_prepared",
            "partial",
            "completed",
            "completed_with_unknowns",
        }
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
