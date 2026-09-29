"""Build a request-free JSON/HTML assessment of nine explicit Scout terminal inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.scout_terminal_report import CASE_IDS, build_terminal_report


def _bindings(values: list[str], name: str) -> dict[str, Path]:
    result = {}
    for value in values:
        case_id, separator, raw_path = value.partition("=")
        if separator != "=" or case_id not in CASE_IDS or not raw_path:
            raise argparse.ArgumentTypeError(f"{name} must use CASE=PATH with CASE in {', '.join(CASE_IDS)}")
        if case_id in result:
            raise argparse.ArgumentTypeError(f"duplicate {name} binding for {case_id}")
        result[case_id] = Path(raw_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", action="append", default=[], metavar="CASE=PATH")
    parser.add_argument("--terminal", action="append", default=[], metavar="CASE=PATH")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="write readiness artifacts without reading or interpreting scientific evidence",
    )
    args = parser.parse_args(argv)
    try:
        evidence = _bindings(args.evidence, "--evidence")
        terminals = _bindings(args.terminal, "--terminal")
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    report = build_terminal_report(
        args.output, evidence=evidence, terminals=terminals, plan_only=args.plan_only
    )
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "mode": report["mode"],
                "complete": report["counts"]["complete"],
                "total": report["counts"]["total"],
                "requests": report["requests"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
