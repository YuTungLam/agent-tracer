#!/usr/bin/env python3
"""Run strict offline accounting for a frozen NT-AgentDojo native matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.neurotaint_native_analysis import analyze_native_matrix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = analyze_native_matrix(args.batch, args.output)
    print(json.dumps({"status": "completed", "planned": summary["counts"]["planned"], "valid": summary["counts"]["evaluation_valid"], "output": str(args.output.resolve())}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
