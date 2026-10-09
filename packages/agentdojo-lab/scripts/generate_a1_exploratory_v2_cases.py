#!/usr/bin/env python
"""Validate two post-S2 exploratory A1 cases with native AgentDojo only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE.parent / "vendor" / "agentdojo" / "src"))

from agentdojo_lab import a1_pc5_v2_cases as v2  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=v2.CONFIG_PATH)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check-only", action="store_true", help="validate without writing generated evidence")
    args = parser.parse_args(argv)
    if os.environ.get("PYTHONUTF8") != "1" or sys.flags.utf8_mode != 1:
        parser.error("v2 case generation requires PYTHONUTF8=1 at Python startup to match the guarded child")
    root = args.results_root.resolve(strict=True)
    if args.check_only and args.out:
        parser.error("--check-only cannot be combined with --out")
    if not args.check_only and not args.out:
        parser.error("--out is required unless --check-only is set")
    out = args.out.resolve() if args.out else None
    if out is not None and (out == root or not out.is_relative_to(root)):
        parser.error("--out must be inside the explicit results checkout")
    bundle = v2.generate_cases(v2.load_config(args.config))
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out) if out is not None else None,
                      "config_sha256": bundle["config_sha256"],
                      "cases_sha256": bundle["cases_sha256"], "counts": bundle["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
