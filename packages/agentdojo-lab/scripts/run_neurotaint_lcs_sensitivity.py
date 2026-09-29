"""Run offline post-hoc LCS sensitivity on a completed frozen reference panel."""

import argparse
import json
from pathlib import Path

from agentdojo_lab.neurotaint_lcs_sensitivity import analyze_lcs_sensitivity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    summary = analyze_lcs_sensitivity(args.panel, args.output)
    print(
        json.dumps(
            {
                "status": summary["status"],
                "method": summary["method"],
                "panel_id": summary["panel_id"],
                "pair_count": summary["pair_count"],
                "post_hoc_sensitivity": summary["post_hoc_sensitivity"],
                "preregistered_result": summary["preregistered_result"],
                "production_fix": summary["production_fix"],
                "threshold": summary["threshold"],
                "overall": summary["overall"],
                "unknowns": summary["unknowns"],
                "input_integrity": summary["input_integrity"],
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
