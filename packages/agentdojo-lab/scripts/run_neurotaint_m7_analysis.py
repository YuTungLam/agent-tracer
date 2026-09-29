"""Aggregate verified saved M7 evidence from a frozen NT-AgentDojo matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.neurotaint_m7_analysis import analyze_m7_batch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze_m7_batch(args.batch, args.output)
    print(
        json.dumps(
            {
                "status": result["status"],
                "batch_id": result["batch_id"],
                "planned_slot_count": result["planned_slot_count"],
                "verified_slot_count": result["verified_slot_count"],
                "verified_proposal_count": len(result["proposals"]),
                "unknowns": result["unknowns"],
                "output": str(args.output.expanduser().absolute()),
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
