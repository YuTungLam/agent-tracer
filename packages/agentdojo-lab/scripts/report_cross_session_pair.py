"""Export an offline comparison of two caller-labelled A/B session pairs."""

import argparse
import json
from pathlib import Path

from agentdojo_lab.cross_session_report import export_cross_session_pair

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-a", type=Path, required=True)
    parser.add_argument("--clean-b", type=Path, required=True)
    parser.add_argument("--attacked-a", type=Path, required=True)
    parser.add_argument("--attacked-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clean-label", default="clean")
    parser.add_argument("--attacked-label", default="attacked")
    args = parser.parse_args()
    result = export_cross_session_pair(
        args.clean_a,
        args.clean_b,
        args.attacked_a,
        args.attacked_b,
        args.output,
        labels=(args.clean_label, args.attacked_label),
    )
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "session_alignment": {
                    stage: result["session_comparisons"][stage]["alignment"]["status"]
                    for stage in ("A", "B")
                },
                "causal_influence": result["causal_influence"],
            }
        )
    )
