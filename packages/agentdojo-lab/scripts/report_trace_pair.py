"""Export an offline clean/attacked tool-proposal comparison without model calls."""

import argparse
import json
from pathlib import Path

from agentdojo_lab.paired_report import export_pair

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", type=Path, required=True)
    parser.add_argument("--attacked", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sensitive-paths", type=Path, help="JSON object mapping tool names to JSON Pointer lists"
    )
    args = parser.parse_args()
    sensitive = json.loads(args.sensitive_paths.read_text()) if args.sensitive_paths else None
    result = export_pair(args.clean, args.attacked, args.output, sensitive_paths=sensitive)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "comparability": result["comparability"],
                "first_tool_proposal_divergence": result["first_tool_proposal_divergence"],
                "first_security_relevant_divergence": result["first_security_relevant_divergence"],
            },
            indent=2,
        )
    )
