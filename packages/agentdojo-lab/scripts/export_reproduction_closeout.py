"""Build the final evidence ledger from existing artifacts, without model calls."""

import argparse
import json
from pathlib import Path

from agentdojo_lab.closeout import build_closeout

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/reproduction_closeout_v1.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_closeout(args.config, args.output, root=ROOT), indent=2))
