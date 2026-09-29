"""Create a separate, read-only correction receipt for the real v1 pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.carrier_scale_correction import build_receipt, render_html


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    receipt = build_receipt(args.batch)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "receipt.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
    )
    (args.output / "index.html").write_text(render_html(receipt), encoding="utf-8")
    print(json.dumps({"output": str(args.output), **receipt["summary"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
