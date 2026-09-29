"""Recompute independent Tier 3/4 carrier detection from a frozen batch.

This command makes no primary model/API requests. It requires the reviewed local
MiniLM snapshot and writes a fresh JSON/HTML report directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.carrier_scale_tiers import (
    ROOT,
    SEMANTIC_MODEL,
    SEMANTIC_REVISION,
    analyze,
    render_html,
)
from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    plan = json.loads((args.batch / "plan.json").read_text(encoding="utf-8"))
    if plan.get("semantic_model") != SEMANTIC_MODEL or plan.get("semantic_revision") != SEMANTIC_REVISION:
        parser.error("Batch must freeze the reviewed MiniLM path and revision")
    model_path = ROOT / SEMANTIC_MODEL
    if not model_path.is_dir():
        parser.error(f"Pinned MiniLM snapshot missing: {model_path}")
    matcher = SemanticMatcher(LocalMiniLMEncoder(model_path, revision=SEMANTIC_REVISION))
    packet = analyze(args.batch, matcher)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "packet.json").write_text(
        json.dumps(packet, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
    )
    (args.output / "index.html").write_text(render_html(packet), encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "planned_slots": packet["population"]["planned_slots"],
                "eligible_executed_sinks": packet["population"]["eligible_executed_sinks"],
                "carrier_pairs": packet["population"]["carrier_pairs"],
            }
        )
    )


if __name__ == "__main__":
    main()
