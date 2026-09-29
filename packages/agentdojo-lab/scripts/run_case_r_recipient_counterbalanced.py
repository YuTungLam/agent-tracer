"""Build and optionally score the frozen Case R counterbalanced offline panel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo_lab.carrier_scale_tiers import SEMANTIC_REVISION
from agentdojo_lab.recipient_context_counterbalanced import (
    build_plan,
    load_config,
    render_markdown,
    score_plan,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    config, config_hash = load_config(args.config)
    plan = build_plan(config, config_sha256=config_hash)
    packet = None
    if not args.preflight_only:
        model_spec = Path(config["semantic"]["model"])
        revision = config["semantic"].get("revision")
        if revision != SEMANTIC_REVISION:
            parser.error("Config semantic revision does not match the protocol pin")
        if model_spec.is_absolute() or ".." in model_spec.parts:
            parser.error("Config semantic model must be a repository-relative path")
        model_path = (ROOT / model_spec).resolve()
        if not model_path.is_relative_to(ROOT.resolve()):
            parser.error("Config semantic model resolves outside the repository")
        if not model_path.is_dir():
            parser.error(f"Pinned MiniLM snapshot missing: {model_path}")
        from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

        matcher = SemanticMatcher(
            LocalMiniLMEncoder(model_path, revision=revision),
            semantic_threshold=config["semantic"]["semantic_threshold"],
            coverage_threshold=config["semantic"]["coverage_threshold"],
        )
        packet = score_plan(plan, matcher)

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "plan.json").write_text(
        json.dumps(plan, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    if packet is not None:
        (args.output / "packet.json").write_text(
            json.dumps(packet, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        (args.output / "analysis.md").write_text(render_markdown(packet), encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "cells": len(plan["cells"]),
                "relations": len(plan["relations"]),
                "scored": packet is not None,
                "model_requests": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
