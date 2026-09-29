"""Run the frozen NT-AgentDojo held-out panel with the pinned local MiniLM."""

import argparse
import json
import os
from pathlib import Path

from agentdojo_lab.neurotaint_reference_panel import run_reference_panel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/neurotaint_reference_panel_v1.json"),
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=Path(".model-cache/all-MiniLM-L6-v2-1110a243"),
    )
    parser.add_argument(
        "--revision",
        default="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    )
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    model_path = str(args.model_path.expanduser().resolve())
    summary = run_reference_panel(
        args.output,
        config_path=args.config,
        encoder_mode="real_local_minilm",
        encoder_configuration={"model_path": model_path, "revision": args.revision},
    )
    print(
        json.dumps(
            {
                "status": summary["status"],
                "panel_id": summary["panel_id"],
                "pair_count": summary["pair_count"],
                "reference_label_counts": summary["reference_label_counts"],
                "attribution_metrics": summary["attribution_metrics"],
                "unknowns": summary["unknowns"],
                "plan_sha256": summary["plan_sha256"],
                "integrity": summary["integrity"],
                "generative_model_requests": summary["generative_model_requests"],
                "external_api_requests": summary["external_api_requests"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if summary["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
