"""Run the frozen string-origin fixture matrix with the pinned local MiniLM only."""

import argparse
import json
import os
from pathlib import Path

from agentdojo_lab.reference_controls import run_reference_controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-path", type=Path, default=Path(".model-cache/all-MiniLM-L6-v2-1110a243"))
    parser.add_argument("--revision", default="1110a243fdf4706b3f48f1d95db1a4f5529b4d41")
    args = parser.parse_args()
    # Offline library settings supplement the encoder's existing local-files-only pin checks.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    from agentdojo_lab.semantic import LocalMiniLMEncoder

    model_path = str(args.model_path.expanduser().resolve())
    result = run_reference_controls(
        args.output,
        encoder_factory=lambda: LocalMiniLMEncoder(model_path, revision=args.revision),
        encoder_mode="real_local_minilm",
        encoder_configuration={"model_path": model_path, "revision": args.revision},
    )
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "status",
                    "fixture_cases",
                    "reference_pairs",
                    "planned_slots",
                    "recorded_slots",
                    "plan_sha256",
                    "integrity",
                    "generative_model_requests",
                )
            },
            indent=2,
        )
    )
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
