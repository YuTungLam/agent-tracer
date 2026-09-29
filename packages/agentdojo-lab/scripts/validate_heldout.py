"""Save two SDK-mocked native controls with honest non-live artifact labels."""

import argparse
import json
import sys
from pathlib import Path

import pytest

from agentdojo_lab import runner
from agentdojo_lab.evaluation_review import _local
from agentdojo_lab.evaluation_runner import run_evaluation_trial
from agentdojo_lab.heldout_runner import expected_run
from agentdojo_lab.span_diagnostic import analyze_span_run

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_heldout_runner import heldout_scripted_client, trial  # noqa: E402


def validate(output: Path) -> dict:
    output = _local(output)
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for condition in ("clean", "injected"):
        with pytest.MonkeyPatch.context() as patch:
            requests, _states = heldout_scripted_client(patch)
            patch.setattr(runner, "RequestPacer", lambda *args, **kwargs: None)
            original = runner.write_json

            def control_write(path, value):
                if Path(path).name in ("manifest.json", "summary.json"):
                    value = {
                        **value,
                        "mode": "scripted-native-control",
                        "real_llm": False,
                        "validation_kind": "SDK-mocked native engineering control; no live API calls",
                    }
                return original(path, value)

            patch.setattr(runner, "write_json", control_write)
            run = output / condition
            run_evaluation_trial(expected_run(), trial(condition), output=run)
            summary = json.loads((run / "summary.json").read_text())
            assert summary["real_llm"] is False
            diagnostic = analyze_span_run(run)
            assert diagnostic["status"] == "complete", diagnostic["reason"]
            assert summary["evaluation"]["raw_native_utility"] is (condition == "clean")
            assert summary["evaluation"]["raw_native_security"] is (condition == "injected")
            records.append(
                {
                    "condition": condition,
                    "execution_kind": "scripted-native-control",
                    "model_calls": 0,
                    "mock_sdk_requests": len(requests),
                    "native_evaluation": summary["evaluation"],
                    "verified_prefixes": diagnostic["validation"],
                    "fields": len(diagnostic["fields"]),
                }
            )
    result = {"schema_version": 1, "engineering_only": True, "records": records}
    (output / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.output), indent=2))
