import importlib.util
import json

import openai
import pytest

from agentdojo_lab.runner import ROOT, RunConfig, run_clean

spec = importlib.util.spec_from_file_location("replay_cost_script", ROOT / "scripts/replay_recording_cost.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


def test_native_offline_replay_verifies_request_and_environment_equality(tmp_path):
    source = tmp_path / "source"
    run_clean(RunConfig(), offline=True, output=source)
    output = tmp_path / "study"
    result = replay.run_study([source], output, pairs=2)
    assert result["real_llm"] is False
    assert len(result["rows"]) == 2  # The warmup pair is retained on disk, excluded here.
    assert result["summary"][0]["all_matched"] is True
    assert len(list((output / "replays").iterdir())) == 6
    assert all(row["recorded_log_bytes"] > 0 for row in result["rows"])
    assert (output / "pairs.csv").is_file()


def test_replay_rejects_divergence_instead_of_fabricating_a_timing(tmp_path):
    source = tmp_path / "source"
    run_clean(RunConfig(), offline=True, output=source)
    config, tape = replay.load_tape(source)
    tape[0][0]["model"] = "different-fixture"
    output = tmp_path / "divergent"
    with pytest.raises(openai.APIConnectionError) as error:
        replay.replay_once(config, tape, output, recorded=True)
    assert isinstance(error.value.__cause__, ValueError)
    assert "diverged" in str(error.value.__cause__)
    assert not (output / "replay.json").exists()
    events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert events[-1]["data"]["status"] == "failed"
