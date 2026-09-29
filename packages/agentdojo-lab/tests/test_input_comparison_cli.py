"""Plan-only and resume CLI boundaries must not issue model calls."""

import json

from agentdojo_lab.cli import main


def test_cli_plan_only_never_executes_or_reads_credentials(tmp_path, monkeypatch, capsys):
    from agentdojo_lab import input_comparison, runner

    def forbidden(*args, **kwargs):
        raise AssertionError("Plan-only must not enter a model execution path")

    monkeypatch.setattr(runner, "configured_key", forbidden)
    monkeypatch.setattr(input_comparison, "execute_input_comparison_batch", forbidden)
    output = tmp_path / "frozen"
    assert main(["input-comparison", "--output", str(output), "--plan-only"]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["planned"] == 10 and response["model_calls"] == 0
    assert not list((output / "jobs").iterdir())


def test_cli_resume_rejects_replacement_config_before_reading_or_launching(tmp_path, monkeypatch, capsys):
    from agentdojo_lab import input_comparison

    def forbidden(*args, **kwargs):
        raise AssertionError("A replacement configuration must be rejected first")

    monkeypatch.setattr(input_comparison, "read_input_comparison_plan", forbidden)
    monkeypatch.setattr(input_comparison, "execute_input_comparison_batch", forbidden)
    assert main([
        "input-comparison", "--resume", str(tmp_path / "batch"),
        "--config", str(tmp_path / "other.json"), "--plan-only",
    ]) != 0
    captured = capsys.readouterr()
    assert "frozen configuration" in captured.out + captured.err
    assert not list(tmp_path.iterdir())
