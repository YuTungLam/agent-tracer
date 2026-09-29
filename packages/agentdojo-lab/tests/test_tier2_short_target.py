"""Controls and report checks for the offline Tier-2 scaling diagnostic."""

from __future__ import annotations

import importlib.util
import random
from collections import Counter
from pathlib import Path

import pytest

from agentdojo_lab.lexical import lcs_evidence
from agentdojo_lab.tier2_short_target import (
    make_pair,
    quantile,
    run_experiment,
    score_distribution,
    wilson_interval,
)


def test_pair_controls_and_canonical_scorer():
    pair = make_pair(random.Random(42), "abcXYZ", 80, 10)
    assert pair["target"] in pair["positive"]
    assert pair["target"] not in pair["negative"]
    assert pair["target"] not in pair["independent_negative"]
    assert len(pair["positive"]) == len(pair["negative"]) == len(pair["independent_negative"]) == 80
    assert Counter(pair["positive"]) == Counter(pair["negative"])
    assert lcs_evidence(pair["positive"], pair["target"])["score"] == 1.0
    assert lcs_evidence(pair["negative"], pair["target"])["score"] is not None
    assert lcs_evidence(pair["independent_negative"], pair["target"])["score"] is not None


def test_factorial_rates_and_seed_reproduction():
    options = {
        "seed": 8,
        "target_lengths": (5, 10),
        "source_lengths": (20, 40),
        "alphabets": {"lowercase_3": "abc"},
        "replicates": 4,
    }
    packet = run_experiment(**options)
    assert packet == run_experiment(**options)
    assert packet["total_pairs"] == 16
    assert packet["total_evaluations"] == 48
    assert len(packet["cells"]) == 4
    assert all(row["positive_contains_target"] and not row["negative_contains_target"] for row in packet["rows"])
    assert all(not row["independent_negative_contains_target"] for row in packet["rows"])
    assert all(row["source_character_histograms_equal"] for row in packet["rows"])
    assert all(row["positive_score"] == 1.0 for row in packet["rows"])
    assert all(cell["tp"] == 4 and cell["fn"] == 0 for cell in packet["cells"])
    assert all(cell["fp"] + cell["tn"] == 4 for cell in packet["cells"])
    assert all(cell["independent_fp"] + cell["independent_tn"] == 4 for cell in packet["cells"])
    assert all(cell["fpr_wilson_95"][0] <= cell["fpr"] <= cell["fpr_wilson_95"][1] for cell in packet["cells"])
    changed = run_experiment(**{**options, "seed": 9})
    assert [row["target_sha256"] for row in packet["rows"]] != [row["target_sha256"] for row in changed["rows"]]


def test_wilson_and_score_distribution_edges():
    lo0, hi0 = wilson_interval(0, 128)
    lo1, hi1 = wilson_interval(128, 128)
    assert lo0 == 0.0 and 0 < hi0 < 0.04
    assert 0.96 < lo1 < 1 and hi1 == 1.0
    assert quantile([0.0, 0.5, 1.0], 0.25) == 0.25
    scores = score_distribution([0.0, 0.5, 1.0])
    assert scores["median"] == 0.5
    assert scores["perfect_matches"] == 1
    with pytest.raises(ValueError):
        wilson_interval(2, 1)


def test_invalid_pair_and_experiment_parameters():
    with pytest.raises(ValueError):
        make_pair(random.Random(1), "ab", 4, 5)
    with pytest.raises(ValueError):
        make_pair(random.Random(1), "aaa", 5, 2)
    with pytest.raises(ValueError):
        run_experiment(target_lengths=(10,), source_lengths=(5,), alphabets={"a": "ab"}, replicates=1)


def test_report_write_is_non_overwriting(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "report_tier2_short_target.py"
    spec = importlib.util.spec_from_file_location("report_tier2_short_target", script)
    assert spec is not None and spec.loader is not None
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)

    # The renderer expects its three frozen source-length series.
    packet = run_experiment(target_lengths=(5, 10), source_lengths=(256, 768, 2048), alphabets={"lowercase_26": "abcdefghijklmnopqrstuvwxyz"}, replicates=2)
    monkeypatch.setattr(report.diagnostic, "run_experiment", lambda: packet)
    output = tmp_path / "new-report"
    report.write_report(output)
    assert (output / "packet.json").is_file()
    rendered = (output / "index.html").read_text(encoding="utf-8")
    assert "false attribution" in rendered
    assert "95% Wilson" in rendered
    with pytest.raises(FileExistsError):
        report.write_report(output)
