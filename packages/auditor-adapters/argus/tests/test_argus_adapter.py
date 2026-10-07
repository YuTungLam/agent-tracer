"""Designs, factory compatibility with the artifact, and the runner end to end against a fake upstream."""

from __future__ import annotations

import inspect
import json
from collections import Counter

import pytest

import argus_adapter as aa
from argus_wire import SampleContext, WirePolicy, WireSession


def test_s2_design_is_balanced_and_deterministic():
    designs = aa.agentlure_designs(0)
    s1, s2 = designs["s1"], designs["s2"]
    attacked = [i for i in s2 if not i.endswith("/clean")]
    assert len(s2) == len(set(s2)) == 120 and len(attacked) == 80
    assert set(Counter(i.split("/")[0] for i in attacked).values()) == {20}
    assert set(Counter(i.split("/")[2] for i in attacked).values()) == {10}
    per_task = Counter(i.rsplit("/", 1)[0] for i in attacked)
    assert len(per_task) == 40 and set(per_task.values()) == {2}  # every user task, twice, distinct vectors
    assert s2[:3] == s1 and len(s1) == 3
    assert {i.split("/")[0] for i in s1} == {"banking", "travel", "slack"} and s1[2].endswith("/clean")
    assert aa.agentlure_designs(0)["s2"] == s2 and aa.agentlure_designs(1)["s2"] != s2
    assert len(designs["full"]) == 360


def test_first_cap_window_covers_every_suite():
    s2 = aa.agentlure_designs(0)["s2"]
    assert {i.split("/")[0] for i in s2[:8]} == {"banking", "slack", "travel", "workspace"}


def test_s3_design_is_a_per_suite_subset_of_the_artifact_draw():
    from agentlure.external import load

    bench = load("agentdojo", version="v1.2.1", attack="important_instructions")
    picked = aa.agentdojo_design(bench, 0)
    keys = [aa.agentdojo_key(s) for s in picked]
    assert len(keys) == len(set(keys)) == 100
    draw = {aa.agentdojo_key(s) for a in (True, False) for s in bench.samples(attacked=a, seed=0)}
    assert set(keys) <= draw
    assert Counter((s.subset, s.attacked) for s in picked) == {
        (suite, attacked): 20 if attacked else 5
        for suite in ("banking", "slack", "travel", "workspace") for attacked in (True, False)}


def test_factories_match_what_agentlure_evaluate_inspects():
    from agentlure.evaluate import _accepts_client, _callable_identity
    from agentlure.warrant import READ_ONLY_TOOLS

    session = WireSession(WirePolicy(), None)
    warrant = aa.WarrantFactory(session, SampleContext("a", "warrant"), None)
    none = aa.UndefendedFactory(session, SampleContext("a", "none"), None)
    assert _accepts_client(warrant) and _accepts_client(none)
    registry = inspect.signature(warrant).parameters["read_only_tools"]
    assert registry.default == READ_ONLY_TOOLS and isinstance(registry.default, frozenset)
    assert "read_only_tools" not in inspect.signature(none).parameters
    assert _callable_identity(warrant) == {"module": "argus_adapter", "name": "WarrantFactory"}


def test_runner_end_to_end_resume_and_config_guard(upstream, tmp_path):
    session = WireSession(WirePolicy(stage="T"), tmp_path / "requests.jsonl")
    ids = ["slack/user_task_0/clean"]
    counts = aa.run_agentlure(ids, ["none", "warrant"], tmp_path, session, "deepseek-flash", workers=1)
    assert counts["valid"] == 2 and counts["invalid"] == 0
    none = json.loads((tmp_path / "agentlure-none.jsonl").read_text(encoding="utf-8"))
    warrant = json.loads((tmp_path / "agentlure-warrant.jsonl").read_text(encoding="utf-8"))
    assert none["error"] is None and none["adapter"]["agent_requests"] == 1 and none["adapter"]["judge_requests"] == 0
    assert none["tokens"] == 105  # the artifact's own MeteredClient still meters through the shim
    assert warrant["error"] is None and warrant["adapter"]["judge_requests"] > 10
    assert warrant["adapter"]["judge_failures"] == 0 and warrant["adapter"]["invariants_unavailable"] is False
    assert warrant["configuration"]["model"] == "deepseek-flash"
    assert all(r["body"]["model"] == "deepseek-flash" for r in upstream.requests)
    assert all(r["body"]["thinking"] == {"type": "disabled"} for r in upstream.requests)
    assert {r["headers"]["x-auditor-sample"] for r in upstream.requests} == {"slack/user_task_0/clean"}
    assert list((tmp_path / "traces" / "agentlure-warrant").glob("*.jsonl"))

    sent = len(upstream.requests)
    again = aa.run_agentlure(ids, ["none", "warrant"], tmp_path, session, "deepseek-flash", workers=1)
    assert again["attempted"] == 0 and again["already_done"] == 2 and len(upstream.requests) == sent

    variant = WireSession(WirePolicy(agent_temperature=0.0), None)
    with pytest.raises(SystemExit, match="different configuration"):
        aa.run_agentlure(ids, ["none"], tmp_path, variant, "deepseek-flash", workers=1)

    summary = aa.summarize(tmp_path, "agentlure", 0.30, 1.20)
    assert summary["rows"]["none"]["clean"] == 1 and summary["rows"]["warrant"]["refusal"]["n"] == 1


def test_budget_refusal_sets_sample_aside_and_stops_the_run(upstream, tmp_path):
    upstream.refuse_after = 3
    session = WireSession(WirePolicy(), tmp_path / "requests.jsonl")
    ids = ["slack/user_task_0/clean", "banking/user_task_0/clean"]
    counts = aa.run_agentlure(ids, ["warrant"], tmp_path, session, "deepseek-flash", workers=1)
    assert counts["invalid"] == 1 and counts["skipped_after_latch"] == 1 and counts["valid"] == 0
    assert not (tmp_path / "agentlure-warrant.jsonl").exists()
    bad = json.loads((tmp_path / "agentlure-warrant.invalid.jsonl").read_text(encoding="utf-8"))
    assert bad["adapter"]["invalid_reason"] == "budget_refusal" and bad["adapter"]["refused"] >= 1
    # Three answered, then refusals; at most one more was already in flight (the labelling thread
    # and the agent run concurrently). After the latch nothing else left the process.
    assert 4 <= len(upstream.requests) <= 5


def test_estimate_arithmetic():
    rows = {"a": {"agent_input_chars": 4000, "judge_calls_total": 10, "judge_chars_total": 40000, "agent_steps": 2}}
    cost = aa.CostModel(judge_overhead_tokens=0, judge_out_tokens=10, agent_out_per_run=100)
    e = aa.estimate(rows, ["a"], ("none", "warrant"), cost)
    assert e["tokens_in"] == 1000 * 2 + 10000 and e["tokens_out"] == 200 + 100
    assert e["requests_base"] == 10 + 4
    assert e["usd_base"] == round(12000 / 1e6 * 0.30 + 300 / 1e6 * 1.20, 2)


def test_wilson_and_mcnemar():
    assert aa.wilson(12, 320) == pytest.approx((0.0216, 0.0645), abs=1e-3)
    assert aa._mcnemar(0, 0) == 1.0 and aa._mcnemar(20, 0) < 1e-5


def test_resume_from_imports_valid_records_and_skips_truncated_lines(upstream, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    ids = ["slack/user_task_0/clean", "slack/user_task_1/clean"]
    session = WireSession(WirePolicy(), None)
    aa.run_agentlure(ids[:1], ["none"], first, session, "deepseek-flash", workers=1)
    with (first / "agentlure-none.jsonl").open("a", encoding="utf-8") as f:
        f.write('{"adapter": {"key": "slack/user_task_1/clean", "trunc')  # a child killed mid-write
    sent = len(upstream.requests)
    counts = aa.run_agentlure(ids, ["none"], second, session, "deepseek-flash", workers=1, resume_from=[first])
    assert counts["already_done"] == 1 and counts["attempted"] == 1  # only the missing sample ran
    assert len(upstream.requests) == sent + 1
    records = aa.read_records(second / "agentlure-none.jsonl")
    assert sorted(r["adapter"]["key"] for r in records) == sorted(ids)
    assert records[0]["adapter"]["imported_from"] == str(first)
    store = aa.ResultStore(first, "agentlure")  # appending after a cut line starts on a fresh line
    store.write("none", {"adapter": {"key": "k", "config_sha": "x"}}, True)
    assert aa.read_records(first / "agentlure-none.jsonl")[-1]["adapter"]["key"] == "k"


def test_stage_config_loads_in_the_common_runner():
    import importlib.util
    from pathlib import Path

    common = Path(aa.__file__).resolve().parents[1] / "common" / "deepseek_route.py"
    if not common.exists():
        pytest.skip("common/deepseek_route.py not present")
    import sys

    spec = importlib.util.spec_from_file_location("deepseek_route_under_test", common)
    route = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = route  # dataclasses resolve annotations through sys.modules
    try:
        spec.loader.exec_module(route)
    finally:
        sys.modules.pop(spec.name, None)
    config = Path(aa.__file__).resolve().parent / "stages.json"
    for stage in ("DRY", "S1", "S2", "S3"):
        merged, _ = route.load_stage(config, stage)
        assert merged["request_model"] == "deepseek-flash" and "{out_dir}/adapter" in merged["argv"]
    assert route.load_stage(config, "DRY")[0]["paid_allowed"] is False
    assert [route.load_stage(config, s)[0]["cap_usd"] for s in ("S1", "S2", "S3")] == [1.0, 26.0, 16.0]


def test_agentdojo_runner_end_to_end(upstream, tmp_path):
    from agentlure.external import load

    bench = load("agentdojo", version="v1.2.1", attack="important_instructions")
    picked = aa.agentdojo_design(bench, 0)
    sample = next(s for s in picked if s.subset == "slack" and not s.attacked)
    session = WireSession(WirePolicy(stage="T3"), None)
    counts = aa.run_agentdojo([sample], bench, ["none", "warrant"], tmp_path, session, "deepseek-flash",
                              workers=1, bench_config={"version": "v1.2.1"})
    assert counts["valid"] == 2, counts
    records = {r["adapter"]["row"]: r for row in ("none", "warrant")
               for r in aa.read_records(tmp_path / f"agentdojo-{row}.jsonl")}
    assert records["none"]["error"] is None and records["warrant"]["error"] is None
    assert records["warrant"]["adapter"]["judge_requests"] > 0 and records["none"]["adapter"]["judge_requests"] == 0
    assert records["warrant"]["blocked"] is False
    assert {r["headers"]["x-auditor-sample"] for r in upstream.requests} == {aa.agentdojo_key(sample)}
    assert aa.summarize(tmp_path, "agentdojo", 0.30, 1.20)["rows"]["warrant"]["clean"] == 1
