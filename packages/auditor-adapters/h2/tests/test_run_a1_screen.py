"""Zero-provider checks for the G1 selection and S1-to-S2 hard gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_a1_screen as a1


def _case(case_id: str, suite: str, split: str = "dev") -> dict:
    arms = {arm: {"arm_text": "clean" if arm == "CLEAN" else "attack",
                  "injections": {} if arm == "CLEAN" else {"vector": "attack"}}
            for arm in a1.ARMS}
    return {"case_id": case_id, "template_id": case_id, "split": split,
            "suite": suite, "user_task_id": "user_task_0", "vector_id": "vector",
            "target": {"function": "send_direct_message", "argument": "recipient"},
            "x": {"value": "Alice"}, "d": {"value": "Bob"}, "l": [{"value": "Charlie"}],
            "arms": arms, "conformance": {"all": True}}


def _bundle(cases: list[dict]) -> dict:
    return {"schema": "a1-stock-cases/v1", "benchmark_version": "v1.2.2",
            "cases": cases, "cases_sha256": a1._digest(cases)}


def test_dev_only_four_arm_expansion_and_no_eval() -> None:
    cases = [_case("w1", "workspace"), _case("s1", "slack"),
             _case("w2", "workspace"), _case("s2", "slack"),
             _case("held-out", "slack", "eval")]
    plan = a1.validate_cases(_bundle(cases), stage="G1-FULL")
    assert len(plan) == 80
    assert {episode["case_id"] for episode in plan} == {"w1", "s1", "w2", "s2"}
    assert {episode["arm"] for episode in plan} == set(a1.ARMS)
    assert sorted({episode["repeat"] for episode in plan}) == list(range(5))


def test_empty_clean_vector_is_valid_and_not_exposed() -> None:
    cases = [_case("w1", "workspace"), _case("s1", "slack"),
             _case("w2", "workspace"), _case("s2", "slack")]
    cases[0]["arms"]["CLEAN"]["arm_text"] = ""
    clean = next(ep for ep in a1.validate_cases(_bundle(cases), stage="G1-SMOKE")
                 if ep["case_id"] == "w1" and ep["arm"] == "CLEAN")
    flags = a1._source_flags([{"tool": "read", "text": "Alice is here"}], clean)
    assert flags["x_exposed"] is True
    assert flags["steering_exposed"] is False


def test_bad_native_conformance_and_vector_refused() -> None:
    cases = [_case("w1", "workspace"), _case("s1", "slack"),
             _case("w2", "workspace"), _case("s2", "slack")]
    cases[1]["conformance"]["all"] = False
    with pytest.raises(a1.ScreenError, match="conformance"):
        a1.validate_cases(_bundle(cases), stage="G1-SMOKE")
    cases[1]["conformance"]["all"] = True
    cases[1]["arms"]["A1-fact"]["injections"] = {"other-vector": "attack"}
    with pytest.raises(a1.ScreenError, match="stock vector"):
        a1.validate_cases(_bundle(cases), stage="G1-SMOKE")


def test_real_generated_bundle_plan_only() -> None:
    """Native GT input, including an empty CLEAN web vector and constructed PC5."""
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo_lab import a1_pc5_slack_s13, a1_stock_cases

    lab = Path(__file__).resolve().parents[3] / "agentdojo-lab"
    script = lab / "scripts/generate_a1_stock_cases.py"
    spec = importlib.util.spec_from_file_location("a1_generator_for_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = a1_stock_cases.load_config(lab / "configs/a1_stock_seeds_v1.json")
    defaults = {}
    for suite_name in {seed["suite"] for seed in config["seeds"]}:
        defaults.update(get_suite(config["benchmark_version"], suite_name).get_injection_vector_defaults())
    pc5 = a1_pc5_slack_s13.make_case()
    pc5["conformance"] = a1_pc5_slack_s13.validate_native(pc5, a1_pc5_slack_s13.native_probe(pc5))
    bundle = a1_stock_cases.generate_cases(
        config, defaults, module._native_probe_provider(config["benchmark_version"]),
        supplemental_cases=[pc5])
    for stage, expected in (("G1-SMOKE", 16), ("G1-FULL", 80)):
        plan = a1.validate_cases(bundle, stage=stage)
        assert len(plan) == expected
        assert len({episode["case_id"] for episode in plan}) == 4
    assert bundle["counts"] == {"total": 7, "dev": 4, "eval": 3}


def test_pc5_environment_uses_constructed_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdojo_lab import a1_pc5_slack_s13 as pc5

    seen: list[object] = []
    monkeypatch.setattr(pc5, "_initial_environment", lambda suite, task, body:
                        seen.append((suite, task, body)) or "pc5-env")
    assert a1._environment({"placement": "pc5-constructed-environment-record",
                            "environment_body": "registered body"}, "suite", "task") == "pc5-env"
    assert seen == [("suite", "task", "registered body")]


def test_full_requires_valid_smoke_receipt_and_fitting_projection(tmp_path: Path) -> None:
    run = tmp_path / "smoke"
    (run / "a1").mkdir(parents=True)
    summary = {"planned": 16, "started": 16, "complete": True}
    summary_path = run / "a1/summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    summary_sha = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    adapter = {"stage": "G1-SMOKE", "exit_code": 0, "case_file_sha256": "case",
               "code_commit": "commit", "summary_sha256": summary_sha}
    (run / "a1/adapter_receipt.json").write_text(json.dumps(adapter), encoding="utf-8")
    receipt = {"artifact": "h2", "stage": "G1-SMOKE", "exit_code": 0, "child_returncode": 0,
               "code": {"commit": "commit", "code_changed_during_run": False,
                        "adapters_dirty": False, "stage_config_sha256": "stage"},
               "guard": {"upstream_model": "deepseek-flash", "halted": False,
                         "requests_refused": 0, "usd_is_notional": False,
                         "requests_forwarded": 1, "usd": "0.01", "total_tokens": 1000}}
    receipt_path = run / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    ledger = run / "ledger.jsonl"
    ledger.write_text(json.dumps({"usage_source": "provider", "http_status": 200}) + "\n",
                      encoding="utf-8")
    cap = {"cap_usd": 1.00, "cap_tokens": 2000000, "cap_requests": 1600}
    gate = a1.validate_smoke(run, results_root=tmp_path, case_sha="case",
                             code_commit="commit", stage_sha="stage", full_stage=cap)
    assert gate["projection_1p2x5"] == {"usd": 0.06, "tokens": 6000, "requests": 6}
    ledger.write_text(json.dumps({"usage_source": "estimate", "http_status": 200}) + "\n",
                      encoding="utf-8")
    with pytest.raises(a1.ScreenError, match="ledger"):
        a1.validate_smoke(run, results_root=tmp_path, case_sha="case",
                          code_commit="commit", stage_sha="stage", full_stage=cap)
