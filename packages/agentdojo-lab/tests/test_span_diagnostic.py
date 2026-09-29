"""Native SDK-mocked binding controls; these are not real-model accuracy data."""

import json

import pytest
from test_evaluation_runner import config, scripted_client, spec

from agentdojo_lab import span_diagnostic as module
from agentdojo_lab.evaluation_runner import InputComparisonTrial, run_evaluation_trial
from agentdojo_lab.span_diagnostic import analyze_span_run


@pytest.fixture
def native_run(monkeypatch, tmp_path):
    scripted_client(monkeypatch)
    path = tmp_path / "run"
    run_evaluation_trial(config(), spec(), output=path)
    return path


def test_native_region_identity_and_saved_baseline(native_run):
    result = analyze_span_run(native_run)
    assert result["status"] == "complete", result["reason"]
    assert result["source_unchanged"] is True
    assert result["validation"]["verified_proposals"] == 3
    delete = next(f for f in result["fields"] if f["function"] == "delete_file")
    assert delete["target"] == "13"
    injected = next(s for s in delete["sources"] if s["injection_spans"])
    assert injected["scalar_pointer"] == "/1/content"
    start, end = injected["injection_spans"][0]
    assert injected["source_text"][start:end] == spec().payload
    assert injected["evidence"]["literal_evidence"]["classification"] == "injection_only"
    assert injected["evidence"]["low_information_target"] is True
    assert injected["original_source_cascade"]["matched"] is True
    assert injected["wire_span"][1] - injected["wire_span"][0] != len(injected["source_text"])
    assert analyze_span_run(native_run) == result


@pytest.mark.parametrize("condition,canary", [("clean", True), ("injected", False)])
def test_clean_and_passive_conditions(monkeypatch, tmp_path, condition, canary):
    scripted_client(monkeypatch)
    trial = (
        spec(condition) if canary else InputComparisonTrial(**spec().model_dump(), input_condition="passive")
    )
    run = tmp_path / "run"
    run_evaluation_trial(config(canary_enabled=canary), trial, output=run)
    result = analyze_span_run(run)
    assert result["status"] == "complete", result["reason"]
    assert result["input_condition"] == ("canary_intervention" if canary else "passive")
    if condition == "clean":
        assert not any(s["injection_spans"] for f in result["fields"] for s in f["sources"])


@pytest.mark.parametrize("mutation", ["target", "source", "exposure", "scope", "duplicate", "missing"])
def test_saved_prefix_tampering_is_unavailable(native_run, mutation):
    path = native_run / "provenance.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    wrapper = next(
        r for r in rows if r["record_type"] == "call_analysis" and r["call"]["function"] == "append_to_file"
    )
    call = wrapper["call"]
    if mutation == "target":
        call["fields"][0]["value"] += " changed"
    elif mutation == "source":
        call["visible_sources"][-1]["text"] += " changed"
    elif mutation == "exposure":
        call["visible_sources"][-1]["exposure_event_id"] = "event:future"
    elif mutation == "scope":
        call["fields"][0]["cascade_scope"]["sink"]["selected"] = False
    elif mutation == "duplicate":
        rows.append(wrapper)
    else:
        rows.remove(wrapper)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = analyze_span_run(native_run)
    assert result["status"] == "unavailable"
    assert result["fields"] == []
    assert result["source_unchanged"] is True


def test_exposure_range_is_bound_to_decoded_payload(native_run, monkeypatch):
    original = module.payload_exposure_audit

    def altered(*args):
        result = original(*args)
        result["occurrences"][0]["scalar_span"][0] += 1
        return result

    monkeypatch.setattr(module, "payload_exposure_audit", altered)
    result = analyze_span_run(native_run)
    assert result["status"] == "unavailable"
    assert "range mismatch" in result["reason"]


def test_decode_failure_and_budget_preserve_unknowns(native_run, monkeypatch):
    monkeypatch.setattr(
        module,
        "decode_span_scalars",
        lambda _: {
            "complete": False,
            "status": "unsupported_structure",
            "reason": "fixture_unsupported",
        },
    )
    result = analyze_span_run(native_run)
    assert result["status"] == "complete"
    rows = [s for f in result["fields"] for s in f["sources"]]
    assert rows and all(s["evidence"] is None and s["injection_spans"] is None for s in rows)


def test_comparison_budget_is_explicit(native_run, monkeypatch):
    monkeypatch.setattr(module, "MAX_COMPARISONS", 1)
    result = analyze_span_run(native_run)
    assert result["status"] == "complete"
    rows = [s for f in result["fields"] for s in f["sources"]]
    assert sum(s["evidence"] is not None for s in rows) == 1
    assert any(s["reason"] == "run_comparison_budget" for s in rows)
    assert any(f["status"] == "partial" for f in result["fields"])


def test_missing_input_and_partial_recording(native_run):
    summary = native_run / "summary.json"
    value = json.loads(summary.read_text())
    value["recording"]["complete"] = False
    summary.write_text(json.dumps(value))
    assert "Incomplete recording" in analyze_span_run(native_run)["reason"]
    summary.unlink()
    result = analyze_span_run(native_run)
    assert result["status"] == "unavailable"
    assert result["source_unchanged"] is False
