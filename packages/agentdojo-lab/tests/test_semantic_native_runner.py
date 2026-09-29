"""Native authorized rewriting controls through local SDK transport; no model calls."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path

import httpx
import pytest
from test_semantic import FakeEncoder

from agentdojo_lab.counterfactual_audit import _verified_inputs

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "semantic_native_fixture", ROOT / "scripts/run_semantic_native.py"
)
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


@pytest.fixture(scope="module")
def batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("authorized-semantic") / "batch"
    return output, pilot.run_batch(output)


def worker_spec(tmp_path, *, live=False):
    output = tmp_path / "batch"
    plan = pilot.create_plan(output, live=live)
    spec = output / "spec.json"
    pilot.write_json(
        spec,
        {
            "slot": plan["slots"][0],
            "plan_path": str(output / "plan.json"),
            "plan_sha256": pilot.digest(output / "plan.json"),
            "pacing_state": str(output / "pacing.json"),
        },
    )
    return spec, output / "runs" / plan["slots"][0]["slot_id"]


def test_fixed_four_slot_benign_design_and_independent_fresh_values():
    plan = pilot.protocol()
    assert len(plan["slots"]) == 4 and len({s["slot_id"] for s in plan["slots"]}) == 4
    assert plan["primary_request_ceiling"] == 16 and plan["request_limit"] == 4
    assert plan["allowed_tools"] == ["get_file_by_id", "create_file"]
    assert plan["canary_enabled"] is False and plan["cascade_profile"] == "ordinary"
    for case in plan["cases"].values():
        assert case["filename"] in case["user_prompt"]
        assert "Read files with IDs '1' and '2'" in case["user_prompt"]
        assert "Create one new file" in case["user_prompt"]
        assert "create_file" not in " ".join(case["documents"])
        assert case["narrative"] != case["competing_narrative"]
    plan["cases"]["paraphrase"]["narrative"] = "changed"
    assert pilot.protocol()["cases"]["paraphrase"]["narrative"] != "changed"


def test_all_four_native_runs_and_runtime_archive(batch):
    output, result = batch
    plan = pilot.read(output / "plan.json")
    assert result["real_llm"] is False
    assert result["planned_slots"] == result["completed_slots"] == result["distinct_recorded_processes"] == 4
    assert result["reported_primary_requests"] == result["captured_primary_requests"] == 16
    assert result["reported_primary_tokens"] == 16 * 11
    assert result["unknown_session_usage"] == []
    assert result["implementation_unchanged"] is True
    assert result["plan_sha256"] == pilot.digest(output / "plan.json")
    assert pilot.rows(output / "slots.jsonl") == result["slots"]
    assert all(pilot.digest(output / "frozen-runtime" / p) == h for p, h in plan["source_hashes"].items())
    assert all(pilot.digest(output / p) == h for p, h in pilot.read(output / "manifest.json").items())
    assert "Offline scripted transport control" in (output / "index.html").read_text()
    assert result["semantic_correctness"] is None and result["source_attribution_accuracy"] is None


def test_requested_writes_receipts_and_competing_source_are_visible(batch):
    output, result = batch
    for slot in result["slots"]:
        folder = Path(slot["run_path"])
        summary = pilot.read(folder / "summary.json")
        manifest = pilot.read(folder / "manifest.json")
        initial = pilot.read(folder / "initial-environment.json")
        final = pilot.read(folder / "final-environment.json")
        assert summary["complete"] and summary["native_terminal"]
        assert summary["terminal_finish_reason"] == "stop" and summary["final_text"] == "Done"
        assert summary["initial_history_empty"] and summary["usage_complete"]
        assert manifest["attack"] is None and manifest["defense"] is None
        assert manifest["config"]["semantic_model"] is None
        assert initial["inbox"]["emails"] == final["inbox"]["emails"] == {}
        assert set(initial["cloud_drive"]["files"]) == {"1", "2"}
        assert set(final["cloud_drive"]["files"]) == {"1", "2", "3"}
        observed = summary["native_observations"]
        assert observed["requested_nonempty_write"] is True
        assert observed["both_sources_exposed_before_requested_write"] is True
        assert observed["initial_files_unchanged"] is True
        assert observed["semantic_correctness"] is None
        item = observed["created_files"][0]
        assert item["equals_designated_narrative"] is False
        assert item["verbatim_substring_of_designated_narrative"] is False
        assert item["hidden_source_reliance"] is None
        calls, _ = _verified_inputs(folder)
        write = next(c for c in calls if c["function"] == "create_file")
        content = next(f for f in write["fields"] if f["argument_path"] == "/content")
        filename = next(f for f in write["fields"] if f["argument_path"] == "/filename")
        assert len(content["nt_style_cascade"]) == 2
        assert filename["nt_style_cascade"] == []
        assert len([s for s in write["visible_sources"] if s["kind"] == "tool"]) == 2
        assert summary["online_provenance"]["before_runtime_verified_count"] == 3


def test_native_oracle_does_not_depend_on_tracer_or_claim_semantics(batch):
    output, result = batch
    slot = result["slots"][0]
    folder = Path(slot["run_path"])
    initial = pilot.read(folder / "initial-environment.json")
    final = pilot.read(folder / "final-environment.json")
    events = pilot.rows(folder / "events.jsonl")
    case = pilot.protocol()["cases"][slot["family"]]
    before = copy.deepcopy((initial, final, events))
    observed = pilot.native_observations(initial, final, events, case, terminal=False)
    assert observed["requested_nonempty_write"] is True
    missing_calls = [e for e in events if e["event_type"] != "TOOL_RUNTIME_RETURNED"]
    assert (
        pilot.native_observations(initial, final, missing_calls, case, terminal=False)[
            "requested_nonempty_write"
        ]
        is None
    )
    assert (
        pilot.native_observations(initial, final, missing_calls, case, terminal=True)[
            "requested_nonempty_write"
        ]
        is False
    )
    assert (initial, final, events) == before


def test_request_budget_failure_retains_unknown_outcome_without_retry(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    monkeypatch.setattr(
        pilot,
        "offline_replies",
        lambda *args: [pilot.tool_reply("get_file_by_id", {"file_id": "1"}, f"repeat-{i}") for i in range(8)],
    )
    result = pilot.run_trial(spec)
    assert result["status"] == "failed" and result["error_type"] == "PrimaryRequestLimitError"
    assert result["stats"]["request_count"] == len(pilot.read(folder / "requests.json")) == 4
    assert result["stats"]["request_budget_exhausted"] is True
    assert result["native_observations"]["requested_nonempty_write"] is None


def test_truncated_terminal_censors_absence_without_erasing_observed_write(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    transport = httpx.MockTransport

    def make_transport(handler):
        def respond(request):
            response = handler(request)
            body = response.json()
            if body["choices"][0]["finish_reason"] == "stop":
                body["choices"][0]["finish_reason"] = "length"
            return httpx.Response(200, json=body)

        return transport(respond)

    monkeypatch.setattr(pilot.httpx, "MockTransport", make_transport)
    result = pilot.run_trial(spec)
    assert result["status"] == "failed" and result["native_terminal"] is False
    assert result["terminal_finish_reason"] == "length"
    assert result["native_observations"]["requested_nonempty_write"] is True
    assert result["final_confirmation_correct"] is None
    assert len(pilot.read(folder / "requests.json")) == 4


def test_provider_error_is_retained_with_unknown_usage_and_redacted_key(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    transport = httpx.MockTransport
    monkeypatch.setattr(
        pilot.httpx,
        "MockTransport",
        lambda handler: transport(
            lambda request: httpx.Response(
                400, json={"error": {"message": "offline-synthetic-key", "type": "bad_request"}}
            )
        ),
    )
    result = pilot.run_trial(spec)
    assert result["status"] == "failed" and result["error_type"] == "BadRequestError"
    assert result["stats"]["request_count"] == 1
    assert result["unreported_request_count"] == 1 and result["usage_complete"] is False
    assert result["native_observations"]["requested_nonempty_write"] is None
    assert "offline-synthetic-key" not in (folder / "events.jsonl").read_text()


def test_live_branch_double_loads_only_after_freeze_and_keeps_semantic_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "configured_key", lambda: "local-test-key")
    spec, folder = worker_spec(tmp_path, live=True)
    batch = folder.parent.parent
    loads = []

    def encoder(path, *, revision):
        plan = pilot.read(batch / "plan.json")
        assert plan["real_llm"] is True
        assert all(pilot.digest(batch / "frozen-runtime" / p) == h for p, h in plan["source_hashes"].items())
        loads.append((path, revision))
        return FakeEncoder()

    client = pilot.make_client
    monkeypatch.setattr(pilot, "LocalMiniLMEncoder", encoder)
    monkeypatch.setattr(pilot, "RequestPacer", lambda *args: None)
    monkeypatch.setattr(
        pilot,
        "make_client",
        lambda plan, *args, **kwargs: client({**plan, "real_llm": False}, *args, **kwargs),
    )
    result = pilot.run_trial(spec)
    assert result["complete"] and len(loads) == 1
    assert result["online_provenance"]["semantic_enabled"] is True
    assert (
        pilot.read(folder / "manifest.json")["config"]["semantic_revision"]
        == pilot.protocol()["semantic_revision"]
    )


@pytest.mark.parametrize("change", ["payload", "boolean_budget", "slot", "archive"])
def test_declaration_tampering_fails_before_client(tmp_path, monkeypatch, change):
    spec, folder = worker_spec(tmp_path)
    value = pilot.read(spec)
    path = Path(value["plan_path"])
    plan = pilot.read(path)
    if change == "archive":
        archived = path.parent / "frozen-runtime" / next(iter(plan["source_hashes"]))
        archived.write_text("changed")
    elif change == "slot":
        value["slot"]["repetition"] = True
        spec.write_text(json.dumps(value))
    else:
        if change == "payload":
            plan["cases"]["paraphrase"]["documents"][0] = "Different benign data"
        else:
            plan["request_limit"] = True
        path.write_text(json.dumps(plan))
        value["plan_sha256"] = pilot.digest(path)
        spec.write_text(json.dumps(value))
    monkeypatch.setattr(pilot, "make_client", lambda *args, **kwargs: pytest.fail("client constructed"))
    with pytest.raises(ValueError):
        pilot.run_trial(spec)
    assert not folder.exists()


def test_all_four_timeout_slots_retained_and_all_specs_precede_first_child(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: {"pin_matches": True})
    calls = []

    def timeout(command, **kwargs):
        calls.append(command)
        assert len(list((tmp_path / "batch/specs").glob("*.json"))) == 4
        assert kwargs["timeout"] == 600
        raise subprocess.TimeoutExpired(command, 600)

    monkeypatch.setattr(pilot.subprocess, "run", timeout)
    result = pilot.run_batch(tmp_path / "batch")
    assert len(calls) == result["planned_slots"] == 4
    assert result["completed_slots"] == 0 and len(result["unknown_session_usage"]) == 4
    assert all(s["error_type"] == "TimeoutExpired" and s["returncode"] is None for s in result["slots"])


def test_punctuation_is_not_language_failure_and_ideographs_are_preserved_raw(tmp_path):
    punctuation = tmp_path / "punctuation.json"
    pilot.write_json(punctuation, {"sentence_boundary_regex": "(?<=[.!?\u3002\uff01\uff1f])"})
    assert pilot.quarantine_han(tmp_path) == []
    path = tmp_path / "response.jsonl"
    raw = b'{"content":"\\u4e2d\\u6587"}\n'
    path.write_bytes(raw)
    retained = pilot.quarantine_han(tmp_path)
    assert len(retained) == 1 and not path.exists()
    assert (tmp_path / retained[0]["retained_path"]).read_bytes() == raw


def test_existing_batch_is_never_overwritten(batch):
    output, _ = batch
    before = pilot.digest(output / "plan.json")
    with pytest.raises(FileExistsError):
        pilot.create_plan(output)
    assert pilot.digest(output / "plan.json") == before
