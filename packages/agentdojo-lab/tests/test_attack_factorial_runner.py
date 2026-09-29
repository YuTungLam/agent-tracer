"""Fresh native environments and real SDK serialization, with local mock transport."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from test_semantic import FakeEncoder

from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.counterfactual_audit import _verified_inputs
from agentdojo_lab.semantic import SemanticMatcher

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "attack_factorial_runner_fixture", ROOT / "scripts/run_attack_factorial.py"
)
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)
sys.path.pop(0)


def read(path):
    return json.loads(path.read_text())


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture(scope="module")
def batch(tmp_path_factory):
    output = tmp_path_factory.mktemp("attack-factorial") / "batch"
    return output, pilot.run_batch(output)


def worker_spec(tmp_path):
    output = tmp_path / "batch"
    plan = pilot.create_plan(output)
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


def test_all_frozen_slots_run_once_in_distinct_processes_and_keep_the_plan(batch):
    output, result = batch
    plan = read(output / "plan.json")
    assert result["real_llm"] is False
    assert result["planned_slots"] == result["completed_slots"] == result["distinct_recorded_processes"] == 16
    assert result["reported_primary_requests"] == result["captured_primary_requests"] == 52
    assert result["reported_primary_tokens"] == 52 * 11
    assert result["unknown_session_usage"] == []
    assert result["implementation_unchanged"] is True
    assert result["plan_sha256"] == pilot.digest(output / "plan.json")
    assert [
        {k: slot[k] for k in ("slot_id", "family", "arm", "repetition")} for slot in result["slots"]
    ] == plan["slots"]
    assert rows(output / "slots.jsonl") == result["slots"]
    assert plan["primary_request_ceiling"] == 64
    assert plan["canary_enabled"] is False and plan["cascade_profile"] == "ordinary"
    assert "src/agentdojo_lab/profiles.py" in plan["source_hashes"]
    assert "src/agentdojo_lab/causal_v2_audit.py" not in plan["source_hashes"]
    assert all(
        pilot.digest(output / path) == digest for path, digest in read(output / "manifest.json").items()
    )


@pytest.mark.parametrize("family", ["content_composition", "conditional_action"])
def test_scripted_both_attacks_and_control_arms_use_real_native_state(batch, family):
    output, result = batch
    plan = read(output / "plan.json")
    for slot in (s for s in result["slots"] if s["family"] == family):
        folder = Path(slot["run_path"])
        summary, initial, final, actions = [
            read(folder / name)
            for name in ("summary.json", "initial-environment.json", "final-environment.json", "actions.json")
        ]
        both = slot["arm"] == "both"
        assert slot["returncode"] == 0 and slot["process_status"] == "completed"
        assert summary == slot["summary"]
        assert summary["complete"] is True and summary["final_text"] == "Total: 42"
        assert summary["initial_history_empty"] is True
        assert summary["stats"]["request_count"] == (4 if both else 3)
        assert summary["stats"]["request_budget_exhausted"] is False
        assert actions[:2] == [
            {"function": "get_file_by_id", "arguments": {"file_id": "1"}},
            {"function": "get_file_by_id", "arguments": {"file_id": "2"}},
        ]
        assert len(actions) == (3 if both else 2)
        assert set(initial["cloud_drive"]["files"]) == {"1", "2"}
        assert [initial["cloud_drive"]["files"][str(i)]["content"] for i in (1, 2)] == plan["documents"][
            family
        ][slot["arm"]]
        assert initial["inbox"]["emails"]["3"]["read"] is False
        if both and family == "content_composition":
            created = final["cloud_drive"]["files"]["3"]
            assert created["filename"] == plan["target_filename"]
            assert created["content"] == plan["target_content"]
        else:
            assert final["cloud_drive"]["files"] == initial["cloud_drive"]["files"]
        assert final["inbox"]["emails"]["3"]["read"] is (both and family == "conditional_action")
        if both and family == "conditional_action":
            assert actions[-1] == {"function": "get_unread_emails", "arguments": {}}
            calls, _ = _verified_inputs(folder)
            sink = next(c for c in calls if c["function"] == "get_unread_emails")
            assert sink["arguments"] == {} and sink["fields"] == []
            assert sink["policy"]["sink"]["selected"] is True
            assert len([s for s in sink["visible_sources"] if s["kind"] == "tool"]) == 2


def test_real_prefixes_receipts_checkpoint_and_english_artifacts(batch):
    output, result = batch
    for slot in result["slots"]:
        folder = Path(slot["run_path"])
        summary, manifest = read(folder / "summary.json"), read(folder / "manifest.json")
        events, provenance = rows(folder / "events.jsonl"), rows(folder / "provenance.jsonl")
        requests = read(folder / "requests.json")
        assert (
            requests
            == rows(folder / "requests.jsonl")
            == [e["data"]["body"] for e in events if e["event_type"] == "MODEL_REQUEST"]
        )
        assert [m["role"] for m in requests[0]["messages"]] == ["system", "user"]
        assert manifest["config"]["canary_enabled"] is False and manifest["input_condition"] == "passive"
        assert manifest["config"]["cascade_profile"] == "ordinary"
        assert summary["recording"]["complete"] and summary["recording"]["audit"]["valid"]
        assert (
            summary["online_provenance"]["complete"]
            and summary["online_provenance"]["subscriber"]["complete"]
        )
        assert summary["online_provenance"]["before_runtime_verified_count"] == len(
            read(folder / "actions.json")
        )
        raw = (folder / "provenance.jsonl").read_bytes().splitlines(True)
        for receipt in (r for r in provenance if r["record_type"] == "analysis_flush"):
            assert (
                receipt["analysis_line_sha256"]
                == hashlib.sha256(raw[receipt["analysis_record_sequence"] - 1]).hexdigest()
            )
        assert all(
            r["analysis_before_runtime"] and r["receipt_before_runtime"]
            for r in provenance
            if r["record_type"] == "runtime_timing"
        )
        assert summary["lineage_state"]["sha256"] == pilot.digest(folder / "lineage-state.json")
        _verified_inputs(folder)
    for path in output.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".jsonl", ".html"}:
            text = path.read_text()
            assert not pilot.CJK.search(text)
            assert "offline-synthetic-key" not in text
            assert '"Authorization"' not in text


def test_four_request_cap_preserves_failed_slot_without_extra_sdk_request(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    monkeypatch.setattr(
        pilot,
        "offline_replies",
        lambda *args: [pilot.tool_reply("get_file_by_id", {"file_id": "1"}, f"read-{i}") for i in range(8)],
    )
    result = pilot.run_trial(spec)
    assert result["status"] == "failed" and result["complete"] is False
    assert result["error_type"] == "PrimaryRequestLimitError"
    assert result["stats"]["request_count"] == len(read(folder / "requests.json")) == 4
    assert result["stats"]["request_budget_exhausted"] is True
    assert result["final_text"] == ""


def test_sdk_failure_keeps_count_and_redacts_known_key_from_error_response(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    original = httpx.MockTransport
    monkeypatch.setattr(
        pilot.httpx,
        "MockTransport",
        lambda handler: original(
            lambda request: httpx.Response(
                400,
                json={"error": {"message": "Rejected offline-synthetic-key", "code": "fixture_error"}},
            )
        ),
    )
    result = pilot.run_trial(spec)
    assert result["error_type"] == "BadRequestError"
    assert result["status"] == "failed" and result["stats"]["request_count"] == 1
    assert len(read(folder / "requests.json")) == 1
    assert "offline-synthetic-key" not in (folder / "events.jsonl").read_text()
    assert "Rejected" not in json.dumps(result)


def test_non_english_response_retains_raw_bytes_and_excludes_timeline_content(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    original = pilot.offline_replies

    def replies(*args):
        value = original(*args)
        value[-1]["content"] = "Unexpected \u4e2d\u6587 response."
        return value

    monkeypatch.setattr(pilot, "offline_replies", replies)
    result = pilot.run_trial(spec)
    assert result["status"] == "failed" and result["complete"] is False
    assert result["error_type"] == "UnsupportedRecordedLanguage"
    assert result["final_text"] is None and result["online_provenance"]["complete"] is False
    assert (folder / "events.jsonl.raw.bin").is_file()
    assert b"Unexpected" in (folder / "final-text.raw.bin").read_bytes()
    for path in folder.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".jsonl", ".html"}:
            assert not pilot.CJK.search(path.read_text())


def test_encoder_sentence_punctuation_does_not_quarantine_valid_native_trace(tmp_path, monkeypatch):
    spec, folder = worker_spec(tmp_path)
    original = pilot.OnlineProvenance
    encoder = FakeEncoder()
    encoder.metadata = {
        "model_id": "offline-punctuation-control",
        "sentence_boundary_regex": "[.!?\u3002\uff01\uff1f]",
    }
    matcher = SemanticMatcher(encoder)

    def sidecar(path, *, semantic_matcher=None, policy, lineage, **kwargs):
        lineage.matcher = CascadeMatcher.for_memory(matcher)
        return original(path, semantic_matcher=matcher, policy=policy, lineage=lineage, **kwargs)

    monkeypatch.setattr(pilot, "OnlineProvenance", sidecar)
    result = pilot.run_trial(spec)
    assert result["complete"] is True and result["status"] == "completed"
    assert result["retained_raw_artifacts"] == [] and result["online_provenance"]["complete"] is True
    assert not list(folder.rglob("*.raw.bin"))
    assert (folder / "manifest.json").exists() and (folder / "report.html").exists()
    _verified_inputs(folder)


def test_process_failures_keep_every_slot_and_unknown_usage(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: {})
    monkeypatch.setattr(pilot.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=17))
    output = tmp_path / "failed"
    result = pilot.run_batch(output)
    assert len(result["slots"]) == len(result["unknown_session_usage"]) == 16
    assert result["completed_slots"] == result["reported_primary_requests"] == 0
    assert all(
        s["process_status"] == "failed" and s["returncode"] == 17 and s["summary"] is None
        for s in result["slots"]
    )
    assert len(rows(output / "slots.jsonl")) == 16


def test_partial_non_english_capture_after_killed_child_keeps_exact_bytes(tmp_path):
    partial = '{"messages": "Unexpected \u4e2d\u6587'.encode()
    path = tmp_path / "requests.jsonl"
    path.write_bytes(partial)
    retained = pilot.quarantine_non_english(tmp_path)
    assert not path.exists()
    assert (tmp_path / "requests.jsonl.raw.bin").read_bytes() == partial
    assert retained == [
        {
            "original_path": "requests.jsonl",
            "retained_path": "requests.jsonl.raw.bin",
            "sha256": hashlib.sha256(partial).hexdigest(),
        }
    ]


def test_summary_does_not_hide_failed_process_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: {})

    def failed_after_summary(command, **kwargs):
        spec = read(Path(command[-1]))
        folder = Path(spec["plan_path"]).parent / "runs" / spec["slot"]["slot_id"]
        folder.mkdir(parents=True)
        pilot.write_json(
            folder / "summary.json",
            {
                "status": "completed",
                "complete": True,
                "pid": 1,
                "stats": {"request_count": 1, "prompt_tokens": 2, "completion_tokens": 3},
            },
        )
        return SimpleNamespace(returncode=19)

    monkeypatch.setattr(pilot.subprocess, "run", failed_after_summary)
    result = pilot.run_batch(tmp_path / "failed")
    assert result["completed_slots"] == 0
    assert result["reported_primary_requests"] == 16 and result["unknown_session_usage"] == []
    assert all(s["summary"] is not None and s["process_status"] == "failed" for s in result["slots"])


def test_timeout_retains_partial_request_lower_bound_without_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "require_upstream", lambda: {})
    calls = []

    def timeout(command, **kwargs):
        calls.append(command)
        spec = read(Path(command[-1]))
        folder = Path(spec["plan_path"]).parent / "runs" / spec["slot"]["slot_id"]
        folder.mkdir(parents=True)
        (folder / "requests.jsonl").write_text('{"messages": []}\n')
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(pilot.subprocess, "run", timeout)
    result = pilot.run_batch(tmp_path / "failed")
    assert len(calls) == len(result["slots"]) == 16
    assert result["captured_primary_requests"] == 16 and result["reported_primary_requests"] == 0
    assert len(result["unknown_session_usage"]) == 16
    assert all(s["error_type"] == "TimeoutExpired" for s in result["slots"])


def test_existing_batch_cannot_be_overwritten(batch):
    output, _ = batch
    before = pilot.digest(output / "plan.json")
    with pytest.raises(FileExistsError):
        pilot.run_batch(output)
    assert pilot.digest(output / "plan.json") == before


def test_mutated_plan_rejected_before_worker_output(tmp_path):
    spec, folder = worker_spec(tmp_path)
    path = Path(read(spec)["plan_path"])
    changed = read(path)
    changed["max_completion_tokens"] = 4096
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="not bound"):
        pilot.run_trial(spec)
    assert not folder.exists()
