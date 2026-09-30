"""Focused, network-free checks for the frozen cross-model pilot runner."""

from __future__ import annotations

import copy
import importlib.util
import io
from pathlib import Path

import pytest
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import text_content_block_from_string

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_cross_model_technical_pilot_v2.py"
SPEC = importlib.util.spec_from_file_location("cross_model_pilot_runner_for_tests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def fake_semantic_identity():
    return {
        "model_id": "sentence-transformers/all-MiniLM-L6-v2",
        "model_path": runner.SEMANTIC_MODEL,
        "revision": runner.SEMANTIC_REVISION,
        "manifest_sha256": "test-model-manifest",
        "versions": {"sentence-transformers": "6.0.1"},
    }


@pytest.fixture(scope="module")
def manifest():
    return runner.build_run_manifest("a" * 40, live=False)


class StubObserver:
    def __init__(self):
        self.request_id = "request-0001"
        self.failures = []

    def begin_model_call(self, _messages):
        return None

    def model_parsed(self, _output):
        return None

    def model_failed(self, error):
        self.failures.append(type(error).__name__)


@pytest.mark.parametrize("provider_id", ["deepseek", "groq"])
def test_actual_sdk_mock_transport_uses_frozen_wire_fields(manifest, provider_id):
    slot = copy.deepcopy(
        next(row for row in manifest["protocol_manifest"]["slots"] if row["provider_id"] == provider_id)
    )
    slot["offline_responses"] = [{"role": "assistant", "content": "Transport complete."}]
    observer = StubObserver()
    captures, reservations = [], []
    requests_stream, reservations_stream = io.StringIO(), io.StringIO()
    runtime = FunctionsRuntime()

    @runtime.register_function
    def inspect_value(value: str) -> str:
        """Inspect a test value.

        :param value: Synthetic value.
        """
        return value

    with runner.make_client(
        manifest,
        slot,
        observer,
        captures,
        reservations,
        requests_stream,
        reservations_stream,
        api_key="offline-key",
    ) as client:
        llm = runner.make_llm(client, slot, observer)
        history = [
            {
                "role": "user",
                "content": [text_content_block_from_string("Inspect this value.")],
            }
        ]
        llm.query("Inspect this value.", runtime, messages=history)

    assert observer.failures == []
    assert len(captures) == len(reservations) == 1
    body = captures[0]["body"]
    runner.cross_model_pilot_v2.assert_frozen_outbound_request(
        manifest["protocol_manifest"]["config"], provider_id, body
    )
    assert reservations[0]["model_request_id"] == "request-0001"
    assert reservations[0]["output_token_upper_bound"] == 2048
    assert reservations[0]["reserved_tokens"] >= 2048


def test_request_budget_rejects_eleventh_sdk_call():
    budget = runner.RequestBudget(10)
    stats = {"request_count": 0, "request_budget_exhausted": False}
    for _ in range(10):
        budget.permit(stats)
        stats["request_count"] += 1
    with pytest.raises(runner.PrimaryRequestLimitError):
        budget.permit(stats)
    assert stats == {"request_count": 10, "request_budget_exhausted": True}


def test_missing_live_keys_fails_before_output_creation(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    output = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="requires both"):
        runner.run_batch(output, agent_tracer_commit="a" * 40, live=True)
    assert not output.exists()


def test_live_semantic_preflight_fails_before_output_creation(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-deepseek")
    monkeypatch.setenv("GROQ_API_KEY", "test-groq")
    monkeypatch.setattr(runner, "_verify_live_revision", lambda _commit: None)
    monkeypatch.setattr(
        runner,
        "_verified_semantic_identity",
        lambda: (_ for _ in ()).throw(ValueError("semantic snapshot invalid")),
    )
    output = tmp_path / "must-not-exist-semantic"

    with pytest.raises(ValueError, match="semantic snapshot invalid"):
        runner.run_batch(output, agent_tracer_commit="a" * 40, live=True)

    assert not output.exists()


def test_live_revision_rejects_any_nonignored_worktree_change(monkeypatch):
    calls = []

    def fake_git(*args):
        calls.append(args)
        return "a" * 40 if args[:2] == ("rev-parse", "HEAD") else "?? untracked-runtime.py"

    monkeypatch.setattr(
        runner,
        "_git",
        fake_git,
    )

    with pytest.raises(ValueError, match="worktree"):
        runner._verify_live_revision("a" * 40)

    assert ("status", "--porcelain", "--untracked-files=all") in calls


def test_env_file_keys_reach_child_dispatch_but_are_never_persisted(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(runner, "_verify_live_revision", lambda _commit: None)
    monkeypatch.setattr(runner, "_verified_semantic_identity", fake_semantic_identity)
    deepseek_key = "test-deepseek-secret"
    groq_key = "test-groq-secret"
    env_file = tmp_path / "credentials.env"
    env_file.write_text(
        f"DEEPSEEK_API_KEY={deepseek_key}\nGROQ_API_KEY={groq_key}\n",
        encoding="utf-8",
    )
    seen = []

    def dispatch(_manifest, slot, output, _manifest_hash, credentials):
        seen.append(dict(credentials))
        item = runner._slot_item(slot, output)
        item["process_status"] = "completed"
        return item

    monkeypatch.setattr(runner, "dispatch", dispatch)
    output = tmp_path / "live-shape-only"
    runner.run_batch(
        output,
        agent_tracer_commit="a" * 40,
        live=True,
        env_file=env_file,
        max_started_slots=1,
    )

    assert seen == [{"DEEPSEEK_API_KEY": deepseek_key, "GROQ_API_KEY": groq_key}]
    persisted = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in output.rglob("*") if path.is_file()
    )
    assert deepseek_key not in persisted
    assert groq_key not in persisted
    assert all(
        not Path(item["run_path"]).is_absolute()
        for item in runner._read_json(output / "summary.json")["slots"]
    )


def _fake_dispatch(calls):
    def dispatch(_manifest, slot, output, _manifest_hash, _credentials):
        calls.append(slot["run_id"])
        item = runner._slot_item(slot, output)
        item["process_status"] = "completed"
        item["summary"] = {
            "acceptance": {
                "request_capture": {"status": "pass"},
                "source_binding": {"status": "fail"},
                "execution_state": {"status": "not_covered"},
                "scoring_and_cost": {"status": "not_covered"},
            }
        }
        return item

    return dispatch


def first_manifest_slots(output):
    return runner._read_json(output / "manifest.json")["protocol_manifest"]["slots"]


def test_checkpoint_resume_starts_only_untouched_slots(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "dispatch", _fake_dispatch(calls))
    output = tmp_path / "checkpointed"
    first = runner.run_batch(
        output,
        agent_tracer_commit="a" * 40,
        live=False,
        max_started_slots=2,
    )
    assert first["paused"] is True
    assert first["started_runs"] == 2
    assert first["acceptance_status_counts"] == {"pass": 2, "fail": 2, "not_covered": 4}

    second = runner.resume_batch(output, max_started_slots=1)
    assert second["paused"] is True
    assert second["started_runs"] == 3
    assert calls == [row["run_id"] for row in first_manifest_slots(output)[:3]]
    assert len(calls) == len(set(calls))


def test_output_limit_keeps_linked_parse_failure():
    events = [
        {
            "event_type": "MODEL_RESPONSE",
            "model_request_id": "request-1",
            "data": {"body": {"choices": [{"finish_reason": "length"}]}},
        },
        {
            "event_type": "MODEL_ERROR",
            "model_request_id": "request-1",
            "data": {"error_type": "JSONDecodeError"},
        },
    ]
    stop = runner.build_stop_record(
        events,
        {"request_count": 1, "request_budget_exhausted": False},
        failure="JSONDecodeError",
        final_text_present=False,
    )
    assert stop == {
        "primary": {"reason": "output_limit_triggered", "model_request_id": "request-1"},
        "secondary": [
            {
                "reason": "parse_error",
                "model_request_id": "request-1",
                "caused_by": "output_limit_triggered",
            }
        ],
        "output_limit_triggered": True,
        "request_limit_triggered": False,
    }


def test_tenth_request_without_final_text_has_distinct_request_limit_stop():
    stop = runner.build_stop_record(
        [],
        {"request_count": 10, "request_budget_exhausted": False},
        failure=None,
        final_text_present=False,
    )
    assert stop == {
        "primary": {"reason": "request_limit_triggered"},
        "secondary": [],
        "output_limit_triggered": False,
        "request_limit_triggered": True,
    }


def test_tenth_request_failure_remains_primary_with_linked_limit():
    stop = runner.build_stop_record(
        [],
        {"request_count": 10, "request_budget_exhausted": False},
        failure="APITimeoutError",
        final_text_present=False,
    )

    assert stop == {
        "primary": {"reason": "network_error"},
        "secondary": [{"reason": "request_limit_triggered", "caused_by": "network_error"}],
        "output_limit_triggered": False,
        "request_limit_triggered": True,
    }


def test_sink_verification_tracks_complete_false_state_without_requiring_success(manifest):
    slot = manifest["protocol_manifest"]["slots"][0]
    sink = slot["base_fixture_slot"]["sink_call"]
    events = [
        {
            "event_id": "proposal",
            "event_type": "TOOL_CALL_PROPOSED",
            "call_ref": "call-1",
            "data": {
                "function": sink["function"],
                "arguments": {"participants": ["person@example.com"]},
            },
        },
        {
            "event_id": "returned",
            "event_type": "TOOL_RUNTIME_RETURNED",
            "call_ref": "call-1",
            "data": {"result": None, "error": "rejected", "raised_exception_type": None},
        },
        {
            "event_id": "result",
            "event_type": "TOOL_RESULT",
            "call_ref": "call-1",
            "data": {"message": {"role": "tool", "content": "rejected"}},
        },
        {
            "event_id": "state",
            "event_type": "STATE_ORACLE_EVALUATED",
            "call_ref": "call-1",
            "data": {
                "oracle_id": slot["state_oracle"]["oracle_id"],
                "argument_executed": False,
                "state_confirmed": False,
                "state_change_confirmed": False,
            },
        },
    ]
    scoring = {
        "argument_executed": False,
        "state_confirmed": False,
        "state_change_confirmed": False,
    }

    records = runner.build_sink_records(events, slot, scoring)

    assert len(records) == 1
    assert records[0]["state_confirmed"] is False
    assert records[0]["state_change_confirmed"] is False
    assert records[0]["argument_executed"] is False
    assert records[0]["result_verified"] is True
    assert records[0]["state_verified"] is True


def test_one_offline_session_writes_auditable_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(
        runner,
        "_semantic_matcher",
        lambda: (None, "OfflineTransportScorerSkipped"),
    )
    manifest = runner.build_run_manifest("a" * 40, live=False)
    output = tmp_path / "single-session"
    (output / "runs").mkdir(parents=True)
    manifest_path = output / "manifest.json"
    runner._write_new(manifest_path, manifest)
    (output / "specs").mkdir()
    spec_path = output / "specs" / "spec.json"
    slot = manifest["protocol_manifest"]["slots"][0]
    runner._write_new(
        spec_path,
        {
            "manifest_path": "manifest.json",
            "manifest_sha256": runner._file_sha(manifest_path),
            "slot": slot,
        },
    )

    result = runner.run_trial(spec_path)

    run_path = output / "runs" / slot["run_id"]
    assert result["real_llm"] is False
    assert result["interpretation"] == "offline transport control only; not model evidence"
    assert set(result["acceptance"]) == {
        "request_capture",
        "source_binding",
        "execution_state",
        "scoring_and_cost",
    }
    assert runner._read_json(run_path / "acceptance.json")["request_counts"]["sdk"] <= 10
    assert runner._read_json(run_path / "summary.json")["run_id"] == slot["run_id"]
    assert (run_path / "source-bindings.json").is_file()
    assert (run_path / "sink-records.json").is_file()
    assert (run_path / "scoring-records.json").is_file()


def test_manifest_records_exact_commit_sources_prices_and_pinned_scorer(manifest):
    assert manifest["agent_tracer_commit"] == "a" * 40
    assert manifest["frozen_config_sha256"] == manifest["protocol_manifest"]["frozen_config_sha256"]
    assert set(manifest["source_hashes"]) == set(runner.RUNTIME_PATHS)
    assert manifest["runtime"]["request_attempt_ceiling"] == 320
    assert manifest["pricing_snapshots"]["groq"]["input_per_unit"] == "0.15"
    assert manifest["pricing_snapshots"]["deepseek"]["output_per_unit"] == "1.20"
    assert manifest["pricing_snapshots"]["groq"]["source_url"].startswith("https://console.groq.com/")
    assert manifest["pricing_snapshots"]["deepseek"]["source_url"].startswith(
        "https://api-docs.deepseek.com/"
    )
    assert manifest["semantic_scoring"] == {
        "model_path": runner.SEMANTIC_MODEL,
        "revision": runner.SEMANTIC_REVISION,
        "stages": ["tier3", "tier4"],
        "source_view": "fixture_declared_passage",
        "model_available_at_manifest_creation": (runner.ROOT / runner.SEMANTIC_MODEL).is_dir(),
        "identity_verified_and_loadable": False,
        "identity": None,
        "missing_model_policy": (
            "eligible pairs remain eligible with scored=false; acceptance fails rather than "
            "substituting native utility or another metric"
        ),
    }
