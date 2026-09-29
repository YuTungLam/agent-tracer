"""Native two-session memory controls; no model, gold labels, or borrowed run logs."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_lineage_memory.py"
SPEC = importlib.util.spec_from_file_location("validate_lineage_memory_fixture", SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def test_native_store_snapshot_restores_current_files_instead_of_stale_initial_files(tmp_path):
    run = fixture.run_session(
        tmp_path / "first", drive=fixture.initial_drive(), script=fixture.session_script()
    )
    assert run["failure"] is None
    assert run["summary"]["recording"]["audit"]["valid"] is True
    assert set(run["drive"].files) == {"1", "2"}
    assert [file.id_ for file in run["drive"].initial_files] == ["1"]
    memory = tmp_path / "native-memory.json"
    snapshot = fixture.save_native_memory(memory, run["drive"])
    restored = fixture.load_native_memory(memory)
    assert restored is not run["drive"]
    assert restored.files["2"] is not run["drive"].files["2"]
    assert restored.files["2"].content == fixture.CONTENT
    assert [restored.files[key].model_dump(mode="json") for key in sorted(restored.files)] == snapshot[
        "files"
    ]
    with pytest.raises(ValueError, match="namespace"):
        fixture.load_native_memory(memory, namespace="another-drive")


@pytest.fixture(scope="module")
def successful_sessions(tmp_path_factory):
    path = tmp_path_factory.mktemp("lineage-integration") / "paired-sessions"
    result = fixture.validate(path)
    assert result["passed"] is True, result["checks"]
    return path, result


def sink_from_artifact(path):
    rows = fixture.read_lines(path / "provenance.jsonl")
    return fixture.file_sink({"rows": rows})


def original_source_ids(path):
    first = sink_from_artifact(path / "session1-traced")
    return {source["source_id"] for source in first["visible_sources"] if source["kind"] == "tool"}


def inherited_originals(call, originals):
    return [
        source for source in call["lineage"]["recovered_sources"] if source["origin_source_id"] in originals
    ]


def test_actual_restored_memory_exposure_recovers_original_session_ancestry(successful_sessions):
    path, result = successful_sessions
    assert result["real_llm"] is False
    assert all(result["checks"].values())
    call = sink_from_artifact(path / "session2-traced")
    original_ids = original_source_ids(path)
    recovered = inherited_originals(call, original_ids)
    assert recovered and all(source["path_edge_ids"] for source in recovered)
    assert call["lineage"]["paths"]
    assert call["lineage"]["summary"]["maliciousness"] == "not_assessed"
    assert call["lineage"]["summary"]["causal_influence"] == "not_assessed"
    request_bodies = json.loads((path / "session2-traced" / "requests.json").read_text())
    assert all(message["role"] != "tool" for message in request_bodies[0]["messages"])
    assert any(
        message["role"] == "tool" and fixture.CONTENT in message["content"]
        for message in request_bodies[1]["messages"]
    )
    events = fixture.read_lines(path / "session2-traced" / "events.jsonl")
    exposed = [event for event in events if event["event_type"] == "TOOL_OUTPUT_EXPOSED"]
    assert any(event["model_request_id"] == call["model_request_id"] for event in exposed)
    assert not original_ids.intersection(source["source_id"] for source in call["visible_sources"])


def test_fixture_artifacts_declare_offline_scope_and_preserve_checkpoint_bytes(successful_sessions):
    path, result = successful_sessions
    assert set(result["timing_ns"]) == {
        "native_memory_save",
        "lineage_checkpoint_save",
        "lineage_checkpoint_load",
        "session2_baseline_native_memory_load",
        "session2_traced_native_memory_load",
    }
    assert all(type(value) is int and value >= 0 for value in result["timing_ns"].values())
    assert "One invocation" in result["timing_scope"]
    manifest = json.loads((path / "session2-traced" / "manifest.json").read_text())
    checkpoint = manifest["online_provenance"]["lineage"]["initial_state"]
    copied = path / "session2-traced" / checkpoint["path"]
    assert copied.read_bytes() == (path / "lineage-state.json").read_bytes()
    assert fixture.hashlib.sha256(copied.read_bytes()).hexdigest() == checkpoint["sha256"]
    for name in ("session1-baseline", "session1-traced", "session2-baseline", "session2-traced"):
        summary = json.loads((path / name / "summary.json").read_text())
        assert summary["real_llm"] is False
        assert summary["evaluable_task_count"] == 0 and summary["task_success_count"] is None
        assert summary["online_provenance"]["enabled"] is name.endswith("-traced")
        if name.endswith("-traced"):
            assert summary["online_provenance"]["active"] is False
            assert summary["online_provenance"]["closed"] is True
        report = (path / name / "report.html").read_text()
        assert "Deterministic native-tool engineering control" in report
        assert "native/fixture.json" in report
    assert manifest["online_provenance"]["implementation_sha256"]["lineage.py"]


@pytest.mark.parametrize("condition", ["no_state", "changed_content", "missing_memory", "different_file"])
def test_checkpoint_cannot_replace_real_memory_or_bind_a_different_file(
    successful_sessions, tmp_path, condition
):
    from agentdojo_lab.lineage import DCPG

    path, _ = successful_sessions
    policy = fixture.fixture_policy()
    core = (
        DCPG(namespace=fixture.NAMESPACE, policy=policy)
        if condition == "no_state"
        else DCPG.load_state(path / "lineage-state.json", namespace=fixture.NAMESPACE, policy=policy)
    )
    drive = fixture.load_native_memory(path / "native-memory.json")
    source_id = "2"
    if condition == "changed_content":
        drive.files["2"].content = "A replacement created outside this checkpoint."
        drive.files["2"].size = len(drive.files["2"].content)
    elif condition == "missing_memory":
        del drive.files["2"]
    elif condition == "different_file":
        clone = drive.files["2"].model_copy(deep=True)
        clone.id_ = "9"
        drive.files["9"] = clone
        source_id = "9"
    native_snapshot = tmp_path / "control-memory.json"
    fixture.save_native_memory(native_snapshot, drive)
    script = fixture.session_script(source_id=source_id)
    baseline = fixture.run_session(
        tmp_path / "baseline", drive=fixture.load_native_memory(native_snapshot), script=script
    )
    traced = fixture.run_session(
        tmp_path / "traced",
        drive=fixture.load_native_memory(native_snapshot),
        script=script,
        lineage=core,
        policy=policy,
        initial_state_path=None if condition == "no_state" else path / "lineage-state.json",
    )
    fixture.assert_native_equal(baseline, traced)
    assert traced["summary"]["online_provenance"]["complete"] is True
    call = fixture.file_sink(traced)
    assert not inherited_originals(call, original_source_ids(path))
    assert call["lineage"]["summary"]["recovered_source_count"] == 0
    if condition in {"no_state", "different_file", "changed_content"}:
        expected = "retrieval_content_mismatch" if condition == "changed_content" else "no_active_binding"
        assert expected in {item["status"] for item in call["lineage"]["memory_events"]}
    if condition == "missing_memory":
        returns = [event for event in traced["events"] if event["event_type"] == "TOOL_RUNTIME_RETURNED"]
        assert returns[0]["data"]["error"] is not None
    elif condition == "changed_content":
        assert any(
            message["role"] == "tool"
            and "A replacement created outside this checkpoint." in message["content"]
            for message in traced["requests"][1]["messages"]
        )


def test_failed_native_store_cannot_commit_persistent_lineage(tmp_path):
    from agentdojo_lab.lineage import DCPG

    policy = fixture.fixture_policy()
    core = DCPG(namespace=fixture.NAMESPACE, policy=policy)
    script = fixture.session_script(failed_write=True)
    baseline = fixture.run_session(tmp_path / "baseline", drive=fixture.initial_drive(), script=script)
    traced = fixture.run_session(
        tmp_path / "traced", drive=fixture.initial_drive(), script=script, lineage=core, policy=policy
    )
    fixture.assert_native_equal(baseline, traced)
    assert traced["failure"] is None
    returns = [event for event in traced["events"] if event["event_type"] == "TOOL_RUNTIME_RETURNED"]
    assert returns[1]["data"]["error"] is not None
    assert set(traced["drive"].files) == {"1"}
    assert core.snapshot()["memory_bindings"] == []
    assert fixture.file_sink(traced)["lineage"]["summary"]["maliciousness"] == "not_assessed"


def test_checkpoint_rejects_a_different_namespace_or_policy(successful_sessions):
    from agentdojo_lab.lineage import DCPG

    path, _ = successful_sessions
    policy = fixture.fixture_policy()
    with pytest.raises(ValueError):
        DCPG.load_state(path / "lineage-state.json", namespace="unrelated-drive", policy=policy)
    altered = policy.metadata["document"]
    altered["policy_id"] = "another-policy"
    with pytest.raises(ValueError):
        DCPG.load_state(
            path / "lineage-state.json",
            namespace=fixture.NAMESPACE,
            policy=fixture.ToolPolicy.from_dict(altered),
        )


def test_validation_refuses_existing_output_without_changing_sources(successful_sessions):
    path, _ = successful_sessions
    before = (path / "native-memory.json").read_bytes()
    with pytest.raises(FileExistsError):
        fixture.validate(path)
    assert (path / "native-memory.json").read_bytes() == before
