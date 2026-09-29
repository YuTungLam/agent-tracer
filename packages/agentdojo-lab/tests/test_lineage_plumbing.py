"""Integration contracts for opt-in lineage, replay, and presentation."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from test_cascade import Stages
from test_html_report import ReportParser
from test_lineage_integration import fixture
from test_semantic import FakeEncoder
from test_verify_online_run import verifier

from agentdojo_lab import runner
from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.html_report import collect_run_record
from agentdojo_lab.lineage import DCPG
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.provenance_report import _lineage_view, export_provenance
from agentdojo_lab.runner import RunConfig
from agentdojo_lab.semantic import SemanticMatcher


@pytest.fixture(scope="module")
def successful_sessions(tmp_path_factory):
    path = tmp_path_factory.mktemp("lineage-plumbing") / "sessions"
    result = fixture.validate(path)
    assert result["passed"]
    return path, result


def test_memory_threshold_profile_is_explicit_and_does_not_mutate_ordinary_matcher():
    original = SemanticMatcher(FakeEncoder())
    before = copy.deepcopy(original.metadata)
    memory = CascadeMatcher.for_memory(original)
    assert original.metadata == before
    assert original.semantic_threshold == 0.60
    assert memory.semantic_matcher.encoder is original.encoder
    assert memory.metadata["thresholds"]["tier3_cosine"] == 0.85
    assert memory.metadata["thresholds"]["tier4_cosine"] == 0.85
    assert memory.metadata["profile_selection"] == "restored_memory_lineage; no_evaluation_labels"
    assert CascadeMatcher(original).metadata["thresholds"]["tier3_cosine"] == 0.60


@pytest.mark.parametrize("score, matched", [(0.8499, False), (0.85, True)])
def test_memory_profile_uses_its_boundary_on_both_semantic_stages(score, matched):
    stages = Stages(tier3=score, tier4=score, coverage=0.10)
    stages.semantic_threshold = 0.85
    result = CascadeMatcher(stages, profile="memory").compare("AAAA", "ZZZZ")
    assert result["matched"] is matched
    assert result["stages"]["tier4"]["status"] == ("skipped" if matched else "scored")
    assert result["metadata"]["thresholds"]["tier4_coverage"] == 0.10


@pytest.mark.parametrize(
    "changes",
    [
        {"lineage_namespace": ""},
        {"lineage_namespace": "store", "provenance_policy": None},
        {"lineage_namespace": "store", "user_tasks": ["user_task_0", "user_task_1"]},
    ],
)
def test_lineage_run_requires_explicit_scope_and_one_native_task(changes):
    config = {"online_provenance": True, "provenance_policy": "configs/workspace_policy_v1.yaml", **changes}
    with pytest.raises(ValueError):
        RunConfig(**config)


def test_tracker_rejects_lineage_created_under_a_different_policy():
    original = fixture.fixture_policy()
    other_document = copy.deepcopy(original.metadata["document"])
    other_document["policy_id"] = "different-policy"
    other = ToolPolicy(other_document)
    core = DCPG(namespace=fixture.NAMESPACE, policy=original)
    with pytest.raises(ValueError, match="policy hashes must match"):
        ProvenanceTracker(policy=other, lineage=core)


def test_runner_does_not_save_lineage_when_observer_reports_incomplete(tmp_path, monkeypatch):
    original = runner.ObservationSession.status

    def incomplete(self):
        return {**original(self), "complete": False}

    monkeypatch.setattr(runner.ObservationSession, "status", incomplete)
    result = runner.run_clean(
        RunConfig(
            online_provenance=True,
            provenance_policy="configs/workspace_policy_v1.yaml",
            lineage_namespace="incomplete-observer",
        ),
        offline=True,
        output=tmp_path / "run",
    )
    assert result["status"] == "completed"
    assert result["recording"]["audit"]["valid"]
    assert not result["online_provenance"]["complete"]
    assert result["lineage_state"] == {"status": "not_saved", "reason": "recording_or_subscriber_incomplete"}
    assert not (tmp_path / "run" / "lineage-state.json").exists()


@pytest.mark.parametrize("session", ["session1-traced", "session2-traced"])
def test_lineage_verifier_replays_complete_checkpoint_and_calls(successful_sessions, session):
    root, _ = successful_sessions
    result = verifier.verify(root / session)
    assert result["passed"] and all(result["checks"].values())
    assert result["lineage_counts"]["restored_comparisons"] == (1 if session == "session2-traced" else 0)


def test_lineage_verifier_detects_a_checkpoint_changed_during_replay(
    successful_sessions, tmp_path, monkeypatch
):
    root, _ = successful_sessions
    run = tmp_path / "run"
    shutil.copytree(root / "session2-traced", run)
    state = run / "lineage-state.json"
    consume = verifier.ProvenanceTracker.consume
    changed = False

    def change_during_replay(self, event):
        nonlocal changed
        if not changed:
            state.write_bytes(state.read_bytes() + b" ")
            changed = True
        return consume(self, event)

    monkeypatch.setattr(verifier.ProvenanceTracker, "consume", change_during_replay)
    result = verifier.verify(run)
    assert result["checks"]["lineage_graph_equals_replay"]
    assert not result["checks"]["source_files_unchanged"]
    assert not result["passed"]


def test_lineage_verifier_rejects_a_tampered_final_graph(successful_sessions, tmp_path):
    root, _ = successful_sessions
    run = tmp_path / "run"
    shutil.copytree(root / "session2-traced", run)
    state = run / "lineage-state.json"
    value = json.loads(state.read_text())
    value["state"]["edges"] = []
    state.write_text(json.dumps(value))
    result = verifier.verify(run)
    assert not result["checks"]["lineage_graph_equals_replay"]
    assert not result["checks"]["lineage_checkpoint_digest_matches"]
    assert not result["passed"]


def test_lineage_timeline_links_never_resolve_reused_ids_from_a_prior_run(successful_sessions):
    root, _ = successful_sessions
    parser = ReportParser((root / "session2-traced" / "report.html").read_text())
    data = parser.record
    graph = data["lineage_state"]["state"]
    old = [n for n in graph["nodes"] if n["kind"] == "tool_step" and n["run_id"] == "session1-traced"]
    new = [n for n in graph["nodes"] if n["kind"] == "tool_step" and n["run_id"] == "session2-traced"]
    assert old and new
    event_ids = {e["event_id"] for e in data["events"]}
    assert any(n["proposal_event_id"] in event_ids for n in old)
    script = next(s["text"] for s in parser.scripts if s["attrs"].get("id") != "record")
    function = next(
        line for line in script.splitlines() if line.startswith("function lineageTimelineEventId(")
    )
    node = shutil.which("node") or "/opt/homebrew/bin/node"
    if not Path(node).is_file():
        pytest.skip("Node.js is unavailable for the pure event-link adapter check")
    program = (
        "const byId = new Map("
        + json.dumps(data["events"])
        + ".map(e=>[e.event_id,e]));\n"
        + function
        + "\nconsole.log(JSON.stringify("
        + json.dumps(old + new)
        + ".map(lineageTimelineEventId)));"
    )
    result = subprocess.run([node, "-e", program], text=True, capture_output=True, check=True)
    links = json.loads(result.stdout)
    assert links[: len(old)] == [None] * len(old)
    assert links[len(old) :] == [n["proposal_event_id"] for n in new]


def test_cross_session_replay_imports_only_declared_local_initial_checkpoint(successful_sessions, tmp_path):
    root, _ = successful_sessions
    source = root / "session2-traced"
    output = tmp_path / "replay"
    before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    report = export_provenance(
        run_dirs=[source], output=output, policy=fixture.fixture_policy(), lineage_namespace=fixture.NAMESPACE
    )
    assert report["lineage"]["restored_comparisons"] == 1
    analysis = json.loads((output / "analysis.json").read_text())
    rows = fixture.read_lines(source / "provenance.jsonl")
    live = [row["call"] for row in rows if row["record_type"] == "call_analysis"]
    replay = analysis["runs"][0]["calls"]
    for call in live + replay:
        call.pop("availability")
    assert live == replay
    assert {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()} == before
    assert "DCPG lineage and memory" in (output / "index.html").read_text()
    assert "memory_restore" in (output / "index.html").read_text()
    record = collect_run_record(source)
    assert record["lineage_state"]["state"] == analysis["runs"][0]["lineage_graph"]


def test_cross_session_replay_rejects_changed_initial_checkpoint(successful_sessions, tmp_path):
    import shutil

    root, _ = successful_sessions
    source = tmp_path / "source"
    shutil.copytree(root / "session2-traced", source)
    path = source / "lineage-initial-state.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed"):
        export_provenance(
            run_dirs=[source],
            output=tmp_path / "replay",
            policy=fixture.fixture_policy(),
            lineage_namespace=fixture.NAMESPACE,
        )


def test_lineage_path_view_never_interprets_tool_labels_as_markup():
    marker = '</summary><img src="bad" onerror="bad()">'
    graph = {
        "nodes": [
            {"node_id": "a", "kind": "tool_step", "function": marker},
            {"node_id": "b", "kind": "tool_step", "function": "store"},
        ],
        "edges": [
            {
                "edge_id": "e",
                "from_node": "a",
                "to_node": "b",
                "relation": "candidate_content",
                "evidence_score": 0.85,
                "tier": "tier3",
            }
        ],
    }
    call = {"lineage": {"paths": [{"label_id": "source", "edge_ids": ["e"], "path_confidence": None}]}}
    view = _lineage_view(call, graph)
    assert "<img" not in view and "&lt;img" in view


def test_lineage_checkpoint_outside_run_is_not_embedded(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    for name in ("manifest.json", "summary.json"):
        (run / name).write_text("{}")
    external = tmp_path / "external.json"
    external.write_text('{"private":"not part of this run"}')
    (run / "lineage-state.json").symlink_to(external)
    record = collect_run_record(run)
    assert "lineage_state" not in record
    assert "lineage-state.json" not in record["source_hashes"]
