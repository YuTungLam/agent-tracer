import hashlib
import json
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from agentdojo_lab import cli, html_report, runner
from agentdojo_lab.html_report import collect_run_record, export_run_html
from agentdojo_lab.runner import RunConfig, RunExecutionError, run_clean


class ReportParser(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.tags = []
        self.scripts = []
        self.active = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self.active = {"attrs": attrs, "text": ""}
            self.scripts.append(self.active)

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = None

    def handle_data(self, data):
        if self.active is not None:
            self.active["text"] += data

    @property
    def record(self):
        return json.loads(next(s["text"] for s in self.scripts if s["attrs"].get("id") == "record"))


def minimal_run(path, *, marker="example"):
    path.mkdir()
    (path / "manifest.json").write_text(
        json.dumps({"config": {"user_tasks": ["user_task_0"]}, "notes": [marker]})
    )
    (path / "summary.json").write_text(json.dumps({"status": "failed", "error": marker}))
    return path


def test_online_sidecar_is_embedded_inertly_and_preserved(tmp_path):
    run = minimal_run(tmp_path / "online")
    row = {"record_type": "call_analysis", "call": {"arguments": {"text": "</script><b>payload</b>"}}}
    path = run / "provenance.jsonl"
    path.write_text(json.dumps(row) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    export_run_html(run)
    parser = ReportParser((run / "report.html").read_text())
    assert parser.record["provenance"] == [row]
    assert parser.record["source_hashes"]["provenance.jsonl"] == digest
    assert len(parser.scripts) == 2
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_online_sidecar_outside_run_is_excluded(tmp_path):
    run = minimal_run(tmp_path / "online")
    external = tmp_path / "external.jsonl"
    external.write_text('{"value":"private"}\n')
    (run / "provenance.jsonl").symlink_to(external)
    record = collect_run_record(run)
    assert not record["provenance"]
    assert "provenance.jsonl" not in record["source_hashes"]
    assert any("provenance.jsonl resolves outside" in warning for warning in record["warnings"])


def test_online_causal_records_render_inert_interactive_evidence(tmp_path):
    run = minimal_run(tmp_path / "causal")
    summary = {
        "status": "completed",
        "online_causal_audit": {
            "enabled": True,
            "complete": True,
            "proposal_count": 1,
            "request_budget": 4,
            "request_count": 1,
            "request_remaining": 3,
            "valid_judgment_count": 1,
            "unknown_judgment_count": 0,
            "runtime_timing_count": 1,
            "before_runtime_verified_count": 1,
            "action_enforcement": "none",
            "model_weight_updates": "none",
            "timing": {"proposal_total_ns": 2_500_000},
        },
    }
    (run / "summary.json").write_text(json.dumps(summary))
    (run / "events.jsonl").write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {
                    "event_type": "TOOL_CALL_PROPOSED",
                    "event_id": "proposal-1",
                    "event_sequence": 1,
                    "run_id": "run-1",
                    "task_id": "user_task_0",
                    "episode_id": "episode-1",
                    "model_request_id": "request-1",
                    "call_ref": "call-1",
                    "data": {"function": "fixture_tool"},
                },
                {
                    "event_type": "TOOL_RUNTIME_STARTED",
                    "event_id": "runtime-1",
                    "event_sequence": 2,
                    "run_id": "run-1",
                    "task_id": "user_task_0",
                    "episode_id": "episode-1",
                    "model_request_id": "request-1",
                    "call_ref": "call-1",
                    "data": {"function": "fixture_tool"},
                },
            )
        )
    )
    causal_rows = [
        {
            "record_type": "causal_analysis",
            "proposal_event_id": "proposal-1",
            "call_ref": "call-1",
            "plan": {"status": "eligible", "probe_count": 1},
            "request_accounting": {"proposal_attempted": 1},
            "decision": {
                "function": "fixture_tool",
                "status": "predicted_control_positive",
                "detector_positive": True,
            },
            "results": [
                {
                    "kind": "single_source",
                    "source_ids": ["</script><b data-causal-probe='1'>source</b>"],
                    "status": "valid",
                    "judgment": {"would_call_anyway": False, "confidence": 0.75},
                    "elapsed_ns": 1_000_000,
                }
            ],
        },
        {
            "record_type": "causal_runtime_timing",
            "proposal_event_id": "proposal-1",
            "runtime_event_id": "runtime-1",
            "call_ref": "call-1",
            "receipt_before_runtime": True,
        },
    ]
    causal_path = run / "causal-online.jsonl"
    causal_path.write_text("\n".join(json.dumps(row) for row in causal_rows) + "\n")
    graph = {
        "added_nodes": [{"node_id": "source-set-1", "kind": "intervened_source_set"}],
        "added_edges": [
            {
                "edge_id": "prediction-1",
                "from_node": "source-set-1",
                "to_node": "sink-1",
                "relation": "predicted_control",
                "proposal_event_id": "proposal-1",
                "detector_positive": True,
            }
        ],
    }
    graph_path = run / "causal-online-graph.json"
    graph_path.write_text(json.dumps(graph))

    export_run_html(run)
    content = (run / "report.html").read_text()
    parser = ReportParser(content)
    assert parser.record["causal_online"] == causal_rows
    assert parser.record["causal_online_graph"] == graph
    assert parser.record["source_hashes"]["causal-online.jsonl"] == hashlib.sha256(
        causal_path.read_bytes()
    ).hexdigest()
    assert parser.record["source_hashes"]["causal-online-graph.json"] == hashlib.sha256(
        graph_path.read_bytes()
    ).hexdigest()
    assert "Online causal audit" in content
    assert "Locate proposal in timeline and diagram" in content
    assert "Typed derived-graph edges" in content
    assert not any("data-causal-probe" in attrs for _, attrs in parser.tags)
    assert len(parser.scripts) == 2
    node = shutil.which("node")
    if node is not None:
        script = next(s["text"] for s in parser.scripts if s["attrs"].get("type") != "application/json")
        checked = subprocess.run([node, "--check"], input=script, text=True, capture_output=True)
        assert checked.returncode == 0, checked.stderr


@pytest.fixture(scope="module")
def completed_run(tmp_path_factory):
    path = tmp_path_factory.mktemp("html-fixture") / "run"
    run_clean(RunConfig(), offline=True, output=path)
    return path


def test_runner_automatically_exports_full_offline_record(completed_run):
    parser = ReportParser((completed_run / "report.html").read_text())
    data = parser.record
    assert data["manifest"]["real_llm"] is False
    assert data["summary"]["tasks"][0]["utility"] is True
    assert len(data["events"]) == 15
    assert len(data["native"][0]["trace"]["messages"]) == 5
    assert data["audit"]["valid"] is True
    assert json.loads((completed_run / "html-report-status.json").read_text())["status"] == "generated"


def test_rebuilding_does_not_modify_experiment_sources(completed_run, tmp_path):
    sources = [
        p
        for p in completed_run.rglob("*")
        if p.is_file() and p.name not in {"report.html", "html-report-status.json"}
    ]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    result = export_run_html(completed_run, output=tmp_path / "copy.html")
    assert result["event_count"] == 15
    assert before == {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    payload = ReportParser((tmp_path / "copy.html").read_text()).record
    for name, digest in payload["source_hashes"].items():
        assert digest == hashlib.sha256((completed_run / name).read_bytes()).hexdigest()


def test_embedded_data_is_inert_and_known_credentials_redacted(tmp_path):
    marker = '</script><b data-probe="literal">text</b>&\u2028\u2029@@NONCE@@'
    run = minimal_run(tmp_path / "run", marker=marker + " fixture-secret-value")
    export_run_html(run, redactions=("fixture-secret-value",))
    text = (run / "report.html").read_text()
    parsed = ReportParser(text)
    assert len(parsed.scripts) == 2
    assert not any("data-probe" in attrs for _, attrs in parsed.tags)
    assert "fixture-secret-value" not in text
    assert parsed.record["summary"]["error"] == marker + " [REDACTED]"
    assert r"\u003c/script\u003e" in text
    nonces = {script["attrs"]["nonce"] for script in parsed.scripts}
    assert len(nonces) == 1
    assert all("src" not in attrs for tag, attrs in parsed.tags if tag == "script")
    assert "connect-src 'none'" in text


def test_old_run_keeps_native_history_without_inventing_events(tmp_path):
    run = minimal_run(tmp_path / "old")
    (run / "native").mkdir()
    native = {"user_task_id": "user_task_0", "messages": [{"role": "assistant", "content": "saved"}]}
    (run / "native" / "trace.json").write_text(json.dumps(native))
    payload = collect_run_record(run)
    assert payload["events"] == []
    assert payload["audit"] is None
    assert payload["native"][0]["trace"] == native
    assert payload["warnings"]


def test_partial_events_preserve_saved_data_and_report_gaps(tmp_path):
    run = minimal_run(tmp_path / "partial")
    event = {"event_type": "MODEL_REQUEST", "episode_id": "attempt-1", "task_id": "task-1", "data": {}}
    (run / "events.jsonl").write_text(json.dumps(event) + '\n{"truncated":')
    payload = collect_run_record(run)
    assert payload["events"] == [event]
    assert payload["audit"]["valid"] is False
    assert any("line 2" in warning for warning in payload["warnings"])


def test_same_provider_id_across_episodes_remains_separate(tmp_path):
    run = minimal_run(tmp_path / "multi")
    events = [
        {
            "event_type": "TOOL_CALL_PROPOSED",
            "task_id": f"task-{i}",
            "episode_id": f"attempt-{i}",
            "tool_call_id": "provider-reused-id",
            "call_ref": f"call-{i}",
            "data": {},
        }
        for i in (1, 2)
    ]
    (run / "events.jsonl").write_text("\n".join(json.dumps(event) for event in events))
    assert collect_run_record(run)["events"] == events


@pytest.mark.parametrize("agent_fails", [False, True])
def test_export_failure_preserves_original_agent_outcome(monkeypatch, tmp_path, agent_fails):
    def fail_export(*args, **kwargs):
        raise OSError("export fixture failure")

    monkeypatch.setattr(runner, "export_run_html", fail_export)
    if agent_fails:

        def fail_client(*args):
            raise RuntimeError("original client failure")

        monkeypatch.setattr(runner, "make_offline_client", fail_client)
    run = tmp_path / "run"
    if agent_fails:
        with pytest.raises(RunExecutionError) as error:
            run_clean(RunConfig(), offline=True, output=run)
        assert str(error.value.__cause__) == "original client failure"
    else:
        assert run_clean(RunConfig(), offline=True, output=run)["task_success_count"] == 1
    saved = json.loads((run / "summary.json").read_text())
    assert saved["status"] == ("failed" if agent_fails else "completed")
    assert json.loads((run / "html-report-status.json").read_text()) == {
        "status": "failed",
        "error_type": "OSError",
    }


def test_atomic_export_keeps_previous_report_on_failure(monkeypatch, tmp_path):
    run = minimal_run(tmp_path / "run")
    (run / "report.html").write_text("previous report")
    monkeypatch.setattr(html_report.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("fixture")))
    with pytest.raises(OSError):
        export_run_html(run)
    assert (run / "report.html").read_text() == "previous report"
    assert not list(run.glob(".report-*.tmp"))


def test_sources_outside_run_are_not_embedded(tmp_path):
    run = minimal_run(tmp_path / "run")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"unrelated": "external-fixture-value"}))
    (run / "native").mkdir()
    (run / "native" / "trace.json").symlink_to(outside)
    data = collect_run_record(run)
    assert data["native"] == []
    assert data["warnings"]
    assert "external-fixture-value" not in json.dumps(data)


def test_html_cli_exports_from_existing_run_without_llm(monkeypatch, completed_run, tmp_path, capsys):
    monkeypatch.setattr(runner, "configured_key", lambda: pytest.fail("HTML must not load credentials"))
    assert cli.main(["html", "--run", str(completed_run), "--output", str(tmp_path / "cli.html")]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "generated"


def test_viewer_script_syntax(completed_run):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional; needed only to check viewer JavaScript syntax")
    parser = ReportParser((completed_run / "report.html").read_text())
    script = next(s["text"] for s in parser.scripts if s["attrs"].get("type") != "application/json")
    checked = subprocess.run([node, "--check"], input=script, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr


def test_bad_report_status_does_not_turn_cli_success_into_failure(monkeypatch, tmp_path, capsys):
    (tmp_path / "html-report-status.json").write_text('{"unfinished":')
    monkeypatch.setattr(
        cli,
        "run_clean",
        lambda *args, **kwargs: {
            "status": "completed",
            "run_dir": str(tmp_path),
            "task_count": 1,
            "task_success_count": 1,
        },
    )
    assert cli.main(["smoke", "--offline"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["task_success_count"] == 1
    assert printed["html_report"]["status"] == "unavailable"


def test_viewer_pure_helpers_accept_damaged_event_fields(completed_run):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional for the JavaScript helper checks")
    parsed = ReportParser((completed_run / "report.html").read_text())
    script = next(s["text"] for s in parsed.scripts if s["attrs"].get("type") != "application/json")
    helpers = script.split("const taskIds=")[0]
    checks = """
const assert = require('node:assert/strict');
assert.deepEqual(asArray({}), []);
assert.equal(category({event_type: 7}), 'run');
assert.equal(eventLabel({event_type: 7}), 'Unknown event');
assert.equal(eventLabel({event_type: '__proto__'}), '__proto__');
assert.equal(eventLabel({event_type: 'MODEL_ERROR'}), 'Model call error');
"""
    # Only pure helper expressions execute; no browser or DOM traversal is used.
    prelude = 'const document={getElementById:()=>({textContent:"{}"})};\n'
    result = subprocess.run([node], input=prelude + helpers + checks, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
