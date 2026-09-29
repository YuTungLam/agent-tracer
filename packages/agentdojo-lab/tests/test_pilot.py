import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from agentdojo_lab import cli, pilot
from agentdojo_lab.pilot import atomic_json, create_plan, execute_trial, read_plan, run_pilot
from agentdojo_lab.pilot_report import collect_pilot, event_metrics, export_pilot_report
from agentdojo_lab.runner import ROOT, RunConfig, run_clean


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "pilot.toml"
    path.write_text("""
[pilot]
repetitions = 2
interval_seconds = 0
[run]
user_tasks = ["user_task_0", "user_task_7"]
[[tasks]]
id = "user_task_0"
label = "Calendar query"
area = "Calendar"
expected_tools = ["search_calendar_events"]
rationale = "Read-only control"
[[tasks]]
id = "user_task_7"
label = "Reschedule"
area = "Calendar"
expected_tools = ["search_calendar_events", "reschedule_calendar_event"]
rationale = "ID reuse"
""")
    return path


def finish_fixture(command, job, timeout, progress):
    """Synthetic records test aggregation; this fixture never calls a model."""
    output = Path(command[command.index("--output") + 1])
    config = RunConfig.model_validate(tomllib.loads(Path(command[command.index("--config") + 1]).read_text()))
    task_id = command[command.index("--task") + 1]
    config.user_tasks = [task_id]
    output.mkdir()
    atomic_json(
        output / "manifest.json",
        {
            "real_llm": True,
            "mode": "live-groq",
            "attack": None,
            "defense": None,
            "config": config.model_dump(),
        },
    )
    failed = task_id == "user_task_0"
    atomic_json(
        output / "summary.json",
        {
            "real_llm": True,
            "mode": "live-groq",
            "status": "completed_with_issues" if failed else "completed",
            "tasks": [{"task": task_id, "status": "error" if failed else "evaluated", "utility": not failed}],
            "usage": {"request_count": 1, "prompt_tokens": 20, "completion_tokens": 4},
            "recording": {"complete": False},
        },
    )
    return {"status": "finished", "exit_code": 2 if failed else 0, "wall_seconds": 0.1}


def test_frozen_plan_has_native_prompts_and_repeat_major_order(config, tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "configured_key", lambda: pytest.fail("plan must not read credentials"))
    result = run_pilot(config_path=config, output=tmp_path / "batch", plan_only=True)
    plan = read_plan(Path(result["batch_dir"]))
    assert [item["id"] for item in plan["schedule"]] == [
        "r01-user_task_0",
        "r01-user_task_7",
        "r02-user_task_0",
        "r02-user_task_7",
    ]
    assert "Networking" in plan["tasks"][0]["prompt"]
    assert result["started_trials"] == 0 and result["pending_trials"] == 4
    assert "src/agentdojo_lab/pilot.py" in plan["source_hashes"]


def test_resume_executes_only_unstarted_slots_and_preserves_errors(config, tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(pilot, "configured_key", lambda: "fixture-key")

    def execute(*args):
        commands.append(args[0])
        return finish_fixture(*args)

    monkeypatch.setattr(pilot, "execute_trial", execute)
    batch = tmp_path / "batch"
    first = run_pilot(config_path=config, output=batch, progress=lambda _: None)
    assert len(commands) == 2
    assert first["evaluated_trials"] == 1 and first["passed_trials"] == 1
    assert first["pending_trials"] == 2
    assert len(collect_pilot(batch)["rows"]) == 4
    assert collect_pilot(batch)["rows"][0]["utility"] is None
    run_pilot(resume=batch, progress=lambda _: None)
    assert len(commands) == 2
    final = run_pilot(resume=batch, through_repeat=2, progress=lambda _: None)
    assert len(commands) == 4
    assert final["distinct_started_tasks"] == 2 and final["started_trials"] == 4
    assert final["evaluated_trials"] == 2


def test_plan_and_implementation_drift_prevent_execution(config, tmp_path, monkeypatch):
    batch = create_plan(config, tmp_path / "batch")
    monkeypatch.setattr(pilot, "configured_key", lambda: "fixture-key")
    monkeypatch.setattr(pilot, "source_hashes", lambda: {"different": "hash"})
    with pytest.raises(ValueError, match="Code or dependency lock changed"):
        run_pilot(resume=batch)
    (batch / "run-config.toml").write_text("changed")
    with pytest.raises(ValueError, match="Frozen pilot file changed"):
        read_plan(batch)


def test_unknown_expected_tools_fail_before_output_creation(config, tmp_path):
    config.write_text(config.read_text().replace("reschedule_calendar_event", "unknown_tool"))
    with pytest.raises(ValueError, match="Unknown native task or expected tool"):
        create_plan(config, tmp_path / "batch")
    assert not (tmp_path / "batch").exists()


def test_active_previous_child_prevents_resume(config, tmp_path, monkeypatch):
    batch = create_plan(config, tmp_path / "batch")
    job = batch / "jobs/r01-user_task_0"
    job.mkdir()
    atomic_json(job / "process.json", {"pid": os.getpid()})
    monkeypatch.setattr(pilot, "configured_key", lambda: "fixture-key")
    with pytest.raises(ValueError, match="may still be active"):
        run_pilot(resume=batch)


def test_hard_timeout_terminates_child_and_keeps_logs(tmp_path):
    output = execute_trial(
        [sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, 0.05, lambda _: None
    )
    assert output["status"] == "timeout" and output["exit_code"] != 0
    pid = json.loads((tmp_path / "process.json").read_text())["pid"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert (tmp_path / "console.log").is_file()


def test_metadata_failure_after_spawn_reaps_child(tmp_path, monkeypatch):
    processes = []
    real_popen = subprocess.Popen

    def capture(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(pilot.subprocess, "Popen", capture)
    monkeypatch.setattr(pilot, "atomic_json", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        execute_trial([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, 2, lambda _: None)
    assert processes[0].poll() is not None


def test_batch_lock_prevents_concurrent_writers(config, tmp_path):
    batch = create_plan(config, tmp_path / "batch")
    with pilot.batch_lock(batch):
        with pytest.raises(ValueError, match="already running"):
            with pilot.batch_lock(batch):
                pass


def test_bad_trial_records_do_not_drop_slots_or_modify_raw_data(config, tmp_path):
    batch = create_plan(config, tmp_path / "batch")
    run = batch / "runs/r01-user_task_0"
    run.mkdir()
    (batch / "jobs/r01-user_task_0").mkdir()
    atomic_json(run / "summary.json", {"tasks": None, "recording": [], "usage": None})
    (run / "events.jsonl").write_bytes(b"not json\n\xff")
    before = {path: path.read_bytes() for path in run.iterdir()}
    report = export_pilot_report(batch)
    row = report["rows"][0]
    assert row["audit_valid"] is False and row["utility"] is None
    assert row["read_errors"] and row["event_read_errors"]
    assert row["proposal_requests_with_prior_tool_messages"] is None
    assert report["totals"]["pending_trials"] == 3
    assert before == {path: path.read_bytes() for path in run.iterdir()}


def test_fixture_trace_counts_are_structural_and_offline_not_live(config, tmp_path):
    batch = create_plan(config, tmp_path / "batch")
    run = batch / "runs/r01-user_task_0"
    (batch / "jobs/r01-user_task_0").mkdir()
    run_clean(RunConfig(), offline=True, output=run)
    metrics = event_metrics(run)
    assert metrics["audit_valid"] is True
    assert metrics["tools"] == ["search_calendar_events"]
    assert metrics["requests_with_tool_messages"] == 1
    assert metrics["proposal_requests_with_prior_tool_messages"] == 0
    report = export_pilot_report(batch)
    assert report["rows"][0]["status"] == "ineligible"
    assert report["totals"]["evaluated_trials"] == 0
    assert report["totals"]["observed_tools"] == []
    assert report["totals"]["complete_recordings"] == 0


def test_export_has_safe_embedded_data_and_valid_javascript(config, tmp_path):
    config.write_text(config.read_text().replace("Calendar query", "</script><b>probe</b>"))
    batch = create_plan(config, tmp_path / "batch")
    export_pilot_report(batch)
    html = (batch / "index.html").read_text()
    assert "</script><b>probe</b>" not in html
    assert "@@RECORD@@" not in html
    assert "connect-src 'none'" in html
    script = re.search(r'<script nonce="[^"]+">(.*?)</script>', html, re.S).group(1)
    assert "innerHTML" not in script
    node = shutil.which("node")
    if node:
        result = subprocess.run([node, "--check"], input=script, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_cli_pilot_plan_is_offline_and_keeps_schedule(tmp_path, capsys):
    code = cli.main(
        [
            "pilot",
            "--config",
            str(ROOT / "configs/pilot_clean.toml"),
            "--output",
            str(tmp_path / "batch"),
            "--plan-only",
        ]
    )
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["planned_trials"] == 30 and result["distinct_planned_tasks"] == 10


def test_index_filters_actual_rows_and_keeps_pending_slots(config, tmp_path, monkeypatch):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional for viewer unit checks")
    monkeypatch.setattr(pilot, "configured_key", lambda: "fixture-key")
    monkeypatch.setattr(pilot, "execute_trial", finish_fixture)
    batch = tmp_path / "batch"
    run_pilot(config_path=config, output=batch, progress=lambda _: None)
    html = (batch / "index.html").read_text()
    record = re.search(r'<script type="application/json"[^>]*>(.*?)</script>', html, re.S).group(1)
    script = re.search(r'<script nonce="[^"]+">(.*?)</script>', html, re.S).group(1)
    adapters = """
const assert=require('node:assert/strict');
class Element {
  constructor(){this.childNodes=[];this.value='';this.listeners={};}
  append(...nodes){this.childNodes.push(...nodes);}
  replaceChildren(...nodes){this.childNodes=nodes;}
  addEventListener(name,fn){this.listeners[name]=fn;}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const document={getElementById:get,createElement:()=>new Element()};
"""
    checks = """
assert.equal(get('trials').childNodes.length,4);
get('filter').value='passed';get('filter').listeners.change();
assert.equal(get('count').textContent,'1 / 4');
get('filter').value='pending';get('filter').listeners.change();
assert.equal(get('count').textContent,'2 / 4');
get('filter').value='';get('search').value='user_task_0';get('search').listeners.input();
assert.equal(get('count').textContent,'2 / 4');
assert.equal(reportLink({report:'https://external.invalid'},'test').href,undefined);
assert.equal(reportLink({report:'runs/r01-user_task_0/report.html'},'test').href,'runs/r01-user_task_0/report.html');
"""
    result = subprocess.run(
        [node],
        input=adapters + f"get('record').textContent={json.dumps(record)};\n" + script + checks,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
