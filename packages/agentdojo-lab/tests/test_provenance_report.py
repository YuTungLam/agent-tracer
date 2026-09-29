"""Export contracts using temporary offline fixtures, without real run data."""

import hashlib
import json
import shutil
from html.parser import HTMLParser

import pytest

from agentdojo_lab.provenance_report import export_provenance
from agentdojo_lab.runner import RunConfig, run_clean


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def read_events(run):
    return [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]


def write_events(run, events):
    (run / "events.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events)
    )


def file_hashes(root):
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def keys_recursively(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from keys_recursively(child)
    elif isinstance(value, list):
        for child in value:
            yield from keys_recursively(child)


@pytest.fixture
def source_run(tmp_path):
    run = tmp_path / "offline-source"
    result = run_clean(RunConfig(), offline=True, output=run)
    assert result["recording"]["complete"] is True
    assert result["real_llm"] is False
    return run


def make_batch(tmp_path, source_run):
    """The selector needs only this hash-checked schedule, not a running pilot."""
    batch = tmp_path / "frozen-batch"
    (batch / "runs").mkdir(parents=True)
    completed = "r01-user_task_0"
    pending = "r02-user_task_0"
    shutil.copytree(source_run, batch / "runs" / completed)
    plan = {
        "schema_version": 1,
        "schedule": [
            {"id": completed, "task_id": "user_task_0", "repeat": 1},
            {"id": pending, "task_id": "user_task_0", "repeat": 2},
        ],
    }
    write_json(batch / "plan.json", plan)
    (batch / "plan.sha256").write_text(hashlib.sha256((batch / "plan.json").read_bytes()).hexdigest() + "\n")
    return batch, completed, pending


def test_export_preserves_source_bytes_hashes_and_does_not_claim_accuracy(source_run, tmp_path):
    before = file_hashes(source_run)
    output = tmp_path / "analysis"
    result = export_provenance(run_dirs=[source_run], output=output)
    analysis = read_json(output / "analysis.json")
    assert file_hashes(source_run) == before
    assert result["analyzed_runs"] == 1
    assert analysis["mode"] == "offline_prefix_replay"
    assert analysis["real_llm_calls_added"] == 0
    assert analysis["runs"][0]["mode"] == "offline-fixture"
    assert analysis["runs"][0]["real_llm"] is False
    assert analysis["runs"][0]["source_hashes"] == {
        name: before[name] for name in ("events.jsonl", "manifest.json", "summary.json")
    }
    assert analysis["counts"]["human_reviewed_fields"] == 0
    assert analysis["counts"]["accuracy"] is None
    assert analysis["counts"]["causal_or_malicious_verdicts"] == 0
    assert (output / "index.html").is_file()
    assert (output / "candidates.jsonl").is_file()
    assert (output / "annotations" / "instructions.md").is_file()


@pytest.mark.parametrize("placement", ["existing", "inside_source", "source_itself"])
def test_export_rejects_overwrite_and_writes_inside_source(source_run, tmp_path, placement):
    if placement == "existing":
        output = tmp_path / "existing-analysis"
        output.mkdir()
        (output / "keep.txt").write_text("Keep the earlier artifact.")
    elif placement == "inside_source":
        output = source_run / "new-analysis"
    else:
        output = source_run
    before = file_hashes(tmp_path)
    with pytest.raises(ValueError, match="new output directory"):
        export_provenance(run_dirs=[source_run], output=output)
    assert file_hashes(tmp_path) == before


def test_output_symlink_into_source_is_rejected(source_run, tmp_path):
    alias = tmp_path / "source-alias"
    alias.symlink_to(source_run, target_is_directory=True)
    with pytest.raises(ValueError, match="new output directory"):
        export_provenance(run_dirs=[source_run], output=alias / "analysis")
    assert not (source_run / "analysis").exists()


@pytest.mark.parametrize("damage", ["sequence_gap", "truncated_json"])
def test_bad_event_audit_rejects_export_before_creating_output(source_run, tmp_path, damage):
    if damage == "sequence_gap":
        events = read_events(source_run)
        events[1]["event_sequence"] += 1
        write_events(source_run, events)
    else:
        with (source_run / "events.jsonl").open("a") as stream:
            stream.write('{"unfinished":')
    before = file_hashes(source_run)
    output = tmp_path / "rejected-analysis"
    with pytest.raises(ValueError, match="audit"):
        export_provenance(run_dirs=[source_run], output=output)
    assert not output.exists()
    assert file_hashes(source_run) == before


def test_incomplete_recording_is_rejected_even_when_saved_events_are_valid(source_run, tmp_path):
    summary = read_json(source_run / "summary.json")
    summary["recording"]["complete"] = False
    write_json(source_run / "summary.json", summary)
    with pytest.raises(ValueError, match="incomplete"):
        export_provenance(run_dirs=[source_run], output=tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_source_file_symlink_outside_run_is_rejected(source_run, tmp_path):
    event_path = source_run / "events.jsonl"
    outside = tmp_path / "external-events.jsonl"
    outside.write_bytes(event_path.read_bytes())
    event_path.unlink()
    event_path.symlink_to(outside)
    with pytest.raises(ValueError, match="local recording files"):
        export_provenance(run_dirs=[source_run], output=tmp_path / "rejected")


def test_annotation_package_is_blank_and_contains_neither_predictions_nor_future_outcomes(
    source_run, tmp_path
):
    events = read_events(source_run)
    final_response = [event for event in events if event["event_type"] == "MODEL_RESPONSE"][-1]
    final_response["data"]["body"] = {"fixture_future_text": "FUTURE_ONLY_942"}
    write_events(source_run, events)
    summary = read_json(source_run / "summary.json")
    summary["evaluation_fixture_note"] = "EVALUATOR_ONLY_715"
    summary["tasks"][0]["evaluation_fixture_note"] = "EVALUATOR_ONLY_715"
    write_json(source_run / "summary.json", summary)
    output = tmp_path / "analysis"
    export_provenance(run_dirs=[source_run], output=output)
    text = (output / "annotations" / "items.jsonl").read_text()
    items = [json.loads(line) for line in text.splitlines()]
    assert items
    assert "FUTURE_ONLY_942" not in text
    assert "EVALUATOR_ONLY_715" not in text
    forbidden = {
        "exact_candidates",
        "exact_status",
        "nt_style_lcs",
        "score",
        "matched",
        "utility",
        "accuracy",
    }
    assert forbidden.isdisjoint(keys_recursively(items))
    by_id = {event["event_id"]: event for event in events}
    for item in items:
        proposal = by_id[item["proposal_event_id"]]
        request = by_id[item["request_event_id"]]
        assert item["cutoff_event_id"] == proposal["event_id"]
        assert request["event_sequence"] < proposal["event_sequence"] < final_response["event_sequence"]
        assert item["request_messages"] == request["data"]["body"]["messages"]
        assert item["review"] == {
            "status": "unreviewed",
            "reviewer": None,
            "source_judgment": None,
            "evidence": [],
            "authorization": None,
            "notes": "",
        }
        assert all(
            by_id[source["source_event_id"]]["event_sequence"] <= request["event_sequence"]
            for source in item["visible_sources"]
        )
    predictions = (output / "candidates.jsonl").read_text()
    assert "exact_candidates" in predictions and "nt_style_lcs" in predictions


class PageStructure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data):
        self.text.append(data)


def test_html_renders_source_target_and_function_as_escaped_text(source_run, tmp_path):
    marker = '<fixture-tag title="demo">A & B</fixture-tag>'
    events = read_events(source_run)
    proposal = next(event for event in events if event["event_type"] == "TOOL_CALL_PROPOSED")
    request = next(
        event
        for event in events
        if event["event_type"] == "MODEL_REQUEST"
        and event["model_request_id"] == proposal["model_request_id"]
    )
    next(message for message in request["data"]["body"]["messages"] if message["role"] == "user")[
        "content"
    ] = marker
    proposal["data"]["arguments"] = {"query": marker}
    proposal["data"]["function"] = marker
    write_events(source_run, events)
    output = tmp_path / "analysis"
    export_provenance(run_dirs=[source_run], output=output)
    html = (output / "index.html").read_text()
    assert marker not in html
    assert "&lt;fixture-tag" in html and "A &amp; B" in html
    page = PageStructure()
    page.feed(html)
    assert "fixture-tag" not in page.tags
    assert "script" not in page.tags
    assert marker in "".join(page.text)
    assert ("http-equiv", "Content-Security-Policy") in page.attributes
    assert not any(key.startswith("on") for key, _ in page.attributes)


def test_pending_batch_slots_are_inventory_not_analysis_samples(source_run, tmp_path):
    batch, completed, pending = make_batch(tmp_path, source_run)
    before = file_hashes(batch)
    output = tmp_path / "analysis"
    result = export_provenance(batch=batch, output=output)
    analysis = read_json(output / "analysis.json")
    assert result["analyzed_runs"] == 1
    assert analysis["batch"]["planned_trials"] == 2
    assert analysis["batch"]["not_started"] == [pending]
    assert len(analysis["runs"]) == 1
    assert analysis["runs"][0]["run_dir"] == str(batch / "runs" / completed)
    assert file_hashes(batch) == before


@pytest.mark.parametrize("folder", ["runs", "jobs"])
@pytest.mark.parametrize("selection", ["batch", "run"])
def test_export_cannot_create_a_directory_for_a_pending_source_batch_slot(
    source_run, tmp_path, folder, selection
):
    batch, completed, pending = make_batch(tmp_path, source_run)
    output = batch / folder / pending
    before = file_hashes(batch)
    selected = {"batch": batch} if selection == "batch" else {"run_dirs": [batch / "runs" / completed]}
    with pytest.raises(ValueError):
        export_provenance(**selected, output=output)
    assert not output.exists()
    assert file_hashes(batch) == before


def test_started_batch_trial_without_run_is_not_treated_as_pending(source_run, tmp_path):
    batch, _, pending = make_batch(tmp_path, source_run)
    job = batch / "jobs" / pending
    job.mkdir(parents=True)
    write_json(job / "started.json", {"id": pending})
    with pytest.raises(ValueError, match="Started trial"):
        export_provenance(batch=batch, output=tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_batch_with_changed_plan_hash_is_rejected(source_run, tmp_path):
    batch, _, _ = make_batch(tmp_path, source_run)
    plan = read_json(batch / "plan.json")
    plan["schedule"].reverse()
    write_json(batch / "plan.json", plan)
    with pytest.raises(ValueError, match="hash mismatch"):
        export_provenance(batch=batch, output=tmp_path / "rejected")


def test_duplicate_run_paths_are_rejected(source_run, tmp_path):
    with pytest.raises(ValueError, match="Duplicate run paths"):
        export_provenance(run_dirs=[source_run, source_run], output=tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_distinct_paths_with_same_run_identity_are_rejected(source_run, tmp_path):
    duplicate = tmp_path / "copied-source"
    shutil.copytree(source_run, duplicate)
    with pytest.raises(ValueError, match="Duplicate run IDs"):
        export_provenance(run_dirs=[source_run, duplicate], output=tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()
