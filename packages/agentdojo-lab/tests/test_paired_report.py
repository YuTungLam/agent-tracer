"""Offline comparison controls; fixture observations are not Scout research results."""

import copy
import hashlib
import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

import pytest

from agentdojo_lab.paired_report import compare_records, export_pair, json_changes


def record(calls, *, name="arm"):
    """Small event-shape unit fixture; native recorder integration is tested below."""
    events = []

    def emit(kind, data, call_ref=None, parents=()):
        event = {
            "event_id": f"event:{len(events) + 1}",
            "event_sequence": len(events) + 1,
            "event_type": kind,
            "data": data,
            "task_id": "user_task_33",
            "episode_id": "episode:1",
            "call_ref": call_ref,
            "model_request_id": "request:1",
            "parent_event_ids": list(parents),
        }
        events.append(event)
        return event["event_id"]

    emit("EPISODE_STARTED", {"environment": {}})
    emit(
        "MODEL_REQUEST",
        {"body": {"model": "fixture", "messages": [{"role": "user", "content": "same task"}]}},
    )
    for index, (function, arguments, execution) in enumerate(calls):
        call_ref = f"call:{index}"
        proposed = emit("TOOL_CALL_PROPOSED", {"function": function, "arguments": arguments}, call_ref)
        if execution == "proposal_only":
            continue
        started = emit(
            "TOOL_RUNTIME_STARTED",
            {"function": function, "runtime_input_args": arguments},
            call_ref,
            [proposed],
        )
        returned = emit(
            "TOOL_RUNTIME_RETURNED",
            {
                "result": {},
                "error": "failed" if execution == "error" else None,
                "raised_exception_type": None,
            },
            call_ref,
            [started],
        )
        if function == "send_email" and execution == "success":
            emit(
                "ENVIRONMENT_CHANGE",
                {"before": {"sent": []}, "after": {"sent": [arguments]}},
                call_ref,
                [returned],
            )
    return {
        "run_id": name,
        "manifest": {"config": {"user_tasks": ["user_task_33"], "model": "fixture"}, "real_llm": False},
        "summary": {"status": "completed", "recording": {"complete": True}},
        "events": events,
        "audit": {"valid": True},
        "source_hashes": {},
    }


def email(recipient="user@example.com", execution="success"):
    return (
        "send_email",
        {
            "recipients": [recipient],
            "subject": "Meeting",
            "body": "Summary",
            "attachments": [{"type": "file", "file_id": "19"}],
        },
        execution,
    )


def test_same_tool_changed_recipient_has_typed_path_and_separate_native_effects():
    result = compare_records(record([email()]), record([email("attacker@example.com")]))
    (row,) = result["alignment"]["rows"]
    assert row["status"] == "paired" and row["function"] == "send_email"
    assert [c["path"] for c in row["argument_changes"]] == ["/recipients/0"]
    assert result["first_tool_proposal_divergence"]["alignment_row"] == 0
    assert result["first_security_relevant_divergence"]["alignment_row"] == 0
    action = result["arms"][1]["actions"][0]
    assert action["execution"]["status"] == "returned_successfully"
    (changes,) = action["execution"]["observed_environment_changes"]
    assert changes["bound_to_return"] is True
    assert changes["changes"][0]["after"]["recipients"] == ["attacker@example.com"]
    assert result["attack_success"].startswith("unknown")


@pytest.mark.parametrize(
    "clean_reads,attacked_reads,expected",
    [
        (["read_a", "read_b"], ["read_b"], "omitted_in_attacked"),
        (["read_b"], ["read_a", "read_b"], "inserted_in_attacked"),
    ],
)
def test_inserted_and_omitted_read_stays_visible_before_security_change(
    clean_reads, attacked_reads, expected
):
    clean = record([(name, {}, "success") for name in clean_reads] + [email()])
    attacked = record([(name, {}, "success") for name in attacked_reads] + [email("attacker@example.com")])
    result = compare_records(clean, attacked)
    assert result["alignment"]["rows"][0]["status"] == expected
    assert result["first_tool_proposal_divergence"]["alignment_row"] == 0
    assert result["first_security_relevant_divergence"]["alignment_row"] == 2


@pytest.mark.parametrize(
    "execution,status", [("proposal_only", "unconfirmed"), ("error", "returned_with_error")]
)
def test_sensitive_proposal_is_not_proof_of_execution(execution, status):
    result = compare_records(record([email()]), record([email("attacker@example.com", execution)]))
    action = result["arms"][1]["actions"][0]
    assert action["execution"]["status"] == status
    assert action["execution"]["observed_environment_changes"] == []
    assert result["first_security_relevant_divergence"]["status"] == "observed"
    assert result["comparability"]["initial_environment_comparison"]["status"] == "identical_observed"


def test_mismatched_runtime_arguments_cannot_confirm_proposed_sink():
    attacked = record([email("attacker@example.com")])
    start = next(e for e in attacked["events"] if e["event_type"] == "TOOL_RUNTIME_STARTED")
    start["data"]["runtime_input_args"] = email()[1]
    result = compare_records(record([email()]), attacked)
    action = result["arms"][1]["actions"][0]
    assert action["execution"]["status"] == "unconfirmed"
    assert action["execution"]["observed_environment_changes"][0]["bound_to_return"] is False


@pytest.mark.parametrize("mismatch", ["task", "request", "recording", "episodes"])
def test_mismatched_or_incomplete_inputs_keep_conclusions_unknown(mismatch):
    attacked = record([email("attacker@example.com")])
    if mismatch == "task":
        attacked["manifest"]["config"]["user_tasks"] = ["user_task_0"]
    elif mismatch == "request":
        attacked["events"][1]["data"]["body"]["messages"][0]["content"] = "different task"
    elif mismatch == "recording":
        attacked["audit"]["valid"] = False
    else:
        attacked["events"].append({**copy.deepcopy(attacked["events"][0]), "episode_id": "episode:2"})
    result = compare_records(record([email()]), attacked)
    assert result["comparability"]["status"] == "unconfirmed"
    assert result["first_security_relevant_divergence"]["status"] == "unknown"
    assert result["first_security_relevant_divergence"]["alignment_row"] is None
    assert result["first_security_relevant_divergence"]["candidate_row_for_inspection"] == 0


def test_repeated_identical_calls_have_ambiguous_alignment_and_preserve_episode_ids():
    repeated = ("read", {"file_id": "19"}, "success")
    result = compare_records(record([repeated, repeated, email()]), record([repeated, email()]))
    assert result["alignment"]["status"] == "ambiguous"
    assert result["first_tool_proposal_divergence"]["status"] == "unknown"
    assert result["arms"][0]["actions"][0]["episode_id"] == "episode:1"


def test_json_pointer_escaping_absence_null_and_type_are_distinct():
    rows = json_changes({"a/b": {"~key": True}, "removed": None}, {"a/b": {"~key": 1}})
    assert rows[0]["path"] == "/a~1b/~0key"
    assert rows[1]["before_present"] is True and rows[1]["after_present"] is False


def test_only_declared_security_paths_are_labelled_and_namespace_exemption_is_visible():
    clean, attacked = record([email()]), record([email()])
    attacked["events"][2]["data"]["arguments"]["body"] = "Reworded summary"
    clean["manifest"]["config"]["lineage_namespace"] = "clean-namespace"
    attacked["manifest"]["config"]["lineage_namespace"] = "attacked-namespace"
    result = compare_records(clean, attacked)
    assert result["first_tool_proposal_divergence"]["status"] == "observed"
    assert result["first_security_relevant_divergence"]["status"] == "none_observed"
    assert result["comparability"]["run_local_configuration_differences"][0]["clean"] == "clean-namespace"
    attacked["manifest"]["config"] = None
    assert compare_records(clean, attacked)["comparability"]["status"] == "unconfirmed"


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.links, self.ids, self.scripts = [], [], set(), []
        self._script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "a":
            self.links.append(values["href"])
        if tag == "script":
            self._script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._script = False

    def handle_data(self, data):
        if self._script:
            self.scripts.append(data)


def test_native_fixture_export_is_immutable_escaped_and_links_existing_graphs(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "validate_canary.py"
    spec = importlib.util.spec_from_file_location("paired_report_native_fixture", script)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    paths = [tmp_path / "clean", tmp_path / "attacked"]
    for index, path in enumerate(paths):
        drive = native.memory.initial_drive()
        drive.files["1"].content = (
            "Meeting content" if index == 0 else '</pre><script>alert("fixture")</script>'
        )
        native.run_arm(path, case="copy", enabled=False, drive=drive)
        manifest_path = path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        # The native helper assigns different fake task and policy path identities
        # per output directory; harmonize only these fixture manifest fields.
        manifest["config"]["user_tasks"] = ["native_paired_fixture"]
        manifest["config"]["provenance_policy"] = "shared-fixture-policy"
        manifest_path.write_text(json.dumps(manifest))

    def hashes():
        return {
            str(file): hashlib.sha256(file.read_bytes()).hexdigest()
            for path in paths
            for file in path.rglob("*")
            if file.is_file()
        }

    before = hashes()
    output = tmp_path / "report"
    result = export_pair(*paths, output, sensitive_paths={"create_file": ["/content"]})
    assert result["comparability"]["status"] == "comparable_under_recorded_checks"
    assert (
        result["comparability"]["initial_environment_comparison"]["status"]
        == "different_observed_not_protocol_validated"
    )
    assert result["first_security_relevant_divergence"]["status"] == "observed"
    action = result["arms"][1]["actions"][-1]
    assert action["execution"]["status"] == "returned_successfully"
    assert action["execution"]["observed_environment_changes"][0]["bound_to_return"]
    assert action["source_exposures_in_request"]
    assert hashes() == before
    assert json.loads((output / "pair.json").read_text()) == result
    page = Page()
    page.feed((output / "index.html").read_text())
    assert page.tags.count("script") == 2
    assert "paired-event-data" in page.ids
    assert "event-list" in page.ids and "event-comparison" in page.ids
    rendered = (output / "index.html").read_text()
    assert "Visual paired event explorer" in rendered
    assert "Clean source evidence" in rendered and "Attacked source evidence" in rendered
    assert "event-graph" in page.ids and "path-overview" in page.ids
    assert "Original tables &amp; complete evidence" in rendered
    assert 'id="original-format" open' not in rendered
    assert "script-src 'nonce-" in rendered
    view = json.loads(page.scripts[0])
    proposal = next(row for row in view["rows"] if row["security_relevant"])
    assert proposal["event_type"] == "TOOL_CALL_PROPOSED"
    assert any(change["path"].endswith("/content") for change in proposal["changes"])
    assert '</pre><script>alert("fixture")</script>' not in rendered
    assert all(
        unquote(link[1:]) in page.ids
        if link.startswith("#")
        else (output / unquote(link)).resolve().is_file()
        for link in page.links
    )
    assert sum(not link.startswith("#") for link in page.links) == 2
    with pytest.raises(FileExistsError):
        export_pair(*paths, output)
    with pytest.raises(ValueError, match="separate"):
        export_pair(*paths, paths[0] / "derived")
    with pytest.raises(ValueError, match="distinct"):
        export_pair(paths[0], paths[0], tmp_path / "self-report")
