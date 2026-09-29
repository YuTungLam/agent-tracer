"""Descriptive paired reporting from temporary native controls, without model calls."""

import hashlib
import html
import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"pair_report_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load_script("validate_canary")
reporter = load_script("report_canary_pair")


def comparable_fixture_manifests(paths):
    """Only synthetic manifest identities are harmonized; observations stay intact.

    The native helper intentionally uses each output name as its fake task name
    and writes an identical policy into each run. A pair report expects one task
    and one policy pathname, so these fixture-only manifest fields share values.
    """
    shared_policy = paths[0].parent / "shared-policy.json"
    shared_policy.write_bytes((paths[0] / "policy.json").read_bytes())
    for path in paths:
        manifest_path = path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["config"]["user_tasks"] = ["native_paired_fixture"]
        manifest["config"]["provenance_policy"] = str(shared_policy)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def tree_hashes(paths):
    return {
        str(file): hashlib.sha256(file.read_bytes()).hexdigest()
        for path in paths
        for file in path.rglob("*")
        if file.is_file()
    }


@pytest.fixture(scope="module")
def pairs(tmp_path_factory):
    output = tmp_path_factory.mktemp("canary-pair-report")
    results = {}
    for case in ("fixed", "copy"):
        root = output / case
        paths = (root / "passive", root / "canary")
        native_runs = [
            native.run_arm(path, case=case, enabled=enabled)
            for path, enabled in zip(paths, (False, True), strict=True)
        ]
        comparable_fixture_manifests(paths)
        results[case] = (paths, native_runs)
    return results


def test_read_arm_counts_use_native_sink_and_result_schema(pairs):
    paths, native_runs = pairs["fixed"]
    for path, raw in zip(paths, native_runs, strict=True):
        arm = reporter.read_arm(path)
        assert arm["runtime_actions"] == raw["actions"]
        assert arm["request_bodies"] == raw["requests"]
        assert arm["tasks"] == [] and arm["real_llm"] is False
        assert arm["recording_complete"] and arm["sidecar_complete"]
        for key, expected in {
            "requests_attempted": 3,
            "responses_received": 3,
            "model_errors": 0,
            "proposals": 2,
            "runtime_entries": 2,
            "sink_proposals": 1,
            "sink_returns": 1,
            "successful_sink_returns": 1,
            "source_policy_tool_results": 1,
            "markers_at_sink_proposal": 0,
            "markers_at_successful_sink_return": 0,
        }.items():
            assert arm["counts"][key] == expected, key
    passive, active = map(reporter.read_arm, paths)
    assert passive["counts"]["assigned_markers"] == 0
    assert active["counts"]["assigned_markers"] == active["counts"]["applied_markers"] == 1
    assert active["counts"]["exposed_markers"] == 1
    assert active["counts"]["marker_exposures"] == 2


def test_read_arm_copy_links_hit_to_actual_proposal_and_successful_runtime(pairs):
    paths, native_runs = pairs["copy"]
    active = reporter.read_arm(paths[1])
    (marker,) = active["markers"]
    (hit,) = marker["sink_hits"]
    proposal = next(
        event
        for event in native_runs[1]["events"]
        if event["event_type"] == "TOOL_CALL_PROPOSED" and event["data"]["function"] == "create_file"
    )
    assert hit["proposal_event_id"] == proposal["event_id"]
    assert hit["call_ref"] == proposal["call_ref"]
    assert hit["function"] == "create_file" and hit["argument_path"] == "/content"
    assert hit["native_return_succeeded"] is True
    target = proposal["data"]["arguments"]["content"]
    for start, end in hit["target_spans"]:
        assert target[start:end] == marker["token"]
    assert active["counts"]["markers_at_successful_sink_return"] == 1
    assert active["counts"]["tier1_matched_pairs"] == 1


@pytest.mark.parametrize("case,actions_equal", [("fixed", True), ("copy", False)])
def test_report_preserves_observed_changes_and_source_artifacts(pairs, tmp_path, case, actions_equal):
    paths, native_runs = pairs[case]
    before = tree_hashes(paths)
    output = tmp_path / "pair-report"
    returned = reporter.report(*paths, output)
    saved = json.loads((output / "pair.json").read_text())
    assert saved["comparisons"] == returned["comparisons"]
    assert saved["arm_order"] == ["passive", "canary_intervention"]
    comparisons = saved["comparisons"]
    assert comparisons["configuration_equal_except_canary"] is True
    assert comparisons["first_actual_request_equal"] is True
    assert comparisons["full_request_sequences_equal"] is False
    assert comparisons["proposed_action_sequences_equal"] is actions_equal
    assert comparisons["runtime_action_sequences_equal"] is actions_equal
    assert comparisons["environment_change_sequences_equal"] is actions_equal
    assert [arm["runtime_actions"] for arm in saved["arms"]] == [run["actions"] for run in native_runs]
    if case == "copy":
        token = saved["arms"][1]["markers"][0]["token"]
        assert token in saved["arms"][1]["runtime_actions"][-1]["arguments"]["content"]
        assert token not in saved["arms"][0]["runtime_actions"][-1]["arguments"]["content"]
    assert tree_hashes(paths) == before
    with pytest.raises(FileExistsError):
        reporter.report(*paths, output)


def test_report_rejects_wrong_arm_order_and_noncanary_config_changes(pairs, tmp_path):
    paths, _ = pairs["fixed"]
    with pytest.raises(ValueError, match="passive arm"):
        reporter.report(paths[1], paths[0], tmp_path / "wrong-order")
    assert not (tmp_path / "wrong-order").exists()
    path = tmp_path / "changed-config"
    native.run_arm(path, case="fixed", enabled=True)
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["config"] = json.loads((paths[1] / "manifest.json").read_text())["config"]
    manifest["config"]["temperature"] = 0.75
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="configurations differ"):
        reporter.report(paths[0], path, tmp_path / "different-config")
    assert not (tmp_path / "different-config").exists()


def test_sidecar_failure_does_not_hide_later_native_proposals_or_sink_outcomes(tmp_path):
    path = tmp_path / "failed-intervention"
    raw = native.run_arm(path, case="fixed", enabled=True, uuid_tokens=("not-a-uuid",))
    assert raw["failure"] is None
    arm = reporter.read_arm(path)
    assert arm["recording_complete"] is False and arm["sidecar_complete"] is False
    assert arm["canary_status"]["complete"] is False
    assert arm["counts"]["proposals"] == 2
    assert arm["counts"]["sink_proposals"] == 1
    assert arm["counts"]["sink_returns"] == arm["counts"]["successful_sink_returns"] == 1
    assert arm["proposed_actions"] == raw["actions"]
    assert arm["runtime_actions"] == raw["actions"]
    assert arm["counts"]["assigned_markers"] == arm["counts"]["tier1_matched_pairs"] == 0
    assert arm["tasks"] == []


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.links = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "a":
            self.links.append(dict(attrs)["href"])

    def handle_data(self, data):
        self.text.append(data)


def test_html_keeps_native_dangerous_text_inert_and_preserves_action_bytes(tmp_path):
    payload = '</pre><script>alert("fixture")</script><img src=x onerror="fixture()"> & text'
    paths = (tmp_path / "passive", tmp_path / "canary")
    for path, enabled in zip(paths, (False, True), strict=True):
        drive = native.memory.initial_drive()
        drive.files["1"].content = payload
        native.run_arm(path, case="copy", enabled=enabled, drive=drive)
    comparable_fixture_manifests(paths)
    output = tmp_path / "report"
    reporter.report(*paths, output)
    content = (output / "index.html").read_text()
    parsed = Page()
    parsed.feed(content)
    assert "script" not in parsed.tags and "img" not in parsed.tags
    assert html.escape("</pre><script>") in content
    assert "default-src 'none'" in content
    assert len(parsed.links) == 2
    assert all((output / link).resolve().is_file() for link in parsed.links)
    saved = json.loads((output / "pair.json").read_text())
    actual = json.loads((paths[1] / "actions.json").read_text())
    assert saved["arms"][1]["runtime_actions"] == actual
    assert "</pre><script>" in actual[-1]["arguments"]["content"]
    assert "</pre><script>" in "".join(parsed.text)
