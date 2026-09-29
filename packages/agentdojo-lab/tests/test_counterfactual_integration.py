"""Native, pinned-encoder counterfactual integration controls; no real API."""

import copy
import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/validate_counterfactual.py"
SPEC = importlib.util.spec_from_file_location("validate_counterfactual_fixture", SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


@pytest.fixture(scope="module")
def controls(tmp_path_factory):
    path = tmp_path_factory.mktemp("counterfactual-integration") / "native-controls"
    result = fixture.validate(path)
    assert result["passed"], {
        "stage": result.get("failure_stage"),
        "error": result.get("error_type"),
        "checks": result["checks"],
    }
    return path, result


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_native_pair_and_pinned_four_negative_stages(controls):
    path, result = controls
    assert result["real_llm"] is False and result["real_api_calls_added"] == 0
    assert result["network_attempts"] == 0 and result["scripted_agent_sessions"] == 7
    assert result["semantic"]["encoder"]["revision"] == fixture.REVISION
    for name in (
        "requests.json",
        "actions.json",
        "native/fixture.json",
        "initial-environment.json",
        "final-environment.json",
    ):
        assert load(path / "implicit-no-audit" / name) == load(path / "implicit-audit" / name)
    assert len(load(path / "implicit-audit/actions.json")) == 2
    assert len(load(path / "implicit-audit/requests.json")) == 3
    for pair in result["implicit_pairs"]:
        assert pair["complete"] is True and pair["matched"] is False
        assert pair["first_matched_tier"] is None
        for tier in ("tier1", "tier2", "tier3", "tier4"):
            assert pair["stages"][tier]["status"] == "scored"


def test_neutralized_context_preserves_original_input_and_native_structure(controls):
    from agentdojo_lab.counterfactual import plan_probe

    path, result = controls
    probe = result["plans"]["implicit"]["probes"][0]
    assert probe["sink"] == {
        "function": "create_file",
        "arguments": {"filename": "opaque-output.txt", "content": fixture.OPAQUE_CONTENT},
    }
    assert probe["context_a"] == load(path / "implicit-audit/requests.json")[1]["messages"]
    changed = [
        index
        for index, (first, second) in enumerate(zip(probe["context_a"], probe["context_b"], strict=True))
        if first != second
    ]
    assert changed
    for index in changed:
        first, second = probe["context_a"][index], probe["context_b"][index]
        assert first["role"] == second["role"] == "tool"
        assert {key: value for key, value in first.items() if key != "content"} == {
            key: value for key, value in second.items() if key != "content"
        }
        assert fixture.SOURCE_CONTENT in first["content"]
        assert fixture.SOURCE_CONTENT not in second["content"]
    rows = fixture.memory.read_lines(path / "implicit-audit/provenance.jsonl")
    call = copy.deepcopy(fixture.sink_call({"rows": rows}))
    graph = load(path / "implicit-audit/graph-observation.json")
    before = fixture.digest({"call": call, "graph": graph})
    repeat = plan_probe(call, graph)
    assert repeat == result["plans"]["implicit"]
    assert fixture.digest({"call": call, "graph": graph}) == before
    repeat["probes"][0]["context_b"][0]["content"] = "Mutation in the returned audit object."
    assert fixture.digest({"call": call, "graph": graph}) == before


@pytest.mark.parametrize("name", ["explicit", "unavailable", "truncated"])
def test_control_evidence_cannot_start_a_counterfactual_judgment(controls, name):
    _, result = controls
    assert result["plans"][name]["status"] == "skipped"
    assert result["plans"][name]["probes"] == []
    assert result["plans"][name]["reason"]


def test_memory_probe_uses_actual_second_session_exposure_and_restored_paths(controls):
    path, result = controls
    plan = result["plans"]["memory"]
    assert plan["status"] == "eligible"
    assert result["memory_recovered_sources"]
    requests = load(path / "memory-session2/requests.json")
    assert all(message["role"] != "tool" for message in requests[0]["messages"])
    for probe in plan["probes"]:
        assert probe["context_a"] == requests[1]["messages"]
    assert any(probe["lineage"]["path_edge_ids"] for probe in plan["probes"])
    assert any(probe["origin_source_ids"] for probe in plan["probes"])
    snapshot = load(path / "native-memory.json")
    file2 = next(file for file in snapshot["files"] if file["id_"] == "2")
    assert file2["content"] == fixture.SOURCE_CONTENT
    assert (path / "memory-session1/lineage-state.json").read_bytes() == (
        path / "memory-session2/lineage-initial-state.json"
    ).read_bytes()


@pytest.mark.parametrize(
    "condition,expected",
    [("yes", "no_alert"), ("no", "alert"), ("error", "unknown"), ("tool_call", "unknown")],
)
def test_actual_no_tools_judge_adapter_preserves_primary_run(controls, condition, expected):
    path, result = controls
    summary = result["mock_judge_controls"][condition]
    requests = load(path / f"judge-{condition}/mock-transport-requests.json")
    assert len(requests) == 1
    assert not {"tools", "tool_choice", "functions"}.intersection(requests[0])
    assert summary["judgments"]["status"] == expected
    assert summary["unchanged_original_hashes"] is True
    assert summary["native_tool_calls_by_auditor"] == summary["primary_model_requests_by_auditor"] == 0
    assert summary["source_hashes_after"] == result["primary_inputs_sha256"]
    rows = fixture.memory.read_lines(path / f"judge-{condition}/counterfactual.jsonl")
    outcomes = [row for row in rows if row["record_type"] == "probe_result"]
    assert len(outcomes) == 1
    if condition in {"yes", "no"}:
        assert outcomes[0]["status"] == "valid"
        assert outcomes[0]["judgment"]["would_call_anyway"] is (condition == "yes")
        assert outcomes[0]["judgment"]["confidence"] == 0.2
    elif condition == "tool_call":
        assert outcomes[0]["status"] == "invalid"
    else:
        assert outcomes[0]["status"] == "error"


def test_deferred_plan_only_and_zero_budget_add_no_judge_calls(controls, tmp_path):
    from agentdojo_lab.counterfactual_audit import audit_run

    path, _ = controls
    source = path / "implicit-audit"
    before = fixture.tree_hashes(source)
    with fixture.block_network() as attempts:
        planned = audit_run(source, tmp_path / "plan-only")
        invoked = []

        def forbidden(body):
            invoked.append(body)
            raise AssertionError("No probe budget remains")

        budgeted = audit_run(source, tmp_path / "budget-zero", judge=forbidden, max_probes=0)
    assert not attempts and not invoked
    assert planned["counts"].get("request", 0) == budgeted["counts"].get("request", 0) == 0
    assert planned["judgments"]["status"] == budgeted["judgments"]["status"] == "unknown"
    assert fixture.tree_hashes(source) == before


def test_existing_native_output_is_refused_without_rewriting_it(controls):
    path, _ = controls
    before = fixture.tree_hashes(path)
    with pytest.raises(FileExistsError):
        fixture.validate(path)
    assert fixture.tree_hashes(path) == before


@pytest.mark.parametrize("tamper", ["analysis", "request", "proposal", "checkpoint", "source_exposure"])
def test_audit_rejects_changed_verified_inputs_before_any_judge_request(controls, tmp_path, tamper):
    from agentdojo_lab.counterfactual_audit import audit_run

    path, _ = controls
    source = tmp_path / "copied-run"
    shutil.copytree(path / "implicit-audit", source)
    if tamper == "source_exposure":
        target = source / "provenance.jsonl"
        raw_lines = target.read_bytes().splitlines(keepends=True)
        rows = [json.loads(line) for line in raw_lines]
        index = next(
            index
            for index, row in enumerate(rows)
            if row["record_type"] == "call_analysis" and row["call"]["function"] == "create_file"
        )
        row = rows[index]
        occurrence = next(item for item in row["call"]["visible_sources"] if item["kind"] == "tool")
        occurrence["exposure_event_id"] = row["call"]["request_event_id"]
        raw_lines[index] = fixture.canonical(row) + b"\n"
        flush_index = next(
            index
            for index, item in enumerate(rows)
            if item["record_type"] == "analysis_flush"
            and item["analysis_record_sequence"] == row["record_sequence"]
        )
        rows[flush_index]["analysis_line_sha256"] = fixture.hashlib.sha256(raw_lines[index]).hexdigest()
        raw_lines[flush_index] = fixture.canonical(rows[flush_index]) + b"\n"
        target.write_bytes(b"".join(raw_lines))
    elif tamper == "analysis":
        target = source / "provenance.jsonl"
        rows = fixture.memory.read_lines(target)
        row = next(row for row in rows if row["record_type"] == "call_analysis")
        row["call"]["function"] = "changed_without_updating_receipt"
        target.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    elif tamper in {"request", "proposal"}:
        target = source / "events.jsonl"
        rows = fixture.memory.read_lines(target)
        if tamper == "request":
            event = next(row for row in rows if row["event_type"] == "MODEL_REQUEST")
            event["data"]["body"]["messages"][0]["content"] += " Detached edit."
        else:
            event = next(row for row in rows if row["event_type"] == "TOOL_CALL_PROPOSED")
            event["data"]["arguments"] = {"file_id": "changed"}
        target.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    else:
        target = source / "lineage-state.json"
        envelope = load(target)
        envelope["state"]["nodes"][0]["tampered"] = True
        target.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    invoked = []

    def forbidden(body):
        invoked.append(body)
        raise AssertionError("Invalid inputs must not reach the judge")

    output = tmp_path / "rejected-audit"
    before = fixture.tree_hashes(source)
    message = "Source occurrence differs" if tamper == "source_exposure" else None
    with fixture.block_network() as attempts, pytest.raises(ValueError, match=message):
        audit_run(source, output, judge=forbidden)
    assert not attempts and not invoked
    assert not output.exists()
    assert fixture.tree_hashes(source) == before


def test_audit_refuses_output_inside_source_before_creating_any_file(controls):
    from agentdojo_lab.counterfactual_audit import audit_run

    path, _ = controls
    source = path / "implicit-audit"
    before = fixture.tree_hashes(source)
    with pytest.raises(ValueError, match="separate"):
        audit_run(source, source / "forbidden-audit")
    assert fixture.tree_hashes(source) == before


@pytest.mark.parametrize("condition", ["invalid_json", "cjk", "cjk_escaped"])
def test_unusable_judge_response_is_retained_without_becoming_a_valid_verdict(controls, tmp_path, condition):
    path, _ = controls
    source = path / "implicit-audit"
    before = fixture.tree_hashes(source)
    output = tmp_path / ("audit-" + condition)
    with fixture.block_network() as attempts:
        result = fixture.mock_audit(source, output, condition)
    assert not attempts
    assert result["summary"]["judgments"]["status"] == "unknown"
    assert fixture.tree_hashes(source) == before
    responses = [row for row in result["rows"] if row["record_type"] == "probe_response"]
    outcomes = [row for row in result["rows"] if row["record_type"] == "probe_result"]
    assert len(responses) == len(outcomes) == 1
    assert outcomes[0]["status"] == "invalid"
    if condition in {"cjk", "cjk_escaped"}:
        raw_path = output / responses[0]["response_file"]
        assert raw_path.suffix == ".bin"
        raw = json.loads(raw_path.read_bytes())
        assert json.loads(raw["choices"][0]["message"]["content"])["reasoning"] == "\u7ed3\u679c"
        assert fixture.hashlib.sha256(raw_path.read_bytes()).hexdigest() == responses[0]["response_sha256"]
    else:
        assert responses[0]["response"]["choices"][0]["message"]["content"] == "{invalid JSON"
    cjk = re.compile("[\u3400-\u9fff\uf900-\ufaff\U00020000-\U000323af]")
    for artifact in output.rglob("*"):
        if artifact.is_file() and artifact.suffix in {".json", ".jsonl", ".html"}:
            assert cjk.search(artifact.read_text(encoding="utf-8")) is None
