"""Static artifact and pure-view logic checks; no browser, model or network."""

import hashlib
import json
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from agentdojo_lab.counterfactual_report import (
    collect_counterfactual_record,
    export_counterfactual_html,
)


class Page(HTMLParser):
    def __init__(self, value):
        super().__init__(convert_charrefs=False)
        self.tags, self.scripts = [], []
        self.active = None
        self.feed(value)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        self.tags.append((tag, attributes))
        if tag == "script":
            self.active = {"attributes": attributes, "text": ""}
            self.scripts.append(self.active)

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = None

    def handle_data(self, value):
        if self.active is not None:
            self.active["text"] += value

    @property
    def record(self):
        return json.loads(next(s["text"] for s in self.scripts if s["attributes"].get("id") == "record"))

    @property
    def code(self):
        return next(s["text"] for s in self.scripts if s["attributes"].get("type") != "application/json")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n")


def probe(probe_id="probe:1", source_id="source:1", marker="Reference text"):
    return {
        "probe_id": probe_id,
        "source_id": source_id,
        "label_ids": ["label:old"],
        "origin_source_ids": ["source:old"],
        "context_a": [
            {"role": "user", "content": "Save a benign note."},
            {"role": "tool", "content": marker},
        ],
        "context_b": [
            {"role": "user", "content": "Save a benign note."},
            {"role": "tool", "content": "Neutralized reference"},
        ],
        "sink": {"function": "create_file", "arguments": {"filename": "note.txt", "content": marker}},
        "replacements": [
            {
                "request_pointer": "/data/body/messages/1/content",
                "message_index": 1,
                "before_sha256": hashlib.sha256(marker.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(b"Neutralized reference").hexdigest(),
                "method": "authored_fixture",
                "leaf_paths": ["/content"],
            }
        ],
        "lineage": {
            "context_edge_ids": ["edge:1"],
            "origin_node_ids": ["node:1"],
            "recovered_origin_refs": ["source:old"],
            "path_edge_ids": ["edge:2", "edge:3"],
        },
    }


def fixture_rows(marker="Reference text"):
    first, second = probe(marker=marker), probe("probe:2", "source:2", "Competing reference")
    return [
        {
            "record_type": "decision",
            "proposal_event_id": "event:1",
            "plan": {"status": "eligible", "reason": "authored_fixture", "probes": [first, second]},
        },
        {
            "record_type": "probe_request",
            "proposal_event_id": "event:1",
            "probe_id": "probe:1",
            "source_id": "source:1",
            "body": {"model": "fixture", "messages": [{"role": "user", "content": marker}]},
            "body_sha256": "fixture-hash",
        },
        {
            "record_type": "probe_response",
            "proposal_event_id": "event:1",
            "probe_id": "probe:1",
            "source_id": "source:1",
            "response": {"choices": [{"message": {"content": marker}}]},
            "pacing_wait_seconds": 0,
        },
        {
            "record_type": "probe_result",
            "proposal_event_id": "event:1",
            "probe_id": "probe:1",
            "source_id": "source:1",
            "status": "valid",
            "judgment": {"would_call_anyway": False, "confidence": 0.8, "reasoning": marker},
            "alert": True,
            "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            "elapsed_seconds": 0.01,
        },
        {
            "record_type": "probe_result",
            "proposal_event_id": "event:1",
            "probe_id": "probe:2",
            "source_id": "source:2",
            "status": "invalid",
            "reason": "Malformed fixture response",
        },
    ]


def audit_fixture(tmp_path, *, rows=None, marker="Reference text"):
    source = tmp_path / "original-run"
    source.mkdir()
    (source / "events.jsonl").write_text("Original native evidence\n")
    output = tmp_path / "separate-audit"
    output.mkdir()
    write_json(
        output / "manifest.json",
        {
            "source_run": str(source),
            "source_hashes": {"events.jsonl": "original-hash"},
            "execution_mode": "deferred_prefix_audit",
            "inference_scope": "auditor_prediction_not_observed_behavior",
            "protocol": {"notes": marker},
        },
    )
    write_json(
        output / "summary.json",
        {
            "counts": {"eligible": 1, "skipped": 0, "request": 1, "valid": 1, "invalid": 1, "error": 0},
            "judgments": {"status": "alert", "alert": True, "alert_count": 1, "unknown_count": 1},
            "unchanged_original_hashes": True,
        },
    )
    (output / "counterfactual.jsonl").write_text(
        "".join(
            json.dumps(row, ensure_ascii=False) + "\n"
            for row in (fixture_rows(marker) if rows is None else rows)
        )
    )
    return source, output


def run_helpers(page, checks, value=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for static JavaScript validation")
    code = page.code.split("// DOM rendering starts here.")[0]
    program = (
        "const assert = require('node:assert/strict');\n"
        + code
        + "\nconst fixture = "
        + json.dumps(value)
        + ";\n"
        + checks
    )
    result = subprocess.run([node], input=program, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def test_export_preserves_all_raw_audit_data_and_input_files(tmp_path):
    source, output = audit_fixture(tmp_path)
    paths = [*source.iterdir(), *output.iterdir()]
    before = {path: path.read_bytes() for path in paths}
    result = export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    assert result["status"] == "generated" and result["record_count"] == 5
    assert result["warning_count"] == 0
    assert page.record["records"] == fixture_rows()
    assert page.record["summary"]["judgments"]["unknown_count"] == 1
    assert page.record["interpretation"] == "auditor_prediction_not_observed_behavior"
    assert set(page.record["audit_input_sha256"]) == {"manifest.json", "summary.json", "counterfactual.jsonl"}
    for path, raw in before.items():
        assert path.read_bytes() == raw
        if path.parent == output:
            assert page.record["audit_input_sha256"][path.name] == hashlib.sha256(raw).hexdigest()
    assert set(source.iterdir()) == {source / "events.jsonl"}
    with pytest.raises(FileExistsError):
        export_counterfactual_html(output)


def test_embedded_content_is_inert_and_only_nonce_authorized_code_runs(tmp_path):
    marker = '</script><script>alert("fixture")</script><img src=x onerror="fixture()"> & \u2028\u2029'
    _, output = audit_fixture(tmp_path, marker=marker)
    export_counterfactual_html(output)
    content = (output / "report.html").read_text()
    page = Page(content)
    assert page.record["records"] == fixture_rows(marker)
    assert marker not in content
    assert len(page.scripts) == 2
    assert not any(tag in {"img", "iframe", "object", "embed", "a"} for tag, _ in page.tags)
    assert not any(name.startswith("on") for _, attrs in page.tags for name in attrs)
    assert not any("src" in attrs for _, attrs in page.tags)
    nonce = page.scripts[0]["attributes"]["nonce"]
    assert all(script["attributes"]["nonce"] == nonce for script in page.scripts)
    csp = next(
        attrs["content"]
        for tag, attrs in page.tags
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
    )
    assert "script-src 'nonce-" + nonce + "'" in csp
    assert "connect-src 'none'" in csp and "default-src 'none'" in csp
    assert ".textContent" in page.code
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "fetch(", "XMLHttpRequest"):
        assert unsafe not in page.code
    assert "confidence is self-reported, not a causal probability" in content


def test_missing_files_and_optional_fields_render_unknown_without_fabricated_results(tmp_path):
    output = tmp_path / "partial"
    output.mkdir()
    write_json(output / "manifest.json", {})
    result = export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    assert result["warning_count"] == 2
    assert page.record["records"] == [] and page.record["summary"] == {}
    assert "No audit records are available" in page.code
    run_helpers(
        page,
        """
        assert.equal(AuditView.count({}, 'valid'), null);
        assert.equal(AuditView.count({counts:{valid:0}}, 'valid'), 0);
        assert.equal(AuditView.count({counts:{valid:false}}, 'valid'), null);
        assert.equal(AuditView.count({judgments:{alert_count:0,status:'unknown'}}, 'alerts'), 0);
        assert.equal(AuditView.judgment({}).alert, null);
        assert.equal(AuditView.findProbe([], {}, undefined), null);
        assert.deepEqual(AuditView.exchange([], {}, null), []);
        """,
    )


def test_malformed_or_nonfinite_jsonl_records_are_preserved_as_unparsed(tmp_path):
    _, output = audit_fixture(tmp_path)
    path = output / "counterfactual.jsonl"
    raw = '{"record_type":"probe_result","confidence":NaN}\n<script>inert</script>\nnull\n{}\n'
    path.write_text(raw)
    result = collect_counterfactual_record(output)
    assert len(result["warnings"]) == 3
    assert [r.get("record_type") for r in result["records"]] == ["unparsed"] * 3 + [None]
    assert result["records"][1]["raw_text"] == "<script>inert</script>"
    assert path.read_text() == raw
    export_counterfactual_html(output)


def test_external_symlink_input_is_not_read(tmp_path):
    _, output = audit_fixture(tmp_path)
    private = tmp_path / "external.jsonl"
    private.write_text('{"private":"EXTERNAL_CONTENT_MUST_NOT_BE_EMBEDDED"}')
    (output / "counterfactual.jsonl").unlink()
    (output / "counterfactual.jsonl").symlink_to(private)
    result = collect_counterfactual_record(output)
    assert result["records"] == []
    assert "counterfactual.jsonl" not in result["audit_input_sha256"]
    assert "EXTERNAL_CONTENT_MUST_NOT_BE_EMBEDDED" not in json.dumps(result)


@pytest.mark.parametrize("child", [False, True])
def test_rejects_writing_into_original_run(tmp_path, child):
    source = tmp_path / "original"
    source.mkdir()
    output = source / "audit" if child else source
    output.mkdir(exist_ok=True)
    write_json(output / "manifest.json", {"source_run": str(source)})
    with pytest.raises(ValueError, match="outside the original"):
        export_counterfactual_html(output)
    assert not (output / "report.html").exists()


def test_pure_linking_keeps_probes_sources_and_proposals_separate(tmp_path):
    _, output = audit_fixture(tmp_path)
    export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    run_helpers(
        page,
        """
        const decision=fixture[0], request=fixture[1], response=fixture[2], result=fixture[3];
        const selected=AuditView.findProbe(fixture,result);
        assert.equal(selected.probe_id,'probe:1');
        assert.equal(selected.context_a[1].content,'Reference text');
        assert.deepEqual(AuditView.sourceMessages(selected),[{message_index:1,message:selected.context_a[1]}]);
        assert.equal(AuditView.findProbe(fixture,decision,'probe:2').source_id,'source:2');
        assert.deepEqual(AuditView.exchange(fixture,decision,selected),[request,response,result]);
        assert.equal(AuditView.linked(result,{...result,source_id:'source:other'}),false);
        assert.equal(AuditView.linked(result,{...result,proposal_event_id:'event:other'}),false);
        assert.equal(AuditView.linked(result,{...result,probe_id:'probe:other'}),false);
        assert.equal(AuditView.linked({},{}),false);
        const missing={record_type:'probe_result',proposal_event_id:'event:1',status:'valid'};
        assert.deepEqual(AuditView.exchange([...fixture,missing],decision,selected),[request,response,result]);
        assert.equal(AuditView.findProbe(fixture,{...result,probe_id:'missing'}),null);
        const skipped={record_type:'decision',plan:{status:'skipped',probes:[]}};
        const prefixed=[skipped,{record_type:'probe_result'},...fixture];
        const unchanged=JSON.stringify(prefixed);
        assert.equal(AuditView.initialIndex(prefixed),2);
        assert.equal(JSON.stringify(prefixed),unchanged);
        assert.equal(AuditView.initialIndex([skipped]),0);
        assert.equal(AuditView.initialIndex([]),-1);
        assert.equal(AuditView.component(decision),'proposal');
        assert.equal(AuditView.component(request),'auditor');
        assert.equal(AuditView.component(response),'auditor');
        assert.equal(AuditView.component(result),'judgment');
        assert.equal(AuditView.component({record_type:'__proto__'}),null);
        """,
        fixture_rows(),
    )


def test_invalid_error_or_unrecorded_alert_never_becomes_no_alert(tmp_path):
    _, output = audit_fixture(tmp_path)
    export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    run_helpers(
        page,
        """
        const valid=fixture[3];
        assert.deepEqual(AuditView.judgment(valid).alert,true);
        assert.equal(AuditView.judgment(valid).confidence,0.8);
        assert.equal(AuditView.judgment({...valid,alert:false}).alert,false);
        const without={...valid}; delete without.alert;
        assert.equal(AuditView.judgment(without).alert,null);
        for(const status of ['invalid','error','not_run','unknown']){
          const j=AuditView.judgment({...valid,status,alert:false});
          assert.equal(j.valid,false);assert.equal(j.alert,null);
          assert.equal(j.confidence,null);assert.equal(j.wouldCall,null);
        }
        for(const confidence of [NaN,Infinity,-0.1,1.1,'0.8',null]){
          assert.equal(AuditView.judgment({...valid,judgment:{...valid.judgment,confidence}}).valid,false);
        }
        assert.equal(AuditView.judgment({...valid,judgment:{...valid.judgment,would_call_anyway:'false'}}).valid,false);
        """,
        fixture_rows(),
    )


def test_language_restricted_response_reference_is_displayed_without_loading_file(tmp_path):
    rows = fixture_rows()
    rows[2] = {
        "record_type": "probe_response",
        "proposal_event_id": "event:1",
        "probe_id": "probe:1",
        "source_id": "source:1",
        "status": "non_english",
        "response_file": "../outside-response.json",
        "response_sha256": "retained-hash",
    }
    _, output = audit_fixture(tmp_path, rows=rows)
    outside = tmp_path / "outside-response.json"
    outside.write_text("UNREFERENCED_EXTERNAL_RESPONSE")
    export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    assert page.record["records"][2] == rows[2]
    assert "UNREFERENCED_EXTERNAL_RESPONSE" not in (output / "report.html").read_text()


def test_complete_script_syntax_and_diagram_identity_mapping(tmp_path):
    _, output = audit_fixture(tmp_path)
    export_counterfactual_html(output)
    page = Page((output / "report.html").read_text())
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for static JavaScript validation")
    checked = subprocess.run([node, "--check"], input=page.code, text=True, capture_output=True, check=False)
    assert checked.returncode == 0, checked.stderr
    ids = {attrs.get("id") for _, attrs in page.tags}
    assert {f"flow-{part}" for part in ("context", "proposal", "auditor", "judgment", "tools")} <= ids
    assert '.classList.toggle("active",active)' in page.code
    assert "No path connects the auditor to native execution" in (output / "report.html").read_text()
    # The only vertical execution edge starts at the recorded proposal, not the auditor.
    wires = [attrs["d"] for tag, attrs in page.tags if tag == "path" and "wire" in attrs.get("class", "")]
    assert wires == ["M240 53 H270", "M495 53 H550", "M785 53 H835", "M382 86 V126"]
