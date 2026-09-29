"""Immutable export and local report behavior, including Unicode and hostile text."""

import json
import re
import shutil
import subprocess

import pytest
from test_span_diagnostic import native_run as native_run

from agentdojo_lab.span_report import CONTROL_SHA, export_span_diagnostic, render_span_report


def test_export_freezes_before_controls_and_keeps_native_artifacts(native_run, tmp_path):
    output = tmp_path / "report"
    result = export_span_diagnostic([native_run], output)
    summary = result["summary"]
    assert summary["controls_passed"] == summary["controls_total"] == 12
    assert summary["selected_fields"] == 3
    assert summary["argument_fields"] == 4
    assert summary["run_status_counts"] == {"complete": 1}
    assert summary["source_files_unchanged"] is True
    assert summary["implementation_unchanged"] is True
    assert summary["model_calls"] == 0
    assert summary["independent_accuracy"] is None
    plan = json.loads((output / "plan.json").read_text())
    assert plan["controls_sha256"] == CONTROL_SHA
    assert plan["input_inventory"][str(native_run)]
    assert len((output / "span-results.jsonl").read_text().splitlines()) == 1
    with pytest.raises(ValueError, match="new output"):
        export_span_diagnostic([native_run], output)


@pytest.mark.parametrize("location", ["inside", "ancestor", "duplicate"])
def test_export_rejects_input_overwrite(native_run, tmp_path, location):
    output = native_run / "derived" if location == "inside" else tmp_path
    runs = [native_run, native_run] if location == "duplicate" else [native_run]
    with pytest.raises(ValueError):
        export_span_diagnostic(runs, output)
    assert not (native_run / "derived").exists()


def test_missing_record_retained_as_unavailable(native_run, tmp_path):
    (native_run / "summary.json").unlink()
    result = export_span_diagnostic([native_run], tmp_path / "report")
    assert result["summary"]["run_status_counts"] == {"unavailable": 1}
    assert result["summary"]["selected_fields"] == 0


def test_html_escaped_data_unicode_highlighting_and_navigation(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable")
    source = "x🧪GO</script><img src=x onerror=bad()>"
    fields = [
        {
            "policy_selected": True,
            "item_id": str(i),
            "function": "write",
            "argument_path": "/content",
            "target": target,
            "sources": [
                {
                    "source_text": source,
                    "scalar_pointer": "/content",
                    "injection_spans": [[1, 4]],
                    "request_pointer": "/data/body/messages/3/content",
                    "evidence": {
                        "status": "scored",
                        "low_information_target": True,
                        "literal_evidence": {
                            "classification": "injection_only",
                            "occurrence_count": 1,
                            "complete": True,
                            "hits": [{"source_span": [1, 4]}],
                        },
                        "optimal_alignment": {
                            "lcs_length": 3,
                            "min_injection_matched_codepoints": 3,
                            "max_injection_matched_codepoints": 3,
                        },
                    },
                }
            ],
        }
        for i, target in enumerate(["🧪GO", "second"])
    ]
    value = {
        "runs": [
            {
                "run_dir": "fixture",
                "condition": "injected",
                "input_condition": "passive",
                "original_report_href": "../run/report.html",
                "fields": fields,
            }
        ],
        "summary": {"requested_runs": 1, "selected_fields": 2, "controls_passed": 0, "controls_total": 0},
        "interpretation": "Lexical only",
        "controls": [],
    }
    output = tmp_path / "index.html"
    render_span_report(value, output)
    html = output.read_text()
    assert "</script><img" not in html
    assert "\\u003c/script\\u003e" in html
    scripts = re.findall(r"<script(?:[^>]*)>(.*?)</script>", html, re.S)
    assert len(scripts) == 2
    assert json.loads(scripts[0]) == value
    assert "innerHTML" not in scripts[1]
    # Minimal DOM exercises our interaction logic; it is not browser layout QA.
    prelude = r"""
const assert=require('node:assert/strict');
class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.handlers={};this._text='';this._value='';this.disabled=false;this.hidden=false;}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  set textContent(v){this._text=String(v);this.children=[];}
  get value(){return this._value;}set value(v){this._value=String(v);}
  get selectedIndex(){return this.children.findIndex(c=>c.value===this.value);}
  set selectedIndex(i){this.value=this.children[i]?.value??'';}
  replaceChildren(...items){this._text='';this.children=items;if(this.tagName==='select')this.selectedIndex=0;}
  append(item){this.children.push(item);}addEventListener(name,fn){this.handlers[name]=fn;}
  setAttribute(name,value){this[name]=value;}
}
const ids=IDS, nodes=new Map(ids.map(id=>[id,new Element(['field','source','control'].includes(id)?'select':'div')]));
nodes.get('span-data').textContent=JSON.stringify(FIXTURE);
const document={getElementById(id){assert(nodes.has(id),id);return nodes.get(id);},createElement(tag){return new Element(tag);}};
""".replace("IDS", json.dumps(re.findall(r'id="([^"]+)"', html))).replace("FIXTURE", json.dumps(value))
    checks = r"""
assert.equal(nodes.get('target-text').textContent,'🧪GO');
assert.equal(nodes.get('source-text').textContent,FIXTURE.runs[0].fields[0].sources[0].source_text);
assert.equal(nodes.get('source-text').children.find(c=>c.tagName==='mark').textContent,'🧪GO');
assert.equal(nodes.get('previous').disabled,true);
nodes.get('next').handlers.click();
assert.equal(nodes.get('target-text').textContent,'second');
assert.equal(nodes.get('position').textContent,'2 / 2');
assert.equal(nodes.get('next').disabled,true);
nodes.get('previous').handlers.click();
assert.equal(nodes.get('position').textContent,'1 / 2');
assert.equal(nodes.get('original').href,'../run/report.html');
""".replace("FIXTURE", json.dumps(value))
    checked = subprocess.run([node], input=prelude + scripts[1] + checks, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr
