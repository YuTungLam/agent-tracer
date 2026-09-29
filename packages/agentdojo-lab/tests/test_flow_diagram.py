import json
import re
import shutil
import subprocess
from importlib.resources import files
from xml.etree import ElementTree

import pytest

from agentdojo_lab.html_report import export_run_html


def run_js(source):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional for JavaScript checks")
    result = subprocess.run([node], input=source, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def flow_source():
    return files("agentdojo_lab").joinpath("templates/agent_flow.js").read_text()


def test_all_event_locations_resolve_to_diagram_components():
    svg = ElementTree.fromstring(files("agentdojo_lab").joinpath("templates/agent_flow.svg").read_text())
    nodes = [node.attrib["data-flow-node"] for node in svg.iter() if "data-flow-node" in node.attrib]
    edges = [node.attrib["data-flow-edge"] for node in svg.iter() if "data-flow-edge" in node.attrib]
    assert len(nodes) == len(set(nodes))
    assert len(edges) == len(set(edges))
    expected = {
        "RUN_STARTED": ["runner"],
        "RUN_END": ["runner"],
        "EPISODE_STARTED": ["pipeline"],
        "EPISODE_ENDED": ["exit"],
        "MODEL_REQUEST": ["request"],
        "MODEL_RESPONSE": ["api"],
        "MODEL_PARSED": ["parse"],
        "MODEL_ERROR": ["request", "api", "parse"],
        "TOOL_CALL_PROPOSED": ["parse"],
        "TOOL_RUNTIME_STARTED": ["runtime"],
        "TOOL_RUNTIME_RETURNED": ["runtime"],
        "ENVIRONMENT_CHANGE": ["environment"],
        "TOOL_OUTPUT_INTERVENTION": ["result"],
        "TOOL_RESULT": ["result"],
        "TOOL_OUTPUT_EXPOSED": ["history", "request"],
    }
    run_js(
        flow_source()
        + f"""
const assert=require('node:assert/strict');
const expected={json.dumps(expected)}, nodes={json.dumps(nodes)}, edges={json.dumps(edges)};
assert.deepEqual(Object.keys(FLOW_EVENT_MAP).sort(),Object.keys(expected).sort());
for(const [type,primary] of Object.entries(expected)) {{
  const location=flowLocation({{event_type:type}});
  assert.deepEqual(location.nodes,primary);
  assert(location.nodes.every(id=>nodes.includes(id)));
  assert(location.edges.every(id=>edges.includes(id)));
  assert(!location.nodes.includes('evaluator'));
}}
"""
    )


def test_phase_and_error_semantics_do_not_claim_success():
    run_js(
        flow_source()
        + """
const assert=require('node:assert/strict');
assert.equal(flowLocation({event_type:'MODEL_RESPONSE',data:{status_code:503}}).tone,'error');
assert.equal(flowLocation({event_type:'TOOL_RESULT',data:{message:{error:'fixture'}}}).tone,'error');
assert.equal(flowLocation({event_type:'EPISODE_ENDED',data:{error_type:'RuntimeError'}}).tone,'error');
assert.equal(flowLocation({event_type:'RUN_END',data:{status:'completed'}}).tone,'active');
assert.deepEqual(flowLocation({event_type:'TOOL_CALL_PROPOSED'}).edges,[]);
assert.deepEqual(flowLocation({event_type:'TOOL_OUTPUT_EXPOSED'}).edges,['history_request']);
for(const value of [null,{}, {event_type:3}, {event_type:'__proto__'}, {event_type:'NEW_KIND'}]) {
  assert.deepEqual(flowLocation(value).nodes,[]);
  assert.deepEqual(flowLocation(value).edges,[]);
}
"""
    )


def test_timeline_selection_updates_and_clears_diagram(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"real_llm": False, "config": {}}))
    (run / "summary.json").write_text(json.dumps({"status": "completed"}))
    event_data = [
        {"event_type": "TOOL_CALL_PROPOSED", "event_id": "event-1", "event_sequence": 1, "data": {}},
        {"event_type": "TOOL_RUNTIME_STARTED", "event_id": "event-2", "event_sequence": 2, "data": {}},
    ]
    (run / "events.jsonl").write_text("\n".join(json.dumps(e) for e in event_data))
    output = export_run_html(run)
    html = (run / "report.html").read_text()
    assert output["event_count"] == 2
    assert "@@FLOW_" not in html
    assert 'data-flow-node="runtime"' in html
    script = re.search(r'<script nonce="[^"]+">(.*?)</script>', html, flags=re.S).group(1)
    helpers = script.split("const taskIds=")[0]
    handlers = script[
        script.index("function showOnlineAttribution") : script.index('$("task-filter").addEventListener')
    ]
    # Exercise the real timeline click callback and highlight renderer against
    # minimal element adapters. This is a unit test, not browser visual QA.
    adapters = """
const assert=require('node:assert/strict');
class Element {
  constructor(tag='div') { this.tag=tag;this.childNodes=[];this.attributes={};this.dataset={};this.value='';this.listeners={};this.classes=new Set();this.classList={toggle:(k,on)=>on?this.classes.add(k):this.classes.delete(k)}; }
  append(...nodes){this.childNodes.push(...nodes);}
  replaceChildren(...nodes){this.childNodes=nodes;}
  getAttribute(k){return this.attributes[k];}
  setAttribute(k,v){this.attributes[k]=v;}
  removeAttribute(k){delete this.attributes[k];}
  addEventListener(k,callback){this.listeners[k]=callback;}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const nodes=['parse','runtime','request','api','history','runner','exit','environment','result','evaluator'].map(id=>{const n=new Element();n.setAttribute('data-flow-node',id);return n;});
const edges=['request_api','history_request','result_history'].map(id=>{const e=new Element();e.setAttribute('data-flow-edge',id);return e;});
const document={getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:selector=>selector==='[data-flow-node]'?nodes:selector==='[data-flow-edge]'?edges:selector==='.event'?get('event-list').childNodes:[]};
"""
    record = json.dumps({"events": event_data})
    setup = f"get('record').textContent={json.dumps(record)};\n"
    checks = """
let selected=null,visible=[];
const episodeNames=new Map();
function jsonDetail(){}
const active=()=>nodes.filter(n=>n.classes.has('is-active')).map(n=>n.getAttribute('data-flow-node'));
initializeFlow(false);
assert.equal(get('flow-api-label').textContent,'Scripted response');
for(const event of [
  {event_type:'MODEL_RESPONSE',data:{status_code:503}},
  {event_type:'EPISODE_ENDED',data:{error_type:'RuntimeError'}},
  {event_type:'RUN_END',data:{status:'failed'}}
]) {
  assert.equal(hasError(event),true);
  assert.equal(flowLocation(event).tone,'error');
}
renderEvents();
assert.deepEqual(active(),['parse']);
get('event-list').childNodes[1].listeners.click();
assert.deepEqual(active(),['runtime']);
assert.equal(get('event-list').childNodes[1].attributes['aria-pressed'],'true');
get('search').value='no matching event';
renderEvents();
assert.deepEqual(active(),[]);
assert.equal(get('flow-selection').textContent,'No event selected');
updateFlow({event_type:'MODEL_ERROR',data:{}});
assert(nodes.filter(n=>n.classes.has('is-error')).length===3);
updateFlow({event_type:'UNKNOWN'});
assert.deepEqual(active(),[]);
assert(nodes.every(n=>!n.classes.has('is-error')));
"""
    run_js(adapters + setup + helpers + handlers + checks)
