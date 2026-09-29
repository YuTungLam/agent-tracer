"""Execute visual report helpers against saved-data shapes without a browser."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def run_helpers(checks, *, dataset=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable; visual helper checks require JavaScript")
    path = Path(__file__).resolve().parents[1] / "src/agentdojo_lab/templates/paired_report.js"
    source = path.read_text(encoding="utf-8")
    marker = "\n$('event-filter').addEventListener"
    assert marker in source, "The helper boundary changed; update the test harness"
    helpers = source.split(marker, 1)[0]
    dataset = dataset or {"arms": [{"events": []}, {"events": []}], "rows": []}
    harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
class Element {
 constructor(tag='div') {this.tagName=tag;this.attrs={};this.children=[];this.textContent='';this.innerHTML='';this.value='';this.hidden=false;}
 setAttribute(key,value) {this.attrs[key]=String(value);}
 append(...nodes) {this.children.push(...nodes);}
 replaceChildren(...nodes) {this.children=[...nodes];}
 addEventListener() {}
 querySelectorAll() {return [];}
}
const elements=new Map();
const element=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const context=vm.createContext({
 assert, element,
 document:{getElementById:element,createElementNS:(_,tag)=>new Element(tag)},
});
element('paired-event-data').textContent=JSON.stringify(DATASET);
element('event-filter').value='all';
vm.runInContext(HELPERS,context,{timeout:5000});
vm.runInContext(CHECKS,context,{timeout:5000});
"""
    program = (
        "const DATASET=" + json.dumps(dataset) + ";\n"
        "const HELPERS=" + json.dumps(helpers) + ";\n"
        "const CHECKS=" + json.dumps(checks) + ";\n" + harness
    )
    result = subprocess.run([node], input=program, text=True, capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr


def test_token_highlights_keep_html_like_evidence_inert_in_both_diff_paths():
    run_helpers(r"""
const attack='</script><img src=x onerror="throw new Error(1)"> & text';
for(const [left,right] of [
 ['Original text',attack],
 [attack,attack],
 [Array.from({length:650},(_,i)=>'left'+i).join(' '),Array.from({length:650},(_,i)=>'right'+i).join(' ')+' '+attack],
]){
 const rendered=tokenDiff(left,right);
 for(const html of rendered){
  assert(!/<(?:img|script)\b/i.test(html),html);
  assert(!/<\/(?:script|option)>/i.test(html),html);
 }
 assert(rendered[1].includes('&lt;'));
 assert(rendered[1].includes('&amp;'));
}
const changed=tokenDiff('keep old end','keep new end');
assert.equal(changed[0],'keep <mark>old</mark> end');
assert.equal(changed[1],'keep <mark>new</mark> end');
""")


def test_missing_null_and_json_types_remain_distinct_in_fields_and_flattening():
    run_helpers(r"""
const removed=fieldHtml({path:'/value',before_present:true,after_present:false,before:null,after:null,kind:'removed'});
assert(removed.includes('<mark>null</mark>'));
assert.equal((removed.match(/Not present/g)||[]).length,1);
const typed=fieldHtml({path:'/value',before_present:true,after_present:true,before:true,after:1,kind:'changed'});
assert(typed.includes('Type changed: boolean → number'));
assert(typed.includes('<mark>true</mark>')&&typed.includes('<mark>1</mark>'));
const textual=fieldHtml({path:'/value',before_present:true,after_present:true,before:'1',after:1,kind:'changed'});
assert(textual.includes('Type changed: string → number'));
const values=flatten({'a/b':{'~key':null},'empty-list':[],'empty-object':{},flag:false});
assert(values.has('/a~1b/~0key'));
assert.equal(values.get('/a~1b/~0key'),null);
assert(!values.has('/missing'));
assert.equal(values.get('/flag'),false);
assert.notEqual(JSON.stringify(values.get('/empty-list')),JSON.stringify(values.get('/empty-object')));
const escaped=fieldHtml({path:'/<img src=x>',before_present:true,after_present:true,before:'safe',after:'<script>bad</script>',kind:'changed'});
assert(!escaped.includes('<img')&&!escaped.includes('<script>'));
""")


def test_sources_pair_by_aligned_exposure_rows_with_reordering_and_missing_values():
    rows = [
        {"index": 0, "clean_event_id": "exposure:a", "attacked_event_id": "exposure:renamed-a"},
        {"index": 1, "clean_event_id": "exposure:b", "attacked_event_id": None},
        {"index": 2, "clean_event_id": "exposure:c", "attacked_event_id": "exposure:renamed-c"},
        {"index": 3, "clean_event_id": None, "attacked_event_id": "exposure:d"},
    ]
    run_helpers(
        r"""
const source=(id,content)=>({exposure_event_id:id,source_result_event_id:'shared-result',content});
const paired=pairSources([
 {sources:[source('exposure:a','A'),source('exposure:b','B'),source('exposure:c','C')]},
 {sources:[source('exposure:renamed-c','Changed C'),source('exposure:renamed-a','A'),source('exposure:d','D')]},
]);
assert.equal(paired.length,4);
assert(paired.some(([a,b])=>a?.content==='A'&&b?.content==='A'));
assert(paired.some(([a,b])=>a?.content==='B'&&b===null));
assert(paired.some(([a,b])=>a?.content==='C'&&b?.content==='Changed C'));
assert(paired.some(([a,b])=>a===null&&b?.content==='D'));
assert.equal(paired.flat().filter(Boolean).length,6);
const unknown=pairSources([{sources:[source('not-recorded','left')]},{sources:[source('not-recorded','right')]}]);
assert.equal(unknown.length,2);
assert(unknown.every(pair=>pair.filter(Boolean).length===1));
""",
        dataset={"arms": [{"events": []}, {"events": []}], "rows": rows},
    )


def test_graph_labels_use_event_ids_and_node_text_preserves_escaped_content():
    def event(identifier):
        return {
            "event_id": identifier,
            "event_sequence": 29,
            "event_type": "TOOL_CALL_PROPOSED",
            "title": "Propose send_email",
            "summary": "Saved proposal",
            "data": {"arguments": {"recipients": ["user@example.com"], "attachments": [{"file_id": "19"}]}},
        }

    dataset = {
        "arms": [{"events": [event("event:00000037")]}, {"events": [event("event:00000092")]}],
        "rows": [
            {
                "index": 0,
                "clean_index": 0,
                "attacked_index": 0,
                "title": "Propose send_email",
                "changed": False,
            }
        ],
    }
    run_helpers(
        r"""
drawGraph();
const texts=[];
function collect(node){if(node.textContent)texts.push(node.textContent);for(const child of node.children)collect(child);}
collect(element('event-graph'));
assert(texts.includes('EVENT 37'));
assert(texts.includes('EVENT 92'));
assert(!texts.includes('EVENT 29'));
assert.equal(eventSummary(data.arms[0].events[0]),'To user@example.com · 1 attachment');
const model={comparison_data:{body:{choices:[{message:{tool_calls:[{function:{arguments:{recipients:['other@example.com']}}}]}}]}},data:{},summary:'Raw response'};
assert.equal(eventSummary(model),'To other@example.com');
""",
        dataset=dataset,
    )


def test_source_selector_treats_unresolved_html_like_ids_as_text():
    identifier = '</option><img src=x onerror="throw new Error(1)">'
    source = {
        "source_result_event_id": identifier,
        "exposure_event_id": "unresolved-exposure",
        "content": "Saved output",
        "function": "<script>tool label</script>",
    }
    event = {"event_type": "TOOL_CALL_PROPOSED", "sources": [source]}
    dataset = {
        "arms": [{"events": [event]}, {"events": []}],
        "rows": [{"index": 0, "clean_index": 0, "attacked_index": None}],
        "first_security_row": 0,
    }
    run_helpers(
        r"""
setupOverviewSources();
const html=element('overview-source').innerHTML;
assert(!/<(?:img|script)\b/i.test(html),html);
assert(html.includes('&lt;img'));
assert(html.includes('&lt;script&gt;tool label&lt;/script&gt;'));
""",
        dataset=dataset,
    )
