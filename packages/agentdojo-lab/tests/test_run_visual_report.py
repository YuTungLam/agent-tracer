"""Evidence-preserving helpers used by the graphical single-run inspector."""

import shutil
import subprocess
from importlib.resources import files

import pytest


def test_visual_event_identifiers_sources_and_state_changes():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional for report JavaScript behavior checks")
    template = files("agentdojo_lab").joinpath("templates/run_report.html").read_text()
    functions = template.split("function shortEventId(event){", 1)[1].split(
        "function lineageTimelineEventId", 1
    )[0]
    functions = "function shortEventId(event){" + functions
    functions = functions.split("$('journey-toggle').addEventListener", 1)[0]
    prelude = r"""
const assert = require('node:assert/strict');
const asArray=value=>Array.isArray(value)?value:[];
const pretty=value=>typeof value==='string'?value:JSON.stringify(value,null,2);
const words=value=>String(value).replaceAll('_',' ');
const hasError=event=>!!event.data?.error;
const eventLabel=event=>event.event_type || 'Unknown event';
const manifest={case_a:{condition:'attacked'}};
const events=[
 {episode_id:'one',call_ref:'same',data:{function:'expected_tool'}},
 {episode_id:'two',call_ref:'same',data:{function:'unrelated_tool'}}
];
"""
    checks = r"""
assert.equal(shortEventId({event_id:'event:00000034',event_sequence:26}),'34');
assert.equal(shortEventId({event_sequence:0}),'0');
assert.equal(shortEventId({}),'?');
assert.equal(toolFor({episode_id:'one',call_ref:'same'}),'expected_tool');
assert.equal(toolFor({episode_id:'missing',call_ref:'same'}),'');
assert.equal(eventTone({event_type:7}),'#245779');
assert.equal(sourceCondition(),'attacked');
assert.equal(readableValue(undefined),'Not recorded');
assert.equal(readableValue(null),'null');
assert.deepEqual(stateDifferences({a:1},{a:1}),[]);
assert.deepEqual(stateDifferences({a:1},{a:2}),[{path:'/a',before:1,after:2}]);
assert.deepEqual(stateDifferences({},{new:null}),
 [{path:'/new',before:undefined,after:null}]);
const after=Object.fromEntries(Array.from({length:50},(_,i)=>['k'+i,i]));
assert.equal(stateDifferences({},after).length,18);
assert.deepEqual(stateDifferences({x:[1]},{x:[1,2]}),
 [{path:'/x',before:[1],after:[1,2]}]);
"""
    result = subprocess.run(
        [node], input=prelude + functions + checks, text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr
