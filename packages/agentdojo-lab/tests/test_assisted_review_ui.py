"""Static UI checks and pure helper tests; no browser rendering is claimed."""

import json
import shutil
import subprocess
from html.parser import HTMLParser
from importlib.resources import files

import pytest

from agentdojo_lab.html_report import _escaped_json


class Page(HTMLParser):
    def __init__(self, value):
        super().__init__(convert_charrefs=False)
        self.tags, self.scripts, self.active = [], [], None
        self.feed(value)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self.active = {"attrs": attrs, "text": ""}
            self.scripts.append(self.active)

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = None

    def handle_data(self, value):
        if self.active is not None:
            self.active["text"] += value


@pytest.fixture
def report():
    marker = '</script><script>alert("fixture")</script><img src=x onerror="fixture()">\u2028'
    data = {
        "schema_version": 1,
        "method": "ai_assisted_source_review_v1",
        "packet": {"packet_digest": "synthetic-packet"},
        "authorship": {
            "project_owner": "Donglin Yu",
            "annotation_author": "Codex",
            "mode": "ai_assisted",
            "labels_human_authored": False,
            "independence_attested": False,
        },
        "rubric": ["Visible support is not causal proof."],
        "items": [
            {
                "item_id": "synthetic-item",
                "target": {"argument_path": "/content", "value": marker},
            }
        ],
        "answers": [
            {
                "item_id": "synthetic-item",
                "verdict": "ambiguous",
                "selected_source_ids": [],
                "rationale": "Partial evidence. More detailed reasoning follows.",
                "evidence_locators": [],
            }
        ],
    }
    template = files("agentdojo_lab").joinpath("assisted_review_template.html").read_text()
    page = Page(template.replace("__NONCE__", "test-nonce").replace("__PAYLOAD__", _escaped_json(data)))
    return data, page


def test_report_keeps_untrusted_content_inert_and_reasoning_collapsed(report):
    data, page = report
    assert len(page.scripts) == 2
    assert json.loads(page.scripts[0]["text"]) == data
    assert not any(tag in {"img", "iframe", "form"} for tag, _ in page.tags)
    assert not any(name.startswith("on") for _, attrs in page.tags for name in attrs)
    assert all("src" not in attrs for _, attrs in page.tags)
    assert all(script["attrs"]["nonce"] == "test-nonce" for script in page.scripts)
    details = [attrs for tag, attrs in page.tags if tag == "details"]
    assert details and all("open" not in attrs for attrs in details)
    assert any(attrs.get("id") == "reasoning-section" for attrs in details)
    assert any(attrs.get("id") == "provenance-section" for attrs in details)
    code = page.scripts[1]["text"]
    assert not any(
        token in code for token in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "fetch(")
    )
    assert "new Blob" in code and "URL.createObjectURL" in code
    assert "localStorage" in code and "packet.packet_digest" in code
    assert "try{" in code and "catch(error)" in code


def test_helpers_preserve_assisted_authorship_and_isolate_imported_notes(report):
    data, page = report
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable for static script and helper validation")
    code = page.scripts[1]["text"]
    syntax = subprocess.run([node, "--check"], input=code, text=True, capture_output=True)
    assert syntax.returncode == 0, syntax.stderr
    program = (
        code.split("// DOM rendering begins here.")[0]
        + "\nconst assert=require('node:assert/strict');\nconst fixture="
        + json.dumps(data)
        + ";\n"
        + """
        const original=JSON.stringify(fixture);
        const exported=AssistedReview.annotations(fixture);
        assert.equal(exported.authorship.project_owner,'Donglin Yu');
        assert.equal(exported.authorship.annotation_author,'Codex');
        assert.equal(exported.authorship.labels_human_authored,false);
        assert.equal(exported.authorship.independence_attested,false);
        assert.equal(Object.hasOwn(exported,'items'),false);
        exported.authorship.labels_human_authored=true;
        assert.equal(fixture.authorship.labels_human_authored,false);
        for(const field of ['labels_human_authored','independence_attested']){
          const forged=JSON.parse(original);forged.authorship[field]=true;
          assert.throws(()=>AssistedReview.annotations(forged),/provenance/);
        }
        const notes=AssistedReview.notesDocument(fixture,{'synthetic-item':'A local note.'});
        assert.equal(AssistedReview.readNotes(fixture,notes)['synthetic-item'],'A local note.');
        const key=AssistedReview.notesStorageKey(fixture);
        const otherOwner={...fixture,authorship:{...fixture.authorship,project_owner:'Another owner'}};
        const otherPacket={...fixture,packet:{...fixture.packet,packet_digest:'another-packet'}};
        assert.notEqual(key,AssistedReview.notesStorageKey(otherOwner));
        assert.notEqual(key,AssistedReview.notesStorageKey(otherPacket));
        assert.notEqual(key,'agentdojo:ai-assisted-notes:v1:'+fixture.packet.packet_digest);
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,packet_digest:'another-packet'}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,project_owner:'Another owner'}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,answers:fixture.answers}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,authorship:exported.authorship}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,notes_by_item:{unknown:'Bad'}}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,notes_by_item:{'synthetic-item':{verdict:'single'}}}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,notes_by_item:{'synthetic-item':'x'.repeat(20001)}}));
        assert.throws(()=>AssistedReview.readNotes(fixture,{...notes,notes_by_item:null}));
        assert.equal(JSON.stringify(fixture),original);
        assert.equal(AssistedReview.quote({text:'A😀BC'},{start:1,end:3}),'😀B');
        assert.equal(AssistedReview.quote({text:'AB'},{start:0,end:3}),null);
        assert.equal(AssistedReview.rationalePreview('First sentence. More detail.'),'First sentence.');
        assert.ok(AssistedReview.rationalePreview('word '.repeat(100)).length<=240);
        assert.deepEqual(AssistedReview.counts(fixture),{completed:1,total:1,verdicts:{ambiguous:1}});
        """
    )
    result = subprocess.run([node], input=program, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
