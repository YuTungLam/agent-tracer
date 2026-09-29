"""Synthetic packet/label validation only; these fixtures are not human annotations."""

import copy
import json
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from agentdojo_lab.evaluation_review import export_review_packet, validate_review_labels


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n")


def read(path):
    return json.loads(path.read_text())


def rows(path):
    return [json.loads(line) for line in path.read_text().split("\n") if line.strip()]


def native_call(marker="Tool reference note"):
    messages = [
        {"role": "system", "content": "Follow the user task."},
        {"role": "user", "content": "Save the reference in a note."},
        {
            "role": "assistant",
            "content": "Read the reference.",
            "tool_calls": [
                {
                    "id": "PRIVATE_PROVIDER_ID",
                    "type": "function",
                    "function": {"name": "get_file_by_id", "arguments": '{"file_id":"1"}'},
                }
            ],
        },
        {"role": "tool", "content": marker, "tool_call_id": "PRIVATE_PROVIDER_ID"},
    ]
    return {
        "run_id": "PRIVATE_RUN_ID",
        "proposal_event_id": "PRIVATE_PROPOSAL_ID",
        "episode_id": "PRIVATE_EPISODE_ID",
        "condition": "PRIVATE_CONDITION",
        "function": "create_file",
        "arguments": {"filename": "note.txt", "content": marker},
        "request_messages": messages,
        "policy": {"sink": {"selected": True}},
        "fields": [
            {
                "item_id": "PRIVATE_FIELD_" + name,
                "argument_path": "/" + name,
                "value": value,
                "cascade_scope": {"sink": {"selected": True}},
                "exact_candidates": [{"score": 0.999, "private_prediction": "PRIVATE_PREDICTION"}],
                "nt_style_cascade": [],
                "exact_status": "no_exact_evidence",
            }
            for name, value in (("filename", "note.txt"), ("content", marker))
        ],
        "visible_sources": [
            {
                "source_id": "PRIVATE_SOURCE_" + message["role"],
                "source_event_id": "PRIVATE_EVENT_" + str(index),
                "kind": message["role"],
                "text": message["content"],
                "message_index": index,
                "request_pointer": f"/data/body/messages/{index}/content",
                "policy": {"eligible": message["role"] == "tool"},
                "score": 0.999,
                "lineage": {"private_label": "PRIVATE_LABEL"},
            }
            for index, message in enumerate(messages)
        ],
    }


def source_run(tmp_path, *, marker="Tool reference note", partial=False, sink=True):
    run = tmp_path / "PRIVATE_TRIAL_CONDITION_REPEAT_MODEL"
    run.mkdir()
    call = native_call(marker)
    call["policy"]["sink"]["selected"] = sink
    write(
        run / "manifest.json",
        {"condition": "PRIVATE_ATTACK_LABEL", "model": "PRIVATE_MODEL", "attack_goal": "PRIVATE_GOAL"},
    )
    write(run / "summary.json", {"outcome": "PRIVATE_OUTCOME", "score": 0.99})
    raw = (
        json.dumps(
            {"record_type": "call_analysis", "call_ref": "PRIVATE_CALL_REF", "call": call}, ensure_ascii=False
        )
        + "\n"
    )
    if partial:
        raw += '{"record_type":"call_analysis","call":'
    (run / "provenance.jsonl").write_text(raw)
    return run


@pytest.fixture
def packet(tmp_path):
    run = source_run(tmp_path)
    output = tmp_path / "review"
    result = export_review_packet([run], output)
    return run, output, result


def submission(output):
    """Simulated test submission, never exported as a genuine human review."""
    labels = read(output / "labels-template.json")
    labels["reviewer"] = {
        "identifier": "Synthetic unit-test reviewer",
        "independence_attested": True,
        "labels_human_authored": True,
    }
    for answer in labels["answers"]:
        answer.update(
            verdict="unjudgeable",
            selected_source_ids=[],
            rationale="Synthetic validation fixture; not a human judgment.",
        )
    return labels


def check(output, value, tmp_path):
    path = tmp_path / "submitted-labels.json"
    write(path, value)
    return validate_review_labels(output, path)


def test_public_items_hide_metadata_but_include_every_visible_source(packet):
    run, output, exported = packet
    assert exported["item_count"] == 2 and exported["labels_prefilled"] is False
    public = rows(output / "items.jsonl")
    assert {item["target"]["argument_path"] for item in public} == {"/filename", "/content"}
    for item in public:
        assert {source["kind"] for source in item["source_options"]} == {
            "system",
            "user",
            "assistant",
            "tool",
        }
        assert [source["message_index"] for source in item["source_options"]] == [0, 1, 2, 3]
        assert item["request_prefix"][2]["tool_calls"][0]["id"] == "call_1"
        assert item["request_prefix"][3]["tool_call_id"] == "call_1"
        assert item["sink"]["arguments"]["content"] == "Tool reference note"
    for name in ("items.jsonl", "packet.json", "labels-template.json", "review.html"):
        text = (output / name).read_text()
        assert "PRIVATE_" not in text
        for key in ("exact_candidates", "nt_style_cascade", "true_labels", "attack_goal"):
            assert key not in text
    private = read(output / "review-key.json")
    assert "PRIVATE_RUN_ID" in json.dumps(private)
    assert (output / "review-key.json").stat().st_mode & 0o777 == 0o600
    for mapping in private["items"].values():
        assert mapping["run_path"] == str(run)
        assert sum(source["policy_eligible"] for source in mapping["source_options"].values()) == 1
        assert {source["source_id"] for source in mapping["source_options"].values()} == {
            "PRIVATE_SOURCE_" + kind for kind in ("system", "user", "assistant", "tool")
        }


def test_export_is_stable_blank_and_does_not_modify_sources(packet, tmp_path):
    run, output, _ = packet
    before = {path: path.read_bytes() for path in run.iterdir()}
    other = tmp_path / "second-review"
    export_review_packet([run], other)
    assert (output / "items.jsonl").read_bytes() == (other / "items.jsonl").read_bytes()
    assert read(output / "packet.json") == read(other / "packet.json")
    assert {path: path.read_bytes() for path in run.iterdir()} == before
    blank = read(output / "labels-template.json")
    assert all(value is None for value in blank["reviewer"].values())
    assert all(
        all(value is None for key, value in answer.items() if key != "item_id") for answer in blank["answers"]
    )
    validated = validate_review_labels(output, output / "labels-template.json")
    assert validated["submitted"] is False and validated["complete"] is False and validated["valid"] is False
    assert validated["answered_count"] == 0 and validated["independence_verified"] is False
    with pytest.raises(FileExistsError):
        export_review_packet([run], output)


def test_partial_log_keeps_completed_call_and_empty_packet_is_supported(tmp_path):
    run = source_run(tmp_path, partial=True)
    output = tmp_path / "partial-review"
    assert export_review_packet([run], output)["item_count"] == 2
    assert read(output / "review-key.json")["source_runs"][0]["unparsed_lines"] == 1
    second_root = tmp_path / "other"
    second_root.mkdir()
    nonsink = source_run(second_root, sink=False)
    empty = tmp_path / "empty-review"
    assert export_review_packet([nonsink], empty)["item_count"] == 0
    assert (empty / "items.jsonl").read_bytes() == b""
    assert read(empty / "labels-template.json")["answers"] == []
    assert validate_review_labels(empty, empty / "labels-template.json")["submitted"] is False
    declared = check(empty, submission(empty), tmp_path)
    assert declared["valid"] is True and declared["complete"] is False
    assert declared["empty_packet"] is True and declared["answered_count"] == 0


def test_repeated_occurrences_use_distinct_blinded_ids_but_verdicts_dedupe_origins(tmp_path):
    run = source_run(tmp_path)
    saved = rows(run / "provenance.jsonl")[0]
    call = saved["call"]
    call["request_messages"].append(copy.deepcopy(call["request_messages"][-1]))
    source = copy.deepcopy(call["visible_sources"][-1])
    source.update(message_index=4, request_pointer="/data/body/messages/4/content")
    call["visible_sources"].append(source)
    (run / "provenance.jsonl").write_text(json.dumps(saved) + "\n")
    output = tmp_path / "review"
    export_review_packet([run], output)
    item = rows(output / "items.jsonl")[0]
    tools = [source["source_id"] for source in item["source_options"] if source["kind"] == "tool"]
    assert len(tools) == len(set(tools)) == 2
    labels = submission(output)
    labels["answers"][0].update(verdict="single", selected_source_ids=tools)
    assert check(output, labels, tmp_path)["valid"] is True
    labels["answers"][0]["verdict"] = "multiple"
    assert check(output, labels, tmp_path)["valid"] is False


def test_submission_requires_complete_human_declarations_and_only_attests_independence(packet, tmp_path):
    _, output, _ = packet
    result = check(output, submission(output), tmp_path)
    assert result["valid"] is result["complete"] is result["submitted"] is True
    assert result["answered_count"] == 2
    assert result["independence_attested"] is True
    assert result["independence_verified"] is False and result["independence_status"] == "attested_only"
    assert not any(key in result for key in ("accuracy", "precision", "recall", "f1"))
    for declaration, invalid in (
        ("identifier", ""),
        ("identifier", "ChatGPT"),
        ("independence_attested", False),
        ("labels_human_authored", False),
    ):
        labels = submission(output)
        labels["reviewer"][declaration] = invalid
        assert check(output, labels, tmp_path)["valid"] is False


def test_exact_ids_digest_and_complete_item_set_are_required(packet, tmp_path):
    _, output, _ = packet
    for mutation in (
        "digest",
        "items_hash",
        "unknown_item",
        "duplicate_item",
        "missing_item",
        "foreign_source",
        "rationale",
        "prefill",
        "schema_bool",
    ):
        labels = submission(output)
        if mutation == "digest":
            labels["packet_digest"] = "wrong"
        elif mutation == "items_hash":
            labels["items_sha256"] = "wrong"
        elif mutation == "unknown_item":
            labels["answers"][0]["item_id"] = "unknown"
        elif mutation == "duplicate_item":
            labels["answers"][1] = copy.deepcopy(labels["answers"][0])
        elif mutation == "missing_item":
            labels["answers"].pop()
        elif mutation == "foreign_source":
            labels["answers"][0]["selected_source_ids"] = ["PRIVATE_SOURCE_tool"]
        elif mutation == "rationale":
            labels["answers"][0]["rationale"] = " "
        elif mutation == "prefill":
            labels["answers"][0]["confidence"] = 0.99
        else:
            labels["schema_version"] = True
        assert check(output, labels, tmp_path)["valid"] is False, mutation


def test_verdicts_and_optional_unicode_evidence_spans(packet, tmp_path):
    _, output, _ = packet
    labels = submission(output)
    first = rows(output / "items.jsonl")[0]
    source_ids = [source["source_id"] for source in first["source_options"]]
    answer = labels["answers"][0]
    answer.update(
        verdict="single",
        selected_source_ids=[source_ids[0]],
        evidence_locators=[{"source_id": source_ids[0], "start": 0, "end": 6}],
    )
    assert check(output, labels, tmp_path)["valid"] is True
    answer["evidence_locators"][0]["end"] = 100000
    assert check(output, labels, tmp_path)["valid"] is False
    answer["evidence_locators"] = [{"source_id": source_ids[0], "locator": "Opening instruction sentence"}]
    answer.update(verdict="multiple", selected_source_ids=source_ids[:2])
    assert check(output, labels, tmp_path)["valid"] is True
    answer.update(verdict="single")
    assert check(output, labels, tmp_path)["valid"] is False
    answer.update(verdict="no_visible_source", selected_source_ids=[])
    answer["evidence_locators"] = None
    assert check(output, labels, tmp_path)["valid"] is True
    answer["selected_source_ids"] = source_ids[:1]
    assert check(output, labels, tmp_path)["valid"] is False
    answer.update(verdict=["unjudgeable"], selected_source_ids=[])
    assert check(output, labels, tmp_path)["valid"] is False


def test_packet_or_private_mapping_tampering_is_rejected(packet, tmp_path):
    _, output, _ = packet
    labels = submission(output)
    original = (output / "review-key.json").read_bytes()
    private = read(output / "review-key.json")
    first = next(iter(private["items"].values()))
    next(iter(first["source_options"].values()))["policy_eligible"] = True
    write(output / "review-key.json", private)
    with pytest.raises(ValueError, match="digest"):
        check(output, labels, tmp_path)
    (output / "review-key.json").write_bytes(original)
    (output / "items.jsonl").write_bytes((output / "items.jsonl").read_bytes() + b"\n")
    with pytest.raises(ValueError, match="digest"):
        check(output, labels, tmp_path)


def test_output_and_input_symlinks_and_source_overwrite_are_rejected(packet, tmp_path):
    run, output, _ = packet
    with pytest.raises(ValueError, match="outside"):
        export_review_packet([run], run / "review")
    with pytest.raises(ValueError, match="Duplicate"):
        export_review_packet([run, run], tmp_path / "duplicate")
    link = tmp_path / "linked-run"
    link.symlink_to(run, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        export_review_packet([link], tmp_path / "linked-review")
    source_file = run / "provenance.jsonl"
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(source_file.read_bytes())
    source_file.unlink()
    source_file.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        export_review_packet([run], tmp_path / "linked-file-review")
    labels_link = tmp_path / "labels-link.json"
    labels_link.symlink_to(output / "labels-template.json")
    with pytest.raises(ValueError, match="symlink"):
        validate_review_labels(output, labels_link)


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


def test_html_is_inert_and_form_helpers_require_explicit_answers(tmp_path):
    marker = '</script><script>alert("fixture")</script><img src=x onerror="fixture()">\u2028\u2029'
    run = source_run(tmp_path, marker=marker)
    output = tmp_path / "review"
    export_review_packet([run], output)
    page = Page((output / "review.html").read_text())
    assert len(page.scripts) == 2
    assert not any(tag in {"img", "iframe", "a", "form"} for tag, _ in page.tags)
    assert not any(name.startswith("on") for _, attrs in page.tags for name in attrs)
    assert all("src" not in attrs for _, attrs in page.tags)
    data = json.loads(page.scripts[0]["text"])
    assert any(item["target"]["value"] == marker for item in data["items"])
    code = page.scripts[1]["text"]
    assert not any(
        word in code for word in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "fetch(")
    )
    assert "new Blob" in code and "URL.createObjectURL" in code
    assert "confidence" not in data["labels_template"]["answers"][0]
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable for static script validation")
    syntax = subprocess.run([node, "--check"], input=code, text=True, capture_output=True)
    assert syntax.returncode == 0, syntax.stderr
    program = (
        code.split("// DOM rendering begins here.")[0]
        + "\nconst assert=require('node:assert/strict');\nconst fixture="
        + json.dumps(data)
        + ";\n"
        + """
      const blank=fixture.labels_template.answers;
      assert.equal(ReviewForm.complete(fixture.items,blank),0);
      const empty=ReviewForm.submission(fixture.packet,fixture.items,blank,fixture.labels_template.reviewer);
      assert.ok(empty.errors.length>0);
      assert.deepEqual(empty.labels.answers,blank);
      const answers=blank.map(a=>({...a,verdict:'unjudgeable',selected_source_ids:[],rationale:'Synthetic unit-test response.'}));
      const reviewer={identifier:'Synthetic unit-test reviewer',independence_attested:true,labels_human_authored:true};
      assert.equal(ReviewForm.submission(fixture.packet,fixture.items,answers,reviewer).errors.length,0);
      assert.equal(ReviewForm.complete(fixture.items,answers),fixture.items.length);
      const changed={...answers[0],verdict:'no_visible_source',selected_source_ids:[fixture.items[0].source_options[0].source_id]};
      assert.ok(ReviewForm.answerErrors(fixture.items[0],changed).length>0);
    """
    )
    checked = subprocess.run([node], input=program, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr
