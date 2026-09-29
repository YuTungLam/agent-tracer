"""Synthetic agreement cases, never treated as empirical reference labels."""

import copy
import json

import pytest
from test_evaluation_review import native_call

from agentdojo_lab.assisted_review import export_assisted_review
from agentdojo_lab.assisted_scoring import _collapse, _decision, _pointer, score_assisted_review
from agentdojo_lab.evaluation_review import _canonical, _sha, export_review_packet


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n")


def fixture(tmp_path, *, repeated=False, full=(True,), uncertain=True, malformed=False):
    run = tmp_path / "run"
    run.mkdir()
    call = native_call("filename: team.docx\nid_: '3'\ncontent: Existing activity")
    call["arguments"] = {"file_id": "3", "content": "A new activity"}
    call["fields"] = [
        {
            "item_id": name,
            "argument_path": "/" + name,
            "value": value,
            "cascade_scope": {"sink": {"selected": True}},
            "nt_style_cascade": [],
        }
        for name, value in call["arguments"].items()
    ]
    if repeated:
        call["request_messages"].append(copy.deepcopy(call["request_messages"][-1]))
        again = copy.deepcopy(call["visible_sources"][-1])
        again.update(message_index=4, request_pointer="/data/body/messages/4/content")
        call["visible_sources"].append(again)
    for source in call["visible_sources"]:
        source["text_sha256"] = _sha(source["text"].encode())
    for field in call["fields"]:
        for index, source in enumerate(
            source for source in call["visible_sources"] if source["kind"] == "tool"
        ):
            prediction = full[index]
            field["nt_style_cascade"].append(
                {
                    "source_id": source["source_id"],
                    "request_pointer": source["request_pointer"],
                    "status": "scored" if prediction is not None else "encoder_error",
                    "matched": prediction,
                    "complete": prediction is not None,
                    "truncated": False,
                }
            )
    write(run / "manifest.json", {"config": {}})
    write(run / "summary.json", {})
    write(
        run / "provenance.jsonl",
        {"record_type": "call_analysis", "call_ref": "PRIVATE_CALL_REF", "call": call},
    )
    if malformed:
        with (run / "provenance.jsonl").open("a") as stream:
            stream.write('{"partial":')
    packet = tmp_path / "packet"
    export_review_packet([run], packet)
    items = [json.loads(line) for line in (packet / "items.jsonl").read_text().splitlines()]
    answers = []
    for item in items:
        source = next(source for source in item["source_options"] if source["kind"] == "tool")
        answers.append(
            {
                "item_id": item["item_id"],
                "verdict": "ambiguous"
                if uncertain and item["target"]["argument_path"] == "/content"
                else "single",
                "selected_source_ids": [source["source_id"]],
                "rationale": "Synthetic explanation <script>bad()</script>.",
                "evidence_locators": [{"source_id": source["source_id"], "start": 0, "end": 5}],
            }
        )
    answers_path = tmp_path / "answers.json"
    write(answers_path, answers)
    assisted = tmp_path / "assisted"
    export_assisted_review(packet, answers_path, "Synthetic owner", assisted)
    return run, packet, assisted / "assisted-labels.json"


def rebind_packet(packet, labels):
    """Recompute envelope checksums to test deeper structural binding, not authenticity."""
    meta = json.loads((packet / "packet.json").read_text())
    key = json.loads((packet / "review-key.json").read_text())
    items_raw = (packet / "items.jsonl").read_bytes()
    meta["items_sha256"] = key["items_sha256"] = _sha(items_raw)
    key.pop("packet_digest", None)
    meta["identity_map_sha256"] = _sha(_canonical(key))
    meta.pop("packet_digest", None)
    meta["packet_digest"] = _sha(_canonical(meta))
    key["packet_digest"] = meta["packet_digest"]
    write(packet / "packet.json", meta)
    write(packet / "review-key.json", key)
    envelope = json.loads(labels.read_text())
    envelope["packet"] = meta
    write(labels, envelope)


def test_complete_assisted_agreement_preserves_inputs_and_excludes_ambiguity(tmp_path):
    run, packet, labels = fixture(tmp_path)
    before = {p: p.read_bytes() for directory in (run, packet) for p in directory.iterdir()}
    result = score_assisted_review(packet, labels, tmp_path / "score")
    assert result["model_calls"] == 0 and result["input_files_unchanged"]
    assert result["coverage"]["definitive_items"] == 1
    assert result["coverage"]["ambiguous_items"] == 1
    assert result["coverage"]["policy_excluded_source_pairs"] == 6
    for method in result["methods"].values():
        assert method["eligible_source_pairs"] == 2
        assert method["comparable_pairs"] == 1 and method["agreement_pairs"] == 1
        assert method["ambiguous_or_unjudgeable_pairs"] == 1 and method["negative_reference_pairs"] == 0
        assert method["assisted_agreement_rate"] == 1.0
    assert result["independent_attribution_metrics"] == {"precision": None, "recall": None, "f1": None}
    assert result["independent_reference"] is False and result["authorship"]["labels_human_authored"] is False
    assert before == {p: p.read_bytes() for p in before}
    assert _sha(labels.read_bytes()) == result["input_sha256_before"][str(labels)]
    page = (tmp_path / "score/index.html").read_text()
    assert "<script>bad()</script>" not in page and "&lt;script&gt;bad()&lt;/script&gt;" in page
    assert "filename: team.docx" not in page and "<details>" in page


@pytest.mark.parametrize(
    "full,expected", [((False, False), False), ((None, True), True), ((False, None), None)]
)
def test_repeated_occurrences_collapse_conservatively(tmp_path, full, expected):
    _, packet, labels = fixture(tmp_path, repeated=True, full=full)
    result = score_assisted_review(packet, labels, tmp_path / "score")
    for item in result["items"]:
        pairs = item["methods"]["saved_full_cascade"]
        assert len(pairs) == 1 and pairs[0]["occurrence_count"] == 2
        assert pairs[0]["prediction"] is expected
    assert result["methods"]["saved_full_cascade"]["eligible_source_pairs"] == 2


def test_partial_source_preserves_unknown_without_false_negative(tmp_path):
    run, packet, labels = fixture(tmp_path, malformed=True, full=(None,))
    result = score_assisted_review(packet, labels, tmp_path / "score")
    counts = result["methods"]["saved_full_cascade"]
    assert counts["unknown_prediction_pairs"] == 2 and counts["comparable_pairs"] == 0
    assert counts["assisted_agreement_rate"] is None
    assert result["methods"]["exact"]["comparable_pairs"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "label_span",
        "foreign_source",
        "item_id",
        "private_hash",
        "source_hash",
        "artifact_path",
        "run_path",
        "target",
        "source_text",
        "source_pointer",
    ],
)
def test_invalid_binding_rejected_before_output(tmp_path, mutation):
    run, packet, labels = fixture(tmp_path)
    if mutation in {"label_span", "foreign_source", "item_id"}:
        value = json.loads(labels.read_text())
        answer = value["answers"][0]
        if mutation == "label_span":
            answer["evidence_locators"][0]["end"] = 10**6
        elif mutation == "foreign_source":
            answer["selected_source_ids"] = ["foreign"]
        else:
            answer["item_id"] = "item_missing"
        write(labels, value)
    elif mutation in {"private_hash", "artifact_path", "run_path"}:
        value = json.loads((packet / "review-key.json").read_text())
        if mutation == "private_hash":
            next(iter(value["items"].values()))["run_id"] = "fake"
        elif mutation == "artifact_path":
            value["source_runs"][0]["source_artifact_sha256"]["../answers.json"] = "fake"
        else:
            value["source_runs"][0]["run_path"] = "relative/path"
        write(packet / "review-key.json", value)
        if mutation != "private_hash":
            rebind_packet(packet, labels)
    elif mutation == "source_hash":
        write(run / "summary.json", {"altered": True})
    else:
        items = [json.loads(line) for line in (packet / "items.jsonl").read_text().splitlines()]
        if mutation == "target":
            items[0]["target"]["value"] = "wrong"
        elif mutation == "source_text":
            items[0]["source_options"][-1]["text"] += " changed"
        else:
            items[0]["source_options"][-1]["request_pointer"] = "/data/body/messages/0/content"
        (packet / "items.jsonl").write_bytes(b"".join(_canonical(item) + b"\n" for item in items))
        rebind_packet(packet, labels)
    with pytest.raises(ValueError):
        score_assisted_review(packet, labels, tmp_path / "score")
    assert not (tmp_path / "score").exists()


def test_protected_output_and_symlinks_rejected(tmp_path):
    run, packet, labels = fixture(tmp_path)
    for output in (run / "nested", packet / "nested", labels.parent):
        with pytest.raises((ValueError, FileExistsError)):
            score_assisted_review(packet, labels, output)
    link = tmp_path / "labels-link.json"
    link.symlink_to(labels)
    with pytest.raises(ValueError, match="symlink"):
        score_assisted_review(packet, link, tmp_path / "score")


def test_decision_and_pointer_unknowns_are_explicit():
    assert (
        _decision(
            {"status": "scored", "matched": True, "complete": False, "truncated": False}, "saved_full_cascade"
        )
        is None
    )
    assert _collapse([]) is None
    assert _collapse([False, None]) is None
    assert _collapse([None, True]) is True
    assert _pointer({"a/b": {"~key": [3]}}, "/a~1b/~0key/0") == 3
    for pointer in ("a", "/~", "/~2", "/a~1b/~0key/00", "/missing"):
        with pytest.raises(ValueError):
            _pointer({"a/b": {"~key": [3]}}, pointer)


def test_negative_and_unjudgeable_reference_denominators_are_separate(tmp_path):
    _, packet, labels = fixture(tmp_path, full=(False,))
    envelope = json.loads(labels.read_text())
    items = {
        item["item_id"]: item for item in map(json.loads, (packet / "items.jsonl").read_text().splitlines())
    }
    for answer in envelope["answers"]:
        is_id = items[answer["item_id"]]["target"]["argument_path"] == "/file_id"
        answer.update(
            verdict="no_visible_source" if is_id else "unjudgeable",
            selected_source_ids=[],
            evidence_locators=[],
        )
    write(labels, envelope)
    result = score_assisted_review(packet, labels, tmp_path / "score")
    assert result["coverage"]["unjudgeable_items"] == 1
    counts = result["methods"]["saved_full_cascade"]
    assert counts["negative_reference_pairs"] == 1 and counts["positive_reference_pairs"] == 0
    assert counts["comparable_pairs"] == 1 and counts["agreement_pairs"] == 1
    assert result["methods"]["exact"]["disagreement_pairs"] == 1


def test_post_join_source_mutation_aborts_without_report(tmp_path, monkeypatch):
    from agentdojo_lab import assisted_scoring

    run, packet, labels = fixture(tmp_path)
    original = assisted_scoring.analyze_trace_ablation

    def mutate(path):
        result = original(path)
        write(run / "summary.json", {"changed_during_analysis": True})
        return result

    monkeypatch.setattr(assisted_scoring, "analyze_trace_ablation", mutate)
    with pytest.raises(ValueError, match="changed during"):
        score_assisted_review(packet, labels, tmp_path / "score")
    assert not (tmp_path / "score").exists()


def test_private_identity_forgery_rehashed_still_fails_saved_binding(tmp_path):
    _, packet, labels = fixture(tmp_path)
    key = json.loads((packet / "review-key.json").read_text())
    next(iter(key["items"].values()))["original_field_item_id"] = "different_field"
    write(packet / "review-key.json", key)
    rebind_packet(packet, labels)
    with pytest.raises(ValueError, match="field identity"):
        score_assisted_review(packet, labels, tmp_path / "score")
