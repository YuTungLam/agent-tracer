"""Synthetic validation of assisted provenance and preserved packet boundaries."""

import copy
import json

import pytest
from test_evaluation_review import source_run

from agentdojo_lab.assisted_review import export_assisted_review, validate_assisted_review
from agentdojo_lab.evaluation_review import export_review_packet, validate_review_labels


@pytest.fixture
def assisted(tmp_path):
    run = source_run(tmp_path, marker="A visible reference with an emoji: 🧪 </script><script>bad()</script>")
    packet = tmp_path / "packet"
    export_review_packet([run], packet)
    items = [json.loads(line) for line in (packet / "items.jsonl").read_text().splitlines()]
    answers = []
    for item in items:
        source = item["source_options"][-1]
        answers.append(
            {
                "item_id": item["item_id"],
                "verdict": "single",
                "selected_source_ids": [source["source_id"]],
                "rationale": "Synthetic validation example; not an experimental reference label.",
                "evidence_locators": [
                    {"source_id": source["source_id"], "start": 0, "end": len(source["text"])}
                ],
            }
        )
    path = tmp_path / "answers.json"
    path.write_text(json.dumps(list(reversed(answers))))
    return packet, path, items


def test_export_preserves_packet_separates_authorship_and_keeps_english(assisted, tmp_path):
    packet, answers, items = assisted
    before = {p.name: p.read_bytes() for p in packet.iterdir()}
    output = tmp_path / "assisted"
    result = export_assisted_review(packet, answers, "Donglin Yu", output)
    labels = json.loads((output / "assisted-labels.json").read_text())
    assert result["complete"] and result["answered_count"] == 2 and result["model_calls"] == 0
    assert result["authorship"]["project_owner"] == "Donglin Yu"
    assert result["authorship"]["annotation_author"] == "Codex"
    assert result["independent_reference"] is False and result["attribution_accuracy"] is None
    assert [a["item_id"] for a in labels["answers"]] == [item["item_id"] for item in items]
    assert validate_assisted_review(packet, labels)["valid"]
    assert not validate_review_labels(packet, output / "assisted-labels.json")["valid"]
    assert before == {p.name: p.read_bytes() for p in packet.iterdir()}
    page = (output / "review.html").read_text()
    assert "</script><script>bad()" not in page
    assert "__PAYLOAD__" not in page and "__NONCE__" not in page
    rows = [json.loads(line) for line in (output / "assisted-labels.jsonl").read_text().splitlines()]
    assert all(row["authorship"]["labels_human_authored"] is False for row in rows)
    with pytest.raises(FileExistsError):
        export_assisted_review(packet, answers, "Donglin Yu", output)
    with pytest.raises(ValueError, match="outside"):
        export_assisted_review(packet, answers, "Donglin Yu", packet / "nested")


def test_public_only_export_does_not_need_private_map(assisted, tmp_path):
    packet, answers, _ = assisted
    (packet / "review-key.json").unlink()
    assert export_assisted_review(packet, answers, "Donglin Yu", tmp_path / "public-only")["valid"]


@pytest.mark.parametrize(
    "mutation",
    ["human", "independent", "missing", "duplicate", "foreign_source", "span", "no_evidence", "rubric"],
)
def test_assisted_contract_rejects_false_authorship_and_bad_evidence(assisted, tmp_path, mutation):
    packet, answers, _ = assisted
    output = tmp_path / "assisted"
    export_assisted_review(packet, answers, "Donglin Yu", output)
    labels = json.loads((output / "assisted-labels.json").read_text())
    if mutation == "human":
        labels["authorship"]["labels_human_authored"] = True
    elif mutation == "independent":
        labels["authorship"]["independence_attested"] = True
    elif mutation == "missing":
        labels["answers"].pop()
    elif mutation == "duplicate":
        labels["answers"][1] = copy.deepcopy(labels["answers"][0])
    elif mutation == "foreign_source":
        labels["answers"][0]["selected_source_ids"] = ["not_in_this_item"]
    elif mutation == "span":
        labels["answers"][0]["evidence_locators"][0]["end"] = 10**6
    elif mutation == "no_evidence":
        labels["answers"][0]["evidence_locators"] = []
    else:
        labels["rubric"] = ["Pretend these are independent labels."]
    with pytest.raises(ValueError):
        validate_assisted_review(packet, labels)


def test_modified_packet_rejected_before_writing_output(assisted, tmp_path):
    packet, answers, _ = assisted
    with (packet / "items.jsonl").open("a") as stream:
        stream.write("{}\n")
    output = tmp_path / "bad-output"
    with pytest.raises(ValueError):
        export_assisted_review(packet, answers, "Donglin Yu", output)
    assert not output.exists()
