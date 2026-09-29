"""Blind, blank human evidence-review packets; no labels or metrics are inferred."""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
from importlib.resources import files
from pathlib import Path

from agentdojo_lab.html_report import _escaped_json

METHOD = "blind_source_evidence_review_v1"
VERDICTS = {"single", "multiple", "no_visible_source", "ambiguous", "unjudgeable"}
ANSWER_KEYS = {"item_id", "verdict", "selected_source_ids", "rationale", "evidence_locators"}
REVIEWER_KEYS = {"identifier", "independence_attested", "labels_human_authored"}


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _strict(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    def constant(_):
        raise ValueError("Non-finite JSON value")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def _local(path):
    path = Path(path).expanduser().absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Review inputs and outputs must not use symlinks")
    return path.resolve()


def _read(path):
    path = _local(path)
    if not path.is_file():
        raise ValueError("Expected a regular review input file")
    return path.read_bytes()


def _prefix(messages):
    """Keep observed content, replacing native call identifiers with local aliases."""
    if not isinstance(messages, list):
        raise ValueError("Selected call lacks its actual request prefix")
    aliases = {}

    def alias(value):
        if not isinstance(value, str):
            raise ValueError("Malformed native call identifier")
        return aliases.setdefault(value, f"call_{len(aliases) + 1}")

    result = []
    for message in messages:
        if not isinstance(message, dict) or not isinstance(message.get("role"), str):
            raise ValueError("Malformed request message")
        public = {"role": message["role"]}
        if "content" in message:
            public["content"] = copy.deepcopy(message["content"])
        if "tool_calls" in message and message["tool_calls"] is not None:
            public["tool_calls"] = []
            for call in message["tool_calls"]:
                function = call["function"]
                item = {
                    "type": call.get("type", "function"),
                    "function": {
                        key: copy.deepcopy(function[key]) for key in ("name", "arguments") if key in function
                    },
                }
                if "id" in call:
                    item["id"] = alias(call["id"])
                public["tool_calls"].append(item)
        if "tool_call_id" in message:
            public["tool_call_id"] = alias(message["tool_call_id"])
        if "name" in message:
            public["name"] = message["name"]
        result.append(public)
    return result


def export_review_packet(run_dirs: list[Path], output: Path) -> dict:
    """Export all recorded policy-selected sink fields, with no answer prefills."""
    output = _local(output)
    runs = [_local(path) for path in run_dirs]
    if len(set(runs)) != len(runs):
        raise ValueError("Duplicate review source run")
    if output.exists():
        raise FileExistsError("Review packet output already exists")
    if any(output.is_relative_to(run) or run.is_relative_to(output) for run in runs):
        raise ValueError("Review packet must be outside its source runs")
    items, mappings, sources = [], {}, []
    for run in runs:
        if not run.is_dir():
            raise ValueError("Source run directory does not exist")
        raw = _read(run / "provenance.jsonl")
        hashes = {"provenance.jsonl": _sha(raw)}
        for name in ("manifest.json", "summary.json", "events.jsonl"):
            path = run / name
            if path.exists() or path.is_symlink():
                hashes[name] = _sha(_read(path))
        malformed = 0
        for line in raw.split(b"\n"):
            if not line.strip():
                continue
            try:
                row = _strict(line)
            except (ValueError, UnicodeError):
                malformed += 1
                continue
            if not isinstance(row, dict) or row.get("record_type") != "call_analysis":
                continue
            call = row.get("call")
            if not isinstance(call, dict):
                raise ValueError("Malformed saved call analysis")
            if call.get("policy", {}).get("sink", {}).get("selected") is not True:
                continue
            if not isinstance(call.get("fields"), list) or not isinstance(call.get("visible_sources"), list):
                raise ValueError("Selected call lacks complete fields or source options")
            prefix = _prefix(call.get("request_messages"))
            for field in call.get("fields", []):
                if field.get("cascade_scope", {}).get("sink", {}).get("selected") is not True:
                    continue
                if "value" not in field:
                    raise ValueError("Selected field lacks its observed value")
                run_id, proposal, argument_path = (
                    call.get("run_id"),
                    call.get("proposal_event_id"),
                    field.get("argument_path"),
                )
                if not all(isinstance(value, str) for value in (run_id, proposal, argument_path)):
                    raise ValueError("Selected review field lacks stable identity")
                identity = [hashes, run_id, proposal, argument_path]
                item_id = "item_" + _sha(_canonical(identity))[:32]
                if item_id in mappings:
                    raise ValueError("Duplicate selected review item")
                options, source_map = [], {}
                for index, source in enumerate(call.get("visible_sources", [])):
                    if not isinstance(source, dict) or not isinstance(source.get("text"), str):
                        raise ValueError("Malformed visible source")
                    position = source.get("message_index")
                    if type(position) is not int or not 0 <= position < len(prefix):
                        raise ValueError("Visible source lacks an actual message position")
                    original_id = source.get("source_id")
                    if not isinstance(original_id, str):
                        raise ValueError("Visible source lacks identity")
                    blinded = "source_" + _sha(_canonical([item_id, original_id, index]))[:24]
                    options.append(
                        {
                            "source_id": blinded,
                            "kind": source.get("kind"),
                            "text": source["text"],
                            "message_index": position,
                            "request_pointer": source.get("request_pointer"),
                        }
                    )
                    source_map[blinded] = {
                        "source_id": original_id,
                        "source_event_id": source.get("source_event_id"),
                        "message_index": position,
                        "request_pointer": source.get("request_pointer"),
                        "policy_eligible": source.get("policy", {}).get("eligible") is True,
                    }
                item = {
                    "schema_version": 1,
                    "item_id": item_id,
                    "task": {"user_messages": [copy.deepcopy(m) for m in prefix if m["role"] == "user"]},
                    "request_prefix": prefix,
                    "sink": {
                        "function": call.get("function"),
                        "arguments": copy.deepcopy(call.get("arguments")),
                    },
                    "target": {"argument_path": argument_path, "value": copy.deepcopy(field.get("value"))},
                    "source_options": options,
                }
                items.append(item)
                mappings[item_id] = {
                    "run_path": str(run),
                    "run_id": run_id,
                    "proposal_event_id": proposal,
                    "episode_id": call.get("episode_id"),
                    "call_ref": row.get("call_ref"),
                    "argument_path": argument_path,
                    "original_field_item_id": field.get("item_id"),
                    "source_artifact_sha256": hashes,
                    "source_options": source_map,
                }
        sources.append({"run_path": str(run), "source_artifact_sha256": hashes, "unparsed_lines": malformed})
    items.sort(key=lambda item: item["item_id"])
    sources.sort(key=lambda source: source["run_path"])
    item_bytes = b"".join(_canonical(item) + b"\n" for item in items)
    private = {
        "schema_version": 1,
        "items_sha256": _sha(item_bytes),
        "item_count": len(items),
        "source_runs": sources,
        "items": mappings,
        "scope": "private_identity_mapping; do_not_distribute_to_reviewers",
    }
    packet = {
        "schema_version": 1,
        "method": METHOD,
        "item_count": len(items),
        "items_sha256": _sha(item_bytes),
        "selection": "all_recorded_policy_selected_sink_fields_regardless_of_prediction",
        "blinding": "partial; recorded_content_may_reveal_condition",
        "scope": "human_visible_evidence_attribution; not_causal_proof_or_maliciousness",
        "identity_map_sha256": _sha(_canonical(private)),
    }
    packet["packet_digest"] = _sha(_canonical(packet))
    blank = {
        "schema_version": 1,
        "packet_digest": packet["packet_digest"],
        "items_sha256": packet["items_sha256"],
        "reviewer": {"identifier": None, "independence_attested": None, "labels_human_authored": None},
        "answers": [
            {
                "item_id": item["item_id"],
                "verdict": None,
                "selected_source_ids": None,
                "rationale": None,
                "evidence_locators": None,
            }
            for item in items
        ],
    }
    private["packet_digest"] = packet["packet_digest"]
    template = files("agentdojo_lab").joinpath("templates/evaluation_review.html").read_text(encoding="utf-8")
    page = template.replace("@@NONCE@@", secrets.token_urlsafe(24)).replace(
        "@@RECORD@@", _escaped_json({"packet": packet, "items": items, "labels_template": blank})
    )
    output.mkdir(parents=True, exist_ok=False)
    (output / "items.jsonl").write_bytes(item_bytes)
    for name, value in (
        ("packet.json", packet),
        ("labels-template.json", blank),
        ("review-key.json", private),
    ):
        with (output / name).open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    (output / "review-key.json").chmod(0o600)
    with (output / "review.html").open("x", encoding="utf-8") as stream:
        stream.write(page)
    return {
        "status": "generated",
        "path": str(output),
        "manifest": packet,
        "item_count": len(items),
        "review_path": str(output / "review.html"),
        "labels_prefilled": False,
        "private_key_path": str(output / "review-key.json"),
    }


def validate_review_labels(packet_dir: Path, labels_path: Path) -> dict:
    """Validate submitted declarations and evidence IDs; independence is attested only."""
    directory = _local(packet_dir)
    packet = _strict(_read(directory / "packet.json"))
    private = _strict(_read(directory / "review-key.json"))
    if not isinstance(packet, dict) or not isinstance(private, dict):
        raise ValueError("Review packet metadata must be objects")
    item_bytes = _read(directory / "items.jsonl")
    items = [_strict(line) for line in item_bytes.split(b"\n") if line.strip()]
    expected = {item["item_id"]: item for item in items}
    base = {key: value for key, value in packet.items() if key != "packet_digest"}
    digest = _sha(_canonical(base))
    if (
        type(packet.get("schema_version")) is not int
        or packet.get("schema_version") != 1
        or packet.get("method") != METHOD
        or digest != packet.get("packet_digest")
        or digest != private.get("packet_digest")
        or _sha(item_bytes) != packet.get("items_sha256")
        or _sha(item_bytes) != private.get("items_sha256")
        or len(expected) != len(items)
        or len(items) != packet.get("item_count")
        or set(private.get("items", {})) != set(expected)
        or _sha(_canonical({k: v for k, v in private.items() if k != "packet_digest"}))
        != packet.get("identity_map_sha256")
    ):
        raise ValueError("Review packet digest or identity mismatch")
    label_bytes = _read(labels_path)
    labels = _strict(label_bytes)
    if not isinstance(labels, dict):
        raise ValueError("Review labels must be an object")
    errors = []
    if set(labels) != {"schema_version", "packet_digest", "items_sha256", "reviewer", "answers"}:
        errors.append("Unexpected or missing submission fields.")
    if (
        type(labels.get("schema_version")) is not int
        or labels.get("schema_version") != 1
        or labels.get("packet_digest") != digest
        or labels.get("items_sha256") != _sha(item_bytes)
    ):
        errors.append("Submission does not identify this exact packet.")
    reviewer = labels.get("reviewer") if isinstance(labels.get("reviewer"), dict) else {}
    identifier = reviewer.get("identifier")
    if set(reviewer) != REVIEWER_KEYS:
        errors.append("Reviewer declaration fields are invalid.")
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 200:
        errors.append("A human reviewer identifier is required.")
    elif identifier.strip().casefold() in {"assistant", "chatgpt", "gpt", "codex", "ai", "openai"}:
        errors.append("Automated or assistant authorship is not human review.")
    for key in ("independence_attested", "labels_human_authored"):
        if reviewer.get(key) is not True:
            errors.append(f"Reviewer must explicitly attest {key.replace('_', ' ')}.")
    answers = labels.get("answers")
    if not isinstance(answers, list):
        answers = []
        errors.append("Answers must be a list.")
    seen, answered = set(), 0
    for answer in answers:
        if not isinstance(answer, dict) or set(answer) != ANSWER_KEYS:
            errors.append("Invalid answer fields.")
            continue
        identity = answer.get("item_id")
        if not isinstance(identity, str) or identity not in expected or identity in seen:
            errors.append("Unknown or duplicate item identity.")
            continue
        seen.add(identity)
        prior = len(errors)
        verdict, selected = answer.get("verdict"), answer.get("selected_source_ids")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            errors.append("Every item requires an allowed verdict.")
        mapping = private["items"][identity]["source_options"]
        if not isinstance(selected, list) or any(
            not isinstance(s, str) or s not in mapping for s in selected
        ):
            errors.append("Selected source IDs must belong to this item.")
            selected = []
        elif len(set(selected)) != len(selected):
            errors.append("Duplicate selected source identity.")
        distinct = {mapping[s]["source_id"] for s in selected}
        if verdict == "single" and len(distinct) != 1:
            errors.append("Single-source verdict requires exactly one distinct recorded source.")
        if verdict == "multiple" and len(distinct) < 2:
            errors.append("Multiple-source verdict requires at least two distinct recorded sources.")
        if verdict == "no_visible_source" and selected:
            errors.append("No-visible-source verdict requires an empty source selection.")
        rationale = answer.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 20000:
            errors.append("Every item requires a written rationale.")
        locators = answer.get("evidence_locators")
        if locators is not None:
            if not isinstance(locators, list):
                errors.append("Evidence locators must be null or a list.")
            else:
                option_texts = {s["source_id"]: s["text"] for s in expected[identity]["source_options"]}
                for locator in locators:
                    if not isinstance(locator, dict) or not set(locator) <= {
                        "source_id",
                        "start",
                        "end",
                        "locator",
                    }:
                        errors.append("Invalid evidence locator.")
                        continue
                    source_id = locator.get("source_id")
                    if source_id not in selected:
                        errors.append("Evidence locator must refer to a selected source.")
                        continue
                    if "start" in locator or "end" in locator:
                        start, end = locator.get("start"), locator.get("end")
                        if (
                            type(start) is not int
                            or type(end) is not int
                            or not 0 <= start < end <= len(option_texts[source_id])
                        ):
                            errors.append("Evidence span is outside the visible source text.")
                    elif not isinstance(locator.get("locator"), str) or not locator["locator"].strip():
                        errors.append("Evidence locator requires a span or written location.")
        answered += len(errors) == prior
    if seen != set(expected):
        errors.append("Submission must answer exactly every packet item.")
    submitted = bool(identifier) or any(
        isinstance(answer, dict) and any(answer.get(k) is not None for k in ANSWER_KEYS - {"item_id"})
        for answer in answers
    )
    return {
        "schema_version": 1,
        "packet_digest": digest,
        "items_sha256": _sha(item_bytes),
        "labels_sha256": _sha(label_bytes),
        "submitted": submitted,
        "valid": not errors,
        "structurally_valid": not errors,
        "complete": bool(items) and not errors and answered == len(items),
        "item_count": len(items),
        "answered_count": answered,
        "reviewer_identifier": identifier,
        "independence_attested": reviewer.get("independence_attested") is True,
        "human_authorship_attested": reviewer.get("labels_human_authored") is True,
        "independence_verified": False,
        "independence_status": "attested_only"
        if reviewer.get("independence_attested") is True
        else "not_attested",
        "answers": copy.deepcopy(answers),
        "errors": errors,
        "scope": "structural_validation_and_reviewer_declaration; no_identity_verification_or_accuracy_computation",
        "empty_packet": not items,
    }
