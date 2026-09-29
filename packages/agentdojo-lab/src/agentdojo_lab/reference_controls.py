"""Fixed scripted string-origin references, independent of detector predictions.

The oracle is the declared character-copy program. It does not label hidden LLM
reliance, semantic paraphrases, maliciousness, or independent human attribution.
"""

from __future__ import annotations

import copy
import hashlib
import html
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from agentdojo_lab.cascade import CascadeMatcher
from agentdojo_lab.evaluation_review import _local
from agentdojo_lab.lexical import exact_spans, lcs_evidence
from agentdojo_lab.profiles import get_profile
from agentdojo_lab.semantic import SemanticMatcher

METHOD = "scripted_string_origin_reference_v1"
PROFILES = ("ordinary", "memory", "implicit_string", "safe_control")
MEASUREMENTS = (
    "exact",
    "lcs",
    "cascade",
    "direct_tier1",
    "direct_tier3",
    "direct_tier4",
    "ordered_tier1",
    "ordered_tier2",
    "ordered_tier3",
    "ordered_tier4",
)
TOKEN = "a3c59e71-4b26-47d8-93ac-28f4a16c507e"
OTHER_TOKEN = "b5d67f82-5c37-48e9-a4bd-39a5b27d618f"
LIMITATIONS = [
    "References describe the known scripted character-copy program, not hidden model reliance or independent human labels.",
    "Semantic paraphrase and implicit-condition cases retain unknown references; they never supply automatic positive or negative semantic labels.",
    "Every profile evaluates the same frozen references. Profile repetitions and competing-source pairs are not independent scenarios.",
    "Direct semantic components are measured even if the ordered cascade skipped them; ordered-stage denominators are conditional on actual entry.",
    "Only scored, complete and untruncated evidence supplies a prediction. Disabled, skipped, failed or incomplete evidence remains unknown.",
    "Marker proofs are synthetic fixture bindings, not observations of an actual model receiving a tool output.",
    "No generative model, agent, native tool, attack, API endpoint or model parameter update is used.",
    "Controlled TP/FP/FN/TN concern scripted-origin references only; no deployment attribution accuracy, malicious propagation or causal benefit is established.",
]


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _source(source_id, start, end):
    return {"kind": "source_span", "source_id": source_id, "span": [start, end]}


def _literal(value):
    return {"kind": "literal", "value": value}


def _user(start, end):
    return {"kind": "user_span", "span": [start, end]}


def fixture_design():
    """The fixed design contains no score, embedding, label search or randomness."""
    cases = []

    def add(case_id, family, source, expression, *, user="", competitors=None, unknown=False, marker=False):
        cases.append(
            {
                "case_id": case_id,
                "family": family,
                "sources": {"a": source, **(competitors or {})},
                "user_text": user,
                "expression": expression,
                "reference_contract": "semantic_unknown" if unknown else "scripted_character_origin",
                "synthetic_canary": {"source_id": "a", "token": TOKEN} if marker else None,
            }
        )

    marker = "QZ7V9K2M5X8P"
    add("whole_marker_copy", "literal_copy", marker, [_source("a", 0, len(marker))])
    add(
        "wrapped_marker_copy",
        "literal_copy",
        "Record " + marker + " ends.",
        [_source("a", 7, 7 + len(marker))],
    )
    add("split_marker", "split_copy", marker, [_source("a", 0, 6), _literal(" / "), _source("a", 6, 12)])
    add(
        "reordered_fragments",
        "reordered_copy",
        "ALPHA7 BETA9 GAMMA2",
        [_source("a", 13, 19), _literal(" "), _source("a", 0, 6)],
    )
    add("substring_extraction", "substring_copy", "prefix [K7Q9V3Z5] suffix", [_source("a", 8, 16)])
    add("unicode_copy", "unicode_copy", "café 🧪 delta", [_source("a", 0, 6)])
    add(
        "mixed_source_copy",
        "multi_source",
        "ORIGIN-A-731",
        [_source("a", 0, 12), _literal(" + "), _source("b", 0, 12)],
        competitors={"b": "ORIGIN-B-952", "c": "UNUSED-C-468"},
    )
    add(
        "competing_source",
        "competing_source",
        "Archive token: UNUSED-Q71",
        [_source("b", 0, 12)],
        competitors={"b": "COPIED-X9M42"},
    )
    add("user_only_marker", "user_only", "Available token: Q71J8V3K", [_user(0, 12)], user="USER-MARK-52")
    add(
        "user_only_email",
        "user_only",
        "Meeting with John and Maria. Contact staff to add participants.",
        [_user(0, len("john.doe@clientcorp.com"))],
        user="john.doe@clientcorp.com",
    )
    add(
        "same_literal_distractor",
        "same_literal_unused_source",
        "Reference identifier [314].",
        [_user(0, 3)],
        user="314",
    )
    add(
        "topical_unused_source",
        "topical_unused_source",
        "The garden contains flowers and watering equipment.",
        [_user(0, 25)],
        user="Water the garden at noon.",
    )
    add("disjoint_characters", "unrelated_unused_source", "AAAAAA", [_user(0, 6)], user="ZZZZZZ")
    add(
        "semantic_paraphrase",
        "semantic_unknown",
        "A gardener waters the roses.",
        [_literal("The flowers receive irrigation.")],
        unknown=True,
    )
    add(
        "implicit_condition",
        "implicit_unknown",
        "Condition alpha is active.",
        [_literal("ZXQJ")],
        unknown=True,
    )
    add("empty_target", "unavailable_input", "Available reference text.", [], unknown=True)
    marked = "A fixed fixture record.\n# NT_CANARY: " + TOKEN + "\n"
    start = marked.index(TOKEN)
    add("canary_copy", "canary_copy", marked, [_source("a", start, start + len(TOKEN))], marker=True)
    add(
        "canary_other_origin",
        "canary_unused_source",
        marked,
        [_user(0, len(OTHER_TOKEN))],
        user=OTHER_TOKEN,
        marker=True,
    )
    return {
        "schema_version": 1,
        "method": METHOD,
        "cases": cases,
        "reference_author": "deterministic_fixture_program",
        "selection": "fixed_before_detector_or_embedding_invocation",
    }


def _span(value, text):
    if not isinstance(value, list) or len(value) != 2 or any(type(x) is not int for x in value):
        raise ValueError("Fixture spans must be exact integer pairs")
    if not 0 <= value[0] < value[1] <= len(text):
        raise ValueError("Fixture span is outside its decoded text")
    return text[value[0] : value[1]]


def compile_references(design):
    """Evaluate source-copy expressions before importing any observed predictions."""
    references, seen = [], set()
    for case in design["cases"]:
        case_id = case["case_id"]
        if case_id in seen:
            raise ValueError("Duplicate fixture case")
        seen.add(case_id)
        sources, witnesses, pieces, offset = case["sources"], [], [], 0
        if not sources or any(not isinstance(k, str) or not isinstance(v, str) for k, v in sources.items()):
            raise ValueError("Fixture sources must be nonempty string mappings")
        if case["reference_contract"] not in {"scripted_character_origin", "semantic_unknown"}:
            raise ValueError("Unknown reference contract")
        for part in case["expression"]:
            kind = part.get("kind")
            if kind == "source_span":
                value = _span(part["span"], sources[part["source_id"]])
                witnesses.append(
                    {
                        "source_id": part["source_id"],
                        "source_span": part["span"],
                        "target_span": [offset, offset + len(value)],
                    }
                )
            elif kind == "user_span":
                value = _span(part["span"], case["user_text"])
            elif kind == "literal" and isinstance(part.get("value"), str):
                value = part["value"]
            else:
                raise ValueError("Unknown target construction operation")
            pieces.append(value)
            offset += len(value)
        target = "".join(pieces)
        for source_id, source in sources.items():
            reference = (
                None
                if case["reference_contract"] == "semantic_unknown"
                else any(w["source_id"] == source_id for w in witnesses)
            )
            canary = case["synthetic_canary"]
            binding = None
            if canary and canary["source_id"] == source_id:
                from agentdojo_lab.canary import METHOD as CANARY_METHOD
                from agentdojo_lab.canary import SCHEME, validate_reference

                token = canary["token"]
                if source.count(token) != 1:
                    raise ValueError("Fixture marker must occur exactly once")
                start = source.index(token)
                binding = validate_reference(
                    {
                        "method": CANARY_METHOD,
                        "scheme": SCHEME,
                        "token": token,
                        "source_span": [start, start + len(token)],
                        "marked_text_sha256": _sha(source.encode()),
                        "policy_sha256": _sha(b"scripted-reference-fixture-policy-v1"),
                        "binding_scope": "synthetic_fixture_only; no_real_model_exposure_asserted",
                    },
                    source,
                )
            references.append(
                {
                    "reference_id": f"{case_id}/{source_id}",
                    "case_id": case_id,
                    "family": case["family"],
                    "source_id": source_id,
                    "source": source,
                    "target": target,
                    "user_text": case["user_text"],
                    "competing_sources": {k: v for k, v in sources.items() if k != source_id},
                    "reference": reference,
                    "reference_contract": case["reference_contract"],
                    "construction_witnesses": [w for w in witnesses if w["source_id"] == source_id],
                    "source_sha256": _sha(source.encode()),
                    "target_sha256": _sha(target.encode()),
                    "synthetic_canary": binding,
                }
            )
    return references


def _unknown(status, *, error_type=None):
    return {
        "status": status,
        "matched": None,
        "complete": False,
        "truncated": False,
        **({"error_type": error_type} if error_type else {}),
    }


def _prediction(evidence):
    return (
        evidence.get("matched")
        if evidence.get("status") == "scored"
        and evidence.get("complete") is True
        and evidence.get("truncated") is False
        and type(evidence.get("matched")) is bool
        else None
    )


def _invoke(call):
    try:
        result = call()
        if not isinstance(result, dict):
            raise TypeError("Expected evidence object")
        _canonical(result)
        return result
    except Exception as error:
        return _unknown("error", error_type=type(error).__name__)


def _exact(source, target):
    if not source or len(target) < 3:
        return {
            **_unknown("not_applicable"),
            "reason": "empty_source_or_target_below_baseline_minimum_length",
        }
    spans = exact_spans(source, target)
    return {
        "status": "scored",
        "matched": bool(spans),
        "complete": True,
        "truncated": False,
        "spans": spans,
        "minimum_length": 3,
    }


def _lcs(source, target, threshold):
    result = lcs_evidence(source, target, threshold=threshold)
    return {
        **result,
        "complete": result["status"] == "scored",
        "truncated": False,
        "matched": result["matched"] if result["status"] == "scored" else None,
    }


def _measure(reference, profile, semantic):
    source, target, canary = reference["source"], reference["target"], reference["synthetic_canary"]
    evidence = {
        "exact": _invoke(lambda: _exact(source, target)),
        "lcs": _invoke(lambda: _lcs(source, target, profile.lexical_threshold)),
        "cascade": _invoke(
            lambda: CascadeMatcher(semantic, profile=profile.name, canary_enabled=canary is not None).compare(
                source, target, canary=canary
            )
        ),
    }
    if canary:
        from agentdojo_lab.canary import marker_matches

        evidence["direct_tier1"] = _invoke(lambda: marker_matches(source, target, canary))
    else:
        evidence["direct_tier1"] = _unknown("disabled_condition")
    for stage in ("tier3", "tier4"):
        evidence["direct_" + stage] = (
            _invoke(lambda stage=stage: getattr(semantic, "compare_" + stage)(source, target))
            if semantic is not None
            else _unknown("encoder_unavailable")
        )
    for stage in ("tier1", "tier2", "tier3", "tier4"):
        evidence["ordered_" + stage] = copy.deepcopy(
            evidence["cascade"].get("stages", {}).get(stage, _unknown("cascade_unavailable"))
        )
    return evidence


def confusion(rows, measurement, *, references_valid=True):
    counts = Counter(
        {
            key: 0
            for key in (
                "tp",
                "fp",
                "fn",
                "tn",
                "unknown_reference",
                "unknown_prediction_with_known_reference",
            )
        }
    )
    statuses = Counter()
    for row in rows:
        truth = row["reference"] if references_valid else None
        evidence = row["evidence"][measurement]
        prediction = _prediction(evidence)
        statuses[evidence.get("status", "unknown")] += 1
        if type(truth) is not bool:
            counts["unknown_reference"] += 1
        elif prediction is None:
            counts["unknown_prediction_with_known_reference"] += 1
        else:
            counts[("tp" if prediction else "fn") if truth else ("fp" if prediction else "tn")] += 1
    evaluated = sum(counts[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        "slots": len(rows),
        **dict(counts),
        "evaluated_pairs": evaluated,
        "unknown_pairs": len(rows) - evaluated,
        "status_counts": dict(statuses),
        "precision": counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else None,
        "recall": counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else None,
        "f1": 2 * counts["tp"] / (2 * counts["tp"] + counts["fp"] + counts["fn"])
        if 2 * counts["tp"] + counts["fp"] + counts["fn"]
        else None,
        "metric_scope": "controlled_scripted_origin_only; not_independent_real_agent_attribution_accuracy",
    }


def _snapshot():
    directory = Path(__file__).parent
    paths = [
        directory / name
        for name in (
            "reference_controls.py",
            "profiles.py",
            "cascade.py",
            "semantic.py",
            "lexical.py",
            "canary.py",
        )
    ]
    runner = directory.parent.parent / "scripts/run_reference_controls.py"
    if runner.is_file():
        paths.append(runner)
    return {str(path): _sha(path.read_bytes()) for path in paths}


def _report(summary, rows):
    def table(metrics):
        return (
            "<table><thead><tr><th>Measurement</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Evaluated</th><th>Unknown reference</th><th>Unknown prediction*</th></tr></thead><tbody>"
            + "".join(
                "<tr><td>"
                + html.escape(name)
                + "</td>"
                + "".join(
                    f"<td>{item[key]}</td>"
                    for key in (
                        "tp",
                        "fp",
                        "fn",
                        "tn",
                        "evaluated_pairs",
                        "unknown_reference",
                        "unknown_prediction_with_known_reference",
                    )
                )
                + "</tr>"
                for name, item in metrics.items()
            )
            + "</tbody></table>"
        )

    sections = []
    for profile, group in summary["profiles"].items():
        sections.append(
            f"<details><summary>{html.escape(profile)} — {group['slot_count']} source-pair controls</summary>"
            + table({key: group["measurements"][key] for key in ("exact", "lcs", "cascade")})
            + "<details><summary>Direct and ordered stage evidence</summary>"
            + table(
                {
                    key: value
                    for key, value in group["measurements"].items()
                    if key not in {"exact", "lcs", "cascade"}
                }
            )
            + "</details><details><summary>Results by fixture family</summary>"
            + "".join(
                f"<h3>{html.escape(family)}</h3>"
                + table({key: metrics[key] for key in ("exact", "lcs", "cascade")})
                for family, metrics in group["families"].items()
            )
            + "</details></details>"
        )
    controls = []
    for row in rows:
        label = (
            "Unknown semantic reference"
            if row["reference"] is None
            else "Copied by the fixture program"
            if row["reference"]
            else "Not copied by the fixture program"
        )
        controls.append(
            f"<details><summary>{html.escape(row['slot_id'])} · {label}</summary><p>Source</p><pre>{html.escape(row['source'])}</pre><p>Target</p><pre>{html.escape(row['target'])}</pre><p>Declared construction evidence</p><pre>{html.escape(_canonical(row['construction_witnesses']).decode())}</pre><p>Measured evidence</p><pre>{html.escape(_canonical(row['evidence']).decode())}</pre></details>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scripted string-origin reference controls</title><style>body{font:16px/1.5 system-ui;max-width:1150px;margin:32px auto;padding:0 20px;color:#17202a}table{width:100%;border-collapse:collapse;font-size:14px}td,th{border:1px solid #ccd4df;padding:7px;text-align:left}details{border:1px solid #ccd4df;border-radius:8px;padding:12px;margin:12px 0;overflow:auto}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.note{background:#fff1ce;padding:15px}a{color:#1257a5}</style><h1>Scripted string-origin reference controls</h1><p class="note">The fixture program supplies the target and its declared character origins before detector invocation. These controlled references do not reveal an LLM\'s hidden reliance or supply independent human attribution labels.</p>'
        + f"<p>Status: {html.escape(summary['status'])} · {summary['fixture_cases']} fixed cases · {summary['reference_pairs']} source-pair references · {summary['planned_slots']} scheduled profile evaluations · {html.escape(summary['encoder_mode'])}</p>"
        + '<p><a href="summary.json">Summary JSON</a> · <a href="results.jsonl">All results JSONL</a> · <a href="references.jsonl">Frozen references</a> · <a href="reference-plan.json">Frozen plan</a> · <a href="manifest.json">File hashes</a></p><p>Profiles reuse the same references; their repeated evaluations are not independent cases. Direct components are measured even when the ordered cascade skips them. *Unknown predictions here have known references; unknown references occupy a separate column.</p>'
        + "".join(sections)
        + "<details><summary>Inspect every scheduled source-pair control</summary>"
        + "".join(controls)
        + "</details><details><summary>Scope and limitations</summary><ul>"
        + "".join("<li>" + html.escape(item) + "</li>" for item in LIMITATIONS)
        + "</ul></details></html>"
    )


def run_reference_controls(
    output: Path, *, encoder_factory, encoder_mode: str, encoder_configuration: dict | None = None
) -> dict:
    """Freeze program/reference bytes, then evaluate all slots without any API use."""
    if encoder_mode not in {"real_local_minilm", "deterministic_test_double"}:
        raise ValueError("Declare a real local encoder or an explicit test double")
    if encoder_mode == "real_local_minilm" and (
        not isinstance(encoder_configuration, dict)
        or set(encoder_configuration) != {"model_path", "revision"}
        or any(not isinstance(value, str) or not value for value in encoder_configuration.values())
    ):
        raise ValueError("Freeze the local model path and revision before encoder construction")
    output = _local(output)
    if output.exists():
        raise FileExistsError(output)
    design = fixture_design()
    references = compile_references(design)
    profile_values = {name: asdict(get_profile(name)) for name in PROFILES}
    implementation = _snapshot()
    reference_bytes = b"".join(_canonical(item) + b"\n" for item in references)
    plan = {
        "schema_version": 1,
        "method": METHOD,
        "design": design,
        "profiles": profile_values,
        "reference_sha256": _sha(reference_bytes),
        "implementation_sha256": implementation,
        "encoder_mode": encoder_mode,
        "reference_labels_frozen_before_encoder_creation": True,
        "encoder_configuration": copy.deepcopy(encoder_configuration),
        "schedule": [
            {
                "slot_id": f"{profile}/{ref['reference_id']}",
                "profile": profile,
                "reference_id": ref["reference_id"],
            }
            for profile in PROFILES
            for ref in references
        ],
        "limits": {"fixture_cases": 18, "reference_pairs": 21, "generative_model_requests": 0},
        "reference_scope": "known_scripted_character_copy_origin; semantic_reference_unknown",
    }
    plan_bytes = _canonical(plan) + b"\n"
    output.mkdir(parents=True, exist_ok=False)
    (output / "reference-plan.json").write_bytes(plan_bytes)
    (output / "references.jsonl").write_bytes(reference_bytes)
    (output / "reference-plan.sha256").write_text(_sha(plan_bytes) + "\n")
    encoder, encoder_error, encoder_metadata = None, None, None
    try:
        encoder = encoder_factory()
        encoder_metadata = copy.deepcopy(encoder.metadata)
        _canonical(encoder_metadata)
    except Exception as error:
        encoder_error = type(error).__name__
        encoder = None
    reference_map = {item["reference_id"]: item for item in references}
    rows = []
    for slot in plan["schedule"]:
        reference = reference_map[slot["reference_id"]]
        profile = get_profile(slot["profile"])
        try:
            semantic = (
                SemanticMatcher(
                    encoder,
                    semantic_threshold=profile.semantic_threshold,
                    coverage_threshold=profile.coverage_threshold,
                )
                if encoder is not None
                else None
            )
            evidence = _measure(reference, profile, semantic)
        except Exception as error:
            evidence = {
                name: _unknown("slot_error", error_type=type(error).__name__) for name in MEASUREMENTS
            }
        rows.append({**copy.deepcopy(reference), **slot, "evidence": evidence})
    integrity = {
        "plan_unchanged": (output / "reference-plan.json").read_bytes() == plan_bytes,
        "references_unchanged": (output / "references.jsonl").read_bytes() == reference_bytes,
        "plan_digest_unchanged": (output / "reference-plan.sha256").read_text() == _sha(plan_bytes) + "\n",
        "implementation_unchanged": _snapshot() == implementation,
        "profiles_unchanged": {name: asdict(get_profile(name)) for name in PROFILES} == profile_values,
    }
    valid = all(integrity.values())
    errors = Counter(
        name
        for row in rows
        for name, evidence in row["evidence"].items()
        if evidence.get("status") in {"error", "encoder_error", "slot_error", "encoder_unavailable"}
    )
    summary = {
        "schema_version": 1,
        "method": METHOD,
        "status": "invalidated_inputs"
        if not valid
        else "completed_with_encoder_failure"
        if encoder_error
        else "completed_with_measurement_failures"
        if errors
        else "completed",
        "encoder_mode": encoder_mode,
        "encoder_metadata": encoder_metadata,
        "encoder_initialization_error": encoder_error,
        "fixture_cases": len(design["cases"]),
        "reference_pairs": len(references),
        "reference_label_counts": {
            "positive": sum(x["reference"] is True for x in references),
            "negative": sum(x["reference"] is False for x in references),
            "unknown": sum(x["reference"] is None for x in references),
        },
        "planned_slots": len(plan["schedule"]),
        "recorded_slots": len(rows),
        "measurement_error_counts": dict(errors),
        "plan_sha256": _sha(plan_bytes),
        "reference_sha256": _sha(reference_bytes),
        "integrity": integrity,
        "reference_labels_frozen_before_detector_invocation": True,
        "profiles": {},
        "generative_model_requests": 0,
        "native_agent_runs": 0,
        "independent_real_agent_attribution_metrics": {"precision": None, "recall": None, "f1": None},
        "limitations": LIMITATIONS,
    }
    for profile in PROFILES:
        group = [row for row in rows if row["profile"] == profile]
        summary["profiles"][profile] = {
            "thresholds": profile_values[profile],
            "slot_count": len(group),
            "measurements": {name: confusion(group, name, references_valid=valid) for name in MEASUREMENTS},
            "families": {
                family: {
                    name: confusion(
                        [row for row in group if row["family"] == family], name, references_valid=valid
                    )
                    for name in MEASUREMENTS
                }
                for family in sorted({row["family"] for row in group})
            },
        }
    (output / "results.jsonl").write_bytes(b"".join(_canonical(row) + b"\n" for row in rows))
    (output / "summary.json").write_bytes(_canonical(summary) + b"\n")
    (output / "index.html").write_text(_report(summary, rows), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "method": METHOD,
        "status": summary["status"],
        "files": {path.name: _sha(path.read_bytes()) for path in sorted(output.iterdir()) if path.is_file()},
        "scope": "fresh_output_only; no_prior_report_or_run_modified",
    }
    (output / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
    return summary
