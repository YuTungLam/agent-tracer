"""Frozen held-out known-origin panel for NT-AgentDojo-Eval-v1.

The reference is a declared character-construction program. It measures controlled
source-to-field correspondence, not natural-agent attribution or hidden model
reliance. This module never invokes a generative model, agent, native tool, or API.
"""

from __future__ import annotations

import copy
import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from agentdojo_lab import reference_controls
from agentdojo_lab.profiles import get_profile
from agentdojo_lab.semantic import SemanticMatcher

PROTOCOL = "nt-agentdojo-heldout-known-origin-panel-v1"
REQUIRED_DOMAINS = frozenset({"calendar", "email", "file"})
SCOPE = "controlled_heldout_known_origin_only; not_natural_agent_attribution_accuracy"
LIMITATIONS = [
    "References are fixed character-construction relations, not labels of hidden model reliance.",
    "The panel executes no generative model, agent, native tool, attack, or external API.",
    "Results measure controlled held-out source-field correspondence only.",
    "Native utility, attack success, malicious propagation, causal benefit, and defense benefit are not measured.",
    "Direct detector components are reported separately from the ordered cascade.",
    "An incomplete, failed, truncated, or unavailable detector result remains an unknown prediction.",
]

_ERROR_STATUSES = frozenset({"error", "encoder_error", "slot_error"})
_UNAVAILABLE_STATUSES = frozenset(
    {
        "cascade_unavailable",
        "disabled_condition",
        "encoder_unavailable",
        "not_applicable",
        "skipped",
        "unavailable",
    }
)
_TIERS = ("tier1", "tier2", "tier3", "tier4")

_TOP_LEVEL_KEYS = {
    "schema_version",
    "panel_id",
    "protocol",
    "suite",
    "benchmark_version",
    "profile",
    "selection",
    "reference_author",
    "scope",
    "domains",
    "limits",
    "pairs",
}
_PAIR_KEYS = {
    "pair_id",
    "domain",
    "family",
    "source_tool",
    "sink_tool",
    "sink_argument_path",
    "source_text",
    "user_text",
    "expression",
    "reference",
}


def _canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _local(path: Path) -> Path:
    path = Path(path).expanduser().absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Panel inputs and outputs must not use symlinks")
    return path.resolve()


def _strict_json(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    def constant(_):
        raise ValueError("Non-finite JSON value")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid panel configuration JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Panel configuration must be a JSON object")
    return value


def _require_ascii_strings(value) -> None:
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("Panel configuration strings must be English ASCII") from error
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_ascii_strings(key)
            _require_ascii_strings(item)
    elif isinstance(value, list):
        for item in value:
            _require_ascii_strings(item)


def _nonempty_string(value, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _string_list(value, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"{field} must be a nonempty unique string list")
    return value


def load_panel_config(path: Path) -> tuple[dict, bytes]:
    """Load and validate a complete panel without importing detector output."""
    path = _local(path)
    if not path.is_file():
        raise ValueError("Expected a regular panel configuration file")
    raw = path.read_bytes()
    if len(raw) > 262_144:
        raise ValueError("Panel configuration exceeds the 262144-byte limit")
    config = _strict_json(raw)
    _require_ascii_strings(config)
    if set(config) != _TOP_LEVEL_KEYS:
        raise ValueError("Panel configuration has missing or unexpected fields")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("Unsupported panel schema version")
    for field in (
        "panel_id",
        "suite",
        "benchmark_version",
        "profile",
        "selection",
        "reference_author",
        "scope",
    ):
        _nonempty_string(config[field], field)
    if config["protocol"] != PROTOCOL or config["scope"] != SCOPE:
        raise ValueError("Panel protocol or scope does not match the implementation")
    if config["suite"] != "workspace":
        raise ValueError("This panel is restricted to the AgentDojo workspace suite")
    get_profile(config["profile"])

    domains = config["domains"]
    if not isinstance(domains, dict) or set(domains) != REQUIRED_DOMAINS:
        raise ValueError("Panel domains must be exactly calendar, email, and file")
    for name, domain in domains.items():
        if not isinstance(domain, dict) or set(domain) != {"source_tools", "sink_tools"}:
            raise ValueError(f"Invalid {name} domain declaration")
        _string_list(domain["source_tools"], f"{name}.source_tools")
        _string_list(domain["sink_tools"], f"{name}.sink_tools")

    limits = config["limits"]
    required_limits = {
        "pairs": 24,
        "positive_pairs": 12,
        "negative_pairs": 12,
        "pairs_per_domain": 8,
        "minimum_pairs_per_domain": 4,
        "generative_model_requests": 0,
        "native_agent_runs": 0,
        "external_api_requests": 0,
    }
    if limits != required_limits:
        raise ValueError("Panel limits must match the frozen v1 inventory")

    pairs = config["pairs"]
    if not isinstance(pairs, list) or len(pairs) != limits["pairs"]:
        raise ValueError("Panel must contain exactly 24 pairs")
    seen = set()
    counts = Counter()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != _PAIR_KEYS:
            raise ValueError("Panel pair has missing or unexpected fields")
        pair_id = _nonempty_string(pair["pair_id"], "pair_id")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", pair_id) or pair_id in seen:
            raise ValueError("Panel pair identifiers must be unique ASCII snake case")
        seen.add(pair_id)
        domain = pair["domain"]
        if domain not in REQUIRED_DOMAINS:
            raise ValueError("Panel pair uses an undeclared domain")
        for field in ("family", "source_tool", "sink_tool", "source_text"):
            _nonempty_string(pair[field], field)
        if pair["source_tool"] not in domains[domain]["source_tools"]:
            raise ValueError("Panel pair source tool is absent from its domain declaration")
        if pair["sink_tool"] not in domains[domain]["sink_tools"]:
            raise ValueError("Panel pair sink tool is absent from its domain declaration")
        if not isinstance(pair["sink_argument_path"], str) or not pair["sink_argument_path"].startswith(
            "/"
        ):
            raise ValueError("Panel sink argument path must be an RFC 6901-style non-root path")
        if not isinstance(pair["user_text"], str):
            raise ValueError("Panel user text must be a string")
        if type(pair["reference"]) is not bool:
            raise ValueError("Panel reference must be a strict boolean")
        expression = pair["expression"]
        if not isinstance(expression, list) or not expression:
            raise ValueError("Panel expression must be a nonempty list")
        for part in expression:
            if not isinstance(part, dict) or set(part) != {"kind", "value"}:
                raise ValueError("Panel expression parts require exactly kind and value")
            if part["kind"] not in {"source_fragment", "user_fragment", "literal"}:
                raise ValueError("Unknown panel expression operation")
            _nonempty_string(part["value"], "expression value")
        derived = any(part["kind"] == "source_fragment" for part in expression)
        if pair["reference"] is not derived:
            raise ValueError("Declared reference disagrees with the construction expression")
        counts[(domain, pair["reference"])] += 1
    for domain in REQUIRED_DOMAINS:
        if counts[(domain, True)] != 4 or counts[(domain, False)] != 4:
            raise ValueError("Each domain must contain four positive and four negative pairs")
    return config, raw


def _unique_fragment_span(text: str, fragment: str, *, origin: str) -> list[int]:
    start = text.find(fragment)
    if start < 0 or text.find(fragment, start + 1) >= 0:
        raise ValueError(f"{origin} fragment must occur exactly once")
    return [start, start + len(fragment)]


def compile_panel_references(config: dict) -> list[dict]:
    """Compile target strings and labels before any detector or encoder call."""
    cases = []
    pair_map = {}
    for pair in config["pairs"]:
        expression = []
        for part in pair["expression"]:
            if part["kind"] == "source_fragment":
                expression.append(
                    {
                        "kind": "source_span",
                        "source_id": "a",
                        "span": _unique_fragment_span(
                            pair["source_text"], part["value"], origin="Source"
                        ),
                    }
                )
            elif part["kind"] == "user_fragment":
                expression.append(
                    {
                        "kind": "user_span",
                        "span": _unique_fragment_span(
                            pair["user_text"], part["value"], origin="User"
                        ),
                    }
                )
            else:
                expression.append({"kind": "literal", "value": part["value"]})
        cases.append(
            {
                "case_id": pair["pair_id"],
                "family": pair["family"],
                "sources": {"a": pair["source_text"]},
                "user_text": pair["user_text"],
                "expression": expression,
                "reference_contract": "scripted_character_origin",
                "synthetic_canary": None,
            }
        )
        pair_map[pair["pair_id"]] = pair
    design = {
        "schema_version": 1,
        "method": PROTOCOL,
        "cases": cases,
        "reference_author": config["reference_author"],
        "selection": config["selection"],
    }
    compiled = reference_controls.compile_references(design)
    references = []
    for item in compiled:
        pair = pair_map[item["case_id"]]
        if item["reference"] is not pair["reference"]:
            raise ValueError("Compiled reference disagrees with frozen pair declaration")
        references.append(
            {
                **item,
                "reference_id": pair["pair_id"],
                "panel_id": config["panel_id"],
                "domain": pair["domain"],
                "source_tool": pair["source_tool"],
                "sink_tool": pair["sink_tool"],
                "sink_argument_path": pair["sink_argument_path"],
                "reference_scope": SCOPE,
                "label_frozen_before_detector_invocation": True,
            }
        )
    if len(references) != 24:
        raise ValueError("Compiled panel does not contain exactly 24 references")
    if sum(item["reference"] is True for item in references) != 12:
        raise ValueError("Compiled panel does not contain exactly 12 positive references")
    if sum(item["reference"] is False for item in references) != 12:
        raise ValueError("Compiled panel does not contain exactly 12 negative references")
    return references


def _snapshot(config_path: Path) -> dict[str, str]:
    directory = Path(__file__).parent
    paths = [
        Path(__file__),
        directory / "reference_controls.py",
        directory / "profiles.py",
        directory / "cascade.py",
        directory / "semantic.py",
        directory / "lexical.py",
        config_path,
    ]
    runner = directory.parent.parent / "scripts" / "run_neurotaint_reference_panel.py"
    if runner.is_file():
        paths.append(runner)
    return {str(path): reference_controls._sha(path.read_bytes()) for path in paths}


def _enrich_confusion(
    metric: dict, rows: list[dict], measurement: str, *, references_valid: bool
) -> dict:
    """Add explicit coverage and availability accounting to a frozen metric."""
    result = copy.deepcopy(metric)
    tp, fp, fn, tn = (result[key] for key in ("tp", "fp", "fn", "tn"))
    sensitivity_denominator = tp + fn
    specificity_denominator = tn + fp
    sensitivity = tp / sensitivity_denominator if sensitivity_denominator else None
    specificity = tn / specificity_denominator if specificity_denominator else None
    result["balanced_accuracy"] = (
        (sensitivity + specificity) / 2
        if sensitivity is not None and specificity is not None
        else None
    )

    availability = Counter(
        {
            "scored": 0,
            "abstention": 0,
            "unavailable": 0,
            "error": 0,
            "unknown_reference": 0,
        }
    )
    for row in rows:
        if not references_valid or type(row.get("reference")) is not bool:
            availability["unknown_reference"] += 1
            continue
        evidence = row.get("evidence", {}).get(measurement, {})
        prediction = reference_controls._prediction(evidence)
        status = evidence.get("status")
        if type(prediction) is bool:
            availability["scored"] += 1
        elif status in _ERROR_STATUSES:
            availability["error"] += 1
        elif status in _UNAVAILABLE_STATUSES:
            availability["unavailable"] += 1
        else:
            availability["abstention"] += 1
    result["scored_coverage"] = {
        "numerator": availability["scored"],
        "denominator": len(rows),
        "rate": availability["scored"] / len(rows) if rows else None,
        "unknown_count": len(rows) - availability["scored"],
        "scope": "controlled_pairs_with_known_reference_and_definitive_prediction",
    }
    result["availability_accounting"] = dict(availability)
    return result


def _ordered_cascade_distribution(rows: list[dict]) -> dict:
    """Describe ordered routing without treating route selection as correctness."""
    stage_status_counts = {tier: Counter() for tier in _TIERS}
    stage_entry = Counter()
    first_hits = Counter({tier: 0 for tier in _TIERS})
    first_hits.update({"complete_negative": 0, "unknown": 0})
    for row in rows:
        cascade = row.get("evidence", {}).get("cascade", {})
        stages = cascade.get("stages") if isinstance(cascade.get("stages"), dict) else {}
        for tier in _TIERS:
            evidence = stages.get(tier)
            if not isinstance(evidence, dict) or not isinstance(evidence.get("status"), str):
                stage_status_counts[tier]["unknown"] += 1
                continue
            status = evidence["status"]
            stage_status_counts[tier][status] += 1
            if status not in {"skipped", "cascade_unavailable", "encoder_unavailable", "unavailable"}:
                stage_entry[tier] += 1
        first = cascade.get("first_matched_tier")
        prediction = reference_controls._prediction(cascade)
        if first in _TIERS:
            first_hits[first] += 1
        elif prediction is False:
            first_hits["complete_negative"] += 1
        else:
            first_hits["unknown"] += 1
    return {
        "scope": "descriptive_ordered_cascade_routing_only; not_attribution_correctness",
        "stage_entry_rule": "A stage record exists and is neither skipped nor unavailable.",
        "stage_entry": [
            {
                "stage": tier,
                "count": stage_entry[tier],
                "denominator": len(rows),
                "rate": stage_entry[tier] / len(rows) if rows else None,
                "unknown_count": stage_status_counts[tier]["unknown"],
            }
            for tier in _TIERS
        ],
        "stage_status_counts": {
            tier: dict(sorted(counts.items())) for tier, counts in stage_status_counts.items()
        },
        "first_hit": [
            {
                "outcome": outcome,
                "count": first_hits[outcome],
                "denominator": len(rows),
                "rate": first_hits[outcome] / len(rows) if rows else None,
            }
            for outcome in (*_TIERS, "complete_negative", "unknown")
        ],
    }


def run_reference_panel(
    output: Path,
    *,
    config_path: Path,
    encoder_factory=None,
    encoder_mode: str,
    encoder_configuration: dict | None = None,
) -> dict:
    """Freeze config, labels, plan, and hashes before evaluating the detector."""
    if encoder_mode not in {"real_local_minilm", "deterministic_test_double"}:
        raise ValueError("Declare a real local encoder or an explicit test double")
    if encoder_mode == "real_local_minilm" and (
        not isinstance(encoder_configuration, dict)
        or set(encoder_configuration) != {"model_path", "revision"}
        or any(not isinstance(value, str) or not value for value in encoder_configuration.values())
    ):
        raise ValueError("Freeze the local model path and revision before encoder construction")
    if encoder_mode == "real_local_minilm" and encoder_factory is not None:
        raise ValueError("Real local MiniLM requires the sealed internal encoder constructor")
    if encoder_mode == "deterministic_test_double" and not callable(encoder_factory):
        raise ValueError("A deterministic test double requires an explicit encoder factory")
    encoder_construction = (
        "internal_local_minilm"
        if encoder_mode == "real_local_minilm"
        else "injected_test_double"
    )

    output = _local(output)
    config_path = _local(config_path)
    if output.exists():
        raise FileExistsError(output)
    config, config_bytes = load_panel_config(config_path)
    references = compile_panel_references(config)
    profile = get_profile(config["profile"])
    profile_value = asdict(profile)
    implementation = _snapshot(config_path)
    reference_bytes = b"".join(_canonical(item) + b"\n" for item in references)
    schedule = [
        {
            "record_sequence": index,
            "reference_id": item["reference_id"],
            "domain": item["domain"],
        }
        for index, item in enumerate(references, start=1)
    ]
    plan = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "panel_id": config["panel_id"],
        "scope": SCOPE,
        "config": copy.deepcopy(config),
        "config_sha256": reference_controls._sha(config_bytes),
        "reference_sha256": reference_controls._sha(reference_bytes),
        "implementation_sha256": implementation,
        "profile": profile_value,
        "encoder_mode": encoder_mode,
        "encoder_construction": encoder_construction,
        "encoder_configuration": copy.deepcopy(encoder_configuration),
        "schedule": schedule,
        "limits": copy.deepcopy(config["limits"]),
        "reference_labels_frozen_before_encoder_creation": True,
        "selection_completed_before_detector_invocation": True,
    }
    plan_bytes = _canonical(plan) + b"\n"
    plan_sha256 = reference_controls._sha(plan_bytes)

    output.mkdir(parents=True, exist_ok=False)
    (output / "panel-config.json").write_bytes(config_bytes)
    (output / "panel-plan.json").write_bytes(plan_bytes)
    (output / "panel-plan.sha256").write_text(plan_sha256 + "\n", encoding="ascii")
    (output / "references.jsonl").write_bytes(reference_bytes)

    encoder, encoder_error, encoder_metadata = None, None, None
    try:
        if encoder_mode == "real_local_minilm":
            from agentdojo_lab.semantic import LocalMiniLMEncoder

            encoder = LocalMiniLMEncoder(
                encoder_configuration["model_path"],
                revision=encoder_configuration["revision"],
            )
        else:
            encoder = encoder_factory()
        encoder_metadata = copy.deepcopy(encoder.metadata)
        _canonical(encoder_metadata)
    except Exception as error:
        encoder_error = type(error).__name__

    reference_map = {item["reference_id"]: item for item in references}
    rows = []
    for slot in schedule:
        reference = reference_map[slot["reference_id"]]
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
            evidence = reference_controls._measure(reference, profile, semantic)
        except Exception as error:
            evidence = {
                name: reference_controls._unknown("slot_error", error_type=type(error).__name__)
                for name in reference_controls.MEASUREMENTS
            }
        rows.append(
            {
                **copy.deepcopy(reference),
                **slot,
                "protocol": PROTOCOL,
                "profile": profile.name,
                "evidence": evidence,
            }
        )

    integrity = {
        "source_config_unchanged": config_path.read_bytes() == config_bytes,
        "config_copy_unchanged": (output / "panel-config.json").read_bytes() == config_bytes,
        "plan_unchanged": (output / "panel-plan.json").read_bytes() == plan_bytes,
        "plan_digest_unchanged": (output / "panel-plan.sha256").read_text(encoding="ascii")
        == plan_sha256 + "\n",
        "references_unchanged": (output / "references.jsonl").read_bytes() == reference_bytes,
        "implementation_unchanged": _snapshot(config_path) == implementation,
        "profile_unchanged": asdict(get_profile(config["profile"])) == profile_value,
    }
    references_valid = all(integrity.values())
    measurement_errors = Counter(
        name
        for row in rows
        for name, evidence in row["evidence"].items()
        if evidence.get("status")
        in {"error", "encoder_error", "slot_error", "encoder_unavailable"}
    )
    measurements = {
        name: _enrich_confusion(
            reference_controls.confusion(rows, name, references_valid=references_valid),
            rows,
            name,
            references_valid=references_valid,
        )
        for name in reference_controls.MEASUREMENTS
    }
    ordered_distribution = _ordered_cascade_distribution(rows)
    attribution = copy.deepcopy(measurements["cascade"])
    attribution["metric_scope"] = SCOPE
    attribution["ordered_cascade_distribution"] = copy.deepcopy(ordered_distribution)
    for value in measurements.values():
        value["metric_scope"] = SCOPE

    summary = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "panel_id": config["panel_id"],
        "status": "invalidated_inputs"
        if not references_valid
        else "completed_with_encoder_failure"
        if encoder_error
        else "completed_with_measurement_failures"
        if measurement_errors
        else "completed",
        "scope": SCOPE,
        "profile": profile_value,
        "encoder_mode": encoder_mode,
        "encoder_construction": encoder_construction,
        "encoder_configuration": copy.deepcopy(encoder_configuration),
        "encoder_metadata": encoder_metadata,
        "encoder_initialization_error": encoder_error,
        "reference_labels_frozen_before_detector_invocation": True,
        "selection_completed_before_detector_invocation": True,
        "pair_count": len(references),
        "planned_pairs": len(schedule),
        "recorded_pairs": len(rows),
        "domain_pair_counts": dict(sorted(Counter(item["domain"] for item in references).items())),
        "reference_label_counts": {
            "positive": sum(item["reference"] is True for item in references),
            "negative": sum(item["reference"] is False for item in references),
            "unknown": sum(type(item["reference"]) is not bool for item in references),
        },
        "attribution_metrics": attribution,
        "measurements": measurements,
        "domains": {
            domain: {
                "pair_count": sum(row["domain"] == domain for row in rows),
                "reference_label_counts": {
                    "positive": sum(row["domain"] == domain and row["reference"] is True for row in rows),
                    "negative": sum(row["domain"] == domain and row["reference"] is False for row in rows),
                    "unknown": sum(
                        row["domain"] == domain and type(row["reference"]) is not bool for row in rows
                    ),
                },
                "measurements": {
                    name: {
                        **_enrich_confusion(
                            reference_controls.confusion(
                                [row for row in rows if row["domain"] == domain],
                                name,
                                references_valid=references_valid,
                            ),
                            [row for row in rows if row["domain"] == domain],
                            name,
                            references_valid=references_valid,
                        ),
                        "metric_scope": SCOPE,
                    }
                    for name in reference_controls.MEASUREMENTS
                },
            }
            for domain in sorted(REQUIRED_DOMAINS)
        },
        "families": {
            family: {
                name: {
                    **_enrich_confusion(
                        reference_controls.confusion(
                            [row for row in rows if row["family"] == family],
                            name,
                            references_valid=references_valid,
                        ),
                        [row for row in rows if row["family"] == family],
                        name,
                        references_valid=references_valid,
                    ),
                    "metric_scope": SCOPE,
                }
                for name in reference_controls.MEASUREMENTS
            }
            for family in sorted({row["family"] for row in rows})
        },
        "unknowns": {
            "reference": attribution["unknown_reference"],
            "prediction_with_known_reference": attribution[
                "unknown_prediction_with_known_reference"
            ],
            "cascade_pairs": attribution["unknown_pairs"],
            "measurement_errors": dict(measurement_errors),
        },
        "ordered_cascade_distribution": ordered_distribution,
        "plan_sha256": plan_sha256,
        "config_sha256": reference_controls._sha(config_bytes),
        "reference_sha256": reference_controls._sha(reference_bytes),
        "integrity": integrity,
        "generative_model_requests": 0,
        "native_agent_runs": 0,
        "external_api_requests": 0,
        "natural_agent_attribution_metrics": {"precision": None, "recall": None, "f1": None},
        "limitations": LIMITATIONS,
    }

    (output / "results.jsonl").write_bytes(
        b"".join(_canonical(row) + b"\n" for row in rows)
    )
    (output / "summary.json").write_bytes(_canonical(summary) + b"\n")
    manifest = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "panel_id": config["panel_id"],
        "status": summary["status"],
        "scope": "new_frozen_output_only; no_prior_report_or_run_modified",
        "files": {
            path.name: reference_controls._sha(path.read_bytes())
            for path in sorted(output.iterdir())
            if path.is_file()
        },
    }
    (output / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
    return summary
