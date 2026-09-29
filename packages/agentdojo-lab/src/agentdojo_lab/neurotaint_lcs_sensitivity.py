"""Offline post-hoc LCS sensitivity for a frozen known-origin panel.

The analysis compares fixed normalization alternatives at the already-frozen
ordinary threshold.  It is descriptive sensitivity analysis, not a
preregistered result, threshold search, production fix, or model invocation.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import math
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

METHOD = "nt_lcs_posthoc_sensitivity_v1"
PANEL_PROTOCOL = "nt-agentdojo-heldout-known-origin-panel-v1"
ORDINARY_THRESHOLD = 0.15
MAX_FILE_BYTES = 67_108_864
MAX_CODEPOINTS_PER_INPUT = 65_536
MAX_LENGTH_PRODUCT = 67_108_864
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9]+(?:[_@./:+-][A-Za-z0-9]+)*|[^\s]")

ALTERNATIVES = (
    {
        "id": "paper_char_min",
        "label": "Character LCS / minimum length",
        "unit": "unicode_codepoint",
        "denominator": "minimum_length",
        "frozen_runtime_baseline": True,
    },
    {
        "id": "char_max",
        "label": "Character LCS / maximum length",
        "unit": "unicode_codepoint",
        "denominator": "maximum_length",
        "frozen_runtime_baseline": False,
    },
    {
        "id": "char_source",
        "label": "Character LCS / source length",
        "unit": "unicode_codepoint",
        "denominator": "source_length",
        "frozen_runtime_baseline": False,
    },
    {
        "id": "char_dice",
        "label": "Two times character LCS / summed lengths",
        "unit": "unicode_codepoint",
        "denominator": "dice_average_length",
        "frozen_runtime_baseline": False,
    },
    {
        "id": "token_min",
        "label": "Case-sensitive token LCS / minimum token length",
        "unit": "ascii_lexical_token",
        "denominator": "minimum_token_length",
        "frozen_runtime_baseline": False,
    },
)

REQUIRED_PANEL_FILES = frozenset(
    {
        "panel-config.json",
        "panel-plan.json",
        "panel-plan.sha256",
        "references.jsonl",
        "results.jsonl",
        "summary.json",
    }
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _local(path: Path, *, must_exist: bool) -> Path:
    path = Path(path).expanduser().absolute()
    existing = path if path.exists() else path.parent
    if any(part.is_symlink() for part in (existing, *existing.parents)):
        raise ValueError("Sensitivity inputs and outputs must not use symlinks")
    resolved = path.resolve()
    if must_exist and not resolved.is_dir():
        raise ValueError("Frozen reference panel must be a directory")
    return resolved


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular input file: {path.name}")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"Input file exceeds the fixed byte limit: {path.name}")
    return raw


def _strict_json(raw: bytes, *, name: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key in {name}")
            result[key] = value
        return result

    def constant(_):
        raise ValueError(f"Non-finite JSON value in {name}")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Invalid JSON in {name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {name}")
    return value


def _jsonl(raw: bytes, *, name: str) -> list[dict]:
    rows = []
    for sequence, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        rows.append(_strict_json(line, name=f"{name} line {sequence}"))
    return rows


def _require_ascii(value: object, *, name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be English ASCII") from exc


def _sequence_lcs_length(left: list[str] | str, right: list[str] | str) -> int:
    if len(left) < len(right):
        left, right = right, left
    masks = {}
    for index, item in enumerate(right):
        masks[item] = masks.get(item, 0) | (1 << index)
    row = 0
    for item in left:
        matches = masks.get(item, 0) | row
        row = matches & ~(matches - ((row << 1) | 1))
    return row.bit_count()


def _tokens(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text)


def _score(source: str, target: str, alternative: dict, threshold: float) -> dict:
    if not isinstance(source, str) or not isinstance(target, str):
        return {
            "status": "invalid_input",
            "reason": "source_or_target_not_string",
            "lcs_length": None,
            "denominator_value": None,
            "score": None,
            "matched": None,
        }
    if alternative["unit"] == "unicode_codepoint":
        left, right = source, target
        source_length, target_length = len(source), len(target)
        if not source_length or not target_length:
            return {
                "status": "not_applicable",
                "reason": "empty_input",
                "source_length": source_length,
                "target_length": target_length,
                "lcs_length": None,
                "denominator_value": None,
                "score": None,
                "matched": None,
            }
        if (
            max(source_length, target_length) > MAX_CODEPOINTS_PER_INPUT
            or source_length * target_length > MAX_LENGTH_PRODUCT
        ):
            return {
                "status": "budget_exceeded",
                "reason": "fixed_lcs_resource_limit",
                "source_length": source_length,
                "target_length": target_length,
                "lcs_length": None,
                "denominator_value": None,
                "score": None,
                "matched": None,
            }
    else:
        left, right = _tokens(source), _tokens(target)
        source_length, target_length = len(left), len(right)
        if not source_length or not target_length:
            return {
                "status": "not_applicable",
                "reason": "empty_token_sequence",
                "source_length": source_length,
                "target_length": target_length,
                "lcs_length": None,
                "denominator_value": None,
                "score": None,
                "matched": None,
            }

    length = _sequence_lcs_length(left, right)
    denominator = alternative["denominator"]
    if denominator in {"minimum_length", "minimum_token_length"}:
        denominator_value = min(source_length, target_length)
        score = length / denominator_value
    elif denominator == "maximum_length":
        denominator_value = max(source_length, target_length)
        score = length / denominator_value
    elif denominator == "source_length":
        denominator_value = source_length
        score = length / denominator_value
    elif denominator == "dice_average_length":
        denominator_value = (source_length + target_length) / 2
        score = length / denominator_value
    else:
        raise ValueError("Unknown frozen LCS sensitivity denominator")
    return {
        "status": "scored",
        "reason": "threshold_met" if score >= threshold else "below_threshold",
        "source_length": source_length,
        "target_length": target_length,
        "lcs_length": length,
        "denominator_value": denominator_value,
        "score": score,
        "threshold": threshold,
        "matched": score >= threshold,
    }


def _prediction(evidence: object) -> bool | None:
    if not isinstance(evidence, dict):
        return None
    if (
        evidence.get("status") != "scored"
        or evidence.get("complete") is not True
        or evidence.get("truncated") is not False
        or type(evidence.get("matched")) is not bool
    ):
        return None
    return evidence["matched"]


def _tier1_gate(evidence: dict) -> tuple[bool | None, bool | None, str]:
    """Mirror the M7 Tier 1 gate without calling it a negative measurement."""
    cascade = evidence.get("cascade")
    if not isinstance(cascade, dict):
        return None, None, "unknown_missing_cascade"
    stages = cascade.get("stages")
    metadata = cascade.get("metadata")
    if not isinstance(stages, dict) or not isinstance(metadata, dict):
        return None, None, "unknown_missing_cascade_contract"
    stage = stages.get("tier1")
    if not isinstance(stage, dict):
        return None, None, "unknown_missing_tier1"
    prediction = _prediction(stage)
    if prediction is False:
        return True, True, "acceptable_explicit_negative_measurement"
    if prediction is True:
        return False, False, "ineligible_positive_measurement"
    canary_enabled = metadata.get("canary_enabled")
    expected = (
        ("disabled_condition", "passive_input_unchanged_no_canary")
        if canary_enabled is False
        else ("not_applicable", "source_has_no_validated_exposed_canary")
        if canary_enabled is True
        else None
    )
    actual = stage.get("status"), stage.get("reason")
    inapplicable_contract = (
        expected is not None
        and actual == expected
        and stage.get("score") is None
        and stage.get("matched") is None
        and stage.get("complete") is False
        and stage.get("truncated") is False
    )
    if inapplicable_contract:
        return False, True, f"acceptable_{stage['status']}"
    return None, None, "unknown_invalid_or_incomplete_tier1"


def _classify(reference: object, prediction: object) -> str:
    if type(reference) is not bool:
        return "unknown_reference"
    if type(prediction) is not bool:
        return "unknown_prediction_with_known_reference"
    if reference:
        return "tp" if prediction else "fn"
    return "fp" if prediction else "tn"


def _stage_implications(result: dict, matched: bool | None, current: bool | None) -> dict:
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    tier1_negative, tier1_acceptable, tier1_gate_status = _tier1_gate(evidence)
    tier3 = _prediction(evidence.get("direct_tier3"))
    tier4 = _prediction(evidence.get("direct_tier4"))
    tier3_eligible = matched is False if matched is not None else None
    if tier3_eligible is True and tier3 is False:
        tier4_eligible = True
    elif tier3_eligible is False or tier3 is True:
        tier4_eligible = False
    else:
        tier4_eligible = None
    post_tier4_negative = (
        True
        if matched is False and tier3 is False and tier4 is False
        else False
        if matched is True or tier3 is True or tier4 is True
        else None
    )
    causal_eligible = tier1_acceptable is True and post_tier4_negative is True
    if causal_eligible:
        causal_status = "eligible_all_active_stages_explicit_negative"
    elif tier1_acceptable is not True:
        causal_status = "ineligible_tier1_gate_unknown_or_positive"
    elif True in {matched, tier3, tier4}:
        causal_status = "ineligible_positive_stage"
    else:
        causal_status = "ineligible_unknown_stage"
    return {
        "tier1_measurement_negative": tier1_negative,
        "tier1_gate_acceptable": tier1_acceptable,
        "tier1_gate_status": tier1_gate_status,
        "tier2_positive_exit": matched,
        "tier3_eligible": tier3_eligible,
        "tier3_frozen_direct_prediction": tier3,
        "tier4_eligible": tier4_eligible,
        "tier4_frozen_direct_prediction": tier4,
        "post_tier4_negative": post_tier4_negative,
        "newly_tier3_eligible_vs_frozen_current": (
            current is True and matched is False
            if current is not None and matched is not None
            else None
        ),
        "lost_tier3_eligibility_vs_frozen_current": (
            current is False and matched is True
            if current is not None and matched is not None
            else None
        ),
        "strict_causal_eligible": causal_eligible,
        "strict_causal_status": causal_status,
    }


def _verify_panel(panel: Path) -> dict:
    raw_manifest = _read(panel / "manifest.json")
    manifest = _strict_json(raw_manifest, name="manifest.json")
    files = manifest.get("files")
    if not isinstance(files, dict) or not REQUIRED_PANEL_FILES.issubset(files):
        raise ValueError("Panel manifest does not bind every required source file")
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("Panel manifest contains an invalid file binding")
        if _sha(_read(panel / name)) != digest:
            raise ValueError(f"Panel manifest hash mismatch: {name}")

    raw_plan = _read(panel / "panel-plan.json")
    raw_plan_digest = _read(panel / "panel-plan.sha256")
    raw_config = _read(panel / "panel-config.json")
    raw_references = _read(panel / "references.jsonl")
    raw_results = _read(panel / "results.jsonl")
    raw_summary = _read(panel / "summary.json")
    plan = _strict_json(raw_plan, name="panel-plan.json")
    config = _strict_json(raw_config, name="panel-config.json")
    summary = _strict_json(raw_summary, name="summary.json")
    references = _jsonl(raw_references, name="references.jsonl")
    results = _jsonl(raw_results, name="results.jsonl")
    plan_sha = _sha(raw_plan)
    config_sha = _sha(raw_config)
    reference_sha = _sha(raw_references)
    if raw_plan_digest != (plan_sha + "\n").encode("ascii"):
        raise ValueError("Frozen panel plan digest does not match panel-plan.json")
    if plan.get("reference_sha256") != reference_sha:
        raise ValueError("Frozen plan reference hash does not match references.jsonl")
    if (
        plan.get("config_sha256") != config_sha
        or summary.get("config_sha256") != config_sha
        or plan.get("config") != config
    ):
        raise ValueError("Frozen panel configuration binding is invalid")
    if summary.get("plan_sha256") != plan_sha or summary.get("reference_sha256") != reference_sha:
        raise ValueError("Panel summary does not bind the frozen plan and references")
    if (
        plan.get("protocol") != PANEL_PROTOCOL
        or summary.get("protocol") != PANEL_PROTOCOL
        or manifest.get("protocol") != PANEL_PROTOCOL
        or plan.get("panel_id") != summary.get("panel_id")
        or plan.get("panel_id") != manifest.get("panel_id")
    ):
        raise ValueError("Panel protocol or identity mismatch")
    if manifest.get("status") != "completed" or summary.get("status") != "completed":
        raise ValueError("Sensitivity analysis requires a completed reference panel")
    integrity = summary.get("integrity")
    if not isinstance(integrity, dict) or not integrity or any(value is not True for value in integrity.values()):
        raise ValueError("Panel summary reports incomplete input integrity")
    if (
        plan.get("reference_labels_frozen_before_encoder_creation") is not True
        or plan.get("selection_completed_before_detector_invocation") is not True
        or summary.get("reference_labels_frozen_before_detector_invocation") is not True
        or summary.get("selection_completed_before_detector_invocation") is not True
    ):
        raise ValueError("Panel labels or selection were not frozen before measurement")

    profile = plan.get("profile")
    if (
        not isinstance(profile, dict)
        or profile.get("name") != "ordinary"
        or type(profile.get("lexical_threshold")) not in (int, float)
        or isinstance(profile.get("lexical_threshold"), bool)
        or not math.isclose(profile["lexical_threshold"], ORDINARY_THRESHOLD, abs_tol=0.0)
    ):
        raise ValueError("Panel does not use the frozen ordinary LCS threshold")
    schedule = plan.get("schedule")
    if not isinstance(schedule, list) or len(schedule) != len(references) or len(results) != len(references):
        raise ValueError("Panel schedule, references, and results have different cardinalities")
    limits = plan.get("limits")
    if (
        not isinstance(limits, dict)
        or limits.get("pairs") != 24
        or limits.get("positive_pairs") != 12
        or limits.get("negative_pairs") != 12
        or len(references) != 24
    ):
        raise ValueError("Panel does not retain the frozen 24-pair inventory")
    positive = sum(row.get("reference") is True for row in references)
    negative = sum(row.get("reference") is False for row in references)
    if positive != 12 or negative != 12:
        raise ValueError("Panel does not retain twelve positive and twelve negative references")
    if (
        summary.get("pair_count") != len(references)
        or summary.get("planned_pairs") != len(references)
        or summary.get("recorded_pairs") != len(results)
        or summary.get("reference_label_counts")
        != {"positive": 12, "negative": 12, "unknown": 0}
    ):
        raise ValueError("Panel summary pair accounting is incomplete")

    seen = set()
    for index, (slot, reference, result) in enumerate(zip(schedule, references, results), 1):
        reference_id = reference.get("reference_id")
        if (
            not isinstance(slot, dict)
            or slot.get("record_sequence") != index
            or slot.get("reference_id") != reference_id
            or slot.get("domain") != reference.get("domain")
            or result.get("record_sequence") != index
            or result.get("reference_id") != reference_id
            or reference_id in seen
        ):
            raise ValueError("Panel schedule or result identity mismatch")
        seen.add(reference_id)
        for field in ("reference_id", "domain", "family", "source", "target"):
            _require_ascii(reference.get(field), name=f"reference {field}")
        if type(reference.get("reference")) is not bool:
            raise ValueError("Known-origin panel contains an unknown reference label")
        if any(result.get(key) != value for key, value in reference.items()):
            raise ValueError("Panel result does not preserve its frozen reference row")
        if (
            result.get("protocol") != PANEL_PROTOCOL
            or result.get("panel_id") != plan["panel_id"]
            or result.get("profile") != "ordinary"
        ):
            raise ValueError("Panel result protocol or profile identity mismatch")
        source, target = reference.get("source"), reference.get("target")
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or reference.get("source_sha256") != _sha(source.encode())
            or reference.get("target_sha256") != _sha(target.encode())
        ):
            raise ValueError("Panel source or target binding is invalid")
        baseline = _score(source, target, ALTERNATIVES[0], ORDINARY_THRESHOLD)
        evidence = result.get("evidence")
        frozen = evidence.get("lcs") if isinstance(evidence, dict) else None
        if (
            not isinstance(frozen, dict)
            or frozen.get("status") != "scored"
            or frozen.get("complete") is not True
            or frozen.get("truncated") is not False
            or frozen.get("lcs_length") != baseline.get("lcs_length")
            or frozen.get("matched") is not baseline.get("matched")
            or frozen.get("threshold") != ORDINARY_THRESHOLD
            or type(frozen.get("score")) not in (int, float)
            or isinstance(frozen.get("score"), bool)
            or not math.isclose(frozen["score"], baseline["score"], rel_tol=0.0, abs_tol=1e-15)
        ):
            raise ValueError("Frozen result LCS evidence does not match the bound source and target")

    source_hashes = {"manifest.json": _sha(raw_manifest), **{name: digest for name, digest in files.items()}}
    return {
        "manifest": manifest,
        "plan": plan,
        "summary": summary,
        "references": references,
        "results": results,
        "source_hashes": dict(sorted(source_hashes.items())),
    }


def _analyze_rows(panel: dict) -> list[dict]:
    rows = []
    threshold = panel["plan"]["profile"]["lexical_threshold"]
    for reference, result in zip(panel["references"], panel["results"]):
        baseline = _score(reference["source"], reference["target"], ALTERNATIVES[0], threshold)
        current = baseline["matched"] if baseline["status"] == "scored" else None
        for alternative in ALTERNATIVES:
            score = _score(reference["source"], reference["target"], alternative, threshold)
            prediction = score["matched"] if score["status"] == "scored" else None
            rows.append(
                {
                    "schema_version": 1,
                    "record_sequence": reference["record_sequence"]
                    if "record_sequence" in reference
                    else result["record_sequence"],
                    "reference_id": reference["reference_id"],
                    "domain": reference["domain"],
                    "family": reference["family"],
                    "reference": reference["reference"],
                    "alternative_id": alternative["id"],
                    "alternative_label": alternative["label"],
                    "unit": alternative["unit"],
                    "denominator": alternative["denominator"],
                    "frozen_runtime_baseline": alternative["frozen_runtime_baseline"],
                    "post_hoc_sensitivity": True,
                    "preregistered_result": False,
                    "production_fix": False,
                    **score,
                    "classification": _classify(reference["reference"], prediction),
                    "stage_implications": _stage_implications(result, prediction, current),
                }
            )
    return rows


def _fraction(numerator: int, denominator: int, unknown_count: int = 0) -> dict:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
        "unknown_count": unknown_count,
    }


def _aggregate(rows: list[dict]) -> dict:
    classes = Counter(row["classification"] for row in rows)
    tp, fp, fn, tn = (classes[key] for key in ("tp", "fp", "fn", "tn"))
    evaluated = tp + fp + fn + tn
    statuses = Counter(row["status"] for row in rows)
    implications = [row["stage_implications"] for row in rows]

    def true_count(key):
        return sum(item[key] is True for item in implications)

    def unknown_count(key):
        return sum(item[key] is None for item in implications)

    tier2_scored = sum(row["status"] == "scored" for row in rows)
    tier3_eligible = true_count("tier3_eligible")
    tier4_eligible = true_count("tier4_eligible")
    reachability = {
        "tier2_input_pairs": len(rows),
        "tier2_scored_pairs": tier2_scored,
        "tier2_unknown_pairs": len(rows) - tier2_scored,
        "tier2_positive_exits": sum(row["matched"] is True for row in rows),
        "tier3_eligible": _fraction(
            tier3_eligible,
            tier2_scored,
            unknown_count("tier3_eligible"),
        ),
        "tier3_positive_exits": sum(
            item["tier3_eligible"] is True and item["tier3_frozen_direct_prediction"] is True
            for item in implications
        ),
        "tier4_eligible": _fraction(
            tier4_eligible,
            tier3_eligible,
            unknown_count("tier4_eligible"),
        ),
        "tier4_positive_exits": sum(
            item["tier4_eligible"] is True and item["tier4_frozen_direct_prediction"] is True
            for item in implications
        ),
        "post_tier4_negative": true_count("post_tier4_negative"),
        "post_tier4_unknown": unknown_count("post_tier4_negative"),
        "newly_tier3_eligible_vs_frozen_current": true_count(
            "newly_tier3_eligible_vs_frozen_current"
        ),
        "lost_tier3_eligibility_vs_frozen_current": true_count(
            "lost_tier3_eligibility_vs_frozen_current"
        ),
        "strict_causal_eligible": _fraction(
            true_count("strict_causal_eligible"),
            len(rows),
            0,
        ),
        "strict_causal_status_counts": dict(
            sorted(Counter(item["strict_causal_status"] for item in implications).items())
        ),
    }
    return {
        "pair_count": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "evaluated_pairs": evaluated,
        "unknown_reference": classes["unknown_reference"],
        "unknown_prediction_with_known_reference": classes[
            "unknown_prediction_with_known_reference"
        ],
        "unknown_pairs": len(rows) - evaluated,
        "status_counts": dict(sorted(statuses.items())),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "stage_reachability": reachability,
    }


def _grouped(rows: list[dict], field: str) -> dict:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row[field]].append(row)
    return {
        name: {
            alternative["id"]: _aggregate(
                [row for row in group if row["alternative_id"] == alternative["id"]]
            )
            for alternative in ALTERNATIVES
        }
        for name, group in sorted(grouped.items())
    }


def _metrics_csv(summary: dict) -> bytes:
    stream = io.StringIO(newline="")
    fields = [
        "stratum_type",
        "stratum",
        "alternative_id",
        "pair_count",
        "tp",
        "fp",
        "fn",
        "tn",
        "evaluated_pairs",
        "unknown_reference",
        "unknown_prediction_with_known_reference",
        "precision",
        "recall",
        "f1",
        "tier2_positive_exits",
        "tier3_eligible",
        "tier3_eligibility_unknown",
        "tier4_eligible",
        "tier4_eligibility_unknown",
        "newly_tier3_eligible_vs_frozen_current",
        "strict_causal_eligible",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    sections = [("overall", {"all": summary["overall"]})]
    sections.extend((name, summary[name]) for name in ("domains", "families"))
    for stratum_type, strata in sections:
        for stratum, alternatives in strata.items():
            for alternative in ALTERNATIVES:
                metric = alternatives[alternative["id"]]
                reach = metric["stage_reachability"]
                writer.writerow(
                    {
                        "stratum_type": stratum_type,
                        "stratum": stratum,
                        "alternative_id": alternative["id"],
                        **{key: metric[key] for key in fields[3:14]},
                        "tier2_positive_exits": reach["tier2_positive_exits"],
                        "tier3_eligible": reach["tier3_eligible"]["numerator"],
                        "tier3_eligibility_unknown": reach["tier3_eligible"]["unknown_count"],
                        "tier4_eligible": reach["tier4_eligible"]["numerator"],
                        "tier4_eligibility_unknown": reach["tier4_eligible"]["unknown_count"],
                        "newly_tier3_eligible_vs_frozen_current": reach[
                            "newly_tier3_eligible_vs_frozen_current"
                        ],
                        "strict_causal_eligible": reach["strict_causal_eligible"]["numerator"],
                    }
                )
    return stream.getvalue().encode("ascii")


def _source_snapshot(panel: Path, names: dict[str, str]) -> dict[str, str]:
    return {name: _sha(_read(panel / name)) for name in names}


def analyze_lcs_sensitivity(panel_dir: Path, output: Path) -> dict:
    """Verify a completed panel, then write a new immutable sensitivity report."""
    panel = _local(panel_dir, must_exist=True)
    destination = _local(output, must_exist=False)
    if destination.exists():
        raise FileExistsError(destination)
    if destination.is_relative_to(panel) or panel.is_relative_to(destination):
        raise ValueError("Sensitivity output must be separate from the frozen panel")

    verified = _verify_panel(panel)
    before = _source_snapshot(panel, verified["source_hashes"])
    rows = _analyze_rows(verified)
    overall = {
        alternative["id"]: _aggregate(
            [row for row in rows if row["alternative_id"] == alternative["id"]]
        )
        for alternative in ALTERNATIVES
    }
    summary = {
        "schema_version": 1,
        "method": METHOD,
        "status": "completed",
        "panel_id": verified["plan"]["panel_id"],
        "panel_protocol": verified["plan"]["protocol"],
        "scope": "post_hoc_controlled_known_origin_lcs_sensitivity_only",
        "post_hoc_sensitivity": True,
        "preregistered_result": False,
        "production_fix": False,
        "threshold_selected_on_panel_performance": False,
        "threshold": verified["plan"]["profile"]["lexical_threshold"],
        "alternative_order_selected_before_this_analysis_run": True,
        "alternative_selection_rule": (
            "Emit every fixed alternative in code order; do not rank or select by observed performance."
        ),
        "alternatives": [
            {
                **copy.deepcopy(alternative),
                "threshold": verified["plan"]["profile"]["lexical_threshold"],
                "post_hoc_sensitivity": True,
                "preregistered_result": False,
                "production_fix": False,
            }
            for alternative in ALTERNATIVES
        ],
        "absolute_minimum_evidence_floor": {
            "included": False,
            "reason": "No post-hoc evidence floor was added or tuned on this panel.",
        },
        "tokenization": {
            "pattern": TOKEN_PATTERN.pattern,
            "case_sensitive": True,
            "unicode_normalization": "none",
            "whitespace_tokens": False,
        },
        "pair_count": len(verified["references"]),
        "reference_label_counts": {
            "positive": sum(row["reference"] is True for row in verified["references"]),
            "negative": sum(row["reference"] is False for row in verified["references"]),
            "unknown": sum(type(row["reference"]) is not bool for row in verified["references"]),
        },
        "overall": overall,
        "domains": _grouped(rows, "domain"),
        "families": _grouped(rows, "family"),
        "unknowns": {
            alternative["id"]: {
                "reference": overall[alternative["id"]]["unknown_reference"],
                "prediction_with_known_reference": overall[alternative["id"]][
                    "unknown_prediction_with_known_reference"
                ],
                "stage_reachability": {
                    "tier3": overall[alternative["id"]]["stage_reachability"][
                        "tier3_eligible"
                    ]["unknown_count"],
                    "tier4": overall[alternative["id"]]["stage_reachability"][
                        "tier4_eligible"
                    ]["unknown_count"],
                    "post_tier4": overall[alternative["id"]]["stage_reachability"][
                        "post_tier4_unknown"
                    ],
                },
            }
            for alternative in ALTERNATIVES
        },
        "stage_reachability_scope": (
            "Counterfactual ordered routing using each Tier 2 alternative and the frozen direct Tier 3/4 "
            "component decisions; no semantic component is rerun. Strict causal eligibility still requires "
            "an explicit negative Tier 1 result."
        ),
        "input_integrity": {
            "verified_before_analysis": True,
            "manifest_hashes_verified": True,
            "plan_digest_verified": True,
            "reference_result_identity_verified": True,
            "frozen_baseline_lcs_verified": True,
            "source_files_sha256": before,
        },
        "source_panel_path": str(panel),
        "generative_model_requests": 0,
        "native_agent_runs": 0,
        "external_api_requests": 0,
        "limitations": [
            "All denominator and token alternatives are post-hoc sensitivity analyses, not preregistered results.",
            "No alternative is selected, recommended, or installed as a production fix.",
            "Controlled character-construction references do not establish natural-agent attribution or hidden model reliance.",
            "Stage reachability is recomputed from saved direct component decisions; no agent, model, encoder, tool, or API is run.",
            "The ordinary threshold remains fixed at 0.15 for every alternative and is not tuned on these labels.",
        ],
    }
    after = _source_snapshot(panel, verified["source_hashes"])
    if before != after:
        raise ValueError("Frozen panel changed during sensitivity analysis")
    summary["input_integrity"]["source_files_unchanged_during_analysis"] = True

    result_bytes = b"".join(_canonical(row) + b"\n" for row in rows)
    summary_bytes = _canonical(summary) + b"\n"
    metrics_bytes = _metrics_csv(summary)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".nt-lcs-sensitivity-", dir=destination.parent) as temp:
        staged = Path(temp) / "output"
        staged.mkdir()
        for name, raw in (
            ("results.jsonl", result_bytes),
            ("summary.json", summary_bytes),
            ("metrics.csv", metrics_bytes),
        ):
            with (staged / name).open("xb") as stream:
                stream.write(raw)
        manifest = {
            "schema_version": 1,
            "method": METHOD,
            "status": "completed",
            "immutable_output": True,
            "source_panel_files_sha256": before,
            "files": {
                path.name: _sha(path.read_bytes()) for path in sorted(staged.iterdir()) if path.is_file()
            },
        }
        with (staged / "manifest.json").open("xb") as stream:
            stream.write(_canonical(manifest) + b"\n")
        try:
            staged.replace(destination)
        except FileExistsError:
            raise FileExistsError(destination) from None
    return summary
