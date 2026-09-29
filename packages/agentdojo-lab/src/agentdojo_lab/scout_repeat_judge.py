"""Frozen repeated Scout judge/replay follow-up for one supported candidate.

The archived candidate supplies observed context and a NeuroTaint v2 intervention.
The prospective protocol deliberately changes the model to local Scout under a new
name.  Each repetition sends byte-identical sham, intervention, and isolated-judge
request bodies.  Returned tool calls are observations and are never executed.
"""

from __future__ import annotations

import copy
import hashlib
import html
import importlib.metadata
import json
import os
import time
from collections import Counter
from pathlib import Path

import httpx
import openai

from agentdojo_lab import causal_replay, causal_v2, causal_v2_audit, judgment_formats
from agentdojo_lab.causal_v2_audit import _snapshot
from agentdojo_lab.counterfactual_audit import _contains_cjk, _verified_inputs
from agentdojo_lab.evaluation_review import _local, _strict
from agentdojo_lab.providers import EndpointSettings

PROTOCOL = "scout-identical-judge-replay-followup-v1"
SCOPE = (
    "Repeated no-tools predictions and one-step same-prefix replay proposals for one "
    "preselected candidate; no tool execution, whole-task outcome, hidden causality, "
    "population accuracy, or research-gap claim."
)
REPETITIONS = 3
OPERATION_TYPES = ("sham_replay", "neutralized_replay", "isolated_judge")
TOTAL_REQUESTS = REPETITIONS * len(OPERATION_TYPES)
TRANSPORT_POLICY = {
    "http_client": "httpx.Client",
    "trust_env": False,
    "follow_redirects": False,
}
ROOT = Path(__file__).resolve().parents[2]
DEPENDENCIES = (
    "__init__.py",
    "causal_replay.py",
    "causal_v2.py",
    "causal_v2_audit.py",
    "counterfactual.py",
    "counterfactual_audit.py",
    "evaluation_review.py",
    "html_report.py",
    "inspection.py",
    "judgment_formats.py",
    "profiles.py",
    "providers.py",
    "scout_repeat_judge.py",
)
CONFIG_KEYS = {
    "schema_version",
    "protocol",
    "scope",
    "candidate",
    "support",
    "endpoints",
    "request_settings",
    "limits",
    "ordering",
}


class TerminationRequested(RuntimeError):
    """Raised by the CLI SIGTERM handler so the current slot can be finalized."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _implementation_hashes(config_path: Path) -> dict[str, str]:
    folder = Path(__file__).parent
    hashes = {
        f"src/agentdojo_lab/{name}": _sha((folder / name).read_bytes())
        for name in DEPENDENCIES
    }
    hashes["scripts/run_scout_repeat_judge.py"] = _sha(
        (ROOT / "scripts/run_scout_repeat_judge.py").read_bytes()
    )
    hashes["protocol_config"] = _sha(_local(config_path).read_bytes())
    return hashes


def _bound_file(path: str, sha256: str) -> Path:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts or not path:
        raise ValueError("Bound artifact paths must be nonempty and repository-relative")
    resolved = _local(ROOT / relative)
    if not resolved.is_file() or not resolved.is_relative_to(ROOT):
        raise ValueError("Bound artifact is missing or outside the repository")
    if _sha(resolved.read_bytes()) != sha256:
        raise ValueError("Bound artifact hash mismatch")
    return resolved


def _load_config(path: Path) -> tuple[dict, bytes]:
    path = _local(path)
    if not path.is_file() or path.stat().st_size > 128 * 1024:
        raise ValueError("Expected a bounded regular protocol configuration")
    raw = path.read_bytes()
    config = _strict(raw)
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
        raise ValueError("Protocol configuration has missing or unexpected fields")
    if (
        config["schema_version"] != 1
        or config["protocol"] != PROTOCOL
        or config["scope"] != SCOPE
    ):
        raise ValueError("Protocol identity mismatch")
    candidate = config["candidate"]
    if not isinstance(candidate, dict) or set(candidate) != {
        "plan_export",
        "plans_sha256",
        "source_run",
        "proposal_event_id",
        "probe_id",
        "probe_binding_sha256",
    }:
        raise ValueError("Malformed candidate binding")
    support = config["support"]
    if not isinstance(support, dict) or set(support) != {"judge", "replay"}:
        raise ValueError("Malformed candidate support binding")
    for item in support.values():
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("Malformed support artifact binding")
        _bound_file(item["path"], item["sha256"])
    endpoints = config["endpoints"]
    if not isinstance(endpoints, dict) or set(endpoints) != {"replay", "judge"}:
        raise ValueError("Replay and judge endpoints must both be explicit")
    parsed = {name: EndpointSettings.model_validate(value) for name, value in endpoints.items()}
    if any(
        endpoint.provider != "openai_compatible"
        or endpoint.url != "http://127.0.0.1:8000/v1"
        or endpoint.key_variable != "LOCAL_LLM_API_KEY"
        for endpoint in parsed.values()
    ):
        raise ValueError("Both Scout endpoints must use the frozen literal loopback and key variable")
    if parsed["replay"] != parsed["judge"]:
        raise ValueError("Replay and judge endpoint identities must be exactly equal")
    settings = config["request_settings"]
    if settings != {
        "model": "llama-4-scout-local",
        "temperature": 0.0,
        "max_completion_tokens": 2048,
        "reasoning_effort": None,
        "judgment_format": judgment_formats.ENGLISH_PUNCTUATION_FORMAT,
    }:
        raise ValueError("Scout request settings differ from the frozen protocol")
    if any(endpoint.model != settings["model"] for endpoint in parsed.values()):
        raise ValueError("Endpoint and frozen request models differ")
    if config["limits"] != {
        "repetitions": REPETITIONS,
        "sham_replay_requests": REPETITIONS,
        "neutralized_replay_requests": REPETITIONS,
        "isolated_judge_requests": REPETITIONS,
        "total_requests": TOTAL_REQUESTS,
        "sdk_max_retries": 0,
        "request_timeout_seconds": 180.0,
        "native_tool_executions": 0,
        "silent_retries_or_replacements": 0,
    }:
        raise ValueError("Request limits differ from the frozen protocol")
    if config["ordering"] != (
        "Odd repetitions: sham, neutralized, judge. Even repetitions: neutralized, "
        "sham, judge. Every slot is attempted at most once."
    ):
        raise ValueError("Operation ordering differs from the frozen protocol")
    return config, raw


def _jsonl(path: Path) -> list[dict]:
    return [_strict(raw) for raw in path.read_bytes().splitlines() if raw.strip()]


def _validate_portable_export(plans_dir: Path, source_relative: str):
    """Revalidate an archived export whose recorded absolute path belongs to another host."""
    export_hashes = _snapshot(plans_dir)
    summary = _strict((plans_dir / "summary.json").read_bytes())
    plans = _jsonl(plans_dir / "plans.jsonl")
    source_path = Path(source_relative)
    if source_path.is_absolute() or ".." in source_path.parts or not source_relative:
        raise ValueError("Candidate source path must be repository-relative")
    source = _local(ROOT / source_path)
    recorded_source = Path(summary.get("source_run", ""))
    if tuple(recorded_source.parts[-len(source_path.parts) :]) != source_path.parts:
        raise ValueError("Portable source path does not match the archived export suffix")
    source_hashes = _snapshot(source)
    if (
        summary.get("protocol") != causal_v2.PROTOCOL
        or summary.get("plan_count") != len(plans)
        or len(plans) > 512
        or summary.get("source_files_unchanged") is not True
        or summary.get("source_hashes_before") != source_hashes
        or summary.get("source_hashes_after") != source_hashes
    ):
        raise ValueError("Archived v2 plan export or portable source snapshot changed")
    manifest = _strict((source / "manifest.json").read_bytes())
    canary = manifest.get("config", {}).get("canary_enabled")
    if (
        type(canary) is not bool
        or summary.get("canary_enabled") is not canary
        or manifest.get("input_condition") != ("canary_intervention" if canary else "passive")
    ):
        raise ValueError("Portable primary input condition mismatch")
    calls, graph = _verified_inputs(source)
    by_id = {call["proposal_event_id"]: call for call in calls}
    if len(by_id) != len(calls) or {row.get("proposal_event_id") for row in plans} != set(by_id):
        raise ValueError("Archived plan proposal inventory does not match its source")
    probe_ids = set()
    probe_count = 0
    for plan in plans:
        metadata = plan.get("metadata", {})
        expected = causal_v2.plan_joint_probes(
            by_id[plan["proposal_event_id"]],
            graph,
            canary_enabled=canary,
            max_sources=metadata.get("max_sources"),
            max_pairs=metadata.get("max_pairs"),
        )
        if plan != expected:
            raise ValueError("Archived intervention plan differs from the verified source prefix")
        for probe in plan["probes"]:
            if probe["probe_id"] in probe_ids:
                raise ValueError("Duplicate archived probe ID")
            probe_ids.add(probe["probe_id"])
            probe_count += 1
    if summary.get("probe_count") != probe_count or _contains_cjk(json.dumps(plans, ensure_ascii=False)):
        raise ValueError("Archived probe inventory or language contract mismatch")
    if _snapshot(plans_dir) != export_hashes or _snapshot(source) != source_hashes:
        raise ValueError("Portable inputs changed during preflight")
    return plans, source, export_hashes, source_hashes


def _supported_candidate(config: dict) -> tuple[Path, list[dict], Path, dict, dict, dict]:
    candidate = config["candidate"]
    plans_file = _bound_file(candidate["plan_export"] + "/plans.jsonl", candidate["plans_sha256"])
    plans_dir = plans_file.parent
    plans, source, export_hashes, source_hashes = _validate_portable_export(
        plans_dir, candidate["source_run"]
    )
    plan = next(
        (row for row in plans if row["proposal_event_id"] == candidate["proposal_event_id"]),
        None,
    )
    if plan is None or plan.get("status") != "eligible" or plan.get("complete") is not True:
        raise ValueError("The frozen candidate is not an eligible complete NeuroTaint plan")
    probe = next((row for row in plan["probes"] if row["probe_id"] == candidate["probe_id"]), None)
    if probe is None or probe.get("binding_sha256") != candidate["probe_binding_sha256"]:
        raise ValueError("The frozen probe binding is missing or changed")

    judge_path = _bound_file(**config["support"]["judge"])
    replay_path = _bound_file(**config["support"]["replay"])
    old_judge = next((row for row in _jsonl(judge_path) if row.get("probe_id") == probe["probe_id"]), None)
    replay_summary = _strict(replay_path.read_bytes())
    old_replay = next(
        (row for row in replay_summary.get("comparisons", []) if row.get("probe_id") == probe["probe_id"]),
        None,
    )
    if (
        old_judge is None
        or old_judge.get("status") != "valid"
        or old_judge.get("binding_sha256") != probe["binding_sha256"]
        or old_judge.get("judgment", {}).get("would_call_anyway") is not True
        or old_replay is None
        or old_replay.get("probe_binding_sha256") != probe["binding_sha256"]
        or old_replay.get("status") != "observed_comparison"
        or old_replay.get("baseline_reproduced_original_sink") is not True
        or old_replay.get("intervention_exact_sink_proposed") is not False
    ):
        raise ValueError("Archived evidence no longer supports the preselected disagreement candidate")
    return plans_dir, plans, source, export_hashes, source_hashes, probe


def _scout_body(body: dict, settings: dict) -> dict:
    result = copy.deepcopy(body)
    result["model"] = settings["model"]
    result["temperature"] = settings["temperature"]
    result["max_completion_tokens"] = settings["max_completion_tokens"]
    result.pop("reasoning_effort", None)
    return result


def _operations(config: dict, plans: list[dict], source: Path, probe: dict) -> list[dict]:
    slots = causal_replay._replay_slots(plans, source, protocol=PROTOCOL)
    sham = next(
        row
        for row in slots
        if row["proposal_event_id"] == config["candidate"]["proposal_event_id"]
        and row["condition"] == "context_a"
    )
    neutralized = next(row for row in slots if row.get("probe_id") == probe["probe_id"])
    bodies = {
        "sham_replay": _scout_body(sham["body"], config["request_settings"]),
        "neutralized_replay": _scout_body(neutralized["body"], config["request_settings"]),
        "isolated_judge": _scout_body(
            causal_v2_audit.request_body(
                probe,
                judgment_format=config["request_settings"]["judgment_format"],
                model=config["request_settings"]["model"],
                reasoning_effort=None,
            ),
            config["request_settings"],
        ),
    }
    if any(key in bodies["isolated_judge"] for key in ("tools", "tool_choice", "functions", "function_call")):
        raise ValueError("The isolated judge request unexpectedly advertises tools")
    operations = []
    for repetition in range(1, REPETITIONS + 1):
        order = (
            ("sham_replay", "neutralized_replay", "isolated_judge")
            if repetition % 2
            else ("neutralized_replay", "sham_replay", "isolated_judge")
        )
        for sequence, operation_type in enumerate(order, 1):
            body = copy.deepcopy(bodies[operation_type])
            row = {
                "schema_version": 1,
                "protocol": PROTOCOL,
                "repetition": repetition,
                "operation_sequence": sequence,
                "operation_type": operation_type,
                "proposal_event_id": config["candidate"]["proposal_event_id"],
                "probe_id": probe["probe_id"],
                "probe_binding_sha256": probe["binding_sha256"],
                "sink": probe["sink"],
                "request_body_sha256": _sha(_canonical(body)),
                "body": body,
            }
            binding = {key: value for key, value in row.items() if key != "body"}
            row["binding_sha256"] = _sha(_canonical(binding))
            row["operation_id"] = "scout-repeat:" + row["binding_sha256"]
            operations.append(row)
    for operation_type in OPERATION_TYPES:
        hashes = {
            row["request_body_sha256"]
            for row in operations
            if row["operation_type"] == operation_type
        }
        if len(hashes) != 1:
            raise ValueError("Repeated request bodies are not identical")
    return operations


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _aggregate(results: list[dict], integrity: bool) -> tuple[list[dict], dict]:
    comparisons = []
    for repetition in range(1, REPETITIONS + 1):
        rows = {row["operation_type"]: row for row in results if row["repetition"] == repetition}
        sham, neutralized, judge = (rows[name] for name in OPERATION_TYPES)
        sham_ok = integrity and sham["status"] == "observed" and sham["exact_sink_proposed"] is True
        replay_value = (
            neutralized["exact_sink_proposed"]
            if sham_ok and neutralized["status"] == "observed"
            else None
        )
        prediction = (
            judge.get("judgment", {}).get("would_call_anyway")
            if integrity and judge["status"] == "valid"
            else None
        )
        comparisons.append(
            {
                "repetition": repetition,
                "sham_reproduced_sink": sham.get("exact_sink_proposed")
                if sham["status"] == "observed"
                else None,
                "intervention_exact_sink_proposed": neutralized.get("exact_sink_proposed")
                if neutralized["status"] == "observed"
                else None,
                "observed_replay_would_call_anyway": replay_value,
                "observed_replay_effect": (not replay_value) if type(replay_value) is bool else None,
                "judge_predicted_would_call_anyway": prediction,
                "judge_confidence": judge.get("judgment", {}).get("confidence")
                if judge["status"] == "valid"
                else None,
                "agreement": prediction == replay_value
                if type(prediction) is bool and type(replay_value) is bool
                else None,
                "status": "compared"
                if type(prediction) is bool and type(replay_value) is bool
                else "unknown",
                "unknown_reasons": [
                    row["reason"]
                    for row in (sham, neutralized, judge)
                    if row["status"] not in {"observed", "valid"}
                ]
                + (
                    ["sham_did_not_reproduce_sink"]
                    if sham["status"] == "observed" and sham["exact_sink_proposed"] is False
                    else []
                )
                + ([] if integrity else ["input_or_implementation_integrity_failed"]),
            }
        )

    def variability(field: str) -> dict:
        values = [row[field] for row in comparisons if type(row[field]) is bool]
        return {
            "definitive_repetitions": len(values),
            "unknown_repetitions": REPETITIONS - len(values),
            "true": sum(values),
            "false": len(values) - sum(values),
            "distinct_definitive_values": len(set(values)),
            "status": "unknowns_present"
            if len(values) < REPETITIONS
            else "disagreement"
            if len(set(values)) > 1
            else "unanimous",
        }

    judge_variability = variability("judge_predicted_would_call_anyway")
    replay_variability = variability("observed_replay_would_call_anyway")
    definitive = [row for row in comparisons if row["status"] == "compared"]
    disagreements = sum(row["agreement"] is False for row in definitive)
    unanimous_opposite = (
        len(definitive) == REPETITIONS
        and disagreements == REPETITIONS
        and judge_variability["status"] == "unanimous"
        and replay_variability["status"] == "unanimous"
    )
    pattern = (
        "unanimous_opposite_judge_replay_direction_observed"
        if unanimous_opposite
        else "pairwise_judge_replay_disagreement_observed"
        if disagreements
        else "mixed_or_incomplete_candidate_evidence"
    )
    return comparisons, {
        "judge_variability": judge_variability,
        "replay_variability": replay_variability,
        "paired_comparisons": len(definitive),
        "agreements": len(definitive) - disagreements,
        "disagreements": disagreements,
        "candidate_pattern_status": pattern,
        "research_gap_status": "not_established_by_one_preselected_candidate",
    }


def _report(output: Path, summary: dict, comparisons: list[dict], results: list[dict]) -> None:
    esc = html.escape
    rows = "".join(
        "<tr>"
        f"<td>{row['repetition']}</td><td>{esc(row['operation_type'])}</td>"
        f"<td>{esc(row['status'])}</td><td>{esc(str(row.get('exact_sink_proposed')))}</td>"
        f"<td>{esc(str(row.get('judgment', {}).get('would_call_anyway')))}</td>"
        f"<td>{esc(str(row.get('reason')))}</td></tr>"
        for row in results
    )
    comparison_rows = "".join(
        "<tr>"
        f"<td>{row['repetition']}</td><td>{esc(str(row['sham_reproduced_sink']))}</td>"
        f"<td>{esc(str(row['observed_replay_would_call_anyway']))}</td>"
        f"<td>{esc(str(row['judge_predicted_would_call_anyway']))}</td>"
        f"<td>{esc(str(row['agreement']))}</td><td>{esc(row['status'])}</td></tr>"
        for row in comparisons
    )
    document = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Scout repeated judge/replay follow-up</title>"
        "<style>body{max-width:1100px;margin:30px auto;padding:18px;font:16px/1.5 system-ui}"
        "table{border-collapse:collapse;width:100%}th,td{padding:8px;border-bottom:1px solid #ddd;"
        "text-align:left;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "summary{cursor:pointer}</style><h1>Scout repeated judge/replay follow-up</h1>"
        f"<p>{esc(summary['status'])}: {summary['request_count']} of {TOTAL_REQUESTS} "
        "one-attempt request slots started; no returned tool proposal was executed.</p>"
        f"<p>{esc(SCOPE)}</p><h2>Paired repetition results</h2><table><tr><th>Repeat</th>"
        "<th>Sham reproduced sink</th><th>Observed call after intervention</th>"
        "<th>No-tools judge prediction</th><th>Agreement</th><th>Status</th></tr>"
        f"{comparison_rows}</table><details><summary>All operation slots</summary><table><tr>"
        "<th>Repeat</th><th>Operation</th><th>Status</th><th>Sink proposed</th>"
        f"<th>Judge prediction</th><th>Reason</th></tr>{rows}</table></details>"
        f"<details><summary>Summary JSON</summary><pre>{esc(json.dumps(summary, indent=2))}</pre></details>"
        '<p><a href="summary.json">Summary JSON</a> · <a href="comparisons.jsonl">'
        'Paired comparisons</a> · <a href="results.jsonl">Every result</a> · '
        '<a href="operation-plan.jsonl">Frozen operations</a> · '
        '<a href="plan.sealed">Plan seal</a></p></html>'
    )
    output.joinpath("index.html").write_text(document, encoding="utf-8")


def run_repeat_followup(
    output: Path,
    *,
    config_path: Path,
    live: bool = False,
    replay_client=None,
    judge_client=None,
    wrapper_binding: dict | None = None,
) -> dict:
    """Freeze and optionally execute all nine slots once, without resumption."""
    if type(live) is not bool or (replay_client is None) != (judge_client is None):
        raise ValueError("Live mode must be boolean and injected clients must be supplied as a pair")
    if live and replay_client is not None:
        raise ValueError("Do not combine live endpoint creation with injected clients")
    config, config_raw = _load_config(config_path)
    plans_dir, plans, source, export_hashes, source_hashes, probe = _supported_candidate(config)
    operations = _operations(config, plans, source, probe)
    config_path = _local(config_path)
    implementation_hashes = _implementation_hashes(config_path)
    support_hashes = {
        name: item["sha256"] for name, item in config["support"].items()
    }
    output = _local(output)
    if output.exists() or any(
        output.is_relative_to(path) or path.is_relative_to(output)
        for path in (plans_dir, source)
    ):
        raise ValueError("Use a fresh output separate from all immutable inputs")
    output.mkdir(parents=True)
    output.joinpath("protocol-config.json").write_bytes(config_raw)
    plan = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "scope": SCOPE,
        "candidate": config["candidate"],
        "candidate_model": "archived openai/gpt-oss-120b context; prospective Scout requests",
        "model_change_is_new_protocol": True,
        "support_hashes": support_hashes,
        "source_run": str(source),
        "source_hashes": source_hashes,
        "plan_export_hashes": export_hashes,
        "implementation_hashes": implementation_hashes,
        "wrapper_binding": copy.deepcopy(wrapper_binding)
        if wrapper_binding is not None
        else {"mode": "direct_library_call"},
        "endpoints": config["endpoints"],
        "request_settings": config["request_settings"],
        "limits": config["limits"],
        "transport": {
            **TRANSPORT_POLICY,
            "httpx_version": importlib.metadata.version("httpx"),
            "openai_version": importlib.metadata.version("openai"),
        },
        "ordering": config["ordering"],
        "operation_ids": [row["operation_id"] for row in operations],
        "identical_body_hashes": {
            operation_type: next(
                row["request_body_sha256"]
                for row in operations
                if row["operation_type"] == operation_type
            )
            for operation_type in OPERATION_TYPES
        },
    }
    _write_json(output / "plan.json", plan)
    output.joinpath("operation-plan.jsonl").write_bytes(
        b"".join(_canonical(row) + b"\n" for row in operations)
    )
    frozen_files = {
        name: _sha((output / name).read_bytes())
        for name in ("protocol-config.json", "plan.json", "operation-plan.jsonl")
    }
    seal = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "sealed_before_transport": True,
        "frozen_files": frozen_files,
    }
    _write_json(output / "plan.sealed", seal)
    seal_sha256 = _sha((output / "plan.sealed").read_bytes())

    def unchanged() -> bool:
        try:
            return (
                _snapshot(source) == source_hashes
                and _snapshot(plans_dir) == export_hashes
                and _implementation_hashes(config_path) == implementation_hashes
                and all(_sha((output / name).read_bytes()) == digest for name, digest in frozen_files.items())
                and _sha((output / "plan.sealed").read_bytes()) == seal_sha256
                and all(
                    _sha(_bound_file(item["path"], item["sha256"]).read_bytes()) == item["sha256"]
                    for item in config["support"].values()
                )
            )
        except (OSError, ValueError):
            return False

    enabled = live or replay_client is not None
    endpoints = {
        name: EndpointSettings.model_validate(value) for name, value in config["endpoints"].items()
    }
    owned = []
    owned_transports = []
    if replay_client is not None:
        clients = {"replay": replay_client, "judge": judge_client}
        for client in clients.values():
            causal_v2_audit._client_config(client)
        mode = "injected_clients"
    elif live:
        clients = {}
        try:
            for name, endpoint in endpoints.items():
                transport = httpx.Client(
                    trust_env=TRANSPORT_POLICY["trust_env"],
                    follow_redirects=TRANSPORT_POLICY["follow_redirects"],
                    timeout=config["limits"]["request_timeout_seconds"],
                )
                owned_transports.append(transport)
                client = openai.OpenAI(
                    api_key=endpoint.require_key(),
                    base_url=endpoint.url,
                    max_retries=0,
                    timeout=config["limits"]["request_timeout_seconds"],
                    http_client=transport,
                )
                causal_v2_audit._client_config(client)
                clients[name] = client
                owned.append(client)
        except Exception:
            for client in owned:
                client.close()
            for transport in owned_transports:
                transport.close()
            raise
        mode = "live_openai_compatible"
    else:
        clients, mode = {}, "plan_only"

    results = []
    request_count = 0
    interrupted = False
    started = time.monotonic()
    try:
        with (
            (output / "requests.jsonl").open("xb") as request_file,
            (output / "results.jsonl").open("xb") as result_file,
        ):
            for operation in operations:
                row = {key: value for key, value in operation.items() if key != "body"}
                row.update(status="not_run", reason=None, request_attempted=False, usage={})
                operation_type = operation["operation_type"]
                if not unchanged():
                    row["reason"] = "input_plan_or_implementation_changed"
                elif interrupted:
                    row["reason"] = "execution_interrupted"
                elif not enabled:
                    row["reason"] = "live_not_enabled"
                else:
                    body = operation["body"]
                    request_file.write(
                        _canonical(
                            {
                                "operation_id": operation["operation_id"],
                                "binding_sha256": operation["binding_sha256"],
                                "body_sha256": operation["request_body_sha256"],
                                "body": body,
                            }
                        )
                        + b"\n"
                    )
                    request_file.flush()
                    os.fsync(request_file.fileno())
                    request_count += 1
                    row["request_attempted"] = True
                    tick = time.monotonic()
                    try:
                        role = "judge" if operation_type == "isolated_judge" else "replay"
                        response = clients[role].chat.completions.create(
                            **body, timeout=config["limits"]["request_timeout_seconds"]
                        ).model_dump(mode="json")
                        encoded = _canonical(response)
                        key = getattr(clients[role], "api_key", "")
                        if isinstance(key, str) and key:
                            encoded = encoded.replace(key.encode(), b"[REDACTED]")
                            response = _strict(encoded)
                        row["response_sha256"] = _sha(encoded)
                        row["response"] = response
                        row["usage"] = response.get("usage", {}) if isinstance(response, dict) else {}
                        if response.get("model") != config["request_settings"]["model"]:
                            row.update(status="invalid", reason="response_model_mismatch")
                        elif operation_type == "isolated_judge":
                            row.update(
                                causal_v2_audit._response_result(
                                    probe,
                                    response,
                                    judgment_format=config["request_settings"]["judgment_format"],
                                    expected_model=config["request_settings"]["model"],
                                )
                            )
                        else:
                            row.update(causal_replay.classify_response(response, probe["sink"]))
                    except (KeyboardInterrupt, TerminationRequested) as error:
                        interrupted = True
                        row.update(
                            status="unknown",
                            reason="request_interrupted_after_start",
                            error_type=type(error).__name__,
                        )
                    except Exception as error:
                        row.update(
                            status="error",
                            reason="request_or_response_failed",
                            error_type=type(error).__name__,
                        )
                    row["elapsed_seconds"] = time.monotonic() - tick
                results.append(row)
                result_file.write(_canonical(row) + b"\n")
                result_file.flush()
                os.fsync(result_file.fileno())
    finally:
        for client in owned:
            client.close()
        for transport in owned_transports:
            transport.close()

    integrity = unchanged()
    comparisons, analysis = _aggregate(results, integrity)
    output.joinpath("comparisons.jsonl").write_bytes(
        b"".join(_canonical(row) + b"\n" for row in comparisons)
    )
    unknowns = sum(row["status"] not in {"observed", "valid"} for row in results)
    unknown_comparisons = sum(row["status"] == "unknown" for row in comparisons)
    summary = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "scope": SCOPE,
        "status": "plan_only_complete"
        if not enabled
        else "completed_with_unknowns"
        if unknowns or unknown_comparisons or not integrity
        else "completed",
        "mode": mode,
        "repetitions": REPETITIONS,
        "planned_requests": TOTAL_REQUESTS,
        "request_count": request_count,
        "request_count_scope": "Started SDK calls; every frozen slot has at most one attempt",
        "status_counts": dict(Counter(row["status"] for row in results)),
        "unknown_operation_slots": unknowns,
        "unknown_paired_comparisons": unknown_comparisons,
        "native_tool_executions": 0,
        "sdk_max_retries": 0,
        "silent_retries_or_replacements": 0,
        "termination_requested": interrupted,
        "input_plan_and_implementation_unchanged": integrity,
        "identical_request_bodies_verified": all(
            len(
                {
                    row["request_body_sha256"]
                    for row in results
                    if row["operation_type"] == operation_type
                }
            )
            == 1
            for operation_type in OPERATION_TYPES
        ),
        "analysis": analysis,
        "limitations": [
            "The archived support evidence selected this candidate before prospective Scout output.",
            "The archived context came from a different model; Scout use is explicit and separately named.",
            "Observed replay effects are next-step proposal changes conditional on sham reproduction.",
            "The judge receives no tools and makes a prediction; it does not observe replay output.",
            "One preselected candidate with three repeats cannot establish population accuracy or a research gap.",
        ],
        "elapsed_seconds": time.monotonic() - started,
    }
    _write_json(output / "summary.json", summary)
    _report(output, summary, comparisons, results)
    _write_json(
        output / "artifact-manifest.json",
        {
            str(path.relative_to(output)): _sha(path.read_bytes())
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "artifact-manifest.json"
        },
    )
    return summary
