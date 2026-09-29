"""Offline descriptive comparison of a prospectively selected clean/attacked pair.

This compares recorded tool proposals, not hidden reasoning or causal influence.
Sensitive paths are an explicit reporting choice, not an attack-success oracle.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote

from agentdojo_lab.html_report import collect_run_record

DEFAULT_SENSITIVE_PATHS = {"send_email": ["/recipients", "/cc", "/bcc", "/attachments"]}
SCOPE = (
    "Descriptive clean/attacked comparison of recorded tool proposals. The first tool-proposal "
    "divergence means the first difference in that sequence; assistant prose, injected input, "
    "and hidden reasoning are outside this comparison. Security relevance means a configured "
    "tool/argument path differs, not that an attack succeeded. Exposure is not causal influence. "
    "Execution and observed native state changes are reported separately. Repeated judgments, "
    "counterfactual effects, and complete propagation attribution require separate evidence. "
    "Cross-session memory comparison is not implemented; multiple episodes remain unaligned. "
    "Arm labels are caller supplied. Initial environment differences are shown without validating "
    "whether they conform to the separate experiment protocol."
)


def _equal(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False) == json.dumps(
        b, sort_keys=True, ensure_ascii=False
    )


def json_changes(before, after, path=""):
    """Typed JSON differences; absence is distinct from an explicit null."""
    if _equal(before, after):
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        rows = []
        for key in sorted(before.keys() | after.keys()):
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before or key not in after:
                rows.append(
                    {
                        "path": pointer,
                        "before_present": key in before,
                        "after_present": key in after,
                        "before": before.get(key),
                        "after": after.get(key),
                    }
                )
            else:
                rows.extend(json_changes(before[key], after[key], pointer))
        return rows
    if isinstance(before, list) and isinstance(after, list):
        rows = []
        for index in range(max(len(before), len(after))):
            pointer = f"{path}/{index}"
            if index >= min(len(before), len(after)):
                rows.append(
                    {
                        "path": pointer,
                        "before_present": index < len(before),
                        "after_present": index < len(after),
                        "before": before[index] if index < len(before) else None,
                        "after": after[index] if index < len(after) else None,
                    }
                )
            else:
                rows.extend(json_changes(before[index], after[index], pointer))
        return rows
    return [{"path": path, "before_present": True, "after_present": True, "before": before, "after": after}]


def _ref(event):
    return {
        key: event.get(key) for key in ("event_id", "event_sequence", "task_id", "episode_id", "call_ref")
    }


def _actions(record):
    events = record["events"]
    actions = []
    for proposal in events:
        if proposal.get("event_type") != "TOOL_CALL_PROPOSED":
            continue
        call_ref = proposal.get("call_ref")
        linked = [e for e in events if call_ref and e.get("call_ref") == call_ref]
        starts = [e for e in linked if e.get("event_type") == "TOOL_RUNTIME_STARTED"]
        returns = [e for e in linked if e.get("event_type") == "TOOL_RUNTIME_RETURNED"]
        changes = [e for e in linked if e.get("event_type") == "ENVIRONMENT_CHANGE"]
        start = starts[0] if len(starts) == 1 else None
        returned = returns[0] if len(returns) == 1 else None
        bound = bool(
            start
            and returned
            and proposal["event_id"] in start.get("parent_event_ids", [])
            and start["event_id"] in returned.get("parent_event_ids", [])
            and start["data"].get("function") == proposal["data"].get("function")
            and _equal(start["data"].get("runtime_input_args"), proposal["data"].get("arguments"))
            and proposal["event_sequence"] < start["event_sequence"] < returned["event_sequence"]
        )
        state = "unconfirmed"
        if bound and {"error", "raised_exception_type"} <= returned["data"].keys():
            state = (
                "returned_successfully"
                if all(returned["data"][key] is None for key in ("error", "raised_exception_type"))
                else "returned_with_error"
            )
        state_changes = []
        for event in changes:
            data = event["data"]
            change_bound = bool(
                bound
                and returned["event_id"] in event.get("parent_event_ids", [])
                and returned["event_sequence"] < event["event_sequence"]
            )
            state_changes.append(
                {
                    **_ref(event),
                    "bound_to_return": change_bound,
                    "changes": json_changes(data.get("before"), data.get("after")),
                }
            )
        exposures = [
            e
            for e in events
            if e.get("event_type") == "TOOL_OUTPUT_EXPOSED"
            and e.get("model_request_id") == proposal.get("model_request_id")
            and e["event_sequence"] < proposal["event_sequence"]
        ]
        actions.append(
            {
                **_ref(proposal),
                "function": proposal["data"].get("function"),
                "arguments": proposal["data"].get("arguments"),
                "execution": {
                    "status": state,
                    "runtime_starts": list(map(_ref, starts)),
                    "runtime_returns": list(map(_ref, returns)),
                    "observed_environment_changes": state_changes,
                },
                "source_exposures_in_request": [
                    {**_ref(e), "source_result_event_id": e["data"].get("source_result_event_id")}
                    for e in exposures
                ],
            }
        )
    return actions


def align_actions(clean, attacked):
    """Minimum edit alignment, with all equally optimal choices counted up to two.

    Exact same-function/argument pairs cost zero, same-function changed arguments
    cost one, and insertion/removal cost one. Different functions never pair.
    A displayed optimal alignment is only a hypothesis about corresponding calls.
    """
    n, m = len(clean), len(attacked)
    if n > 500 or m > 500:
        raise ValueError("This small-pair report supports at most 500 proposals per arm")
    costs = [[0] * (m + 1) for _ in range(n + 1)]
    ways = [[1] * (m + 1) for _ in range(n + 1)]
    choices = {}
    for i in range(n, -1, -1):
        for j in range(m, -1, -1):
            if (i, j) == (n, m):
                continue
            options = []
            if i < n and j < m and clean[i]["function"] == attacked[j]["function"]:
                delta = int(not _equal(clean[i]["arguments"], attacked[j]["arguments"]))
                options.append((delta + costs[i + 1][j + 1], "paired", i + 1, j + 1))
            if i < n:
                options.append((1 + costs[i + 1][j], "omitted_in_attacked", i + 1, j))
            if j < m:
                options.append((1 + costs[i][j + 1], "inserted_in_attacked", i, j + 1))
            best = min(option[0] for option in options)
            optimal = [option for option in options if option[0] == best]
            costs[i][j] = best
            ways[i][j] = min(2, sum(ways[ni][nj] for _, _, ni, nj in optimal))
            choices[i, j] = optimal[0]
    rows = []
    i = j = 0
    while (i, j) != (n, m):
        _, kind, ni, nj = choices[i, j]
        left, right = clean[i] if ni > i else None, attacked[j] if nj > j else None
        changed = json_changes(left["arguments"], right["arguments"]) if left and right else []
        rows.append(
            {
                "index": len(rows),
                "status": kind,
                "clean_index": i if left else None,
                "attacked_index": j if right else None,
                "clean_event_id": left["event_id"] if left else None,
                "attacked_event_id": right["event_id"] if right else None,
                "function": (left or right)["function"],
                "argument_changes": changed,
                "different": kind != "paired" or bool(changed),
            }
        )
        i, j = ni, nj
    return {
        "status": "ambiguous" if ways[0][0] > 1 else "unique_under_rule",
        "optimal_alignment_count_capped_at_two": ways[0][0],
        "edit_cost": costs[0][0],
        "rule": "exact=0; same-function argument change=1; insertion/removal=1; other pairing forbidden",
        "rows": rows,
    }


def _overlaps(path, root):
    return path == root or path.startswith(root + "/") or root.startswith(path + "/")


def compare_records(clean, attacked, *, sensitive_paths=None):
    sensitive = DEFAULT_SENSITIVE_PATHS if sensitive_paths is None else sensitive_paths
    if not isinstance(sensitive, dict) or any(
        not isinstance(name, str)
        or not isinstance(paths, list)
        or any(not isinstance(path, str) or not path.startswith("/") for path in paths)
        for name, paths in sensitive.items()
    ):
        raise ValueError("Sensitive paths must map tool names to lists of absolute JSON Pointers")
    records = [clean, attacked]
    reasons = []
    manifests = [r["manifest"] for r in records]
    raw_configs = [r.get("config") for r in manifests]
    configs = [config if isinstance(config, dict) else {} for config in raw_configs]
    run_local = []
    # Namespace isolates independently recorded runs. Keep its exact values in
    # the result, while comparing every experimental setting without exemptions.
    namespaces = [config.get("lineage_namespace") for config in configs]
    if not _equal(*namespaces):
        run_local.append(
            {
                "path": "/lineage_namespace",
                "clean": namespaces[0],
                "attacked": namespaces[1],
                "reason": "run-local lineage isolation; cross-session comparison is unsupported",
            }
        )
    comparable_configs = [
        {key: value for key, value in config.items() if key != "lineage_namespace"} for config in configs
    ]
    if any(not isinstance(config, dict) for config in raw_configs) or not _equal(*comparable_configs):
        reasons.append("manifest configurations differ or are missing")
    for key in ("real_llm", "endpoint", "upstream", "adapter", "defense"):
        if not _equal(*(manifest.get(key) for manifest in manifests)):
            reasons.append(f"manifest {key} differs")
    for key in ("policy", "semantic", "implementation_sha256"):
        settings = [(manifest.get("online_provenance") or {}).get(key) for manifest in manifests]
        if not _equal(*settings):
            reasons.append(f"recorded online provenance {key} differs")
    if any(not config.get("user_tasks") for config in configs):
        reasons.append("task identity is missing")
    requests = [[e for e in r["events"] if e.get("event_type") == "MODEL_REQUEST"] for r in records]
    if any(not request for request in requests):
        reasons.append("initial model request is missing")
    elif not _equal(*(request[0]["data"].get("body") for request in requests)):
        reasons.append("initial model request bodies differ")
    initial_environments = []
    for name, record in zip(("clean", "attacked"), records, strict=True):
        if (record.get("audit") or {}).get("valid") is not True or record["summary"].get("recording", {}).get(
            "complete"
        ) is not True:
            reasons.append(f"{name} recording integrity is unconfirmed")
        episodes = [e for e in record["events"] if e.get("event_type") == "EPISODE_STARTED"]
        initial_environments.append(episodes[0]["data"].get("environment") if episodes else None)
        if len(episodes) != 1:
            reasons.append(f"{name} has {len(episodes)} recorded episodes; this comparison requires one")
    arms = []
    for name, record in zip(("clean", "attacked"), records, strict=True):
        arms.append(
            {
                "condition": name,
                "run_id": record["run_id"],
                "input_sha256": record["source_hashes"],
                "real_llm": record["manifest"].get("real_llm"),
                "status": record["summary"].get("status"),
                "native_tasks": record["summary"].get("tasks", []),
                "audit": record.get("audit"),
                "warnings": record.get("warnings", []),
                "actions": _actions(record),
            }
        )
    alignment = align_actions(*(arm["actions"] for arm in arms))
    for row in alignment["rows"]:
        roots = sensitive.get(row["function"], [])
        row["security_argument_changes"] = [
            change
            for change in row["argument_changes"]
            if any(_overlaps(change["path"], root) for root in roots)
        ]
        row["security_relevant"] = bool(
            row["security_argument_changes"] or (roots and row["status"] != "paired")
        )
    uncertainty = reasons + (
        ["multiple equally optimal proposal alignments"] if alignment["status"] == "ambiguous" else []
    )
    environment_changes = json_changes(*initial_environments)
    environment_status = (
        "unknown"
        if any(environment is None for environment in initial_environments)
        else "different_observed_not_protocol_validated"
        if environment_changes
        else "identical_observed"
    )

    def first(key):
        candidate = next((row for row in alignment["rows"] if row[key]), None)
        return {
            "status": "unknown" if uncertainty else ("observed" if candidate else "none_observed"),
            "alignment_row": candidate["index"] if candidate and not uncertainty else None,
            "candidate_row_for_inspection": candidate["index"] if candidate else None,
            "limitations": uncertainty,
        }

    return {
        "schema_version": 1,
        "protocol": "offline-tool-proposal-pair-v1",
        "scope": SCOPE,
        "comparability": {
            "status": "comparable_under_recorded_checks" if not reasons else "unconfirmed",
            "reasons": reasons,
            "run_local_configuration_differences": run_local,
            "initial_environment_comparison": {"status": environment_status, "changes": environment_changes},
        },
        "sensitive_paths": sensitive,
        "arms": arms,
        "alignment": alignment,
        "first_tool_proposal_divergence": first("different"),
        "first_security_relevant_divergence": first("security_relevant"),
        "attack_success": "unknown; use the separately declared native state oracle",
    }


def _page(result, records, output):
    esc = html.escape

    def dump(value):
        return "<pre>" + esc(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"

    def event_link(arm, event_id):
        return (
            f'<a href="#{arm}-{esc(quote(event_id, safe=""), quote=True)}">{esc(event_id)}</a>'
            if event_id
            else "Absent"
        )

    rows = []
    for row in result["alignment"]["rows"]:
        rows.append(
            "<tr>"
            + f"<td>{row['index']}</td><td>{esc(row['status'])}</td><td>{esc(str(row['function']))}</td>"
            + f"<td>{event_link('clean', row['clean_event_id'])}</td>"
            + f"<td>{event_link('attacked', row['attacked_event_id'])}</td>"
            + "<td>"
            + dump(row["argument_changes"])
            + "</td></tr>"
        )
    sections = []
    for arm, record in zip(result["arms"], records, strict=True):
        name = arm["condition"]
        report = Path(arm.get("report_path", Path(arm["path"]) / "report.html"))
        report_link = "Per-run graph unavailable."
        if report.is_file():
            href = quote(Path(os.path.relpath(report, output)).as_posix(), safe="/")
            report_link = (
                f'<a href="{esc(href, quote=True)}">Open existing interactive timeline and graph</a>'
            )
        chains = []
        for action in arm["actions"]:
            refs = [("proposal", action["event_id"])]
            for exposure in action["source_exposures_in_request"]:
                refs.extend(
                    [
                        ("exposed source result", exposure["source_result_event_id"]),
                        ("outbound exposure", exposure["event_id"]),
                    ]
                )
            for key, label in (
                ("runtime_starts", "runtime entry"),
                ("runtime_returns", "runtime return"),
                ("observed_environment_changes", "native state change"),
            ):
                refs.extend((label, item["event_id"]) for item in action["execution"][key])
            chains.append(
                "<p>"
                + esc(str(action["function"]))
                + ": "
                + " · ".join(esc(label) + " " + event_link(name, event_id) for label, event_id in refs)
                + "</p>"
            )
        events = "".join(
            f'<details id="{name}-{esc(e["event_id"], quote=True)}"><summary>'
            f"{esc(e['event_id'])} · {esc(e['event_type'])}</summary>{dump(e)}</details>"
            for e in record["events"]
        )
        sections.append(
            f"<section><h2>{esc(name)}: {esc(arm['run_id'])}</h2><p>{report_link}</p>"
            + "<p>Linked observations below record exposure and execution, not causal propagation.</p>"
            + "".join(chains)
            + "<details open><summary>Proposals, execution, exposure, and observed state changes</summary>"
            + dump(arm)
            + "</details><h3>Linked recorded events</h3>"
            + events
            + "</section>"
        )
    overview = {
        key: result[key]
        for key in (
            "comparability",
            "first_tool_proposal_divergence",
            "first_security_relevant_divergence",
            "attack_success",
            "sensitive_paths",
        )
    }
    from agentdojo_lab.html_report import _escaped_json
    from agentdojo_lab.paired_report_data import build_paired_view

    view = build_paired_view(result, records)
    for arm, model in zip(result["arms"], view["arms"], strict=True):
        report = Path(arm.get("report_path", Path(arm["path"]) / "report.html"))
        model["report_href"] = (
            quote(Path(os.path.relpath(report, output)).as_posix(), safe="/")
            if report.is_file() else None
        )
    legacy = (
        "<h2>Original comparison and evidence</h2><p>" + esc(SCOPE) + "</p>"
        + dump(overview)
        + "<p>Alignment: " + esc(result["alignment"]["status"]) + ". "
        + esc(result["alignment"]["rule"]) + ".</p>"
        + '<div class="table"><table><thead><tr><th>Row</th><th>Alignment</th>'
        + '<th>Tool</th><th>Clean evidence</th><th>Attacked evidence</th>'
        + '<th>Argument changes</th></tr></thead><tbody>'
        + "".join(rows) + "</tbody></table></div>" + "".join(sections)
    )
    templates = files("agentdojo_lab").joinpath("templates")
    template = templates.joinpath("paired_report.html").read_text(encoding="utf-8")
    # Replace trusted presentation assets before inserting inert recorded data.
    template = template.replace(
        "@@STYLE@@", templates.joinpath("paired_report.css").read_text(encoding="utf-8")
    ).replace(
        "@@SCRIPT@@", templates.joinpath("paired_report.js").read_text(encoding="utf-8")
    ).replace("@@NONCE@@", secrets.token_urlsafe(24))
    parts = {"VIEW": _escaped_json(view), "LEGACY": legacy}
    return re.sub(r"@@(VIEW|LEGACY)@@", lambda match: parts[match[1]], template)



def export_pair(clean: Path, attacked: Path, output: Path, *, sensitive_paths=None) -> dict:
    """Write only a fresh derived report directory, leaving all source files intact."""
    paths = [Path(clean).expanduser().resolve(), Path(attacked).expanduser().resolve()]
    output = Path(output).expanduser().resolve()
    if paths[0] == paths[1]:
        raise ValueError("Clean and attacked arms must be distinct run directories")
    if any(output.is_relative_to(path) or path.is_relative_to(output) for path in paths):
        raise ValueError("Report output must be separate from both source directories")
    records = [collect_run_record(path) for path in paths]
    # Loading and auditing read the files separately; reject concurrent input changes.
    for path, record in zip(paths, records, strict=True):
        for name, expected in record["source_hashes"].items():
            if hashlib.sha256((path / name).read_bytes()).hexdigest() != expected:
                raise ValueError("Source changed while reading; preserve it before exporting")
        report = path / "report.html"
        if report.is_file() and report.resolve().is_relative_to(path):
            record["source_hashes"]["report.html"] = hashlib.sha256(report.read_bytes()).hexdigest()
    result = compare_records(*records, sensitive_paths=sensitive_paths)
    for arm, path in zip(result["arms"], paths, strict=True):
        arm["path"] = str(path)
    page = _page(result, records, output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "pair.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "index.html").write_text(page, encoding="utf-8")
    return result
