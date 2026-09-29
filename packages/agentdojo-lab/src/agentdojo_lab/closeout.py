"""Offline evidence closeout; preserve study boundaries and unknown outcomes."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict

from agentdojo_lab.evaluation_review import _local, _strict

MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 10000


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Paper(_Record):
    title: str
    url: str
    verified_at: str
    reading_scope: str


class _Component(_Record):
    id: str
    title: str
    assessment: str
    paper_anchor: str
    method_reference: str
    local_result: str
    limits: str
    evidence: list[str]


class _Experiment(_Record):
    id: str
    title: str
    summary: str
    report: str
    arm_key: str
    group_label: str
    validation: str


class _Finding(_Record):
    id: str
    title: str
    status: str
    observation: str
    limit: str
    evidence: list[str]


class _Fallacy(_Record):
    id: str
    title: str
    assessment: str
    reason: str


class _Config(_Record):
    schema_version: int
    title: str
    verdict: str
    closure_status: str
    accepted_gates: int
    total_gates: int
    progress_path: str
    paper: _Paper
    components: list[_Component]
    experiments: list[_Experiment]
    findings: list[_Finding]
    fallacy_checks: list[_Fallacy]
    limitations: list[str]


def _hash(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > MAX_BYTES or path.name.startswith(".env"):
        raise ValueError("Evidence must be an existing bounded non-secret file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ref(root: Path, value: str) -> Path:
    relative = Path(value)
    if not value or relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Evidence references must be relative files within the project")
    path = _local(root / relative)
    if not path.is_relative_to(root):
        raise ValueError("Evidence escapes the project")
    return path


def _json(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _ratios(value) -> None:
    """Reject malformed saved ratios rather than hiding impossible source metrics."""
    if isinstance(value, dict):
        if {"numerator", "denominator", "rate"} <= value.keys():
            n, d, rate = value["numerator"], value["denominator"], value["rate"]
            if not _count(n) or not _count(d) or n > d or not _count(value.get("unknown_count", 0)):
                raise ValueError("Invalid saved ratio counts")
            if d == 0:
                if rate is not None:
                    raise ValueError("A zero-denominator ratio must have a null rate")
            elif type(rate) not in (int, float) or not math.isfinite(rate) or not math.isclose(rate, n / d):
                raise ValueError("Invalid saved ratio rate")
        for item in value.values():
            _ratios(item)
    elif isinstance(value, list):
        for item in value:
            _ratios(item)


def _ratio(rows, key, *, attack=False):
    relevant = [row for row in rows if not attack or row["condition"] == "injected"]
    values = []
    for row in relevant:
        value = row.get(key)
        if value is not None and type(value) is not bool:
            raise ValueError("Trial outcomes must be booleans or null")
        if (
            value is not None
            and key != "payload_exposed"
            and not (row.get("evaluation_valid") is True and row.get("evaluation_completed") is True)
        ):
            raise ValueError("Known native outcomes require completed valid evaluation")
        values.append(value)
    known = [value for value in values if value is not None]
    return {
        "applicable": bool(relevant),
        "numerator": sum(known),
        "denominator": len(known),
        "unknown_count": len(values) - len(known),
        "rate": sum(known) / len(known) if known else None,
    }


def _display(metric):
    if not metric["applicable"]:
        return "N/A"
    return f"{metric['numerator']}/{metric['denominator']} ({metric['unknown_count']} unknown)"


def _csv(rows, columns):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _overlap(left, right):
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def build_closeout(config: Path, output: Path, root: Path | None = None) -> dict:
    """Verify three immutable studies and export an evidence-limited offline closeout."""
    if root is None:
        from agentdojo_lab.runner import ROOT

        root = ROOT
    root, config_path, destination = _local(root), _local(config), _local(output)
    if destination.exists():
        raise ValueError("Closeout requires a fresh output directory")
    evidence = {}

    def remember(path):
        path = _local(path)
        if not path.is_relative_to(root):
            raise ValueError("All source evidence must be inside the project")
        digest = _hash(path)
        if path in evidence and evidence[path] != digest:
            raise ValueError("Source evidence mutated during generation")
        evidence[path] = digest
        if len(evidence) > MAX_FILES:
            raise ValueError("Evidence file budget exceeded")
        return path

    def read(path):
        path = remember(path)
        value = _strict(path.read_bytes())
        if _hash(path) != evidence[path]:
            raise ValueError("Source snapshot mutated while reading")
        return value

    cfg = _Config.model_validate(read(config_path))
    if (
        cfg.schema_version != 1
        or cfg.closure_status != "completed_with_evidence_limits"
        or (cfg.accepted_gates, cfg.total_gates) != (7, 8)
        or len(cfg.experiments) != 3
        or len(cfg.fallacy_checks) != 11
        or not cfg.components
    ):
        raise ValueError("Closeout requires three studies, eleven checks and seven of eight accepted gates")
    if re.search(r"[\u3400-\u9fff]", _json(cfg.model_dump())):
        raise ValueError("Closeout presentation must be English")
    for entries in (cfg.components, cfg.experiments, cfg.findings, cfg.fallacy_checks):
        if len({entry.id for entry in entries}) != len(entries) or any(not entry.id for entry in entries):
            raise ValueError("Closeout entries require unique nonempty IDs")
    if any(c.assessment not in {"verified_in_scope", "partial", "unvalidated"} for c in cfg.components):
        raise ValueError("Unknown component assessment")
    if urlsplit(cfg.paper.url).scheme not in {"https", "http"}:
        raise ValueError("Paper link must be an HTTP(S) URL")
    progress_path = _ref(root, cfg.progress_path)
    progress = read(progress_path)
    milestones = progress.get("milestones", [])
    if (
        len(milestones) != 8
        or len({m.get("id") for m in milestones}) != 8
        or sum(m.get("status") == "accepted" for m in milestones) != 7
        or any(
            m.get("status") not in {"accepted", "in_progress", "pending", "unvalidated", "not_accepted"}
            for m in milestones
        )
        or progress.get("efficacy", {}).get("independent_attribution_accuracy", "missing") is not None
    ):
        raise ValueError("Progress snapshot does not support seven of eight gates and null accuracy")
    for item in [*cfg.components, *cfg.findings]:
        if not item.evidence:
            raise ValueError("Every component and finding requires evidence")
        for name in item.evidence:
            remember(_ref(root, name))
    batches, runs, experiments, containers = set(), set(), [], set()
    batch_inventories = {}
    for experiment in cfg.experiments:
        summary_path = _ref(root, experiment.summary)
        data = read(summary_path)
        _ratios(data)
        report_path = remember(_ref(root, experiment.report))
        validation_path = _ref(root, experiment.validation)
        validation = read(validation_path)
        containers.update((summary_path.parent, report_path.parent, validation_path.parent))
        batch = _local(data["batch_path"])
        if (
            not batch.is_relative_to(root)
            or not batch.is_dir()
            or any(_overlap(batch, previous) for previous in batches)
        ):
            raise ValueError("Duplicate, overlapping or external experiment batch")
        batches.add(batch)
        containers.add(batch)
        before = data.get("source_hashes_before")
        if (
            not isinstance(before, dict)
            or not before
            or before != data.get("source_hashes_after")
            or data.get("source_files_unchanged") is not True
        ):
            raise ValueError("Analysis source snapshots must match")
        for name, digest in before.items():
            path = _ref(batch, name)
            remember(path)
            if not isinstance(digest, str) or evidence[path] != digest:
                raise ValueError("Recorded batch snapshot does not match current evidence")
        batch_files = sorted(path for path in batch.rglob("*") if path.is_file() or path.is_symlink())
        batch_inventories[batch] = set(batch_files)
        for path in batch_files:
            remember(path)
        plan = read(batch / "plan.json")
        rows, schedule = data.get("trials"), plan.get("schedule")
        if not isinstance(rows, list) or not rows or not isinstance(schedule, list):
            raise ValueError("A complete planned slot inventory is required")
        row_ids = [row.get("trial_id") for row in rows]
        if len(set(row_ids)) != len(rows) or set(row_ids) != {slot.get("trial_id") for slot in schedule}:
            raise ValueError("Summary does not preserve every planned slot exactly once")
        if len(schedule) != len(rows) or data.get("counts", {}).get("planned") != len(rows):
            raise ValueError("Planned trial denominator mismatch")
        accuracy = data.get("attribution_accuracy", {})
        if any(accuracy.get(key, "missing") is not None for key in ("precision", "recall", "f1")):
            raise ValueError("Independent attribution accuracy must remain null")
        slots = {slot["trial_id"]: slot for slot in schedule}
        for row in rows:
            if row.get("condition") not in {"clean", "injected"} or row["condition"] != slots[
                row["trial_id"]
            ].get("condition"):
                raise ValueError("Trial condition differs from its planned slot")
            path = _local(row["run_path"])
            if path != batch / "runs" / row["trial_id"] or path in runs:
                raise ValueError("Duplicate or foreign run path")
            slot = slots[row["trial_id"]]
            if "input_condition" in slot and row.get("input_condition") != slot["input_condition"]:
                raise ValueError("Trial input condition differs from its planned slot")
            runs.add(path)
            for key in ("utility", "attack_goal_success", "payload_exposed"):
                if row.get(key) is not None and type(row[key]) is not bool:
                    raise ValueError("Trial outcomes must be booleans or null")
            if row["condition"] == "clean" and any(
                row.get(key) is not None for key in ("attack_goal_success", "payload_exposed")
            ):
                raise ValueError("Clean assigned-attack outcomes must remain not applicable")
        if experiment.arm_key not in {"conditions", "input_conditions"}:
            raise ValueError("Unknown experiment arm key")
        key = "condition" if experiment.arm_key == "conditions" else "input_condition"
        groups = data.get(experiment.arm_key)
        if not isinstance(groups, list) or not groups:
            raise ValueError("Experiment arm inventory is missing")
        labels = [group.get(key) for group in groups]
        if (
            len(set(labels)) != len(labels)
            or set(labels) != {row.get(key) for row in rows}
            or any(not isinstance(label, str) for label in labels)
        ):
            raise ValueError("Experiment arms do not cover every trial")
        arms = []
        for group in groups:
            selected = [row for row in rows if row[key] == group[key]]
            metrics = {
                name: _ratio(selected, name, attack=name != "utility")
                for name in ("utility", "attack_goal_success", "payload_exposed")
            }
            for name, metric in metrics.items():
                saved = group.get("metrics", {}).get(name)
                if saved is not None and any(
                    saved.get(k) != metric[k] for k in ("numerator", "denominator", "unknown_count", "rate")
                ):
                    raise ValueError("Saved arm ratio differs from its trial outcomes")
            arms.append({"arm": group[key], "planned": len(selected), "metrics": metrics})
        experiments.append(
            {
                **experiment.model_dump(),
                "batch_path": str(batch),
                "arms": arms,
                "planned_slots": len(rows),
                "raw_status_counts": {
                    key: dict(Counter(str(row.get(key)) for row in rows))
                    for key in (
                        "execution_status",
                        "process_status",
                        "started",
                        "evaluation_valid",
                        "evaluation_completed",
                    )
                },
                "trials": [
                    {
                        key: row.get(key)
                        for key in (
                            "trial_id",
                            "run_path",
                            "condition",
                            "input_condition",
                            "started",
                            "execution_status",
                            "process_status",
                            "evaluation_valid",
                            "evaluation_completed",
                            "utility",
                            "attack_goal_success",
                            "payload_exposed",
                        )
                    }
                    for row in rows
                ],
                "primary_usage": data.get("primary_usage"),
                "primary_usage_scope": data.get("primary_usage_scope"),
                "timing": data.get("timing"),
                "timing_scope": data.get("timing_scope"),
                "scope_note": "Usage and timing copied from the original batch; null scope means the summary did not provide that field. Consult the linked original report. Timer scopes overlap; no pooled outcome or causal overhead estimate is computed.",
                "validation": validation,
                "validation_path": experiment.validation,
                "source_snapshot_file_count": len(before),
                "current_batch_file_count": len(batch_files),
            }
        )
    if any(_overlap(destination, path) for path in containers) or any(
        destination == path or destination in path.parents for path in evidence
    ):
        raise ValueError("Closeout output overlaps source artifacts")
    if destination == root or not destination.is_relative_to(root):
        raise ValueError("Closeout output must be a fresh directory inside the project")
    data = {
        **cfg.model_dump(),
        "experiments": experiments,
        "gate_progress": {"accepted": 7, "total": 8, "independent_accuracy": None},
        "counts": {
            "unique_batches": len(batches),
            "planned_slots": len(runs),
            "components": len(cfg.components),
            "findings": len(cfg.findings),
            "fallacy_checks": len(cfg.fallacy_checks),
        },
        "aggregation_scope": "Three distinct study groups; trial outcomes are never pooled across experiments.",
        "verification": {
            "sources_unchanged": True,
            "evidence_files": len(evidence),
            "independent_accuracy_is_null": True,
        },
    }
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "config.json").write_bytes(config_path.read_bytes())
    (destination / "progress.json").write_bytes(progress_path.read_bytes())
    claims = [{"record_type": "component", **item.model_dump()} for item in cfg.components] + [
        {"record_type": "finding", **item.model_dump()} for item in cfg.findings
    ]
    (destination / "claims.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n" for row in claims)
    )
    (destination / "components.csv").write_text(
        _csv(
            [item.model_dump() for item in cfg.components],
            ["id", "title", "assessment", "method_reference", "local_result", "limits"],
        )
    )
    outcome_rows = [
        {
            "experiment": exp["id"],
            "group": exp["group_label"],
            "arm": arm["arm"],
            "planned": arm["planned"],
            "metric": key,
            **value,
        }
        for exp in experiments
        for arm in exp["arms"]
        for key, value in arm["metrics"].items()
    ]
    (destination / "outcomes.csv").write_text(
        _csv(
            outcome_rows,
            [
                "experiment",
                "group",
                "arm",
                "planned",
                "metric",
                "applicable",
                "numerator",
                "denominator",
                "unknown_count",
                "rate",
            ],
        )
    )
    (destination / "closeout.json").write_text(_json(data))
    (destination / "closeout.md").write_text(_markdown(data))
    (destination / "index.html").write_text(_html(data, root, destination))
    after = {path: _hash(path) for path in evidence}
    inventories_after = {
        batch: {path for path in batch.rglob("*") if path.is_file() or path.is_symlink()} for batch in batches
    }
    if after != evidence or inventories_after != batch_inventories:
        data["verification"]["sources_unchanged"] = False
        (destination / "closeout.json").write_text(_json(data))
        raise ValueError("Source evidence mutated during generation; output is not verified")
    source_hashes = {str(path.relative_to(root)): digest for path, digest in sorted(evidence.items())}
    manifest = {
        "schema_version": 1,
        "method": "offline_closeout_v1",
        "source_root": str(root),
        "source_hashes_before": source_hashes,
        "source_hashes_after": source_hashes,
        "source_files_unchanged": True,
        "batch_paths": sorted(str(path) for path in batches),
        "output_hashes": {path.name: _hash(path) for path in sorted(destination.iterdir()) if path.is_file()},
    }
    (destination / "manifest.json").write_text(_json(manifest))
    return {"output": str(destination), "counts": data["counts"], "verification": data["verification"]}


def _markdown(data):
    lines = [
        f"# {data['title']}",
        "",
        data["verdict"],
        "",
        "Closure: completed with evidence limits. Gates accepted: 7/8. Independent attribution accuracy: unavailable.",
        "",
        "## Separate experiments",
        "",
    ]
    for exp in data["experiments"]:
        lines += [
            f"### {exp['title']}",
            "",
            f"{exp['group_label']}; {exp['planned_slots']} planned slots.",
            "",
        ]
        lines += [
            f"- {arm['arm']}: utility {_display(arm['metrics']['utility'])}; attack goal {_display(arm['metrics']['attack_goal_success'])}; payload exposure {_display(arm['metrics']['payload_exposed'])}."
            for arm in exp["arms"]
        ]
        lines.append("")
    lines += ["## Limits", "", *[f"- {limit}" for limit in data["limitations"]], ""]
    return "\n".join(lines)


def _html(data, root, output):
    esc = html.escape

    def link(relative, label):
        href = quote(os.path.relpath(root / relative, output), safe="/.")
        return f'<a href="{esc(href, quote=True)}">{esc(label)}</a>'

    def references(names):
        return " · ".join(link(name, Path(name).name) for name in names)

    def paper_link(component):
        anchor = component["paper_anchor"]
        suffix = anchor if anchor.startswith("#") else "#" + quote(anchor, safe=".")
        href = data["paper"]["url"].split("#", 1)[0] + suffix
        return f'<a href="{esc(href, quote=True)}">Paper method section</a>'

    components = "".join(
        f"<tr><td>{esc(c['title'])}</td><td>{esc(c['assessment'].replace('_', ' '))}</td><td><details><summary>Evidence and limits</summary><p>{esc(c['local_result'])}</p><p>{esc(c['method_reference'])} · {paper_link(c)}</p><p>{esc(c['limits'])}</p><p>{references(c['evidence'])}</p></details></td></tr>"
        for c in data["components"]
    )
    experiments = []
    for exp in data["experiments"]:
        rows = "".join(
            f"<tr><th>{esc(arm['arm'])}</th><td>{arm['planned']}</td><td>{_display(arm['metrics']['utility'])}</td><td>{_display(arm['metrics']['attack_goal_success'])}</td><td>{_display(arm['metrics']['payload_exposed'])}</td></tr>"
            for arm in exp["arms"]
        )
        details = esc(
            _json(
                {
                    key: exp[key]
                    for key in (
                        "raw_status_counts",
                        "primary_usage",
                        "primary_usage_scope",
                        "timing",
                        "timing_scope",
                        "scope_note",
                    )
                }
            )
        )
        experiments.append(
            f"<section><h3>{esc(exp['title'])}</h3><p>{esc(exp['group_label'])} · {link(exp['report'], 'Original interactive report')} · {link(exp['validation_path'], 'Validation evidence')}</p><div class='scroll'><table><thead><tr><th>Arm</th><th>Planned</th><th>Utility</th><th>Attack goal</th><th>Payload exposure</th></tr></thead><tbody>{rows}</tbody></table></div><details><summary>Raw statuses, usage and timing</summary><pre>{details}</pre></details></section>"
        )
    findings = "".join(
        f"<details><summary>{esc(f['title'])} — {esc(f['status'])}</summary><p>{esc(f['observation'])}</p><p>{esc(f['limit'])}</p><p>{references(f['evidence'])}</p></details>"
        for f in data["findings"]
    )
    checks = "".join(
        f"<details><summary>{esc(c['title'])} — {esc(c['assessment'])}</summary><p>{esc(c['reason'])}</p></details>"
        for c in data["fallacy_checks"]
    )
    limits = "".join(f"<li>{esc(item)}</li>" for item in data["limitations"])
    paper = data["paper"]
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(data["title"])}</title><style>body{{font:16px/1.55 system-ui,sans-serif;max-width:1100px;margin:auto;padding:32px;background:#f5f6f8;color:#182330}}h1{{font-size:30px;line-height:1.2}}section,.card{{background:white;border:1px solid #dce2e9;border-radius:12px;padding:18px;margin:16px 0}}.badge{{background:#e2edf9;padding:6px 12px;border-radius:20px;display:inline-block}}table{{width:100%;border-collapse:collapse;font-size:14px}}td,th{{border-bottom:1px solid #e0e5eb;padding:10px;text-align:left;vertical-align:top}}details{{margin:10px 0}}summary{{cursor:pointer}}a{{color:#175fab}}pre{{font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}}.scroll{{overflow:auto}}</style><h1>{esc(data["title"])}</h1><p>{esc(data["verdict"])}</p><p class="badge">Closeout complete with evidence limits · 7/8 gates accepted</p><p>Independent attribution accuracy remains unavailable. Closing this evidence package does not make the last evaluation gate accepted.</p><section><h2>What was reproduced</h2><table><thead><tr><th>Component</th><th>Assessment</th><th>Result and limits</th></tr></thead><tbody>{components}</tbody></table></section><details><summary>Three separate experiments — expand grouped results</summary><p>Every planned slot is retained. Ratios show known outcomes and unknown counts; N/A means no assigned attack. Experiments are not pooled.</p>{"".join(experiments)}</details><section><h2>Findings</h2>{findings}</section><details><summary>Eleven claim checks</summary>{checks}</details><details><summary>Limitations and source reading</summary><ul>{limits}</ul><p><a href="{esc(paper["url"], quote=True)}">{esc(paper["title"])}</a> · verified {esc(paper["verified_at"])}</p><p>{esc(paper["reading_scope"])}</p></details><p>{link(data["progress_path"], "Original gate checklist")} · <a href="closeout.json">Data</a> · <a href="manifest.json">Source verification</a> · <a href="claims.jsonl">Claim records</a> · <a href="components.csv">Components CSV</a> · <a href="outcomes.csv">Outcomes CSV</a> · <a href="closeout.md">Markdown</a></p></html>'''
