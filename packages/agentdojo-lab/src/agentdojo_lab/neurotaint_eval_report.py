"""Render normalized NeuroTaint testbed results without rescoring experiment data.

The input producer owns every scientific label and aggregate.  This module only
validates JSON-shaped rows, exports them, and presents supplied values.  In
particular, it never derives attribution ground truth from detector output.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import os
import secrets
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

STANDARD_TRIAL_FIELDS = (
    "trial_id",
    "scenario_id",
    "condition",
    "repeat",
    "status",
    "utility",
    "attack_success",
    "exposure",
    "report",
)


def _load_object(source: dict | Path | str) -> tuple[dict, Path | None]:
    if isinstance(source, dict):
        return copy.deepcopy(source), None
    path = Path(source).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Cannot read normalized evaluation summary ({type(exc).__name__})") from exc
    if not isinstance(value, dict):
        raise ValueError("Normalized evaluation summary must be a JSON object")
    return value, path.parent


def _rows(value, *, name: str) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{name} must be a list of JSON objects")
    if any(not isinstance(key, str) for row in value for key in row):
        raise ValueError(f"{name} must use string field names")
    return copy.deepcopy(value)


def _row_source(summary: dict, singular: str) -> object:
    plural = singular + "s"
    if plural in summary:
        return summary[plural]
    if singular + "_rows" in summary:
        return summary[singular + "_rows"]
    rows = summary.get("rows")
    return rows.get(plural) if isinstance(rows, dict) else None


def _finite_json(value: object) -> None:
    """Reject values that cannot be represented by the inert HTML payload."""
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Normalized evaluation input must contain finite JSON values") from exc


def _safe_href(value: object) -> str | None:
    """Keep local HTML links while excluding active or remote URL schemes."""
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(char) < 32 for char in value)
    ):
        return None
    try:
        split = urlsplit(value)
    except ValueError:
        return None
    if split.scheme or split.netloc or split.query or not split.path.lower().endswith(".html"):
        return None
    if split.path.startswith(("/", "\\")):
        return None
    return value


def _report_href(row: dict, *, source_dir: Path | None, output: Path | None) -> str | None:
    for key in ("report_href", "report"):
        safe = _safe_href(row.get(key))
        if safe is not None:
            return safe
    run_path = row.get("run_path")
    if source_dir is None or output is None or not isinstance(run_path, str) or not run_path:
        return None
    candidate = Path(run_path).expanduser()
    if not candidate.is_absolute():
        candidate = source_dir / candidate
    if candidate.name != "report.html":
        candidate = candidate / "report.html"
    try:
        candidate = candidate.resolve()
        if not candidate.is_file():
            return None
        return os.path.relpath(candidate, output.resolve()).replace(os.sep, "/")
    except OSError:
        return None


def normalize_neurotaint_eval_input(
    source: dict | Path | str,
    *,
    trial_rows: list[dict] | None = None,
    proposal_rows: list[dict] | None = None,
    output: Path | None = None,
) -> dict:
    """Return a detached presentation record from already-normalized inputs.

    ``trial_rows`` and ``proposal_rows`` override embedded ``trials`` and
    ``proposals``.  No outcome, ratio, truth label, or aggregate is calculated.
    """
    summary, source_dir = _load_object(source)
    trials = _rows(
        trial_rows if trial_rows is not None else _row_source(summary, "trial"), name="trial rows"
    )
    proposals = _rows(
        proposal_rows if proposal_rows is not None else _row_source(summary, "proposal"),
        name="proposal rows",
    )
    plan = summary.get("plan")
    if plan is None:
        plan = {"schedule": summary.get("schedule", [])}
    if not isinstance(plan, dict) or not isinstance(plan.get("schedule", []), list):
        raise ValueError("plan.schedule must be a list")
    if any(not isinstance(row, dict) for row in plan.get("schedule", [])):
        raise ValueError("plan.schedule must contain JSON objects")

    record = copy.deepcopy(summary)
    record["plan"] = copy.deepcopy(plan)
    record["trials"] = trials
    record["proposals"] = proposals
    # Remove alternate row containers so the embedded record has one canonical source.
    record.pop("trial_rows", None)
    record.pop("proposal_rows", None)
    record.pop("rows", None)
    record["presentation"] = {
        "language": "en",
        "aggregates_supplied_by_input": True,
        "ground_truth_inferred_by_renderer": False,
        "missing_values": "unavailable",
    }
    for row in trials:
        row["_report_href"] = _report_href(row, source_dir=source_dir, output=output)
    trial_links = {
        row.get("trial_id"): row.get("_report_href")
        for row in trials
        if isinstance(row.get("trial_id"), str) and row.get("_report_href")
    }
    for row in proposals:
        row["_report_href"] = _report_href(row, source_dir=source_dir, output=output) or trial_links.get(
            row.get("trial_id")
        )
    _finite_json(record)
    return record


def _escaped_ascii_json(value: object) -> str:
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    return text.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")


def render_neurotaint_eval_html(data: dict) -> str:
    """Render one offline HTML document from a normalized presentation record."""
    template = files("agentdojo_lab").joinpath("templates/neurotaint_eval_report.html").read_text(
        encoding="utf-8"
    )
    return template.replace("@@NONCE@@", secrets.token_urlsafe(24)).replace(
        "@@RECORD@@", _escaped_ascii_json(data)
    )


def _csv_value(value: object) -> object:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True)
    if value is None:
        return ""
    return value


def _csv_text(rows: list[dict]) -> str:
    fields: list[str] = []
    for field in STANDARD_TRIAL_FIELDS:
        if any(field in row for row in rows):
            fields.append(field)
    for row in rows:
        fields.extend(key for key in row if key not in fields and not key.startswith("_"))
    if not fields:
        fields = list(STANDARD_TRIAL_FIELDS)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_value(value) for key, value in row.items() if not key.startswith("_")})
    return stream.getvalue()


def _jsonl_text(rows: list[dict]) -> str:
    return "".join(
        json.dumps(
            {key: value for key, value in row.items() if not key.startswith("_")},
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
        for row in rows
    )


def _atomic_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def export_neurotaint_eval_report(
    source: dict | Path | str,
    output: Path,
    *,
    trial_rows: list[dict] | None = None,
    proposal_rows: list[dict] | None = None,
) -> dict:
    """Export ``index.html``, ``trials.csv``, and ``proposals.jsonl``.

    Existing derived files are replaced atomically.  The source summary and row
    objects remain unchanged.
    """
    output = Path(output).expanduser().resolve()
    data = normalize_neurotaint_eval_input(
        source,
        trial_rows=trial_rows,
        proposal_rows=proposal_rows,
        output=output,
    )
    output.mkdir(parents=True, exist_ok=True)
    _atomic_text(output / "trials.csv", _csv_text(data["trials"]))
    _atomic_text(output / "proposals.jsonl", _jsonl_text(data["proposals"]))
    _atomic_text(output / "index.html", render_neurotaint_eval_html(data))
    return {
        "status": "generated",
        "trial_count": len(data["trials"]),
        "proposal_count": len(data["proposals"]),
        "outputs": {
            "html": str(output / "index.html"),
            "trials_csv": str(output / "trials.csv"),
            "proposals_jsonl": str(output / "proposals.jsonl"),
        },
    }
