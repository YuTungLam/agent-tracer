"""Self-contained, offline HTML records of individual experiments.

Data stays inert: JSON is escaped for the HTML parser and the viewer uses text
nodes rather than interpreting recorded model/tool content as markup or code.
"""

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from agentdojo_lab.inspection import inspect_events


def collect_run_record(run_dir: Path, *, summary: dict | None = None) -> dict:
    run_dir = run_dir.expanduser().resolve()
    if not run_dir.is_dir():
        raise ValueError(f"Run directory does not exist: {run_dir}")
    warnings = []
    hashes = {}

    def read_json(path, *, required=False):
        relative = str(path.relative_to(run_dir))
        try:
            if not path.resolve().is_relative_to(run_dir):
                raise ValueError("source outside run directory")
            raw = path.read_bytes()
            hashes[relative] = hashlib.sha256(raw).hexdigest()
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("expected JSON object")
            return value
        except (OSError, ValueError, UnicodeError) as exc:
            if required:
                raise ValueError(f"Cannot read {relative} ({type(exc).__name__}).") from exc
            warnings.append(f"Cannot read {relative} ({type(exc).__name__})")
            return None

    manifest = read_json(run_dir / "manifest.json", required=True)
    stored_summary = read_json(run_dir / "summary.json", required=summary is None)
    selected_summary = dict(summary if summary is not None else stored_summary)
    # HTML export status is stored outside the immutable experimental outcome.
    events = []
    event_path = run_dir / "events.jsonl"
    audit = None
    if event_path.exists():
        if not event_path.resolve().is_relative_to(run_dir):
            warnings.append("events.jsonl resolves outside the run directory and was excluded")
        else:
            raw = event_path.read_bytes()
            hashes["events.jsonl"] = hashlib.sha256(raw).hexdigest()
            for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("expected event object")
                    events.append(event)
                except ValueError:
                    warnings.append(f"Cannot parse events.jsonl line {index}; the original file is preserved")
            audit = inspect_events(event_path)
    provenance = []
    provenance_path = run_dir / "provenance.jsonl"
    if provenance_path.exists():
        if not provenance_path.resolve().is_relative_to(run_dir):
            warnings.append("provenance.jsonl resolves outside the run directory and was excluded")
        else:
            raw = provenance_path.read_bytes()
            hashes["provenance.jsonl"] = hashlib.sha256(raw).hexdigest()
            for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("expected attribution object")
                    provenance.append(row)
                except ValueError:
                    warnings.append(
                        f"Cannot parse provenance.jsonl line {index}; the original file is preserved"
                    )
    if selected_summary.get("online_provenance", {}).get("enabled"):
        if not provenance or selected_summary["online_provenance"].get("complete") is not True:
            warnings.append(
                "Online attribution is incomplete. Saved candidates are provisional; inspect timing and errors."
            )
    causal_online = []
    causal_online_path = run_dir / "causal-online.jsonl"
    if causal_online_path.exists():
        if not causal_online_path.resolve().is_relative_to(run_dir):
            warnings.append("causal-online.jsonl resolves outside the run directory and was excluded")
        else:
            raw = causal_online_path.read_bytes()
            hashes["causal-online.jsonl"] = hashlib.sha256(raw).hexdigest()
            for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("expected causal audit object")
                    causal_online.append(row)
                except ValueError:
                    warnings.append(
                        f"Cannot parse causal-online.jsonl line {index}; the original file is preserved"
                    )
    causal_online_graph = (
        read_json(run_dir / "causal-online-graph.json")
        if (run_dir / "causal-online-graph.json").exists()
        else None
    )
    if selected_summary.get("online_causal_audit", {}).get("enabled"):
        if not causal_online:
            warnings.append(
                "Online causal audit is enabled, but no causal-online.jsonl records were embedded."
            )
        if selected_summary["online_causal_audit"].get("complete") is not True:
            warnings.append(
                "Online causal audit is incomplete. Treat unresolved predictions and timing as unknown."
            )
        if causal_online_graph is None:
            warnings.append("The online causal derived graph is unavailable.")
    lineage_state = (
        read_json(run_dir / "lineage-state.json") if (run_dir / "lineage-state.json").exists() else None
    )
    native = []
    for path in sorted((run_dir / "native").rglob("*.json")):
        trace = read_json(path)
        if trace is not None:
            native.append({"source": str(path.relative_to(run_dir)), "trace": trace})
    if not events:
        warnings.append(
            "No recorded online events are available. Native conversation history is shown separately; event timing and provenance are not inferred."
        )
    return {
        "schema_version": 1,
        "run_id": run_dir.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest": manifest,
        "summary": selected_summary,
        "events": events,
        "provenance": provenance,
        "causal_online": causal_online,
        **(
            {"causal_online_graph": causal_online_graph}
            if causal_online_graph is not None
            else {}
        ),
        **({"lineage_state": lineage_state} if lineage_state is not None else {}),
        "audit": audit,
        "native": native,
        "warnings": warnings,
        "source_hashes": hashes,
    }


def _escaped_json(value):
    text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    for char, escaped in (
        ("&", r"\u0026"),
        ("<", r"\u003c"),
        (">", r"\u003e"),
        ("\u2028", r"\u2028"),
        ("\u2029", r"\u2029"),
    ):
        text = text.replace(char, escaped)
    return text


def _redact(value, known):
    if isinstance(value, str):
        for secret in known:
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {_redact(key, known): _redact(item, known) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, known) for item in value]
    return value


def export_run_html(
    run_dir: Path,
    *,
    output: Path | None = None,
    summary: dict | None = None,
    redactions: tuple[str, ...] = (),
) -> dict:
    record = collect_run_record(run_dir, summary=summary)
    record = _redact(record, sorted({s for s in redactions if s}, key=len, reverse=True))
    templates = files("agentdojo_lab").joinpath("templates")
    template = templates.joinpath("run_report.html").read_text(encoding="utf-8")
    template = template.replace(
        "@@FLOW_SVG@@", templates.joinpath("agent_flow.svg").read_text(encoding="utf-8")
    )
    template = template.replace(
        "@@FLOW_SCRIPT@@", templates.joinpath("agent_flow.js").read_text(encoding="utf-8")
    )
    nonce = secrets.token_urlsafe(24)
    html = template.replace("@@NONCE@@", nonce).replace("@@RECORD@@", _escaped_json(record))
    destination = (output or (run_dir / "report.html")).expanduser().resolve()
    if destination.suffix.lower() != ".html":
        raise ValueError("HTML report output must end in .html")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Rebuilding the derived report is intentional; raw logs are never rewritten.
    # The temporary file is closed before os.replace: Windows refuses to move an open file.
    descriptor, name = tempfile.mkstemp(dir=destination.parent, prefix=".report-", suffix=".tmp")
    temporary = Path(name)
    try:
        with open(descriptor, "w", encoding="utf-8") as stream:
            stream.write(html)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "status": "generated",
        "path": str(destination),
        "event_count": len(record["events"]),
        "native_trace_count": len(record["native"]),
        "warning_count": len(record["warnings"]),
    }
