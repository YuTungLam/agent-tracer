"""Standalone, inert-data viewer for a separate deferred counterfactual audit."""

import hashlib
import json
import secrets
from importlib.resources import files
from pathlib import Path

from agentdojo_lab.html_report import _escaped_json


def collect_counterfactual_record(output_dir: Path) -> dict:
    """Read only the three local audit artifacts; never follow the source-run path."""
    directory = Path(output_dir).expanduser().resolve()
    if not directory.is_dir():
        raise ValueError("Counterfactual audit directory does not exist")
    warnings, hashes = [], {}

    def strict_json(raw):
        def reject_constant(_):
            raise ValueError("Non-finite JSON value")

        return json.loads(raw, parse_constant=reject_constant)

    def read(name):
        path = directory / name
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(directory):
                raise ValueError("Audit input must be a local regular file")
            raw = path.read_bytes()
        except (OSError, ValueError) as error:
            warnings.append(f"Cannot read {name} ({type(error).__name__}); evidence is unavailable.")
            return None
        hashes[name] = hashlib.sha256(raw).hexdigest()
        return raw

    def document(name):
        raw = read(name)
        if raw is None:
            return {}
        try:
            value = strict_json(raw)
            if not isinstance(value, dict):
                raise ValueError("Expected an object")
            return value
        except (ValueError, UnicodeError):
            warnings.append(f"Cannot parse {name} as an object; inspect its unchanged original file.")
            return {}

    manifest, summary = document("manifest.json"), document("summary.json")
    records = []
    raw = read("counterfactual.jsonl")
    if raw is not None:
        # U+2028/U+2029 are legal characters inside JSON strings, not JSONL boundaries.
        for number, line in enumerate(raw.decode("utf-8", errors="replace").split("\n"), 1):
            if not line.strip():
                continue
            try:
                value = strict_json(line)
                if not isinstance(value, dict):
                    raise ValueError("Expected a record object")
            except ValueError:
                warnings.append(f"Unparsed counterfactual.jsonl line {number}; no judgment is inferred.")
                value = {"record_type": "unparsed", "line_number": number, "raw_text": line}
            records.append(value)
    return {
        "schema_version": 1,
        "manifest": manifest,
        "summary": summary,
        "records": records,
        "audit_input_sha256": hashes,
        "warnings": warnings,
        "interpretation": "auditor_prediction_not_observed_behavior",
    }


def export_counterfactual_html(output_dir: Path) -> dict:
    """Create report.html once beside audit files, outside the original source run."""
    requested = Path(output_dir).expanduser()
    if requested.is_symlink():
        raise ValueError("Counterfactual output directory must not be a symlink")
    directory = requested.resolve()
    record = collect_counterfactual_record(directory)
    source = record["manifest"].get("source_run")
    if isinstance(source, str) and source.strip():
        source_path = Path(source).expanduser()
        if not source_path.is_absolute():
            source_path = directory / source_path
        if directory.is_relative_to(source_path.resolve()):
            raise ValueError("Counterfactual report must be outside the original source run")
    template = (
        files("agentdojo_lab").joinpath("templates/counterfactual_report.html").read_text(encoding="utf-8")
    )
    nonce = secrets.token_urlsafe(24)
    page = template.replace("@@NONCE@@", nonce).replace("@@RECORD@@", _escaped_json(record))
    destination = directory / "report.html"
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(page)
    return {
        "status": "generated",
        "path": str(destination),
        "record_count": len(record["records"]),
        "warning_count": len(record["warnings"]),
        "audit_input_sha256": record["audit_input_sha256"],
        "validation_scope": "standalone_artifact; no_browser_visual_QA",
    }
