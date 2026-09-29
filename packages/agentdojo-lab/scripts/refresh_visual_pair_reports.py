"""Refresh graphical paired views from immutable saved comparisons, without inference."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

from agentdojo_lab.html_report import collect_run_record
from agentdojo_lab.paired_report import _page

LAB = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_html(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def refresh(library, *, update_current=False):
    library = library.resolve()
    current_source = LAB / "runs/scout-case-a-prepared-v5/paired-report/pair.json"
    candidates = sorted((LAB / "runs").glob("*/paired-report/pair.json"))
    candidates.extend(sorted((LAB / "reports").glob("*/pair.json")))
    receipt = {"presentation_version": "graphical-paired-view-v2", "pairs": [], "skipped": []}
    for source in candidates:
        if not source.is_file():
            continue
        result = json.loads(source.read_text())
        if result.get("protocol") != "offline-tool-proposal-pair-v1":
            receipt["skipped"].append({"source": str(source), "reason": "different_pair_protocol"})
            continue
        original_result = copy.deepcopy(result)
        records = []
        input_hashes = {}
        for arm in result["arms"]:
            run = Path(arm["path"])
            if not run.is_dir() and "/agentdojo-lab/" in str(run):
                run = LAB / str(run).split("/agentdojo-lab/", 1)[1]
            for name, expected in arm["input_sha256"].items():
                path = run / name
                if digest(path) != expected:
                    raise ValueError(f"Saved comparison source hash mismatch: {path}")
                input_hashes[str(path)] = expected
            arm["path"] = str(run)
            visual = library / "runs" / run.relative_to(LAB) / "report.html"
            if visual.is_file():
                arm["report_path"] = str(visual)
            records.append(collect_run_record(run))
        current = source == current_source
        name = "case-a" if current else (
            source.parent.parent.name if source.parent.name == "paired-report" else source.parent.name
        )
        output = library / "paired" / name
        output.mkdir(parents=True, exist_ok=True)
        # Preserve the historical comparison result; this is only a new presentation.
        saved = output / "pair.json"
        if saved.exists() and json.loads(saved.read_text()) != original_result:
            raise ValueError(f"Different saved comparison already exists: {saved}")
        saved.write_bytes(source.read_bytes())
        atomic_html(output / "index.html", _page(result, records, output))
        updated = None
        backup = None
        if update_current and current:
            target = source.parent / "index.html"
            old_hash = digest(target)
            backup = library / "original-pages" / ("case-a-paired-" + old_hash + ".html")
            backup.parent.mkdir(parents=True, exist_ok=True)
            if not backup.exists():
                backup.write_bytes(target.read_bytes())
            atomic_html(target, _page(result, records, target.parent))
            updated = str(target)
        for path, expected in input_hashes.items():
            if digest(Path(path)) != expected:
                raise ValueError(f"Source changed while rendering: {path}")
        receipt["pairs"].append({
            "source_pair_json": str(source),
            "source_pair_sha256": digest(source),
            "view": str(output / "index.html"),
            "view_sha256": digest(output / "index.html"),
            "source_inputs_verified": input_hashes,
            "updated_current_html": updated,
            "previous_html_backup": str(backup) if backup else None,
        })
    (library / "paired-refresh.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=LAB / "reports/visual-library-v1")
    parser.add_argument("--update-current", action="store_true", help="Refresh the requested Case A URL")
    args = parser.parse_args()
    report = refresh(args.library, update_current=args.update_current)
    print(json.dumps({"pairs_refreshed": len(report["pairs"]), "skipped": report["skipped"]}, indent=2))
