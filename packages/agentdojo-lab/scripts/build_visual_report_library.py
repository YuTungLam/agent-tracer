#!/usr/bin/env python3
"""Build an offline visual library from saved evidence without rewriting source files."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from agentdojo_lab.html_report import collect_run_record, export_run_html


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _paths(lab: Path, output: Path) -> list[Path]:
    found = []
    for root in (lab / "runs", lab / "reports"):
        for directory, folders, filenames in os.walk(root, followlinks=False):
            parent = Path(directory)
            folders[:] = sorted(
                name
                for name in folders
                if name not in {"frozen-runtime", ".git", ".venv", ".python"}
                and not (parent / name).is_symlink()
                and (parent / name).resolve() != output
            )
            found.extend(parent / name for name in sorted(filenames) if not (parent / name).is_symlink())
    return found


def _link(path: Path, output: Path) -> str:
    return quote(os.path.relpath(path, output), safe="/.-_")


def _title(path: Path, lab: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:35000]
    except OSError:
        return str(path.relative_to(lab))
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = html.unescape(re.sub(r"\s+", " ", match.group(1)).strip()) if match else ""
    return title or path.parent.name.replace("-", " ")


def _category(path: str, single_run: bool) -> str:
    if "scout-case-" in path or "scout-analysis" in path or "scout-terminal" in path:
        return "Scout research"
    if "meeting-packet" in path:
        return "Meeting packet"
    if single_run:
        return "Recorded runs"
    if "pair" in path or "comparison" in path or "cross-session" in path:
        return "Comparisons"
    if "audit" in path or "counterfactual" in path or "replay" in path:
        return "Audits and replays"
    return "Research reports"


def _run_title(relative: str) -> str:
    parts = [part for part in Path(relative).parts if part != "runs"]
    if not parts:
        return "Recorded run"
    case = re.fullmatch(r"scout-case-([a-z]\d*)-prepared-v\d+", parts[0])
    if case:
        head = f"Scout Case {case.group(1).upper()}"
    else:
        head = re.sub(r"^\d{8}(?:T\d+Z)?-", "", parts[0]).replace("-", " ").replace("_", " ")
        head = head[:1].upper() + head[1:]
    tail = " / ".join(part.replace("-", " ").replace("_", " ") for part in parts[1:])
    return f"{head} · {tail}" if tail else head


def _run_details(record: dict) -> dict:
    summary = record["summary"]
    manifest = record["manifest"]
    counts = Counter(event.get("event_type", "unknown") for event in record["events"])
    tasks = summary.get("native_tasks", [])
    tasks = tasks if isinstance(tasks, list) else []
    utilities = [task.get("utility") for task in tasks if isinstance(task, dict)]
    return {
        "status": str(summary.get("status", "unknown")),
        "event_count": len(record["events"]),
        "request_count": counts["MODEL_REQUEST"] if record["events"] else None,
        "proposal_count": counts["TOOL_CALL_PROPOSED"] if record["events"] else None,
        "exposure_count": counts["TOOL_OUTPUT_EXPOSED"] if record["events"] else None,
        "real_llm": summary.get("real_llm", manifest.get("real_llm")),
        "warning_count": len(record["warnings"]),
        "native_utility_pass_count": sum(value is True for value in utilities),
        "native_utility_fail_count": sum(value is False for value in utilities),
        "native_utility_unknown_count": sum(value is not True and value is not False for value in utilities),
    }


def build_library(lab: Path, output: Path, *, render_runs: bool = True) -> dict:
    lab, output = lab.resolve(), output.resolve()
    if not output.is_relative_to(lab / "reports") or output == lab / "reports":
        raise ValueError("The visual library must have its own directory below LAB/reports")
    paths = _paths(lab, output)
    source_html = sorted(path for path in paths if path.suffix == ".html")
    source_html_hashes = {str(path.relative_to(lab)): _sha(path) for path in source_html}
    run_records, errors = {}, []
    for path in paths:
        if path.name != "manifest.json" or not (path.parent / "summary.json").is_file():
            continue
        manifest = _read_object(path)
        if not ((path.parent / "events.jsonl").is_file() or "mode" in manifest or "event_recording" in manifest):
            continue
        source = path.parent
        relative = str(source.relative_to(lab))
        destination = output / "runs" / source.relative_to(lab) / "report.html"
        try:
            record = collect_run_record(source)
            if render_runs:
                export_run_html(source, output=destination)
            if not destination.is_file():
                raise ValueError("No visual copy exists; run with --build before --catalog-only")
            changed = [name for name, digest in record["source_hashes"].items() if _sha(source / name) != digest]
            if changed:
                raise ValueError(f"Source evidence changed during export: {', '.join(changed)}")
            run_records[relative] = {
                "source_directory": relative,
                "visual_path": str(destination.relative_to(lab)),
                "source_sha256": record["source_hashes"],
                **_run_details(record),
            }
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append({"source_directory": relative, "error": str(exc)})
    entries = []
    represented = set()
    paired_views = {}
    for row in _read_object(output / "paired-refresh.json").get("pairs", []):
        if not isinstance(row, dict) or not row.get("source_pair_json") or not row.get("view"):
            continue
        source = Path(row["source_pair_json"]).resolve().with_name("index.html")
        visual = Path(row["view"]).resolve()
        if source in source_html and visual.is_relative_to(output / "paired") and visual.is_file():
            paired_views[source] = visual
    for path in source_html:
        relative = str(path.relative_to(lab))
        run = run_records.get(str(path.parent.relative_to(lab))) if path.name == "report.html" else None
        paired = paired_views.get(path)
        if run:
            represented.add(run["source_directory"])
        summary = _read_object(path.parent / "summary.json")
        title = _run_title(run["source_directory"]) if run else _title(path, lab)
        if paired:
            pair_name = "Scout Case A" if paired.parent.name == "case-a" else _run_title(paired.parent.name)
            title = pair_name + " · Clean vs Attacked"
        entries.append({
            "title": title,
            "source_path": relative,
            "source_sha256": source_html_hashes[relative],
            "category": _category(relative, run is not None),
            "view": "Visual run" if run else "Visual comparison" if paired else "Archived report",
            "href": _link(lab / run["visual_path"] if run else paired or path, output),
            "original_href": _link(path, output),
            "status": str(summary.get("status", "not specified")),
            **({key: value for key, value in run.items() if key != "source_sha256"} if run else {}),
        })
    for relative, run in run_records.items():
        if relative in represented:
            continue
        entries.append({
            "title": _run_title(relative),
            "source_path": relative,
            "category": _category(relative, True),
            "view": "Visual run",
            "href": _link(lab / run["visual_path"], output),
            "original_href": None,
            **{key: value for key, value in run.items() if key != "source_sha256"},
        })
    for path in sorted((output / "paired").glob("**/index.html")):
        if path in paired_views.values():
            continue
        entries.append({
            "title": _title(path, lab),
            "source_path": str(path.relative_to(lab)),
            "category": "Comparisons",
            "view": "Visual comparison",
            "href": _link(path, output),
            "original_href": None,
            "status": "Saved evidence",
        })
    entries.sort(key=lambda row: (row["view"] == "Archived report", row["source_path"]), reverse=False)
    changed_html = [name for name, digest in source_html_hashes.items() if _sha(lab / name) != digest]
    if changed_html:
        raise ValueError(f"Source HTML changed while building library: {', '.join(changed_html)}")
    inventory = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_html_count": len(source_html),
        "visual_run_count": len(run_records),
        "visual_comparison_count": sum(row["view"] == "Visual comparison" for row in entries),
        "archived_report_count": sum(row["view"] == "Archived report" for row in entries),
        "entries": entries,
        "run_records": list(run_records.values()),
        "source_html_sha256": source_html_hashes,
        "source_inputs_unchanged": True,
        "errors": errors,
        "limitations": [
            "Visual run copies use the current presentation template and preserve saved experimental outcomes.",
            "Reports with aggregate, audit, or unsupported schemas remain available as archived HTML.",
            "Counts describe available records, not task success, attack success, or causal influence.",
            "No model, network, scheduler, or simulated tool requests are made by this builder.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    (output / "index.html").write_text(_page(inventory, lab, output), encoding="utf-8")
    return inventory


def _page(inventory: dict, lab: Path, output: Path) -> str:
    def route(relative: str) -> str:
        original = lab / relative
        if relative == "runs/scout-case-a-prepared-v5/paired-report/index.html":
            paired = output / "paired/case-a/index.html"
            if paired.is_file():
                return _link(paired, output)
        visual = output / "runs" / original.relative_to(lab)
        return _link(visual if visual.is_file() else original, output)

    features = [
        ("A", "Two runs. One changed recipient.", "Compare the clean and attacked execution at the same event.",
         "runs/scout-case-a-prepared-v5/paired-report/index.html", "Clean vs Attacked", "pair"),
        ("B", "Four source conditions.", "Inspect both sources, either source alone, and the neither-source control.",
         "runs/scout-case-b-prepared-v3/index.html", "Open condition comparison", "joint"),
        ("C", "Where the memory path stops.", "See the first-session write and the unobserved cross-session continuation.",
         "runs/scout-case-c-prepared-v2/attacked/A/report.html", "Open attacked first session", "memory"),
        ("↗", "The meeting, in one place.", "Recorded outcomes, coverage limits, and all thirteen deliverables.",
         "reports/20260916-meeting-packet-v1/index.html", "Open meeting packet", "meeting"),
    ]
    feature_html = "".join(
        f'<a class="feature {kind}" href="{route(path)}"><div class="feature-top">'
        f'<span class="case">{mark}</span><span class="eyebrow">Current Scout pilot</span></div>'
        f'<div class="mini-flow" aria-hidden="true"><i></i><b></b><i></i><b></b><i></i></div>'
        f'<h3>{title}</h3><p>{desc}</p><span class="feature-link">{label} <span>↗</span></span></a>'
        for mark, title, desc, path, label, kind in features
        if (lab / path).is_file()
    )
    cards = []
    for index, row in enumerate(inventory["entries"]):
        esc = html.escape
        is_visual = row["view"] != "Archived report"
        count = row.get("event_count")
        data = "Recorded events unavailable" if count is None else f"{count} recorded events"
        if row["view"] == "Visual comparison":
            data = "Clean and attacked event comparison"
        if row.get("request_count") is not None:
            data += f" · {row['request_count']} model requests"
        known = row.get("real_llm")
        mode = "Live model" if known is True else "Offline / fixture" if known is False else ""
        original = (
            f'<a class="original" href="{esc(row["original_href"], quote=True)}">Original HTML</a>'
            if row.get("original_href") and is_visual else ""
        )
        cards.append(
            f'<article class="report-card" data-entry="{index}"><div class="card-labels">'
            f'<span class="view {"visual" if is_visual else "archive"}">{esc(row["view"])}</span>'
            f'<span class="mode">{esc(mode)}</span></div><h3><a href="{esc(row["href"], quote=True)}">'
            f'{esc(row["title"])}</a></h3><p class="report-path">{esc(row["source_path"])}</p>'
            f'<div class="card-meta"><span>{esc(data)}</span><span>{esc(row["status"])}</span></div>'
            f'<div class="card-footer"><a href="{esc(row["href"], quote=True)}">'
            f'{"Explore visual report" if is_visual else "Open archived report"} ↗</a>{original}</div></article>'
        )
    categories = sorted({row["category"] for row in inventory["entries"]})
    options = "".join(f'<option>{html.escape(name)}</option>' for name in categories)
    payload = json.dumps(inventory["entries"], ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    return TEMPLATE.replace("@@FEATURES@@", feature_html).replace("@@CARDS@@", "".join(cards)).replace(
        "@@OPTIONS@@", options
    ).replace("@@DATA@@", payload).replace("@@SOURCE_COUNT@@", str(inventory["source_html_count"])).replace(
        "@@VISUAL_COUNT@@", str(inventory["visual_run_count"])
    ).replace("@@ARCHIVE_COUNT@@", str(inventory["archived_report_count"])).replace(
        "@@ENTRY_COUNT@@", str(len(inventory["entries"]))
    )


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Evidence Atlas · Visual Report Library</title><style>
:root{--ink:#16303a;--muted:#6b7d83;--teal:#157f76;--line:#dce6e6;--paper:#f5f8f7;--orange:#d88a54}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 system-ui,-apple-system,sans-serif}a{color:inherit}button,input,select{font:inherit}button,a,input,select{outline-offset:5px}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid var(--teal)}
.topbar{padding:19px 5vw;border-bottom:1px solid var(--line);background:#fff;display:flex;align-items:center;justify-content:space-between}.brand{font-size:14px;font-weight:750;letter-spacing:.12em;text-transform:uppercase;display:flex;align-items:center;gap:12px}.brand-icon{display:grid;grid-template-columns:repeat(2,7px);gap:3px}.brand-icon i{background:var(--teal);width:7px;height:7px;border-radius:2px}.topbar small{color:var(--muted)}main{max-width:1480px;margin:auto;padding:55px 5vw 70px}.eyebrow{text-transform:uppercase;font-size:10px;letter-spacing:.13em;font-weight:750;color:var(--muted)}
.hero{display:grid;grid-template-columns:1.3fr 1fr;gap:40px;align-items:center;margin-bottom:46px}.hero h1{font-size:clamp(38px,4.6vw,65px);line-height:1.05;letter-spacing:-.065em;margin:15px 0 18px;font-weight:720}.hero h1 span{color:var(--teal)}.hero p{max-width:540px;color:var(--muted);font-size:16px;line-height:1.75}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{border-left:1px solid #cedcda;padding-left:20px}.metric strong{font-size:38px;display:block;letter-spacing:-.055em;font-weight:650;line-height:1.3}.metric span{color:var(--muted);font-size:12px;display:block;max-width:92px}.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:20px;margin:28px 0 18px}.section-head h2{margin:0;font-size:21px;letter-spacing:-.03em}.section-head p{font-size:12px;color:var(--muted);margin:0}
.features{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.feature{background:white;border:1px solid var(--line);padding:22px;border-radius:16px;text-decoration:none;display:flex;flex-direction:column;min-height:300px;transition:transform .16s,box-shadow .16s}.feature:hover{transform:translateY(-4px);box-shadow:0 12px 30px #173f3b0c}.feature.pair{background:#e6f1ed;border-color:#b8d5cb}.feature-top{display:flex;gap:10px;align-items:center}.case{height:31px;width:31px;background:#fff9;border:1px solid #cadecf;display:grid;place-items:center;border-radius:9px;font-weight:700;color:var(--teal)}.feature h3{font-size:21px;line-height:1.2;letter-spacing:-.035em;margin:16px 0 9px}.feature p{color:var(--muted);font-size:12px;line-height:1.6;margin:0 0 20px}.feature-link{display:flex;justify-content:space-between;gap:6px;font-size:11px;font-weight:700;margin-top:auto;color:var(--teal)}.mini-flow{display:flex;align-items:center;height:37px;gap:0;margin-top:20px;max-width:190px}.mini-flow i{width:27px;height:21px;background:#b7dacf;border:2px solid #699a8d;border-radius:5px}.mini-flow i:last-child{background:#f1d9c6;border-color:#bf9270}.mini-flow b{flex:1;height:2px;background:#adc9c2;position:relative}.mini-flow b:after{content:'';position:absolute;right:0;top:-3px;border-left:5px solid #adc9c2;border-top:4px solid transparent;border-bottom:4px solid transparent}.joint .mini-flow i:first-child{box-shadow:0 -8px 0 -2px #d7e1ef,0 8px 0 -2px #d7e1ef}.memory .mini-flow b:last-of-type{background:repeating-linear-gradient(90deg,#adc9c2 0 4px,transparent 4px 7px)}.memory .mini-flow i:last-child{border-style:dashed;background:#fff9}.meeting .mini-flow i{background:#d5e3ef;border-color:#8ca8c2}
.archive-head{margin-top:50px}.filters{display:flex;gap:12px;margin:18px 0;align-items:center;flex-wrap:wrap}.search{flex:1;min-width:200px;position:relative}.search span{position:absolute;left:16px;top:11px;color:#82958f;font-size:19px}.search input{width:100%;padding:12px 16px 12px 42px;border:1px solid var(--line);border-radius:9px;background:white;color:var(--ink)}select{padding:12px;border:1px solid var(--line);border-radius:9px;background:#fff;max-width:230px;color:var(--ink)}.count{font-size:12px;color:var(--muted);margin:16px 0}.reports{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.report-card{border:1px solid var(--line);border-radius:12px;background:#fff;padding:20px;display:flex;flex-direction:column;min-width:0;transition:border-color .15s}.report-card:hover{border-color:#a7c3b9}.card-labels{display:flex;justify-content:space-between;gap:10px;align-items:center}.view{font-size:9px;letter-spacing:.08em;text-transform:uppercase;border-radius:4px;padding:4px 7px;font-weight:750}.visual{color:#27735b;background:#edf5f0}.archive{color:#6e7683;background:#f0f2f5}.mode{font-size:10px;color:var(--muted)}.report-card h3{font-size:15px;line-height:1.45;margin:17px 0 10px;overflow-wrap:anywhere;font-weight:650}.report-card h3 a{text-decoration:none}.report-path{font:10px/1.6 ui-monospace,monospace;color:#81918f;overflow-wrap:anywhere;margin:0 0 16px}.card-meta{display:flex;gap:10px;flex-wrap:wrap;font-size:10px;color:var(--muted);margin-top:auto}.card-footer{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #edf1ef;margin-top:16px;padding-top:14px;font-size:11px;color:var(--teal);font-weight:650}.card-footer a{text-decoration:none}.card-footer .original{color:var(--muted);font-weight:400}.report-card[hidden]{display:none}.empty{padding:50px;text-align:center;border:1px dashed var(--line);border-radius:12px;color:var(--muted)}footer{border-top:1px solid var(--line);padding-top:22px;margin-top:40px;display:flex;gap:20px;justify-content:space-between;font-size:11px;color:var(--muted)}footer p{margin:0;max-width:760px}
@media(max-width:1100px){.features{grid-template-columns:repeat(2,minmax(0,1fr))}.reports{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{grid-template-columns:1fr}.hero p{max-width:650px}.metrics{max-width:500px}.feature{min-height:280px}}@media(max-width:640px){main{padding:32px 20px}.topbar{padding:18px 20px}.topbar small{display:none}.features,.reports{grid-template-columns:1fr}.section-head{align-items:flex-start;flex-direction:column;gap:5px}.feature{min-height:260px}.filters{align-items:stretch}.filters select{flex:1;max-width:none;min-width:0}.search{flex-basis:100%}.metric{padding-left:13px}.metric strong{font-size:33px}footer{flex-direction:column}.hero{gap:22px}}@media(prefers-reduced-motion:reduce){*{transition:none!important}}@media print{.filters,.topbar{display:none}.features,.reports{grid-template-columns:repeat(2,1fr)}.feature,.report-card{break-inside:avoid}.hero h1{font-size:36px}}
</style></head><body><header class="topbar"><div class="brand"><span class="brand-icon" aria-hidden="true"><i></i><i></i><i></i><i></i></span>Evidence Atlas</div><small>AgentDojo Lab / Visual report library</small></header><main>
<section class="hero"><div><span class="eyebrow">Saved experiments · One visual workspace</span><h1>Evidence,<br><span>at a glance.</span></h1><p>Follow an execution, compare two runs, and inspect the exact event behind a result. Start with the current Scout pilot or explore the complete report archive.</p></div><div class="metrics"><div class="metric"><strong>@@VISUAL_COUNT@@</strong><span>visual run copies</span></div><div class="metric"><strong>@@SOURCE_COUNT@@</strong><span>original HTML reports</span></div><div class="metric"><strong>@@ARCHIVE_COUNT@@</strong><span>other archived reports</span></div></div></section>
<div class="section-head"><h2>Start with the current research</h2><p>Saved outcomes and known limits remain visible.</p></div><section class="features" aria-label="Current Scout reports">@@FEATURES@@</section>
<div class="section-head archive-head"><h2>Explore the library</h2><p>New visual run views and preserved historical reports.</p></div><div class="filters"><label class="search"><span aria-hidden="true">⌕</span><input id="search" type="search" aria-label="Search reports" placeholder="Search a case, condition, run, or report…"></label><select id="category" aria-label="Filter by category"><option value="">All categories</option>@@OPTIONS@@</select><select id="view" aria-label="Filter by report view"><option value="">All views</option><option>Visual run</option><option>Visual comparison</option><option>Archived report</option></select></div><p class="count" id="result-count" role="status" aria-live="polite">@@ENTRY_COUNT@@ reports</p><section class="reports" id="reports" aria-label="Report catalog">@@CARDS@@</section><p class="empty" id="empty" hidden>No reports match these filters. Try another case name or clear the search.</p>
<footer><p>Visual copies preserve source evidence. Archived reports retain their original format and interpretation date. Event counts describe available records; they do not measure attack success or causal influence.</p><a href="inventory.json">Evidence inventory and hashes ↗</a></footer></main>
<script id="catalog-data" type="application/json">@@DATA@@</script><script>
const entries=JSON.parse(document.getElementById('catalog-data').textContent), cards=[...document.querySelectorAll('[data-entry]')];
const search=document.getElementById('search'), category=document.getElementById('category'), view=document.getElementById('view');
function filter(){const terms=search.value.toLowerCase().trim().split(/\\s+/).filter(Boolean);let visible=0;cards.forEach((card,index)=>{const item=entries[index],text=[item.title,item.source_path,item.category,item.view,item.status].join(' ').toLowerCase();const shown=terms.every(term=>text.includes(term))&&(!category.value||item.category===category.value)&&(!view.value||item.view===view.value);card.hidden=!shown;if(shown)visible++;});document.getElementById('result-count').textContent=visible+' of '+entries.length+' reports';document.getElementById('empty').hidden=visible!==0;}
search.addEventListener('input',filter);category.addEventListener('change',filter);view.addEventListener('change',filter);
</script></body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--build", action="store_true", help="Render visual run copies and build the library")
    actions.add_argument("--catalog-only", action="store_true", help="Refresh catalog using existing visual copies")
    parser.add_argument("--lab", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="Defaults to LAB/reports/visual-library-v1")
    args = parser.parse_args()
    inventory = build_library(
        args.lab, args.output or args.lab / "reports/visual-library-v1", render_runs=args.build
    )
    print(json.dumps({
        key: inventory[key]
        for key in (
            "source_html_count", "visual_run_count", "visual_comparison_count", "archived_report_count",
            "source_inputs_unchanged", "errors",
        )
    }, indent=2))


if __name__ == "__main__":
    main()
