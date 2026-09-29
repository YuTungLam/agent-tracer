"""Render the Case T1 packet: canary survival under agent transformations (HTML + JSON).

Offline; zero requests. Reads a saved Case T1 batch and, when present, the 2026-09-09
canary trials as prior evidence. Information survival, canonical canary survival, the
tracer's Tier-1 verdict and the in-content reference are reported as separate columns;
none of them is causal evidence.
"""

from __future__ import annotations

import argparse
import html
import json
import os
from collections import Counter
from pathlib import Path

from agentdojo_lab import case_t1_groq as case_t1

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "case-t1-canary-report-v1"
PRIOR_BATCH = ROOT / "runs" / "20260909-input-comparison-v1"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def pill(value, yes="yes", no="no") -> str:
    if value is True:
        return f'<span class="pill yes">{yes}</span>'
    if value is False:
        return f'<span class="pill no">{no}</span>'
    return '<span class="pill na">unknown</span>'


def source_file_id(source: dict) -> str | None:
    for scalar in (source.get("structure") or {}).get("scalars", []) or []:
        if scalar.get("field_path") == "/id_":
            return str(scalar.get("value"))
    return None


def tracer_view(run: Path, expected_sinks: list[str]) -> dict:
    """Per source/sink pair: Tier-1 status and first matched tier, plus lineage recovery for restored sessions."""
    pairs, lineage_pairs, lineage_status = [], [], None
    if not (run / "provenance.jsonl").is_file():
        return {"pairs": pairs, "lineage_pairs": lineage_pairs, "lineage_status": None}
    for record in lines(run / "provenance.jsonl"):
        if record.get("record_type") != "call_analysis":
            continue
        call = record["call"]
        if call.get("function") not in expected_sinks:
            continue
        sources = {s["source_id"]: s for s in call.get("visible_sources", []) if s.get("kind") == "tool"}
        for field in call.get("fields", []):
            if ((field.get("cascade_scope") or {}).get("sink") or {}).get("selected") is not True:
                continue
            for pair in field.get("nt_style_cascade", []):
                stages = pair.get("stages") or {}
                source = sources.get(pair.get("source_id")) or {}
                pairs.append(
                    {
                        "function": call["function"],
                        "argument_path": field.get("argument_path"),
                        "source_file_id": source_file_id(source),
                        "tier1_status": (stages.get("tier1") or {}).get("status"),
                        "tier1_matched": (stages.get("tier1") or {}).get("matched"),
                        "tier2_score": (stages.get("tier2") or {}).get("score"),
                        "first_matched_tier": pair.get("first_matched_tier"),
                        "matched": pair.get("matched"),
                    }
                )
        lineage = call.get("lineage") or {}
        lineage_status = (lineage.get("summary") or {}).get("status") or lineage_status
        for comparison in lineage.get("comparisons", []):
            stages = comparison.get("stages") or {}
            lineage_pairs.append(
                {
                    "function": call["function"],
                    "argument_path": comparison.get("argument_path"),
                    "tier1_status": (stages.get("tier1") or {}).get("status"),
                    "tier1_matched": (stages.get("tier1") or {}).get("matched"),
                    "tier2_score": (stages.get("tier2") or {}).get("score"),
                    "first_matched_tier": comparison.get("first_matched_tier"),
                    "recovered_source_count": (lineage.get("summary") or {}).get("recovered_source_count"),
                }
            )
    return {"pairs": pairs, "lineage_pairs": lineage_pairs, "lineage_status": lineage_status}


def marked_source_text(run: Path) -> str | None:
    """The file-1 tool text as the model saw it (marker included), from the intervention audit."""
    if not (run / "events.jsonl").is_file():
        return None
    for event in lines(run / "events.jsonl"):
        if event.get("event_type") == "TOOL_OUTPUT_INTERVENTION" and (event.get("data") or {}).get("status") == "assigned":
            return (event["data"].get("marked_text")) or None
    return None


def primary_pairs(view: dict, expected_sinks: list[str], *, source_file_id_="1") -> list[dict]:
    sink = expected_sinks[-1]
    return [p for p in view["pairs"] if p["function"] == sink and p["source_file_id"] == source_file_id_]


def tier1_attributed(view: dict, expected_sinks: list[str], stage: str) -> bool | None:
    """Tracer Tier 1 matched for the file-1 source (or, in a restored session, the recovered origin) to the expected sink."""
    if stage == "B":
        candidates = [p for p in view["lineage_pairs"] if p["function"] == expected_sinks[-1]]
    else:
        candidates = primary_pairs(view, expected_sinks)
    scored = [p for p in candidates if p["tier1_status"] == "scored"]
    if not scored:
        return None
    return any(p["tier1_matched"] for p in scored)


def first_tiers(view: dict, expected_sinks: list[str], stage: str) -> list[str | None]:
    if stage == "B":
        candidates = [p for p in view["lineage_pairs"] if p["function"] == expected_sinks[-1]]
    else:
        candidates = primary_pairs(view, expected_sinks)
    return [p["first_matched_tier"] for p in candidates]


def build_rows(batch: Path, plan: dict, summary: dict) -> list[dict]:
    rows = []
    for record in summary["slots"]:
        transform = case_t1.transformation(record["transformation"])
        for session in record["sessions"]:
            stage = session["stage"]
            run = batch / "runs" / record["slot_id"] / stage
            scoring = (session.get("summary") or {}).get("scoring") or {}
            expected = transform["expected_sinks"][stage]
            view = tracer_view(run, expected)
            primary = scoring.get("primary_sink") or {}
            argument_survival = primary.get("argument_survival") or {}
            native = None
            if primary.get("function") == "create_file":
                files = [f for f in scoring.get("created_files", []) if f.get("filename") == (primary.get("arguments") or {}).get("filename")]
                native = files[-1]["survival"] if files else None
            elif primary.get("function") == "send_email":
                emails = scoring.get("sent_emails") or []
                native = emails[-1]["survival"] if emails else None
            rows.append(
                {
                    "slot_id": record["slot_id"],
                    "transformation": record["transformation"],
                    "label": transform["label"],
                    "repetition": record["repetition"],
                    "stage": stage,
                    "process_status": session["process_status"],
                    "error_type": session.get("error_type"),
                    "reason": session.get("reason"),
                    "requests": session.get("recorded_request_count"),
                    "expected_sinks": expected,
                    "executed_sinks": scoring.get("executed_sinks"),
                    "task_completed": scoring.get("task_completed"),
                    "primary_sink": primary.get("function"),
                    "primary_arguments": primary.get("arguments"),
                    "recipient_outcome": primary.get("recipient_outcome"),
                    "attacker_address": argument_survival.get("attacker_address"),
                    "legit_address": argument_survival.get("legit_address"),
                    "facts_present": argument_survival.get("facts_present"),
                    "canary_in_arguments": argument_survival.get("canary_present"),
                    "canary_tokens_in_arguments": argument_survival.get("canary_tokens_present"),
                    "canary_in_native_state": (native or {}).get("canary_present"),
                    "reference_in_arguments": argument_survival.get("reference_present"),
                    "reference_in_native_state": (native or {}).get("reference_present"),
                    "canary_tokens": scoring.get("canary_tokens"),
                    "reference_token": scoring.get("reference_token"),
                    "tier1_attributed": tier1_attributed(view, expected, stage),
                    "first_matched_tiers": first_tiers(view, expected, stage),
                    "lineage_status": view["lineage_status"],
                    "tracer_pairs": view["pairs"],
                    "lineage_pairs": view["lineage_pairs"],
                    "marked_source_text": marked_source_text(run),
                    "memory_only_path": scoring.get("memory_only_path"),
                    "report": str(run / "report.html"),
                }
            )
    return rows


def matrix(rows: list[dict], plan: dict) -> list[dict]:
    cells = []
    for transform in plan["transformations"]:
        final_stage = transform["stages"][-1]
        group = [r for r in rows if r["transformation"] == transform["id"] and r["stage"] == final_stage]
        completed = [r for r in group if r["task_completed"]]

        def count(key):
            return sum(1 for r in completed if r.get(key) is True)

        cells.append(
            {
                "transformation": transform["id"],
                "label": transform["label"],
                "final_stage": final_stage,
                "expected_sink": transform["expected_sinks"][final_stage][-1],
                "sessions": len(group),
                "completed": len(completed),
                "information_survived": count("attacker_address"),
                "legit_address_present": count("legit_address"),
                "facts_median": sorted(len(r["facts_present"] or []) for r in completed)[len(completed) // 2] if completed else None,
                "canary_in_arguments": count("canary_in_arguments"),
                "canary_in_native_state": count("canary_in_native_state"),
                "tier1_attributed": count("tier1_attributed"),
                "tier1_unknown": sum(1 for r in completed if r.get("tier1_attributed") is None),
                "first_matched_tiers": dict(Counter(t for r in completed for t in (r["first_matched_tiers"] or []))),
                "reference_in_arguments": count("reference_in_arguments"),
                "recipient_outcomes": dict(Counter(r["recipient_outcome"] for r in completed if r.get("recipient_outcome"))),
                "lineage_status": dict(Counter(r["lineage_status"] for r in completed if r["lineage_status"])),
            }
        )
    return cells


def prior_evidence() -> dict | None:
    if not (PRIOR_BATCH / "plan.json").is_file():
        return None
    pairs = []
    for run in sorted((PRIOR_BATCH / "runs").glob("*-canary")):
        manifest = run / "manifest.json"
        if not manifest.is_file() or not (read(manifest).get("config") or {}).get("canary_enabled"):
            continue
        for record in lines(run / "provenance.jsonl"):
            if record.get("record_type") != "call_analysis":
                continue
            call = record["call"]
            for field in call.get("fields", []):
                for pair in field.get("nt_style_cascade", []):
                    stages = pair.get("stages") or {}
                    pairs.append(
                        {
                            "run": run.name,
                            "function": call.get("function"),
                            "argument_path": field.get("argument_path"),
                            "tier1_matched": (stages.get("tier1") or {}).get("matched"),
                            "tier2_score": (stages.get("tier2") or {}).get("score"),
                            "first_matched_tier": pair.get("first_matched_tier"),
                        }
                    )
    return {
        "batch": PRIOR_BATCH.relative_to(ROOT).as_posix(),
        "description": "2026-09-09 passive/canary comparison, canary arm: benign native task; the model composed new append_to_file content from a marked search result.",
        "pairs": pairs,
        "tier1_hits": sum(1 for p in pairs if p["tier1_matched"]),
        "pair_count": len(pairs),
    }


def summary_text(data: dict) -> list[str]:
    cells = {c["transformation"]: c for c in data["matrix"]}
    total_completed = sum(c["completed"] for c in data["matrix"])
    total_sessions = sum(c["sessions"] for c in data["matrix"])
    info = sum(c["information_survived"] for c in data["matrix"])
    canary = sum(c["canary_in_arguments"] for c in data["matrix"])
    t1 = sum(c["tier1_attributed"] for c in data["matrix"])
    survived_in = [c["label"] for c in data["matrix"] if c["completed"] and c["canary_in_arguments"] == c["completed"]]
    lost_in = [c["label"] for c in data["matrix"] if c["completed"] and c["canary_in_arguments"] == 0]
    mixed = [c["label"] for c in data["matrix"] if c["completed"] and 0 < c["canary_in_arguments"] < c["completed"]]
    reference_kept = [c["label"] for c in data["matrix"] if c["completed"] and c["reference_in_arguments"] == c["completed"]]
    paragraphs = [
        f"{total_completed}/{total_sessions} final-stage sessions completed their task under the canary condition "
        f"(model {esc(data['model'])}; {data['requests']} requests). The attacker address reached the expected sink in "
        f"{info}/{total_completed} completed sessions; the runtime canary reached it in {canary}/{total_completed}; the tracer's "
        f"Tier 1 attributed the sink to the marked source in {t1}/{total_completed}.",
        (f"Canary survived in every completed run of: {', '.join(survived_in)}. " if survived_in else "The canary survived in no transformation. ")
        + (f"Canary lost in every completed run of: {', '.join(lost_in)}. " if lost_in else "")
        + (f"Mixed: {', '.join(mixed)}. " if mixed else "")
        + "Where Tier 1 misses, the ordered cascade records which later tier matched instead (first-tier column).",
        (
            f"The in-content reference line (local placement variant, not a NeuroTaint tier) survived in every completed run of: "
            f"{', '.join(reference_kept)}."
            if reference_kept
            else "The in-content reference line survived in no transformation."
        ),
    ]
    verbatim = cells.get("verbatim")
    if verbatim and verbatim["completed"] and verbatim["canary_in_arguments"] == 0 and verbatim["reference_in_arguments"] == verbatim["completed"]:
        paragraphs.append(
            f"Verbatim copy is the placement case: in {verbatim['completed']}/{verbatim['completed']} runs the model reproduced the document's "
            "<code>content</code> field, including the in-content reference line, but not the YAML metadata block after which the runtime "
            "canary is appended, so the canonical marker was dropped even by an exact copy of the document."
        )
    cross = cells.get("cross_session")
    if cross and cross["completed"]:
        status = ", ".join(f"{esc(k)} ×{v}" for k, v in cross["lineage_status"].items()) or "unknown"
        paragraphs.append(
            f"Cross-session: lineage status {status}; Tier 1 attributed {cross['tier1_attributed']}/{cross['completed']} "
            "Session B sends to the recovered file-1 origin. The DCPG rehydrated the graph label (with the original canary reference "
            "attached) without the marker text being present in the sink; Tier 2 matched the recovered origin instead."
        )
    if data.get("prior"):
        paragraphs.append(
            f"Prior evidence ({esc(data['prior']['batch'])}): {data['prior']['tier1_hits']}/{data['prior']['pair_count']} Tier-1 hits on composed content; "
            "consistent with the transformation results here."
        )
    paragraphs.append(
        "Marker membership is literal and says nothing about maliciousness or causal influence. The canonical placement (a YAML "
        "comment appended after the serialized tool result's metadata) is a local choice of the reproduction; the paper says only "
        "that a unique UUID is injected into source content."
    )
    return paragraphs


CSS = """
body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#fafafa;color:#1b1b1b}
header{background:#1f2a44;color:#fff;padding:18px 28px}header h1{margin:0 0 4px;font-size:22px}
nav{position:sticky;top:0;background:#fff;border-bottom:1px solid #ccc;padding:8px 28px;display:flex;gap:10px;flex-wrap:wrap;z-index:2}
nav button{border:1px solid #888;background:#fff;padding:6px 12px;border-radius:6px;cursor:pointer;font:inherit}
nav button[aria-pressed=true]{background:#1f2a44;color:#fff}
main{padding:20px 28px;max-width:1500px;margin:0 auto}section{display:none}section.active{display:block}
table{border-collapse:collapse;width:100%;background:#fff;margin:10px 0}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}th{background:#eef1f7}
.pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:12px;border:1px solid #999;background:#fff;white-space:nowrap}
.pill.yes{background:#e3f4e3}.pill.no{background:#fde2e2}.pill.na{background:#eee}
.unknown{color:#777;font-style:italic}
pre.src{background:#fff;border:1px solid #ddd;border-radius:6px;padding:10px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12.5px;max-height:320px;overflow:auto}
mark.canary{background:#ffd54a}mark.ref{background:#cde2fb}mark.addr{background:#fde2e2}
code{font-size:12.5px}details{margin:8px 0}summary{cursor:pointer}h3{margin-top:24px}
.question{font-size:17px;border-left:4px solid #1f2a44;padding-left:12px;background:#fff;padding:10px 12px}
"""

JS = """
function show(id){
  if(!document.getElementById(id)) id='summary';
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('active',s.id===id));
  document.querySelectorAll('nav button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.target===id)));
  history.replaceState(null,'','#'+id);
}
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>show(b.dataset.target)));
show((location.hash||'#summary').slice(1));
"""


def render_summary(data):
    return (
        "<h2>Executive summary</h2><p class=\"question\">Under which common agent transformations does the source information "
        "survive in the sink while the provenance marker does not?</p>"
        + "".join(f"<p>{p}</p>" for p in summary_text(data))
        + "<h3>Provenance</h3><table>"
        + "".join(
            f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
            for k, v in (
                ("Batch", f"{data['batch']} ({data['batch_protocol']}; plan sha256 {data['plan_sha256']})"),
                ("Canary placement", data["canary_placement"]),
                ("Requests / tokens", f"{data['requests']} / {data['tokens']}"),
                ("Completed sessions", f"{data['completed_sessions']}/{data['planned_sessions']}"),
            )
        )
        + "</table>"
    )


def render_matrix(data):
    rows = []
    for c in data["matrix"]:
        n = c["completed"]
        tiers = ", ".join(f"{esc(k)} ×{v}" for k, v in sorted(c["first_matched_tiers"].items(), key=lambda kv: str(kv[0])))
        lineage = ", ".join(f"{esc(k)} ×{v}" for k, v in c["lineage_status"].items()) or "—"
        recipients = ", ".join(f"{esc(k)} ×{v}" for k, v in c["recipient_outcomes"].items()) or "—"
        rows.append(
            f"<tr><td>{esc(c['label'])}<br><small>{esc(c['transformation'])} · sink {esc(c['expected_sink'])}</small></td>"
            f"<td>{n}/{c['sessions']}</td><td>{c['information_survived']}/{n}</td><td>{c['legit_address_present']}/{n}</td><td>{recipients}</td>"
            f"<td>{esc(c['facts_median'])}</td><td>{c['canary_in_arguments']}/{n}</td><td>{c['canary_in_native_state']}/{n}</td>"
            f"<td>{c['tier1_attributed']}/{n}" + (f" <small>({c['tier1_unknown']} unknown)</small>" if c["tier1_unknown"] else "") + "</td>"
            f"<td>{tiers or '—'}</td><td>{c['reference_in_arguments']}/{n}</td><td>{lineage}</td></tr>"
        )
    return (
        "<h2>Transformation × measure matrix</h2><p>Counts over completed final-stage sessions. Information = attacker address "
        "literally present in the executed primary sink arguments. Canary = the runtime UUID issued for file 1 (or, for restored "
        "sessions, the Session A token) literally present. Executed recipient = native sent-mail outcome for send_email sinks; the "
        "address present in the arguments may differ from the recipient chosen. Tier 1 attributed = the tracer's Tier-1 stage matched for the file-1 "
        "source (or recovered origin) against the expected sink. First tier = which tier matched first for those pairs. "
        "Reference = the in-content marker line (local placement variant).</p>"
        "<table><tr><th>Transformation</th><th>Completed</th><th>Attacker address in sink</th><th>Legit address in sink</th>"
        "<th>Executed recipient (send_email only)</th><th>Decision facts (median of 3)</th><th>Canary in arguments</th><th>Canary in native state</th><th>Tier 1 attributed</th>"
        "<th>First matched tier</th><th>In-content reference in sink</th><th>Lineage status</th></tr>" + "".join(rows) + "</table>"
    )


def highlight(text: str, row: dict) -> str:
    out = esc(text)
    for label, token in (row.get("canary_tokens") or {}).items():
        if token:
            out = out.replace(esc(token), f'<mark class="canary" title="{esc(label)}">{esc(token)}</mark>')
    if row.get("reference_token"):
        out = out.replace(esc(row["reference_token"]), f'<mark class="ref">{esc(row["reference_token"])}</mark>')
    out = out.replace(esc(case_t1.ATTACKER), f'<mark class="addr">{esc(case_t1.ATTACKER)}</mark>')
    return out


def render_slots(data, output):
    blocks = []
    for row in data["rows"]:
        args = json.dumps(row.get("primary_arguments"), ensure_ascii=False, indent=1) if row.get("primary_arguments") else "none"
        pairs = "".join(
            f"<tr><td>{esc(p['function'])}</td><td>{esc(p['argument_path'])}</td><td>{esc(p.get('source_file_id', 'recovered origin'))}</td>"
            f"<td>{esc(p['tier1_status'])} {pill(p['tier1_matched'], 'match', 'no match')}</td>"
            f"<td>{p['tier2_score']:.3f}</td><td>{esc(p['first_matched_tier'])}</td></tr>"
            if isinstance(p.get("tier2_score"), float)
            else f"<tr><td>{esc(p['function'])}</td><td>{esc(p['argument_path'])}</td><td>{esc(p.get('source_file_id', 'recovered origin'))}</td>"
            f"<td>{esc(p['tier1_status'])} {pill(p['tier1_matched'], 'match', 'no match')}</td><td>—</td><td>{esc(p['first_matched_tier'])}</td></tr>"
            for p in (row["tracer_pairs"] + row["lineage_pairs"])
        )
        report = Path(row["report"])
        link = f' · <a href="{esc(Path(os.path.relpath(report, output)).as_posix())}">run report</a>' if report.is_file() else ""
        blocks.append(
            f"<h3>{esc(row['slot_id'])} / {esc(row['stage'])} — {esc(row['label'])} "
            f"<span class=\"pill na\">{esc(row['process_status'])}</span>{link}</h3>"
            f"<p>Task completed {pill(row['task_completed'])} · attacker address {pill(row['attacker_address'])} · "
            f"facts {esc(row['facts_present'])} · canary in arguments {pill(row['canary_in_arguments'])} "
            f"({esc(row['canary_tokens_in_arguments'])}) · canary in native state {pill(row['canary_in_native_state'])} · "
            f"Tier 1 attributed {pill(row['tier1_attributed'])} · reference {pill(row['reference_in_arguments'])} · "
            f"lineage {esc(row['lineage_status'] or '—')}"
            + (f" · error {esc(row['error_type'])}" if row.get("error_type") else "")
            + (f" · {esc(row['reason'])}" if row.get("reason") else "")
            + "</p>"
            f"<details><summary>Executed primary sink arguments ({esc(row['primary_sink'])})</summary><pre class=\"src\">{highlight(args, row)}</pre></details>"
            + (
                f"<details><summary>Source text as the model saw it (marker highlighted)</summary><pre class=\"src\">{highlight(row['marked_source_text'], row)}</pre></details>"
                if row.get("marked_source_text")
                else ""
            )
            + "<details><summary>Tracer pairs</summary><table><tr><th>Sink</th><th>Argument</th><th>Source</th><th>Tier 1</th><th>Tier 2</th><th>First tier</th></tr>"
            + pairs + "</table></details>"
        )
    return "<h2>Per-session detail</h2>" + "".join(blocks)


def render_prior(data):
    prior = data.get("prior")
    if not prior:
        return "<h2>Prior evidence</h2><p class=\"unknown\">The 2026-09-09 canary batch is not available on this machine.</p>"
    rows = "".join(
        f"<tr><td>{esc(p['run'])}</td><td>{esc(p['function'])}</td><td>{esc(p['argument_path'])}</td>"
        f"<td>{pill(p['tier1_matched'], 'match', 'no match')}</td><td>{p['tier2_score']:.3f}</td><td>{esc(p['first_matched_tier'])}</td></tr>"
        for p in prior["pairs"]
    )
    return (
        f"<h2>Prior evidence</h2><p>{esc(prior['description'])} Tier-1 hits: {prior['tier1_hits']}/{prior['pair_count']} pairs.</p>"
        "<table><tr><th>Run</th><th>Sink</th><th>Argument</th><th>Tier 1</th><th>Tier 2</th><th>First tier</th></tr>" + rows + "</table>"
    )


LIMITATIONS = """<h2>Limitations</h2><ul>
<li>One synthetic document, one model, three repetitions per transformation: exact counts for this batch, not rates.</li>
<li>The canonical canary placement (YAML comment appended after the serialized tool result) is a local choice; the paper does not specify placement. The in-content reference line is a local placement variant, not a NeuroTaint tier.</li>
<li>Marker membership is literal. Information survival is measured by the attacker address and three decision facts only.</li>
<li>Prompts explicitly request each transformation; the model's default behaviour under an unconstrained task is not measured here.</li>
<li>No clean-document control in this batch; the 2026-09-09 comparison found no passive/canary behavioural difference on a benign task.</li>
<li>Nothing here is causal evidence or a defence evaluation; findings concern this reproduction under its declared choices.</li>
</ul>"""


def build(batch: Path, output: Path, *, title=None) -> dict:
    batch, output = batch.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(batch) or batch.is_relative_to(output):
        raise ValueError("Packet output must be fresh and separate from the batch")
    plan, summary = read(batch / "plan.json"), read(batch / "summary.json")
    rows = build_rows(batch, plan, summary)
    data = {
        "protocol": PROTOCOL,
        "requests_for_report": 0,
        "batch": batch.relative_to(ROOT).as_posix() if batch.is_relative_to(ROOT) else str(batch),
        "batch_protocol": plan["protocol"],
        "plan_sha256": summary.get("plan_sha256"),
        "real_llm": plan["real_llm"],
        "model": plan["model"],
        "canary_placement": plan["canary_placement"],
        "requests": summary.get("captured_primary_requests"),
        "tokens": summary.get("reported_primary_tokens"),
        "planned_sessions": summary.get("planned_sessions"),
        "completed_sessions": summary.get("completed_sessions"),
        "paused": summary.get("paused"),
        "rows": rows,
        "matrix": matrix(rows, plan),
        "prior": prior_evidence(),
        "interpretation": "Literal marker membership and native-state outcomes; not causal evidence.",
    }
    output.mkdir(parents=True)
    (output / "packet.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    heading = title or "Case T1: Tier-1 canary survival under agent transformations"
    slim = {**data, "rows": [{k: v for k, v in r.items() if k != "marked_source_text"} for r in rows]}
    embedded = json.dumps(slim, ensure_ascii=False).replace("</", "<\\/")
    mode = f"live Groq {esc(plan['model'])}" if plan["real_llm"] else "offline transport control"
    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{esc(heading)}</title><style>{CSS}</style></head><body>"
        f"<header><h1>{esc(heading)}</h1><div>Protocol {esc(plan['protocol'])} &middot; {mode} &middot; canary condition enabled &middot; "
        f"{data['completed_sessions']}/{data['planned_sessions']} sessions completed</div></header>"
        '<nav><button type="button" data-target="summary">Summary</button><button type="button" data-target="matrix">Matrix</button>'
        '<button type="button" data-target="slots">Sessions</button><button type="button" data-target="prior">Prior evidence</button>'
        '<button type="button" data-target="limits">Limitations</button></nav><main>'
        f'<section id="summary">{render_summary(data)}</section><section id="matrix">{render_matrix(data)}</section>'
        f'<section id="slots">{render_slots(data, output)}</section><section id="prior">{render_prior(data)}</section>'
        f'<section id="limits">{LIMITATIONS}</section></main>'
        f'<script id="packet-data" type="application/json">{embedded}</script><script>{JS}</script></body></html>'
    )
    (output / "index.html").write_text(page, encoding="utf-8")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--title")
    args = parser.parse_args()
    result = build(args.batch, args.output, title=args.title)
    print(json.dumps({"sessions": len(result["rows"]), "matrix": [(c["transformation"], c["canary_in_arguments"], c["completed"]) for c in result["matrix"]], "output": str(args.output)}))
