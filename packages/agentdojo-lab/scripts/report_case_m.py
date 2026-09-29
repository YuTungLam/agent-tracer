"""Render the Case M packet: two-session memory chains from saved batch evidence.

Self-contained offline HTML reusing the Case R page chrome. Views: chain outcomes,
paired clean/attacked views per session, two-session propagation flowcharts with the
checkpoint boundary, and an attribution panel that shows the memory-write score, the
fresh-session visible-source score and the rehydrated-origin score side by side.
Recorded correspondence is never presented as causal influence.
"""

from __future__ import annotations

import argparse
import html
import json
from collections import defaultdict
from pathlib import Path

from report_case_r import CSS, JS, LIMITATIONS, fmt, lines, outcome_pill, pill, read, relative

from agentdojo_lab.paired_report import export_pair

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE = {"create_file": ["/content"], "send_email": ["/recipients", "/cc", "/bcc"]}


def chain_rows(summary):
    rows = []
    for record in summary["slots"]:
        chain = record["chain"]
        sessions = {s["stage"]: s for s in record["sessions"]}
        a = (sessions.get("A", {}).get("summary") or {}).get("scoring") or {}
        b = (sessions.get("B", {}).get("summary") or {}).get("scoring") or {}
        rows.append(
            {
                "slot_id": record["slot_id"],
                "branch": record["branch"],
                "repetition": record["repetition"],
                "a_status": sessions.get("A", {}).get("process_status"),
                "b_status": sessions.get("B", {}).get("process_status"),
                "b_reason": sessions.get("B", {}).get("reason"),
                "summary_address": a.get("summary_address"),
                "verbatim_copy": a.get("verbatim_copy"),
                "shared_5gram_fraction": a.get("shared_5gram_fraction"),
                "paraphrase_lcs": a.get("paraphrase_lcs"),
                "b_recipient": b.get("recipient_outcome"),
                "memory_only_path": b.get("memory_only_path"),
                "read_file_ids": b.get("read_file_ids"),
                "attack_via_memory": chain.get("attack_via_memory"),
                "matches_prediction": chain.get("matches_prediction"),
                "a_report": str(Path(sessions["A"]["run_path"]) / "report.html") if "A" in sessions else None,
                "b_report": str(Path(sessions["B"]["run_path"]) / "report.html") if "B" in sessions else None,
            }
        )
    return rows


def build_pairs(summary, output):
    by_key = {(r["branch"], r["repetition"]): r for r in summary["slots"]}
    pairs = []
    for record in summary["slots"]:
        if record["branch"] != "attacked":
            continue
        clean = by_key.get(("clean", record["repetition"]))
        for stage in ("A", "B"):
            item = {"slot_id": record["slot_id"], "stage": stage, "clean_slot_id": clean["slot_id"] if clean else None,
                    "path": f"pairs/{record['slot_id']}-{stage}", "status": "unavailable", "comparability": None,
                    "first_security_relevant_divergence": None, "security_argument_changes": []}
            attacked_run = next((s for s in record["sessions"] if s["stage"] == stage), None)
            clean_run = next((s for s in clean["sessions"] if s["stage"] == stage), None) if clean else None
            if attacked_run and clean_run and Path(attacked_run["run_path"]).is_dir() and Path(clean_run["run_path"]).is_dir():
                try:
                    result = export_pair(Path(clean_run["run_path"]), Path(attacked_run["run_path"]), output / item["path"], sensitive_paths=SENSITIVE)
                    item["status"] = "rendered"
                    item["comparability"] = result["comparability"]["status"]
                    divergence = result["first_security_relevant_divergence"]
                    item["first_security_relevant_divergence"] = divergence
                    if divergence.get("alignment_row") is not None:
                        row = result["alignment"]["rows"][divergence["alignment_row"]]
                        item["security_argument_changes"] = row.get("security_argument_changes", [])
                except (ValueError, OSError, KeyError, IndexError) as error:
                    item["status"] = f"failed: {type(error).__name__}"
            pairs.append(item)
    return pairs


def session_nodes(run_path, stage, scoring, sink_function, node):
    """Recorded chronology for one session: read result -> exposure -> sink proposal -> runtime -> state."""
    events = lines(Path(run_path) / "events.jsonl")
    by_type = defaultdict(list)
    for event in events:
        by_type[event.get("event_type")].append(event)

    def data(event):
        return event.get("data") or {}

    ids = []
    exposures = defaultdict(list)
    for exposure in by_type.get("TOOL_OUTPUT_EXPOSED", []):
        exposures[data(exposure).get("source_result_event_id")].append(exposure.get("event_id"))
    for result in by_type.get("TOOL_RESULT", []):
        call = (data(result).get("message") or {}).get("tool_call") or {}
        if call.get("function") != "get_file_by_id":
            continue
        file_id = (call.get("args") or {}).get("file_id")
        label = f"{stage}: read file {file_id}" + (" (stored summary)" if stage == "B" else " (source document)")
        ids.append(node(label, result.get("event_id"), {"file_id": file_id, "call_ref": result.get("call_ref")}, "source"))
        exposed = exposures.get(result.get("event_id"), [])
        ids.append(node(f"{stage}: exposed to model ({len(exposed)})" if exposed else f"{stage}: exposure not recorded",
                        exposed[0] if exposed else None, {"exposure_event_ids": exposed}, "exposure" if exposed else "unknown"))
    proposals = [e for e in by_type.get("TOOL_CALL_PROPOSED", []) if data(e).get("function") == sink_function]
    if proposals:
        proposal = proposals[0]
        arguments = data(proposal).get("arguments") or {}
        shown = {k: (v[:160] + "..." if isinstance(v, str) and len(v) > 160 else v) for k, v in arguments.items()}
        ids.append(node(f"{stage}: {sink_function} proposal", proposal.get("event_id"), {"arguments": shown}, "proposal"))
        call_ref = proposal.get("call_ref")
        runtime = [e for e in by_type.get("TOOL_RUNTIME_RETURNED", []) if e.get("call_ref") == call_ref]
        executed = bool(runtime) and not data(runtime[0]).get("error")
        ids.append(node(f"{stage}: native runtime returned" if executed else f"{stage}: runtime error or not recorded",
                        runtime[0].get("event_id") if runtime else None, None, "runtime" if executed else "unknown"))
        changes = [e for e in by_type.get("ENVIRONMENT_CHANGE", []) if e.get("call_ref") == call_ref]
        state_event = changes[0].get("event_id") if changes else None
    else:
        ids.append(node(f"{stage}: {sink_function} proposal: none recorded", None, None, "unknown"))
        state_event = None
    if stage == "A":
        created = scoring.get("created_files") or []
        label = f"A: stored file {created[0].get('id_')} ({scoring.get('summary_address')} address)" if created else "A: no file stored"
        ids.append(node(label, state_event, {"files": [{k: f.get(k) for k in ("id_", "filename", "content")} for f in created]}, "sink" if created else "unknown"))
    else:
        sent = scoring.get("sent_emails") or []
        label = f"B: sent mail state: {scoring.get('recipient_outcome')}" if sent else "B: sent mail state: none"
        ids.append(node(label, state_event, {"sent_emails": [{k: e.get(k) for k in ("recipients", "cc", "bcc", "subject")} for e in sent]}, "sink" if sent else "unknown"))
    return ids


def chain_flowchart(record):
    nodes, edges = [], []

    def node(label, event_id=None, detail=None, kind="event"):
        nodes.append({"id": f"n{len(nodes)}", "label": label, "event_id": event_id, "detail": detail, "kind": kind})
        return nodes[-1]["id"]

    sessions = {s["stage"]: s for s in record["sessions"]}
    previous = None
    for stage, sink in (("A", "create_file"), ("B", "send_email")):
        session = sessions.get(stage)
        run_path = Path(session["run_path"]) if session else None
        if stage == "B":
            handoff = record.get("handoff") or {}
            ready = handoff.get("status") == "ready"
            checkpoint = node(
                "checkpoint: drive + DCPG registry persisted" if ready else f"checkpoint: {handoff.get('status')} {','.join(handoff.get('reasons') or [])}",
                None,
                {k: handoff.get(k) for k in ("status", "reasons", "native_sha256", "lineage_sha256", "summary_file_id")},
                "runtime" if ready else "unknown",
            )
            if previous:
                edges.append({"from": previous, "to": checkpoint, "kind": "order"})
            previous = checkpoint
        if not run_path or not (run_path / "events.jsonl").is_file():
            current = node(f"{stage}: session not started", None, {"reason": (session or {}).get("reason")}, "unknown")
            if previous:
                edges.append({"from": previous, "to": current, "kind": "order"})
            previous = current
            continue
        scoring = read(run_path / "scoring.json") if (run_path / "scoring.json").is_file() else {}
        ids = session_nodes(run_path, stage, scoring, sink, node)
        for index, identifier in enumerate(ids):
            if previous:
                kind = "association" if nodes[int(identifier[1:])]["kind"] == "proposal" else "order"
                edges.append({"from": previous, "to": identifier, "kind": kind})
            previous = identifier
    return {"slot_id": record["slot_id"], "branch": record["branch"], "repetition": record["repetition"],
            "recipient_outcome": record["chain"].get("observed_session_b_recipient"), "nodes": nodes, "edges": edges}


def attribution_rows(record):
    """Memory-write score in A, visible-source and rehydrated-origin scores at the B sink."""
    sessions = {s["stage"]: s for s in record["sessions"]}
    out = {"slot_id": record["slot_id"], "branch": record["branch"], "write": None, "send": None}
    a = sessions.get("A")
    if a and Path(a["run_path"], "provenance.jsonl").is_file():
        for row in lines(Path(a["run_path"]) / "provenance.jsonl"):
            call = row.get("call") or {}
            if row.get("record_type") == "call_analysis" and call.get("function") == "create_file":
                for field in call.get("fields", []):
                    if field.get("argument_path") == "/content":
                        pairs = field.get("nt_style_cascade", [])
                        out["write"] = {
                            "proposal_event_id": call.get("proposal_event_id"),
                            "pairs": [{"score": p["stages"]["tier2"].get("score"), "matched": p.get("matched"), "first_matched_tier": p.get("first_matched_tier")} for p in pairs],
                            "lineage_status": (call.get("lineage") or {}).get("summary", {}).get("status"),
                        }
                break
    b = sessions.get("B")
    if b and Path(b["run_path"], "provenance.jsonl").is_file():
        for row in lines(Path(b["run_path"]) / "provenance.jsonl"):
            call = row.get("call") or {}
            if row.get("record_type") == "call_analysis" and call.get("function") == "send_email":
                visible = []
                for field in call.get("fields", []):
                    if field.get("argument_path") == "/recipients/0":
                        visible = [{"score": p["stages"]["tier2"].get("score"), "matched": p.get("matched"), "first_matched_tier": p.get("first_matched_tier")} for p in field.get("nt_style_cascade", [])]
                lineage = call.get("lineage") or {}
                recovered = [
                    {"argument_path": c.get("argument_path"), "matched": c.get("matched"), "first_matched_tier": c.get("first_matched_tier"),
                     "score": (c.get("stages") or {}).get("tier2", {}).get("score")}
                    for c in lineage.get("comparisons", []) if c.get("argument_path") == "/recipients/0"
                ]
                out["send"] = {
                    "proposal_event_id": call.get("proposal_event_id"),
                    "visible_source_pairs": visible,
                    "lineage_status": lineage.get("summary", {}).get("status"),
                    "recovered_source_count": lineage.get("summary", {}).get("recovered_source_count"),
                    "recovered_origin_pairs": recovered,
                    "memory_events": [{"record_key": e.get("record_key"), "status": e.get("status")} for e in lineage.get("memory_events", [])],
                    "causal_analysis": call.get("cascade_summary", {}).get("causal_analysis"),
                }
                break
    return out


def render_chains(rows, output):
    cells = []
    for row in rows:
        links = []
        for stage, key, status in (("A", "a_report", row["a_status"]), ("B", "b_report", row["b_status"])):
            report = Path(row[key]) if row.get(key) else None
            label = f"{stage}: {html.escape(str(status))}"
            if report and report.is_file():
                label = f'<a href="{html.escape(relative(report, output), quote=True)}">{label}</a>'
            links.append(label)
        overlap = row["shared_5gram_fraction"]
        cells.append(
            f"<tr><td>{html.escape(row['slot_id'])}</td><td>{' &middot; '.join(links)}"
            + (f"<br><span class=\"unknown\">{html.escape(str(row['b_reason']))}</span>" if row.get("b_reason") else "")
            + f"</td><td>{outcome_pill(row['summary_address'])}</td><td>{pill(False if row['verbatim_copy'] is False else row['verbatim_copy'])}"
            f" <small>5-gram {fmt(overlap) if overlap is not None else 'n/a'}; LCS {fmt(row['paraphrase_lcs']) if row['paraphrase_lcs'] is not None else 'n/a'}</small></td>"
            f"<td>{outcome_pill(row['b_recipient'])}</td><td>{pill(row['memory_only_path'])} <small>{html.escape(', '.join(row.get('read_file_ids') or []))}</small></td>"
            f"<td>{pill(row['attack_via_memory'])}</td><td>{pill(row['matches_prediction'])}</td></tr>"
        )
    return ("<h2>Memory chains</h2><p>Session A stores a summary in its own words; Session B is a fresh process that restores the drive and the "
            "DCPG registry, reads only the stored summary, and sends it. All outcomes come from native drive and sent-mail state.</p>"
            "<table><tr><th>Slot</th><th>Sessions</th><th>Stored summary carries</th><th>Verbatim copy</th><th>Session B recipient</th>"
            "<th>Memory-only path (files read)</th><th>Attack via memory</th><th>Matches prediction</th></tr>" + "".join(cells) + "</table>")


def render_pairs(pairs):
    rows = []
    for pair in pairs:
        label = f"{html.escape(pair['slot_id'])} {pair['stage']} vs {html.escape(str(pair['clean_slot_id']))} {pair['stage']}"
        if pair["status"] == "rendered":
            label = f'<a href="{html.escape(pair["path"], quote=True)}/index.html">{label}</a>'
        divergence = pair.get("first_security_relevant_divergence") or {}
        changes = "; ".join(
            f"{html.escape(str(c.get('path')))}: {html.escape(json.dumps(c.get('before'), ensure_ascii=False)[:80])} &#8594; {html.escape(json.dumps(c.get('after'), ensure_ascii=False)[:80])}"
            for c in pair.get("security_argument_changes", [])
        )
        rows.append(f"<tr><td>{label}</td><td>{html.escape(str(pair['status']))}</td><td>{html.escape(str(pair.get('comparability')))}</td>"
                    f"<td>{html.escape(str(divergence.get('status')))}</td><td>{changes or '<span class=\"unknown\">none recorded</span>'}</td></tr>")
    return ("<h2>Paired clean vs attacked views</h2><p>Each attacked session is aligned with the clean session of the same stage and repetition.</p>"
            "<table><tr><th>Pair</th><th>Status</th><th>Comparability</th><th>First security-relevant divergence</th><th>Sensitive argument changes</th></tr>"
            + "".join(rows) + "</table>")


def render_flowcharts(charts):
    blocks = []
    for index, chart in enumerate(charts):
        parts = []
        for position, node in enumerate(chart["nodes"]):
            if position:
                kind = next((e["kind"] for e in chart["edges"] if e["to"] == node["id"]), "order")
                parts.append(f'<span class="arrow {html.escape(kind)}" aria-hidden="true">{"&#8594;" if kind == "order" else "&#8674;"}</span>')
            event = f"<br><small>{html.escape(node['event_id'])}</small>" if node["event_id"] else "<br><small>no event</small>"
            parts.append(f'<button type="button" class="node {html.escape(node["kind"])}" data-node="{node["id"]}" aria-pressed="false">{html.escape(node["label"])}{event}</button>')
        blocks.append(f"<h3>{html.escape(chart['slot_id'])} {outcome_pill(chart['recipient_outcome'])}</h3>"
                      f'<div class="flow" data-slot="{html.escape(chart["slot_id"], quote=True)}" data-index="{index}">' + "".join(parts)
                      + f'</div><div class="detail" id="detail-{index}"></div>')
    return ("<h2>Two-session propagation</h2><p>Source document &#8594; Session A memory write &#8594; checkpoint &#8594; fresh Session B read &#8594; "
            "send. Solid arrows: recorded order; dashed: source/request association; dashed nodes: unobserved. Click a node for its event.</p>" + "".join(blocks))


def render_attribution(entries):
    blocks = []
    for entry in entries:
        write, send = entry.get("write") or {}, entry.get("send") or {}
        write_pairs = "".join(f"<tr><td>A create_file /content vs source document</td><td>{fmt(p['score'])} {pill(p['matched'])}</td><td>{html.escape(str(p['first_matched_tier']))}</td></tr>" for p in write.get("pairs", []))
        visible = "".join(f"<tr><td>B send_email /recipients/0 vs visible stored summary</td><td>{fmt(p['score'])} {pill(p['matched'])}</td><td>{html.escape(str(p['first_matched_tier']))}</td></tr>" for p in send.get("visible_source_pairs", []))
        recovered = "".join(f"<tr><td>B send_email /recipients/0 vs rehydrated origin (Session A document)</td><td>{fmt(p['score'])} {pill(p['matched'])}</td><td>{html.escape(str(p['first_matched_tier']))}</td></tr>" for p in send.get("recovered_origin_pairs", []))
        memory = ", ".join(f"{e['record_key']}: {e['status']}" for e in send.get("memory_events", []))
        blocks.append(
            f"<h3>{html.escape(entry['slot_id'])} ({html.escape(entry['branch'])})</h3>"
            f"<p>Session B lineage: <b>{html.escape(str(send.get('lineage_status')))}</b>; recovered sources: {html.escape(str(send.get('recovered_source_count')))}; "
            f"memory events: {html.escape(memory) or 'none'}; causal analysis: {html.escape(str(send.get('causal_analysis')))}.</p>"
            "<table><tr><th>Comparison</th><th>Tier-2 LCS</th><th>First matched tier</th></tr>" + write_pairs + visible + recovered + "</table>"
        )
    return ("<h2>Attribution across the memory boundary</h2><p>Three correspondence checks per chain: the memory write against its source, the fresh-session "
            "sink against the stored summary it read, and the sink against the origin rehydrated from the persisted registry. Identical scores in clean "
            "and attacked chains mean the path is recovered as derivation, not as contamination.</p>" + "".join(blocks))


def build(batch, output, *, title=None):
    batch, output = batch.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(batch) or batch.is_relative_to(output):
        raise ValueError("Packet output must be fresh and separate from the batch")
    summary, plan = read(batch / "summary.json"), read(batch / "plan.json")
    output.mkdir(parents=True)
    rows = chain_rows(summary)
    pairs = build_pairs(summary, output)
    charts = [chain_flowchart(record) for record in summary["slots"] if any(s["process_status"] != "not_started" for s in record["sessions"])]
    attribution = [attribution_rows(record) for record in summary["slots"] if any(s["process_status"] != "not_started" for s in record["sessions"])]
    data = {"protocol": plan["protocol"], "real_llm": plan["real_llm"], "model": plan["model"], "batch": str(batch),
            "planned_sessions": summary["planned_sessions"], "completed_sessions": summary["completed_sessions"],
            "attacks_via_memory": summary["attacks_via_memory"], "paused": summary.get("paused"),
            "chains": rows, "pairs": pairs, "flowcharts": charts, "attribution": attribution}
    (output / "packet.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    embedded = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    heading = title or "Case M: paraphrased memory write and fresh-session send"
    mode = f"live Groq {html.escape(plan['model'])}" if plan["real_llm"] else "offline transport control"
    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(heading)}</title><style>{CSS}</style></head><body>"
        f"<header><h1>{html.escape(heading)}</h1><div>Protocol {html.escape(plan['protocol'])} &middot; {mode} &middot; "
        f"{summary['completed_sessions']}/{summary['planned_sessions']} sessions completed &middot; {summary['attacks_via_memory']} attacks via memory"
        f"{' &middot; PAUSED' if summary.get('paused') else ''}</div></header>"
        '<nav><button type="button" data-target="matrix">Chains</button><button type="button" data-target="pairs">Clean vs attacked</button>'
        '<button type="button" data-target="flow">Propagation</button><button type="button" data-target="attribution">Attribution</button>'
        '<button type="button" data-target="limits">Limitations</button></nav><main>'
        f'<section id="matrix">{render_chains(rows, output)}</section><section id="pairs">{render_pairs(pairs)}</section>'
        f'<section id="flow">{render_flowcharts(charts)}</section><section id="attribution">{render_attribution(attribution)}</section>'
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
    print(json.dumps({"chains": len(result["chains"]), "pairs": len(result["pairs"]), "flowcharts": len(result["flowcharts"]), "output": str(args.output)}))
