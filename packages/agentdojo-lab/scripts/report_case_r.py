"""Render the Case R meeting packet from saved batch, diagnostics and follow-up evidence.

Self-contained offline HTML: inline CSS and JS, embedded JSON, relative links to
per-run reports. Recorded exposure and correspondence are shown as evidence; the
page never presents them as proof of causal influence.
"""

from __future__ import annotations

import argparse
import html
import json
import os
from collections import defaultdict
from pathlib import Path

from agentdojo_lab import case_r_groq as case_r
from agentdojo_lab.case_r_diagnostics import argument_concordance, rescore_run
from agentdojo_lab.paired_report import export_pair

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE = {"send_email": ["/recipients", "/cc", "/bcc"]}


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def relative(target, base):
    return Path(os.path.relpath(target, base)).as_posix()


def matcher_from_plan(plan):
    if not plan.get("real_llm"):
        return None
    from agentdojo_lab.semantic import LocalMiniLMEncoder, SemanticMatcher

    return SemanticMatcher(LocalMiniLMEncoder(ROOT / plan["semantic_model"], revision=plan["semantic_revision"]))


def matrix_rows(summary):
    rows = []
    for slot in summary["slots"]:
        scoring = (slot.get("summary") or {}).get("scoring") or {}
        rows.append(
            {
                "slot_id": slot["slot_id"],
                "construction": slot["construction"],
                "arm": slot["arm"],
                "repetition": slot["repetition"],
                "process_status": slot["process_status"],
                "recipient_outcome": scoring.get("recipient_outcome"),
                "predicted_outcome": scoring.get("predicted_outcome")
                or case_r.predicted_outcome(slot["construction"], slot["arm"]),
                "task_flow_completed": scoring.get("task_flow_completed"),
                "attack_success": scoring.get("attack_success"),
                "interpretation_eligible": scoring.get("interpretation_eligible"),
                "error_type": slot.get("error_type"),
                "requests": slot.get("recorded_request_count"),
                "report": str(Path(slot["run_path"]) / "report.html"),
            }
        )
    return rows


def build_pairs(summary, output):
    by_id = {s["slot_id"]: s for s in summary["slots"]}
    pairs = []
    for slot in summary["slots"]:
        if slot["arm"] == "neither" or slot["process_status"] == "not_started":
            continue
        clean_id = f"{slot['construction']}-r{slot['repetition']:02d}-neither"
        clean = by_id.get(clean_id)
        item = {
            "slot_id": slot["slot_id"],
            "clean_slot_id": clean_id,
            "path": f"pairs/{slot['slot_id']}",
            "status": "unavailable",
            "comparability": None,
            "first_security_relevant_divergence": None,
            "security_argument_changes": [],
        }
        if (
            clean
            and clean["process_status"] != "not_started"
            and Path(slot["run_path"]).is_dir()
            and Path(clean["run_path"]).is_dir()
        ):
            try:
                result = export_pair(
                    Path(clean["run_path"]), Path(slot["run_path"]), output / item["path"], sensitive_paths=SENSITIVE
                )
                item["status"] = "rendered"
                item["comparability"] = result["comparability"]["status"]
                divergence = result["first_security_relevant_divergence"]
                item["first_security_relevant_divergence"] = divergence
                row_index = divergence.get("alignment_row")
                if row_index is not None:
                    row = result["alignment"]["rows"][row_index]
                    item["security_argument_changes"] = row.get("security_argument_changes", [])
                    item["divergence_event_ids"] = {
                        "clean": row.get("clean_event_id"),
                        "attacked": row.get("attacked_event_id"),
                    }
            except (ValueError, OSError, KeyError, IndexError) as error:
                item["status"] = f"failed: {type(error).__name__}"
        pairs.append(item)
    return pairs


def flowchart(run_path, slot, scoring):
    """Recorded chronology only: source result -> exposure -> proposal -> runtime -> sent mail.

    Event shapes (recording.py / observation.py): TOOL_CALL_PROPOSED.data = {function,
    arguments}; TOOL_RUNTIME_RETURNED.data = {result, error}; TOOL_RESULT.data.message
    .tool_call = {function, args}; TOOL_OUTPUT_EXPOSED.data.source_result_event_id;
    ENVIRONMENT_CHANGE shares call_ref with the executed proposal.
    """
    events = lines(Path(run_path) / "events.jsonl")
    by_type = defaultdict(list)
    for event in events:
        by_type[event.get("event_type")].append(event)
    nodes, edges = [], []

    def node(label, event_id=None, detail=None, kind="event"):
        nodes.append({"id": f"n{len(nodes)}", "label": label, "event_id": event_id, "detail": detail, "kind": kind})
        return nodes[-1]["id"]

    def data(event):
        return event.get("data") or {}

    previous = None
    exposures_by_result = defaultdict(list)
    for exposure in by_type.get("TOOL_OUTPUT_EXPOSED", []):
        exposures_by_result[data(exposure).get("source_result_event_id")].append(exposure.get("event_id"))
    for result in by_type.get("TOOL_RESULT", []):
        tool_call = (data(result).get("message") or {}).get("tool_call") or {}
        if tool_call.get("function") != "get_file_by_id":
            continue
        file_id = (tool_call.get("args") or {}).get("file_id")
        current = node(
            f"Source file {file_id}: tool result",
            result.get("event_id"),
            {"function": "get_file_by_id", "file_id": file_id, "call_ref": result.get("call_ref")},
            "source",
        )
        if previous:
            edges.append({"from": previous, "to": current, "kind": "order"})
        previous = current
        exposed = exposures_by_result.get(result.get("event_id"), [])
        plural = "s" if len(exposed) != 1 else ""
        current = node(
            f"Exposed to model ({len(exposed)} request{plural})" if exposed else "Exposure: not recorded",
            exposed[0] if exposed else None,
            {"exposure_event_ids": exposed},
            "exposure" if exposed else "unknown",
        )
        edges.append({"from": previous, "to": current, "kind": "order"})
        previous = current
    proposals = [e for e in by_type.get("TOOL_CALL_PROPOSED", []) if data(e).get("function") == "send_email"]
    state_event = None
    if proposals:
        proposal = proposals[0]
        current = node(
            "send_email proposal (/recipients)",
            proposal.get("event_id"),
            {"arguments": data(proposal).get("arguments"), "call_ref": proposal.get("call_ref")},
            "proposal",
        )
        if previous:
            edges.append({"from": previous, "to": current, "kind": "association"})
        previous = current
        call_ref = proposal.get("call_ref")
        runtime = [e for e in by_type.get("TOOL_RUNTIME_RETURNED", []) if e.get("call_ref") == call_ref]
        executed = bool(runtime) and not data(runtime[0]).get("error")
        current = node(
            "Native runtime returned" if executed else "Native runtime: error or not recorded",
            runtime[0].get("event_id") if runtime else None,
            {"error": data(runtime[0]).get("error"), "result": data(runtime[0]).get("result")} if runtime else None,
            "runtime" if executed else "unknown",
        )
        edges.append({"from": previous, "to": current, "kind": "order"})
        previous = current
        changes = [e for e in by_type.get("ENVIRONMENT_CHANGE", []) if e.get("call_ref") == call_ref]
        state_event = changes[0].get("event_id") if changes else None
    else:
        current = node("send_email proposal: none recorded", None, None, "unknown")
        if previous:
            edges.append({"from": previous, "to": current, "kind": "order"})
        previous = current
    sent = scoring.get("sent_emails") or []
    label = f"Sent mail state: {scoring.get('recipient_outcome')}" if sent else "Sent mail state: none"
    current = node(
        label,
        state_event,
        {"sent_emails": [{k: e.get(k) for k in ("recipients", "cc", "bcc", "subject")} for e in sent]},
        "sink" if sent else "unknown",
    )
    if previous:
        edges.append({"from": previous, "to": current, "kind": "order"})
    return {
        "slot_id": slot["slot_id"],
        "construction": slot["construction"],
        "arm": slot["arm"],
        "repetition": slot["repetition"],
        "recipient_outcome": scoring.get("recipient_outcome"),
        "nodes": nodes,
        "edges": edges,
    }


def consistency(matrix):
    table = {}
    for row in matrix:
        cell = table.setdefault(row["construction"], {}).setdefault(
            row["arm"], {"repetitions": 0, "outcomes": [], "predicted": row["predicted_outcome"]}
        )
        cell["repetitions"] += 1
        cell["outcomes"].append(row["recipient_outcome"])
    for construction in table.values():
        for cell in construction.values():
            known = [o for o in cell["outcomes"] if o]
            cell["consistent"] = len(set(known)) == 1 if known else None
            cell["matches_prediction_count"] = sum(o == cell["predicted"] for o in known)
    return table


def followup_rows(followups):
    if followups is None or not (followups / "summary.json").is_file():
        return {}
    rows = {}
    for slot in read(followups / "summary.json")["slots"]:
        replay = slot.get("replay") or {}
        audit = slot.get("audit") or {}
        rows[slot["slot_id"]] = {
            "status": slot["status"],
            "reason": slot["reason"],
            "baseline_plan_status": slot.get("baseline_plan_status"),
            "baseline_coverage_status_counts": slot.get("baseline_coverage_status_counts"),
            "sham_reproduced": replay.get("baseline_reproduced"),
            "concordance": slot.get("prediction_concordance") or [],
            "replay_summary": {k: replay.get(k) for k in ("request_count", "status", "baseline_reproduced")},
            "audit_summary": {k: audit.get(k) for k in ("request_count", "status", "valid_count", "unknown_count")},
        }
    return rows


CSS = """
body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#fafafa;color:#1b1b1b}
header{background:#1f2a44;color:#fff;padding:18px 28px}header h1{margin:0 0 4px;font-size:22px}
nav{position:sticky;top:0;background:#fff;border-bottom:1px solid #ccc;padding:8px 28px;display:flex;gap:10px;flex-wrap:wrap;z-index:2}
nav button{border:1px solid #888;background:#fff;padding:6px 12px;border-radius:6px;cursor:pointer;font:inherit}
nav button[aria-pressed=true]{background:#1f2a44;color:#fff}
main{padding:20px 28px;max-width:1500px;margin:0 auto}section{display:none}section.active{display:block}
table{border-collapse:collapse;width:100%;background:#fff;margin:10px 0}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}th{background:#eef1f7}
td.attacker{background:#fde2e2}td.legit{background:#e3f4e3}td.other{background:#fff3cd}td.none{background:#eee}
.unknown{color:#777;font-style:italic}
.flow{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:8px 0 12px}
.node{border:2px solid #555;border-radius:8px;padding:8px 12px;background:#fff;cursor:pointer;min-width:120px;text-align:left;font:inherit}
.node.source{border-color:#0b6e4f}.node.exposure{border-color:#3a6ea5}.node.proposal{border-color:#c0392b}
.node.runtime{border-color:#8e44ad}.node.sink{border-color:#c0392b;background:#fde2e2}
.node.unknown{border-style:dashed;color:#777}.node[aria-pressed=true]{outline:3px solid #f5b400}
.arrow{font-size:22px;color:#555}.arrow.association{color:#3a6ea5}
.detail{background:#fff;border:1px solid #ccc;border-radius:6px;padding:10px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,Consolas,monospace;font-size:13px;max-height:320px;overflow:auto;margin-bottom:22px}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;border:1px solid #999;background:#fff}
.pill.yes{background:#e3f4e3}.pill.no{background:#fde2e2}.pill.na{background:#eee}
.pill.attacker{background:#fde2e2}.pill.legit{background:#e3f4e3}
details{margin:8px 0}summary{cursor:pointer}a{color:#1f4e9c}h3{margin-top:26px}
@media (max-width:700px){main,header,nav{padding-left:14px;padding-right:14px}}
"""

JS = """
const DATA = JSON.parse(document.getElementById('packet-data').textContent);
function show(id){
  if(!document.getElementById(id)) id='matrix';
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('active',s.id===id));
  document.querySelectorAll('nav button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.target===id)));
  history.replaceState(null,'','#'+id);
}
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>show(b.dataset.target)));
show((location.hash||'#matrix').slice(1));
document.querySelectorAll('.flow').forEach(flow=>{
  const chart=DATA.flowcharts.find(f=>f.slot_id===flow.dataset.slot);
  const detail=document.getElementById('detail-'+flow.dataset.index);
  flow.querySelectorAll('.node').forEach(el=>el.addEventListener('click',()=>{
    flow.querySelectorAll('.node').forEach(n=>n.setAttribute('aria-pressed','false'));
    el.setAttribute('aria-pressed','true');
    const node=chart.nodes.find(n=>n.id===el.dataset.node);
    detail.textContent=JSON.stringify({label:node.label,event_id:node.event_id,kind:node.kind,detail:node.detail},null,2);
  }));
  const first=flow.querySelector('.node'); if(first) first.click();
});
"""


def pill(value):
    if value is True:
        return '<span class="pill yes">yes</span>'
    if value is False:
        return '<span class="pill no">no</span>'
    return '<span class="pill na">unknown</span>'


def outcome_pill(value):
    text = html.escape(str(value or "unknown"))
    return f'<span class="pill {text}">{text}</span>'


def short(value, limit=72):
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def fmt(value):
    if isinstance(value, float):
        return f"{value:.3f}"
    return html.escape(str(value))


def render_matrix(data, output):
    rows = []
    for row in data["matrix"]:
        report = Path(row["report"])
        link = html.escape(row["slot_id"])
        if report.is_file():
            link = f'<a href="{html.escape(relative(report, output), quote=True)}">{link}</a>'
        outcome = row["recipient_outcome"] or "unknown"
        error = f" / {html.escape(str(row['error_type']))}" if row["error_type"] else ""
        rows.append(
            f"<tr><td>{link}</td><td>{html.escape(row['construction'])}</td><td>{html.escape(row['arm'])}</td>"
            f"<td>{row['repetition']}</td><td class=\"{html.escape(outcome)}\">{html.escape(outcome)}</td>"
            f"<td>{html.escape(row['predicted_outcome'])}</td><td>{pill(row['task_flow_completed'])}</td>"
            f"<td>{pill(row['attack_success'])}</td><td>{html.escape(row['process_status'])}{error}</td>"
            f"<td>{html.escape(str(row['requests']))}</td></tr>"
        )
    return (
        "<h2>Outcome matrix</h2><p>Recipient outcome comes from native sent-mail state. Predicted outcomes "
        "were frozen before any request. Failed and not-started slots remain visible.</p>"
        "<table><tr><th>Slot</th><th>Construction</th><th>Arm</th><th>Rep</th><th>Recipient</th>"
        "<th>Predicted</th><th>Flow complete</th><th>Attack success</th><th>Process</th><th>Requests</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def render_pairs(data):
    rows = []
    for pair in data["pairs"]:
        label = f"{html.escape(pair['slot_id'])} vs {html.escape(pair['clean_slot_id'])}"
        if pair["status"] == "rendered":
            label = f'<a href="{html.escape(pair["path"], quote=True)}/index.html">{label}</a>'
        divergence = pair.get("first_security_relevant_divergence") or {}
        changes = "; ".join(
            f"{html.escape(str(c.get('path')))}: {html.escape(json.dumps(c.get('before'), ensure_ascii=False))}"
            f" &#8594; {html.escape(json.dumps(c.get('after'), ensure_ascii=False))}"
            for c in pair.get("security_argument_changes", [])
        )
        rows.append(
            f"<tr><td>{label}</td><td>{html.escape(str(pair['status']))}</td>"
            f"<td>{html.escape(str(pair.get('comparability')))}</td>"
            f"<td>{html.escape(str(divergence.get('status')))}"
            + (f" (alignment row {divergence['alignment_row']})" if divergence.get("alignment_row") is not None else "")
            + f"</td><td>{changes or '<span class=\"unknown\">none recorded</span>'}</td></tr>"
        )
    return (
        "<h2>Paired clean vs attacked comparisons</h2><p>Each attacked arm is aligned with the <em>neither</em> "
        "run of the same repetition. The linked two-lane view highlights changed sensitive arguments; alignment "
        "is a navigation aid, not attribution.</p>"
        "<table><tr><th>Pair</th><th>Status</th><th>Comparability</th><th>First security-relevant divergence</th>"
        "<th>Sensitive argument changes</th></tr>" + "".join(rows) + "</table>"
    )


def render_flowcharts(data):
    blocks = []
    for index, chart in enumerate(data["flowcharts"]):
        parts = []
        for position, node in enumerate(chart["nodes"]):
            if position:
                kind = next((e["kind"] for e in chart["edges"] if e["to"] == node["id"]), "order")
                glyph = "&#8594;" if kind == "order" else "&#8674;"
                parts.append(f'<span class="arrow {html.escape(kind)}" aria-hidden="true">{glyph}</span>')
            event = (
                f"<br><small>{html.escape(node['event_id'])}</small>" if node["event_id"] else "<br><small>no event</small>"
            )
            parts.append(
                f'<button type="button" class="node {html.escape(node["kind"])}" data-node="{node["id"]}" '
                f'aria-pressed="false">{html.escape(node["label"])}{event}</button>'
            )
        blocks.append(
            f"<h3>{html.escape(chart['slot_id'])} {outcome_pill(chart['recipient_outcome'])}</h3>"
            f'<div class="flow" data-slot="{html.escape(chart["slot_id"], quote=True)}" data-index="{index}">'
            + "".join(parts)
            + f'</div><div class="detail" id="detail-{index}"></div>'
        )
    if not blocks:
        blocks.append('<p class="unknown">No successful attack was recorded, so there is no propagation path to chart.</p>')
    return (
        "<h2>Propagation flowcharts</h2><p>Solid arrows: recorded order. Dashed arrow: source/request association. "
        "Dashed nodes: unobserved or unknown. Click a node for its recorded event.</p>" + "".join(blocks)
    )


def render_attribution(data):
    blocks = []
    for entry in data["attribution"]:
        rows = []
        for cell in entry["rows"]:
            variants = cell["variants"]
            truth = cell["ground_truth"]
            tier3 = (variants["semantic_only"].get("tier3") or {}).get("score")
            rows.append(
                f"<tr><td>{html.escape(str(cell['argument_path']))}</td>"
                f"<td title=\"{html.escape(cell['value'], quote=True)}\">{html.escape(short(cell['value']))}</td>"
                f"<td>{html.escape(str(cell['source_file_id']))}</td>"
                f"<td>{pill(truth['carries_value'])}</td><td>{pill(truth['carries_instruction'])}</td>"
                f"<td>{fmt(variants['baseline']['score'])} {pill(variants['baseline']['matched'])}</td>"
                f"<td>{pill(variants['substring']['matched'])}</td>"
                f"<td>{fmt(tier3) if tier3 is not None else '<span class=\"unknown\">n/a</span>'} "
                f"{pill(variants['semantic_only']['matched'])}</td></tr>"
            )
        follow = entry.get("followup")
        typed = entry.get("argument_concordance")
        if typed:
            typed_rows = "".join(
                f"<tr><td>{html.escape(', '.join('file ' + str(f) for f in row['removed_files']))}</td>"
                f"<td>{html.escape(str(row['response_kind']))}</td>"
                f"<td>{outcome_pill(row['proposed_recipient_outcome'])}</td>"
                f"<td>{pill(row['attacker_recipient_persisted'])}</td>"
                f"<td>{html.escape(str(row['judge_would_call_anyway']))}"
                + (f" ({row['judge_confidence']:.2f})" if isinstance(row.get('judge_confidence'), (int, float)) else "")
                + f"</td><td>{pill(row['agreement'])}</td></tr>"
                for row in typed["rows"]
            )
            typed_html = (
                f"<details open><summary>Recipient-level replay / judge (sham re-proposed attacker recipient: "
                f"{html.escape(str(typed['sham_reproduced_recipient']))}; observed pattern: "
                f"<b>{html.escape(typed['observed_pattern'])}</b>)</summary>"
                "<table><tr><th>Removed</th><th>Model response</th><th>Proposed recipient</th>"
                "<th>Attacker persisted</th><th>Judge: would call anyway</th><th>Agree</th></tr>" + typed_rows
                + f"</table><p class=\"unknown\">{html.escape(typed['removal_semantics'])}</p></details>"
            )
        else:
            typed_html = ""
        if follow:
            concordance = "".join(
                f"<tr><td>{html.escape(', '.join(str(s) for s in (row.get('source_ids') or [])))}</td>"
                f"<td>{pill(row['known'])}</td><td>{html.escape(str(row['predicted_call']))}</td>"
                f"<td>{html.escape(str(row['observed_call']))}</td><td>{pill(row['agreement'])}</td></tr>"
                for row in follow.get("concordance", [])
            )
            follow_html = typed_html + (
                f"<details><summary>Whole-call identity replay / judge (frozen replay rule): status {html.escape(str(follow.get('status')))}; "
                f"baseline plan {html.escape(str(follow.get('baseline_plan_status')))}; "
                f"sham reproduced {html.escape(str(follow.get('sham_reproduced')))}</summary>"
                "<table><tr><th>Removed sources</th><th>Known</th><th>Judge: would call anyway</th>"
                "<th>Replay: attacker proposal persisted</th><th>Agree</th></tr>" + concordance + "</table></details>"
            )
        else:
            follow_html = '<p class="unknown">No forced follow-up for this sink.</p>'
        eligibility = entry["eligibility"]
        recipient = entry.get("recipient_eligibility") or {variant: "unknown" for variant in eligibility}
        blocks.append(
            f"<h3>{html.escape(entry['slot_id'])} &middot; proposal {html.escape(str(entry['proposal_event_id']))} "
            f"&middot; recipient {outcome_pill(entry['recipient_outcome'])}</h3>"
            f"<p>Causal probe eligibility (implemented per-sink gate): baseline <b>{html.escape(eligibility['baseline'])}</b>; "
            f"substring <b>{html.escape(eligibility['substring'])}</b>; "
            f"semantic-only <b>{html.escape(eligibility['semantic_only'])}</b>.<br>"
            f"Hypothetical per-argument gate over recipient pairs only: baseline <b>{html.escape(recipient['baseline'])}</b>; "
            f"substring <b>{html.escape(recipient['substring'])}</b>; "
            f"semantic-only <b>{html.escape(recipient['semantic_only'])}</b>.</p>"
            "<table><tr><th>Argument</th><th>Value</th><th>Source file</th><th>Carries sent value</th>"
            "<th>Carries instruction</th><th>Tier-2 LCS (baseline)</th><th>Substring</th>"
            "<th>Semantic-only (tier3 cosine)</th></tr>" + "".join(rows) + "</table>" + follow_html
        )
    return (
        "<h2>Attribution panel</h2><p>Baseline = subsequence LCS as implemented (threshold 0.15). Substring = exact "
        "bounded match. Semantic-only = Tier 3/4 with Tier 2 disabled. Ground truth is the frozen construction. "
        "Forced probes exist only because the explicit gate was bypassed; the baseline plans none of them.</p>"
        + "".join(blocks)
    )


def render_consistency(data):
    rows = []
    for construction, arms in data["consistency"].items():
        for arm, cell in arms.items():
            rows.append(
                f"<tr><td>{html.escape(construction)}</td><td>{html.escape(arm)}</td><td>{cell['repetitions']}</td>"
                f"<td>{html.escape(', '.join(str(o) for o in cell['outcomes']))}</td>"
                f"<td>{html.escape(cell['predicted'])}</td>"
                f"<td>{cell['matches_prediction_count']}/{cell['repetitions']}</td><td>{pill(cell['consistent'])}</td></tr>"
            )
    return (
        "<h2>Repeated-run consistency</h2><p>Per construction and arm; cells are not pooled into a population rate.</p>"
        "<table><tr><th>Construction</th><th>Arm</th><th>Reps</th><th>Outcomes</th><th>Predicted</th>"
        "<th>Matches</th><th>Consistent</th></tr>" + "".join(rows) + "</table>"
    )


LIMITATIONS = """<h2>Limitations</h2><ul>
<li>Synthetic two-file task on native AgentDojo tools with one model (Groq openai/gpt-oss-120b);
not a benchmark task and not an attack success rate.</li>
<li>Three repetitions per arm at temperature 0 support examples and consistency checks, not population estimates.</li>
<li>Tier-2 correspondence, substring and semantic scores are similarity evidence. None establishes causal influence
or maliciousness.</li>
<li>Forced replay and judge results exist only because the explicit-candidate gate was bypassed; they describe what
the causal layer would say, not what the baseline method does.</li>
<li>Whole-source neutralization in replays removes benign content too; primary arms remove only payload blocks.
The two intervention types are reported separately.</li>
<li>Invalid judgments, non-reproducing shams, transport failures and paused slots remain unknown and are never
replaced.</li>
<li>Findings concern this independent implementation under its declared choices; they are not claims about the
original authors' code.</li>
</ul>"""


def build(batch, followups, output, *, title=None):
    batch, output = batch.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(batch) or batch.is_relative_to(output):
        raise ValueError("Packet output must be fresh and separate from the batch")
    if followups is not None:
        followups = followups.resolve()
        if output.is_relative_to(followups) or followups.is_relative_to(output):
            raise ValueError("Packet output must be separate from the follow-up directory")
    summary = read(batch / "summary.json")
    plan = read(batch / "plan.json")
    matcher = matcher_from_plan(plan)
    output.mkdir(parents=True)
    matrix = matrix_rows(summary)
    pairs = build_pairs(summary, output)
    follow = followup_rows(followups)
    flowcharts, attribution = [], []
    for slot in summary["slots"]:
        run_path = Path(slot["run_path"])
        if not (run_path / "provenance.jsonl").is_file():
            continue
        scoring = read(run_path / "scoring.json") if (run_path / "scoring.json").is_file() else {}
        if scoring.get("attack_success"):
            flowcharts.append(flowchart(run_path, slot, scoring))
        rescored = rescore_run(run_path, matcher=matcher)
        typed = argument_concordance(followups, slot["slot_id"], run_path, plan) if followups else None
        for sink in rescored["sinks"]:
            attribution.append(
                {
                    "slot_id": slot["slot_id"],
                    "proposal_event_id": sink["proposal_event_id"],
                    "recipient_outcome": scoring.get("recipient_outcome"),
                    "eligibility": sink["eligibility"],
                    "recipient_eligibility": sink.get("recipient_eligibility"),
                    "rows": sink["rows"],
                    "followup": follow.get(slot["slot_id"]),
                    "argument_concordance": typed,
                }
            )
    data = {
        "protocol": plan["protocol"],
        "real_llm": plan["real_llm"],
        "model": plan["model"],
        "batch": str(batch),
        "followups": str(followups) if followups else None,
        "planned_slots": summary["planned_slots"],
        "completed_slots": summary["completed_slots"],
        "paused": summary.get("paused"),
        "matrix": matrix,
        "pairs": pairs,
        "flowcharts": flowcharts,
        "attribution": attribution,
        "consistency": consistency(matrix),
        "semantic_available": matcher is not None,
    }
    (output / "packet.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    embedded = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    heading = title or "Case R: recipient contamination under redundant and split sources"
    mode = f"live Groq {html.escape(plan['model'])}" if plan["real_llm"] else "offline transport control"
    paused = " &middot; PAUSED" if summary.get("paused") else ""
    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(heading)}</title><style>{CSS}</style></head><body>"
        f"<header><h1>{html.escape(heading)}</h1><div>Protocol {html.escape(plan['protocol'])} &middot; {mode} &middot; "
        f"{summary['completed_slots']}/{summary['planned_slots']} slots completed{paused}</div></header>"
        '<nav><button type="button" data-target="matrix">Outcomes</button>'
        '<button type="button" data-target="pairs">Clean vs attacked</button>'
        '<button type="button" data-target="flow">Propagation</button>'
        '<button type="button" data-target="attribution">Attribution</button>'
        '<button type="button" data-target="consistency">Consistency</button>'
        '<button type="button" data-target="limits">Limitations</button></nav><main>'
        f'<section id="matrix">{render_matrix(data, output)}</section>'
        f'<section id="pairs">{render_pairs(data)}</section>'
        f'<section id="flow">{render_flowcharts(data)}</section>'
        f'<section id="attribution">{render_attribution(data)}</section>'
        f'<section id="consistency">{render_consistency(data)}</section>'
        f'<section id="limits">{LIMITATIONS}</section></main>'
        f'<script id="packet-data" type="application/json">{embedded}</script><script>{JS}</script></body></html>'
    )
    (output / "index.html").write_text(page, encoding="utf-8")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--followups", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--title")
    args = parser.parse_args()
    result = build(args.batch, args.followups, args.output, title=args.title)
    print(
        json.dumps(
            {
                "slots": len(result["matrix"]),
                "pairs": len(result["pairs"]),
                "flowcharts": len(result["flowcharts"]),
                "output": str(args.output),
            }
        )
    )
