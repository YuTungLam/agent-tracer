"""Render a saved Case R controlled semantic packet without rescoring it.

The packet is the evidence authority. This script makes no model or network
requests and never infers a conclusion from a score. Every dynamic value is
HTML-escaped, including source text, chunk text and JSON disclosures.
"""

from __future__ import annotations

import argparse
import html
import json
import math
from pathlib import Path

SECTIONS = (
    ("baseline", "Original Case R baseline"),
    ("crossover", "Recipient string × context crossover"),
    ("generality", "Predeclared independent inputs"),
    ("granularity", "Source granularity diagnostic"),
)
ROW_FIELDS = frozenset(
    {
        "id",
        "source_unit",
        "source_text",
        "target_text",
        "source_sha256",
        "target_sha256",
        "exact",
        "tier3",
        "tier4",
    }
)


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def pretty(value: object) -> str:
    return esc(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))


def number(value: object) -> str:
    if isinstance(value, bool) or value is None:
        return "—"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return "—"
        return f"{value:.6f}" if isinstance(value, float) else str(value)
    return esc(value)


def status(value: object) -> str:
    if value is True:
        return '<span class="badge yes">match</span>'
    if value is False:
        return '<span class="badge no">no match</span>'
    return '<span class="badge unknown">unknown</span>'


def row_metadata(row: dict) -> dict:
    return {key: value for key, value in row.items() if key not in ROW_FIELDS}


def flatten_counts(value: object, prefix: str = "") -> list[tuple[str, object]]:
    if isinstance(value, dict):
        result = []
        for key, child in value.items():
            path = f"{prefix} / {key}" if prefix else str(key)
            result.extend(flatten_counts(child, path))
        return result
    return [(prefix, value)]


def field_value(row: dict, *names: str) -> object:
    for name in names:
        value = row.get(name)
        if value is not None:
            return value
    return "—"


def provenance_value(row: dict, *names: str) -> object:
    provenance = row.get("provenance")
    return field_value(provenance, *names) if isinstance(provenance, dict) else "—"


def score_cell(stage: object, *, tier4: bool = False) -> str:
    if not isinstance(stage, dict):
        return "—"
    score = number(stage.get("score"))
    coverage = f"<br><small>coverage {number(stage.get('coverage'))}</small>" if tier4 else ""
    return (
        f"<strong>{score}</strong> {status(stage.get('matched'))}{coverage}"
        f"<br><small>{esc(stage.get('status', 'unknown'))}; "
        f"truncated {esc(stage.get('truncated', 'unknown'))}</small>"
    )


def span_text(source: object, span: object) -> str | None:
    if not isinstance(source, str) or not isinstance(span, (list, tuple)) or len(span) != 2:
        return None
    start, end = span
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(source):
        return None
    return source[start:end]


def chunk_rows(row: dict) -> str:
    tier4 = row.get("tier4")
    chunks = tier4.get("chunks") if isinstance(tier4, dict) else None
    if not isinstance(chunks, list) or not chunks:
        return '<p class="muted">No chunks were returned.</p>'
    source = row.get("source_text")
    target = row.get("target_text")
    scored = [
        (index, chunk["score"])
        for index, chunk in enumerate(chunks)
        if isinstance(chunk, dict)
        and isinstance(chunk.get("score"), (int, float))
        and not isinstance(chunk["score"], bool)
        and math.isfinite(chunk["score"])
    ]
    best = max(scored, key=lambda item: item[1])[0] if scored else None
    result = []
    for index, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            result.append(f"<pre>{pretty(chunk)}</pre>")
            continue
        original = span_text(source, chunk.get("span"))
        encoded = span_text(source, chunk.get("visible_span"))
        contains_original = (
            isinstance(target, str) and bool(target) and original is not None and target in original
        )
        contains_full_target = (
            isinstance(target, str) and bool(target) and encoded is not None and target in encoded
        )
        classes = ' class="best"' if index == best else ""
        result.append(
            f"<details{classes}><summary>Chunk {index + 1}{' · best score' if index == best else ''} "
            f"· cosine {number(chunk.get('score'))} · {esc(chunk.get('span'))} "
            f"· {status(chunk.get('matched'))}</summary>"
            '<dl class="facts">'
            f"<dt>Original span</dt><dd>{esc(chunk.get('span'))}</dd>"
            f"<dt>Encoded visible span</dt><dd>{esc(chunk.get('visible_span'))}</dd>"
            f"<dt>Sentence range</dt><dd>{esc(chunk.get('sentence_range'))}</dd>"
            f"<dt>Complete target within original chunk</dt><dd>{esc(contains_original)}</dd>"
            f"<dt>Complete target within encoded view</dt><dd>{esc(contains_full_target)}</dd>"
            f"<dt>Tokenization</dt><dd><pre>{pretty(chunk.get('tokenization'))}</pre></dd>"
            '</dl>'
            '<div class="two">'
            f"<div><h5>Original chunk text</h5><pre>{esc(original) if original is not None else 'Unavailable: invalid span'}</pre></div>"
            f"<div><h5>Encoded visible text</h5><pre>{esc(encoded) if encoded is not None else 'Unavailable: invalid visible span'}</pre></div>"
            '</div>'
            f"<details><summary>Complete chunk record</summary><pre>{pretty(chunk)}</pre></details>"
            '</details>'
        )
    return "".join(result)


def detail(row: dict, section: str, index: int) -> str:
    source = row.get("source_text")
    target = row.get("target_text")
    tier3 = row.get("tier3")
    tier4 = row.get("tier4")
    exact = row.get("exact")
    source_length = len(source) if isinstance(source, str) else "unknown"
    target_length = len(target) if isinstance(target, str) else "unknown"
    metadata = row_metadata(row)
    return (
        f'<details class="pair" id="{esc(section)}-row-{index}">'
        f"<summary>{esc(row.get('id', f'row-{index}'))} · {esc(row.get('source_unit', 'unknown unit'))}"
        f" · {status(tier4.get('matched') if isinstance(tier4, dict) else None)}</summary>"
        '<dl class="facts">'
        f"<dt>Source SHA-256</dt><dd><code>{esc(row.get('source_sha256', 'unknown'))}</code></dd>"
        f"<dt>Target SHA-256</dt><dd><code>{esc(row.get('target_sha256', 'unknown'))}</code></dd>"
        f"<dt>Source / target code points</dt><dd>{esc(source_length)} / {esc(target_length)}</dd>"
        f"<dt>Exact-string control</dt><dd>{status(exact.get('matched') if isinstance(exact, dict) else None)}</dd>"
        '</dl>'
        '<div class="two">'
        f"<div><h4>Complete source input</h4><pre>{esc(source) if isinstance(source, str) else 'Unavailable'}</pre></div>"
        f"<div><h4>Target input</h4><pre>{esc(target) if isinstance(target, str) else 'Unavailable'}</pre></div>"
        '</div>'
        '<div class="two">'
        f"<div><h4>Exact-string bounds and spans</h4><pre>{pretty(exact)}</pre></div>"
        f"<div><h4>Provenance and edit metadata</h4><pre>{pretty(metadata)}</pre></div>"
        '</div>'
        '<h4>Tier 3 full-source cosine</h4>'
        f"<p>{score_cell(tier3)}</p><pre>{pretty(tier3)}</pre>"
        '<h4>Tier 4 chunk evidence</h4>'
        f"<p>{score_cell(tier4, tier4=True)}. "
        f"Matched-span union: {esc(tier4.get('matched_visible_spans') if isinstance(tier4, dict) else None)}.</p>"
        + chunk_rows(row)
        + f"<details><summary>Complete Tier 4 result</summary><pre>{pretty(tier4)}</pre></details>"
        '</details>'
    )


def summary_table(rows: list[dict], section: str) -> str:
    if not rows:
        return '<p class="muted">No rows recorded.</p>'
    body = []
    for index, row in enumerate(rows, 1):
        tier3, tier4 = row.get("tier3"), row.get("tier4")
        exact = row.get("exact")
        exact_match = exact.get("matched") if isinstance(exact, dict) else None
        factor = field_value(
            row,
            "context_template",
            "context_label",
            "context_id",
            "context",
            "template_id",
            "template",
            "condition",
        )
        if factor == "—":
            factor = provenance_value(row, "context", "context_template", "condition")
        panel = provenance_value(row, "panel")
        body.append(
            '<tr>'
            f'<td><a href="#{esc(section)}-row-{index}">{esc(row.get("id", f"row-{index}"))}</a></td>'
            f"<td>{esc(row.get('source_unit', 'unknown'))}</td>"
            f"<td><code>{esc(row.get('target_text', 'unknown'))}</code></td>"
            f"<td>{esc(panel)}</td>"
            f"<td>{esc(factor)}</td>"
            f"<td>{status(exact_match)}</td>"
            f"<td>{score_cell(tier3)}</td>"
            f"<td>{score_cell(tier4, tier4=True)}</td>"
            '</tr>'
        )
    return (
        '<div class="scroll"><table><thead><tr><th>Pair</th><th>Source unit</th><th>Target string</th>'
        '<th>Panel</th><th>Context / condition</th><th>Exact</th><th>Tier 3 cosine</th>'
        '<th>Tier 4 best cosine / coverage</th></tr></thead><tbody>'
        + "".join(body)
        + '</tbody></table></div>'
    )


def crossover_matrix(rows: list[dict]) -> str:
    contexts = sorted({str(provenance_value(row, "context")) for row in rows})
    targets = sorted({str(row.get("target_text", "—")) for row in rows})
    if len(contexts) < 2 or len(targets) < 2:
        return ""
    header = "".join(f"<th><code>{esc(target)}</code></th>" for target in targets)
    body = []
    for context in contexts:
        cells = []
        for target in targets:
            selected = [
                (index, row)
                for index, row in enumerate(rows, 1)
                if str(provenance_value(row, "context")) == context
                and str(row.get("target_text", "—")) == target
            ]
            if not selected:
                cells.append('<td class="muted">No saved pair</td>')
                continue
            parts = []
            for index, row in selected:
                tier3, tier4 = row.get("tier3") or {}, row.get("tier4") or {}
                parts.append(
                    f'<a href="#crossover-row-{index}">{esc(row.get("id", f"row-{index}"))}</a>'
                    f"<br>T3 {number(tier3.get('score'))} {status(tier3.get('matched'))}"
                    f"<br>T4 {number(tier4.get('score'))} {status(tier4.get('matched'))}"
                    f"<br>coverage {number(tier4.get('coverage'))}"
                )
            cells.append("<td>" + "<hr>".join(parts) + "</td>")
        body.append(f"<tr><th>{esc(context)}</th>{''.join(cells)}</tr>")
    return (
        '<h3>Context × target comparison</h3><div class="scroll"><table>'
        f'<thead><tr><th>Context</th>{header}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'
    )


def granularity_view_cell(row: object) -> str:
    if not isinstance(row, dict):
        return '<span class="muted">Not scored</span>'
    tier3 = row.get("tier3") or {}
    tier4 = row.get("tier4") or {}
    chunks = tier4.get("chunks") if isinstance(tier4, dict) else None
    count = len(chunks) if isinstance(chunks, list) else "—"
    return (
        f"<strong>{esc(row.get('source_unit', 'unknown unit'))}</strong>"
        f"<br>T3 {number(tier3.get('score'))} {status(tier3.get('matched'))}"
        f"<br>T4 {number(tier4.get('score'))} {status(tier4.get('matched'))}"
        f"<br>coverage {number(tier4.get('coverage'))}; chunks {esc(count)}"
        f"<br><small>T3 truncated {esc(tier3.get('truncated', 'unknown'))}; "
        f"T4 truncated {esc(tier4.get('truncated', 'unknown'))}</small>"
    )


def granularity_summary_table(rows: list[dict]) -> str:
    if not rows:
        return '<p class="muted">No rows recorded.</p>'
    body = []
    for index, wrapper in enumerate(rows, 1):
        body.append(
            '<tr>'
            f'<td><a href="#granularity-wrapper-{index}">{esc(wrapper.get("id", f"row-{index}"))}</a>'
            f"<br><small>occurrences {esc(wrapper.get('occurrences', 'unknown'))}</small></td>"
            f"<td><code>{esc(wrapper.get('original_pair_ids', []))}</code></td>"
            f"<td>{granularity_view_cell(wrapper.get('full'))}</td>"
            f"<td>{granularity_view_cell(wrapper.get('parsed_content'))}</td>"
            f"<td>{granularity_view_cell(wrapper.get('carrier_passage'))}</td>"
            '</tr>'
        )
    return (
        '<div class="scroll"><table><thead><tr><th>Original pair group</th><th>Original pair IDs</th>'
        '<th>Full source</th><th>Parsed content</th><th>Carrier passage</th></tr></thead><tbody>'
        + "".join(body)
        + '</tbody></table></div>'
    )


def granularity_detail(wrapper: dict, index: int) -> str:
    view_labels = (
        ("full", "Complete model-visible source"),
        ("parsed_content", "Parsed content"),
        ("carrier_passage", "Predeclared carrier passage"),
    )
    views = []
    for key, label in view_labels:
        score_row = wrapper.get(key)
        if score_row is None:
            views.append(f'<h4>{esc(label)}</h4><p class="muted">Not scored.</p>')
        else:
            views.append(f'<h4>{esc(label)}</h4>' + detail(score_row, f"granularity-{key}", index))
    other = {key: value for key, value in wrapper.items() if key not in {"full", "parsed_content", "carrier_passage"}}
    return (
        f'<details class="pair" id="granularity-wrapper-{index}"><summary>'
        f"{esc(wrapper.get('id', f'row-{index}'))} · "
        f"{esc(wrapper.get('occurrences', 'unknown'))} occurrence(s)</summary>"
        f'<details><summary>Group metadata</summary><pre>{pretty(other)}</pre></details>'
        + "".join(views)
        + '</details>'
    )


def render_counts(counts: object) -> str:
    if not isinstance(counts, dict) or not counts:
        return '<p class="muted">No count summary recorded.</p>'
    rows = flatten_counts(counts)
    return (
        '<div class="scroll"><table><thead><tr><th>Measure</th><th>Recorded value</th></tr></thead><tbody>'
        + "".join(f"<tr><td>{esc(name)}</td><td>{esc(value)}</td></tr>" for name, value in rows)
        + '</tbody></table></div>'
    )


def section_html(packet: dict, key: str, title: str) -> str:
    section = packet[key]
    rows = section["rows"]
    count_block = '<h3>Recorded counts</h3>' + render_counts(section.get("counts")) if key == "baseline" else ""
    if key == "granularity":
        return (
            f'<section id="{esc(key)}"><h2>{esc(title)}</h2>'
            '<p class="muted">Each group compares the same saved pair across declared source units. '
            'A carrier passage is an explicitly selected analysis view.</p>'
            + granularity_summary_table(rows)
            + '<h3>Complete view evidence</h3>'
            + "".join(granularity_detail(row, index) for index, row in enumerate(rows, 1))
            + '</section>'
        )
    return (
        f'<section id="{esc(key)}"><h2>{esc(title)}</h2>'
        + count_block
        + f'<p class="muted">{len(rows)} saved input pair(s). Scores below are the recorded values.</p>'
        + (crossover_matrix(rows) if key == "crossover" else "")
        + summary_table(rows, key)
        + '<h3>Input and scoring evidence</h3>'
        + "".join(detail(row, key, index) for index, row in enumerate(rows, 1))
        + '</section>'
    )


def interpretation_html(value: object) -> str:
    if not isinstance(value, dict):
        return f'<p>{esc(value)}</p>'
    verdict = value.get("verdict")
    explanation = value.get("explanation")
    limits = value.get("limits")
    parts = []
    if verdict is not None:
        parts.append(f'<h3>Verdict</h3><p class="verdict">{esc(verdict)}</p>')
    if explanation is not None:
        parts.append(f'<p>{esc(explanation)}</p>')
    if limits is not None:
        parts.append('<h3>Limits</h3>')
        if isinstance(limits, list):
            parts.append('<ul>' + "".join(f'<li>{esc(item)}</li>' for item in limits) + '</ul>')
        else:
            parts.append(f'<pre>{pretty(limits)}</pre>')
    remaining = {key: item for key, item in value.items() if key not in {"verdict", "explanation", "limits"}}
    if remaining:
        parts.append(f'<h3>Other recorded interpretation</h3><pre>{pretty(remaining)}</pre>')
    return "".join(parts) or f'<pre>{pretty(value)}</pre>'


def render(packet: dict) -> str:
    if not isinstance(packet, dict):
        raise ValueError("Packet must be a JSON object")
    for key in ("manifest", "baseline", "crossover", "generality", "granularity", "interpretation"):
        if key not in packet:
            raise ValueError(f"Missing packet field: {key}")
    for key, _ in SECTIONS:
        section = packet[key]
        if not isinstance(section, dict) or not isinstance(section.get("rows"), list):
            raise ValueError(f"{key}.rows must be a list")
        if any(not isinstance(row, dict) for row in section["rows"]):
            raise ValueError(f"{key}.rows entries must be objects")
    for wrapper in packet["granularity"]["rows"]:
        if not isinstance(wrapper.get("full"), dict) or not isinstance(wrapper.get("parsed_content"), dict):
            raise ValueError("granularity rows require full and parsed_content score objects")
        if wrapper.get("carrier_passage") is not None and not isinstance(wrapper["carrier_passage"], dict):
            raise ValueError("granularity carrier_passage must be a score object or null")
    if not isinstance(packet["manifest"], dict):
        raise ValueError("manifest must be an object")
    nav = "".join(f'<a href="#{esc(key)}">{esc(title)}</a>' for key, title in SECTIONS)
    content = "".join(section_html(packet, key, title) for key, title in SECTIONS)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Case R controlled semantic diagnostic</title>'
        '<style>'
        ':root{color-scheme:light;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
        'background:#f6f7f5;color:#172328}*{box-sizing:border-box}body{margin:0}main{max-width:1320px;margin:auto;'
        'padding:32px 24px 80px}header{background:#183a42;color:#fff;padding:42px 24px}header>div{max-width:1320px;'
        'margin:auto}h1{margin:0 0 8px;font-size:2rem}h2{margin:0 0 18px}h3{margin:26px 0 12px}h4{margin:20px 0 8px}'
        'h5{margin:12px 0 8px}p{line-height:1.5}nav{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0 0}'
        'nav a{color:#fff;border:1px solid #8db0b4;border-radius:999px;padding:7px 11px;text-decoration:none}'
        'section{background:#fff;border:1px solid #d9e0e0;border-radius:14px;padding:24px;margin:28px 0;box-shadow:0 2px 12px #17232809}'
        '.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{border-bottom:1px solid #dce4e3;'
        'padding:10px 12px;text-align:left;vertical-align:top}th{background:#edf3f2;white-space:nowrap}tr:hover td{background:#f8fbfa}'
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}pre{background:#f3f6f5;'
        'padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.82rem;line-height:1.5}'
        'details{border:1px solid #dce4e3;border-radius:9px;margin:9px 0;padding:10px 12px}details.best{border-color:#2c7888}'
        'summary{cursor:pointer;font-weight:600}details.pair{padding:15px;margin:14px 0}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}'
        '.two>*{min-width:0}.facts{display:grid;grid-template-columns:max-content 1fr;gap:7px 15px;font-size:.9rem}'
        '.facts dt{font-weight:600}.facts dd{margin:0;overflow-wrap:anywhere}.badge{display:inline-block;font-size:.74rem;'
        'border-radius:999px;padding:2px 7px;white-space:nowrap}.yes{background:#d8f3e5;color:#155d39}.no{background:#fbe5dd;'
        'color:#823926}.unknown{background:#e6e9ef;color:#404b64}.muted,small{color:#526368}a{color:#185d70}'
        '@media(max-width:760px){main{padding:20px 12px 60px}section{padding:16px}.two{grid-template-columns:1fr}'
        '.facts{grid-template-columns:1fr}.facts dd{margin-bottom:8px}}'
        '.verdict{font-size:1.08rem;font-weight:600;border-left:4px solid #2c7888;padding:10px 14px;background:#edf5f4}'
        '</style></head><body><header><div><h1>Case R controlled semantic diagnostic</h1>'
        '<p>Saved full-source inputs, exact-string controls, and independent Tier 3 / Tier 4 scores.</p>'
        f'<nav><a href="#interpretation">Result</a>{nav}<a href="#manifest">Manifest</a></nav>'
        '</div></header><main>'
        + '<section id="interpretation"><h2>Result and limits</h2>'
        + interpretation_html(packet["interpretation"])
        + '</section>'
        + content
        + '<section id="manifest"><h2>Manifest and fixed controls</h2>'
        + f'<pre>{pretty(packet["manifest"])}</pre></section>'
        + '</main></body></html>'
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", nargs="?", type=Path, help="Saved packet.json")
    parser.add_argument("output", nargs="?", type=Path, help="New index.html")
    parser.add_argument("--packet", dest="packet_option", type=Path, help="Saved packet.json")
    parser.add_argument("--output", dest="output_option", type=Path, help="New index.html")
    parser.add_argument("--force", action="store_true", help="Replace an existing derived HTML file")
    args = parser.parse_args()
    packet_path = args.packet_option or args.packet
    output_path = args.output_option or args.output
    if packet_path is None or output_path is None:
        parser.error("packet and output paths are required")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    page = render(packet)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w" if args.force else "x", encoding="utf-8") as stream:
        stream.write(page)


if __name__ == "__main__":
    main()
