"""Write the frozen, zero-request Tier-2 synthetic scaling packet."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path

from agentdojo_lab import tier2_short_target as diagnostic

ROOT = Path(__file__).resolve().parents[1]
COLORS = {256: "#167a70", 768: "#bd6820", 2048: "#683eaa"}


def escape(value) -> str:
    return html.escape(str(value), quote=True)


def percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def rate_with_interval(rate: float, interval: list[float]) -> str:
    return f"{percent(rate)} <small>[{percent(interval[0])}, {percent(interval[1])}]</small>"


def fpr_plot(cells: list[dict], alphabet_id: str, metric: str) -> str:
    local = [cell for cell in cells if cell["alphabet"] == alphabet_id]
    lengths = sorted({cell["target_length"] for cell in local})
    sources = sorted({cell["source_length"] for cell in local})
    left, top, width, height = 56, 18, 520, 198
    pieces = [
        '<svg viewBox="0 0 610 270" role="img" '
        f'aria-label="{escape(metric)} by target length for {escape(alphabet_id)}">',
        '<rect width="610" height="270" fill="white"/>',
    ]
    for fraction in (0, 0.25, 0.5, 0.75, 1):
        y = top + height * (1 - fraction)
        pieces.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + width}" y2="{y:.1f}" stroke="#e1e7ea"/>')
        pieces.append(f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end">{fraction:.2f}</text>')
    for index, target_length in enumerate(lengths):
        x = left + index * width / (len(lengths) - 1)
        pieces.append(f'<text x="{x:.1f}" y="{top + height + 23}" text-anchor="middle">{target_length}</text>')
    pieces.append(f'<text x="{left + width / 2}" y="{top + height + 46}" text-anchor="middle">Target length (code points)</text>')
    for source_length in sources:
        group = sorted((cell for cell in local if cell["source_length"] == source_length), key=lambda c: c["target_length"])
        color = COLORS[source_length]
        points = [
            (left + index * width / (len(lengths) - 1), top + height * (1 - cell[metric]))
            for index, cell in enumerate(group)
        ]
        encoded = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        pieces.append(f'<polyline points="{encoded}" fill="none" stroke="{color}" stroke-width="2.7"/>')
        for x, y in points:
            pieces.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{color}"/>')
    pieces.append("</svg>")
    return "".join(pieces)


def render_html(packet: dict) -> str:
    cells = packet["cells"]
    alphabets = packet["plan"]["alphabets"]
    overall_fp = sum(c["fp"] for c in cells)
    independent_fp = sum(c["independent_fp"] for c in cells)
    overall_neg = sum(c["n_negative"] for c in cells)
    overall_tp = sum(c["tp"] for c in cells)
    overall_pos = sum(c["n_positive"] for c in cells)
    low_cells = sorted(cells, key=lambda c: (c["fpr"], c["source_length"], c["target_length"]))
    lowest = low_cells[0]
    independent_lowest = min(cells, key=lambda c: (c["independent_fpr"], c["source_length"], c["target_length"]))
    pooled_rows = "".join(
        "<tr>"
        f"<td>{item['target_length']}</td>"
        f"<td>{item['n_per_label']}</td>"
        f"<td>{percent(item['tpr'])}</td>"
        f"<td>{percent(item['fpr'])}</td>"
        f"<td>{percent(item['independent_fpr'])}</td>"
        f"<td>{item['negative_distribution']['median']:.3f}</td>"
        f"<td>{item['independent_negative_distribution']['median']:.3f}</td>"
        "</tr>"
        for item in packet["by_target_length"]
    )
    sections = []
    for alphabet_id, alphabet in alphabets.items():
        local = [cell for cell in cells if cell["alphabet"] == alphabet_id]
        body = "".join(
            "<tr>"
            f"<td>{cell['source_length']}</td>"
            f"<td>{cell['target_length']}</td>"
            f"<td>{cell['source_target_ratio']:.1f}</td>"
            f"<td>{rate_with_interval(cell['tpr'], cell['tpr_wilson_95'])}</td>"
            f"<td>{rate_with_interval(cell['fpr'], cell['fpr_wilson_95'])}</td>"
            f"<td>{rate_with_interval(cell['independent_fpr'], cell['independent_fpr_wilson_95'])}</td>"
            f"<td>{cell['negative_distribution']['p05']:.3f}</td>"
            f"<td>{cell['negative_distribution']['median']:.3f}</td>"
            f"<td>{cell['negative_distribution']['p95']:.3f}</td>"
            f"<td>{cell['independent_negative_distribution']['p05']:.3f}</td>"
            f"<td>{cell['independent_negative_distribution']['median']:.3f}</td>"
            f"<td>{cell['independent_negative_distribution']['p95']:.3f}</td>"
            "</tr>"
            for cell in local
        )
        sections.append(
            f'<section id="{escape(alphabet_id)}"><h2>{escape(alphabet_id)}</h2>'
            f'<p>Uniform draws from {len(alphabet)} distinct code points. Three source lengths; '
            '128 target triples per cell.</p>'
            '<div class="plotgrid"><figure><h3>Histogram-matched shuffle FPR</h3>'
            f'{fpr_plot(cells, alphabet_id, "fpr")}</figure>'
            '<figure><h3>Independent uniform draw FPR</h3>'
            f'{fpr_plot(cells, alphabet_id, "independent_fpr")}</figure></div>'
            '<p class="legend"><span class="s256">● 256</span> &nbsp; '
            '<span class="s768">● 768</span> &nbsp; '
            '<span class="s2048">● 2048</span> source code points</p>'
            '<div class="tablewrap"><table><thead><tr><th>Source</th><th>Target</th><th>Ratio</th>'
            '<th>TPR, 95% Wilson</th><th>Shuffle FPR, 95% Wilson</th><th>Independent FPR, 95% Wilson</th>'
            '<th>Shuffle p05</th><th>Median</th><th>p95</th>'
            '<th>Independent p05</th><th>Median</th><th>p95</th>'
            f'</tr></thead><tbody>{body}</tbody></table></div></section>'
        )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in packet["limitations"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tier-2 short-target scaling | {diagnostic.PROTOCOL}</title>
<style>
:root{{--ink:#193044;--muted:#536879;--line:#dce5e9;--paper:#f6f8f9;--navy:#173c58}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}
header{{background:var(--navy);color:white;padding:2.3rem max(24px,calc((100vw - 1150px)/2))}}
header h1{{margin:.2rem 0;font-size:2.2rem}} header p{{max-width:900px;opacity:.9}}
main{{max-width:1150px;margin:auto;padding:24px}} section{{background:white;border:1px solid var(--line);border-radius:12px;padding:22px;margin:0 0 24px}}
h2{{margin:.1rem 0 12px}} p{{margin:8px 0 16px}} .lede{{font-size:1.05rem}} .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 24px}}
.card{{background:white;border:1px solid var(--line);border-radius:12px;padding:17px}} .card strong{{display:block;font-size:1.8rem;color:var(--navy)}}
.card span,small{{color:var(--muted)}} .tablewrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}}
th,td{{padding:8px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}} th:first-child,td:first-child{{text-align:left}}
th{{background:#edf3f5}} tr:hover td{{background:#f4f8f9}} svg{{max-width:100%;height:auto;font-size:12px;fill:var(--muted)}}
.legend{{text-align:center;margin:-8px 0 17px}} .s256{{color:#167a70}} .s768{{color:#bd6820}} .s2048{{color:#683eaa}}
.plotgrid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}} figure{{margin:0}} figure h3{{font-size:1rem;text-align:center;margin:5px 0}}
code{{background:#eef3f5;padding:2px 5px;border-radius:4px}} a{{color:#165f87}} .note{{border-left:4px solid #bd6820;padding:10px 14px;background:#fff8ec}}
@media(max-width:750px){{.cards{{grid-template-columns:repeat(2,1fr)}}.plotgrid{{grid-template-columns:1fr}}header{{padding:24px}}section{{padding:15px}}}}
</style></head><body>
<header><p>OFFLINE SYNTHETIC DIAGNOSTIC · 0 MODEL REQUESTS · {escape(diagnostic.PROTOCOL)}</p>
<h1>Tier-2 short-target scaling</h1>
<p>Exact subsequence LCS divided by the shorter string length, as implemented in the local NeuroTaint reproduction. A match is score ≥ 0.15. The construction tests correspondence against literal containment, not source influence.</p></header>
<main><div class="cards">
<div class="card"><strong>{packet['total_pairs']:,}</strong><span>target triples</span></div>
<div class="card"><strong>{percent(overall_tp/overall_pos)}</strong><span>positive match rate</span></div>
<div class="card"><strong>{percent(overall_fp/overall_neg)}</strong><span>shuffle false-positive rate</span></div>
<div class="card"><strong>{percent(independent_fp/overall_neg)}</strong><span>independent false-positive rate</span></div></div>
<section><h2>What was controlled</h2>
<p class="lede">For each random target, an exact copy is inserted into a positive source. One negative source shuffles the same characters, preserving the exact character histogram. A second negative source is drawn independently from the same uniform alphabet, preserving the source length and generating distribution without conditioning on the target's characters. Neither negative contains the target contiguously.</p>
<p>Target lengths: 5, 10, 20, 40, 80, 160 code points. Source lengths: 256, 768, 2048. Character sets: 26 lowercase letters, 62 alphanumeric characters, and 256 extended Latin code points. There are 128 independent target triples per cell, seeded with {packet['plan']['seed']}.</p>
<p class="note">A negative match is a <em>literal-containment false positive</em> under this constructed label. It is not a measured false attribution in an agent execution. The lowest shuffled-cell FPR is {percent(lowest['fpr'])}; the lowest independent-cell FPR is {percent(independent_lowest['independent_fpr'])} ({escape(independent_lowest['alphabet'])}, source {independent_lowest['source_length']}, target {independent_lowest['target_length']}). The two controls test different source-composition assumptions.</p>
<p><a href="packet.json">Download all {packet['total_pairs']:,} triple records and exact scores</a>.</p></section>
<section><h2>By target length, pooled descriptively</h2>
<p>Each row pools nine source-length × alphabet cells. The cell tables below retain the controlled comparisons and nominal 95% Wilson intervals; pooled values are descriptive mixtures.</p>
<div class="tablewrap"><table><thead><tr><th>Target</th><th>Triples</th><th>TPR</th><th>Shuffle FPR</th><th>Independent FPR</th><th>Shuffle median</th><th>Independent median</th></tr></thead><tbody>{pooled_rows}</tbody></table></div></section>
{''.join(sections)}
<section><h2>Interpretation boundaries</h2><ul>{limitations}</ul>
<p>Every positive score is 1.0 by construction, so TPR is a manipulation check. The two negative distributions and FPRs show how much the result depends on target-conditioned character counts versus an independent source. The 95% intervals quantify repetition under this synthetic generator only.</p>
<p>Reproduce with <code>.venv/bin/python scripts/report_tier2_short_target.py --output reports/20260923-tier2-short-target-scaling-v1</code>. The script refuses to overwrite an existing directory.</p></section></main></body></html>"""


def write_report(output: Path) -> dict:
    output = Path(output)
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    packet = diagnostic.run_experiment()
    packet["lexical_sha256"] = hashlib.sha256((ROOT / "src/agentdojo_lab/lexical.py").read_bytes()).hexdigest()
    packet["generator_sha256"] = hashlib.sha256((ROOT / "src/agentdojo_lab/tier2_short_target.py").read_bytes()).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    (output / "packet.json").write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "index.html").write_text(render_html(packet), encoding="utf-8")
    return packet


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packet = write_report(args.output)
    print(json.dumps({"protocol": packet["protocol"], "output": str(args.output), "pairs": packet["total_pairs"], "requests": 0}))


if __name__ == "__main__":
    main()
