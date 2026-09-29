"""Export the new phase overview from retained evidence, without model calls."""

import argparse
import hashlib
import html
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def export(output):
    inputs = {
        "progress": ROOT / "METHOD_COMPLETION_PROGRESS.json",
        "reference": ROOT / "reports/20260910-reference-controls-v1/summary.json",
        "memory": ROOT / "runs/20260910-memory-pair-live-v1/summary.json",
        "validation": ROOT / "reports/20260910-method-completion-validation-v1/quality.json",
    }
    values = {key: read(path) for key, path in inputs.items()}
    progress, reference, memory = (values[key] for key in ("progress", "reference", "memory"))
    accepted = sum(m["status"] == "accepted" for m in progress["milestones"])
    output.mkdir(parents=True, exist_ok=False)

    def link(path, label):
        return f'<a href="{html.escape(os.path.relpath(path, output), quote=True)}">{html.escape(label)}</a>'

    milestone_rows = "".join(
        f'<details><summary>{i}. {html.escape(m["title"])} — {html.escape(m["status"])}</summary>'
        + '<ul>' + ''.join(f'<li>{link(ROOT / p, Path(p).name)}</li>' for p in m["evidence"])
        + '</ul></details>' for i, m in enumerate(progress["milestones"], 1)
    )
    reference_rows = []
    for profile, group in reference["profiles"].items():
        for method in ("exact", "lcs", "cascade", "direct_tier3", "direct_tier4"):
            counts = group["measurements"][method]
            reference_rows.append('<tr><td>' + html.escape(profile) + '</td><td>' + html.escape(method)
                                  + '</td>' + ''.join(f'<td>{counts[key]}</td>' for key in
                                                       ("tp", "fp", "fn", "tn", "unknown_pairs")) + '</tr>')
    memory_link = link(ROOT / "runs/20260910-memory-pair-live-v1/index.html", "Open four session timelines")
    ref_link = link(ROOT / "reports/20260910-reference-controls-v1/index.html", "Inspect reference cases and evidence")
    ordinary = reference["profiles"]["ordinary"]["measurements"]["cascade"]
    document = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NeuroTaint method completion</title>
<style>
body{{font:16px system-ui;line-height:1.55;max-width:960px;margin:32px auto;padding:0 20px;background:#fafafa;color:#202124}}
h1{{font-size:1.7rem;line-height:1.25}}h2{{font-size:1.2rem}}progress{{width:100%;height:18px;accent-color:#2767b2}}
details{{margin:14px 0}}summary{{cursor:pointer;padding:6px 0}}a{{color:#205da3}}li{{overflow-wrap:anywhere}}
table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{text-align:left;padding:7px;border-bottom:1px solid #bbb}}
.scroll{{overflow:auto}}.muted{{color:#54585e}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
@media(prefers-color-scheme:dark){{body{{background:#17191c;color:#eceef2}}.muted{{color:#b5bdc8}}a{{color:#a0c7ff}}}}
</style>
<h1>NeuroTaint method completion</h1>
<p><strong>{accepted} / {len(progress["milestones"])} scoped deliverables accepted</strong> · September 10, 2026</p>
<progress value="{accepted}" max="{len(progress["milestones"])}" aria-label="Accepted scoped deliverables"></progress>
<p class="muted">The bar counts this phase's deliverables. It does not measure time remaining or full-paper reproduction.</p>
<h2>What changed</h2>
<ul><li>Four fixed threshold profiles, with explicit runtime selection.</li>
<li>A separate passive / argument-free causal protocol and bounded joint-source probes.</li>
<li>{reference["recorded_slots"]} / {reference["planned_slots"]} local reference evaluations with actual pinned MiniLM.</li>
<li>{memory["completed_sessions"]} / 4 real Groq sessions; {memory["reported_primary_requests"]} requests and {memory["reported_primary_tokens"]:,} reported tokens.</li></ul>
<h2>Two results to inspect</h2>
<p><strong>Cross-session restoration worked in the copy pilot.</strong> The original reference reached the new file in Session B,
and its matched lineage returned to Session A. The neutralized branch had no reference marker. {memory_link}</p>
<p><strong>LCS also selected unused sources in the constructed controls.</strong> Ordinary cascade: {ordinary["tp"]} positive relations detected;
{ordinary["fp"]} of {ordinary["fp"] + ordinary["tn"]} negative relations selected. These are known program-origin controls, not real-agent false-positive estimates. {ref_link}</p>
<details><summary>Implementation evidence</summary>{milestone_rows}</details>
<details><summary>Controlled reference comparison</summary><p>21 source-pair references per profile, from 18 fixed cases.
Three references remain unknown. Repeated profiles are not independent cases.</p><div class="scroll"><table>
<tr><th>Profile</th><th>Method</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Unknown</th></tr>{''.join(reference_rows)}</table></div></details>
<details><summary>What is still unvalidated</summary><ul>
<li>Independent real-agent semantic attribution and malicious-propagation accuracy.</li>
<li>Real-model joint causal accuracy; self-reported judgments are not causal ground truth.</li>
<li>General memory backends, unseen tools/attacks and original benchmark result tables.</li>
</ul><p>The September 9 closeout and its independent-evaluation gate remain unchanged.</p></details>
<details><summary>Validation receipt</summary><pre>{html.escape(json.dumps(values["validation"], indent=2))}</pre></details>
</html>'''
    (output / "index.html").write_text(document)
    (output / "summary.json").write_text(json.dumps(values, indent=2, ensure_ascii=False) + "\n")
    manifest = {"inputs": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in inputs.values()},
                "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in output.iterdir() if p.is_file()}, "model_requests": 0}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {"accepted": accepted, "total": len(progress["milestones"]), "report": str(output / "index.html")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.output.resolve())))
