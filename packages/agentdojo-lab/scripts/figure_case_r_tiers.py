"""Render the Case R tier-diagnostic figure from a diagnostic packet (packet.json).

Two panels: (a) per-pair Tier-2, Tier-3 and Tier-4 scores on the recipient pairs,
grouped by sent outcome and source role, with the paper thresholds; (b) the
synthetic Tier-2 length sweep, score against target length with the 0.15
threshold. Canonical and diagnostic lanes are labelled. Static SVG, PDF and PNG.
Zero model requests.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

# Palette shared with figure_case_r.py (dataviz reference instance); tier hues validated.
ATTACKER, LEGIT, INK, INK2, GRID = "#d03b3b", "#0ca30c", "#0b0b0b", "#52514e", "#e6e5e1"
TIER = {"tier2": "#256abf", "tier3": "#d97706", "tier4": "#7c3aed"}
ROLE_ORDER = ["both", "value", "instruction", "neither"]
ROLE_LABEL = {"both": "value+instr.", "value": "value", "instruction": "instruction", "neither": "neither"}
MARKER = {"attacker": "o", "legit": "s"}

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 8.5,
        "axes.edgecolor": INK2,
        "axes.labelcolor": INK,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "svg.fonttype": "none",
    }
)


def panel_scores(ax, rows):
    rows = [r for r in rows if r["is_recipient"] and r["role"] is not None and r["join_status"] == "joined"]
    groups = [(outcome, role) for outcome in ("attacker", "legit") for role in ROLE_ORDER]
    groups = [g for g in groups if any(r["recipient_outcome"] == g[0] and r["role"] == g[1] for r in rows)]
    tiers = [
        ("tier2", "Tier 2 LCS (canonical)", lambda r: r["canonical"]["tier2_score"]),
        ("tier3", "Tier 3 cosine (diagnostic)", lambda r: (r["diagnostic"] or {}).get("tier3_score")),
        ("tier4", "Tier 4 best chunk (diagnostic)", lambda r: (r["diagnostic"] or {}).get("tier4_best_score")),
    ]
    width = 0.26
    for gi, (outcome, role) in enumerate(groups):
        members = [r for r in rows if r["recipient_outcome"] == outcome and r["role"] == role]
        for ti, (tier, _, getter) in enumerate(tiers):
            x = gi + (ti - 1) * width
            values = [getter(r) for r in members if getter(r) is not None]
            jitter = [x + (i - (len(values) - 1) / 2) * (width / max(1, len(values)) * 0.8) for i in range(len(values))]
            ax.scatter(
                jitter, values, s=22, marker=MARKER[outcome], facecolor=TIER[tier], edgecolor="white", linewidth=0.6, zorder=3
            )
    ax.axhline(0.15, color=TIER["tier2"], linestyle=(0, (4, 3)), linewidth=1, zorder=2)
    ax.text(-0.45, 0.165, "Tier-2 threshold 0.15", color=TIER["tier2"], ha="left", va="bottom", fontsize=7.5)
    ax.axhline(0.60, color=TIER["tier4"], linestyle=(0, (4, 3)), linewidth=1, zorder=2)
    ax.text(len(groups) - 0.5, 0.615, "Tier-3/4 semantic threshold 0.60", color=TIER["tier4"], ha="right", va="bottom", fontsize=7.5)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels([f"{o}-sent\n{ROLE_LABEL[r]}" for o, r in groups], fontsize=7.5)
    ax.set_ylim(-0.05, 1.08)
    ax.set_ylabel("score")
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.set_title("(a) Recipient pairs: canonical Tier 2 versus independent Tier 3/4, by sent outcome and source role", loc="left", fontsize=9)
    handles = [Line2D([], [], marker="o", linestyle="", color=TIER[t], label=label) for t, label, _ in tiers]
    handles += [
        Line2D([], [], marker="o", linestyle="", color=INK2, label="attacker-sent sink"),
        Line2D([], [], marker="s", linestyle="", color=INK2, label="legit-sent sink"),
    ]
    ax.legend(handles=handles, loc="upper center", fontsize=7.5, frameon=False, ncol=5, bbox_to_anchor=(0.5, -0.16))


def panel_sweep(ax, sweep):
    pairs = [p for p in sweep["pairs"] if not p["truncated_to_sentence"]]
    xs = [p["target_length"] for p in pairs]
    ys = [p["score"] for p in pairs]
    ax.scatter(xs, ys, s=16, facecolor=TIER["tier2"], edgecolor="white", linewidth=0.5, alpha=0.8, zorder=3)
    meds = [(row["nominal_length"], row["median"]) for row in sweep["per_length"] if row["median"] is not None]
    lengths = {row["nominal_length"]: row for row in sweep["per_length"]}
    ax.plot([n for n, _ in meds], [m for _, m in meds], color=INK, linewidth=1.4, zorder=4, label="median per length")
    ax.axhline(0.15, color=ATTACKER, linestyle=(0, (4, 3)), linewidth=1, zorder=2)
    ax.text(max(xs), 0.165, "threshold 0.15", color=ATTACKER, ha="right", va="bottom", fontsize=7.5)
    ax.set_xscale("log")
    ax.set_xticks(sweep["lengths"])
    ax.set_xticklabels([str(n) for n in sweep["lengths"]])
    ax.set_ylim(-0.05, 1.08)
    ax.set_xlabel("target length (code points, prefixes of frozen sentences; log scale)")
    ax.set_ylabel("Tier-2 LCS / min length")
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    counts = ", ".join(f"{n}: {lengths[n]['n']}" for n in sweep["lengths"])
    ax.set_title(
        f"(b) Synthetic Tier-2 sweep against non-containing frozen documents (constructed supplement)\npairs per length {counts}",
        loc="left", fontsize=9,
    )
    ax.legend(loc="lower left", fontsize=7.5, frameon=False)


def render(packet: dict, output: Path, stem: str = "figure-case-r-tiers") -> list[Path]:
    fig, axes = plt.subplots(2, 1, figsize=(9.2, 8.0), gridspec_kw={"height_ratios": [1.35, 1]})
    panel_scores(axes[0], packet["rows"])
    panel_sweep(axes[1], packet["length_synthetic"])
    fig.suptitle(
        "Case R tier ablation (offline; 0 requests): Tier 3/4 evaluated independently on the recorded pairs",
        x=0.01, ha="left", fontsize=10.5, color=INK,
    )
    fig.text(
        0.01, 0.008,
        "Correspondence scores only; none establishes causal influence. Canonical = recorded cascade; diagnostic = recomputed with the pinned MiniLM.\n"
        "Batch groq-case-r-v1 (24 trajectories, 23 sinks, 46 recipient pairs); encoder all-MiniLM-L6-v2 @1110a243; thresholds 0.15 / 0.60 / coverage 0.10.",
        fontsize=7, color=INK2,
    )
    fig.subplots_adjust(left=0.07, right=0.99, top=0.93, bottom=0.1, hspace=0.5)
    output.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext in ("svg", "pdf", "png"):
        path = output / f"{stem}.{ext}"
        fig.savefig(path, dpi=200 if ext == "png" else None, metadata={"Date": None} if ext == "svg" else None)
        paths.append(path)
    plt.close(fig)
    return paths


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    packet = json.loads(args.packet.read_text(encoding="utf-8"))
    written = render(packet, args.output)
    print(json.dumps({"written": [str(p) for p in written]}))
