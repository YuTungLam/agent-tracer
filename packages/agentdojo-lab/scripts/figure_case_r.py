"""Render the Case R summary figure from a rendered packet (packet.json).

Four panels: (a) construction and native outcomes per repetition, (b) Tier-2 LCS
correspondence for every recipient/source pair against construction truth, (c) how
many sinks the explicit stage let through to the causal layer, (d) forced one-step
counterfactuals versus judge predictions versus trajectory-level arm outcomes.
Static vector output (SVG, PDF) plus PNG. Zero model requests.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import patches  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

# Reference palette (dataviz skill): status colors carry attacker/legit polarity with a
# shape channel as backup; the sequential blue ramp carries magnitude; grays are neutral.
ATTACKER = "#d03b3b"
LEGIT = "#0ca30c"
NONE = "#9a9994"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e6e5e1"
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
ARMS = ["both", "a_only", "b_only", "neither"]
ARM_LABEL = {"both": "A+B", "a_only": "A only", "b_only": "B only", "neither": "neither"}
CONSTRUCTIONS = ["r_redundant", "r_split"]
CON_LABEL = {"r_redundant": "Redundant (address in A and B)", "r_split": "Split (instruction in A, address in B)"}

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 7.5,
        "axes.edgecolor": INK2,
        "axes.linewidth": 0.6,
        "axes.titlesize": 8.5,
        "axes.titleweight": "bold",
        "axes.titlelocation": "left",
        "xtick.color": INK2,
        "ytick.color": INK2,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 6.8,
        "legend.frameon": False,
        "svg.fonttype": "none",
        "pdf.fonttype": 42,
    }
)


def outcome_style(outcome):
    if outcome == "attacker":
        return {"marker": "o", "color": ATTACKER, "fill": ATTACKER}
    if outcome == "legit":
        return {"marker": "o", "color": LEGIT, "fill": "white"}
    return {"marker": "x", "color": NONE, "fill": NONE}


def panel_outcomes(ax, data):
    """(a) construction x arm grid; each cell shows three repetition markers."""
    cells = defaultdict(list)
    for row in data["matrix"]:
        cells[(row["construction"], row["arm"])].append((row["repetition"], row["recipient_outcome"]))
    ax.set_xlim(-0.5, len(ARMS) - 0.5)
    ax.set_ylim(-0.6, len(CONSTRUCTIONS) - 0.4)
    for y, construction in enumerate(CONSTRUCTIONS):
        for x, arm in enumerate(ARMS):
            ax.add_patch(patches.Rectangle((x - 0.46, y - 0.42), 0.92, 0.84, fc="white", ec=GRID, lw=0.6))
            reps = sorted(cells[(construction, arm)])
            for index, (_, outcome) in enumerate(reps):
                style = outcome_style(outcome)
                dx = (index - (len(reps) - 1) / 2) * 0.24
                ax.plot(
                    x + dx, y, marker=style["marker"], ms=6.2, mfc=style["fill"], mec=style["color"],
                    mew=1.2, ls="none", zorder=3,
                )
    ax.set_xticks(range(len(ARMS)))
    ax.set_xticklabels([ARM_LABEL[a] for a in ARMS])
    ax.set_yticks(range(len(CONSTRUCTIONS)))
    ax.set_yticklabels(["Redundant", "Split"])
    ax.invert_yaxis()
    ax.set_xlabel("Payload blocks present", color=INK2)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("(a) Executed recipient, three repetitions per arm")
    handles = [
        Line2D([], [], marker="o", ms=6, mfc=ATTACKER, mec=ATTACKER, ls="none", label="attacker@example.com sent"),
        Line2D([], [], marker="o", ms=6, mfc="white", mec=LEGIT, mew=1.2, ls="none", label="legitimate recipient sent"),
        Line2D([], [], marker="x", ms=6, mec=NONE, mew=1.2, ls="none", label="no email executed"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.3), ncol=1, handletextpad=0.3, labelspacing=0.25)


def panel_lcs(ax, ax_variants, data):
    """(b) Tier-2 LCS score per recipient/source pair, marker fill = carries the sent value."""
    rows = []
    for entry in data["attribution"]:
        construction, rep, arm = entry["slot_id"].split("-")
        for cell in entry["rows"]:
            if cell["argument_path"] != "/recipients/0" or cell["source_file_id"] is None:
                continue
            truth = cell["ground_truth"]
            rows.append(
                {
                    "construction": construction,
                    "arm": arm,
                    "file": cell["source_file_id"],
                    "score": cell["variants"]["baseline"]["score"],
                    "substring": cell["variants"]["substring"]["matched"],
                    "semantic": cell["variants"]["semantic_only"]["matched"],
                    "carries_value": truth.get("carries_value"),
                    "carries_instruction": truth.get("carries_instruction"),
                }
            )
    groups = [(c, a, f) for c in CONSTRUCTIONS for a in ARMS for f in ("1", "2")]
    positions = {g: i for i, g in enumerate(groups)}
    ax.axvspan(0, 0.15, color=GRID, alpha=0.6, lw=0, zorder=0)
    ax.axvline(0.15, color=INK2, lw=0.7, ls=(0, (2, 2)), zorder=1)
    ax.text(0.17, -0.55, "match threshold 0.15", color=INK2, fontsize=6.5, va="center")
    counts = defaultdict(lambda: {"substring": 0, "semantic": 0, "n": 0})
    for row in rows:
        key = (row["construction"], row["arm"], row["file"])
        y = positions[key]
        fill = SEQ[5] if row["carries_value"] else "white"
        ax.plot(row["score"], y, marker="o", ms=5.2, mfc=fill, mec=SEQ[5], mew=1.1, ls="none", zorder=3, alpha=0.9)
        counts[key]["n"] += 1
        counts[key]["substring"] += bool(row["substring"])
        counts[key]["semantic"] += bool(row["semantic"])
    ax.set_yticks(range(len(groups)))
    ax.set_yticklabels([f"{ARM_LABEL[a]}  /  file {f}" for _, a, f in groups])
    ax.axhline(7.5, color=INK2, lw=0.5)
    for label, y_mid in (("Redundant", 3.5), ("Split", 11.5)):
        ax.text(-0.27, y_mid, label, rotation=90, va="center", ha="center", color=INK, fontsize=7.5,
                transform=ax.get_yaxis_transform())
    ax.set_ylim(len(groups) - 0.5, -1.1)
    ax.set_xlim(0, 1.0)
    ax.set_xticks([0, 0.15, 0.5, 1.0])
    ax.set_xlabel("Tier-2 LCS score of the sent recipient against each source", color=INK2)
    ax.grid(axis="x", color=GRID, lw=0.5)
    ax.set_axisbelow(True)
    for name in ("top", "right"):
        ax.spines[name].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("(b) Tier-2 correspondence: every source matches the sent recipient")
    handles = [
        Line2D([], [], marker="o", ms=5, mfc=SEQ[5], mec=SEQ[5], ls="none", label="source carries the sent address"),
        Line2D([], [], marker="o", ms=5, mfc="white", mec=SEQ[5], mew=1.1, ls="none", label="source does not carry it"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, handletextpad=0.3, columnspacing=1.5)
    # Narrow matrix: how many of the three repetitions the stricter variants matched.
    ax_variants.set_xlim(-0.5, 1.5)
    ax_variants.set_ylim(len(groups) - 0.5, -1.1)
    for key, y in positions.items():
        for x, variant in enumerate(("substring", "semantic")):
            k = counts[key][variant]
            n = counts[key]["n"] or 1
            shade = SEQ[0] if k == 0 else SEQ[2] if k < n else SEQ[5]
            ax_variants.add_patch(patches.Rectangle((x - 0.42, y - 0.42), 0.84, 0.84, fc=shade, ec="white", lw=1))
            ax_variants.text(x, y, f"{k}/{n}", ha="center", va="center", fontsize=6, color="white" if k == n else INK)
    ax_variants.axhline(7.5, color=INK2, lw=0.5)
    ax_variants.set_xticks([0, 1])
    ax_variants.set_xticklabels(["substring", "semantic"], rotation=90)
    ax_variants.set_title("matches / reps", fontsize=6, fontweight="normal", loc="center", pad=3)
    ax_variants.set_yticks([])
    for spine in ax_variants.spines.values():
        spine.set_visible(False)
    ax_variants.tick_params(length=0, labelsize=6.5)


def panel_gate(ax, data):
    """(c) How many sinks reach the causal layer under the implemented gate."""
    sinks = [a for a in data["attribution"]]
    total = len(sinks)
    tier2 = sum(1 for a in sinks if any(c["variants"]["baseline"]["matched"] for c in a["rows"]))
    closed = sum(1 for a in sinks if a["eligibility"]["baseline"].startswith("not_eligible"))
    forced = sum(1 for a in sinks if a.get("argument_concordance"))
    labels = [
        "send_email sinks",
        "Tier-2 candidate present",
        "causal gate closed",
        "probes planned by method",
        "probes forced (this study)",
    ]
    values = [total, tier2, closed, 0, forced]
    colors = [SEQ[2], SEQ[3], SEQ[4], NONE, INK2]
    y = list(range(len(labels)))
    ax.barh(y, values, color=colors, height=0.62, zorder=2)
    for yi, value in zip(y, values):
        ax.text(value + 0.4, yi, str(value), va="center", ha="left", color=INK, fontsize=7.5)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, total + 4)
    ax.set_xticks([])
    for name in ("top", "right", "bottom"):
        ax.spines[name].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("(c) Causal-layer reach")


def panel_counterfactual(ax, data):
    """(d) removal outcome: trajectory arm vs forced one-step replay vs judge, per sink."""
    sinks = [a for a in data["attribution"] if a.get("argument_concordance")]
    sinks.sort(key=lambda a: (a["slot_id"].split("-")[0], a["slot_id"].split("-")[1]))
    arm_outcome = {(r["construction"], r["repetition"], r["arm"]): r["recipient_outcome"] for r in data["matrix"]}
    removals = [("1",), ("2",), ("1", "2")]
    removal_label = {("1",): "remove A", ("2",): "remove B", ("1", "2"): "remove both"}
    arm_for_removal = {("1",): "b_only", ("2",): "a_only", ("1", "2"): "neither"}
    columns = ["trajectory", "replay", "judge"]
    col_label = {"trajectory": "whole-trajectory arm", "replay": "forced one-step replay", "judge": "no-tools judge"}
    n_rows = len(sinks) * len(removals)
    ax.set_xlim(-0.6, len(columns) - 0.4)
    ax.set_ylim(n_rows - 0.5, -0.5)
    y = 0
    ylabels = []
    for sink in sinks:
        construction, rep, _ = sink["slot_id"].split("-")
        rep_number = int(rep[1:])
        typed = sink["argument_concordance"]
        by_removed = {tuple(r["removed_files"]): r for r in typed["rows"]}
        for removal in removals:
            row = by_removed.get(removal)
            traj = arm_outcome.get((construction, rep_number, arm_for_removal[removal]))
            traj_call = traj == "attacker" if traj in ("attacker", "legit") else None
            replay_call = row["attacker_recipient_persisted"] if row else None
            judge_call = row["judge_would_call_anyway"] if row else None
            values = {"trajectory": traj_call, "replay": replay_call, "judge": judge_call}
            for x, column in enumerate(columns):
                value = values[column]
                if value is True:
                    ax.add_patch(patches.Rectangle((x - 0.42, y - 0.4), 0.84, 0.8, fc=ATTACKER, ec="white", lw=1))
                elif value is False:
                    ax.add_patch(patches.Rectangle((x - 0.42, y - 0.4), 0.84, 0.8, fc="white", ec=LEGIT, lw=1.1))
                else:
                    ax.add_patch(patches.Rectangle((x - 0.42, y - 0.4), 0.84, 0.8, fc=GRID, ec="white", lw=1))
            if row and row["agreement"] is False:
                ax.text(len(columns) - 0.35, y, "x", ha="left", va="center", color=ATTACKER, fontsize=8, fontweight="bold")
            ylabels.append(f"{'Red.' if construction == 'r_redundant' else 'Split'} r{rep_number}  {removal_label[removal]}")
            y += 1
        ax.axhline(y - 0.5, color=INK2, lw=0.5)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(ylabels)
    ax.set_xticks(range(len(columns)))
    ax.set_xticklabels([col_label[c] for c in columns])
    ax.xaxis.tick_top()
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("(d) Does removing a source stop the attacker send? Three answers per sink", pad=18)
    handles = [
        patches.Patch(fc=ATTACKER, ec="white", label="attacker send persists"),
        patches.Patch(fc="white", ec=LEGIT, label="attacker send stops"),
        patches.Patch(fc=GRID, ec="white", label="unknown"),
        Line2D([], [], marker="$x$", ms=6, mec=ATTACKER, mfc=ATTACKER, ls="none", label="judge disagrees with replay"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=2, handletextpad=0.4, columnspacing=1.0)


def render(packet: Path, output: Path):
    data = json.loads(packet.read_text(encoding="utf-8"))
    fig = plt.figure(figsize=(7.2, 9.0), dpi=150)
    outer = fig.add_gridspec(3, 1, height_ratios=[1.0, 1.75, 2.0], hspace=0.5, left=0.2, right=0.975, top=0.965, bottom=0.045)
    top = outer[0].subgridspec(1, 2, width_ratios=[1.0, 1.0], wspace=1.05)
    middle = outer[1].subgridspec(1, 2, width_ratios=[1.0, 0.16], wspace=0.08)
    ax_a = fig.add_subplot(top[0, 0])
    ax_c = fig.add_subplot(top[0, 1])
    ax_b = fig.add_subplot(middle[0, 0])
    ax_b2 = fig.add_subplot(middle[0, 1])
    ax_d = fig.add_subplot(outer[2])
    panel_outcomes(ax_a, data)
    panel_gate(ax_c, data)
    panel_lcs(ax_b, ax_b2, data)
    panel_counterfactual(ax_d, data)
    output.parent.mkdir(parents=True, exist_ok=True)
    written = []
    for suffix in ("svg", "pdf", "png"):
        target = output.with_suffix("." + suffix)
        fig.savefig(target, dpi=300 if suffix == "png" else None, facecolor="white")
        written.append(str(target))
    plt.close(fig)
    return written


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path, help="packet.json from report_case_r.py")
    parser.add_argument("--output", required=True, type=Path, help="output path without extension")
    args = parser.parse_args()
    print(json.dumps({"written": render(args.packet, args.output)}))
