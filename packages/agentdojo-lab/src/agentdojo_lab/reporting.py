"""Export descriptive tables and an observed execution case from saved clean runs.

Figure contract: demonstrate what one recorded execution contains, with a run
table as supporting evidence. Python-only asymmetric composite, 183 mm width,
editable SVG/PDF and 300 dpi PNG. CSV source data accompany every panel. Repeated
runs are not independent tasks; no aggregate performance or causal claim is made.
"""

import csv
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from textwrap import shorten
from uuid import uuid4

from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.report_data import collect_runs, write_csv


def _json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _plotting():
    os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "agentdojo-lab-matplotlib"))
    try:
        import matplotlib
    except ImportError as exc:
        raise ValueError("Install plotting dependencies with: uv sync --locked --extra figures") from exc
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
            "font.size": 7.5,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
            "text.usetex": False,
            "text.parse_math": False,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.linewidth": 0.6,
            "savefig.facecolor": "white",
        }
    )
    return plt


def _save(plt, fig, stem):
    # Keep the declared physical dimensions; inspect the matching PNG visually.
    fig.canvas.draw()
    for extension in ("png", "svg", "pdf"):
        fig.savefig(stem.with_suffix(f".{extension}"), dpi=300, facecolor="white")
    plt.close(fig)


def _number(value, decimals=None):
    if value is None:
        return "—"
    return f"{value:.{decimals}f}" if decimals is not None else f"{value:,}"


def _recording(row):
    if row["recording_complete"] is True:
        return f"{_number(row['event_count'])} events"
    if row["recording_complete"] is False:
        return "Incomplete"
    return "Disabled" if row["recording_enabled"] is False else "No metadata*"


def _task_result(row):
    if row.get("status") != "completed":
        return str(row.get("status") or "Unknown")
    return f"{_number(row['successful_tasks'])}/{_number(row['evaluated_tasks'])}"


def render_tables(plt, rows, out, unique_tasks):
    """Paginate run-level rows; never attribute run-level cost to each task."""
    pages = []
    for start in range(0, len(rows), 12):
        page = rows[start : start + 12]
        fig = plt.figure(figsize=(183 / 25.4, (43 + 7 * len(page)) / 25.4))
        ax = fig.add_axes((0.045, 0.29, 0.91, 0.42))
        ax.axis("off")
        fig.text(0.045, 0.91, "Clean-run observations", weight="bold", fontsize=11)
        fig.text(
            0.045,
            0.81,
            f"{len(rows)} real LLM runs · {unique_tasks} unique evaluated task(s) · descriptive records",
            color="#52616D",
            fontsize=7.5,
        )
        cells = []
        for index, row in enumerate(page, start + 1):
            task_result = _task_result(row)
            cells.append(
                [
                    f"R{index}",
                    str(row["model"] or "Unknown").removeprefix("openai/"),
                    task_result,
                    _number(row["model_requests"]),
                    f"{_number(row['proposed_tool_calls'])}/{_number(row['tool_errors'])}",
                    f"{_number(row['input_tokens'])}/{_number(row['output_tokens'])}",
                    _number(row["elapsed_seconds"], 3),
                    _recording(row),
                ]
            )
        table = ax.table(
            cellText=cells,
            colLabels=[
                "Run",
                "Model",
                "Task result\npassed/evaluated",
                "LLM\nrequests",
                "Tool calls\n/errors",
                "Tokens\ninput/output",
                "Time\n(s)",
                "Event log",
            ],
            colWidths=[0.055, 0.175, 0.16, 0.085, 0.105, 0.155, 0.075, 0.19],
            cellLoc="center",
            bbox=[0, 0, 1, 1],
        )
        table.auto_set_font_size(False)
        table.set_fontsize(6.7)
        for (r, _), cell in table.get_celld().items():
            cell.visible_edges = "horizontal"
            cell.set_edgecolor("#D2D9DF")
            cell.set_linewidth(0.45)
            if r == 0:
                cell.set_text_props(weight="bold", color="#253B4B")
                cell.set_linewidth(0.8)
        fig.text(
            0.045,
            0.17,
            "Costs are per run. Repeated runs of one task are not independent task samples.",
            fontsize=6.7,
        )
        fig.text(
            0.045,
            0.09,
            "* Recording metadata absent. Times are observations, not controlled overhead measurements.",
            fontsize=6.7,
        )
        stem = out / ("table_runs" if start == 0 else f"table_runs_{start // 12 + 1}")
        _save(plt, fig, stem)
        pages.append(stem.name)
    return pages


def _tex(value):
    mapping = {
        "\\": r"\textbackslash{}",
        "_": r"\_",
        "%": r"\%",
        "&": r"\&",
        "#": r"\#",
        "$": r"\$",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(mapping.get(char, char) for char in str(value))


def write_latex(rows, path, unique_tasks):
    lines = [
        "% Requires \\usepackage{booktabs}. Costs are per run; no pooled success estimate.",
        r"\begin{table*}[t]",
        r"\centering",
        r"\small",
        r"\caption{Descriptive clean-run observations: "
        + str(len(rows))
        + " real LLM runs and "
        + str(unique_tasks)
        + r" unique evaluated task(s). Repetitions are not independent task samples.}",
        r"\begin{tabular}{llrrrrrl}",
        r"\toprule",
        r"Run & Model & Passed/evaluated & Requests & Tools/errors & In/out tokens & Time (s) & Event log \\",
        r"\midrule",
    ]
    for i, row in enumerate(rows, 1):
        values = [
            f"R{i}",
            row["model"] if row["model"] is not None else "—",
            _task_result(row),
            _number(row["model_requests"]),
            f"{_number(row['proposed_tool_calls'])}/{_number(row['tool_errors'])}",
            f"{_number(row['input_tokens'])}/{_number(row['output_tokens'])}",
            _number(row["elapsed_seconds"], 3),
            _recording(row),
        ]
        lines.append(" & ".join(_tex(value).replace("—", "--") for value in values) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\par\footnotesize * Recording metadata absent. Times do not estimate tracing overhead.",
            r"\end{table*}",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_records(path, records, fields):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def trace_data(events, episode_id):
    """Prepare chronology and a request-inclusion matrix, not a provenance DAG."""
    events = [event for event in events if event["episode_id"] == episode_id]
    requests = [event for event in events if event["event_type"] == "MODEL_REQUEST"]
    results = [event for event in events if event["event_type"] == "TOOL_RESULT"]
    request_index = {event["model_request_id"]: i + 1 for i, event in enumerate(requests)}
    result_index = {event["call_ref"]: i + 1 for i, event in enumerate(results)}
    proposals = {}
    for event in events:
        if event["event_type"] == "TOOL_CALL_PROPOSED":
            proposals.setdefault(event["model_request_id"], []).append(event["data"])
    nodes = []
    for event in events:
        data = event["data"]
        if event["event_type"] == "MODEL_PARSED":
            number = request_index[event["model_request_id"]]
            calls = proposals.get(event["model_request_id"], [])
            if calls:
                call = calls[0]
                args = call.get("arguments", {})
                hint = (
                    f"date={args['date']}"
                    if "date" in args
                    else f"query={args['query']}"
                    if "query" in args
                    else f"{len(args)} argument(s)"
                )
                detail = f"{call['function']}\n{shorten(hint, width=39, placeholder='…')}"
                title = (
                    f"Request {number} · tool proposal"
                    if len(calls) == 1
                    else f"Request {number} · {len(calls)} proposals (first shown)"
                )
            else:
                detail = "No tool proposals in this response"
                title = f"Request {number} · model response"
            kind = "model"
        elif event["event_type"] == "TOOL_RESULT":
            number = result_index[event["call_ref"]]
            error = data["message"].get("error")
            title = f"Tool result {number} · {'error' if error else 'returned'}"
            detail = (
                shorten(str(error), width=78, placeholder="…")
                if error
                else "Result appended to agent history"
            )
            kind = "tool_error" if error else "tool"
        else:
            continue
        nodes.append(
            {
                "event_id": event["event_id"],
                "event_sequence": event["event_sequence"],
                "kind": kind,
                "title": title,
                "detail": detail,
            }
        )
    included = {
        (e["call_ref"], e["model_request_id"]) for e in events if e["event_type"] == "TOOL_OUTPUT_EXPOSED"
    }
    matrix = [
        {
            "tool_result": i,
            "request": j,
            "included": int((call_ref, request_id) in included),
            "call_ref": call_ref,
            "model_request_id": request_id,
        }
        for call_ref, i in result_index.items()
        for request_id, j in request_index.items()
    ]
    return {"nodes": nodes, "matrix": matrix, "requests": len(requests), "results": len(results)}


def render_trace(plt, data, out, row, task_id):
    from matplotlib.colors import ListedColormap
    from matplotlib.patches import FancyBboxPatch

    nodes = data["nodes"]
    height_mm = max(122, 28 + len(nodes) * 15)
    fig = plt.figure(figsize=(183 / 25.4, height_mm / 25.4))
    fig.text(0.055, 0.94, "A recorded agent execution", fontsize=12, weight="bold")
    fig.text(
        0.055,
        0.895,
        f"{row['model']} · {row['suite']}/{task_id} · one clean episode",
        fontsize=7.5,
        color="#52616D",
    )
    ax = fig.add_axes((0.055, 0.14, 0.575, 0.69))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.text(0.055, 0.85, "a  Execution order", weight="bold", fontsize=8.5)
    box_height = min(0.16, 0.82 / max(1, len(nodes)))
    previous = None
    for index, node in enumerate(nodes):
        y = 0.90 - index * 0.80 / max(1, len(nodes) - 1)
        is_model = node["kind"] == "model"
        x = 0.015 if is_model else 0.31
        width = 0.67
        color = "#EAF2F8" if is_model else "#FFF0DD" if node["kind"] == "tool_error" else "#EFF3F4"
        edge = "#5083A5" if is_model else "#BA8538" if node["kind"] == "tool_error" else "#758892"
        if previous is not None:
            ax.annotate(
                "",
                xy=(x + width / 2, y + box_height / 2),
                xytext=(previous[0], previous[1] - box_height / 2),
                arrowprops={"arrowstyle": "->", "color": "#88949C", "lw": 0.9},
            )
        ax.add_patch(
            FancyBboxPatch(
                (x, y - box_height / 2),
                width,
                box_height,
                boxstyle="round,pad=0.012",
                fc=color,
                ec=edge,
                lw=0.7,
            )
        )
        ax.text(x + 0.025, y + box_height * 0.21, node["title"], fontsize=7, weight="bold", va="center")
        detail = node["detail"]
        if node["kind"] == "tool_error":
            from textwrap import fill

            detail = fill(detail, width=43)
        ax.text(x + 0.025, y - box_height * 0.20, detail, fontsize=6.4, va="center", linespacing=1.25)
        previous = (x + width / 2, y)
    fig.text(0.70, 0.85, "b  Tool output in requests", weight="bold", fontsize=8.5)
    mx = fig.add_axes((0.725, 0.46, 0.225, 0.26))
    matrix = [[0] * data["requests"] for _ in range(data["results"])]
    for cell in data["matrix"]:
        matrix[cell["tool_result"] - 1][cell["request"] - 1] = cell["included"]
    mx.imshow(matrix, cmap=ListedColormap(["#F3F5F7", "#B8D2E5"]), vmin=0, vmax=1, aspect="auto")
    mx.set_xticks(range(data["requests"]), [f"R{i + 1}" for i in range(data["requests"])])
    mx.set_yticks(range(data["results"]), [f"T{i + 1}" for i in range(data["results"])])
    mx.tick_params(length=0, labelsize=7)
    mx.set_xlabel("Model request", fontsize=7)
    for spine in mx.spines.values():
        spine.set_visible(False)
    for i, values in enumerate(matrix):
        for j, value in enumerate(values):
            mx.text(j, i, "yes" if value else "—", ha="center", va="center", fontsize=7.5, color="#263C4B")
    fig.text(
        0.70,
        0.33,
        "T = tool result\nRepeated history can expose\nthe same result more than once.",
        fontsize=7,
        linespacing=1.5,
    )
    fig.text(0.055, 0.075, "Arrows show observed sequence; spacing does not encode duration.", fontsize=7)
    fig.text(
        0.055,
        0.04,
        "Inclusion in an outbound request does not establish model attention, source attribution or causality.",
        fontsize=7,
    )
    _save(plt, fig, out / "figure_trace")


def export_report(runs_dir: Path, output: Path | None = None) -> dict:
    runs_dir = runs_dir.expanduser().resolve()
    collected = collect_runs(runs_dir)
    rows = collected["rows"]
    if not rows:
        raise ValueError("No real clean Groq run summaries found; offline fixtures are excluded.")
    plt = _plotting()
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = runs_dir.parent / "reports" / f"{stamp}-{uuid4().hex[:8]}"
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    write_csv(output / "run_table.csv", rows)
    _json(output / "run_inventory.json", collected["inventory"])
    pages = render_tables(plt, rows, output, collected["unique_tasks"])
    write_latex(rows, output / "table_runs.tex", collected["unique_tasks"])
    report = {
        "output_dir": str(output),
        "real_runs": len(rows),
        "unique_evaluated_tasks": collected["unique_tasks"],
        "table_pages": pages,
        "trace": None,
        "trace_candidates": [],
        "source_hashes": {},
    }
    for row in rows:
        for name in ("manifest.json", "summary.json"):
            path = runs_dir / row["run_id"] / name
            report["source_hashes"][f"{row['run_id']}/{name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    for row in reversed(rows):
        path = runs_dir / row["run_id"] / "events.jsonl"
        if row["recording_complete"] is not True or not path.is_file():
            continue
        audit = inspect_events(path)
        report["trace_candidates"].append({"run_id": row["run_id"], "audit": audit})
        if not audit["valid"]:
            continue
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        episodes = [event for event in events if event["event_type"] == "EPISODE_STARTED"]
        for episode in episodes:
            data = trace_data(events, episode["episode_id"])
            if not data["nodes"] or not data["results"]:
                continue
            render_trace(plt, data, output, row, episode["task_id"])
            _write_records(
                output / "trace_nodes.csv",
                data["nodes"],
                ["event_id", "event_sequence", "kind", "title", "detail"],
            )
            _write_records(
                output / "trace_exposure.csv",
                data["matrix"],
                ["tool_result", "request", "included", "call_ref", "model_request_id"],
            )
            report["trace"] = {
                "run_id": row["run_id"],
                "episode_id": episode["episode_id"],
                "task_id": episode["task_id"],
                "model_requests": data["requests"],
                "tool_results": data["results"],
                "audit_valid": True,
            }
            report["source_hashes"][f"{row['run_id']}/events.jsonl"] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            break
        if report["trace"]:
            break
    notes = (
        "# Figure and table notes\n\n"
        f"Included {len(rows)} real clean runs and {collected['unique_tasks']} unique evaluated tasks. "
        "Offline fixtures are excluded; every considered run and exclusion reason is in run_inventory.json.\n\n"
        "Table 1 | Descriptive clean-run observations. R1, R2, etc. follow run_table.csv row order. "
        "Requests, tokens and wall-clock times are per run. Repeated runs are not independent tasks. "
        "Missing values remain missing. Recorded times do not measure tracing overhead.\n\n"
        "Figure 1 | One observed clean-agent episode. Panel a follows model-response and tool-result event order; "
        "arrows and spacing do not encode causality or duration. Panel b marks tool messages included in actual "
        "outbound model requests. Repeated exposure is not an additional tool execution. "
        "The first episode with tool results in the most recent complete, audited recording is selected.\n\n"
        "No pooled success estimate, ASR, confidence interval, significance test, or attribution-accuracy estimate "
        "is supported by this pilot. Native utility is a task-specific evaluator result.\n\n"
        "Source data: run_table.csv, trace_nodes.csv and trace_exposure.csv when a trace is available. "
        "Source hashes and exact run/episode identity: report.json. "
        "Exports use editable SVG text, embedded TrueType PDF fonts and 300 dpi PNG previews, at 183 mm width.\n"
    )
    (output / "captions.md").write_text(notes, encoding="utf-8")
    _json(output / "report.json", report)
    return report
