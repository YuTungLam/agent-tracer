"""Run the frozen, request-free Case R score-and-chunk evidence synthesis v1.

Verifies the protocol digest and every frozen input digest before parsing
any packet, computes the ledger, contrasts, cross-suite view and exploratory
threshold sweep, and fails loudly if any protocol anchor does not reproduce.
On an anchor failure only ``logs/anchor-checks.json`` is written.

Every output (JSON evidence, HTML report, README, manifest and checksums) is
built and scanned in memory before anything is written.  Existing outputs are
never overwritten unless ``--replace`` is given, and then only the runner's
own files are replaced; ``config/question-map.json`` is never written.

The HTML report comes from ``agentdojo_lab.score_chunk_synthesis_html``.
``--render-only`` re-renders ``reports/index.html`` from the saved derived
JSON, anchor log, frozen config and question map without recomputing
anything; it first checks every saved file against ``checksums.sha256`` and
then refreshes only the report, ``manifest.json`` and ``checksums.sha256``.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

from agentdojo_lab import score_chunk_synthesis as synthesis
from agentdojo_lab import score_chunk_synthesis_html as report_html

REQUESTS = {"model": 0, "provider": 0, "network": 0, "encoder": 0}


def _render_only(parser: argparse.ArgumentParser, output: Path, replace: bool) -> int:
    owned = (report_html.REPORT_FILE, report_html.MANIFEST_FILE, report_html.CHECKSUMS_FILE)
    existing = sorted(name for name in owned if (output / name).exists())
    if existing and not replace:
        parser.error(f"refusing to overwrite existing outputs (use --replace): {existing}")
    try:
        files, summary = report_html.render_only_files(output)
    except report_html.ReportInputError as error:
        raise SystemExit(f"Render-only refused: {error}") from error
    question_map = output / synthesis.QUESTION_MAP
    question_map_bytes = question_map.read_bytes() if question_map.is_file() else None
    written = synthesis.write_files(output, files, replace=replace)
    verified = synthesis.verify_written(output, files)
    if question_map_bytes is not None and question_map.read_bytes() != question_map_bytes:
        raise SystemExit("The question map changed during the run")
    print(
        json.dumps(
            {
                "protocol": synthesis.PROTOCOL,
                "mode": "render_only",
                "renderer": report_html.RENDERER_ID,
                "output": f"experiments/{synthesis.EXPERIMENT_ID}",
                "written": written,
                "verified_on_disk": verified,
                **summary,
                "requests": REQUESTS,
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results-root", type=Path, help="agent-tracer-results checkout (required unless --render-only)")
    parser.add_argument("--output", type=Path, required=True, help=f"experiments/{synthesis.EXPERIMENT_ID} directory")
    parser.add_argument("--protocol", type=Path, help="frozen protocol Markdown file (required unless --render-only)")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace this runner's own existing outputs (never the hand-authored question map)",
    )
    parser.add_argument(
        "--render-only",
        action="store_true",
        help=(
            "re-render reports/index.html from the existing derived JSON, anchor log, frozen config and question "
            "map without recomputing; refreshes manifest.json and checksums.sha256 (needs --replace when they exist)"
        ),
    )
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output.name != synthesis.EXPERIMENT_ID:
        parser.error(f"--output must be the {synthesis.EXPERIMENT_ID} experiment directory")
    unexpected = synthesis.unexpected_files(output)
    if unexpected:
        parser.error(f"unexpected files in the experiment directory: {unexpected}")
    if args.render_only:
        if args.results_root is not None and not output.is_relative_to(args.results_root.resolve()):
            parser.error("--output must lie inside --results-root")
        return _render_only(parser, output, args.replace)

    if args.results_root is None or args.protocol is None:
        parser.error("--results-root and --protocol are required unless --render-only is given")
    results_root = args.results_root.resolve()
    if not output.is_relative_to(results_root):
        parser.error("--output must lie inside --results-root")
    existing = sorted(name for name in synthesis.OUTPUT_FILES.values() if (output / name).exists())
    if existing and not args.replace:
        parser.error(f"refusing to overwrite existing outputs (use --replace): {existing}")

    protocol = synthesis.verify_protocol(args.protocol)
    payloads, input_table = synthesis.read_verified_inputs(results_root)
    documents = synthesis.synthesize(payloads, input_table)
    anchors = documents["anchor_checks"]
    if not anchors["all_passed"]:
        text = synthesis.dump_json(anchors).encode("utf-8")
        synthesis.write_files(output, {synthesis.JSON_OUTPUTS["anchor_checks"]: text}, replace=args.replace)
        failed = [check["id"] for check in anchors["checks"] if not check["passed"]]
        raise SystemExit(f"Anchor checks failed: {failed}")

    tests = Path(__file__).resolve().parents[1] / "tests" / "test_score_chunk_synthesis.py"
    code_paths = {
        "module": Path(synthesis.__file__),
        "report_renderer": Path(report_html.__file__),
        "runner": Path(__file__),
    }
    if tests.is_file():
        code_paths["tests"] = tests
    code = synthesis.code_provenance(code_paths)
    documents["frozen_config"] = synthesis.build_frozen_config(
        protocol, args.protocol, input_table, results_root, code, output
    )
    question_map = output / synthesis.QUESTION_MAP
    question_map_bytes = question_map.read_bytes() if question_map.is_file() else None
    created_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = report_html.publication_files(documents, question_map_bytes, created_at)
    written = synthesis.write_files(output, files, replace=args.replace)
    verified = synthesis.verify_written(output, files)
    if question_map_bytes is not None and question_map.read_bytes() != question_map_bytes:
        raise SystemExit("The question map changed during the run")
    print(
        json.dumps(
            {
                "protocol": synthesis.PROTOCOL,
                "mode": "compute_and_render",
                "renderer": report_html.RENDERER_ID,
                "output": f"experiments/{synthesis.EXPERIMENT_ID}",
                "written": written,
                "replaced_existing": existing if args.replace else [],
                "verified_on_disk": verified,
                "anchors_passed": anchors["passed"],
                "anchors_failed": anchors["failed"],
                "ledger_rows": documents["ledger"]["row_count"],
                "requests": REQUESTS,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
