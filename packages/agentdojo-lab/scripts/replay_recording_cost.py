"""Paired offline replays of saved clean responses; never makes live model calls.

This is an engineering control for recording, not an additional model evaluation.
The native tools execute against freshly loaded AgentDojo simulation environments.
"""

import argparse
import csv
import datetime
import hashlib
import json
import statistics
import time
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.benchmark import benchmark_suite_without_injections
from agentdojo.default_suites.v1.tools import email_client
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.inspection import inspect_events
from agentdojo_lab.observation import ObservationSession
from agentdojo_lab.pilot import atomic_json, digest
from agentdojo_lab.recording import EventRecorder, _json_dump
from agentdojo_lab.runner import RunConfig, build_pipeline, require_upstream


class FixedEmailClock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        # Calendar writes send notification emails with wall-clock timestamps.
        # Control that exogenous value equally in both offline conditions only.
        fixed = cls(2024, 1, 1, tzinfo=datetime.timezone.utc)
        return fixed.astimezone(tz) if tz is not None else fixed.replace(tzinfo=None)


class Capture(BasePipelineElement):
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.name = pipeline.name
        self.states = []

    def query(self, *args, **kwargs):
        result = self.pipeline.query(*args, **kwargs)
        self.states.append(json.loads(_json_dump({"environment": result[2], "messages": result[3]})))
        return result


def load_tape(run: Path):
    manifest = json.loads((run / "manifest.json").read_text())
    summary = json.loads((run / "summary.json").read_text())
    config = RunConfig.model_validate(manifest["config"])
    if manifest.get("attack", "missing") is not None or manifest.get("defense", "missing") is not None:
        raise ValueError("Only clean, undefended source recordings are supported")
    if len(config.user_tasks) != 1 or summary.get("recording", {}).get("complete") is not True:
        raise ValueError("Source must have one task and a complete recording")
    if not inspect_events(run / "events.jsonl")["valid"]:
        raise ValueError("Source event audit failed")
    events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
    requests = [event for event in events if event["event_type"] == "MODEL_REQUEST"]
    responses = {
        event["model_request_id"]: event for event in events if event["event_type"] == "MODEL_RESPONSE"
    }
    tape = []
    for request in requests:
        response = responses.get(request["model_request_id"])
        if response is None or response["data"].get("status_code") != 200:
            raise ValueError("Replay requires a completed HTTP 200 response for every source request")
        tape.append((request["data"]["body"], response["data"]["body"]))
    return config, tape


def replay_once(config: RunConfig, tape: list, output: Path, recorded: bool) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    cursor = 0
    request_hashes = []

    def handler(request):
        nonlocal cursor
        body = json.loads(request.content)
        if cursor >= len(tape) or body != tape[cursor][0]:
            raise ValueError("Replay diverged from the saved outbound request")
        request_hashes.append(hashlib.sha256(_json_dump(body).encode()).hexdigest())
        response = tape[cursor][1]
        cursor += 1
        return httpx.Response(200, json=response)

    recorder = EventRecorder(output / "events.jsonl", output.name) if recorded else None
    observer = ObservationSession(recorder) if recorder else None
    if recorder:
        recorder.emit("RUN_STARTED", {"mode": "offline-response-replay"})
    outcome = "failed"
    try:
        with openai.OpenAI(
            api_key="offline-replay-fixture",
            base_url="https://replay.invalid/openai/v1",
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        ) as client:
            if observer:
                observer.attach(client)
            llm = GroqLLM(
                client,
                config.model,
                temperature=config.temperature,
                max_completion_tokens=config.max_completion_tokens,
                reasoning_effort=config.reasoning_effort,
                observer=observer,
            )
            llm.name = "offline_response_replay"
            pipeline = Capture(build_pipeline(llm, config, observer))
            suite = get_suite(config.benchmark_version, config.suite)
            with (output / "console.log").open("w") as console, redirect_stdout(console):
                fixed_clock = SimpleNamespace(**{**vars(datetime), "datetime": FixedEmailClock})
                with (
                    OutputLogger(str(output / "native")),
                    patch.object(email_client, "datetime", fixed_clock),
                ):
                    start = time.perf_counter_ns()
                    results = benchmark_suite_without_injections(
                        pipeline,
                        suite,
                        logdir=output / "native",
                        force_rerun=False,
                        user_tasks=config.user_tasks,
                        benchmark_version=config.benchmark_version,
                    )
                    elapsed_ns = time.perf_counter_ns() - start
        if cursor != len(tape) or not pipeline.states:
            raise ValueError("Replay did not consume the full source tape")
        state_hash = hashlib.sha256(_json_dump(pipeline.states).encode()).hexdigest()
        utility = list(results["utility_results"].values())
        outcome = "completed"
    finally:
        if recorder:
            recorder.emit("RUN_END", {"status": outcome})
            recorder.close()
    audit = inspect_events(output / "events.jsonl") if recorder else None
    result = {
        "mode": "offline-response-replay",
        "real_llm": False,
        "recorded": recorded,
        "elapsed_ms": elapsed_ns / 1e6,
        "request_hashes": request_hashes,
        "episode_state_hash": state_hash,
        "utility": utility,
        "recording_valid": audit["valid"] if audit else None,
        "log_bytes": (output / "events.jsonl").stat().st_size if recorder else 0,
    }
    atomic_json(output / "replay.json", result)
    return result


def run_study(runs: list[Path], output: Path, pairs: int = 5) -> dict:
    if not 2 <= pairs <= 30:
        raise ValueError("Use 2 to 30 paired repetitions")
    upstream = require_upstream()
    tapes = [(path, *load_tape(path)) for path in runs]
    output.mkdir(parents=True, exist_ok=False)
    atomic_json(
        output / "plan.json",
        {
            "mode": "offline-response-replay",
            "real_llm": False,
            "pairs_per_source": pairs,
            "warmup_pairs_per_source": 1,
            "order": "alternating off/on and on/off",
            "upstream": upstream,
            "script_sha256": digest(Path(__file__)),
            "sources": [
                {"run": str(path.resolve()), "events_sha256": digest(path / "events.jsonl")} for path in runs
            ],
            "timing": "native benchmark execution including observer hot path and common end-state capture; excludes client/pipeline setup, recorder opening/closing, audit, HTML, network and pacing",
            "clock_control": "email_client.datetime.now fixed to 2024-01-01 in both offline conditions; timers and live agent runs unchanged",
        },
    )
    rows = []
    for source_index, (source, config, tape) in enumerate(tapes):
        for pair in range(pairs + 1):
            order = [False, True] if pair % 2 == 0 else [True, False]
            measured = {}
            for enabled in order:
                destination = (
                    output / "replays" / f"s{source_index:02d}-p{pair:02d}-{'on' if enabled else 'off'}"
                )
                measured[enabled] = replay_once(config, tape, destination, enabled)
            off, on = measured[False], measured[True]
            matches = all(off[key] == on[key] for key in ("request_hashes", "episode_state_hash", "utility"))
            if not matches or on["recording_valid"] is not True:
                raise ValueError(
                    "Paired replay equality or event audit failed; preserve this study for diagnosis"
                )
            if pair:
                rows.append(
                    {
                        "source_run": source.name,
                        "task_id": config.user_tasks[0],
                        "pair": pair,
                        "order": "off-on" if order[0] is False else "on-off",
                        "off_ms": off["elapsed_ms"],
                        "on_ms": on["elapsed_ms"],
                        "delta_ms": on["elapsed_ms"] - off["elapsed_ms"],
                        "matched": matches,
                        "recorded_log_bytes": on["log_bytes"],
                    }
                )
    summaries = []
    for source, config, _ in tapes:
        group = [row for row in rows if row["source_run"] == source.name]
        summaries.append(
            {
                "source_run": source.name,
                "task_id": config.user_tasks[0],
                "pairs": len(group),
                "median_off_ms": statistics.median(r["off_ms"] for r in group),
                "median_on_ms": statistics.median(r["on_ms"] for r in group),
                "median_paired_delta_ms": statistics.median(r["delta_ms"] for r in group),
                "all_matched": all(r["matched"] for r in group),
            }
        )
    result = {"mode": "offline-response-replay", "real_llm": False, "rows": rows, "summary": summaries}
    atomic_json(output / "results.json", result)
    with (output / "pairs.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=5)
    args = parser.parse_args()
    result = run_study(args.run, args.output, args.pairs)
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
