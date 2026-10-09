#!/usr/bin/env python
"""Count saved A1 G1 outcomes and assistant-only diagnostic phrases, offline.

This script reads existing JSONL/transcripts. It never invokes a model or copies
transcript text into its output. The input config is frozen in the results repo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_HASH = re.compile(r"[0-9a-f]{40}\Z")
MAX_JSON_BYTES = 64 * 1024 * 1024


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a short ASCII identifier")
    return value


def _relative_file(root: Path, value: Any, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("source path must be a nonempty, POSIX-style relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("source path must not be absolute or traverse directories")
    if not path.parts or path.parts[0] != "experiments":
        raise ValueError("source path must be inside experiments/")
    resolved = (root / Path(*path.parts)).resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("source path escapes the results checkout")
    if directory and not resolved.is_dir():
        raise ValueError("source directory is not a directory")
    if not directory and not resolved.is_file():
        raise ValueError("source file is not a file")
    return resolved


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_BYTES} bytes: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _transcript_path(directory: Path, name: Any) -> Path:
    _require_id(name, "transcript_path")
    if not name.endswith(".json"):
        raise ValueError("transcript_path must end in .json")
    resolved = (directory / name).resolve(strict=True)
    if not resolved.is_relative_to(directory) or not resolved.is_file():
        raise ValueError("transcript_path escapes its declared directory")
    return resolved


def _new_counts() -> dict[str, int]:
    return {
        "rows": 0,
        "legitimate_episodes": 0,
        "no_call_episodes": 0,
        "x_sink_called_episodes": 0,
        "x_sink_calls": 0,
        "a1_rows": 0,
        "a1_registered_exposure_episodes": 0,
        "ss_rows": 0,
    }


def _add_episode(counts: dict[str, int], episode: dict[str, Any]) -> None:
    outcome = episode.get("outcome")
    if not isinstance(outcome, str):
        raise ValueError("outcome must be a string")
    arm = _require_id(episode.get("arm"), "arm")
    for field in ("x_sink_called", "x_steering_different_sources"):
        if type(episode.get(field)) is not bool:
            raise ValueError(f"{field} must be a boolean")
    x_calls = episode.get("x_sink_calls")
    if type(x_calls) is not int or x_calls < 0:
        raise ValueError("x_sink_calls must be a nonnegative integer")
    counts["rows"] += 1
    counts["legitimate_episodes"] += int(outcome == "legitimate")
    counts["no_call_episodes"] += int(outcome == "no_call")
    counts["x_sink_called_episodes"] += int(episode["x_sink_called"])
    counts["x_sink_calls"] += x_calls
    if arm.startswith("A1-"):
        counts["a1_rows"] += 1
        counts["a1_registered_exposure_episodes"] += int(episode["x_steering_different_sources"])
    if arm.startswith("SS-"):
        counts["ss_rows"] += 1


def _assistant_text(transcript: dict[str, Any]) -> str:
    attempts = transcript.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("transcript attempts must be a list")
    chunks: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict) or not isinstance(attempt.get("messages"), list):
            raise ValueError("transcript attempt messages must be a list")
        for message in attempt["messages"]:
            if not isinstance(message, dict):
                raise ValueError("transcript message must be an object")
            if message.get("role") != "assistant":
                continue
            content = message.get("content")
            if not isinstance(content, list):
                raise ValueError("assistant message content must be a list")
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("content"), str):
                    chunks.append(part["content"])
    return "\n".join(chunks).lower()


def _analyze_input(root: Path, spec: dict[str, Any], phrases: list[str]) -> dict[str, Any]:
    version = _require_id(spec.get("version"), "version")
    experiment_id = _require_id(spec.get("experiment_id"), "experiment_id")
    stage = _require_id(spec.get("stage"), "stage")
    expected_rows = spec.get("expected_rows")
    if type(expected_rows) is not int or expected_rows < 1:
        raise ValueError("expected_rows must be a positive integer")
    episodes_path = _relative_file(root, spec.get("episodes"))
    transcript_dir = _relative_file(root, spec.get("transcript_directory"), directory=True)
    experiment_root = (root / "experiments" / experiment_id).resolve(strict=True)
    if not episodes_path.is_relative_to(experiment_root) or not transcript_dir.is_relative_to(experiment_root):
        raise ValueError("input paths do not match experiment_id")

    all_counts = _new_counts()
    case_counts: dict[str, dict[str, int]] = defaultdict(_new_counts)
    case_arms: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(_new_counts))
    arm_counts: dict[str, dict[str, int]] = defaultdict(_new_counts)
    case_suite: dict[str, str] = {}
    seen_episode_ids: set[str] = set()
    phrase_counts = {phrase: 0 for phrase in phrases}
    a1_transcripts = 0
    positive_episodes = 0
    source_bytes = episodes_path.read_bytes()
    if len(source_bytes) > MAX_JSON_BYTES:
        raise ValueError("episodes JSONL exceeds size limit")
    for line_number, line in enumerate(source_bytes.decode("utf-8").splitlines(), 1):
        if not line.strip():
            raise ValueError(f"empty JSONL line {line_number}")
        episode = json.loads(line)
        if not isinstance(episode, dict):
            raise ValueError(f"episode line {line_number} must be an object")
        case_id = _require_id(episode.get("case_id"), "case_id")
        suite = _require_id(episode.get("suite"), "suite")
        arm = _require_id(episode.get("arm"), "arm")
        repeat = episode.get("repeat")
        if type(repeat) is not int or repeat < 0:
            raise ValueError("repeat must be a nonnegative integer")
        episode_id = episode.get("episode_id")
        if episode_id != f"{case_id}|{arm}|r{repeat}":
            raise ValueError(f"episode_id does not match case, arm and repeat at line {line_number}")
        if episode_id in seen_episode_ids:
            raise ValueError(f"duplicate episode_id at line {line_number}")
        seen_episode_ids.add(episode_id)
        if case_id in case_suite and case_suite[case_id] != suite:
            raise ValueError("case_id has inconsistent suite")
        case_suite[case_id] = suite

        transcript_path = _transcript_path(transcript_dir, episode.get("transcript_path"))
        transcript_sha = episode.get("transcript_sha256")
        if not isinstance(transcript_sha, str) or SHA256.fullmatch(transcript_sha) is None:
            raise ValueError("invalid transcript_sha256")
        actual_sha = hashlib.sha256(transcript_path.read_bytes()).hexdigest()
        if actual_sha != transcript_sha:
            raise ValueError(f"transcript hash mismatch at line {line_number}")
        _add_episode(all_counts, episode)
        _add_episode(case_counts[case_id], episode)
        _add_episode(case_arms[case_id][arm], episode)
        _add_episode(arm_counts[arm], episode)

        if version == "v1" and arm.startswith("A1-"):
            transcript = _read_json(transcript_path)
            if not isinstance(transcript, dict) or transcript.get("episode_id") != episode_id:
                raise ValueError(f"transcript episode_id mismatch at line {line_number}")
            assistant_text = _assistant_text(transcript)
            hits = {phrase for phrase in phrases if phrase in assistant_text}
            a1_transcripts += 1
            positive_episodes += int(bool(hits))
            for phrase in hits:
                phrase_counts[phrase] += 1

    if all_counts["rows"] != expected_rows:
        raise ValueError(f"{version}: expected {expected_rows} rows, found {all_counts['rows']}")
    result: dict[str, Any] = {
        "experiment_id": experiment_id,
        "stage": stage,
        "episodes_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "counts": all_counts,
        "arms": {arm: arm_counts[arm] for arm in sorted(arm_counts)},
        "cases": [
            {
                "case_id": case_id,
                "suite": case_suite[case_id],
                "counts": case_counts[case_id],
                "arms": {arm: case_arms[case_id][arm] for arm in sorted(case_arms[case_id])},
            }
            for case_id in sorted(case_counts)
        ],
    }
    if version == "v1":
        result["assistant_keyword_diagnostic"] = {
            "a1_episodes_examined": a1_transcripts,
            "episodes_with_any_phrase": positive_episodes,
            "per_phrase_episode_counts": phrase_counts,
            "interpretation": "mechanical assistant-text signal; not a human recognition label",
        }
    return result


def analyze(results_root: Path, config_path: Path) -> dict[str, Any]:
    root = results_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("results root is not a directory")
    config_path = config_path.resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise ValueError("config must be inside the explicit results checkout")
    config_bytes = config_path.read_bytes()
    if len(config_bytes) > 1024 * 1024:
        raise ValueError("config exceeds 1 MiB")
    config = json.loads(config_bytes.decode("utf-8"))
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise ValueError("unsupported analysis config schema")
    analysis_id = _require_id(config.get("analysis_id"), "analysis_id")
    source_commit = config.get("source_results_commit")
    if not isinstance(source_commit, str) or GIT_HASH.fullmatch(source_commit) is None:
        raise ValueError("source_results_commit must be a full lower-case 40-character Git hash")
    if type(config.get("new_model_requests")) is not int or config["new_model_requests"] != 0:
        raise ValueError("this offline analysis requires new_model_requests=0")
    diagnostic = config.get("assistant_keyword_diagnostic")
    if not isinstance(diagnostic, dict):
        raise ValueError("assistant_keyword_diagnostic must be an object")
    phrases = diagnostic.get("literal_case_insensitive_phrases")
    if (
        not isinstance(phrases, list)
        or not phrases
        or any(not isinstance(value, str) or not value or len(value) > 80 for value in phrases)
        or len(set(phrases)) != len(phrases)
    ):
        raise ValueError("invalid literal diagnostic phrases")
    phrases = [phrase.lower() for phrase in phrases]
    if len(set(phrases)) != len(phrases):
        raise ValueError("duplicate diagnostic phrases after case folding")
    specs = config.get("inputs")
    if not isinstance(specs, list) or not specs:
        raise ValueError("inputs must be a nonempty list")
    versions: dict[str, Any] = {}
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("input spec must be an object")
        version = _require_id(spec.get("version"), "version")
        if version in versions:
            raise ValueError("duplicate input version")
        versions[version] = _analyze_input(root, spec, phrases)
    return {
        "schema_version": 1,
        "analysis_id": analysis_id,
        "source_results_commit": source_commit,
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "new_model_requests": 0,
        "versions": {version: versions[version] for version in sorted(versions)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.results_root.resolve(strict=True)
        report = analyze(root, args.config)
        allowed_root = (root / "experiments" / report["analysis_id"]).resolve()
        if not allowed_root.is_relative_to(root):
            raise ValueError("analysis directory escapes the results checkout")
        output = args.output.resolve()
        if output == allowed_root or not output.is_relative_to(allowed_root):
            raise ValueError("output must be inside experiments/<analysis_id>/")
        if output.suffix != ".json":
            raise ValueError("output must be a JSON file")
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists; create a new immutable artifact path")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps({"output": str(output), "rows_by_version": {
        name: item["counts"]["rows"] for name, item in report["versions"].items()
    }}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
