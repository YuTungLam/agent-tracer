#!/usr/bin/env python
"""NeuroTaint causal judge over planned probes, through the DeepSeek route (guarded).

Reads the single-source probes planned offline by ``run_reference.py`` (each probe
is a recorded prefix and the same prefix with one tool result neutralised), sends
the frozen lab judge request for each (``counterfactual_audit.SYSTEM_PROMPT`` and
``request_body``), and writes one bound record per probe to ``judgments.jsonl``.
Parsing and folding into the NeuroTaint records happen offline afterwards
(``run_reference.py --judgments``), so a judgment is never trusted without its
probe binding.

Launch only through ``../common/deepseek_route.py run-stage --artifact reference``
with the lab venv (``--artifact-root <agent-tracer>/packages/agentdojo-lab``); the
script refuses to send anything unless ``require_guard()`` succeeds. It never reads
a key or a ``.env``. ``--plan-only`` counts probes and estimates tokens without any
request. It also refuses probes planned on SS traces or on inexact prefixes (no
declared metric uses them) unless ``--allow-ss`` / ``--allow-inexact-prefix``.
``--resume-from`` skips only probes that already have an answer (HTTP 200 with
content); errored probes are sent again. Model output is saved as untrusted data and
never interpreted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ref_common import (  # noqa: E402
    COMMON, CONFIG_PATH, code_hashes, lab_code_hashes, load_config, read_jsonl, sha256_bytes, write_json,
)

sys.path.insert(0, str(COMMON))

EXIT_OK, EXIT_CONFIG, EXIT_GUARD_HALT, EXIT_ERRORS, EXIT_OTHER = 0, 2, 3, 6, 1
MAX_CONSECUTIVE_ERRORS = 5
SCHEMA_JUDGMENT = "reference-nt-judgment/v1"
EXPECTED_MODEL = "deepseek-flash"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def check_body(body: dict[str, Any], config: dict[str, Any], token: str) -> None:
    """The outbound judge request must be exactly the frozen shape (never sent otherwise)."""
    rc = config["neurotaint"]["judge"]["request_config"]
    problems = []
    for key in ("tools", "tool_choice", "functions"):
        if key in body:
            problems.append(f"forbidden {key}")
    for key, value in rc.items():
        if body.get(key) != value:
            problems.append(f"{key}={body.get(key)!r} != {value!r}")
    if body.get("model") != EXPECTED_MODEL:
        problems.append(f"model {body.get('model')!r}")
    messages = body.get("messages") or []
    if len(messages) != 2 or messages[0].get("role") != "system" or messages[1].get("role") != "user":
        problems.append("messages must be [system, user]")
    if token and token in json.dumps(body, ensure_ascii=False):
        problems.append("guard token inside the request body")
    if problems:
        raise ValueError("judge request violates the frozen shape: " + "; ".join(problems))


def post(base_url: str, token: str, body: dict[str, Any], timeout: float) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        except Exception:  # noqa: BLE001
            return error.code, {}


def estimate(probes: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    """Rough plan-time estimate (UNVERIFIED): prompt tokens ~ request bytes / 4."""
    from neurotaint_offline import judge_request_body

    rc = config["neurotaint"]["judge"]["request_config"]
    prompt = sum(len(json.dumps(judge_request_body(p, config)).encode("utf-8")) // 4 for p in probes)
    completion_cap = len(probes) * int(rc["max_completion_tokens"])
    from deepseek_route import PRICE_SNAPSHOT
    usd = (prompt * float(PRICE_SNAPSHOT["input_per_million"]) + completion_cap * float(PRICE_SNAPSHOT["output_per_million"])) / 1e6
    return {"probes": len(probes), "prompt_tokens_bytes_over_4": prompt, "completion_tokens_ceiling": completion_cap,
            "usd_upper_at_snapshot": round(usd, 4), "price_snapshot": PRICE_SNAPSHOT["snapshot_id"],
            "note": "UNVERIFIED: bytes/4 is a heuristic; the guard's own pre-flight uses bytes/2 (overestimates)"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NeuroTaint causal judge through the DeepSeek route.")
    parser.add_argument("--probes", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--lab-root", type=Path, default=None, help="recorded only (lab is located by ref_common)")
    parser.add_argument("--max-probes", type=int, default=None)
    parser.add_argument("--resume-from", type=Path, action="append", default=[])
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--allow-ss", action="store_true",
                        help="send probes planned on SS traces (refused by default: no declared metric uses them)")
    parser.add_argument("--allow-inexact-prefix", action="store_true",
                        help="send probes whose trace prefix is not exact (refused by default)")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    from neurotaint_offline import _binding, judge_request_body, judgment_is_answer
    from agentdojo_lab import counterfactual_audit

    probes = read_jsonl(args.probes)
    for probe in probes:
        if probe.get("binding_sha256") != _binding(probe) or probe.get("probe_id") != "ref-nt-probe-v1:" + probe["binding_sha256"]:
            print(f"refused: probe binding changed ({probe.get('probe_id')})", file=sys.stderr)
            return EXIT_CONFIG
        if probe.get("stratum") == "SS" and not args.allow_ss:
            print(f"refused: probe {probe.get('probe_id')} was planned on an SS trace (the SS eligibility result "
                  "needs no judge; pass --allow-ss only with an explicit decision)", file=sys.stderr)
            return EXIT_CONFIG
        if probe.get("prefix_exact") is not True and not args.allow_inexact_prefix:
            print(f"refused: probe {probe.get('probe_id')} has an inexact prefix (pass --allow-inexact-prefix only "
                  "with an explicit decision)", file=sys.stderr)
            return EXIT_CONFIG
    # Resume: only a probe that already has an answer (HTTP 200 with content) is done; errored rows are retried.
    done = {r["probe_id"] for d in args.resume_from for r in read_jsonl(Path(d) / "judgments.jsonl")
            if judgment_is_answer(r)}
    todo = [p for p in probes if p["probe_id"] not in done]
    if args.max_probes is not None:
        todo = todo[: max(0, args.max_probes)]
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    plan = {"schema": "reference-nt-judge-plan/v1", "probes_file": str(args.probes),
            "probes_file_sha256": sha256_bytes(args.probes.read_bytes()), "total": len(probes),
            "skipped_as_done": len(probes) - len([p for p in probes if p["probe_id"] not in done]),
            "to_send": len(todo), "estimate": estimate(todo, config)}
    write_json(out / "judge_plan.json", plan)
    if args.plan_only:
        print(json.dumps(plan["estimate"]))
        return EXIT_OK

    from deepseek_route import RouteError, require_guard
    try:
        base_url, token = require_guard()
    except RouteError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    receipt: dict[str, Any] = {
        "schema": "reference-nt-judge-receipt/v1", "mode": os.environ.get("AUDITOR_MODE"),
        "stage": os.environ.get("AUDITOR_STAGE"), "backbone": os.environ.get("AUDITOR_BACKBONE"),
        "started_at": _utc(), "probes_file_sha256": plan["probes_file_sha256"],
        "system_prompt_sha256": sha256_bytes(counterfactual_audit.SYSTEM_PROMPT.encode("utf-8")),
        "request_config": config["neurotaint"]["judge"]["request_config"],
        "judgment_format": config["neurotaint"]["judge"]["judgment_format"],
        "code_sha256_lf": code_hashes([Path(__file__), HERE / "neurotaint_offline.py", HERE / "ref_common.py",
                                       HERE / "ref_trace.py", COMMON / "deepseek_route.py"]),
        "lab_code_sha256_lf": lab_code_hashes(),
        "overrides": {"allow_ss": bool(args.allow_ss), "allow_inexact_prefix": bool(args.allow_inexact_prefix)},
        "config_sha256": sha256_bytes(args.config.read_bytes()), "lab_root": str(args.lab_root) if args.lab_root else None,
    }
    path = out / "judgments.jsonl"
    sent = ok = errors = consecutive = 0
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    exit_code, stop = EXIT_OK, "all planned probes sent"
    try:
        for probe in todo:
            body = judge_request_body(probe, config)
            try:
                check_body(body, config, token)
            except ValueError as exc:
                exit_code, stop = EXIT_CONFIG, str(exc)[:300]
                break
            t0 = time.monotonic()
            try:
                status, response = post(base_url, token, body, args.timeout)
            except Exception as exc:  # noqa: BLE001 - transport errors are recorded, never retried silently
                status, response = 0, {"transport_error": type(exc).__name__}
            sent += 1
            choice = ((response.get("choices") or [{}])[0]) if isinstance(response, dict) else {}
            content = ((choice.get("message") or {}).get("content")) if status == 200 else None
            u = (response.get("usage") or {}) if isinstance(response, dict) else {}
            usage["prompt_tokens"] += int(u.get("prompt_tokens") or 0)
            usage["completion_tokens"] += int(u.get("completion_tokens") or 0)
            row = {"schema": SCHEMA_JUDGMENT, "probe_id": probe["probe_id"], "binding_sha256": probe["binding_sha256"],
                   "trace_id": probe["trace_id"], "proposal_id": probe["proposal_id"], "source_id": probe["source_id"],
                   "http_status": status, "raw_content": content, "finish_reason": choice.get("finish_reason"),
                   "usage": {k: u.get(k) for k in ("prompt_tokens", "completion_tokens")},
                   "request_body_sha256": sha256_bytes(json.dumps(body, sort_keys=True).encode("utf-8")),
                   "seconds": round(time.monotonic() - t0, 3), "at": _utc()}
            _append(path, row)
            if status == 200 and content is not None:
                ok += 1
                consecutive = 0
                continue
            errors += 1
            consecutive += 1
            if status in (401, 402, 403):
                exit_code, stop = EXIT_GUARD_HALT, f"guard or provider refused with HTTP {status}"
                break
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                exit_code, stop = EXIT_ERRORS, f"{consecutive} consecutive judge errors"
                break
    except KeyboardInterrupt:
        exit_code, stop = EXIT_OTHER, "interrupted"
    finally:
        receipt.update({"finished_at": _utc(), "sent": sent, "ok": ok, "errors": errors, "usage": usage,
                        "exit_code": exit_code, "stop_reason": stop,
                        "judgments_sha256": sha256_bytes(path.read_bytes()) if path.exists() else None})
        write_json(out / "judge_receipt.json", receipt)
    print(json.dumps({"sent": sent, "ok": ok, "errors": errors, "exit_code": exit_code, "stop_reason": stop}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
