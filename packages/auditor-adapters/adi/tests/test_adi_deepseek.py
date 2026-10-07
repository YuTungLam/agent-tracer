"""Tests for the ADI DeepSeek adapter. Zero cost: every upstream is an in-process loopback fake.

Run with the ADI artifact's venv from a directory without a .env, for example:

    <ADI_ARTIFACT_ROOT>/.venv/Scripts/python -m pytest -p no:cacheprovider --rootdir <adi adapter dir> <this file>

Pure tests need only the stdlib. Integration tests need the ADI fork importable (they are skipped
otherwise); the run_stage tests also need this interpreter to be <ADI_ARTIFACT_ROOT>/.venv.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parents[1] / "adi_deepseek.py"
CONFIG = ADAPTER.with_name("config.template.json")
STAGES = ADAPTER.with_name("stages.json")
GUARD_TOKEN = "guard-token-for-tests-1f2e"
FAKE_DEEPSEEK_KEY = "sk-fake-deepseek-key-for-tests-9c8b"


def load_adapter():
    spec = importlib.util.spec_from_file_location("adi_deepseek_under_test", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


ad = load_adapter()
dr = ad.deepseek_route
HAVE_FORK = bool(importlib.util.find_spec("agentdojo")) and bool(importlib.util.find_spec("langchain_openai"))
ARTIFACT_ROOT = Path(sys.prefix).resolve().parent
IN_ADI_VENV = HAVE_FORK and Path(sys.prefix).resolve() == (ARTIFACT_ROOT / ".venv").resolve()
needs_fork = pytest.mark.skipif(not HAVE_FORK, reason="ADI fork not importable in this interpreter")
needs_adi_venv = pytest.mark.skipif(not IN_ADI_VENV, reason="run_stage tests need <ADI_ARTIFACT_ROOT>/.venv")


# ------------------------------------------------------------------------------------------
# Pure unit tests
# ------------------------------------------------------------------------------------------


def test_scrub_removes_credentials_routing_and_tracing_and_reports_names_only():
    env = {"OPENAI_API_KEY": "v1", "OPENAI_BASE_URL": "v2", "DEEPSEEK_API_KEY": "v3", "ANTHROPIC_API_KEY": "v4",
           "GOOGLE_API_KEY": "v5", "TOGETHER_API_KEY": "v6", "HF_API_TOKEN": "v7", "LANGSMITH_API_KEY": "v8",
           "langchain_endpoint": "v9", "AUDITOR_GUARD_TOKEN": "v10", "AUDITOR_STAGE": "S1", "PATH": "p"}
    removed = ad.scrub_environment(env)
    assert set(env) == {"PATH", "AUDITOR_STAGE", *ad.FORCED_ENV}
    assert env["LANGCHAIN_TRACING_V2"] == "false" and env["HF_HUB_OFFLINE"] == "1"
    assert "OPENAI_API_KEY" in removed and "langchain_endpoint" in removed and "AUDITOR_GUARD_TOKEN" in removed
    assert not any(value.startswith("v") and value in removed for value in ("v1", "v3", "v10"))


def test_guard_is_required_and_must_be_loopback():
    good = {"AUDITOR_GUARD_URL": "http://127.0.0.1:5000/v1", "AUDITOR_GUARD_TOKEN": "t",
            "OPENAI_BASE_URL": "http://127.0.0.1:5000/v1"}
    assert ad.take_guard(good) == ("http://127.0.0.1:5000/v1", "t")
    for bad in ({}, {**good, "AUDITOR_GUARD_URL": "https://api.deepseek.com", "OPENAI_BASE_URL": "https://api.deepseek.com"},
                {**good, "OPENAI_BASE_URL": "https://api.deepseek.com"}, {**good, "AUDITOR_GUARD_TOKEN": ""}):
        with pytest.raises(ad.AdapterError):
            ad.take_guard(bad)


def test_check_paths_refuses_dotenv_and_repo_output(tmp_path):
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    with pytest.raises(ad.AdapterError, match=".env"):
        ad.check_paths(tmp_path / "out", tmp_path)
    clean = tmp_path / "clean"
    clean.mkdir()
    ad.check_paths(tmp_path / "out", clean)
    if ad.find_repo_root(ad.HERE) is not None:
        with pytest.raises(ad.AdapterError, match="code repository"):
            ad.check_paths(ad.HERE / "scratch-out", clean)


def test_suites_must_be_explicit_d1():
    with pytest.raises(ad.AdapterError, match="D1"):
        ad.check_suites([])
    with pytest.raises(ad.AdapterError):
        ad.check_suites(["camel_bypass_poc"])
    assert ad.check_suites(["slack", "banking", "slack"]) == ["slack", "banking"]


def test_parse_case():
    assert ad.parse_case("banking/user_task_15/injection_task_0") == ("banking", "user_task_15", "injection_task_0")
    for bad in ("banking/user_task_15", "banking/15/0", "a/b/c/d"):
        with pytest.raises(ad.AdapterError):
            ad.parse_case(bad)


def test_wilson_matches_notes_band():
    assert ad.wilson(53, 108) == pytest.approx([0.398, 0.584], abs=0.001)  # NOTES.md section 6
    assert ad.wilson(0, 0) is None


def _s2_episodes():
    eps = [ad.Episode("attack", s, "u", "injection_task_0") for s, n in
           (("workspace", 55), ("slack", 16), ("banking", 9), ("travel", 28)) for _ in range(n)]
    eps += [ad.Episode("benign", s, "u", None) for s, n in
            (("workspace", 39), ("slack", 21), ("banking", 16), ("travel", 20)) for _ in range(n)]
    return eps


def test_config_and_runner_stages_agree():
    config = ad.load_config(CONFIG)
    runner = json.loads(STAGES.read_text(encoding="utf-8"))
    assert set(config["stages"]) == set(runner["stages"]) == {"DRY", "S1", "S2"}
    for name, spec in config["stages"].items():
        merged, _ = dr.load_stage(STAGES, name)  # the shared runner's own validation
        argv = merged["argv"]
        named = {argv[i + 1] for i, item in enumerate(argv) if item == "-s"}
        assert set(ad.required_suites(spec)) <= named, name
        assert argv[argv.index("--stage") + 1] == "{stage}"
        assert spec["max_model_calls"] <= merged.get("cap_requests", merged["dry_run_cap_requests"]), name
    assert runner["stages"]["DRY"]["paid_allowed"] is False
    assert runner["stages"]["S2"]["dry_run_allowed"] is False
    assert config["stages"]["DRY"]["max_model_calls"] <= runner["defaults"]["dry_run_cap_requests"] <= 10
    for blob in (CONFIG.read_text(encoding="utf-8"), STAGES.read_text(encoding="utf-8")):
        stripped = blob.replace("https://", "").replace("http://", "")
        assert ":\\" not in stripped and ":/" not in stripped  # no machine-specific absolute paths


def test_s2_estimate_fits_caps():
    config = ad.load_config(CONFIG)
    caps = json.loads(STAGES.read_text(encoding="utf-8"))["stages"]["S2"]
    est = ad.estimate_tokens(config, _s2_episodes())
    assert est["lab_native_basis_total_tokens"] == 3183163
    assert est["adi_gt_proxy_input_tokens"] == [3681380, 4908555]
    high = est["adi_gt_proxy_with_allowance"]
    assert high["input"][1] + high["output_high"] < caps["cap_tokens"]
    assert est["usd_high_gt_proxy_basis"] < caps["cap_usd"]
    assert 1.0 < est["usd_low_lab_basis"] < est["usd_high_gt_proxy_basis"] < 3.0


# ------------------------------------------------------------------------------------------
# Fake upstream (stands in for the guard, or for api.deepseek.com behind the real guard)
# ------------------------------------------------------------------------------------------


def _completion(message: dict, finish: str, n: int) -> dict:
    return {"id": f"chatcmpl-fake-{n}", "object": "chat.completion", "created": 0, "model": "deepseek-flash",
            "choices": [{"index": 0, "finish_reason": finish, "message": message}],
            "usage": {"prompt_tokens": 1000 + n, "completion_tokens": 10, "total_tokens": 1010 + n}}


TOOL_CALL = {"role": "assistant", "content": "", "tool_calls": [{"id": "call_fake_1", "type": "function", "function": {
    "name": "get_most_recent_transactions", "arguments": json.dumps({"n": 100})}}]}
FINAL = {"role": "assistant", "content": "I could not complete the refund."}


class FakeUpstream:
    def __init__(self, script: list[tuple[dict, str]]):
        self.script = script
        self.requests: list[dict] = []
        self.auth: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "body": body})
                outer.auth.append(self.headers.get("Authorization", ""))
                message, finish = outer.script[min(len(outer.requests), len(outer.script)) - 1]
                data = json.dumps(_completion(message, finish, len(outer.requests))).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def run_adapter(tmp_path: Path, args: list[str], guard_url: str | None = None) -> subprocess.CompletedProcess:
    env = dr.sanitized_env(os.environ)
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    if guard_url:
        env.update(AUDITOR_GUARD_URL=guard_url, AUDITOR_GUARD_TOKEN=GUARD_TOKEN, OPENAI_BASE_URL=guard_url,
                   OPENAI_API_KEY=GUARD_TOKEN)
    cwd = tmp_path / "cwd"
    cwd.mkdir(exist_ok=True)
    return subprocess.run([sys.executable, str(ADAPTER), *args], cwd=cwd, env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=600)


# ------------------------------------------------------------------------------------------
# Adapter-only integration (fake guard)
# ------------------------------------------------------------------------------------------


@needs_fork
def test_plan_only_s2_enumerates_108_attack_and_96_benign(tmp_path):
    proc = run_adapter(tmp_path, ["--stage", "S2", "-s", "workspace", "-s", "slack", "-s", "banking",
                                  "-s", "travel", "--plan-only"])
    assert proc.returncode == 0, proc.stderr[-2000:]
    plan = json.loads(proc.stdout[proc.stdout.index("{"):])
    assert (plan["n_attack"], plan["n_benign"]) == (108, 96)
    assert plan["estimate"]["lab_native_basis_total_tokens"] == 3183163


@needs_fork
def test_missing_suite_flag_is_refused(tmp_path):
    proc = run_adapter(tmp_path, ["--stage", "S1", "-s", "banking", "--plan-only"])
    assert proc.returncode == 2 and "-s slack -s workspace" in proc.stderr


@needs_fork
def test_unguarded_run_is_refused_before_any_request(tmp_path):
    proc = run_adapter(tmp_path, ["--stage", "DRY", "-s", "banking", "--out-dir", str(tmp_path / "out")])
    assert proc.returncode == 2 and "auditor guard" in proc.stderr
    assert not (tmp_path / "out").exists()


@needs_fork
def test_client_wire_before_the_guard(tmp_path):
    fake = FakeUpstream([(TOOL_CALL, "tool_calls"), (FINAL, "stop")])
    try:
        out = tmp_path / "out"
        proc = run_adapter(tmp_path, ["--stage", "DRY", "-s", "banking", "--out-dir", str(out)], guard_url=fake.url)
    finally:
        fake.close()
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert len(fake.requests) == 2
    for req in fake.requests:
        body = req["body"]
        assert req["path"] == "/v1/chat/completions"
        assert body["model"] == "deepseek-flash" and body["max_tokens"] == 2048
        assert body["thinking"] == {"type": "disabled"} and body["stream"] is False
        assert body["temperature"] == 0.0 and body["tool_choice"] == "auto" and body["tools"]
        assert body["parallel_tool_calls"] is True  # artifact binding; the guard drops it
        for forbidden in ("max_completion_tokens", "reasoning_effort", "reasoning", "extra_body"):
            assert forbidden not in body
    assert all(a == f"Bearer {GUARD_TOKEN}" for a in fake.auth)
    tool_msgs = [m for m in fake.requests[1]["body"]["messages"] if m["role"] == "tool"]
    assert len(tool_msgs) == 1 and set(tool_msgs[0]) == {"role", "content", "tool_call_id"}
    assert isinstance(tool_msgs[0]["content"], str) and "GA320SBK21038512280" in tool_msgs[0]["content"]
    roles = [m["role"] for m in fake.requests[1]["body"]["messages"]]
    assert roles[:2] == ["system", "user"] and "developer" not in roles
    summary = json.loads((out / "adi_summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "complete" and summary["artifact"]["tree_clean"] is True
    assert summary["results"]["adi_asr"]["n"] == 1 and summary["adapter_usage"]["model_calls"] == 2
    assert "OPENAI_API_KEY" in summary["env_removed"] and "AUDITOR_GUARD_TOKEN" in summary["env_removed"]
    for text in (proc.stdout, proc.stderr, (out / "adi_summary.json").read_text(encoding="utf-8")):
        assert GUARD_TOKEN not in text
    trace = out / "traces" / "baseline_deepseek-flash" / "banking" / "user_task_15" / "data_only_syntactic"
    assert (trace / "injection_task_0.json").exists()


@needs_fork
def test_adapter_call_ceiling_stops_the_run(tmp_path):
    fake = FakeUpstream([(TOOL_CALL, "tool_calls")])  # never finishes on its own
    try:
        out = tmp_path / "out"
        proc = run_adapter(tmp_path, ["--stage", "DRY", "-s", "banking", "--out-dir", str(out),
                                      "--max-model-calls", "3"], guard_url=fake.url)
    finally:
        fake.close()
    assert proc.returncode == 2 and "max_model_calls=3" in proc.stderr
    assert len(fake.requests) == 3
    summary = json.loads((out / "adi_summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "incomplete" and summary["failure"]["type"] == "AdapterError"
    assert summary["results"]["adi_asr"]["n"] == 0


@needs_fork
def test_registry_refuses_other_models():
    code = (
        "import sys, importlib.util as u\n"
        f"spec = u.spec_from_file_location('m', r'{ADAPTER}')\n"
        "m = u.module_from_spec(spec); sys.modules['m'] = m; spec.loader.exec_module(m)\n"
        "s = m.ModelSettings('http://127.0.0.1:1/v1', 'x', 2048, 0.0, 5, 0, 1)\n"
        "m.install_registry(s, m.CallBudget(1))\n"
        "import agents.baseline.graph as g\n"
        "assert type(g._get_model_instance('deepseek-flash')).__name__ == 'GuardedDeepSeekChat'\n"
        "try:\n    g._get_model_instance('gpt-5.2-2025-12-11')\nexcept m.AdapterError:\n    print('refused')\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          env=dr.sanitized_env(os.environ), timeout=300)
    assert proc.returncode == 0 and "refused" in proc.stdout, proc.stderr[-2000:]


# ------------------------------------------------------------------------------------------
# Full path: shared runner -> real guard (paid mode) -> adapter -> guard -> loopback fake DeepSeek
# ------------------------------------------------------------------------------------------


def _stage_request(tmp_path: Path, stage: str, **overrides) -> dr.StageRequest:
    lab_env = tmp_path / "lab.env"  # not named .env, and holds only a fake key
    lab_env.write_text(f"DEEPSEEK_API_KEY={FAKE_DEEPSEEK_KEY}\n", encoding="utf-8")
    fields = dict(artifact="adi", stage=stage, cap_usd=Decimal("0.01"), cap_tokens=60000,
                  out_root=tmp_path / "runs", lab_env=lab_env, artifact_root=ARTIFACT_ROOT, timeout_seconds=600)
    fields.update(overrides)
    return dr.StageRequest(**fields)


@needs_adi_venv
def test_run_stage_paid_mode_through_real_guard(tmp_path):
    fake = FakeUpstream([(TOOL_CALL, "tool_calls"), (FINAL, "stop")])
    try:
        # DRY is dry-run only, so the paid path is exercised with a test copy that allows it.
        runner = json.loads(STAGES.read_text(encoding="utf-8"))
        runner["stages"]["DRY"]["paid_allowed"] = True
        config_copy = tmp_path / "stages.json"
        config_copy.write_text(json.dumps(runner), encoding="utf-8")
        receipt = dr.run_stage(_stage_request(tmp_path, "DRY", config_path=config_copy,
                                              deepseek_url_override=fake.url))
    finally:
        fake.close()
    stderr = Path(receipt["stderr"]).read_text(encoding="utf-8", errors="replace")
    assert receipt["status"] == "completed", stderr[-3000:]
    assert receipt["guard"]["requests_forwarded"] == 2 and receipt["guard"]["requests_refused"] == 0
    assert all(a == f"Bearer {FAKE_DEEPSEEK_KEY}" for a in fake.auth)
    for req in fake.requests:
        body = req["body"]
        assert body["model"] == "deepseek-flash" and body["max_tokens"] == 2048
        assert body["thinking"] == {"type": "disabled"} and body["temperature"] == 0.0
        assert "parallel_tool_calls" not in body and "max_completion_tokens" not in body
    out_dir = Path(receipt["receipt_path"]).parent
    ledger = [json.loads(line) for line in (out_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["outcome"] for r in ledger] == ["ok", "ok"]
    assert all(r["dropped_fields"] == ["parallel_tool_calls"] for r in ledger)
    summary = json.loads((out_dir / "adapter" / "adi_summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "complete" and summary["mode"] == "deepseek"
    for path in out_dir.rglob("*"):
        if path.is_file():
            assert FAKE_DEEPSEEK_KEY not in path.read_text(encoding="utf-8", errors="replace"), path


@needs_adi_venv
def test_run_stage_guard_cap_stops_the_adapter_without_upstream_calls(tmp_path):
    fake = FakeUpstream([(FINAL, "stop")])
    try:
        receipt = dr.run_stage(_stage_request(tmp_path, "S1", cap_usd=Decimal("0.01"), cap_tokens=3000,
                                              deepseek_url_override=fake.url))
    finally:
        fake.close()
    assert receipt["status"] == "halted" and receipt["guard"]["halt_reason"] == "token_cap_preflight"
    assert receipt["guard"]["requests_forwarded"] == 0 and fake.requests == []
    summary = json.loads((Path(receipt["receipt_path"]).parent / "adapter" / "adi_summary.json")
                         .read_text(encoding="utf-8"))
    assert summary["status"] == "incomplete" and summary["results"]["adi_asr"]["n"] == 0
