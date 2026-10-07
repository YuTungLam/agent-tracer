"""Unit tests for the shared DeepSeek route.  Every upstream is a loopback fake.

Run: python -m unittest discover -s packages/auditor-adapters/common/tests -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import threading
import unittest
import urllib.error
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMMON))

import deepseek_route as dr  # noqa: E402

FAKE_KEY = "sk-test-0123456789abcdef"
SENTINEL = "SENTINEL-PROMPT-TEXT-7f3a"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class FakeUpstream:
    """Loopback stand-in for DeepSeek or Ollama with scripted responses."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        self.headers: list[dict] = []
        self.status = 200
        self.usage: dict | None = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
        self.stream_usage = True
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):  # noqa: D401
                return

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.received.append(body)
                outer.headers.append(dict(self.headers))
                if self.path.endswith("/embeddings"):
                    payload = {"object": "list", "model": body["model"],
                               "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
                               "usage": {"prompt_tokens": 3, "total_tokens": 3}}
                    return self._send(200, json.dumps(payload).encode())
                if outer.status != 200:
                    return self._send(outer.status, json.dumps({"error": {"message": "fake"}}).encode())
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    chunks = [
                        {"id": "fake-1", "choices": [{"index": 0, "delta": {"content": "po"}}]},
                        {"id": "fake-1", "choices": [{"index": 0, "delta": {"content": "ng"}, "finish_reason": "stop"}]},
                    ]
                    if outer.stream_usage:
                        chunks.append({"id": "fake-1", "choices": [], "usage": outer.usage})
                    for chunk in chunks:
                        self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                    self.wfile.write(b"data: [DONE]\n\n")
                    return
                payload = {
                    "id": f"fake-{len(outer.received)}",
                    "object": "chat.completion",
                    "model": body["model"],
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "pong"}}],
                }
                if outer.usage is not None:
                    payload["usage"] = outer.usage
                self._send(200, json.dumps(payload).encode())

            def _send(self, status, data):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def post(url: str, token: str | None, body: dict | bytes, path: str = "/chat/completions"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url + path, data=data, headers=headers, method="POST")
    try:
        with OPENER.open(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def chat(model: str = "deepseek-flash", **extra) -> dict:
    return {"model": model, "messages": [{"role": "user", "content": SENTINEL}], **extra}


class GuardTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.upstream = FakeUpstream()
        self.guards: list[dr.BudgetGuard] = []

    def tearDown(self) -> None:
        for guard in self.guards:
            guard.stop()
        self.upstream.close()
        self.tmp.cleanup()

    def guard(self, **overrides) -> dr.BudgetGuard:
        settings = dict(
            stage_id="test/stage",
            ledger_path=self.dir / f"ledger{len(self.guards)}.jsonl",
            cap_usd=Decimal("1"),
            cap_tokens=1_000_000,
            upstream="deepseek",
            upstream_base_url=self.upstream.url,
            api_key=FAKE_KEY,
        )
        settings.update(overrides)
        guard = dr.BudgetGuard(dr.GuardConfig(**settings))
        guard.start()
        self.guards.append(guard)
        return guard

    def ledger(self, guard: dr.BudgetGuard) -> list[dict]:
        return [json.loads(line) for line in guard.config.ledger_path.read_text(encoding="utf-8").splitlines()]


class EnvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / ".env"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, text: str) -> None:
        self.path.write_bytes(textwrap.dedent(text).encode("utf-8"))

    def test_reads_only_key_and_strips_providers(self) -> None:
        self.write(f"""\
            GROQ_API_KEY=gsk-other-secret-value
            OTHER_SETTING=not-for-children
            DEEPSEEK_API_KEY={FAKE_KEY}
            """)
        base = {
            "PATH": "/bin", "OPENAI_API_KEY": "sk-openai", "OPENAI_ORG_ID": "org",
            "ANTHROPIC_API_KEY": "a", "GOOGLE_APPLICATION_CREDENTIALS": "g", "TOGETHER_API_KEY": "t",
            "HF_TOKEN": "h", "GROQ_API_KEY": "q", "GITHUB_TOKEN": "gh", "AWS_SECRET_ACCESS_KEY": "aws",
            "LANGCHAIN_TRACING_V2": "true",
        }
        env = dr.load_deepseek_env(self.path, base_env=base)
        self.assertEqual(env["OPENAI_API_KEY"], FAKE_KEY)
        self.assertEqual(env["OPENAI_BASE_URL"], "https://api.deepseek.com")
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(set(env), {"PATH", "OPENAI_API_KEY", "OPENAI_BASE_URL"})
        blob = json.dumps(env)
        self.assertNotIn("gsk-other-secret-value", blob)
        self.assertNotIn("not-for-children", blob)

    def test_value_forms(self) -> None:
        for line in (f'DEEPSEEK_API_KEY="{FAKE_KEY}"', f"export DEEPSEEK_API_KEY='{FAKE_KEY}'",
                     f"DEEPSEEK_API_KEY={FAKE_KEY}  # comment", f"  DEEPSEEK_API_KEY = {FAKE_KEY}\r"):
            self.write(line + "\n")
            self.assertEqual(dr.read_deepseek_key(self.path), FAKE_KEY, line)

    def test_missing_duplicate_malformed_do_not_leak(self) -> None:
        self.write("GROQ_API_KEY=gsk-secret-zzz\n# DEEPSEEK_API_KEY=commented\n")
        with self.assertRaises(dr.RouteError) as ctx:
            dr.read_deepseek_key(self.path)
        self.assertNotIn("gsk-secret-zzz", str(ctx.exception))
        self.write(f"DEEPSEEK_API_KEY={FAKE_KEY}\nDEEPSEEK_API_KEY={FAKE_KEY}\n")
        with self.assertRaises(dr.RouteError):
            dr.read_deepseek_key(self.path)
        self.write("DEEPSEEK_API_KEY=has space inside\n")
        with self.assertRaises(dr.RouteError) as ctx:
            dr.read_deepseek_key(self.path)
        self.assertNotIn("space inside", str(ctx.exception))

    def test_other_lines_are_never_decoded(self) -> None:
        self.path.write_bytes(b"BINARY=\xff\xfe\xfa\nDEEPSEEK_API_KEY=" + FAKE_KEY.encode() + b"\n")
        self.assertEqual(dr.read_deepseek_key(self.path), FAKE_KEY)

    def test_guarded_child_env_has_no_key(self) -> None:
        env = dr.guarded_child_env({"DEEPSEEK_API_KEY": FAKE_KEY, "OPENAI_API_KEY": "x", "PATH": "p"},
                                   "http://127.0.0.1:9/v1", "guard-token")
        self.assertNotIn(FAKE_KEY, json.dumps(env))
        self.assertEqual(env["OPENAI_API_KEY"], "guard-token")
        self.assertEqual(dr.require_guard(env), ("http://127.0.0.1:9/v1", "guard-token"))
        with self.assertRaises(dr.RouteError):
            dr.require_guard({"OPENAI_BASE_URL": "https://api.deepseek.com"})


class ConfigTests(unittest.TestCase):
    def base(self, **overrides) -> dr.GuardConfig:
        settings = dict(stage_id="s", ledger_path=Path("unused.jsonl"), cap_usd=Decimal("1"), cap_tokens=10,
                        upstream="deepseek", api_key=FAKE_KEY)
        settings.update(overrides)
        return dr.GuardConfig(**settings)

    def test_upstream_allowlist(self) -> None:
        self.base().validate()
        self.base(upstream_base_url="http://127.0.0.1:1/v1").validate()
        for bad in (
            dict(upstream_base_url="https://api.openai.com/v1"),
            dict(upstream_model="deepseek-reasoner"),
            dict(api_key=None),
            dict(upstream="ollama", upstream_base_url="https://example.com/v1", api_key=None),
            dict(upstream="ollama", upstream_base_url="http://localhost:11434/v1"),  # key must not go to dry run
            dict(embeddings_base_url="https://api.openai.com/v1", embeddings_model="x"),
            dict(cap_usd=Decimal("0")),
        ):
            with self.assertRaises(dr.RouteError, msg=str(bad)):
                self.base(**bad).validate()

    def test_repr_hides_secrets(self) -> None:
        config = self.base()
        self.assertNotIn(FAKE_KEY, repr(config))
        self.assertNotIn(config.client_token, repr(config))


class GuardTests(GuardTestCase):
    def test_forwarding_rewrites_wire_and_ledger_has_no_text(self) -> None:
        guard = self.guard(model_aliases=("gpt-4o-mini",))
        body = chat(
            "gpt-4o-mini",
            max_completion_tokens=9000,
            reasoning_effort="low",
            parallel_tool_calls=True,
            messages=[
                {"role": "developer", "content": SENTINEL},
                {"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
                {"role": "tool", "name": "f", "tool_call_id": "c1", "content": "r"},
            ],
        )
        status, payload = post(guard.base_url, guard.config.client_token, body)
        self.assertEqual(status, 200, payload)
        sent = self.upstream.received[-1]
        self.assertEqual(sent["model"], "deepseek-flash")
        self.assertEqual(sent["thinking"], {"type": "disabled"})
        self.assertEqual(sent["max_tokens"], 4096)  # clamped to the ceiling
        for gone in ("max_completion_tokens", "reasoning_effort", "parallel_tool_calls"):
            self.assertNotIn(gone, sent)
        self.assertEqual(sent["messages"][0]["role"], "system")
        self.assertEqual(sent["messages"][1]["content"], "a\nb")
        self.assertNotIn("name", sent["messages"][2])
        auth = {k.lower(): v for k, v in self.upstream.headers[-1].items()}["authorization"]
        self.assertEqual(auth, f"Bearer {FAKE_KEY}")
        records = self.ledger(guard)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["prompt_tokens"], record["completion_tokens"]), (100, 20))
        self.assertEqual(record["usd"], "0.00005400")  # 100*0.30/M + 20*1.20/M
        self.assertTrue(record["max_tokens_clamped"])
        self.assertEqual(record["requested_model"], "gpt-4o-mini")
        raw = guard.config.ledger_path.read_text(encoding="utf-8")
        self.assertNotIn(SENTINEL, raw)
        self.assertNotIn(FAKE_KEY, raw)
        self.assertNotIn(guard.config.client_token, raw)

    def test_auth_and_model_refusals_never_reach_upstream(self) -> None:
        guard = self.guard()
        self.assertEqual(post(guard.base_url, None, chat())[0], 401)
        self.assertEqual(post(guard.base_url, "wrong", chat())[0], 401)
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat("gpt-4o"))[0], 400)
        self.assertEqual(post(guard.base_url, guard.config.client_token, b"not json")[0], 400)
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat(), path="/completions")[0], 404)
        self.assertEqual(self.upstream.received, [])
        self.assertFalse(guard.halted)
        self.assertEqual(guard.refused, 5)

    def test_models_endpoint_is_local(self) -> None:
        guard = self.guard(model_aliases=("gpt-4.1-mini",))
        request = urllib.request.Request(guard.base_url + "/models",
                                         headers={"Authorization": f"Bearer {guard.config.client_token}"})
        with OPENER.open(request, timeout=10) as response:
            ids = [m["id"] for m in json.loads(response.read())["data"]]
        self.assertEqual(ids, ["deepseek-flash", "gpt-4.1-mini"])
        self.assertEqual(self.upstream.received, [])

    def test_token_cap_halts_and_refuses(self) -> None:
        guard = self.guard(cap_tokens=300, max_tokens_default=16, max_tokens_ceiling=16)
        token = guard.config.client_token
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)  # 120 tokens
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)  # 240 tokens
        status, payload = post(guard.base_url, token, chat())  # 240 + estimate > 300
        self.assertEqual(status, 402)
        self.assertIn(b"token_cap", payload)
        self.assertEqual(len(self.upstream.received), 2)
        self.assertEqual(guard.halt_reason, "token_cap_preflight")
        self.assertEqual(post(guard.base_url, token, chat())[0], 402)
        self.assertEqual(len(self.upstream.received), 2)
        records = self.ledger(guard)
        self.assertEqual([r["outcome"] for r in records], ["ok", "ok", "refused", "refused"])
        refusal = records[2]
        self.assertEqual((refusal["refusal"], refusal["committed_tokens"]), ("token_cap", 240))
        self.assertGreater(refusal["est_prompt_tokens"] + refusal["est_completion_tokens"], 60)

    def test_usd_cap_reached_after_response(self) -> None:
        self.upstream.usage = {"prompt_tokens": 1_000_000, "completion_tokens": 0}
        guard = self.guard(cap_usd=Decimal("0.50"), cap_tokens=10_000_000, max_tokens_default=8, max_tokens_ceiling=8)
        token = guard.config.client_token
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)  # $0.30 actual, under the cap
        self.assertFalse(guard.halted)
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)  # $0.60 actual: reached
        self.assertEqual(guard.halt_reason, "usd_cap_reached")
        self.assertEqual(post(guard.base_url, token, chat())[0], 402)
        self.assertEqual(len(self.upstream.received), 2)
        self.assertEqual(guard.summary()["usd"], "0.60000000")

    def test_preflight_reservation_blocks_large_request(self) -> None:
        guard = self.guard(cap_usd=Decimal("0.001"), max_tokens_ceiling=8192)
        status, _ = post(guard.base_url, guard.config.client_token, chat(max_tokens=8192, messages=[
            {"role": "user", "content": "x" * 4000}]))
        # estimate: about 2,050 prompt + 8,192 completion -> about $0.0104 > $0.001
        self.assertEqual(status, 402)
        self.assertEqual(self.upstream.received, [])
        self.assertEqual(guard.halt_reason, "usd_cap_preflight")

    def test_request_cap(self) -> None:
        guard = self.guard(cap_requests=1)
        token = guard.config.client_token
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)
        self.assertEqual(guard.halt_reason, "request_cap_reached")
        self.assertEqual(post(guard.base_url, token, chat())[0], 402)
        self.assertEqual(len(self.upstream.received), 1)

    def test_missing_usage_charges_estimate_and_halts(self) -> None:
        self.upstream.usage = None
        guard = self.guard(max_tokens_default=10, max_tokens_ceiling=10)
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat())[0], 200)
        record = self.ledger(guard)[0]
        self.assertEqual(record["usage_source"], "estimate")
        self.assertEqual(record["completion_tokens"], 10)
        self.assertGreater(record["prompt_tokens"], 0)
        self.assertEqual(guard.halt_reason, "usage_missing")

    def test_upstream_auth_failure_halts(self) -> None:
        self.upstream.status = 401
        guard = self.guard()
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat())[0], 401)
        self.assertEqual(guard.halt_reason, "upstream_http_401")
        self.assertEqual(self.ledger(guard)[0]["usd"], "0.00000000")

    def test_streaming_relay_counts_usage(self) -> None:
        guard = self.guard()
        status, payload = post(guard.base_url, guard.config.client_token, chat(stream=True))
        self.assertEqual(status, 200)
        self.assertIn(b"data: [DONE]", payload)
        self.assertEqual(self.upstream.received[-1]["stream_options"], {"include_usage": True})
        record = self.ledger(guard)[0]
        self.assertEqual((record["prompt_tokens"], record["finish_reason"], record["upstream_id"]), (100, "stop", "fake-1"))
        self.upstream.stream_usage = False
        post(guard.base_url, guard.config.client_token, chat(stream=True))
        self.assertEqual(guard.halt_reason, "usage_missing")

    def test_stream_options_dropped_without_stream(self) -> None:
        guard = self.guard()
        post(guard.base_url, guard.config.client_token, chat(stream_options={"include_usage": True}))
        self.assertNotIn("stream_options", self.upstream.received[-1])

    def test_embeddings_refused_or_local(self) -> None:
        guard = self.guard()
        status, payload = post(guard.base_url, guard.config.client_token,
                               {"model": "text-embedding-3-large", "input": ["a"]}, path="/embeddings")
        self.assertEqual(status, 400)
        self.assertIn(b"embeddings_unavailable", payload)
        local = self.guard(embeddings_base_url=self.upstream.url, embeddings_model="nomic-embed-text")
        status, payload = post(local.base_url, local.config.client_token,
                               {"model": "text-embedding-3-large", "input": ["a"]}, path="/embeddings")
        self.assertEqual(status, 200)
        self.assertEqual(self.upstream.received[-1]["model"], "nomic-embed-text")
        self.assertEqual(json.loads(payload)["model"], "text-embedding-3-large")
        record = self.ledger(local)[0]
        self.assertEqual((record["endpoint"], record["counts_toward_caps"]), ("embeddings", False))
        self.assertEqual(local.total_tokens, 0)

    def test_concurrent_requests_respect_request_cap(self) -> None:
        guard = self.guard(cap_requests=3)
        token = guard.config.client_token
        statuses: list[int] = []
        threads = [threading.Thread(target=lambda: statuses.append(post(guard.base_url, token, chat())[0]))
                   for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertLessEqual(len(self.upstream.received), 3)
        self.assertEqual(statuses.count(200), len(self.upstream.received))


CHILD = textwrap.dedent(
    """
    import json, os, sys, urllib.request
    base, token = os.environ["OPENAI_BASE_URL"], os.environ["OPENAI_API_KEY"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    n = int(sys.argv[1])
    results = []
    for i in range(n):
        req = urllib.request.Request(base + "/chat/completions",
            data=json.dumps({"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST")
        try:
            with opener.open(req, timeout=30) as r:
                results.append(r.status)
        except urllib.error.HTTPError as e:
            results.append(e.code)
    report = {"statuses": results, "env_names": sorted(os.environ), "cwd": os.getcwd(),
              "env_blob_has_key": %r in json.dumps(dict(os.environ))}
    open(os.path.join(os.environ["AUDITOR_OUT_DIR"], "child.json"), "w").write(json.dumps(report))
    """
) % FAKE_KEY


class RunnerTests(GuardTestCase):
    def make_config(self, argv: list[str], **stage) -> Path:
        (self.dir / "child.py").write_text(CHILD, encoding="utf-8")
        config = {
            "schema": dr.SCHEMA_STAGES,
            "artifact": "fake",
            "defaults": {"timeout_seconds": 60, "max_tokens_default": 16, "max_tokens_ceiling": 16},
            "stages": {"s1": {"argv": argv, "cap_usd": 1, "cap_tokens": 100000, **stage}},
        }
        path = self.dir / "stages.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def request(self, config: Path, **overrides) -> dr.StageRequest:
        settings = dict(artifact="fake", stage="s1", cap_usd=Decimal("0.5"), cap_tokens=50_000,
                        out_root=self.dir / "out", config_path=config, grace_seconds=0.5)
        settings.update(overrides)
        return dr.StageRequest(**settings)

    def test_dry_run_receipt_ledger_and_child_env(self) -> None:
        config = self.make_config(["{python}", str(self.dir / "child.py"), "2"])
        base_env = {**os.environ, "OPENAI_ORG_ID": "org", "ANTHROPIC_API_KEY": "anthropic"}
        receipt = dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url),
                               base_env=base_env)
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["guard"]["requests_forwarded"], 2)
        self.assertEqual(receipt["ledger_lines"], 2)
        self.assertEqual(self.upstream.received[-1]["model"], dr.OLLAMA_DEFAULT_MODEL)
        self.assertNotIn("authorization", {k.lower() for k in self.upstream.headers[-1]})
        out_dir = Path(receipt["receipt_path"]).parent
        child = json.loads((out_dir / "child.json").read_text())
        self.assertEqual(child["statuses"], [200, 200])
        self.assertNotIn("OPENAI_ORG_ID", child["env_names"])
        self.assertNotIn("ANTHROPIC_API_KEY", child["env_names"])
        self.assertEqual(Path(child["cwd"]).resolve(), (out_dir / "cwd").resolve())
        self.assertIn("plumbing dry run", receipt["fidelity_label"])

    def test_paid_mode_keeps_key_in_guard(self) -> None:
        config = self.make_config(["{python}", str(self.dir / "child.py"), "1"])
        lab_env = self.dir / "lab.env"
        lab_env.write_text(f"GROQ_API_KEY=gsk-x\nDEEPSEEK_API_KEY={FAKE_KEY}\n", encoding="utf-8")
        receipt = dr.run_stage(self.request(config, lab_env=lab_env, deepseek_url_override=self.upstream.url))
        self.assertEqual(receipt["status"], "completed", receipt)
        out_dir = Path(receipt["receipt_path"]).parent
        child = json.loads((out_dir / "child.json").read_text())
        self.assertFalse(child["env_blob_has_key"])
        auth = {k.lower(): v for k, v in self.upstream.headers[-1].items()}["authorization"]
        self.assertEqual(auth, f"Bearer {FAKE_KEY}")
        for name in ("receipt.json", "ledger.jsonl", "child_stdout.txt", "child_stderr.txt"):
            self.assertNotIn(FAKE_KEY, (out_dir / name).read_text(encoding="utf-8", errors="replace"))
        self.assertIn("backbone-substituted", receipt["fidelity_label"])

    def test_halt_kills_runaway_child(self) -> None:
        config = self.make_config(["{python}", str(self.dir / "child.py"), "1000"])
        receipt = dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url,
                                            cap_requests=3))
        self.assertEqual(receipt["status"], "halted")
        self.assertEqual(receipt["exit_code"], 3)
        self.assertEqual(receipt["guard"]["requests_forwarded"], 3)
        self.assertEqual(len(self.upstream.received), 3)

    def test_runaway_child_is_killed(self) -> None:
        script = self.dir / "forever.py"
        script.write_text(textwrap.dedent(
            """
            import json, os, time, urllib.error, urllib.request
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while True:  # ignores 402 refusals on purpose
                req = urllib.request.Request(os.environ["OPENAI_BASE_URL"] + "/chat/completions",
                    data=json.dumps({"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]}).encode(),
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]}, method="POST")
                try:
                    opener.open(req, timeout=30).close()
                except urllib.error.HTTPError:
                    pass
                time.sleep(0.05)
            """), encoding="utf-8")
        config = self.make_config(["{python}", str(script), "0"])
        receipt = dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url,
                                            cap_requests=2, timeout_seconds=60))
        self.assertEqual(receipt["status"], "halted")
        self.assertNotEqual(receipt["child_returncode"], 0)
        self.assertEqual(len(self.upstream.received), 2)
        self.assertLess(receipt["duration_seconds"], 30)

    def test_exact_cap_lets_child_finish(self) -> None:
        script = self.dir / "exact.py"
        script.write_text(CHILD.replace("open(os.path.join", "__import__('time').sleep(1.5)\nopen(os.path.join"),
                          encoding="utf-8")
        config = self.make_config(["{python}", str(script), "3"])
        receipt = dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url,
                                            cap_requests=3))
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["guard"]["halt_reason"], "request_cap_reached")
        self.assertFalse(receipt["guard"]["stop_child"])
        self.assertTrue((Path(receipt["receipt_path"]).parent / "child.json").exists())

    def test_refusals(self) -> None:
        config = self.make_config(["{python}", str(self.dir / "child.py"), "1"], dry_run_cap_requests=2)
        with self.assertRaises(dr.RouteError):  # above the stage ceiling
            dr.run_stage(self.request(config, cap_usd=Decimal("2"), dry_run_ollama=True))
        with self.assertRaises(dr.RouteError):  # paid mode without a lab env
            dr.run_stage(self.request(config))
        with self.assertRaises(dr.RouteError):  # output inside the code repository
            dr.run_stage(self.request(config, dry_run_ollama=True, out_root=COMMON / "out"))
        with self.assertRaises(dr.RouteError):  # dry runs only go to loopback
            dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url="https://api.openai.com/v1"))
        with self.assertRaises(dr.RouteError):  # .env on the scratch path
            (self.dir / ".env").write_text("X=1\n", encoding="utf-8")
            try:
                dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url))
            finally:
                (self.dir / ".env").unlink()
        self.assertEqual(self.upstream.received, [])

    def test_stage_config_rejects_credentials(self) -> None:
        config = self.make_config(["{python}"], env={"SOME_API_KEY": "sk-literal"})
        with self.assertRaises(dr.RouteError):
            dr.load_stage(config, "s1")
        config = self.make_config(["{python}"], env={"OPENAI_BASE_URL": "https://api.openai.com/v1"})
        with self.assertRaises(dr.RouteError):
            dr.load_stage(config, "s1")
        config = self.make_config(["{python}"], env={"SOME_API_KEY": "{guard_token}", "OPENAI_MODEL": "x"})
        dr.load_stage(config, "s1")

    def test_metadata_keys_ignored_but_typos_refused(self) -> None:
        config = self.make_config(["{python}"], purpose="notes", expected_counts={"a": 1})
        merged, _ = dr.load_stage(config, "s1")
        self.assertEqual(merged["_ignored_keys"], ["expected_counts", "purpose"])
        for typo in ({"cap_usd_max": 1}, {"model_alias": ["x"]}, {"max_tokens_ceil": 9}, {"dry_run_caps": 2}):
            config = self.make_config(["{python}"], **typo)
            with self.assertRaises(dr.RouteError, msg=str(typo)):
                dr.load_stage(config, "s1")

    def test_plan_only_reads_no_key(self) -> None:
        config = self.make_config(["{python}", "{unknown_placeholder}"])
        with self.assertRaises(dr.RouteError):
            dr.run_stage(self.request(config, plan_only=True))
        result = dr.run_stage(self.request(config, plan_only=True, extra_values={"unknown_placeholder": "v"}))
        self.assertEqual(result["plan"]["argv"][-1], "v")
        self.assertFalse((self.dir / "out").exists())


class TrackedStageTests(GuardTestCase):
    """The stage files actually tracked next to this module (RUN-PLAN-DEEPSEEK.md)."""

    def test_every_adapter_stage_file_loads(self) -> None:
        files = sorted(dr.ADAPTERS_DIR.glob("*/stages.json"))
        self.assertIn("common", [path.parent.name for path in files])
        for path in files:
            config = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(config.get("artifact"), path.parent.name, path)
            for stage in config["stages"]:
                merged, _ = dr.load_stage(path, stage)
                self.assertLessEqual(int(merged.get("max_tokens_default", 2048)),
                                     int(merged.get("max_tokens_ceiling", 4096)), f"{path} {stage}")

    def test_s0_key_sends_exactly_one_one_token_request(self) -> None:
        lab_env = self.dir / "lab.env"
        lab_env.write_text(f"DEEPSEEK_API_KEY={FAKE_KEY}\n", encoding="utf-8")
        self.upstream.usage = {"prompt_tokens": 26, "completion_tokens": 1, "total_tokens": 27}
        receipt = dr.run_stage(dr.StageRequest(
            artifact="common", stage="s0-key", cap_usd=Decimal("0.001"), cap_tokens=500,
            out_root=self.dir / "out", lab_env=lab_env, deepseek_url_override=self.upstream.url, grace_seconds=0.5,
        ))
        self.assertEqual((receipt["status"], receipt["exit_code"]), ("completed", 0), receipt)
        self.assertEqual(len(self.upstream.received), 1)
        sent = self.upstream.received[0]
        self.assertEqual((sent["model"], sent["max_tokens"], sent["thinking"]),
                         (dr.DEEPSEEK_MODEL, 1, {"type": "disabled"}))
        self.assertEqual(receipt["guard"]["requests_forwarded"], 1)
        self.assertEqual(receipt["guard"]["halt_reason"], "request_cap_reached")
        self.assertFalse(receipt["guard"]["stop_child"])
        out_dir = Path(receipt["receipt_path"]).parent
        (row,) = [json.loads(line) for line in (out_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual((row["usage_source"], row["max_tokens"], row["max_tokens_clamped"]), ("provider", 1, True))
        for name in ("receipt.json", "ledger.jsonl", "canary.json", "child_stdout.txt", "child_stderr.txt"):
            self.assertNotIn(FAKE_KEY, (out_dir / name).read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
