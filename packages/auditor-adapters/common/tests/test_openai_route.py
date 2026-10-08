"""Unit tests for the OpenAI provider of the shared guard.  Every upstream is a loopback fake.

Run: python -m unittest discover -s packages/auditor-adapters/common/tests -v

Covers: the exact-model allowlist, no model rewrite, logprobs pass-through, embeddings
accounting, caps, key isolation, provider-mismatch refusals, the tracked OpenAI stages,
and a DeepSeek regression pin (test_deepseek_route.py is unchanged and still runs).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMMON))

import deepseek_route as dr  # noqa: E402

OPENAI_KEY = "sk-openai-test-0123456789abcdef"
DEEPSEEK_KEY = "sk-deepseek-test-fedcba9876543210"
SENTINEL = "SENTINEL-OPENAI-PROMPT-91c2"
MINI = "gpt-4o-mini-2024-07-18"
GPT41 = "gpt-4.1-mini-2025-04-14"
GPT4O = "gpt-4o-2024-05-13"
EMBED = "text-embedding-3-large"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
LOGPROBS = {"content": [{"token": "yes", "logprob": -0.01, "bytes": [121, 101, 115],
                         "top_logprobs": [{"token": "yes", "logprob": -0.01, "bytes": [121, 101, 115]},
                                          {"token": "no", "logprob": -4.6, "bytes": [110, 111]}]}],
            "refusal": None}


class FakeOpenAI:
    """Loopback stand-in for api.openai.com/v1 (chat completions and embeddings)."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        self.raw: list[bytes] = []
        self.paths: list[str] = []
        self.headers: list[dict] = []
        self.status = 200
        self.usage: dict | None = {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100,
                                   "prompt_tokens_details": {"cached_tokens": 0},
                                   "completion_tokens_details": {"reasoning_tokens": 0}}
        self.embedding_usage: dict | None = {"prompt_tokens": 7, "total_tokens": 7}
        self.service_tier: str | None = "default"
        self.model_override: str | None = None
        # Optional per-request rejection (HTTP 400), e.g. a model that refuses a field.
        self.reject = None
        self.last_payload: bytes = b""
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):  # noqa: D401
                return

            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                body = json.loads(raw)
                outer.raw.append(raw)
                outer.received.append(body)
                outer.paths.append(self.path)
                outer.headers.append({k.lower(): v for k, v in self.headers.items()})
                if outer.status != 200:
                    return self._send(outer.status, json.dumps({"error": {"message": "fake"}}).encode())
                if outer.reject is not None and outer.reject(body):
                    return self._send(400, json.dumps({"error": {"message": "fake: unsupported parameter",
                                                                 "code": "unsupported_parameter"}}).encode())
                model = outer.model_override or body.get("model")
                if self.path.endswith("/embeddings"):
                    inputs = body["input"] if isinstance(body["input"], list) else [body["input"]]
                    payload = {"object": "list", "model": model,
                               "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]}
                                        for i in range(len(inputs))]}
                    if outer.embedding_usage is not None:
                        payload["usage"] = outer.embedding_usage
                    return self._send(200, json.dumps(payload).encode())
                choice = {"index": 0, "finish_reason": "stop", "logprobs": None,
                          "message": {"role": "assistant", "content": "pong", "refusal": None}}
                if body.get("tools"):
                    choice["finish_reason"] = "tool_calls"
                    choice["message"] = {"role": "assistant", "content": None, "tool_calls": [
                        {"id": "call_1", "type": "function",
                         "function": {"name": body["tools"][0]["function"]["name"], "arguments": "{\"account_id\": 42}"}}]}
                if body.get("logprobs"):
                    choice["logprobs"] = LOGPROBS
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    chunks = [
                        {"id": "chatcmpl-s", "model": model, "service_tier": outer.service_tier,
                         "choices": [{"index": 0, "delta": {"content": "po"}, "logprobs": choice["logprobs"]}]},
                        {"id": "chatcmpl-s", "model": model, "service_tier": outer.service_tier,
                         "choices": [{"index": 0, "delta": {"content": "ng"}, "finish_reason": "stop"}]},
                        {"id": "chatcmpl-s", "model": model, "choices": [], "usage": outer.usage},
                    ]
                    for chunk in chunks:
                        self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                    self.wfile.write(b"data: [DONE]\n\n")
                    return
                payload = {"id": f"chatcmpl-{len(outer.received)}", "object": "chat.completion", "model": model,
                           "service_tier": outer.service_tier, "choices": [choice]}
                if outer.usage is not None:
                    payload["usage"] = outer.usage
                data = json.dumps(payload).encode()
                outer.last_payload = data
                self._send(200, data)

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


def chat(model: str = MINI, **extra) -> dict:
    return {"model": model, "messages": [{"role": "user", "content": SENTINEL}], **extra}


def specs(*models: str) -> dict[str, dr.ModelSpec]:
    return dr.provider_models(dr.load_providers(), "openai", models)


class OpenAIGuardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.upstream = FakeOpenAI()
        self.guards: list[dr.BudgetGuard] = []

    def tearDown(self) -> None:
        for guard in self.guards:
            guard.stop()
        self.upstream.close()
        self.tmp.cleanup()

    def guard(self, models: tuple[str, ...] = (MINI, EMBED), **overrides) -> dr.BudgetGuard:
        settings = dict(
            stage_id="test/openai",
            ledger_path=self.dir / f"ledger{len(self.guards)}.jsonl",
            cap_usd=Decimal("1"),
            cap_tokens=1_000_000,
            upstream="openai",
            upstream_base_url=self.upstream.url,
            upstream_model="",
            request_model=models[0],
            api_key=OPENAI_KEY,
            max_tokens_default=256,
            max_tokens_ceiling=1024,
            models=specs(*models),
        )
        settings.update(overrides)
        guard = dr.BudgetGuard(dr.GuardConfig(**settings))
        guard.start()
        self.guards.append(guard)
        return guard

    def ledger(self, guard: dr.BudgetGuard) -> list[dict]:
        return [json.loads(line) for line in guard.config.ledger_path.read_text(encoding="utf-8").splitlines()]


class ProviderTableTests(unittest.TestCase):
    def test_table_loads_and_mirrors_deepseek_constants(self) -> None:
        table = dr.load_providers()
        deepseek = table["providers"]["deepseek"]
        self.assertEqual((deepseek["base_url"], deepseek["key_env"], deepseek["upstream_model"]),
                         (dr.DEEPSEEK_BASE_URL, dr.DEEPSEEK_KEY_ENV, dr.DEEPSEEK_MODEL))
        openai_entry = table["providers"]["openai"]
        self.assertEqual((openai_entry["base_url"], openai_entry["key_env"]), (dr.OPENAI_BASE_URL, dr.OPENAI_KEY_ENV))
        pricing = openai_entry["pricing"]
        self.assertEqual(pricing["fetched"], "2026-10-08")
        self.assertIn("https://developers.openai.com/api/docs/pricing", pricing["sources"])
        for name, entry in openai_entry["models"].items():
            self.assertTrue(entry.get("price_basis"), name)
            self.assertNotIn(name, ("gpt-4o-mini", "gpt-4.1-mini", "gpt-4o", "gpt-5.2"), "aliases must stay out")

    def test_prices_and_cached_policy(self) -> None:
        got = specs(MINI, GPT41, GPT4O, "gpt-5.2-2025-12-11", EMBED)
        self.assertEqual(got[GPT4O].price.cached_input_per_million, None)  # no cached price listed
        self.assertEqual(got[EMBED].kind, "embedding")
        self.assertEqual(got[EMBED].price.output_per_million, Decimal(0))
        # 1M prompt tokens, 400k cached: cached tokens use the listed cached price, else the input price
        self.assertEqual(got[MINI].price.cost_with_cache(1_000_000, 400_000, 0), Decimal("0.12"))
        self.assertEqual(got[GPT4O].price.cost_with_cache(1_000_000, 400_000, 0), Decimal("5"))

    def test_drift_and_unpriced_models_are_refused(self) -> None:
        table = json.loads(dr.PROVIDERS_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            drifted = json.loads(json.dumps(table))
            drifted["providers"]["deepseek"]["price_snapshot"]["input_per_million"] = "0.10"
            path.write_text(json.dumps(drifted), encoding="utf-8")
            with self.assertRaises(dr.RouteError):
                dr.load_providers(path)
        unpriced = json.loads(json.dumps(table))
        unpriced["providers"]["openai"]["models"][GPT41]["input_per_million"] = None
        with self.assertRaises(dr.RouteError) as ctx:
            dr.provider_models(unpriced, "openai", [GPT41])
        self.assertIn("refuse", str(ctx.exception))
        for unknown in ("gpt-4o-mini", "deepseek-flash", "gpt-5.5"):
            with self.assertRaises(dr.RouteError, msg=unknown):
                dr.provider_models(table, "openai", [unknown])


class AllowlistAndRewriteTests(OpenAIGuardCase):
    def test_exact_ids_only_and_never_rewritten(self) -> None:
        guard = self.guard(models=(MINI, GPT41, EMBED))
        token = guard.config.client_token
        for model in (MINI, GPT41):
            status, payload = post(guard.base_url, token, chat(model))
            self.assertEqual(status, 200, payload)
            self.assertEqual(self.upstream.received[-1]["model"], model)
        refused = ["gpt-4o-mini", "gpt-4.1-mini", GPT4O, "deepseek-flash", EMBED, ""]
        before = len(self.upstream.received)
        for model in refused:
            status, payload = post(guard.base_url, token, chat(model))
            self.assertEqual(status, 400, model)
            self.assertIn(b"model_not_allowed", payload)
        status, payload = post(guard.base_url, token, {"model": MINI, "input": ["a"]}, path="/embeddings")
        self.assertEqual(status, 400)  # a chat model on the embeddings endpoint
        self.assertEqual(len(self.upstream.received), before)
        rows = self.ledger(guard)
        self.assertEqual([r["outcome"] for r in rows].count("refused"), len(refused) + 1)
        ok = [r for r in rows if r["outcome"] == "ok"]
        self.assertEqual([(r["requested_model"], r["upstream_model"], r["response_model_matches"]) for r in ok],
                         [(MINI, MINI, True), (GPT41, GPT41, True)])

    def test_wire_passes_through_unchanged(self) -> None:
        guard = self.guard()
        body = {
            "model": MINI,
            "messages": [
                {"role": "developer", "content": SENTINEL},
                {"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
                {"role": "tool", "name": "f", "tool_call_id": "c1", "content": "r é"},
            ],
            "parallel_tool_calls": False,
            "reasoning_effort": "low",
            "store": False,
            "metadata": {"k": "v"},
            "temperature": 0.0,
            "service_tier": "default",
            "max_completion_tokens": 100,
        }
        status, payload = post(guard.base_url, guard.config.client_token, body)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload, self.upstream.last_payload)  # the response is relayed byte for byte
        sent = self.upstream.received[-1]
        self.assertEqual(sent, body)  # nothing added, dropped, renamed or normalised
        self.assertNotIn("thinking", sent)
        self.assertEqual(self.upstream.paths[-1], "/v1/chat/completions")
        auth = self.upstream.headers[-1]["authorization"]
        self.assertEqual(auth, f"Bearer {OPENAI_KEY}")
        self.assertNotIn("openai-organization", self.upstream.headers[-1])
        row = self.ledger(guard)[0]
        self.assertEqual((row["max_tokens_field"], row["max_tokens"], row["max_tokens_clamped"]),
                         ("max_completion_tokens", 100, False))
        self.assertEqual((row["reasoning_effort"], row["service_tier"], row["dropped_fields"]), ("low", "default", []))
        raw = guard.config.ledger_path.read_text(encoding="utf-8")
        for secret in (SENTINEL, OPENAI_KEY, guard.config.client_token):
            self.assertNotIn(secret, raw)

    def test_output_limit_fields_are_clamped_not_renamed(self) -> None:
        guard = self.guard()
        token = guard.config.client_token
        post(guard.base_url, token, chat(max_tokens=5000))
        self.assertEqual(self.upstream.received[-1]["max_tokens"], 1024)
        self.assertNotIn("max_completion_tokens", self.upstream.received[-1])
        post(guard.base_url, token, chat(max_completion_tokens=5000))
        self.assertEqual(self.upstream.received[-1]["max_completion_tokens"], 1024)
        self.assertNotIn("max_tokens", self.upstream.received[-1])
        post(guard.base_url, token, chat(max_tokens=10, max_completion_tokens=5000))
        self.assertEqual((self.upstream.received[-1]["max_tokens"], self.upstream.received[-1]["max_completion_tokens"]),
                         (10, 1024))
        post(guard.base_url, token, chat())
        self.assertEqual(self.upstream.received[-1]["max_completion_tokens"], 256)  # stage default added
        rows = self.ledger(guard)
        self.assertEqual([(r["max_tokens_field"], r["max_tokens"], r["max_tokens_clamped"]) for r in rows],
                         [("max_tokens", 1024, True), ("max_completion_tokens", 1024, True), ("both", 1024, True),
                          ("default:max_completion_tokens", 256, False)])
        for bad in (dict(max_tokens=0), dict(max_completion_tokens="9"), dict(max_tokens=True), dict(n=9)):
            self.assertEqual(post(guard.base_url, token, chat(**bad))[0], 400, bad)
        self.assertEqual(len(self.upstream.received), 4)

    def test_refused_fields(self) -> None:
        guard = self.guard()
        token = guard.config.client_token
        for extra in (dict(thinking={"type": "disabled"}), dict(service_tier="priority"), dict(service_tier="flex"),
                      dict(service_tier="auto"), dict(audio={"voice": "x"}), dict(modalities=["text", "audio"]),
                      dict(web_search_options={}), dict(prediction={"type": "content", "content": "x"})):
            status, payload = post(guard.base_url, token, chat(**extra))
            self.assertEqual(status, 400, extra)
        self.assertEqual(self.upstream.received, [])
        self.assertEqual(post(guard.base_url, token, chat(modalities=["text"]))[0], 200)

    def test_models_endpoint_lists_the_allowlist(self) -> None:
        guard = self.guard(models=(GPT41, EMBED))
        request = urllib.request.Request(guard.base_url + "/models",
                                         headers={"Authorization": f"Bearer {guard.config.client_token}"})
        with OPENER.open(request, timeout=10) as response:
            ids = [m["id"] for m in json.loads(response.read())["data"]]
        self.assertEqual(ids, [GPT41, EMBED])
        self.assertEqual(self.upstream.received, [])


class LogprobsTests(OpenAIGuardCase):
    def test_logprobs_pass_through(self) -> None:
        guard = self.guard(models=(GPT41,))
        body = chat(GPT41, logprobs=True, top_logprobs=5, max_completion_tokens=4, temperature=0.2, top_p=0.9)
        status, payload = post(guard.base_url, guard.config.client_token, body)
        self.assertEqual(status, 200)
        sent = self.upstream.received[-1]
        self.assertEqual((sent["logprobs"], sent["top_logprobs"]), (True, 5))
        self.assertEqual(json.loads(payload)["choices"][0]["logprobs"], LOGPROBS)
        row = self.ledger(guard)[0]
        self.assertEqual((row["logprobs"], row["top_logprobs"], row["logprobs_returned"]), (True, 5, True))
        self.assertEqual(guard.summary()["logprobs_responses"], 1)

    def test_logprobs_validation_and_streaming(self) -> None:
        guard = self.guard()
        token = guard.config.client_token
        for bad in (dict(logprobs="yes"), dict(logprobs=True, top_logprobs=21), dict(logprobs=True, top_logprobs=-1)):
            self.assertEqual(post(guard.base_url, token, chat(**bad))[0], 400, bad)
        self.assertEqual(self.upstream.received, [])
        status, payload = post(guard.base_url, token, chat(logprobs=True, top_logprobs=0, stream=True))
        self.assertEqual(status, 200)
        self.assertIn(b'"top_logprobs"', payload)
        self.assertEqual(self.upstream.received[-1]["stream_options"], {"include_usage": True})
        row = self.ledger(guard)[-1]
        self.assertEqual((row["logprobs_returned"], row["usage_source"], row["response_model"]), (True, "provider", MINI))


class EmbeddingsTests(OpenAIGuardCase):
    def test_embeddings_forwarded_and_charged(self) -> None:
        guard = self.guard(models=(GPT4O, EMBED))
        self.upstream.embedding_usage = {"prompt_tokens": 1_000_000, "total_tokens": 1_000_000}
        body = {"model": EMBED, "input": ["send_email(recipients = ['a@example.com'])", "get_balance()"],
                "encoding_format": "float"}
        status, payload = post(guard.base_url, guard.config.client_token, body, path="/embeddings")
        self.assertEqual(status, 200, payload)
        self.assertEqual(self.upstream.paths[-1], "/v1/embeddings")
        self.assertEqual(self.upstream.received[-1], body)
        self.assertEqual(self.upstream.headers[-1]["authorization"], f"Bearer {OPENAI_KEY}")
        self.assertEqual(len(json.loads(payload)["data"]), 2)
        row = self.ledger(guard)[0]
        self.assertEqual((row["endpoint"], row["inputs"], row["prompt_tokens"], row["completion_tokens"]),
                         ("embeddings", 2, 1_000_000, 0))
        self.assertEqual((row["usd"], row["counts_toward_caps"], row["usage_source"]), ("0.13000000", True, "provider"))
        summary = guard.summary()
        self.assertEqual((summary["embedding_requests"], summary["embedding_prompt_tokens"], summary["usd"]),
                         (1, 1_000_000, "0.13000000"))
        self.assertEqual(summary["requests_forwarded"], 1)

    def test_embeddings_count_toward_caps(self) -> None:
        guard = self.guard(models=(MINI, EMBED), cap_tokens=60, cap_requests=5)
        token = guard.config.client_token
        self.upstream.embedding_usage = {"prompt_tokens": 50, "total_tokens": 50}
        self.assertEqual(post(guard.base_url, token, {"model": EMBED, "input": "x"}, path="/embeddings")[0], 200)
        status, payload = post(guard.base_url, token, {"model": EMBED, "input": "y" * 40}, path="/embeddings")
        self.assertEqual(status, 402)
        self.assertIn(b"token_cap", payload)
        self.assertEqual(guard.halt_reason, "token_cap_preflight")
        self.assertEqual(len(self.upstream.received), 1)

    def test_embeddings_without_usage_charge_the_estimate_and_halt(self) -> None:
        guard = self.guard()
        self.upstream.embedding_usage = None
        self.assertEqual(post(guard.base_url, guard.config.client_token, {"model": EMBED, "input": ["a"]},
                              path="/embeddings")[0], 200)
        row = self.ledger(guard)[0]
        self.assertEqual(row["usage_source"], "estimate")
        self.assertGreater(row["prompt_tokens"], 0)
        self.assertEqual(guard.halt_reason, "usage_missing")
        self.assertTrue(guard.stop_child)

    def test_empty_or_invalid_embeddings_requests(self) -> None:
        guard = self.guard()
        token = guard.config.client_token
        for body in ({"model": EMBED, "input": []}, {"model": EMBED}, {"model": "text-embedding-3-small", "input": "a"},
                     b"[1, 2]"):
            self.assertEqual(post(guard.base_url, token, body, path="/embeddings")[0], 400, body)
        self.assertEqual(self.upstream.received, [])


class CapTests(OpenAIGuardCase):
    def test_cached_tokens_priced_per_model(self) -> None:
        self.upstream.usage = {"prompt_tokens": 1_000_000, "completion_tokens": 0,
                               "prompt_tokens_details": {"cached_tokens": 600_000},
                               "completion_tokens_details": {"reasoning_tokens": 0}}
        cheap = self.guard(models=(MINI,), max_tokens_default=8, max_tokens_ceiling=8)
        post(cheap.base_url, cheap.config.client_token, chat())
        row = self.ledger(cheap)[0]
        # 400k x 0.15 + 600k x 0.075 = 0.105; uncached basis 0.15
        self.assertEqual((row["usd"], row["usd_uncached_basis"], row["cached_tokens"]),
                         ("0.10500000", "0.15000000", 600_000))
        dear = self.guard(models=(GPT4O,), max_tokens_default=8, max_tokens_ceiling=8, cap_usd=Decimal("20"))
        post(dear.base_url, dear.config.client_token, chat(GPT4O))
        row = self.ledger(dear)[0]
        self.assertEqual((row["usd"], row["usd_uncached_basis"]), ("5.00000000", "5.00000000"))  # no cached price
        self.assertEqual(dear.summary()["cached_tokens"], 600_000)

    def test_usd_cap_reached_and_preflight_uses_model_price(self) -> None:
        self.upstream.usage = {"prompt_tokens": 100_000, "completion_tokens": 10_000}
        guard = self.guard(models=(GPT41,), cap_usd=Decimal("0.10"), max_tokens_default=16, max_tokens_ceiling=16)
        token = guard.config.client_token
        self.assertEqual(post(guard.base_url, token, chat(GPT41))[0], 200)  # 0.04 + 0.016 = 0.056
        self.assertFalse(guard.halted)
        self.assertEqual(post(guard.base_url, token, chat(GPT41))[0], 200)  # 0.112: reached
        self.assertEqual(guard.halt_reason, "usd_cap_reached")
        self.assertEqual(post(guard.base_url, token, chat(GPT41))[0], 402)
        self.assertEqual(len(self.upstream.received), 2)
        self.assertEqual(guard.summary()["usd"], "0.11200000")
        # same request, same cap: the cheap model passes pre-flight, the expensive one does not
        cheap = self.guard(models=(MINI,), cap_usd=Decimal("0.001"), max_tokens_ceiling=1024)
        big = chat(MINI, max_tokens=1024, messages=[{"role": "user", "content": "x" * 3000}])
        self.assertEqual(post(cheap.base_url, cheap.config.client_token, big)[0], 200)
        dear = self.guard(models=(GPT4O,), cap_usd=Decimal("0.001"), max_tokens_ceiling=1024)
        status, payload = post(dear.base_url, dear.config.client_token, {**big, "model": GPT4O})
        self.assertEqual(status, 402)
        self.assertIn(b"usd_cap", payload)

    def test_request_cap_counts_chat_and_embeddings(self) -> None:
        guard = self.guard(cap_requests=2)
        token = guard.config.client_token
        self.assertEqual(post(guard.base_url, token, chat())[0], 200)
        self.assertEqual(post(guard.base_url, token, {"model": EMBED, "input": "a"}, path="/embeddings")[0], 200)
        self.assertEqual(guard.halt_reason, "request_cap_reached")
        self.assertEqual(post(guard.base_url, token, chat())[0], 402)
        self.assertEqual(len(self.upstream.received), 2)

    def test_non_standard_service_tier_in_response_halts(self) -> None:
        self.upstream.service_tier = "priority"
        guard = self.guard()
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat())[0], 200)
        self.assertEqual(guard.halt_reason, "service_tier_priority")
        self.assertTrue(guard.stop_child)
        self.assertEqual(post(guard.base_url, guard.config.client_token, chat())[0], 402)

    def test_response_model_mismatch_is_flagged(self) -> None:
        self.upstream.model_override = "gpt-4o-mini-2099-01-01"
        guard = self.guard()
        post(guard.base_url, guard.config.client_token, chat())
        row = self.ledger(guard)[0]
        self.assertEqual((row["response_model"], row["response_model_matches"]), ("gpt-4o-mini-2099-01-01", False))
        self.assertEqual(guard.summary()["response_model_mismatches"], 1)

    def test_missing_usage_and_upstream_auth_failure(self) -> None:
        self.upstream.usage = None
        guard = self.guard(max_tokens_default=10, max_tokens_ceiling=10)
        post(guard.base_url, guard.config.client_token, chat())
        self.assertEqual((self.ledger(guard)[0]["usage_source"], guard.halt_reason), ("estimate", "usage_missing"))
        self.upstream.status = 401
        other = self.guard()
        self.assertEqual(post(other.base_url, other.config.client_token, chat())[0], 401)
        self.assertEqual(other.halt_reason, "upstream_http_401")
        self.assertEqual(self.ledger(other)[0]["usd"], "0.00000000")
        summary = other.summary()
        self.assertEqual(summary["upstream_error_responses"], 1)  # charged 0, counted for reconciliation
        self.assertIn("UNVERIFIED", summary["upstream_error_billing"])

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


class ProviderMismatchTests(unittest.TestCase):
    def config(self, **overrides) -> dr.GuardConfig:
        settings = dict(stage_id="s", ledger_path=Path("unused.jsonl"), cap_usd=Decimal("1"), cap_tokens=10,
                        upstream="openai", upstream_base_url=dr.OPENAI_BASE_URL, upstream_model="",
                        request_model=MINI, api_key=OPENAI_KEY, models=specs(MINI, EMBED))
        settings.update(overrides)
        return dr.GuardConfig(**settings)

    def test_guard_config_refusals(self) -> None:
        self.config().validate()
        with self.assertRaises(dr.RouteError):  # GuardConfig's default base URL is DeepSeek's: refused for openai
            dr.GuardConfig(stage_id="s", ledger_path=Path("unused.jsonl"), cap_usd=Decimal("1"), cap_tokens=10,
                           upstream="openai", request_model=MINI, api_key=OPENAI_KEY, models=specs(MINI)).validate()
        self.config(upstream_base_url="http://127.0.0.1:1/v1").validate()
        for bad in (
            dict(upstream_base_url=dr.DEEPSEEK_BASE_URL),
            dict(upstream_base_url="https://example.com/v1"),
            dict(api_key=None),
            dict(models={}),
            dict(model_aliases=("gpt-4o-mini",)),
            dict(request_model=GPT41),
            dict(request_model="deepseek-flash"),
            dict(embeddings_base_url="http://127.0.0.1:11434/v1", embeddings_model="nomic-embed-text"),
            dict(upstream="deepseek", upstream_base_url=dr.DEEPSEEK_BASE_URL, upstream_model=dr.DEEPSEEK_MODEL,
                 request_model=dr.DEEPSEEK_MODEL),  # a DeepSeek guard may not carry an OpenAI allowlist
            dict(upstream="anthropic"),
        ):
            with self.assertRaises(dr.RouteError, msg=str(bad)):
                self.config(**bad).validate()

    def test_repr_hides_secrets(self) -> None:
        config = self.config()
        self.assertNotIn(OPENAI_KEY, repr(config))
        self.assertNotIn(config.client_token, repr(config))


class StageAndRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.upstream = FakeOpenAI()

    def tearDown(self) -> None:
        self.upstream.close()
        self.tmp.cleanup()

    def stage_file(self, section: str = dr.PROVIDER_STAGES_SECTION, **stage) -> Path:
        body = {"argv": ["{python}", "-c", "pass"], "cap_usd": 1, "cap_tokens": 100000, "provider": "openai",
                "models": [MINI], "request_model": MINI, "dry_run_allowed": False, **stage}
        config = {
            "schema": dr.SCHEMA_STAGES,
            "artifact": "fake",
            "defaults": {"timeout_seconds": 60, "max_tokens_default": 16, "max_tokens_ceiling": 16},
            "stages": {"s0": {"argv": ["{python}"], "cap_usd": 1, "cap_tokens": 10}},
        }
        config.setdefault(section, {})["s1"] = body
        path = self.dir / f"stages{len(list(self.dir.glob('stages*.json')))}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def lab_env(self, text: str | None = None) -> Path:
        path = self.dir / "lab.env"
        path.write_text(text or f"DEEPSEEK_API_KEY={DEEPSEEK_KEY}\nOPENAI_API_KEY={OPENAI_KEY}\n", encoding="utf-8")
        return path

    def request(self, config: Path, **overrides) -> dr.StageRequest:
        settings = dict(artifact="fake", stage="s1", cap_usd=Decimal("0.5"), cap_tokens=50_000,
                        out_root=self.dir / "out", config_path=config, grace_seconds=0.5)
        settings.update(overrides)
        return dr.StageRequest(**settings)

    def test_stage_level_provider_refusals(self) -> None:
        dr.load_stage(self.stage_file(), "s1")
        for bad in (
            dict(provider="anthropic"),
            dict(provider=["openai", "deepseek"]),
            dict(models=["deepseek-flash"], request_model="deepseek-flash"),
            dict(models=["gpt-4o-mini"], request_model="gpt-4o-mini"),
            dict(models=[MINI, MINI]),
            dict(models=[]),
            dict(request_model=GPT41),
            dict(models=[EMBED], request_model=EMBED),
            dict(model_aliases=["gpt-4o-mini"]),
            dict(local_embeddings={"base_url": "http://127.0.0.1:11434/v1", "model": "nomic-embed-text"}),
            dict(dry_run_allowed=True),
            dict(blocked=""),
            dict(model=MINI),  # typo of a safety key
            dict(provider=None),  # provider_stages must name their provider
            dict(provider="deepseek", request_model="deepseek-flash"),
        ):
            with self.assertRaises(dr.RouteError, msg=str(bad)):
                dr.load_stage(self.stage_file(**bad), "s1")
        with self.assertRaises(dr.RouteError):  # an OpenAI stage under "stages" would run as DeepSeek on old runners
            dr.load_stage(self.stage_file(section="stages"), "s1")
        with self.assertRaises(dr.RouteError):  # DeepSeek stages cannot declare an OpenAI allowlist
            dr.load_stage(self.stage_file(section="stages", provider="deepseek", request_model="deepseek-flash"), "s1")
        path = self.stage_file()
        config = json.loads(path.read_text(encoding="utf-8"))
        config["stages"]["s1"] = config["stages"]["s0"]
        path.write_text(json.dumps(config), encoding="utf-8")
        with self.assertRaises(dr.RouteError):  # one name in both sections
            dr.load_stage(path, "s0")
        # The DeepSeek stage of the same file is unaffected by its provider_stages neighbour.
        merged, _ = dr.load_stage(self.stage_file(), "s0")
        self.assertNotIn("provider", merged)

    def test_runner_refusals_send_nothing(self) -> None:
        config = self.stage_file()
        lab_env = self.lab_env()
        with self.assertRaises(dr.RouteError):  # no Ollama dry run for an OpenAI stage
            dr.run_stage(self.request(config, dry_run_ollama=True, ollama_url=self.upstream.url))
        with self.assertRaises(dr.RouteError):  # the DeepSeek test hook cannot redirect an OpenAI stage
            dr.run_stage(self.request(config, lab_env=lab_env, deepseek_url_override=self.upstream.url))
        with self.assertRaises(dr.RouteError):  # the OpenAI test hook is loopback only
            dr.run_stage(self.request(config, lab_env=lab_env, upstream_url_override="https://api.deepseek.com"))
        with self.assertRaises(dr.RouteError) as ctx:  # only the DeepSeek key: no fallback to DeepSeek
            dr.run_stage(self.request(config, lab_env=self.lab_env(f"DEEPSEEK_API_KEY={DEEPSEEK_KEY}\n"),
                                      upstream_url_override=self.upstream.url))
        self.assertIn("OPENAI_API_KEY", str(ctx.exception))
        self.assertNotIn(DEEPSEEK_KEY, str(ctx.exception))
        blocked = self.stage_file(blocked="adapter not ready")
        with self.assertRaises(dr.RouteError) as ctx:
            dr.run_stage(self.request(blocked, lab_env=lab_env, upstream_url_override=self.upstream.url))
        self.assertIn("blocked", str(ctx.exception))
        plan = dr.run_stage(self.request(blocked, plan_only=True))["plan"]
        self.assertEqual((plan["provider"], plan["models"], plan["blocked"], plan["mode"]),
                         ("openai", [MINI], "adapter not ready", "openai"))
        self.assertEqual(self.upstream.received, [])
        self.assertFalse((self.dir / "out").exists() and any((self.dir / "out").rglob("ledger.jsonl")))

    def test_key_isolation_end_to_end_with_the_tracked_s0_key_openai(self) -> None:
        child = self.dir / "child.py"
        child.write_text(
            "import json, os, sys\n"
            "keys = [k for k in os.environ if k.startswith(('OPENAI_', 'DEEPSEEK_', 'ANTHROPIC_')) or k.endswith('_API_KEY')]\n"
            "blob = json.dumps(dict(os.environ))\n"
            f"leak = {OPENAI_KEY!r} in blob or {DEEPSEEK_KEY!r} in blob or 'sk-real-env' in blob\n"
            "json.dump({'keys': sorted(keys), 'leak': leak, 'provider': os.environ.get('AUDITOR_PROVIDER'),\n"
            "           'models': os.environ.get('AUDITOR_MODELS'), 'backbone': os.environ.get('AUDITOR_BACKBONE'),\n"
            "           'token_is_guard': os.environ['OPENAI_API_KEY'] == os.environ['AUDITOR_GUARD_TOKEN']},\n"
            "          open(os.path.join(os.environ['AUDITOR_OUT_DIR'], 'env.json'), 'w'))\n",
            encoding="utf-8")
        base_env = {**os.environ, "OPENAI_API_KEY": "sk-real-env-1", "OPENAI_ORG_ID": "org-x",
                    "OPENAI_PROJECT_ID": "proj-x", "DEEPSEEK_API_KEY": "sk-real-env-2", "ANTHROPIC_API_KEY": "a"}
        env_receipt = dr.run_stage(self.request(self.stage_file(argv=["{python}", str(child)]), lab_env=self.lab_env(),
                                                upstream_url_override=self.upstream.url), base_env=base_env)
        self.assertEqual(env_receipt["status"], "completed", env_receipt)
        report = json.loads((Path(env_receipt["receipt_path"]).parent / "env.json").read_text())
        self.assertFalse(report["leak"])
        self.assertTrue(report["token_is_guard"])
        self.assertEqual(report["keys"], ["OPENAI_API_BASE", "OPENAI_API_KEY", "OPENAI_BASE_URL"])
        self.assertEqual((report["provider"], report["models"], report["backbone"]), ("openai", MINI, f"openai:{MINI}"))
        self.assertIn("OPENAI_ORG_ID", env_receipt["child_env_stripped"])
        self.assertTrue({"AUDITOR_PROVIDER", "AUDITOR_MODELS"} <= set(env_receipt["child_env_added"]))

        # the tracked stage, end to end against the fake: one request, max_tokens clamped to 1, OpenAI key upstream
        self.upstream.usage = {"prompt_tokens": 20, "completion_tokens": 1, "total_tokens": 21,
                               "prompt_tokens_details": {"cached_tokens": 0}}
        receipt = dr.run_stage(dr.StageRequest(
            artifact="common", stage="s0-key-openai", cap_usd=Decimal("0.001"), cap_tokens=500,
            out_root=self.dir / "out", lab_env=self.lab_env(), upstream_url_override=self.upstream.url,
            grace_seconds=0.5), base_env=base_env)
        self.assertEqual((receipt["status"], receipt["exit_code"], receipt["mode"]), ("completed", 0, "openai"), receipt)
        self.assertEqual(len(self.upstream.received), 1)
        sent = self.upstream.received[0]
        self.assertEqual((sent["model"], sent["max_tokens"]), (MINI, 1))
        self.assertNotIn("thinking", sent)
        self.assertEqual(self.upstream.headers[0]["authorization"], f"Bearer {OPENAI_KEY}")
        self.assertEqual(receipt["provider"], "openai")
        self.assertIn("published-backbone", receipt["fidelity_label"])
        self.assertEqual(receipt["price_snapshot"]["models"][MINI]["input_per_million"], "0.15")
        self.assertEqual(receipt["code"]["providers_sha256"], dr._sha256_file(dr.PROVIDERS_PATH))
        self.assertEqual(receipt["guard"]["halt_reason"], "request_cap_reached")
        self.assertFalse(receipt["guard"]["usd_is_notional"])
        out_dir = Path(receipt["receipt_path"]).parent
        (row,) = [json.loads(line) for line in (out_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual((row["max_tokens_field"], row["max_tokens"], row["usd"]), ("max_tokens", 1, "0.00000360"))
        for name in ("receipt.json", "ledger.jsonl", "canary.json", "child_stdout.txt", "child_stderr.txt"):
            text = (out_dir / name).read_text(encoding="utf-8", errors="replace")
            for secret in (OPENAI_KEY, DEEPSEEK_KEY, "sk-real-env"):
                self.assertNotIn(secret, text, name)

    def test_tracked_s1_openai_canary_end_to_end(self) -> None:
        self.upstream.usage = {"prompt_tokens": 30, "completion_tokens": 5, "total_tokens": 35,
                               "prompt_tokens_details": {"cached_tokens": 0},
                               "completion_tokens_details": {"reasoning_tokens": 0}}
        self.upstream.embedding_usage = {"prompt_tokens": 12, "total_tokens": 12}
        gpt52 = "gpt-5.2-2025-12-11"
        # gpt-5.2 rejecting max_tokens is one possible answer to open issue 3: the probe records it,
        # the canary still passes, and the guard charges the upstream 400 as 0 (counted).
        self.upstream.reject = lambda body: body.get("model") == gpt52 and "max_tokens" in body
        receipt = dr.run_stage(dr.StageRequest(
            artifact="common", stage="s1-openai-canary", cap_usd=Decimal("0.02"), cap_tokens=10_000,
            out_root=self.dir / "out", lab_env=self.lab_env(), upstream_url_override=self.upstream.url,
            grace_seconds=0.5))
        self.assertEqual((receipt["status"], receipt["exit_code"]), ("completed", 0), receipt)
        out_dir = Path(receipt["receipt_path"]).parent
        all_results = json.loads((out_dir / "openai_canary.json").read_text(encoding="utf-8"))["results"]
        self.assertEqual(len(all_results), 12)
        probes = [r for r in all_results if r.get("probe")]
        self.assertEqual([(r["model"], r["request"], r["http_status"], r["answer"]) for r in probes],
                         [(gpt52, "probe_max_tokens", 400, "field rejected (HTTP 400)"),
                          (gpt52, "probe_temperature_0", 200, "field accepted")])
        results = [r for r in all_results if not r.get("probe")]
        self.assertEqual(len(results), 10)
        self.assertTrue(all(r["http_status"] == 200 for r in results))
        self.assertTrue(all(r["model_echo"] == r["model"] for r in results))
        logprobs = [r for r in results if r["request"] == "logprobs"]
        self.assertEqual([r["top_logprobs_per_token"] for r in logprobs], [[2]])
        (embeddings,) = [r for r in results if r["request"] == "embeddings"]
        self.assertEqual((embeddings["vectors"], embeddings["usage"]["prompt_tokens"]), (2, 12))
        sent_fields = {(b["model"], k) for b in self.upstream.received for k in ("max_tokens", "max_completion_tokens")
                       if k in b}
        self.assertIn((GPT4O, "max_tokens"), sent_fields)
        self.assertIn((gpt52, "max_tokens"), sent_fields)  # only the probe sends it
        checked_bodies = [b for b in self.upstream.received if b.get("model") == gpt52 and "temperature" not in b
                          and "max_tokens" not in b]
        self.assertEqual(len(checked_bodies), 2)  # the plain and tool-call requests use max_completion_tokens
        self.assertEqual([b.get("temperature") for b in self.upstream.received if "temperature" in b], [0])
        guard = receipt["guard"]
        self.assertEqual((guard["requests_forwarded"], guard["embedding_requests"], guard["logprobs_responses"]),
                         (12, 1, 1))
        self.assertEqual((guard["upstream_error_responses"], guard["halt_reason"]), (1, None))
        self.assertEqual(guard["embedding_prompt_tokens"], 12)


class TrackedOpenAIStageTests(unittest.TestCase):
    """The OpenAI stages tracked in the adapter stage files (RUN-PLAN-OPENAI.md)."""

    def openai_stages(self):
        for path in sorted(dr.ADAPTERS_DIR.glob("*/stages.json")):
            config = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(config["schema"], dr.SCHEMA_STAGES, path)
            for name in config["stages"]:
                merged, _ = dr.load_stage(path, name)
                self.assertEqual(merged.get("provider", "deepseek"), "deepseek", f"{path} {name}")
            for name in config.get(dr.PROVIDER_STAGES_SECTION) or {}:
                merged, _ = dr.load_stage(path, name)
                yield path, name, merged

    def test_every_openai_stage_is_capped_priced_and_declared(self) -> None:
        stages = list(self.openai_stages())
        names = {(path.parent.name, name) for path, name, _ in stages}
        for expected in (("common", "s0-key-openai"), ("common", "s1-openai-canary"), ("attriguard", "S2-openai"),
                         ("argus", "S2-openai"), ("argus", "S2-openai-full"), ("melon", "s2-openai-reduced"),
                         ("adi", "S2-openai"), ("harness", "S2-openai")):
            self.assertIn(expected, names)
        table = dr.load_providers()
        for path, name, merged in stages:
            label = f"{path.parent.name}/{name}"
            self.assertEqual(merged["provider"], "openai", label)
            self.assertGreater(float(merged["cap_usd"]), 0, label)
            self.assertFalse(merged.get("dry_run_allowed"), label)
            self.assertTrue(merged.get("estimate") and merged.get("compares_to"), label)
            self.assertIn("UNVERIFIED", json.dumps(merged["estimate"]), label)
            dr.provider_models(table, "openai", merged["models"])  # every model priced
            if path.parent.name != "common":
                self.assertTrue(merged.get("blocked"), f"{label} must stay blocked until its adapter is ready")
            plan = dr.run_stage(dr.StageRequest(
                artifact=path.parent.name, stage=name, cap_usd=Decimal(str(merged["cap_usd"])),
                cap_tokens=int(merged["cap_tokens"]), out_root=Path(tempfile.gettempdir()) / "plan-only-unused",
                config_path=path, plan_only=True, artifact_root=Path(tempfile.gettempdir()),
                extra_values={"embedder_dir": "unused"}))["plan"]
            self.assertEqual((plan["provider"], plan["models"]), ("openai", merged["models"]), label)

    def test_deepseek_plans_carry_no_provider_keys(self) -> None:
        plan = dr.run_stage(dr.StageRequest(artifact="common", stage="s0-key", cap_usd=Decimal("0.001"), cap_tokens=500,
                                            out_root=Path(tempfile.gettempdir()) / "plan-only-unused",
                                            plan_only=True))["plan"]
        self.assertEqual(sorted(plan), ["argv", "artifact", "cap_requests", "cap_tokens", "cap_usd", "config",
                                        "env_names", "ignored_keys", "mode", "out_dir", "stage"])
        self.assertEqual(plan["mode"], "deepseek")


class DeepSeekRegressionTests(unittest.TestCase):
    """Pin the DeepSeek wire to the bytes the fe2e3e0 guard forwarded for the same request."""

    GOLDEN = (b'{"model":"deepseek-flash","temperature":0.0,"logprobs":true,"top_logprobs":5,"messages":[{"role":'
              b'"system","content":"sys"},{"role":"user","content":"a\\nb"},{"role":"tool","tool_call_id":"c1",'
              b'"content":"r \xc3\xa9"}],"tools":[{"type":"function","function":{"name":"f","parameters":'
              b'{"type":"object"}}}],"thinking":{"type":"disabled"},"max_tokens":4096}')

    def test_deepseek_forwarded_bytes_unchanged(self) -> None:
        upstream = FakeOpenAI()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                guard = dr.BudgetGuard(dr.GuardConfig(
                    stage_id="golden", ledger_path=Path(tmp) / "l.jsonl", cap_usd=Decimal("1"), cap_tokens=10**6,
                    upstream="deepseek", upstream_base_url=upstream.url, api_key=DEEPSEEK_KEY,
                    model_aliases=("gpt-4o-mini",)))
                guard.start()
                try:
                    body = {"model": "gpt-4o-mini", "max_completion_tokens": 9000, "reasoning_effort": "low",
                            "parallel_tool_calls": True, "store": False, "service_tier": "auto", "temperature": 0.0,
                            "logprobs": True, "top_logprobs": 5,
                            "messages": [{"role": "developer", "content": "sys"},
                                         {"role": "user", "content": [{"type": "text", "text": "a"},
                                                                      {"type": "text", "text": "b"}]},
                                         {"role": "tool", "name": "f", "tool_call_id": "c1", "content": "r é"}],
                            "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]}
                    status, _ = post(guard.base_url, guard.config.client_token, body)
                finally:
                    guard.stop()
                self.assertEqual(status, 200)
                self.assertEqual(upstream.raw[0], self.GOLDEN)
                self.assertEqual(upstream.headers[0]["authorization"], f"Bearer {DEEPSEEK_KEY}")
                row = json.loads((Path(tmp) / "l.jsonl").read_text(encoding="utf-8"))
                self.assertNotIn("max_tokens_field", row)  # DeepSeek ledger rows keep their v1 shape
                self.assertEqual(row["upstream_model"], dr.DEEPSEEK_MODEL)
        finally:
            upstream.close()


# ---------------------------------------------------------------------------
# Review fixes (2026-10-08): M1-M4 and the minor items, loopback fakes only
# ---------------------------------------------------------------------------


class StallingUpstream:
    """Loopback upstream that starts a stream, optionally sends usage, then stalls (never finishes)."""

    def __init__(self, send_usage: bool, stall_seconds: float = 2.0) -> None:
        self.received: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):  # noqa: D401
                return

            def do_POST(self):  # noqa: N802
                outer.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                chunk = {"id": "s", "model": outer.received[-1].get("model"),
                         "choices": [{"index": 0, "delta": {"content": "po"}}]}
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                if send_usage:
                    usage = {"id": "s", "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 2}}
                    self.wfile.write(b"data: " + json.dumps(usage).encode() + b"\n\n")
                self.wfile.flush()
                time.sleep(stall_seconds)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class StreamBreakTests(unittest.TestCase):
    """Minor 1: an upstream that stalls or drops mid-stream is still ledgered and charged."""

    def run_stream(self, upstream_kind: str, send_usage: bool):
        upstream = StallingUpstream(send_usage=send_usage)
        tmp = tempfile.TemporaryDirectory()
        try:
            settings = dict(stage_id="stream", ledger_path=Path(tmp.name) / "l.jsonl", cap_usd=Decimal("1"),
                            cap_tokens=10**6, upstream_base_url=upstream.url, request_timeout_s=0.5)
            if upstream_kind == "openai":
                settings.update(upstream="openai", upstream_model="", request_model=MINI, api_key=OPENAI_KEY,
                                models=specs(MINI), max_tokens_default=16, max_tokens_ceiling=16)
                body = chat(stream=True)
            else:
                settings.update(upstream="deepseek", api_key=DEEPSEEK_KEY, max_tokens_default=16,
                                max_tokens_ceiling=16)
                body = {"model": dr.DEEPSEEK_MODEL, "messages": [{"role": "user", "content": "x"}], "stream": True}
            guard = dr.BudgetGuard(dr.GuardConfig(**settings))
            guard.start()
            try:
                status, payload = post(guard.base_url, guard.config.client_token, body)
            finally:
                guard.stop()
            rows = [json.loads(line) for line in (Path(tmp.name) / "l.jsonl").read_text(encoding="utf-8").splitlines()]
            return status, payload, rows, guard
        finally:
            upstream.close()
            tmp.cleanup()

    def assert_released(self, guard: dr.BudgetGuard) -> None:
        self.assertEqual((guard._inflight, guard._reserved_tokens, guard._reserved_usd), (0, 0, Decimal(0)))
        self.assertEqual(guard.requests, 1)

    def test_openai_stall_without_usage_charges_the_reservation(self) -> None:
        status, payload, rows, guard = self.run_stream("openai", send_usage=False)
        self.assertEqual(status, 200)
        self.assertIn(b"po", payload)  # what arrived was relayed
        (row,) = rows
        self.assertEqual((row["outcome"], row["usage_source"], row["http_status"]), ("transport_error", "estimate", 502))
        self.assertEqual(row["stream_error"], "TimeoutError")
        self.assertEqual(row["prompt_tokens"], row["est_prompt_tokens"])
        self.assertGreater(Decimal(row["usd"]), 0)
        self.assertEqual(guard.summary()["usd"], row["usd"])
        self.assert_released(guard)

    def test_deepseek_stall_after_usage_keeps_provider_usage(self) -> None:
        status, _, rows, guard = self.run_stream("deepseek", send_usage=True)
        self.assertEqual(status, 200)
        (row,) = rows
        self.assertEqual((row["outcome"], row["usage_source"], row["prompt_tokens"], row["completion_tokens"]),
                         ("ok", "provider", 11, 2))
        self.assertNotIn("stream_error", row)  # DeepSeek ledger rows keep their v1 shape
        self.assert_released(guard)

    def test_deepseek_stall_without_usage_is_a_transport_error(self) -> None:
        _, _, rows, guard = self.run_stream("deepseek", send_usage=False)
        (row,) = rows
        self.assertEqual((row["outcome"], row["usage_source"]), ("transport_error", "estimate"))
        self.assert_released(guard)


class ContentPartTests(OpenAIGuardCase):
    """Minor 2: non-text content parts are refused, because the pre-flight cannot price them."""

    def test_image_audio_and_file_parts_are_refused(self) -> None:
        guard = self.guard()
        token = guard.config.client_token
        for part in ({"type": "image_url", "image_url": {"url": "data:image/png;base64," + "A" * 64}},
                     {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
                     {"type": "file", "file": {"file_id": "file-x"}}, "bare string part"):
            body = chat(messages=[{"role": "user", "content": [{"type": "text", "text": "a"}, part]}])
            status, payload = post(guard.base_url, token, body)
            self.assertEqual(status, 400, part)
            self.assertIn(b"content_part_not_allowed", payload)
        self.assertEqual(self.upstream.received, [])
        ok = chat(messages=[{"role": "user", "content": [{"type": "text", "text": "a"}]},
                            {"role": "assistant", "content": [{"type": "refusal", "refusal": "no"}]}])
        self.assertEqual(post(guard.base_url, token, ok)[0], 200)


class MisplacedRunnerOptionTests(unittest.TestCase):
    """M1: runner options after '--' are refused before any key is read or guard started."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def main(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = dr.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_detection(self) -> None:
        self.assertEqual(dr.misplaced_runner_options(["--resume-from", "x", "--traces-dir", "y", "--out-dir", "z",
                                                      "--out", "o", "--max-tokens", "4096", "--resume", "--"]), [])
        self.assertEqual(dr.misplaced_runner_options(["--plan-only", "--cap-usd=5", "--lab-env", "k", "--plan",
                                                      "--dry-run", "--grace-seconds", "1"]),
                         ["--plan-only", "--cap-usd", "--lab-env", "--plan", "--dry-run", "--grace-seconds"])

    def test_plan_only_after_double_dash_is_refused_with_exit_2(self) -> None:
        out_root = self.dir / "out"
        missing_env = self.dir / "never-read.env"
        for tail in (["--", "--plan-only"], ["--", "--resume-from", "x", "--plan-only"], ["--", "--cap-usd", "1"]):
            code, stdout, stderr = self.main(
                "run-stage", "--artifact", "common", "--stage", "s0-key-openai", "--cap-usd", "0.001",
                "--cap-tokens", "500", "--lab-env", str(missing_env), "--out-root", str(out_root), *tail)
            self.assertEqual(code, 2, tail)
            self.assertIn("before '--'", stderr)
            self.assertEqual(stdout, "")
        self.assertFalse(out_root.exists())  # no run directory, no guard, no key read

    def test_plan_only_before_double_dash_still_resolves(self) -> None:
        code, stdout, _ = self.main(
            "run-stage", "--artifact", "argus", "--stage", "S2-openai", "--cap-usd", "17", "--cap-tokens", "80000000",
            "--artifact-root", str(self.dir), "--out-root", str(self.dir / "out"), "--plan-only",
            "--", "--resume-from", "prev/adapter")
        self.assertEqual(code, 0)
        plan = json.loads(stdout)
        self.assertEqual(plan["argv"][-2:], ["--resume-from", "prev/adapter"])
        self.assertIn("blocked", plan)


class KeyFileLocationTests(unittest.TestCase):
    """M3: the OpenAI key must be in a dedicated file, not a .env and not inside any git work tree."""

    def test_check_provider_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dedicated = Path(tmp) / "openai-guard.key.env"
            dr.check_provider_key_file(dedicated, "OPENAI_API_KEY")  # outside every work tree: accepted
            with self.assertRaises(dr.RouteError) as ctx:
                dr.check_provider_key_file(Path(tmp) / ".env", "OPENAI_API_KEY")
            self.assertIn("not named .env", str(ctx.exception))
        # Paths only: neither file is opened (the second does not exist).
        for inside in (dr.ADAPTERS_DIR.parent / "agentdojo-lab" / ".env", dr.COMMON_DIR / "openai.key"):
            with self.assertRaises(dr.RouteError, msg=str(inside)):
                dr.check_provider_key_file(inside, "OPENAI_API_KEY")

    def test_run_stage_refuses_a_dot_env_key_file_before_reading_it(self) -> None:
        upstream = FakeOpenAI()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                lab_env = Path(tmp) / ".env"
                lab_env.write_text(f"OPENAI_API_KEY={OPENAI_KEY}\n", encoding="utf-8")
                with self.assertRaises(dr.RouteError) as ctx:
                    dr.run_stage(dr.StageRequest(artifact="common", stage="s0-key-openai", cap_usd=Decimal("0.001"),
                                                 cap_tokens=500, out_root=Path(tmp) / "out", lab_env=lab_env,
                                                 upstream_url_override=upstream.url, grace_seconds=0.5))
                self.assertNotIn(OPENAI_KEY, str(ctx.exception))
                self.assertFalse((Path(tmp) / "out").exists())
            self.assertEqual(upstream.received, [])
        finally:
            upstream.close()


class ExactServeTests(unittest.TestCase):
    """Minor 3: `serve --provider openai` is bounded by a provider stage like run-stage."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.key = self.dir / "openai.key"
        self.key.write_text(f"OPENAI_API_KEY={OPENAI_KEY}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def args(self, *extra: str, cap_usd: str = "0.02", cap_tokens: str = "10000"):
        return dr._build_parser().parse_args([
            "serve", "--provider", "openai", "--stage-id", "dev", "--ledger", str(self.dir / "l.jsonl"),
            "--cap-usd", cap_usd, "--cap-tokens", cap_tokens, "--lab-env", str(self.key), *extra])

    def test_stage_bounds_apply(self) -> None:
        cfg = dr.exact_serve_config(self.args("--artifact", "common", "--stage", "s1-openai-canary"))
        self.assertEqual((cfg.cap_requests, cfg.max_tokens_ceiling, cfg.request_model), (14, 64, MINI))
        self.assertEqual(sorted(cfg.models), sorted([MINI, GPT41, GPT4O, "gpt-5.2-2025-12-11", EMBED]))
        self.assertEqual(cfg.api_key, OPENAI_KEY)
        narrowed = dr.exact_serve_config(self.args("--artifact", "common", "--stage", "s1-openai-canary",
                                                   "--model", GPT41, "--cap-requests", "99"))
        self.assertEqual((list(narrowed.models), narrowed.request_model, narrowed.cap_requests), ([GPT41], GPT41, 14))

    def test_refusals(self) -> None:
        for extra, kwargs in (
            ((), {}),  # no stage
            (("--artifact", "melon", "--stage", "s1-openai"), {"cap_usd": "0.3", "cap_tokens": "60000"}),  # blocked
            (("--artifact", "common", "--stage", "s1-openai-canary"), {"cap_usd": "0.03"}),  # above the ceiling
            (("--artifact", "common", "--stage", "s1-openai-canary"), {"cap_tokens": "10001"}),
            (("--artifact", "common", "--stage", "s1-openai-canary", "--model", "gpt-4o-mini"), {}),  # alias
            (("--artifact", "common", "--stage", "s1-openai-canary", "--model", EMBED), {}),  # not a chat model
            (("--artifact", "common", "--stage", "s0-key"), {}),  # a DeepSeek stage
        ):
            with self.assertRaises(dr.RouteError, msg=str(extra)):
                dr.exact_serve_config(self.args(*extra, **kwargs))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = dr.main(["serve", "--provider", "openai", "--stage-id", "dev", "--ledger", str(self.dir / "l.jsonl"),
                            "--cap-usd", "0.3", "--cap-tokens", "60000", "--lab-env", str(self.key),
                            "--artifact", "melon", "--stage", "s1-openai"])
        self.assertEqual(code, 2)
        self.assertIn("blocked", err.getvalue())


class RunLockAndSnapshotTests(unittest.TestCase):
    """M2: a live run is marked by a lock file, and code edits during a run are detected and recorded."""

    CHILD = (
        "import json, os, sys, pathlib\n"
        "sys.path.insert(0, {common!r})\n"
        "import deepseek_route as dr\n"
        "out = pathlib.Path(os.environ['AUDITOR_OUT_DIR'])\n"
        "state = dr._git_state(dr._repo_root())\n"
        "json.dump({{'locks': dr._live_run_locks(), 'status': state.get('adapters_status', [])}},\n"
        "          open(out / 'child.json', 'w'))\n"
        "edit = os.environ.get('EDIT_DURING_RUN')\n"
        "if edit:\n"
        "    p = pathlib.Path(edit); p.write_text(p.read_text(encoding='utf-8') + ' ', encoding='utf-8')\n"
    )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.upstream = FakeOpenAI()
        self.child = self.dir / "child.py"
        self.child.write_text(self.CHILD.format(common=str(COMMON)), encoding="utf-8")
        self.key = self.dir / "openai.key"
        self.key.write_text(f"OPENAI_API_KEY={OPENAI_KEY}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.upstream.close()
        self.tmp.cleanup()

    def run_child(self, edit: bool) -> tuple[dict, dict]:
        config = self.dir / "stages.json"
        config.write_text(json.dumps({
            "schema": dr.SCHEMA_STAGES, "artifact": "fake",
            "defaults": {"timeout_seconds": 60, "max_tokens_default": 16, "max_tokens_ceiling": 16},
            dr.PROVIDER_STAGES_SECTION: {"s1": {
                "argv": ["{python}", str(self.child)], "cap_usd": 1, "cap_tokens": 1000, "provider": "openai",
                "models": [MINI], "request_model": MINI, "dry_run_allowed": False}},
        }), encoding="utf-8")
        base_env = {**os.environ, "EDIT_DURING_RUN": str(config) if edit else ""}
        receipt = dr.run_stage(dr.StageRequest(
            artifact="fake", stage="s1", cap_usd=Decimal("0.5"), cap_tokens=1000, out_root=self.dir / "out",
            config_path=config, lab_env=self.key, upstream_url_override=self.upstream.url, grace_seconds=0.5),
            base_env=base_env)
        child = json.loads((Path(receipt["receipt_path"]).parent / "child.json").read_text(encoding="utf-8"))
        return receipt, child

    def test_lock_is_live_during_the_child_and_removed_after(self) -> None:
        receipt, child = self.run_child(edit=False)
        self.assertEqual(receipt["status"], "completed", receipt)
        code = receipt["code"]
        lock = Path(code["run_lock"])
        self.assertIn(lock.name, child["locks"])  # the child saw its own run's lock
        self.assertFalse(lock.exists())  # removed when the child ended
        self.assertFalse(any(".run-stage-" in line for line in child["status"]))  # not reported as a code change
        self.assertFalse(code["code_changed_during_run"])
        self.assertEqual((code["changed_during_run"], code["files_changed_during_run"]), ([], []))
        self.assertIsInstance(code["adapters_status_changed_during_run"], bool)  # other adapters' edits: reported apart
        launch = code["launch"]
        self.assertEqual(launch["deepseek_route_sha256"], code["deepseek_route_sha256"])
        self.assertEqual(code["deepseek_route_sha256_at_import"], code["deepseek_route_sha256"])
        self.assertEqual(launch["stage_config_sha256"], code["stage_config_sha256"])
        self.assertEqual(launch["adapter_tree_sha256"], code["end_adapter_tree_sha256"])
        self.assertGreater(launch["adapter_tree_files"], 5)
        self.assertEqual(launch["git"]["commit"], code["commit"])
        self.assertEqual(launch["providers_sha256"], code["providers_sha256"])

    def test_an_edit_during_the_run_is_recorded(self) -> None:
        receipt, _ = self.run_child(edit=True)
        code = receipt["code"]
        self.assertTrue(code["code_changed_during_run"])
        self.assertIn("stage_config_sha256", code["changed_during_run"])
        self.assertNotEqual(code["launch"]["stage_config_sha256"], code["stage_config_sha256"])

    def test_lock_lines_are_not_git_changes(self) -> None:
        for line in ("?? packages/auditor-adapters/common/.run-stage-123-abcdef01.lock",
                     '?? "packages/auditor-adapters/common/.run-stage-9-0a.lock"'):
            self.assertTrue(dr._RUN_LOCK_STATUS.search(line.strip().strip('"')), line)
        for line in (" M packages/auditor-adapters/common/deepseek_route.py", "?? packages/auditor-adapters/h2/"):
            self.assertFalse(dr._RUN_LOCK_STATUS.search(line), line)


class StageRuleTests(unittest.TestCase):
    """Minor 8, 9 and 12, and the M4 fidelity rule."""

    def test_deepseek_stages_cannot_use_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stages.json"
            path.write_text(json.dumps({"schema": dr.SCHEMA_STAGES, "stages": {
                "s1": {"argv": ["{python}"], "cap_usd": 1, "cap_tokens": 10, "blocked": "not ready"}}}),
                encoding="utf-8")
            with self.assertRaises(dr.RouteError) as ctx:
                dr.load_stage(path, "s1")
            self.assertIn("paid_allowed", str(ctx.exception))

    def test_reduced_melon_stage_cannot_run_the_full_plan(self) -> None:
        config = json.loads((dr.ADAPTERS_DIR / "melon" / "stages.json").read_text(encoding="utf-8"))
        reduced = config[dr.PROVIDER_STAGES_SECTION]["s2-openai-reduced"]["argv"]
        full = config[dr.PROVIDER_STAGES_SECTION]["s2-openai-full"]["argv"]
        self.assertNotEqual(reduced, full)
        source = (dr.ADAPTERS_DIR / "melon" / "run_melon_stage.py").read_text(encoding="utf-8")
        known = re.search(r"^STAGES\s*=\s*\(([^)]*)\)", source, re.M).group(1)
        stage_arg = reduced[reduced.index("--stage") + 1]
        self.assertNotIn(f'"{stage_arg}"', known)  # today's adapter rejects it before any request

    def test_adi_openai_stages_allow_long_gpt52_requests(self) -> None:
        for name in ("S1-openai", "S2-openai"):
            merged, _ = dr.load_stage(dr.ADAPTERS_DIR / "adi" / "stages.json", name)
            self.assertGreaterEqual(merged["request_timeout_seconds"], 600, name)
        merged, _ = dr.load_stage(dr.ADAPTERS_DIR / "adi" / "stages.json", "S1-openai")
        self.assertIn("excluded from adi_asr", merged["blocked"])

    def test_fidelity_rule(self) -> None:
        import fidelity_rule as fr  # noqa: PLC0415

        self.assertEqual(fr.acceptance_band(108, 53, 108, 2), (37, 69))
        self.assertAlmostEqual(fr.one_sample_pass_probability(108, 53, 108), 0.844, places=3)
        self.assertAlmostEqual(fr.pass_probability(108, 53, 108, 2), 0.975, places=3)
        self.assertFalse(fr.consistent(78, 108, 53, 108, 2))  # the DeepSeek ADI count is told apart
        self.assertTrue(fr.consistent(53, 108, 53, 108, 2))
        self.assertEqual(fr.acceptance_band(230, 0, 230, 3), (0, 6))
        report = fr.table()
        self.assertGreaterEqual(min(r["p_joint_if_equal"] for r in report.values()), 0.95)


if __name__ == "__main__":
    unittest.main()
