"""Offline tests for the pinned Groq G1 route; every upstream is a loopback fake."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMMON))

import deepseek_route as dr
from test_openai_route import FakeOpenAI, post

MODEL = "openai/gpt-oss-120b"
KEY = "sk-groq-test-0123456789abcdef"


class GroqGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.upstream = FakeOpenAI()
        self.upstream.service_tier = "on_demand"
        self.guards: list[dr.BudgetGuard] = []

    def tearDown(self) -> None:
        for guard in self.guards:
            guard.stop()
        self.upstream.close()
        self.tmp.cleanup()

    def guard(self, **overrides) -> dr.BudgetGuard:
        settings = {
            "stage_id": "test/groq", "ledger_path": self.root / f"ledger-{len(self.guards)}.jsonl",
            "cap_usd": Decimal("0.10"), "cap_tokens": 100_000, "cap_requests": 10,
            "upstream": "groq", "upstream_base_url": self.upstream.url, "upstream_model": "",
            "request_model": MODEL, "api_key": KEY,
            "models": dr.provider_models(dr.load_providers(), "groq", [MODEL]),
            "max_tokens_default": 2048, "max_tokens_ceiling": 2048,
        }
        settings.update(overrides)
        guard = dr.BudgetGuard(dr.GuardConfig(**settings))
        self.guards.append(guard)
        guard.start()
        return guard

    @staticmethod
    def body(**overrides) -> dict:
        value = {
            "model": MODEL, "messages": [{"role": "user", "content": "hello"}],
            "tools": [{"type": "function", "function": {"name": "ping", "parameters": {"type": "object"}}}],
            "tool_choice": "auto", "temperature": 0,
            "max_completion_tokens": 2048, "reasoning_effort": "low",
        }
        value.update(overrides)
        return value

    def test_official_price_exact_model_and_url(self) -> None:
        table = dr.load_providers()
        entry = table["providers"]["groq"]
        self.assertEqual((entry["base_url"], entry["key_env"], entry["endpoints"]),
                         (dr.GROQ_BASE_URL, dr.GROQ_KEY_ENV, ["chat.completions"]))
        spec = dr.provider_models(table, "groq", [MODEL])[MODEL]
        self.assertEqual((spec.price.input_per_million, spec.price.cached_input_per_million,
                          spec.price.output_per_million),
                         (Decimal("0.15"), Decimal("0.075"), Decimal("0.60")))
        for model in ("llama-3.3-70b-versatile", "openai/gpt-oss-20b", "deepseek-flash"):
            with self.assertRaises(dr.RouteError):
                dr.provider_models(table, "groq", [model])
        with self.assertRaises(dr.RouteError):
            dr.GuardConfig(stage_id="test", ledger_path=self.root / "bad.jsonl",
                           cap_usd=Decimal(1), cap_tokens=1000, upstream="groq",
                           upstream_base_url=dr.OPENAI_BASE_URL, request_model=MODEL,
                           models={MODEL: spec}, api_key=KEY).validate()

    def test_wire_model_identity_tier_usage_and_caps(self) -> None:
        self.upstream.usage = {"prompt_tokens": 1000, "completion_tokens": 100,
                               "prompt_tokens_details": {"cached_tokens": 400},
                               "completion_tokens_details": {"reasoning_tokens": 12}}
        guard = self.guard(cap_requests=1)
        raw = json.dumps(self.body(), separators=(",", ":")).encode()
        status, _ = post(guard.base_url, guard.config.client_token, raw)
        self.assertEqual(status, 200)
        self.assertEqual(self.upstream.raw, [raw])
        self.assertEqual(self.upstream.headers[0]["authorization"], f"Bearer {KEY}")
        self.assertEqual(self.upstream.paths, ["/v1/chat/completions"])
        self.assertEqual(guard.summary()["usd"], "0.00018000")
        self.assertEqual(guard.summary()["reasoning_tokens"], 12)
        self.assertEqual(guard.summary()["halt_reason"], "request_cap_reached")
        status, _ = post(guard.base_url, guard.config.client_token, self.body())
        self.assertEqual(status, 402)
        self.assertEqual(len(self.upstream.received), 1)
        (row,) = [json.loads(x) for x in guard.config.ledger_path.read_text().splitlines()
                  if json.loads(x).get("outcome") == "ok"]
        self.assertEqual((row["requested_model"], row["service_tier"], row["reasoning_effort"]),
                         (MODEL, "on_demand", "low"))
        self.assertIn("system_fingerprint", row)

    def test_unsupported_groq_wire_is_refused_before_upstream(self) -> None:
        guard = self.guard()
        invalid = [
            self.body(model="llama-3.3-70b-versatile"),
            self.body(n=2), self.body(logprobs=True), self.body(top_logprobs=1),
            self.body(logit_bias={"1": 1}), self.body(max_tokens=10),
            self.body(reasoning_effort="medium"), self.body(temperature=0.4),
            self.body(tool_choice="required"), self.body(service_tier="auto"),
            self.body(messages=[{"role": "user", "name": "x", "content": "hello"}]),
            self.body(thinking={"type": "disabled"}),
        ]
        for body in invalid:
            with self.subTest(body=body):
                status, _ = post(guard.base_url, guard.config.client_token, body)
                self.assertEqual(status, 400)
        status, _ = post(guard.base_url, guard.config.client_token,
                         {"model": MODEL, "input": "hello"}, path="/embeddings")
        self.assertEqual(status, 400)
        self.assertEqual(self.upstream.received, [])

    def test_wrong_upstream_model_halts(self) -> None:
        self.upstream.model_override = "openai/gpt-oss-20b"
        guard = self.guard()
        status, _ = post(guard.base_url, guard.config.client_token, self.body())
        self.assertEqual(status, 200)
        self.assertEqual(guard.summary()["halt_reason"], "response_model_mismatch")
        self.assertTrue(guard.stop_child)

    def test_dedicated_key_only_and_child_secret_isolation(self) -> None:
        config = self.root / "stages.json"
        child = self.root / "child.py"
        child.write_text(
            "import json, os, urllib.request\n"
            "body={'model':'openai/gpt-oss-120b','messages':[{'role':'user','content':'hello'}],"
            "'tools':[{'type':'function','function':{'name':'ping','parameters':{'type':'object'}}}],"
            "'tool_choice':'auto','temperature':0,'max_completion_tokens':16,'reasoning_effort':'low'}\n"
            "raw=json.dumps(body).encode()\n"
            "req=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/chat/completions',data=raw,"
            "headers={'Authorization':'Bearer '+os.environ['OPENAI_API_KEY'],'Content-Type':'application/json'})\n"
            "response=urllib.request.urlopen(req).read()\n"
            "assert response\n"
            "assert 'GROQ_API_KEY' not in os.environ\n"
            "assert os.environ['OPENAI_API_KEY']==os.environ['AUDITOR_GUARD_TOKEN']\n",
            encoding="utf-8",
        )
        config.write_text(json.dumps({
            "schema": dr.SCHEMA_STAGES,
            "provider_stages": {"s1": {
                "provider": "groq", "models": [MODEL], "request_model": MODEL,
                "argv": ["{python}", str(child)], "cap_usd": 0.10,
                "cap_tokens": 100000, "cap_requests": 10,
                "max_tokens_default": 16, "max_tokens_ceiling": 16,
                "dry_run_allowed": False,
            }},
        }), encoding="utf-8")
        secret_file = self.root / "provider.keys"
        secret_file.write_text(f"GROQ_API_KEY={KEY}\n", encoding="utf-8")
        request = dr.StageRequest(artifact="common", stage="s1", config_path=config,
                                  cap_usd=Decimal("0.05"), cap_tokens=50000,
                                  out_root=self.root / "results", lab_env=secret_file,
                                  upstream_url_override=self.upstream.url)
        receipt = dr.run_stage(request, base_env={**os.environ, "GROQ_API_KEY": "would-leak"})
        self.assertEqual((receipt["status"], receipt["provider"], receipt["exit_code"]),
                         ("completed", "groq", 0), receipt)
        self.assertEqual(self.upstream.headers[0]["authorization"], f"Bearer {KEY}")
        self.assertIn("GROQ_API_KEY", receipt["child_env_stripped"])
        self.assertEqual(receipt["guard"]["upstream_base_url"], self.upstream.url)
        self.assertEqual(receipt["price_snapshot"]["models"][MODEL]["output_per_million"], "0.60")
        for path in Path(receipt["receipt_path"]).parent.iterdir():
            if path.is_file():
                self.assertNotIn(KEY, path.read_text(encoding="utf-8", errors="replace"), str(path))
        blocked = self.root / ".env"
        blocked.write_text(f"GROQ_API_KEY={KEY}\n", encoding="utf-8")
        with self.assertRaises(dr.RouteError):
            dr.run_stage(dr.StageRequest(**{**request.__dict__, "lab_env": blocked}))


if __name__ == "__main__":
    unittest.main()
