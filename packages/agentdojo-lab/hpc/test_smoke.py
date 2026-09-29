"""No-network regression checks for bounded smoke-job failure modes."""

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import case_a_batch
import preflight
import smoke


def answer(message, finish="stop", model=smoke.MODEL):
    return {"model": model, "choices": [{"finish_reason": finish, "message": message}]}


def tool_call(name, arguments, identifier="call_1"):
    return {"id": identifier, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)}}


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, replies):
        self.replies, self.requests = iter(replies), []

    def open(self, request, timeout):
        self.requests.append(request)
        value = next(self.replies)
        if isinstance(value, Exception):
            raise value
        return Response(value if isinstance(value, bytes) else json.dumps(value).encode())


class SmokeTests(unittest.TestCase):
    def test_round_trip_and_isolated_judge(self):
        replies = [
            answer({"role": "assistant", "content": None, "tool_calls": [
                tool_call("make_receipt", {"labels": ["café", "tea"], "note": None})]}, "tool_calls"),
            answer({"role": "assistant", "content": "SCOUT_RECEIPT_6131"}),
            answer({"role": "assistant", "tool_calls": [tool_call("lookup_item", {"item_id": 9}),
                   tool_call("lookup_item", {"item_id": 7}, "call_2")]}, "tool_calls"),
            answer({"role": "assistant", "content": json.dumps({
                "same_action": False, "confidence": 0.9, "reasoning": "Different recipients."})}),
        ]
        opener = Opener(replies)
        client = smoke.Client("http://127.0.0.1:8000/v1", "secret", opener)
        smoke.run_checks(client)
        self.assertEqual([row["status"] for row in client.rows], ["passed"] * 4)
        requests = [json.loads(row.data) for row in opener.requests]
        self.assertEqual(len(client.rows[0]["request"]["messages"]), 2)
        self.assertEqual(client.rows[0]["request"], requests[0])
        self.assertEqual(requests[1]["messages"][-1]["tool_call_id"], "call_1")
        self.assertEqual(requests[1]["messages"][-2]["tool_calls"][0]["id"], "call_1")
        self.assertNotIn("tools", requests[3])
        self.assertNotIn("tool_choice", requests[3])
        self.assertNotIn("reasoning_effort", requests[3])
        self.assertEqual(requests[3]["response_format"], {"type": "json_object"})
        self.assertNotIn("secret", json.dumps(client.rows))
        with self.assertRaisesRegex(smoke.SmokeError, "budget"):
            client.chat("unplanned", [])
        self.assertEqual(len(opener.requests), 4)

    def test_rejects_remote_urls_and_credentials(self):
        for url in ("https://api.groq.com/openai/v1", "http://localhost:8000/v1",
                    "http://127.0.0.1:8000/v1?token=secret", "http://user:secret@127.0.0.1:8000/v1",
                    "http://127.0.0.1:bad/v1"):
            with self.subTest(url=url), self.assertRaises(smoke.SmokeError):
                smoke.local_url(url)
        with self.assertRaisesRegex(smoke.SmokeError, "redirect"):
            smoke.NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.com")

    def test_http_failure_is_retained_without_body_or_retry(self):
        error = urllib.error.HTTPError("http://127.0.0.1:8000/v1", 500, "secret", {}, io.BytesIO(b"secret"))
        opener = Opener([error])
        client = smoke.Client("http://127.0.0.1:8000/v1", "secret", opener)
        with self.assertRaisesRegex(smoke.SmokeError, "http_status_500"):
            client.chat("single_tool", [])
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(client.rows[0]["status"], "failed")
        self.assertNotIn("secret", json.dumps(client.rows))

    def test_rejects_stringified_array_boolean_integer_and_duplicate_ids(self):
        for bad in ({"labels": '["café","tea"]', "note": None}, {"labels": ["café", "tea"], "note": "null"}):
            with self.subTest(bad=bad), self.assertRaisesRegex(smoke.SmokeError, "type_mismatch"):
                smoke.calls({"tool_calls": [tool_call("make_receipt", bad)]}, "make_receipt",
                            [{"labels": ["café", "tea"], "note": None}])
        with self.assertRaisesRegex(smoke.SmokeError, "type_mismatch"):
            smoke.calls({"tool_calls": [tool_call("lookup_item", {"item_id": True})]},
                        "lookup_item", [{"item_id": 1}])
        with self.assertRaisesRegex(smoke.SmokeError, "duplicate_call_id"):
            smoke.calls({"tool_calls": [tool_call("lookup_item", {"item_id": 7}),
                                        tool_call("lookup_item", {"item_id": 9})]},
                        "lookup_item", [{"item_id": 7}, {"item_id": 9}])

    def test_truncation_wrong_model_and_large_body(self):
        for reply in (answer({"role": "assistant", "content": "partial"}, "length"),
                      answer({"role": "assistant", "content": "x"}, model="unexpected-model"),
                      b"x" * (smoke.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(reply_type=type(reply).__name__):
                client = smoke.Client("http://127.0.0.1:8000/v1", "secret", Opener([reply]))
                with self.assertRaises(smoke.SmokeError):
                    client.chat("single_tool", [])
                self.assertEqual(client.rows[0]["status"], "failed")

    def test_invalid_judge_numbers_and_schema(self):
        for content in ('{"same_action":false,"confidence":NaN,"reasoning":"x"}',
                        '{"same_action":false,"confidence":1e999,"reasoning":"x"}',
                        '{"same_action":"false","confidence":0.8,"reasoning":"x"}',
                        '{"same_action":false,"confidence":true,"reasoning":"x"}',
                        '{"same_action":false,"confidence":0.8,"reasoning":"x","extra":1}',
                        '{"same_action":false,"same_action":true,"confidence":0.8,"reasoning":"x"}'):
            with self.subTest(content=content), self.assertRaises(smoke.SmokeError):
                smoke.judge_result({"content": content})

    def test_readiness_timeout_and_dead_server_are_bounded(self):
        now = [0.0]
        opener = Opener([OSError("unavailable")] * 2)
        client = smoke.Client("http://127.0.0.1:8000/v1", "secret", opener)
        with self.assertRaisesRegex(smoke.SmokeError, "readiness_timeout"):
            smoke.wait_ready(client, 6, clock=lambda: now[0], sleep=lambda value: now.__setitem__(0, now[0] + value))
        self.assertEqual(now[0], 6)
        self.assertEqual(len(opener.requests), 2)
        with patch.object(smoke.os, "kill", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(smoke.SmokeError, "server_exited"):
                smoke.wait_ready(client, 10, server_pid=999999)

    def test_main_preserves_failed_receipt_and_redacts_echoed_key(self):
        fake = Opener([answer({"role": "assistant", "content": "secret-key"})])
        args = ["smoke.py", "--output"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with patch("sys.argv", args + [str(path)]), patch.dict("os.environ", {"LOCAL_LLM_API_KEY": "secret-key"}), \
                    patch.object(smoke, "wait_ready", return_value={}), \
                    patch.object(smoke.urllib.request, "build_opener", return_value=fake):
                self.assertEqual(smoke.main(), 1)
            text = path.read_text()
            self.assertNotIn("secret-key", text)
            record = json.loads(text)
            self.assertEqual(record["requests_started"], 1)
            self.assertEqual(record["requests"][0]["status"], "failed")
            with patch("sys.argv", args + [str(path)]), self.assertRaises(FileExistsError):
                smoke.main()
            self.assertEqual(path.read_text(), text)


class PreflightTests(unittest.TestCase):
    def test_limits_distinguish_smoke_phase_from_case_a_job(self):
        smoke_only = preflight.limit_records(native=False, case_a_mode=False)
        self.assertEqual(smoke_only["limits"]["scope"], "smoke_phase_only")
        self.assertEqual(smoke_only["limits"]["intended_walltime_minutes"], 45)
        self.assertEqual(smoke_only["limits"]["generative_requests"], 4)
        self.assertNotIn("enclosing_case_a_limits", smoke_only)

        case_a = preflight.limit_records(native=True, case_a_mode=True)
        self.assertEqual(case_a["limits"]["scope"], "smoke_phase_only")
        self.assertEqual(case_a["limits"]["intended_walltime_minutes"], 60)
        self.assertEqual(case_a["limits"]["generative_requests"], 8)
        self.assertEqual(case_a["enclosing_case_a_limits"], {
            "scope": "smoke_plus_case_a_job",
            "walltime_seconds": 7200,
            "total_generation_requests": 24,
            "case_requests": 16,
            "online_auditor_requests": 0,
        })

        case_b = preflight.limit_records(native=True, case_a_mode=False, case_b_mode=True)
        self.assertEqual(case_b["limits"]["scope"], "smoke_phase_only")
        self.assertEqual(case_b["enclosing_case_b_limits"], {
            "scope": "smoke_plus_case_b_job",
            "walltime_seconds": 7200,
            "total_generation_requests": 24,
            "case_requests": 16,
            "case_slots": 4,
            "requests_per_case_slot": 4,
            "online_auditor_requests": 0,
        })
        case_c = preflight.limit_records(
            native=True,
            case_a_mode=False,
            case_c_mode=True,
        )
        self.assertEqual(case_c["limits"]["scope"], "smoke_phase_only")
        self.assertEqual(case_c["enclosing_case_c_limits"], {
            "scope": "smoke_plus_case_c_job",
            "walltime_seconds": 7200,
            "total_generation_requests": 24,
            "case_requests": 16,
            "case_sessions": 4,
            "requests_per_case_session": 4,
            "online_auditor_requests": 0,
        })
        with self.assertRaises(ValueError):
            preflight.limit_records(native=True, case_a_mode=True, case_b_mode=True)
        with self.assertRaises(ValueError):
            preflight.limit_records(
                native=True,
                case_a_mode=False,
                case_b_mode=True,
                case_c_mode=True,
            )
        with self.assertRaises(ValueError):
            preflight.limit_records(
                native=True,
                case_a_mode=True,
                case_b_mode=False,
                case_c_mode=True,
            )
        self.assertEqual(
            (case_a["limits"], case_a["enclosing_case_a_limits"]),
            case_a_batch.fixed_preflight_limits(),
        )

    def test_missing_shard_and_external_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "model"
            root.mkdir()
            (root / "model.safetensors.index.json").write_text(json.dumps({"weight_map": {"weight": "part.safetensors"}}))
            (root / "config.json").write_text(json.dumps({"model_type": "llama4", "text_config": {"num_local_experts": 16}}))
            for name in ("tokenizer.json", "tokenizer_config.json"):
                (root / name).write_text("{}")
            with self.assertRaises(FileNotFoundError):
                preflight.inspect_snapshot(root, "a" * 40)
            outside = Path(directory) / "outside"
            outside.write_bytes(b"weights")
            (root / "part.safetensors").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "materialized"):
                preflight.inspect_snapshot(root, "a" * 40)
            (root / "part.safetensors").unlink()
            (root / "part.safetensors").write_bytes(b"weights")
            result = preflight.inspect_snapshot(root, "a" * 40)
            self.assertEqual(result["declared_revision"], "a" * 40)
            self.assertIn("sizes measured", result["weight_integrity"])

    def test_container_or_template_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.sif"
            path.write_bytes(b"first")
            digest = preflight.sha256(path)
            self.assertEqual(preflight.checked_file(path, digest)["sha256"], digest)
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                preflight.checked_file(path, digest)


if __name__ == "__main__":
    unittest.main()
