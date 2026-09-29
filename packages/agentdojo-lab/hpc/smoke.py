"""Four bounded synthetic chat requests to a local OpenAI-compatible endpoint.

Python standard library only; no AgentDojo import, external tools, or SDK retries.
The request/response receipt excludes authentication headers and redacts the key.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MODEL = "llama-4-scout-local"
MAX_RESPONSE_BYTES = 1024 * 1024


class SmokeError(ValueError):
    """A bounded transport or contract failure with a safe diagnostic message."""


def strict_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise SmokeError("duplicate_json_key")
            result[key] = item
        return result

    def invalid(_value):
        raise SmokeError("nonfinite_json_number")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise SmokeError("nonfinite_json_number")
        return result

    try:
        return json.loads(value, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite_float)
    except (ValueError, UnicodeError, TypeError) as error:
        raise SmokeError("invalid_json") from error


def local_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
                 and parsed.port is not None and 1024 <= parsed.port <= 65535
                 and parsed.path.rstrip("/") == "/v1" and not parsed.query
                 and not parsed.fragment and parsed.username is None and parsed.password is None)
    except ValueError:
        valid = False
    if not valid:
        raise SmokeError("require_literal_loopback_http_endpoint")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SmokeError("redirect_rejected")


class Client:
    def __init__(self, base_url: str, key: str, opener=None):
        self.base_url = local_url(base_url)
        if not key or any(char in key for char in "\r\n"):
            raise SmokeError("missing_or_invalid_local_key")
        self.key = key
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.rows = []

    def request(self, path: str, body=None, *, timeout=120):
        encoded = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=encoded, headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + self.key,
        })
        try:
            with self.opener.open(request, timeout=timeout) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if response.status != 200:
                    raise SmokeError("unexpected_http_status")
            if len(payload) > MAX_RESPONSE_BYTES:
                raise SmokeError("response_too_large")
            result = strict_json(payload)
            if not isinstance(result, dict):
                raise SmokeError("response_not_object")
            return result
        except urllib.error.HTTPError as error:
            # Never persist response bodies/headers: servers can echo credentials.
            raise SmokeError(f"http_status_{error.code}") from None
        except (OSError, urllib.error.URLError) as error:
            raise SmokeError("transport_failed_" + type(error).__name__) from None

    def chat(self, stage: str, messages: list, **extra):
        if len(self.rows) >= 4:
            raise SmokeError("request_budget_exhausted")
        body = copy.deepcopy({"model": MODEL, "messages": messages, "temperature": 0,
                              "max_completion_tokens": 512, **extra})
        row = {"stage": stage, "status": "started", "request": body}
        self.rows.append(row)
        started = time.monotonic()
        try:
            response = self.request("/chat/completions", body)
            row["response"] = response
            if response.get("model") != MODEL:
                raise SmokeError("response_model_mismatch")
            choices = response.get("choices")
            if not isinstance(choices, list) or len(choices) != 1:
                raise SmokeError("expected_one_choice")
            choice = choices[0]
            if not isinstance(choice, dict) or choice.get("finish_reason") not in {"stop", "tool_calls"}:
                raise SmokeError("incomplete_or_invalid_completion")
            message = choice.get("message")
            if not isinstance(message, dict) or message.get("role") != "assistant":
                raise SmokeError("invalid_assistant_message")
            row["status"] = "returned"
            return message
        except SmokeError as error:
            row.update(status="failed", error=str(error))
            raise
        finally:
            row["elapsed_seconds"] = time.monotonic() - started


def wait_ready(client: Client, seconds: float, server_pid=None, *, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    attempts = 0
    while clock() < deadline:
        if server_pid is not None:
            try:
                os.kill(server_pid, 0)
            except OSError:
                raise SmokeError("server_exited_before_readiness") from None
        attempts += 1
        try:
            response = client.request("/models", timeout=min(5, max(0.1, deadline - clock())))
            models = response.get("data")
            if isinstance(models, list) and any(isinstance(row, dict) and row.get("id") == MODEL for row in models):
                return {"attempts": attempts, "model": MODEL}
            raise SmokeError("served_model_missing")
        except SmokeError as error:
            # Authentication/wrong-service failures will not improve by polling.
            if str(error) in {"http_status_401", "http_status_403", "redirect_rejected", "served_model_missing"}:
                raise
            sleep(min(5, max(0, deadline - clock())))
    raise SmokeError("readiness_timeout")


def calls(message: dict, name: str, expected: list[dict]) -> list[dict]:
    result = message.get("tool_calls")
    if not isinstance(result, list) or len(result) != len(expected):
        raise SmokeError("wrong_tool_call_count")
    seen, arguments = set(), []
    for call in result:
        if not isinstance(call, dict) or call.get("type") != "function":
            raise SmokeError("invalid_tool_call")
        identifier, function = call.get("id"), call.get("function")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen:
            raise SmokeError("missing_or_duplicate_call_id")
        seen.add(identifier)
        if not isinstance(function, dict) or function.get("name") != name:
            raise SmokeError("wrong_tool_function")
        raw = function.get("arguments")
        if not isinstance(raw, str):
            raise SmokeError("arguments_not_json_string")
        arguments.append(strict_json(raw))
    # Canonical bytes keep bool distinct from int and preserve array element order.
    def canonical(item):
        return json.dumps(item, sort_keys=True, ensure_ascii=False, allow_nan=False)

    if sorted(map(canonical, arguments)) != sorted(map(canonical, expected)):
        raise SmokeError("tool_argument_value_or_type_mismatch")
    return [{"id": call["id"], "type": "function", "function": call["function"]} for call in result]


def final_text(message: dict) -> str:
    if message.get("tool_calls"):
        raise SmokeError("unexpected_tool_call_in_final")
    text = message.get("content")
    if not isinstance(text, str) or not text.strip():
        raise SmokeError("missing_final_text")
    return text.strip()


def judge_result(message: dict) -> dict:
    value = strict_json(final_text(message))
    if not isinstance(value, dict) or set(value) != {"same_action", "confidence", "reasoning"}:
        raise SmokeError("judge_schema_mismatch")
    if type(value["same_action"]) is not bool or value["same_action"] is not False:
        raise SmokeError("judge_boolean_mismatch")
    confidence = value["confidence"]
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise SmokeError("judge_confidence_invalid")
    if not isinstance(value["reasoning"], str) or not value["reasoning"].strip():
        raise SmokeError("judge_reasoning_missing")
    return value


def run_checks(client: Client):
    expected = {"labels": ["café", "tea"], "note": None}
    schema = {"type": "function", "function": {"name": "make_receipt",
              "description": "Create a synthetic receipt for the exact supplied labels and optional note.",
              "parameters": {"type": "object", "properties": {
                  "labels": {"type": "array", "items": {"type": "string"}},
                  "note": {"type": ["string", "null"]}},
                  "required": ["labels", "note"], "additionalProperties": False}}}
    messages = [{"role": "system", "content": "Use the provided synthetic tools exactly as requested."},
                {"role": "user", "content": 'Call make_receipt once with labels ["café", "tea"] and note null. '
                 "When the receipt is returned, reply with only its receipt_id and do not call tools again."}]
    message = client.chat("single_tool", messages, tools=[schema], tool_choice="auto")
    selected = calls(message, "make_receipt", [expected])
    client.rows[-1]["status"] = "passed"
    messages += [{"role": "assistant", "content": message.get("content"), "tool_calls": selected},
                 {"role": "tool", "tool_call_id": selected[0]["id"],
                  "content": '{"receipt_id":"SCOUT_RECEIPT_6131","labels":["café","tea"],"note":null}'}]
    final = client.chat("tool_result_round_trip", messages, tools=[schema], tool_choice="auto")
    if final_text(final) != "SCOUT_RECEIPT_6131":
        raise SmokeError("tool_result_not_recovered")
    client.rows[-1]["status"] = "passed"
    lookup = {"type": "function", "function": {"name": "lookup_item", "description": "Read a synthetic item.",
              "parameters": {"type": "object", "properties": {"item_id": {"type": "integer"}},
                             "required": ["item_id"], "additionalProperties": False}}}
    parallel = client.chat("parallel_tools", [{"role": "user", "content":
        "Call lookup_item for item_id 7 and item_id 9 in the same response: exactly two calls, no other text."}],
        tools=[lookup], tool_choice="auto")
    calls(parallel, "lookup_item", [{"item_id": 7}, {"item_id": 9}])
    client.rows[-1]["status"] = "passed"
    judged = client.chat("no_tools_judge", [{"role": "system", "content":
        'Return only JSON with same_action (boolean), confidence (number 0..1), reasoning (nonempty string). '
        "No Markdown. Different recipients make the actions different."}, {"role": "user", "content":
        'Compare send_email(recipients=["a@example.invalid"]) and '
        'send_email(recipients=["b@example.invalid"]). Are they the same action?'}],
        response_format={"type": "json_object"})
    judge_result(judged)
    client.rows[-1]["status"] = "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/v1")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wait-seconds", type=int, default=1500, choices=range(1, 1501), metavar="1..1500")
    parser.add_argument("--server-pid", type=int)
    args = parser.parse_args()
    key = os.environ.get("LOCAL_LLM_API_KEY", "")
    summary = {"protocol": "nesi-scout-smoke-v1", "status": "failed", "max_requests": 4,
               "scope": "synthetic transport/model-format smoke; not AgentDojo or attribution evaluation"}
    # Reserve before networking so an existing successful receipt is never replaced.
    with args.output.open("x", encoding="utf-8") as stream:
        client = None
        try:
            client = Client(args.base_url, key)
            summary["readiness"] = wait_ready(client, args.wait_seconds, args.server_pid)
            run_checks(client)
            summary["status"] = "passed"
        except SmokeError as error:
            summary["error"] = str(error)
            if client and client.rows and client.rows[-1]["status"] == "returned":
                client.rows[-1].update(status="failed", error=str(error))
        finally:
            summary["requests"] = client.rows if client else []
            summary["requests_started"] = len(summary["requests"])
            encoded = json.dumps(summary, ensure_ascii=False, indent=2)
            stream.write((encoded.replace(key, "[REDACTED]") if key else encoded) + "\n")
    print("Scout smoke " + summary["status"] + "; inspect the local receipt.")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
