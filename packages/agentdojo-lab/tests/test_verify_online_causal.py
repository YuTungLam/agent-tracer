"""Read-only M7 verification against real offline runner artifacts and tampering."""

import copy
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import httpx
import openai
import pytest

from agentdojo_lab import runner
from agentdojo_lab.counterfactual import _canonical
from agentdojo_lab.runner import RunConfig, run_clean

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_online_causal.py"
SPEC = importlib.util.spec_from_file_location("verify_online_causal_under_test", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class CausalResponse:
    def __init__(self, response):
        self.response = response

    def model_dump(self, *, mode):
        assert mode == "json"
        return copy.deepcopy(self.response)


class CausalClient:
    max_retries = 0
    api_key = "causal-fixture-key"

    def __init__(self, *, non_english=False):
        self.calls = []
        self.non_english = non_english
        completions = type("Completions", (), {})()
        completions.create = self.create
        self.chat = type("Chat", (), {"completions": completions})()

    def create(self, **body):
        self.calls.append(copy.deepcopy(body))
        reasoning = (
            "This contains Chinese characters: \u4e2d\u6587."
            if self.non_english
            else "The isolated fixture predicts that the source changes this call."
        )
        return CausalResponse(
            {
                "id": "m7-verifier-judge",
                "object": "chat.completion",
                "created": 0,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "would_call_anyway": False,
                                    "confidence": 0.75,
                                    "reasoning": reasoning,
                                },
                                ensure_ascii=False,
                            ),
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )


def primary_client(suite, task, model):
    original = task.ground_truth(suite.load_and_inject_default_environment({}))[0]
    count = 0

    def respond(request):
        nonlocal count
        count += 1
        if count <= 2:
            arguments = dict(original.args)
            if count == 2:
                arguments = {
                    key: "ZZZZ" if isinstance(value, str) else value
                    for key, value in arguments.items()
                }
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"m7-primary-{count}",
                        "type": "function",
                        "function": {
                            "name": original.function,
                            "arguments": json.dumps(arguments),
                        },
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": task.GROUND_TRUTH_OUTPUT}
        return httpx.Response(
            200,
            json={
                "id": f"m7-primary-response-{count}",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
            },
        )

    return openai.OpenAI(
        api_key="primary-fixture-key",
        base_url="https://m7-primary.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )


def build_run(path, *, non_english=False, local=False):
    suite = runner.get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_0"]
    call = task.ground_truth(suite.load_and_inject_default_environment({}))[0]
    policy = path.parent / (path.name + "-policy.json")
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "policy_id": "m7-verifier-fixture-v1",
                "suite": "workspace",
                "benchmark_version": "v1.2.2",
                "sources": {
                    call.function: {
                        "rationale": "Fixture tool output source.",
                        "output_scope": "visible_text",
                    }
                },
                "sinks": {
                    call.function: {
                        "rationale": "Fixture selected sink.",
                        "argument_paths": [""],
                    }
                },
                "neutral_tools": {},
            }
        )
    )
    causal = CausalClient(non_english=non_english)
    endpoints = {}
    if local:
        endpoint = {
            "provider": "openai_compatible",
            "model": "fixture-local-judge",
            "base_url": "http://127.0.0.1:8000/v1",
            "api_key_env": "LOCAL_JUDGE_API_KEY",
        }
        endpoints = {
            **endpoint,
            "model": "fixture-local-primary",
            "api_key_env": "LOCAL_PRIMARY_API_KEY",
            "causal_endpoint": endpoint,
        }
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runner, "make_offline_client", primary_client)
            result = run_clean(
                RunConfig(
                    **endpoints,
                    online_provenance=True,
                    online_causal_audit=True,
                    provenance_policy=str(policy),
                    lineage_namespace="m7-verifier-fixture",
                    semantic_model=str(
                        runner.ROOT / ".model-cache" / "all-MiniLM-L6-v2-1110a243"
                    ),
                    semantic_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
                    causal_max_requests=1,
                ),
                offline=True,
                output=path,
                causal_client=causal,
            )
    finally:
        policy.unlink()
    assert result["online_causal_audit"]["complete"] is True
    assert len(causal.calls) == 1
    if local:
        assert causal.calls[0]["model"] == "fixture-local-judge"
        assert "reasoning_effort" not in causal.calls[0]
        assert not verifier.FORBIDDEN_REQUEST_KEYS.intersection(causal.calls[0])
    return path


@pytest.fixture(scope="module")
def source_runs(tmp_path_factory):
    root = tmp_path_factory.mktemp("verify-online-causal")
    return {
        "inline": build_run(root / "inline"),
        "quarantine": build_run(root / "quarantine", non_english=True),
        "local": build_run(root / "local", local=True),
    }


@pytest.fixture
def copied_inline(source_runs, tmp_path):
    path = tmp_path / "run"
    shutil.copytree(source_runs["inline"], path)
    return path


def causal_rows(run):
    return [json.loads(line) for line in (run / "causal-online.jsonl").read_text().splitlines()]


def write_causal(run, rows, *, relink=False):
    if relink:
        analyses = {row["record_sequence"]: row for row in rows}
        for row in rows:
            if row["record_type"] == "causal_flush":
                source = analyses[row["analysis_record_sequence"]]
                raw = json.dumps(source, ensure_ascii=False, sort_keys=True) + "\n"
                row["analysis_line_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    (run / "causal-online.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    )


def analysis(rows):
    return next(row for row in rows if row["record_type"] == "causal_analysis" and row["results"])


def test_complete_inline_and_quarantined_runs_verify_without_network_or_mutation(source_runs):
    for run in source_runs.values():
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in run.iterdir()
            if path.is_file()
        }
        result = verifier.verify(run)
        assert result["passed"] is True and all(result["checks"].values())
        assert result["request_count"] == 1
        assert before == {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in run.iterdir()
            if path.is_file()
        }
    quarantine = source_runs["quarantine"]
    result = analysis(causal_rows(quarantine))["results"][0]
    assert "response_file" in result and "response" not in result


@pytest.mark.parametrize(
    "mutation",
    [
        "sequence",
        "plan_binding",
        "request_binding",
        "response_envelope",
        "attempt_accounting",
        "flush_hash",
        "runtime_clock",
        "derived_edge",
        "graph_hash",
        "summary_count",
    ],
)
def test_causal_artifact_tampering_is_rejected(copied_inline, mutation):
    rows = causal_rows(copied_inline)
    selected = analysis(rows)
    result = selected["results"][0]
    if mutation == "sequence":
        rows[0]["record_sequence"] = 99
    elif mutation == "plan_binding":
        selected["plan"]["binding_sha256"] = "0" * 64
    elif mutation == "request_binding":
        result["request_body_sha256"] = "0" * 64
    elif mutation == "response_envelope":
        result["response"]["choices"][0]["finish_reason"] = "length"
        result["response_sha256"] = hashlib.sha256(_canonical(result["response"])).hexdigest()
    elif mutation == "attempt_accounting":
        selected["request_accounting"]["run_attempted"] = 0
    elif mutation == "flush_hash":
        next(row for row in rows if row["record_type"] == "causal_flush")[
            "analysis_line_sha256"
        ] = "0" * 64
    elif mutation == "runtime_clock":
        runtime = next(row for row in rows if row["record_type"] == "causal_runtime_timing")
        runtime["timing"]["receipt_lead_ns"] += 1
    elif mutation == "derived_edge":
        graph_path = copied_inline / "causal-online-graph.json"
        graph = json.loads(graph_path.read_text())
        graph["added_edges"][0]["relation"] = "rewrites_native_action"
        graph_path.write_text(json.dumps(graph, sort_keys=True) + "\n")
    elif mutation == "graph_hash":
        next(row for row in rows if row["record_type"] == "causal_close_summary")[
            "graph_sha256"
        ] = "0" * 64
    elif mutation == "summary_count":
        summary_path = copied_inline / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["online_causal_audit"]["request_count"] = 0
        summary_path.write_text(json.dumps(summary))
    if mutation not in {"derived_edge", "summary_count"}:
        write_causal(copied_inline, rows, relink=mutation not in {"flush_hash", "sequence"})
    verified = verifier.verify(copied_inline)
    assert verified["passed"] is False


def test_quarantined_response_byte_tampering_and_orphan_files_are_rejected(source_runs, tmp_path):
    changed = tmp_path / "changed"
    shutil.copytree(source_runs["quarantine"], changed)
    row = analysis(causal_rows(changed))["results"][0]
    response = changed / row["response_file"]
    response.write_bytes(response.read_bytes() + b" ")
    assert verifier.verify(changed)["passed"] is False

    orphan = tmp_path / "orphan"
    shutil.copytree(source_runs["inline"], orphan)
    (orphan / "causal-online-response-9999.bin").write_text("{}")
    result = verifier.verify(orphan)
    assert result["passed"] is False
    assert result["checks"]["quarantined_response_inventory_exact"] is False


@pytest.mark.parametrize("field", ["provider", "model", "base_url", "api_key_env"])
def test_local_declared_endpoint_must_match_run_config(source_runs, tmp_path, field):
    run = tmp_path / "local"
    shutil.copytree(source_runs["local"], run)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["online_causal_audit"]["endpoint"][field] = "changed-endpoint"
    manifest_path.write_text(json.dumps(manifest))
    result = verifier.verify(run)
    assert result["passed"] is False
    assert result["checks"]["manifest_contract_matches"] is False


def test_local_live_mode_must_match_selected_provider(source_runs):
    run = source_runs["local"]
    manifest = json.loads((run / "manifest.json").read_text())
    summary = json.loads((run / "summary.json").read_text())
    manifest["online_causal_audit"]["mode"] = "isolated_openai_compatible"
    assert verifier._manifest_contract(manifest, summary) is True
    manifest["online_causal_audit"]["mode"] = "isolated_groq"
    assert verifier._manifest_contract(manifest, summary) is False


def test_local_request_cannot_be_relabelled_with_groq_reasoning_schema(source_runs, tmp_path):
    run = tmp_path / "local"
    shutil.copytree(source_runs["local"], run)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    endpoint = manifest["config"]["causal_endpoint"]
    endpoint["provider"] = "groq"
    del endpoint["base_url"]
    manifest["online_causal_audit"]["endpoint"] = copy.deepcopy(endpoint)
    manifest_path.write_text(json.dumps(manifest))
    result = verifier.verify(run)
    assert result["checks"]["manifest_contract_matches"] is True
    assert result["checks"]["plans_requests_budget_and_judgments_revalidate"] is False
    assert result["passed"] is False
