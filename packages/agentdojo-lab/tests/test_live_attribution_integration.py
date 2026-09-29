"""Live sidecar contracts with native AgentDojo tools and an SDK mock transport.

These benign deterministic fixtures establish integration properties, not model
capability, provenance accuracy, attack efficacy, or a hard runtime deadline.
"""

import json
from copy import deepcopy

import httpx
import openai
import test_observation as native

from agentdojo_lab.groq_adapter import GroqLLM
from agentdojo_lab.observation import ObservationSession, observe_pipeline
from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.recording import EventRecorder
from agentdojo_lab.runner import RunConfig, run_clean


class DeterministicMatcher:
    metadata = {"method": "fixture-semantic", "component_mode": "independent_all_pairs"}

    def __init__(self, *, fail=False):
        self.fail = fail
        self.comparisons = []

    def compare(self, source, target):
        self.comparisons.append((source, target))
        if self.fail:
            raise RuntimeError("fixture payload must not appear in sidecar diagnostics")
        return {
            "status": "scored" if source and target else "not_applicable",
            "matched": source == target if source and target else None,
            "tier3": {"status": "scored", "score": 0.25, "matched": False},
            "tier4": {"status": "scored", "score": 0.25, "matched": False, "chunks": []},
        }


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run_native(tmp_path, script, *, enabled, matcher=None, query_count=1, sidecar_builder=None):
    """Run the same actual SDK/native runtime path with only the sidecar changed."""
    tmp_path.mkdir()
    requests, executed, runtime_observations = [], [], []
    runtime = native.note_runtime(executed)
    original_runtime = runtime.run_function
    provenance_path = tmp_path / "provenance.jsonl"
    sidecar = (
        sidecar_builder(provenance_path)
        if enabled and sidecar_builder is not None
        else OnlineProvenance(provenance_path, semantic_matcher=matcher)
        if enabled
        else None
    )
    recorder = EventRecorder(
        tmp_path / "events.jsonl",
        "same-fixture-run",
        on_event=sidecar.consume if sidecar is not None else None,
    )
    observer = ObservationSession(recorder)

    def runtime_entry(env, function, args, *rest, **kwargs):
        if sidecar is not None:
            # Read from disk at the original runtime's entry, not after the run.
            runtime_observations.append(
                {"function": function, "arguments": deepcopy(args), "rows": read_lines(provenance_path)}
            )
        return original_runtime(env, function, args, *rest, **kwargs)

    runtime.run_function = runtime_entry

    def respond(request):
        requests.append(json.loads(request.content))
        assert len(requests) <= len(script), "Attribution must not add or retry generation requests"
        reply = script[len(requests) - 1]
        if isinstance(reply, tuple):
            return httpx.Response(reply[0], json=reply[1])
        return httpx.Response(200, json=native.completion(deepcopy(reply)))

    client = openai.OpenAI(
        api_key="synthetic-local-sidecar-key",
        base_url="https://sidecar.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    observer.attach(client)
    llm = GroqLLM(client, native.MODEL, observer=observer)
    pipeline = observe_pipeline(native.native_pipeline(llm), observer)
    env, initial_history, extra_args = native.NoteEnv(), [], {"fixture": "same-object"}
    messages, failure = [], None
    try:
        with client:
            for _ in range(query_count):
                output = pipeline.query("Use the note tools.", runtime, env, initial_history, extra_args)
                assert output[1] is runtime and output[2] is env and output[4] is extra_args
                messages.append(deepcopy(output[3]))
    except Exception as exc:
        failure = (type(exc), type(exc.__cause__) if exc.__cause__ else None)
    finally:
        recorder.close()
        if sidecar is not None:
            sidecar.close()
    assert initial_history == [] and extra_args == {"fixture": "same-object"}
    return {
        "requests": requests,
        "executed": executed,
        "messages": messages,
        "environment": env.model_dump(),
        "stats": llm.stats,
        "failure": failure,
        "events": read_lines(tmp_path / "events.jsonl"),
        "recording_status": observer.status(),
        "subscriber_status": recorder.subscriber_status(),
        "sidecar_status": sidecar.status() if sidecar is not None else None,
        "rows": read_lines(provenance_path) if sidecar is not None else [],
        "at_runtime_entry": runtime_observations,
    }


def assert_native_equal(baseline, enabled):
    for field in ("requests", "executed", "messages", "environment", "stats", "failure"):
        assert enabled[field] == baseline[field], field
    assert enabled["recording_status"]["complete"] is True


def normal_script():
    return [
        native.tool_message(native.tool_call("read_note", {"labels": ["alpha"]}, "read-1")),
        native.tool_message(
            native.tool_call("update_note", {"text": "Future text not present in this request."}, "write-1"),
            native.tool_call("update_note", {"text": "Original note."}, "write-2"),
        ),
        native.final_message(),
    ]


def test_sidecar_preserves_requests_actions_and_environment_and_flushes_before_tool_entry(tmp_path):
    baseline = run_native(tmp_path / "disabled", normal_script(), enabled=False)
    enabled = run_native(tmp_path / "enabled", normal_script(), enabled=True)
    assert_native_equal(baseline, enabled)
    assert enabled["failure"] is None
    assert enabled["sidecar_status"]["complete"] is True
    assert enabled["sidecar_status"]["analysis_count"] == 3
    proposals = native.of_type(enabled["events"], "TOOL_CALL_PROPOSED")
    starts = native.of_type(enabled["events"], "TOOL_RUNTIME_STARTED")
    assert len(enabled["at_runtime_entry"]) == len(starts) == len(proposals) == 3
    for proposal, start, observed in zip(proposals, starts, enabled["at_runtime_entry"], strict=True):
        available = [row for row in observed["rows"] if row.get("proposal_event_id") == proposal["event_id"]]
        assert {row["record_type"] for row in available} >= {"call_analysis", "analysis_flush"}
        timing = next(row for row in available if row["record_type"] == "runtime_timing")
        assert timing["runtime_event_id"] == start["event_id"]
        assert timing["analysis_before_runtime"] is True
        assert timing["receipt_before_runtime"] is True
        assert timing["timing"]["analysis_flushed_monotonic_ns"] <= start["monotonic_ns"]


def test_m7_online_causal_is_isolated_bound_and_non_enforcing_on_native_runtime(tmp_path):
    from test_causal_v2 import NegativeSemantic

    from agentdojo_lab.lineage import DCPG
    from agentdojo_lab.online_causal import OnlineCausalAuditor
    from agentdojo_lab.policy import ToolPolicy

    script = [
        native.tool_message(native.tool_call("read_note", {"labels": ["alpha"]}, "read-1")),
        native.tool_message(
            native.tool_call("update_note", {"text": "ZXQJ QVBN"}, "write-1"),
            native.tool_call("update_note", {"text": "Original note."}, "write-2"),
        ),
        native.final_message(),
    ]
    baseline = run_native(tmp_path / "disabled", script, enabled=False)
    policy = ToolPolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "m7-native-fixture",
            "suite": "workspace",
            "benchmark_version": "v1.2.2",
            "sources": {
                "read_note": {
                    "output_scope": "visible_text",
                    "rationale": "Fixture external note content.",
                }
            },
            "sinks": {
                "update_note": {
                    "argument_paths": ["/text"],
                    "rationale": "Fixture state-changing note update.",
                }
            },
            "neutral_tools": {},
        }
    )
    matcher = NegativeSemantic()
    lineage = DCPG("m7-native-fixture", policy)
    judge_requests = []

    def judge_response(request):
        body = json.loads(request.content)
        judge_requests.append(body)
        assert not {"tools", "tool_choice", "functions", "function_call"}.intersection(body)
        return httpx.Response(
            200,
            json={
                "id": "isolated-m7-judge",
                "object": "chat.completion",
                "created": 0,
                "model": "openai/gpt-oss-120b",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "would_call_anyway": False,
                                    "confidence": 0.8,
                                    "reasoning": "The recorded source changes this predicted call.",
                                }
                            ),
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    judge_client = openai.OpenAI(
        api_key="isolated-fixture-key",
        base_url="https://isolated-m7.invalid/v1",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(judge_response)),
    )
    causal = None

    def build_sidecar(path):
        nonlocal causal
        causal = OnlineCausalAuditor(path.with_name("causal-online.jsonl"), client=judge_client)
        return OnlineProvenance(
            path,
            semantic_matcher=matcher,
            policy=policy,
            lineage=lineage,
            causal_auditor=causal,
        )

    enabled = run_native(
        tmp_path / "enabled", script, enabled=True, sidecar_builder=build_sidecar
    )
    assert causal is not None
    causal.close(final_graph=lineage.snapshot())
    judge_client.close()

    assert_native_equal(baseline, enabled)
    status = causal.status()
    assert status["complete"] is True
    assert status["request_count"] == len(judge_requests) == 1
    assert status["before_runtime_verified_count"] == 3
    assert enabled["sidecar_status"]["causal_bridge_error_count"] == 0
    assert len(native.of_type(enabled["events"], "MODEL_REQUEST")) == len(enabled["requests"])
    rows = read_lines(tmp_path / "enabled" / "causal-online.jsonl")
    assert len([row for row in rows if row["record_type"] == "causal_analysis"]) == 3
    assert all(
        row["receipt_before_runtime"] is True
        for row in rows
        if row["record_type"] == "causal_runtime_timing"
    )
    graph = json.loads((tmp_path / "enabled" / "causal-online-graph.json").read_text())
    assert "predicted_control" in {edge["relation"] for edge in graph["added_edges"]}


def test_live_results_equal_prefix_replay_and_same_response_cannot_see_later_results(tmp_path):
    matcher = DeterministicMatcher()
    result = run_native(tmp_path / "run", normal_script(), enabled=True, matcher=matcher)
    tracker = ProvenanceTracker(semantic_matcher=DeterministicMatcher())
    replayed = [call for event in result["events"] if (call := tracker.consume(event)) is not None]
    live = [deepcopy(row["call"]) for row in result["rows"] if row["record_type"] == "call_analysis"]
    assert len(live) == len(replayed) == 3
    for actual, expected in zip(live, replayed, strict=True):
        assert actual.pop("availability").startswith("live_synchronous_sidecar")
        expected.pop("availability")
        assert actual == expected
    assert live[1]["request_event_id"] == live[2]["request_event_id"]
    assert live[1]["visible_sources"] == live[2]["visible_sources"]
    tools = [source for source in live[2]["visible_sources"] if source["kind"] == "tool"]
    assert tools and all("Future text" not in source["text"] for source in tools)
    assert all("Future text" not in source for source, _ in matcher.comparisons)


def test_semantic_exception_disables_only_attribution_and_does_not_leak_payload(tmp_path):
    baseline = run_native(tmp_path / "disabled", normal_script(), enabled=False)
    enabled = run_native(
        tmp_path / "enabled", normal_script(), enabled=True, matcher=DeterministicMatcher(fail=True)
    )
    assert_native_equal(baseline, enabled)
    assert enabled["failure"] is None
    status = enabled["sidecar_status"]
    assert status["complete"] is False and status["disabled"] is True
    assert status["errors"]
    assert "fixture payload" not in json.dumps(status)
    assert not [row for row in enabled["rows"] if row["record_type"] == "call_analysis"]
    assert len(enabled["requests"]) == 3 and len(enabled["executed"]) == 3


def test_provider_error_stays_a_provider_error_without_retry_or_fabricated_attribution(tmp_path):
    script = [(400, {"error": {"message": "Synthetic invalid request", "type": "invalid_request_error"}})]
    baseline = run_native(tmp_path / "disabled", script, enabled=False)
    enabled = run_native(tmp_path / "enabled", script, enabled=True)
    assert_native_equal(baseline, enabled)
    assert enabled["failure"][0] is openai.BadRequestError
    assert len(enabled["requests"]) == 1
    assert enabled["executed"] == []
    assert not [row for row in enabled["rows"] if row["record_type"] in {"call_analysis", "runtime_timing"}]


def test_unknown_and_failing_tools_keep_native_behavior_and_distinct_runtime_coverage(tmp_path):
    script = [
        native.tool_message(
            native.tool_call("no_such_tool", {"text": "absent"}, "missing"),
            native.tool_call("unavailable_note", {"note_id": "missing"}, "failing"),
        ),
        native.final_message(),
    ]
    baseline = run_native(tmp_path / "disabled", script, enabled=False)
    enabled = run_native(tmp_path / "enabled", script, enabled=True)
    assert_native_equal(baseline, enabled)
    calls = [row for row in enabled["rows"] if row["record_type"] == "call_analysis"]
    timings = [row for row in enabled["rows"] if row["record_type"] == "runtime_timing"]
    assert len(calls) == 2 and len(timings) == 1
    assert (
        next(row for row in calls if row["proposal_event_id"] == timings[0]["proposal_event_id"])["call"][
            "function"
        ]
        == "unavailable_note"
    )
    assert enabled["sidecar_status"]["complete"] is True


def test_new_episode_does_not_inherit_previous_visible_tool_sources(tmp_path):
    script = [
        native.tool_message(native.tool_call("read_note", {"labels": []}, "reused-provider-id")),
        native.final_message(),
        native.tool_message(
            native.tool_call("update_note", {"text": "Original note."}, "reused-provider-id")
        ),
        native.final_message(),
    ]
    enabled = run_native(tmp_path / "run", script, enabled=True, query_count=2)
    calls = [row["call"] for row in enabled["rows"] if row["record_type"] == "call_analysis"]
    assert enabled["failure"] is None
    assert len(calls) == 2 and calls[0]["episode_id"] != calls[1]["episode_id"]
    assert not [source for source in calls[1]["visible_sources"] if source["kind"] == "tool"]
    assert enabled["sidecar_status"]["complete"] is True


def test_run_clean_opt_in_keeps_native_results_and_default_creates_no_sidecar(tmp_path):
    baseline = run_clean(RunConfig(), offline=True, output=tmp_path / "disabled")
    enabled = run_clean(RunConfig(online_provenance=True), offline=True, output=tmp_path / "enabled")
    assert enabled["tasks"] == baseline["tasks"]
    assert enabled["usage"] == baseline["usage"]
    assert enabled["task_success_count"] == baseline["task_success_count"] == 1
    for result, label in ((baseline, "disabled"), (enabled, "enabled")):
        result["native_messages"] = json.loads((tmp_path / label / result["tasks"][0]["trace"]).read_text())[
            "messages"
        ]
    assert enabled["native_messages"] == baseline["native_messages"]
    assert enabled["recording"]["complete"] is True
    assert enabled["online_provenance"]["complete"] is True
    assert not (tmp_path / "disabled" / "provenance.jsonl").exists()
    rows = read_lines(tmp_path / "enabled" / "provenance.jsonl")
    assert len([row for row in rows if row["record_type"] == "call_analysis"]) == 1
