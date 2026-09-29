"""Explicit runtime profile selection through real prefixes and native SDK mocks."""

import copy
import json

import pytest
from test_heldout_runner import heldout_config, heldout_scripted_client
from test_online import feed, rows
from test_policy_cascade_integration import document, prepared
from test_semantic import FakeEncoder

from agentdojo_lab import runner, semantic
from agentdojo_lab.lineage import DCPG
from agentdojo_lab.online import OnlineProvenance
from agentdojo_lab.policy import ToolPolicy
from agentdojo_lab.profiles import get_profile
from agentdojo_lab.provenance import ProvenanceTracker
from agentdojo_lab.runner import RunConfig, load_config
from agentdojo_lab.semantic import SemanticMatcher


def _calls(tape, **kwargs):
    tracker = ProvenanceTracker(**kwargs)
    return [call for event in tape.events if (call := tracker.consume(event)) is not None]


@pytest.mark.parametrize("policy", [None, ToolPolicy.from_dict(document())])
def test_explicit_ordinary_preserves_complete_prefix_outputs(policy):
    tape, _, _, _ = prepared()
    assert _calls(tape, policy=policy) == _calls(tape, policy=policy, cascade_profile="ordinary")


@pytest.mark.parametrize("name", ["memory", "implicit_string", "safe_control"])
def test_tracker_rejects_nonordinary_profile_without_policy(name):
    with pytest.raises(ValueError, match="requires a frozen source/sink policy"):
        ProvenanceTracker(cascade_profile=name)


@pytest.mark.parametrize("name", ["implicit_string", "safe_control", "unknown"])
def test_invalid_online_profile_setup_disables_sidecar_before_open(tmp_path, name):
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path, cascade_profile=name)
    assert sidecar.status()["disabled"] is True
    assert sidecar.status()["complete"] is False
    assert sidecar.status()["errors"] == [
        {"stage": "initialize", "error_type": "ValueError", "event_sequence": None}
    ]
    assert not path.exists()
    sidecar.close()


@pytest.mark.parametrize(
    "name,source,target,ordinary_tier,selected_tier",
    [
        ("implicit_string", "AAAXXXXXXX", "AAAYYYYYYY", "tier2", "tier3"),
        ("safe_control", "AAAA", "BBBB", "tier3", None),
    ],
)
def test_profile_reaches_online_proposal_with_unchanged_recorded_inputs(
    tmp_path, name, source, target, ordinary_tier, selected_tier
):
    tape, _, _, _ = prepared(sources=(("read_note", source),), arguments={"text": target})
    for event in tape.events:
        event["data"]["evaluation"] = {"gold": False, "safe_control": True, "family": "memory"}
    original = copy.deepcopy(tape.events)
    policy = ToolPolicy.from_dict(document())
    vectors = {source: (3.0, 4.0), target: (5.0, 0.0)}
    ordinary = _calls(tape, policy=policy, semantic_matcher=SemanticMatcher(FakeEncoder(vectors)))[-1]
    assert ordinary["fields"][0]["nt_style_cascade"][0]["first_matched_tier"] == ordinary_tier
    profile = get_profile(name)
    matcher = SemanticMatcher(
        FakeEncoder(vectors),
        semantic_threshold=profile.semantic_threshold,
        coverage_threshold=profile.coverage_threshold,
    )
    path = tmp_path / "provenance.jsonl"
    sidecar = OnlineProvenance(path, semantic_matcher=matcher, policy=policy, cascade_profile=name)
    feed(sidecar, tape.events)
    sidecar.close()
    call = [row["call"] for row in rows(path) if row["record_type"] == "call_analysis"][-1]
    pair = call["fields"][0]["nt_style_cascade"][0]
    assert pair["first_matched_tier"] == selected_tier
    assert pair["metadata"]["profile"] == name
    assert pair["metadata"]["profile_selection"] == "caller_declared_profile; no_evaluation_labels"
    assert pair["stages"]["tier1"]["status"] == "disabled_condition"
    assert sidecar.status()["complete"] is True
    assert tape.events == original


def test_restored_memory_thresholds_do_not_change_explicit_direct_profile():
    policy = ToolPolicy.from_dict(document())
    encoder = FakeEncoder()
    matcher = SemanticMatcher(encoder, semantic_threshold=0.95)
    lineage = DCPG("fixture-memory-store", policy, semantic_matcher=matcher)
    tracker = ProvenanceTracker(
        semantic_matcher=matcher, policy=policy, lineage=lineage, cascade_profile="safe_control"
    )
    assert tracker.cascade_matcher.profile == "safe_control"
    assert tracker.cascade_matcher.semantic_threshold == 0.95
    assert lineage.matcher.profile == "memory"
    assert lineage.matcher.semantic_threshold == 0.85
    assert lineage.matcher.semantic_matcher.encoder is encoder
    assert matcher.semantic_threshold == 0.95


def test_default_config_dump_retains_legacy_shape_and_explicit_profile_is_recorded():
    default = RunConfig()
    assert default.cascade_profile == "ordinary"
    assert "cascade_profile" not in default.model_dump()
    assert "cascade_profile" not in json.loads(default.model_dump_json())
    assert RunConfig(cascade_profile="ordinary").model_dump() == default.model_dump()
    assert RunConfig.model_validate(default.model_dump()).model_dump() == default.model_dump()
    selected = heldout_config(cascade_profile="safe_control")
    assert selected.model_dump()["cascade_profile"] == "safe_control"
    assert RunConfig.model_validate(selected.model_dump()).cascade_profile == "safe_control"


@pytest.mark.parametrize("name", ["ordinary", "implicit_string", "safe_control"])
def test_toml_profile_is_explicit_and_requires_policy_for_new_profiles(tmp_path, name):
    path = tmp_path / "run.toml"
    path.write_text(
        f'cascade_profile = "{name}"\nonline_provenance = true\nprovenance_policy = "policy.yaml"\n'
    )
    assert load_config(path).cascade_profile == name
    if name != "ordinary":
        with pytest.raises(ValueError, match="requires a frozen provenance policy"):
            RunConfig(cascade_profile=name)
        with pytest.raises(ValueError, match="requires online_provenance"):
            RunConfig(cascade_profile=name, provenance_policy="policy.yaml")


@pytest.mark.parametrize("name", ["memory", "unknown", "safe-control", True, None])
def test_runtime_config_does_not_offer_memory_as_a_direct_source_profile(name):
    with pytest.raises(ValueError):
        heldout_config(cascade_profile=name)


@pytest.mark.parametrize("name", ["ordinary", "implicit_string", "safe_control"])
def test_native_clean_runner_configures_semantics_and_records_selected_profile(monkeypatch, tmp_path, name):
    requests, states = heldout_scripted_client(monkeypatch)
    encoder = FakeEncoder()
    monkeypatch.setattr(semantic, "LocalMiniLMEncoder", lambda *args, **kwargs: encoder)
    output = tmp_path / "run"
    result = runner.run_clean(
        heldout_config(
            cascade_profile=name, semantic_model="fixture-local-model", semantic_revision="fixture-fixed"
        ),
        output=output,
    )
    assert result["status"] == "completed"
    assert result["task_success_count"] == 1
    assert result["online_provenance"]["complete"] is True
    assert len(requests) == 3
    assert states[-1]["value"] is True
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["input_condition"] == "passive"
    assert manifest["config"].get("cascade_profile", "ordinary") == name
    assert "profiles.py" in manifest["online_provenance"]["implementation_sha256"]
    pairs = [
        pair
        for row in rows(output / "provenance.jsonl")
        if row["record_type"] == "call_analysis"
        for field in row["call"]["fields"]
        for pair in field.get("nt_style_cascade", [])
    ]
    assert pairs
    thresholds = get_profile(name)
    for pair in pairs:
        assert pair["metadata"].get("profile", "ordinary") == name
        assert pair["metadata"]["thresholds"] == {
            "tier2_lcs": thresholds.lexical_threshold,
            "tier3_cosine": thresholds.semantic_threshold,
            "tier4_cosine": thresholds.semantic_threshold,
            "tier4_coverage": thresholds.coverage_threshold,
        }
        assert pair["stages"]["tier1"]["status"] == "disabled_condition"
