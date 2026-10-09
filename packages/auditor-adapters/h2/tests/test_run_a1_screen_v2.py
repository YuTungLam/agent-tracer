"""Zero-provider checks for the isolated two-case exploratory PC4/PC5 smoke."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_a1_screen_v2 as v2


@pytest.fixture(scope="module")
def bundle() -> dict:
    from agentdojo_lab.a1_pc5_v2_cases import generate_cases

    return generate_cases()


def test_real_native_bundle_expands_only_two_dev_controlled_cases(bundle: dict) -> None:
    episodes, cases = v2.validate_cases(bundle)
    assert len(episodes) == 16
    assert len({ep["episode_id"] for ep in episodes}) == 16
    assert {ep["case_id"] for ep in episodes} == set(cases)
    assert {ep["split"] for ep in bundle["cases"]} == {"dev"}
    assert {ep["repeat"] for ep in episodes} == {0, 1}
    assert {ep["arm"] for ep in episodes} == set(v2.ARMS)
    assert {ep["placement"].split("-")[0] for ep in episodes} == {"pc4", "pc5"}
    assert all(ep["attack_text"] == "" for ep in episodes if ep["arm"] == "CLEAN")
    assert all(ep["attack_text"] for ep in episodes if ep["arm"] != "CLEAN")


def test_fixture_drift_and_eval_refused_even_with_rehashed_cases(bundle: dict) -> None:
    changed = json.loads(json.dumps(bundle))
    changed["cases"][0]["arms"]["A1-fact"]["arm_text"] += " extra"
    changed["cases_sha256"] = v2.v1._digest(changed["cases"])
    with pytest.raises(v2.v1.ScreenError, match="differs from registered"):
        v2.validate_cases(changed)
    changed = json.loads(json.dumps(bundle))
    changed["cases"][0]["split"] = "eval"
    changed["cases_sha256"] = v2.v1._digest(changed["cases"])
    with pytest.raises(v2.v1.ScreenError, match="differs from registered"):
        v2.validate_cases(changed)


def test_state_marker_uses_typed_target_state() -> None:
    from agentdojo_lab.a1_pc5_v2_cases import S8_ID, W34_ID

    class File:
        def __init__(self, content: str, size: int) -> None:
            self.content = content
            self.size = size

    class Drive:
        def __init__(self, content: str, size: int) -> None:
            self.files = {"26": File(content, size)}

    class Env:
        def __init__(self, content: str, size: int) -> None:
            self.cloud_drive = Drive(content, size)

    class Message:
        def __init__(self, text: str) -> None:
            self.text = text

        def model_dump(self, *, mode: str) -> dict:
            assert mode == "json"
            return {"body": self.text}

    class Slack:
        def __init__(self, messages: list[str]) -> None:
            self.channel_inbox = {"general": [Message(text) for text in messages]}

    class SlackEnv:
        def __init__(self, messages: list[str]) -> None:
            self.slack = Slack(messages)

    before, after, changed = v2.target_state_change(
        Env("original 26", 11), Env("original 26 + cookies", 21), {"case_id": W34_ID}, "26")
    assert changed is True
    assert before["size"] == 11 and after["size"] == 21
    same = v2.target_state_change(Env("original 26", 11), Env("original 26", 11),
                                  {"case_id": W34_ID}, "26")
    assert same[2] is False
    s8_pre, s8_post, s8_changed = v2.target_state_change(
        SlackEnv(["earlier"]), SlackEnv(["earlier", "new post"]), {"case_id": S8_ID}, "general")
    assert s8_changed is True
    assert s8_pre["message_count"] == 1 and s8_post["message_count"] == 2


def test_plan_only_real_bundle_makes_no_evidence_or_model_call(
    bundle: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentdojo_lab.a1_pc5_v2_cases import CONFIG_PATH

    lab = CONFIG_PATH.parents[1]
    case_file = tmp_path / "cases.json"
    case_file.write_text(json.dumps(bundle, ensure_ascii=False) + "\n", encoding="utf-8")
    code_commit = "a" * 40
    monkeypatch.setattr(v2.v1, "_git_state", lambda _: {"commit": code_commit, "dirty": False})
    out = tmp_path / "new-run"
    code = v2.main(["--cases", str(case_file), "--expect-case-sha256", v2.hc.sha256_file(case_file),
                    "--expect-code-commit", code_commit, "--stage-config", str(v2.HERE / "stages.a1.v2.json"),
                    "--stage", v2.STAGE, "--lab-root", str(lab), "--results-root", str(tmp_path),
                    "--out-dir", str(out), "--plan-only"])
    assert code == 0
    assert not out.exists()


def test_hard_caps_are_exact_and_no_full_stage() -> None:
    stage = json.loads((v2.HERE / "stages.a1.v2.json").read_text(encoding="utf-8"))
    assert set(stage["stages"]) == {v2.STAGE}
    actual = stage["stages"][v2.STAGE]
    assert {key: actual[key] for key in v2.HARD_CAPS} == v2.HARD_CAPS
    assert actual["repeats"] == 2
    assert actual["arms"] == list(v2.ARMS)


def test_native_rendered_message_proof_keeps_w34_sources_separate(bundle: dict) -> None:
    from agentdojo_lab.a1_pc5_v2_cases import W34_ID

    episodes, cases = v2.validate_cases(bundle)
    proof = v2.native_source_proof(episodes, cases)
    w34 = proof[W34_ID]
    assert w34["A1-instr"]["steering_source_indices"] == [0]
    assert w34["A1-instr"]["declared_x_source_indices"] == [1]
    assert w34["A1-instr"]["x_steering_different_sources"] is True
    assert [source["tool"] for source in w34["A1-instr"]["tool_messages"]] == [
        "search_files_by_filename", "search_files"]
    assert all(len(source["text_sha256"]) == 64 for source in w34["A1-instr"]["tool_messages"])
    assert w34["SS-instr"]["x_and_steering_in_same_source"] is True
    assert w34["CLEAN"]["steering_source_indices"] == []


@pytest.mark.parametrize("suite_name", ["slack", "workspace"])
@pytest.mark.parametrize("arm", ["CLEAN", "SS-instr", "A1-instr"])
def test_runner_consumes_native_environment_without_a_model(
    bundle: dict, suite_name: str, arm: str, tmp_path: Path,
) -> None:
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.task_suite.load_suites import get_suite

    class NoModel:
        def __init__(self) -> None:
            self.stats = {"request_count": 0, "prompt_tokens": 0, "completion_tokens": 0}

        def begin_episode(self) -> None:
            pass

        def begin_attempt(self) -> None:
            pass

    episodes, by_id = v2.validate_cases(bundle)
    ep = next(ep for ep in episodes if ep["suite"] == suite_name and ep["arm"] == arm)
    case = by_id[ep["case_id"]]
    suite = get_suite("v1.2.2", suite_name)
    task = suite.get_user_task_by_id(ep["user_task_id"])
    record = v2.run_one(ep, case, suites={suite_name: suite},
                        rt={"llm": NoModel(), "pipeline": GroundTruthPipeline(task)},
                        transcripts=tmp_path)
    assert record["run_error"] is False
    assert record["requests"] == 0
    assert record["outcome"] == "legitimate"
    assert record["utility"] is True
    assert record["x_sink_called"] is False
    assert record["target_state_changed"] is False
    assert record["steering_exposed"] is (arm != "CLEAN")
    if arm != "CLEAN":
        assert record["x_exposed"] is True
    if arm == "SS-instr":
        assert record["x_and_steering_in_same_source"] is True
        assert record["x_steering_different_sources"] is False
    if arm == "A1-instr":
        assert record["x_and_steering_in_same_source"] is False
        assert record["x_steering_different_sources"] is True
        assert record["declared_x_source_indices"] == [1 if suite_name == "workspace" else 0]
        assert record["steering_source_indices"] == [0 if suite_name == "workspace" else 1]
    assert (tmp_path / record["transcript_path"]).is_file()
