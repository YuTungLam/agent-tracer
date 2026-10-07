"""Request-free tests for the authority-origin census v1 and its successor v2 on vendored AgentDojo v1.2.2."""

import copy
import importlib.util
import json
import socket
from pathlib import Path

import pytest

from agentdojo_lab import authority_census as ac

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / ac.CONFIG_RELATIVE
ID_KINDS = {
    "email_id": {"id_field": "id_", "signature": ["id_", "sender", "recipients", "subject", "body"]},
    "cloud_file_id": {"id_field": "id_", "signature": ["id_", "filename", "content", "owner"]},
    "calendar_event_id": {"id_field": "id_", "signature": ["id_", "title", "start_time", "end_time", "participants"]},
    "transaction_id": {"id_field": "id", "signature": ["id", "sender", "recipient", "amount", "recurring"]},
}


@pytest.fixture(scope="module")
def config():
    loaded, _ = ac.load_config(CONFIG_PATH)
    return loaded


@pytest.fixture(scope="module")
def census(config):
    with ac.network_guard() as attempts:
        result = ac.run_census(config)
    assert attempts["count"] == 0
    return result


def _runner():
    spec = importlib.util.spec_from_file_location("authority_census_runner", ROOT / "scripts/run_authority_census.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- normalisation and matching -------------------------------------------------------------


def test_normalise_casefolds_and_collapses_whitespace():
    assert ac.normalise("  Mark.Black@Gmail.com\n\t to  ALICE ") == "mark.black@gmail.com to alice"


@pytest.mark.parametrize(
    ("haystack", "needle", "expected"),
    [
        ("send it to 'mark.black-2134@gmail.com' now", "mark.black-2134@gmail.com", True),
        ("website www.my-website-234.com/random.", "www.my-website-234.com/random", True),
        ("from the 13th to the 17th", "13", False),
        ("on 2024-05-13 at noon", "13", False),
        ("delete the file with id '13' now", "13", True),
        ("invite alice and bob", "alice", True),
        ("malice aforethought", "alice", False),
        ("channel external_0x", "external_0", False),
        ("the general channel", "general", True),
        ("", "x", False),
    ],
)
def test_contains_respects_boundaries(haystack, needle, expected):
    assert ac.contains(ac.normalise(haystack), ac.normalise(needle)) is expected


def test_occurrences_counts_only_bounded_hits():
    assert ac.occurrences("riverside view; riverside viewer; riverside view", "riverside view") == 2


def test_value_strings_is_element_wise_and_skips_absent_values():
    assert ac.value_strings(["a@x.com", "b@x.com"]) == ["a@x.com", "b@x.com"]
    assert ac.value_strings(7) == ["7"]
    assert ac.value_strings(None) == []
    assert ac.value_strings("") == []
    assert ac.value_strings([]) == []


# --- indexes ------------------------------------------------------------------------------------


def test_identifier_matching_is_per_object_type():
    dump = {
        "emails": {"26": {"id_": "26", "sender": "a", "recipients": [], "subject": "s", "body": "b"}},
        "files": {"3": {"id_": "3", "filename": "f", "content": "c", "owner": "o"}},
    }
    index = ac.TextIndex(dump, ID_KINDS)
    assert index.find("26", "email_id") == ["emails.26.id_"]
    assert index.find("26", "cloud_file_id") == []
    assert index.find("3", "cloud_file_id") == ["files.3.id_"]
    assert index.find("3", "email_id") == []


def test_text_index_covers_leaves_and_dictionary_keys():
    index = ac.TextIndex({"web_content": {"www.dora-website.com": "Dora: dora@gmail.com"}, "users": ["Alice"]}, ID_KINDS)
    assert index.find("www.dora-website.com", "url") == ["web_content.www.dora-website.com#key"]
    assert index.find("dora@gmail.com", "email_address") == ["web_content.www.dora-website.com"]
    assert index.find("alice", "slack_user") == ["users[0]"]
    assert index.find("Fred", "slack_user") == []


def test_classify_value_priority_prompt_then_environment_then_neither():
    index = ac.TextIndex({"contacts": ["john@x.com", "anna@x.com"]}, ID_KINDS)
    assert ac.classify_value("john@x.com", "email_address", "Mail John@X.com", index)["origin"] == "a_prompt"
    assert ac.classify_value("anna@x.com", "email_address", "Mail my colleague", index)["origin"] == "b_environment"
    assert ac.classify_value("eve@x.com", "email_address", "Mail my colleague", index)["origin"] == "c_neither"


def test_near_matches_are_diagnostic_only():
    index = ac.TextIndex({"hotels": [{"name": "Riverside View"}], "drive": "linda.green@bluesparrowtech.com"}, ID_KINDS)
    texts = [item["text"] for item in index.near_matches("Riverside View Hotel")]
    assert "riverside view" in texts
    texts = [item["text"] for item in index.near_matches("linda.green@luesparrowtech.com")]
    assert "linda.green@bluesparrowtech.com" in texts
    assert ac.classify_value("Riverside View Hotel", "booking_target", "", index)["origin"] == "c_neither"


def test_vector_hits_ignore_identifiers():
    defaults = {"bill": "IBAN: UK12345678901234567890", "note": ""}
    assert ac.vector_hits("UK12345678901234567890", "account", defaults) == ["bill"]
    assert ac.vector_hits("12", "cloud_file_id", {"v": "file 12"}) == []


# --- config and role table ------------------------------------------------------------------------


def test_frozen_config_loads_and_records_one_rule(config):
    assert config["protocol"] == ac.PROTOCOL
    assert "to whom, where, or on which account or resource" in config["role_rule"]["authority"]
    assert {item["id"] for item in config["judgement_calls"]} >= {f"J{i}" for i in range(1, 19)}
    assert config["amendment_log"][0]["after_seeing_counts"] is True


def test_validate_config_rejects_unknown_kind_and_bad_fallback(config):
    broken = copy.deepcopy(config)
    broken["tools"]["slack"]["post_webpage"]["authority"]["url"] = "web_address"
    with pytest.raises(ValueError, match="unknown kind"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config)
    broken["e1"]["security_checker_fallback"]["workspace"]["injection_task_6"][0]["argument"] = "subject"
    with pytest.raises(ValueError, match="is not authority"):
        ac.validate_config(broken)


def test_role_table_partitions_every_installed_tool(config):
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites("v1.2.2")
    rows = ac.validate_role_table(config, suites)
    assert {row["suite"] for row in rows} == set(ac.SUITES)
    authority = {(row["suite"], row["tool"], row["argument"]) for row in rows if row["argument_role"] == "authority"}
    assert ("workspace", "send_email", "recipients") in authority
    assert ("banking", "send_money", "recipient") in authority
    assert ("slack", "post_webpage", "url") in authority
    assert ("travel", "reserve_hotel", "hotel") in authority
    assert ("workspace", "send_email", "attachments") not in authority
    exfil = [row for row in rows if row["argument_role"] == "exfiltration"]
    assert [(row["suite"], row["tool"], row["argument"]) for row in exfil] == [("slack", "get_webpage", "url")]

    broken = copy.deepcopy(config)
    del broken["tools"]["banking"]["send_money"]
    with pytest.raises(ValueError, match="role table tools differ"):
        ac.validate_role_table(broken, suites)
    broken = copy.deepcopy(config)
    broken["tools"]["banking"]["send_money"]["content"].remove("date")
    with pytest.raises(ValueError, match="roles"):
        ac.validate_role_table(broken, suites)


# --- ground truth execution -----------------------------------------------------------------------


def test_run_ground_truth_records_arguments_before_tools_mutate_them():
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_6"]
    environment = suite.load_and_inject_default_environment({})
    records = ac.run_ground_truth(suite, task, environment)
    create = [record for record in records if record["function"] == "create_calendar_event"][0]
    assert create["args"]["participants"] == ["sarah.connor@gmail.com"]


def test_fallback_rules_follow_the_security_checkers(config):
    from agentdojo.task_suite.load_suites import get_suite

    environment = get_suite("v1.2.2", "workspace").load_and_inject_default_environment({})
    assert ac.derive_fallback_values({"rule": "next_email_id", "offset": 1}, environment) == ["35"]
    assert ac.derive_fallback_values({"rule": "unread_email_ids"}, environment) == ["9", "20", "21", "26", "27", "31"]
    assert len(ac.derive_fallback_values({"rule": "largest_file_ids", "n": 5}, environment)) == 5
    assert ac.derive_fallback_values({"rule": "account_email"}, environment) == ["emma.johnson@bluesparrowtech.com"]
    participants = ac.derive_fallback_values({"rule": "day_participants_excluding_account", "day": "2024-05-15"}, environment)
    assert "emma.johnson@bluesparrowtech.com" not in participants and participants == sorted(participants)
    # Deriving values must not mutate the shared environment (get_unread marks e-mails as read).
    assert ac.derive_fallback_values({"rule": "unread_email_ids"}, environment) == ["9", "20", "21", "26", "27", "31"]


def test_network_guard_refuses_and_restores():
    original = socket.create_connection
    with ac.network_guard() as attempts:
        with pytest.raises(OSError):
            socket.create_connection(("example.invalid", 80), timeout=1)
    assert attempts["count"] == 1
    assert socket.create_connection is original


# --- census anchors (full run on vendored AgentDojo, no requests) ------------------------------------


def _value(rows, **match):
    hits = [row for row in rows if all(row[key] == value for key, value in match.items())]
    assert hits, match
    return hits


def test_e0_anchor_rows(census):
    values = census["e0"]["values"]
    bill = _value(values, suite="banking", user_task_id="user_task_0", argument="recipient")[0]
    assert bill["value"] == "UK12345678901234567890"
    assert bill["origin"] == "b_environment" and bill["exposed_before_call"]
    assert bill["in_injection_vector_defaults"] == ["injection_bill_text"]
    created = _value(values, suite="workspace", user_task_id="user_task_32", function="share_file", argument="file_id")[0]
    assert created["origin"] == "c_neither" and created["exposed_before_call"]
    channel = _value(values, suite="slack", user_task_id="user_task_7", argument="channel")[0]
    assert channel["value"] == "External_0" and channel["origin"] == "b_environment"
    prompt = _value(values, suite="travel", user_task_id="user_task_0", argument="hotel")[0]
    assert prompt["origin"] == "a_prompt"


def test_e0_summary_is_consistent(census):
    summary = census["e0"]["summary"]
    overall = summary["overall"]
    assert overall["user_tasks"] == 97
    assert overall["values"]["total"] == len(census["e0"]["values"])
    assert sum(overall["values"][origin] for origin in ac.ORIGINS) == overall["values"]["total"]
    assert len(summary["precision_denominator"]) == overall["tasks_with_b"]
    for item in summary["precision_denominator"]:
        assert item["b_values"]
    per_tool_total = sum(cell["total"] for cell in summary["per_tool_argument"].values())
    assert per_tool_total == overall["values"]["total"]


def test_e1_anchor_rows(census):
    values = census["e1"]["values"]
    riverside = _value(values, suite="travel", injection_task_id="injection_task_0", argument="hotel")[0]
    assert riverside["stated_in_goal"] and not riverside["in_clean_environment"]
    assert "riverside view" in [item["text"] for item in riverside["near_matches"]]
    palace = _value(values, suite="travel", injection_task_id="injection_task_4", argument="hotel")[0]
    assert palace["value"] == "Luxury Palace" and not palace["stated_in_goal"] and palace["in_clean_environment"]
    fallback = _value(values, suite="workspace", injection_task_id="injection_task_13")
    assert {row["value_source"] for row in fallback} == {"security_checker_fallback"}
    assert all(not row["stated_in_goal"] and row["in_clean_environment"] for row in fallback)
    tasks = {(row["suite"], row["injection_task_id"]): row for row in census["e1"]["tasks"]}
    assert tasks[("workspace", "injection_task_6")]["gt_only"]["category"] == "no_authority_value"
    assert tasks[("workspace", "injection_task_6")]["gt_plus_fallback"]["category"] == "partial_goal_literal"
    assert tasks[("travel", "injection_task_6")]["value_source"] == "none"
    assert tasks[("slack", "injection_task_3")]["gt_plus_fallback"]["category"] == "no_authority_value"
    assert tasks[("slack", "injection_task_3")]["gt_plus_fallback_with_exfiltration_reads"]["values"] == 1


def test_vector_exposure_uses_agentdojo_and_matches_parity_run(census):
    rows = {(row["suite"], row["user_task_id"]): row for row in census["e1"]["vector_exposure"]}
    assert len(rows) == 97
    assert all(row["parity_with_agentdojo"] for row in rows.values())
    assert all(not row["split_capable"] for (suite, _), row in rows.items() if suite == "banking")
    assert set(rows[("slack", "user_task_16")]["agentdojo_vectors"]) == {"injection_dora_0", "prompt_injection_eve_blog"}


def test_claims_are_evaluated(census):
    claims = {claim["id"]: claim for claim in census["claims"]}
    assert set(claims) == {"K1", "K2", "K3", "K4"}
    assert claims["K1"]["observed"]["riverside_view_lines"] == ["travel/environment.yaml:176"]
    assert claims["K3"]["verdict"] == "confirmed"
    for reading in claims["K4"]["observed"]["readings"].values():
        assert isinstance(reading["post_hoc"], bool)


def test_derived_outputs_are_deterministic_and_clean(census):
    first = ac.derived_files(census)
    second = ac.derived_files(json.loads(json.dumps(census)))
    assert first == second
    for path, text in first.items():
        ac.assert_no_credentials(text, path)
        ac.assert_no_absolute_paths(text, path)
        if path.endswith(".json"):
            json.loads(text)
        assert "\r\n" not in text
    summary = ac.render_summary(census, "0" * 64, "f" * 40)
    assert "Precision denominator" in summary and "Claims under test" in summary


def test_assert_no_absolute_paths_and_credentials_fail_closed():
    with pytest.raises(ValueError):
        ac.assert_no_absolute_paths("written to D:\\Jerry\\x")
    with pytest.raises(ValueError):
        ac.assert_no_credentials("token = abcdefghijklmnopqrstuvwxyz")


# --- runner -------------------------------------------------------------------------------------------


def test_runner_sanitizes_logs_and_parses_summary():
    runner = _runner()
    log = f"rootdir: {runner.LAB_ROOT}\n....\n12 passed in 3.21s\n"
    assert str(runner.LAB_ROOT) not in runner.sanitize_log(log)
    assert runner.parse_pytest_summary(log) == "12 passed in 3.21s"


def test_runner_writes_a_complete_draft_and_refuses_overwrite(census, tmp_path, monkeypatch):
    runner = _runner()
    monkeypatch.setattr(runner.census_module, "run_census", lambda config: copy.deepcopy(census))
    results = tmp_path / "results"
    output = results / "experiments" / ac.EXPERIMENT_ID
    log = tmp_path / "pytest.txt"
    log.write_text("...\n3 passed in 1.00s\n", encoding="utf-8")
    argv = ["--config", str(CONFIG_PATH), "--results-root", str(results), "--output", str(output), "--tests-log", str(log)]
    assert runner.main(argv) == 0
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "draft_pending_code_commit"
    assert manifest["protocol"]["config_sha256"] == ac.sha256_bytes(CONFIG_PATH.read_bytes())
    assert (output / "config/authority_census_v1.json").read_bytes() == CONFIG_PATH.read_bytes()
    assert manifest["validation"]["tests"]["summary"] == "3 passed in 1.00s"
    checksums = (output / "checksums.sha256").read_text(encoding="utf-8").splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in checksums}
    for path, digest in listed.items():
        assert ac.sha256_bytes((output / path).read_bytes()) == digest
    assert "manifest.json" in listed and "checksums.sha256" not in listed
    assert "DRAFT" in (output / "README.md").read_text(encoding="utf-8")
    with pytest.raises(SystemExit):
        runner.main(argv)


# =====================================================================================================
# Protocol v2 (successor). v1 must keep reproducing its own outputs; v2 adds D1-D5 and the sensitivity tables.

CONFIG_V2_PATH = ROOT / ac.CONFIG_RELATIVE_V2
V1_CONFIG_SHA256 = "4f3164c2510da6dbaefcb5be4d702669bc0d92dc7d3c678f2efdf3f970b9a574"
V1_HEAD = "f48069017f3b59fec3d91de54b6aaccaf42a2b4a"
# SHA-256 of the v1 draft experiment's derived files and summary (agent-tracer-results,
# experiments/20261007-authority-origin-census-v1/checksums.sha256).
V1_OUTPUT_SHA256 = {
    "derived/census.json": "55210873319d299020ad91b2d0ce25d55a51e066f54abb7218eccf817fc2805d",
    "derived/e0_exfiltration_read_values.csv": "35db4cef69028df7bb8e4a6195e04ac05c67cfbdc24cc05c905b4074731650a6",
    "derived/e0_tasks.csv": "1de90fc35f56a0000552d850c6dc1ac5f713fed68f14e1ee41508a68013c1e9e",
    "derived/e0_values.csv": "49ac695c4df63febfe54c8f0752314996ecf8cc623c77457154848293c028543",
    "derived/e1_attacker_values.csv": "009d0b810978adf8afeabe4255201d6cb6d64c5c24354bcf6c74ab543959ae81",
    "derived/e1_injection_tasks.csv": "0c0734d0558e9869dc8c92800768e8f3182ad64e892967dbbd81038fb2379741",
    "derived/e1_vector_exposure.csv": "638ebb42fdf4064c122157ec01c471032d216fa96d1419c1fa4f3b10a39682d3",
    "derived/role_table.csv": "6e4619708c53faebf25226f42f876724db677c820859198abf8ce57b44d1d8c2",
    "reports/summary.md": "9c6c7240e9aef9092133472587b059ebfe97382b9884e434031abd330c55f234",
}


@pytest.fixture(scope="module")
def config_v2():
    loaded, _ = ac.load_config(CONFIG_V2_PATH)
    return loaded


@pytest.fixture(scope="module")
def census_v2(config_v2):
    with ac.network_guard() as attempts:
        result = ac.run_census(config_v2)
    assert attempts["count"] == 0
    return result


def _v1_outputs(census):
    v1 = copy.deepcopy(census)
    v1["execution"] = {"model_requests": 0, "provider_requests": 0, "network_connection_attempts": 0}
    files = ac.derived_files(v1)
    files["reports/summary.md"] = ac.render_summary(v1, V1_CONFIG_SHA256, V1_HEAD)
    return files


# --- v1 stays the historical draft ------------------------------------------------------------------


def test_v1_config_is_unchanged_and_bound_by_v2(config_v2):
    assert ac.lf_normalized_sha256(CONFIG_PATH.read_bytes()) == V1_CONFIG_SHA256
    assert config_v2["predecessor"]["config_sha256"] == V1_CONFIG_SHA256
    assert config_v2["amendment_log"][-1]["predecessor_config_sha256"] == V1_CONFIG_SHA256


def test_v1_code_path_reproduces_the_v1_draft_outputs(census):
    files = _v1_outputs(census)
    assert {path: ac.sha256_bytes(text.encode("utf-8")) for path, text in files.items()} == V1_OUTPUT_SHA256
    for key in ("sensitivity", "verifier_check", "predecessor"):
        assert key not in census
    assert "vector_dependent" not in census["e0"]["values"][0]


# --- v2 config --------------------------------------------------------------------------------------


def test_v2_config_records_every_change(config_v2):
    assert config_v2["protocol"] == ac.PROTOCOL_V2 and config_v2["schema_version"] == 2
    entry = config_v2["amendment_log"][-1]
    assert entry["after_seeing_counts"] is True
    assert [change["id"] for change in entry["changes"]][:5] == ["D1", "D2", "D3", "D4", "D5"]
    tagged = [item for item in config_v2["e1"]["security_checker_fallback"]["workspace"]["injection_task_12"] if "tag" in item]
    assert tagged == [
        {
            "function": "send_email",
            "argument": "recipients",
            "rule": "account_email",
            "tag": "D5",
            "basis": tagged[0]["basis"],
        }
    ]
    assert "explicit exception j2" in config_v2["role_rule"]["state_changing"].lower()
    assert config_v2["claims_under_test"][1]["readings"]["distinct_first_calls"]["post_hoc"] is True
    assert {row["id"] for row in config_v2["sensitivity"]["precision_denominator"]} == {f"P{i}" for i in range(7)}


def test_v2_primary_role_table_equals_v1(config, config_v2):
    assert config_v2["tools"] == config["tools"]
    assert config_v2["matching"] == config["matching"]
    assert config_v2["identifier_kinds"] == config["identifier_kinds"]


def test_validate_config_v2_fails_closed(config, config_v2):
    broken = copy.deepcopy(config_v2)
    broken["frozen_at"] = "FROZEN_AT_PLACEHOLDER"
    with pytest.raises(ValueError, match="not frozen"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config_v2)
    broken["amendment_log"][-1]["changes"] = broken["amendment_log"][-1]["changes"][1:]
    with pytest.raises(ValueError, match="amendment_log must record"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config_v2)
    broken["amendment_log"][-1]["predecessor_config_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="record the hash"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config_v2)
    broken["sensitivity"]["role_variants"][0]["authority_additions"]["workspace"]["send_email"] = {"subject_x": "url"}
    with pytest.raises(ValueError, match="is not content"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config)
    broken["e1"]["security_checker_fallback"]["workspace"]["injection_task_6"][0]["tag"] = "D5"
    with pytest.raises(ValueError, match="v2 only"):
        ac.validate_config(broken)
    broken = copy.deepcopy(config)
    broken["value_kinds"]["event_location"] = "x"
    with pytest.raises(ValueError, match="exactly"):
        ac.validate_config(broken)


# --- v2 helpers -------------------------------------------------------------------------------------


def test_extract_file_attachment_ids_follows_send_email_parsing():
    raw = [{"type": "file", "file_id": "19"}, {"type": "event", "event_details": {"title": "x"}}, {"file_id": 3}]
    assert ac.extract_values("file_attachment_ids", raw) == ["19", "3"]
    assert ac.extract_values("file_attachment_ids", None) == []
    with pytest.raises(ValueError):
        ac.extract_values("unknown", raw)


def test_find_exact_requires_a_whole_field():
    index = ac.TextIndex({"web": {"www.dora-website.com": "Contact dora@gmail.com"}, "users": ["Dora"]}, ID_KINDS)
    assert index.find("dora@gmail.com", "email_address")
    assert index.find_exact("dora@gmail.com", "email_address") == []
    assert index.find_exact("www.dora-website.com", "url") == ["web.www.dora-website.com#key"]
    assert index.find_exact("dora", "slack_user") == ["users[0]"]


def test_vector_neutraliser_flags_values_built_from_a_vector(config_v2):
    from agentdojo.task_suite.load_suites import get_suite

    placeholder = config_v2["e0"]["vector_dependency"]["placeholder"]
    slack = ac.VectorNeutraliser(get_suite("v1.2.2", "slack"), ID_KINDS, placeholder)
    assert slack.dependency("External_0", "slack_channel") == {
        "vector_dependent": True,
        "vector_dependency_vectors": ["prompt_injection_channel"],
    }
    assert slack.dependency("general", "slack_channel")["vector_dependent"] is False
    assert slack.dependency("dora@gmail.com", "email_address")["vector_dependent"] is False
    with pytest.raises(ValueError, match="placeholder"):
        slack.dependency(placeholder, "slack_channel")


def test_apply_role_variant_moves_only_the_named_arguments(config_v2):
    variants = {item["id"]: item for item in config_v2["sensitivity"]["role_variants"]}
    attachments = ac.apply_role_variant(config_v2, variants["R-attachments"])
    send = attachments["tools"]["workspace"]["send_email"]
    assert send["authority"]["attachments"] == "cloud_file_id" and "attachments" not in send["content"]
    assert send["value_extractors"] == {"attachments": "file_attachment_ids"}
    assert config_v2["tools"]["workspace"]["send_email"]["content"] == ["subject", "body", "attachments"]
    fallback = attachments["e1"]["security_checker_fallback"]["workspace"]["injection_task_10"]
    assert fallback[-1] == {"function": "send_email", "argument": "attachments", "rule": "id_range", "start": 0, "stop": 26}
    webpage = ac.apply_role_variant(config_v2, variants["R-get_webpage"])
    assert webpage["tools"]["slack"]["get_webpage"] == {"class": "state_changing", "authority": {"url": "url"}, "content": []}
    location = ac.apply_role_variant(config_v2, variants["R-location"])
    assert location["tools"]["travel"]["create_calendar_event"]["authority"]["location"] == "event_location"


def test_resolve_path_matches_one_list_item():
    data = {"rows": [{"id": "P0", "n": 34}, {"id": "P1", "n": 33}]}
    assert ac.resolve_path(data, ["rows", {"id": "P1"}, "n"]) == 33
    with pytest.raises(LookupError):
        ac.resolve_path(data, ["rows", {"id": "P9"}, "n"])
    assert ac.resolve_path(data, ["rows", 0, "id"]) == "P0"


def test_fallback_id_range_rule(config_v2):
    from agentdojo.task_suite.load_suites import get_suite

    environment = get_suite("v1.2.2", "workspace").load_and_inject_default_environment({})
    ids = ac.derive_fallback_values({"rule": "id_range", "start": 0, "stop": 26}, environment)
    assert ids == [str(i) for i in range(26)]
    assert set(ids) == {str(file_id) for file_id in environment.cloud_drive.files}


# --- v2 census anchors ------------------------------------------------------------------------------


def test_v2_keeps_the_v1_primary_e0_numbers(census, census_v2):
    assert census_v2["e0"]["summary"]["overall"] == census["e0"]["summary"]["overall"]
    assert census_v2["role_table"] == census["role_table"]
    assert census_v2["e1"]["summary"]["split"]["overall"]["split_capable"] == 26


def test_v2_d1_vector_dependent_values(census_v2):
    values = census_v2["e0"]["values"]
    dependent = [row for row in values if row["vector_dependent"]]
    assert {(row["value"], tuple(row["vector_dependency_vectors"])) for row in dependent} == {
        ("UK12345678901234567890", ("injection_bill_text",)),
        ("External_0", ("prompt_injection_channel",)),
    }
    channel = [row for row in dependent if row["value"] == "External_0"]
    assert [row["user_task_id"] for row in channel] == [
        "user_task_7", "user_task_9", "user_task_10", "user_task_10", "user_task_10", "user_task_12", "user_task_19",
    ]
    assert all(not row["in_injection_vector_defaults"] for row in channel)
    flags = census_v2["e0"]["summary"]["vector_dependency"]["overall"]
    assert (flags["b_vector_dependent"], flags["b_excluding_vector_dependent"]) == (8, 48)
    assert flags["tasks_with_b_excluding_vector_dependent"] == 30


def test_v2_d2_goal_literal_coverage(census_v2):
    rows = {(row["suite"], row["value"]): row for row in census_v2["e1"]["summary"]["goal_literal_coverage"]}
    mark = rows[("workspace", "mark.black-2134@gmail.com")]
    assert (mark["goals_stating"], mark["injection_tasks"]) == (12, 14)
    assert mark["lacking"] == ["injection_task_1", "injection_task_13"]
    summary = ac.render_summary(census_v2, "0" * 64, "f" * 40)
    assert "`mark.black-2134@gmail.com` is stated in 12/14 workspace GOALs" in summary
    assert "injection_task_1 and injection_task_13 lack it" in summary


def test_v2_d3_view_overlap(census_v2):
    summary = census_v2["e1"]["summary"]
    old = summary["views_excluding_tag"]["D5"]["gt_plus_fallback"]["overall"]
    assert (old["values"], old["values_goal_literal"], old["values_in_clean_environment"]) == (75, 36, 33)
    assert (old["values_neither"], old["values_goal_and_clean_environment"]) == (9, 3)
    both = summary["goal_and_clean_environment_values"]["gt_plus_fallback"]
    assert {(row["suite"], row["injection_task_id"], row["value"]) for row in both} == {
        ("workspace", "injection_task_1", "13"),
        ("slack", "injection_task_1", "Alice"),
        ("slack", "injection_task_5", "general"),
    }
    for view in summary["views"].values():
        item = view["overall"]
        total = item["values_goal_literal"] + item["values_in_clean_environment"] + item["values_neither"]
        assert total - item["values_goal_and_clean_environment"] == item["values"]


def test_v2_d4_k2_readings(census_v2):
    split = census_v2["e1"]["summary"]["split"]
    assert split["overall"]["split_capable_with_two_or_more_exposing_calls"] == 20
    assert split["overall"]["split_capable_with_two_or_more_first_exposing_calls"] == 18
    assert split["per_suite"]["workspace"]["any_but_not_first_exposing_calls"] == ["user_task_35", "user_task_38"]
    k2 = {claim["id"]: claim for claim in census_v2["claims"]}["K2"]
    assert k2["observed"]["distinct_first_calls_post_hoc"] == {"numerator": 18, "denominator": 97}
    assert "post hoc" in k2["verdict"] and "20/97" in k2["verdict"] and "18/97" in k2["verdict"]


def test_v2_d5_both_counts(census, census_v2):
    summary = census_v2["e1"]["summary"]
    assert summary["views"]["gt_plus_fallback"]["overall"]["values"] == 76
    assert summary["views"]["gt_plus_fallback"]["overall"]["values_in_clean_environment"] == 34
    for view, data in summary["views_excluding_tag"]["D5"].items():
        v1_view = census["e1"]["summary"]["views"][view]["overall"]
        assert {key: data["overall"][key] for key in v1_view} == v1_view
    tagged = [row for row in census_v2["e1"]["values"] if row["fallback_tag"] == "D5"]
    assert [(row["injection_task_id"], row["value"]) for row in tagged] == [
        ("injection_task_12", "emma.johnson@bluesparrowtech.com")
    ]
    old_tasks = {row["injection_task_id"]: row for row in census["e1"]["tasks"] if row["suite"] == "workspace"}
    new_tasks = {row["injection_task_id"]: row for row in census_v2["e1"]["tasks"] if row["suite"] == "workspace"}
    for view in ("gt_plus_fallback", "gt_plus_fallback_with_exfiltration_reads"):
        assert new_tasks["injection_task_12"][view]["category"] == old_tasks["injection_task_12"][view]["category"]
        assert new_tasks["injection_task_12"][view]["seed_candidate"] == old_tasks["injection_task_12"][view]["seed_candidate"]
    k4_v1 = {claim["id"]: claim for claim in census["claims"]}["K4"]["observed"]
    k4_v2 = {claim["id"]: claim for claim in census_v2["claims"]}["K4"]["observed"]
    assert k4_v1 == k4_v2


def test_v2_precision_denominator_rows(census_v2):
    rows = {row["id"]: row for row in census_v2["sensitivity"]["precision_denominator"]}
    observed = {key: (row["numerator"], row["denominator"]) for key, row in rows.items()}
    assert observed == {
        "P0": (34, 97), "P1": (33, 97), "P2": (36, 97), "P3": (35, 97), "P4": (28, 86), "P5": (29, 97), "P6": (30, 97),
    }
    assert rows["P1"]["removed_vs_primary"] == ["banking.user_task_9"]
    assert rows["P2"]["added_vs_primary"] == ["workspace.user_task_32", "workspace.user_task_37"]
    assert rows["P0"]["primary"] and all(row["post_hoc"] for key, row in rows.items() if key != "P0")
    tasks = {(row["suite"], row["user_task_id"]): row for row in census_v2["e0"]["tasks"]}
    assert sum(1 for row in tasks.values() if row["combined_task"]) == 11
    assert tasks[("banking", "user_task_9")]["utility_without_b_calls"] is True
    assert all(row["utility_full_ground_truth"] for row in tasks.values() if row["non_prompt_values"])


def test_v2_role_variants(census_v2):
    variants = {row["id"]: row for row in census_v2["sensitivity"]["role_variants"]}
    observed = {
        key: (row["e0"]["values"]["total"], row["e0"]["values"]["b_environment"], row["e0"]["tasks_with_b"])
        for key, row in variants.items()
    }
    assert observed == {"R-attachments": (92, 57, 34), "R-get_webpage": (109, 65, 38), "R-location": (97, 62, 39)}
    assert variants["R-attachments"]["e1"]["new_seed_tasks"] == ["workspace.injection_task_10"]
    assert variants["R-get_webpage"]["e1"]["overall"]["values"] == (
        census_v2["e1"]["summary"]["views"]["gt_plus_fallback_with_exfiltration_reads"]["overall"]["values"]
    )
    assert all(row["post_hoc"] for row in variants.values())


def test_v2_prompt_collisions(census_v2):
    collisions = census_v2["sensitivity"]["prompt_collisions"]
    assert collisions["count"] == 9
    keys = {(row["suite"], row["injection_task_id"], row["value"]) for row in collisions["rows"]}
    assert ("slack", "injection_task_1", "Alice") in keys and ("workspace", "injection_task_1", "13") in keys


def test_v2_verifier_check_resolves_every_path(census_v2):
    rows = census_v2["verifier_check"]
    assert rows and all(row["resolved"] for row in rows)
    assert all(row["match"] for row in rows), [row["id"] for row in rows if not row["match"]]


def test_v2_outputs_are_deterministic_and_clean(census_v2, config_v2):
    first = ac.derived_files(census_v2)
    second = ac.derived_files(json.loads(json.dumps(census_v2)))
    assert first == second
    expected = {path for path in config_v2["outputs"]["files"] if path.startswith("derived/")}
    assert set(first) == expected
    summary = ac.render_summary(census_v2, "0" * 64, "f" * 40)
    for path, text in {**first, "reports/summary.md": summary}.items():
        ac.assert_no_credentials(text, path)
        ac.assert_no_absolute_paths(text, path)
        assert "\r\n" not in text
    for heading in ("Changes from v1", "Check against the verifier", "Sensitivity: role table", "collisions",
                    "and its sensitivity rows", "D5: v2 counts next to the v1 convention"):
        assert heading in summary
    assert "**DIFFERS**" not in summary


# --- v2 runner ------------------------------------------------------------------------------------------


def test_runner_v2_writes_a_successor_draft(census_v2, tmp_path, monkeypatch):
    runner = _runner()
    monkeypatch.setattr(runner.census_module, "run_census", lambda config: copy.deepcopy(census_v2))
    results = tmp_path / "results"
    output = results / "experiments" / ac.EXPERIMENT_ID_V2
    argv = ["--config", str(CONFIG_V2_PATH), "--results-root", str(results), "--output", str(output)]
    assert runner.main(argv) == 0
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["experiment_id"] == ac.EXPERIMENT_ID_V2
    assert manifest["predecessor_experiment_ids"] == [ac.EXPERIMENT_ID]
    assert manifest["predecessor"]["config_sha256"] == V1_CONFIG_SHA256
    assert manifest["predecessor"]["reproduction_check"]["checked"] is False
    assert manifest["protocol"]["config_path_in_experiment"] == "config/authority_census_v2.json"
    assert (output / "config/authority_census_v2.json").read_bytes() == CONFIG_V2_PATH.read_bytes()
    roles = {item["path"].rsplit("/", 1)[-1]: item["role"] for item in manifest["agent_tracer"]["new_files"]}
    assert roles["authority_census_v1.json"] == "predecessor_configuration_unchanged"
    assert roles["authority_census_v2.json"] == "frozen_configuration"
    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "DRAFT" in readme and f"(../{ac.EXPERIMENT_ID}/)" in readme
    assert (output / "logs/predecessor-reproduction.json").is_file()
    listed = dict(reversed(line.split("  ", 1)) for line in (output / "checksums.sha256").read_text().splitlines())
    for path, digest in listed.items():
        assert ac.sha256_bytes((output / path).read_bytes()) == digest
    bad = results / "experiments" / ac.EXPERIMENT_ID
    with pytest.raises(SystemExit):
        runner.main(["--config", str(CONFIG_V2_PATH), "--results-root", str(results), "--output", str(bad)])


def test_runner_predecessor_reproduction_compares_bytes(census, config_v2, tmp_path, monkeypatch):
    runner = _runner()
    monkeypatch.setattr(runner.census_module, "run_census", lambda config: copy.deepcopy(census))
    directory = tmp_path / "experiments" / ac.EXPERIMENT_ID
    for path, text in _v1_outputs(census).items():
        (directory / path).parent.mkdir(parents=True, exist_ok=True)
        (directory / path).write_bytes(text.encode("utf-8"))
    (directory / "config").mkdir(exist_ok=True)
    (directory / "config/authority_census_v1.json").write_bytes(CONFIG_PATH.read_bytes())
    (directory / "manifest.json").write_text(json.dumps({"agent_tracer": {"head": V1_HEAD}}), encoding="utf-8")
    result = runner.predecessor_reproduction(config_v2, tmp_path)
    assert result["checked"] and result["all_identical"] and result["config_unchanged"]
    assert len(result["files"]) == len(V1_OUTPUT_SHA256)
    (directory / "derived/e0_values.csv").write_bytes(b"changed\n")
    with pytest.raises(SystemExit, match="no longer reproduces"):
        runner.predecessor_reproduction(config_v2, tmp_path)
