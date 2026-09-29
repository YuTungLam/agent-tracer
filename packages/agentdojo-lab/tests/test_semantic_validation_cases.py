"""Data-only integrity tests; no matcher, embedding or generative model is used."""

import copy
import hashlib
import json
from collections import Counter

import pytest

from agentdojo_lab.semantic_validation_cases import (
    CASE_IDS,
    FAMILY_COUNTS,
    compile_references,
    design_sha256,
    fixture_design,
)


def test_frozen_matrix_has_sixteen_pairs_and_explicit_reference_scopes():
    design = fixture_design()
    rows = compile_references(design)
    assert [row["case_id"] for row in rows] == list(CASE_IDS)
    assert Counter(row["family"] for row in rows) == FAMILY_COUNTS
    assert Counter(row["reference"] for row in rows) == {True: 8, False: 6, None: 2}
    assert Counter(row["reference_scope"] for row in rows) == {
        "authored_transformation_reference": 8,
        "declared_program_origin": 6,
        "unresolved_semantic_correspondence": 2,
    }
    assert len({row["reference_id"] for row in rows}) == 16
    assert all(row["synthetic_canary"] is None and row["independent_human_labels"] is False for row in rows)
    assert design["profile"] == "ordinary" and design["canary_enabled"] is False


def test_design_copies_and_compilation_are_independent_and_deterministic():
    design = fixture_design()
    before = copy.deepcopy(design)
    rows = compile_references(design)
    assert design == before
    rows[0]["source"] = "Changed local row."
    design["cases"][0]["sources"]["a"] = "Changed local design."
    assert fixture_design() == before
    assert compile_references()[0]["source"] == before["cases"][0]["sources"]["a"]
    assert design_sha256() == design_sha256(copy.deepcopy(before))


def test_quotes_and_hashes_locate_the_declared_authored_correspondence():
    for row in compile_references():
        assert hashlib.sha256(row["source"].encode()).hexdigest() == row["source_sha256"]
        assert hashlib.sha256(row["target"].encode()).hexdigest() == row["target_sha256"]
        if row["reference"] is True:
            for witness in row["construction_witnesses"]:
                start, end = witness["source_span"]
                assert row["source"][start:end] == witness["source_quote"]
                start, end = witness["target_span"]
                assert row["target"][start:end] == witness["target_quote"]
                assert witness["kind"] == "authored_semantic_correspondence"


def test_negative_origin_program_selects_b_even_for_equivalent_or_identical_text():
    rows = {row["case_id"]: row for row in compile_references()}
    for row in rows.values():
        if row["reference"] is False:
            assert row["construction"] == {"kind": "copy_other_origin", "source_id": "b"}
            assert row["target"] == row["competing_sources"]["b"]
            assert all(w["source_id"] == "b" for w in row["construction_witnesses"])
    identical = rows["related_identical_ferry"]
    assert identical["source"] == identical["target"] and identical["reference"] is False
    assert identical["text_only_origin_identifiability"] == "not_identifiable_from_text"
    assert (
        rows["related_equivalent_instruction"]["semantic_relation"]
        == "equivalent_meaning_designated_other_origin"
    )


def test_whole_statement_negation_controls_and_unknowns_keep_distinct_contracts():
    rows = compile_references()
    negatives = [row for row in rows if row["family"] == "negation_other_origin"]
    assert len(negatives) == 2
    assert all(
        " not " in row["target"] and " not " not in row["source"] and row["reference"] is False
        for row in negatives
    )
    unknown = [row for row in rows if row["family"] == "ambiguous"]
    assert len(unknown) == 2
    assert all(row["reference"] is None and row["construction_witnesses"] == [] for row in unknown)


@pytest.mark.parametrize("change", ["duplicate", "reorder", "missing", "foreign"])
def test_inventory_changes_are_rejected(change):
    design = fixture_design()
    if change == "duplicate":
        design["cases"][1] = copy.deepcopy(design["cases"][0])
    elif change == "reorder":
        design["cases"].reverse()
    elif change == "missing":
        design["cases"].pop()
    else:
        design["cases"][0]["case_id"] = "foreign_case"
    with pytest.raises(ValueError):
        compile_references(design)


@pytest.mark.parametrize("change", ["quote", "target_copy", "origin", "assigned_unknown", "score_field"])
def test_inconsistent_or_post_scoring_reference_fields_rejected(change):
    design = fixture_design()
    if change == "quote":
        design["cases"][0]["correspondence"][0]["source_quote"] = "Absent quotation."
    elif change == "target_copy":
        design["cases"][8]["target"] = "Not the declared copied target."
    elif change == "origin":
        design["cases"][8]["construction"]["source_id"] = "a"
    elif change == "assigned_unknown":
        design["cases"][-1]["construction"] = {"kind": "authored_transformation", "source_id": "a"}
    else:
        design["cases"][0]["observed_score"] = 0.9
    with pytest.raises(ValueError):
        compile_references(design)


@pytest.mark.parametrize(
    "key,value",
    [
        ("profile", "implicit_string"),
        ("canary_enabled", True),
        ("independent_human_labels", 0),
        ("schema_version", True),
    ],
)
def test_fixed_protocol_and_exact_metadata_types_are_required(key, value):
    design = fixture_design()
    design[key] = value
    with pytest.raises(ValueError):
        compile_references(design)


def test_all_artifact_text_is_ascii_and_design_contains_no_scoring_output():
    assert json.dumps(fixture_design(), ensure_ascii=False).isascii()
    assert json.dumps(compile_references(), ensure_ascii=False).isascii()
    for case in fixture_design()["cases"]:
        assert not {"score", "embedding", "prediction", "matched", "threshold", "expected_tier"}.intersection(
            case
        )
