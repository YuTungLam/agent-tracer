"""Sixteen predeclared synthetic semantic correspondence and origin controls.

This module contains data and reference compilation only. It imports no matcher,
encoder, model client or benchmark data. Positive semantic correspondence is an
authored reference, not a measured model-generation history. Negative references
describe a declared target-copy program whose input is another origin.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter

METHOD = "authored_semantic_correspondence_controls_v1"
FAMILY_COUNTS = {
    "paraphrase": 4,
    "summarization": 4,
    "related_other_origin": 4,
    "negation_other_origin": 2,
    "ambiguous": 2,
}
CASE_IDS = (
    "paraphrase_delivery",
    "paraphrase_lights",
    "paraphrase_migration",
    "paraphrase_recharge",
    "summary_bakery",
    "summary_rooftop",
    "summary_depot",
    "summary_water_trial",
    "related_reservoir",
    "related_fruit",
    "related_equivalent_instruction",
    "related_identical_ferry",
    "negation_locked_door",
    "negation_backup",
    "ambiguous_approval",
    "ambiguous_shutdown",
)
LIMITATIONS = (
    "The eight positive pairs are assistant-authored semantic transformation references; they are not independent human labels or observed model reliance.",
    "The six negative pairs copy their target from declared origin b while candidate a is unused. Other-origin means a fixture-program assignment, not independently collected documents or authors.",
    "Meaning preservation, topical overlap and contradiction are described separately from declared origin. Semantic similarity alone cannot distinguish identical or equivalent text from another origin.",
    "Negation controls test correspondence to a declared unused origin; contradiction alone would not prove that a real model was uninfluenced by the source.",
    "Ambiguous pairs have unknown references and must remain outside binary-reference metrics even if a matcher returns a confident score.",
    "Measure direct Tier 3 and Tier 4 on all pairs separately from actual ordered-stage entry. An early lexical exit is not a successful semantic-stage invocation.",
    "Use only the unchanged ordinary profile and passive Tier 1 condition. Do not filter cases, tune thresholds or alter text after inspecting scores.",
    "Shared templates and deliberately identical text are controlled contrasts, not independent deployment samples. No real-agent attribution accuracy, maliciousness or causal benefit is established.",
)


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _text_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def fixture_design():
    """Return fresh data without inspecting predictions, lexical scores or embeddings."""
    cases = []

    def positive(case_id, family, source, target, rationale, witnesses=None):
        cases.append(
            {
                "case_id": case_id,
                "family": family,
                "candidate_source_id": "a",
                "sources": {"a": source},
                "target": target,
                "construction": {"kind": "authored_transformation", "source_id": "a"},
                "semantic_relation": "meaning_preserving_paraphrase"
                if family == "paraphrase"
                else "supported_compression",
                "rationale": rationale,
                "correspondence": witnesses or [{"source_quote": source, "target_quote": target}],
                "text_only_origin_identifiability": "not_established",
            }
        )

    positive(
        "paraphrase_delivery",
        "paraphrase",
        "The courier delivered the parcel during the morning.",
        "The package arrived before midday.",
        "Rephrase the delivery and its time; omit the courier's identity.",
    )
    positive(
        "paraphrase_lights",
        "paraphrase",
        "At dawn, the caretaker extinguished every lamp.",
        "The custodian switched off all lights at daybreak.",
        "Replace the actor, action and time expressions with corresponding wording.",
    )
    positive(
        "paraphrase_migration",
        "paraphrase",
        "As winter approached, the cranes flew south.",
        "The birds migrated south when winter was near.",
        "Generalize cranes to birds while retaining movement direction and season.",
    )
    positive(
        "paraphrase_recharge",
        "paraphrase",
        "Without an overnight charge, the scooter cannot finish the journey.",
        "An overnight recharge is required for the scooter to complete the trip.",
        "Express the same necessary condition using a positive requirement.",
    )
    positive(
        "summary_bakery",
        "summarization",
        "The village bakery opened at six in the morning. By nine, every loaf had sold. The owner baked another batch before noon.",
        "The bakery sold its morning bread and baked more.",
        "Compress the sale and replacement batch while omitting the exact hours.",
        [
            {"source_quote": "every loaf had sold", "target_quote": "sold its morning bread"},
            {"source_quote": "baked another batch", "target_quote": "baked more"},
        ],
    )
    positive(
        "summary_rooftop",
        "summarization",
        "Strong overnight wind loosened two rooftop panels. The team postponed the morning inspection until conditions improved. Replacement brackets were ordered for delivery on Friday.",
        "Wind loosened roof panels; inspection was delayed and repair parts were ordered.",
        "Retain damage, postponement and procurement while omitting count and delivery date.",
        [
            {"source_quote": "wind loosened two rooftop panels", "target_quote": "Wind loosened roof panels"},
            {"source_quote": "postponed the morning inspection", "target_quote": "inspection was delayed"},
            {
                "source_quote": "Replacement brackets were ordered",
                "target_quote": "repair parts were ordered",
            },
        ],
    )
    positive(
        "summary_depot",
        "summarization",
        "The depot's flour stock fell to twelve bags. A scheduled delivery was delayed. Because stocks were low and the delivery was late, the manager requested urgent replenishment. The request was entered in the evening log.",
        "Low flour stocks and a late delivery prompted an urgent restocking request.",
        "Preserve the explicitly stated cause and action; omit quantity and logging detail.",
        [
            {"source_quote": "stocks were low", "target_quote": "Low flour stocks"},
            {"source_quote": "the delivery was late", "target_quote": "a late delivery"},
            {
                "source_quote": "requested urgent replenishment",
                "target_quote": "an urgent restocking request",
            },
        ],
    )
    positive(
        "summary_water_trial",
        "summarization",
        "The class compared two ways to clean muddy water. A cloth filter removed visible particles. Boiling was used after filtration. The class recommended filtering first and boiling afterward.",
        "The water-cleaning trial recommended filtration followed by boiling.",
        "Select the final recommendation from a four-sentence procedure description.",
        [
            {"source_quote": "clean muddy water", "target_quote": "water-cleaning trial"},
            {
                "source_quote": "recommended filtering first and boiling afterward",
                "target_quote": "recommended filtration followed by boiling",
            },
        ],
    )

    def other(case_id, family, source, alternate, relation, rationale, identifiability="not_established"):
        cases.append(
            {
                "case_id": case_id,
                "family": family,
                "candidate_source_id": "a",
                "sources": {"a": source, "b": alternate},
                "target": alternate,
                "construction": {"kind": "copy_other_origin", "source_id": "b"},
                "semantic_relation": relation,
                "rationale": rationale,
                "correspondence": [],
                "text_only_origin_identifiability": identifiability,
            }
        )

    other(
        "related_reservoir",
        "related_other_origin",
        "The north reservoir will be drained on Tuesday.",
        "The south reservoir will be drained on Tuesday.",
        "same_template_different_entity",
        "The target copies origin b's south-reservoir record. Candidate a refers to a different reservoir.",
    )
    other(
        "related_fruit",
        "related_other_origin",
        "The store received twelve crates of lemons.",
        "The store received twelve crates of oranges.",
        "same_template_different_object",
        "The target copies origin b's orange shipment. Candidate a's lemon shipment is unused.",
    )
    other(
        "related_equivalent_instruction",
        "related_other_origin",
        "Please place the repaired radios in the locked cabinet.",
        "Put the fixed radios inside the secured cupboard.",
        "equivalent_meaning_designated_other_origin",
        "The declared program copies origin b despite equivalent meaning in candidate a; similarity cannot reveal this program choice.",
        "not_identifiable_from_semantic_equivalence",
    )
    other(
        "related_identical_ferry",
        "related_other_origin",
        "The ferry leaves at seven.",
        "The ferry leaves at seven.",
        "identical_text_designated_other_origin",
        "Both origins contain identical text. The program selects b, so text matching cannot identify the selected origin.",
        "not_identifiable_from_text",
    )
    other(
        "negation_locked_door",
        "negation_other_origin",
        "The archive door must remain locked.",
        "The archive door must not remain locked.",
        "whole_statement_negation",
        "The program copies b's opposing directive. The unused candidate differs mainly by negation.",
    )
    other(
        "negation_backup",
        "negation_other_origin",
        "The backup job completed successfully.",
        "The backup job did not complete successfully.",
        "whole_statement_negation",
        "The program copies b's failure report. Word overlap with candidate a's success report is deliberately high.",
    )

    def ambiguous(case_id, sources, target, relation, rationale):
        cases.append(
            {
                "case_id": case_id,
                "family": "ambiguous",
                "candidate_source_id": "a",
                "sources": sources,
                "target": target,
                "construction": {"kind": "unresolved"},
                "semantic_relation": relation,
                "rationale": rationale,
                "correspondence": [],
                "text_only_origin_identifiability": "unresolved",
            }
        )

    ambiguous(
        "ambiguous_approval",
        {
            "a": "Jordan told Casey that the proposal was approved.",
            "b": "Casey told Jordan that the proposal was approved.",
        },
        "They approved the proposal.",
        "unresolved_actor_and_origin",
        "The target does not resolve who approved the proposal or which account supplied it. No generating program is specified.",
    )
    ambiguous(
        "ambiguous_shutdown",
        {
            "a": "The pump stopped during the night.",
            "b": "An alarm was reported shortly after the equipment stopped.",
        },
        "An alarm followed the shutdown.",
        "possible_summary_or_combination",
        "The target could compress b alone or combine the two records. Candidate a's contribution is not assigned.",
    )
    return {
        "schema_version": 1,
        "method": METHOD,
        "profile": "ordinary",
        "canary_enabled": False,
        "reference_author": "assistant_authored_synthetic_fixture",
        "independent_human_labels": False,
        "selection": "fixed_before_lexical_or_embedding_scores; no_score_based_filtering_or_rewriting",
        "measurement_contract": "Direct semantic stages on every pair; ordinary cascade separately with actual entry and early lexical exit counts",
        "cases": cases,
        "limitations": list(LIMITATIONS),
    }


def _nonempty_ascii(value):
    return isinstance(value, str) and bool(value.strip()) and value.isascii()


def _quote_span(text, quote):
    if not _nonempty_ascii(quote) or text.count(quote) != 1:
        raise ValueError("Correspondence quote must occur exactly once in its declared text")
    start = text.index(quote)
    return [start, start + len(quote)]


def compile_references(design=None):
    """Compile sixteen candidate-a rows without computing a detector prediction.

    Positive spans locate authored claims only; this function checks strings and
    construction integrity, not whether a human or model agrees with their meaning.
    """
    design = fixture_design() if design is None else copy.deepcopy(design)
    template = fixture_design()
    if (
        not isinstance(design, dict)
        or set(design) != set(template)
        or type(design.get("schema_version")) is not int
    ):
        raise ValueError("Invalid semantic fixture design schema")
    if any(_canonical(design[key]) != _canonical(value) for key, value in template.items() if key != "cases"):
        raise ValueError("Frozen semantic protocol metadata changed")
    cases = design["cases"]
    if not isinstance(cases, list) or len(cases) != 16 or any(not isinstance(case, dict) for case in cases):
        raise ValueError("Exactly sixteen semantic cases are required")
    if [case.get("case_id") for case in cases] != list(CASE_IDS) or Counter(
        case.get("family") for case in cases
    ) != FAMILY_COUNTS:
        raise ValueError("Duplicate, missing, reordered or foreign semantic case")
    references = []
    for case in cases:
        if set(case) != set(template["cases"][0]):
            raise ValueError("Invalid semantic case fields")
        sources, candidate, target = case["sources"], case["candidate_source_id"], case["target"]
        if (
            candidate != "a"
            or not isinstance(sources, dict)
            or set(sources) not in ({"a"}, {"a", "b"})
            or any(not _nonempty_ascii(text) or len(text) > 4096 for text in sources.values())
            or not _nonempty_ascii(target)
            or len(target) > 4096
            or any(
                not _nonempty_ascii(case[key])
                for key in ("semantic_relation", "rationale", "text_only_origin_identifiability")
            )
        ):
            raise ValueError("Fixture texts and identity fields must be bounded nonempty ASCII strings")
        source = sources[candidate]
        construction = case["construction"]
        witnesses = []
        if case["family"] in {"paraphrase", "summarization"}:
            if construction != {"kind": "authored_transformation", "source_id": candidate} or set(
                sources
            ) != {"a"}:
                raise ValueError("Authored positive requires its declared candidate source")
            if not isinstance(case["correspondence"], list) or not case["correspondence"]:
                raise ValueError("Authored positive requires explicit correspondence quotes")
            for correspondence in case["correspondence"]:
                if not isinstance(correspondence, dict) or set(correspondence) != {
                    "source_quote",
                    "target_quote",
                }:
                    raise ValueError("Invalid correspondence fields")
                witnesses.append(
                    {
                        "kind": "authored_semantic_correspondence",
                        "source_id": candidate,
                        "source_span": _quote_span(source, correspondence["source_quote"]),
                        "target_span": _quote_span(target, correspondence["target_quote"]),
                        **correspondence,
                    }
                )
            reference, scope = True, "authored_transformation_reference"
        elif case["family"] in {"related_other_origin", "negation_other_origin"}:
            if (
                construction != {"kind": "copy_other_origin", "source_id": "b"}
                or sources.get("b") != target
                or case["correspondence"] != []
            ):
                raise ValueError("Negative target must be copied exactly from declared other origin b")
            witnesses = [
                {
                    "kind": "other_origin_character_copy",
                    "source_id": "b",
                    "source_span": [0, len(target)],
                    "target_span": [0, len(target)],
                }
            ]
            reference, scope = False, "declared_program_origin"
        else:
            if construction != {"kind": "unresolved"} or case["correspondence"] != []:
                raise ValueError("Ambiguous origin must remain unresolved without assigned witnesses")
            reference, scope = None, "unresolved_semantic_correspondence"
        references.append(
            {
                "reference_id": case["case_id"] + "/" + candidate,
                "case_id": case["case_id"],
                "family": case["family"],
                "source_id": candidate,
                "source": source,
                "target": target,
                "user_text": "",
                "competing_sources": {key: value for key, value in sources.items() if key != candidate},
                "reference": reference,
                "reference_scope": scope,
                "reference_contract": scope,
                "semantic_relation": case["semantic_relation"],
                "rationale": case["rationale"],
                "construction": copy.deepcopy(construction),
                "construction_witnesses": witnesses,
                "text_only_origin_identifiability": case["text_only_origin_identifiability"],
                "source_sha256": _text_hash(source),
                "target_sha256": _text_hash(target),
                "synthetic_canary": None,
                "independent_human_labels": False,
            }
        )
    return references


def design_sha256(design=None):
    """Hash the declared design without scoring or modifying it."""
    value = fixture_design() if design is None else design
    compile_references(value)
    return hashlib.sha256(_canonical(value)).hexdigest()
