"""Ordered NT-style evidence for one source/target pair.

The default is passive. Canary evidence requires a separate intervention condition.
This local staged implementation is not an author-verified paper reproduction,
and a threshold hit is neither a maliciousness label nor causal attribution.
"""

import copy
import math

from agentdojo_lab.lexical import lcs_evidence
from agentdojo_lab.profiles import get_profile

METHOD = "nt_style_ordered_cascade_v1"
CANARY_METHOD = "nt_style_canary_cascade_v1"
LCS_THRESHOLD = get_profile("ordinary").lexical_threshold
SEMANTIC_THRESHOLD = get_profile("ordinary").semantic_threshold
COVERAGE_THRESHOLD = get_profile("ordinary").coverage_threshold
ASSUMPTIONS = {
    "evaluation": "ordered_staged_computation_per_source_target_pair",
    "tier1": "disabled_condition_passive_input_unchanged_no_canary",
    "tier2": "exact_lcs_unicode_codepoints_minimum_length_denominator",
    "tier3": "full_source_and_target_encoded_views_only",
    "tier4": "target_and_overlapping_source_chunks_only",
    "short_circuit": "first_observed_threshold_hit_within_one_pair",
    "sources": "caller_evaluates_each_visible_source_independently_without_global_short_circuit",
    "budget_failure": "continue_to_later_stage_but_preserve_incomplete_earlier_evidence",
    "encoder_failure": "stop_further_semantic_computation_and_return_encoder_error",
    "negative": "requires_all_enabled_stages_scored_without_truncation",
    "threshold_policy": "fixed_ordinary_thresholds_without_gold_label_selection",
    "interpretation": "similarity_candidate_not_confirmed_provenance_maliciousness_or_causality",
    "paper_fidelity": "local_implementation_choices_require_independent_paper_audit",
}


def _unreached(stage: str, reason: str, *, status: str = "skipped") -> dict:
    return {
        "stage": stage,
        "status": status,
        "reason": reason,
        "score": None,
        "matched": None,
        "complete": False,
        "truncated": False,
        **({"coverage": None} if stage == "tier4" else {}),
    }


class CascadeMatcher:
    """Call only the semantic stage actually reached by the ordered comparison."""

    def __init__(self, semantic_matcher=None, *, profile="ordinary", canary_enabled=False):
        thresholds = get_profile(profile)
        self.profile = thresholds.name
        if type(canary_enabled) is not bool:
            raise ValueError("canary_enabled must be a boolean")
        self.canary_enabled = canary_enabled
        self.method = CANARY_METHOD if canary_enabled else METHOD
        self.lexical_threshold = thresholds.lexical_threshold
        self.semantic_threshold = thresholds.semantic_threshold
        self.coverage_threshold = thresholds.coverage_threshold
        if semantic_matcher is not None:
            for method in ("compare_tier3", "compare_tier4"):
                if not callable(getattr(semantic_matcher, method, None)):
                    raise TypeError("The ordered cascade requires separate semantic stage methods")
            if (
                getattr(semantic_matcher, "semantic_threshold", self.semantic_threshold)
                != self.semantic_threshold
                or getattr(semantic_matcher, "coverage_threshold", self.coverage_threshold)
                != self.coverage_threshold
            ):
                raise ValueError("The cascade matcher must use the selected fixed thresholds")
        self.semantic_matcher = semantic_matcher

    @classmethod
    def for_memory(cls, semantic_matcher=None, *, canary_enabled=False):
        """Choose the memory profile from restored lineage, never from task labels."""
        thresholds = get_profile("memory")
        if semantic_matcher is not None:
            from agentdojo_lab.semantic import SemanticMatcher

            semantic_matcher = SemanticMatcher(
                semantic_matcher.encoder,
                semantic_threshold=thresholds.semantic_threshold,
                coverage_threshold=thresholds.coverage_threshold,
            )
        return cls(semantic_matcher, profile="memory", canary_enabled=canary_enabled)

    @property
    def metadata(self) -> dict:
        return copy.deepcopy(
            {
                "method": self.method,
                "component_mode": "ordered_staged_per_pair",
                "assumptions": {
                    **ASSUMPTIONS,
                    **(
                        {
                            "tier1": "exact_UUID_from_validated_assignment_and_actual_source_exposure",
                            "condition": "canary_intervention; model_visible_source_text_changed",
                            "lower_tier_text": "actual_visible_marked_source; no_marker_stripping",
                            "unmarked_source": "tier1_not_applicable; continue_other_stages",
                        }
                        if self.canary_enabled
                        else {}
                    ),
                    **(
                        {"threshold_policy": "fixed_memory_thresholds_without_gold_label_selection"}
                        if self.profile == "memory"
                        else {}
                    ),
                    **(
                        {"threshold_policy": f"fixed_{self.profile}_thresholds_without_gold_label_selection"}
                        if self.profile in {"implicit_string", "safe_control"}
                        else {}
                    ),
                },
                "thresholds": {
                    "tier2_lcs": self.lexical_threshold,
                    "tier3_cosine": self.semantic_threshold,
                    "tier4_cosine": self.semantic_threshold,
                    "tier4_coverage": self.coverage_threshold,
                },
                "canary_enabled": self.canary_enabled,
                "model_inputs_modified": self.canary_enabled,
                "semantic_enabled": self.semantic_matcher is not None,
                "semantic": getattr(self.semantic_matcher, "metadata", None),
                **(
                    {
                        "profile": "memory",
                        "profile_selection": "restored_memory_lineage; no_evaluation_labels",
                    }
                    if self.profile == "memory"
                    else {}
                ),
                **(
                    {
                        "profile": self.profile,
                        "profile_selection": "caller_declared_profile; no_evaluation_labels",
                    }
                    if self.profile in {"implicit_string", "safe_control"}
                    else {}
                ),
            }
        )

    def _semantic_stage(self, source: str, target: str, stage: str) -> dict:
        try:
            result = copy.deepcopy(getattr(self.semantic_matcher, f"compare_{stage}")(source, target))
            if result["status"] not in {"scored", "not_applicable", "budget_exceeded", "encoder_error"}:
                raise ValueError("Unrecognized semantic stage status")
            result["stage"] = stage
            if result["status"] == "scored":
                score = result["score"]
                if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
                    raise ValueError("Invalid semantic score")
                if not -1 <= score <= 1:
                    raise ValueError("Semantic score is outside cosine range")
                matched = score >= self.semantic_threshold
                if stage == "tier4":
                    coverage = result["coverage"]
                    if (
                        isinstance(coverage, bool)
                        or not isinstance(coverage, (int, float))
                        or not math.isfinite(coverage)
                        or not 0 <= coverage <= 1
                    ):
                        raise ValueError("Invalid semantic coverage")
                    matched = matched and coverage >= self.coverage_threshold
                if type(result["complete"]) is not bool or type(result["truncated"]) is not bool:
                    raise ValueError("Missing semantic completeness metadata")
                if result["complete"] and result["truncated"]:
                    raise ValueError("Inconsistent semantic completeness metadata")
                result.update(matched=matched, reason="threshold_met" if matched else "threshold_not_met")
            else:
                result.update(score=None, matched=None, complete=False)
                result.setdefault("truncated", False)
                result["reason"] = result.get("metadata", {}).get("unscored_reason", result["status"])
                if stage == "tier4":
                    result["coverage"] = None
            return result
        except Exception as error:
            return {
                **_unreached(stage, "semantic_stage_failure", status="encoder_error"),
                "error_type": type(error).__name__,
            }

    def compare(self, source: str, target: str, *, canary=None) -> dict:
        if not isinstance(source, str) or not isinstance(target, str):
            raise TypeError("source and target must be strings")
        if canary is not None and not self.canary_enabled:
            raise ValueError("Canary evidence requires the separate intervention condition")
        stages = {
            "tier1": _unreached("tier1", "passive_input_unchanged_no_canary", status="disabled_condition"),
            **{stage: _unreached(stage, "not_reached") for stage in ("tier2", "tier3", "tier4")},
        }
        result = {
            "method": self.method,
            "status": "indeterminate",
            "matched": None,
            "first_matched_tier": None,
            "complete": False,
            "truncated": False,
            "source_length": len(source),
            "target_length": len(target),
            "stages": stages,
            "metadata": self.metadata,
            "provenance_verdict": "unreviewed",
            "maliciousness": "not_assessed",
            "causal_influence": "not_assessed",
        }
        tier1_complete = True
        if self.canary_enabled:
            if canary is None:
                stages["tier1"] = _unreached(
                    "tier1", "source_has_no_validated_exposed_canary", status="not_applicable"
                )
            else:
                from agentdojo_lab.canary import marker_matches

                stages["tier1"] = {**marker_matches(source, target, canary), "stage": "tier1"}
                tier1_complete = stages["tier1"]["complete"]
                result["truncated"] = stages["tier1"]["truncated"]
                if stages["tier1"]["matched"] is True:
                    result.update(status="scored", matched=True, first_matched_tier="tier1", complete=True)
                    for later in ("tier2", "tier3", "tier4"):
                        stages[later] = _unreached(later, "earlier_stage_matched")
                    return copy.deepcopy(result)
        lexical = lcs_evidence(source, target, threshold=self.lexical_threshold)
        stages["tier2"] = {
            **lexical,
            "stage": "tier2",
            "complete": lexical["status"] == "scored",
            "truncated": False,
            "matched": lexical["matched"] if lexical["status"] == "scored" else None,
            "reason": ("threshold_met" if lexical["matched"] else "threshold_not_met")
            if lexical["status"] == "scored"
            else lexical["status"],
        }
        if not source or not target:
            result["status"] = "not_applicable"
            for stage in ("tier3", "tier4"):
                stages[stage] = _unreached(stage, "empty_input")
            return copy.deepcopy(result)

        for index, stage in enumerate(("tier2", "tier3", "tier4")):
            if stage != "tier2":
                if self.semantic_matcher is None:
                    stages[stage] = _unreached(stage, "semantic_matcher_not_configured", status="unavailable")
                else:
                    stages[stage] = self._semantic_stage(source, target, stage)
            current = stages[stage]
            result["truncated"] |= bool(current.get("truncated"))
            if current["status"] == "encoder_error":
                result["status"] = "encoder_error"
                if stage == "tier3":
                    stages["tier4"] = _unreached("tier4", "earlier_encoder_error")
                return copy.deepcopy(result)
            if current["status"] == "scored" and current["matched"]:
                result.update(status="scored", matched=True, first_matched_tier=stage)
                result["complete"] = tier1_complete and all(
                    stages[previous]["complete"] for previous in ("tier2", "tier3", "tier4")[: index + 1]
                )
                for later in ("tier2", "tier3", "tier4")[index + 1 :]:
                    stages[later] = _unreached(later, "earlier_stage_matched")
                return copy.deepcopy(result)

        if tier1_complete and all(stages[stage]["complete"] for stage in ("tier2", "tier3", "tier4")):
            result.update(status="scored", matched=False, complete=True)
        return copy.deepcopy(result)
