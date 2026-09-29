"""Auditable views over full Tier-3/Tier-4 results.

This module adds source-bound chunk text and target-containment annotations to
the existing semantic scorer. It performs no model loading or network access.
"""

from __future__ import annotations

import hashlib
import math

DEFAULT_SCORE_TOLERANCE = 1e-6


def _validated_span(value: object, text_length: int, label: str) -> list[int]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise ValueError(f"Invalid {label} span")
    start, end = value
    if not 0 <= start < end <= text_length:
        raise ValueError(f"Out-of-range {label} span")
    return [start, end]


def detailed_semantic_stage(
    matcher,
    name: str,
    source: str,
    target: str,
    *,
    score_tolerance: float = DEFAULT_SCORE_TOLERANCE,
) -> dict:
    """Retain and validate scorer detail for an independently invoked stage."""
    if name not in ("tier3", "tier4"):
        raise ValueError("Detailed semantic stage must be tier3 or tier4")
    try:
        result = getattr(matcher, f"compare_{name}")(source, target)
    except Exception as error:
        raise RuntimeError(f"Detailed {name} scoring failed: {type(error).__name__}") from error
    if not isinstance(result, dict):
        raise ValueError(f"Detailed {name} scorer returned a non-object")
    status = result.get("status")
    matched = result.get("matched") if status == "scored" else None
    if status == "scored" and type(matched) is not bool:
        raise ValueError(f"Detailed {name} result lacks a Boolean match decision")
    detail = {
        "status": status,
        "matched": matched,
        "score": result.get("score"),
        "complete": result.get("complete"),
        "truncated": result.get("truncated"),
    }
    if status != "scored":
        return detail
    score = detail["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise ValueError(f"Detailed {name} result has an invalid score")
    if type(detail["complete"]) is not bool or type(detail["truncated"]) is not bool:
        raise ValueError(f"Detailed {name} result lacks completeness metadata")
    if "target_tokenization" in result:
        detail["target_tokenization"] = result["target_tokenization"]
    if name == "tier3":
        for key in ("source_tokenization", "source_visible_span"):
            if key in result:
                detail[key] = result[key]
        return detail

    coverage = result.get("coverage")
    if isinstance(coverage, bool) or not isinstance(coverage, (int, float)) or not math.isfinite(coverage):
        raise ValueError("Detailed tier4 result has invalid coverage")
    chunks = result.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("Detailed tier4 result lacks chunks")
    annotated = []
    for index, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            raise ValueError("Detailed tier4 chunk is not an object")
        span = _validated_span(chunk.get("span"), len(source), "raw chunk")
        visible_span = _validated_span(chunk.get("visible_span"), len(source), "encoded chunk")
        if not span[0] <= visible_span[0] < visible_span[1] <= span[1]:
            raise ValueError("Encoded chunk span is outside the raw chunk")
        chunk_score = chunk.get("score")
        if (
            isinstance(chunk_score, bool)
            or not isinstance(chunk_score, (int, float))
            or not math.isfinite(chunk_score)
            or type(chunk.get("matched")) is not bool
        ):
            raise ValueError("Detailed tier4 chunk has invalid score metadata")
        raw_text = source[span[0] : span[1]]
        visible_text = source[visible_span[0] : visible_span[1]]
        annotated.append(
            {
                **chunk,
                "index": index,
                "span": span,
                "visible_span": visible_span,
                "raw_text": raw_text,
                "raw_text_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
                "encoded_visible_text": visible_text,
                "encoded_visible_text_sha256": hashlib.sha256(visible_text.encode("utf-8")).hexdigest(),
                "contains_complete_target_raw": target in raw_text,
                "contains_complete_target_encoded": target in visible_text,
            }
        )
    best = max(annotated, key=lambda item: item["score"])
    best_indices = [item["index"] for item in annotated if item["score"] == best["score"]]
    target_chunks = [item for item in annotated if item["contains_complete_target_encoded"]]
    best_target = max(target_chunks, key=lambda item: item["score"], default=None)
    best_target_indices = (
        [item["index"] for item in target_chunks if item["score"] == best_target["score"]]
        if best_target
        else []
    )
    if not math.isclose(best["score"], score, rel_tol=0.0, abs_tol=score_tolerance):
        raise ValueError("Detailed tier4 best chunk disagrees with the stage score")
    matched_spans = [
        _validated_span(span, len(source), "matched visible")
        for span in result.get("matched_visible_spans", [])
    ]
    detail.update(
        coverage=coverage,
        chunks=annotated,
        matched_visible_spans=matched_spans,
        target_occurrences_in_source=source.count(target),
        target_exact_in_source=target in source,
        best_chunk_index=best["index"],
        best_chunk_indices=best_indices,
        best_chunk_contains_complete_target_encoded=best["contains_complete_target_encoded"],
        any_best_chunk_contains_complete_target_encoded=any(
            annotated[index]["contains_complete_target_encoded"] for index in best_indices
        ),
        all_best_chunks_contain_complete_target_encoded=all(
            annotated[index]["contains_complete_target_encoded"] for index in best_indices
        ),
        best_target_containing_chunk_index=best_target["index"] if best_target else None,
        best_target_containing_chunk_indices=best_target_indices,
        best_target_containing_chunk_score=best_target["score"] if best_target else None,
        matched_chunk_count=sum(item["matched"] for item in annotated),
        matched_target_containing_chunk_count=sum(
            item["matched"] and item["contains_complete_target_encoded"] for item in annotated
        ),
    )
    return detail
