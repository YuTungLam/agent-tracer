"""Deterministic, request-free Tier-2 short-target scaling controls.

This is a synthetic diagnostic of the local paper-style LCS implementation,
not an agent trajectory, a provenance oracle, or a calibrated deployment rate.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
from collections import Counter

from agentdojo_lab.lexical import lcs_evidence

PROTOCOL = "tier2-short-target-scaling-v1"
SEED = 20260923
THRESHOLD = 0.15
TARGET_LENGTHS = (5, 10, 20, 40, 80, 160)
SOURCE_LENGTHS = (256, 768, 2048)
REPLICATES = 128
ALPHABETS = {
    "lowercase_26": "abcdefghijklmnopqrstuvwxyz",
    "alphanumeric_62": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "unicode_256": "".join(chr(code) for code in range(0x0100, 0x0200)),
}
Z_95 = 1.959963984540054


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cell_seed(seed: int, alphabet_id: str, source_length: int, target_length: int) -> int:
    label = f"{seed}/{alphabet_id}/{source_length}/{target_length}"
    return int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest(), "big")


def make_pair(rng: random.Random, alphabet: str, source_length: int, target_length: int) -> dict:
    """Make a carrier plus paired-shuffle and independent-stream noncarriers."""
    if target_length < 1 or source_length < target_length:
        raise ValueError("source_length must be at least target_length and both must be positive")
    if len(set(alphabet)) != len(alphabet) or len(alphabet) < 2:
        raise ValueError("alphabet must have at least two distinct characters")

    target = "".join(rng.choices(alphabet, k=target_length))
    scaffold = "".join(rng.choices(alphabet, k=source_length))
    insertion = rng.randrange(source_length - target_length + 1)
    positive = scaffold[:insertion] + target + scaffold[insertion + target_length :]
    characters = list(positive)
    for attempts in range(1, 1001):
        rng.shuffle(characters)
        negative = "".join(characters)
        if target not in negative:
            break
    else:
        raise RuntimeError("could not construct a noncontaining shuffle in 1000 attempts")

    for independent_attempts in range(1, 1001):
        independent = "".join(rng.choices(alphabet, k=source_length))
        if target not in independent:
            break
    else:
        raise RuntimeError("could not construct an independent noncarrier in 1000 attempts")

    if target not in positive or target in negative or target in independent:
        raise RuntimeError("constructed literal-containment labels are invalid")
    if len(positive) != source_length or len(negative) != source_length or len(independent) != source_length:
        raise RuntimeError("constructed source lengths are invalid")
    if Counter(positive) != Counter(negative):
        raise RuntimeError("shuffled control changed source character counts")
    return {
        "target": target,
        "positive": positive,
        "negative": negative,
        "independent_negative": independent,
        "insertion_index": insertion,
        "negative_shuffle_attempts": attempts,
        "independent_draw_attempts": independent_attempts,
    }


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> list[float]:
    """Wilson score interval for a binomial construction's nominal 95% range."""
    if not 0 <= successes <= trials or trials < 1:
        raise ValueError("require 0 <= successes <= trials and trials >= 1")
    p = successes / trials
    z2 = z * z
    denominator = 1 + z2 / trials
    center = (p + z2 / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def quantile(sorted_values: list[float], q: float) -> float:
    if not sorted_values or not 0 <= q <= 1:
        raise ValueError("quantile requires nonempty sorted values and 0 <= q <= 1")
    position = (len(sorted_values) - 1) * q
    low = math.floor(position)
    high = math.ceil(position)
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (position - low)


def score_distribution(scores: list[float]) -> dict:
    ordered = sorted(scores)
    return {
        "min": ordered[0],
        "p05": quantile(ordered, 0.05),
        "p25": quantile(ordered, 0.25),
        "median": statistics.median(ordered),
        "p75": quantile(ordered, 0.75),
        "p95": quantile(ordered, 0.95),
        "max": ordered[-1],
        "perfect_matches": sum(score == 1.0 for score in scores),
    }


def run_experiment(
    *,
    seed: int = SEED,
    target_lengths: tuple[int, ...] = TARGET_LENGTHS,
    source_lengths: tuple[int, ...] = SOURCE_LENGTHS,
    alphabets: dict[str, str] | None = None,
    replicates: int = REPLICATES,
) -> dict:
    """Run all factorial cells using the existing exact Tier-2 scorer."""
    alphabets = ALPHABETS if alphabets is None else alphabets
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if isinstance(replicates, bool) or not isinstance(replicates, int) or replicates < 1:
        raise ValueError("replicates must be a positive integer")
    if not target_lengths or not source_lengths or not alphabets:
        raise ValueError("target lengths, source lengths and alphabets must be nonempty")
    if min(source_lengths) < max(target_lengths):
        raise ValueError("every source length must be at least every target length")

    rows, cells = [], []
    for alphabet_id, alphabet in alphabets.items():
        for source_length in source_lengths:
            for target_length in target_lengths:
                rng = random.Random(_cell_seed(seed, alphabet_id, source_length, target_length))
                cell_rows = []
                for repetition in range(1, replicates + 1):
                    pair = make_pair(rng, alphabet, source_length, target_length)
                    pos = lcs_evidence(pair["positive"], pair["target"], threshold=THRESHOLD)
                    neg = lcs_evidence(pair["negative"], pair["target"], threshold=THRESHOLD)
                    ind = lcs_evidence(pair["independent_negative"], pair["target"], threshold=THRESHOLD)
                    if any(evidence["status"] != "scored" for evidence in (pos, neg, ind)):
                        raise RuntimeError("a synthetic pair exceeded the frozen exact-LCS budget")
                    row = {
                        "alphabet": alphabet_id,
                        "source_length": source_length,
                        "target_length": target_length,
                        "source_target_ratio": source_length / target_length,
                        "repetition": repetition,
                        "target_sha256": sha256_text(pair["target"]),
                        "positive_source_sha256": sha256_text(pair["positive"]),
                        "negative_source_sha256": sha256_text(pair["negative"]),
                        "independent_negative_source_sha256": sha256_text(pair["independent_negative"]),
                        "insertion_index": pair["insertion_index"],
                        "negative_shuffle_attempts": pair["negative_shuffle_attempts"],
                        "independent_draw_attempts": pair["independent_draw_attempts"],
                        "positive_contains_target": True,
                        "negative_contains_target": False,
                        "independent_negative_contains_target": False,
                        "source_character_histograms_equal": True,
                        "positive_score": pos["score"],
                        "positive_lcs_length": pos["lcs_length"],
                        "positive_matched": pos["matched"],
                        "negative_score": neg["score"],
                        "negative_lcs_length": neg["lcs_length"],
                        "negative_matched": neg["matched"],
                        "independent_negative_score": ind["score"],
                        "independent_negative_lcs_length": ind["lcs_length"],
                        "independent_negative_matched": ind["matched"],
                    }
                    rows.append(row)
                    cell_rows.append(row)
                tp = sum(row["positive_matched"] for row in cell_rows)
                fp = sum(row["negative_matched"] for row in cell_rows)
                independent_fp = sum(row["independent_negative_matched"] for row in cell_rows)
                cells.append(
                    {
                        "alphabet": alphabet_id,
                        "source_length": source_length,
                        "target_length": target_length,
                        "source_target_ratio": source_length / target_length,
                        "n_positive": replicates,
                        "n_negative": replicates,
                        "tp": tp,
                        "fn": replicates - tp,
                        "fp": fp,
                        "tn": replicates - fp,
                        "tpr": tp / replicates,
                        "fpr": fp / replicates,
                        "independent_fp": independent_fp,
                        "independent_tn": replicates - independent_fp,
                        "independent_fpr": independent_fp / replicates,
                        "tpr_wilson_95": wilson_interval(tp, replicates),
                        "fpr_wilson_95": wilson_interval(fp, replicates),
                        "independent_fpr_wilson_95": wilson_interval(independent_fp, replicates),
                        "positive_distribution": score_distribution([r["positive_score"] for r in cell_rows]),
                        "negative_distribution": score_distribution([r["negative_score"] for r in cell_rows]),
                        "independent_negative_distribution": score_distribution(
                            [r["independent_negative_score"] for r in cell_rows]
                        ),
                        "shuffle_rejections": sum(r["negative_shuffle_attempts"] - 1 for r in cell_rows),
                        "independent_rejections": sum(r["independent_draw_attempts"] - 1 for r in cell_rows),
                    }
                )

    length_summary = []
    for target_length in target_lengths:
        subset = [row for row in rows if row["target_length"] == target_length]
        tp = sum(row["positive_matched"] for row in subset)
        fp = sum(row["negative_matched"] for row in subset)
        independent_fp = sum(row["independent_negative_matched"] for row in subset)
        n = len(subset)
        length_summary.append(
            {
                "target_length": target_length,
                "n_per_label": n,
                "tpr": tp / n,
                "fpr": fp / n,
                "independent_fpr": independent_fp / n,
                "negative_distribution": score_distribution([row["negative_score"] for row in subset]),
                "independent_negative_distribution": score_distribution(
                    [row["independent_negative_score"] for row in subset]
                ),
            }
        )
    return {
        "protocol": PROTOCOL,
        "requests": 0,
        "population": "synthetic_constructed_controls",
        "scorer": "agentdojo_lab.lexical.lcs_evidence",
        "threshold": THRESHOLD,
        "sequence_unit": "unicode_codepoint",
        "plan": {
            "seed": seed,
            "cell_seed": "SHA-256(integer seed/alphabet id/source length/target length), interpreted as big-endian integer",
            "target_lengths": list(target_lengths),
            "source_lengths": list(source_lengths),
            "replicates_per_cell": replicates,
            "alphabets": alphabets,
            "target_sampling": "uniform_with_replacement_from_alphabet",
            "source_sampling": "uniform_with_replacement_from_same_alphabet",
            "positive": "replace a source-length-matched random scaffold span with the exact target",
            "negative": "shuffle the full positive source until the exact target is not a contiguous substring",
            "independent_negative": "draw a new source uniformly from the same alphabet until the exact target is not a contiguous substring",
            "shuffled_control": "same target, exact source length, and exact source character histogram",
            "independent_control": "same target, exact source length, and same sampling distribution; source histogram is not conditioned on target",
            "confidence_interval": "two-sided Wilson score, nominal 95%, conditional on the synthetic sampling design",
            "quantile": "linear interpolation at index (n-1)*q in sorted scores",
        },
        "rows": rows,
        "cells": cells,
        "by_target_length": length_summary,
        "total_pairs": len(rows),
        "total_evaluations": len(rows) * 3,
        "limitations": [
            "Synthetic character streams are not natural tool outputs or real sensitive arguments.",
            "The shuffled arm conditions on the target's exact character counts; the independent arm does not. Their difference is part of the result.",
            "The negative label means no literal contiguous target, not absence of semantic or causal influence.",
            "Wilson intervals describe repeated sampling under this generator, not uncertainty over real-world tasks.",
            "This diagnoses one independent Unicode-code-point reproduction of the paper's underspecified LCS units.",
        ],
    }
