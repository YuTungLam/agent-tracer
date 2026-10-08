"""Two-sample fidelity rule for published-backbone runs (RUN-PLAN-OPENAI.md section 1).

A run on the paper's own backbone is compared with a published count, which is itself
a sample.  The rule therefore asks whether the *difference* of the two proportions is
consistent with 0, not whether our one-sample interval contains the published point
estimate (that one-sample rule fails a faithful reproduction about 1 time in 6 per
number, and 30-56% of the time jointly over 2-4 numbers).

Rule: for each of the k numbers an auditor is checked on, compute the Newcombe
hybrid-score interval (Newcombe 1998, Statistics in Medicine 17:873-890, method 10)
of ``ours - published`` at confidence ``1 - 0.05/k`` (Bonferroni).  A number is
"consistent" when its interval contains 0; the auditor's fidelity check passes when
every number is consistent.

``python fidelity_rule.py`` prints the acceptance bands and the pass probabilities
under equal true rates (exact binomial enumeration) for the targets in the plan.
Standard library only.
"""

from __future__ import annotations

import json
import math
import sys
from statistics import NormalDist


def wilson(successes: int, n: int, z: float) -> tuple[float, float]:
    if n <= 0 or not 0 <= successes <= n:
        raise ValueError("need 0 <= successes <= n and n > 0")
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def z_for(k: int, alpha: float = 0.05) -> float:
    """Two-sided normal quantile for Bonferroni level alpha/k."""
    if k < 1:
        raise ValueError("k must be >= 1")
    return NormalDist().inv_cdf(1 - alpha / (2 * k))


def newcombe_difference(x1: int, n1: int, x2: int, n2: int, z: float) -> tuple[float, float, float]:
    """(difference, lower, upper) of p1 - p2, Newcombe hybrid score interval."""
    p1, p2 = x1 / n1, x2 / n2
    l1, u1 = wilson(x1, n1, z)
    l2, u2 = wilson(x2, n2, z)
    difference = p1 - p2
    lower = difference - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    upper = difference + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return difference, lower, upper


def consistent(ours: int, n_ours: int, published: int, n_published: int, k: int) -> bool:
    _, lower, upper = newcombe_difference(ours, n_ours, published, n_published, z_for(k))
    return lower <= 0 <= upper


def acceptance_band(n_ours: int, published: int, n_published: int, k: int) -> tuple[int, int]:
    """Smallest and largest of our counts that are consistent with the published count."""
    accepted = [x for x in range(n_ours + 1) if consistent(x, n_ours, published, n_published, k)]
    return accepted[0], accepted[-1]


def _pmf(n: int, p: float) -> list[float]:
    return [math.comb(n, x) * p ** x * (1 - p) ** (n - x) for x in range(n + 1)]


def pass_probability(n_ours: int, published: int, n_published: int, k: int) -> float:
    """P(consistent) when both runs share the true rate published/n_published (exact enumeration)."""
    p = published / n_published
    ours, theirs = _pmf(n_ours, p), _pmf(n_published, p)
    z = z_for(k)
    total = 0.0
    for x, px in enumerate(ours):
        if px == 0.0:
            continue
        for y, py in enumerate(theirs):
            if py == 0.0:
                continue
            _, lower, upper = newcombe_difference(x, n_ours, y, n_published, z)
            if lower <= 0 <= upper:
                total += px * py
    return total


def one_sample_pass_probability(n_ours: int, published: int, n_published: int) -> float:
    """The earlier rule (our Wilson 95% interval contains the published point estimate), for comparison."""
    p = published / n_published
    ours, theirs = _pmf(n_ours, p), _pmf(n_published, p)
    z = NormalDist().inv_cdf(0.975)
    total = 0.0
    for x, px in enumerate(ours):
        lower, upper = wilson(x, n_ours, z)
        for y, py in enumerate(theirs):
            if lower <= y / n_published <= upper:
                total += px * py
    return total


# (number, published count, published n, our planned n) per auditor; k = numbers per auditor.
TARGETS: dict[str, list[tuple[str, int, int, int]]] = {
    "adi/S2-openai": [("ADI ASR", 53, 108, 108), ("benign utility", 83, 96, 96)],
    "attriguard/S2-openai (attriguard_l2)": [("BU", 24, 34, 34), ("UA", 154, 230, 230), ("ASR", 0, 230, 230)],
    "argus/S2-openai-full": [("Warrant ASR", 12, 320, 320), ("Warrant Uc", 35, 40, 40),
                             ("no-defense ASR", 92, 320, 320), ("no-defense Uc", 37, 40, 40)],
    "argus/S2-openai (subset)": [("Warrant ASR", 12, 320, 80), ("Warrant Uc", 35, 40, 40),
                                 ("no-defense ASR", 92, 320, 80), ("no-defense Uc", 37, 40, 40)],
}


def table() -> dict[str, dict]:
    report: dict[str, dict] = {}
    for auditor, rows in TARGETS.items():
        k = len(rows)
        joint, joint_old = 1.0, 1.0
        numbers = []
        for name, published, n_published, n_ours in rows:
            probability = pass_probability(n_ours, published, n_published, k)
            old = one_sample_pass_probability(n_ours, published, n_published)
            joint *= probability
            joint_old *= old
            numbers.append({
                "number": name, "published": f"{published}/{n_published}", "n_ours": n_ours,
                "accept_ours": list(acceptance_band(n_ours, published, n_published, k)),
                "p_consistent_if_equal": round(probability, 3), "p_one_sample_rule": round(old, 3),
            })
        report[auditor] = {"k": k, "confidence": round(1 - 0.05 / k, 4), "numbers": numbers,
                           "p_joint_if_equal": round(joint, 3), "p_joint_one_sample_rule": round(joint_old, 3),
                           "joint_note": "product over numbers (independence assumed)"}
    return report


if __name__ == "__main__":
    json.dump(table(), sys.stdout, indent=2)
    print()
