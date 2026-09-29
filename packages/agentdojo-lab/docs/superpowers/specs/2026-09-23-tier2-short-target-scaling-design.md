# Tier-2 short-target scaling diagnostic v1

Design and run date: 2026-09-23. Protocol ID:
`tier2-short-target-scaling-v1`. This is a synthetic, offline diagnostic with
zero model requests. It extends the bounded Case R length panel into a controlled
factorial, without changing or interpreting saved Case R trajectories.

## Question and inference boundary

When the local paper-style Tier-2 score is
`LCS(source, target) / min(len(source), len(target))` and the threshold is 0.15,
how often does an exact but noncontiguous subsequence match arise for short
targets in long sources, and how does conditioning source composition on the
target change the result? A negative here
means only that the source does not contain the target as a *contiguous literal
substring*. It does not mean the source cannot influence an agent. The measured
false-positive rate is relative to that constructed literal-containment label,
not a deployment estimate or a paper-author benchmark.

The existing `agentdojo_lab.lexical.lcs_evidence` implementation is reused
without changes. It uses Unicode code points, exact bitset LCS, no case folding
or normalization and a 0.15 threshold. The paper does not uniquely specify
sequence units or preprocessing, so results are limited to this reproduction.

## Frozen design

| Dimension | Values |
| --- | --- |
| Target lengths | 5, 10, 20, 40, 80, 160 code points |
| Source lengths | 256, 768, 2048 code points |
| Character distributions | Uniform lowercase 26, alphanumeric 62, extended Latin Unicode 256 (`U+0100`–`U+01FF`) |
| Repetitions | 128 independent target triples per factorial cell |
| Seed | `20260923`; cell seed is SHA-256 of `seed/alphabet_id/source_length/target_length` |
| Scorer | `lcs_evidence`, threshold 0.15, exact full strings |
| Total | 54 cells, 6,912 triples, 20,736 Tier-2 evaluations |

For each triple, draw a target and a source scaffold uniformly with replacement
from the same alphabet. Replace a random span of the scaffold with the target to
form the positive source. Two negative controls use the *same target* and source
length:

1. **Histogram-matched shuffle:** randomly shuffle the exact positive source
   until it does not contain the target as a contiguous substring. Positive and
   shuffled-negative sources have exactly the same character counts. This
   isolates order and literal adjacency under a deliberately strong
   target-composition match.
2. **Independent uniform draw:** draw a new source from the same alphabet until
   it does not contain the target contiguously. This shares the generating
   distribution but does not condition the source histogram on the target.

A maximum of 1,000 attempts per negative is allowed; exhaustion is an error,
not an omitted sample. Insertion index, attempts, hashes, scores and decisions
are retained for every triple. The generator checks both labels and exact
histogram equality of the shuffled pair before scoring.

The three distributions examine how alphabet size changes chance subsequence
overlap. They are synthetic streams; none claims to model natural language,
email-address syntax or AgentDojo tool-output distribution. Since a literal
positive contains the entire target, its LCS score must be 1.0 and positive
match rate is a manipulation check.

## Measures and output

Each cell reports TP/FN/FP/TN, TPR, FPR for both negative controls, two-sided
nominal 95% Wilson intervals for those rates, source/target length ratio and
min/p05/p25/median/p75/p95/max score distributions for all three sources.
Per-target-length rates
pooled across cells are descriptive only because the underlying cell
probabilities can differ. The report makes no pooled binomial CI claim.

The script writes a new `packet.json` with the frozen plan, all triple records,
cell and length summaries, SHA-256 of the scorer and generator, and limitations.
The self-contained `index.html` displays FPR curves, per-cell counts, intervals
and score quantiles. The output directory must not already exist. All files in
older `runs/` and `reports/` remain untouched.

From `codebase/agentdojo-lab`:

```bash
.venv/bin/python scripts/report_tier2_short_target.py \
  --output reports/20260923-tier2-short-target-scaling-v1
.venv/bin/pytest -q tests/test_tier2_short_target.py
.venv/bin/ruff check src/agentdojo_lab/tier2_short_target.py \
  scripts/report_tier2_short_target.py tests/test_tier2_short_target.py
```

## Interpretation rule

Describe a length/distribution/ratio regime only from the measured cells and
their intervals. Do not extrapolate a universal short-target boundary from this
generator. Do not treat correspondence as causal provenance, attack success,
Tier-1/3/4 performance, or author-code replication. Do not tune the threshold
after observing this protocol's results; a sensitivity analysis would require a
separately named protocol.
