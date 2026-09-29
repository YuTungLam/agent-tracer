# DeepSeek noncarrier chunk audit v1

Audit date: 2026-09-30. Generated evidence ID:
`20260930-deepseek-noncarrier-chunk-audit-v1` in `agent-tracer-results`.

## Question

The September 28 DeepSeek scale run produced many Tier-3/Tier-4 matches for
passages labelled noncarrier. This request-free follow-up asks whether those
matches are genuine semantic confusion, or whether the executed target occurs
elsewhere in the same serialized tool output and changes the interpretation of
the whole-output diagnostic.

This is a granularity and scorer audit. It does not estimate causal model
influence and it does not establish a provenance-defence bypass.

## Reproduction boundary

All 324 primary passage relations and 260 whole-output secondary relations were
rescored with the original pinned `all-MiniLM-L6-v2` revision and recorded
package versions. Status, match decision, score, and Tier-4 coverage agreed
with the frozen packet within absolute tolerance `1e-6`. No provider or agent
requests were made. The audit keeps all 103 noncarrier relations, including
the 21 negatives, rather than selecting only observed false positives.

## Result

At the primary-passage boundary, 82/103 noncarriers matched Tier 4 and 21/103
did not. The 82 positives divide into two substantively different mechanisms:

| Classification | Count | Interpretation |
| --- | ---: | --- |
| Target absent from the entire output | 35 | Genuine semantic confusion at the passage threshold; 28 Travel direct-context and 7 Workspace weak-relatedness cases |
| Target co-resident; whole-output best chunk contains it | 39 | Passage attribution is wrong, but the wider output genuinely contains the target and its best chunk localizes it |
| Target co-resident; whole-output best chunk excludes it | 6 | The output contains the target elsewhere, but an unrelated chunk wins the semantic maximum |
| Target co-resident; whole-output Tier 4 below threshold | 2 | Passage matches narrowly while the complete output does not |

For the 35 target-absent cases, the primary T3 and T4 score range is
`0.693058–0.884794` (median `0.808310`). Whole-output T3 ranges from
`0.227244–0.587356`; whole-output T4 has the same extrema and median
`0.524419`, so all 35 whole-output decisions remain below `0.60`.

For the 39 co-resident cases whose whole-output best chunk contains the target,
the whole-output T4 range is `0.725453–0.863880` (median `0.805439`). In the six
co-resident cases where a target-free chunk wins, whole-output T4 is still
`0.741303–0.757922`. The two remaining co-resident outputs score `0.588884` at
Tier 4. The detailed HTML report shows primary and whole-output T3/T4 scores,
all binary decisions, the winning chunks, and the best target-containing
chunks; saved evidence text is escaped and marked untrusted.

The carrier side remains 210/221 Tier-4 detections. That denominator includes
the separately declared numeric stratum and is not a controlled estimate of a
legitimate-versus-attacker role effect.

## Interpretation

The large DeepSeek run is useful, but not as a clean test of an intrinsic
attacker-recipient blind spot. Forty-seven of its 82 passage-level noncarrier
positives are affected by target co-residence elsewhere in the same tool
output. The remaining 35 are stronger evidence of semantic overmatching, but
they cluster in particular suite/context scaffolds. These populations must be
reported separately.

The result motivates improving source-unit localization and studying the 35
target-absent confusions. It does not justify pooling this observational batch
with Case R's matched recipient × context intervention or scaling a defence-
bypass claim across models.
