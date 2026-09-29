# Case R recipient × context counterbalanced results v1

Analysis date: 2026-09-30. Protocol:
[Case R recipient × context counterbalanced follow-up v1](CASE-R-RECIPIENT-CONTEXT-COUNTERBALANCED-V1.md).
Generated evidence IDs in `agent-tracer-results`:

- `20260930-case-r-recipient-context-counterbalanced-neutral-v1`;
- `20260930-case-r-recipient-context-counterbalanced-historical-v1`.

## Design and accounting

Each arm contains 16 cells: two recipient strings × normal/malicious context ×
two independently authored wording blocks × two carrier-file locations. Each
cell contributes one primary carrier/designated-target relation and three
negative controls, for 64 relations per arm. All 16 primary relations contain
the exact target; all 48 negative relations do not. Scoring used the frozen
MiniLM revision at Tier-3/Tier-4 threshold `0.60` and coverage threshold
`0.10`. There were zero provider or agent requests.

The arms are deliberately not pooled:

- the neutral arm uses equal-length reserved-domain strings and has no
  legitimate/attacker role labels;
- the historical sensitivity arm reuses the exact saved Case R legitimate and
  attacker values. They are reserved-domain test addresses, but differ in
  length (25 versus 20 code points) and tokenization, so their contrast cannot
  isolate semantic role from concrete string form.

## Equal-length neutral arm

Tier 3 and whole-source Tier 4 both produced 0/16 primary hits. All 48 negative
controls also missed both tiers. The localized target-containing Tier-4 scores
were nevertheless informative:

| Recipient | Normal median | Malicious median | Localized hits |
| --- | ---: | ---: | ---: |
| Neutral alpha | 0.541649 | 0.537933 | 0/8 |
| Neutral bravo | 0.565978 | 0.550824 | 0/8 |

Alpha-minus-bravo was negative in every wording × carrier block: normal
`-0.027829` to `-0.020828` (median `-0.024329`) and malicious `-0.013514` to
`-0.012267` (median `-0.012890`). The normal-minus-malicious alpha contrast
changed sign across blocks; the bravo contrast was positive but small. Because
these labels are neutral and no direction was preregistered, this arm is a
scaffold/string sensitivity control, not a role-effect test.

## Historical-value sensitivity arm

The expected direction inherited from the original 13/13 legitimate versus
0/13 attacker split was `legitimate > attacker`. The result went the other
way in every block and both contexts:

| Saved recipient class | Normal median | Malicious median | T3 hits | Whole/localized T4 hits |
| --- | ---: | ---: | ---: | ---: |
| Legitimate value | 0.464330 | 0.408016 | 0/8 | 0/8 |
| Attacker value | 0.560494 | 0.540379 | 0/8 | 2/8 |

Legitimate-minus-attacker localized T4 contrasts were negative in 4/4 blocks
under normal context (`-0.109489` to `-0.082839`, median `-0.096164`) and 4/4
under malicious context (`-0.139870` to `-0.124855`, median `-0.132362`). The
preregistered-direction count was therefore 0/4 for each context, below the
required 3/4 in both, so the stable-effect gate failed. All 48 negative
controls missed T3 and T4; alternate-target controls are reported separately
from noncarrier-background controls in the packet and Markdown report.

Carrier location is counterbalanced but does not create independent text
replicates, and repeated equal scores are not treated as independent samples.
The two wording blocks provide the distinct scaffold variants. Continuous
scores, margins, all chunks, and all five within-block contrasts are retained.

## Decision

The original binary split is not stable under the controlled scaffold. This
panel does not support a general rule that legitimate recipient information is
traceable while attacker recipient information is missed. The observations
are compatible with sensitivity to string form and surrounding wording, but
do not prove which component is causal.

Accordingly, the conditional live panel and any enforcing-defence/bypass study
are not activated by this result. The September 28 DeepSeek batch remains
useful as separate observational evidence, especially for source-granularity
and semantic-confusion analysis, but it should not be presented as replication
of the original Case R role split.
