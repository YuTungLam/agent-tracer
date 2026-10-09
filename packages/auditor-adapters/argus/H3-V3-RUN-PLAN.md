# H3 v3 final guarded diagnostic and conditional panel

The private results checkout retains two incomplete exploratory H3 stages:
`20261010-deepseek-h3-exploratory-v1` and `-v2`. V1's first workspace Warrant
row hit a 192-request per-episode ceiling before its 195 context spans were
fully labeled. V2 labeled all spans, then ARGUS continued a breadth-first
grounding search for file ID `11`; the row hit the 300,000-token per-episode
ceiling after 218 requests. Both invalid rows are excluded from any H3 rate.
The two stages cost $0.04668510 and $0.10174770 respectively, with no H3
effect estimate.

V2's later grounding requests had increasing input lengths. Extrapolating
the remaining contexts and checkers suggests roughly 420k–440k tokens for a
first audit; a blocked call may cause an agent retry and another audit. The
final v3 stage therefore permits up to **640 requests and 1M tokens per
episode**, with a stricter aggregate S1 guard of **$0.60 / 2M tokens / 1,600
requests**. This is an operational ceiling, not an expected workload. It does
not change the pinned case/plan bytes, model, ARGUS algorithm, row methods or
scorer. All eight S1 rows run afresh. If S1 is incomplete for any reason,
stop this ARGUS H3 route; do not raise the bounds again in this sequence.

The user directed execution after a concrete plan without another approval.
V1 and v2 actual cost plus v3 S1's $0.60 maximum and conditional S2's $2.50
maximum equals **$3.24843280**, below the previously presented $3.25 total.
All calls still pass through the shared hard USD/token/request guard.

S1 passes to S2 only when all eight rows are complete and valid, inputs and
model identity match, every undefended arm executes L with native utility,
every Warrant arm proposes L, and per-case undefended utility differs by at
most 10 percentage points. A Warrant false block is an outcome, not a gate
failure. Before S2, multiply S1's actual USD, tokens and forwarded requests
by `1.2 * 5`; all three projections must fit S2's independent **$2.50 / 12M
tokens / 10,000 requests** guard. S2 runs 40 fresh rows and never reuses S1.

V3 remains an after-data exploratory, single-auditor, two-development-pair
probe with a substituted DeepSeek backbone. It does not establish the frozen
protocol's confirmatory cross-method H3 claim. Put generated evidence under
the confirmed private results checkout in experiment
`20261010-deepseek-h3-exploratory-v3`.
