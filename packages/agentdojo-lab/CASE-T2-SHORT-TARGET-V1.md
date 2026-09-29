# Tier-2 short-target scaling: offline synthetic diagnostic

Protocol: `tier2-short-target-scaling-v1`, frozen on 2026-09-23 in
[the design note](docs/superpowers/specs/2026-09-23-tier2-short-target-scaling-design.md).
Output: [HTML report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260923-tier2-short-target-scaling-v1/index.html)
and [complete JSON packet](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260923-tier2-short-target-scaling-v1/packet.json).
The command made **zero model requests** and did not read or modify saved
trajectories:

```bash
cd codebase/agentdojo-lab
.venv/bin/python scripts/report_tier2_short_target.py \
  --output reports/20260923-tier2-short-target-scaling-v1
```

The 54 factorial cells vary target length (5, 10, 20, 40, 80, 160), source
length (256, 768, 2048), and uniform alphabet size (26 lowercase, 62
alphanumeric, 256 extended Latin code points). Each has 128 seeded target
triples: a literal-positive source, a histogram-matched shuffled negative,
and an independent same-alphabet negative. Both negatives exclude a contiguous
copy of the target. There are 6,912 triples and 20,736 exact Tier-2 evaluations
at the frozen 0.15 threshold. The original `lexical.lcs_evidence` function is
used directly, with no new filtering or threshold tuning.

| Control | Tier-2 matches | Scope |
| --- | ---: | --- |
| Literal positive | 6,912/6,912 | Expected manipulation check; LCS score 1.0 |
| Histogram-matched shuffled negative | 6,912/6,912 | 54/54 cells at 100% FPR against literal containment |
| Independent same-alphabet negative | 6,775/6,912 | 51/54 cells at 100% FPR; result varies at high alphabet size and short source |

The sharpest boundary is the 256-symbol alphabet with a 256-code-point source
and a 160-code-point target. Shuffling the literal carrier yields 128/128
noncontaining negatives above threshold (minimum score 0.15625; median 0.1875;
nominal 95% Wilson FPR interval 0.971–1.000). An independent source from the
same alphabet yields 7/128 matches (FPR 0.0547; 95% interval 0.0267–0.1086;
median score 0.13125). The only other independent cells below 100% are this
alphabet/source length at target length 5 (127/128) and 80 (113/128). Thus
source/target length ratio and composition conditioning matter: the data support
a broad high-false-positive region under the tested generators, not a universal
length cutoff or a claim that every noncarrier source will match.

These rates use a constructed label: no contiguous target string. They are not
agent source-attribution accuracy, decision influence, or attack success.
Natural text, email syntax, source dependencies and other sequence-unit choices
are not sampled. The Wilson intervals describe hypothetical repeats of this
generator, not uncertainty over real-world tasks. This is evidence about the
independent Unicode-code-point implementation, not the original authors' code.

## Verification and handoff

From `codebase/agentdojo-lab`, the following checks ran on 2026-09-23:

```bash
.venv/bin/pytest -q tests/test_tier2_short_target.py tests/test_lexical.py \
  tests/test_case_r_tier_diagnostic.py
.venv/bin/ruff check src/agentdojo_lab/tier2_short_target.py \
  scripts/report_tier2_short_target.py tests/test_tier2_short_target.py
git diff --check
```

Result: 58 tests passed; Ruff and `git diff --check` passed. Packet counts,
construction flags, code hashes and note links were checked. The report was
regenerated in a temporary directory and both artifacts were byte-identical:
`packet.json` SHA-256 `521179d2df76a9abaf3109a232365182da9794855221df0c8de9e30d19f52c50`;
`index.html` SHA-256 `70cf304234a2ccb6690257d262d9fd8638b79725bdb79c7bf75c8b62652dcad0`.
All new paths were checked for Git ignore rules; the diagnostic task did not
attempt remote synchronization. The integration milestone and sync status are
recorded in PROJECT_CONTEXT.md.
