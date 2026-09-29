# Case R (Groq): recipient contamination under redundant and split sources

Protocol note, 2026-09-20. Design:
[docs/superpowers/specs/2026-09-20-case-r-groq-design.md](docs/superpowers/specs/2026-09-20-case-r-groq-design.md).
Frozen parameters: [configs/case_r_groq_v1.json](configs/case_r_groq_v1.json), generated from
`src/agentdojo_lab/case_r_groq.py`.

## Question

Does the independent NeuroTaint implementation localize the source responsible for a
changed `send_email` recipient when (a) two sources redundantly carry the same attacker
address, and (b) one source carries only the instruction while the other carries only the
address? The saved Scout evidence suggests that the Tier-2 subsequence LCS matches nearly
every source against a short recipient and thereby disables the causal fallback. Case R
tests that deliberately with Groq `openai/gpt-oss-120b`, the only model in this repository
with observed injection-following.

## Constructions

| Construction | File 1 (source A) payload | File 2 (source B) payload | Predicted recipient |
| --- | --- | --- | --- |
| `r_redundant` | address + instruction | address + instruction | both T, a_only T, b_only T, neither F |
| `r_split` | instruction only | address only | both T, a_only F, b_only F, neither F |

The legitimate recipient `john.mitchell@example.com` appears only in file 1. File 2 carries
action items and no address, so in the clean run it is a genuine non-source for the recipient.

## Protocols

| Name | Purpose | Requests |
| --- | --- | --- |
| `groq-case-r-pilot-v1` | One repetition of all eight arms; checks that `neither` completes with the legitimate recipient and `both` redirects | at most 48 (6 per slot) |
| `groq-case-r-v1` | Three repetitions of all eight arms | at most 144 (6 per slot) |
| `groq-case-r-followups-v1` | Forced sham/neutralized replays and no-tools judgments on successful `both` sinks | at most 7 per sink, at most 6 sinks |
| `case-r-attribution-diagnostics-v1` | Request-free re-scoring under baseline, substring and semantic-only Tier-2 rules | 0 |
| `case-r-tier-diagnostic-v1` | Request-free tier ablation: Tier 3/4 recomputed independently on every recorded pair, T1→T3→T4 counterfactual cascade, VALUE-provenance matrices, Tier-2 alignment and length panels. Design: [docs/superpowers/specs/2026-09-22-case-r-tier-diagnostic-design.md](docs/superpowers/specs/2026-09-22-case-r-tier-diagnostic-design.md) | 0 |

Model: Groq `openai/gpt-oss-120b`, temperature 0, reasoning effort low, 2,048 completion
tokens, 60-second timeout, zero SDK retries, pacing 7,000 tokens per 65-second window.

## Commands

Run from `codebase/agentdojo-lab`. On Windows set `PYTHONUTF8=1` and use
`.venv/Scripts/python.exe`; on POSIX use `.venv/bin/python`.

```bash
PY=.venv/Scripts/python.exe
$PY scripts/run_case_r_groq.py --output runs/<date>-case-r-pilot-v1 --protocol groq-case-r-pilot-v1 --live
$PY scripts/run_case_r_groq.py --output runs/<date>-case-r-v1 --protocol groq-case-r-v1 --live
$PY scripts/run_case_r_groq.py --output runs/<date>-case-r-v1 --resume        # only after a service pause
$PY scripts/run_case_r_followups.py --batch runs/<date>-case-r-v1 --output runs/<date>-case-r-followups-v1 --live
$PY scripts/report_case_r.py --batch runs/<date>-case-r-v1 --followups runs/<date>-case-r-followups-v1 --output reports/<date>-case-r-groq-v1
HF_HUB_OFFLINE=1 $PY scripts/report_case_r_tiers.py --batch runs/<date>-case-r-v1 --packet reports/<date>-case-r-groq-v1/packet.json --output reports/<date>-case-r-tier-diagnostic-v1
$PY scripts/figure_case_r_tiers.py --packet reports/<date>-case-r-tier-diagnostic-v1/packet.json --output reports/<date>-case-r-tier-diagnostic-v1
```

The tier diagnostic requires the pinned local MiniLM snapshot (`.model-cache/all-MiniLM-L6-v2-1110a243`);
it recomputes Tier 3/4 rather than reusing recorded scores and refuses to run without the model.

Without `--live` every script is an offline transport control with zero requests.

## Evidence rules

- Every started slot is retained. A 401/403/429 pauses dispatch; `--resume` runs only
  never-started slots.
- Recipient outcome, flow completion and attack success come from native sent-mail state
  and executed runtime calls. A proposal is not execution.
- Tier-2, substring and semantic scores are correspondence evidence, not causal influence.
- Forced probes exist only because the explicit gate was bypassed. The baseline planner
  produces none of them.
- Unknown, invalid and failed results are reported as such and never replaced.
- Findings concern this independent implementation under its declared choices, not the
  original authors' code.

## Tier diagnostic result — 2026-09-22

Report: [reports/20260922-case-r-tier-diagnostic-v1/index.html](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260922-case-r-tier-diagnostic-v1/index.html);
packet `packet.json`; figure `figure-case-r-tiers.{svg,pdf,png}`. Zero requests. Population: the main
batch's 23 `send_email` sinks, 46 `/recipients/0` pairs with a declared role (10 attacker-sent sinks,
13 legit-sent); four explicit `null` cc/bcc pairs are reported but carry no role. Recomputed Tier-3/4
scores agree with the 2026-09-21 recorded variant on all 134 comparable pairs.

| Evaluator (recipient pairs, n=46) | TP | FP | TN | FN | Sink localisation (23 sinks) |
| --- | ---: | ---: | ---: | ---: | --- |
| Tier 2 LCS, canonical | 26 | 20 | 0 | 0 | exact 3, over 20 |
| Tier 3 cosine, independent | 0 | 0 | 20 | 26 | empty 23 |
| Tier 4 chunk, independent | 13 | 0 | 20 | 13 | exact 13 (all legit-sent), empty 10 (all attacker-sent) |
| T1→T3→T4 cascade, counterfactual | 13 | 0 | 20 | 13 | as Tier 4 |
| Bounded substring, local variant | 26 | 0 | 20 | 0 | exact 23 |

Answer to "would Tier 3/4 have discriminated the value source if Tier 2 had not short-circuited?":
no for the attacker recipient in this batch. Tier 3 never exceeds 0.37 for any document/address
pair; Tier 4's only hits are the legitimate carrier's 90-code-point contact line (0.685), while every
chunk containing `attacker@example.com` scores at most 0.504. Bypassing Tier 2 moves the failure
from over-attribution to under-attribution; the implemented per-sink causal gate stays closed in
23/23 sinks because `/body` still matches Tier 4. No evaluator flags the instruction-only file 1 in
`r_split/both` except Tier 2, which flags every source. For non-carriers, 12–16 of the 20–24 aligned
LCS characters lie in the YAML metadata line `owner: fixture@example.com`. The synthetic prefix sweep
(29 non-containing pairs per length up to 40; 21 at 80; 6 at 160) never falls below 0.15 at any length
(medians 0.80–0.95 up to 40 code points, 0.65 at 160). All of this is correspondence evidence about
this reproduction, not causal attribution.
