# Scout four-candidate identical-input judge/replay confirmation v1

This confirmatory protocol is separate from the queued one-candidate
`scout-identical-judge-replay-followup-v1` experiment. It does not alter or
reinterpret that protocol. It freezes all four structurally eligible
`kind=single_source` probes at `event:00000030` / `get_unread_emails` across the
archived `conditional_action-r01-both` and `conditional_action-r02-both` runs.
The inclusion rule is independent of every archived and prospective judge or
replay outcome.

The frozen inventory is:

- r01 source A: `probe-v2:90e105eff2c03004bc4347f4b39fd055a4290ec061b235832aebf0626f3006d8`
- r01 source B: `probe-v2:40da3b5551cc859c9a5c9b9703df09a397519ff426aa19addd3cec9c5f588481`
- r02 source A: `probe-v2:049799f0ddaea6f9eeb2cce1efc088cd63dbc98387b5536e7dce05517378ee66`
- r02 source B: `probe-v2:640c38156b9bdbdc71a38ed9f66c2ad6a9c278dd0e674cbae7bcf7699ceb4498`

The configuration binds the full archived plan and source-run trees plus each
run's judge and replay support artifact. Those support outcomes are provenance
for the archive and play no role in selecting the four probes.

For each probe, the runner sends three byte-identical sham replays, three
byte-identical neutralized replays, and three byte-identical isolated no-tools
judgments. It attempts at most 36 SDK calls, disables SDK retries, retains every
error and unknown, and never executes a proposed tool call. Both roles use the
same literal-loopback Scout endpoint through explicit `httpx.Client` instances
with environment proxy discovery and redirects disabled.

The report keeps 12 per-probe paired comparisons and a pooled view. A replay
direction is usable only when its paired sham reproduces the exact archived
sink. The strongest systematic label additionally requires all 12 comparisons,
stable within-probe directions, and passing transport, parser, source-exposure,
neutralization, and implementation-integrity checks. Even that result is
construction-scoped evidence from one conditional-action task family; a second
task family may still be needed before claiming a general research gap.

The nearest archived second-family candidate is `content_composition` r01/r02.
Its recovered both-source runs pass request-free input verification, but the v2
no-argument planner correctly reports `explicit_candidate_present` for their
`create_file` sink. Reusing that family therefore requires a separately named,
prospectively frozen argument-level intervention protocol that deterministically
selects the complete matched-source inventory. Creating that plan needs no model
selection calls. Its replay and judgment outcomes would be new prospective calls
and cannot be inferred from this protocol.

Request-free plan preparation uses a fresh directory:

```bash
.venv/bin/python scripts/run_scout_multi_repeat_judge.py \
  --output runs/NEW-scout-multi-repeat-judge-v1
```

Live execution is permitted only inside the strict Slurm wrapper and its
same-allocation authenticated Scout server. The wrapper runs both existing smoke
gates, validates an immutable copied bundle and plan, requires sufficient
scheduler time, caps the live runner at two hours, and preserves partial ledgers
on interruption. It has a 44-request combined ceiling: four synthetic smoke,
up to four native smoke, and 36 protocol calls.
