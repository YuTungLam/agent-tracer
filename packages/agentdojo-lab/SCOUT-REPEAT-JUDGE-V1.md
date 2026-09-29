# Scout identical-input judge/replay follow-up v1

This bounded protocol addresses deliverables 7, 8, and 13 without claiming that
one candidate establishes a method limitation. It preselects the archived
`conditional_action-r01-both` source-A probe because its valid no-tools judgment
predicted that the sink would remain while its archived one-step intervention did
not propose the sink. Those old observations support selection only. The new
protocol changes the evaluated model to local Llama 4 Scout and records that as a
separately named prospective experiment.

The runner freezes three byte-identical requests of each type: sham replay,
neutralized replay, and isolated no-tools judgment. Odd/even repetitions reverse
the two replay controls; the judge remains last. The fixed ceiling is nine SDK
calls. SDK retries are disabled, every slot is attempted at most once, errors and
invalid replies remain unknown, and no returned tool call is executed. A replay
label exists only when its same-repetition sham reproduces the exact recorded sink.

Plan-only preparation is request-free and writes the same JSON/HTML analysis
surface as execution:

```bash
.venv/bin/python scripts/run_scout_repeat_judge.py \
  --output runs/NEW-scout-repeat-judge-v1
```

Live execution requires the local Scout server in the same scheduler allocation
and `LOCAL_LLM_API_KEY` in the environment:

```bash
.venv/bin/python scripts/run_scout_repeat_judge.py \
  --output runs/NEW-scout-repeat-judge-v1 --live
```

The wrapper contract is strict: run from the lab checkout; use a fresh output;
do not alter the configuration, archived plan, support artifacts, source run, or
implementation after sealing; do not resume a partial directory; and do not
replace failed slots. The result includes `plan.json`, `plan.sealed`, the complete
operation plan, every request/result/comparison as JSONL, `summary.json`, an HTML
report, and a final artifact hash manifest. The wrapper does not start a server,
request a scheduler allocation, submit a job, execute a simulated tool, or fall
back to Groq.

The CLI binds its own bytes, the exact config bytes, interpreter, working
directory, and whether the named local key variable was configured; it never
records the key value. It converts `SIGTERM` into a terminal unknown result for a
started request, writes every later slot as unstarted, completes the JSON/HTML
artifacts, and exits with status 143. `SIGKILL` and host loss cannot be finalized
by a process; the incrementally flushed `requests.jsonl` and `results.jsonl`
remain the durable boundary in those cases.
