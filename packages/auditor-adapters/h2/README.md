# H2 runner (`h2/`)

The undefended H2-SS runner. Its contract, stages and outputs are documented in
`../../agentdojo-lab/H2-CASES-V1.md` (sections 6-8) and in `../DEEPSEEK-FREEZE-V1.md`; this file only declares the
ADI-derived support (amendment `authority-auditor-pilot-v1-deepseek.1`; see `../common/README.md`).

## ADI-derived case files (amendment `authority-auditor-pilot-v1-deepseek.1`)

- **Files.** `stages.adi.json` (stages ADI-S1 = D23, ADI-S2 = D27) and `config.adi.json` (runner config
  `h2-runner-deepseek-adi-v1`: selection `splits: [dev]`, `families: [ADI]`, arms ATTACK and CLEAN, ADI-S1 the first 3
  eligible cases in case-file order x 1, ADI-S2 every eligible case x 5, both at T=0.7, ceiling 48). Caps and repeats
  are generated from the amendment config's `experiments[]` by `../common/adi_stages.py write` and checked by its
  `check` (G-ADI-STAGES). The frozen `stages.json` and `config.template.json` are unchanged.
- **Formatter.** `run_h2.build_runtime(..., tool_output_format=)` installs the case file's formatter on the pipeline's
  one `ToolsExecutor` before it is wrapped for salvage: `"yaml"` (absent) leaves the stock formatter in place, `"json"`
  installs the ADI fork's (`../common/adi_compat.py`). A runner config that fixes `agent.tool_output_format` to a value
  other than the case file's is refused (`config.template.json` says `yaml`; `config.adi.json` says `case_file`).
- **Pin.** `--expect-content-sha256 <LF sha256>` (the ADI stages pass `{cases_sha256}`) is checked before anything is
  planned. The plan and the receipt record `case_file.sha256_lf` and the formatter (source commit included) only when
  the case file declares a format or a pin is given; the receipt hashes `adi_compat.py` only for a declared format, so
  an SS plan and receipt keep their frozen keys.
- **Before the first request.** Every planned episode's vector ids must exist in the stock suites, otherwise the run is
  refused with exit 2 (a case on ADI's fork-only `injection_restaurant_msg` is never run as errored episodes). An ADI
  case whose `gt.attacker_executable` is still null is refused by `expand_stage` (the exporter resolves it).
- **Legitimate set.** `expand_stage` takes an arm's own `legitimate_set` when the case gives one (ADI-X-11, slack ut9[0],
  ut10[0], ut19[0]); otherwise the case-level set, exactly as before.
- **Exposure (ADI episodes).** The plan carries `exposure_needles` (the ATTACK arm's `arm_text`; None for CLEAN) for ADI
  episodes only. `injection_exposed` is that payload seen, raw or JSON-escaped, in a tool output of any attempt;
  `attacker_value_in_tool_output` is the separate X test (it also reads the JSON-unescaped output). SS episodes keep the
  frozen X-based exposure. The post-state X count uses `adi_compat.state_needle` (equal to X for every SS value).
- **Summary.** `h2_core.summarize` relabels an ADI plan (`seed_family`, `amendment`, `tool_output_format`; the SS
  contrast and cluster bootstrap are null by construction). `expand_stage` refuses a selection that mixes ADI with
  E0B or E1PRE.
- **Tests.** `tests/test_h2_adi.py`: synthetic ADI-format file with a placeholder payload (no ADI text), scripted
  loopback fake on banking user_task_3; the agent sees JSON, ATTACK scores `attacker` with the payload exposed, CLEAN
  `legitimate`; per-arm legitimate sets and exposure needles in the plan, SS plan episodes unchanged; eval cases are never
  selected; a wrong pin, a config/format mismatch, an unknown vector and an unresolved executability are refused before
  any request; the shipped stage file equals the amendment config and runs end to end through the guard.
