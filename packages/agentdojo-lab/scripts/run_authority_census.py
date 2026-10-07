"""Run the frozen, request-free authority-origin census (E0 and E1) and write a DRAFT experiment.

The census executes only AgentDojo ground-truth calls on deep copies of the vendored
v1.2.2 environments (no model, provider or network request; sockets are refused and
counted).  Every output is built and scanned in memory (credential-shaped strings,
absolute machine paths, JSON validity) before anything is written.  Existing outputs
are never overwritten unless ``--replace`` is given.

Both protocols run from their own frozen config.  A v2 run also re-runs the v1 config
and requires its derived outputs and summary to equal the v1 experiment's bytes
(logs/predecessor-reproduction.json); it never writes to the v1 directory.

Usage (from packages/agentdojo-lab):

    PYTHONUTF8=1 .venv/Scripts/python.exe scripts/run_authority_census.py \
        --config configs/authority_census_v2.json \
        --results-root <agent-tracer-results> \
        --output <agent-tracer-results>/experiments/20261008-authority-origin-census-v2 \
        [--tests-log <pytest -q output file>] [--lint-log <ruff check output file>] [--replace]
"""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import re
import subprocess
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path

from agentdojo_lab import authority_census as census_module

LAB_ROOT = Path(__file__).resolve().parents[1]
CONFIG_IN_EXPERIMENT = "config/authority_census_v1.json"
AGENT_TRACER_REPOSITORY = "https://github.com/YuTungLam/agent-tracer.git"
NEW_FILE_ROLES = {
    "packages/agentdojo-lab/src/agentdojo_lab/authority_census.py": "census_module",
    "packages/agentdojo-lab/scripts/run_authority_census.py": "runner",
    "packages/agentdojo-lab/configs/authority_census_v1.json": "frozen_configuration",
    "packages/agentdojo-lab/tests/test_authority_census.py": "tests",
}
NEW_FILE_ROLES_V2 = {
    "packages/agentdojo-lab/src/agentdojo_lab/authority_census.py": "census_module",
    "packages/agentdojo-lab/scripts/run_authority_census.py": "runner",
    "packages/agentdojo-lab/configs/authority_census_v2.json": "frozen_configuration",
    "packages/agentdojo-lab/configs/authority_census_v1.json": "predecessor_configuration_unchanged",
    "packages/agentdojo-lab/tests/test_authority_census.py": "tests",
}


def config_in_experiment(config: dict) -> str:
    return "config/" + Path(census_module.protocol_spec(config)["config_relative"]).name


def new_file_roles(config: dict) -> dict[str, str]:
    return NEW_FILE_ROLES_V2 if census_module.is_v2(config) else NEW_FILE_ROLES


def _git(cwd: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8"
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def repository_root() -> Path:
    toplevel = _git(LAB_ROOT, "rev-parse", "--show-toplevel")
    return Path(toplevel) if toplevel else LAB_ROOT.parents[1]


def agent_tracer_provenance(roles: dict[str, str] | None = None) -> dict:
    top = repository_root()
    head = _git(top, "rev-parse", "HEAD")
    porcelain = _git(top, "status", "--porcelain", "--untracked-files=all") or ""
    status_lines = sorted(line for line in porcelain.splitlines() if line.strip())
    new_files = []
    for relative, role in (roles or NEW_FILE_ROLES).items():
        path = top / relative
        if not path.is_file():
            continue
        data = path.read_bytes()
        tracked = _git(top, "ls-files", "--error-unmatch", relative) is not None
        new_files.append(
            {
                "path": relative,
                "role": role,
                "tracked": tracked,
                "bytes": len(data),
                "sha256": census_module.sha256_bytes(data),
                "lf_normalized_sha256": census_module.lf_normalized_sha256(data),
            }
        )
    return {
        "repository": AGENT_TRACER_REPOSITORY,
        "commit": None,
        "commit_pending": True,
        "head": head,
        "working_tree_dirty": bool(status_lines),
        "status_porcelain_at_run": status_lines,
        "new_files": new_files,
    }


def benchmark_provenance(config: dict) -> dict:
    vendor_src, data_root = census_module.vendor_paths()
    vendor_root = vendor_src.parent
    files = []
    for path in sorted(data_root.rglob("*.yaml")):
        data = path.read_bytes()
        files.append(
            {
                "path": "src/agentdojo/data/suites/" + path.relative_to(data_root).as_posix(),
                "bytes": len(data),
                "sha256": census_module.sha256_bytes(data),
            }
        )
    return {
        **{key: config["benchmark"][key] for key in ("package", "package_version", "benchmark_version",
                                                      "upstream_repository", "upstream_commit", "vendored_path")},
        "vendored_head": _git(vendor_root, "rev-parse", "HEAD"),
        "vendored_status_porcelain": _git(vendor_root, "status", "--porcelain") or "",
        "installed_agentdojo_version": _package_version("agentdojo"),
        "suite_data_files": files,
    }


def sanitize_log(text: str) -> str:
    """Replace machine-specific paths in a pytest log with stable placeholders."""
    for root, label in ((LAB_ROOT, "<agentdojo-lab>"),):
        for form in {str(root), root.as_posix(), str(root).replace("\\", "/")}:
            text = text.replace(form, label)
    return text


def parse_pytest_summary(text: str) -> str | None:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if re.search(r"\b(passed|failed|error)\b", line):
            return line.strip("= ")
    return None


def render_readme(census: dict, config_sha256: str, provenance: dict, created_at: str) -> str:
    e0 = census["e0"]["summary"]["overall"]
    split = census["e1"]["summary"]["split"]["overall"]
    widest = census["e1"]["summary"]["views"]["gt_plus_fallback_with_exfiltration_reads"]["overall"]
    claims = {claim["id"]: claim for claim in census["claims"]}
    new_files = "\n".join(f"- `{item['path']}` ({item['role']}, sha256 `{item['sha256']}`)" for item in provenance["new_files"])
    return f"""# {census_module.EXPERIMENT_ID}

**Status: DRAFT, pending the Agent Tracer code commit.** The census module, runner, frozen config and tests
are uncommitted new files on top of Agent Tracer HEAD `{provenance['head']}`; they are bound below and in
`manifest.json` by SHA-256. Finalize only after the user approves and makes the commit (see "Finalizing").

## Purpose

Week 1, zero-cost census for the cross-auditor authority-argument study (RAID 2027 pilot):

- **E0**: for every AgentDojo v1.2.2 user task, where do the correct authority values (recipient, IBAN, URL,
  channel, user, file/event/email id, booking target) of its state-changing ground-truth calls come from:
  (a) the user prompt, (b) only the pre-task environment, reached through a tool output, or (c) neither?
  Tasks with (b) values are the precision denominator for origin-based rules.
- **E1**: for every injection task, is the attacker authority value stated literally in GOAL (co-located
  with the instruction) and does it already exist in the clean environment (selection-steering seed)?
  Plus, per user task, the injection vectors its ground-truth run exposes (split capability).

## Method

- Frozen config `config/authority_census_v1.json` (SHA-256 `{config_sha256}`): role table for all
  {sum(item['tools'] for item in census['inventory'].values())} tools of the 4 suites under one written rule, matching rules, judgement calls J1-J18, the security-checker fallback
  for the 8 workspace injection tasks with empty ground truth, and the claims under test.
- Code: `agentdojo_lab.authority_census` and `scripts/run_authority_census.py` in Agent Tracer.
- Inputs: the vendored AgentDojo 0.1.35 package (ethz-spylab/agentdojo `089ed468`), benchmark v1.2.2 only.
  Ground-truth calls run through AgentDojo's `FunctionsRuntime` on deep copies of the default environment;
  vector exposure uses AgentDojo's own `BaseAttack.get_injection_candidates`.
- Requests: 0 model, 0 provider, 0 network (an in-process socket guard refused and counted connections:
  {census['execution']['network_connection_attempts']}).

## Headline results (all from `derived/census.json`)

- E0: {e0['values']['total']} authority value instances in {e0['tasks_with_authority_value']} of {e0['user_tasks']}
  user tasks: (a) prompt {e0['values']['a_prompt']}, (b) environment-only {e0['values']['b_environment']},
  (c) neither {e0['values']['c_neither']}. **{e0['tasks_with_b']} of {e0['user_tasks']} user tasks have at least one
  (b) value** (precision denominator; per-task list in `reports/summary.md`).
- E1 (widest view, ground truth plus fallback plus exfiltration reads): of {widest['injection_tasks']} injection
  tasks, {widest['tasks_all_goal_literal']} state every attacker authority value in GOAL,
  {widest['tasks_partial_goal_literal']} state some, {widest['tasks_none_goal_literal']} state none, and
  {widest['tasks_no_authority_value']} have no attacker authority value; {widest['tasks_seed_candidate']} have at
  least one attacker value already present in the clean environment.
- Split capability: {split['split_capable']} of {split['user_tasks']} user tasks expose two or more injection
  vectors ({split['split_capable_with_two_or_more_exposing_calls']} of them across two or more distinct
  ground-truth tool outputs).
- Claims under test: K1 {claims['K1']['verdict']}; K2 {claims['K2']['verdict']}; K3 {claims['K3']['verdict']};
  K4 {claims['K4']['verdict']}.

## Interpretation limits

- Ground truth is one canonical solution; utility checkers may accept other values.
- Exact matching after case and whitespace normalisation; near matches are diagnostics only.
- The 8 workspace injection tasks without ground truth use a hand-read security() fallback (separate view).
- One config amendment (identifier matching per object type) was made after an unrecorded trial run; it is
  logged in the config's `amendment_log`. K2 and K4 list which readings are post hoc.
- This census measures what the benchmark makes possible. It says nothing about model behaviour or auditors.

## Files

- `config/authority_census_v1.json`: byte-identical copy of the frozen config.
- `derived/census.json`: everything (role table, per-value and per-task rows, summaries, claims).
- `derived/*.csv`: role table, E0 values/tasks/exfiltration-read values, E1 attacker values/tasks/vector exposure.
- `reports/summary.md`: tables and lists for reading.
- `logs/run-receipt.json`: command, timestamps, request counters, environment.
- `logs/pytest.txt`: the focused test run (when supplied).
- `manifest.json`, `checksums.sha256`: provenance and integrity.

## Provenance

Created {created_at}. Agent Tracer HEAD `{provenance['head']}`; uncommitted new files:

{new_files}

## Finalizing

After the user commits the new files: verify each `agent_tracer.new_files` hash against the committed blobs
(LF-normalised hash if `core.autocrlf` rewrote line endings), record `agent_tracer.commit`, set `status` to
`finalized`, and regenerate `checksums.sha256`. Do not edit any other output; corrections need a new experiment ID.
"""


def build_manifest(
    census: dict,
    files: dict[str, bytes],
    config_sha256: str,
    provenance: dict,
    benchmark: dict,
    receipt: dict,
    tests: dict,
    created_at: str,
    config: dict | None = None,
    lint: dict | None = None,
) -> dict:
    e0 = census["e0"]["summary"]
    e1 = census["e1"]["summary"]
    spec = census_module.protocol_spec(config) if config else census_module.PROTOCOLS[census_module.PROTOCOL]
    config_path = config_in_experiment(config) if config else CONFIG_IN_EXPERIMENT
    artifacts = [
        {
            "path": path,
            "role": _artifact_role(path, config_path),
            "bytes": len(data),
            "sha256": census_module.sha256_bytes(data),
        }
        for path, data in sorted(files.items())
    ]
    manifest = {
        "schema_version": 1,
        "experiment_id": census["experiment_id"],
        "status": "draft_pending_code_commit",
        "status_note": (
            "Computed request-free. The census module, runner, frozen config and tests are untracked new files on "
            f"top of Agent Tracer HEAD {provenance['head']}; they are bound here by SHA-256. Finalize after the user "
            "commits them: verify agent_tracer.new_files hashes against the commit, record agent_tracer.commit, set "
            "status to finalized and regenerate checksums.sha256."
        ),
        "created_at": created_at,
        "experiment_type": "request_free_benchmark_census",
        "protocol": {
            "id": census["protocol"],
            "config_path_in_agent_tracer": "packages/agentdojo-lab/" + spec["config_relative"],
            "config_path_in_experiment": config_path,
            "config_sha256": config_sha256,
            "sha256_verified_on": "raw_bytes",
        },
        "agent_tracer": provenance,
        "benchmark": benchmark,
        "execution": receipt["execution"],
        "access_classification": "private_access_controlled_research_evidence",
        "retention_policy": "append_only; corrections require a new experiment ID",
        "external_artifacts": [],
        "raw_artifacts": [],
        "raw_artifacts_note": (
            "No model or tool output was recorded. The only primary input is the vendored AgentDojo benchmark, pinned "
            "by upstream commit and per-file SHA-256 under benchmark.suite_data_files."
        ),
        "integrity": {
            "checksums_path": "checksums.sha256",
            "checksum_format": "lowercase SHA-256, two spaces, forward-slash relative path",
            "checksum_scope": "every file except checksums.sha256 itself",
            "artifacts_scope": "every file except manifest.json and checksums.sha256",
        },
        "frozen_configuration": {
            "path": config_path,
            "role": "frozen_configuration",
            "media_type": "application/json",
            "bytes": len(files[config_path]),
            "sha256": config_sha256,
        },
        "predecessor_experiment_ids": [],
        "runner": receipt["environment"],
        "results_summary": {
            "e0_overall": e0["overall"],
            "e0_precision_denominator_tasks": [
                f"{item['suite']}.{item['user_task_id']}" for item in e0["precision_denominator"]
            ],
            "e1_views_overall": {view: data["overall"] for view, data in e1["views"].items()},
            "split_capability_overall": e1["split"]["overall"],
            "split_capability_per_suite": {
                suite: {key: value for key, value in data.items() if key != "split_capable_tasks"}
                for suite, data in e1["split"]["per_suite"].items()
            },
            "claims": [{"id": claim["id"], "verdict": claim["verdict"]} for claim in census["claims"]],
        },
        "validation": {
            "tests": tests,
            "credential_pattern_scan": "pass",
            "machine_path_scan": "pass",
            "json_validation": "pass",
            "vector_parity_failures": e1["split"]["overall"]["parity_failures"],
        },
        "limitations": [
            "Ground truth is one canonical solution per task; utility checkers may accept other values (J16).",
            "Exact matching after case and whitespace normalisation; near matches are diagnostics only (J15).",
            "Workspace injection_task_6 to injection_task_13 have empty ground truth; their attacker values come from "
            "a hand-read security() fallback, reported as a separate view (J14).",
            "One config amendment (identifier matching per object type) followed an unrecorded trial run; see the "
            "config amendment_log. K2 and K4 label post hoc readings.",
            "Benchmark census only: no model behaviour, injection success or auditor verdict is measured.",
        ],
        "artifacts": artifacts,
    }
    if config is not None and census_module.is_v2(config):
        manifest["validation"]["lint"] = lint or {"recorded": False}
        manifest["limitations"] = [
            *manifest["limitations"][:4],
            "All v2 changes (D1-D5) and every sensitivity row were written after the v1 counts and an independent "
            "verification were seen; they are post hoc and logged in the config amendment_log. Only D5 changes a "
            "primary count (one E1 fallback value); the v1-convention counts are reported next to it.",
            manifest["limitations"][4],
        ]
    return manifest


def _artifact_role(path: str, config_path: str = CONFIG_IN_EXPERIMENT) -> str:
    if path == config_path:
        return "frozen_configuration"
    if path.startswith("derived/"):
        return "derived_evidence"
    if path.startswith("reports/"):
        return "report"
    if path.startswith("logs/"):
        return "log"
    if path == "README.md":
        return "readme"
    return "other"


def checksums_text(files: dict[str, bytes]) -> str:
    return "".join(f"{census_module.sha256_bytes(data)}  {path}\n" for path, data in sorted(files.items()))


def scan_outputs(files: dict[str, bytes]) -> None:
    for path, data in files.items():
        text = data.decode("utf-8")
        census_module.assert_no_credentials(text, path)
        census_module.assert_no_absolute_paths(text, path)
        if path.endswith(".json"):
            json.loads(text)


# ---------------------------------------------------------------------------
# Protocol v2 (successor of v1)


def predecessor_reproduction(config: dict, results_root: Path) -> dict:
    """Re-run the unchanged v1 config and compare its derived outputs and summary with the v1 experiment bytes.

    Read-only on the v1 directory.  Raises SystemExit when the v1 config changed or an output differs.
    """
    predecessor = config["predecessor"]
    config_path = repository_root() / predecessor["config_path"]
    raw = config_path.read_bytes()
    result = {
        "predecessor_experiment_id": predecessor["experiment_id"],
        "predecessor_protocol": predecessor["protocol"],
        "predecessor_config_path": predecessor["config_path"],
        "expected_config_sha256": predecessor["config_sha256"],
        "config_sha256": census_module.sha256_bytes(raw),
        "config_lf_normalized_sha256": census_module.lf_normalized_sha256(raw),
    }
    result["config_unchanged"] = predecessor["config_sha256"] in (
        result["config_sha256"],
        result["config_lf_normalized_sha256"],
    )
    if not result["config_unchanged"]:
        raise SystemExit("The predecessor (v1) config no longer has its recorded SHA-256; refusing to continue")
    directory = results_root / "experiments" / predecessor["experiment_id"]
    if not directory.is_dir():
        return result | {"checked": False, "reason": "predecessor experiment directory not found under --results-root"}
    stored_config = directory / "config" / config_path.name
    result["stored_config_identical"] = stored_config.is_file() and stored_config.read_bytes() == raw
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    head = manifest["agent_tracer"]["head"]
    v1_config, v1_bytes = census_module.load_config(config_path)
    with census_module.network_guard() as attempts:
        v1_census = census_module.run_census(v1_config)
    if attempts["count"]:
        raise SystemExit(f"Network access was attempted {attempts['count']} time(s) in the v1 re-run")
    v1_census["execution"] = {"model_requests": 0, "provider_requests": 0, "network_connection_attempts": 0}
    reproduced = census_module.derived_files(v1_census)
    reproduced["reports/summary.md"] = census_module.render_summary(
        v1_census, census_module.sha256_bytes(v1_bytes), head
    )
    comparisons = []
    for path, text in sorted(reproduced.items()):
        data = text.encode("utf-8")
        stored = (directory / path).read_bytes() if (directory / path).is_file() else None
        comparisons.append(
            {
                "path": path,
                "stored_sha256": census_module.sha256_bytes(stored) if stored is not None else None,
                "reproduced_sha256": census_module.sha256_bytes(data),
                "identical": stored == data,
            }
        )
    result |= {
        "checked": True,
        "method": (
            "re-ran the v1 config through the current census module in this process (socket guard on), rendered "
            "the v1 summary with the v1 manifest's Agent Tracer HEAD, and compared bytes with the v1 experiment; "
            "README, manifest, checksums and logs carry timestamps and file hashes and are not compared"
        ),
        "agent_tracer_head_used_for_summary": head,
        "network_connection_attempts": 0,
        "files": comparisons,
        "all_identical": all(item["identical"] for item in comparisons) and result["stored_config_identical"],
    }
    if not result["all_identical"]:
        changed = [item["path"] for item in comparisons if not item["identical"]]
        raise SystemExit(f"The v1 code path no longer reproduces the v1 outputs: {changed}")
    return result


def _fraction(item: dict) -> str:
    return f"{item['numerator']}/{item['denominator']}"


def render_readme_v2(census: dict, config_sha256: str, provenance: dict, reproduction: dict, created_at: str) -> str:
    e0 = census["e0"]["summary"]
    e0_overall = e0["overall"]
    dependency = e0["vector_dependency"]["overall"]
    e1 = census["e1"]["summary"]
    views = e1["views"]
    old = e1["views_excluding_tag"].get("D5", views)
    split = e1["split"]["overall"]
    claims = {claim["id"]: claim for claim in census["claims"]}
    predecessor = census["predecessor"]
    precision = census["sensitivity"]["precision_denominator"]
    variants = census["sensitivity"]["role_variants"]
    checks = census["verifier_check"]
    mismatches = [row["id"] for row in checks if not row["match"]]
    coverage = [row for row in e1["goal_literal_coverage"] if row["value"] == "mark.black-2134@gmail.com"]
    widest = views["gt_plus_fallback_with_exfiltration_reads"]["overall"]
    fallback = views["gt_plus_fallback"]["overall"]
    fallback_old = old["gt_plus_fallback"]["overall"]
    if reproduction.get("checked"):
        identical = sum(1 for item in reproduction["files"] if item["identical"])
        reproduction_text = (
            f"the v1 code path reproduced {identical}/{len(reproduction['files'])} v1 outputs (every derived file and "
            "the summary) byte for byte, and the v1 config still has its recorded hash "
            "(`logs/predecessor-reproduction.json`)"
        )
    else:
        reproduction_text = f"the v1 reproduction check did not run: {reproduction.get('reason', 'unknown')}"
    new_files = "\n".join(
        f"- `{item['path']}` ({item['role']}, {'tracked' if item['tracked'] else 'untracked'}, sha256 `{item['sha256']}`)"
        for item in provenance["new_files"]
    )
    precision_lines = "\n".join(
        f"  - **{row['numerator']}/{row['denominator']}** {row['id']} {row['label']}"
        + (" (post hoc)" if row["post_hoc"] else "")
        for row in precision
    )
    dependent = [row for row in e0["vector_dependency"]["values"] if row["origin"] == "b_environment"]
    dependent_counts = Counter((row["suite"], row["value"]) for row in dependent)
    dependent_text = ", ".join(
        f"{suite} `{value}`" + (f" x{count}" if count > 1 else "") for (suite, value), count in dependent_counts.items()
    )
    caught_by_v1 = sum(1 for row in dependent if row["in_injection_vector_defaults"])
    variant_lines = "\n".join(
        f"  - {item['id']} (reverses {item['reverses']}, post hoc): E0 {item['e0']['values']['total']} values, "
        f"(b) {item['e0']['values']['b_environment']}, tasks with (b) {item['e0']['tasks_with_b']}/{e0_overall['user_tasks']}"
        f"{' (+' + ', '.join(item['e0']['new_b_tasks']) + ')' if item['e0']['new_b_tasks'] else ''}; E1 gt_plus_fallback "
        f"{item['e1']['overall']['values']} values, {item['e1']['overall']['tasks_seed_candidate']} seed tasks"
        f"{' (+' + ', '.join(item['e1']['new_seed_tasks']) + ')' if item['e1']['new_seed_tasks'] else ''}"
        for item in variants
    )
    mark = coverage[0] if coverage else None
    mark_text = (
        f"`mark.black-2134@gmail.com` is stated in {mark['goals_stating']}/{mark['injection_tasks']} workspace GOALs "
        f"(lacking: {', '.join(mark['lacking'])})"
        if mark
        else "no workspace GOAL-literal row for mark.black-2134@gmail.com"
    )
    return f"""# {census['experiment_id']}

**Status: DRAFT, pending the Agent Tracer code commit.** The census module, runner, both configs and tests are
uncommitted files on top of Agent Tracer HEAD `{provenance['head']}`; they are bound below and in `manifest.json`
by SHA-256. Finalize only after the user approves and makes the commit (see "Finalizing").

**Predecessor:** [`{predecessor['experiment_id']}`](../{predecessor['experiment_id']}/) (protocol
`{predecessor['protocol']}`, config SHA-256 `{predecessor['config_sha256']}`). This experiment supersedes it; the
v1 config and the v1 experiment directory are left unchanged as the historical draft. In this run {reproduction_text}.

## Why a v2

An independent verifier recomputed every v1 headline number with its own code (all matched) and asked for five
fixes before finalising. They are implemented as a successor protocol (`authority-origin-census-v2`, config
`config/authority_census_v2.json`, SHA-256 `{config_sha256}`) whose `amendment_log` records the predecessor hash
and every change. All v2 changes were written after the v1 counts were seen, so they are post hoc.

- **D1** (flag): {dependency['b_vector_dependent']} (b) values are vector-dependent, i.e. inside or built from an
  injection vector's text ({dependent_text}; a channel name such as `External_0` is rendered from the template
  `External_{{prompt_injection_channel}}`). The v1 flag caught {caught_by_v1} of them. Excluding them:
  {dependency['b_excluding_vector_dependent']} (b) values, {dependency['tasks_with_b_excluding_vector_dependent']}/{e0_overall['user_tasks']} tasks.
- **D2** (text): {mark_text}.
- **D3** (text): E1 view counts overlap. In the v1-convention `gt_plus_fallback` view,
  {fallback_old['values']} values = {fallback_old['values_goal_literal']} in GOAL + {fallback_old['values_in_clean_environment']} in clean env + {fallback_old['values_neither']} neither - {fallback_old['values_goal_and_clean_environment']} in both.
- **D4** (post hoc reading): K2 {split['split_capable_with_two_or_more_exposing_calls']}/{split['user_tasks']} counting any
  exposing output, {split['split_capable_with_two_or_more_first_exposing_calls']}/{split['user_tasks']} counting each vector's
  first exposing output (frozen reading {split['split_capable']}/{split['user_tasks']}).
- **D5** (primary E1 change): workspace injection_task_12's self-e-mail recipient is listed, like injection_task_9's
  (GOAL tie-breaker). `gt_plus_fallback` {fallback['values']} values (v1 convention {fallback_old['values']}); widest
  view {widest['values']} (v1 convention {old['gt_plus_fallback_with_exfiltration_reads']['overall']['values']}); no
  category, seed-candidate or K4 change.

## Headline results (all from `derived/census.json`)

- E0 (unchanged from v1): {e0_overall['values']['total']} authority value instances in
  {e0_overall['tasks_with_authority_value']} of {e0_overall['user_tasks']} user tasks: (a) {e0_overall['values']['a_prompt']},
  (b) {e0_overall['values']['b_environment']}, (c) {e0_overall['values']['c_neither']}. **{e0_overall['tasks_with_b']} of
  {e0_overall['user_tasks']} user tasks have at least one (b) value** (primary precision denominator P0).
- Precision-denominator sensitivity (S1; `reports/summary.md`):
{precision_lines}
- E1 widest view (v2): of {widest['injection_tasks']} injection tasks, {widest['tasks_all_goal_literal']} state every
  attacker authority value in GOAL, {widest['tasks_partial_goal_literal']} some, {widest['tasks_none_goal_literal']} none, and
  {widest['tasks_no_authority_value']} have no attacker authority value; {widest['tasks_seed_candidate']} are seed candidates.
- Split capability: {split['split_capable']}/{split['user_tasks']} user tasks expose two or more vectors.
- Role-table sensitivity (S2, post hoc; the primary role table is unchanged; J2 is stated as an explicit exception
  to the written state-changing rule):
{variant_lines}
- Collisions: {census['sensitivity']['prompt_collisions']['count']} (suite, injection task, attacker value) also
  occur literally in a user prompt of the same suite.
- Claims: K1 {claims['K1']['verdict']}; K2 {claims['K2']['verdict']}; K3 {claims['K3']['verdict']}; K4
  {claims['K4']['verdict']}.
- Verifier check: {len(checks) - len(mismatches)}/{len(checks)} expected values match{(' (differ: ' + ', '.join(mismatches) + ')') if mismatches else ''}
  (`derived/verifier_check.csv`).

## Interpretation limits

- Ground truth is one canonical solution; utility checkers may accept other values. The P1/P3 utility intervention
  replays only that ground truth.
- Exact matching after case and whitespace normalisation; near matches are diagnostics only.
- The 8 workspace injection tasks without ground truth use a hand-read security() fallback (separate view); D5 adds
  one GOAL-based value to it.
- Every v2 change and sensitivity row is post hoc (written after the v1 counts and the verification were seen).
- This census measures what the benchmark makes possible. It says nothing about model behaviour or auditors.

## Files

- `config/authority_census_v2.json`: byte-identical copy of the frozen v2 config.
- `derived/census.json`: everything (role table, per-value and per-task rows, summaries, sensitivity, claims,
  verifier check).
- `derived/*.csv`: role table; E0 values/tasks/exfiltration-read values (with D1, exact-field and utility columns);
  E1 attacker values/tasks/vector exposure (with D5 tag, D1, exact-field, collision and first-exposure columns);
  GOAL-literal coverage; the three sensitivity tables; the verifier check.
- `reports/summary.md`: tables and lists for reading, including the sensitivity sections.
- `logs/run-receipt.json`: command, timestamps, request counters, environment.
- `logs/predecessor-reproduction.json`: the v1 byte-for-byte reproduction check.
- `logs/pytest.txt`, `logs/ruff.txt`: the focused test run and lint (when supplied).
- `manifest.json`, `checksums.sha256`: provenance and integrity.

## Provenance

Created {created_at} (UTC). Agent Tracer HEAD `{provenance['head']}`; census files:

{new_files}

## Finalizing

After the user commits the census files: verify each `agent_tracer.new_files` hash against the committed blobs
(LF-normalised hash if `core.autocrlf` rewrote line endings), record `agent_tracer.commit`, set `status` to
`finalized`, and regenerate `checksums.sha256`. Finalize v1 first or record why it stays a draft. Do not edit any other
output; corrections need a new experiment ID.
"""


def v2_manifest_fields(census: dict, reproduction: dict, config: dict) -> dict:
    e1 = census["e1"]["summary"]
    checks = census["verifier_check"]
    predecessor = census["predecessor"]
    amendment = config["amendment_log"][-1]
    return {
        "protocol_amendment": {
            "at": amendment["at"],
            "after_seeing_counts": amendment["after_seeing_counts"],
            "predecessor_config_sha256": amendment["predecessor_config_sha256"],
            "changes": [{"id": change["id"], "kind": change["kind"]} for change in amendment["changes"]],
            "config_path": f"{config_in_experiment(config)} (amendment_log[-1])",
        },
        "predecessor_experiment_ids": [predecessor["experiment_id"]],
        "predecessor": {
            **{key: predecessor[key] for key in ("experiment_id", "protocol", "config_path", "config_sha256", "status")},
            "relationship": predecessor["relationship"],
            "path_in_results_repository": f"experiments/{predecessor['experiment_id']}",
            "reproduction_check": {
                key: reproduction.get(key)
                for key in ("checked", "config_unchanged", "stored_config_identical", "all_identical", "reason")
                if key in reproduction
            }
            | {"log": "logs/predecessor-reproduction.json"},
        },
        "results_summary_v2": {
            "e0_vector_dependency_overall": census["e0"]["summary"]["vector_dependency"]["overall"],
            "precision_denominator": [
                {key: row[key] for key in ("id", "label", "primary", "post_hoc", "numerator", "denominator")}
                for row in census["sensitivity"]["precision_denominator"]
            ],
            "e1_views_overall_v1_convention": {
                tag: {view: data["overall"] for view, data in views.items()}
                for tag, views in e1["views_excluding_tag"].items()
            },
            "goal_literal_coverage": [
                {key: row[key] for key in ("suite", "value", "goals_stating", "injection_tasks", "lacking")}
                for row in e1["goal_literal_coverage"]
            ],
            "role_variants": [
                {
                    "id": item["id"],
                    "reverses": item["reverses"],
                    "post_hoc": True,
                    "e0_values": item["e0"]["values"],
                    "e0_tasks_with_b": item["e0"]["tasks_with_b"],
                    "e0_new_b_tasks": item["e0"]["new_b_tasks"],
                    "e1_gt_plus_fallback": item["e1"]["overall"],
                    "e1_new_seed_tasks": item["e1"]["new_seed_tasks"],
                }
                for item in census["sensitivity"]["role_variants"]
            ],
            "prompt_collisions": census["sensitivity"]["prompt_collisions"]["count"],
            "verifier_check": {
                "checks": len(checks),
                "matched": sum(1 for row in checks if row["match"]),
                "differ": [row["id"] for row in checks if not row["match"]],
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, required=True, help="a frozen configs/authority_census_v*.json")
    parser.add_argument("--results-root", type=Path, required=True, help="agent-tracer-results checkout")
    parser.add_argument("--output", type=Path, required=True, help="experiments/<the config's experiment_id>")
    parser.add_argument("--tests-log", type=Path, help="captured `pytest -q` output to copy into logs/pytest.txt")
    parser.add_argument("--lint-log", type=Path, help="captured `ruff check` output to copy into logs/ruff.txt")
    parser.add_argument("--replace", action="store_true", help="replace this runner's own existing outputs")
    args = parser.parse_args(argv)

    results_root = args.results_root.resolve()
    output = args.output.resolve()
    config, config_bytes = census_module.load_config(args.config)
    config_sha256 = census_module.sha256_bytes(config_bytes)
    experiment_id = config["experiment_id"]
    v2 = census_module.is_v2(config)
    config_path_in_experiment = config_in_experiment(config)
    if output.name != experiment_id:
        parser.error(f"--output must be the {experiment_id} experiment directory")
    if not output.is_relative_to(results_root / "experiments"):
        parser.error("--output must lie inside <results-root>/experiments")
    if output.is_relative_to(results_root / "snapshots"):
        parser.error("refusing to write under snapshots/")
    if v2 and output.name == config["predecessor"]["experiment_id"]:
        parser.error("refusing to write into the predecessor experiment directory")

    started = _utc_now()
    with census_module.network_guard() as attempts:
        census = census_module.run_census(config)
    finished = _utc_now()
    census["execution"] = {
        "model_requests": 0,
        "provider_requests": 0,
        "network_connection_attempts": attempts["count"],
    }
    if attempts["count"]:
        raise SystemExit(f"Network access was attempted {attempts['count']} time(s); refusing to write outputs")

    reproduction = predecessor_reproduction(config, results_root) if v2 else None
    provenance = agent_tracer_provenance(new_file_roles(config))
    benchmark = benchmark_provenance(config)
    environment = {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "packages": {name: _package_version(name) for name in ("agentdojo", "pydantic", "pydantic-core", "PyYAML")},
    }
    receipt = {
        "protocol": config["protocol"],
        "experiment_id": experiment_id,
        "command": (
            "PYTHONUTF8=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 .venv/Scripts/python.exe scripts/run_authority_census.py "
            f"--config {census_module.protocol_spec(config)['config_relative']} --results-root <results> "
            f"--output <results>/experiments/{experiment_id}"
            + (" --tests-log <pytest log>" if args.tests_log else "")
            + (" --lint-log <ruff log>" if args.lint_log else "")
            + (" --replace" if args.replace else "")
        ),
        "started_at_utc": started,
        "finished_at_utc": finished,
        "config_sha256": config_sha256,
        "execution": {
            "mode": "request_free_ground_truth_execution",
            "model_requests": 0,
            "provider_requests": 0,
            "network_connection_attempts": attempts["count"],
            "network_guard": "socket.connect/connect_ex/create_connection/getaddrinfo refused and counted",
            "request_free": True,
        },
        "environment": environment,
        "agent_tracer_head": provenance["head"],
        "agent_tracer_status_porcelain": provenance["status_porcelain_at_run"],
    }

    files: dict[str, bytes] = {config_path_in_experiment: config_bytes}
    for path, text in census_module.derived_files(census).items():
        files[path] = text.encode("utf-8")
    files["reports/summary.md"] = census_module.render_summary(census, config_sha256, provenance["head"]).encode("utf-8")
    files["logs/run-receipt.json"] = census_module.dump_json(receipt).encode("utf-8")
    if v2:
        files["logs/predecessor-reproduction.json"] = census_module.dump_json(reproduction).encode("utf-8")
    tests = {"recorded": False}
    if args.tests_log:
        log_text = sanitize_log(args.tests_log.read_text(encoding="utf-8", errors="replace"))
        files["logs/pytest.txt"] = log_text.encode("utf-8")
        tests = {
            "recorded": True,
            "log": "logs/pytest.txt",
            "command": (
                "PYTHONUTF8=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 .venv/Scripts/python.exe -m pytest -q "
                "-p no:cacheprovider tests/test_authority_census.py"
            ),
            "summary": parse_pytest_summary(log_text),
        }
    lint = {"recorded": False}
    if args.lint_log:
        lint_text = sanitize_log(args.lint_log.read_text(encoding="utf-8", errors="replace"))
        files["logs/ruff.txt"] = lint_text.encode("utf-8")
        lint = {
            "recorded": True,
            "log": "logs/ruff.txt",
            "command": (
                ".venv/Scripts/ruff.exe check src/agentdojo_lab/authority_census.py scripts/run_authority_census.py "
                "tests/test_authority_census.py"
            ),
            "summary": lint_text.strip().splitlines()[-1] if lint_text.strip() else None,
        }
    created_at = finished
    if v2:
        readme = render_readme_v2(census, config_sha256, provenance, reproduction, created_at)
    else:
        readme = render_readme(census, config_sha256, provenance, created_at)
    files["README.md"] = readme.encode("utf-8")
    scan_outputs(files)
    manifest = build_manifest(
        census, files, config_sha256, provenance, benchmark, receipt, tests, created_at, config=config, lint=lint
    )
    if v2:
        manifest |= v2_manifest_fields(census, reproduction, config)
        manifest["validation"]["predecessor_reproduction"] = (
            "pass" if reproduction.get("all_identical") else "not_checked"
        )
        manifest["validation"]["verifier_expected_values"] = manifest["results_summary_v2"]["verifier_check"]
    files["manifest.json"] = census_module.dump_json(manifest).encode("utf-8")
    scan_outputs({"manifest.json": files["manifest.json"]})
    files["checksums.sha256"] = checksums_text(files).encode("utf-8")

    existing = sorted(path for path in files if (output / path).exists())
    if existing and not args.replace:
        parser.error(f"refusing to overwrite existing outputs (use --replace): {existing}")
    unexpected = sorted(
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file() and path.relative_to(output).as_posix() not in files
    ) if output.exists() else []
    if unexpected:
        parser.error(f"unexpected files in the experiment directory: {unexpected}")
    for path, data in files.items():
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    mismatched = [path for path, data in files.items() if (output / path).read_bytes() != data]
    if mismatched:
        raise SystemExit(f"Written files differ from memory: {mismatched}")
    print(
        json.dumps(
            {
                "protocol": config["protocol"],
                "output": f"experiments/{experiment_id}",
                "written": sorted(files),
                "config_sha256": config_sha256,
                "e0_overall": census["e0"]["summary"]["overall"],
                "split_overall": census["e1"]["summary"]["split"]["overall"],
                "claims": {claim["id"]: claim["verdict"] for claim in census["claims"]},
                "requests": census["execution"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
