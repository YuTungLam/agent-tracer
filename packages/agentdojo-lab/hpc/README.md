# Bounded Scout serving smoke test

Prepared 2026-09-14. The bounded serving smoke has now deployed Scout for one
terminal scheduled integration run. The batch script requires an already prepared
local model, chat template, and Apptainer image. It never downloads them, submits
another job, or runs research attacks.

Status rechecked 2026-09-15: model download/verification job `9029207` completed,
container job `9029215` failed during SIF creation after 50m 31s, and dependent
GPU job `9029415` was cancelled without starting.
See [the current setup status](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/HPC_SETUP.md#status-recheck-on-2026-09-15).

Continuation on 2026-09-15 submitted the separately named SSD/gzip-level-1
container attempt **9039259**, followed by the dependent synthetic/native smoke
**9039289**. The CPU job completed on `g01` in **6m 49s**, publishing the verified
SIF. The GPU job then ran on `mg15` and completed in **9m 54s**, exit `0:0`.
Synthetic requests passed 4/4; the three-request benign native run passed all nine
checks. This verifies the bounded Scout integration, not an attack or attribution
result. Inspect the terminal receipts before submitting another attempt. The
original model download is reused.

## Resource and software choice

`scout-smoke.sbatch` requests one Milan node, four A100s, 48 CPU cores,
320 GiB host RAM and 45 minutes, with no automatic requeue. The maximum
GPU allocation is 3 GPU-hours. The request is 48 CPUs; on this system Slurm
allocates 96 logical CPUs for it, so inspect actual accounting rather than
treating requested CPU count as billed usage. Host RAM is separate
from GPU VRAM. These are initial smoke limits, not measured Scout requirements.
NeSI documents four A100 80 GB GPUs and 64 cores per Milan GPU node; 320 GiB
leaves room below its reported schedulable host memory and per-core ratio.
[NeSI hardware](https://docs.nesi.org.nz/Batch_Computing/Hardware/),
[GPU resource syntax](https://docs.nesi.org.nz/Batch_Computing/Using_GPUs/).

The serving candidate is **vLLM 0.29.0, CUDA 12.9, linux/amd64** in a local SIF.
The release and image tag are documented by the
[vLLM 0.29.0 release](https://github.com/vllm-project/vllm/releases/tag/v0.29.0).
Registry inspection resolved `vllm/vllm-openai:v0.29.0-cu129` on 2026-09-14:

- Registry index: `sha256:7ef5a35d1ef8ce2cf9d671dd91eec6e367c5849262e0362b4d3d4a26be0d87d2`.
- Linux/amd64 manifest: `sha256:3e10e8189823e0f7ae4620c271bcdaaf64127ec7d0edc351591a508498b7684a`.

The manifest reference is in `site.env.example`; image preparation is a separate
step. Record the resulting **SIF file's own SHA-256** after preparation. The
registry digest and SIF checksum are different artifacts; do not interchange
them. GPU driver compatibility was verified by terminal job `9039289`.
The runtime precheck requires vLLM 0.29.0 (including its `+cu129` package suffix),
PyTorch CUDA 12.9, and four visible A100 GPUs.

Use the separately named local
[`tool_chat_template_llama4_pythonic_typed_v1.jinja`](tool_chat_template_llama4_pythonic_typed_v1.jinja),
derived from the **v0.29.0** vLLM template as described below. Its SHA-256 is
pinned in `site.env.example`. Llama 4's recommended parser is
`llama4_pythonic`; automatic tool choice is enabled.
[Official tool-calling documentation](https://docs.vllm.ai/en/v0.29.0/features/tool_calling/).
The job fixes BF16, tensor parallel size 4, one active sequence, context 8192,
GPU memory fraction 0.90, eager safetensors loading and eager execution. The
safetensors strategy avoids random memory-mapped reads on the shared filesystem;
its host-memory use still needs measurement. Eager execution
reduces CUDA-graph startup work for this smoke test; it is not a performance
benchmark. [Pinned serve arguments](https://docs.vllm.ai/en/v0.29.0/cli/serve/).

### Prospective template correction: typed_v1

The upstream
[`examples/tool_chat_template_llama4_pythonic.jinja`](https://github.com/vllm-project/vllm/blob/v0.29.0/examples/tool_chat_template_llama4_pythonic.jinja)
is preserved byte-for-byte in the
[`v0.29.0 regression fixture`](../tests/fixtures/tool_chat_template_llama4_pythonic_v0_29_0.jinja)
and in its original downloaded location. Its 7,347 bytes have SHA-256
`3fe950790d033a6ee07a563fb6ad7c34e40f860b8ff99333b0b0aed6204ba258`.
The source belongs to the Apache-2.0-licensed vLLM project; its
[upstream license](third_party/vllm-LICENSE) is retained alongside these files.

That template quotes every historical tool argument after string formatting:
an actual list becomes `labels="['café', 'tea']"`, null becomes `note="None"`,
and an integer becomes `count="7"`. Embedded quotes, backslashes and newlines
are also unescaped. This changes the previous call seen by the model and can
produce malformed Pythonic history. It is a serving-template defect, not an
observed influence-tracking result or a model capability finding.

The local `typed_v1` file adds one recursive, zero-output Jinja macro and changes
only historical argument-value serialization. Strings use Transformers'
`tojson(ensure_ascii=False)` escaping; arrays and objects recurse; null and
booleans use Python literals; finite numbers retain their numeric form.
Nonfinite numbers fail explicitly. System/user/tool text, tool definitions,
role delimiters, call order and generation-prefix behavior retain the upstream
template's bytes. The original request objects are not mutated.

This is a **new, explicitly recorded serving condition**, prepared before the
first Scout GPU smoke. The 8,830-byte corrected file has SHA-256
`524a672eb654846b9ba1ab8a59ad9c3a80e3ad035dd7d01f701c64a71a09385f`.
It must not be substituted into historical runs or described as the unmodified
official template. The job preflight records its actual path and hash.

The offline
[`template tests`](../tests/test_scout_chat_template.py) demonstrate the original
type/escaping regression and verify rendered values through `ast.literal_eval`,
including nested objects, arrays, Unicode/emoji, booleans, null, numeric types,
quotes, backslashes and newlines. No function call or payload is executed.
They also compare unaffected prompt regions and exercise the production
Transformers compiler when installed. vLLM normalizes empty assistant content
and parses serialized tool arguments before template rendering; the fixture
uses that normalized input shape. Job `9039289` subsequently passed the live
Scout tool round trip.

On 2026-09-14, all 28 template tests passed in the restored lab environment.
The separately downloaded, pinned Scout tokenizer also passed real
`apply_chat_template` rendering and token encode/decode checks for 20 argument
cases (328 prompt tokens), using Transformers 5.16.1. The local
[`tokenizer receipt`](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260914-nesi-setup-v1/typed-template-check.json)
records tokenizer-file and template hashes. This is offline tokenizer evidence;
it does not establish the serving container's runtime or model behavior.

## Prepare inputs outside the GPU allocation

Copy `site.env.example` to a private file outside Git and fill its placeholders.
Its defaults keep large regenerable data under
`/nesi/nobackup/uoa04799/dyu848/tool-output-lab/{models,cache,containers,tmp}`.
The storage check found a 10,240 GiB scratch quota and a 200 GiB project
quota: the approximately 203 GiB BF16 weight estimate alone exceeds the latter.
Keep code and small durable evidence under `/nesi/project/uoa04799/dyu848/`.
Do not treat scratch as archival storage.

The HF CLI is `/nesi/project/uoa04799/dyu848/tools/hf/bin/hf`. Authenticate during
preparation, keeping its token at private `~/.cache/huggingface/token`.
`HF_HUB_CACHE` and `HF_XET_CACHE` point to scratch; `HF_HOME` is not moved there.
Do not add an HF token to the site file or submission command. The GPU job uses
no HF credentials and creates its own temporary local API key in memory.

Required inputs:

| Variable | Requirement |
| --- | --- |
| `SCOUT_SNAPSHOT` | Absolute, complete materialized local Scout snapshot directory |
| `SCOUT_REVISION` | Exact 40-hex Hugging Face commit used for the download |
| `SCOUT_MODEL_INTEGRITY` | Successful complete download/checksum receipt matching this snapshot |
| `SCOUT_CHAT_TEMPLATE`, `SCOUT_TEMPLATE_SHA256` | Local typed_v1 template and recorded SHA-256 |
| `VLLM_SIF`, `VLLM_SIF_SHA256` | Prepared local SIF and its recorded SHA-256 |
| `SCOUT_RUN_DIR` | Fresh directory for durable evidence; existing directories are rejected |
| `SCOUT_HPC_DIR` | Absolute path to this folder, which must remain available on the compute node |

Public model metadata resolves Scout to revision
`92f3b1597a195b523d8d9e5700e57e4fbb8f20d3`: 50 root safetensors files total
217,283,738,720 bytes (about 202.4 GiB). The checked defaults use that revision
and `models/llama-4-scout-92f3b159`. Authentication and a gated config download
have since passed; this is still distinct from complete weight verification. Its local receipt is
`reports/20260914-nesi-setup-v1/scout-public-metadata.json` in the lab.

Keep the full download receipt in durable project evidence and set
`SCOUT_MODEL_INTEGRITY` to it. Preflight requires its successful terminal status,
matching snapshot/revision, and verified sizes/hashes for every serving file.
Metadata content is rechecked against its pinned checksum; every index-listed
weight shard must exist with the verified size,
and hashes the config, tokenizer files, index, chat template, and SIF. It does
**not** reread hundreds of GB of weight data for full shard hashing inside the
allocation; the recorded revision is a declared download identity, not proof of
origin by itself. Complete integrity verification belongs to model preparation.
An HF cache snapshot with symlinks pointing outside its directory is rejected:
materialize it first so binding `/scout-model` cannot break shard/tokenizer paths.

The CPU download script performs the complete integrity pass outside the GPU
allocation. With a signed-in HF CLI and the prepared site file:

```bash
sbatch --export=HOME,PATH,LANG \
  --output=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-download-%j.log \
  scout-download.sbatch /nesi/project/uoa04799/dyu848/tools/scout-site.env \
  /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-download-UNIQUE_ID
```

It requests four CPUs, 16 GiB RAM and four hours maximum, with two download
workers and no GPU. Job `9029207` completed successfully in 27m 05s; all 63
selected files passed verification. Reuse that snapshot and receipt. It writes a pinned inventory before downloading, then a terminal
`model-integrity.json` only after all 63 selected root files pass their LFS
SHA-256 or Git blob checks. A partial/failed receipt cannot pass GPU preflight.
A nonblocking snapshot lock prevents two copies of this preparation script from
writing concurrently. Set the site receipt path to the matching attempt.

Check inputs before spending GPU time, using a new receipt path:

```bash
source /path/to/private/scout-site.env
python3 "$SCOUT_HPC_DIR/preflight.py" --output /path/to/fresh/preflight-check.json
```

For the first combined check, run four synthetic requests followed by one
benign native AgentDojo task in the same allocation. Submit **once** with a
60-minute ceiling and dependencies on the successful preparation jobs:

```bash
sbatch --time=01:00:00 --dependency=afterok:9029207:9029215 \
  --kill-on-invalid-dep=yes \
  --export=HOME,PATH,LANG,SCOUT_SITE_FILE=/nesi/project/uoa04799/dyu848/tools/scout-site.env,SCOUT_NATIVE_SMOKE=1 \
  --output=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-smoke-%j.log \
  scout-smoke.sbatch
```

The site file is read at job start, after successful preparation. Update job IDs
for a later attempt and use a fresh `SCOUT_RUN_DIR`. The combined ceiling is
four GPU-hours and **eight generative requests**: four synthetic requests at
512 completion tokens each, then at most four native requests at 2,048 tokens
each. The native wrapper rejects further SDK attempts across native retries,
uses no online auditor, and has a 780-second process deadline. It fixes native
workspace `user_task_0`, records actual task utility, validates event links and
successful tool execution, and exports per-run HTML. A failed native task remains
a failed integration/utility check; it is not attack evidence. The wrapper hash,
server command, synthetic receipt, and model/container/template pins are linked
in `native-smoke.json`. The loopback client uses no proxies or redirects.

### Submitted same-allocation Case A continuation

Completed job `9039289` ran the frozen smoke wrapper and exited after smoke; it
cannot append Case A. Do not alter its site file or v2 submission bundle.
[`scout-smoke-case-a.sbatch`](scout-smoke-case-a.sbatch) is a separately named
protocol for a fresh allocation. Set
`SCOUT_RUN_DIR` to a new absolute smoke directory, `SCOUT_CASE_A_DIR` to a
separate absolute directory containing only a verified `plan.json` and
`preparation.json`, and `SCOUT_CASE_A_RUNNER` to the active absolute runner.
Freeze this wrapper and all sibling HPC helpers together before submission.

The wrapper repeats four synthetic requests and the bounded native smoke in the
same job, then reserves `case-a-phase.json` before any Case A request. It reads
the current job's `%i|%L|%l` fields from `squeue` and leaves Case A unstarted if
the job ID or duration cannot be parsed, the job limit exceeds two hours, or
less than 3,900 seconds remain. It rechecks the authenticated literal-loopback
server and limits the whole Case A process group to 3,600 seconds with TERM and
KILL cleanup. The combined ceilings are 24 generation attempts (4 synthetic,
at most 4 native, at most 16 Case A), zero online auditors, and zero SDK retries.

The following is a template for a future separately named attempt. Do not use it
while job `9050478` is queued. A reviewed submission invokes a frozen wrapper,
site file and fresh scheduler log parent directly:

```bash
sbatch \
  --export=HOME,PATH,LANG,SCOUT_SITE_FILE=/path/to/frozen-scout-case-a-site.env \
  --output=/path/to/existing/log-directory/scout-case-a-%j.log \
  /path/to/frozen-hpc/scout-smoke-case-a.sbatch
```

The sibling `${SCOUT_RUN_DIR}.case-a-pre-smoke.json` receipt binds the plan and
runner before server startup. The smoke directory retains `preflight.json`,
`smoke.json`,
`native-smoke.json`, the pre-Case phase and server checks, helper hashes,
separate Case wrapper and job exit codes, cleanup evidence, and the terminal
`case-a-batch-summary.json`. The terminal receipt accounts for requests and
framework completion. Scientific sink outcomes remain in the Case A summary
and paired report, including unsuccessful and unconfirmed trials.

The current plan is `runs/scout-case-a-prepared-v4`, with 85 bound source files,
zero requests and plan SHA-256
`5e3b9aa67767e2bf0b5c1275dac14742ee02f596efff84f0d6fe2cd4c95b5d31`.
The first submitted bundle was
`evidence/scout-case-a-submission-20260915-v1`, using private site
`/nesi/project/uoa04799/dyu848/tools/scout-case-a-site-20260915-v1.env`.
Job `9043206` was submitted at 15:36 NZST, then cancelled at 15:47 before
allocation after audit found that one relative helper path would resolve from
Slurm's spool directory. Accounting records 00:00:00 elapsed, zero GPU time and
zero requests. Preserve that submission record.
The mode-0400 `cancelled.json` in that bundle has SHA-256
`35bfde30958b8ecb49aafcb31c448e69c0c0e71fe57ce8387f8c535b6d6a9e5a` and
records no assigned node.

The corrected launch source checkpoint
`228f7c2ce4255a8587921ef955c633868b1fb10d` is pushed. Its immutable bundle is
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-a-submission-20260915-v2`,
with private site
`/nesi/project/uoa04799/dyu848/tools/scout-case-a-site-20260915-v2.env`.
The site, helper manifest and offline preflight SHA-256 values are
`985c5f97ca5ce6141b5d6c04a8abaef797251f900eccce51676f0bfce1ca905d`,
`5cc8195c816e43c1c2ec22237cbadc9cacd4503f5beca75ae5e4a243014a6451`
and `6a8b2f5e3ba7da0f61c7dd9b0723135cdf7b12d15b97fe37492852c004f54aab`.
Request-free validation passed, and an independent audit returned GO with no
P1/P2 findings after 81 focused tests plus 16 subtests.

Job `9050478` was submitted at scheduler display Sep 15 17:08. It is pending for
Priority with runtime zero, no allocation and no observed model requests. Slurm's
Sep 15 22:35 NZST start and prospective `mg14` node are estimates, not guarantees
or allocation evidence. It starts automatically. The `submitted.json` receipt
has SHA-256
`770b8e9fc66590f968d1e0f6bbc7e731b70ff7db66c1c197366955b25a4744c9`.
Monitor it rather than submitting a duplicate; after terminal completion, inspect
all smoke, request-accounting, Case A and report artifacts.

For a synthetic-only check, omit `SCOUT_NATIVE_SMOKE=1` and retain the default
45-minute batch limit. Neither mode starts research experiments. Native input
prompts must fit the explicit 8,192-token context; there is no silent truncation.


The log parent directory must already exist before `sbatch`; Slurm opens its
output before the script creates directories. The combined command was submitted
as job **9029415** on 2026-09-14; it was cancelled after container preparation
failed. The command above records that historical submission. A new attempt
needs successful preparation dependencies and a fresh evidence directory. The job and smoke client use the stdlib
features available in Python 3.9+, so the host Python suffices; the AgentDojo lab
itself still requires its separate Python 3.12 environment.

### Case B same-allocation wrapper

[`scout-smoke-case-b.sbatch`](scout-smoke-case-b.sbatch) implements protocol
`nesi-scout-smoke-case-b-v1`. It requests four A100s for at most two hours and
permits at most 24 generation attempts: four synthetic smoke, four benign-native
smoke and 16 Case B attempts. It requires at least 3,900 scheduler-reported
seconds before Case B, limits the Case B process group to 3,600 seconds, binds
server PID/phase/cleanup evidence and repeats the full request-free source verifier
at terminal close. Its frozen launch manifest must contain exactly nine entries.
See [the Case B protocol](../CASE-B-SCOUT-V1.md).

The independent final Case A/B selection passed 191 tests plus 16 subtests;
root's broader selection passed 214 tests plus 16 subtests. Ruff, Bash syntax,
Python compilation and diff checks passed. The prepared Case B v2 design
inventory contains 163 source files, including all
113 runtime/package-metadata files from pinned AgentDojo commit
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Its upstream runtime-tree SHA-256 is
`4c58924aeb917f1daf29a4fcb11d79e716af8baf7266b73c592b39aa93a4edd7`.
Preserved v1 has 41 sources, zero model requests and plan SHA-256
`4b8bc845437ce557fe6bbe589dd90d6ccc5b083d92955ef0fb1324f4df52c036`;
it is now source-invalidated. `runs/scout-case-b-prepared-v2` contains exactly
`plan.json` and `preparation.json`; their SHA-256 values are
`69b0b0c2a77bff5057789719ae76a4a05c757a1acc511e3f66f14bd13dff60ff`
and `ba663d561892b614f7320be36a8fc9c4bf363c946c15837ac52e905fa1b45906`.
It records zero model calls.

The immutable submission bundle is
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-b-submission-20260915-v1`,
using private site
`/nesi/project/uoa04799/dyu848/tools/scout-case-b-site-20260915-v1.env`.
All 163 bound sources are physical mode-0400 files: 50 bind pushed parent commit
`228f7c2ce4255a8587921ef955c633868b1fb10d`, and 113 bind pinned AgentDojo
commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. Their combined source-tree
SHA-256 is `8ecf7918e814b30989d5a4b94514895093998c897ad3fe2f4adcdaf64e147884`.
The site, nine-entry manifest, offline preflight, request-free validation and
submission-plan SHA-256 values are
`38c6ab9d6441cc55672efcccd434b4442e0dc12e5c0f4357aee26b6a567e5980`,
`951a00e2cf1d00b255ee390feeebc43a35321cc7162363651bd6d9509b092eac`,
`6c3b6b501733595985df9872fcca2eeca590e773176ca8333a5a866f3df1ea60`,
`4e7748b77e204c5fcebfa95512b3a8b7df114e7607ce1942ca4965921440a424`
and `938cb660d45586a3c5330ae105cbc139228dc567412f8ea715d065d619b9566e`.
Import isolation and fixed limits validated; independent audit returned GO with
no P1/P2 findings.

Job `9052477` was submitted at scheduler display Sep 15 17:30. It is pending for
Priority with runtime zero, no allocation and no model calls. Its displayed Sep
16 00:40 NZST start and prospective `mg14` node are provisional. It starts
automatically. The `submitted.json` SHA-256 is
`88b00e37fa87aa45755de4749aeaa6ae0a2ee81d62c84c9c36bd2c1bb3812408`.
No live Case B result exists yet.

## Separate CPU container preparation

`container-prep.sbatch` downloads the pinned public linux/amd64 OCI manifest and
converts it to a SIF on a compute node. It requests 8 CPUs, 32 GiB host memory,
60 minutes and **zero GPUs**. The build itself has a 3,000-second timeout;
SquashFS compression is limited to 8 workers and 8 GiB. Slurm CPU affinity and
memory limits also apply. `apptainer build` is used because the installed 1.4.5
`pull` command does not expose compressor resource flags.
[Apptainer build documentation](https://apptainer.org/docs/user/1.4/build_a_container.html).

After successful conversion, `finalize_container.py` hashes the SIF, publishes it
without overwriting an existing image, and atomically changes only
`VLLM_SIF_SHA256` in the private site file. It preserves failed/partial artifacts
and records the immutable OCI source, SIF bytes/hash, job ID and config-update
status. No source site contents or tokens are written to evidence. GPU runtime
validation remains a separate smoke job. The anonymous public registry download
does not use HF authentication.

After reviewing the populated private site file, a fresh preparation can use:

```bash
SCOUT_SITE_FILE=/path/to/private/scout-site.env \
SCOUT_PREP_EVIDENCE=/path/to/fresh/container-preparation \
  sbatch --output=/path/to/existing/log-directory/container-%j.log \
  codebase/agentdojo-lab/hpc/container-prep.sbatch
```

The first authorized submission on 2026-09-14 is job `9029215`; its live state is
recorded by Slurm, not by this README. Evidence is under
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/container-prep-20260914-v1`,
with scheduler log `evidence/prep-logs/container-9029215.log`. A job ID is not a
completion or deployment claim. Do not submit a replacement without inspecting
the retained outcome and its bounded protocol.

### Recovery attempt: SSD and gzip level 1, v2

The first job's 50m 31s elapsed time is consistent with its 3,000-second build
timeout and 30-second kill grace. Its log reached SIF creation, but does not
explicitly identify timeout or out-of-memory termination. Accounting reports
136,732 KiB MaxRSS for the cancelled build step; that sample does not establish
the peak memory of all compressor subprocesses. No partial SIF remains at its
planned destination. Its roughly 21 GiB extracted temporary tree and 9.9 GiB OCI
cache remain; the failed tree is preserved and is not used as a completed image.

[`container-prep-ssd-v2.sbatch`](container-prep-ssd-v2.sbatch) is a new protocol,
`nesi-scout-container-prep-ssd-gzip1-v2`. It uses the same immutable OCI source,
8 requested CPUs, 32 GiB RAM, a 2-hour ceiling and a 6,600-second build timeout.
It requests one Genoa node's SSD with `--gres=ssd`, requires the supplied
`JOB_SCRATCH_DIR`, and refuses a RAM/shared-filesystem fallback. The observed
job directory is on XFS with about 3.18 TB free at start. This avoids extracting
and rereading thousands of files on shared scratch. NeSI removes the new local
temporary tree when the job ends; logs, stage timestamps, receipts and any
published image remain in their durable/shared locations.
[NeSI temporary directories](https://docs.nesi.org.nz/Batch_Computing/Temporary_Directories/).

The compressor retains gzip compatibility but explicitly uses level 1, with
8 workers and an 8 GiB compressor-memory bound. This follows Apptainer's
documented fast gzip setting; its actual elapsed time remains a measured result,
not a promised speedup. The warm content-addressed OCI cache is reused.
[Apptainer compressors](https://apptainer.org/docs/user/1.4/build_a_container.html#alternative-compressors).

The new site file is
`/nesi/project/uoa04799/dyu848/tools/scout-site-20260915-v2.env`.
It preserves the original site and selects
`containers/vllm-openai-v0.29.0-cu129-ssd-gzip1-v2.sif` under the same scratch
root. The finalizer accepts the explicit new protocol while preserving the v1
default for historical tooling. It publishes without overwrite and updates
only the new site's SIF checksum.

The submission bundle is
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-recovery-submission-20260915-v2`.
It contains copied helper scripts/template, `submission-plan.json`,
`submitted.json`, hashes and initial Slurm status. `SCOUT_HPC_DIR` points to this
bundle's `hpc` directory so subsequent repository edits cannot change the frozen
HPC helpers. The native client uses the existing lab Python explicitly.
The copied CPU script SHA-256 is
`0d03b0ad215a0439ed5b33afd284083a555560d436cabb974c800c57c8ea62c7`;
the unchanged GPU script is
`8554d25dc2a9288111c578eae0b05fbd1fb0e837526f46de373f320705787420`.

CPU job **9039259** completed and writes `evidence/container-prep-20260915-v2`, including
`stages.jsonl` with preparation, build, inspection and publication timestamps.
The scheduler log is `evidence/prep-logs/container-v2-9039259.log`.
GPU job **9039289** used `afterok:9039259` and `--kill-on-invalid-dep=yes`;
it wrote the fresh `evidence/scout-smoke-20260915-v2` directory and scheduler
log `evidence/prep-logs/scout-smoke-v2-9039289.log`.
The GPU limits remain four A100s, 48 requested CPUs, 320 GiB, one hour and at most
eight generation requests. It completed on `mg15` in 9m 54s with exit `0:0`.
No research trial was included.

Its terminal receipt records **11,042,500,608 bytes** and SIF SHA-256
`2e34131f9ef3257b67e628e735fa76dee506449152f3882bf50204c92e38b6c2`, with
`site_checksum_updated: true` and `gpu_validation: not_run`. The build took
391.20 seconds; inspection and checksum/publication took about 10.23 seconds.
Slurm's allocation elapsed time was **6m 49s**, with exit `0:0`, 16 allocated
logical CPUs and 32 GiB RAM. The build step's sampled MaxRSS was 6,111,080 KiB.
These timestamps establish completion of this preparation attempt, not an
isolated speed comparison between compressors or filesystems. The original
failure and its remaining extracted files are preserved.

`completed-input-preflight.json` in the submission bundle passed the complete
input preflight, including the new SIF hash, template hash and binding to the
verified model receipt. The running container reported vLLM `0.29.0+cu129`, CUDA
12.9 and four visible A100 SXM4 80 GB devices. All 50 shards loaded; the slowest
worker took 375.30 seconds and reported 52.72 GiB loaded. Synthetic requests
passed 4/4. The benign native task used three requests and passed all nine checks,
including utility, recording/link integrity, tool round trips and HTML export.
Total use was 7/8 allowed requests.

Terminal hashes are:

- `preflight.json`: `cf6ac029df212ce19a9ab171b0e841e26b13423fa9d86a29588d2ff3c79465ea`
- `container-runtime.json`: `f239a98ceb184be2ff63eaafe68f5e40f46965b38b17b9cb49749d9237bd3f34`
- `smoke.json`: `d7c2b167ab7c1ebd014b16c6fb0cb195323535db2620a5ae921376dd2a287a48`
- `native-smoke.json`: `283361a3e17c8e98f0d71a28fc624be6910243f92e7b01cad5d7c7ac2c8d3192`
- `job-exit-code.txt`: `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa`
- scheduler log: `31cf94502677f83157cfb228ec7ba7cb0dd33623d2aa0975b0ba844c2311fcca`

On 2026-09-15, the HPC pytest suite passed **28 tests and 25 subtests**;
Ruff, the new script's `bash -n`, and `git diff --check` passed. New finalizer
checks verify explicit v2 receipt identity and refusal to publish an unknown
protocol. These checks are separate from the live smoke results above.

## Content-composition argument panel

The prospective second-family panel is specified in
[`SCOUT-CONTENT-COMPOSITION-ARGUMENT-V1.md`](../SCOUT-CONTENT-COMPOSITION-ARGUMENT-V1.md).
Its request-free runner freezes 42 scientific slots over two archived prefixes,
three repetitions, and sham/A/B/joint removal arms. The dedicated
`scout-smoke-content-composition-argument.sbatch` wrapper requests four A100s for
3.5 hours, reuses the same-allocation smoke server, and has a 50-generation-call
combined ceiling. It never executes a returned protocol tool proposal.

Each intervention replaces only the frozen `/content`-contributing fragment in
every frozen carrier occurrence and preserves all surrounding and non-target
text. Scientific comparisons score exact `/content` persistence after an
exact-call sham gate; `/filename` persistence and exact-call reproduction are
reported separately. Terminal slots with an invalid or unknown response do not
make the panel scientifically complete. This panel always records supervisor
item 13 as unestablished by this protocol alone and requires prospective
combination with the frozen `conditional_action` panel.

Submit this wrapper with explicit distinct absolute `sbatch --output` and
`sbatch --error` paths. The private site file must resolve the corresponding
`SCOUT_CONTENT_ARGUMENT_STDOUT` and `SCOUT_CONTENT_ARGUMENT_STDERR` variables to
those exact paths. The batch gate records authoritative `scontrol` `StdOut` and
`StdErr` values; planned metadata is not treated as the actual scheduler path.
The wrapper rejects overlaps among those logs, the smoke/plan/live outputs, and
all protocol sidecars. Its outer cleanup trap is active before generic smoke
logic begins preflight, so early failures still attempt an authoritative terminal
receipt. The wrapper sources its separately named, manifest-bound content smoke helper; it
does not alter the byte-frozen shared `scout-smoke.sbatch` used by older wrappers.
All output directories, sidecars, and authoritative logs must be outside and
disjoint from the immutable copied bundle.

## Automatic terminal-panel collector

[`scout-terminal-report-afterany.sbatch`](scout-terminal-report-afterany.sbatch)
is a CPU-only Genoa job that runs the request-free nine-input terminal report
after every submitted experiment reaches any terminal Slurm state. Its `afterany`
dependency is deliberate: failed, cancelled, incomplete and missing inputs are
still passed to the report and remain unknown. The collector does not query
Slurm, call a model or network endpoint, or execute a native tool.

Freeze a separate physical copy at
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-collector-submission-20260917-v1`.
Its `submission-sha256.txt` must cover every other file exactly once, including
the wrapper, report CLI, report module and frozen baseline deliverable ledger.
Make bundle files read-only, review the manifest SHA-256, and export that digest
as `SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256`. The wrapper checks the exact
bundle path, reviewed manifest digest, complete manifest inventory, file hashes,
absence of symlinks and writable files, and its own spooled bytes. It also
requires the lab interpreter to report Python 3.12.

Before submission, verify that the report directory and both `%j` log targets
are fresh. Then use this exact command with the reviewed manifest digest already
exported:

```bash
sbatch \
  --dependency=afterany:9123394:9123398:9123399:9126739:9126740:9126776:9129880:9129940:9135588 \
  --export=HOME,PATH,LANG,SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256 \
  --output=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-%j.out \
  --error=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-%j.err \
  /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-collector-submission-20260917-v1/hpc/scout-terminal-report-afterany.sbatch
```

The fresh report destination is
`/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-20260917-v1`.
All nine evidence roots and all nine batch summaries are fixed in the wrapper.
In particular, CONTENT uses its live root
`scout-content-composition-argument-20260917-v1` and the external smoke-root
sidecar
`scout-content-composition-argument-smoke-20260917-v1.content-composition-argument-batch-summary.json`.
The output must remain disjoint from every evidence input, terminal sidecar,
immutable bundle and scheduler log.

## Bounds, isolation, and receipts

The server binds `127.0.0.1`, receives a new random key through `VLLM_API_KEY`,
and the client reads the matching `LOCAL_LLM_API_KEY`. No token is passed on a
command line or written to the receipt. HTTP proxies and redirects are disabled
for the smoke client. Requests require literal loopback HTTP; no remote fallback
exists. Apptainer uses a new private home and `--cleanenv --no-eval`, retaining
host IPC for tensor-parallel shared memory. HF/Transformers offline flags and
disabled telemetry prevent intentional model downloads; this is not a network
namespace sandbox. [Apptainer environment controls](https://apptainer.org/docs/user/1.4/environment_and_metadata.html),
[vLLM environment settings](https://docs.vllm.ai/en/v0.29.0/configuration/env_vars/).

Readiness polls authenticated `/v1/models` for at most 1,500 seconds and checks
the exact served name. Wrong-model/authentication failures stop immediately.
Each synthetic generation allows 120 seconds and 512 completion tokens, without retries:

1. One automatic function call with Unicode labels, an array, and a null value.
2. Return a synthetic tool result under the original call ID and require its
   receipt identifier in the final text.
3. Two automatic function calls in one response with separate IDs and integer
   arguments; these calls are validated but not executed.
4. An isolated JSON judge request with `response_format={"type":"json_object"}`
   and without tool definitions or tool history, matching the local auditor path.

This is at most **four generative requests and 2,048 generated tokens**. A failed
stage stops dependent execution; unstarted stages are not retried. GET readiness
requests are separate from that generation count. On exit or Slurm's early TERM,
the job terminates the server process group, waits up to ten seconds, and sends
KILL if needed. Slurm remains the final walltime bound. Existing cache/evidence
files are retained; no experiment artifacts are deleted.

`SCOUT_RUN_DIR` receives `preflight.json`, `gpus.csv`, `container-runtime.json`,
`server-command.txt`, `server.log`, `smoke.json`, and `job-exit-code.txt` as far as
execution reaches. The receipt records each attempted synthetic request,
response, status, and timing, excluding authentication headers and redacting
any echoed local key. Forced scheduler termination can leave an incomplete
receipt; that remains a failed/unavailable smoke attempt.

A passing synthetic phase demonstrates this narrow transport/parser behavior.
With `SCOUT_NATIVE_SMOKE=1`, the same allocation then checks one native clean
AgentDojo task and saves its separate receipt. Neither phase establishes
NeuroTaint accuracy, attack success, long-context reliability, performance or
repeated-run stability. The integrated lab uses `configs/local_scout.toml` and
the same served model/key environment names. The job shuts its server down after
its selected phases finish or a failure stops dependent execution.

## Offline verification

```bash
python3 -m unittest discover -s codebase/agentdojo-lab/hpc -p 'test_*.py' -v
bash -n codebase/agentdojo-lab/hpc/scout-smoke.sbatch
bash -n codebase/agentdojo-lab/hpc/site.env.example
bash -n codebase/agentdojo-lab/hpc/container-prep.sbatch
bash -n codebase/agentdojo-lab/hpc/container-prep-ssd-v2.sbatch
codebase/agentdojo-lab/.venv/bin/ruff check codebase/agentdojo-lab/hpc
codebase/agentdojo-lab/.venv/bin/python -m pytest codebase/agentdojo-lab/tests/test_scout_chat_template.py -q
```

Run these from the repository root. Tests cover a complete fake round trip,
argument types, duplicate IDs, truncated/wrong-model replies, request budgets,
credential redaction, failed receipts, bounded readiness, missing weight shards,
escaping model symlinks, and frozen image/template drift. They open no network
socket and do not load model weights.
