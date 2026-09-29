#!/usr/bin/env bash
#SBATCH --job-name=scout-terminal-report
#SBATCH --account=uoa04799
#SBATCH --partition=genoa
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=2G
#SBATCH --time=00:10:00
#SBATCH --no-requeue
#SBATCH --dependency=afterany:9123394:9123398:9123399:9126739:9126740:9126776:9129880:9129940:9135588
#SBATCH --output=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-%j.out
#SBATCH --error=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-%j.err

# Build the request-free nine-input report after every experiment reaches any
# terminal Slurm state. The submitted copy must come from the frozen bundle below.
set -euo pipefail
umask 077
export LC_ALL=C

[[ ${SLURM_JOB_ID:-} =~ ^[0-9]+$ ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_PARTITION:-} == genoa ]] || exit 2
[[ ${SLURM_CPUS_PER_TASK:-0} == 1 ]] || exit 2
: "${SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256:?Export the reviewed collector manifest SHA-256}"
[[ "$SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2

COLLECTOR_BUNDLE=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-collector-submission-20260917-v1
COLLECTOR_MANIFEST="$COLLECTOR_BUNDLE/submission-sha256.txt"
COLLECTOR_WRAPPER="$COLLECTOR_BUNDLE/hpc/scout-terminal-report-afterany.sbatch"
COLLECTOR_CLI="$COLLECTOR_BUNDLE/scripts/report_scout_terminal_panel.py"
COLLECTOR_MODULE="$COLLECTOR_BUNDLE/src/agentdojo_lab/scout_terminal_report.py"
COLLECTOR_BASELINE="$COLLECTOR_BUNDLE/reports/20260916-meeting-packet-v1/deliverables.json"
COLLECTOR_PYTHON=/nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/.venv/bin/python
COLLECTOR_OUTPUT=/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-20260917-v1
COLLECTOR_STDOUT="/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-${SLURM_JOB_ID}.out"
COLLECTOR_STDERR="/nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-terminal-panel-afterany-20260917-v1-${SLURM_JOB_ID}.err"
readonly COLLECTOR_BUNDLE COLLECTOR_MANIFEST COLLECTOR_WRAPPER COLLECTOR_CLI
readonly COLLECTOR_MODULE COLLECTOR_BASELINE COLLECTOR_PYTHON COLLECTOR_OUTPUT
readonly COLLECTOR_STDOUT COLLECTOR_STDERR

[[ -d "$COLLECTOR_BUNDLE" && ! -L "$COLLECTOR_BUNDLE" ]] || exit 2
[[ "$(realpath -e -- "$COLLECTOR_BUNDLE")" == "$COLLECTOR_BUNDLE" ]] || exit 2
[[ -f "$COLLECTOR_MANIFEST" && ! -L "$COLLECTOR_MANIFEST" ]] || exit 2
[[ "$(realpath -e -- "$COLLECTOR_MANIFEST")" == "$COLLECTOR_MANIFEST" ]] || exit 2
read -r COLLECTOR_ACTUAL_MANIFEST_SHA256 _ < <(sha256sum -- "$COLLECTOR_MANIFEST")
[[ "$COLLECTOR_ACTUAL_MANIFEST_SHA256" == "$SCOUT_TERMINAL_COLLECTOR_MANIFEST_SHA256" ]] || exit 2

# Require one safe, unique manifest entry for every physical bundle file other
# than the manifest itself. Its reviewed digest then binds the exact inventory.
awk '
    NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ ||
        $2 !~ /^[A-Za-z0-9_.\/-]+$/ || $2 ~ /^\// ||
        $2 ~ /(^|\/)\.\.(\/|$)/ || seen[$2]++ { bad = 1 }
    END { exit bad }
' "$COLLECTOR_MANIFEST" || exit 2
COLLECTOR_MANIFEST_ENTRIES=$(wc -l < "$COLLECTOR_MANIFEST")
COLLECTOR_PHYSICAL_FILES=$(find "$COLLECTOR_BUNDLE" -type f ! -path "$COLLECTOR_MANIFEST" -printf '.\n' | wc -l)
[[ "$COLLECTOR_MANIFEST_ENTRIES" == "$COLLECTOR_PHYSICAL_FILES" ]] || exit 2
[[ -z "$(find "$COLLECTOR_BUNDLE" -type l -print -quit)" ]] || exit 2
[[ -z "$(find "$COLLECTOR_BUNDLE" -type f -perm /0222 -print -quit)" ]] || exit 2
[[ -z "$(find "$COLLECTOR_BUNDLE" -type d -perm /0022 -print -quit)" ]] || exit 2
(cd -- "$COLLECTOR_BUNDLE" && sha256sum --check --strict --status submission-sha256.txt)

COLLECTOR_REQUIRED=(
    hpc/scout-terminal-report-afterany.sbatch
    scripts/report_scout_terminal_panel.py
    src/agentdojo_lab/scout_terminal_report.py
    reports/20260916-meeting-packet-v1/deliverables.json
)
for relative_path in "${COLLECTOR_REQUIRED[@]}"; do
    required_path="$COLLECTOR_BUNDLE/$relative_path"
    [[ -f "$required_path" && ! -L "$required_path" ]] || exit 2
    [[ "$(realpath -e -- "$required_path")" == "$required_path" ]] || exit 2
    awk -v expected="$relative_path" '$2 == expected { count++ } END { exit count == 1 ? 0 : 1 }' \
        "$COLLECTOR_MANIFEST" || exit 2
done
COLLECTOR_EXECUTED_WRAPPER=$(realpath -e -- "${BASH_SOURCE[0]}")
cmp --silent -- "$COLLECTOR_EXECUTED_WRAPPER" "$COLLECTOR_WRAPPER" || exit 2
[[ -x "$COLLECTOR_PYTHON" ]] || exit 2
"$COLLECTOR_PYTHON" -I -c \
    'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 2)'

EVIDENCE_PATHS=(
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-a-prepared-v6
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-b-prepared-v4
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-c-prepared-v3
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-c2-prepared-v2
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-d-prepared-v2
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-repeat-judge-20260917-v1
    /nesi/project/uoa04799/dyu848/repos/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/codebase/agentdojo-lab/runs/scout-case-e-prepared-v1
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-multi-repeat-judge-20260917-v1
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-content-composition-argument-20260917-v1
)
TERMINAL_PATHS=(
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-a-20260917-v4/case-a-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-b-20260917-v3/case-b-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-c-20260917-v3/case-c-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-c2-20260917-v1/case-c2-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-d-20260917-v1/case-d-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-repeat-judge-smoke-20260917-v1/repeat-judge-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-case-e-20260917-v1/case-e-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-multi-repeat-judge-smoke-20260917-v1/multi-repeat-judge-batch-summary.json
    /nesi/project/uoa04799/dyu848/tool-output-lab/evidence/scout-content-composition-argument-smoke-20260917-v1.content-composition-argument-batch-summary.json
)
readonly EVIDENCE_PATHS TERMINAL_PATHS
[[ ${#EVIDENCE_PATHS[@]} == 9 && ${#TERMINAL_PATHS[@]} == 9 ]] || exit 2

paths_overlap() {
    local left=${1%/}
    local right=${2%/}
    [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}

[[ "$COLLECTOR_OUTPUT" == /* && "$(realpath -m -- "$COLLECTOR_OUTPUT")" == "$COLLECTOR_OUTPUT" ]] || exit 2
[[ ! -e "$COLLECTOR_OUTPUT" && ! -L "$COLLECTOR_OUTPUT" ]] || exit 2
for input_path in "${EVIDENCE_PATHS[@]}" "${TERMINAL_PATHS[@]}"; do
    [[ "$input_path" == /* && "$(realpath -m -- "$input_path")" == "$input_path" ]] || exit 2
    paths_overlap "$COLLECTOR_OUTPUT" "$input_path" && exit 2
done
for protected_path in "$COLLECTOR_BUNDLE" "$COLLECTOR_MANIFEST" "$COLLECTOR_STDOUT" "$COLLECTOR_STDERR"; do
    [[ "$protected_path" == /* && "$(realpath -m -- "$protected_path")" == "$protected_path" ]] || exit 2
    paths_overlap "$COLLECTOR_OUTPUT" "$protected_path" && exit 2
done

# The report only reads saved bytes. Missing or failed inputs are deliberately
# still passed so the collector records them as unknown instead of dropping them.
unset PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONBREAKPOINT
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
unset HF_TOKEN HUGGING_FACE_HUB_TOKEN GROQ_API_KEY LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY
export PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export PYTHONPATH="$COLLECTOR_BUNDLE/src"

"$COLLECTOR_PYTHON" -B -P "$COLLECTOR_CLI" \
    --output "$COLLECTOR_OUTPUT" \
    --evidence "A=${EVIDENCE_PATHS[0]}" --terminal "A=${TERMINAL_PATHS[0]}" \
    --evidence "B=${EVIDENCE_PATHS[1]}" --terminal "B=${TERMINAL_PATHS[1]}" \
    --evidence "C=${EVIDENCE_PATHS[2]}" --terminal "C=${TERMINAL_PATHS[2]}" \
    --evidence "C2=${EVIDENCE_PATHS[3]}" --terminal "C2=${TERMINAL_PATHS[3]}" \
    --evidence "D=${EVIDENCE_PATHS[4]}" --terminal "D=${TERMINAL_PATHS[4]}" \
    --evidence "REPEAT=${EVIDENCE_PATHS[5]}" --terminal "REPEAT=${TERMINAL_PATHS[5]}" \
    --evidence "E=${EVIDENCE_PATHS[6]}" --terminal "E=${TERMINAL_PATHS[6]}" \
    --evidence "MULTI=${EVIDENCE_PATHS[7]}" --terminal "MULTI=${TERMINAL_PATHS[7]}" \
    --evidence "CONTENT=${EVIDENCE_PATHS[8]}" --terminal "CONTENT=${TERMINAL_PATHS[8]}"
