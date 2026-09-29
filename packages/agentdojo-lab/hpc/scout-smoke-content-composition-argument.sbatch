#!/usr/bin/env bash
#SBATCH --job-name=scout-content-arg
#SBATCH --account=uoa04799
#SBATCH --partition=milan
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gpus-per-node=a100:4
#SBATCH --cpus-per-task=48
#SBATCH --mem=320G
#SBATCH --time=03:30:00
#SBATCH --signal=B:TERM@60
#SBATCH --no-requeue
#SBATCH --output=scout-content-arg-%j.out
#SBATCH --error=scout-content-arg-%j.err

# Start Scout, repeat both smoke gates, and run the 42-call content-composition argument
# protocol while the same authenticated loopback server and allocation live.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the absolute private content-composition argument site file}"
: "${SCOUT_SITE_SHA256:?Export its reviewed SHA-256 at submission}"
[[ "$SCOUT_SITE_FILE" == /* && -f "$SCOUT_SITE_FILE" && ! -L "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_SITE_FILE")" == "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$SCOUT_SITE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
CCA_SITE_FILE="$SCOUT_SITE_FILE"
CCA_SITE_SHA256="$SCOUT_SITE_SHA256"
readonly CCA_SITE_FILE CCA_SITE_SHA256
read -r CCA_ACTUAL_SITE_SHA256 _ < <(sha256sum -- "$CCA_SITE_FILE")
[[ "$CCA_ACTUAL_SITE_SHA256" == "$CCA_SITE_SHA256" ]] || exit 2
source "$CCA_SITE_FILE"

: "${SCOUT_HPC_DIR:?Set the frozen hpc directory}"
: "${SCOUT_HPC_MANIFEST:?Set the frozen bundle checksum manifest}"
: "${SCOUT_HPC_MANIFEST_SHA256:?Set the reviewed manifest SHA-256}"
: "${SCOUT_LAB_PYTHON:?Set the Python 3.12 lab executable}"
: "${SCOUT_RUN_DIR:?Set a fresh smoke evidence directory}"
: "${SCOUT_CONTENT_ARGUMENT_PLAN_DIR:?Set a fresh request-free plan directory}"
: "${SCOUT_CONTENT_ARGUMENT_OUTPUT:?Set a fresh live content-composition argument directory}"
: "${SCOUT_CONTENT_ARGUMENT_RUNNER:?Set the frozen content-composition argument runner}"
: "${SCOUT_CONTENT_ARGUMENT_CONFIG:?Set the frozen content-composition argument config}"
: "${SCOUT_CONTENT_ARGUMENT_STDOUT:?Set the exact absolute sbatch --output path}"
: "${SCOUT_CONTENT_ARGUMENT_STDERR:?Set the exact absolute sbatch --error path}"
[[ "$SCOUT_CONTENT_ARGUMENT_STDOUT" == /* && "$SCOUT_CONTENT_ARGUMENT_STDERR" == /* \
    && "$SCOUT_CONTENT_ARGUMENT_STDOUT" != "$SCOUT_CONTENT_ARGUMENT_STDERR" \
    && "$SCOUT_CONTENT_ARGUMENT_STDOUT" != *[[:space:]]* \
    && "$SCOUT_CONTENT_ARGUMENT_STDERR" != *[[:space:]]* ]] || exit 2

CCA_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")
CCA_BUNDLE_ROOT=$(realpath -e -- "$CCA_HPC_DIR/..")
CCA_MANIFEST=$(realpath -e -- "$SCOUT_HPC_MANIFEST")
CCA_CANONICAL_WRAPPER="$CCA_HPC_DIR/scout-smoke-content-composition-argument.sbatch"
CCA_BATCH="$CCA_HPC_DIR/content_composition_argument_batch.py"
CCA_RUNNER="$CCA_BUNDLE_ROOT/scripts/run_scout_content_composition_argument.py"
CCA_CONFIG="$CCA_BUNDLE_ROOT/configs/scout_content_composition_argument_v1.json"
CCA_EXECUTED_WRAPPER=$(realpath -e -- "${BASH_SOURCE[0]}")
readonly CCA_HPC_DIR CCA_BUNDLE_ROOT CCA_MANIFEST CCA_CANONICAL_WRAPPER CCA_BATCH
readonly CCA_RUNNER CCA_CONFIG CCA_EXECUTED_WRAPPER
[[ "$CCA_HPC_DIR" == "$CCA_BUNDLE_ROOT/hpc" ]] || exit 2
[[ "$CCA_MANIFEST" == "$CCA_BUNDLE_ROOT/submission-sha256.txt" ]] || exit 2
[[ "$SCOUT_HPC_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
read -r CCA_ACTUAL_MANIFEST_SHA256 _ < <(sha256sum -- "$CCA_MANIFEST")
[[ "$CCA_ACTUAL_MANIFEST_SHA256" == "$SCOUT_HPC_MANIFEST_SHA256" ]] || exit 2
(cd -- "$CCA_BUNDLE_ROOT" && sha256sum --check --strict --status submission-sha256.txt)
cmp --silent -- "$CCA_EXECUTED_WRAPPER" "$CCA_CANONICAL_WRAPPER" || exit 2
[[ "$SCOUT_CONTENT_ARGUMENT_RUNNER" == "$CCA_RUNNER" && "$SCOUT_CONTENT_ARGUMENT_CONFIG" == "$CCA_CONFIG" ]] || exit 2
[[ -x "$SCOUT_LAB_PYTHON" && -f "$CCA_BATCH" && -f "$CCA_RUNNER" && -f "$CCA_CONFIG" \
    && -f "$CCA_HPC_DIR/scout-smoke-content-composition-base.bash" ]] || exit 2
for path in "$SCOUT_RUN_DIR" "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR" "$SCOUT_CONTENT_ARGUMENT_OUTPUT"; do
    [[ "$path" == /* && ! -e "$path" && ! -L "$path" ]] || exit 2
done
[[ "$SCOUT_RUN_DIR" != "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR" \
    && "$SCOUT_RUN_DIR" != "$SCOUT_CONTENT_ARGUMENT_OUTPUT" \
    && "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR" != "$SCOUT_CONTENT_ARGUMENT_OUTPUT" ]] || exit 2

export PYTHONPATH="$CCA_BUNDLE_ROOT/vendor/agentdojo/src:$CCA_BUNDLE_ROOT/src:$CCA_BUNDLE_ROOT/scripts"
export PYTHONDONTWRITEBYTECODE=1
unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY GROQ_API_KEY
SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY=1
source "$CCA_HPC_DIR/scout-smoke-content-composition-base.bash"
unset SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY
declare -F write_pre_phase_terminal >/dev/null || exit 2

CCA_PRE_SMOKE="${SCOUT_RUN_DIR}.content-composition-argument-pre-smoke.json"
CCA_PHASE="${SCOUT_RUN_DIR}.content-composition-argument-phase.json"
CCA_EXIT_FILE="${SCOUT_RUN_DIR}.content-composition-argument-wrapper-exit-code.txt"
CCA_CLEANUP="${SCOUT_RUN_DIR}.content-composition-argument-cleanup.json"
CCA_FINAL="${SCOUT_RUN_DIR}.content-composition-argument-batch-summary.json"
paths_overlap() {
    local left=${1%/}
    local right=${2%/}
    [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}
CCA_OUTPUT_PATHS=(
    "$CCA_BUNDLE_ROOT"
    "$SCOUT_RUN_DIR" "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR" "$SCOUT_CONTENT_ARGUMENT_OUTPUT"
    "$CCA_PRE_SMOKE" "$CCA_PHASE" "$CCA_EXIT_FILE" "$CCA_CLEANUP" "$CCA_FINAL"
    "$SCOUT_CONTENT_ARGUMENT_STDOUT" "$SCOUT_CONTENT_ARGUMENT_STDERR"
)
for destination in "${CCA_OUTPUT_PATHS[@]}"; do
    [[ "$(realpath -m -- "$destination")" == "$destination" ]] || exit 2
done
for ((left_index=0; left_index < ${#CCA_OUTPUT_PATHS[@]}; left_index++)); do
    for ((right_index=left_index + 1; right_index < ${#CCA_OUTPUT_PATHS[@]}; right_index++)); do
        paths_overlap "${CCA_OUTPUT_PATHS[left_index]}" "${CCA_OUTPUT_PATHS[right_index]}" && exit 2
    done
done
for sidecar in "$CCA_PRE_SMOKE" "$CCA_PHASE" "$CCA_EXIT_FILE" "$CCA_CLEANUP" "$CCA_FINAL"; do
    [[ ! -e "$sidecar" && ! -L "$sidecar" ]] || exit 2
done
mkdir -p -- "$(dirname -- "$SCOUT_RUN_DIR")"
unset SCOUT_SERVER_PID
SCOUT_SERVER_PID=''

CCA_RUNNER_PID=0
CCA_RUNNER_STOPPED=true
CCA_RUNNER_TERM=false
CCA_RUNNER_KILL=false
CCA_SERVER_TERM=false
CCA_SERVER_KILL=false
CCA_SERVER_STOPPED=false
CCA_WATCHDOG_PID=''
CCA_WRAPPER_STAGE=plan_only
SCOUT_SMOKE_STAGE=''
CCA_SERVER_CHECK="$SCOUT_RUN_DIR/content-composition-argument-server-check.json"
CCA_RUNNER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/content-composition-argument-cleanup-runner-kill"
CCA_SERVER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/content-composition-argument-cleanup-server-kill"

stop_runner() {
    if [[ "$CCA_RUNNER_PID" =~ ^[0-9]+$ ]] && (( CCA_RUNNER_PID > 1 )) \
        && kill -0 -- "-$CCA_RUNNER_PID" 2>/dev/null; then
        if kill -TERM -- "-$CCA_RUNNER_PID" 2>/dev/null; then
            CCA_RUNNER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$CCA_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$CCA_RUNNER_PID" =~ ^[0-9]+$ ]] && (( CCA_RUNNER_PID > 1 )) \
        && kill -0 -- "-$CCA_RUNNER_PID" 2>/dev/null; then
        if kill -KILL -- "-$CCA_RUNNER_PID" 2>/dev/null; then
            CCA_RUNNER_KILL=true
            : > "$CCA_RUNNER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$CCA_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$CCA_RUNNER_PID" =~ ^[0-9]+$ ]] && (( CCA_RUNNER_PID > 1 )) \
        && kill -0 -- "-$CCA_RUNNER_PID" 2>/dev/null; then
        CCA_RUNNER_STOPPED=false
    else
        CCA_RUNNER_STOPPED=true
        if [[ "$CCA_RUNNER_PID" =~ ^[0-9]+$ ]] && (( CCA_RUNNER_PID > 1 )); then
            wait "$CCA_RUNNER_PID" 2>/dev/null || true
        fi
    fi
}

stop_server() {
    local server_pid=${SCOUT_SERVER_PID:-0}
    if [[ "$server_pid" =~ ^[0-9]+$ ]] && (( server_pid > 1 )) \
        && kill -0 -- "-$server_pid" 2>/dev/null; then
        if kill -TERM -- "-$server_pid" 2>/dev/null; then
            CCA_SERVER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$server_pid" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$server_pid" =~ ^[0-9]+$ ]] && (( server_pid > 1 )) \
        && kill -0 -- "-$server_pid" 2>/dev/null; then
        if kill -KILL -- "-$server_pid" 2>/dev/null; then
            CCA_SERVER_KILL=true
            : > "$CCA_SERVER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$server_pid" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$server_pid" =~ ^[0-9]+$ ]] && (( server_pid > 1 )) \
        && kill -0 -- "-$server_pid" 2>/dev/null; then
        CCA_SERVER_STOPPED=false
    else
        CCA_SERVER_STOPPED=true
        if [[ "$server_pid" =~ ^[0-9]+$ ]] && (( server_pid > 1 )); then
            wait "$server_pid" 2>/dev/null || true
        fi
    fi
}

terminal_cleanup() {
    local status=$?
    trap - EXIT TERM INT
    set +e
    [[ -n "$CCA_WATCHDOG_PID" ]] && kill "$CCA_WATCHDOG_PID" 2>/dev/null
    [[ -n "$CCA_WATCHDOG_PID" ]] && wait "$CCA_WATCHDOG_PID" 2>/dev/null
    stop_runner
    mkdir -p -- "$(dirname -- "$CCA_EXIT_FILE")"
    [[ -e "$CCA_EXIT_FILE" ]] || printf '%s\n' "$status" > "$CCA_EXIT_FILE"
    stop_server
    if [[ ! -e "$CCA_CLEANUP" ]]; then
        "$SCOUT_LAB_PYTHON" "$CCA_BATCH" cleanup \
            --output "$CCA_CLEANUP" --job-id "$SLURM_JOB_ID" \
            --server-pid "${SCOUT_SERVER_PID:-0}" --runner-pid "$CCA_RUNNER_PID" \
            --server-term "$CCA_SERVER_TERM" --server-kill "$CCA_SERVER_KILL" \
            --server-stopped "$CCA_SERVER_STOPPED" --runner-term "$CCA_RUNNER_TERM" \
            --runner-kill "$CCA_RUNNER_KILL" --runner-stopped "$CCA_RUNNER_STOPPED"
    fi
    if [[ ! -e "$CCA_FINAL" ]]; then
        if [[ -e "$CCA_PHASE" ]]; then
            "$SCOUT_LAB_PYTHON" "$CCA_BATCH" finalize \
                --output "$CCA_FINAL" --phase-path "$CCA_PHASE" \
                --pre-smoke-path "$CCA_PRE_SMOKE" --smoke-path "$SCOUT_RUN_DIR/smoke.json" \
                --native-path "$SCOUT_RUN_DIR/native-smoke.json" \
                --server-check-path "$CCA_SERVER_CHECK" --cleanup-path "$CCA_CLEANUP" \
                --runner-exit-path "$CCA_EXIT_FILE" --live-dir "$SCOUT_CONTENT_ARGUMENT_OUTPUT" \
                --job-id "$SLURM_JOB_ID" --expected-stdout "$SCOUT_CONTENT_ARGUMENT_STDOUT" \
                --expected-stderr "$SCOUT_CONTENT_ARGUMENT_STDERR"
        else
            write_pre_phase_terminal "$CCA_FINAL" \
                'nesi-scout-smoke-content-composition-argument-v1' \
                "${SCOUT_SMOKE_STAGE:-$CCA_WRAPPER_STAGE}" "$status" \
                "$SCOUT_RUN_DIR/smoke.json" "$SCOUT_RUN_DIR/native-smoke.json" \
                "$CCA_PRE_SMOKE" "$CCA_CLEANUP" "$CCA_EXIT_FILE" 42 50 true \
                "$SLURM_JOB_ID" "$SCOUT_CONTENT_ARGUMENT_STDOUT" \
                "$SCOUT_CONTENT_ARGUMENT_STDERR"
        fi
        [[ $? == 0 ]] || { [[ "$status" == 0 ]] && status=1; }
    fi
    unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY GROQ_API_KEY
    exit "$status"
}
trap terminal_cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT


# Generate and validate the exact request plan without transport before loading Scout.
CCA_WRAPPER_STAGE=plan_only
(cd -- "$CCA_BUNDLE_ROOT" && "$SCOUT_LAB_PYTHON" "$CCA_RUNNER" \
    --config "$CCA_CONFIG" --output "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR")
CCA_WRAPPER_STAGE=pre_smoke_validation
"$SCOUT_LAB_PYTHON" "$CCA_BATCH" validate \
    --output "$CCA_PRE_SMOKE" --bundle "$CCA_BUNDLE_ROOT" \
    --manifest "$CCA_MANIFEST" --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" \
    --site "$CCA_SITE_FILE" --site-sha256 "$CCA_SITE_SHA256" \
    --executed-wrapper "$CCA_EXECUTED_WRAPPER" --plan-dir "$SCOUT_CONTENT_ARGUMENT_PLAN_DIR" \
    --smoke-dir "$SCOUT_RUN_DIR" --live-dir "$SCOUT_CONTENT_ARGUMENT_OUTPUT" \
    --runner "$CCA_RUNNER" --config "$CCA_CONFIG" --job-id "$SLURM_JOB_ID" \
    --expected-stdout "$SCOUT_CONTENT_ARGUMENT_STDOUT" \
    --expected-stderr "$SCOUT_CONTENT_ARGUMENT_STDERR"

# Source the protocol-local smoke helper while this wrapper owns every terminal
# trap, including vLLM startup and both smoke gates. The shared frozen smoke
# wrapper remains byte-identical for queued and historical protocols.
export SCOUT_HPC_DIR="$CCA_HPC_DIR"
export SCOUT_NATIVE_SMOKE=1
export SCOUT_PORT=8000
export SCOUT_PROTOCOL_PARENT_OWNS_TRAPS=1
unset SCOUT_SITE_FILE SCOUT_SITE_SHA256
CCA_WRAPPER_STAGE=smoke
source "$CCA_HPC_DIR/scout-smoke-content-composition-base.bash"
if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then
    SCOUT_SERVER_PID=''
    exit 2
fi
export SCOUT_SERVER_PID
SCOUT_SMOKE_STAGE=''


# Require one exact current Slurm record and at least 8,400 seconds remaining.
CCA_WRAPPER_STAGE=phase_reservation
CCA_TIME_RECORD=''
if command -v squeue >/dev/null; then
    CCA_TIME_RECORD=$(squeue -h -j "$SLURM_JOB_ID" -o '%i|%L|%l' 2>/dev/null) || CCA_TIME_RECORD=''
fi
CCA_REPORTED_JOB=''
CCA_REMAINING=''
CCA_TIME_LIMIT=''
if [[ "$CCA_TIME_RECORD" != *$'\n'* ]]; then
    IFS='|' read -r CCA_REPORTED_JOB CCA_REMAINING CCA_TIME_LIMIT <<< "$CCA_TIME_RECORD"
fi
set +e
"$SCOUT_LAB_PYTHON" "$CCA_BATCH" reserve \
    --output "$CCA_PHASE" --pre-smoke "$CCA_PRE_SMOKE" \
    --bundle "$CCA_BUNDLE_ROOT" --manifest "$CCA_MANIFEST" \
    --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" --job-id "$SLURM_JOB_ID" \
    --reported-job-id "$CCA_REPORTED_JOB" --remaining "$CCA_REMAINING" \
    --time-limit "$CCA_TIME_LIMIT" --server-pid "$SCOUT_SERVER_PID"
CCA_GATE_STATUS=$?
set -e
if [[ "$CCA_GATE_STATUS" == 3 ]]; then
    printf '%s\n' 3 > "$CCA_EXIT_FILE"
    exit 3
fi
[[ "$CCA_GATE_STATUS" == 0 ]] || exit "$CCA_GATE_STATUS"

"$SCOUT_LAB_PYTHON" "$CCA_BATCH" server-check \
    --output "$CCA_SERVER_CHECK" --base-url 'http://127.0.0.1:8000/v1' \
    --server-pid "$SCOUT_SERVER_PID" --job-id "$SLURM_JOB_ID"

CCA_WRAPPER_STAGE=repeat_judge
set +e
cd -- "$CCA_BUNDLE_ROOT"
OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    setsid "$SCOUT_LAB_PYTHON" "$CCA_RUNNER" --config "$CCA_CONFIG" \
        --output "$SCOUT_CONTENT_ARGUMENT_OUTPUT" --live \
        > "$SCOUT_RUN_DIR/content-composition-argument-wrapper.log" 2>&1 &
CCA_RUNNER_PID=$!
CCA_RUNNER_STOPPED=false
(
    sleep 7800
    if kill -TERM -- "-$CCA_RUNNER_PID" 2>/dev/null; then
        : > "$SCOUT_RUN_DIR/content-composition-argument-watchdog-term"
        sleep 10
        if kill -KILL -- "-$CCA_RUNNER_PID" 2>/dev/null; then
            : > "$SCOUT_RUN_DIR/content-composition-argument-watchdog-kill"
        fi
    fi
) &
CCA_WATCHDOG_PID=$!
wait "$CCA_RUNNER_PID"
CCA_RUNNER_STATUS=$?
kill "$CCA_WATCHDOG_PID" 2>/dev/null || true
wait "$CCA_WATCHDOG_PID" 2>/dev/null || true
CCA_WATCHDOG_PID=''
[[ -e "$SCOUT_RUN_DIR/content-composition-argument-watchdog-term" ]] && CCA_RUNNER_TERM=true
[[ -e "$SCOUT_RUN_DIR/content-composition-argument-watchdog-kill" ]] && CCA_RUNNER_KILL=true
CCA_RUNNER_STOPPED=true
set -e
printf '%s\n' "$CCA_RUNNER_STATUS" > "$CCA_EXIT_FILE"
exit "$CCA_RUNNER_STATUS"
