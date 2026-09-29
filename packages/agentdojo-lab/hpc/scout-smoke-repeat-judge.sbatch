#!/usr/bin/env bash
#SBATCH --job-name=scout-repeat-judge
#SBATCH --account=uoa04799
#SBATCH --partition=milan
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gpus-per-node=a100:4
#SBATCH --cpus-per-task=48
#SBATCH --mem=320G
#SBATCH --time=02:00:00
#SBATCH --signal=B:TERM@60
#SBATCH --no-requeue
#SBATCH --output=scout-repeat-judge-%j.log

# Start Scout, repeat both smoke gates, and run the nine-call repeat/judge
# protocol while the same authenticated loopback server and allocation live.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the absolute private repeat/judge site file}"
: "${SCOUT_SITE_SHA256:?Export its reviewed SHA-256 at submission}"
[[ "$SCOUT_SITE_FILE" == /* && -f "$SCOUT_SITE_FILE" && ! -L "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_SITE_FILE")" == "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$SCOUT_SITE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
RJ_SITE_FILE="$SCOUT_SITE_FILE"
RJ_SITE_SHA256="$SCOUT_SITE_SHA256"
readonly RJ_SITE_FILE RJ_SITE_SHA256
read -r RJ_ACTUAL_SITE_SHA256 _ < <(sha256sum -- "$RJ_SITE_FILE")
[[ "$RJ_ACTUAL_SITE_SHA256" == "$RJ_SITE_SHA256" ]] || exit 2
source "$RJ_SITE_FILE"

: "${SCOUT_HPC_DIR:?Set the frozen hpc directory}"
: "${SCOUT_HPC_MANIFEST:?Set the frozen bundle checksum manifest}"
: "${SCOUT_HPC_MANIFEST_SHA256:?Set the reviewed manifest SHA-256}"
: "${SCOUT_LAB_PYTHON:?Set the Python 3.12 lab executable}"
: "${SCOUT_RUN_DIR:?Set a fresh smoke evidence directory}"
: "${SCOUT_REPEAT_PLAN_DIR:?Set a fresh request-free plan directory}"
: "${SCOUT_REPEAT_OUTPUT:?Set a fresh live repeat/judge directory}"
: "${SCOUT_REPEAT_RUNNER:?Set the frozen repeat/judge runner}"
: "${SCOUT_REPEAT_CONFIG:?Set the frozen repeat/judge config}"

RJ_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")
RJ_BUNDLE_ROOT=$(realpath -e -- "$RJ_HPC_DIR/..")
RJ_MANIFEST=$(realpath -e -- "$SCOUT_HPC_MANIFEST")
RJ_CANONICAL_WRAPPER="$RJ_HPC_DIR/scout-smoke-repeat-judge.sbatch"
RJ_BATCH="$RJ_HPC_DIR/repeat_judge_batch.py"
RJ_RUNNER="$RJ_BUNDLE_ROOT/scripts/run_scout_repeat_judge.py"
RJ_CONFIG="$RJ_BUNDLE_ROOT/configs/scout_repeat_judge_v1.json"
RJ_EXECUTED_WRAPPER=$(realpath -e -- "${BASH_SOURCE[0]}")
readonly RJ_HPC_DIR RJ_BUNDLE_ROOT RJ_MANIFEST RJ_CANONICAL_WRAPPER RJ_BATCH
readonly RJ_RUNNER RJ_CONFIG RJ_EXECUTED_WRAPPER
[[ "$RJ_HPC_DIR" == "$RJ_BUNDLE_ROOT/hpc" ]] || exit 2
[[ "$RJ_MANIFEST" == "$RJ_BUNDLE_ROOT/submission-sha256.txt" ]] || exit 2
[[ "$SCOUT_HPC_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
read -r RJ_ACTUAL_MANIFEST_SHA256 _ < <(sha256sum -- "$RJ_MANIFEST")
[[ "$RJ_ACTUAL_MANIFEST_SHA256" == "$SCOUT_HPC_MANIFEST_SHA256" ]] || exit 2
(cd -- "$RJ_BUNDLE_ROOT" && sha256sum --check --strict --status submission-sha256.txt)
cmp --silent -- "$RJ_EXECUTED_WRAPPER" "$RJ_CANONICAL_WRAPPER" || exit 2
[[ "$SCOUT_REPEAT_RUNNER" == "$RJ_RUNNER" && "$SCOUT_REPEAT_CONFIG" == "$RJ_CONFIG" ]] || exit 2
[[ -x "$SCOUT_LAB_PYTHON" && -f "$RJ_BATCH" && -f "$RJ_RUNNER" && -f "$RJ_CONFIG" \
    && -f "$RJ_HPC_DIR/scout-smoke-content-composition-base.bash" ]] || exit 2
for path in "$SCOUT_RUN_DIR" "$SCOUT_REPEAT_PLAN_DIR" "$SCOUT_REPEAT_OUTPUT"; do
    [[ "$path" == /* && ! -e "$path" && ! -L "$path" ]] || exit 2
done
[[ "$SCOUT_RUN_DIR" != "$SCOUT_REPEAT_PLAN_DIR" \
    && "$SCOUT_RUN_DIR" != "$SCOUT_REPEAT_OUTPUT" \
    && "$SCOUT_REPEAT_PLAN_DIR" != "$SCOUT_REPEAT_OUTPUT" ]] || exit 2

export PYTHONPATH="$RJ_BUNDLE_ROOT/vendor/agentdojo/src:$RJ_BUNDLE_ROOT/src:$RJ_BUNDLE_ROOT/scripts"
export PYTHONDONTWRITEBYTECODE=1
unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY GROQ_API_KEY
SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY=1
source "$RJ_HPC_DIR/scout-smoke-content-composition-base.bash"
unset SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY
declare -F write_pre_phase_terminal >/dev/null || exit 2

RJ_PRE_SMOKE="${SCOUT_RUN_DIR}.repeat-judge-pre-smoke.json"
RJ_PHASE="${SCOUT_RUN_DIR}.repeat-judge-phase.json"
[[ ! -e "$RJ_PRE_SMOKE" && ! -e "$RJ_PHASE" ]] || exit 2
SCOUT_SERVER_PID=''
RJ_RUNNER_PID=0
RJ_RUNNER_STOPPED=true
RJ_RUNNER_TERM=false
RJ_RUNNER_KILL=false
RJ_SERVER_TERM=false
RJ_SERVER_KILL=false
RJ_SERVER_STOPPED=false
RJ_WATCHDOG_PID=''
RJ_EXIT_FILE="$SCOUT_RUN_DIR/repeat-judge-wrapper-exit-code.txt"
RJ_SERVER_CHECK="$SCOUT_RUN_DIR/repeat-judge-server-check.json"
RJ_CLEANUP="$SCOUT_RUN_DIR/repeat-judge-cleanup.json"
RJ_FINAL="$SCOUT_RUN_DIR/repeat-judge-batch-summary.json"
RJ_RUNNER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/repeat-judge-cleanup-runner-kill"
RJ_SERVER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/repeat-judge-cleanup-server-kill"
RJ_WRAPPER_STAGE=plan_only
SCOUT_SMOKE_STAGE=''

stop_runner() {
    if [[ "$RJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( RJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$RJ_RUNNER_PID" 2>/dev/null; then
        if kill -TERM -- "-$RJ_RUNNER_PID" 2>/dev/null; then
            RJ_RUNNER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$RJ_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$RJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( RJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$RJ_RUNNER_PID" 2>/dev/null; then
        if kill -KILL -- "-$RJ_RUNNER_PID" 2>/dev/null; then
            RJ_RUNNER_KILL=true
            : > "$RJ_RUNNER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$RJ_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$RJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( RJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$RJ_RUNNER_PID" 2>/dev/null; then
        RJ_RUNNER_STOPPED=false
    else
        RJ_RUNNER_STOPPED=true
        if [[ "$RJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( RJ_RUNNER_PID > 1 )); then
            wait "$RJ_RUNNER_PID" 2>/dev/null || true
        fi
    fi
}

stop_server() {
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        if kill -TERM -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            RJ_SERVER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        if kill -KILL -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            RJ_SERVER_KILL=true
            : > "$RJ_SERVER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        RJ_SERVER_STOPPED=false
    else
        RJ_SERVER_STOPPED=true
        if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )); then
            wait "$SCOUT_SERVER_PID" 2>/dev/null || true
        fi
    fi
}

terminal_cleanup() {
    local status=$?
    trap - EXIT TERM INT
    set +e
    [[ -n "$RJ_WATCHDOG_PID" ]] && kill "$RJ_WATCHDOG_PID" 2>/dev/null
    [[ -n "$RJ_WATCHDOG_PID" ]] && wait "$RJ_WATCHDOG_PID" 2>/dev/null
    stop_runner
    mkdir -p -- "$(dirname -- "$RJ_EXIT_FILE")"
    [[ -e "$RJ_EXIT_FILE" ]] || printf '%s\n' "$status" > "$RJ_EXIT_FILE"
    stop_server
    if [[ ! -e "$RJ_CLEANUP" ]]; then
        "$SCOUT_LAB_PYTHON" "$RJ_BATCH" cleanup \
            --output "$RJ_CLEANUP" --job-id "$SLURM_JOB_ID" \
            --server-pid "${SCOUT_SERVER_PID:-0}" --runner-pid "$RJ_RUNNER_PID" \
            --server-term "$RJ_SERVER_TERM" --server-kill "$RJ_SERVER_KILL" \
            --server-stopped "$RJ_SERVER_STOPPED" --runner-term "$RJ_RUNNER_TERM" \
            --runner-kill "$RJ_RUNNER_KILL" --runner-stopped "$RJ_RUNNER_STOPPED"
    fi
    if [[ ! -e "$RJ_FINAL" ]]; then
        if [[ -e "$RJ_PHASE" ]]; then
            "$SCOUT_LAB_PYTHON" "$RJ_BATCH" finalize \
                --output "$RJ_FINAL" --phase-path "$RJ_PHASE" \
                --pre-smoke-path "$RJ_PRE_SMOKE" --smoke-path "$SCOUT_RUN_DIR/smoke.json" \
                --native-path "$SCOUT_RUN_DIR/native-smoke.json" \
                --server-check-path "$RJ_SERVER_CHECK" --cleanup-path "$RJ_CLEANUP" \
                --runner-exit-path "$RJ_EXIT_FILE" --live-dir "$SCOUT_REPEAT_OUTPUT"
        else
            write_pre_phase_terminal "$RJ_FINAL" \
                'nesi-scout-smoke-repeat-judge-v1' \
                "${SCOUT_SMOKE_STAGE:-$RJ_WRAPPER_STAGE}" "$status" \
                "$SCOUT_RUN_DIR/smoke.json" "$SCOUT_RUN_DIR/native-smoke.json" \
                "$RJ_PRE_SMOKE" "$RJ_CLEANUP" "$RJ_EXIT_FILE" 9 17 false
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
RJ_WRAPPER_STAGE=plan_only
(cd -- "$RJ_BUNDLE_ROOT" && "$SCOUT_LAB_PYTHON" "$RJ_RUNNER" \
    --config "$RJ_CONFIG" --output "$SCOUT_REPEAT_PLAN_DIR")
RJ_WRAPPER_STAGE=pre_smoke_validation
"$SCOUT_LAB_PYTHON" "$RJ_BATCH" validate \
    --output "$RJ_PRE_SMOKE" --bundle "$RJ_BUNDLE_ROOT" \
    --manifest "$RJ_MANIFEST" --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" \
    --site "$RJ_SITE_FILE" --site-sha256 "$RJ_SITE_SHA256" \
    --executed-wrapper "$RJ_EXECUTED_WRAPPER" --plan-dir "$SCOUT_REPEAT_PLAN_DIR" \
    --smoke-dir "$SCOUT_RUN_DIR" --live-dir "$SCOUT_REPEAT_OUTPUT" \
    --runner "$RJ_RUNNER" --config "$RJ_CONFIG"

# Keep this protocol's terminal trap installed throughout server startup and
# both smoke gates; the shared helper leaves the authenticated server alive.
export SCOUT_HPC_DIR="$RJ_HPC_DIR"
export SCOUT_NATIVE_SMOKE=1
export SCOUT_PORT=8000
export SCOUT_PROTOCOL_PARENT_OWNS_TRAPS=1
unset SCOUT_SITE_FILE SCOUT_SITE_SHA256
RJ_WRAPPER_STAGE=smoke
source "$RJ_HPC_DIR/scout-smoke-content-composition-base.bash"
if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then
    SCOUT_SERVER_PID=''
    exit 2
fi
export SCOUT_SERVER_PID
SCOUT_SMOKE_STAGE=''

# Require one exact current Slurm record and at least 3,900 seconds remaining.
RJ_WRAPPER_STAGE=phase_reservation
RJ_TIME_RECORD=''
if command -v squeue >/dev/null; then
    RJ_TIME_RECORD=$(squeue -h -j "$SLURM_JOB_ID" -o '%i|%L|%l' 2>/dev/null) || RJ_TIME_RECORD=''
fi
RJ_REPORTED_JOB=''
RJ_REMAINING=''
RJ_TIME_LIMIT=''
if [[ "$RJ_TIME_RECORD" != *$'\n'* ]]; then
    IFS='|' read -r RJ_REPORTED_JOB RJ_REMAINING RJ_TIME_LIMIT <<< "$RJ_TIME_RECORD"
fi
set +e
"$SCOUT_LAB_PYTHON" "$RJ_BATCH" reserve \
    --output "$RJ_PHASE" --pre-smoke "$RJ_PRE_SMOKE" \
    --bundle "$RJ_BUNDLE_ROOT" --manifest "$RJ_MANIFEST" \
    --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" --job-id "$SLURM_JOB_ID" \
    --reported-job-id "$RJ_REPORTED_JOB" --remaining "$RJ_REMAINING" \
    --time-limit "$RJ_TIME_LIMIT" --server-pid "$SCOUT_SERVER_PID"
RJ_GATE_STATUS=$?
set -e
if [[ "$RJ_GATE_STATUS" == 3 ]]; then
    printf '%s\n' 3 > "$RJ_EXIT_FILE"
    exit 3
fi
[[ "$RJ_GATE_STATUS" == 0 ]] || exit "$RJ_GATE_STATUS"

"$SCOUT_LAB_PYTHON" "$RJ_BATCH" server-check \
    --output "$RJ_SERVER_CHECK" --base-url 'http://127.0.0.1:8000/v1' \
    --server-pid "$SCOUT_SERVER_PID" --job-id "$SLURM_JOB_ID"

RJ_WRAPPER_STAGE=repeat_judge
set +e
cd -- "$RJ_BUNDLE_ROOT"
OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    setsid "$SCOUT_LAB_PYTHON" "$RJ_RUNNER" --config "$RJ_CONFIG" \
        --output "$SCOUT_REPEAT_OUTPUT" --live \
        > "$SCOUT_RUN_DIR/repeat-judge-wrapper.log" 2>&1 &
RJ_RUNNER_PID=$!
RJ_RUNNER_STOPPED=false
(
    sleep 3600
    if kill -TERM -- "-$RJ_RUNNER_PID" 2>/dev/null; then
        : > "$SCOUT_RUN_DIR/repeat-judge-watchdog-term"
        sleep 10
        if kill -KILL -- "-$RJ_RUNNER_PID" 2>/dev/null; then
            : > "$SCOUT_RUN_DIR/repeat-judge-watchdog-kill"
        fi
    fi
) &
RJ_WATCHDOG_PID=$!
wait "$RJ_RUNNER_PID"
RJ_RUNNER_STATUS=$?
kill "$RJ_WATCHDOG_PID" 2>/dev/null || true
wait "$RJ_WATCHDOG_PID" 2>/dev/null || true
RJ_WATCHDOG_PID=''
[[ -e "$SCOUT_RUN_DIR/repeat-judge-watchdog-term" ]] && RJ_RUNNER_TERM=true
[[ -e "$SCOUT_RUN_DIR/repeat-judge-watchdog-kill" ]] && RJ_RUNNER_KILL=true
RJ_RUNNER_STOPPED=true
set -e
printf '%s\n' "$RJ_RUNNER_STATUS" > "$RJ_EXIT_FILE"
exit "$RJ_RUNNER_STATUS"
