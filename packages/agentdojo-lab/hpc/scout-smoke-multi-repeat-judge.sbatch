#!/usr/bin/env bash
#SBATCH --job-name=scout-multi-rj
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
#SBATCH --output=scout-multi-rj-%j.log

# Start Scout, repeat both smoke gates, and run the 36-call multi-candidate repeat/judge
# protocol while the same authenticated loopback server and allocation live.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the absolute private multi-candidate repeat/judge site file}"
: "${SCOUT_SITE_SHA256:?Export its reviewed SHA-256 at submission}"
[[ "$SCOUT_SITE_FILE" == /* && -f "$SCOUT_SITE_FILE" && ! -L "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_SITE_FILE")" == "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$SCOUT_SITE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
MRJ_SITE_FILE="$SCOUT_SITE_FILE"
MRJ_SITE_SHA256="$SCOUT_SITE_SHA256"
readonly MRJ_SITE_FILE MRJ_SITE_SHA256
read -r MRJ_ACTUAL_SITE_SHA256 _ < <(sha256sum -- "$MRJ_SITE_FILE")
[[ "$MRJ_ACTUAL_SITE_SHA256" == "$MRJ_SITE_SHA256" ]] || exit 2
source "$MRJ_SITE_FILE"

: "${SCOUT_HPC_DIR:?Set the frozen hpc directory}"
: "${SCOUT_HPC_MANIFEST:?Set the frozen bundle checksum manifest}"
: "${SCOUT_HPC_MANIFEST_SHA256:?Set the reviewed manifest SHA-256}"
: "${SCOUT_LAB_PYTHON:?Set the Python 3.12 lab executable}"
: "${SCOUT_RUN_DIR:?Set a fresh smoke evidence directory}"
: "${SCOUT_MULTI_REPEAT_PLAN_DIR:?Set a fresh request-free plan directory}"
: "${SCOUT_MULTI_REPEAT_OUTPUT:?Set a fresh live multi-candidate repeat/judge directory}"
: "${SCOUT_MULTI_REPEAT_RUNNER:?Set the frozen multi-candidate repeat/judge runner}"
: "${SCOUT_MULTI_REPEAT_CONFIG:?Set the frozen multi-candidate repeat/judge config}"

MRJ_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")
MRJ_BUNDLE_ROOT=$(realpath -e -- "$MRJ_HPC_DIR/..")
MRJ_MANIFEST=$(realpath -e -- "$SCOUT_HPC_MANIFEST")
MRJ_CANONICAL_WRAPPER="$MRJ_HPC_DIR/scout-smoke-multi-repeat-judge.sbatch"
MRJ_BATCH="$MRJ_HPC_DIR/multi_repeat_judge_batch.py"
MRJ_RUNNER="$MRJ_BUNDLE_ROOT/scripts/run_scout_multi_repeat_judge.py"
MRJ_CONFIG="$MRJ_BUNDLE_ROOT/configs/scout_multi_repeat_judge_v1.json"
MRJ_EXECUTED_WRAPPER=$(realpath -e -- "${BASH_SOURCE[0]}")
readonly MRJ_HPC_DIR MRJ_BUNDLE_ROOT MRJ_MANIFEST MRJ_CANONICAL_WRAPPER MRJ_BATCH
readonly MRJ_RUNNER MRJ_CONFIG MRJ_EXECUTED_WRAPPER
[[ "$MRJ_HPC_DIR" == "$MRJ_BUNDLE_ROOT/hpc" ]] || exit 2
[[ "$MRJ_MANIFEST" == "$MRJ_BUNDLE_ROOT/submission-sha256.txt" ]] || exit 2
[[ "$SCOUT_HPC_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
read -r MRJ_ACTUAL_MANIFEST_SHA256 _ < <(sha256sum -- "$MRJ_MANIFEST")
[[ "$MRJ_ACTUAL_MANIFEST_SHA256" == "$SCOUT_HPC_MANIFEST_SHA256" ]] || exit 2
(cd -- "$MRJ_BUNDLE_ROOT" && sha256sum --check --strict --status submission-sha256.txt)
cmp --silent -- "$MRJ_EXECUTED_WRAPPER" "$MRJ_CANONICAL_WRAPPER" || exit 2
[[ "$SCOUT_MULTI_REPEAT_RUNNER" == "$MRJ_RUNNER" && "$SCOUT_MULTI_REPEAT_CONFIG" == "$MRJ_CONFIG" ]] || exit 2
[[ -x "$SCOUT_LAB_PYTHON" && -f "$MRJ_BATCH" && -f "$MRJ_RUNNER" && -f "$MRJ_CONFIG" \
    && -f "$MRJ_HPC_DIR/scout-smoke-content-composition-base.bash" ]] || exit 2
for path in "$SCOUT_RUN_DIR" "$SCOUT_MULTI_REPEAT_PLAN_DIR" "$SCOUT_MULTI_REPEAT_OUTPUT"; do
    [[ "$path" == /* && ! -e "$path" && ! -L "$path" ]] || exit 2
done
[[ "$SCOUT_RUN_DIR" != "$SCOUT_MULTI_REPEAT_PLAN_DIR" \
    && "$SCOUT_RUN_DIR" != "$SCOUT_MULTI_REPEAT_OUTPUT" \
    && "$SCOUT_MULTI_REPEAT_PLAN_DIR" != "$SCOUT_MULTI_REPEAT_OUTPUT" ]] || exit 2

export PYTHONPATH="$MRJ_BUNDLE_ROOT/vendor/agentdojo/src:$MRJ_BUNDLE_ROOT/src:$MRJ_BUNDLE_ROOT/scripts"
export PYTHONDONTWRITEBYTECODE=1
unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY GROQ_API_KEY
SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY=1
source "$MRJ_HPC_DIR/scout-smoke-content-composition-base.bash"
unset SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY
declare -F write_pre_phase_terminal >/dev/null || exit 2

MRJ_PRE_SMOKE="${SCOUT_RUN_DIR}.multi-repeat-judge-pre-smoke.json"
MRJ_PHASE="${SCOUT_RUN_DIR}.multi-repeat-judge-phase.json"
[[ ! -e "$MRJ_PRE_SMOKE" && ! -e "$MRJ_PHASE" ]] || exit 2
SCOUT_SERVER_PID=''
MRJ_RUNNER_PID=0
MRJ_RUNNER_STOPPED=true
MRJ_RUNNER_TERM=false
MRJ_RUNNER_KILL=false
MRJ_SERVER_TERM=false
MRJ_SERVER_KILL=false
MRJ_SERVER_STOPPED=false
MRJ_WATCHDOG_PID=''
MRJ_EXIT_FILE="$SCOUT_RUN_DIR/multi-repeat-judge-wrapper-exit-code.txt"
MRJ_SERVER_CHECK="$SCOUT_RUN_DIR/multi-repeat-judge-server-check.json"
MRJ_CLEANUP="$SCOUT_RUN_DIR/multi-repeat-judge-cleanup.json"
MRJ_FINAL="$SCOUT_RUN_DIR/multi-repeat-judge-batch-summary.json"
MRJ_RUNNER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/multi-repeat-judge-cleanup-runner-kill"
MRJ_SERVER_STOP_KILL_MARKER="$SCOUT_RUN_DIR/multi-repeat-judge-cleanup-server-kill"
MRJ_WRAPPER_STAGE=plan_only
SCOUT_SMOKE_STAGE=''

stop_runner() {
    if [[ "$MRJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( MRJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
        if kill -TERM -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
            MRJ_RUNNER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$MRJ_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$MRJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( MRJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
        if kill -KILL -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
            MRJ_RUNNER_KILL=true
            : > "$MRJ_RUNNER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$MRJ_RUNNER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$MRJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( MRJ_RUNNER_PID > 1 )) \
        && kill -0 -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
        MRJ_RUNNER_STOPPED=false
    else
        MRJ_RUNNER_STOPPED=true
        if [[ "$MRJ_RUNNER_PID" =~ ^[0-9]+$ ]] && (( MRJ_RUNNER_PID > 1 )); then
            wait "$MRJ_RUNNER_PID" 2>/dev/null || true
        fi
    fi
}

stop_server() {
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        if kill -TERM -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            MRJ_SERVER_TERM=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        if kill -KILL -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            MRJ_SERVER_KILL=true
            : > "$MRJ_SERVER_STOP_KILL_MARKER"
        fi
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )) \
        && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        MRJ_SERVER_STOPPED=false
    else
        MRJ_SERVER_STOPPED=true
        if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )); then
            wait "$SCOUT_SERVER_PID" 2>/dev/null || true
        fi
    fi
}

terminal_cleanup() {
    local status=$?
    trap - EXIT TERM INT
    set +e
    [[ -n "$MRJ_WATCHDOG_PID" ]] && kill "$MRJ_WATCHDOG_PID" 2>/dev/null
    [[ -n "$MRJ_WATCHDOG_PID" ]] && wait "$MRJ_WATCHDOG_PID" 2>/dev/null
    stop_runner
    mkdir -p -- "$(dirname -- "$MRJ_EXIT_FILE")"
    [[ -e "$MRJ_EXIT_FILE" ]] || printf '%s\n' "$status" > "$MRJ_EXIT_FILE"
    stop_server
    if [[ ! -e "$MRJ_CLEANUP" ]]; then
        "$SCOUT_LAB_PYTHON" "$MRJ_BATCH" cleanup \
            --output "$MRJ_CLEANUP" --job-id "$SLURM_JOB_ID" \
            --server-pid "${SCOUT_SERVER_PID:-0}" --runner-pid "$MRJ_RUNNER_PID" \
            --server-term "$MRJ_SERVER_TERM" --server-kill "$MRJ_SERVER_KILL" \
            --server-stopped "$MRJ_SERVER_STOPPED" --runner-term "$MRJ_RUNNER_TERM" \
            --runner-kill "$MRJ_RUNNER_KILL" --runner-stopped "$MRJ_RUNNER_STOPPED"
    fi
    if [[ ! -e "$MRJ_FINAL" ]]; then
        if [[ -e "$MRJ_PHASE" ]]; then
            "$SCOUT_LAB_PYTHON" "$MRJ_BATCH" finalize \
                --output "$MRJ_FINAL" --phase-path "$MRJ_PHASE" \
                --pre-smoke-path "$MRJ_PRE_SMOKE" --smoke-path "$SCOUT_RUN_DIR/smoke.json" \
                --native-path "$SCOUT_RUN_DIR/native-smoke.json" \
                --server-check-path "$MRJ_SERVER_CHECK" --cleanup-path "$MRJ_CLEANUP" \
                --runner-exit-path "$MRJ_EXIT_FILE" --live-dir "$SCOUT_MULTI_REPEAT_OUTPUT"
        else
            write_pre_phase_terminal "$MRJ_FINAL" \
                'nesi-scout-smoke-multi-repeat-judge-v1' \
                "${SCOUT_SMOKE_STAGE:-$MRJ_WRAPPER_STAGE}" "$status" \
                "$SCOUT_RUN_DIR/smoke.json" "$SCOUT_RUN_DIR/native-smoke.json" \
                "$MRJ_PRE_SMOKE" "$MRJ_CLEANUP" "$MRJ_EXIT_FILE" 36 44 false
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
MRJ_WRAPPER_STAGE=plan_only
(cd -- "$MRJ_BUNDLE_ROOT" && "$SCOUT_LAB_PYTHON" "$MRJ_RUNNER" \
    --config "$MRJ_CONFIG" --output "$SCOUT_MULTI_REPEAT_PLAN_DIR")
MRJ_WRAPPER_STAGE=pre_smoke_validation
"$SCOUT_LAB_PYTHON" "$MRJ_BATCH" validate \
    --output "$MRJ_PRE_SMOKE" --bundle "$MRJ_BUNDLE_ROOT" \
    --manifest "$MRJ_MANIFEST" --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" \
    --site "$MRJ_SITE_FILE" --site-sha256 "$MRJ_SITE_SHA256" \
    --executed-wrapper "$MRJ_EXECUTED_WRAPPER" --plan-dir "$SCOUT_MULTI_REPEAT_PLAN_DIR" \
    --smoke-dir "$SCOUT_RUN_DIR" --live-dir "$SCOUT_MULTI_REPEAT_OUTPUT" \
    --runner "$MRJ_RUNNER" --config "$MRJ_CONFIG"

# Keep this protocol's terminal trap installed throughout server startup and
# both smoke gates; the shared helper leaves the authenticated server alive.
export SCOUT_HPC_DIR="$MRJ_HPC_DIR"
export SCOUT_NATIVE_SMOKE=1
export SCOUT_PORT=8000
export SCOUT_PROTOCOL_PARENT_OWNS_TRAPS=1
unset SCOUT_SITE_FILE SCOUT_SITE_SHA256
MRJ_WRAPPER_STAGE=smoke
source "$MRJ_HPC_DIR/scout-smoke-content-composition-base.bash"
if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then
    SCOUT_SERVER_PID=''
    exit 2
fi
export SCOUT_SERVER_PID
SCOUT_SMOKE_STAGE=''

# Require one exact current Slurm record and at least 7,800 seconds remaining.
MRJ_WRAPPER_STAGE=phase_reservation
MRJ_TIME_RECORD=''
if command -v squeue >/dev/null; then
    MRJ_TIME_RECORD=$(squeue -h -j "$SLURM_JOB_ID" -o '%i|%L|%l' 2>/dev/null) || MRJ_TIME_RECORD=''
fi
MRJ_REPORTED_JOB=''
MRJ_REMAINING=''
MRJ_TIME_LIMIT=''
if [[ "$MRJ_TIME_RECORD" != *$'\n'* ]]; then
    IFS='|' read -r MRJ_REPORTED_JOB MRJ_REMAINING MRJ_TIME_LIMIT <<< "$MRJ_TIME_RECORD"
fi
set +e
"$SCOUT_LAB_PYTHON" "$MRJ_BATCH" reserve \
    --output "$MRJ_PHASE" --pre-smoke "$MRJ_PRE_SMOKE" \
    --bundle "$MRJ_BUNDLE_ROOT" --manifest "$MRJ_MANIFEST" \
    --manifest-sha256 "$SCOUT_HPC_MANIFEST_SHA256" --job-id "$SLURM_JOB_ID" \
    --reported-job-id "$MRJ_REPORTED_JOB" --remaining "$MRJ_REMAINING" \
    --time-limit "$MRJ_TIME_LIMIT" --server-pid "$SCOUT_SERVER_PID"
MRJ_GATE_STATUS=$?
set -e
if [[ "$MRJ_GATE_STATUS" == 3 ]]; then
    printf '%s\n' 3 > "$MRJ_EXIT_FILE"
    exit 3
fi
[[ "$MRJ_GATE_STATUS" == 0 ]] || exit "$MRJ_GATE_STATUS"

"$SCOUT_LAB_PYTHON" "$MRJ_BATCH" server-check \
    --output "$MRJ_SERVER_CHECK" --base-url 'http://127.0.0.1:8000/v1' \
    --server-pid "$SCOUT_SERVER_PID" --job-id "$SLURM_JOB_ID"

MRJ_WRAPPER_STAGE=repeat_judge
set +e
cd -- "$MRJ_BUNDLE_ROOT"
OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    setsid "$SCOUT_LAB_PYTHON" "$MRJ_RUNNER" --config "$MRJ_CONFIG" \
        --output "$SCOUT_MULTI_REPEAT_OUTPUT" --live \
        > "$SCOUT_RUN_DIR/multi-repeat-judge-wrapper.log" 2>&1 &
MRJ_RUNNER_PID=$!
MRJ_RUNNER_STOPPED=false
(
    sleep 7200
    if kill -TERM -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
        : > "$SCOUT_RUN_DIR/multi-repeat-judge-watchdog-term"
        sleep 10
        if kill -KILL -- "-$MRJ_RUNNER_PID" 2>/dev/null; then
            : > "$SCOUT_RUN_DIR/multi-repeat-judge-watchdog-kill"
        fi
    fi
) &
MRJ_WATCHDOG_PID=$!
wait "$MRJ_RUNNER_PID"
MRJ_RUNNER_STATUS=$?
kill "$MRJ_WATCHDOG_PID" 2>/dev/null || true
wait "$MRJ_WATCHDOG_PID" 2>/dev/null || true
MRJ_WATCHDOG_PID=''
[[ -e "$SCOUT_RUN_DIR/multi-repeat-judge-watchdog-term" ]] && MRJ_RUNNER_TERM=true
[[ -e "$SCOUT_RUN_DIR/multi-repeat-judge-watchdog-kill" ]] && MRJ_RUNNER_KILL=true
MRJ_RUNNER_STOPPED=true
set -e
printf '%s\n' "$MRJ_RUNNER_STATUS" > "$MRJ_EXIT_FILE"
exit "$MRJ_RUNNER_STATUS"
