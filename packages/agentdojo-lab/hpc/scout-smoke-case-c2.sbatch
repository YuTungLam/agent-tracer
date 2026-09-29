#!/usr/bin/env bash
#SBATCH --job-name=scout-case-c2
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
#SBATCH --output=scout-case-c2-%j.log

# Repeat both smoke gates and then run the fixed Case C2 four-arm schedule while
# the same authenticated loopback server and Slurm allocation remain live.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the absolute private Case C2 site file}"
: "${SCOUT_SITE_SHA256:?Export the reviewed site-file SHA-256 at submission}"
[[ "$SCOUT_SITE_FILE" == /* && -f "$SCOUT_SITE_FILE" && ! -L "$SCOUT_SITE_FILE" ]] || exit 2
[[ "$SCOUT_SITE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
CASE_C2_SITE_FILE="$SCOUT_SITE_FILE"
CASE_C2_SITE_SHA256="$SCOUT_SITE_SHA256"
readonly CASE_C2_SITE_FILE CASE_C2_SITE_SHA256
read -r ACTUAL_SITE_SHA256 _ < <(sha256sum -- "$CASE_C2_SITE_FILE")
[[ "$ACTUAL_SITE_SHA256" == "$CASE_C2_SITE_SHA256" ]] || exit 2
source "$CASE_C2_SITE_FILE"

: "${SCOUT_HPC_DIR:?Set the canonical frozen helper directory in the site file}"
: "${SCOUT_HPC_MANIFEST:?Set the frozen helper checksum manifest in the site file}"
: "${SCOUT_HPC_MANIFEST_SHA256:?Set its reviewed SHA-256 in the site file}"
[[ "$SCOUT_HPC_DIR" == /* && "$SCOUT_HPC_MANIFEST" == /* ]] || exit 2
[[ "$SCOUT_HPC_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_HPC_DIR")" == "$SCOUT_HPC_DIR" ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_HPC_MANIFEST")" == "$SCOUT_HPC_MANIFEST" ]] || exit 2
CASE_C2_HPC_DIR=$(realpath -e -- "$SCOUT_HPC_DIR")
CASE_C2_BUNDLE_ROOT=$(realpath -e -- "$CASE_C2_HPC_DIR/..")
CASE_C2_HPC_MANIFEST=$(realpath -e -- "$SCOUT_HPC_MANIFEST")
CASE_C2_EXECUTED_WRAPPER=$(realpath -e -- "${BASH_SOURCE[0]}")
CASE_C2_CANONICAL_WRAPPER="$CASE_C2_HPC_DIR/scout-smoke-case-c2.sbatch"
CASE_C2_RUNNER="$CASE_C2_BUNDLE_ROOT/scripts/run_case_c2_scout.py"
CASE_C2_CHAT_TEMPLATE="$CASE_C2_HPC_DIR/tool_chat_template_llama4_pythonic_typed_v1.jinja"
CASE_C2_MANIFEST_SHA256="$SCOUT_HPC_MANIFEST_SHA256"
readonly CASE_C2_HPC_DIR CASE_C2_BUNDLE_ROOT CASE_C2_HPC_MANIFEST CASE_C2_EXECUTED_WRAPPER
readonly CASE_C2_CANONICAL_WRAPPER CASE_C2_RUNNER CASE_C2_CHAT_TEMPLATE CASE_C2_MANIFEST_SHA256
[[ "$CASE_C2_HPC_DIR" == "$CASE_C2_BUNDLE_ROOT/hpc" ]] || exit 2
[[ "$CASE_C2_HPC_MANIFEST" == "$CASE_C2_BUNDLE_ROOT/submission-sha256.txt" ]] || exit 2
read -r ACTUAL_MANIFEST_SHA256 _ < <(sha256sum -- "$CASE_C2_HPC_MANIFEST")
[[ "$ACTUAL_MANIFEST_SHA256" == "$CASE_C2_MANIFEST_SHA256" ]] || exit 2
(cd -- "$CASE_C2_BUNDLE_ROOT" && sha256sum --check --strict --status submission-sha256.txt)
cmp --silent -- "$CASE_C2_EXECUTED_WRAPPER" "$CASE_C2_CANONICAL_WRAPPER" || exit 2
: "${SCOUT_RUN_DIR:?Set a fresh smoke evidence directory in the new site file}"
: "${SCOUT_CASE_C2_DIR:?Set an existing pristine Case C2 preparation directory}"
: "${SCOUT_CASE_C2_RUNNER:?Set the absolute active run_case_c2_scout.py path}"
: "${SCOUT_LAB_PYTHON:?Set the lab Python 3.12 executable}"
: "${SCOUT_CHAT_TEMPLATE:?Set the pinned local Llama 4 chat template}"
[[ "$SCOUT_RUN_DIR" == /* && "$SCOUT_CASE_C2_DIR" == /* ]] || exit 2
[[ "$SCOUT_CASE_C2_RUNNER" == /* && "$SCOUT_LAB_PYTHON" == /* ]] || exit 2
[[ "$SCOUT_CHAT_TEMPLATE" == /* ]] || exit 2
[[ -x "$SCOUT_LAB_PYTHON" && -d "$SCOUT_CASE_C2_DIR" \
    && ! -L "$SCOUT_CASE_C2_DIR" ]] || exit 2
[[ "$(realpath -e -- "$SCOUT_CASE_C2_DIR")" == "$SCOUT_CASE_C2_DIR" ]] || exit 2
[[ "$SCOUT_CASE_C2_RUNNER" == "$CASE_C2_RUNNER" && -f "$CASE_C2_RUNNER" \
    && ! -L "$CASE_C2_RUNNER" ]] || exit 2
[[ "$SCOUT_CHAT_TEMPLATE" == "$CASE_C2_CHAT_TEMPLATE" && -f "$CASE_C2_CHAT_TEMPLATE" \
    && ! -L "$CASE_C2_CHAT_TEMPLATE" ]] || exit 2
export SCOUT_CHAT_TEMPLATE="$CASE_C2_CHAT_TEMPLATE"
for directory in "$CASE_C2_BUNDLE_ROOT" "$CASE_C2_HPC_DIR" \
    "$CASE_C2_BUNDLE_ROOT/configs" "$CASE_C2_BUNDLE_ROOT/scripts" \
    "$CASE_C2_BUNDLE_ROOT/src" \
    "$CASE_C2_BUNDLE_ROOT/src/agentdojo_lab" \
    "$CASE_C2_BUNDLE_ROOT/vendor/agentdojo/src" \
    "$CASE_C2_BUNDLE_ROOT/vendor/agentdojo/src/agentdojo"; do
    [[ -d "$directory" && ! -L "$directory" ]] || exit 2
    [[ "$(realpath -e -- "$directory")" == "$directory" ]] || exit 2
    [[ "$directory" == "$CASE_C2_BUNDLE_ROOT" \
        || "$directory" == "$CASE_C2_BUNDLE_ROOT/"* ]] || exit 2
done
export PYTHONPATH="$CASE_C2_BUNDLE_ROOT/vendor/agentdojo/src:$CASE_C2_BUNDLE_ROOT/src:$CASE_C2_BUNDLE_ROOT/scripts"
for helper in scout-smoke-case-c2.sbatch scout-smoke.sbatch case_c2_batch.py \
    case_a_batch.py preflight.py smoke.py native_smoke.py \
    tool_chat_template_llama4_pythonic_typed_v1.jinja; do
    [[ -f "$CASE_C2_HPC_DIR/$helper" ]] || exit 2
done
[[ -f "$SCOUT_CASE_C2_RUNNER" && -f "$CASE_C2_HPC_MANIFEST" \
    && -f "$CASE_C2_BUNDLE_ROOT/configs/local_scout.toml" ]] || exit 2

CASE_C2_RUNTIME_ARGS=(
    --runtime-source CASE-C2-SCOUT-V1.md "$CASE_C2_BUNDLE_ROOT/CASE-C2-SCOUT-V1.md"
    --runtime-source configs/case_c2_scout_v1.toml "$CASE_C2_BUNDLE_ROOT/configs/case_c2_scout_v1.toml"
    --runtime-source configs/local_scout.toml "$CASE_C2_BUNDLE_ROOT/configs/local_scout.toml"
    --runtime-source hpc/scout-smoke-case-c2.sbatch "$CASE_C2_HPC_DIR/scout-smoke-case-c2.sbatch"
    --runtime-source hpc/scout-smoke.sbatch "$CASE_C2_HPC_DIR/scout-smoke.sbatch"
    --runtime-source hpc/case_c2_batch.py "$CASE_C2_HPC_DIR/case_c2_batch.py"
    --runtime-source hpc/case_a_batch.py "$CASE_C2_HPC_DIR/case_a_batch.py"
    --runtime-source hpc/preflight.py "$CASE_C2_HPC_DIR/preflight.py"
    --runtime-source hpc/smoke.py "$CASE_C2_HPC_DIR/smoke.py"
    --runtime-source hpc/native_smoke.py "$CASE_C2_HPC_DIR/native_smoke.py"
    --runtime-source hpc/tool_chat_template_llama4_pythonic_typed_v1.jinja "$SCOUT_CHAT_TEMPLATE"
    --runtime-source scripts/run_case_c2_scout.py "$SCOUT_CASE_C2_RUNNER"
    --runtime-source scripts/run_case_c_scout.py "$CASE_C2_BUNDLE_ROOT/scripts/run_case_c_scout.py"
)

# Verify the complete plan and exact launch bytes before vLLM can start.
SCOUT_CASE_C2_PRE_SMOKE="${SCOUT_RUN_DIR}.case-c2-pre-smoke.json"
[[ "$SCOUT_CASE_C2_PRE_SMOKE" == /* && ! -e "$SCOUT_CASE_C2_PRE_SMOKE" ]] || exit 2
"$SCOUT_LAB_PYTHON" "$CASE_C2_HPC_DIR/case_c2_batch.py" validate \
    --output "$SCOUT_CASE_C2_PRE_SMOKE" --case-dir "$SCOUT_CASE_C2_DIR" \
    --smoke-dir "$SCOUT_RUN_DIR" --runner-path "$SCOUT_CASE_C2_RUNNER" \
    --site-path "$CASE_C2_SITE_FILE" --site-sha256 "$CASE_C2_SITE_SHA256" \
    --manifest-path "$CASE_C2_HPC_MANIFEST" \
    --manifest-sha256 "$CASE_C2_MANIFEST_SHA256" \
    --executed-wrapper-path "$CASE_C2_EXECUTED_WRAPPER" \
    "${CASE_C2_RUNTIME_ARGS[@]}"

# Successful sourcing returns with vLLM alive. Override its helper directory and
# discard the site-file pointer so it cannot source configuration a second time.
SCOUT_PORT=${SCOUT_PORT:-8000}
[[ "$SCOUT_PORT" == 8000 ]] || exit 2
export SCOUT_HPC_DIR="$CASE_C2_HPC_DIR"
export SCOUT_NATIVE_SMOKE=1
# C2 names the experiment; CASE_C_MODE selects the shared bounded smoke envelope.
export SCOUT_CASE_C2_MODE=1
export SCOUT_CASE_C_MODE=1
export SCOUT_CASE_C_DIR="$SCOUT_CASE_C2_DIR"
export SCOUT_CASE_C2_DIR
unset SCOUT_SITE_FILE SCOUT_SITE_SHA256
source "$CASE_C2_HPC_DIR/scout-smoke.sbatch"
if [[ ! ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] || (( SCOUT_SERVER_PID <= 1 )); then
    SCOUT_SERVER_PID=''
    exit 2
fi
[[ "$SCOUT_HPC_DIR" == "$CASE_C2_HPC_DIR" && "$SCOUT_NATIVE_SMOKE" == 1 \
    && "$SCOUT_CASE_C2_MODE" == 1 && "$SCOUT_CASE_C_MODE" == 1 \
    && "$SCOUT_PORT" == 8000 ]] || exit 2
export SCOUT_SERVER_PID

CASE_C2_PROCESS_PID=''
CASE_C2_LAUNCHED_PID=0
CASE_C2_PROCESS_STOPPED=true
CASE_C2_WATCHDOG_PID=''
CASE_C2_TERM_MARKER="$SCOUT_RUN_DIR/case-c2-term-sent"
CASE_C2_KILL_MARKER="$SCOUT_RUN_DIR/case-c2-kill-sent"

stop_case_process() {
    if [[ -n "$CASE_C2_PROCESS_PID" ]]; then
        if [[ "$CASE_C2_PROCESS_PID" =~ ^[0-9]+$ ]] && (( CASE_C2_PROCESS_PID > 1 )); then
            if kill -0 -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
                if kill -TERM -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
                    : > "$CASE_C2_TERM_MARKER"
                fi
                for _ in {1..10}; do
                    kill -0 -- "-$CASE_C2_PROCESS_PID" 2>/dev/null || break
                    sleep 1
                done
                if kill -0 -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
                    if kill -KILL -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
                        : > "$CASE_C2_KILL_MARKER"
                    fi
                fi
            fi
            wait "$CASE_C2_PROCESS_PID" 2>/dev/null || true
            if kill -0 -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
                CASE_C2_PROCESS_STOPPED=false
            else
                CASE_C2_PROCESS_STOPPED=true
            fi
        else
            CASE_C2_PROCESS_STOPPED=false
        fi
        CASE_C2_PROCESS_PID=''
    fi
}

stop_server_and_record() {
    [[ -e "$SCOUT_RUN_DIR/case-c2-cleanup.json" ]] && return
    local server_term=false server_kill=false server_stopped=true
    local recorded_server_pid=${SCOUT_SERVER_PID:-0}
    local valid_server_pid=false
    if [[ ${SCOUT_SERVER_PID:-} =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )); then
        valid_server_pid=true
    fi
    if $valid_server_pid && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        if kill -TERM -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            server_term=true
        fi
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
        if kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
            if kill -KILL -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
                server_kill=true
            fi
        fi
        wait "$SCOUT_SERVER_PID" 2>/dev/null || true
    fi
    if $valid_server_pid && kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null; then
        server_stopped=false
    elif ! $valid_server_pid; then
        server_stopped=false
    fi
    SCOUT_SERVER_PID=''
    local case_term=false case_kill=false
    [[ -e "$CASE_C2_TERM_MARKER" ]] && case_term=true
    [[ -e "$CASE_C2_KILL_MARKER" ]] && case_kill=true
    "$SCOUT_LAB_PYTHON" "$CASE_C2_HPC_DIR/case_c2_batch.py" cleanup \
        --output "$SCOUT_RUN_DIR/case-c2-cleanup.json" \
        --server-pid "$recorded_server_pid" --term-sent "$server_term" \
        --kill-sent "$server_kill" --stopped "$server_stopped" \
        --case-pid "$CASE_C2_LAUNCHED_PID" --case-term-sent "$case_term" \
        --case-kill-sent "$case_kill" --case-stopped "$CASE_C2_PROCESS_STOPPED" \
        --job-id "$SLURM_JOB_ID" || true
}

CASE_C2_FINALIZE_STATUS=1
finalize_terminal() {
    [[ -e "$SCOUT_RUN_DIR/case-c2-phase.json" ]] || return 0
    [[ -e "$SCOUT_RUN_DIR/case-c2-batch-summary.json" ]] && return
    set +e
    "$SCOUT_LAB_PYTHON" "$CASE_C2_HPC_DIR/case_c2_batch.py" finalize \
        --output "$SCOUT_RUN_DIR/case-c2-batch-summary.json" \
        --phase-path "$SCOUT_RUN_DIR/case-c2-phase.json" \
        --pre-smoke-path "$SCOUT_CASE_C2_PRE_SMOKE" \
        --runner-path "$SCOUT_CASE_C2_RUNNER" \
        --preflight-path "$SCOUT_RUN_DIR/preflight.json" \
        --smoke-path "$SCOUT_RUN_DIR/smoke.json" \
        --native-path "$SCOUT_RUN_DIR/native-smoke.json" \
        --case-summary-path "$SCOUT_CASE_C2_DIR/case-summary.json" \
        --case-plan-path "$SCOUT_CASE_C2_DIR/plan.json" \
        --execution-path "$SCOUT_CASE_C2_DIR/execution.json" \
        --wrapper-exit-path "$SCOUT_RUN_DIR/case-c2-wrapper-exit-code.txt" \
        --wrapper-sha256-path "$SCOUT_RUN_DIR/case-c2-wrapper-sha256.txt" \
        --server-check-path "$SCOUT_RUN_DIR/case-a-server-check.json" \
        --cleanup-path "$SCOUT_RUN_DIR/case-c2-cleanup.json"
    CASE_C2_FINALIZE_STATUS=$?
    set -e
}

case_c2_catch_cleanup() {
    local status=$?
    trap - EXIT TERM INT
    if [[ -n "$CASE_C2_WATCHDOG_PID" ]]; then
        kill "$CASE_C2_WATCHDOG_PID" 2>/dev/null || true
        wait "$CASE_C2_WATCHDOG_PID" 2>/dev/null || true
    fi
    stop_case_process
    if [[ -e "$SCOUT_RUN_DIR/case-c2-phase.json" && ! -e "$SCOUT_RUN_DIR/case-c2-wrapper-exit-code.txt" ]]; then
        printf '%s\n' "$status" > "$SCOUT_RUN_DIR/case-c2-wrapper-exit-code.txt"
    fi
    stop_server_and_record
    finalize_terminal
    printf '%s\n' "$status" > "$SCOUT_RUN_DIR/job-exit-code.txt"
    unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY
    exit "$status"
}
trap case_c2_catch_cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

CASE_C2_WRAPPER_SHA256="$SCOUT_RUN_DIR/case-c2-wrapper-sha256.txt"
declare -A CASE_C2_HASHED_PATHS=()
for input in "$CASE_C2_EXECUTED_WRAPPER" "$CASE_C2_SITE_FILE" \
    "$CASE_C2_CANONICAL_WRAPPER" "$CASE_C2_HPC_DIR/scout-smoke.sbatch" \
    "$CASE_C2_BUNDLE_ROOT/CASE-C2-SCOUT-V1.md" \
    "$CASE_C2_BUNDLE_ROOT/configs/case_c2_scout_v1.toml" \
    "$CASE_C2_BUNDLE_ROOT/configs/local_scout.toml" \
    "$CASE_C2_HPC_DIR/case_c2_batch.py" "$CASE_C2_HPC_DIR/case_a_batch.py" \
    "$CASE_C2_HPC_DIR/preflight.py" "$CASE_C2_HPC_DIR/smoke.py" \
    "$CASE_C2_HPC_DIR/native_smoke.py" "$SCOUT_CASE_C2_RUNNER" \
    "$CASE_C2_BUNDLE_ROOT/scripts/run_case_c_scout.py" \
    "$SCOUT_CHAT_TEMPLATE" "$CASE_C2_HPC_MANIFEST"; do
    input=$(realpath -e -- "$input")
    [[ -v 'CASE_C2_HASHED_PATHS[$input]' ]] && continue
    sha256sum -- "$input" >> "$CASE_C2_WRAPPER_SHA256"
    CASE_C2_HASHED_PATHS[$input]=1
done
readonly CASE_C2_WRAPPER_SHA256

# Missing, malformed, mismatched, over-two-hour, or sub-3,900-second scheduler
# evidence leaves all four Case C2 arms unstarted.
SCOUT_TIME_RECORD=''
if command -v squeue >/dev/null; then
    SCOUT_TIME_RECORD=$(squeue -h -j "$SLURM_JOB_ID" -o '%i|%L|%l' 2>/dev/null) || SCOUT_TIME_RECORD=''
fi
REPORTED_JOB_ID=''
REMAINING_TIME=''
TIME_LIMIT=''
if [[ "$SCOUT_TIME_RECORD" != *$'\n'* ]]; then
    IFS='|' read -r REPORTED_JOB_ID REMAINING_TIME TIME_LIMIT <<< "$SCOUT_TIME_RECORD"
fi

set +e
"$SCOUT_LAB_PYTHON" "$CASE_C2_HPC_DIR/case_c2_batch.py" reserve \
    --output "$SCOUT_RUN_DIR/case-c2-phase.json" \
    --job-id "$SLURM_JOB_ID" --reported-job-id "$REPORTED_JOB_ID" \
    --remaining "$REMAINING_TIME" --time-limit "$TIME_LIMIT" \
    --server-pid "$SCOUT_SERVER_PID" \
    --case-dir "$SCOUT_CASE_C2_DIR" --pre-smoke-path "$SCOUT_CASE_C2_PRE_SMOKE" \
    --runner-path "$SCOUT_CASE_C2_RUNNER" \
    --wrapper-sha256-path "$CASE_C2_WRAPPER_SHA256" "${CASE_C2_RUNTIME_ARGS[@]}"
CASE_C2_GATE_STATUS=$?
set -e
if [[ "$CASE_C2_GATE_STATUS" == 3 ]]; then
    printf '%s\n' 3 > "$SCOUT_RUN_DIR/case-c2-wrapper-exit-code.txt"
    stop_server_and_record
    finalize_terminal
    exit 3
fi
[[ "$CASE_C2_GATE_STATUS" == 0 ]] || exit "$CASE_C2_GATE_STATUS"

# Case C2's shared serving validator deliberately consumes this exact historical
# filename. The checked helper verifies authentication, PID, cgroup, host, and
# the current Slurm record without starting a generation request.
"$SCOUT_LAB_PYTHON" "$CASE_C2_HPC_DIR/case_a_batch.py" server-check \
    --output "$SCOUT_RUN_DIR/case-a-server-check.json" \
    --base-url "http://127.0.0.1:$SCOUT_PORT/v1" --server-pid "$SCOUT_SERVER_PID" \
    --job-id "$SLURM_JOB_ID"

set +e
OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    setsid "$SCOUT_LAB_PYTHON" "$SCOUT_CASE_C2_RUNNER" run "$SCOUT_CASE_C2_DIR" \
    --serving-receipt "$SCOUT_RUN_DIR/preflight.json" \
    > "$SCOUT_RUN_DIR/case-c2-wrapper.log" 2>&1 &
CASE_C2_PROCESS_PID=$!
CASE_C2_LAUNCHED_PID=$CASE_C2_PROCESS_PID
(
    sleep 3600
    if [[ "$CASE_C2_PROCESS_PID" =~ ^[0-9]+$ ]] && (( CASE_C2_PROCESS_PID > 1 )) \
        && kill -TERM -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
        : > "$CASE_C2_TERM_MARKER"
        sleep 10
        if kill -KILL -- "-$CASE_C2_PROCESS_PID" 2>/dev/null; then
            : > "$CASE_C2_KILL_MARKER"
        fi
    fi
) &
CASE_C2_WATCHDOG_PID=$!
wait "$CASE_C2_PROCESS_PID"
CASE_C2_WRAPPER_STATUS=$?
kill "$CASE_C2_WATCHDOG_PID" 2>/dev/null || true
wait "$CASE_C2_WATCHDOG_PID" 2>/dev/null || true
CASE_C2_WATCHDOG_PID=''
stop_case_process
set -e
printf '%s\n' "$CASE_C2_WRAPPER_STATUS" > "$SCOUT_RUN_DIR/case-c2-wrapper-exit-code.txt"

stop_server_and_record
finalize_terminal
[[ "$CASE_C2_WRAPPER_STATUS" == 0 ]] || exit "$CASE_C2_WRAPPER_STATUS"
exit "$CASE_C2_FINALIZE_STATUS"
