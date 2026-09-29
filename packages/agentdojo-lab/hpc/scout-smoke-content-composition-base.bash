#!/usr/bin/env bash
#SBATCH --job-name=scout-smoke
#SBATCH --account=uoa04799
#SBATCH --partition=milan
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --gpus-per-node=a100:4
#SBATCH --cpus-per-task=48
#SBATCH --mem=320G
#SBATCH --time=00:45:00
#SBATCH --signal=B:TERM@60
#SBATCH --no-requeue
#SBATCH --output=scout-smoke-%j.log

# Submit from this directory; required inputs and offline checks are in README.md.
write_pre_phase_terminal() {
    local output=$1
    local protocol=$2
    local failure_stage=$3
    local wrapper_status=$4
    local smoke_path=$5
    local native_path=$6
    local pre_smoke_path=$7
    local cleanup_path=$8
    local exit_path=$9
    local repeat_limit=${10}
    local total_limit=${11}
    local content_argument=${12}
    local job_id=${13:-}
    local expected_stdout=${14:-}
    local expected_stderr=${15:-}
    "$SCOUT_LAB_PYTHON" - "$output" "$protocol" "$failure_stage" "$wrapper_status" \
        "$smoke_path" "$native_path" "$pre_smoke_path" "$cleanup_path" "$exit_path" \
        "$repeat_limit" "$total_limit" "$content_argument" "$job_id" \
        "$expected_stdout" "$expected_stderr" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    output_raw,
    protocol,
    stage,
    exit_raw,
    smoke_raw,
    native_raw,
    pre_smoke_raw,
    cleanup_raw,
    exit_path_raw,
    repeat_limit_raw,
    total_limit_raw,
    content_argument_raw,
    job_id,
    stdout_raw,
    stderr_raw,
) = sys.argv[1:]

output = Path(output_raw)
smoke_path = Path(smoke_raw)
native_path = Path(native_raw)
repeat_limit = int(repeat_limit_raw)
total_limit = int(total_limit_raw)


def request_count(path, field, limit, *, rows_field=None):
    if not os.path.lexists(path):
        return 0
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    count = value.get(field) if isinstance(value, dict) else None
    if type(count) is not int or not 0 <= count <= limit:
        return None
    if rows_field is not None:
        rows = value.get(rows_field)
        if not isinstance(rows, list) or len(rows) != count:
            return None
    return count


def receipt(path):
    if path.is_symlink() or not path.is_file():
        return None
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


synthetic = request_count(smoke_path, "requests_started", 4, rows_field="requests")
native = request_count(native_path, "native_requests_started", 4)
total = synthetic + native if type(synthetic) is int and type(native) is int else None
paths = {
    "pre_smoke": Path(pre_smoke_raw),
    "smoke": smoke_path,
    "native": native_path,
    "cleanup": Path(cleanup_raw),
    "runner_exit": Path(exit_path_raw),
}
artifacts = {name: item for name, path in paths.items() if (item := receipt(path)) is not None}
value = {
    "protocol": protocol,
    "status": "terminal_before_repeat_judge_phase",
    "wrapper_exit_code": int(exit_raw),
    "failure": {
        "stage": stage,
        "error_type": "WrapperStageFailure",
        "message": f"Wrapper exited during {stage} before repeat/judge phase reservation",
    },
    "limits": {
        "synthetic_requests": 4,
        "native_requests": 4,
        "repeat_judge_requests": repeat_limit,
        "total_generation_requests": total_limit,
    },
    "requests": {
        "synthetic": synthetic,
        "native": native,
        "repeat": 0,
        "total": total,
        "limit": total_limit,
        "accounting_complete": total is not None,
    },
    "scientific_outcome": {
        "started": False,
        "complete": False,
        "reason": "wrapper_failed_before_repeat_judge_phase",
    },
    "artifacts": artifacts,
}
if content_argument_raw == "true":
    combination = (
        "Combine this second-task-family panel prospectively with the independently frozen "
        "conditional_action panel before assessing supervisor item 13."
    )
    value.update(
        scheduler_io_binding={
            "reported_job_id": job_id,
            "expected_stdout": stdout_raw,
            "expected_stderr": stderr_raw,
            "authoritative_scontrol_recheck_completed": False,
        },
        item_13_status="not_established_by_this_protocol_alone",
        standalone_item_13_claim_permitted=False,
        combination_requirement=combination,
    )
    value["scientific_outcome"].update(
        all_slots_terminal=False,
        item_13_status="not_established_by_this_protocol_alone",
        standalone_item_13_claim_permitted=False,
        combination_requirement=combination,
    )
output.parent.mkdir(parents=True, exist_ok=True)
with output.open("xb") as stream:
    stream.write(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

if [[ ${SCOUT_SMOKE_HELPER_DEFINITIONS_ONLY:-0} == 1 ]]; then
    return 0
fi

set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
# Read prepared pins at job start, including when queued behind preparation jobs.
if [[ -n ${SCOUT_SITE_FILE:-} ]]; then source "$SCOUT_SITE_FILE"; fi
SCOUT_NATIVE_SMOKE=${SCOUT_NATIVE_SMOKE:-0}
[[ "$SCOUT_NATIVE_SMOKE" == 0 || "$SCOUT_NATIVE_SMOKE" == 1 ]] || exit 2
[[ ${SCOUT_PROTOCOL_PARENT_OWNS_TRAPS:-0} == 1 ]] || exit 2
declare -F terminal_cleanup >/dev/null || exit 2
: "${SCOUT_SNAPSHOT:?Set the predownloaded materialized Scout snapshot directory}"
: "${SCOUT_REVISION:?Set its exact Hugging Face commit revision}"
: "${SCOUT_CHAT_TEMPLATE:?Set the local matching vLLM chat template}"
: "${SCOUT_TEMPLATE_SHA256:?Set the previously recorded template SHA-256}"
: "${VLLM_SIF:?Set the prebuilt local Apptainer SIF path}"
: "${VLLM_SIF_SHA256:?Set the previously recorded SIF SHA-256}"
: "${SCOUT_RUN_DIR:?Set a fresh durable evidence directory}"
: "${SCOUT_MODEL_INTEGRITY:?Set the successful full-download integrity receipt}"

SCOUT_HPC_DIR=${SCOUT_HPC_DIR:-${SLURM_SUBMIT_DIR}}
SCOUT_PYTHON=${SCOUT_PYTHON:-python3}
SCOUT_CACHE_ROOT=${SCOUT_CACHE_ROOT:-/nesi/nobackup/uoa04799/dyu848/tool-output-lab/cache}
SCOUT_PORT=${SCOUT_PORT:-8000}
[[ "$SCOUT_PORT" =~ ^[0-9]+$ ]] && ((SCOUT_PORT >= 1024 && SCOUT_PORT <= 65535)) || exit 2
command -v apptainer >/dev/null
command -v setsid >/dev/null
command -v timeout >/dev/null
[[ -f "$SCOUT_HPC_DIR/smoke.py" && -f "$SCOUT_HPC_DIR/preflight.py" ]] || exit 2
SCOUT_LAB_PYTHON=${SCOUT_LAB_PYTHON:-$SCOUT_HPC_DIR/../.venv/bin/python}
if [[ "$SCOUT_NATIVE_SMOKE" == 1 ]]; then
    [[ -x "$SCOUT_LAB_PYTHON" && -f "$SCOUT_HPC_DIR/native_smoke.py" ]] || exit 2
fi
export SCOUT_NATIVE_SMOKE
mkdir -p -- "$(dirname -- "$SCOUT_RUN_DIR")"
mkdir -- "$SCOUT_RUN_DIR"
SCOUT_RUN_DIR=$(cd -- "$SCOUT_RUN_DIR" && pwd -P)
SCOUT_CACHE_ROOT=$(realpath -m -- "$SCOUT_CACHE_ROOT")
SCOUT_JOB_CACHE="$SCOUT_CACHE_ROOT/scout-smoke-$SLURM_JOB_ID"
mkdir -p -- "$SCOUT_JOB_CACHE"
mkdir -- "$SCOUT_JOB_CACHE/home"

SCOUT_SERVER_PID=''
cleanup() {
    local status=$?
    trap - EXIT TERM INT
    if [[ "$SCOUT_SERVER_PID" =~ ^[0-9]+$ ]] && (( SCOUT_SERVER_PID > 1 )); then
        kill -TERM -- "-$SCOUT_SERVER_PID" 2>/dev/null || true
        for _ in {1..10}; do
            kill -0 -- "-$SCOUT_SERVER_PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL -- "-$SCOUT_SERVER_PID" 2>/dev/null || true
        wait "$SCOUT_SERVER_PID" 2>/dev/null || true
    fi
    printf '%s\n' "$status" > "$SCOUT_RUN_DIR/job-exit-code.txt"
    unset LOCAL_LLM_API_KEY APPTAINERENV_VLLM_API_KEY
    exit "$status"
}
# The enclosing protocol installed terminal_cleanup before sourcing this helper.
# Do not replace it: preflight/server/smoke failures must flow through that
# protocol's terminal receipt.

SCOUT_SMOKE_STAGE=preflight
"$SCOUT_PYTHON" "$SCOUT_HPC_DIR/preflight.py" --output "$SCOUT_RUN_DIR/preflight.json"
SCOUT_SMOKE_STAGE=gpu_inventory
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv > "$SCOUT_RUN_DIR/gpus.csv"

# A new private key authenticates this local job only. Never pass an HF token.
LOCAL_LLM_API_KEY=$("$SCOUT_PYTHON" -c 'import secrets; print(secrets.token_hex(32))')
export LOCAL_LLM_API_KEY
export APPTAINERENV_VLLM_API_KEY="$LOCAL_LLM_API_KEY"
export APPTAINERENV_HF_HUB_OFFLINE=1 APPTAINERENV_TRANSFORMERS_OFFLINE=1
export APPTAINERENV_HF_HUB_DISABLE_TELEMETRY=1 APPTAINERENV_VLLM_NO_USAGE_STATS=1
export APPTAINERENV_HF_HOME=/scout-cache/hf APPTAINERENV_XDG_CACHE_HOME=/scout-cache/xdg
export APPTAINERENV_VLLM_CACHE_ROOT=/scout-cache/vllm
export APPTAINERENV_TRITON_CACHE_DIR=/scout-cache/triton
export APPTAINERENV_VLLM_ENGINE_READY_TIMEOUT_S=1500
export APPTAINERENV_OMP_NUM_THREADS=4
export APPTAINERENV_CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:?Missing allocated GPU visibility}"
unset APPTAINERENV_HF_TOKEN APPTAINERENV_HUGGING_FACE_HUB_TOKEN APPTAINERENV_GROQ_API_KEY

# Keep host IPC for tensor-parallel shared memory; --containall would isolate it.
SCOUT_CONTAINER=(apptainer exec --nv --cleanenv --no-eval
    --home "$SCOUT_JOB_CACHE/home:/scout-home" --pwd /scout-home
    --bind "$SCOUT_SNAPSHOT:/scout-model:ro"
    --bind "$SCOUT_CHAT_TEMPLATE:/scout-template.jinja:ro"
    --bind "$SCOUT_JOB_CACHE:/scout-cache"
    "$VLLM_SIF")
SCOUT_SMOKE_STAGE=container_runtime
timeout --signal=TERM --kill-after=10s 120s "${SCOUT_CONTAINER[@]}" python3 -c '
import importlib.metadata, json, sys, torch
version = importlib.metadata.version("vllm")
devices = [{"name": torch.cuda.get_device_name(i), "bytes": torch.cuda.get_device_properties(i).total_memory}
           for i in range(torch.cuda.device_count())]
print(json.dumps({"vllm": version, "torch": torch.__version__, "cuda": torch.version.cuda,
                  "python": sys.version, "devices": devices}, indent=2))
if version not in {"0.29.0", "0.29.0+cu129"} or torch.version.cuda != "12.9" or len(devices) != 4 or any("A100" not in d["name"] for d in devices):
    raise SystemExit("Expected vLLM 0.29.0 and four allocated A100 GPUs")
' > "$SCOUT_RUN_DIR/container-runtime.json"

SCOUT_SERVE=(vllm serve /scout-model --served-model-name llama-4-scout-local
    --host 127.0.0.1 --port "$SCOUT_PORT" --tensor-parallel-size 4 --dtype bfloat16
    --max-model-len 8192 --max-num-seqs 1 --gpu-memory-utilization 0.90
    --load-format safetensors --safetensors-load-strategy eager
    --enforce-eager --limit-mm-per-prompt '{"image":0}'
    --enable-auto-tool-choice --tool-call-parser llama4_pythonic
    --chat-template /scout-template.jinja --generation-config vllm)
printf '%q ' "${SCOUT_SERVE[@]}" > "$SCOUT_RUN_DIR/server-command.txt"
printf '\n' >> "$SCOUT_RUN_DIR/server-command.txt"
SCOUT_SMOKE_STAGE=server_startup
setsid "${SCOUT_CONTAINER[@]}" "${SCOUT_SERVE[@]}" > "$SCOUT_RUN_DIR/server.log" 2>&1 &
SCOUT_SERVER_PID=$!
SCOUT_SMOKE_STAGE=synthetic_smoke
"$SCOUT_PYTHON" "$SCOUT_HPC_DIR/smoke.py" --base-url "http://127.0.0.1:$SCOUT_PORT/v1" \
    --wait-seconds 1500 --server-pid "$SCOUT_SERVER_PID" --output "$SCOUT_RUN_DIR/smoke.json"
if [[ "$SCOUT_NATIVE_SMOKE" == 1 ]]; then
    # Submit this combined mode with --time=01:00:00. No online auditor or attack.
    SCOUT_SMOKE_STAGE=native_smoke
    OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
        HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
        timeout --signal=TERM --kill-after=10s 780s \
        "$SCOUT_LAB_PYTHON" "$SCOUT_HPC_DIR/native_smoke.py" \
        --base-url "http://127.0.0.1:$SCOUT_PORT/v1" \
        --serving-receipt "$SCOUT_RUN_DIR/preflight.json" \
        --output "$SCOUT_RUN_DIR/native-smoke.json" --run-dir "$SCOUT_RUN_DIR/native-run" \
        > "$SCOUT_RUN_DIR/native-wrapper.log" 2>&1
fi
SCOUT_SMOKE_STAGE=smoke_complete
