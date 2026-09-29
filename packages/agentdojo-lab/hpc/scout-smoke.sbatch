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
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
[[ ${SLURM_JOB_NUM_NODES:-0} == 1 ]] || { echo 'One node is required.' >&2; exit 2; }
# Read prepared pins at job start, including when queued behind preparation jobs.
if [[ -n ${SCOUT_SITE_FILE:-} ]]; then source "$SCOUT_SITE_FILE"; fi
SCOUT_NATIVE_SMOKE=${SCOUT_NATIVE_SMOKE:-0}
[[ "$SCOUT_NATIVE_SMOKE" == 0 || "$SCOUT_NATIVE_SMOKE" == 1 ]] || exit 2
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
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

"$SCOUT_PYTHON" "$SCOUT_HPC_DIR/preflight.py" --output "$SCOUT_RUN_DIR/preflight.json"
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
setsid "${SCOUT_CONTAINER[@]}" "${SCOUT_SERVE[@]}" > "$SCOUT_RUN_DIR/server.log" 2>&1 &
SCOUT_SERVER_PID=$!
"$SCOUT_PYTHON" "$SCOUT_HPC_DIR/smoke.py" --base-url "http://127.0.0.1:$SCOUT_PORT/v1" \
    --wait-seconds 1500 --server-pid "$SCOUT_SERVER_PID" --output "$SCOUT_RUN_DIR/smoke.json"
if [[ "$SCOUT_NATIVE_SMOKE" == 1 ]]; then
    # Submit this combined mode with --time=01:00:00. No online auditor or attack.
    OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
        HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
        timeout --signal=TERM --kill-after=10s 780s \
        "$SCOUT_LAB_PYTHON" "$SCOUT_HPC_DIR/native_smoke.py" \
        --base-url "http://127.0.0.1:$SCOUT_PORT/v1" \
        --serving-receipt "$SCOUT_RUN_DIR/preflight.json" \
        --output "$SCOUT_RUN_DIR/native-smoke.json" --run-dir "$SCOUT_RUN_DIR/native-run" \
        > "$SCOUT_RUN_DIR/native-wrapper.log" 2>&1
fi
