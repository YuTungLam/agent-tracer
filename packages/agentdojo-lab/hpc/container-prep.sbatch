#!/usr/bin/env bash
#SBATCH --job-name=scout-container
#SBATCH --account=uoa04799
#SBATCH --partition=milan
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=01:00:00
#SBATCH --signal=B:TERM@60
#SBATCH --no-requeue
#SBATCH --output=scout-container-%j.log

# Public OCI download and SIF conversion only. No GPU allocation or model loading.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the private site configuration path}"
: "${SCOUT_PREP_EVIDENCE:?Set a fresh durable container-preparation evidence directory}"
source "$SCOUT_SITE_FILE"
: "${SCOUT_HPC_DIR:?Missing HPC script directory}"
: "${SCOUT_STORAGE_ROOT:?Missing scratch root}"
: "${VLLM_SIF:?Missing destination SIF path}"
: "${VLLM_OCI_REFERENCE:?Missing immutable image source}"
[[ "$VLLM_OCI_REFERENCE" == docker://vllm/vllm-openai@sha256:3e10e8189823e0f7ae4620c271bcdaaf64127ec7d0edc351591a508498b7684a ]] || exit 2
[[ "$VLLM_SIF" == "$SCOUT_STORAGE_ROOT/containers/"* && ! -e "$VLLM_SIF" ]] || exit 2
[[ ${SLURM_CPUS_PER_TASK:-0} == 8 ]] || exit 2
mkdir -p -- "$(dirname -- "$SCOUT_PREP_EVIDENCE")"
mkdir -- "$SCOUT_PREP_EVIDENCE"
trap 'status=$?; printf "%s\n" "$status" > "$SCOUT_PREP_EVIDENCE/job-exit-code.txt"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
export APPTAINER_CACHEDIR="$SCOUT_STORAGE_ROOT/cache/apptainer"
export APPTAINER_TMPDIR="$SCOUT_STORAGE_ROOT/tmp/container-prep-$SLURM_JOB_ID"
mkdir -p -- "$APPTAINER_CACHEDIR" "$(dirname -- "$VLLM_SIF")"
mkdir -- "$APPTAINER_TMPDIR"
SCOUT_PARTIAL_SIF="$VLLM_SIF.partial-$SLURM_JOB_ID"
export SCOUT_PARTIAL_SIF
apptainer --version > "$SCOUT_PREP_EVIDENCE/apptainer-version.txt"
sha256sum "$SCOUT_HPC_DIR/container-prep.sbatch" "$SCOUT_HPC_DIR/finalize_container.py" \
    > "$SCOUT_PREP_EVIDENCE/tooling-sha256.txt"
python3 - "$SCOUT_PREP_EVIDENCE/plan.json" <<'PY'
import json, os, sys
from datetime import datetime, timezone
data = {"protocol": "nesi-scout-container-prep-v1", "job_id": os.environ["SLURM_JOB_ID"],
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "source": os.environ["VLLM_OCI_REFERENCE"], "destination": os.environ["VLLM_SIF"],
        "partial": os.environ["SCOUT_PARTIAL_SIF"],
        "limits": {"cpus": 8, "memory_gib": 32, "walltime_minutes": 60,
                   "build_timeout_seconds": 3000, "mksquashfs_memory_gib": 8, "gpus": 0}}
with open(sys.argv[1], "x") as stream:
    json.dump(data, stream, indent=2)
    stream.write("\n")
PY

# No login CPU conversion. Explicit compressor bounds complement Slurm limits.
# Anonymous Docker Hub registry auth is handled by Apptainer, never echoed.
srun --cpu-bind=cores --kill-on-bad-exit=1 \
    env -u HF_TOKEN -u HUGGING_FACE_HUB_TOKEN -u GROQ_API_KEY -u LOCAL_LLM_API_KEY \
    timeout --signal=TERM --kill-after=30s 3000s \
    apptainer build --notest --arch amd64 --mksquashfs-args '-processors 8 -mem 8G' \
    "$SCOUT_PARTIAL_SIF" "$VLLM_OCI_REFERENCE" \
    > "$SCOUT_PREP_EVIDENCE/build.log" 2>&1
apptainer inspect --json "$SCOUT_PARTIAL_SIF" > "$SCOUT_PREP_EVIDENCE/image-metadata.json"
python3 "$SCOUT_HPC_DIR/finalize_container.py" --partial "$SCOUT_PARTIAL_SIF" \
    --destination "$VLLM_SIF" --site "$SCOUT_SITE_FILE" \
    --output "$SCOUT_PREP_EVIDENCE/completed.json"
