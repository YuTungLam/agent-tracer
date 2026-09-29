#!/usr/bin/env bash
#SBATCH --job-name=scout-container-v2
#SBATCH --account=uoa04799
#SBATCH --partition=genoa
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --gres=ssd
#SBATCH --time=02:00:00
#SBATCH --signal=B:TERM@60
#SBATCH --no-requeue
#SBATCH --output=scout-container-v2-%j.log

# A separately named retry: immutable OCI, SSD temporary files, gzip level 1.
# No model load or GPU. The original failed protocol and its files are retained.
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} ]] || { echo 'Use a Slurm allocation.' >&2; exit 2; }
: "${SCOUT_SITE_FILE:?Set the new private site configuration path}"
: "${SCOUT_PREP_EVIDENCE:?Set a fresh durable preparation evidence directory}"
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
stage() {
    python3 - "$SCOUT_PREP_EVIDENCE/stages.jsonl" "$1" <<'PY'
import json, sys
from datetime import datetime, timezone
with open(sys.argv[1], "a") as stream:
    stream.write(json.dumps({"stage": sys.argv[2], "utc": datetime.now(timezone.utc).isoformat()}) + "\n")
PY
}
stage preparation_started
# NeSI creates JOB_SCRATCH_DIR only for --gres=ssd. Refuse RAM/shared fallback.
: "${JOB_SCRATCH_DIR:?The requested per-job SSD was not supplied}"
[[ -d "$JOB_SCRATCH_DIR" && -w "$JOB_SCRATCH_DIR" ]] || exit 2
SCOUT_TMP_FS=$(stat -f -c %T -- "$JOB_SCRATCH_DIR")
[[ "$SCOUT_TMP_FS" != tmpfs && "$SCOUT_TMP_FS" != ramfs && "$SCOUT_TMP_FS" != nfs* && "$SCOUT_TMP_FS" != weka* ]] || exit 2
export SCOUT_TMP_FS
export APPTAINER_CACHEDIR="$SCOUT_STORAGE_ROOT/cache/apptainer"
export APPTAINER_TMPDIR="$JOB_SCRATCH_DIR/scout-container-v2-$SLURM_JOB_ID"
mkdir -p -- "$APPTAINER_CACHEDIR" "$(dirname -- "$VLLM_SIF")"
mkdir -- "$APPTAINER_TMPDIR"
export SCOUT_PARTIAL_SIF="$VLLM_SIF.partial-$SLURM_JOB_ID"
apptainer --version > "$SCOUT_PREP_EVIDENCE/apptainer-version.txt"
df -PT -- "$APPTAINER_TMPDIR" > "$SCOUT_PREP_EVIDENCE/temporary-filesystem.txt"
sha256sum "$SCOUT_HPC_DIR/container-prep-ssd-v2.sbatch" "$SCOUT_HPC_DIR/finalize_container.py" \
    > "$SCOUT_PREP_EVIDENCE/tooling-sha256.txt"
python3 - "$SCOUT_PREP_EVIDENCE/plan.json" <<'PY'
import json, os, shutil, sys
from datetime import datetime, timezone
free = shutil.disk_usage(os.environ["APPTAINER_TMPDIR"]).free
data = {"protocol": "nesi-scout-container-prep-ssd-gzip1-v2",
        "job_id": os.environ["SLURM_JOB_ID"],
        "partition": os.environ.get("SLURM_JOB_PARTITION"),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "source": os.environ["VLLM_OCI_REFERENCE"], "destination": os.environ["VLLM_SIF"],
        "partial": os.environ["SCOUT_PARTIAL_SIF"],
        "temporary_directory": os.environ["APPTAINER_TMPDIR"],
        "temporary_filesystem": os.environ["SCOUT_TMP_FS"], "temporary_free_bytes": free,
        "temporary_files_removed_by_scheduler": True,
        "reused_cache": os.environ["APPTAINER_CACHEDIR"],
        "previous_extracted_rootfs_reused": False,
        "limits": {"cpus": 8, "memory_gib": 32, "walltime_minutes": 120,
                   "build_timeout_seconds": 6600, "mksquashfs_memory_gib": 8,
                   "compressor": "gzip", "compression_level": 1, "gpus": 0}}
with open(sys.argv[1], "x") as stream:
    json.dump(data, stream, indent=2)
    stream.write("\n")
if free < 80 * 1024**3:
    raise SystemExit("At least 80 GiB free SSD temporary space is required.")
PY

# Gzip remains compatible with the first attempt, with the documented fast level.
# The warm content-addressed OCI cache is reusable; the incomplete rootfs is not.
stage build_started
srun --cpu-bind=cores --kill-on-bad-exit=1 \
    env -u HF_TOKEN -u HUGGING_FACE_HUB_TOKEN -u GROQ_API_KEY -u LOCAL_LLM_API_KEY \
    timeout --signal=TERM --kill-after=30s 6600s \
    apptainer build --notest --arch amd64 \
    --mksquashfs-args '-processors 8 -mem 8G -comp gzip -Xcompression-level 1' \
    "$SCOUT_PARTIAL_SIF" "$VLLM_OCI_REFERENCE" \
    > "$SCOUT_PREP_EVIDENCE/build.log" 2>&1
stage build_completed
apptainer inspect --json "$SCOUT_PARTIAL_SIF" > "$SCOUT_PREP_EVIDENCE/image-metadata.json"
stage inspection_completed
stage checksum_and_publication_started
python3 "$SCOUT_HPC_DIR/finalize_container.py" --partial "$SCOUT_PARTIAL_SIF" \
    --destination "$VLLM_SIF" --site "$SCOUT_SITE_FILE" \
    --protocol nesi-scout-container-prep-ssd-gzip1-v2 \
    --output "$SCOUT_PREP_EVIDENCE/completed.json"
stage completed
