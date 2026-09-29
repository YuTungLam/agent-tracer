#!/usr/bin/env bash
#SBATCH --job-name=scout-download
#SBATCH --account=uoa04799
#SBATCH --partition=genoa
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --no-requeue
#SBATCH --output=scout-download-%j.log

# sbatch scout-download.sbatch /absolute/private/site.env /absolute/fresh/receipt-dir
set -euo pipefail
umask 077
[[ -n ${SLURM_JOB_ID:-} && $# == 2 ]] || exit 2
source "$1"
SCOUT_DOWNLOAD_RUN=$2
mkdir -- "$SCOUT_DOWNLOAD_RUN"
trap 'printf "%s\n" "$?" > "$SCOUT_DOWNLOAD_RUN/job-exit-code.txt"' EXIT
: "${SCOUT_SNAPSHOT:?}"
: "${SCOUT_HPC_DIR:?}"
: "${HF_XET_CACHE:?}"
mkdir -p -- "$SCOUT_SNAPSHOT" "$HF_XET_CACHE"
exec 9>"$SCOUT_SNAPSHOT/.download.lock"
flock -n 9 || { echo 'Another Scout download owns this snapshot.' >&2; exit 2; }
export HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_UPDATE_CHECK=1
export HF_HUB_DISABLE_PROGRESS_BARS=1 HF_XET_HIGH_PERFORMANCE=0
export HF_XET_NUM_CONCURRENT_RANGE_GETS=4 OMP_NUM_THREADS=2
SCOUT_HF_PYTHON=/nesi/project/uoa04799/dyu848/tools/hf/bin/python
"$SCOUT_HF_PYTHON" "$SCOUT_HPC_DIR/download_scout.py" \
    --snapshot "$SCOUT_SNAPSHOT" --output "$SCOUT_DOWNLOAD_RUN/model-integrity.json"
