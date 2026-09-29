"""Download and verify the pinned Scout root files in a CPU allocation."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from huggingface_hub import HfApi, snapshot_download

MODEL_ID = "meta-llama/Llama-4-Scout-17B-16E-Instruct"
REVISION = "92f3b1597a195b523d8d9e5700e57e4fbb8f20d3"


def digest(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    if algorithm == "sha1":
        # Hub small-file IDs are Git blob IDs, not a plain file SHA-1.
        value.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.snapshot.is_absolute():
        raise ValueError("Use a fresh receipt path and an absolute snapshot path")
    started = datetime.now(timezone.utc).isoformat()
    info = HfApi().model_info(MODEL_ID, revision=REVISION, files_metadata=True)
    if info.sha != REVISION:
        raise ValueError("Unexpected remote revision")
    files = [item for item in info.siblings if "/" not in item.rfilename
             and not item.rfilename.startswith(".")]
    shards = [item for item in files if item.rfilename.endswith(".safetensors")]
    if len(shards) != 50 or sum(item.size for item in shards) != 217283738720:
        raise ValueError("Unexpected Scout shard inventory")
    inventory = {"model_id": MODEL_ID, "revision": REVISION, "started_utc": started,
                 "files": [{"path": item.rfilename, "bytes": item.size,
                            "algorithm": "sha256" if item.lfs else "git-blob-sha1",
                            "expected": item.lfs.sha256 if item.lfs else item.blob_id}
                           for item in files]}
    with args.output.with_suffix(".inventory.json").open("x") as stream:
        json.dump(inventory, stream, indent=2)
        stream.write("\n")
    print(f"Downloading {len(files)} files at {REVISION}; {len(shards)} weight shards", flush=True)
    snapshot_download(MODEL_ID, revision=REVISION, local_dir=args.snapshot,
                      allow_patterns=[item.rfilename for item in files], max_workers=2)
    for row in inventory["files"]:
        path = args.snapshot / row["path"]
        if path.is_symlink() or not path.is_file() or path.stat().st_size != row["bytes"]:
            raise ValueError(f"Invalid local file: {row['path']}")
        actual = digest(path, "sha256" if row["algorithm"] == "sha256" else "sha1")
        if not row["expected"] or actual != row["expected"]:
            raise ValueError(f"Checksum mismatch: {row['path']}")
        row["verified"] = True
        print(f"Verified {row['path']}", flush=True)
    inventory["completed_utc"] = datetime.now(timezone.utc).isoformat()
    inventory["status"] = "all_selected_files_verified"
    inventory["snapshot"] = str(args.snapshot)
    with args.output.open("x") as stream:
        json.dump(inventory, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
