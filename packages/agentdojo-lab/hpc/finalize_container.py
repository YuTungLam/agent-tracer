"""Publish a completed SIF without overwrite and update its private site checksum."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

OCI_SOURCE = "docker://vllm/vllm-openai@sha256:3e10e8189823e0f7ae4620c271bcdaaf64127ec7d0edc351591a508498b7684a"
CHECKSUM_LINE = re.compile(r"^(?:export\s+)?VLLM_SIF_SHA256=.*$", re.MULTILINE)
PROTOCOLS = ("nesi-scout-container-prep-v1", "nesi-scout-container-prep-ssd-gzip1-v2")


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def set_site_checksum(site: Path, checksum: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Invalid SIF checksum")
    original = site.read_text(encoding="utf-8")
    if len(CHECKSUM_LINE.findall(original)) != 1:
        raise ValueError("Site must have exactly one VLLM_SIF_SHA256 assignment")
    replacement = CHECKSUM_LINE.sub("export VLLM_SIF_SHA256=" + checksum, original)
    original_stat = site.stat()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=site.parent,
                                         prefix=".scout-site-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(original_stat.st_mode))
        # Catch concurrent edits before replacing; never copy site contents to logs.
        if site.read_text(encoding="utf-8") != original:
            raise ValueError("Site changed during checksum update")
        os.replace(temporary, site)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def finalize(partial: Path, destination: Path, site: Path, output: Path,
             protocol: str = PROTOCOLS[0]) -> dict:
    if protocol not in PROTOCOLS:
        raise ValueError("Unknown container preparation protocol")
    if not partial.is_file() or partial.stat().st_size == 0:
        raise ValueError("Missing or empty completed SIF")
    if partial.is_symlink() or destination.exists() or destination.is_symlink():
        raise ValueError("Refusing a symlink source or existing destination")
    receipt = {"protocol": protocol, "source": OCI_SOURCE,
               "job_id": os.environ.get("SLURM_JOB_ID"), "destination": str(destination),
               "bytes": partial.stat().st_size, "sha256": file_hash(partial),
               "completed_utc": datetime.now(timezone.utc).isoformat(), "site_checksum_updated": False,
               "gpu_validation": "not_run"}
    # Exclusive output and hard-link creation prevent replacing prior evidence/image.
    with output.open("x", encoding="utf-8") as stream:
        os.link(partial, destination)
        partial.unlink()
        try:
            set_site_checksum(site, receipt["sha256"])
            receipt["site_checksum_updated"] = True
        finally:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("partial", "destination", "site", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--protocol", choices=PROTOCOLS, default=PROTOCOLS[0])
    args = parser.parse_args()
    try:
        finalize(args.partial, args.destination, args.site, args.output, args.protocol)
    except (OSError, ValueError):
        print("Container finalization failed; preserve local image and receipts for inspection.")
        return 2
    print("Container prepared and private SIF checksum updated; GPU validation remains pending.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
