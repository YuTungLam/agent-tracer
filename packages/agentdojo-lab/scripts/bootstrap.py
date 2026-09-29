"""Fetch the pinned upstream and install the locked project environment."""

import argparse
import json
import os
import shutil
import subprocess
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.12.10"


def run(*args: str, env=None) -> None:
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="3.12", help="Python 3.12 executable or version")
    args = parser.parse_args()
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    vendor = ROOT / "vendor" / "agentdojo"
    if not (vendor / ".git").exists():
        if vendor.exists():
            raise SystemExit(f"Refusing to replace existing non-git directory: {vendor}")
        vendor.parent.mkdir(exist_ok=True)
        run("git", "clone", "--filter=blob:none", "--no-checkout", upstream["repository"], str(vendor))
        run("git", "-C", str(vendor), "checkout", "--detach", upstream["commit"])
    actual = subprocess.check_output(["git", "-C", str(vendor), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(vendor), "status", "--porcelain"], text=True).strip()
    if actual != upstream["commit"] or dirty:
        raise SystemExit("Upstream differs from upstream.json or has local changes; left untouched.")

    bootstrap = ROOT / ".bootstrap"
    bootstrap_python = bootstrap / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not bootstrap_python.exists():
        venv.EnvBuilder(with_pip=True).create(bootstrap)
    run(str(bootstrap_python), "-m", "pip", "install", "--disable-pip-version-check", f"uv=={UV_VERSION}")
    env = os.environ.copy()
    env["UV_CACHE_DIR"] = str(ROOT / ".uv-cache")
    env["UV_PYTHON_INSTALL_DIR"] = str(ROOT / ".python")
    run(
        str(bootstrap_python),
        "-m",
        "uv",
        "sync",
        "--locked",
        "--extra",
        "figures",
        "--python",
        args.python,
        env=env,
    )
    if not (ROOT / ".env").exists():
        shutil.copyfile(ROOT / ".env.example", ROOT / ".env")
        (ROOT / ".env").chmod(0o600)
    executable = Path(".venv") / ("Scripts/dojo-lab.exe" if os.name == "nt" else "bin/dojo-lab")
    print(f"Ready. Run: {executable} doctor")


if __name__ == "__main__":
    main()
