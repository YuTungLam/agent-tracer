"""The v2 generator must use the same Unicode decoding mode as the guard."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/generate_a1_exploratory_v2_cases.py"


def test_generator_refuses_non_utf8_mode_before_writing(tmp_path: Path) -> None:
    out = tmp_path / "cases.json"
    env = {**os.environ, "PYTHONUTF8": "0"}
    result = subprocess.run([sys.executable, str(SCRIPT), "--results-root", str(tmp_path),
                             "--out", str(out)], env=env, capture_output=True, text=True,
                            check=False, timeout=30)
    assert result.returncode == 2
    assert "requires PYTHONUTF8=1 at Python startup" in result.stderr
    assert not out.exists()


def test_generator_check_only_accepts_utf8_mode(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONUTF8": "1"}
    result = subprocess.run([sys.executable, str(SCRIPT), "--results-root", str(tmp_path),
                             "--check-only"], env=env, capture_output=True, text=True,
                            check=False, timeout=60)
    assert result.returncode == 0, result.stderr
    assert '"total": 2' in result.stdout
    assert list(tmp_path.iterdir()) == []
