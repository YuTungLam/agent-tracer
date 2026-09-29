"""Prepare or execute the separately gated two-slot Scout Case A protocol."""

# The frozen bundle source path must be installed before experiment imports.
# ruff: noqa: E402

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLED_SOURCE = ROOT / "src"
BUNDLED_AGENTDOJO_SOURCE = ROOT / "vendor/agentdojo/src"


def require_physical_bundle_directory(path: Path) -> None:
    """Reject symlinked or external import roots before importing experiment code."""
    if not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise RuntimeError(f"Frozen import directory must be physical and canonical: {path}")
    if path != ROOT and not path.is_relative_to(ROOT):
        raise RuntimeError(f"Frozen import directory escaped its physical bundle: {path}")


for required_directory in (
    ROOT,
    BUNDLED_SOURCE,
    BUNDLED_SOURCE / "agentdojo_lab",
    BUNDLED_AGENTDOJO_SOURCE,
    BUNDLED_AGENTDOJO_SOURCE / "agentdojo",
):
    require_physical_bundle_directory(required_directory)
for bundled_source in reversed((BUNDLED_AGENTDOJO_SOURCE, BUNDLED_SOURCE)):
    source_text = str(bundled_source)
    sys.path[:] = [entry for entry in sys.path if entry != source_text]
    sys.path.insert(0, source_text)

import agentdojo

import agentdojo_lab
from agentdojo_lab import case_a_scout, runner

main = case_a_scout.main


def bound_import_paths() -> dict[str, str]:
    """Require every loaded experiment module to resolve inside this physical bundle."""
    paths = {
        "agentdojo": Path(agentdojo.__file__).resolve(),
        "agentdojo_lab": Path(agentdojo_lab.__file__).resolve(),
        "case_a_scout": Path(case_a_scout.__file__).resolve(),
        "runner": Path(runner.__file__).resolve(),
    }
    expected = {
        "agentdojo": (BUNDLED_AGENTDOJO_SOURCE / "agentdojo").resolve(),
        "agentdojo_lab": (BUNDLED_SOURCE / "agentdojo_lab").resolve(),
        "case_a_scout": (BUNDLED_SOURCE / "agentdojo_lab/case_a_scout.py").resolve(),
        "runner": (BUNDLED_SOURCE / "agentdojo_lab/runner.py").resolve(),
    }
    if any(not paths[name].is_relative_to(expected[name]) for name in paths):
        raise RuntimeError("Case A imports escaped the frozen source bundle")
    package_roots = {
        "agentdojo": BUNDLED_AGENTDOJO_SOURCE / "agentdojo",
        "agentdojo_lab": BUNDLED_SOURCE / "agentdojo_lab",
    }
    for module_name, module in tuple(sys.modules.items()):
        package = next(
            (
                name
                for name in package_roots
                if module_name == name or module_name.startswith(name + ".")
            ),
            None,
        )
        raw_path = getattr(module, "__file__", None)
        if package is None or raw_path is None:
            continue
        module_path = Path(raw_path)
        if (
            module_path.is_symlink()
            or module_path.resolve() != module_path
            or not module_path.is_relative_to(package_roots[package])
        ):
            raise RuntimeError("Case A imports escaped the frozen source bundle")
    return {name: str(path) for name, path in paths.items()}


BOUND_IMPORT_PATHS = bound_import_paths()

if __name__ == "__main__":
    raise SystemExit(main())
