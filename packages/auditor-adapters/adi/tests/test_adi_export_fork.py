"""Zero-cost tests for the fork side of the ADI exporter (``adi_export_fork.py``; ADI amendment).

Runs in the ADI artifact venv (the fork installed editable). It imports the pinned fork's case definitions and
checks them against the amendment config's expected hashes; it asserts on hashes, counts and booleans only, so
no payload text is printed even on failure. No model request; the ground truth only.

    <EXT>/adi/.venv/Scripts/python.exe -m pytest -p no:cacheprovider packages/auditor-adapters/adi/tests/test_adi_export_fork.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ADI_DIR = Path(__file__).resolve().parents[1]
REPO = ADI_DIR.parents[2]
ACFG = REPO / "packages" / "agentdojo-lab" / "configs" / "pilot_protocol_v1_deepseek_amendment_1.json"
FORK_SRC = Path(os.environ.get("ADI_FORK_SRC") or REPO.parent / "external-auditors" / "adi" / "src")


def _module():
    spec = importlib.util.spec_from_file_location("adi_export_fork_under_test", ADI_DIR / "adi_export_fork.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _in_fork_venv() -> bool:
    try:
        import agentdojo
    except ImportError:
        return False
    return FORK_SRC.is_dir() and Path(agentdojo.__file__).resolve().is_relative_to(FORK_SRC.resolve())


def test_rules_without_the_fork():
    m = _module()
    case = {"case_id": "c", "attacker_value": {"rule": "literal", "value": "general"}}
    assert m.attacker_value(case, {"prompt_injection_channel": "p"}) == "general"
    case = {"case_id": "c", "attacker_value": {"rule": "slack_external_channel", "value": None}}
    assert m.attacker_value(case, {"prompt_injection_channel": "p"}) == "External_p"
    with pytest.raises(ValueError):
        m.attacker_value({"case_id": "c", "attacker_value": {"rule": "other"}}, {})
    assert m.canonical_injections_sha256({"b": "2", "a": "1"}) == m.sha256_text('{"a":"1","b":"2"}')


def test_main_refuses_an_output_inside_the_repository(tmp_path):
    m = _module()
    assert m.main(["--acfg", str(ACFG), "--fork-src", str(tmp_path), "--out", str(REPO / "packages" / "x.json")]) == 2
    assert not (REPO / "packages" / "x.json").exists()


@pytest.mark.skipif(not _in_fork_venv(), reason="needs the ADI fork's venv and its checkout")
def test_the_fork_payloads_match_every_expected_hash():
    m = _module()
    acfg = json.loads(ACFG.read_text(encoding="utf-8"))
    ident = m.fork_identity(FORK_SRC)
    assert ident["package_inside_fork_src"] is True
    rows = m.export(acfg, FORK_SRC)["rows"]
    assert len(rows) == 19
    bad = [r["ref"] for r in rows if not r["hashes_match_acfg"]]
    assert bad == []                                       # case refs only, never payload text
    assert all(set(r["env_form"].values()) == {"raw"} for r in rows)   # the fork's escaping unescapes in every case
    assert all(len(r["gt_attack_outputs"]) == len(r["gt_clean_outputs"]) for r in rows)
