"""Do not promote historical or unbound predictions into format-v3 concordance."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "semantic_audit_runner", Path(__file__).resolve().parents[1] / "scripts/run_semantic_audit.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_format_and_binding_are_required_for_concordance():
    comparison = {"probe_id": "p", "probe_binding_sha256": "bound", "intervention_exact_sink_proposed": False}
    judgment = {
        "probe_id": "p",
        "binding_sha256": "bound",
        "status": "valid",
        "judgment": {"would_call_anyway": False},
    }
    assert module.concordance([comparison], [judgment], inputs_valid=True)[0]["agreement"] is None
    judgment["judgment_format"] = module.FORMAT
    assert module.concordance([comparison], [judgment], inputs_valid=True)[0]["agreement"] is True
    assert module.concordance([comparison], [judgment], inputs_valid=False)[0]["agreement"] is None
    judgment["binding_sha256"] = "different"
    assert module.concordance([comparison], [judgment], inputs_valid=True)[0]["agreement"] is None


def test_invalid_and_missing_predictions_stay_unknown():
    comparisons = [
        {"probe_id": p, "probe_binding_sha256": p, "intervention_exact_sink_proposed": False}
        for p in ("a", "b")
    ]
    judgment = {
        "probe_id": "a",
        "binding_sha256": "a",
        "status": "invalid",
        "judgment_format": module.FORMAT,
        "judgment": {"would_call_anyway": False},
    }
    assert all(r["agreement"] is None for r in module.concordance(comparisons, [judgment], inputs_valid=True))


def test_late_implementation_change_downgrades_final_ledger(tmp_path, monkeypatch):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    comparison = {"probe_id": "p", "probe_binding_sha256": "bound", "intervention_exact_sink_proposed": False}
    monkeypatch.setattr(module, "preflight", lambda _: [{"slot_id": "a", "comparisons": [comparison]}])
    monkeypatch.setattr(module, "snapshot", lambda _: {"file": "stable"})
    calls = []

    def code():
        calls.append(1)
        return {"code": "changed" if len(calls) >= 3 else "stable"}

    monkeypatch.setattr(module, "code_snapshot", code)

    def audit(_source, folder, **kwargs):
        folder.mkdir()
        judgment = {
            "probe_id": "p",
            "binding_sha256": "bound",
            "status": "valid",
            "judgment_format": module.FORMAT,
            "judgment": {"would_call_anyway": False},
        }
        (folder / "judgments.jsonl").write_text(json.dumps(judgment) + "\n")
        return {
            "source_files_unchanged": True,
            "plan_export_hashes_before": {},
            "plan_export_hashes_after": {},
            "request_count": 0,
            "valid_judgments": 1,
        }

    monkeypatch.setattr(module, "run_audit", audit)
    result = module.run(source, output)
    assert result["inputs_valid"] is False
    live = json.loads((output / "live-slots.jsonl").read_text())
    final = json.loads((output / "slots.jsonl").read_text())
    assert live["concordance"][0]["known"] is True
    assert final["concordance"][0]["known"] is False
    assert final["concordance"][0]["agreement"] is None
