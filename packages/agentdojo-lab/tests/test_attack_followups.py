import importlib.util
from pathlib import Path


def controller():
    path = Path(__file__).resolve().parents[1] / "scripts/run_attack_followups.py"
    spec = importlib.util.spec_from_file_location("attack_followup_control", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_predeclared_first_replay_group_can_spend_budget(monkeypatch):
    module = controller()
    plans = [{"proposal_event_id": "target", "status": "eligible", "complete": True,
              "probes": [{"source_ids": ["a"]}, {"source_ids": ["b"]}, {"source_ids": ["a", "b"]}]}]
    slots = [{"proposal_event_id": "target", "condition": condition}
             for condition in ("context_a", "context_b", "context_b", "context_b")]
    monkeypatch.setattr(module, "_replay_slots", lambda *args: slots)
    assert module.selected_group(plans, Path("unused"), "target")
    slots[0]["proposal_event_id"] = "earlier-action"
    assert not module.selected_group(plans, Path("unused"), "target")
    slots[0]["proposal_event_id"] = "target"
    plans[0]["complete"] = False
    assert not module.selected_group(plans, Path("unused"), "target")


def test_source_pair_shape_required_before_replay(monkeypatch):
    module = controller()
    plans = [{"proposal_event_id": "target", "status": "eligible", "complete": True,
              "probes": [{"source_ids": ["a"]}, {"source_ids": ["b"]}, {"source_ids": ["c"]}]}]
    def forbidden(*args):
        raise AssertionError("No replay planning for a non-pair")
    monkeypatch.setattr(module, "_replay_slots", forbidden)
    assert not module.selected_group(plans, Path("unused"), "target")
