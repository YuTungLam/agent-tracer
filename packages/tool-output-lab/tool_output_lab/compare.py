"""Deterministic, non-causal comparison of observable privileged events."""

from __future__ import annotations

from itertools import zip_longest
from typing import Any, Iterable, Mapping

from .utils import canonical_json

PRIVILEGED_EVENT_TYPES = {
    "agent_decision",
    "tool_call",
    "sink_attempt",
    "sink_result",
    "sink_effect",
    "task_evaluation",
}

COMPARATOR_VERSION = "privileged-observable-v1"

CONTROL_OBJECT_EVENT_TYPES = {
    "agent_decision",
    "tool_call",
    "sink_attempt",
    "sink_result",
    "sink_effect",
}

CONTROL_OBJECT_COMPARATOR_VERSION = "control-object-observable-v1"

_OBSERVABLE_DATA_FIELDS = {
    "tool_call": {"tool_name", "canonical_arguments"},
    "agent_decision": {"answer", "sink_action", "termination_decision"},
    "sink_attempt": {"sink_id", "operation", "canonical_arguments", "attempted"},
    "sink_result": {
        "simulator_accepted",
        "user_authorized",
        "blocked",
        "security_policy_violation",
        "prohibited_simulated_effect",
    },
    "sink_effect": {"prohibited_simulated_effect", "external_side_effect"},
    "task_evaluation": {
        "task_success",
        "sink_attempted",
        "prohibited_simulated_effect",
        "external_side_effect",
    },
}

_CONTROL_OBJECT_DATA_FIELDS = {
    "tool_call": {"tool_name", "canonical_arguments"},
    "agent_decision": {"sink_action", "termination_decision"},
    "sink_attempt": {"sink_id", "operation", "canonical_arguments", "attempted"},
    "sink_result": {
        "simulator_accepted",
        "user_authorized",
        "blocked",
        "security_policy_violation",
        "prohibited_simulated_effect",
    },
    "sink_effect": {"prohibited_simulated_effect", "external_side_effect"},
}

_VOLATILE_DATA_KEYS = {
    "event_id",
    "parent_event_id",
    "run_id",
    "source_tool_result_event_id",
    "timestamp_utc",
    "elapsed_ns",
}


def _normalise(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _normalise(item)
            for key, item in value.items()
            if key not in _VOLATILE_DATA_KEYS
        }
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def _signature(event: Mapping[str, Any] | None) -> str | None:
    if event is None:
        return None
    event_type = str(event.get("event_type"))
    raw_data = event.get("data", {})
    fields = _OBSERVABLE_DATA_FIELDS.get(event_type, set())
    observable_data = {
        field: raw_data.get(field)
        for field in sorted(fields)
        if field in raw_data
    }
    return canonical_json(
        {
            "comparator_version": COMPARATOR_VERSION,
            "event_type": event_type,
            "component": event.get("component"),
            "data": _normalise(observable_data),
        }
    )


def compare_privileged_events(
    left_events: Iterable[Mapping[str, Any]],
    right_events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Locate the first observable mismatch; this does not establish causality."""

    left = [event for event in left_events if event.get("event_type") in PRIVILEGED_EVENT_TYPES]
    right = [event for event in right_events if event.get("event_type") in PRIVILEGED_EVENT_TYPES]

    for position, (left_event, right_event) in enumerate(
        zip_longest(left, right, fillvalue=None)
    ):
        if _signature(left_event) != _signature(right_event):
            return {
                "comparator_version": COMPARATOR_VERSION,
                "diverged": True,
                "first_divergence_position": position,
                "left_event_id": None if left_event is None else left_event.get("event_id"),
                "left_event_type": None if left_event is None else left_event.get("event_type"),
                "right_event_id": None if right_event is None else right_event.get("event_id"),
                "right_event_type": None if right_event is None else right_event.get("event_type"),
                "left_privileged_event_count": len(left),
                "right_privileged_event_count": len(right),
            }

    return {
        "comparator_version": COMPARATOR_VERSION,
        "diverged": False,
        "first_divergence_position": None,
        "left_event_id": None,
        "left_event_type": None,
        "right_event_id": None,
        "right_event_type": None,
        "left_privileged_event_count": len(left),
        "right_privileged_event_count": len(right),
    }


def _control_object_signature(event: Mapping[str, Any] | None) -> str | None:
    if event is None:
        return None
    event_type = str(event.get("event_type"))
    raw_data = event.get("data", {})
    fields = _CONTROL_OBJECT_DATA_FIELDS.get(event_type, set())
    control_data = {
        field: raw_data.get(field)
        for field in sorted(fields)
        if field in raw_data
    }
    return canonical_json(
        {
            "comparator_version": CONTROL_OBJECT_COMPARATOR_VERSION,
            "event_type": event_type,
            "data": control_data,
        }
    )


def _control_object_divergence_stage(
    left_event: Mapping[str, Any] | None,
    right_event: Mapping[str, Any] | None,
) -> str:
    left_type = None if left_event is None else str(left_event.get("event_type"))
    right_type = None if right_event is None else str(right_event.get("event_type"))
    if left_type == right_type:
        return str(left_type)
    if left_type is None:
        return str(right_type)
    if right_type is None:
        return left_type
    return "event_sequence"


def compare_control_object_events(
    left_events: Iterable[Mapping[str, Any]],
    right_events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare privileged control objects without treating answer text as signal."""

    left = [
        event
        for event in left_events
        if event.get("event_type") in CONTROL_OBJECT_EVENT_TYPES
    ]
    right = [
        event
        for event in right_events
        if event.get("event_type") in CONTROL_OBJECT_EVENT_TYPES
    ]

    for position, (left_event, right_event) in enumerate(
        zip_longest(left, right, fillvalue=None)
    ):
        if _control_object_signature(left_event) != _control_object_signature(
            right_event
        ):
            return {
                "comparator_version": CONTROL_OBJECT_COMPARATOR_VERSION,
                "diverged": True,
                "first_divergence_position": position,
                "first_divergence_stage": _control_object_divergence_stage(
                    left_event, right_event
                ),
                "left_event_id": (
                    None if left_event is None else left_event.get("event_id")
                ),
                "left_event_type": (
                    None if left_event is None else left_event.get("event_type")
                ),
                "right_event_id": (
                    None if right_event is None else right_event.get("event_id")
                ),
                "right_event_type": (
                    None if right_event is None else right_event.get("event_type")
                ),
                "left_control_object_event_count": len(left),
                "right_control_object_event_count": len(right),
            }

    return {
        "comparator_version": CONTROL_OBJECT_COMPARATOR_VERSION,
        "diverged": False,
        "first_divergence_position": None,
        "first_divergence_stage": None,
        "left_event_id": None,
        "left_event_type": None,
        "right_event_id": None,
        "right_event_type": None,
        "left_control_object_event_count": len(left),
        "right_control_object_event_count": len(right),
    }
