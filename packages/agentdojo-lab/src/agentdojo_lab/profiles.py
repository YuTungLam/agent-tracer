"""Fixed, caller-selected threshold profiles; no inference from content or labels."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ThresholdProfile:
    """An immutable operational profile, not an attribution or safety label."""

    name: str
    lexical_threshold: float
    semantic_threshold: float
    coverage_threshold: float


_PROFILES = MappingProxyType(
    {
        "ordinary": ThresholdProfile("ordinary", 0.15, 0.60, 0.10),
        "memory": ThresholdProfile("memory", 0.15, 0.85, 0.10),
        "implicit_string": ThresholdProfile("implicit_string", 0.40, 0.60, 0.10),
        "safe_control": ThresholdProfile("safe_control", 0.15, 0.95, 0.10),
    }
)


def get_profile(name: str) -> ThresholdProfile:
    """Resolve one exact name; unknown names never fall back to ordinary thresholds.

    Callers must declare the profile independently of evaluation outcomes. This
    accessor does not classify tools, tasks, source content, or source trust.
    """
    if type(name) is not str or name not in _PROFILES:
        raise ValueError("Unknown cascade profile")
    return _PROFILES[name]
