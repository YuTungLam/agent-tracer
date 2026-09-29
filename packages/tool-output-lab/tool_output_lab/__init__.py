"""Sandboxed tool-output injection research harness."""

__version__ = "0.8.0"

from .attack_spec import AttackSpec
from .domain import Condition, Task
from .experiment import ExperimentConfig, ExperimentResult, run_experiment
from .propagation import (
    GuardMode,
    IngressChannel,
    PropagationConfig,
    PropagationResult,
    run_propagation_testbed,
)

__all__ = [
    "AttackSpec",
    "Condition",
    "ExperimentConfig",
    "ExperimentResult",
    "GuardMode",
    "IngressChannel",
    "PropagationConfig",
    "PropagationResult",
    "Task",
    "run_experiment",
    "run_propagation_testbed",
]
