"""Canonical, controller-only taxonomy for tool-output attack treatments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .utils import canonical_json, sha256_text


ATTACK_SPEC_SCHEMA_VERSION = "attack-spec-v1"
_SAFE_VERSION = re.compile(r"^[a-z0-9]+(?:[a-z0-9_-]*[a-z0-9])?$")


class AttackFamily(str, Enum):
    """Root threat family; the remaining fields are independent axes."""

    TOOL_OUTPUT_INJECTION = "tool_output_injection"


class AttackCarrier(str, Enum):
    """Container that carries attacker-controlled content."""

    TOOL_OUTPUT = "tool_output"
    MCP_SERVER_RESPONSE = "mcp_server_response"


class AttackInterface(str, Enum):
    """Tool boundary through which the carrier enters the agent."""

    IN_PROCESS_MOCK_DOCUMENT = "in_process_mock_document"
    MOCK_WEB_SEARCH = "mock_web_search"
    FILE_SYSTEM_READER = "file_system_reader"
    API_ENDPOINT = "api_endpoint"
    MCP = "mcp"


class PayloadTechnique(str, Enum):
    """Semantic and representational payload technique."""

    PLAIN_TEXT_INSTRUCTION = "plain_text_instruction"
    STRUCTURED_JSON_INSTRUCTION = "structured_json_instruction"
    STRUCTURED_XML_INSTRUCTION = "structured_xml_instruction"
    ROLE_ESCALATION_PROMPT = "role_escalation_prompt"


class PayloadPlacement(str, Enum):
    """Location of the payload inside the carrier."""

    OPERATOR_NOTE = "operator_note"
    TOP_LEVEL_FIELD = "top_level_field"
    NESTED_FIELD = "nested_field"
    RESPONSE_PREFIX = "response_prefix"
    RESPONSE_INFIX = "response_infix"
    RESPONSE_SUFFIX = "response_suffix"


class PropagationPattern(str, Enum):
    """Predeclared route, not an assertion that propagation occurred."""

    SINGLE_HOP = "single_hop"
    MULTI_HOP_CROSS_TOOL = "multi_hop_cross_tool"


class AttackObjective(str, Enum):
    """Objective whose success must be evaluated from observable outcomes."""

    UNAUTHORIZED_SIMULATED_SINK_ACTION = (
        "unauthorized_simulated_sink_action"
    )
    DATA_EXFILTRATION = "data_exfiltration"
    UNSAFE_ACTION_EXECUTION = "unsafe_action_execution"
    GOAL_DEVIATION = "goal_deviation"
    CROSS_TOOL_CONTAMINATION = "cross_tool_contamination"
    PERSISTENT_MEMORY_CORRUPTION = "persistent_memory_corruption"


class OptimisationRegime(str, Enum):
    """How the payload was produced."""

    FIXED_TEMPLATE = "fixed_template"
    GCG_SUFFIX = "gcg_suffix"


_FIELD_ENUMS: Mapping[str, type[Enum]] = {
    "attack_family": AttackFamily,
    "carrier": AttackCarrier,
    "interface": AttackInterface,
    "payload_technique": PayloadTechnique,
    "placement": PayloadPlacement,
    "propagation": PropagationPattern,
    "objective": AttackObjective,
    "optimisation_regime": OptimisationRegime,
}
ATTACK_SPEC_FIELDS = (
    "attack_family",
    "carrier",
    "interface",
    "payload_technique",
    "placement",
    "propagation",
    "objective",
    "optimisation_regime",
    "payload_version",
)


@dataclass(frozen=True)
class AttackSpec:
    """One predeclared taxonomy treatment kept outside model-visible data."""

    attack_family: str
    carrier: str
    interface: str
    payload_technique: str
    placement: str
    propagation: str
    objective: str
    optimisation_regime: str
    payload_version: str

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AttackSpec":
        """Parse an exact canonical mapping and reject ambiguous metadata."""

        if not isinstance(value, Mapping):
            raise ValueError("AttackSpec must be an object")
        observed = set(value)
        expected = set(ATTACK_SPEC_FIELDS)
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        if missing:
            raise ValueError(
                f"AttackSpec is missing required fields: {', '.join(missing)}"
            )
        if unknown:
            raise ValueError(
                f"AttackSpec has unknown fields: {', '.join(unknown)}"
            )
        invalid_types = sorted(
            field
            for field in ATTACK_SPEC_FIELDS
            if type(value[field]) is not str
        )
        if invalid_types:
            raise ValueError(
                "AttackSpec fields must be strings: "
                f"{', '.join(invalid_types)}"
            )
        return cls(**{field: value[field] for field in ATTACK_SPEC_FIELDS})

    def validate(self) -> None:
        for field in ATTACK_SPEC_FIELDS:
            value = getattr(self, field)
            if type(value) is not str or not value.strip():
                raise ValueError(
                    f"AttackSpec field {field} must be a non-empty string"
                )
            if value != value.strip():
                raise ValueError(
                    f"AttackSpec field {field} must not contain outer whitespace"
                )
        for field, enum_type in _FIELD_ENUMS.items():
            value = getattr(self, field)
            try:
                enum_type(value)
            except ValueError as exc:
                choices = ", ".join(item.value for item in enum_type)
                raise ValueError(
                    f"Unknown AttackSpec {field} {value!r}; choose one of: "
                    f"{choices}"
                ) from exc
        if (
            len(self.payload_version) > 80
            or _SAFE_VERSION.fullmatch(self.payload_version) is None
        ):
            raise ValueError(
                "AttackSpec payload_version must be a safe 1-80 character "
                "lowercase identifier"
            )

    def to_mapping(self) -> dict[str, str]:
        """Return the fixed-order canonical wire representation."""

        return {field: getattr(self, field) for field in ATTACK_SPEC_FIELDS}

    def declaration_mapping(self) -> dict[str, Any]:
        """Return the versioned material bound by the canonical digest."""

        return {
            "schema_version": ATTACK_SPEC_SCHEMA_VERSION,
            "spec": self.to_mapping(),
        }

    @property
    def spec_id(self) -> str:
        return f"attack-spec-{self.payload_version}-{self.sha256[:12]}"

    @property
    def sha256(self) -> str:
        return sha256_text(canonical_json(self.declaration_mapping()))


def attack_spec_from_mapping(value: Mapping[str, Any]) -> AttackSpec:
    """Named helper used by persisted-record validators."""

    return AttackSpec.from_mapping(value)
