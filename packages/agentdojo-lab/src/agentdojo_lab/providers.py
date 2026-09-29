"""Explicit endpoint selection for new runs; credentials remain environment-only."""

import json
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import openai
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
Provider = Literal["groq", "openai_compatible"]


class EndpointSettings(BaseModel):
    """Serializable endpoint identity, containing a key variable name, never its value."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    provider: Provider
    model: str = Field(min_length=1)
    base_url: str | None = Field(default=None, exclude_if=lambda value: value is None)
    api_key_env: str | None = Field(default=None, exclude_if=lambda value: value is None)

    @field_validator("model")
    @classmethod
    def nonempty_model(cls, value):
        if not value.strip() or value != value.strip():
            raise ValueError("model must be nonempty without surrounding whitespace")
        return value

    @field_validator("api_key_env")
    @classmethod
    def valid_key_variable(cls, value):
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("api_key_env must be an environment variable name, not a key")
        return value

    @field_validator("base_url")
    @classmethod
    def credential_free_url(cls, value):
        if value is None:
            return value
        try:
            parsed = urlsplit(value)
            valid_port = parsed.port is None or 1 <= parsed.port <= 65535
        except ValueError:
            raise ValueError("base_url must be a valid HTTP(S) endpoint") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or not valid_port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in value)
        ):
            raise ValueError("base_url must be HTTP(S), without credentials, query, fragment, or whitespace")
        return value

    @model_validator(mode="after")
    def explicit_selection(self):
        if self.provider == "openai_compatible":
            if not self.base_url or not self.api_key_env:
                raise ValueError("openai_compatible requires explicit base_url and api_key_env")
        elif self.base_url is not None:
            raise ValueError("Use openai_compatible for a custom endpoint; groq has a fixed base URL")
        return self

    @property
    def url(self) -> str:
        return self.base_url if self.provider == "openai_compatible" else GROQ_BASE_URL

    @property
    def key_variable(self) -> str:
        return self.api_key_env or "GROQ_API_KEY"

    def configured_key(self) -> str:
        return os.environ.get(self.key_variable, "").strip()

    def require_key(self) -> str:
        key = self.configured_key()
        if not key:
            raise ValueError(f"Set {self.key_variable} locally before a live request")
        return key

    def client(self, *, key: str, timeout: float) -> openai.OpenAI:
        return openai.OpenAI(api_key=key, base_url=self.url, max_retries=0, timeout=timeout)


def reject_implicit_groq_audit(source: Path) -> None:
    """Keep legacy live auditors from selecting Groq for a new local source run."""
    manifest_path = Path(source) / "manifest.json"
    if not manifest_path.is_file():
        return  # The caller's ordinary input validation reports missing artifacts.
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("config", {}).get("provider") == "openai_compatible":
        raise ValueError(
            "This local-provider trace requires an explicitly configured auditor. "
            "Use dojo-lab counterfactual --judge-config for a configured no-tools audit; "
            "the legacy paper_audit/causal_v2 live protocols remain Groq-only."
        )
