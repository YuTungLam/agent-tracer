"""Declared local substitutes for MELON's hard-coded OpenAI embedder.

The artifact builds ``OpenAI(api_key="your-api-key")`` in ``MELON.__init__``
(pi_detector.py:209) and calls ``self.detection_model.embeddings.create(
input=<str>, model="text-embedding-3-large")`` (pi_detector.py:396-399 and
:431-434), reading ``response.data[0].embedding``. DeepSeek has no embeddings
endpoint, so the harness replaces the ``detection_model`` attribute after
construction with one of the clients below. The artifact source is not edited.

Substitutes (both are declared deviations; their cosine scale differs from
text-embedding-3-large, while the artifact's threshold of 0.8 stays fixed):

* ``minilm``: the lab's pinned sentence-transformers/all-MiniLM-L6-v2
  directory, run in-process with transformers. It reproduces the
  sentence-transformers module stack listed in that directory's
  ``modules.json``: Transformer (max_seq_length 256), mean pooling, L2 normalise.
* ``ollama-nomic``: ``nomic-embed-text`` on a loopback Ollama server, as in the
  Week-1 smoke test.

Neither substitute makes a remote network request.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

ARTIFACT_EMBEDDING_MODEL = "text-embedding-3-large"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class MiniLMEncoder:
    """all-MiniLM-L6-v2 with the sentence-transformers pooling, without that package."""

    name = "minilm"

    def __init__(self, model_dir: str | Path, *, max_seq_length: int | None = None) -> None:
        import torch  # noqa: F401  (imported here so tests can run without loading it)
        from transformers import AutoModel, AutoTokenizer

        self.model_dir = Path(model_dir)
        if not (self.model_dir / "model.safetensors").is_file():
            raise FileNotFoundError(f"no model.safetensors under {self.model_dir}")
        modules = json.loads((self.model_dir / "modules.json").read_text(encoding="utf-8"))
        module_types = [m.get("type", "") for m in modules]
        expected = [
            "sentence_transformers.models.Transformer",
            "sentence_transformers.models.Pooling",
            "sentence_transformers.models.Normalize",
        ]
        if module_types != expected:
            raise ValueError(f"unexpected sentence-transformers module stack: {module_types}")
        pooling = json.loads((self.model_dir / "1_Pooling" / "config.json").read_text(encoding="utf-8"))
        if not pooling.get("pooling_mode_mean_tokens") or any(
            pooling.get(k) for k in ("pooling_mode_cls_token", "pooling_mode_max_tokens", "pooling_mode_mean_sqrt_len_tokens")
        ):
            raise ValueError(f"expected mean pooling only, got {pooling}")
        st_cfg = json.loads((self.model_dir / "sentence_bert_config.json").read_text(encoding="utf-8"))
        self.max_seq_length = int(max_seq_length or st_cfg.get("max_seq_length", 256))
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir), local_files_only=True)
        self.model = AutoModel.from_pretrained(str(self.model_dir), local_files_only=True)
        self.model.eval()
        self.weights_sha256 = sha256_file(self.model_dir / "model.safetensors")
        self.description = {
            "substitute": "minilm",
            "model_id": "sentence-transformers/all-MiniLM-L6-v2",
            "model_dir_name": self.model_dir.name,
            "weights_sha256": self.weights_sha256,
            "pooling": "mean over attention mask, then L2 normalise",
            "max_seq_length": self.max_seq_length,
            "dimension": int(self.model.config.hidden_size),
        }

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        import torch
        import torch.nn.functional as F

        with torch.no_grad():
            batch = self.tokenizer(
                list(texts), padding=True, truncation=True, max_length=self.max_seq_length, return_tensors="pt"
            )
            hidden = self.model(**batch).last_hidden_state
            mask = batch["attention_mask"].unsqueeze(-1).to(hidden.dtype)
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            normed = F.normalize(pooled, p=2, dim=1)
        return [row.tolist() for row in normed]


class OllamaEncoder:
    """nomic-embed-text through a loopback Ollama OpenAI-compatible endpoint."""

    name = "ollama-nomic"

    def __init__(self, base_url: str = "http://127.0.0.1:11434/v1", model: str = "nomic-embed-text") -> None:
        host = urlparse(base_url).hostname
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"Ollama embedder must be loopback, got host {host!r}")
        import openai

        self._client = openai.OpenAI(base_url=base_url, api_key="ollama", max_retries=0, timeout=120)
        self.model = model
        self.description = {"substitute": "ollama-nomic", "model_id": model, "endpoint_host": host}

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        response = self._client.embeddings.create(input=list(texts), model=self.model)
        return [list(item.embedding) for item in response.data]


class _EmbeddingsFacade:
    """Implements the one method the artifact calls: ``embeddings.create(input=..., model=...)``."""

    def __init__(self, encoder: Any, *, max_requests: int | None, on_request: Callable[[dict], None] | None) -> None:
        self._encoder = encoder
        self._cache: dict[str, list[float]] = {}
        self.max_requests = max_requests
        self.on_request = on_request
        self.requested_models: list[str] = []
        self.request_count = 0
        self.encoded_count = 0

    def create(self, input: Any, model: str, **_: Any) -> SimpleNamespace:  # noqa: A002 (artifact's keyword)
        if self.max_requests is not None and self.request_count >= self.max_requests:
            raise RuntimeError(f"embedding request cap {self.max_requests} reached")
        self.request_count += 1
        self.requested_models.append(model)
        texts = [input] if isinstance(input, str) else list(input)
        missing = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if missing:
            for text, vector in zip(missing, self._encoder.encode(missing), strict=True):
                self._cache[text] = vector
            self.encoded_count += len(missing)
        if self.on_request is not None:
            self.on_request({"requested_model": model, "n_inputs": len(texts), "n_new": len(missing)})
        data = [SimpleNamespace(embedding=list(self._cache[t]), index=i, object="embedding") for i, t in enumerate(texts)]
        return SimpleNamespace(data=data, model=f"substitute:{self._encoder.name}", object="list")

    def vector(self, text: str) -> list[float] | None:
        return self._cache.get(text)


class SubstituteEmbeddingClient:
    """Drop-in for ``MELON.detection_model``; exposes ``.embeddings`` like an OpenAI client."""

    def __init__(self, encoder: Any, *, max_requests: int | None = None, on_request: Callable[[dict], None] | None = None) -> None:
        self.encoder = encoder
        self.embeddings = _EmbeddingsFacade(encoder, max_requests=max_requests, on_request=on_request)

    @property
    def description(self) -> dict:
        return dict(getattr(self.encoder, "description", {"substitute": getattr(self.encoder, "name", "unknown")}))


def build_encoder(kind: str, *, minilm_dir: str | Path | None = None, ollama_base_url: str | None = None) -> Any:
    if kind == "minilm":
        if not minilm_dir:
            raise ValueError("--embedder minilm needs --embedder-dir or MELON_EMBEDDER_DIR")
        return MiniLMEncoder(minilm_dir)
    if kind == "ollama-nomic":
        return OllamaEncoder(ollama_base_url or "http://127.0.0.1:11434/v1")
    raise ValueError(f"unknown embedder {kind!r}")


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    import math

    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
