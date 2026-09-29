"""Local, inspectable NeuroTaint-style semantic evidence, not a safety verdict.

The paper specifies MiniLM/cosine and thresholds but leaves chunking, coverage,
tokenization, and resource policy incomplete. ASSUMPTIONS fixes those choices.
Importing this module does not import ML packages, load a model, or use a network.
"""

import copy
import hashlib
import importlib.metadata
import json
import math
import re
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol, Sequence

METHOD = "nt_style_semantic_v1"
MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_PIN_PATH = Path(__file__).parent / "model_pins" / "minilm-v1.json"
MAX_CODEPOINTS_PER_INPUT = 65_536
MAX_CHUNKS = 128
MAX_TOKENS = 256
ASSUMPTIONS = {
    "sentence_boundary_regex": r"(?<=[.!?。！？])\s+|[\r\n]+",
    "sentence_edge_whitespace": "excluded_from_spans_without_changing_original_text",
    "chunk_sentences": 3,
    "chunk_overlap_sentences": 1,
    "coverage": "union_length_of_threshold_matching_encoded_token_envelopes/source_codepoints",
    "coverage_denominator": "all_original_source_codepoints_including_whitespace",
    "offset_unit": "unicode_codepoint_half_open",
    "threshold_policy": "fixed_ordinary_thresholds_without_gold_label_selection",
    "evaluation": "score_tiers_3_and_4_independently_not_the_full_ordered_cascade",
    "cosine_accumulation": "python_math_fsum_float64_over_float32_model_embeddings",
    "truncation": "score_encoded_view_and_report_incomplete_without_claiming_full_text_coverage",
    "interpretation": "semantic_similarity_candidate_not_confirmed_provenance_or_maliciousness",
}
_SENTENCE_BOUNDARY = re.compile(ASSUMPTIONS["sentence_boundary_regex"])


@dataclass(frozen=True)
class EncodedText:
    embedding: Sequence[float]
    tokenization: dict


class TextEncoder(Protocol):
    metadata: dict

    def encode(self, texts: Sequence[str]) -> list[EncodedText]: ...


def _model_inventory(path: Path) -> tuple[tuple[str, int, int, int, int], ...]:
    inventory = []
    for file in sorted(path.rglob("*")):
        relative = file.relative_to(path)
        if any(part.startswith(".") for part in relative.parts):
            continue
        if file.is_symlink():
            raise ValueError("Local model inputs must not contain symbolic links")
        if file.is_file() and file.suffix in {".json", ".txt", ".safetensors"}:
            stat = file.stat()
            inventory.append(
                (
                    relative.as_posix(),
                    stat.st_size,
                    stat.st_mtime_ns,
                    stat.st_ctime_ns,
                    stat.st_ino,
                )
            )
    return tuple(inventory)


@lru_cache(maxsize=16)
def _verified_local_minilm_identity(
    path_text: str,
    revision: str,
    cache_size: int,
    pin_path_text: str,
    pin_sha256: str,
    inventory: tuple[tuple[str, int, int, int, int], ...],
    versions_items: tuple[tuple[str, str], ...],
) -> dict:
    path = Path(path_text)
    pin_path = Path(pin_path_text)
    pin_bytes = pin_path.read_bytes()
    if hashlib.sha256(pin_bytes).hexdigest() != pin_sha256:
        raise ValueError("Reviewed MiniLM pin changed during identity verification")
    try:
        pin = json.loads(pin_bytes)
    except json.JSONDecodeError as error:
        raise ValueError("Reviewed MiniLM pin is not valid JSON") from error
    if (
        not isinstance(pin, dict)
        or pin.get("model_id") != MODEL_ID
        or pin.get("revision") != revision
        or not isinstance(pin.get("files_sha256"), dict)
    ):
        raise ValueError("Model identity or revision does not match the reviewed pin")
    files = {}
    for relative, size, mtime_ns, ctime_ns, inode in inventory:
        file = path / relative
        stat = file.stat()
        expected_stat = (size, mtime_ns, ctime_ns, inode)
        if (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino) != expected_stat:
            raise ValueError("Local model input changed during identity verification")
        digest = hashlib.sha256()
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        stat = file.stat()
        if (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino) != expected_stat:
            raise ValueError("Local model input changed during identity verification")
        files[relative] = digest.hexdigest()
    if _model_inventory(path) != inventory:
        raise ValueError("Local model inventory changed during identity verification")
    if hashlib.sha256(pin_path.read_bytes()).hexdigest() != pin_sha256:
        raise ValueError("Reviewed MiniLM pin changed during identity verification")
    if not pin["files_sha256"] or files != pin["files_sha256"]:
        raise ValueError("Local model input file hashes do not match the reviewed pin")
    if not any(name.endswith(".safetensors") for name in files):
        raise FileNotFoundError("Local MiniLM snapshot must include safetensors weights")

    manifest = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "model_id": MODEL_ID,
        "model_path": str(path),
        "revision": revision,
        "revision_verification": "pinned_manifest_verified",
        "pin_sha256": pin_sha256,
        "files_sha256": files,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "device": "cpu",
        "dtype": "float32",
        "max_tokens": MAX_TOKENS,
        "trust_remote_code": False,
        "local_files_only": True,
        "use_safetensors": True,
        "cache_max_entries": cache_size,
        "cache_max_codepoints": 1_048_576,
        "cache_key": "exact_input_text",
        "normalize_embeddings": True,
        "versions": dict(versions_items),
    }


def local_minilm_identity(
    model_path: str | Path,
    *,
    revision: str,
    cache_size: int = 1024,
) -> dict:
    """Verify the complete local snapshot and return its runtime metadata contract."""
    path = Path(model_path).expanduser().resolve()
    if not path.is_dir():
        raise FileNotFoundError("MiniLM requires an existing local snapshot directory")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ValueError("revision must be an immutable 40-character commit hash")
    if (
        isinstance(cache_size, bool)
        or not isinstance(cache_size, int)
        or not 0 <= cache_size <= 4096
    ):
        raise ValueError("cache_size must be an integer between 0 and 4096")
    pin_path = MODEL_PIN_PATH.expanduser().resolve()
    pin_bytes = pin_path.read_bytes()
    versions = []
    for package in ("sentence-transformers", "transformers", "tokenizers", "torch"):
        try:
            value = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            value = "unavailable"
        versions.append((package, value))
    metadata = _verified_local_minilm_identity(
        str(path),
        revision,
        cache_size,
        str(pin_path),
        hashlib.sha256(pin_bytes).hexdigest(),
        _model_inventory(path),
        tuple(versions),
    )
    return copy.deepcopy(metadata)


def sentence_spans(text: str) -> list[tuple[int, int]]:
    """Deterministic sentence approximation retaining original Unicode offsets."""
    spans = []
    start = 0
    for boundary in [*_SENTENCE_BOUNDARY.finditer(text), None]:
        end = boundary.start() if boundary else len(text)
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        if start < end:
            spans.append((start, end))
        if boundary:
            start = boundary.end()
    return spans


def chunk_spans(text: str) -> list[dict]:
    sentences = sentence_spans(text)
    chunks = []
    for first in range(0, len(sentences), 2):
        last = min(first + 3, len(sentences))
        chunks.append(
            {"span": [sentences[first][0], sentences[last - 1][1]], "sentence_range": [first, last]}
        )
        if last == len(sentences):
            break
    return chunks


def _union_spans(spans: Sequence[Sequence[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) == 0 or len(left) != len(right):
        raise ValueError("Invalid embedding dimensions")
    if not all(math.isfinite(value) for vector in (left, right) for value in vector):
        raise ValueError("Nonfinite embedding")
    left_norm = math.sqrt(math.fsum(value * value for value in left))
    right_norm = math.sqrt(math.fsum(value * value for value in right))
    if not left_norm or not right_norm:
        raise ValueError("Zero embedding")
    score = math.fsum(a * b for a, b in zip(left, right, strict=True)) / (left_norm * right_norm)
    return min(1.0, max(-1.0, score))


def _validate_encoding(encoded: EncodedText, text: str) -> None:
    meta = encoded.tokenization
    full, used, limit = (meta[key] for key in ("input_tokens", "encoded_tokens", "max_tokens"))
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (full, used, limit)
    ):
        raise ValueError("Invalid token counts")
    if not 0 < used <= full or not used <= limit or meta["truncated"] is not (full > used):
        raise ValueError("Inconsistent truncation metadata")
    span = meta["visible_span"]
    if not isinstance(span, (list, tuple)) or len(span) != 2:
        raise ValueError("Missing encoded token span")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in span):
        raise ValueError("Invalid encoded token span")
    if not 0 <= span[0] < span[1] <= len(text):
        raise ValueError("Encoded span is outside the input")


class SemanticMatcher:
    def __init__(
        self, encoder: TextEncoder, *, semantic_threshold: float = 0.60, coverage_threshold: float = 0.10
    ):
        for value in (semantic_threshold, coverage_threshold):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("Thresholds must be finite numbers")
            if not 0 <= value <= 1:
                raise ValueError("Thresholds must lie between 0 and 1")
        self.encoder = encoder
        self.semantic_threshold = semantic_threshold
        self.coverage_threshold = coverage_threshold

    @property
    def metadata(self) -> dict:
        return copy.deepcopy(
            {
                "method": METHOD,
                "assumptions": {
                    **ASSUMPTIONS,
                    **(
                        {"threshold_policy": "explicit_memory_profile_without_gold_label_selection"}
                        if self.semantic_threshold == 0.85
                        else {}
                    ),
                },
                "semantic_threshold": self.semantic_threshold,
                "coverage_threshold": self.coverage_threshold,
                "limits": {"max_codepoints_per_input": MAX_CODEPOINTS_PER_INPUT, "max_chunks": MAX_CHUNKS},
                "encoder": self.encoder.metadata,
            }
        )

    def _stage_result(self, source: str, target: str, stage: str) -> dict:
        if not isinstance(source, str) or not isinstance(target, str):
            raise TypeError("source and target must be strings")
        metadata = self.metadata
        metadata["assumptions"]["evaluation"] = f"compute_{stage}_only_when_explicitly_called"
        result = {
            "method": METHOD,
            "stage": stage,
            "status": "not_applicable",
            "score": None,
            "matched": None,
            "complete": False,
            "truncated": False,
            "source_length": len(source),
            "target_length": len(target),
            "semantic_threshold": self.semantic_threshold,
            "metadata": metadata,
        }
        if stage == "tier4":
            result.update(
                coverage=None,
                coverage_threshold=self.coverage_threshold,
                chunks=[],
                matched_visible_spans=[],
            )
        return result

    @staticmethod
    def _stage_unscored(result: dict, status: str, reason: str) -> dict:
        result["status"] = status
        result["metadata"]["unscored_reason"] = reason
        return copy.deepcopy(result)

    def compare_tier3(self, source: str, target: str) -> dict:
        """Encode only the source and target; never construct or budget chunks."""
        result = self._stage_result(source, target, "tier3")
        if not source or not target:
            return result
        if max(len(source), len(target)) > MAX_CODEPOINTS_PER_INPUT:
            return self._stage_unscored(result, "budget_exceeded", "max_codepoints_per_input")
        if not source.strip() or not target.strip():
            return result
        try:
            texts = [source, target]
            encodings = self.encoder.encode(texts)
            if len(encodings) != len(texts):
                raise ValueError("Encoder returned the wrong number of results")
            for encoded, text in zip(encodings, texts, strict=True):
                _validate_encoding(encoded, text)
            source_encoded, target_encoded = encodings
            score = _cosine(source_encoded.embedding, target_encoded.embedding)
            truncated = any(encoded.tokenization["truncated"] for encoded in encodings)
            result.update(
                status="scored",
                score=score,
                matched=score >= self.semantic_threshold,
                complete=not truncated,
                truncated=truncated,
                source_tokenization=source_encoded.tokenization,
                target_tokenization=target_encoded.tokenization,
                source_visible_span=source_encoded.tokenization["visible_span"],
            )
            result["metadata"]["scoring_scope"] = (
                "encoded_views_only" if truncated else "full_tokenized_inputs"
            )
        except Exception as error:
            return self._stage_unscored(
                self._stage_result(source, target, "tier3"), "encoder_error", type(error).__name__
            )
        return copy.deepcopy(result)

    def compare_tier4(self, source: str, target: str) -> dict:
        """Encode only the target and source chunks, preserving visible-span coverage."""
        result = self._stage_result(source, target, "tier4")
        if not source or not target:
            return result
        if max(len(source), len(target)) > MAX_CODEPOINTS_PER_INPUT:
            return self._stage_unscored(result, "budget_exceeded", "max_codepoints_per_input")
        if not source.strip() or not target.strip():
            return result
        chunks = chunk_spans(source)
        if len(chunks) > MAX_CHUNKS:
            return self._stage_unscored(result, "budget_exceeded", "max_chunks")
        texts = [target, *[source[start:end] for start, end in (chunk["span"] for chunk in chunks)]]
        try:
            encodings = self.encoder.encode(texts)
            if len(encodings) != len(texts):
                raise ValueError("Encoder returned the wrong number of results")
            for encoded, text in zip(encodings, texts, strict=True):
                _validate_encoding(encoded, text)
            target_encoded, *chunk_encodings = encodings
            matched_spans = []
            for chunk, encoded in zip(chunks, chunk_encodings, strict=True):
                score = _cosine(encoded.embedding, target_encoded.embedding)
                visible = [chunk["span"][0] + offset for offset in encoded.tokenization["visible_span"]]
                chunk.update(
                    score=score,
                    matched=score >= self.semantic_threshold,
                    tokenization=encoded.tokenization,
                    visible_span=visible,
                )
                if chunk["matched"]:
                    matched_spans.append(visible)
            merged = _union_spans(matched_spans)
            coverage = sum(end - start for start, end in merged) / len(source)
            best_score = max(chunk["score"] for chunk in chunks)
            truncated = any(encoded.tokenization["truncated"] for encoded in encodings)
            result.update(
                status="scored",
                score=best_score,
                coverage=coverage,
                matched=best_score >= self.semantic_threshold and coverage >= self.coverage_threshold,
                complete=not truncated,
                truncated=truncated,
                chunks=chunks,
                matched_visible_spans=merged,
                target_tokenization=target_encoded.tokenization,
            )
            result["metadata"]["scoring_scope"] = (
                "encoded_views_only" if truncated else "full_tokenized_inputs"
            )
        except Exception as error:
            return self._stage_unscored(
                self._stage_result(source, target, "tier4"), "encoder_error", type(error).__name__
            )
        return copy.deepcopy(result)

    def compare(self, source: str, target: str) -> dict:
        if not isinstance(source, str) or not isinstance(target, str):
            raise TypeError("source and target must be strings")
        result = {
            "method": METHOD,
            "status": "not_applicable",
            "matched": None,
            "complete": False,
            "truncated": False,
            "source_length": len(source),
            "target_length": len(target),
            "tier3": {
                "status": "not_applicable",
                "score": None,
                "matched": None,
                "complete": False,
                "truncated": False,
            },
            "tier4": {
                "status": "not_applicable",
                "score": None,
                "coverage": None,
                "matched": None,
                "complete": False,
                "truncated": False,
                "chunks": [],
                "matched_visible_spans": [],
            },
            "metadata": self.metadata,
        }
        if not source or not target:
            return result
        if max(len(source), len(target)) > MAX_CODEPOINTS_PER_INPUT:
            return self._unscored(result, "budget_exceeded", "max_codepoints_per_input")
        if not source.strip() or not target.strip():
            return result
        chunks = chunk_spans(source)
        if len(chunks) > MAX_CHUNKS:
            return self._unscored(result, "budget_exceeded", "max_chunks")
        texts = [source, target, *[source[start:end] for start, end in (chunk["span"] for chunk in chunks)]]
        try:
            encodings = self.encoder.encode(texts)
            if len(encodings) != len(texts):
                raise ValueError("Encoder returned the wrong number of results")
            for encoded, text in zip(encodings, texts, strict=True):
                _validate_encoding(encoded, text)
            source_encoded, target_encoded, *chunk_encodings = encodings
            score = _cosine(source_encoded.embedding, target_encoded.embedding)
            result["tier3"].update(
                status="scored",
                score=score,
                matched=score >= self.semantic_threshold,
                complete=not (
                    source_encoded.tokenization["truncated"] or target_encoded.tokenization["truncated"]
                ),
                truncated=source_encoded.tokenization["truncated"]
                or target_encoded.tokenization["truncated"],
                source_tokenization=source_encoded.tokenization,
                target_tokenization=target_encoded.tokenization,
                source_visible_span=source_encoded.tokenization["visible_span"],
            )
            matched_spans = []
            for chunk, encoded in zip(chunks, chunk_encodings, strict=True):
                score = _cosine(encoded.embedding, target_encoded.embedding)
                visible = [chunk["span"][0] + offset for offset in encoded.tokenization["visible_span"]]
                chunk.update(
                    score=score,
                    matched=score >= self.semantic_threshold,
                    tokenization=encoded.tokenization,
                    visible_span=visible,
                )
                if chunk["matched"]:
                    matched_spans.append(visible)
            merged = _union_spans(matched_spans)
            coverage = sum(end - start for start, end in merged) / len(source)
            best_score = max(chunk["score"] for chunk in chunks)
            result["tier4"].update(
                status="scored",
                score=best_score,
                coverage=coverage,
                matched=best_score >= self.semantic_threshold and coverage >= self.coverage_threshold,
                complete=not any(
                    encoded.tokenization["truncated"] for encoded in [target_encoded, *chunk_encodings]
                ),
                truncated=any(
                    encoded.tokenization["truncated"] for encoded in [target_encoded, *chunk_encodings]
                ),
                chunks=chunks,
                matched_visible_spans=merged,
                target_tokenization=target_encoded.tokenization,
            )
            truncated = any(encoded.tokenization["truncated"] for encoded in encodings)
            result.update(
                status="scored",
                matched=result["tier3"]["matched"] or result["tier4"]["matched"],
                complete=not truncated,
                truncated=truncated,
            )
            result["metadata"]["scoring_scope"] = (
                "encoded_views_only" if truncated else "full_tokenized_inputs"
            )
        except Exception as error:
            # Never fabricate a zero score or include possibly sensitive encoder error text.
            result = self._unscored(result, "encoder_error", type(error).__name__)
        return copy.deepcopy(result)

    @staticmethod
    def _unscored(result: dict, status: str, reason: str) -> dict:
        result.update(status=status, matched=None, complete=False)
        result["tier3"] = {
            "status": status,
            "score": None,
            "matched": None,
            "complete": False,
            "truncated": False,
        }
        result["tier4"] = {
            "status": status,
            "score": None,
            "coverage": None,
            "matched": None,
            "complete": False,
            "truncated": False,
            "chunks": [],
            "matched_visible_spans": [],
        }
        result["metadata"]["unscored_reason"] = reason
        return copy.deepcopy(result)


class LocalMiniLMEncoder:
    """CPU float32 encoder using only an already downloaded local snapshot.

    The package's reviewed pin fixes the model revision and required input file
    hashes. Loading does not fetch either the model or its pin from a network.
    """

    def __init__(self, model_path: str | Path, *, revision: str, cache_size: int = 1024):
        metadata = local_minilm_identity(model_path, revision=revision, cache_size=cache_size)
        path = Path(metadata["model_path"])
        try:
            import torch
            from sentence_transformers import SentenceTransformer
        except ImportError as error:
            raise RuntimeError(
                "Local semantic scoring requires the optional sentence-transformers dependency"
            ) from error
        self._model = SentenceTransformer(
            str(path),
            device="cpu",
            revision=revision,
            local_files_only=True,
            trust_remote_code=False,
            model_kwargs={"use_safetensors": True, "torch_dtype": torch.float32, "local_files_only": True},
            processor_kwargs={"local_files_only": True, "use_fast": True},
        )
        self._model.float()
        self._model.eval()
        self._model.max_seq_length = MAX_TOKENS
        if not self._model.tokenizer.is_fast:
            raise ValueError("An offset-capable fast tokenizer is required")
        self._cache: OrderedDict[str, EncodedText] = OrderedDict()
        self._cache_size = cache_size
        self._cache_codepoints = 0
        self._max_cache_codepoints = metadata["cache_max_codepoints"]
        self._metadata = metadata

    @property
    def metadata(self) -> dict:
        return copy.deepcopy(self._metadata)

    def _tokenization(self, text: str) -> dict:
        options = {
            "add_special_tokens": True,
            "return_offsets_mapping": True,
            "return_attention_mask": False,
            # Untruncated tokens are counted only, never passed to the model.
            "verbose": False,
        }
        full = self._model.tokenizer(text, truncation=False, **options)
        used = self._model.tokenizer(text, truncation=True, max_length=MAX_TOKENS, **options)
        actual = self._model.preprocess([text])["input_ids"][0].tolist()
        if actual != used["input_ids"]:
            raise ValueError("Tokenizer preprocessing changed the audited input token IDs")
        offsets = [(start, end) for start, end in used["offset_mapping"] if end > start]
        return {
            "input_tokens": len(full["input_ids"]),
            "encoded_tokens": len(used["input_ids"]),
            "max_tokens": MAX_TOKENS,
            "truncated": len(full["input_ids"]) > len(used["input_ids"]),
            "visible_span": [min(start for start, _ in offsets), max(end for _, end in offsets)]
            if offsets
            else None,
            "special_tokens_included": True,
            "offset_unit": "unicode_codepoint",
            "tokenizer_input_ids_verified": True,
        }

    def encode(self, texts: Sequence[str]) -> list[EncodedText]:
        if isinstance(texts, str) or len(texts) > MAX_CHUNKS + 2:
            raise ValueError("encode expects a bounded sequence of texts")
        if any(not isinstance(text, str) for text in texts):
            raise TypeError("Every encoder input must be a string")
        if any(len(text) > MAX_CODEPOINTS_PER_INPUT for text in texts):
            raise ValueError("Encoder input exceeds the code-point budget")
        current = {}
        missing = []
        for text in texts:
            if text in current:
                continue
            if text in self._cache:
                self._cache.move_to_end(text)
                current[text] = self._cache[text]
            else:
                current[text] = None
                missing.append(text)
        if missing:
            audits = [self._tokenization(text) for text in missing]
            embeddings = self._model.encode(
                missing,
                batch_size=16,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
                precision="float32",
                device="cpu",
            )
            if len(embeddings) != len(missing):
                raise ValueError("MiniLM returned the wrong number of embeddings")
            for text, vector, audit in zip(missing, embeddings, audits, strict=True):
                encoded = EncodedText(tuple(float(value) for value in vector), audit)
                current[text] = encoded
                if self._cache_size and len(text) <= self._max_cache_codepoints:
                    self._cache[text] = encoded
                    self._cache_codepoints += len(text)
                    while (
                        len(self._cache) > self._cache_size
                        or self._cache_codepoints > self._max_cache_codepoints
                    ):
                        old_text, _ = self._cache.popitem(last=False)
                        self._cache_codepoints -= len(old_text)
        return [copy.deepcopy(current[text]) for text in texts]
