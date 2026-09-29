import copy
import hashlib
import json
import math
import sys
from types import SimpleNamespace

import pytest

from agentdojo_lab import semantic
from agentdojo_lab.semantic import (
    EncodedText,
    LocalMiniLMEncoder,
    SemanticMatcher,
    chunk_spans,
    sentence_spans,
)


class FakeEncoder:
    metadata = {"model_id": "fixture", "local_files_only": True}

    def __init__(self, vectors=None, *, max_tokens=100_000):
        self.vectors = vectors or {}
        self.max_tokens = max_tokens
        self.calls = []
        self.results = []

    def encode(self, texts):
        self.calls.append(list(texts))
        self.results = [
            EncodedText(
                self.vectors.get(text, (1.0, 0.0)),
                {
                    "input_tokens": len(text) + 2,
                    "encoded_tokens": min(len(text) + 2, self.max_tokens),
                    "max_tokens": self.max_tokens,
                    "truncated": len(text) + 2 > self.max_tokens,
                    "visible_span": [0, min(len(text), self.max_tokens - 2)],
                },
            )
            for text in texts
        ]
        return self.results


def test_sentence_and_chunk_spans_preserve_original_unicode_offsets():
    source = "  🧪 One. Two!\n 三。 Four? Five.  "
    spans = sentence_spans(source)
    assert [source[start:end] for start, end in spans] == ["🧪 One.", "Two!", "三。", "Four?", "Five."]
    chunks = chunk_spans(source)
    assert [chunk["sentence_range"] for chunk in chunks] == [[0, 3], [2, 5]]
    assert chunks[0]["span"] == [spans[0][0], spans[2][1]]
    assert chunks[1]["span"] == [spans[2][0], spans[4][1]]
    assert source[chunks[0]["span"][0] : chunks[0]["span"][1]] == "🧪 One. Two!\n 三。"
    assert sentence_spans("a.b") == [(0, 3)]
    assert sentence_spans("a\r\nb") == [(0, 1), (3, 4)]


@pytest.mark.parametrize("count,expected", [(1, [[0, 1]]), (3, [[0, 3]]), (4, [[0, 3], [2, 4]])])
def test_chunk_windows_have_no_redundant_trailing_window(count, expected):
    assert [chunk["sentence_range"] for chunk in chunk_spans("A. " * count)] == expected


def test_similarity_is_cosine_and_threshold_equality_matches():
    encoder = FakeEncoder({"Source": (3.0, 4.0), "target": (5.0, 0.0)})
    result = SemanticMatcher(encoder).compare("Source", "target")
    assert result["status"] == "scored" and result["complete"] is True
    assert result["tier3"]["score"] == 0.60
    assert result["tier3"]["matched"] is True
    assert result["tier4"]["matched"] is True
    assert (
        SemanticMatcher(encoder, semantic_threshold=math.nextafter(0.60, 1)).compare("Source", "target")[
            "matched"
        ]
        is False
    )


def test_coverage_uses_union_of_overlapping_matched_visible_spans():
    source = "One. Two. Three. Four. Five."
    result = SemanticMatcher(FakeEncoder({source: (0.0, 1.0)})).compare(source, "target")
    assert result["tier3"]["matched"] is False
    assert len(result["tier4"]["chunks"]) == 2
    assert result["tier4"]["matched_visible_spans"] == [[0, len(source)]]
    assert result["tier4"]["coverage"] == 1.0
    assert result["matched"] is True


def test_truncated_chunks_only_contribute_encoded_spans_to_coverage():
    source = "One. Two. Three. Four. Five."
    result = SemanticMatcher(FakeEncoder(max_tokens=8)).compare(source, "x")
    assert result["status"] == "scored" and result["truncated"] is True
    assert result["complete"] is False
    assert result["tier3"]["source_visible_span"] == [0, 6]
    assert result["tier3"]["truncated"] is True
    assert result["tier4"]["truncated"] is True
    start = source.index("Three.")
    assert result["tier4"]["matched_visible_spans"] == [[0, 6], [start, start + 6]]
    assert result["tier4"]["coverage"] == 12 / len(source)
    assert result["metadata"]["scoring_scope"] == "encoded_views_only"


def test_target_truncation_marks_both_tiers_incomplete():
    result = SemanticMatcher(FakeEncoder(max_tokens=6)).compare("a", "long target")
    for tier in ("tier3", "tier4"):
        assert result[tier]["complete"] is False
        assert result[tier]["target_tokenization"]["truncated"] is True


def test_coverage_threshold_equality_and_zero_similarity_candidate_set():
    source = "        One. Two. Three. Four. Five."
    encoder = FakeEncoder()
    observed = SemanticMatcher(encoder).compare(source, "target")["tier4"]["coverage"]
    assert (
        SemanticMatcher(encoder, coverage_threshold=observed).compare(source, "target")["tier4"]["matched"]
        is True
    )
    higher = SemanticMatcher(encoder, coverage_threshold=math.nextafter(observed, 1)).compare(
        source, "target"
    )
    assert higher["tier4"]["matched"] is False
    result = SemanticMatcher(FakeEncoder({"target": (0.0, 1.0)})).compare(source, "target")
    assert result["tier4"]["coverage"] == 0
    assert result["tier4"]["matched_visible_spans"] == []


@pytest.mark.parametrize("source,target", [("", "x"), ("x", ""), (" \n", "x"), ("x", "\t")])
def test_empty_inputs_are_unscored_and_do_not_call_encoder(source, target):
    encoder = FakeEncoder()
    result = SemanticMatcher(encoder).compare(source, target)
    assert result["status"] == "not_applicable"
    assert result["matched"] is None
    assert result["tier3"]["score"] is None and result["tier4"]["coverage"] is None
    assert not encoder.calls


def test_resource_limits_do_not_become_nonmatches(monkeypatch):
    encoder = FakeEncoder()
    monkeypatch.setattr(semantic, "MAX_CODEPOINTS_PER_INPUT", 5)
    result = SemanticMatcher(encoder).compare("123456", "x")
    assert result["status"] == "budget_exceeded" and result["matched"] is None
    assert result["metadata"]["unscored_reason"] == "max_codepoints_per_input"
    monkeypatch.setattr(semantic, "MAX_CODEPOINTS_PER_INPUT", 100)
    monkeypatch.setattr(semantic, "MAX_CHUNKS", 1)
    result = SemanticMatcher(encoder).compare("A. B. C. D.", "x")
    assert result["status"] == "budget_exceeded" and result["tier4"]["score"] is None
    assert result["metadata"]["unscored_reason"] == "max_chunks"
    assert not encoder.calls


@pytest.mark.parametrize("vector", [(), (0.0, 0.0), (math.nan, 0.0), (1.0, 0.0, 0.0)])
def test_invalid_embeddings_are_unscored_errors(vector):
    result = SemanticMatcher(FakeEncoder({"source": vector})).compare("source", "target")
    assert result["status"] == "encoder_error" and result["matched"] is None
    assert result["tier3"]["score"] is None


def test_invalid_tokenization_offsets_are_not_published_as_evidence():
    class BadOffsets(FakeEncoder):
        def encode(self, texts):
            result = super().encode(texts)
            result[0].tokenization["visible_span"] = [0, 999]
            return result

    result = SemanticMatcher(BadOffsets()).compare("source", "target")
    assert result["status"] == "encoder_error"
    assert result["tier4"]["chunks"] == []


def test_encoder_error_text_is_not_copied_into_results():
    class Broken(FakeEncoder):
        def encode(self, texts):
            raise RuntimeError("sensitive source fixture")

    result = SemanticMatcher(Broken()).compare("source", "target")
    assert result["metadata"]["unscored_reason"] == "RuntimeError"
    assert "sensitive" not in json.dumps(result)


def test_results_and_metadata_do_not_mutate_encoder_or_assumptions():
    encoder = FakeEncoder()
    matcher = SemanticMatcher(encoder)
    result = matcher.compare("source", "target")
    result["tier3"]["source_tokenization"]["visible_span"][0] = 99
    result["metadata"]["assumptions"]["chunk_sentences"] = 99
    result["metadata"]["encoder"]["model_id"] = "changed"
    assert encoder.results[0].tokenization["visible_span"] == [0, 6]
    assert matcher.metadata["assumptions"]["chunk_sentences"] == 3
    assert matcher.metadata["encoder"]["model_id"] == "fixture"


@pytest.mark.parametrize("value", [-1, 2, math.nan, math.inf, True, "0.60"])
def test_threshold_validation(value):
    with pytest.raises(ValueError):
        SemanticMatcher(FakeEncoder(), semantic_threshold=value)
    with pytest.raises(ValueError):
        SemanticMatcher(FakeEncoder(), coverage_threshold=value)


class FakeTokenizer:
    is_fast = True

    def __call__(self, text, *, truncation, max_length=None, **_):
        tokens = [
            (index + 1000, (index, index + 1))
            for index, character in enumerate(text)
            if not character.isspace()
        ]
        if truncation:
            tokens = tokens[: max_length - 2]
        return {
            "input_ids": [101, *[token for token, _ in tokens], 102],
            "offset_mapping": [(0, 0), *[offset for _, offset in tokens], (0, 0)],
        }


class FakeSentenceTransformer:
    instances = []

    def __init__(self, path, **kwargs):
        self.path, self.kwargs = path, kwargs
        self.tokenizer = FakeTokenizer()
        self.calls = []
        self.floating = self.evaluating = False
        self.__class__.instances.append(self)

    def float(self):
        self.floating = True

    def eval(self):
        self.evaluating = True

    def preprocess(self, texts):
        ids = self.tokenizer(texts[0], truncation=True, max_length=self.max_seq_length)["input_ids"]
        return {"input_ids": [SimpleNamespace(tolist=lambda: ids)]}

    def encode(self, texts, **kwargs):
        self.calls.append((list(texts), kwargs))
        return [[1.0, 0.0] for _ in texts]


@pytest.fixture
def local_fixture(tmp_path, monkeypatch):
    path = tmp_path / "model"
    path.mkdir()
    (path / "model.safetensors").write_bytes(b"fake weights, never loaded by torch")
    (path / "config.json").write_text("{}")
    (path / "vocab.txt").write_text("fixture")
    (path / "README.md").write_text("ignored model card")
    cache = path / ".cache"
    cache.mkdir()
    (cache / "receipt.json").write_text("{}")
    files = {
        file.name: hashlib.sha256(file.read_bytes()).hexdigest()
        for file in path.iterdir()
        if file.suffix in {".json", ".txt", ".safetensors"}
    }
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"model_id": semantic.MODEL_ID, "revision": "a" * 40, "files_sha256": files}))
    monkeypatch.setattr(semantic, "MODEL_PIN_PATH", pin)
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(float32="fixture-float32"))
    monkeypatch.setitem(
        sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=FakeSentenceTransformer)
    )
    return path, pin


def test_local_loader_pins_files_and_forbids_remote_or_pickle_loading(local_fixture):
    path, pin = local_fixture
    encoder = LocalMiniLMEncoder(path, revision="a" * 40)
    model = encoder._model
    assert model.floating and model.evaluating
    assert model.kwargs["local_files_only"] is True and model.kwargs["trust_remote_code"] is False
    assert model.kwargs["device"] == "cpu"
    assert model.kwargs["model_kwargs"]["use_safetensors"] is True
    assert model.kwargs["model_kwargs"]["torch_dtype"] == "fixture-float32"
    assert model.kwargs["processor_kwargs"]["local_files_only"] is True
    assert model.max_seq_length == 256
    assert encoder.metadata["revision_verification"] == "pinned_manifest_verified"
    assert encoder.metadata["pin_sha256"] == hashlib.sha256(pin.read_bytes()).hexdigest()
    assert set(encoder.metadata["files_sha256"]) == {"model.safetensors", "config.json", "vocab.txt"}


def test_local_identity_verifies_weights_without_loading_the_encoder(local_fixture):
    path, _ = local_fixture
    metadata = semantic.local_minilm_identity(path, revision="a" * 40)
    assert metadata["model_path"] == str(path.resolve())
    assert metadata["revision_verification"] == "pinned_manifest_verified"
    assert metadata["files_sha256"]["model.safetensors"]
    (path / "model.safetensors").write_bytes(b"changed but still never loaded")
    with pytest.raises(ValueError, match="file hashes"):
        semantic.local_minilm_identity(path, revision="a" * 40)


def test_loader_rejects_changed_or_unpinned_input_files_and_revision(local_fixture):
    path, _ = local_fixture
    with pytest.raises(ValueError, match="revision"):
        LocalMiniLMEncoder(path, revision="b" * 40)
    with pytest.raises(ValueError, match="immutable"):
        LocalMiniLMEncoder(path, revision="main")
    (path / "adapter_config.json").write_text("{}")
    with pytest.raises(ValueError, match="file hashes"):
        LocalMiniLMEncoder(path, revision="a" * 40)
    (path / "adapter_config.json").unlink()
    (path / "vocab.txt").write_text("changed")
    with pytest.raises(ValueError, match="file hashes"):
        LocalMiniLMEncoder(path, revision="a" * 40)


def test_local_tokenization_records_truncation_and_original_unicode_offsets(local_fixture):
    path, _ = local_fixture
    encoder = LocalMiniLMEncoder(path, revision="a" * 40)
    text = "  🧪" + "a" * 300
    result = encoder.encode([text])[0]
    assert result.tokenization["input_tokens"] == 303
    assert result.tokenization["encoded_tokens"] == 256
    assert result.tokenization["truncated"] is True
    assert result.tokenization["visible_span"] == [2, 256]
    assert result.tokenization["tokenizer_input_ids_verified"] is True


def test_local_audit_rejects_preprocessing_token_id_mismatch(local_fixture):
    path, _ = local_fixture
    encoder = LocalMiniLMEncoder(path, revision="a" * 40)
    encoder._model.preprocess = lambda _: {"input_ids": [SimpleNamespace(tolist=lambda: [0])]}
    with pytest.raises(ValueError, match="preprocessing"):
        encoder.encode(["source"])
    assert not encoder._model.calls


def test_local_cache_is_exact_bounded_and_returns_detached_values(local_fixture):
    path, _ = local_fixture
    encoder = LocalMiniLMEncoder(path, revision="a" * 40, cache_size=2)
    result = encoder.encode(["one", "one", "two"])
    assert encoder._model.calls[0][0] == ["one", "two"]
    result[0].tokenization["visible_span"][0] = 99
    assert result[1].tokenization["visible_span"][0] == 0
    assert encoder.encode(["one"])[0].tokenization["visible_span"] == [0, 3]
    encoder.encode(["three"])
    assert list(encoder._cache) == ["one", "three"]
    encoder.encode(["ONE"])
    assert list(encoder._cache) == ["three", "ONE"]
    encoder._max_cache_codepoints = 5
    encoder.encode(["123456"])
    assert "123456" not in encoder._cache
    assert encoder.metadata["cache_key"] == "exact_input_text"
    before = copy.deepcopy(encoder.metadata)
    encoder.metadata["files_sha256"]["vocab.txt"] = "mutated"
    assert encoder.metadata == before


def test_local_cache_can_be_disabled(local_fixture):
    path, _ = local_fixture
    encoder = LocalMiniLMEncoder(path, revision="a" * 40, cache_size=0)
    encoder.encode(["text"])
    encoder.encode(["text"])
    assert len(encoder._model.calls) == 2 and not encoder._cache
