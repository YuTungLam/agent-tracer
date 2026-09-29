"""Decode bounded JSON/YAML value scalars while retaining original token spans.

Offsets index Unicode codepoints in the original string. ``wire_span`` encloses
the scalar's original token; it is not a decoded-character-to-wire-character
map. Quotes, escapes, indentation, and YAML folding can change both the text
and its length. No objects or custom tag constructors are executed.
"""

from __future__ import annotations

import hashlib
import json

import yaml
from yaml.events import MappingEndEvent, MappingStartEvent, ScalarEvent, SequenceEndEvent, SequenceStartEvent
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, DirectiveToken, TagToken

LIMITS = {"max_codepoints": 65536, "max_nodes": 4096, "max_depth": 32, "max_scalars": 512}
STYLES = {
    None: "plain",
    '"': "double_quoted",
    "'": "single_quoted",
    "|": "literal_block",
    ">": "folded_block",
}


class _Unsupported(ValueError):
    pass


class _BudgetExceeded(ValueError):
    pass


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pointer_token(text: str) -> str:
    return text.replace("~", "~0").replace("/", "~1")


def _is_json_document(text: str) -> bool:
    """Recognize strict JSON; do not relabel YAML flow syntax as JSON."""

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _Unsupported("duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise _Unsupported("non_finite_json_constant")

    try:
        json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
            parse_int=str,
            parse_float=str,
        )
        return True
    except json.JSONDecodeError:
        return False


def _preflight(text: str) -> None:
    """Enforce structural budgets before the composer builds its node tree."""
    for token in yaml.scan(text, Loader=yaml.BaseLoader):
        if isinstance(token, (AliasToken, AnchorToken, TagToken, DirectiveToken)):
            raise _Unsupported("aliases_anchors_explicit_tags_or_directives")
    depth, nodes = 0, 0
    for event in yaml.parse(text, Loader=yaml.BaseLoader):
        if isinstance(event, (MappingStartEvent, SequenceStartEvent, ScalarEvent)):
            nodes += 1
            if nodes > LIMITS["max_nodes"]:
                raise _BudgetExceeded("max_nodes")
            if depth > LIMITS["max_depth"]:
                raise _BudgetExceeded("max_depth")
        if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
            depth -= 1


def decode_span_scalars(text: str) -> dict:
    """Return value scalars or a complete failure, never a partial parse.

    Mapping keys participate in validation and node budgets but are not emitted as
    value scalars. BaseLoader preserves lexical scalar values without type coercion.
    Comments are not scalar values. Empty/comment-only documents have no scalars.
    The ``plain_text`` status identifies an unquoted root scalar decoded by YAML;
    leading whitespace and YAML line folding therefore follow its scalar semantics.

        Strict JSON string tokens are decoded with ``json.loads`` so escaped
        surrogate pairs retain JSON's Unicode semantics. Other scalar values retain
        BaseLoader's lexical text; ``decode_mode`` makes this distinction explicit.
        Lone surrogates and surrogate escapes in non-JSON YAML are unsupported. An
        incomplete result cannot support a negative conclusion about omitted content.
    """
    result = {"status": "unsupported_structure", "complete": False, "scalars": [], "limits": dict(LIMITS)}
    if type(text) is not str:
        return {**result, "reason": "input_not_string"}
    if len(text) > LIMITS["max_codepoints"]:
        return {**result, "status": "budget_exceeded", "reason": "max_codepoints"}
    try:
        text.encode("utf-8")
        _preflight(text)
        json_document = _is_json_document(text)
        decode_mode = "json_string_tokens" if json_document else "yaml_baseloader"
        root = yaml.compose(text, Loader=yaml.BaseLoader)
        scalars, seen = [], set()

        def validate_node(node, depth: int) -> None:
            if id(node) in seen:
                raise _Unsupported("shared_node")
            seen.add(id(node))
            if len(seen) > LIMITS["max_nodes"]:
                raise _BudgetExceeded("max_nodes")
            if depth > LIMITS["max_depth"]:
                raise _BudgetExceeded("max_depth")
            if not isinstance(node, (MappingNode, SequenceNode, ScalarNode)):
                raise _Unsupported("unsupported_node")
            start, end = node.start_mark.index, node.end_mark.index
            if not (type(start) is int and type(end) is int and 0 <= start <= end <= len(text)):
                raise _Unsupported("invalid_node_span")

        def scalar_value(node: ScalarNode) -> str:
            if node.tag != "tag:yaml.org,2002:str" or type(node.value) is not str or node.style not in STYLES:
                raise _Unsupported("unsupported_scalar")
            if json_document and node.style == '"':
                value = json.loads(text[node.start_mark.index : node.end_mark.index])
                if type(value) is not str:
                    raise _Unsupported("invalid_json_string_token")
            else:
                value = node.value
            value.encode("utf-8")
            return value

        def walk(node, pointer: str, depth: int) -> None:
            validate_node(node, depth)
            if isinstance(node, ScalarNode):
                decoded = scalar_value(node)
                if len(scalars) >= LIMITS["max_scalars"]:
                    raise _BudgetExceeded("max_scalars")
                start, end = node.start_mark.index, node.end_mark.index
                scalars.append(
                    {
                        "scalar_pointer": pointer,
                        "decoded_text": decoded,
                        "wire_span": [start, end],
                        "decoded_sha256": _hash(decoded),
                        "wire_token_sha256": _hash(text[start:end]),
                        "style": STYLES[node.style],
                        "decode_mode": decode_mode,
                    }
                )
            elif isinstance(node, SequenceNode):
                if node.tag != "tag:yaml.org,2002:seq":
                    raise _Unsupported("unsupported_sequence")
                for index, child in enumerate(node.value):
                    walk(child, f"{pointer}/{index}", depth + 1)
            else:
                if node.tag != "tag:yaml.org,2002:map":
                    raise _Unsupported("unsupported_mapping")
                keys = set()
                for key, child in node.value:
                    validate_node(key, depth + 1)
                    if not isinstance(key, ScalarNode):
                        raise _Unsupported("non_scalar_key")
                    key_value = scalar_value(key)
                    if key_value in keys:
                        raise _Unsupported("duplicate_key")
                    keys.add(key_value)
                    walk(child, f"{pointer}/{_pointer_token(key_value)}", depth + 1)

        if root is not None:
            walk(root, "", 0)
        status = "plain_text" if isinstance(root, ScalarNode) and root.style is None else "parsed"
        return {**result, "status": status, "complete": True, "scalars": scalars, "decode_mode": decode_mode}
    except _BudgetExceeded as error:
        return {**result, "status": "budget_exceeded", "reason": str(error)}
    except _Unsupported as error:
        return {**result, "reason": str(error)}
    except UnicodeError:
        return {**result, "reason": "invalid_unicode_scalar"}
    except RecursionError:
        return {**result, "status": "budget_exceeded", "reason": "parser_recursion_limit"}
    except yaml.YAMLError:
        return {**result, "reason": "yaml_syntax_error"}
    except ValueError:
        return {**result, "reason": "invalid_scalar_escape"}
