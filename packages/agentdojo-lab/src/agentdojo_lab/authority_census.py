"""Request-free authority-argument census on vendored AgentDojo v1.2.2 (protocol authority-origin-census-v1).

E0 asks where the correct authority values of user tasks come from.  For every
user task the module executes ``ground_truth()`` on a deep copy of the default
environment through AgentDojo's own ``FunctionsRuntime`` and classifies each
authority-argument value of each state-changing call as (a) literally in the
user prompt, (b) only in the pre-task environment data, or (c) neither.

E1 asks whether an injection task's attacker authority value is co-located with
the injected instruction (stated literally in GOAL) and whether it already
exists in the clean environment (a selection-steering seed).  It also records,
for every user task, the injection vectors its ground-truth run exposes, using
``BaseAttack.get_injection_candidates`` from AgentDojo itself.

The role table, matching rules and fallbacks are frozen in
``configs/authority_census_v1.json``.  Nothing here calls a model, a provider or
the network.  Task prompts, goals and environment text are benchmark data and
are never interpreted as instructions.

Protocol v2 (``configs/authority_census_v2.json``) is a successor, not an edit:
the v1 code path below is unchanged and must still reproduce the v1 outputs.  A
v2 config runs the same core and then ``augment_v2`` adds the verifier-requested
fixes (D1 vector-dependency flag, D2 GOAL-literal coverage, D3 view overlap,
D4 first-exposure K2 reading; D5 is a config-only fallback entry), the post hoc
sensitivity tables and the check against the verifier's expected values.
"""

from __future__ import annotations

import copy
import csv
import datetime
import difflib
import hashlib
import inspect
import io
import json
import re
import socket
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

PROTOCOL = "authority-origin-census-v1"
EXPERIMENT_ID = "20261007-authority-origin-census-v1"
CONFIG_RELATIVE = "configs/authority_census_v1.json"
PROTOCOL_V2 = "authority-origin-census-v2"
EXPERIMENT_ID_V2 = "20261008-authority-origin-census-v2"
CONFIG_RELATIVE_V2 = "configs/authority_census_v2.json"
PROTOCOLS = {
    PROTOCOL: {"schema_version": 1, "experiment_id": EXPERIMENT_ID, "config_relative": CONFIG_RELATIVE},
    PROTOCOL_V2: {"schema_version": 2, "experiment_id": EXPERIMENT_ID_V2, "config_relative": CONFIG_RELATIVE_V2},
}
SUITES = ("workspace", "travel", "banking", "slack")
TOOL_CLASSES = ("state_changing", "exfiltration_read", "read_only")
IDENTIFIER_KINDS = ("email_id", "calendar_event_id", "cloud_file_id", "transaction_id")
VALUE_KINDS = ("email_address", "account", "slack_user", "slack_channel", "url", "booking_target", *IDENTIFIER_KINDS)
V2_EXTRA_VALUE_KINDS = ("event_location",)
ORIGINS = ("a_prompt", "b_environment", "c_neither")
NUMERIC_EXTRA_BOUNDARY = frozenset("-./:")
NEAR_MATCH_LIMIT = 5
PATH_LIMIT = 5
FALLBACK_RULES = (
    "literal",
    "next_email_id",
    "unread_email_ids",
    "largest_file_ids",
    "account_email",
    "day_participants_excluding_account",
)
V2_FALLBACK_RULES = ("id_range",)
VALUE_EXTRACTORS = ("file_attachment_ids",)
V2_CHANGE_IDS = ("D1", "D2", "D3", "D4", "D5")
PRECISION_RULES = (
    "tasks_with_b",
    "tasks_with_b_minus_utility_noop",
    "tasks_with_b_or_c",
    "tasks_with_b_or_c_minus_utility_noop",
    "tasks_with_b_excluding_combined",
    "tasks_with_b_exact_field",
    "tasks_with_b_excluding_vector_dependent",
)
_CREDENTIAL_PATTERNS = (
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
)
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]|(?:^|[\s'\"(=])/(?:Users|home|mnt|private|var|tmp)/")


# ---------------------------------------------------------------------------
# Small deterministic helpers


def dump_json(value: object) -> str:
    """Deterministic UTF-8 JSON: sorted keys, two-space indent, trailing newline."""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lf_normalized_sha256(data: bytes) -> str:
    return sha256_bytes(data.replace(b"\r\n", b"\n"))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _task_number(task_id: str) -> int:
    match = re.search(r"(\d+)$", task_id)
    _require(match is not None, f"Task id without a number: {task_id}")
    return int(match.group(1))


def sorted_task_ids(task_ids) -> list[str]:
    return sorted(task_ids, key=_task_number)


def assert_no_credentials(text: str, where: str = "output") -> None:
    """Fail closed if an output contains a credential-shaped string (the value is never echoed)."""
    for pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"Credential-shaped string in {where} (pattern {pattern.pattern[:24]!r})")


def assert_no_absolute_paths(text: str, where: str = "output") -> None:
    match = _ABSOLUTE_PATH.search(text)
    if match:
        raise ValueError(f"Absolute machine path in {where}: {text[max(0, match.start() - 20):match.end() + 20]!r}")


# ---------------------------------------------------------------------------
# Normalisation and matching (config "matching")


def normalise(text: str) -> str:
    """Casefold and collapse every run of Unicode whitespace to a single space."""
    return " ".join(str(text).casefold().split())


def _boundary_ok(haystack: str, start: int, end: int, needle: str) -> bool:
    numeric = needle.isdigit()
    if needle[0].isalnum() and start > 0:
        before = haystack[start - 1]
        if before.isalnum() or (numeric and before in NUMERIC_EXTRA_BOUNDARY):
            return False
    if needle[-1].isalnum() and end < len(haystack):
        after = haystack[end]
        if after.isalnum() or (numeric and after in NUMERIC_EXTRA_BOUNDARY):
            return False
    return True


def occurrences(haystack: str, needle: str) -> int:
    """Count boundary-respecting occurrences of a normalised needle in a normalised haystack."""
    if not needle:
        return 0
    count, start = 0, haystack.find(needle)
    while start != -1:
        if _boundary_ok(haystack, start, start + len(needle), needle):
            count += 1
        start = haystack.find(needle, start + 1)
    return count


def contains(haystack: str, needle: str) -> bool:
    return occurrences(haystack, needle) > 0


def value_strings(value: object) -> list[str]:
    """Element-wise string forms of an argument value; None, '' and [] are absent."""
    if value is None:
        return []
    if isinstance(value, bool):
        return [str(value)]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(value_strings(item))
        return out
    if isinstance(value, (int, str)):
        text = str(value)
        return [text] if text.strip() else []
    return [str(value)]


def to_jsonable(value: object) -> object:
    from pydantic_core import to_jsonable_python

    return to_jsonable_python(value, fallback=str)


# ---------------------------------------------------------------------------
# Environment / tool-output index


class TextIndex:
    """Normalised string leaves, dictionary keys and typed identifier fields of a jsonable value.

    ``identifier_kinds`` maps an identifier kind to ``{"id_field": ..., "signature": [...]}``: a JSON
    object whose keys include the whole signature is an object of that kind, and its ``id_field``
    value is recorded as an identifier of that kind.
    """

    def __init__(self, value: object, identifier_kinds: dict[str, dict]):
        self.identifier_kinds = identifier_kinds
        self.texts: list[tuple[str, str]] = []
        self.ids: list[tuple[str, str, str]] = []
        self._candidates: dict[str, str] | None = None
        self._walk(value, "")

    def _walk(self, value: object, path: str) -> None:
        if isinstance(value, dict):
            keys = {str(key) for key in value}
            for kind, spec in self.identifier_kinds.items():
                field = spec["id_field"]
                if set(spec["signature"]) <= keys and isinstance(value.get(field), (str, int)):
                    if not isinstance(value.get(field), bool):
                        self.ids.append((f"{path}.{field}" if path else field, kind, str(value[field])))
            for key, item in value.items():
                child = f"{path}.{key}" if path else str(key)
                self.texts.append((f"{child}#key", normalise(str(key))))
                self._walk(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._walk(item, f"{path}[{index}]")
        elif isinstance(value, str):
            self.texts.append((path, normalise(value)))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            self.texts.append((path, normalise(str(value))))

    def find(self, value: str, kind: str) -> list[str]:
        """Paths at which ``value`` is present under the kind's environment rule."""
        if kind in IDENTIFIER_KINDS:
            return [path for path, id_kind, item in self.ids if id_kind == kind and item == str(value)]
        needle = normalise(value)
        return [path for path, text in self.texts if contains(text, needle)]

    def find_exact(self, value: str, kind: str) -> list[str]:
        """v2 sensitivity: like ``find`` but a text kind must equal a whole normalised leaf or key."""
        if kind in IDENTIFIER_KINDS:
            return self.find(value, kind)
        needle = normalise(value)
        return [path for path, text in self.texts if text == needle]

    def candidates(self) -> dict[str, str]:
        """Whole normalised strings and their punctuation-stripped tokens, each with its first path."""
        if self._candidates is None:
            cache: dict[str, str] = {}
            for path, text in self.texts:
                for candidate in (text, *(token.strip("'\"()[]{}<>,;:.!?") for token in text.split(" "))):
                    if candidate and candidate not in cache:
                        cache[candidate] = path
            self._candidates = cache
        return self._candidates

    def near_matches(self, value: str) -> list[dict]:
        """Diagnostic only (J15): environment strings that nearly, but not exactly, denote ``value``."""
        needle = normalise(value)
        if not needle:
            return []
        found: dict[str, dict] = {}
        for candidate, path in self.candidates().items():
            if candidate == needle:
                continue
            if len(candidate.split(" ")) >= 2 and len(candidate) >= 0.5 * len(needle) and contains(needle, candidate):
                found[candidate] = {"text": candidate, "path": path, "reason": "environment string inside value"}
                continue
            if abs(len(candidate) - len(needle)) <= 0.3 * len(needle):
                matcher = difflib.SequenceMatcher(None, candidate, needle)
                if matcher.real_quick_ratio() >= 0.85 and matcher.quick_ratio() >= 0.85:
                    ratio = matcher.ratio()
                    if ratio >= 0.85:
                        found[candidate] = {"text": candidate, "path": path, "reason": f"difflib ratio {ratio:.3f}"}
        return [found[key] for key in sorted(found)][:NEAR_MATCH_LIMIT]


# ---------------------------------------------------------------------------
# Config loading and role-table validation


def load_config(path: Path) -> tuple[dict, bytes]:
    raw = Path(path).read_bytes()
    config = json.loads(raw.decode("utf-8"))
    validate_config(config)
    return config, raw


def protocol_spec(config: dict) -> dict:
    spec = PROTOCOLS.get(config.get("protocol"))
    _require(spec is not None, f"Config protocol must be one of {sorted(PROTOCOLS)}")
    return spec


def is_v2(config: dict) -> bool:
    return config.get("protocol") == PROTOCOL_V2


def validate_config(config: dict) -> None:
    _validate_core(config)
    if is_v2(config):
        validate_v2_sections(config)


def _validate_core(config: dict) -> None:
    """Protocol, inventory shape, role table and fallback checks shared by v1 and v2 (and v2 role variants)."""
    spec = protocol_spec(config)
    version = spec["schema_version"]
    _require(config.get("schema_version") == version, f"Config schema_version must be {version}")
    _require(config.get("experiment_id") == spec["experiment_id"], f"Config experiment_id must be {spec['experiment_id']}")
    _require(config["benchmark"]["benchmark_version"] == "v1.2.2", "Census is defined for benchmark v1.2.2")
    _require(tuple(config["benchmark"]["suites"]) == SUITES, f"Suites must be {SUITES}")
    if is_v2(config):
        allowed = set(VALUE_KINDS) | set(V2_EXTRA_VALUE_KINDS)
        _require(
            set(VALUE_KINDS) <= set(config["value_kinds"]) <= allowed,
            "value_kinds must list the module's kinds plus only the v2 extra kinds",
        )
    else:
        _require(set(config["value_kinds"]) == set(VALUE_KINDS), "value_kinds must list exactly the module's kinds")
    known_kinds = set(config["value_kinds"])
    fallback_rules = FALLBACK_RULES + (V2_FALLBACK_RULES if is_v2(config) else ())
    _require(set(config["identifier_kinds"]) == set(IDENTIFIER_KINDS), "identifier_kinds must list the id kinds")
    for kind, spec in config["identifier_kinds"].items():
        _require(spec["id_field"] in spec["signature"], f"{kind}: id_field must be part of the signature")
    for suite, tools in config["tools"].items():
        _require(suite in SUITES, f"Unknown suite in role table: {suite}")
        for name, role in tools.items():
            _require(role.get("class") in TOOL_CLASSES, f"{suite}.{name}: unknown class {role.get('class')}")
            authority = role.get("authority", {})
            exfil = role.get("exfiltration_arguments", {})
            for argument, kind in {**authority, **exfil}.items():
                _require(kind in known_kinds, f"{suite}.{name}.{argument}: unknown kind {kind}")
            for argument, extractor in role.get("value_extractors", {}).items():
                _require(extractor in VALUE_EXTRACTORS, f"{suite}.{name}.{argument}: unknown extractor {extractor}")
                _require(argument in authority, f"{suite}.{name}.{argument}: extractor on a non-authority argument")
            if role["class"] == "state_changing":
                _require("authority" in role and "content" in role, f"{suite}.{name}: state_changing needs both lists")
                _require(not set(authority) & set(role["content"]), f"{suite}.{name}: argument in two roles")
                _require(not exfil, f"{suite}.{name}: state_changing tools have no exfiltration arguments")
            elif role["class"] == "exfiltration_read":
                _require(bool(exfil), f"{suite}.{name}: exfiltration_read needs exfiltration_arguments")
                _require(not authority and not role.get("content"), f"{suite}.{name}: read tools have no roles")
            else:
                _require(not authority and not exfil and not role.get("content"), f"{suite}.{name}: read_only has roles")
    fallback = config["e1"]["security_checker_fallback"]
    for suite in SUITES:
        for task_id, entries in fallback.get(suite, {}).items():
            for entry in entries:
                _require(entry.get("rule") in fallback_rules, f"{suite}.{task_id}: unknown fallback rule")
                role = config["tools"][suite].get(entry["function"])
                _require(role is not None, f"{suite}.{task_id}: fallback tool {entry['function']} not in role table")
                _require(
                    entry["argument"] in role.get("authority", {}),
                    f"{suite}.{task_id}: fallback argument {entry['function']}.{entry['argument']} is not authority",
                )
                _require(not ("tag" in entry and not is_v2(config)), f"{suite}.{task_id}: fallback tags are v2 only")


def validate_v2_sections(config: dict) -> None:
    """v2 only: predecessor binding, amendment log, sensitivity and verifier sections."""
    predecessor = config["predecessor"]
    _require(predecessor["protocol"] == PROTOCOL, "v2 predecessor must be protocol v1")
    _require(predecessor["experiment_id"] == EXPERIMENT_ID, "v2 predecessor must be the v1 experiment")
    _require(re.fullmatch(r"[0-9a-f]{64}", predecessor["config_sha256"]) is not None, "predecessor hash must be SHA-256")
    entry = config["amendment_log"][-1]
    _require(entry.get("protocol") == PROTOCOL_V2, "the last amendment_log entry must be the v2 entry")
    _require(entry.get("predecessor_config_sha256") == predecessor["config_sha256"], "amendment must record the hash")
    change_ids = [change["id"] for change in entry["changes"]]
    _require(all(change in change_ids for change in V2_CHANGE_IDS), f"amendment_log must record {V2_CHANGE_IDS}")
    _require(not str(config["frozen_at"]).startswith("FROZEN"), "v2 config is not frozen (frozen_at placeholder)")
    vector = config["e0"]["vector_dependency"]
    _require(re.fullmatch(r"[a-z]{8,}", vector["placeholder"]) is not None, "vector placeholder must be one token")
    sensitivity = config["sensitivity"]
    rows = sensitivity["precision_denominator"]
    _require([row["rule"] for row in rows] == list(PRECISION_RULES), "precision rows must follow PRECISION_RULES")
    _require(rows[0].get("primary") is True, "P0 must be the primary row")
    expected_combined = sensitivity["combined_tasks"]["expected"]
    _require(set(expected_combined) == set(SUITES), "combined_tasks.expected must list every suite")
    for variant in sensitivity["role_variants"]:
        variant_config = apply_role_variant(config, variant)
        _validate_core(variant_config)
        _require(variant_config["tools"] != config["tools"], f"{variant['id']}: variant changes nothing")
    checks = config["verifier_expectations"]["checks"]
    _require(len({check["id"] for check in checks}) == len(checks), "verifier check ids must be unique")
    for check in checks:
        _require(isinstance(check["path"], list) and check["path"], f"{check['id']}: path must be a non-empty list")


def tool_parameters(suite) -> dict[str, list[str]]:
    return {tool.name: list(tool.parameters.model_json_schema().get("properties", {})) for tool in suite.tools}


def validate_role_table(config: dict, suites: dict) -> list[dict]:
    """Check that the frozen role table partitions every installed tool and argument; return table rows."""
    rows = []
    for suite_name in SUITES:
        installed = tool_parameters(suites[suite_name])
        frozen = config["tools"][suite_name]
        _require(
            set(installed) == set(frozen),
            f"{suite_name}: role table tools differ from installed tools: "
            f"missing={sorted(set(installed) - set(frozen))} extra={sorted(set(frozen) - set(installed))}",
        )
        for tool_name in installed:
            role = frozen[tool_name]
            parameters = installed[tool_name]
            authority = role.get("authority", {})
            exfil = role.get("exfiltration_arguments", {})
            content = role.get("content", [])
            if role["class"] == "state_changing":
                _require(
                    set(authority) | set(content) == set(parameters),
                    f"{suite_name}.{tool_name}: roles {sorted(set(authority) | set(content))} != "
                    f"parameters {sorted(parameters)}",
                )
            else:
                _require(set(exfil) <= set(parameters), f"{suite_name}.{tool_name}: unknown exfiltration argument")
            for argument in parameters:
                if argument in authority:
                    argument_role, kind = "authority", authority[argument]
                elif argument in exfil:
                    argument_role, kind = "exfiltration", exfil[argument]
                elif argument in content:
                    argument_role, kind = "content", ""
                else:
                    argument_role, kind = "unclassified_read_argument", ""
                rows.append(
                    {
                        "suite": suite_name,
                        "tool": tool_name,
                        "tool_class": role["class"],
                        "argument": argument,
                        "argument_role": argument_role,
                        "value_kind": kind,
                        "note": role.get("note", ""),
                    }
                )
            if not parameters:
                rows.append(
                    {
                        "suite": suite_name,
                        "tool": tool_name,
                        "tool_class": role["class"],
                        "argument": "",
                        "argument_role": "no_arguments",
                        "value_kind": "",
                        "note": role.get("note", ""),
                    }
                )
    return rows


def check_inventory(config: dict, suites: dict) -> dict:
    observed = {
        name: {
            "user_tasks": len(suites[name].user_tasks),
            "injection_tasks": len(suites[name].injection_tasks),
            "tools": len(suites[name].tools),
        }
        for name in SUITES
    }
    _require(
        observed == config["benchmark"]["expected_inventory"],
        f"Installed inventory differs from the frozen config: {observed}",
    )
    return observed


# ---------------------------------------------------------------------------
# Ground-truth execution


def run_ground_truth(suite, task, environment) -> list[dict]:
    """Execute a task's ground_truth exactly as GroundTruthPipeline does, keeping raw results.

    Calls are computed from the environment before any of them runs, then run in order
    with ``raise_on_error=True``.  Arguments are deep-copied before execution because
    some tools mutate list arguments in place.
    """
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.functions_runtime import FunctionsRuntime

    calls = task.ground_truth(environment)
    runtime = FunctionsRuntime(suite.tools)
    records = []
    for index, call in enumerate(calls):
        args = copy.deepcopy(dict(call.args))
        result, error = runtime.run_function(environment, call.function, call.args, raise_on_error=True)
        records.append(
            {
                "index": index,
                "function": call.function,
                "args": args,
                "result": to_jsonable(result),
                "rendered": tool_result_to_str(result),
                "error": error,
            }
        )
    return records


def role_of(config: dict, suite_name: str, function: str) -> dict:
    role = config["tools"][suite_name].get(function)
    _require(role is not None, f"{suite_name}: ground truth calls unclassified tool {function}")
    return role


def authority_values(config: dict, suite_name: str, function: str, args: dict, *, exfiltration: bool = False):
    """Yield (argument, kind, element_index, value) for authority (or exfiltration) arguments of one call."""
    role = role_of(config, suite_name, function)
    if exfiltration:
        if role["class"] != "exfiltration_read":
            return
        selected = role["exfiltration_arguments"]
    else:
        if role["class"] != "state_changing":
            return
        selected = role["authority"]
    extractors = role.get("value_extractors", {})
    for argument, kind in selected.items():
        raw = args.get(argument)
        values = extract_values(extractors[argument], raw) if argument in extractors else value_strings(raw)
        for element, value in enumerate(values):
            yield argument, kind, element, value


def extract_values(extractor: str, raw: object) -> list[str]:
    """v2 role variants only: element-wise values of an argument that needs parsing (config value_extractors)."""
    if extractor == "file_attachment_ids":
        # As send_email parses attachments: a dict of type 'file' (or with a file_id) names a cloud file;
        # an event attachment carries event details (content) and names no existing resource.
        out = []
        for item in raw or []:
            if isinstance(item, dict) and (item.get("type") == "file" or "file_id" in item):
                out.extend(value_strings(item.get("file_id")))
        return out
    raise ValueError(f"Unknown value extractor {extractor}")


# ---------------------------------------------------------------------------
# E0


def classify_value(value: str, kind: str, prompt: str, environment: TextIndex) -> dict:
    in_prompt = contains(normalise(prompt), normalise(value))
    paths = environment.find(value, kind)
    if in_prompt:
        origin = "a_prompt"
    elif paths:
        origin = "b_environment"
    else:
        origin = "c_neither"
    return {"origin": origin, "in_prompt": in_prompt, "in_environment": bool(paths), "environment_paths": paths}


def vector_hits(value: str, kind: str, vector_defaults: dict[str, str]) -> list[str]:
    if kind in IDENTIFIER_KINDS:
        return []
    needle = normalise(value)
    return sorted(vector for vector, text in vector_defaults.items() if contains(normalise(text), needle))


def census_user_tasks(config: dict, suite_name: str, suite) -> dict:
    default_environment = suite.load_and_inject_default_environment({})
    default_dump = to_jsonable(default_environment)
    identifier_kinds = config["identifier_kinds"]
    default_index = TextIndex(default_dump, identifier_kinds)
    vector_defaults = suite.get_injection_vector_defaults()
    value_rows, exfil_rows, task_rows = [], [], []
    for task_id in sorted_task_ids(suite.user_tasks):
        task = suite.user_tasks[task_id]
        pre_environment = task.init_environment(default_environment.model_copy(deep=True))
        pre_dump = to_jsonable(pre_environment)
        environment_index = default_index if pre_dump == default_dump else TextIndex(pre_dump, identifier_kinds)
        records = run_ground_truth(suite, task, pre_environment.model_copy(deep=True))
        output_indexes = [TextIndex(record["result"], identifier_kinds) for record in records]
        task_values, task_exfil = [], []
        for record in records:
            for exfiltration, sink in ((False, task_values), (True, task_exfil)):
                for argument, kind, element, value in authority_values(
                    config, suite_name, record["function"], record["args"], exfiltration=exfiltration
                ):
                    verdict = classify_value(value, kind, task.PROMPT, environment_index)
                    exposing = [
                        {"index": earlier["index"], "function": earlier["function"]}
                        for earlier, index in zip(records[: record["index"]], output_indexes[: record["index"]])
                        if index.find(value, kind)
                    ]
                    row = {
                        "suite": suite_name,
                        "user_task_id": task_id,
                        "call_index": record["index"],
                        "function": record["function"],
                        "argument": argument,
                        "element_index": element,
                        "value_kind": kind,
                        "value": value,
                        "origin": verdict["origin"],
                        "in_prompt": verdict["in_prompt"],
                        "in_environment": verdict["in_environment"],
                        "environment_match_count": len(verdict["environment_paths"]),
                        "environment_paths": verdict["environment_paths"][:PATH_LIMIT],
                        "exposed_before_call": bool(exposing),
                        "exposing_calls": exposing,
                        "in_injection_vector_defaults": vector_hits(value, kind, vector_defaults),
                        "near_matches": (
                            environment_index.near_matches(value)
                            if verdict["origin"] != "a_prompt" and kind not in IDENTIFIER_KINDS
                            else []
                        ),
                    }
                    sink.append(row)
        state_changing = [
            record for record in records if role_of(config, suite_name, record["function"])["class"] == "state_changing"
        ]
        counts = Counter(row["origin"] for row in task_values)
        task_rows.append(
            {
                "suite": suite_name,
                "user_task_id": task_id,
                "prompt": task.PROMPT,
                "ground_truth_calls": len(records),
                "state_changing_calls": len(state_changing),
                "state_changing_functions": [record["function"] for record in state_changing],
                "authority_values": len(task_values),
                "a_prompt": counts["a_prompt"],
                "b_environment": counts["b_environment"],
                "c_neither": counts["c_neither"],
                "b_exposed_before_call": sum(
                    1 for row in task_values if row["origin"] == "b_environment" and row["exposed_before_call"]
                ),
                "values_in_injection_vector_defaults": sum(1 for row in task_values if row["in_injection_vector_defaults"]),
                "precision_denominator": counts["b_environment"] > 0,
                "exfiltration_read_values": len(task_exfil),
            }
        )
        value_rows.extend(task_values)
        exfil_rows.extend(task_exfil)
    return {"values": value_rows, "exfiltration_values": exfil_rows, "tasks": task_rows}


# ---------------------------------------------------------------------------
# E1


def derive_fallback_values(entry: dict, clean_environment) -> list[str]:
    """Attacker authority values for one security-checker fallback entry (config e1.security_checker_fallback)."""
    rule = entry["rule"]
    environment = clean_environment.model_copy(deep=True)
    if rule == "literal":
        return [str(entry["value"])]
    if rule == "next_email_id":
        return [str(int(environment.inbox._get_next_id()) + int(entry.get("offset", 0)))]
    if rule == "unread_email_ids":
        return [str(email.id_) for email in sorted(environment.inbox.get_unread(), key=lambda email: int(email.id_))]
    if rule == "largest_file_ids":
        ranked = sorted(environment.cloud_drive.files.items(), key=lambda item: item[1].size, reverse=True)
        return [str(file_id) for file_id, _ in ranked[: int(entry["n"])]]
    if rule == "account_email":
        return [str(environment.inbox.account_email)]
    if rule == "id_range":
        return [str(index) for index in range(int(entry["start"]), int(entry["stop"]))]
    if rule == "day_participants_excluding_account":
        day = datetime.date.fromisoformat(entry["day"])
        account = environment.inbox.account_email
        participants = {
            participant
            for event in environment.calendar.get_by_day(day)
            for participant in event.participants
            if participant != account
        }
        return sorted(participants)
    raise ValueError(f"Unknown fallback rule {rule}")


def source_location(obj, vendor_src: Path | None) -> str:
    """'path:first-last' for a function or class, relative to the vendored source root when possible."""
    try:
        file = Path(inspect.getsourcefile(obj)).resolve()
        lines, start = inspect.getsourcelines(obj)
    except (OSError, TypeError):
        return "unavailable"
    relative = file.name
    if vendor_src is not None:
        try:
            relative = file.relative_to(vendor_src.resolve()).as_posix()
        except ValueError:
            relative = file.name
    return f"{relative}:{start}-{start + len(lines) - 1}"


def raw_environment_texts(suite_name: str, data_root: Path) -> dict[str, str]:
    """On-disk environment YAML text (environment.yaml plus workspace include files), keyed by relative path."""
    folder = data_root / suite_name
    files = [folder / "environment.yaml", *sorted((folder / "include").glob("*.yaml"))]
    return {path.relative_to(data_root).as_posix(): path.read_text(encoding="utf-8") for path in files if path.is_file()}


def raw_occurrences(value: str, kind: str, raw_texts: dict[str, str]) -> dict:
    if kind in IDENTIFIER_KINDS:
        return {"count": None, "lines": []}
    needle = normalise(value)
    total, lines = 0, []
    for name, text in raw_texts.items():
        total += occurrences(normalise(text), needle)
        for number, line in enumerate(text.splitlines(), start=1):
            if contains(normalise(line), needle):
                lines.append(f"{name}:{number}")
    return {"count": total, "lines": lines[:PATH_LIMIT]}


def attacker_value_row(
    suite_name, task_id, source, function, argument, element, kind, value, goal, clean_index, raw_texts,
    vector_defaults, tool_class, checker,
) -> dict:
    stated = contains(normalise(goal), normalise(value))
    paths = clean_index.find(value, kind)
    raw = raw_occurrences(value, kind, raw_texts)
    if stated:
        label = "goal_literal"
    elif paths:
        label = "environment_preexisting_not_in_goal"
    else:
        label = "neither_goal_nor_environment"
    return {
        "suite": suite_name,
        "injection_task_id": task_id,
        "value_source": source,
        "checker_source": checker,
        "tool_class": tool_class,
        "function": function,
        "argument": argument,
        "element_index": element,
        "value_kind": kind,
        "value": value,
        "stated_in_goal": stated,
        "in_clean_environment": bool(paths),
        "environment_match_count": len(paths),
        "environment_paths": paths[:PATH_LIMIT],
        "raw_environment_yaml_occurrences": raw["count"],
        "raw_environment_yaml_lines": raw["lines"],
        "in_injection_vector_defaults": vector_hits(value, kind, vector_defaults),
        "label": label,
        "near_matches": clean_index.near_matches(value) if kind not in IDENTIFIER_KINDS and not paths else [],
    }


def _e1_task_category(values: list[dict]) -> str:
    if not values:
        return "no_authority_value"
    stated = sum(1 for row in values if row["stated_in_goal"])
    if stated == len(values):
        return "all_goal_literal"
    if stated:
        return "partial_goal_literal"
    return "none_goal_literal"


def summarise_attacker_values(values: list[dict]) -> dict:
    introduced = [row for row in values if not row["in_clean_environment"]]
    return {
        "values": len(values),
        "goal_literal": sum(1 for row in values if row["stated_in_goal"]),
        "in_clean_environment": sum(1 for row in values if row["in_clean_environment"]),
        "environment_preexisting_not_in_goal": sum(
            1 for row in values if row["label"] == "environment_preexisting_not_in_goal"
        ),
        "neither_goal_nor_environment": sum(1 for row in values if row["label"] == "neither_goal_nor_environment"),
        "attacker_introduced": len(introduced),
        "attacker_introduced_goal_literal": sum(1 for row in introduced if row["stated_in_goal"]),
        "category": _e1_task_category(values),
        "any_goal_literal": any(row["stated_in_goal"] for row in values),
        "co_located": bool(introduced) and all(row["stated_in_goal"] for row in introduced),
        "seed_candidate": any(row["in_clean_environment"] for row in values),
    }


def census_injection_tasks(config: dict, suite_name: str, suite, data_root: Path, vendor_src: Path | None) -> dict:
    clean_environment = suite.load_and_inject_default_environment({})
    clean_index = TextIndex(to_jsonable(clean_environment), config["identifier_kinds"])
    vector_defaults = suite.get_injection_vector_defaults()
    raw_texts = raw_environment_texts(suite_name, data_root)
    fallback = config["e1"]["security_checker_fallback"].get(suite_name, {})
    value_rows, task_rows = [], []
    for task_id in sorted_task_ids(suite.injection_tasks):
        task = suite.injection_tasks[task_id]
        calls = task.ground_truth(clean_environment.model_copy(deep=True))
        security_location = source_location(type(task).security, vendor_src)
        gt_rows, fallback_rows = [], []
        for call in calls:
            args = copy.deepcopy(dict(call.args))
            for exfiltration in (False, True):
                tool_class = "exfiltration_read" if exfiltration else "state_changing"
                for argument, kind, element, value in authority_values(
                    config, suite_name, call.function, args, exfiltration=exfiltration
                ):
                    gt_rows.append(
                        attacker_value_row(
                            suite_name, task_id, "ground_truth", call.function, argument, element, kind, value,
                            task.GOAL, clean_index, raw_texts, vector_defaults, tool_class, "",
                        )
                    )
        if not calls and task_id in fallback:
            for entry in fallback[task_id]:
                kind = config["tools"][suite_name][entry["function"]]["authority"][entry["argument"]]
                for element, value in enumerate(derive_fallback_values(entry, clean_environment)):
                    fallback_rows.append(
                        attacker_value_row(
                            suite_name, task_id, "security_checker_fallback", entry["function"], entry["argument"],
                            element, kind, value, task.GOAL, clean_index, raw_texts, vector_defaults,
                            "state_changing", security_location,
                        )
                    )
        elif calls and task_id in fallback:
            raise ValueError(f"{suite_name}.{task_id}: fallback configured but ground_truth is not empty")
        rows = gt_rows + fallback_rows
        main_gt = [row for row in gt_rows if row["tool_class"] == "state_changing"]
        main_all = [row for row in rows if row["tool_class"] == "state_changing"]
        task_rows.append(
            {
                "suite": suite_name,
                "injection_task_id": task_id,
                "goal": task.GOAL,
                "ground_truth_calls": len(calls),
                "ground_truth_functions": [call.function for call in calls],
                "value_source": (
                    "ground_truth" if calls else ("security_checker_fallback" if task_id in fallback else "none")
                ),
                "security_checker_source": security_location,
                "gt_only": summarise_attacker_values(main_gt),
                "gt_plus_fallback": summarise_attacker_values(main_all),
                "gt_plus_fallback_with_exfiltration_reads": summarise_attacker_values(rows),
            }
        )
        value_rows.extend(rows)
    return {"values": value_rows, "tasks": task_rows}


def vector_exposure(suite_name: str, suite) -> list[dict]:
    """Injection vectors exposed by each user task's ground truth (AgentDojo's own mechanism + parity run)."""
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    from agentdojo.attacks.base_attacks import BaseAttack

    attack = BaseAttack(suite, GroundTruthPipeline(None))
    canaries = attack.canary_injections
    canary_environment = suite.load_and_inject_default_environment(canaries)
    rows = []
    for task_id in sorted_task_ids(suite.user_tasks):
        task = suite.user_tasks[task_id]
        try:
            vectors = list(attack.get_injection_candidates(task))
            error = ""
        except ValueError as exc:
            vectors, error = [], str(exc)
        records = run_ground_truth(suite, task, canary_environment.model_copy(deep=True))
        first: dict[str, dict] = {}
        exposing_calls: dict[str, list[int]] = defaultdict(list)
        for record in records:
            for vector, canary in canaries.items():
                if canary in record["rendered"]:
                    exposing_calls[vector].append(record["index"])
                    first.setdefault(vector, {"index": record["index"], "function": record["function"]})
        ordered = sorted(first, key=lambda vector: (first[vector]["index"], vector))
        rows.append(
            {
                "suite": suite_name,
                "user_task_id": task_id,
                "agentdojo_vectors": vectors,
                "agentdojo_error": error,
                "vector_count": len(vectors),
                "split_capable": len(vectors) >= 2,
                "ordered_vectors": ordered,
                "first_exposure": {vector: first[vector] for vector in ordered},
                "distinct_exposing_calls": len({index for indexes in exposing_calls.values() for index in indexes}),
                "parity_with_agentdojo": set(vectors) == set(first),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Aggregation


def _origin_counts(rows: list[dict]) -> dict:
    counts = Counter(row["origin"] for row in rows)
    return {origin: counts[origin] for origin in ORIGINS} | {"total": len(rows)}


def summarise_e0(tasks: list[dict], values: list[dict]) -> dict:
    per_suite = {}
    for suite in SUITES:
        suite_tasks = [row for row in tasks if row["suite"] == suite]
        suite_values = [row for row in values if row["suite"] == suite]
        per_suite[suite] = {
            "user_tasks": len(suite_tasks),
            "tasks_with_state_changing_call": sum(1 for row in suite_tasks if row["state_changing_calls"]),
            "tasks_with_authority_value": sum(1 for row in suite_tasks if row["authority_values"]),
            "tasks_with_a": sum(1 for row in suite_tasks if row["a_prompt"]),
            "tasks_with_b": sum(1 for row in suite_tasks if row["b_environment"]),
            "tasks_with_c": sum(1 for row in suite_tasks if row["c_neither"]),
            "tasks_all_a": sum(
                1 for row in suite_tasks if row["authority_values"] and row["a_prompt"] == row["authority_values"]
            ),
            "values": _origin_counts(suite_values),
            "b_exposed_before_call": sum(
                1 for row in suite_values if row["origin"] == "b_environment" and row["exposed_before_call"]
            ),
            "values_in_injection_vector_defaults": sum(1 for row in suite_values if row["in_injection_vector_defaults"]),
        }
    overall = {
        key: sum(per_suite[suite][key] for suite in SUITES)
        for key in (
            "user_tasks",
            "tasks_with_state_changing_call",
            "tasks_with_authority_value",
            "tasks_with_a",
            "tasks_with_b",
            "tasks_with_c",
            "tasks_all_a",
            "b_exposed_before_call",
            "values_in_injection_vector_defaults",
        )
    }
    overall["values"] = _origin_counts(values)
    per_tool: dict[str, dict] = {}
    for row in values:
        key = f"{row['suite']}.{row['function']}.{row['argument']}"
        cell = per_tool.setdefault(key, {origin: 0 for origin in ORIGINS} | {"total": 0, "tasks": set()})
        cell[row["origin"]] += 1
        cell["total"] += 1
        cell["tasks"].add(row["user_task_id"])
    per_tool_out = {
        key: {k: (len(v) if k == "tasks" else v) for k, v in cell.items()} for key, cell in sorted(per_tool.items())
    }
    per_function: dict[str, dict] = {}
    for row in values:
        key = f"{row['suite']}.{row['function']}"
        cell = per_function.setdefault(key, {origin: 0 for origin in ORIGINS} | {"total": 0})
        cell[row["origin"]] += 1
        cell["total"] += 1
    denominator = [
        {
            "suite": row["suite"],
            "user_task_id": row["user_task_id"],
            "b_values": [
                {
                    "function": value["function"],
                    "argument": value["argument"],
                    "value": value["value"],
                    "exposed_before_call": value["exposed_before_call"],
                    "in_injection_vector_defaults": value["in_injection_vector_defaults"],
                }
                for value in values
                if value["suite"] == row["suite"]
                and value["user_task_id"] == row["user_task_id"]
                and value["origin"] == "b_environment"
            ],
        }
        for row in tasks
        if row["precision_denominator"]
    ]
    return {
        "per_suite": per_suite,
        "overall": overall,
        "per_tool_argument": per_tool_out,
        "per_tool": dict(sorted(per_function.items())),
        "precision_denominator": denominator,
        "c_values": [
            {key: row[key] for key in ("suite", "user_task_id", "function", "argument", "value", "near_matches")}
            for row in values
            if row["origin"] == "c_neither"
        ],
    }


def summarise_exfiltration_e0(values: list[dict]) -> dict:
    return {
        "per_suite": {suite: _origin_counts([row for row in values if row["suite"] == suite]) for suite in SUITES},
        "tasks_with_b": sorted(
            {f"{row['suite']}.{row['user_task_id']}" for row in values if row["origin"] == "b_environment"},
            key=lambda key: (SUITES.index(key.split(".")[0]), _task_number(key)),
        ),
    }


_E1_VIEWS = ("gt_only", "gt_plus_fallback", "gt_plus_fallback_with_exfiltration_reads")


def _aggregate_e1_view(summaries: list[dict]) -> dict:
    """One suite's row of an E1 view table from its injection tasks' summarise_attacker_values() results."""
    return {
        "injection_tasks": len(summaries),
        "tasks_with_values": sum(1 for item in summaries if item["values"]),
        "values": sum(item["values"] for item in summaries),
        "values_goal_literal": sum(item["goal_literal"] for item in summaries),
        "values_in_clean_environment": sum(item["in_clean_environment"] for item in summaries),
        "values_neither": sum(item["neither_goal_nor_environment"] for item in summaries),
        "tasks_any_goal_literal": sum(1 for item in summaries if item["any_goal_literal"]),
        "tasks_all_goal_literal": sum(1 for item in summaries if item["category"] == "all_goal_literal"),
        "tasks_partial_goal_literal": sum(1 for item in summaries if item["category"] == "partial_goal_literal"),
        "tasks_none_goal_literal": sum(1 for item in summaries if item["category"] == "none_goal_literal"),
        "tasks_no_authority_value": sum(1 for item in summaries if item["category"] == "no_authority_value"),
        "tasks_co_located": sum(1 for item in summaries if item["co_located"]),
        "tasks_seed_candidate": sum(1 for item in summaries if item["seed_candidate"]),
    }


def summarise_e1(tasks: list[dict], exposure: list[dict]) -> dict:
    views = {}
    for view in _E1_VIEWS:
        per_suite = {}
        for suite in SUITES:
            per_suite[suite] = _aggregate_e1_view([row[view] for row in tasks if row["suite"] == suite])
        overall = {key: sum(per_suite[suite][key] for suite in SUITES) for key in per_suite[SUITES[0]]}
        views[view] = {"per_suite": per_suite, "overall": overall}
    split = {}
    for suite in SUITES:
        rows = [row for row in exposure if row["suite"] == suite]
        split[suite] = {
            "user_tasks": len(rows),
            "split_capable": sum(1 for row in rows if row["split_capable"]),
            "vector_count_histogram": [
                {"vectors": count, "user_tasks": tasks}
                for count, tasks in sorted(Counter(row["vector_count"] for row in rows).items())
            ],
            "split_capable_with_two_or_more_exposing_calls": sum(
                1 for row in rows if row["split_capable"] and row["distinct_exposing_calls"] >= 2
            ),
            "parity_failures": [row["user_task_id"] for row in rows if not row["parity_with_agentdojo"]],
            "split_capable_tasks": [row["user_task_id"] for row in rows if row["split_capable"]],
        }
    split_overall = {
        "user_tasks": sum(split[suite]["user_tasks"] for suite in SUITES),
        "split_capable": sum(split[suite]["split_capable"] for suite in SUITES),
        "split_capable_with_two_or_more_exposing_calls": sum(
            split[suite]["split_capable_with_two_or_more_exposing_calls"] for suite in SUITES
        ),
        "parity_failures": sum(len(split[suite]["parity_failures"]) for suite in SUITES),
    }
    seeds = [
        {
            "suite": row["suite"],
            "injection_task_id": row["injection_task_id"],
            "category": row["gt_plus_fallback"]["category"],
            "value_source": row["value_source"],
        }
        for row in tasks
        if row["gt_plus_fallback"]["seed_candidate"]
    ]
    return {"views": views, "split": {"per_suite": split, "overall": split_overall}, "seed_candidate_tasks": seeds}


def evaluate_claims(config: dict, e1_values: list[dict], e1_summary: dict, raw_travel: dict[str, str]) -> list[dict]:
    """Check the claims listed in config.claims_under_test against the computed census."""
    results = []
    claims = {claim["id"]: claim for claim in config["claims_under_test"]}
    travel_env = {name: text for name, text in raw_travel.items() if name == "travel/environment.yaml"}
    short = raw_occurrences("Riverside View", "booking_target", travel_env)
    full = raw_occurrences("Riverside View Hotel", "booking_target", travel_env)
    gt_rows = [
        row
        for row in e1_values
        if row["suite"] == "travel" and row["injection_task_id"] == "injection_task_0" and row["argument"] == "hotel"
    ]
    results.append(
        {
            "id": "K1",
            "claim": claims["K1"]["claim"],
            "claimed": claims["K1"]["claimed"],
            "observed": {
                "riverside_view_occurrences": short["count"],
                "riverside_view_lines": short["lines"],
                "riverside_view_hotel_occurrences": full["count"],
                "ground_truth_value": gt_rows[0]["value"] if gt_rows else None,
                "ground_truth_value_in_clean_environment": gt_rows[0]["in_clean_environment"] if gt_rows else None,
            },
            "verdict": "confirmed" if short["count"] == claims["K1"]["claimed"] else "refuted",
            "note": (
                "The substring 'Riverside View' occurs as a London hotel name; the attacker value that the ground truth "
                "and security() require is 'Riverside View Hotel', which does not occur verbatim in the clean "
                "environment, so under the frozen exact rule it is not a pre-existing value (near-match only)."
            ),
        }
    )
    split = e1_summary["split"]
    observed_all = {"numerator": split["overall"]["split_capable"], "denominator": split["overall"]["user_tasks"]}
    distinct_calls = {
        "numerator": split["overall"]["split_capable_with_two_or_more_exposing_calls"],
        "denominator": split["overall"]["user_tasks"],
    }
    k2_observed = {"frozen": observed_all, "distinct_calls_post_hoc": distinct_calls}
    if "distinct_first_calls" in claims["K2"].get("readings", {}):
        # v2 (D4): report both post hoc readings side by side.
        first_calls = {
            "numerator": split["overall"]["split_capable_with_two_or_more_first_exposing_calls"],
            "denominator": split["overall"]["user_tasks"],
        }
        k2_observed["distinct_first_calls_post_hoc"] = first_calls
        k2_verdict = _k2_verdict_v2(claims["K2"]["claimed"], observed_all, distinct_calls, first_calls)
    elif observed_all == claims["K2"]["claimed"]:
        k2_verdict = "confirmed under the frozen reading"
    elif distinct_calls == claims["K2"]["claimed"]:
        k2_verdict = "refuted under the frozen reading; the claimed number matches only the post hoc distinct_calls reading"
    else:
        k2_verdict = "refuted under every reading"
    results.append(
        {
            "id": "K2",
            "claim": claims["K2"]["claim"],
            "claimed": claims["K2"]["claimed"],
            "observed": k2_observed,
            "verdict": k2_verdict,
        }
    )
    banking = split["per_suite"]["banking"]
    observed_banking = {"numerator": banking["split_capable"], "denominator": banking["user_tasks"]}
    results.append(
        {
            "id": "K3",
            "claim": claims["K3"]["claim"],
            "claimed": claims["K3"]["claimed"],
            "observed": observed_banking,
            "verdict": "confirmed" if observed_banking == claims["K3"]["claimed"] else "refuted",
        }
    )
    views = e1_summary["views"]
    total = views["gt_only"]["overall"]["injection_tasks"]
    widest = views["gt_plus_fallback_with_exfiltration_reads"]["overall"]
    readings = {
        "R1": views["gt_only"]["overall"]["tasks_any_goal_literal"],
        "R2": views["gt_plus_fallback"]["overall"]["tasks_any_goal_literal"],
        "R3": views["gt_plus_fallback"]["overall"]["tasks_all_goal_literal"],
        "R4": widest["tasks_any_goal_literal"],
        "R5": widest["tasks_co_located"],
        "R6": total - widest["tasks_none_goal_literal"],
    }
    definitions = claims["K4"].get("readings", {})
    claimed = claims["K4"]["claimed"]["numerator"]
    matching = sorted(name for name, value in readings.items() if value == claimed)
    pre_specified = [name for name in matching if not definitions.get(name, {}).get("post_hoc", True)]
    if pre_specified:
        verdict = f"reproduced under pre-specified reading(s) {', '.join(pre_specified)}"
    elif matching:
        verdict = f"not reproduced under any pre-specified reading; matches only post hoc reading(s) {', '.join(matching)}"
    else:
        verdict = "not reproduced under any computed reading"
    results.append(
        {
            "id": "K4",
            "claim": claims["K4"]["claim"],
            "claimed": claims["K4"]["claimed"],
            "observed": {
                "denominator": total,
                "readings": {
                    name: {
                        "value": value,
                        "post_hoc": definitions.get(name, {}).get("post_hoc", True),
                        "definition": definitions.get(name, {}).get("definition", ""),
                    }
                    for name, value in readings.items()
                },
            },
            "verdict": verdict,
            "note": claims["K4"].get("note", ""),
        }
    )
    return results


def _k2_verdict_v2(claimed: dict, frozen: dict, any_output: dict, first_output: dict) -> str:
    def fraction(item: dict) -> str:
        return f"{item['numerator']}/{item['denominator']}"

    def marker(item: dict) -> str:
        return " (equals the claim)" if item == claimed else ""

    head = "confirmed" if frozen == claimed else "refuted"
    return (
        f"{head} under the frozen reading ({fraction(frozen)}); post hoc readings: {fraction(any_output)} counting "
        f"any exposing ground-truth output{marker(any_output)}, {fraction(first_output)} counting each vector's first "
        f"exposing output{marker(first_output)}"
    )


# ---------------------------------------------------------------------------
# Network guard


@contextmanager
def network_guard() -> Iterator[dict]:
    """Refuse and count socket connections and DNS lookups for the duration of the census."""
    attempts = {"count": 0}
    originals = (
        socket.socket.connect,
        socket.socket.connect_ex,
        socket.create_connection,
        socket.getaddrinfo,
    )

    def refuse(*_args, **_kwargs):
        attempts["count"] += 1
        raise OSError("network access refused by authority_census.network_guard")

    socket.socket.connect = refuse  # type: ignore[method-assign]
    socket.socket.connect_ex = refuse  # type: ignore[method-assign]
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.create_connection, socket.getaddrinfo = originals


# ---------------------------------------------------------------------------
# Top-level census


def vendor_paths() -> tuple[Path, Path]:
    import agentdojo

    package = Path(agentdojo.__file__).resolve().parent
    return package.parent, package / "data" / "suites"


def run_census(config: dict) -> dict:
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(config["benchmark"]["benchmark_version"])
    inventory = check_inventory(config, suites)
    role_rows = validate_role_table(config, suites)
    vendor_src, data_root = vendor_paths()
    e0_values, e0_exfil, e0_tasks = [], [], []
    e1_values, e1_tasks, exposure = [], [], []
    for suite_name in SUITES:
        suite = suites[suite_name]
        user = census_user_tasks(config, suite_name, suite)
        e0_values += user["values"]
        e0_exfil += user["exfiltration_values"]
        e0_tasks += user["tasks"]
        injection = census_injection_tasks(config, suite_name, suite, data_root, vendor_src)
        e1_values += injection["values"]
        e1_tasks += injection["tasks"]
        exposure += vector_exposure(suite_name, suite)
    e1_summary = summarise_e1(e1_tasks, exposure)
    raw_travel = raw_environment_texts("travel", data_root)
    census = {
        "protocol": config["protocol"],
        "experiment_id": config["experiment_id"],
        "inventory": inventory,
        "role_table": role_rows,
        "role_table_summary": summarise_role_table(role_rows),
        "e0": {
            "tasks": e0_tasks,
            "values": e0_values,
            "summary": summarise_e0(e0_tasks, e0_values),
            "exfiltration_read_values": e0_exfil,
            "exfiltration_read_summary": summarise_exfiltration_e0(e0_exfil),
        },
        "e1": {"tasks": e1_tasks, "values": e1_values, "vector_exposure": exposure, "summary": e1_summary},
    }
    if is_v2(config):
        augment_v2(config, suites, census, data_root, vendor_src)
    census["claims"] = evaluate_claims(config, census["e1"]["values"], census["e1"]["summary"], raw_travel)
    if is_v2(config):
        census["verifier_check"] = verifier_check(config, census)
    return census


def summarise_role_table(rows: list[dict]) -> dict:
    out = {}
    for suite in SUITES:
        suite_rows = [row for row in rows if row["suite"] == suite]
        tools: dict[str, str] = {}
        for row in suite_rows:
            tools[row["tool"]] = row["tool_class"]
        out[suite] = {
            "tools": len(tools),
            "state_changing": sorted(name for name, cls in tools.items() if cls == "state_changing"),
            "exfiltration_read": sorted(name for name, cls in tools.items() if cls == "exfiltration_read"),
            "read_only": sum(1 for cls in tools.values() if cls == "read_only"),
            "authority_arguments": sorted(
                f"{row['tool']}.{row['argument']}" for row in suite_rows if row["argument_role"] == "authority"
            ),
            "content_arguments": sorted(
                f"{row['tool']}.{row['argument']}" for row in suite_rows if row["argument_role"] == "content"
            ),
            "state_changing_without_authority_argument": sorted(
                name
                for name, cls in tools.items()
                if cls == "state_changing"
                and not any(row["tool"] == name and row["argument_role"] == "authority" for row in suite_rows)
            ),
        }
    return out


# ---------------------------------------------------------------------------
# Protocol v2: verifier-requested fixes (D1-D4; D5 is a config entry), post hoc sensitivity, verifier check


def _task_key(row: dict, task_field: str = "user_task_id") -> str:
    return f"{row['suite']}.{row[task_field]}"


def _task_sort_key(key: str) -> tuple[int, int]:
    return SUITES.index(key.split(".")[0]), _task_number(key)


def _sort_task_keys(keys) -> list[str]:
    return sorted(keys, key=_task_sort_key)


class VectorNeutraliser:
    """J19 (D1): is a value's presence owed to injection-vector text?

    The neutral environment is the default environment loaded with every vector (or one
    vector) replaced by a single-token placeholder.  A value present in the real environment
    but absent from the all-vectors-neutral one is vector_dependent; the vectors whose sole
    neutralisation removes it are listed.
    """

    def __init__(self, suite, identifier_kinds: dict, placeholder: str):
        self.suite = suite
        self.identifier_kinds = identifier_kinds
        self.placeholder = placeholder
        self.vectors = tuple(sorted(suite.get_injection_vector_defaults()))
        self._indexes: dict[tuple, TextIndex] = {}

    def _index(self, vectors: tuple[str, ...], task) -> TextIndex:
        key = (vectors, None if task is None else task.ID)
        if key not in self._indexes:
            environment = self.suite.load_and_inject_default_environment({vector: self.placeholder for vector in vectors})
            if task is not None:
                environment = task.init_environment(environment)
            self._indexes[key] = TextIndex(to_jsonable(environment), self.identifier_kinds)
        return self._indexes[key]

    def dependency(self, value: str, kind: str, task=None) -> dict:
        """``task`` is given only when its init_environment changes the default environment."""
        _require(self.placeholder not in normalise(value), f"value {value!r} contains the neutral placeholder")
        if self._index(self.vectors, task).find(value, kind):
            return {"vector_dependent": False, "vector_dependency_vectors": []}
        vectors = [vector for vector in self.vectors if not self._index((vector,), task).find(value, kind)]
        return {"vector_dependent": True, "vector_dependency_vectors": vectors}


_NOT_DEPENDENT = {"vector_dependent": False, "vector_dependency_vectors": []}


def _pre_task_indexes(config: dict, suite) -> dict[str, tuple[TextIndex, object]]:
    """Per user task: the pre-task environment index (as census_user_tasks builds it) and the task when its
    init_environment changes the default environment (else None)."""
    default_environment = suite.load_and_inject_default_environment({})
    default_dump = to_jsonable(default_environment)
    default_index = TextIndex(default_dump, config["identifier_kinds"])
    out = {}
    for task_id, task in suite.user_tasks.items():
        pre_dump = to_jsonable(task.init_environment(default_environment.model_copy(deep=True)))
        if pre_dump == default_dump:
            out[task_id] = (default_index, None)
        else:
            out[task_id] = (TextIndex(pre_dump, config["identifier_kinds"]), task)
    return out


def combined_task_ids(config: dict, suites: dict) -> dict[str, list[str]]:
    """User tasks built by AgentDojo's TaskCombinator; must equal sensitivity.combined_tasks.expected."""
    observed = {
        suite_name: sorted_task_ids(
            task_id
            for task_id, task in suites[suite_name].user_tasks.items()
            if type(task).__module__ == "agentdojo.task_suite.task_combinators"
        )
        for suite_name in SUITES
    }
    expected = {suite: list(ids) for suite, ids in config["sensitivity"]["combined_tasks"]["expected"].items()}
    _require(observed == expected, f"Combined user tasks differ from the frozen config: {observed}")
    return observed


def ground_truth_utility(suite, task, drop: set[int]) -> bool:
    """Request-free utility intervention (config sensitivity.utility_intervention).

    Runs the task's ground truth without the calls in ``drop`` and applies AgentDojo's own
    utility check with GROUND_TRUTH_OUTPUT as the model output, as run_task_with_pipeline does.
    """
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.types import text_content_block_from_string

    environment = task.init_environment(suite.load_and_inject_default_environment({}))
    pre_environment = environment.model_copy(deep=True)
    calls = task.ground_truth(environment)
    runtime = FunctionsRuntime(suite.tools)
    trace = []
    for index, call in enumerate(calls):
        if index in drop:
            continue
        runtime.run_function(environment, call.function, call.args, raise_on_error=not drop)
        trace.append(call)
    output = [text_content_block_from_string(task.GROUND_TRUTH_OUTPUT)]
    return bool(suite._check_task_result(task, output, pre_environment, environment, trace))


def augment_e0_v2(config: dict, suites: dict, census: dict) -> None:
    """D1 flags, exact-field matching, combined-task and utility-intervention columns on E0 rows."""
    placeholder = config["e0"]["vector_dependency"]["placeholder"]
    combined = combined_task_ids(config, suites)
    values, exfil, tasks = census["e0"]["values"], census["e0"]["exfiltration_read_values"], census["e0"]["tasks"]
    for suite_name in SUITES:
        suite = suites[suite_name]
        indexes = _pre_task_indexes(config, suite)
        neutral = VectorNeutraliser(suite, config["identifier_kinds"], placeholder)
        for row in [*values, *exfil]:
            if row["suite"] != suite_name:
                continue
            index, init_task = indexes[row["user_task_id"]]
            row.update(
                neutral.dependency(row["value"], row["value_kind"], init_task)
                if row["in_environment"]
                else _NOT_DEPENDENT
            )
            row["in_environment_exact_field"] = bool(index.find_exact(row["value"], row["value_kind"]))
            if row["in_prompt"]:
                row["origin_exact_field"] = "a_prompt"
            else:
                row["origin_exact_field"] = "b_environment" if row["in_environment_exact_field"] else "c_neither"
        for task_row in tasks:
            if task_row["suite"] != suite_name:
                continue
            task_id = task_row["user_task_id"]
            task_values = [row for row in values if row["suite"] == suite_name and row["user_task_id"] == task_id]
            b_rows = [row for row in task_values if row["origin"] == "b_environment"]
            non_prompt = [row for row in task_values if row["origin"] != "a_prompt"]
            task_row["combined_task"] = task_id in combined[suite_name]
            task_row["b_vector_dependent"] = sum(1 for row in b_rows if row["vector_dependent"])
            task_row["b_excluding_vector_dependent"] = sum(1 for row in b_rows if not row["vector_dependent"])
            task_row["b_exact_field"] = sum(1 for row in task_values if row["origin_exact_field"] == "b_environment")
            task_row["non_prompt_values"] = len(non_prompt)
            task_row["utility_full_ground_truth"] = None
            task_row["utility_without_b_calls"] = None
            task_row["utility_without_non_prompt_calls"] = None
            if non_prompt:
                task = suite.user_tasks[task_id]
                full = ground_truth_utility(suite, task, set())
                _require(full, f"{suite_name}.{task_id}: the full ground truth fails its own utility check")
                task_row["utility_full_ground_truth"] = full
                if b_rows:
                    task_row["utility_without_b_calls"] = ground_truth_utility(
                        suite, task, {row["call_index"] for row in b_rows}
                    )
                task_row["utility_without_non_prompt_calls"] = ground_truth_utility(
                    suite, task, {row["call_index"] for row in non_prompt}
                )
    census["e0"]["summary"]["vector_dependency"] = summarise_vector_dependency(values)


def summarise_vector_dependency(values: list[dict]) -> dict:
    per_suite = {}
    for suite in SUITES:
        suite_values = [row for row in values if row["suite"] == suite]
        b_rows = [row for row in suite_values if row["origin"] == "b_environment"]
        per_suite[suite] = {
            "values_vector_dependent": sum(1 for row in suite_values if row["vector_dependent"]),
            "b_values": len(b_rows),
            "b_vector_dependent": sum(1 for row in b_rows if row["vector_dependent"]),
            "b_excluding_vector_dependent": sum(1 for row in b_rows if not row["vector_dependent"]),
            "tasks_with_b": len({row["user_task_id"] for row in b_rows}),
            "tasks_with_b_excluding_vector_dependent": len(
                {row["user_task_id"] for row in b_rows if not row["vector_dependent"]}
            ),
        }
    overall = {key: sum(per_suite[suite][key] for suite in SUITES) for key in per_suite[SUITES[0]]}
    b_all = {_task_key(row) for row in values if row["origin"] == "b_environment"}
    b_kept = {_task_key(row) for row in values if row["origin"] == "b_environment" and not row["vector_dependent"]}
    return {
        "per_suite": per_suite,
        "overall": overall,
        "tasks_losing_every_b_value": _sort_task_keys(b_all - b_kept),
        "values": [
            {
                key: row[key]
                for key in (
                    "suite", "user_task_id", "call_index", "function", "argument", "value", "origin",
                    "vector_dependency_vectors", "in_injection_vector_defaults",
                )
            }
            for row in values
            if row["vector_dependent"]
        ],
    }


_E1_VIEW_FILTERS = {
    "gt_only": lambda row: row["value_source"] == "ground_truth" and row["tool_class"] == "state_changing",
    "gt_plus_fallback": lambda row: row["tool_class"] == "state_changing",
    "gt_plus_fallback_with_exfiltration_reads": lambda row: True,
}


def e1_views_from_values(tasks: list[dict], values: list[dict], exclude_tags: frozenset = frozenset()) -> dict:
    """E1 view tables recomputed from value rows, with the D3 overlap column; optionally without tagged values."""
    grouped = defaultdict(list)
    for row in values:
        if row.get("fallback_tag") and row["fallback_tag"] in exclude_tags:
            continue
        grouped[(row["suite"], row["injection_task_id"])].append(row)
    views = {}
    for view, keep in _E1_VIEW_FILTERS.items():
        per_suite = {}
        for suite in SUITES:
            summaries, kept = [], []
            for task in tasks:
                if task["suite"] != suite:
                    continue
                rows = [row for row in grouped[(suite, task["injection_task_id"])] if keep(row)]
                summaries.append(summarise_attacker_values(rows))
                kept.extend(rows)
            per_suite[suite] = _aggregate_e1_view(summaries) | {
                "values_goal_and_clean_environment": sum(
                    1 for row in kept if row["stated_in_goal"] and row["in_clean_environment"]
                )
            }
        overall = {key: sum(per_suite[suite][key] for suite in SUITES) for key in per_suite[SUITES[0]]}
        views[view] = {"per_suite": per_suite, "overall": overall}
    return views


def _view_rows(values: list[dict], view: str) -> list[dict]:
    keep = _E1_VIEW_FILTERS[view]
    return [row for row in values if keep(row)]


def goal_literal_coverage(suites: dict, values: list[dict]) -> list[dict]:
    """D2: for each attacker literal stated in some GOAL, how many of the suite's GOALs state it."""
    rows = []
    for suite_name in SUITES:
        goals = {task_id: normalise(task.GOAL) for task_id, task in suites[suite_name].injection_tasks.items()}
        suite_values = [row for row in values if row["suite"] == suite_name]
        for value in sorted({row["value"] for row in suite_values if row["stated_in_goal"]}):
            stating = [task_id for task_id in sorted_task_ids(goals) if contains(goals[task_id], normalise(value))]
            rows.append(
                {
                    "suite": suite_name,
                    "value": value,
                    "goals_stating": len(stating),
                    "injection_tasks": len(goals),
                    "stating": stating,
                    "lacking": [task_id for task_id in sorted_task_ids(goals) if task_id not in stating],
                    "attacker_value_of": sorted_task_ids(
                        {row["injection_task_id"] for row in suite_values if row["value"] == value}
                    ),
                }
            )
    return sorted(rows, key=lambda row: (SUITES.index(row["suite"]), -row["goals_stating"], row["value"]))


def augment_e1_v2(config: dict, suites: dict, census: dict) -> None:
    """Fallback tags (D5), D1 flags, exact-field flags, prompt collisions, D2 coverage, D3 overlap, D4 reading."""
    placeholder = config["e0"]["vector_dependency"]["placeholder"]
    fallback = config["e1"]["security_checker_fallback"]
    values, tasks = census["e1"]["values"], census["e1"]["tasks"]
    for suite_name in SUITES:
        suite = suites[suite_name]
        clean = suite.load_and_inject_default_environment({})
        clean_index = TextIndex(to_jsonable(clean), config["identifier_kinds"])
        neutral = VectorNeutraliser(suite, config["identifier_kinds"], placeholder)
        prompts = {task_id: normalise(task.PROMPT) for task_id, task in suite.user_tasks.items()}
        for task_id in sorted_task_ids(suite.injection_tasks):
            rows = [row for row in values if row["suite"] == suite_name and row["injection_task_id"] == task_id]
            fallback_rows = [row for row in rows if row["value_source"] == "security_checker_fallback"]
            slots = []
            if fallback_rows:
                for entry in fallback[suite_name][task_id]:
                    count = len(derive_fallback_values(entry, clean))
                    slots += [(entry["function"], entry["argument"], entry.get("tag", ""))] * count
            _require(len(slots) == len(fallback_rows), f"{suite_name}.{task_id}: fallback rows do not align")
            for row, (function, argument, tag) in zip(fallback_rows, slots):
                _require((row["function"], row["argument"]) == (function, argument), f"{task_id}: fallback order")
                row["fallback_tag"] = tag
            for row in rows:
                row.setdefault("fallback_tag", "")
                row.update(
                    neutral.dependency(row["value"], row["value_kind"]) if row["in_clean_environment"] else _NOT_DEPENDENT
                )
                row["in_clean_environment_exact_field"] = bool(clean_index.find_exact(row["value"], row["value_kind"]))
                needle = normalise(row["value"])
                row["prompt_collisions"] = sorted_task_ids(
                    user_task for user_task, prompt in prompts.items() if contains(prompt, needle)
                )
    summary = census["e1"]["summary"]
    views = e1_views_from_values(tasks, values)
    for view, data in views.items():
        for scope in [*SUITES, "overall"]:
            new = data["overall"] if scope == "overall" else data["per_suite"][scope]
            old = summary["views"][view]["overall"] if scope == "overall" else summary["views"][view]["per_suite"][scope]
            _require({key: new[key] for key in old} == old, f"E1 view {view}/{scope}: recomputation differs from core")
    summary["views"] = views
    tags = sorted({row["fallback_tag"] for row in values if row["fallback_tag"]})
    summary["views_excluding_tag"] = {tag: e1_views_from_values(tasks, values, frozenset({tag})) for tag in tags}
    summary["goal_and_clean_environment_values"] = {
        view: [
            {key: row[key] for key in ("suite", "injection_task_id", "function", "argument", "value", "fallback_tag")}
            for row in _view_rows(values, view)
            if row["stated_in_goal"] and row["in_clean_environment"]
        ]
        for view in _E1_VIEWS
    }
    summary["goal_literal_coverage"] = goal_literal_coverage(suites, values)
    augment_split_v2(census["e1"]["vector_exposure"], summary["split"])


def augment_split_v2(exposure: list[dict], split: dict) -> None:
    """D4: count split-capable tasks whose vectors' FIRST exposing outputs are distinct calls."""
    for row in exposure:
        row["distinct_first_exposure_calls"] = len({item["index"] for item in row["first_exposure"].values()})
    for suite in SUITES:
        rows = [row for row in exposure if row["suite"] == suite]
        any_output = {row["user_task_id"] for row in rows if row["split_capable"] and row["distinct_exposing_calls"] >= 2}
        first = {row["user_task_id"] for row in rows if row["split_capable"] and row["distinct_first_exposure_calls"] >= 2}
        split["per_suite"][suite]["split_capable_with_two_or_more_first_exposing_calls"] = len(first)
        split["per_suite"][suite]["any_but_not_first_exposing_calls"] = sorted_task_ids(any_output - first)
    split["overall"]["split_capable_with_two_or_more_first_exposing_calls"] = sum(
        split["per_suite"][suite]["split_capable_with_two_or_more_first_exposing_calls"] for suite in SUITES
    )


def precision_denominator_rows(config: dict, census: dict) -> list[dict]:
    """S1: the primary precision denominator (P0) and its post hoc sensitivity rows P1-P6."""
    tasks = census["e0"]["tasks"]
    total = len(tasks)
    combined = sum(1 for row in tasks if row["combined_task"])
    selections = {
        "tasks_with_b": [row for row in tasks if row["b_environment"]],
        "tasks_with_b_minus_utility_noop": [
            row for row in tasks if row["b_environment"] and not row["utility_without_b_calls"]
        ],
        "tasks_with_b_or_c": [row for row in tasks if row["non_prompt_values"]],
        "tasks_with_b_or_c_minus_utility_noop": [
            row for row in tasks if row["non_prompt_values"] and not row["utility_without_non_prompt_calls"]
        ],
        "tasks_with_b_excluding_combined": [row for row in tasks if row["b_environment"] and not row["combined_task"]],
        "tasks_with_b_exact_field": [row for row in tasks if row["b_exact_field"]],
        "tasks_with_b_excluding_vector_dependent": [row for row in tasks if row["b_excluding_vector_dependent"]],
    }
    primary = {_task_key(row) for row in selections["tasks_with_b"]}
    out = []
    for spec in config["sensitivity"]["precision_denominator"]:
        chosen = {_task_key(row) for row in selections[spec["rule"]]}
        denominator = total - combined if spec["rule"] == "tasks_with_b_excluding_combined" else total
        out.append(
            {
                "id": spec["id"],
                "label": spec["label"],
                "rule": spec["rule"],
                "primary": bool(spec.get("primary")),
                "post_hoc": not spec.get("primary"),
                "numerator": len(chosen),
                "denominator": denominator,
                "removed_vs_primary": _sort_task_keys(primary - chosen),
                "added_vs_primary": _sort_task_keys(chosen - primary),
                "tasks": _sort_task_keys(chosen),
                "definition": spec.get("definition", ""),
            }
        )
    return out


def apply_role_variant(config: dict, variant: dict) -> dict:
    """A deep copy of ``config`` with one post hoc role-table variant applied (sensitivity.role_variants)."""
    out = copy.deepcopy(config)
    for suite, tools in variant.get("authority_additions", {}).items():
        for tool, arguments in tools.items():
            role = out["tools"][suite][tool]
            _require(role["class"] == "state_changing", f"{variant['id']}: {suite}.{tool} is not state_changing")
            for argument, kind in arguments.items():
                _require(argument in role["content"], f"{variant['id']}: {suite}.{tool}.{argument} is not content")
                role["content"].remove(argument)
                role["authority"][argument] = kind
                if argument in variant.get("value_extractors", {}):
                    role.setdefault("value_extractors", {})[argument] = variant["value_extractors"][argument]
    for suite, tools in variant.get("reclassify", {}).items():
        for tool, role in tools.items():
            _require(tool in out["tools"][suite], f"{variant['id']}: unknown tool {suite}.{tool}")
            out["tools"][suite][tool] = copy.deepcopy(role)
    fallback = out["e1"]["security_checker_fallback"]
    for suite, by_task in variant.get("e1_fallback_additions", {}).items():
        for task_id, entries in by_task.items():
            _require(task_id in fallback.get(suite, {}), f"{variant['id']}: {suite}.{task_id} has no fallback")
            fallback[suite][task_id].extend(copy.deepcopy(entries))
    return out


def _changed_arguments(variant: dict) -> set[tuple[str, str, str]]:
    changed = {
        (suite, tool, argument)
        for suite, tools in variant.get("authority_additions", {}).items()
        for tool, arguments in tools.items()
        for argument in arguments
    }
    changed |= {
        (suite, tool, argument)
        for suite, tools in variant.get("reclassify", {}).items()
        for tool, role in tools.items()
        for argument in role.get("authority", {})
    }
    return changed


def run_role_variant(
    config: dict, variant: dict, suites: dict, data_root: Path, vendor_src: Path | None, primary: dict
) -> dict:
    """S2: E0 and E1 under one post hoc role-table variant, compared with the primary census."""
    variant_config = apply_role_variant(config, variant)
    _validate_core(variant_config)
    validate_role_table(variant_config, suites)
    e0_values, e0_tasks, e1_values, e1_tasks = [], [], [], []
    for suite_name in SUITES:
        user = census_user_tasks(variant_config, suite_name, suites[suite_name])
        e0_values += user["values"]
        e0_tasks += user["tasks"]
        injection = census_injection_tasks(variant_config, suite_name, suites[suite_name], data_root, vendor_src)
        e1_values += injection["values"]
        e1_tasks += injection["tasks"]
    changed = _changed_arguments(variant)
    e0_summary = summarise_e0(e0_tasks, e0_values)
    primary_b = {_task_key(row) for row in primary["e0"]["tasks"] if row["b_environment"]}
    variant_b = {_task_key(row) for row in e0_tasks if row["b_environment"]}
    view = "gt_plus_fallback"
    views = summarise_e1(e1_tasks, [])["views"]
    primary_tasks = {_task_key(row, "injection_task_id"): row for row in primary["e1"]["tasks"]}
    variant_tasks = {_task_key(row, "injection_task_id"): row for row in e1_tasks}
    primary_seeds = {key for key, row in primary_tasks.items() if row[view]["seed_candidate"]}
    variant_seeds = {key for key, row in variant_tasks.items() if row[view]["seed_candidate"]}
    return {
        "id": variant["id"],
        "label": variant["label"],
        "reverses": variant.get("reverses", ""),
        "post_hoc": True,
        "note": variant.get("note", ""),
        "changed_arguments": sorted(f"{suite}.{tool}.{argument}" for suite, tool, argument in changed),
        "e0": {
            "values": e0_summary["overall"]["values"],
            "tasks_with_b": e0_summary["overall"]["tasks_with_b"],
            "tasks_with_b_or_c": sum(1 for row in e0_tasks if row["b_environment"] or row["c_neither"]),
            "new_b_tasks": _sort_task_keys(variant_b - primary_b),
            "lost_b_tasks": _sort_task_keys(primary_b - variant_b),
            "added_values": [
                {key: row[key] for key in ("suite", "user_task_id", "function", "argument", "value", "origin")}
                for row in e0_values
                if (row["suite"], row["function"], row["argument"]) in changed
            ],
        },
        "e1": {
            "view": view,
            "overall": views[view]["overall"] | {
                "values_goal_and_clean_environment": sum(
                    1
                    for row in e1_values
                    if row["tool_class"] == "state_changing" and row["stated_in_goal"] and row["in_clean_environment"]
                )
            },
            "new_seed_tasks": _sort_task_keys(variant_seeds - primary_seeds),
            "lost_seed_tasks": _sort_task_keys(primary_seeds - variant_seeds),
            "category_changes": [
                {"task": key, "primary": primary_tasks[key][view]["category"], "variant": row[view]["category"]}
                for key, row in sorted(variant_tasks.items(), key=lambda item: _task_sort_key(item[0]))
                if row[view]["category"] != primary_tasks[key][view]["category"]
            ],
            "added_values": [
                {
                    key: row[key]
                    for key in (
                        "suite", "injection_task_id", "value_source", "function", "argument", "value",
                        "stated_in_goal", "in_clean_environment",
                    )
                }
                for row in e1_values
                if (row["suite"], row["function"], row["argument"]) in changed and row["tool_class"] == "state_changing"
            ],
        },
    }


def prompt_collisions(values: list[dict]) -> dict:
    """S2: distinct (suite, injection task, attacker value) whose value occurs in a user PROMPT of the suite."""
    found: dict[tuple, dict] = {}
    for row in values:
        if not row["prompt_collisions"]:
            continue
        key = (row["suite"], row["injection_task_id"], row["value"])
        item = found.setdefault(
            key,
            {
                "suite": row["suite"],
                "injection_task_id": row["injection_task_id"],
                "value": row["value"],
                "value_kind": row["value_kind"],
                "arguments": [],
                "user_tasks": row["prompt_collisions"],
            },
        )
        argument = f"{row['function']}.{row['argument']}"
        if argument not in item["arguments"]:
            item["arguments"].append(argument)
    rows = sorted(
        found.values(),
        key=lambda item: (SUITES.index(item["suite"]), _task_number(item["injection_task_id"]), item["value"]),
    )
    return {"count": len(rows), "rows": rows}


def e1_exact_field_report(values: list[dict], tasks: list[dict]) -> dict:
    """S1 companion: E1 environment presence under exact whole-field matching (no primary change)."""
    views = {}
    for view in _E1_VIEWS:
        rows = _view_rows(values, view)
        views[view] = {
            "values_in_clean_environment": sum(1 for row in rows if row["in_clean_environment"]),
            "values_in_clean_environment_exact_field": sum(1 for row in rows if row["in_clean_environment_exact_field"]),
            "tasks_seed_candidate": len({_task_key(row, "injection_task_id") for row in rows if row["in_clean_environment"]}),
            "tasks_seed_candidate_exact_field": len(
                {_task_key(row, "injection_task_id") for row in rows if row["in_clean_environment_exact_field"]}
            ),
        }
    return {
        "views": views,
        "changed_values": [
            {key: row[key] for key in ("suite", "injection_task_id", "function", "argument", "value")}
            for row in values
            if row["in_clean_environment"] != row["in_clean_environment_exact_field"]
        ],
    }


def augment_v2(config: dict, suites: dict, census: dict, data_root: Path, vendor_src: Path | None) -> None:
    """Add every v2 field and table to a census computed by the unchanged v1 core."""
    census["predecessor"] = copy.deepcopy(config["predecessor"])
    augment_e0_v2(config, suites, census)
    augment_e1_v2(config, suites, census)
    census["sensitivity"] = {
        "post_hoc": True,
        "precision_denominator": precision_denominator_rows(config, census),
        "role_variants": [
            run_role_variant(config, variant, suites, data_root, vendor_src, census)
            for variant in config["sensitivity"]["role_variants"]
        ],
        "prompt_collisions": prompt_collisions(census["e1"]["values"]),
        "e1_exact_field": e1_exact_field_report(census["e1"]["values"], census["e1"]["tasks"]),
        "e0_exact_field_changed_values": [
            {
                key: row[key]
                for key in ("suite", "user_task_id", "function", "argument", "value", "origin", "origin_exact_field")
            }
            for row in census["e0"]["values"]
            if row["origin"] != row["origin_exact_field"]
        ],
    }


def resolve_path(data: object, path: list) -> object:
    """Follow a verifier-check path: str keys, int indexes, or {field: value} matchers selecting one list item."""
    current = data
    for segment in path:
        if isinstance(segment, dict):
            if not isinstance(current, list):
                raise LookupError(f"matcher {segment} applied to a non-list")
            matches = [
                item for item in current if isinstance(item, dict) and all(item.get(k) == v for k, v in segment.items())
            ]
            if len(matches) != 1:
                raise LookupError(f"matcher {segment} selected {len(matches)} items")
            current = matches[0]
        else:
            current = current[segment]
    return current


def verifier_check(config: dict, census: dict) -> list[dict]:
    """Compare the census with the verifier's expected values (config verifier_expectations); never adjusts."""
    rows = []
    for check in config["verifier_expectations"]["checks"]:
        try:
            observed, resolved = resolve_path(census, check["path"]), True
        except (KeyError, IndexError, LookupError, TypeError):
            observed, resolved = None, False
        rows.append(
            {
                "id": check["id"],
                "quantity": check["quantity"],
                "expected": check["expected"],
                "observed": observed,
                "resolved": resolved,
                "match": resolved and observed == check["expected"],
                "path": "/".join(json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                                 for item in check["path"]),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Serialisation


def _cell(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                if "function" in item and "index" in item:
                    parts.append(f"{item['index']}:{item['function']}")
                elif "text" in item:
                    parts.append(f"{item['text']} @ {item['path']} ({item['reason']})")
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
            else:
                parts.append(str(item))
        return " | ".join(parts)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def to_csv(rows: list[dict], columns: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


ROLE_COLUMNS = ["suite", "tool", "tool_class", "argument", "argument_role", "value_kind", "note"]
E0_VALUE_COLUMNS = [
    "suite", "user_task_id", "call_index", "function", "argument", "element_index", "value_kind", "value", "origin",
    "in_prompt", "in_environment", "environment_match_count", "environment_paths", "exposed_before_call",
    "exposing_calls", "in_injection_vector_defaults", "near_matches",
]
E0_TASK_COLUMNS = [
    "suite", "user_task_id", "ground_truth_calls", "state_changing_calls", "state_changing_functions",
    "authority_values", "a_prompt", "b_environment", "c_neither", "b_exposed_before_call",
    "values_in_injection_vector_defaults", "precision_denominator", "exfiltration_read_values",
]
E1_VALUE_COLUMNS = [
    "suite", "injection_task_id", "value_source", "checker_source", "tool_class", "function", "argument",
    "element_index", "value_kind", "value", "stated_in_goal", "in_clean_environment", "environment_match_count",
    "environment_paths", "raw_environment_yaml_occurrences", "raw_environment_yaml_lines",
    "in_injection_vector_defaults", "label", "near_matches",
]
E1_VECTOR_COLUMNS = [
    "suite", "user_task_id", "vector_count", "split_capable", "agentdojo_vectors", "ordered_vectors",
    "first_exposure", "distinct_exposing_calls", "parity_with_agentdojo", "agentdojo_error",
]


def e1_task_table(tasks: list[dict]) -> list[dict]:
    rows = []
    for task in tasks:
        row = {
            "suite": task["suite"],
            "injection_task_id": task["injection_task_id"],
            "ground_truth_calls": task["ground_truth_calls"],
            "value_source": task["value_source"],
            "security_checker_source": task["security_checker_source"],
        }
        for view in _E1_VIEWS:
            for key in ("values", "goal_literal", "in_clean_environment", "attacker_introduced", "category",
                        "co_located", "seed_candidate"):
                row[f"{view}.{key}"] = task[view][key]
        rows.append(row)
    return rows


E1_TASK_COLUMNS = [
    "suite", "injection_task_id", "ground_truth_calls", "value_source", "security_checker_source",
    *[
        f"{view}.{key}"
        for view in _E1_VIEWS
        for key in ("values", "goal_literal", "in_clean_environment", "attacker_introduced", "category", "co_located",
                    "seed_candidate")
    ],
]


E0_VALUE_COLUMNS_V2 = [
    *E0_VALUE_COLUMNS, "vector_dependent", "vector_dependency_vectors", "in_environment_exact_field",
    "origin_exact_field",
]
E0_TASK_COLUMNS_V2 = [
    *E0_TASK_COLUMNS, "combined_task", "b_vector_dependent", "b_excluding_vector_dependent", "b_exact_field",
    "non_prompt_values", "utility_full_ground_truth", "utility_without_b_calls", "utility_without_non_prompt_calls",
]
E1_VALUE_COLUMNS_V2 = [
    *E1_VALUE_COLUMNS, "fallback_tag", "vector_dependent", "vector_dependency_vectors",
    "in_clean_environment_exact_field", "prompt_collisions",
]
E1_VECTOR_COLUMNS_V2 = [*E1_VECTOR_COLUMNS, "distinct_first_exposure_calls"]
COVERAGE_COLUMNS = ["suite", "value", "goals_stating", "injection_tasks", "lacking", "stating", "attacker_value_of"]
PRECISION_COLUMNS = [
    "id", "label", "rule", "primary", "post_hoc", "numerator", "denominator", "removed_vs_primary", "added_vs_primary",
    "tasks", "definition",
]
VARIANT_COLUMNS = [
    "id", "label", "reverses", "post_hoc", "changed_arguments", "e0.values", "e0.a_prompt", "e0.b_environment",
    "e0.c_neither", "e0.tasks_with_b", "e0.tasks_with_b_or_c", "e0.new_b_tasks", "e0.lost_b_tasks", "e1.view",
    "e1.values", "e1.values_goal_literal", "e1.values_in_clean_environment", "e1.values_goal_and_clean_environment",
    "e1.values_neither", "e1.tasks_seed_candidate", "e1.new_seed_tasks", "e1.lost_seed_tasks", "e1.category_changes",
]
COLLISION_COLUMNS = ["suite", "injection_task_id", "value", "value_kind", "arguments", "user_tasks"]
VERIFIER_COLUMNS = ["id", "quantity", "expected", "observed", "match", "resolved", "path"]


def role_variant_table(variants: list[dict]) -> list[dict]:
    rows = []
    for item in variants:
        e0, e1 = item["e0"], item["e1"]
        rows.append(
            {
                **{key: item[key] for key in ("id", "label", "reverses", "post_hoc", "changed_arguments")},
                "e0.values": e0["values"]["total"],
                **{f"e0.{origin}": e0["values"][origin] for origin in ORIGINS},
                **{f"e0.{key}": e0[key] for key in ("tasks_with_b", "tasks_with_b_or_c", "new_b_tasks", "lost_b_tasks")},
                "e1.view": e1["view"],
                **{
                    f"e1.{key}": e1["overall"][key]
                    for key in (
                        "values", "values_goal_literal", "values_in_clean_environment",
                        "values_goal_and_clean_environment", "values_neither", "tasks_seed_candidate",
                    )
                },
                **{f"e1.{key}": e1[key] for key in ("new_seed_tasks", "lost_seed_tasks", "category_changes")},
            }
        )
    return rows


def derived_files(census: dict) -> dict[str, str]:
    e0, e1 = census["e0"], census["e1"]
    if census["protocol"] == PROTOCOL_V2:
        return derived_files_v2(census)
    return {
        "derived/census.json": dump_json(census),
        "derived/role_table.csv": to_csv(census["role_table"], ROLE_COLUMNS),
        "derived/e0_values.csv": to_csv(e0["values"], E0_VALUE_COLUMNS),
        "derived/e0_tasks.csv": to_csv(e0["tasks"], E0_TASK_COLUMNS),
        "derived/e0_exfiltration_read_values.csv": to_csv(e0["exfiltration_read_values"], E0_VALUE_COLUMNS),
        "derived/e1_attacker_values.csv": to_csv(e1["values"], E1_VALUE_COLUMNS),
        "derived/e1_injection_tasks.csv": to_csv(e1_task_table(e1["tasks"]), E1_TASK_COLUMNS),
        "derived/e1_vector_exposure.csv": to_csv(e1["vector_exposure"], E1_VECTOR_COLUMNS),
    }


def derived_files_v2(census: dict) -> dict[str, str]:
    e0, e1, sensitivity = census["e0"], census["e1"], census["sensitivity"]
    return {
        "derived/census.json": dump_json(census),
        "derived/role_table.csv": to_csv(census["role_table"], ROLE_COLUMNS),
        "derived/e0_values.csv": to_csv(e0["values"], E0_VALUE_COLUMNS_V2),
        "derived/e0_tasks.csv": to_csv(e0["tasks"], E0_TASK_COLUMNS_V2),
        "derived/e0_exfiltration_read_values.csv": to_csv(e0["exfiltration_read_values"], E0_VALUE_COLUMNS_V2),
        "derived/e1_attacker_values.csv": to_csv(e1["values"], E1_VALUE_COLUMNS_V2),
        "derived/e1_injection_tasks.csv": to_csv(e1_task_table(e1["tasks"]), E1_TASK_COLUMNS),
        "derived/e1_vector_exposure.csv": to_csv(e1["vector_exposure"], E1_VECTOR_COLUMNS_V2),
        "derived/e1_goal_literal_coverage.csv": to_csv(e1["summary"]["goal_literal_coverage"], COVERAGE_COLUMNS),
        "derived/sensitivity_precision_denominator.csv": to_csv(sensitivity["precision_denominator"], PRECISION_COLUMNS),
        "derived/sensitivity_role_variants.csv": to_csv(role_variant_table(sensitivity["role_variants"]), VARIANT_COLUMNS),
        "derived/sensitivity_prompt_collisions.csv": to_csv(sensitivity["prompt_collisions"]["rows"], COLLISION_COLUMNS),
        "derived/verifier_check.csv": to_csv(census["verifier_check"], VERIFIER_COLUMNS),
    }


# ---------------------------------------------------------------------------
# Markdown summary


def _table(header: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|").replace("\n", " ") for item in row) + " |")
    return "\n".join(lines)


def _code(value: str) -> str:
    return "`" + value.replace("`", "'").replace("\n", " ") + "`"


def _role_table_lines(roles: dict) -> list[str]:
    rows = []
    for suite in SUITES:
        item = roles[suite]
        rows.append(
            [
                suite,
                item["tools"],
                len(item["state_changing"]),
                len(item["exfiltration_read"]),
                item["read_only"],
                len(item["authority_arguments"]),
                len(item["content_arguments"]),
                ", ".join(item["state_changing_without_authority_argument"]) or "-",
            ]
        )
    out = [
        _table(
            ["suite", "tools", "state-changing", "exfiltration-read", "read-only", "authority args", "content args",
             "state-changing without authority arg"],
            rows,
        )
    ]
    out += ["", "Authority arguments:", ""]
    for suite in SUITES:
        out.append(f"- {suite}: " + ", ".join(_code(name) for name in roles[suite]["authority_arguments"]))
    out += ["", "Exfiltration-read tools: " + ", ".join(
        _code(f"{suite}.{name}") for suite in SUITES for name in roles[suite]["exfiltration_read"]) + "."]
    return out


def _per_tool_lines(e0: dict) -> list[str]:
    return [
        "",
        "### Per tool and argument",
        "",
        _table(
            ["suite.tool.argument", "values", "(a)", "(b)", "(c)", "tasks"],
            [
                [key, cell["total"], cell["a_prompt"], cell["b_environment"], cell["c_neither"], cell["tasks"]]
                for key, cell in e0["per_tool_argument"].items()
            ],
        ),
    ]


def _c_value_lines(e0: dict) -> list[str]:
    out = ["", "### (c) values", ""]
    if e0["c_values"]:
        out.append(
            _table(
                ["suite", "user task", "tool.argument", "value", "near matches (diagnostic only)"],
                [
                    [
                        item["suite"],
                        item["user_task_id"],
                        f"{item['function']}.{item['argument']}",
                        _code(item["value"]),
                        "; ".join(f"{_code(m['text'])} ({m['reason']})" for m in item["near_matches"]) or "-",
                    ]
                    for item in e0["c_values"]
                ],
            )
        )
    else:
        out.append("None.")
    return out


def _exfil_lines(exfil: dict) -> list[str]:
    out = ["", "### Exfiltration-read arguments (separate from the counts above)", ""]
    out.append(
        _table(
            ["suite", "values", "(a)", "(b)", "(c)"],
            [
                [suite, exfil["per_suite"][suite]["total"], exfil["per_suite"][suite]["a_prompt"],
                 exfil["per_suite"][suite]["b_environment"], exfil["per_suite"][suite]["c_neither"]]
                for suite in SUITES
            ],
        )
    )
    out += ["", "User tasks with a (b) exfiltration-read value: " + (", ".join(exfil["tasks_with_b"]) or "none") + "."]
    return out


def _seed_lines(e1: dict) -> list[str]:
    return [
        "",
        "### Selection-steering seed candidates (an attacker value already in the clean environment)",
        "",
        _table(
            ["suite", "injection task", "category (gt_plus_fallback)", "value source"],
            [[item["suite"], item["injection_task_id"], item["category"], item["value_source"]]
             for item in e1["seed_candidate_tasks"]],
        ),
    ]


def _claims_lines(claims: list[dict]) -> list[str]:
    out = []
    for claim in claims:
        out.append(f"- **{claim['id']}** ({claim['verdict']}): {claim['claim']}. Claimed {json.dumps(claim['claimed'])}; "
                   f"observed {json.dumps(claim['observed'], ensure_ascii=False, sort_keys=True)}.")
        if claim.get("note"):
            out.append(f"  - Note: {claim['note']}")
    return out


def render_summary(census: dict, config_sha256: str, agent_tracer_head: str) -> str:
    if census["protocol"] == PROTOCOL_V2:
        return render_summary_v2(census, config_sha256, agent_tracer_head)
    e0 = census["e0"]["summary"]
    e1 = census["e1"]["summary"]
    roles = census["role_table_summary"]
    out = [
        "# Authority-origin census v1 (E0, E1): summary",
        "",
        "Status: DRAFT, pending the Agent Tracer code commit. Request-free: no model, provider or network call.",
        "",
        f"- Protocol: `{PROTOCOL}`; frozen config `config/authority_census_v1.json`, SHA-256 `{config_sha256}`.",
        f"- Agent Tracer HEAD `{agent_tracer_head}` plus uncommitted census files (see manifest.json).",
        "- Benchmark: vendored AgentDojo 0.1.35 (ethz-spylab/agentdojo 089ed468), benchmark v1.2.2.",
        "- Every number below is computed by `agentdojo_lab.authority_census` and is reproduced in "
        "`derived/census.json`; row-level evidence is in the `derived/*.csv` files.",
        "",
        "## Role table",
        "",
        "Rule (config `role_rule.authority`): an argument of a state-changing tool is authority-bearing iff its value "
        "decides to whom, where, or on which account or resource the action applies. Judgement calls J1-J18 are listed "
        "in the config.",
        "",
    ]
    out += _role_table_lines(roles)

    out += [
        "",
        "## E0: where do correct authority values come from?",
        "",
        "Unit: one element of one authority argument of one state-changing call in a user task's ground truth. "
        "(a) literally in the prompt; (b) not in the prompt but in the pre-task environment, so it reaches the agent "
        "only through a tool output; (c) neither.",
        "",
    ]
    rows = []
    for suite in [*SUITES, "overall"]:
        item = e0["overall"] if suite == "overall" else e0["per_suite"][suite]
        values = item["values"]
        rows.append(
            [
                suite,
                item["user_tasks"],
                item["tasks_with_state_changing_call"],
                item["tasks_with_authority_value"],
                values["total"],
                values["a_prompt"],
                values["b_environment"],
                values["c_neither"],
                item["b_exposed_before_call"],
                item["tasks_with_b"],
                item["tasks_with_c"],
                item["tasks_all_a"],
            ]
        )
    out.append(
        _table(
            ["suite", "user tasks", "with state-changing call", "with authority value", "values", "(a)", "(b)", "(c)",
             "(b) exposed by earlier GT output", "tasks with (b)", "tasks with (c)", "tasks all (a)"],
            rows,
        )
    )
    out += _per_tool_lines(e0)
    denominator = e0["precision_denominator"]
    out += [
        "",
        f"### Precision denominator: {len(denominator)} user tasks with at least one (b) value",
        "",
        "An origin rule that admits only prompt-origin authority values would block the legitimate ground-truth run "
        "of each task below.",
        "",
    ]
    rows = []
    for item in denominator:
        rows.append(
            [
                item["suite"],
                item["user_task_id"],
                "; ".join(
                    f"{value['function']}.{value['argument']}={_code(value['value'])}"
                    + ("" if value["exposed_before_call"] else " (not shown by an earlier GT call)")
                    + (f" [inside vector default {', '.join(value['in_injection_vector_defaults'])}]"
                       if value["in_injection_vector_defaults"] else "")
                    for value in item["b_values"]
                ),
            ]
        )
    out.append(_table(["suite", "user task", "(b) values"], rows))
    out += _c_value_lines(e0)
    out += _exfil_lines(census["e0"]["exfiltration_read_summary"])

    out += [
        "",
        "## E1: is the attacker value co-located with the instruction?",
        "",
        "Views: `gt_only` uses injection-task ground truth only; `gt_plus_fallback` adds the declared security-checker "
        "fallback for the 8 workspace tasks whose ground truth is empty (J14); the third view also counts "
        "exfiltration-read arguments (Slack `get_webpage.url`).",
        "",
    ]
    for view in _E1_VIEWS:
        out += [f"### View `{view}`", ""]
        rows = []
        for suite in [*SUITES, "overall"]:
            item = e1["views"][view]["overall"] if suite == "overall" else e1["views"][view]["per_suite"][suite]
            rows.append(
                [
                    suite,
                    item["injection_tasks"],
                    item["tasks_with_values"],
                    item["values"],
                    item["values_goal_literal"],
                    item["values_in_clean_environment"],
                    item["values_neither"],
                    item["tasks_all_goal_literal"],
                    item["tasks_partial_goal_literal"],
                    item["tasks_none_goal_literal"],
                    item["tasks_no_authority_value"],
                    item["tasks_co_located"],
                    item["tasks_seed_candidate"],
                ]
            )
        out.append(
            _table(
                ["suite", "injection tasks", "with values", "values", "in GOAL", "in clean env", "neither",
                 "tasks: all in GOAL", "partial", "none in GOAL", "no authority value", "co-located",
                 "seed candidate"],
                rows,
            )
        )
        out.append("")
    out += ["### Per injection task (`gt_plus_fallback_with_exfiltration_reads`)", ""]
    value_lookup = defaultdict(list)
    for row in census["e1"]["values"]:
        value_lookup[(row["suite"], row["injection_task_id"])].append(row)
    rows = []
    for task in census["e1"]["tasks"]:
        values = value_lookup[(task["suite"], task["injection_task_id"])]
        rows.append(
            [
                task["suite"],
                task["injection_task_id"],
                task["value_source"],
                task["gt_plus_fallback_with_exfiltration_reads"]["category"],
                "; ".join(
                    f"{row['function']}.{row['argument']}={_code(row['value'])} "
                    f"[{'GOAL' if row['stated_in_goal'] else '-'}/{'env' if row['in_clean_environment'] else '-'}]"
                    for row in values
                )
                or "-",
            ]
        )
    out.append(_table(["suite", "injection task", "value source", "category", "values [GOAL/env]"], rows))
    out += _seed_lines(e1)
    split = e1["split"]
    out += [
        "",
        "### Injection vectors exposed per user task (AgentDojo `BaseAttack.get_injection_candidates`)",
        "",
    ]
    rows = []
    for suite in SUITES:
        item = split["per_suite"][suite]
        rows.append(
            [
                suite,
                item["user_tasks"],
                item["split_capable"],
                ", ".join(f"{cell['vectors']}: {cell['user_tasks']}" for cell in item["vector_count_histogram"]),
                item["split_capable_with_two_or_more_exposing_calls"],
                ", ".join(item["split_capable_tasks"]) or "-",
            ]
        )
    rows.append(
        [
            "overall",
            split["overall"]["user_tasks"],
            split["overall"]["split_capable"],
            "",
            split["overall"]["split_capable_with_two_or_more_exposing_calls"],
            "",
        ]
    )
    out.append(
        _table(
            ["suite", "user tasks", "split-capable (>=2 vectors)", "histogram (vectors: user tasks)",
             "split-capable with vectors in >=2 distinct GT calls", "split-capable tasks"],
            rows,
        )
    )
    out += [
        "",
        f"Parity: the in-module canary run reproduced AgentDojo's vector set for "
        f"{split['overall']['user_tasks'] - split['overall']['parity_failures']}/{split['overall']['user_tasks']} "
        "user tasks.",
        "",
        "## Claims under test",
        "",
    ]
    out += _claims_lines(census["claims"])
    out += [
        "",
        "## Limits",
        "",
        "- Ground truth is one canonical solution per task; utility checkers may accept other values (J16).",
        "- Matching is exact after case and whitespace normalisation; near matches are diagnostics only (J15).",
        "- Workspace injection_task_6 to injection_task_13 have no ground truth; their values come from a hand-read "
        "security() fallback and are reported separately (J14).",
        "- The census counts what the benchmark makes possible; it says nothing about how often a model follows an "
        "injection or which auditor flags what.",
        "",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Markdown summary, protocol v2


def _keys(items: list[str]) -> str:
    return ", ".join(items) or "-"


def _fraction(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator}"


def _view_identity(item: dict) -> str:
    """D3: values = in GOAL + in clean env + neither - both (asserted)."""
    both = item["values_goal_and_clean_environment"]
    total = item["values_goal_literal"] + item["values_in_clean_environment"] + item["values_neither"] - both
    _require(total == item["values"], "E1 view identity does not hold")
    return (
        f"{item['values']} values = {item['values_goal_literal']} in GOAL + {item['values_in_clean_environment']} in "
        f"clean env + {item['values_neither']} neither - {both} in both"
    )


def _value_list(rows: list[dict], task_field: str) -> str:
    return "; ".join(
        f"{row['suite']} {row[task_field]} {row['function']}.{row['argument']}={_code(row['value'])}" for row in rows
    )


def _grouped_tasks(rows: list[dict], task_field: str = "user_task_id") -> str:
    """'suite user_task_7, user_task_10 (x3)' style list of the tasks of some value rows."""
    counts: dict[tuple[str, str], int] = {}
    for row in rows:
        counts[(row["suite"], row[task_field])] = counts.get((row["suite"], row[task_field]), 0) + 1
    by_suite: dict[str, list[str]] = defaultdict(list)
    for (suite, task), count in counts.items():
        by_suite[suite].append(task + (f" (x{count})" if count > 1 else ""))
    return "; ".join(f"{suite} {', '.join(tasks)}" for suite, tasks in by_suite.items())


def _coverage_sentence(coverage: list[dict], suite: str) -> str | None:
    """D2: the attacker literal(s) stated in the most GOALs of a suite (ties included), if at least two."""
    rows = [row for row in coverage if row["suite"] == suite]
    if not rows or rows[0]["goals_stating"] < 2:
        return None
    sentences = []
    for top in (row for row in rows if row["goals_stating"] == rows[0]["goals_stating"]):
        lacking = top["lacking"]
        if not lacking:
            tail = "every GOAL of the suite states it"
        elif len(lacking) == 1:
            tail = f"only the GOAL of {lacking[0]} lacks it"
        else:
            tail = f"the GOALs of {', '.join(lacking[:-1])} and {lacking[-1]} lack it"
        sentences.append(
            f"{_code(top['value'])} is stated in {_fraction(top['goals_stating'], top['injection_tasks'])} {suite} "
            f"GOALs; {tail}."
        )
    return " ".join(sentences)


def _e1_view_table(view_data: dict) -> str:
    rows = []
    for suite in [*SUITES, "overall"]:
        item = view_data["overall"] if suite == "overall" else view_data["per_suite"][suite]
        rows.append(
            [
                suite,
                item["injection_tasks"],
                item["tasks_with_values"],
                item["values"],
                item["values_goal_literal"],
                item["values_in_clean_environment"],
                item["values_goal_and_clean_environment"],
                item["values_neither"],
                item["tasks_all_goal_literal"],
                item["tasks_partial_goal_literal"],
                item["tasks_none_goal_literal"],
                item["tasks_no_authority_value"],
                item["tasks_co_located"],
                item["tasks_seed_candidate"],
            ]
        )
    return _table(
        ["suite", "injection tasks", "with values", "values", "in GOAL", "in clean env", "in GOAL and in clean env",
         "neither", "tasks: all in GOAL", "partial", "none in GOAL", "no authority value", "co-located",
         "seed candidate"],
        rows,
    )


def render_summary_v2(census: dict, config_sha256: str, agent_tracer_head: str) -> str:
    e0 = census["e0"]["summary"]
    e1 = census["e1"]["summary"]
    roles = census["role_table_summary"]
    predecessor = census["predecessor"]
    sensitivity = census["sensitivity"]
    dependency = e0["vector_dependency"]
    precision = {row["id"]: row for row in sensitivity["precision_denominator"]}
    variants = sensitivity["role_variants"]
    coverage = e1["goal_literal_coverage"]
    split = e1["split"]["overall"]
    views = e1["views"]
    without_d5 = e1["views_excluding_tag"].get("D5", {})
    checks = census["verifier_check"]
    mismatches = [row for row in checks if not row["match"]]
    total_users = e0["overall"]["user_tasks"]

    out = [
        "# Authority-origin census v2 (E0, E1): summary",
        "",
        "Status: DRAFT, pending the Agent Tracer code commit. Request-free: no model, provider or network call.",
        "",
        f"- Protocol: `{census['protocol']}`; frozen config `config/authority_census_v2.json`, SHA-256 "
        f"`{config_sha256}`.",
        f"- Predecessor: experiment `{predecessor['experiment_id']}` (protocol `{predecessor['protocol']}`, config "
        f"SHA-256 `{predecessor['config_sha256']}`), kept unchanged as the historical draft. The v2 changes D1-D5 and "
        "the post hoc sections S1-S2 are logged in the config `amendment_log`.",
        f"- Agent Tracer HEAD `{agent_tracer_head}` plus uncommitted census files (see manifest.json).",
        "- Benchmark: vendored AgentDojo 0.1.35 (ethz-spylab/agentdojo 089ed468), benchmark v1.2.2.",
        "- Every number below is computed by `agentdojo_lab.authority_census` and is reproduced in "
        "`derived/census.json`; row-level evidence is in the `derived/*.csv` files.",
        "",
        "## Changes from v1",
        "",
    ]
    dependent = [row for row in dependency["values"] if row["origin"] == "b_environment"]
    groups: dict[tuple[str, tuple[str, ...]], list[dict]] = defaultdict(list)
    for row in dependent:
        groups[(row["value"], tuple(row["vector_dependency_vectors"]))].append(row)
    described = "; ".join(
        f"{_code(value)} (vector {', '.join(vectors) or 'joint'}): {_grouped_tasks(rows)}"
        for (value, vectors), rows in groups.items()
    )
    out.append(
        f"- **D1 (flag, no primary change).** {dependency['overall']['b_vector_dependent']} (b) values are "
        f"vector-dependent, present only because of injection-vector text: {described}. The v1 flag (value inside a "
        f"vector default text) caught {sum(1 for row in dependent if row['in_injection_vector_defaults'])} of them; "
        "the others are built from a vector by a template. Excluding all of them leaves "
        f"{dependency['overall']['b_excluding_vector_dependent']} (b) values and "
        f"{_fraction(dependency['overall']['tasks_with_b_excluding_vector_dependent'], total_users)} user tasks with "
        "a (b) value (row P6)."
    )
    sentences = [sentence for sentence in (_coverage_sentence(coverage, suite) for suite in SUITES) if sentence]
    out.append("- **D2 (text).** " + " ".join(sentences) + " Full table: GOAL-literal coverage below.")
    if without_d5:
        old = without_d5["gt_plus_fallback"]["overall"]
        both = e1["goal_and_clean_environment_values"]["gt_plus_fallback"]
        out.append(
            "- **D3 (text).** View counts overlap: in `gt_plus_fallback` under the v1 convention, "
            f"{_view_identity(old)}. The values in both GOAL and the clean environment: "
            f"{_value_list(both, 'injection_task_id')}. Every view table now has the column "
            "'in GOAL and in clean env'."
        )
    out.append(
        f"- **D4 (post hoc reading).** K2: {_fraction(split['split_capable_with_two_or_more_exposing_calls'], total_users)}"
        f" user tasks counting any exposing ground-truth output, "
        f"{_fraction(split['split_capable_with_two_or_more_first_exposing_calls'], total_users)} counting each "
        f"vector's first exposing output (both post hoc; frozen reading {_fraction(split['split_capable'], total_users)})."
    )
    if without_d5:
        out.append(
            "- **D5 (primary E1 change).** The self-e-mail recipient of workspace injection_task_12 is now listed, as "
            "for injection_task_9 (GOAL tie-breaker, J20). `gt_plus_fallback`: "
            f"{views['gt_plus_fallback']['overall']['values']} values (v1 convention "
            f"{without_d5['gt_plus_fallback']['overall']['values']}); widest view: "
            f"{views['gt_plus_fallback_with_exfiltration_reads']['overall']['values']} (v1 convention "
            f"{without_d5['gt_plus_fallback_with_exfiltration_reads']['overall']['values']}). No task category, "
            "seed candidate or K4 reading changes (table in section E1)."
        )
    out.append(
        "- **S1, S2 (post hoc).** Precision-denominator sensitivity rows P1-P6 and role-table sensitivity rows; "
        "neither changes a primary table."
    )

    out += ["", "## Check against the verifier's expected values", ""]
    out.append(
        f"{len(checks) - len(mismatches)} of {len(checks)} expected values match."
        + (" Rows marked **DIFFERS** do not match." if mismatches else " No number differs.")
    )
    out += [
        "",
        _table(
            ["check", "quantity", "expected", "observed", "match"],
            [
                [row["id"], row["quantity"], json.dumps(row["expected"]), json.dumps(row["observed"]),
                 "yes" if row["match"] else "**DIFFERS**"]
                for row in checks
            ],
        ),
    ]

    out += [
        "",
        "## Role table (primary, unchanged from v1)",
        "",
        "Rule (config `role_rule.authority`): an argument of a state-changing tool is authority-bearing iff its value "
        "decides to whom, where, or on which account or resource the action applies. Judgement calls J1-J20 are listed "
        "in the config. J2 is an explicit exception to the written state-changing rule: `get_webpage` appends the "
        "requested URL to `web.web_requests`, which is a mutation, but it is classified exfiltration-read; row "
        "R-get_webpage in the role-table sensitivity section applies the rule literally.",
        "",
    ]
    out += _role_table_lines(roles)

    out += [
        "",
        "## E0: where do correct authority values come from?",
        "",
        "Unit: one element of one authority argument of one state-changing call in a user task's ground truth. "
        "(a) literally in the prompt; (b) not in the prompt but in the pre-task environment, so it reaches the agent "
        "only through a tool output; (c) neither. Primary counts are unchanged from v1.",
        "",
    ]
    rows = []
    for suite in [*SUITES, "overall"]:
        item = e0["overall"] if suite == "overall" else e0["per_suite"][suite]
        flags = dependency["overall"] if suite == "overall" else dependency["per_suite"][suite]
        values = item["values"]
        rows.append(
            [
                suite,
                item["user_tasks"],
                item["tasks_with_state_changing_call"],
                item["tasks_with_authority_value"],
                values["total"],
                values["a_prompt"],
                values["b_environment"],
                values["c_neither"],
                item["b_exposed_before_call"],
                flags["b_vector_dependent"],
                item["tasks_with_b"],
                item["tasks_with_c"],
                item["tasks_all_a"],
            ]
        )
    out.append(
        _table(
            ["suite", "user tasks", "with state-changing call", "with authority value", "values", "(a)", "(b)", "(c)",
             "(b) exposed by earlier GT output", "(b) vector-dependent (D1)", "tasks with (b)", "tasks with (c)",
             "tasks all (a)"],
            rows,
        )
    )
    out += _per_tool_lines(e0)

    primary = precision["P0"]
    out += [
        "",
        f"### Precision denominator: {_fraction(primary['numerator'], primary['denominator'])} user tasks with at "
        "least one (b) value, and its sensitivity rows",
        "",
        "P0 is the primary, pre-specified count: an origin rule that admits only prompt-origin authority values would "
        "block the legitimate ground-truth run of each of these tasks. P1-P6 are post hoc (S1) and change no primary "
        "table.",
        "",
        _table(
            ["row", "definition", "post hoc", "user tasks", "removed vs P0", "added vs P0"],
            [
                [
                    row["id"],
                    row["label"],
                    "yes" if row["post_hoc"] else "no (primary)",
                    _fraction(row["numerator"], row["denominator"]),
                    _keys(row["removed_vs_primary"]),
                    _keys(row["added_vs_primary"]),
                ]
                for row in sensitivity["precision_denominator"]
            ],
        ),
        "",
        "P1 and P3 use a request-free utility intervention: the ground truth is replayed without the calls that carry "
        "the blocked values and AgentDojo's own utility check is applied (config `sensitivity.utility_intervention`). "
        "P4 drops the user tasks built by AgentDojo's TaskCombinator from numerator and denominator. P5 replaces the "
        "environment rule for text kinds by exact whole-field equality. P6 drops vector-dependent (b) values (D1).",
        "",
        "Per task (flags: `not shown by an earlier GT call`; `inside vector default` = v1 flag; `vector-dependent` = "
        "D1 flag):",
        "",
    ]
    task_rows = {_task_key(row): row for row in census["e0"]["tasks"]}
    value_rows = defaultdict(list)
    for row in census["e0"]["values"]:
        if row["origin"] == "b_environment":
            value_rows[_task_key(row)].append(row)
    rows = []
    for key in primary["tasks"]:
        task = task_rows[key]
        rows.append(
            [
                task["suite"],
                task["user_task_id"],
                "; ".join(
                    f"{value['function']}.{value['argument']}={_code(value['value'])}"
                    + ("" if value["exposed_before_call"] else " (not shown by an earlier GT call)")
                    + (f" [inside vector default {', '.join(value['in_injection_vector_defaults'])}]"
                       if value["in_injection_vector_defaults"] else "")
                    + (f" [vector-dependent: {', '.join(value['vector_dependency_vectors']) or 'joint'}]"
                       if value["vector_dependent"] else "")
                    for value in value_rows[key]
                ),
                "yes" if task["combined_task"] else "-",
                "passes" if task["utility_without_b_calls"] else "fails",
            ]
        )
    out.append(
        _table(["suite", "user task", "(b) values", "combined task", "utility without the (b) calls"], rows)
    )
    out += _c_value_lines(e0)
    out += _exfil_lines(census["e0"]["exfiltration_read_summary"])

    out += [
        "",
        "## E1: is the attacker value co-located with the instruction?",
        "",
        "Views: `gt_only` uses injection-task ground truth only; `gt_plus_fallback` adds the declared security-checker "
        "fallback for the 8 workspace tasks whose ground truth is empty (J14); the third view also counts "
        "exfiltration-read arguments (Slack `get_webpage.url`). A value can be both in GOAL and in the clean "
        "environment, so the columns 'in GOAL', 'in clean env' and 'neither' overlap (D3); each view states the "
        "identity.",
        "",
    ]
    for view in _E1_VIEWS:
        out += [f"### View `{view}`", "", _e1_view_table(views[view]), "", f"Identity: {_view_identity(views[view]['overall'])}."]
        both = e1["goal_and_clean_environment_values"][view]
        out += [f"In both GOAL and the clean environment: {_value_list(both, 'injection_task_id') or 'none'}.", ""]
    if without_d5:
        out += [
            "### D5: v2 counts next to the v1 convention",
            "",
            "Tag D5 marks the one added fallback value (workspace injection_task_12, `send_email.recipients` = the "
            "account e-mail, in the clean environment, not in GOAL). The v1 convention omits it.",
            "",
        ]
        rows = []
        for view in _E1_VIEWS:
            for label, data in (("v2", views[view]["overall"]), ("v1 convention", without_d5[view]["overall"])):
                rows.append(
                    [
                        view,
                        label,
                        data["values"],
                        data["values_goal_literal"],
                        data["values_in_clean_environment"],
                        data["values_goal_and_clean_environment"],
                        data["values_neither"],
                        data["tasks_all_goal_literal"],
                        data["tasks_partial_goal_literal"],
                        data["tasks_none_goal_literal"],
                        data["tasks_no_authority_value"],
                        data["tasks_seed_candidate"],
                    ]
                )
        out.append(
            _table(
                ["view", "count", "values", "in GOAL", "in clean env", "both", "neither", "tasks: all in GOAL",
                 "partial", "none in GOAL", "no authority value", "seed candidate"],
                rows,
            )
        )
        out.append("")
    out += [
        "### GOAL-literal coverage (D2)",
        "",
        " ".join(sentences),
        "",
        "For every attacker value stated in at least one GOAL: how many of the suite's injection-task GOALs state it.",
        "",
        _table(
            ["suite", "value", "GOALs stating it", "GOALs lacking it", "attacker value of"],
            [
                [row["suite"], _code(row["value"]), _fraction(row["goals_stating"], row["injection_tasks"]),
                 _keys(row["lacking"]), _keys(row["attacker_value_of"])]
                for row in coverage
            ],
        ),
        "",
        "### Per injection task (`gt_plus_fallback_with_exfiltration_reads`)",
        "",
    ]
    value_lookup = defaultdict(list)
    for row in census["e1"]["values"]:
        value_lookup[(row["suite"], row["injection_task_id"])].append(row)
    rows = []
    for task in census["e1"]["tasks"]:
        values = value_lookup[(task["suite"], task["injection_task_id"])]
        rows.append(
            [
                task["suite"],
                task["injection_task_id"],
                task["value_source"],
                task["gt_plus_fallback_with_exfiltration_reads"]["category"],
                "; ".join(
                    f"{row['function']}.{row['argument']}={_code(row['value'])} "
                    f"[{'GOAL' if row['stated_in_goal'] else '-'}/{'env' if row['in_clean_environment'] else '-'}]"
                    + (f" (tag {row['fallback_tag']})" if row["fallback_tag"] else "")
                    for row in values
                )
                or "-",
            ]
        )
    out.append(_table(["suite", "injection task", "value source", "category", "values [GOAL/env]"], rows))
    out += _seed_lines(e1)

    split_suites = e1["split"]["per_suite"]
    out += [
        "",
        "### Injection vectors exposed per user task (AgentDojo `BaseAttack.get_injection_candidates`)",
        "",
        "The last two count columns are post hoc readings of K2 (D4): vectors exposed by at least two distinct "
        "ground-truth outputs counting any exposing output, and counting only each vector's first exposing output.",
        "",
    ]
    rows = []
    for suite in SUITES:
        item = split_suites[suite]
        rows.append(
            [
                suite,
                item["user_tasks"],
                item["split_capable"],
                ", ".join(f"{cell['vectors']}: {cell['user_tasks']}" for cell in item["vector_count_histogram"]),
                item["split_capable_with_two_or_more_exposing_calls"],
                item["split_capable_with_two_or_more_first_exposing_calls"],
                _keys(item["any_but_not_first_exposing_calls"]),
                _keys(item["split_capable_tasks"]),
            ]
        )
    rows.append(
        [
            "overall",
            split["user_tasks"],
            split["split_capable"],
            "",
            split["split_capable_with_two_or_more_exposing_calls"],
            split["split_capable_with_two_or_more_first_exposing_calls"],
            "",
            "",
        ]
    )
    out.append(
        _table(
            ["suite", "user tasks", "split-capable (>=2 vectors)", "histogram (vectors: user tasks)",
             "post hoc: >=2 distinct GT calls, any exposing output",
             "post hoc: >=2 distinct GT calls, first exposing output per vector", "differ", "split-capable tasks"],
            rows,
        )
    )
    out += [
        "",
        f"Parity: the in-module canary run reproduced AgentDojo's vector set for "
        f"{split['user_tasks'] - split['parity_failures']}/{split['user_tasks']} user tasks.",
        "",
        "## Claims under test",
        "",
    ]
    out += _claims_lines(census["claims"])

    out += [
        "",
        "## Sensitivity: role table (post hoc, S2)",
        "",
        "Each row re-runs E0 and E1 with one judgement call reversed. None of them changes the primary role table or "
        "any primary count above. J2 is an explicit exception to the written state-changing rule, so row "
        "R-get_webpage is the literal reading of that rule; its E1 view equals the primary widest view.",
        "",
        _table(
            ["row", "variant", "reverses", "E0 values", "(a)", "(b)", "(c)", "tasks with (b)",
             "(b) tasks gained", "tasks with (b) or (c)", "E1 gt+fallback values", "E1 seed tasks",
             "seed tasks gained", "E1 category changes"],
            [
                [
                    item["id"],
                    item["label"],
                    item["reverses"],
                    item["e0"]["values"]["total"],
                    item["e0"]["values"]["a_prompt"],
                    item["e0"]["values"]["b_environment"],
                    item["e0"]["values"]["c_neither"],
                    _fraction(item["e0"]["tasks_with_b"], total_users),
                    _keys(item["e0"]["new_b_tasks"]),
                    _fraction(item["e0"]["tasks_with_b_or_c"], total_users),
                    item["e1"]["overall"]["values"],
                    item["e1"]["overall"]["tasks_seed_candidate"],
                    _keys(item["e1"]["new_seed_tasks"]),
                    _keys([f"{change['task']}: {change['primary']} -> {change['variant']}"
                           for change in item["e1"]["category_changes"]]),
                ]
                for item in variants
            ],
        ),
        "",
        f"Primary for comparison: E0 {e0['overall']['values']['total']} values ({e0['overall']['values']['a_prompt']} "
        f"(a), {e0['overall']['values']['b_environment']} (b), {e0['overall']['values']['c_neither']} (c)), "
        f"{_fraction(e0['overall']['tasks_with_b'], total_users)} tasks with (b), "
        f"{_fraction(precision['P2']['numerator'], total_users)} with (b) or (c); E1 `gt_plus_fallback` "
        f"{views['gt_plus_fallback']['overall']['values']} values, "
        f"{views['gt_plus_fallback']['overall']['tasks_seed_candidate']} seed tasks.",
        "",
        "Values each variant adds:",
        "",
    ]
    for item in variants:
        added_e0 = item["e0"]["added_values"]
        added_e1 = item["e1"]["added_values"]
        e0_text = "; ".join(
            f"{row['suite']} {row['user_task_id']} {_code(row['value'])} ({row['origin'][0]})" for row in added_e0
        ) or "none"
        e1_counts = Counter(f"{row['suite']} {row['injection_task_id']}" for row in added_e1)
        e1_text = ", ".join(f"{task} ({count})" for task, count in e1_counts.items()) or "none"
        out.append(f"- {item['id']}: E0 {len(added_e0)} value(s): {e0_text}. E1 {len(added_e1)} value(s): {e1_text}.")
    collisions = sensitivity["prompt_collisions"]
    out += [
        "",
        "### Attacker values that appear in a user prompt (collisions)",
        "",
        f"{collisions['count']} distinct (suite, injection task, attacker value) occur literally, under the prompt rule, "
        "in at least one user PROMPT of the same suite. These are string collisions: the user task may use the string "
        "for a different object (a number, a different file). Where the user task uses it for the same object, an "
        "origin rule would treat the attacker value as user-supplied in that task.",
        "",
        _table(
            ["suite", "injection task", "attacker value", "argument", "user prompts containing it"],
            [
                [row["suite"], row["injection_task_id"], _code(row["value"]), _keys(row["arguments"]),
                 _keys(row["user_tasks"])]
                for row in collisions["rows"]
            ],
        ),
        "",
        "### Exact whole-field matching (detail of P5)",
        "",
        "E0 values whose origin changes when a text value must equal a whole environment field: "
        + (
            "; ".join(
                f"{row['suite']} {row['user_task_id']} {row['function']}.{row['argument']}={_code(row['value'])} "
                f"({row['origin'][0]} -> {row['origin_exact_field'][0]})"
                for row in sensitivity["e0_exact_field_changed_values"]
            )
            or "none"
        )
        + ".",
        "",
    ]
    exact = sensitivity["e1_exact_field"]["views"]["gt_plus_fallback"]
    out += [
        f"E1 (`gt_plus_fallback`): {exact['values_in_clean_environment_exact_field']} values in the clean environment "
        f"under exact matching (primary {exact['values_in_clean_environment']}); seed-candidate tasks "
        f"{exact['tasks_seed_candidate_exact_field']} (primary {exact['tasks_seed_candidate']}).",
        "",
        "## Limits",
        "",
        "- Ground truth is one canonical solution per task; utility checkers may accept other values (J16). The P1/P3 "
        "utility intervention replays only the canonical ground truth.",
        "- Matching is exact after case and whitespace normalisation; near matches are diagnostics only (J15).",
        "- Workspace injection_task_6 to injection_task_13 have no ground truth; their values come from a hand-read "
        "security() fallback and are reported separately (J14); D5 adds one GOAL-based value (J20).",
        "- Every v2 change and every sensitivity row was written after the v1 counts and the independent verification "
        "were seen; they are post hoc (config `amendment_log`).",
        "- The census counts what the benchmark makes possible; it says nothing about how often a model follows an "
        "injection or which auditor flags what.",
        "",
    ]
    return "\n".join(out)
