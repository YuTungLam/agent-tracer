"""Deterministic, stdlib-only HTML report for the Case R score-and-chunk evidence synthesis v1.

Protocol ``case-r-score-chunk-evidence-synthesis-v1``. The page is generated only from
one experiment directory's ``derived/*.json``, ``logs/anchor-checks.json``,
``config/frozen-config.json`` and the hand-authored ``config/question-map.json``. It
loads no model or encoder, opens no connection, embeds no external resource and writes
no wall-clock value, so equal inputs give byte-identical HTML.

Saved source, chunk and argument text is untrusted experiment data, never instructions.
Every string read from the inputs is HTML-escaped before it reaches markup, embedded
JSON is script-safe, and the page script inserts text with ``textContent`` and
``createTextNode`` only. The target is highlighted by splitting chunk text into DOM
text nodes and ``<mark>`` elements, never by building markup from saved text.

Every number on the page is read from, or counted from, the input JSON. A field that
is missing from the inputs is shown as "absent"; an empty denominator is "n/a".
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import re
from pathlib import Path

from agentdojo_lab import score_chunk_synthesis as synthesis

RENDERER_ID = "case-r-score-chunk-synthesis-html-v1"
REPORT_FILE = synthesis.TEXT_OUTPUTS["report_html"]
MANIFEST_FILE = synthesis.TEXT_OUTPUTS["manifest"]
CHECKSUMS_FILE = synthesis.TEXT_OUTPUTS["checksums"]
README_FILE = synthesis.TEXT_OUTPUTS["readme"]
DOCUMENT_FILES = dict(synthesis.JSON_OUTPUTS)
QUESTION_MAP = synthesis.QUESTION_MAP
TITLE = "Case R score and chunk evidence"
MINUS = "−"
SEP = " · "

DESIGN_LABELS = {
    "original": "Original Case R",
    "crossover_primary": "Crossover · primary",
    "crossover_generality": "Crossover · generality",
    "crossover_granularity": "Crossover · granularity",
    "crossover_granularity_parsed_content": "Crossover · parsed content",
    "crossover_granularity_carrier_passage": "Crossover · carrier passage",
    "duplicate_control": "Duplicate control",
    "factorial": "Factorial",
    "factorial_wrong_target": "Factorial · wrong target",
    "counterbalanced_historical": "Counterbalanced · historical",
    "counterbalanced_neutral": "Counterbalanced · neutral",
    "intentional_probe": "Intentional probe (replay)",
}
ROLE_ORDER = ("legitimate", "attacker", "neutral_alpha", "neutral_bravo", "neutral_address_a", "neutral_address_b")
CONTEXT_ORDER = ("normal", "attack", "malicious", "contact", "updated", "summary", "directive")
STAGE_LABELS = {
    "tier3": "Tier 3 · whole-source cosine",
    "tier4": "Tier 4 · best-chunk cosine",
}
SWEEP_STAGES = ("tier3", "tier4_coverage_on", "tier4_coverage_off")
SWEEP_SERIES = (
    ("legitimate", "legit", "Legitimate carriers matched"),
    ("attacker", "attack", "Attacker carriers matched"),
    ("noncarrier", "non", "Noncarriers matched (false positives)"),
)
PAIR_LABELS = {
    "carriers_vs_noncarriers": "Carriers vs noncarriers",
    "legitimate_over_attacker": "Legitimate over attacker",
    "attacker_over_legitimate": "Attacker over legitimate",
    "legitimate_vs_noncarriers": "Legitimate vs noncarriers",
    "attacker_vs_noncarriers": "Attacker vs noncarriers",
}
DEFAULT_PAIR = "carriers_vs_noncarriers"
STATUS = {
    "answered": ("st-ok", "✓", "Answered"),
    "partial": ("st-part", "◐", "Partial"),
    "gated": ("st-gate", "⊘", "Gated"),
    "open": ("st-open", "○", "Open"),
}
CONTRAST_DESIGNS = (
    "crossover_primary",
    "crossover_generality",
    "duplicate_control",
    "factorial",
    "counterbalanced_historical",
    "counterbalanced_neutral",
)
SECTION_TITLES = {
    1: "Supervisor question map",
    2: "Ledger: every scored relation",
    3: "Threshold sensitivity (exploratory)",
    4: "Design contrasts",
    5: "Cross-suite view (DeepSeek)",
    6: "Anchor checks, method and limits",
}
# Topics whose tables live in one section of this page; used only to flag a wrong reference in the map.
SECTION_TOPICS = (("DeepSeek", 5),)
SCORE_LABELS = {
    "tier4_whole_source_best_chunk_cosine": "whole-source best-chunk T4",
    "tier4_localized_target_and_context_chunk_cosine": "localized target-and-context T4",
    "tier4_best_target_containing_chunk_cosine": "best target-containing chunk T4",
    "tier3_whole_source_cosine": "whole-source T3",
}
AUDIT_CLASS_LABELS = {
    "target_absent_whole_output_semantic_confusion": "Target absent from the whole output: semantic confusion",
    "target_coresident_best_chunk_contains_target": "Target co-resident: best chunk contains the target",
    "target_coresident_best_chunk_excludes_target": "Target co-resident: best chunk excludes the target",
    "target_coresident_whole_output_t4_below_threshold": "Target co-resident: whole-output T4 below threshold",
}
INFO_LABELS = {
    "counterbalanced_distinct_blocks": "Counterbalanced arms, distinct blocks",
    "deepseek_passage_tier3_equals_tier4": "DeepSeek passage level: every T3 total equals its T4 total",
    "run_denominator_tier3_attack": "Run denominator, attack condition: T3 verified attacker hits / runs",
    "run_denominator_tier3_clean": "Run denominator, clean condition: T3 verified legitimate hits / runs",
}


class ReportInputError(ValueError):
    """A saved input is missing, unparsable or differs from the recorded digests."""


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT = _Absent()


# --------------------------------------------------------------------------- helpers


def g(value, *path):
    """Nested lookup that returns ``ABSENT`` instead of raising."""
    for key in path:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and isinstance(key, int) and -len(value) <= key < len(value):
            value = value[key]
        else:
            return ABSENT
    return value


def glist(value, *path) -> list:
    found = g(value, *path)
    return found if isinstance(found, list) else []


def gdict(value, *path) -> dict:
    found = g(value, *path)
    return found if isinstance(found, dict) else {}


def esc(value) -> str:
    if value is ABSENT:
        return "absent"
    return html.escape("" if value is None else str(value), quote=True)


def is_num(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value, digits: int = 4) -> str:
    """Plain-text number: ``absent`` for a missing field, ``n/a`` for null."""
    if value is ABSENT:
        return "absent"
    if value is None:
        return "n/a"
    if not is_num(value):
        return str(value)
    if is_int(value):
        return str(value).replace("-", MINUS)
    text = f"{value:.{digits}f}"
    if text.startswith("-") and float(text) == 0:
        text = text[1:]
    return text.replace("-", MINUS)


def sfmt(value, digits: int = 4) -> str:
    text = fmt(value, digits)
    if not is_num(value) or text.startswith(MINUS) or float(text.replace(MINUS, "-")) == 0:
        return text
    return "+" + text


def num_h(value, digits: int = 4) -> str:
    if value is ABSENT:
        return "<span class='absent' title='field absent in the derived JSON'>absent</span>"
    if value is None:
        return "<span class='na'>n/a</span>"
    return esc(fmt(value, digits))


def signed_h(value, digits: int = 4) -> str:
    if value is ABSENT or value is None:
        return num_h(value, digits)
    return esc(sfmt(value, digits))


def yes_no(value) -> str:
    if value is ABSENT:
        return "absent"
    if value is None:
        return "n/a"
    if value is True:
        return "yes"
    if value is False:
        return "no"
    if isinstance(value, list):
        return " / ".join(yes_no(item) for item in value) + " (varies by row)"
    return str(value)


def pct(value: float, lo: float, hi: float) -> float:
    if hi <= lo:
        return 0.0
    return max(0.0, min(100.0, (value - lo) / (hi - lo) * 100.0))


def script_json(data) -> str:
    """JSON that is safe inside a ``<script>`` element (no ``<``, ``>``, ``&`` or line separators)."""
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for raw, safe in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(raw, safe)
    return text


def tip_attr(lines: list[str]) -> str:
    return esc("\n".join(lines))


def design_label(design) -> str:
    return DESIGN_LABELS.get(design, str(design)) if isinstance(design, str) else "absent"


def context_label(value) -> str:
    """Design context label; identical text saved under several labels ('a|b') reads 'a + b'."""
    if not isinstance(value, str):
        return words(value)
    return " + ".join(words(part) for part in value.replace("+", "|").split("|"))


def score_label(name) -> str:
    return SCORE_LABELS.get(name, words(name)) if isinstance(name, str) else "score absent"


def h2(number: int) -> str:
    return f"<h2>{number} · {esc(SECTION_TITLES[number])}</h2>"


def words(value) -> str:
    return str(value).replace("_", " ") if isinstance(value, str) else fmt(value)


def cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def sentence(text) -> str:
    """Escaped text that ends with a full stop."""
    body = esc(text).rstrip()
    return body if body.endswith((".", "!", "?")) else body + "."


def plural(count, noun: str) -> str:
    return f"{fmt(count)} {noun}" + ("" if count == 1 else "s")


def ordered(keys, order) -> list:
    rank = {key: index for index, key in enumerate(order)}
    return sorted(keys, key=lambda key: (rank.get(key, len(order)), str(key)))


def ratio_cell_text(cell) -> str:
    if cell is ABSENT or not isinstance(cell, dict):
        return "absent"
    display = cell.get("display")
    if isinstance(display, str):
        return display
    hits, scored = cell.get("hits"), cell.get("scored")
    if is_int(hits) and is_int(scored):
        return f"{hits}/{scored}" if scored else "n/a"
    return "absent"


def ratio_h(cell, meter: bool = True) -> str:
    if cell is ABSENT or not isinstance(cell, dict):
        return num_h(ABSENT)
    text = ratio_cell_text(cell)
    rate = cell.get("rate")
    if text == "n/a" or rate is None:
        return "<span class='na'>n/a</span>"
    if not meter or not is_num(rate):
        return f"<span class='rv'>{esc(text)}</span>"
    return (
        f"<span class='rt'><span class='rv'>{esc(text)}</span>"
        f"<span class='mt' aria-hidden='true'><i style='width:{max(0.0, min(1.0, rate)) * 100:.1f}%'></i></span></span>"
    )


def basis_h(basis) -> str:
    if not isinstance(basis, str):
        return "<span class='basis absent'>basis absent</span>"
    if basis.startswith("saved_field"):
        kind, label = "saved", "saved field"
    elif basis.startswith("inferred_not_verifiable"):
        kind, label = "unverifiable", "not verifiable"
    elif basis.startswith("inferred"):
        kind, label = "inferred", "inferred from text"
    else:
        kind, label = "other", "see basis"
    return f"<span class='basis {kind}' title='{esc(basis)}'>{label}</span>"


def role_class(role) -> str:
    return {"legitimate": "legit", "attacker": "attack"}.get(role, "other")


def table_h(headers: list[str], rows: list[list[str]], *, cls: str = "", caption: str = "") -> str:
    """Headers are trusted constants; every cell must already be escaped markup."""
    head = "".join(f"<th scope='col'>{header}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    cap = f"<caption>{caption}</caption>" if caption else ""
    return f"<div class='tscroll'><table class='{cls}'>{cap}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def stack_slots(positions: list[float], gap: float) -> list[int]:
    """Vertical slot per mark so marks closer than ``gap`` (percent) never overlap."""
    order = sorted(range(len(positions)), key=lambda index: (positions[index], index))
    last: list[float] = []
    slots = [0] * len(positions)
    for index in order:
        position = positions[index]
        for slot, previous in enumerate(last):
            if position - previous >= gap:
                last[slot] = position
                slots[index] = slot
                break
        else:
            slots[index] = len(last)
            last.append(position)
    return slots


def nice_ticks(lo: float, hi: float, step: float) -> list[float]:
    count = int(round((hi - lo) / step))
    return [round(lo + step * index, 6) for index in range(count + 1)]


# --------------------------------------------------------------------------- facts


def _original_rows(documents: dict) -> list[dict]:
    return [row for row in glist(documents, "ledger", "rows") if g(row, "design") == "original"]


def _tally(rows: list[dict], kinds: tuple[str, ...], stage: str):
    selected = [row for row in rows if g(row, "relation_kind") in kinds]
    if not selected:
        return ABSENT
    hits = total = 0
    for row in selected:
        occurrences, matched = g(row, "occurrences"), g(row, stage, "matched")
        if not is_int(occurrences) or not isinstance(matched, bool):
            return ABSENT
        total += occurrences
        hits += occurrences if matched else 0
    return {"hits": hits, "total": total, "distinct": len(selected), "text": f"{hits}/{total}"}


def _tally_text(tally) -> str:
    return tally["text"] if isinstance(tally, dict) else "absent"


def _contrast_designs(documents: dict) -> dict:
    return {g(entry, "design"): entry for entry in glist(documents, "contrasts", "designs") if isinstance(entry, dict)}


def _localized_is_best(documents: dict, designs: tuple[str, ...]):
    """(rows whose localized chunk is the whole-source best chunk, rows with a localized score), counted."""
    rows = [row for row in glist(documents, "ledger", "rows")
            if g(row, "design") in designs and isinstance(g(row, "localized_tier4"), dict)]
    if not rows:
        return ABSENT
    same = 0
    for row in rows:
        local, best = g(row, "localized_tier4"), g(row, "tier4")
        index, best_index = g(local, "best_chunk_index"), g(best, "best_chunk", "index")
        score, best_score = g(local, "best_score"), g(best, "best_score")
        if is_int(index) and index == best_index and is_num(score) and score == best_score:
            same += 1
    return same, len(rows)


def _feature_changes(designs: dict, matched: tuple[str, ...]) -> list[str]:
    """Design features that differ between the crossover primary and every matched design (read, not inferred)."""
    primary = gdict(designs.get("crossover_primary"), "design_features")
    others = [gdict(designs.get(name), "design_features") for name in matched]
    if not primary or not all(others):
        return []
    changes = []
    if g(primary, "name_cue_present", "legitimate") is True and all(
            g(other, "name_cue_present", "legitimate") is False for other in others):
        changes.append("name_cue")
    if all(isinstance(g(other, "source_unit"), str) and g(other, "source_unit") != g(primary, "source_unit")
           for other in others):
        changes.append("source_unit")
    if all(gdict(other, "context_strength") != gdict(primary, "context_strength") for other in others):
        changes.append("context")
    return changes


def facts(documents: dict) -> dict:
    """Headline numbers, each read or counted from the documents (``ABSENT`` when missing)."""
    rows = _original_rows(documents)
    legit_rows = [row for row in rows if g(row, "relation_kind") == "legitimate_carrier"]
    attack_rows = [row for row in rows if g(row, "relation_kind") == "attacker_carrier"]
    legit_scores = [g(row, "tier4", "best_score") for row in legit_rows]
    legit_best = max(legit_scores) if legit_scores and all(is_num(s) for s in legit_scores) else ABSENT
    legit_texts = {g(row, "tier4", "best_chunk", "text") for row in legit_rows}
    legit_same = len(legit_rows) > 1 and len(legit_texts) == 1 and ABSENT not in legit_texts
    legit_cp = ABSENT
    for row in legit_rows:
        if g(row, "tier4", "best_score") == legit_best:
            legit_cp = g(row, "tier4", "best_chunk", "codepoints")
            break
    target_scores = [g(row, "tier4", "best_target_containing_chunk", "score") for row in attack_rows]
    target_ok = bool(target_scores) and all(is_num(s) for s in target_scores)
    designs = _contrast_designs(documents)
    primary = gdict(designs.get("crossover_primary"), "blocks", 0, "value_contrast")
    factorial = gdict(designs.get("factorial"), "blocks", 0, "value_contrast")
    historical = gdict(designs.get("counterbalanced_historical"), "summary", "value_contrast")
    interval = g(documents, "threshold_sensitivity", "separating_intervals", "by_stage", "tier4_coverage_on",
                 "carriers_vs_noncarriers")
    population = gdict(documents, "threshold_sensitivity", "population")
    passage = gdict(documents, "cross_suite", "passage_level")
    anchors = gdict(documents, "anchor_checks")
    matched_designs = ("factorial", "counterbalanced_historical")
    return {
        "primary_score": g(designs.get("crossover_primary"), "score_used"),
        "factorial_score": g(designs.get("factorial"), "score_used"),
        "historical_score": g(designs.get("counterbalanced_historical"), "score_used"),
        "localized_is_best": _localized_is_best(documents, matched_designs),
        "feature_changes": _feature_changes(designs, matched_designs),
        "thr_legit_texts": g(population, "distinct_legitimate_carrier_texts"),
        "thr_attack_texts": g(population, "distinct_attacker_carrier_texts"),
        "ds_legit_text": g(passage, "carrier_totals", "legitimate_text", "tier4"),
        "ds_legit_numeric": g(passage, "carrier_totals", "legitimate_numeric", "tier4"),
        "legit_t4": _tally(rows, ("legitimate_carrier",), "tier4"),
        "attack_t4": _tally(rows, ("attacker_carrier",), "tier4"),
        "carriers_t3": _tally(rows, ("legitimate_carrier", "attacker_carrier"), "tier3"),
        "noncarrier_t4": _tally(rows, ("noncarrier",), "tier4"),
        "legit_best": legit_best,
        "legit_best_cp": legit_cp,
        "legit_same_chunk": legit_same,
        "attack_target_min": min(target_scores) if target_ok else ABSENT,
        "attack_target_max": max(target_scores) if target_ok else ABSENT,
        "primary_normal": g(primary, "normal"),
        "primary_attack": g(primary, "attack"),
        "factorial_normal": g(factorial, "normal"),
        "factorial_malicious": g(factorial, "malicious"),
        "historical_normal": g(historical, "normal", "median"),
        "historical_malicious": g(historical, "malicious", "median"),
        "historical_positive": g(historical, "normal", "positive_blocks"),
        "historical_blocks": g(historical, "normal", "distinct_blocks"),
        "interval": interval if isinstance(interval, dict) else ABSENT,
        "ds_legit": g(passage, "carrier_totals", "legitimate_all", "tier4"),
        "ds_attack": g(passage, "carrier_totals", "attacker_all", "tier4"),
        "ds_noncarrier": g(passage, "noncarrier_totals", "tier4"),
        "anchors_passed": g(anchors, "passed"),
        "anchors_failed": g(anchors, "failed"),
        "anchors_all": g(anchors, "all_passed"),
    }


def posthoc_text(legit_texts, attack_texts) -> str:
    """The three elements every part of the threshold view repeats: post hoc, carrier-text count, no operating point."""
    if is_int(legit_texts) and is_int(attack_texts):
        texts = f"over {legit_texts + attack_texts} unique carrier texts ({legit_texts} legitimate, {attack_texts} attacker)"
    else:
        texts = "over a carrier-text count that is absent from the derived JSON"
    return f"Post hoc, {texts}; not a proposed operating point"


def _distinct_text(cell) -> str:
    return ratio_cell_text(g(cell, "distinct_texts"))


def _change_clause(changes: list[str]) -> str:
    changed = [label for key, label in (("source_unit", "the source unit"), ("context", "the context wording"))
               if key in changes]
    clause = ", which remove the name cue" if "name_cue" in changes else ""
    if changed:
        clause += (" but also change " if clause else ", which change ") + " and ".join(changed)
    return clause + " (Section 4, design-feature matrix)"


def bottom_line(f: dict) -> str:
    legit, attack, t3 = f["legit_t4"], f["attack_t4"], f["carriers_t3"]
    interval = f["interval"]
    caveat = esc(posthoc_text(f["thr_legit_texts"], f["thr_attack_texts"]))
    if isinstance(interval, dict) and interval.get("exists") is True:
        separation = (
            f"{caveat}: only Tier-4 thresholds in ({esc(fmt(interval.get('lower_exclusive')))}, "
            f"{esc(fmt(interval.get('upper_inclusive')))}] separate all carriers from all noncarriers."
        )
    elif isinstance(interval, dict):
        separation = f"{caveat}: no Tier-4 threshold separates every carrier from every noncarrier."
    else:
        separation = "The separating-interval field is absent."
    distinct_legit = legit["distinct"] if isinstance(legit, dict) else "absent"
    distinct_attack = attack["distinct"] if isinstance(attack, dict) else "absent"
    blocks = (
        f"{esc(fmt(f['historical_positive']))}/{esc(fmt(f['historical_blocks']))} distinct blocks positive"
    )
    same = f["localized_is_best"]
    if isinstance(same, tuple) and same[1] and same[0] == same[1]:
        same_text = (
            f" In all {same[1]} of those factorial and counterbalanced rows the localized chunk is the whole-source "
            f"best chunk, so {esc(score_label(f['primary_score']))} gives the same contrasts."
        )
    elif isinstance(same, tuple):
        same_text = (f" The localized chunk is the whole-source best chunk in {same[0]} of {same[1]} of those rows, "
                     "so the two scores can differ there.")
    else:
        same_text = ""
    return (
        f"In the original Case R line, Tier 4 matched <b>{esc(_tally_text(legit))}</b> legitimate- and "
        f"<b>{esc(_tally_text(attack))}</b> attacker-recipient carrier relations; Tier 3 matched "
        f"<b>{esc(_tally_text(t3))}</b>. These are only {esc(distinct_legit)} and "
        f"{esc(distinct_attack)} distinct texts. The legitimate texts pass on "
        f"{'the same' if f['legit_same_chunk'] else 'a'} {esc(fmt(f['legit_best_cp']))}-code-point chunk "
        f"({esc(fmt(f['legit_best']))}); the attacker "
        f"addresses' best target-containing chunks score {esc(fmt(f['attack_target_min']))}"
        f"–{esc(fmt(f['attack_target_max']))}. Legitimate − attacker is positive on the original "
        f"crossover scaffold ({esc(score_label(f['primary_score']))}: {esc(sfmt(f['primary_normal']))} normal, "
        f"{esc(sfmt(f['primary_attack']))} attack) but negative in the factorial and counterbalanced designs"
        f"{esc(_change_clause(f['feature_changes']))}: factorial ({esc(score_label(f['factorial_score']))}) "
        f"{esc(sfmt(f['factorial_normal']))} normal / {esc(sfmt(f['factorial_malicious']))} malicious; "
        f"counterbalanced medians ({esc(score_label(f['historical_score']))}) "
        f"{esc(sfmt(f['historical_normal']))} / {esc(sfmt(f['historical_malicious']))}, {blocks}.{same_text} "
        f"{separation} "
        f"DeepSeek, reported separately and never pooled: passage-level Tier 4 flags "
        f"{esc(ratio_cell_text(f['ds_legit_text']))} legitimate text carriers "
        f"(+{esc(ratio_cell_text(f['ds_legit_numeric']))} numeric) and {esc(ratio_cell_text(f['ds_attack']))} "
        f"attacker carriers, and also {esc(ratio_cell_text(f['ds_noncarrier']))} noncarriers (relations); by distinct "
        f"passage text and target: {esc(_distinct_text(f['ds_legit_text']))}, "
        f"{esc(_distinct_text(f['ds_legit_numeric']))}, {esc(_distinct_text(f['ds_attack']))} and "
        f"{esc(_distinct_text(f['ds_noncarrier']))}."
    )


# --------------------------------------------------------------------------- header


def _header(documents: dict, f: dict, question_note: str) -> str:
    frozen = gdict(documents, "frozen_config")
    requests = gdict(frozen, "requests")
    request_text = ", ".join(f"{key} {fmt(value)}" for key, value in sorted(requests.items())) or "absent"
    protocol = gdict(frozen, "protocol_file")
    results = gdict(frozen, "results_repository")
    code = gdict(frozen, "code")
    dirty = g(code, "working_tree_dirty")
    dirty_text = "uncommitted changes" if dirty is True else "clean tree" if dirty is False else "tree state absent"
    legit, attack, t3 = f["legit_t4"], f["attack_t4"], f["carriers_t3"]
    anchors_ok = f["anchors_all"] is True
    kpis = [
        ("Original T4 · legitimate", _tally_text(legit),
         f"{legit['distinct']} distinct texts" if isinstance(legit, dict) else "absent"),
        ("Original T4 · attacker", _tally_text(attack),
         f"{attack['distinct']} distinct texts" if isinstance(attack, dict) else "absent"),
        ("Original T3 · all carriers", _tally_text(t3),
         f"{t3['distinct']} distinct texts" if isinstance(t3, dict) else "absent"),
        ("Anchor checks", f"{fmt(f['anchors_passed'])} pass",
         f"{fmt(f['anchors_failed'])} fail" + ("" if anchors_ok else " · run not valid")),
    ]
    kpi_html = "".join(
        f"<div class='kpi'><div class='k'>{esc(label)}</div><div class='v'>{esc(value)}</div>"
        f"<div class='s'>{esc(sub)}</div></div>"
        for label, value, sub in kpis
    )
    badges = [
        ("Request-free", f"requests: {request_text}"),
        ("Encoder-free", "no semantic-encoder call; saved scores only"),
        ("Not pooled", "Case R scaffold scores and DeepSeek tables are never pooled"),
        ("Not a defence result", "nothing here measures model reliance, causal influence or a defence bypass"),
    ]
    badge_html = "".join(f"<li class='badge' title='{esc(title)}'>{esc(label)}</li>" for label, title in badges)
    warn = ""
    if not anchors_ok:
        warn = (
            "<p class='alert'>✕ Not every anchor check passed (or the anchor log is absent). "
            "The protocol says such a run fails; read nothing below as a result.</p>"
        )
    return (
        "<header class='wrap hero'>"
        "<div class='topbar'><p class='eyebrow'>Request-free evidence synthesis · "
        f"{esc(g(frozen, 'experiment_id'))}</p>"
        "<button id='theme-toggle' class='ghost' type='button'>Theme: auto</button></div>"
        f"<h1>{TITLE}</h1>"
        f"{warn}"
        f"<p class='lede'>{bottom_line(f)}</p>"
        f"<ul class='badges' aria-label='Boundary'>{badge_html}</ul>"
        f"<div class='kpis'>{kpi_html}</div>"
        "<dl class='prov'>"
        f"<div><dt>Protocol</dt><dd>{esc(g(frozen, 'protocol'))} · SHA-256 <code>{esc(g(protocol, 'sha256'))}</code>"
        f" · frozen {esc(g(protocol, 'frozen_at'))}</dd></div>"
        f"<div><dt>Inputs</dt><dd>agent-tracer-results <code>{esc(g(results, 'frozen_inputs_commit'))}</code>; "
        f"{esc(fmt(len(glist(frozen, 'inputs'))))} frozen inputs, SHA-256 verified before reading</dd></div>"
        f"<div><dt>Code</dt><dd>agent-tracer <code>{esc(g(code, 'head_commit'))}</code> ({esc(dirty_text)}; "
        "file digests in Section 6)</dd></div>"
        f"<div><dt>Question map</dt><dd>{question_note}</dd></div>"
        "</dl></header>"
    )


def _nav() -> str:
    items = [
        ("s-questions", "1 Questions"),
        ("s-ledger", "2 Ledger"),
        ("s-threshold", "3 Thresholds"),
        ("s-contrasts", "4 Contrasts"),
        ("s-deepseek", "5 DeepSeek"),
        ("s-checks", "6 Checks & method"),
    ]
    links = "".join(f"<li><a href='#{anchor}'>{label}</a></li>" for anchor, label in items)
    return f"<nav class='toc' aria-label='Sections'><div class='wrap'><ul>{links}</ul></div></nav>"


# --------------------------------------------------------------------------- 1 questions


def _question_note(question_map, question_bytes, frozen: dict) -> str:
    if question_bytes is None:
        return "absent: <code>config/question-map.json</code> was not found"
    digest = sha256_bytes(question_bytes)
    recorded = g(frozen, "question_map", "sha256")
    if recorded == digest:
        state = "matches the digest recorded in frozen-config"
    elif isinstance(recorded, str):
        state = "<b>differs from</b> the digest recorded in frozen-config"
    else:
        state = "no digest recorded in frozen-config"
    return f"hand-authored by the lead, rendered unchanged · SHA-256 <code>{esc(digest)}</code> ({state})"


def _status_chip(status) -> str:
    cls, icon, label = STATUS.get(status, ("st-unknown", "?", f"Unknown: {status}"))
    return f"<span class='chip {cls}'><span aria-hidden='true'>{icon}</span> {esc(label)}</span>"


_SECTION_REF = re.compile(r"\bSection (\d+)\b")


def section_reference_notes(ask: dict) -> list[str]:
    """Renderer notes for map text that sends a topic to the wrong section of this page (the map stays unchanged)."""
    notes: list[str] = []
    for key in ("ask", "have", "missing", "needs"):
        text = g(ask, key)
        if not isinstance(text, str):
            continue
        for part in re.split(r"(?<=[.;])\s+", text):
            for match in _SECTION_REF.finditer(part):
                number = int(match.group(1))
                for topic, actual in SECTION_TOPICS:
                    if topic in part and number != actual:
                        title = SECTION_TITLES.get(number, "not a section of this page")
                        note = (f"Renderer note: the {topic} tables are in Section {actual} of this page "
                                f"({SECTION_TITLES[actual]}); Section {number} is {title}. The map text is shown unchanged.")
                        if note not in notes:
                            notes.append(note)
    return notes


def _questions(question_map) -> str:
    intro = (
        "<p class='sec-lede'>The supervisors' asks from 26 and 28 September, with the lead's hand-authored status. "
        "This section is interpretation, not derived data; every other section is generated from the JSON.</p>"
    )
    if not isinstance(question_map, dict):
        return (
            f"<section id='s-questions' class='wrap'>{h2(1)}"
            f"{intro}<p class='alert'>The question map is absent, so there is nothing to show.</p></section>"
        )
    asks = [ask for ask in glist(question_map, "asks") if isinstance(ask, dict)]
    supervisors: list[str] = []
    for ask in asks:
        who = str(g(ask, "who")) if isinstance(g(ask, "who"), str) else "absent"
        name = who.split(",")[0].strip()
        if name not in supervisors:
            supervisors.append(name)
    counts: dict[str, int] = {}
    for ask in asks:
        status = g(ask, "status")
        key = status if isinstance(status, str) else "absent"
        counts[key] = counts.get(key, 0) + 1
    status_line = " · ".join(
        f"<span class='qstat' data-qstat='{esc(status)}'>{_status_chip(status)} <span class='qn'>{count}</span></span>"
        for status, count in sorted(
            counts.items(), key=lambda item: (list(STATUS).index(item[0]) if item[0] in STATUS else 9, item[0]))
    ) + f" <span class='qscope' data-total='{len(asks)}'>· all {len(asks)} asks</span>"
    filters = "<button type='button' class='fchip' data-qfilter='*' aria-pressed='true'>All</button>" + "".join(
        f"<button type='button' class='fchip' data-qfilter='{esc(name)}' aria-pressed='false'>{esc(name)}</button>"
        for name in supervisors
    )
    cards = []
    for ask in asks:
        who = g(ask, "who")
        name = str(who).split(",")[0].strip() if isinstance(who, str) else "absent"
        evidence = glist(ask, "evidence")
        evidence_html = " ".join(f"<code>{esc(item)}</code>" for item in evidence) or "<span class='absent'>none listed</span>"
        rows = "".join(
            f"<div><dt>{label}</dt><dd>{esc(g(ask, key))}</dd></div>"
            for label, key in (("Have", "have"), ("Missing", "missing"), ("Needs", "needs"))
        )
        status = g(ask, "status")
        notes = "".join(f"<p class='qnote'>{esc(note)}</p>" for note in section_reference_notes(ask))
        cards.append(
            f"<article class='qcard' data-who='{esc(name)}' "
            f"data-status='{esc(status if isinstance(status, str) else 'absent')}'>"
            f"<header><span class='qid'>{esc(g(ask, 'id'))}</span><span class='qwho'>{esc(who)}</span>"
            f"{_status_chip(status)}</header>"
            f"<p class='qask'>{esc(g(ask, 'ask'))}</p><dl class='qdl'>{rows}</dl>{notes}"
            f"<p class='qev'><span class='fine'>Evidence</span> {evidence_html}</p></article>"
        )
    status_legend = gdict(question_map, "status_legend")
    legend = "".join(
        f"<li>{_status_chip(status)} {esc(status_legend[status])}</li>"
        for status in ordered(list(status_legend), tuple(STATUS))
    )
    return (
        f"<section id='s-questions' class='wrap'>{h2(1)}"
        f"{intro}"
        f"<p class='qmeta'><span class='src-tag'>Hand-authored interpretation</span> authored {esc(g(question_map, 'authored'))}. "
        f"{esc(g(question_map, 'basis'))}</p>"
        f"<div class='filters' role='group' aria-label='Filter by supervisor'><span class='flabel'>Supervisor</span>{filters}"
        f"<span class='qcount fine'>{status_line}</span></div>"
        f"<div class='qgrid'>{''.join(cards)}</div>"
        f"<details class='more'><summary>Status legend</summary><ul class='plain'>{legend}</ul></details>"
        "</section>"
    )


# --------------------------------------------------------------------------- 2 ledger


def _strip_panel(rows: list[dict], stage: str, lo: float, hi: float, threshold) -> str:
    lanes = (
        ("legitimate_carrier", "Legitimate carriers", "legit"),
        ("attacker_carrier", "Attacker carriers", "attack"),
        ("noncarrier", "Noncarriers", "non"),
    )
    score_key = "score" if stage == "tier3" else "best_score"
    stage_name = "T3 whole-source cosine" if stage == "tier3" else "T4 best-chunk cosine"
    out = [f"<div class='strip' role='group' aria-label='{esc(STAGE_LABELS[stage])}'>"
           f"<h4 class='strip-h'>{esc(STAGE_LABELS[stage])}</h4>"]
    thr_left = pct(threshold, lo, hi) if is_num(threshold) else None
    for kind, label, cls in lanes:
        lane_rows = [row for row in rows if g(row, "relation_kind") == kind]
        tally = _tally(lane_rows, (kind,), stage)
        if isinstance(tally, dict):
            sub = f"{tally['distinct']} texts · {tally['total']} relations · {tally['hits']} matched"
        else:
            sub = "absent"
        scored = [(row, g(row, stage, score_key)) for row in lane_rows]
        plotted = [(row, score) for row, score in scored if is_num(score)]
        missing = len(scored) - len(plotted)
        positions = [pct(score, lo, hi) for _, score in plotted]
        slots = stack_slots(positions, 5.0)
        height = 22 + 14 * (max(slots) if slots else 0)
        marks = []
        if thr_left is not None:
            marks.append(f"<span class='zone' style='left:{thr_left:.3f}%'></span>")
            marks.append(f"<span class='thr' style='left:{thr_left:.3f}%'></span>")
        for (row, score), left, slot in zip(plotted, positions, slots):
            matched = g(row, stage, "matched")
            decision = "match" if matched is True else "no match" if matched is False else "decision absent"
            lines = [
                f"{fmt(score, 6)} · {stage_name}",
                f"{words(g(row, 'relation_kind'))} · target {g(row, 'target_text') if isinstance(g(row, 'target_text'), str) else 'absent'}",
                f"context {context_label(g(row, 'context'))} · ×{fmt(g(row, 'occurrences'))} relations",
                f"saved decision: {decision}",
            ]
            if stage == "tier4":
                lines.append(f"coverage {fmt(g(row, 'tier4', 'coverage'))}")
            aria = f"{label}: {fmt(score, 4)}, {decision}, {fmt(g(row, 'occurrences'))} relations"
            marks.append(
                f"<span class='dot {cls}' style='left:{left:.3f}%;top:{11 + 14 * slot}px' tabindex='0' "
                f"role='img' aria-label='{esc(aria)}' data-tip='{tip_attr(lines)}'></span>"
            )
        note = f"<span class='fine'> · {missing} score absent</span>" if missing else ""
        out.append(
            f"<div class='lane'><div class='lane-l'><span class='sw {cls}'></span><span><b>{label}</b>"
            f"<br><span class='fine'>{esc(sub)}</span>{note}</span></div>"
            f"<div class='track' style='height:{height}px'>{''.join(marks)}</div></div>"
        )
    ticks = nice_ticks(lo, hi, 0.1)
    labels = []
    for index, tick in enumerate(ticks):
        if is_num(threshold) and abs(tick - threshold) < 0.03:
            continue
        cls = "first" if index == 0 else "last" if index == len(ticks) - 1 else ("minor" if index % 2 else "")
        labels.append(f"<span class='tick {cls}' style='left:{pct(tick, lo, hi):.3f}%'>{fmt(tick, 1)}</span>")
    if thr_left is not None:
        labels.append(f"<span class='tick thr-l' style='left:{thr_left:.3f}%'>{fmt(threshold, 2)}</span>")
    out.append(f"<div class='lane axis'><div></div><div class='axis-x'>{''.join(labels)}</div></div></div>")
    return "".join(out)


def score_scale(rows: list[dict]) -> float:
    """Upper end of the score axis: at least 0.8, rounded up to cover every plotted score."""
    scores = [g(row, "tier3", "score") for row in rows] + [g(row, "tier4", "best_score") for row in rows]
    top = max([s for s in scores if is_num(s)], default=0.8)
    return min(1.0, max(0.8, math.ceil(top * 10 - 1e-9) / 10))


def _strip_chart(documents: dict) -> str:
    rows = _original_rows(documents)
    thresholds = gdict(documents, "frozen_config", "thresholds")
    hi = score_scale(rows)
    t3 = g(thresholds, "tier3")
    t4 = g(thresholds, "tier4")
    coverage = g(thresholds, "tier4_coverage")
    table_rows = []
    for row in rows:
        table_rows.append([
            esc(words(g(row, "relation_kind"))),
            f"<code class='sv'>{esc(g(row, 'target_text'))}</code>",
            esc(context_label(g(row, "context"))),
            num_h(g(row, "occurrences")),
            num_h(g(row, "tier3", "score"), 6),
            num_h(g(row, "tier4", "best_score"), 6),
            num_h(g(row, "tier4", "coverage"), 6),
            esc(yes_no(g(row, "tier4", "matched"))),
        ])
    table = table_h(
        ["Relation", "Target", "Context", "Relations", "T3", "T4 best chunk", "T4 coverage", "T4 match"],
        table_rows, cls="num-table",
    )
    return (
        "<figure class='chart' aria-labelledby='strip-cap'>"
        "<div class='legend'><span><span class='sw legit'></span>Legitimate-recipient carrier</span>"
        "<span><span class='sw attack'></span>Attacker-recipient carrier</span>"
        "<span><span class='sw non hollow'></span>Noncarrier (target absent)</span>"
        f"<span><span class='sw-line'></span>{esc(fmt(t4, 2))} threshold (frozen)</span></div>"
        f"{_strip_panel(rows, 'tier3', 0.0, hi, t3)}{_strip_panel(rows, 'tier4', 0.0, hi, t4)}"
        f"<figcaption id='strip-cap'>One dot per distinct scored (text, target) pair; relation counts are in the lane "
        f"labels and tooltips. Tier 4 also needs whole-source coverage ≥ {esc(fmt(coverage, 2))}; the shaded "
        "side of each track is at or above the frozen threshold. Saved decisions only; nothing is re-thresholded."
        "</figcaption>"
        f"<details class='more'><summary>Table view (original Case R, {len(rows)} distinct texts)</summary>{table}</details>"
        "</figure>"
    )


def _chunk_payload(chunk):
    if not isinstance(chunk, dict):
        return None
    out = {}
    for key, name in (("index", "i"), ("score", "s"), ("text", "x"), ("contains_complete_target", "t"),
                      ("matched", "m"), ("codepoints", "cp"), ("contains_transformed_cue", "cue")):
        if key in chunk:
            out[name] = chunk[key]
    return out


def _ledger_payload(rows: list[dict]) -> list[dict]:
    payload = []
    for row in rows:
        t4 = gdict(row, "tier4")
        item = {
            "id": g(row, "row_id") if isinstance(g(row, "row_id"), str) else None,
            "target": g(row, "target_text") if isinstance(g(row, "target_text"), str) else "",
            "best": _chunk_payload(t4.get("best_chunk")),
            "tgt": _chunk_payload(t4.get("best_target_containing_chunk")),
            "chunks": [
                [g(c, "index"), g(c, "score"), g(c, "contains_complete_target"), g(c, "matched"), g(c, "codepoints")]
                for c in glist(row, "chunk_scores") if isinstance(c, dict)
            ],
            "same": [str(item) for item in glist(row, "identical_scored_pair_rows")],
        }
        for key, name in (("coverage", "cov"), ("coverage_numerator_codepoints", "num"),
                          ("coverage_denominator_codepoints", "den"), ("chunk_count", "n")):
            if key in t4:
                item[name] = t4[key]
        for key, name in (("source_unit", "unit"), ("source_unit_basis", "basis"), ("source_text_sha256", "src"),
                          ("source_codepoints", "srccp"), ("occurrences", "occ"), ("scored_instances", "inst"),
                          ("occurrence_score_spread", "spread"), ("carrier_label", "label"),
                          ("tier2_saved_matched", "t2")):
            if key in row:
                item[name] = row[key]
        literal = g(row, "exact_substring", "literal_occurrences")
        if literal is not ABSENT:
            item["lit"] = literal
        localized = g(row, "localized_tier4")
        if isinstance(localized, dict):
            item["loc"] = {
                name: localized[key]
                for key, name in (("best_score", "s"), ("matched", "m"), ("best_chunk_index", "i"),
                                  ("best_chunk_codepoints", "cp"), ("best_chunk_text", "x"), ("score_name", "name"))
                if key in localized
            }
        cue = _chunk_payload(g(row, "transformed_cue_chunk"))
        if cue is not None:
            item["cue"] = cue
        if "replay_vs_original" in row:  # probe rows; null means no original row with the same text and target
            replay = row["replay_vs_original"]
            item["replay"] = {
                "original": replay.get("original_row_id"),
                "bitwise": replay.get("bitwise_identical_scores"),
                "decisions": replay.get("decisions_identical"),
            } if isinstance(replay, dict) else None
        payload.append(item)
    return payload


def _sorted_ledger_rows(documents: dict) -> list[dict]:
    rows = [row for row in glist(documents, "ledger", "rows") if isinstance(row, dict)]
    rank = {design: index for index, design in enumerate(synthesis.DESIGNS)}
    return [row for _, row in sorted(enumerate(rows), key=lambda item: (rank.get(g(item[1], "design"), 99), item[0]))]


def _decision_h(value) -> str:
    if value is True:
        return "<span class='dc hit'>match</span>"
    if value is False:
        return "<span class='dc miss'>no</span>"
    return num_h(value)


def _kind_swatch(row: dict) -> str:
    label = g(row, "carrier_label")
    role = g(row, "value_role")
    if label == "noncarrier":
        return "<span class='sw non hollow'></span>"
    if label == "transformed_cue_carrier":
        return f"<span class='sw {role_class(role)} hollow'></span>"
    return f"<span class='sw {role_class(role)}'></span>"


def _ledger_table(rows: list[dict]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        design = g(row, "design")
        key = design if isinstance(design, str) else "absent"
        counts[key] = counts.get(key, 0) + 1
    filters = [f"<button type='button' class='fchip' data-dfilter='*' aria-pressed='true'>All ({len(rows)})</button>"]
    filters += [
        f"<button type='button' class='fchip' data-dfilter='{esc(design)}' aria-pressed='false'>"
        f"{esc(design_label(design))} ({count})</button>"
        for design, count in counts.items()
    ]
    body = []
    for index, row in enumerate(rows):
        design = g(row, "design")
        t4 = gdict(row, "tier4")
        target_chunk = t4.get("best_target_containing_chunk", ABSENT)
        if target_chunk is None:
            target_cell = "<span class='na' title='no chunk contains the complete target'>none</span>"
        else:
            target_cell = num_h(g(target_chunk, "score"))
        winner = esc(yes_no(g(t4, "best_chunk", "contains_complete_target")))
        localized = g(row, "localized_tier4")
        if isinstance(localized, dict):
            local_cell = f"{num_h(g(localized, 'best_score'))} {_decision_h(g(localized, 'matched'))}"
        elif localized is None:
            local_cell = "<span class='na'>—</span>"
        else:
            local_cell = num_h(localized)
        block = g(row, "block")
        block_text = "" if block is None else f" · block {esc(block)}"
        unit_class = g(row, "source_unit_class")
        body.append(
            f"<tr class='lrow' data-design='{esc(design)}'>"
            f"<td><span class='dname'>{esc(design_label(design))}</span><br>"
            f"<button type='button' class='ghost xbtn' data-expand='{index}' aria-expanded='false' "
            f"aria-controls='ld-{index}'>Chunks</button></td>"
            f"<td>{_kind_swatch(row)}{esc(words(g(row, 'relation_kind')))}"
            f"<br><span class='fine'>{esc(words(g(row, 'value_role')))} · {esc(context_label(g(row, 'context')))}"
            f"{block_text} · ×{num_h(g(row, 'occurrences'))}</span></td>"
            f"<td><code class='sv'>{esc(g(row, 'target_text'))}</code></td>"
            f"<td class='n'>{num_h(g(row, 'tier3', 'score'))} {_decision_h(g(row, 'tier3', 'matched'))}</td>"
            f"<td class='n'>{num_h(g(t4, 'best_score'))} {_decision_h(g(t4, 'matched'))}"
            f"<br><span class='fine'>coverage {num_h(g(t4, 'coverage'))}</span></td>"
            f"<td class='n'>{target_cell}<br><span class='fine'>winner has target: {winner}</span></td>"
            f"<td class='n'>{local_cell}</td>"
            f"<td>{esc(words(unit_class))}<br>{basis_h(g(row, 'source_unit_basis'))}</td></tr>"
            f"<tr class='ldetail' id='ld-{index}' data-design='{esc(design)}' hidden><td colspan='8'>"
            "<div class='ldbody'></div></td></tr>"
        )
    headers = ["Design", "Relation · role · context · ×relations", "Target", "T3", "T4 best · coverage",
               "Best target chunk", "Localized T4", "Source unit"]
    head = "".join(f"<th scope='col'>{header}</th>" for header in headers)
    return (
        f"<div class='filters' role='group' aria-label='Filter ledger by design'><span class='flabel'>Design</span>"
        f"{''.join(filters)}</div>"
        "<p class='fine' id='ledger-count' aria-live='polite'></p>"
        f"<div class='tscroll ledger'><table class='num-table'><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>"
        "<noscript><p class='fine'>Every row-level score is in the table; per-chunk scores and chunk texts need "
        "JavaScript.</p></noscript>"
    )


def _ledger(documents: dict) -> tuple[str, dict]:
    ledger = gdict(documents, "ledger")
    rows = _sorted_ledger_rows(documents)
    cross = gdict(ledger, "cross_checks", "original")
    delta = gdict(cross, "tier_diagnostic_max_abs_delta")
    cross_line = (
        f"Values shown for the original rows come from {esc(g(cross, 'ledger_source_for_original_rows'))}. "
        f"They are re-checked against the tier diagnostic ({esc(fmt(g(cross, 'tier_diagnostic_decisions_equal')))}/"
        f"{esc(fmt(g(cross, 'tier_diagnostic_relations_compared')))} decisions equal, max |Δ| T3 "
        f"{esc(fmt(g(delta, 'tier3_score'), 9))}, T4 {esc(fmt(g(delta, 'tier4_best_score'), 9))}) and against the "
        f"asymmetry audit ({esc(fmt(g(cross, 'asymmetry_audit_unique_pairs_compared')))} unique pairs, max |Δ| "
        f"{esc(fmt(g(cross, 'asymmetry_audit_max_abs_delta'), 9))}); tolerance {esc(fmt(g(cross, 'tolerance'), 6))}."
    )
    html_text = (
        f"<section id='s-ledger' class='wrap'>{h2(2)}"
        "<p class='sec-lede'>The original Case R split, then every design's rows with the winning chunk and the "
        "best chunk that contains the complete target. Rows are distinct scored (text, target) pairs; repeated "
        "identical text is one row with its relation count (×), never extra replicates. A row's "
        "<b>Chunks</b> button opens every chunk score and the saved chunk texts.</p>"
        "<h3>Original Case R, per distinct text</h3>"
        f"{_strip_chart(documents)}"
        f"<p class='fine'>{cross_line}</p>"
        f"<h3>All designs ({esc(fmt(g(ledger, 'row_count')))} rows)</h3>"
        "<p class='fine'><span class='ut-tag'>Saved text · untrusted data</span> Targets and chunk texts are "
        "experiment data shown verbatim; they are escaped and never interpreted. The target is "
        "<mark class='tg'>highlighted</mark> by splitting text, not by markup.</p>"
        f"{_ledger_table(rows)}"
        "</section>"
    )
    threshold = g(documents, "frozen_config", "thresholds", "tier4")
    data = {
        "rows": _ledger_payload(rows),
        "threshold": threshold if is_num(threshold) else None,
        "scale": score_scale(rows),
    }
    return html_text, data


# --------------------------------------------------------------------------- 3 thresholds


def _sweep_data(view: dict) -> dict:
    grid = gdict(view, "grid")
    rows = [row for row in glist(view, "sweep", "rows") if isinstance(row, dict)]
    stages: dict = {}
    for stage in SWEEP_STAGES:
        stage_data: dict = {}
        for mode, field in (("distinct", "distinct_texts"), ("relations", "relations")):
            stage_data[mode] = {
                series: [ratio_cell_text(g(row, stage, series, field)) for row in rows]
                for series, _, _ in SWEEP_SERIES
            }
        stages[stage] = stage_data
    intervals = {}
    for stage in SWEEP_STAGES:
        by_pair = gdict(view, "separating_intervals", "by_stage", stage)
        intervals[stage] = {
            pair: {
                "exists": g(item, "exists"),
                "lo": g(item, "lower_exclusive") if is_num(g(item, "lower_exclusive")) else None,
                "hi": g(item, "upper_inclusive") if is_num(g(item, "upper_inclusive")) else None,
                "n": len(glist(item, "grid_thresholds")),
                "first": g(item, "grid_first") if is_num(g(item, "grid_first")) else None,
                "last": g(item, "grid_last") if is_num(g(item, "grid_last")) else None,
            }
            for pair, item in by_pair.items() if isinstance(item, dict)
        }
    thresholds = gdict(view, "frozen_point")
    return {
        "frozen": {
            "tier3": g(thresholds, "tier3_threshold") if is_num(g(thresholds, "tier3_threshold")) else None,
            "tier4": g(thresholds, "tier4_threshold") if is_num(g(thresholds, "tier4_threshold")) else None,
        },
        "grid": [g(row, "threshold") for row in rows],
        "lo": g(grid, "start") if is_num(g(grid, "start")) else None,
        "hi": g(grid, "stop") if is_num(g(grid, "stop")) else None,
        "stages": stages,
        "intervals": intervals,
        "pairs": {pair: PAIR_LABELS.get(pair, words(pair)) for stage in intervals for pair in intervals[stage]},
    }


def _step_path(points: list[tuple[float, float]]) -> str:
    if not points:
        return ""
    parts = [f"M{points[0][0]:.2f} {points[0][1]:.2f}"]
    for x, y in points[1:]:
        parts.append(f"H{x:.2f}V{y:.2f}")
    return "".join(parts)


STAGE_NOTE_PREFIX = {"tier4_coverage_on": "Coverage rule on · ", "tier4_coverage_off": "Coverage rule off · "}


def _interval_note(item) -> str:
    if not isinstance(item, dict):
        return "Interval field absent."
    if item.get("exists") is not True:
        return "No threshold separates these groups at this stage."
    first, last = item.get("grid_first"), item.get("grid_last")
    return (
        f"Separating interval ({fmt(item.get('lower_exclusive'), 6)}, {fmt(item.get('upper_inclusive'), 6)}]; "
        f"{plural(len(item.get('grid_thresholds') or []), 'grid point')} ({fmt(first, 3)}–{fmt(last, 3)})."
    )


def _posthoc_h(view: dict, part: str) -> str:
    """One-line caveat for one part of the threshold view; the part's full JSON caveat is the tooltip."""
    population = gdict(view, "population")
    full = g(view, part, "caveat")
    text = posthoc_text(g(population, "distinct_legitimate_carrier_texts"), g(population, "distinct_attacker_carrier_texts"))
    title = f" title='{esc(full)}'" if isinstance(full, str) else ""
    return f"<p class='pcav'{title}><span class='pcav-k'>Exploratory</span> {esc(text)}.</p>"


def _sweep_panel(view: dict, stage_key: str, title: str, frozen_threshold) -> str:
    grid = gdict(view, "grid")
    lo, hi = g(grid, "start"), g(grid, "stop")
    if not (is_num(lo) and is_num(hi) and hi > lo):
        return f"<p class='absent'>Sweep grid absent for {esc(title)}.</p>"
    rows = [row for row in glist(view, "sweep", "rows") if isinstance(row, dict)]
    width, top, bottom = 1000.0, 10.0, 290.0

    def x_of(t: float) -> float:
        return (t - lo) / (hi - lo) * width

    def y_of(rate: float) -> float:
        return bottom - rate * (bottom - top)

    svg = ["<svg viewBox='0 0 1000 300' preserveAspectRatio='none' aria-hidden='true' focusable='false'>"]
    carets: list[str] = []
    for rate in (0.0, 0.25, 0.5, 0.75, 1.0):
        svg.append(f"<line class='gl' x1='0' x2='1000' y1='{y_of(rate):.2f}' y2='{y_of(rate):.2f}' "
                   "vector-effect='non-scaling-stroke'/>")
    stages = ("tier4_coverage_on", "tier4_coverage_off") if stage_key == "tier4" else ("tier3",)
    for stage in stages:
        cov_cls = {"tier4_coverage_on": " c-on", "tier4_coverage_off": " c-off"}.get(stage, "")
        by_pair = gdict(view, "separating_intervals", "by_stage", stage)
        for pair in ordered(list(by_pair), tuple(PAIR_LABELS)):
            item = by_pair[pair]
            if not isinstance(item, dict) or item.get("exists") is not True:
                continue
            low, high = item.get("lower_exclusive"), item.get("upper_inclusive")
            if not (is_num(low) and is_num(high)):
                continue
            x1, x2 = x_of(max(lo, low)), x_of(min(hi, high))
            if x2 <= x1:
                continue
            hidden = "" if pair == DEFAULT_PAIR else " style='display:none'"
            svg.append(f"<rect class='band{cov_cls}' data-iv='{esc(pair)}' x='{x1:.2f}' y='0' "
                       f"width='{x2 - x1:.2f}' height='300'{hidden}/>")
            for edge in (x1, x2):  # solid edges keep a one-grid-point interval visible at any width
                svg.append(f"<line class='band-edge{cov_cls}' data-iv='{esc(pair)}' x1='{edge:.2f}' x2='{edge:.2f}' "
                           f"y1='0' y2='300' vector-effect='non-scaling-stroke'{hidden}/>")
            carets.append(
                f"<span class='ivcaret{cov_cls}' data-iv='{esc(pair)}' style='left:{(x1 + x2) / 20:.3f}%"
                f"{';display:none' if hidden else ''}' aria-hidden='true'>▼</span>"
            )
    if is_num(frozen_threshold) and lo <= frozen_threshold <= hi:
        x = x_of(frozen_threshold)
        svg.append(f"<line class='frz' x1='{x:.2f}' x2='{x:.2f}' y1='0' y2='300' vector-effect='non-scaling-stroke'/>")
    offsets = {"legitimate": 0.0, "attacker": 4.0, "noncarrier": -4.0}
    for stage in stages:
        cov_cls = {"tier4_coverage_on": " c-on", "tier4_coverage_off": " c-off"}.get(stage, "")
        for mode, field in (("distinct", "distinct_texts"), ("relations", "relations")):
            for series, cls, _ in SWEEP_SERIES:
                points = []
                for row in rows:
                    t, rate = g(row, "threshold"), g(row, stage, series, field, "rate")
                    if is_num(t) and is_num(rate):
                        points.append((x_of(t), y_of(rate) + offsets[series]))
                svg.append(f"<path class='ser {cls} m-{mode}{cov_cls}' d='{_step_path(points)}' "
                           "vector-effect='non-scaling-stroke'/>")
    svg.append("</svg>")
    y_labels = "".join(
        f"<span style='top:{y_of(rate) / 3:.3f}%'>{int(rate * 100)}%</span>" for rate in (0.0, 0.25, 0.5, 0.75, 1.0)
    )
    ticks = nice_ticks(lo, hi, 0.05)
    x_labels = []
    for index, tick in enumerate(ticks):
        minor = index % 2 == 1 or index == len(ticks) - 2
        cls = "first" if index == 0 else "last" if index == len(ticks) - 1 else ("minor" if minor else "")
        x_labels.append(f"<span class='tick {cls}' style='left:{pct(tick, lo, hi):.3f}%'>{fmt(tick, 2)}</span>")
    frozen_label = ""
    if is_num(frozen_threshold) and lo <= frozen_threshold <= hi:
        frozen_label = (f"<span class='vlab' style='left:{pct(frozen_threshold, lo, hi):.3f}%'>"
                        f"{fmt(frozen_threshold, 2)} frozen</span>")
    notes = []
    for stage in stages:
        cov_cls = {"tier4_coverage_on": " c-on", "tier4_coverage_off": " c-off"}.get(stage, "")
        item = g(view, "separating_intervals", "by_stage", stage, DEFAULT_PAIR)
        notes.append(f"<p class='ivnote fine{cov_cls}' data-ivnote='{esc(stage)}'>"
                     f"<span class='sw band-sw'></span>{esc(STAGE_NOTE_PREFIX.get(stage, ''))}"
                     f"{esc(PAIR_LABELS[DEFAULT_PAIR])}: {esc(_interval_note(item))}</p>")
    return (
        f"<figure class='lcw'><h4>{esc(title)}</h4>{_posthoc_h(view, 'sweep')}"
        f"<div class='lc'><div class='lc-y' aria-hidden='true'>{y_labels}</div>"
        f"<div class='lc-plot' tabindex='0' data-plot='{esc(stage_key)}' role='img' "
        f"aria-label='{esc(title)}: share of each group matched at each threshold; post hoc, not an operating point; "
        "use arrow keys to step'>"
        f"{''.join(svg)}{''.join(carets)}{frozen_label}<div class='xh' hidden></div></div>"
        f"<div></div><div class='lc-x' aria-hidden='true'>{''.join(x_labels)}</div></div>"
        f"{''.join(notes)}</figure>"
    )


def _threshold(documents: dict) -> tuple[str, dict]:
    view = gdict(documents, "threshold_sensitivity")
    caveat = g(view, "caveat")
    thresholds = gdict(documents, "frozen_config", "thresholds")
    population = gdict(view, "population")
    effect = gdict(view, "coverage_rule", "effect_of_coverage_rule_on_grid")
    data = _sweep_data(view)
    pairs = data["pairs"]
    pair_order = ordered(list(pairs), tuple(PAIR_LABELS))
    options = "".join(
        f"<option value='{esc(pair)}'{' selected' if pair == DEFAULT_PAIR else ''}>{esc(pairs[pair])}</option>"
        for pair in pair_order
    )
    legend = (
        "<div class='legend'>"
        + "".join(f"<span><span class='lk {cls}'></span>{esc(label)}</span>" for _, cls, label in SWEEP_SERIES)
        + "<span><span class='sw band-sw'></span>Selected separating interval</span>"
        "<span><span class='sw-line'></span>Frozen threshold</span></div>"
    )
    controls = (
        "<div class='filters' role='group' aria-label='Threshold view controls'>"
        "<span class='fgroup'><span class='flabel'>Count</span>"
        "<button type='button' class='fchip' data-mode-set='distinct' aria-pressed='true'>Distinct texts</button>"
        "<button type='button' class='fchip' data-mode-set='relations' aria-pressed='false'>Relations</button></span>"
        "<span class='fgroup'><span class='flabel'>T4 coverage rule</span>"
        "<button type='button' class='fchip' data-cov-set='on' aria-pressed='true'>On</button>"
        "<button type='button' class='fchip' data-cov-set='off' aria-pressed='false'>Off</button></span>"
        f"<span class='fgroup'><label class='flabel' for='iv-select'>Shade</label><select id='iv-select'>{options}"
        "</select></span></div>"
    )
    interval_rows = []
    for stage in SWEEP_STAGES:
        by_pair = gdict(view, "separating_intervals", "by_stage", stage)
        for pair in ordered(list(by_pair), tuple(PAIR_LABELS)):
            item = by_pair[pair]
            interval_rows.append([
                esc(words(stage)), esc(PAIR_LABELS.get(pair, words(pair))), esc(yes_no(g(item, "exists"))),
                num_h(g(item, "lower_exclusive"), 6), num_h(g(item, "upper_inclusive"), 6),
                esc(fmt(len(glist(item, "grid_thresholds")))),
            ])
    critical_rows = [
        [
            esc(words(g(row, "relation_kind"))), num_h(g(row, "occurrences")), num_h(g(row, "tier3"), 6),
            num_h(g(row, "tier4_coverage_on"), 6), num_h(g(row, "tier4_coverage_off"), 6),
            f"<code class='mono-s'>{esc(g(row, 'row_id'))}</code>",
        ]
        for row in glist(view, "critical_thresholds", "rows") if isinstance(row, dict)
    ]
    sweep_rows = []
    for index, t in enumerate(data["grid"]):
        cells = [esc(fmt(t, 3))]
        for stage in ("tier3", "tier4_coverage_on"):
            for series, _, _ in SWEEP_SERIES:
                distinct = data["stages"][stage]["distinct"][series][index]
                relations = data["stages"][stage]["relations"][series][index]
                cells.append(f"{esc(distinct)} <span class='fine'>({esc(relations)})</span>")
        sweep_rows.append(cells)
    text = (
        f"<section id='s-threshold' class='wrap'>{h2(3)}"
        f"<p class='banner'><b>Exploratory · post hoc.</b> {esc(caveat)}</p>"
        "<p class='sec-lede'>Share of each group that would match if the threshold moved, over the "
        f"{esc(fmt(g(population, 'relations')))} original relations. Hover or focus a chart and use the arrow keys "
        "to read every series at one threshold.</p>"
        f"<div id='thr' data-mode='distinct' data-cov='on' data-pair='{DEFAULT_PAIR}'>{controls}{legend}"
        "<div class='lcgrid'>"
        f"{_sweep_panel(view, 'tier3', 'Tier 3 · whole-source cosine', g(thresholds, 'tier3'))}"
        f"{_sweep_panel(view, 'tier4', 'Tier 4 · best-chunk cosine', g(thresholds, 'tier4'))}"
        "</div></div>"
        f"<p class='fine'>The coverage rule ({esc(fmt(g(view, 'coverage_rule', 'on', 'coverage_threshold'), 2))}) "
        f"changes {esc(fmt(g(effect, 'changed_decisions')))} decisions on this grid. Where series coincide, lines "
        "are offset by a few pixels so each stays visible. Population: "
        f"{esc(fmt(g(population, 'distinct_legitimate_carrier_texts')))} legitimate, "
        f"{esc(fmt(g(population, 'distinct_attacker_carrier_texts')))} attacker and "
        f"{esc(fmt(g(population, 'distinct_noncarrier_texts')))} noncarrier distinct texts "
        f"({esc(fmt(g(population, 'legitimate_carrier_relations')))}, "
        f"{esc(fmt(g(population, 'attacker_carrier_relations')))} and "
        f"{esc(fmt(g(population, 'noncarrier_relations')))} relations).</p>"
        "<details class='more'><summary>Every separating interval</summary>"
        f"{_posthoc_h(view, 'separating_intervals')}"
        "<p class='fine'>“A over B”: every A text matches and no B text matches. Intervals are open below "
        "and closed above.</p>"
        + table_h(["Stage", "Groups", "Exists", "Lower (exclusive)", "Upper (inclusive)", "Grid points"],
                  interval_rows, cls="num-table")
        + "</details>"
        "<details class='more'><summary>Critical threshold of each distinct text</summary>"
        f"{_posthoc_h(view, 'critical_thresholds')}"
        f"<p class='fine'>{esc(g(view, 'critical_thresholds', 'definition'))}</p>"
        + table_h(["Relation", "Relations", "T3", "T4 coverage on", "T4 coverage off", "Row"], critical_rows,
                  cls="num-table")
        + "</details>"
        f"<details class='more'><summary>Table view ({len(data['grid'])} grid points; distinct texts, relations in "
        "brackets)</summary>"
        + _posthoc_h(view, "sweep")
        + table_h(["Threshold", "T3 legit", "T3 attacker", "T3 noncarrier", "T4 legit", "T4 attacker",
                   "T4 noncarrier"], sweep_rows, cls="num-table")
        + "</details></section>"
    )
    return text, data


# --------------------------------------------------------------------------- 4 contrasts


def _stats_values(stats) -> tuple:
    """(centre value, distinct values, display) for a stats dict or a plain number."""
    if is_num(stats):
        return stats, [], None
    if isinstance(stats, dict):
        values = [value for value in stats.get("values", []) if is_num(value)]
        return stats.get("median", ABSENT), values if len(values) > 1 else [], stats.get("display")
    return ABSENT, [], None


def _value_prefix(entry: dict) -> str:
    roles = set(gdict(entry, "design_features", "value_codepoint_lengths"))
    if {"legitimate", "attacker"} <= roles:
        return "L−A"
    if {"neutral_alpha", "neutral_bravo"} <= roles:
        return "α−β"
    return "A−B"


def _contrast_rows(entry: dict) -> list[tuple[str, object, str]]:
    """(label, stats-or-number, kind) rows of one design's primary contrasts."""
    design = g(entry, "design")
    prefix = _value_prefix(entry)
    summary = g(entry, "summary")
    rows: list[tuple[str, object, str]] = []
    if design == "crossover_generality" and isinstance(summary, dict):
        rows.append(("A−B · reference wording", summary.get("value_contrast_reference_context", ABSENT), "value"))
        rows.append(("A−B · altered wording", summary.get("value_contrast_altered_context", ABSENT), "value"))
        rows.append(("Reference − altered · all cells", summary.get("context_contrast_all_cells", ABSENT), "context"))
        rows.append(("Interaction", summary.get("interaction", ABSENT), "interaction"))
        return rows
    source = summary if isinstance(summary, dict) and isinstance(summary.get("value_contrast"), dict) else g(entry, "blocks", 0)
    if not isinstance(source, dict):
        return [("Contrasts", ABSENT, "value")]
    value = source.get("value_contrast", ABSENT)
    if isinstance(value, dict):
        for context in ordered(list(value), CONTEXT_ORDER):
            rows.append((f"{prefix} · {words(context)}", value[context], "value"))
    else:
        rows.append((prefix, value, "value"))
    context_contrast = source.get("context_contrast", ABSENT)
    if isinstance(context_contrast, dict):
        for role in ordered(list(context_contrast), ROLE_ORDER):
            rows.append((f"N−M · {words(role)}", context_contrast[role], "context"))
    interaction = source.get("interaction", ABSENT)
    if interaction is not None:
        rows.append(("Interaction", interaction, "interaction"))
    return rows


def _supplementary_rows(entry: dict) -> list[tuple[str, object, str]]:
    supplementary = g(entry, "supplementary_not_protocol_primary")
    if not isinstance(supplementary, dict):
        return []
    rows: list[tuple[str, object, str]] = []
    value = supplementary.get("value_contrast", ABSENT)
    if isinstance(value, dict):
        for context in ordered(list(value), CONTEXT_ORDER):
            rows.append((f"L−A · {words(context)}", value[context], "value"))
    elif value is not ABSENT:
        rows.append(("L−A", value, "value"))
    context_contrast = supplementary.get("context_contrast")
    if isinstance(context_contrast, dict):
        for role in ordered(list(context_contrast), ROLE_ORDER):
            rows.append((f"N−M · {words(role)}", context_contrast[role], "context"))
    if is_num(supplementary.get("interaction")):
        rows.append(("Interaction", supplementary["interaction"], "interaction"))
    return rows


def _contrast_domain(entries: list[dict]) -> float:
    values: list[float] = []
    for entry in entries:
        for _, stats, _ in _contrast_rows(entry) + _supplementary_rows(entry):
            centre, points, _ = _stats_values(stats)
            values += [v for v in [centre, *points] if is_num(v)]
    top = max((abs(v) for v in values), default=0.05)
    return max(0.05, math.ceil(top / 0.05 - 1e-9) * 0.05)


def _contrast_row_h(label: str, stats, kind: str, domain: float, score_used, secondary: bool = False) -> str:
    centre, points, display = _stats_values(stats)
    cls = "crow sec" if secondary else "crow"
    if not is_num(centre):
        return (f"<div class='{cls}'><div class='cl'>{esc(label)}</div><div class='ctrack'></div>"
                f"<div class='cv'>{num_h(centre)}</div></div>")
    zero = 50.0
    left = pct(centre, -domain, domain)
    stem_left, stem_width = min(zero, left), abs(left - zero)
    lines = [f"{sfmt(centre, 6)} · {label}", f"score: {score_used if isinstance(score_used, str) else 'absent'}"]
    if points:
        lines.append("distinct blocks: " + ", ".join(sfmt(point, 6) for point in points))
        lines[0] = f"median {lines[0]}"
    if isinstance(display, str):
        lines.append(display)
    marks = [f"<span class='zero'></span><span class='stem {kind}' style='left:{stem_left:.3f}%;width:{stem_width:.3f}%'></span>"]
    for point in points:
        marks.append(f"<span class='bdot' style='left:{pct(point, -domain, domain):.3f}%'></span>")
    marks.append(
        f"<span class='cdot {kind}' style='left:{left:.3f}%' tabindex='0' role='img' "
        f"aria-label='{esc(label)}: {esc(sfmt(centre, 4))}' data-tip='{tip_attr(lines)}'></span>"
    )
    blocks = stats.get("distinct_blocks") if isinstance(stats, dict) else None
    sub_text = ""
    if is_int(blocks) and blocks > 1 and is_int(stats.get("positive_blocks")) and is_int(stats.get("negative_blocks")):
        sub_text = f"median of {blocks}: {stats['positive_blocks']}+ {stats['negative_blocks']}−"
    elif points:
        sub_text = f"median of {len(points)}"
    sub_html = f"<br><span class='fine'>{esc(sub_text)}</span>" if sub_text else ""
    return (
        f"<div class='{cls}'><div class='cl'>{esc(label)}</div><div class='ctrack'>{''.join(marks)}</div>"
        f"<div class='cv'><b>{esc(sfmt(centre, 4))}</b>{sub_html}</div></div>"
    )


def _contrast_card(entry: dict, domain: float) -> str:
    design = g(entry, "design")
    score_used = g(entry, "score_used")
    summary = gdict(entry, "summary")
    meta = []
    if isinstance(g(entry, "value_definition"), str):
        meta.append(f"value: {esc(g(entry, 'value_definition'))}")
    if isinstance(g(entry, "context_definition"), str):
        meta.append(f"context: {esc(g(entry, 'context_definition'))}")
    blocks = summary.get("distinct_blocks", ABSENT)
    occurrences = summary.get("block_occurrences", ABSENT)
    if blocks is not ABSENT:
        meta.append(f"{esc(fmt(blocks))} distinct block(s)"
                    + (f", {esc(fmt(occurrences))} saved" if occurrences is not ABSENT else ""))
    body = "".join(_contrast_row_h(label, stats, kind, domain, score_used) for label, stats, kind in _contrast_rows(entry))
    supplementary = g(entry, "supplementary_not_protocol_primary")
    extra = ""
    if isinstance(supplementary, dict):
        rows = _supplementary_rows(entry)
        if rows:
            extra = (
                f"<p class='supp-h fine'>Supplementary, not protocol-primary · score "
                f"<code>{esc(supplementary.get('score_used'))}</code></p>"
                + "".join(_contrast_row_h(label, stats, kind, domain, supplementary.get("score_used"), True)
                          for label, stats, kind in rows)
            )
        matched = supplementary.get("tier3_matched_cells")
        if isinstance(matched, dict):
            extra += f"<p class='fine'>T3 matches in these cells: {esc(ratio_cell_text(matched))}.</p>"
    note = ""
    for block in glist(entry, "blocks"):
        if isinstance(block, dict) and isinstance(block.get("single_context_note"), str):
            note = f"<p class='fine'>{esc(block['single_context_note'])}</p>"
            break
    if isinstance(g(entry, "block_text_note"), str):
        note += f"<p class='fine'>{esc(g(entry, 'block_text_note'))}</p>"
    return (
        f"<article class='ccard'><h4>{esc(design_label(design))}</h4>"
        f"<p class='fine'>score <code>{esc(score_used)}</code>{SEP if meta else ''}{SEP.join(meta)}</p>"
        f"{body}{extra}{_contrast_axis(domain)}{note}</article>"
    )


def _contrast_axis(domain: float) -> str:
    ticks = [-domain, -domain / 2, 0.0, domain / 2, domain]
    labels = []
    for index, tick in enumerate(ticks):
        cls = "first" if index == 0 else "last" if index == len(ticks) - 1 else ("minor" if index % 2 else "")
        labels.append(f"<span class='tick {cls}' style='left:{pct(tick, -domain, domain):.3f}%'>{esc(sfmt(tick, 2))}</span>")
    return (
        "<div class='crow axis'><div class='cl fine'>shared scale</div>"
        f"<div class='axis-x'>{''.join(labels)}</div><div class='cv'></div></div>"
    )


def _feature_value(features: dict, key: str) -> str:
    value = features.get(key, ABSENT)
    if isinstance(value, dict):
        return " · ".join(f"{esc(words(role))}: {esc(yes_no(value[role]))}" for role in ordered(list(value), ROLE_ORDER))
    return esc(yes_no(value))


def _lengths_text(lengths: dict) -> str:
    return ", ".join(f"{words(role)} {fmt(lengths[role])}" for role in ordered(list(lengths), ROLE_ORDER))


def _feature_rows(design: str, features: dict, label_suffix: str = "") -> list[str]:
    lengths = features.get("value_codepoint_lengths")
    by_block = features.get("value_codepoint_lengths_by_block")
    length_text = ""
    if isinstance(by_block, dict) and by_block:
        # Lengths differ between blocks: show every block, never one block's lengths for the design.
        length_text = " (" + esc("; ".join(
            f"{block}: {_lengths_text(value)}" for block, value in sorted(by_block.items()) if isinstance(value, dict)
        )) + ")"
    elif isinstance(lengths, dict):
        length_text = " (" + esc(_lengths_text(lengths)) + ")"
    strength = features.get("context_strength")
    if isinstance(strength, dict):
        strength_html = "".join(
            f"<div><b>{esc(words(key))}</b>: {esc(strength[key])}</div>"
            for key in ordered(list(strength), CONTEXT_ORDER)
        )
    else:
        strength_html = esc(yes_no(strength) if strength is not ABSENT else "absent")
    return [
        f"<b>{esc(design_label(design))}</b>{esc(label_suffix)}",
        _feature_value(features, "name_cue_present"),
        f"{esc(yes_no(features.get('equal_length_values', ABSENT)))}{length_text}",
        f"<div class='strength'>{strength_html}</div>",
        f"<code class='mono-s'>{esc(features.get('source_unit', ABSENT))}</code><br>{basis_h(features.get('source_unit_basis'))}",
    ]


def _feature_matrix(entries: list[dict]) -> str:
    rows = []
    for entry in entries:
        design = g(entry, "design")
        features = gdict(entry, "design_features")
        if "source_unit" in features or not features:
            rows.append(_feature_rows(design, features))
        else:
            for unit in sorted(features):
                if isinstance(features[unit], dict):
                    rows.append(_feature_rows(design, features[unit], f" · {words(unit)}"))
    return table_h(["Design", "Name cue present", "Equal-length values", "Context strength", "Source unit"], rows,
                   cls="feat")


def _other_design_cards(designs: dict) -> str:
    cards = []
    original = designs.get("original")
    if isinstance(original, dict):
        rows = [
            [esc(words(g(item, "value_role"))), esc(words(g(item, "context"))),
             ", ".join(esc(fmt(score)) for score in glist(item, "scores")) or num_h(ABSENT),
             num_h(g(item, "median")), ", ".join(esc(fmt(o)) for o in glist(item, "occurrences"))]
            for item in glist(original, "descriptive_distinct_text_scores") if isinstance(item, dict)
        ]
        cards.append(
            "<article class='ccard'><h4>Original Case R · no contrast</h4>"
            f"<p class='fine'>{esc(g(original, 'reason'))} Descriptive scores only (score "
            f"<code>{esc(g(original, 'score_used'))}</code>).</p>"
            + table_h(["Role", "Context", "Distinct-text scores", "Median", "Relations"], rows, cls="num-table")
            + "</article>"
        )
    granularity = designs.get("crossover_granularity")
    if isinstance(granularity, dict):
        counts = gdict(granularity, "distinct_text_hit_counts")
        rows = []
        for unit in sorted(counts):
            unit_counts = gdict(counts, unit)
            row = [esc(words(unit))]
            for kind in ("legitimate_carrier", "attacker_carrier", "noncarrier"):
                for stage in ("tier3_distinct", "tier4_distinct"):
                    row.append(ratio_h(g(unit_counts, kind, stage), meter=False))
            rows.append(row)
        cards.append(
            "<article class='ccard wide'><h4>Crossover · granularity (source unit, not value × context)</h4>"
            f"<p class='fine'>{esc(g(granularity, 'reason'))} {esc(g(granularity, 'caveat'))}</p>"
            + table_h(["Unit", "Legit T3", "Legit T4", "Attacker T3", "Attacker T4", "Noncarrier T3", "Noncarrier T4"],
                      rows, cls="num-table")
            + "</article>"
        )
    probe = designs.get("intentional_probe")
    if isinstance(probe, dict):
        arm_rows = [
            [esc(context_label(g(item, "arms"))), esc(g(item, "source_file")), esc(words(g(item, "value_role"))),
             esc(words(g(item, "carrier_label"))), num_h(g(item, "occurrences")), num_h(g(item, "tier3_score")),
             num_h(g(item, "tier4_best_score")), esc(yes_no(g(item, "tier4_matched")))]
            for item in glist(probe, "arm_rows") if isinstance(item, dict)
        ]
        outcome_rows = [
            [esc(words(g(item, "arm"))), ratio_h(g(item, "legitimate_at_recipients_0"), meter=False),
             ratio_h(g(item, "attacker_at_recipients_0"), meter=False), ratio_h(g(item, "native_confirmed"), meter=False),
             num_h(g(item, "planned_slots"))]
            for item in glist(probe, "native_outcomes_by_arm", "rows") if isinstance(item, dict)
        ]
        diff = gdict(probe, "file2_obfuscated_minus_literal")
        cards.append(
            "<article class='ccard wide'><h4>Intentional probe (replay; not a value × context design)</h4>"
            + table_h(["Arm", "File", "Role", "Label", "Relations", "T3", "T4 best", "T4 match"], arm_rows,
                      cls="num-table")
            + f"<p class='fine'>File 2, obfuscated − literal: T3 {esc(sfmt(g(diff, 'tier3')))}, "
            f"T4 {esc(sfmt(g(diff, 'tier4')))}. {esc(g(diff, 'note'))}</p>"
            + "<p class='fine'>Outcome at <code>/recipients/0</code>, per arm. "
            f"{esc(g(probe, 'native_outcomes_by_arm', 'note'))}</p>"
            + table_h(["Arm", "Legitimate", "Attacker", "Native-confirmed", "Planned slots"], outcome_rows,
                      cls="num-table")
            + "</article>"
        )
    return "".join(cards)


def _contrasts(documents: dict) -> str:
    designs = _contrast_designs(documents)
    entries = [designs[name] for name in CONTRAST_DESIGNS if isinstance(designs.get(name), dict)]
    domain = _contrast_domain(entries)
    cards = "".join(_contrast_card(entry, domain) for entry in entries)
    definitions = gdict(documents, "contrasts", "definitions")
    all_entries = [entry for entry in glist(documents, "contrasts", "designs") if isinstance(entry, dict)]
    return (
        f"<section id='s-contrasts' class='wrap'>{h2(4)}"
        "<p class='sec-lede'><b>L−A</b>: legitimate − attacker at fixed context and block. "
        "<b>N−M</b>: normal − malicious at fixed value and block. <b>Interaction</b>: "
        "(L−A)<sub>normal</sub> − (L−A)<sub>malicious</sub>. Each card uses the score its design treats "
        "as primary, named on the card. Dots right of zero mean the first term scored higher.</p>"
        f"<p class='fine'>Replicates: {sentence(g(definitions, 'replicate_rule'))} Inference: "
        f"{sentence(g(definitions, 'statistical_inference'))}</p>"
        "<div class='legend'><span><span class='cdot-k value'></span>Value contrast</span>"
        "<span><span class='cdot-k context'></span>Context contrast</span>"
        "<span><span class='cdot-k interaction'></span>Interaction</span>"
        "<span><span class='bdot-k'></span>Distinct block (median shown large)</span></div>"
        f"<div class='cgrid'>{cards}</div>"
        "<h3>Designs without a value × context contrast</h3>"
        f"<div class='cgrid'>{_other_design_cards(designs)}</div>"
        "<h3>Design-feature matrix</h3>"
        "<p class='fine'>What differs between designs. Name cue: a two-token ‘First Last’ name derived from "
        "the target occurs in the source outside the target. Source-unit basis: saved field, or inferred from saved text.</p>"
        f"{_feature_matrix(all_entries)}"
        "</section>"
    )


# --------------------------------------------------------------------------- 5 cross-suite


DISTINCT = (("distinct_texts", "distinct"),)
WHOLE_DISTINCT = (("distinct_texts", "distinct texts"), ("distinct_run_outputs", "run-level"))


def _distinct_line(cell, keys=DISTINCT) -> str:
    """Second line of a cell: distinct counts (texts, run-level outputs); nothing when the cell itself is empty."""
    if not isinstance(cell, dict) or ratio_cell_text(cell) in ("n/a", "absent"):
        return ""
    parts = []
    for key, label in keys:
        distinct = cell.get(key)
        if isinstance(distinct, dict):
            parts.append(f"<span class='dd'>{esc(ratio_cell_text(distinct))} {esc(label)}</span>")
        else:
            parts.append(f"<span class='absent'>{esc(label)} absent</span>")
    return f"<div class='ts sub'><span class='tl'></span>{' · '.join(parts)}</div>"


def _two_stage_h(cell_t3, cell_t4, *, distinct=DISTINCT, meter: bool = True) -> str:
    """T3 and T4 lines; each relation count is followed by its distinct counts."""
    return "".join(
        f"<div class='ts'><span class='tl'>{label}</span>{ratio_h(cell, meter)}</div>"
        + (_distinct_line(cell, distinct) if distinct else "")
        for label, cell in (("T3", cell_t3), ("T4", cell_t4))
    )


def _complement(cell) -> dict | object:
    if not isinstance(cell, dict) or not is_int(cell.get("hits")) or not is_int(cell.get("scored")):
        return ABSENT
    scored, hits = cell["scored"], cell["hits"]
    if scored == 0:
        return {"display": "n/a", "rate": None, "hits": 0, "scored": 0}
    return {"display": f"{scored - hits}/{scored}", "rate": (scored - hits) / scored, "hits": scored - hits, "scored": scored}


def _specificity_cell(cell) -> dict | object:
    """Noncarriers not matched / scored, for relations and (when saved) distinct texts."""
    out = _complement(cell)
    if isinstance(out, dict) and isinstance(cell.get("distinct_texts"), dict):
        out["distinct_texts"] = _complement(cell["distinct_texts"])
    return out


def _suites_and_roles(rows: list[dict], role_key: str) -> tuple[list, list]:
    suites, roles = [], []
    for row in rows:
        if g(row, "suite") not in suites:
            suites.append(g(row, "suite"))
        if g(row, role_key) not in roles:
            roles.append(g(row, role_key))
    return suites, roles


def _suite_matrix(suites: list, groups: list, *, total: bool, caption: str, distinct=DISTINCT) -> str:
    """Groups of rows (one per stratum) by suite columns; ``groups`` holds (heading, [(label, {suite: (t3, t4)}, total)])."""
    width = 1 + len(suites) + (1 if total else 0)
    head = "<th scope='col'>Group</th>" + "".join(f"<th scope='col'>{esc(cap(str(suite)))}</th>" for suite in suites)
    head += "<th scope='col'>Total</th>" if total else ""
    body = []
    for heading, rows in groups:
        body.append(f"<tr class='grp'><th scope='colgroup' colspan='{width}'>{esc(heading)}</th></tr>")
        for label, cells, total_cells in rows:
            tds = [f"<th scope='row'>{esc(label)}</th>"]
            tds += [f"<td>{_two_stage_h(*cells.get(suite, (ABSENT, ABSENT)), distinct=distinct)}</td>" for suite in suites]
            if total:
                tds.append(f"<td class='tot'>{_two_stage_h(*total_cells, distinct=distinct)}</td>")
            body.append("<tr>" + "".join(tds) + "</tr>")
    return (f"<div class='tscroll'><table class='xs'><caption>{caption}</caption><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table></div>")


def _stage_cells(row) -> tuple:
    return g(row, "tier3"), g(row, "tier4")


def _passage_table(passage: dict) -> str:
    table = [row for row in glist(passage, "carrier_table") if isinstance(row, dict)]
    suites, roles = _suites_and_roles(table, "role_stratum")
    carriers = {(g(row, "suite"), g(row, "role_stratum")): row for row in table}
    noncarriers = {(g(row, "suite"), g(row, "value_stratum")): row
                   for row in glist(passage, "noncarrier_by_suite_value_stratum") if isinstance(row, dict)}
    totals = gdict(passage, "carrier_totals")
    nc_totals = gdict(passage, "noncarrier_totals_by_value_stratum")
    carrier_rows = [
        (cap(words(role)), {suite: _stage_cells(carriers.get((suite, role))) for suite in suites},
         _stage_cells(g(totals, role)))
        for role in roles
    ]
    values = ("text", "numeric")
    positive_rows = [
        (f"Noncarrier {value}", {suite: _stage_cells(noncarriers.get((suite, value))) for suite in suites},
         _stage_cells(g(nc_totals, value)))
        for value in values
    ]
    specificity_rows = [
        (f"Noncarrier {value}",
         {suite: tuple(_specificity_cell(cell) for cell in _stage_cells(noncarriers.get((suite, value))))
          for suite in suites},
         tuple(_specificity_cell(cell) for cell in _stage_cells(g(nc_totals, value))))
        for value in values
    ]
    groups = [
        ("Carriers · detections / scored relations", carrier_rows),
        ("Noncarriers · Tier-3/4 positives / scored relations", positive_rows),
        ("Noncarrier specificity · not matched / scored", specificity_rows),
    ]
    caption = ("Each cell: relations matched / scored with a meter, then the same count over distinct "
               "(passage text, target) pairs. Numeric carriers and numeric noncarriers are separate rows.")
    return _suite_matrix(suites, groups, total=True, caption=caption)


def _repeated_sentence(whole: dict) -> str:
    repeated = gdict(whole, "repeated_whole_scorings")
    count = g(repeated, "relations_repeating_a_run_level_whole_scoring")
    if not is_int(count):
        return "The repeated whole-output scoring count is absent."
    if count == 0:
        return "No relation repeats another relation's run-level whole-output scoring."
    groups = gdict(repeated, "label_transitions_of_groups_with_more_than_one_relation")
    identical = g(repeated, "identical_saved_whole_scores_and_decisions_within_groups")
    distinct = g(repeated, "distinct_run_level_whole_scorings")
    paired = g(whole, "paired_relations")
    tail = (f" Relation counts include both relations; distinct counts score each run-level whole output once "
            f"({fmt(distinct)} distinct run-level scorings of {fmt(paired)} paired relations).")
    if groups == {"carrier->carrier|carrier->noncarrier": count} and identical is True:
        return (f"{fmt(count)} of the {fmt(paired)} paired relations reuse the whole-output score of their "
                "carrier→carrier partner: in each of those runs, two relations share one whole output and one "
                "target, one labelled carrier→carrier and one carrier→noncarrier, and both carry identical saved "
                "whole-output T3/T4 scores." + tail)
    composition = ", ".join(f"{key.replace('|', ' + ')}: {fmt(value)}" for key, value in sorted(groups.items()))
    return (f"{fmt(count)} relations repeat another relation's run-level whole-output scoring (same slot, whole "
            f"output and target; groups by label transition: {composition}; identical saved whole scores: "
            f"{yes_no(identical)})." + tail)


def _whole_table(whole: dict) -> tuple[str, str]:
    table = [row for row in glist(whole, "table") if isinstance(row, dict)]
    suites, roles = _suites_and_roles(table, "target_role_stratum")
    cells = {(g(row, "suite"), g(row, "target_role_stratum")): row for row in table}
    groups = [
        (heading, [
            (cap(words(role)), {suite: (g(cells.get((suite, role)), key, "tier3"), g(cells.get((suite, role)), key, "tier4"))
                                for suite in suites}, (ABSENT, ABSENT))
            for role in roles
        ])
        for heading, key in (
            ("Whole-label carriers · matches / scored relations", "whole_label_carrier"),
            ("Whole-label noncarriers · positives / scored relations", "whole_label_noncarrier_positives"),
        )
    ]
    caption = ("Matches, not detections. Each cell: relations matched / scored with a meter, then the same count "
               "over distinct (whole-output text, target) pairs and over distinct run-level whole outputs (slot, "
               "whole output, target). Rows are the target role of the executed value.")
    pivot = _suite_matrix(suites, groups, total=False, caption=caption, distinct=WHOLE_DISTINCT)
    detail_rows = []
    for row in table:
        reasons = gdict(row, "excluded_reasons")
        transitions = gdict(row, "label_transitions_whole_to_passage")
        flips = gdict(row, "decision_transitions_whole_vs_passage")
        carrier = gdict(row, "whole_label_carrier")
        flip_lines = "".join(
            f"<div class='ts'><span class='tl'>{label}</span>"
            f"{ratio_h(g(flips, stage, 'all', 'flip_cell'), meter=False)}</div>"
            for label, stage in (("T3", "tier3"), ("T4", "tier4"))
        )
        detail_rows.append([
            esc(g(row, "suite")), esc(words(g(row, "target_role_stratum"))),
            _two_stage_h(g(carrier, "tier3"), g(carrier, "tier4"), meter=False, distinct=WHOLE_DISTINCT),
            _two_stage_h(g(row, "whole_label_noncarrier_positives", "tier3"),
                         g(row, "whole_label_noncarrier_positives", "tier4"), meter=False, distinct=WHOLE_DISTINCT),
            num_h(g(row, "excluded_relations"))
            + ("<br><span class='fine'>" + esc(", ".join(f"{words(k)} {fmt(v)}" for k, v in sorted(reasons.items())))
               + "</span>" if reasons else ""),
            flip_lines,
            esc(", ".join(f"{k}: {fmt(v)}" for k, v in sorted(transitions.items()))) or "<span class='na'>n/a</span>",
        ])
    detail = table_h(
        ["Suite", "Target role", "Carrier matches", "Noncarrier positives", "Excluded", "Decision flips",
         "Label whole→passage"],
        detail_rows, cls="num-table",
    )
    return pivot, detail


def _custom_table(custom: dict) -> tuple[str, str]:
    table = [row for row in glist(custom, "table") if isinstance(row, dict)]
    rows = [
        [esc(g(row, "suite")), esc(words(g(row, "target_role"))),
         _two_stage_h(g(row, "carrier", "tier3"), g(row, "carrier", "tier4"), meter=False),
         _two_stage_h(g(row, "noncarrier_positives", "tier3"), g(row, "noncarrier_positives", "tier4"), meter=False)]
        for row in table
    ]
    nonempty, others = [], []
    for row in table:
        for kind, key in (("carrier", "carrier"), ("noncarrier", "noncarrier_positives")):
            scored, distinct = g(row, key, "tier4", "scored"), g(row, key, "tier4", "distinct_texts", "scored")
            if is_int(scored) and scored > 0:
                nonempty.append(distinct)
                if distinct != 1:
                    others.append(f"{g(row, 'suite')} {words(g(row, 'target_role'))} {kind}: {fmt(distinct)}")
    if nonempty:
        ones = sum(1 for value in nonempty if value == 1)
        note = (f"Distinct (source text, sink value) per non-empty cell: 1 in {ones} of {len(nonempty)} cells"
                + (f"; {', '.join(others)}" if others else "")
                + ". Each 9/9 or 18/18 is repeated scoring of one fixture text (or two), not 9 or 18 independent texts.")
    else:
        note = "No non-empty cell."
    return table_h(["Suite", "Target role", "Carrier detections", "Noncarrier positives"], rows,
                   cls="num-table"), note


def _run_table(run: dict) -> str:
    rows = []
    for row in glist(run, "rows"):
        if not isinstance(row, dict):
            continue
        rows.append([
            esc(g(row, "suite")),
            ratio_h(g(row, "clean_legitimate_tier4_hits"), meter=False),
            num_h(g(row, "clean_scorable_legitimate_carrier_runs")),
            ratio_h(g(row, "attack_attacker_executed"), meter=False),
            ratio_h(g(row, "attack_attacker_tier4_hits"), meter=False),
            num_h(g(row, "attack_scorable_attacker_carrier_runs")),
            ratio_h(g(row, "by_condition", "attack", "tier4_noncarrier_false_positive_runs"), meter=False),
        ])
    totals = gdict(run, "totals")
    attack = gdict(run, "totals_by_condition", "attack")
    rows.append([
        "<b>Total</b>", ratio_h(g(totals, "clean_legitimate_tier4_hits"), meter=False), "",
        ratio_h(g(totals, "attack_attacker_executed"), meter=False),
        ratio_h(g(totals, "attack_attacker_tier4_hits"), meter=False), "",
        ratio_h(g(attack, "tier4_noncarrier_false_positive_runs"), meter=False),
    ])
    return table_h(["Suite", "Clean: legit T4 hits / runs", "Clean: scorable legit runs",
                    "Attack: attacker executed / runs", "Attack: attacker T4 hits / runs",
                    "Attack: scorable attacker runs", "Attack: noncarrier T4 FP runs"], rows, cls="num-table wrap-head")


def _classes_table(passage: dict) -> str:
    by_suite = gdict(passage, "noncarrier_tier4_positive_classes_by_suite")
    suites = ordered(list(by_suite), synthesis.SUITES)
    classes = sorted({name for counts in by_suite.values() if isinstance(counts, dict) for name in counts})
    rows = []
    for name in classes:
        counts = [gdict(by_suite, suite).get(name, 0) for suite in suites]
        label = AUDIT_CLASS_LABELS.get(name, cap(words(name)))
        rows.append([f"{esc(label)}<br><code class='mono-s'>{esc(name)}</code>"]
                    + [esc(fmt(count)) for count in counts]
                    + [esc(fmt(sum(count for count in counts if is_int(count))))])
    return table_h(["Chunk-audit class"] + [esc(cap(str(suite))) for suite in suites] + ["Total"], rows,
                   cls="num-table wrap-head")


def _cross_suite(documents: dict) -> str:
    cross = gdict(documents, "cross_suite")
    passage = gdict(cross, "passage_level")
    whole = gdict(cross, "whole_output_level")
    comparison = gdict(cross, "noncarrier_runs_versus_relations")
    table = [row for row in glist(passage, "carrier_table") if isinstance(row, dict)]
    empty = [row for row in table if g(row, "tier4", "scored") == 0]
    nonempty = [row for row in table if is_int(g(row, "tier4", "scored")) and g(row, "tier4", "scored") > 0]
    with_distinct = [row for row in nonempty if is_int(g(row, "tier4", "distinct_texts", "scored"))]
    attacker_suites = [str(g(row, "suite")) for row in nonempty if str(g(row, "role_stratum")).startswith("attacker")]
    if with_distinct:
        smallest = min(with_distinct, key=lambda row: (g(row, "tier4", "distinct_texts", "scored"), g(row, "tier4", "scored")))
        distinct_text = (
            f"counted by distinct (passage text, target), the smallest non-empty cell has n = "
            f"{fmt(g(smallest, 'tier4', 'distinct_texts', 'scored'))} ({g(smallest, 'suite')} "
            f"{words(g(smallest, 'role_stratum'))}, {fmt(g(smallest, 'tier4', 'scored'))} relations)"
        )
    else:
        distinct_text = "distinct-text counts are absent"
    small_n = (
        f"{len(empty)} of {len(table)} passage carrier cells are empty (n/a); {distinct_text}; by relations the "
        f"smallest non-empty cell has n = {fmt(min(g(row, 'tier4', 'scored') for row in nonempty)) if nonempty else 'absent'}; "
        f"attacker carriers exist only in {', '.join(attacker_suites) if attacker_suites else 'no suite'}."
    )
    pivot, detail = _whole_table(whole)
    custom_table, custom_note = _custom_table(gdict(cross, "custom_main_whole_source"))
    flips = gdict(whole, "decision_flips_whole_vs_passage")
    labels = gdict(whole, "label_transition_counts")
    fp_passages = gdict(passage, "noncarrier_tier4_distinct_false_positive_passages")
    nc_total = g(passage, "noncarrier_totals", "tier4")
    return (
        f"<section id='s-deepseek' class='wrap'>{h2(5)}"
        f"<p class='banner'><b>Not poolable with Case R.</b> {esc(g(cross, 'never_pooled'))} Model "
        f"<code>{esc(g(cross, 'model'))}</code>. Small n: {esc(small_n)}</p>"
        "<p class='sec-lede'>Passage level: <b>detections</b> / scored relations per cell. Whole-output level: "
        f"<b>matches</b> / scored relations. {esc(g(whole, 'cell_wording'))} Tier 3 and Tier 4 are kept apart. Under "
        "every relation count is the same count over distinct scored (text, target) pairs, because replicates are "
        "counted by distinct text; the relation totals are the protocol-anchored ones. Empty cells: "
        f"{esc(g(cross, 'empty_cell_rule'))}.</p>"
        "<h3>Passage level</h3>"
        f"<p class='fine'>Source unit <code>{esc(g(passage, 'source_unit'))}</code> ({basis_h(g(passage, 'source_unit_basis'))}). "
        f"Role axis: {esc(g(passage, 'role_axis'))}. Distinct key: {esc(g(passage, 'distinct_text_key'))}. "
        "Specificity = noncarriers not matched / noncarriers scored. All noncarriers pooled over text and numeric "
        f"(the protocol anchor): T3 {esc(ratio_cell_text(g(passage, 'noncarrier_totals', 'tier3')))}, T4 "
        f"{esc(ratio_cell_text(nc_total))} relations ({esc(_distinct_text(nc_total))} distinct).</p>"
        f"{_passage_table(passage)}"
        "<details class='more'><summary>What the noncarrier Tier-4 positives are (chunk audit)</summary>"
        f"<p class='fine'>Source: {esc(g(passage, 'noncarrier_tier4_positive_classes_source'))}. Counts are relations. "
        f"{esc(fmt(g(fp_passages, 'passages')))} distinct passages (passage text alone) are Tier-4 positive, equal to "
        f"the {esc(fmt(g(fp_passages, 'saved_in_chunk_audit')))} the chunk audit saves; counted by distinct "
        f"(passage text, target) the positives are {esc(_distinct_text(nc_total))}.</p>"
        f"{_classes_table(passage)}</details>"
        "<h3>Whole-output level</h3>"
        f"<p class='fine'>Source unit <code>{esc(g(whole, 'source_unit'))}</code> ({basis_h(g(whole, 'source_unit_basis'))}); "
        f"role axis: {esc(g(whole, 'role_axis'))}. Paired relations {esc(fmt(g(whole, 'paired_relations')))}, excluded "
        f"{esc(fmt(g(whole, 'excluded_relations')))} (counted, never dropped silently); decision flips whole vs "
        f"passage: T3 {esc(fmt(g(flips, 'tier3')))}, T4 {esc(fmt(g(flips, 'tier4')))}; label transitions "
        f"{esc(', '.join(f'{k} {fmt(v)}' for k, v in sorted(labels.items())))}.</p>"
        f"<p class='fine'><b>Repeated scorings.</b> {esc(_repeated_sentence(whole))}</p>"
        f"{pivot}"
        "<details class='more'><summary>Per-cell exclusions, noncarrier positives and decision flips</summary>"
        f"<p class='fine'>{esc(g(whole, 'excluded_note'))} {esc(g(whole, 'decision_transition_definition'))} "
        f"Distinct run-level outputs: {esc(g(whole, 'distinct_run_output_key'))}. Flips are relation-level "
        "(paired whole and passage decisions).</p>"
        f"{detail}</details>"
        "<details class='more'><summary>Custom-fixture batch (whole source; separate population)</summary>"
        f"<p class='fine'>{esc(g(cross, 'custom_main_whole_source', 'source_unit'))} "
        f"({basis_h(g(cross, 'custom_main_whole_source', 'source_unit_basis'))}). "
        f"{esc(g(cross, 'custom_main_whole_source', 'source_unit_note'))}</p>"
        f"<p class='fine'><b>Small n.</b> {esc(custom_note)} Distinct key: "
        f"{esc(g(cross, 'custom_main_whole_source', 'distinct_text_key'))}.</p>"
        f"{custom_table}</details>"
        "<details class='more'><summary>Run denominator (end-to-end yields, not detection rates)</summary>"
        f"<p class='fine'>{esc(g(cross, 'run_denominator', 'definition'))}</p>"
        f"{_run_table(gdict(cross, 'run_denominator'))}"
        f"<p class='fine'>{esc(g(comparison, 'note'))}</p></details>"
        "</section>"
    )


# --------------------------------------------------------------------------- 6 checks and method


def _anchor_value(value, digits: int = 6) -> str:
    if isinstance(value, list):
        return ", ".join(_anchor_value(item, digits) for item in value)
    if is_num(value) and not is_int(value):
        return fmt(value, digits)
    return fmt(value)


def info_value_h(value) -> str:
    """An informational value as text, or as a small nested list for an object (never raw JSON)."""
    if isinstance(value, dict):
        items = "".join(f"<li>{esc(words(key))}: {info_value_h(value[key])}</li>" for key in sorted(value))
        return f"<ul class='plain sub'>{items}</ul>"
    if isinstance(value, list):
        return esc(", ".join(_anchor_value(item) for item in value))
    if isinstance(value, bool) or value is None:
        return esc(yes_no(value))
    return esc(_anchor_value(value))


_INTERACTION = re.compile(r"\(L-A\)(normal|malicious)")


def rule_h(text) -> str:
    """Escaped rule text; '(L-A)normal' is shown with the subscript used in Section 4."""
    return _INTERACTION.sub(lambda match: f"(L−A)<sub>{match.group(1)}</sub>", esc(text))


def _checks(documents: dict) -> str:
    anchors = gdict(documents, "anchor_checks")
    frozen = gdict(documents, "frozen_config")
    items = []
    for check in glist(anchors, "checks"):
        if not isinstance(check, dict):
            continue
        passed = check.get("passed") is True
        icon, cls, label = ("✓", "pass", "Pass") if passed else ("✕", "fail", "Fail")
        tolerance = check.get("tolerance", ABSENT)
        items.append(
            f"<li class='ac {cls}'><span class='chip {('st-ok' if passed else 'st-open')}'>"
            f"<span aria-hidden='true'>{icon}</span> {label}</span>"
            f"<span class='ac-d'>{esc(check.get('description', ABSENT))}</span>"
            f"<span class='ac-v fine'>expected {esc(_anchor_value(check.get('expected', ABSENT)))} · observed "
            f"{esc(_anchor_value(check.get('observed', ABSENT), 9))} · tolerance "
            f"{esc(_anchor_value(tolerance) if is_num(tolerance) else tolerance)}</span></li>"
        )
    info = gdict(anchors, "informational")
    info_html = "".join(
        f"<li><b>{esc(INFO_LABELS.get(key, cap(words(key))))}</b>: {info_value_h(value)}"
        f" <code class='mono-s fine'>{esc(key)}</code></li>"
        for key, value in sorted(info.items())
    )
    rules = gdict(frozen, "rules")
    rules_html = "".join(f"<div><dt>{esc(words(key))}</dt><dd>{rule_h(text)}</dd></div>" for key, text in sorted(rules.items()))
    thresholds = gdict(frozen, "thresholds")
    sweep = gdict(frozen, "sweep_grid")
    inputs = [
        [esc(g(item, "key")), f"<code class='mono-s'>{esc(g(item, 'path'))}</code>", num_h(g(item, "bytes")),
         f"<code class='mono-s'>{esc(g(item, 'sha256'))}</code>"]
        for item in glist(frozen, "inputs") if isinstance(item, dict)
    ]
    code_rows = [
        [esc(name), f"<code class='mono-s'>{esc(g(item, 'path'))}</code>", f"<code class='mono-s'>{esc(g(item, 'sha256'))}</code>"]
        for name, item in sorted(gdict(frozen, "code", "files").items())
    ]
    limits = [
        "Rearranges saved scorer outputs; it measures neither agent behaviour, model reliance, causal influence nor "
        "a defence bypass.",
        "Case R scaffold scores and DeepSeek tables use different source units and populations and are never pooled.",
        "Repeated scoring of identical text is not an independent observation; replicates are distinct texts or blocks.",
        "The threshold view is post hoc over very few distinct carrier texts and is not a proposed operating point.",
        "Source units of the counterbalanced arms and the probe are inferred from saved text; the custom-batch unit "
        "cannot be verified from its packet.",
        "The question map is the lead's interpretation, shown unchanged; it is not derived data.",
    ]
    status = (
        f"{esc(fmt(g(anchors, 'passed')))} passed, {esc(fmt(g(anchors, 'failed')))} failed"
        + ("" if g(anchors, "all_passed") is True else " — <b>the run is not valid</b>")
    )
    return (
        f"<section id='s-checks' class='wrap'>{h2(6)}"
        f"<p class='sec-lede'>Protocol anchors that must reproduce (absolute tolerance "
        f"{esc(fmt(g(anchors, 'score_tolerance'), 6))} for scores, exact for counts): {status}.</p>"
        f"<ul class='aclist'>{''.join(items)}</ul>"
        f"<details class='more'><summary>Informational values</summary><ul class='plain'>{info_html}</ul></details>"
        "<h3>Method</h3>"
        f"<p class='fine'>Thresholds: T3 {esc(fmt(g(thresholds, 'tier3'), 2))}, T4 {esc(fmt(g(thresholds, 'tier4'), 2))}, "
        f"T4 coverage {esc(fmt(g(thresholds, 'tier4_coverage'), 2))}. Sweep: {esc(fmt(g(sweep, 'start'), 3))} to "
        f"{esc(fmt(g(sweep, 'stop'), 3))} in steps of {esc(fmt(g(sweep, 'step'), 3))} "
        f"({esc(fmt(g(sweep, 'points')))} points). Runtime: Python {esc(g(frozen, 'runtime', 'python'))}.</p>"
        f"<dl class='rules'>{rules_html}</dl>"
        "<h3>Limits</h3>"
        f"<ul class='plain limits'>{''.join(f'<li>{esc(item)}</li>' for item in limits)}</ul>"
        "<details class='more'><summary>Frozen inputs (SHA-256 verified before reading)</summary>"
        + table_h(["Key", "Path (agent-tracer-results)", "Bytes", "SHA-256"], inputs, cls="num-table")
        + "</details><details class='more'><summary>Code digests</summary>"
        + table_h(["Name", "Path (agent-tracer)", "SHA-256"], code_rows, cls="num-table")
        + f"</details><p class='fine'>Rendered by <code>{RENDERER_ID}</code> from the saved JSON only; "
        "no model, provider, network or encoder call.</p></section>"
    )


# --------------------------------------------------------------------------- page


CSS = r"""
:root{color-scheme:light;
--page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f1f0eb;--ink:#0b0b0b;--ink-2:#52514e;--muted:#6b6a65;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--border-2:rgba(11,11,11,.22);
--legit:#2a78d6;--attack:#eb6834;--non:#1baf7a;--other:#898781;
--band:rgba(42,120,214,.16);--zone:rgba(11,11,11,.045);
--good:#0ca30c;--good-text:#006300;--warning:#fab219;--warn-text:#7a5200;--serious:#ec835a;--critical:#d03b3b;--crit-text:#a32424;
--ut:#a36d00;--ut-bg:rgba(250,178,25,.09);--hl:#fde68a;--hl-ink:#0b0b0b;--focus:#2a78d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
--page:#0d0d0d;--surface:#1a1a19;--surface-2:#242422;--ink:#ffffff;--ink-2:#c3c2b7;--muted:#a3a29b;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--border-2:rgba(255,255,255,.24);
--legit:#3987e5;--attack:#d95926;--non:#199e70;--other:#898781;
--band:rgba(57,135,229,.24);--zone:rgba(255,255,255,.05);
--good-text:#0ca30c;--warn-text:#fab219;--crit-text:#e66767;
--ut:#fab219;--ut-bg:rgba(250,178,25,.07);--hl:#5c4a00;--hl-ink:#ffffff;--focus:#3987e5}}
:root[data-theme="dark"]{color-scheme:dark;
--page:#0d0d0d;--surface:#1a1a19;--surface-2:#242422;--ink:#ffffff;--ink-2:#c3c2b7;--muted:#a3a29b;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--border-2:rgba(255,255,255,.24);
--legit:#3987e5;--attack:#d95926;--non:#199e70;--other:#898781;
--band:rgba(57,135,229,.24);--zone:rgba(255,255,255,.05);
--good-text:#0ca30c;--warn-text:#fab219;--crit-text:#e66767;
--ut:#fab219;--ut-bg:rgba(250,178,25,.07);--hl:#5c4a00;--hl-ink:#ffffff;--focus:#3987e5}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-padding-top:48px}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow-wrap:break-word}
code,pre,.mono-s{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
code{overflow-wrap:anywhere}
.mono-s{font-size:12px}
a{color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.wrap{max-width:1160px;margin:0 auto;padding-left:16px;padding-right:16px}
.hero{padding-top:20px;padding-bottom:8px}
.topbar{display:flex;gap:12px;align-items:flex-start;justify-content:space-between}
#theme-toggle{white-space:nowrap;flex:none}
.eyebrow{font-size:12.5px;color:var(--ink-2);margin:4px 0 8px;overflow-wrap:anywhere}
h1{font-size:clamp(26px,4.4vw,38px);line-height:1.1;margin:0 0 12px;font-weight:650;letter-spacing:-.01em}
h2{font-size:clamp(19px,2.6vw,24px);margin:0 0 6px;line-height:1.2}
h3{font-size:16.5px;margin:22px 0 8px}
h4{font-size:14px;margin:0 0 6px}
.lede{font-size:16.5px;line-height:1.6;max-width:82ch;margin:0 0 14px}
.badges{display:flex;flex-wrap:wrap;gap:6px;padding:0;margin:0 0 14px;list-style:none}
.badge{font-size:12.5px;border:1px solid var(--border-2);border-radius:999px;padding:2px 10px;background:var(--surface);color:var(--ink-2)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,160px),1fr));gap:8px;margin:0 0 12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:9px 12px}
.kpi .k{font-size:12.5px;color:var(--ink-2)}
.kpi .v{font-size:26px;font-weight:600;line-height:1.25}
.kpi .s{font-size:12px;color:var(--muted)}
.prov{margin:0 0 6px;font-size:13px;color:var(--ink-2);display:grid;gap:3px}
.prov div{display:grid;grid-template-columns:minmax(0,7rem) minmax(0,1fr);gap:8px}
.prov dt{font-weight:600;color:var(--ink)}
.prov dd{margin:0;min-width:0}
.alert{border:1px solid var(--critical);border-left-width:4px;border-radius:8px;padding:8px 12px;background:var(--surface);color:var(--crit-text)}
.banner{border:1px solid var(--warning);border-left-width:4px;border-radius:8px;padding:8px 12px;background:var(--ut-bg);max-width:96ch}
nav.toc{position:sticky;top:0;z-index:5;background:var(--page);border-bottom:1px solid var(--border);border-top:1px solid var(--border)}
nav.toc ul{display:flex;flex-wrap:wrap;gap:2px 16px;margin:0;padding:7px 0;list-style:none;font-size:13.5px}
nav.toc a{text-decoration:none;color:var(--ink-2)}
nav.toc a:hover{color:var(--ink);text-decoration:underline}
section{padding-top:28px;padding-bottom:12px}
section+section{border-top:1px solid var(--border)}
.sec-lede{color:var(--ink-2);max-width:86ch;margin:0 0 12px}
.fine{font-size:12.5px;color:var(--muted)}
.absent{color:var(--crit-text);font-style:italic}
.na{color:var(--muted)}
button,select{font:inherit;color:inherit}
button.ghost,.fchip,select{background:var(--surface);border:1px solid var(--border-2);border-radius:8px;padding:3px 10px;font-size:13.5px;cursor:pointer;min-height:28px}
button.ghost:hover,.fchip:hover{background:var(--surface-2)}
.fchip[aria-pressed="true"]{background:var(--ink);color:var(--page);border-color:var(--ink)}
select{max-width:100%;min-width:0}
.filters{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;margin:0 0 10px}
.fgroup{display:inline-flex;flex-wrap:nowrap;align-items:center;gap:6px}
.flabel{font-size:13px;color:var(--ink-2);margin-left:4px}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12.5px;color:var(--ink-2);margin:0 0 10px;align-items:center}
.legend>span{display:inline-flex;align-items:center;gap:6px}
.sw{display:inline-block;width:11px;height:11px;border-radius:50%;flex:none;margin-right:5px;vertical-align:-1px}
.sw.legit{background:var(--legit)}.sw.attack{background:var(--attack)}.sw.non{background:var(--non)}.sw.other{background:var(--other)}
.sw.hollow{background:var(--surface)!important;border:2.5px solid currentColor}
.sw.non.hollow{color:var(--non)}.sw.legit.hollow{color:var(--legit)}.sw.attack.hollow{color:var(--attack)}.sw.other.hollow{color:var(--other)}
.sw-line{display:inline-block;width:2px;height:13px;background:var(--ink)}
.sw.band-sw{border-radius:2px;background:var(--band);border:1px solid var(--border-2)}
.lk{display:inline-block;width:16px;height:2px;border-radius:1px}
.lk.legit{background:var(--legit)}.lk.attack{background:var(--attack)}.lk.non{background:var(--non)}
details.more{margin:8px 0 12px}
details.more>summary{cursor:pointer;font-size:13.5px;color:var(--ink-2)}
ul.plain{list-style:none;padding:0;margin:6px 0}
ul.plain li{margin:3px 0}
ul.plain.sub{margin:2px 0 0 16px}
.tscroll{overflow-x:auto;max-width:100%;border:1px solid var(--border);border-radius:8px;background:var(--surface);margin:6px 0 10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{font-weight:600;color:var(--ink-2);background:var(--surface-2);white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
.num-table td{font-variant-numeric:tabular-nums}
td.n{white-space:nowrap;font-variant-numeric:tabular-nums}
caption{text-align:left;padding:6px 8px;color:var(--ink-2)}
.chip{display:inline-flex;gap:4px;align-items:center;font-size:12px;font-weight:600;border-radius:999px;padding:1px 8px;border:1px solid;white-space:nowrap}
.st-ok{color:var(--good-text);border-color:var(--good)}
.st-part{color:var(--warn-text);border-color:var(--warning)}
.st-gate{color:var(--ink-2);border-color:var(--border-2)}
.st-open,.st-unknown{color:var(--crit-text);border-color:var(--critical)}
.src-tag,.ut-tag{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;border-radius:4px;padding:0 6px;margin-right:6px}
.src-tag{border:1px solid var(--border-2);color:var(--ink-2)}
.ut-tag{border:1px solid var(--ut);color:var(--ut)}
.qmeta{font-size:13px;color:var(--ink-2);max-width:96ch}
.qgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,330px),1fr));gap:10px}
.qcard{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 12px;min-width:0}
.qcard header{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;margin-bottom:4px}
.qid{font-weight:700}
.qwho{font-size:12.5px;color:var(--ink-2);flex:1}
.qask{font-weight:600;margin:4px 0 6px}
.qdl{margin:0;display:grid;gap:4px;font-size:13.5px}
.qdl div{display:grid;grid-template-columns:4.6rem minmax(0,1fr);gap:6px}
.qdl dt{font-weight:600;color:var(--ink-2)}
.qdl dd{margin:0}
.qev{margin:6px 0 0;font-size:12px}
.qev code{font-size:11.5px;background:var(--surface-2);border-radius:4px;padding:0 4px}
.qcount{margin-left:auto}
.qnote{font-size:12.5px;color:var(--warn-text);border-left:3px solid var(--warning);padding:2px 8px;margin:6px 0 0}
figure.chart{margin:0 0 6px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px}
figcaption{font-size:12.5px;color:var(--muted);margin-top:6px}
.strip{margin:4px 0 12px}
.strip-h{font-size:13px;color:var(--ink-2);margin:4px 0}
.lane{display:grid;grid-template-columns:minmax(0,10.5rem) minmax(0,1fr);gap:10px;align-items:center;margin:3px 0}
.lane-l{display:flex;align-items:flex-start;font-size:13px;line-height:1.3}
.lane-l .sw{margin-top:3px}
.track{position:relative;border-left:1px solid var(--axis);border-bottom:1px solid var(--grid)}
.zone{position:absolute;top:0;bottom:0;right:0;background:var(--zone)}
.thr{position:absolute;top:-3px;bottom:-3px;width:2px;margin-left:-1px;background:var(--ink)}
.dot{position:absolute;width:11px;height:11px;margin:-5.5px 0 0 -5.5px;border-radius:50%;box-shadow:0 0 0 2px var(--surface);cursor:default}
.dot::before{content:"";position:absolute;inset:-7px}
.dot.legit{background:var(--legit)}.dot.attack{background:var(--attack)}
.dot.non{background:var(--surface);border:2.5px solid var(--non)}
.dot:hover,.dot:focus-visible{transform:scale(1.35)}
.axis-x{position:relative;height:18px;font-size:11.5px;color:var(--muted);font-variant-numeric:tabular-nums}
.tick{position:absolute;top:2px;transform:translateX(-50%);white-space:nowrap}
.tick.first{transform:none}.tick.last{transform:translateX(-100%)}
.tick.thr-l{top:-1px;color:var(--ink);font-weight:700;background:var(--surface);padding:0 3px}
.lcgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}
.lcw{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 12px;min-width:0}
figure.lcw{margin:0}
.pcav{font-size:12px;color:var(--warn-text);margin:2px 0 6px}
.pcav-k{font-weight:700;text-transform:uppercase;font-size:10.5px;letter-spacing:.03em;border:1px solid var(--warning);border-radius:4px;padding:0 4px;margin-right:4px}
.lc{display:grid;grid-template-columns:2.4rem minmax(0,1fr);gap:0 6px;margin-top:20px}
.lc-y{position:relative;height:210px;font-size:11px;color:var(--muted)}
.lc-y span{position:absolute;right:0;transform:translateY(-50%)}
.lc-plot{position:relative;height:210px;border-left:1px solid var(--axis);border-bottom:1px solid var(--axis);touch-action:pan-y;cursor:crosshair}
.lc-plot svg{position:absolute;inset:0;width:100%;height:100%;display:block;overflow:visible}
.lc-x{position:relative;height:20px;font-size:11px;color:var(--muted)}
.gl{stroke:var(--grid);stroke-width:1}
.frz{stroke:var(--ink);stroke-width:2}
.band{fill:var(--band)}
.band-edge{stroke:var(--legit);stroke-width:1.5}
.ivcaret{position:absolute;top:-15px;transform:translateX(-50%);font-size:11px;line-height:1;color:var(--legit);pointer-events:none}
.ser{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.ser.legit{stroke:var(--legit)}.ser.attack{stroke:var(--attack)}.ser.non{stroke:var(--non)}
#thr[data-mode="distinct"] .m-relations,#thr[data-mode="relations"] .m-distinct{display:none}
#thr[data-cov="on"] .c-off,#thr[data-cov="off"] .c-on{display:none}
.vlab{position:absolute;top:-17px;transform:translateX(-50%);font-size:11px;font-weight:600;white-space:nowrap}
.xh{position:absolute;top:0;bottom:0;width:1px;background:var(--ink-2);pointer-events:none}
.ivnote{margin:6px 0 0}
.cgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,460px),1fr));gap:10px}
.ccard{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 12px;min-width:0}
.ccard.wide{grid-column:1/-1}
.ccard .tscroll{border-radius:6px}
.axis-card{margin:8px 0 6px;padding:6px 12px}
.crow{display:grid;grid-template-columns:minmax(0,9.4rem) minmax(0,1fr) 7.2rem;gap:10px;align-items:center;margin:5px 0;font-size:13px}
.crow.axis{margin-top:2px;border-top:1px solid var(--border);padding-top:2px}
.crow.sec{opacity:.82}
.crow .cl{line-height:1.25}
.crow .cv{font-variant-numeric:tabular-nums;font-size:12.5px;line-height:1.25}
.ctrack{position:relative;height:22px;background:linear-gradient(var(--grid),var(--grid)) center/100% 1px no-repeat}
.ctrack .zero{position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--axis)}
.stem{position:absolute;top:10px;height:2px;border-radius:1px;background:var(--ink-2)}
.cdot{position:absolute;top:11px;width:11px;height:11px;margin:-5.5px 0 0 -5.5px;border-radius:50%;box-shadow:0 0 0 2px var(--surface);background:var(--ink)}
.cdot::before{content:"";position:absolute;inset:-7px}
.cdot.context{background:var(--surface);border:2.5px solid var(--ink)}
.cdot.interaction{border-radius:2px;transform:rotate(45deg)}
.bdot{position:absolute;top:11px;width:7px;height:7px;margin:-3.5px 0 0 -3.5px;border-radius:50%;border:1.5px solid var(--ink-2);background:var(--surface)}
.cdot-k,.bdot-k{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--ink)}
.cdot-k.context{background:var(--surface);border:2.5px solid var(--ink)}
.cdot-k.interaction{border-radius:2px;transform:rotate(45deg);width:9px;height:9px}
.bdot-k{width:7px;height:7px;border:1.5px solid var(--ink-2);background:var(--surface)}
.supp-h{margin:8px 0 2px;border-top:1px solid var(--border);padding-top:6px}
table.feat td{min-width:8rem}
.strength{font-size:12px;line-height:1.35;max-width:36ch}
.strength div{margin-bottom:3px}
.basis{display:inline-block;font-size:11px;border-radius:4px;padding:0 5px;margin-top:2px;border:1px solid var(--border-2);color:var(--ink-2);white-space:nowrap}
.basis.inferred{border-color:var(--warning);color:var(--warn-text)}
.basis.unverifiable,.basis.absent{border-color:var(--critical);color:var(--crit-text)}
.dname{font-weight:600}
.dc{display:inline-block;font-size:11px;border-radius:999px;padding:0 6px;margin-left:2px;border:1px solid var(--ink-2)}
.dc.hit{background:var(--ink);color:var(--page);border-color:var(--ink)}
.dc.miss{color:var(--ink-2)}
code.sv{font-size:12px;background:var(--ut-bg);border:1px solid var(--border);border-radius:4px;padding:0 4px;white-space:nowrap}
.tscroll.ledger{max-height:75vh;overflow:auto}
.tscroll.ledger thead th{position:sticky;top:0;z-index:2;box-shadow:0 1px 0 var(--border-2)}
.ledger table{min-width:900px}
.ledger th{white-space:normal}
.ledger td.n .fine{white-space:normal}
.xbtn{white-space:nowrap;margin-top:4px}
.ldetail td{background:var(--surface-2)}
.ldbody{display:grid;gap:8px;position:sticky;left:8px;width:min(1040px,calc(100vw - 58px))}
.ldmeta{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:4px 14px;font-size:12.5px}
.ldmeta b{color:var(--ink-2);font-weight:600}
.ut{border:1px solid var(--border);border-left:4px solid var(--ut);border-radius:6px;background:var(--surface)}
.ut-h{display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center;padding:5px 8px;border-bottom:1px solid var(--border);font-size:12px;color:var(--ink-2)}
.ut-x{margin:0;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12.5px;line-height:1.45;background:var(--ut-bg)}
mark.tg{background:var(--hl);color:var(--hl-ink);border-radius:3px;padding:0 1px;box-shadow:0 0 0 1px var(--ut)}
.cbars{position:relative;display:flex;align-items:flex-end;gap:2px;height:64px;border-bottom:1px solid var(--axis);padding-top:2px;max-width:520px;margin:0 22px 8px 0}
.cbar{flex:1 1 0;min-width:4px;max-width:28px;background:var(--other);border-radius:3px 3px 0 0;position:relative}
.cbar.tgt{background:var(--ink)}
.cbar.win{outline:2px solid var(--focus);outline-offset:1px}
.cbar.neg{height:5px!important;margin-bottom:-6px;border-radius:0 0 3px 3px;opacity:.75}
.cbase{position:absolute;right:-16px;bottom:-7px;font-size:10.5px;color:var(--ink-2)}
.cbk{display:inline-block;width:10px;height:10px;border-radius:2px;vertical-align:-1px;margin:0 3px 0 6px;background:var(--other)}
.cbk.tgt{background:var(--ink)}
.cbk.win{background:transparent;outline:2px solid var(--focus);outline-offset:-2px}
.cthr{position:absolute;left:0;right:0;height:1px;background:var(--ink)}
.cthr::after{content:attr(data-l);position:absolute;right:0;top:-15px;font-size:10.5px;color:var(--ink-2)}
.chunk-list{font-size:12px;color:var(--ink-2);font-variant-numeric:tabular-nums}
.ts{display:flex;align-items:center;gap:6px;white-space:nowrap;font-variant-numeric:tabular-nums}
.tl{font-size:11px;color:var(--muted);width:1.4rem}
.rt{display:inline-flex;align-items:center;gap:6px}
.mt{display:inline-block;width:46px;height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden;border:1px solid var(--border)}
.mt i{display:block;height:100%;background:var(--ink-2)}
table.xs td{min-width:7.2rem}
table.xs tr.grp th{background:var(--surface);color:var(--ink);font-weight:650;border-top:1px solid var(--border-2);white-space:normal}
table.xs tbody th[scope=row]{background:transparent;color:var(--ink);font-weight:600}
table.xs td.tot{border-left:1px solid var(--border-2)}
table.wrap-head th{white-space:normal}
.ts.sub{margin:-2px 0 3px}
.dd{font-size:11.5px;color:var(--muted)}
.aclist{list-style:none;padding:0;margin:8px 0;display:grid;gap:4px;grid-template-columns:repeat(auto-fill,minmax(min(100%,520px),1fr))}
.ac{display:grid;grid-template-columns:auto minmax(0,1fr);gap:0 8px;align-items:start;font-size:13px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:4px 8px}
.ac-v{grid-column:2}
.rules{display:grid;gap:4px;font-size:13px;margin:6px 0}
.rules div{display:grid;grid-template-columns:minmax(0,10rem) minmax(0,1fr);gap:8px}
.rules dt{font-weight:600;color:var(--ink-2)}
.rules dd{margin:0}
.limits li{padding-left:14px;position:relative}
.limits li::before{content:"\2013";position:absolute;left:0;color:var(--muted)}
#tip{position:fixed;z-index:20;max-width:min(360px,calc(100vw - 16px));background:var(--surface);color:var(--ink);border:1px solid var(--border-2);border-radius:8px;padding:6px 9px;font-size:12.5px;box-shadow:0 4px 16px rgba(0,0,0,.18);pointer-events:none;overflow-wrap:anywhere}
#tip .tip-h{font-weight:700;font-variant-numeric:tabular-nums}
#tip .tip-l{color:var(--ink-2)}
footer{padding:20px 0 40px;font-size:12px;color:var(--muted)}
@media (max-width:640px){
 .lane{grid-template-columns:minmax(0,6.8rem) minmax(0,1fr);gap:8px}
 .lane-l{font-size:12px}
 .crow{grid-template-columns:minmax(0,5.6rem) minmax(0,1fr) 5.6rem;gap:6px;font-size:12px}
 .tick.minor{display:none}
 .prov div{grid-template-columns:minmax(0,1fr)}
 .rules div{grid-template-columns:minmax(0,1fr)}
 .qdl div{grid-template-columns:minmax(0,1fr)}
 .kpi .v{font-size:22px}
}
@media print{nav.toc,#theme-toggle,.filters{display:none}}
@media (forced-colors:active){.dot,.cdot,.sw,.lk{forced-color-adjust:none}}
"""

JS = r"""
(function(){
'use strict';
var root = document.documentElement;
function el(tag, cls, text){ var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = String(text); return e; }
function fmt(x, d){ if (x === null) return 'n/a'; if (x === undefined) return 'absent'; if (typeof x !== 'number') return String(x); if (Number.isInteger(x) && d === undefined) return String(x).replace('-', '−'); var s = x.toFixed(d === undefined ? 4 : d); if (/^-0\.0+$/.test(s)) s = s.slice(1); return s.replace('-', '−'); }
function field(o, k, d){ if (!o || !(k in o)) return 'absent'; return fmt(o[k], d); }
function yn(v){ return v === true ? 'yes' : v === false ? 'no' : v === null ? 'n/a' : 'absent'; }
function readJSON(id){ var node = document.getElementById(id); if (!node) return null; try { return JSON.parse(node.textContent); } catch (e) { return null; } }

/* theme */
var themeBtn = document.getElementById('theme-toggle');
function readTheme(){ try { return window.localStorage.getItem('case-r-score-chunk-theme'); } catch (e) { return null; } }
function applyTheme(t){ if (t === 'light' || t === 'dark') root.setAttribute('data-theme', t); else root.removeAttribute('data-theme'); if (themeBtn) themeBtn.textContent = 'Theme: ' + (t || 'auto'); }
var theme = readTheme(); applyTheme(theme);
if (themeBtn) themeBtn.addEventListener('click', function(){
  theme = theme === 'light' ? 'dark' : theme === 'dark' ? null : 'light'; applyTheme(theme);
  try { if (theme) window.localStorage.setItem('case-r-score-chunk-theme', theme); else window.localStorage.removeItem('case-r-score-chunk-theme'); } catch (e) {}
});

/* tooltip: enhances, never gates (every value is also in a table) */
var tip = document.getElementById('tip');
var canHover = window.matchMedia && window.matchMedia('(hover: hover)').matches;
function showTip(lines){ tip.replaceChildren(); lines.forEach(function(line, i){ tip.appendChild(el('div', i === 0 ? 'tip-h' : 'tip-l', line)); }); tip.hidden = false; }
function placeTip(x, y){ var r = tip.getBoundingClientRect(); var left = Math.min(window.innerWidth - r.width - 8, x + 14); var top = y + 16; if (top + r.height > window.innerHeight - 8) top = y - r.height - 12; tip.style.left = Math.max(8, left) + 'px'; tip.style.top = Math.max(8, top) + 'px'; }
function hideTip(){ tip.hidden = true; }
document.querySelectorAll('[data-tip]').forEach(function(node){
  var lines = node.getAttribute('data-tip').split('\n');
  if (canHover) {
    node.addEventListener('pointermove', function(ev){ showTip(lines); placeTip(ev.clientX, ev.clientY); });
    node.addEventListener('pointerleave', hideTip);
  }
  node.addEventListener('click', function(){ var r = node.getBoundingClientRect(); showTip(lines); placeTip(r.left + 8, r.bottom - 4); });
  node.addEventListener('focus', function(){ var r = node.getBoundingClientRect(); showTip(lines); placeTip(r.left + 8, r.bottom - 4); });
  node.addEventListener('blur', hideTip);
});
document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') hideTip(); });
window.addEventListener('scroll', hideTip, {passive: true});

function pressGroup(buttons, active){ buttons.forEach(function(b){ b.setAttribute('aria-pressed', b === active ? 'true' : 'false'); }); }

/* 1 question map filter; the status counts follow the visible cards */
var qButtons = Array.prototype.slice.call(document.querySelectorAll('[data-qfilter]'));
var qScope = document.querySelector('.qscope');
function recountQuestions(who){
  var counts = {}, shown = 0;
  document.querySelectorAll('.qcard').forEach(function(card){ if (!card.hidden) { shown += 1; var st = card.getAttribute('data-status'); counts[st] = (counts[st] || 0) + 1; } });
  document.querySelectorAll('[data-qstat]').forEach(function(node){ var n = node.querySelector('.qn'); if (n) n.textContent = String(counts[node.getAttribute('data-qstat')] || 0); });
  if (qScope) { var total = qScope.getAttribute('data-total'); qScope.textContent = who === '*' ? '· all ' + total + ' asks' : '· ' + shown + ' of ' + total + ' asks (' + who + ')'; }
}
qButtons.forEach(function(button){
  button.addEventListener('click', function(){
    var who = button.getAttribute('data-qfilter');
    pressGroup(qButtons, button);
    document.querySelectorAll('.qcard').forEach(function(card){ card.hidden = !(who === '*' || card.getAttribute('data-who') === who); });
    recountQuestions(who);
  });
});

/* 2 ledger filter and chunk details */
var LEDGER_DATA = readJSON('ledger-data') || {};
var LEDGER = LEDGER_DATA.rows || [];
var THRESHOLD = typeof LEDGER_DATA.threshold === 'number' ? LEDGER_DATA.threshold : null;
var SCALE = typeof LEDGER_DATA.scale === 'number' && LEDGER_DATA.scale > 0 ? LEDGER_DATA.scale : 1;
var dButtons = Array.prototype.slice.call(document.querySelectorAll('[data-dfilter]'));
var countNode = document.getElementById('ledger-count');
function applyDesign(design){
  var shown = 0;
  document.querySelectorAll('tr.lrow').forEach(function(row){
    var ok = design === '*' || row.getAttribute('data-design') === design;
    row.hidden = !ok; if (ok) shown += 1;
    var button = row.querySelector('[data-expand]');
    var detail = button ? document.getElementById(button.getAttribute('aria-controls')) : null;
    if (detail) detail.hidden = !ok || button.getAttribute('aria-expanded') !== 'true';
  });
  if (countNode) countNode.textContent = 'Showing ' + shown + ' of ' + LEDGER.length + ' rows.';
}
dButtons.forEach(function(button){ button.addEventListener('click', function(){ pressGroup(dButtons, button); applyDesign(button.getAttribute('data-dfilter')); }); });
applyDesign('*');

function appendTargetText(parent, text, target){
  text = typeof text === 'string' ? text : '';
  if (typeof target !== 'string' || target.length === 0) { parent.appendChild(document.createTextNode(text)); return; }
  var start = 0, at;
  while ((at = text.indexOf(target, start)) !== -1) {
    if (at > start) parent.appendChild(document.createTextNode(text.slice(start, at)));
    parent.appendChild(el('mark', 'tg', target));
    start = at + target.length;
  }
  if (start < text.length) parent.appendChild(document.createTextNode(text.slice(start)));
}
function chunkBox(title, c, target, note){
  var box = el('div', 'ut');
  var head = el('div', 'ut-h');
  head.appendChild(el('span', 'ut-tag', 'Saved text · untrusted'));
  head.appendChild(el('b', null, title));
  head.appendChild(el('span', null, 'chunk #' + field(c, 'i') + ' · score ' + field(c, 's', 6) + ' · ' + field(c, 'cp') + ' code points'));
  head.appendChild(el('span', null, 'contains target: ' + ('t' in c ? yn(c.t) : 'flag not saved for this chunk') + ('cue' in c ? ' · transformed cue: ' + yn(c.cue) : '') + ' · chunk ≥ threshold: ' + yn(c.m)));
  box.appendChild(head);
  var pre = el('pre', 'ut-x');
  if ('x' in c) appendTargetText(pre, c.x, target); else pre.appendChild(document.createTextNode('(text absent)'));
  box.appendChild(pre);
  if (note) box.appendChild(el('div', 'ut-h', note));
  return box;
}
function chunkBars(r){
  var wrap = el('div');
  if (!r.chunks || !r.chunks.length) { wrap.appendChild(el('p', 'fine', 'Per-chunk scores absent.')); return wrap; }
  var bars = el('div', 'cbars'); bars.setAttribute('role', 'img');
  var bestIndex = r.best && 'i' in r.best ? r.best.i : null;
  bars.setAttribute('aria-label', 'Tier-4 score of each of ' + r.chunks.length + ' chunks');
  if (THRESHOLD !== null) { var line = el('div', 'cthr'); line.style.bottom = (THRESHOLD / SCALE * 100) + '%'; line.setAttribute('data-l', fmt(THRESHOLD, 2)); bars.appendChild(line); }
  bars.appendChild(el('span', 'cbase', '0'));
  var parts = [], negatives = 0;
  r.chunks.forEach(function(c){
    var neg = typeof c[1] === 'number' && c[1] <= 0;
    if (neg) negatives += 1;
    var bar = el('div', 'cbar' + (c[2] ? ' tgt' : '') + (c[0] === bestIndex ? ' win' : '') + (neg ? ' neg' : ''));
    var h = typeof c[1] === 'number' ? Math.max(0, Math.min(1, c[1] / SCALE)) * 100 : 0;
    bar.style.height = h + '%';
    bar.title = '#' + fmt(c[0]) + ' ' + fmt(c[1], 6);
    bars.appendChild(bar);
    parts.push('#' + fmt(c[0]) + ' ' + fmt(c[1], 4) + (c[2] ? ' (target)' : '') + (c[0] === bestIndex ? ' (winner)' : ''));
  });
  wrap.appendChild(bars);
  /* the legend uses the bars' own classes, so it matches in light and dark themes */
  var legend = el('p', 'chunk-list');
  legend.appendChild(document.createTextNode('T4 chunk scores, bar height 0 to ' + fmt(SCALE, 2) + (THRESHOLD !== null ? ', line at ' + fmt(THRESHOLD, 2) : '') + ': '));
  legend.appendChild(el('span', 'cbk tgt')); legend.appendChild(document.createTextNode('contains the complete target · '));
  legend.appendChild(el('span', 'cbk')); legend.appendChild(document.createTextNode('does not · '));
  legend.appendChild(el('span', 'cbk win')); legend.appendChild(document.createTextNode('winner (outlined)'));
  legend.appendChild(document.createTextNode(negatives ? '; ' + negatives + (negatives === 1 ? ' score is' : ' scores are') + ' ≤ 0, drawn as a short stub below the baseline. ' : '. '));
  legend.appendChild(document.createTextNode(parts.join(' · ')));
  wrap.appendChild(legend);
  return wrap;
}
function buildDetail(body, r){
  var meta = el('div', 'ldmeta');
  function add(label, value){ var d = el('div'); d.appendChild(el('b', null, label + ': ')); d.appendChild(document.createTextNode(value)); meta.appendChild(d); }
  add('Row', r.id === null ? 'absent' : r.id);
  add('Source text SHA-256', field(r, 'src'));
  add('Source code points', field(r, 'srccp'));
  add('Chunks', field(r, 'n'));
  add('Coverage', field(r, 'cov', 6) + ' (' + field(r, 'num') + ' / ' + field(r, 'den') + ' code points)');
  add('Relations / scored instances', field(r, 'occ') + ' / ' + field(r, 'inst') + ' (score spread ' + field(r, 'spread', 6) + ')');
  add('Carrier label', field(r, 'label'));
  add('Literal target occurrences', field(r, 'lit'));
  add('Saved Tier-2 match', 't2' in r ? yn(r.t2) : 'absent');
  add('Source unit', field(r, 'unit'));
  add('Unit basis', field(r, 'basis'));
  add('Identical scored pair in', r.same && r.same.length ? r.same.join(', ') : 'no other design');
  if ('replay' in r) add('Replay vs original', r.replay ? (r.replay.original || 'absent') + ' · bitwise-identical scores: ' + yn(r.replay.bitwise) + ' · same decisions: ' + yn(r.replay.decisions) : 'not compared: no original Case R row has this source text and target (saved field is null)');
  body.appendChild(meta);
  body.appendChild(chunkBars(r));
  if (r.best) body.appendChild(chunkBox('Winning chunk (highest T4 score)', r.best, r.target));
  else body.appendChild(el('p', 'fine', 'Winning chunk absent.'));
  if (r.tgt && r.best && r.tgt.i === r.best.i) body.appendChild(el('p', 'fine', 'The winning chunk is also the best chunk containing the complete target.'));
  else if (r.tgt) body.appendChild(chunkBox('Best chunk containing the complete target', r.tgt, r.target));
  else body.appendChild(el('p', 'fine', 'No chunk contains the complete target.'));
  if (r.loc) body.appendChild(chunkBox('Localized T4 chunk (' + field(r.loc, 'name') + ')', r.loc, r.target));
  if (r.cue) body.appendChild(chunkBox('Chunk with the transformed cue', r.cue, r.target, 'The literal target does not occur in this text; the saved flag marks the transformed cue. No cue string is saved, so nothing is highlighted.'));
}
document.querySelectorAll('[data-expand]').forEach(function(button){
  button.addEventListener('click', function(){
    var index = parseInt(button.getAttribute('data-expand'), 10);
    var detail = document.getElementById(button.getAttribute('aria-controls'));
    if (!detail) return;
    var body = detail.querySelector('.ldbody');
    if (body && !body.getAttribute('data-built') && LEDGER[index]) { buildDetail(body, LEDGER[index]); body.setAttribute('data-built', '1'); }
    var open = button.getAttribute('aria-expanded') !== 'true';
    button.setAttribute('aria-expanded', open ? 'true' : 'false');
    button.textContent = open ? 'Hide' : 'Chunks';
    detail.hidden = !open;
  });
});

/* 3 threshold view */
var SWEEP = readJSON('sweep-data');
var thr = document.getElementById('thr');
if (SWEEP && thr) {
  var state = {mode: 'distinct', cov: 'on', pair: 'carriers_vs_noncarriers'};
  var modeButtons = Array.prototype.slice.call(thr.querySelectorAll('[data-mode-set]'));
  var covButtons = Array.prototype.slice.call(thr.querySelectorAll('[data-cov-set]'));
  var select = document.getElementById('iv-select');
  function noteText(item){
    if (!item) return 'Interval field absent.';
    if (item.exists !== true) return 'No threshold separates these groups at this stage.';
    return 'Separating interval (' + fmt(item.lo, 6) + ', ' + fmt(item.hi, 6) + ']; ' + item.n + (item.n === 1 ? ' grid point (' : ' grid points (') + fmt(item.first, 3) + '–' + fmt(item.last, 3) + ').';
  }
  function applyThr(){
    thr.setAttribute('data-mode', state.mode); thr.setAttribute('data-cov', state.cov); thr.setAttribute('data-pair', state.pair);
    thr.querySelectorAll('[data-iv]').forEach(function(node){ node.style.display = node.getAttribute('data-iv') === state.pair ? '' : 'none'; });
    thr.querySelectorAll('[data-ivnote]').forEach(function(node){
      var stage = node.getAttribute('data-ivnote');
      var item = SWEEP.intervals[stage] ? SWEEP.intervals[stage][state.pair] : null;
      var prefix = stage === 'tier4_coverage_on' ? 'Coverage rule on · ' : stage === 'tier4_coverage_off' ? 'Coverage rule off · ' : '';
      node.replaceChildren(el('span', 'sw band-sw'), document.createTextNode(prefix + (SWEEP.pairs[state.pair] || state.pair) + ': ' + noteText(item)));
    });
  }
  modeButtons.forEach(function(b){ b.addEventListener('click', function(){ state.mode = b.getAttribute('data-mode-set'); pressGroup(modeButtons, b); applyThr(); }); });
  covButtons.forEach(function(b){ b.addEventListener('click', function(){ state.cov = b.getAttribute('data-cov-set'); pressGroup(covButtons, b); applyThr(); }); });
  if (select) select.addEventListener('change', function(){ state.pair = select.value; applyThr(); });
  applyThr();
  var grid = SWEEP.grid || [];
  thr.querySelectorAll('[data-plot]').forEach(function(plot){
    var cross = plot.querySelector('.xh');
    var current = -1;
    function stageKey(){ var s = plot.getAttribute('data-plot'); return s === 'tier4' ? (state.cov === 'on' ? 'tier4_coverage_on' : 'tier4_coverage_off') : s; }
    function lines(i){
      var st = SWEEP.stages[stageKey()][state.mode];
      var unit = state.mode === 'distinct' ? 'distinct texts' : 'relations';
      return ['threshold ' + fmt(grid[i], 3) + ' · ' + unit, 'legitimate matched ' + st.legitimate[i], 'attacker matched ' + st.attacker[i], 'noncarrier matched ' + st.noncarrier[i]];
    }
    function show(i, x, y){
      if (!grid.length || SWEEP.lo === null || SWEEP.hi === null) return;
      current = Math.max(0, Math.min(grid.length - 1, i));
      var left = (grid[current] - SWEEP.lo) / (SWEEP.hi - SWEEP.lo) * 100;
      cross.style.left = left + '%'; cross.hidden = false;
      showTip(lines(current));
      if (x === undefined) { var r = plot.getBoundingClientRect(); x = r.left + r.width * left / 100; y = r.top + 8; }
      placeTip(x, y);
    }
    function nearest(clientX){ var r = plot.getBoundingClientRect(); var t = SWEEP.lo + (clientX - r.left) / r.width * (SWEEP.hi - SWEEP.lo); var best = 0; grid.forEach(function(g, i){ if (Math.abs(g - t) < Math.abs(grid[best] - t)) best = i; }); return best; }
    plot.addEventListener('pointermove', function(ev){ show(nearest(ev.clientX), ev.clientX, ev.clientY); });
    plot.addEventListener('pointerdown', function(ev){ show(nearest(ev.clientX), ev.clientX, ev.clientY); });
    plot.addEventListener('pointerleave', function(){ cross.hidden = true; hideTip(); });
    plot.addEventListener('focus', function(){ var stage = plot.getAttribute('data-plot'); var frozen = SWEEP.frozen ? SWEEP.frozen[stage] : null; var i = current >= 0 ? current : (typeof frozen === 'number' ? grid.findIndex(function(v){ return Math.abs(v - frozen) < 1e-9; }) : 0); show(i >= 0 ? i : 0); });
    plot.addEventListener('blur', function(){ cross.hidden = true; hideTip(); });
    plot.addEventListener('keydown', function(ev){
      if (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft') { ev.preventDefault(); show(current + (ev.key === 'ArrowRight' ? 1 : -1)); }
      else if (ev.key === 'Home') { ev.preventDefault(); show(0); }
      else if (ev.key === 'End') { ev.preventDefault(); show(grid.length - 1); }
    });
  });
}
})();
"""


def _page(documents: dict, question_map, question_bytes) -> str:
    frozen = gdict(documents, "frozen_config")
    f = facts(documents)
    question_note = _question_note(question_map, question_bytes, frozen)
    ledger_html, ledger_data = _ledger(documents)
    threshold_html, sweep_data = _threshold(documents)
    body = (
        _header(documents, f, question_note)
        + _nav()
        + "<main id='main'>"
        + _questions(question_map)
        + ledger_html
        + threshold_html
        + _contrasts(documents)
        + _cross_suite(documents)
        + _checks(documents)
        + "</main>"
        + "<footer class='wrap'>Private research evidence · self-contained page: no external script, font or "
        "network request.</footer>"
    )
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'>"
        "<link rel='icon' href='data:,'>"
        f"<title>{TITLE}</title>"
        f"<meta name='description' content='{esc(g(frozen, 'protocol'))}: Tier-3/Tier-4 scores and chunks, "
        "design contrasts, threshold view and DeepSeek cross-suite tables (request-free).'>"
        f"<style>{CSS}</style></head><body>"
        + body
        + "<div id='tip' role='tooltip' hidden></div>"
        + f"<script type='application/json' id='ledger-data'>{script_json(ledger_data)}</script>"
        + f"<script type='application/json' id='sweep-data'>{script_json(sweep_data)}</script>"
        + f"<script>{JS}</script></body></html>\n"
    )


def render_report(documents: dict, question_map_bytes: bytes | None) -> str:
    """Self-contained English HTML report; deterministic for equal inputs."""
    question_map = None
    if question_map_bytes is not None:
        try:
            question_map = json.loads(question_map_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReportInputError(f"{QUESTION_MAP} is not valid UTF-8 JSON: {error}") from error
    return _page(documents, question_map, question_map_bytes)


# --------------------------------------------------------------------------- files


def load_documents(output_dir: Path) -> tuple[dict, bytes | None]:
    """Read the derived JSON, anchor log, frozen config and question map of one experiment directory."""
    output_dir = Path(output_dir)
    documents: dict = {}
    for name, path in DOCUMENT_FILES.items():
        target = output_dir / path
        if not target.is_file():
            raise ReportInputError(f"{path} is missing")
        try:
            documents[name] = json.loads(target.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReportInputError(f"{path} is not valid UTF-8 JSON: {error}") from error
    question_map = output_dir / QUESTION_MAP
    return documents, (question_map.read_bytes() if question_map.is_file() else None)


def read_checksums(output_dir: Path) -> dict[str, str]:
    target = Path(output_dir) / CHECKSUMS_FILE
    if not target.is_file():
        raise ReportInputError(f"{CHECKSUMS_FILE} is missing; recompute instead of re-rendering")
    entries: dict[str, str] = {}
    for line in target.read_text(encoding="utf-8").splitlines():
        digest, _, path = line.partition("  ")
        if len(digest) != 64 or not path:
            raise ReportInputError(f"{CHECKSUMS_FILE}: malformed line {line!r}")
        entries[path] = digest
    return entries


def verify_inputs_against_checksums(output_dir: Path, checksums: dict[str, str]) -> list[str]:
    """Every listed file except the report must match its recorded digest; the render inputs must be listed."""
    output_dir = Path(output_dir)
    required = set(DOCUMENT_FILES.values())
    if (output_dir / QUESTION_MAP).is_file():
        required.add(QUESTION_MAP)
    missing = sorted(required - set(checksums))
    if missing:
        raise ReportInputError(f"{CHECKSUMS_FILE} does not list the render inputs {missing}")
    verified = []
    for path, digest in sorted(checksums.items()):
        if path == REPORT_FILE:
            continue
        target = output_dir / path
        if not target.is_file() or sha256_bytes(target.read_bytes()) != digest:
            raise ReportInputError(f"{path} differs from {CHECKSUMS_FILE}; refusing to re-render from it")
        verified.append(path)
    return verified


def renderer_record(mode: str) -> dict:
    path = Path(__file__).resolve()
    relative = path.name
    for parent in path.parents:
        if parent.name == "packages":
            relative = path.relative_to(parent.parent).as_posix()
            break
    return {
        "renderer_id": RENDERER_ID,
        "mode": mode,
        "renderer_file": {"path": relative, "sha256": sha256_bytes(path.read_bytes())},
        "inputs": sorted(DOCUMENT_FILES.values()) + [QUESTION_MAP],
        "note": "reports/index.html is generated from the files listed in inputs only; no request of any kind.",
    }


def _with_inventory(files: dict[str, bytes], manifest: dict, question_map_bytes: bytes | None,
                    disk: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """Add manifest and checksums so that checksums cover every file (the question map included)."""
    manifest_text = synthesis.dump_json(manifest)
    synthesis._scan(MANIFEST_FILE, manifest_text)
    files[MANIFEST_FILE] = manifest_text.encode("utf-8")
    inventory = dict(disk or {})
    inventory.update(files)
    inventory.pop(CHECKSUMS_FILE, None)
    if question_map_bytes is not None:
        inventory[QUESTION_MAP] = question_map_bytes
    files[CHECKSUMS_FILE] = synthesis.render_checksums(inventory).encode("utf-8")
    return files


def publication_files(documents: dict, question_map_bytes: bytes | None, created_at: str) -> dict[str, bytes]:
    """Every runner output, as ``synthesis.publication_files`` builds it but with this module's report."""
    files: dict[str, bytes] = {}
    for name, path in synthesis.JSON_OUTPUTS.items():
        synthesis.assert_no_absolute_paths(documents[name], path)
        text = synthesis.dump_json(documents[name])
        if json.loads(text) != documents[name]:
            raise ValueError(f"{path}: JSON round trip differs")
        synthesis._scan(path, text)
        files[path] = text.encode("utf-8")
    report = render_report(documents, question_map_bytes)
    synthesis._scan(REPORT_FILE, report)
    files[REPORT_FILE] = report.encode("utf-8")
    readme = synthesis.render_readme(documents)
    synthesis._scan(README_FILE, readme)
    files[README_FILE] = readme.encode("utf-8")
    inventory = dict(files)
    if question_map_bytes is not None:
        inventory[QUESTION_MAP] = question_map_bytes
    manifest = synthesis.build_manifest(documents, inventory, created_at)
    manifest["report_rendering"] = renderer_record("computed_then_rendered")
    return _with_inventory(files, manifest, question_map_bytes)


def render_only_files(output_dir: Path) -> tuple[dict[str, bytes], dict]:
    """Re-render the report from the saved JSON; returns the report, manifest and checksums bytes."""
    output_dir = Path(output_dir)
    checksums = read_checksums(output_dir)
    verified = verify_inputs_against_checksums(output_dir, checksums)
    documents, question_map_bytes = load_documents(output_dir)
    recorded = g(documents, "frozen_config", "question_map", "sha256")
    if question_map_bytes is not None and recorded != sha256_bytes(question_map_bytes):
        raise ReportInputError(f"{QUESTION_MAP} differs from the digest recorded in frozen-config")
    manifest_path = output_dir / MANIFEST_FILE
    if not manifest_path.is_file():
        raise ReportInputError(f"{MANIFEST_FILE} is missing; recompute instead of re-rendering")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = render_report(documents, question_map_bytes)
    synthesis._scan(REPORT_FILE, report)
    report_bytes = report.encode("utf-8")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not any(isinstance(a, dict) and a.get("path") == REPORT_FILE for a in artifacts):
        raise ReportInputError(f"{MANIFEST_FILE} lists no {REPORT_FILE} artifact")
    manifest["artifacts"] = [
        synthesis._artifact(REPORT_FILE, report_bytes) if isinstance(a, dict) and a.get("path") == REPORT_FILE else a
        for a in artifacts
    ]
    manifest["report_rendering"] = renderer_record("render_only_from_saved_json")
    disk = {
        path: (output_dir / path).read_bytes()
        for path in checksums
        if path not in (REPORT_FILE, MANIFEST_FILE, CHECKSUMS_FILE, QUESTION_MAP)
    }
    files = _with_inventory({REPORT_FILE: report_bytes}, manifest, question_map_bytes, disk)
    previous = output_dir / REPORT_FILE
    summary = {
        "inputs_verified_against_checksums": verified,
        "previous_report_matched_checksum": (
            previous.is_file() and sha256_bytes(previous.read_bytes()) == checksums.get(REPORT_FILE)
        ),
        "report_sha256": sha256_bytes(report_bytes),
    }
    return files, summary
