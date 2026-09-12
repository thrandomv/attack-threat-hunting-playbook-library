#!/usr/bin/env python3
"""A small Sigma evaluation engine used to unit-test the rules in this repository.

Written against the Python standard library; PyYAML is used only to read rule and fixture files.

Why this exists
---------------
Detection content that has never been executed against an event is an
assertion, not a detection. Converting rules with ``sigma-cli`` proves they
*compile*; it does not prove they *fire on the behaviour* and *stay quiet on the
benign lookalike*. This module evaluates Sigma detection logic directly against
synthetic events so every rule in the library ships with true-positive and
false-positive tests that run in CI in under a second, with no SIEM involved.

Scope and honesty about limits
------------------------------
Implemented: field/value maps, value lists (OR), lists of maps (OR), keyword
lists, ``null`` values, wildcards (``*``/``?`` with backslash escaping),
case-insensitive matching by default, dotted field paths, and the modifiers
``contains``, ``startswith``, ``endswith``, ``all``, ``re`` (+ ``i``/``m``/``s``
flags), ``cased``, ``cidr``, ``exists``, ``windash``, ``lt``, ``lte``, ``gt``,
``gte``, ``base64offset|contains``. Condition grammar: ``and``, ``or``,
``not``, parentheses, ``N of pattern``, ``all of pattern``, ``... of them``.
Correlations: ``event_count``, ``value_count``, ``temporal``,
``temporal_ordered`` with ``group-by`` and ``timespan``.

Not implemented (deliberately): ``expand``, ``fieldref``, ``base64``/``utf16``
transformations beyond ``base64offset|contains``, backend-specific field
mapping, and legacy in-condition aggregations (``| count() > 5``). A rule using
an unsupported construct raises ``UnsupportedSigmaFeature`` instead of silently
passing, so the test suite can never report a green run it did not earn.

This engine models Sigma semantics, not any particular SIEM's execution engine.
Passing tests mean the logic is sound; they do not replace validation in the
target platform.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "SigmaRule",
    "CorrelationRule",
    "UnsupportedSigmaFeature",
    "SigmaSyntaxError",
    "load_rule_file",
    "evaluate_correlation",
]


class SigmaSyntaxError(ValueError):
    """The rule is not valid Sigma as this engine understands it."""


class UnsupportedSigmaFeature(SigmaSyntaxError):
    """The rule uses a construct this engine refuses to guess at."""


SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "i",
    "m",
    "s",
    "cased",
    "cidr",
    "exists",
    "windash",
    "lt",
    "lte",
    "gt",
    "gte",
    "base64offset",
}
TIMESPAN_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #
def parse_timespan(value: str | int) -> timedelta:
    """Parse a Sigma timespan such as ``15m`` into a :class:`timedelta`."""
    text = str(value).strip()
    match = re.fullmatch(r"(\d+)([smhdw]?)", text)
    if not match:
        raise SigmaSyntaxError(f"invalid timespan: {value!r}")
    amount, unit = int(match.group(1)), match.group(2) or "s"
    return timedelta(**{TIMESPAN_UNITS[unit]: amount})


def wildcard_to_regex(pattern: str) -> str:
    """Translate a Sigma wildcard string into a regular expression."""
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            nxt = pattern[index + 1] if index + 1 < len(pattern) else ""
            if nxt in ("*", "?", "\\"):
                out.append(re.escape(nxt))
                index += 2
                continue
            out.append(re.escape(char))
            index += 1
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1
    return "".join(out)


def windash_variants(value: str) -> list[str]:
    """Expand the Sigma ``windash`` modifier: interchangeable command-line dashes."""
    dashes = ["-", "/", "–", "—", "―"]
    variants = {value}
    for index, char in enumerate(value):
        if char in dashes:
            for replacement in dashes:
                variants.add(value[:index] + replacement + value[index + 1 :])
    return sorted(variants)


def base64offset_variants(value: str) -> list[str]:
    """Return the three base64 encodings of a value at byte offsets 0, 1 and 2."""
    raw = value.encode("utf-8")
    variants = []
    for offset in range(3):
        encoded = base64.b64encode(b"\x00" * offset + raw).decode("ascii")
        start = (offset * 8 + 5) // 6 if offset else 0
        end = len(encoded) - (len(encoded) % 4) if "=" in encoded else len(encoded)
        variants.append(encoded[start:end].rstrip("="))
    return variants


def as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True)
class FieldMatcher:
    """One ``field|modifiers: value`` expression from a Sigma detection."""

    field_path: str
    modifiers: tuple[str, ...]
    values: tuple[Any, ...]

    def matches(self, event: dict[str, Any]) -> bool:
        present, actual = lookup(event, self.field_path)
        mods = set(self.modifiers)

        if "exists" in mods:
            expected = self.values[0]
            expected_bool = expected if isinstance(expected, bool) else as_text(expected).lower() == "true"
            return present is expected_bool

        if not present:
            # ``field: null`` matches an absent field; everything else cannot match.
            return any(value is None for value in self.values)

        candidates = actual if isinstance(actual, (list, tuple)) else [actual]
        results = [
            any(self._match_single(candidate, expected) for candidate in candidates)
            for expected in self.values
        ]
        return all(results) if "all" in mods else any(results)

    def _match_single(self, actual: Any, expected: Any) -> bool:  # noqa: PLR0911
        mods = set(self.modifiers)

        if expected is None:
            return actual is None

        if mods & {"lt", "lte", "gt", "gte"}:
            try:
                left, right = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            if "lt" in mods:
                return left < right
            if "lte" in mods:
                return left <= right
            if "gt" in mods:
                return left > right
            return left >= right

        if "cidr" in mods:
            try:
                network = ipaddress.ip_network(str(expected), strict=False)
                return ipaddress.ip_address(as_text(actual)) in network
            except ValueError:
                return False

        if "re" in mods:
            flags = 0
            if "i" in mods:
                flags |= re.IGNORECASE
            if "m" in mods:
                flags |= re.MULTILINE
            if "s" in mods:
                flags |= re.DOTALL
            return re.search(str(expected), as_text(actual), flags) is not None

        if isinstance(expected, bool) or isinstance(actual, bool):
            return as_text(actual).lower() == as_text(expected).lower()

        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            try:
                return float(actual) == float(expected)
            except (TypeError, ValueError):
                return as_text(actual) == as_text(expected)

        expected_values = [str(expected)]
        if "windash" in mods:
            expected_values = windash_variants(str(expected))
        if "base64offset" in mods:
            if "contains" not in mods:
                raise UnsupportedSigmaFeature("base64offset requires the contains modifier")
            expected_values = [
                variant for value in expected_values for variant in base64offset_variants(value)
            ]

        haystack = as_text(actual)
        cased = "cased" in mods
        flags = 0 if cased else re.IGNORECASE

        for value in expected_values:
            pattern = wildcard_to_regex(value)
            if "contains" in mods and "base64offset" not in mods:
                pattern = f".*{pattern}.*"
            elif "startswith" in mods:
                pattern = f"{pattern}.*"
            elif "endswith" in mods:
                pattern = f".*{pattern}"
            elif "base64offset" in mods:
                pattern = f".*{pattern}.*"
            if re.fullmatch(pattern, haystack, flags | re.DOTALL) is not None:
                return True
        return False


def lookup(event: dict[str, Any], path: str) -> tuple[bool, Any]:
    """Resolve a field name, supporting dotted paths and case-insensitive keys."""
    if path in event:
        return True, event[path]
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict):
            if part in current:
                current = current[part]
                continue
            lowered = {key.lower(): key for key in current}
            if part.lower() in lowered:
                current = current[lowered[part.lower()]]
                continue
        return False, None
    return True, current


@dataclass(frozen=True)
class KeywordMatcher:
    """A bare keyword list: substring search across every value in the event."""

    values: tuple[Any, ...]

    def matches(self, event: dict[str, Any]) -> bool:
        haystack = " ".join(flatten_values(event)).lower()
        return any(
            re.search(wildcard_to_regex(str(value)).replace(r"\ ", " "), haystack, re.IGNORECASE)
            for value in self.values
        )


def flatten_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for inner in value.values() for item in flatten_values(inner)]
    if isinstance(value, (list, tuple)):
        return [item for inner in value for item in flatten_values(inner)]
    return [as_text(value)]


@dataclass(frozen=True)
class Selection:
    """A named block inside ``detection:``."""

    name: str
    matchers: tuple[Any, ...]
    combine_or: bool

    def matches(self, event: dict[str, Any]) -> bool:
        if self.combine_or:
            return any(matcher.matches(event) for matcher in self.matchers)
        return all(matcher.matches(event) for matcher in self.matchers)


def build_matchers(block: Any, name: str) -> Selection:
    if isinstance(block, dict):
        return Selection(name, tuple(build_field_matchers(block)), combine_or=False)
    if isinstance(block, list):
        if all(isinstance(item, dict) for item in block):
            inner = [
                Selection(f"{name}[{index}]", tuple(build_field_matchers(item)), combine_or=False)
                for index, item in enumerate(block)
            ]
            return Selection(name, tuple(inner), combine_or=True)
        return Selection(name, (KeywordMatcher(tuple(block)),), combine_or=True)
    raise SigmaSyntaxError(f"detection block {name!r} must be a map or a list")


def build_field_matchers(block: dict[str, Any]) -> Iterable[FieldMatcher]:
    for raw_field, raw_value in block.items():
        parts = str(raw_field).split("|")
        field_path, modifiers = parts[0], tuple(parts[1:])
        unknown = set(modifiers) - SUPPORTED_MODIFIERS
        if unknown:
            raise UnsupportedSigmaFeature(
                f"field {raw_field!r} uses unsupported modifier(s): {sorted(unknown)}"
            )
        values = tuple(raw_value) if isinstance(raw_value, list) else (raw_value,)
        yield FieldMatcher(field_path, modifiers, values)


# --------------------------------------------------------------------------- #
# Condition parsing
# --------------------------------------------------------------------------- #
TOKEN_RE = re.compile(r"\(|\)|\||[\w*.\-]+")


class ConditionParser:
    """Recursive-descent parser for the Sigma condition grammar."""

    def __init__(self, condition: str, selections: dict[str, Selection]) -> None:
        if "|" in condition:
            raise UnsupportedSigmaFeature(
                "in-condition aggregations are deprecated; express them as a correlation rule"
            )
        self.tokens = TOKEN_RE.findall(condition)
        self.position = 0
        self.selections = selections
        self.used: set[str] = set()

    # -- token helpers ----------------------------------------------------- #
    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def next_token(self) -> str:
        token = self.peek()
        if token is None:
            raise SigmaSyntaxError("unexpected end of condition")
        self.position += 1
        return token

    # -- grammar ----------------------------------------------------------- #
    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise SigmaSyntaxError(f"unparsed condition tokens near {self.peek()!r}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while (token := self.peek()) and token.lower() == "or":
            self.next_token()
            right = self.parse_and()
            node = ("or", node, right)
        return node

    def parse_and(self):
        node = self.parse_not()
        while (token := self.peek()) and token.lower() == "and":
            self.next_token()
            right = self.parse_not()
            node = ("and", node, right)
        return node

    def parse_not(self):
        token = self.peek()
        if token and token.lower() == "not":
            self.next_token()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        token = self.next_token()
        if token == "(":
            node = self.parse_or()
            closing = self.next_token()
            if closing != ")":
                raise SigmaSyntaxError("unbalanced parentheses in condition")
            return node
        lowered = token.lower()
        if lowered == "all" or lowered.isdigit():
            following = self.peek()
            if following and following.lower() == "of":
                self.next_token()
                pattern = self.next_token()
                return self.build_quantifier(lowered, pattern)
        if token not in self.selections:
            raise SigmaSyntaxError(f"condition references unknown selection {token!r}")
        self.used.add(token)
        return ("selection", token)

    def build_quantifier(self, quantifier: str, pattern: str):
        if pattern.lower() == "them":
            names = sorted(self.selections)
        else:
            regex = re.compile(wildcard_to_regex(pattern) + r"\Z")
            names = sorted(name for name in self.selections if regex.match(name))
        if not names:
            raise SigmaSyntaxError(f"quantifier '{quantifier} of {pattern}' matches no selection")
        self.used.update(names)
        required = len(names) if quantifier == "all" else int(quantifier)
        return ("quantifier", required, tuple(names))


def evaluate_node(node, selections: dict[str, Selection], event: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "selection":
        return selections[node[1]].matches(event)
    if kind == "and":
        return evaluate_node(node[1], selections, event) and evaluate_node(node[2], selections, event)
    if kind == "or":
        return evaluate_node(node[1], selections, event) or evaluate_node(node[2], selections, event)
    if kind == "not":
        return not evaluate_node(node[1], selections, event)
    if kind == "quantifier":
        _, required, names = node
        hits = sum(1 for name in names if selections[name].matches(event))
        return hits >= required
    raise SigmaSyntaxError(f"unknown condition node {kind!r}")


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@dataclass
class SigmaRule:
    """A parsed Sigma detection rule that can be evaluated against events."""

    raw: dict[str, Any]
    source: Path | None = None
    selections: dict[str, Selection] = field(default_factory=dict)
    condition_ast: Any = None
    timeframe: timedelta | None = None

    def __post_init__(self) -> None:
        detection = self.raw.get("detection")
        if not isinstance(detection, dict):
            raise SigmaSyntaxError(f"{self.identifier}: missing detection block")
        condition = detection.get("condition")
        if condition is None:
            raise SigmaSyntaxError(f"{self.identifier}: missing detection condition")
        if isinstance(condition, list):
            condition = " or ".join(f"({item})" for item in condition)
        for name, block in detection.items():
            if name in ("condition", "timeframe"):
                continue
            self.selections[name] = build_matchers(block, name)
        parser = ConditionParser(str(condition), self.selections)
        self.condition_ast = parser.parse()
        self.unused_selections = sorted(set(self.selections) - parser.used)
        if "timeframe" in detection:
            self.timeframe = parse_timespan(detection["timeframe"])

    @property
    def identifier(self) -> str:
        return str(self.raw.get("name") or self.raw.get("id") or self.raw.get("title") or "<rule>")

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))

    def matches(self, event: dict[str, Any]) -> bool:
        return evaluate_node(self.condition_ast, self.selections, event)


@dataclass
class CorrelationRule:
    """A Sigma correlation rule (``event_count``, ``value_count``, ``temporal``)."""

    raw: dict[str, Any]
    source: Path | None = None

    @property
    def identifier(self) -> str:
        return str(self.raw.get("name") or self.raw.get("id") or self.raw.get("title") or "<correlation>")

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))

    @property
    def spec(self) -> dict[str, Any]:
        return self.raw["correlation"]

    @property
    def referenced_rules(self) -> list[str]:
        rules = self.spec.get("rules", [])
        return [rules] if isinstance(rules, str) else list(rules)


def event_timestamp(event: dict[str, Any], field_name: str = "timestamp") -> datetime:
    present, value = lookup(event, field_name)
    if not present:
        raise SigmaSyntaxError(f"correlation test event is missing the {field_name!r} field")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def evaluate_correlation(
    correlation: CorrelationRule,
    base_rules: dict[str, SigmaRule],
    events: Sequence[dict[str, Any]],
    timestamp_field: str = "timestamp",
) -> list[dict[str, Any]]:
    """Return one entry per group that satisfies the correlation, oldest first."""
    spec = correlation.spec
    corr_type = str(spec.get("type", "")).lower()
    if corr_type not in {"event_count", "value_count", "temporal", "temporal_ordered"}:
        raise UnsupportedSigmaFeature(f"unsupported correlation type {corr_type!r}")

    missing = [name for name in correlation.referenced_rules if name not in base_rules]
    if missing:
        raise SigmaSyntaxError(f"{correlation.identifier}: unknown referenced rule(s) {missing}")

    timespan = parse_timespan(spec.get("timespan", "0s"))
    group_by = spec.get("group-by") or spec.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    condition = spec.get("condition") or {}

    tagged: list[tuple[datetime, tuple, dict[str, Any], str]] = []
    for event in events:
        for name in correlation.referenced_rules:
            if base_rules[name].matches(event):
                key_parts = []
                for group_field in group_by:
                    present, value = lookup(event, group_field)
                    key_parts.append(as_text(value) if present else None)
                if any(part is None for part in key_parts):
                    continue
                tagged.append((event_timestamp(event, timestamp_field), tuple(key_parts), event, name))
                break
    tagged.sort(key=lambda item: item[0])

    hits: list[dict[str, Any]] = []
    groups: dict[tuple, list[tuple[datetime, dict[str, Any], str]]] = {}
    for stamp, key, event, rule_name in tagged:
        groups.setdefault(key, []).append((stamp, event, rule_name))

    for key, entries in groups.items():
        for index, (start, _event, _name) in enumerate(entries):
            window = [item for item in entries[index:] if item[0] - start <= timespan]
            if not window:
                continue
            if corr_type == "event_count":
                measured: Any = len(window)
            elif corr_type == "value_count":
                target = condition.get("field")
                if not target:
                    raise SigmaSyntaxError(f"{correlation.identifier}: value_count needs condition.field")
                seen = set()
                for _stamp, event, _name in window:
                    present, value = lookup(event, target)
                    if present:
                        seen.add(as_text(value))
                measured = len(seen)
            else:  # temporal / temporal_ordered
                observed = [name for _stamp, _event, name in window]
                required = correlation.referenced_rules
                if corr_type == "temporal":
                    satisfied = set(required).issubset(set(observed))
                else:
                    position = 0
                    for name in observed:
                        if position < len(required) and name == required[position]:
                            position += 1
                    satisfied = position == len(required)
                if satisfied:
                    hits.append(
                        {
                            "group": dict(zip(group_by, key)),
                            "first_seen": window[0][0].isoformat(),
                            "last_seen": window[-1][0].isoformat(),
                            "events": len(window),
                            "rules": sorted(set(observed)),
                        }
                    )
                    break
                continue

            if satisfies_threshold(measured, condition):
                hits.append(
                    {
                        "group": dict(zip(group_by, key)),
                        "first_seen": window[0][0].isoformat(),
                        "last_seen": window[-1][0].isoformat(),
                        "events": len(window),
                        "measured": measured,
                    }
                )
                break
    return sorted(hits, key=lambda item: item["first_seen"])


def satisfies_threshold(value: float, condition: dict[str, Any]) -> bool:
    checks = {key: condition[key] for key in ("gt", "gte", "lt", "lte", "eq") if key in condition}
    if not checks:
        raise SigmaSyntaxError("correlation condition needs one of gt/gte/lt/lte/eq")
    for operator, threshold in checks.items():
        threshold = float(threshold)
        if operator == "gt" and not value > threshold:
            return False
        if operator == "gte" and not value >= threshold:
            return False
        if operator == "lt" and not value < threshold:
            return False
        if operator == "lte" and not value <= threshold:
            return False
        if operator == "eq" and not value == threshold:
            return False
    return True


def load_rule_file(path: Path) -> tuple[list[SigmaRule], list[CorrelationRule]]:
    """Parse a (possibly multi-document) Sigma YAML file."""
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:  # pragma: no cover - guidance path
        raise SystemExit("PyYAML is required: pip install -r requirements-dev.txt") from None

    documents = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
    detections: list[SigmaRule] = []
    correlations: list[CorrelationRule] = []
    for document in documents:
        if "correlation" in document:
            correlations.append(CorrelationRule(document, path))
        else:
            detections.append(SigmaRule(document, path))
    return detections, correlations
