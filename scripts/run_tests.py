#!/usr/bin/env python3
"""Run the Sigma unit-test suite for this repository.

Every Sigma rule ships with synthetic events that assert two things:

* the rule fires on the behaviour it claims to detect (true positive), and
* the rule stays quiet on the benign lookalike that generated the tuning note
  (false positive).

The suite fails if a rule has no true-positive case, no false-positive case, or
if any case produces the wrong verdict. Fixtures live in ``tests/rules/``.

Usage
-----
    python3 scripts/run_tests.py             # run the suite
    python3 scripts/run_tests.py -v          # list every case
    python3 scripts/run_tests.py --selftest  # exercise the evaluation engine itself
    python3 scripts/run_tests.py --rule TH-018
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sigma_eval import (  # noqa: E402
    CorrelationRule,
    SigmaRule,
    SigmaSyntaxError,
    evaluate_correlation,
    load_rule_file,
    parse_timespan,
    wildcard_to_regex,
)

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "sigma"
FIXTURES = ROOT / "tests" / "rules"

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def load_yaml(path: Path) -> Any:
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:  # pragma: no cover - guidance path
        raise SystemExit("PyYAML is required: pip install -r requirements-dev.txt") from None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def pick_rule(candidates: list[SigmaRule], target: str | None) -> SigmaRule:
    if target is None:
        if len(candidates) != 1:
            raise SigmaSyntaxError(
                "the rule file contains several detection rules; add 'target: <rule name or id>'"
            )
        return candidates[0]
    for rule in candidates:
        identifiers = {
            str(rule.raw.get("name", "")),
            str(rule.raw.get("id", "")),
            str(rule.raw.get("title", "")),
        }
        if target in identifiers:
            return rule
    raise SigmaSyntaxError(f"no detection rule matches target {target!r}")


def pick_correlation(candidates: list[CorrelationRule], target: str | None) -> CorrelationRule:
    if target is None:
        if len(candidates) != 1:
            raise SigmaSyntaxError(
                "the rule file contains several correlation rules; add 'target: <rule name or id>'"
            )
        return candidates[0]
    for rule in candidates:
        identifiers = {
            str(rule.raw.get("name", "")),
            str(rule.raw.get("id", "")),
            str(rule.raw.get("title", "")),
        }
        if target in identifiers:
            return rule
    raise SigmaSyntaxError(f"no correlation rule matches target {target!r}")


def run_suite(selected: str | None, verbose: bool) -> int:
    if not FIXTURES.exists():
        print("No fixtures directory found", file=sys.stderr)
        return 1

    fixture_files = sorted(FIXTURES.glob("TH-*.yml"))
    if selected:
        fixture_files = [path for path in fixture_files if selected in path.name]
    if not fixture_files:
        print("No fixtures matched", file=sys.stderr)
        return 1

    failures: list[str] = []
    total_cases = 0
    covered: dict[str, dict[str, int]] = {}

    for fixture_path in fixture_files:
        fixture = load_yaml(fixture_path)
        rule_stem = fixture.get("rule") or fixture_path.stem
        rule_path = RULES / f"{rule_stem}.yml"
        if not rule_path.exists():
            failures.append(f"{fixture_path.name}: rule file {rule_path.name} not found")
            continue

        try:
            detections, correlations = load_rule_file(rule_path)
        except SigmaSyntaxError as exc:
            failures.append(f"{rule_path.name}: {exc}")
            continue

        for rule in detections + correlations:
            covered.setdefault(f"{rule_path.name}::{rule.identifier}", {"match": 0, "no_match": 0})

        print(f"\n{rule_path.name}")
        base_rules = {rule.identifier: rule for rule in detections}

        for case in fixture.get("cases", []):
            total_cases += 1
            name = case.get("name", "<unnamed case>")
            expect = case.get("expect")
            if expect not in ("match", "no_match"):
                failures.append(f"{fixture_path.name} [{name}]: expect must be match or no_match")
                continue

            try:
                if "events" in case:
                    correlation = pick_correlation(correlations, case.get("target"))
                    hits = evaluate_correlation(
                        correlation,
                        base_rules,
                        case["events"],
                        case.get("timestamp_field", "timestamp"),
                    )
                    observed = "match" if hits else "no_match"
                    identity = f"{rule_path.name}::{correlation.identifier}"
                    detail = f"{len(hits)} correlation hit(s)"
                else:
                    rule = pick_rule(detections, case.get("target"))
                    fired = rule.matches(case["event"])
                    observed = "match" if fired else "no_match"
                    identity = f"{rule_path.name}::{rule.identifier}"
                    detail = "rule fired" if fired else "rule silent"
            except (SigmaSyntaxError, KeyError, ValueError) as exc:
                failures.append(f"{fixture_path.name} [{name}]: {type(exc).__name__}: {exc}")
                print(f"  {colour('ERROR', RED)}  {name}: {exc}")
                continue

            covered.setdefault(identity, {"match": 0, "no_match": 0})[expect] += 1

            if observed == expect:
                if verbose:
                    print(f"  {colour('pass', GREEN)}   {name} ({detail})")
            else:
                failures.append(
                    f"{fixture_path.name} [{name}]: expected {expect}, observed {observed}"
                )
                print(f"  {colour('FAIL', RED)}   {name}: expected {expect}, observed {observed}")

        if not verbose:
            case_count = len(fixture.get("cases", []))
            print(f"  {colour('ok', GREEN)}     {case_count} case(s)")

    uncovered = [
        f"{identity}: missing {'true-positive' if counts['match'] == 0 else 'false-positive'} case"
        for identity, counts in sorted(covered.items())
        if counts["match"] == 0 or counts["no_match"] == 0
    ]

    print()
    if failures or uncovered:
        for problem in failures + uncovered:
            print(f" - {problem}")
        print(
            colour(
                f"\nFAILED: {len(failures)} failing case(s), {len(uncovered)} rule(s) without full coverage",
                RED,
            )
        )
        return 1

    print(
        colour(
            f"PASSED: {total_cases} case(s) across {len(covered)} Sigma rule document(s); "
            "every rule has true-positive and false-positive coverage.",
            GREEN,
        )
    )
    return 0


# --------------------------------------------------------------------------- #
# Engine self-tests: the test harness has to be trustworthy too.
# --------------------------------------------------------------------------- #
def selftest() -> int:  # noqa: PLR0915
    checks: list[tuple[str, bool]] = []

    def check(label: str, condition: bool) -> None:
        checks.append((label, condition))

    def rule(detection: dict[str, Any]) -> SigmaRule:
        return SigmaRule({"title": "t", "id": "x", "detection": detection})

    contains = rule({"sel": {"CommandLine|contains": "lsass"}, "condition": "sel"})
    check("contains matches substring", contains.matches({"CommandLine": "dump LSASS.exe now"}))
    check("contains is case-insensitive", contains.matches({"CommandLine": "LSASS"}))
    check("contains rejects absent field", not contains.matches({"Image": "x"}))

    wildcard = rule({"sel": {"Image": "*\\schtasks.exe"}, "condition": "sel"})
    check("wildcard suffix match", wildcard.matches({"Image": "C:\\Windows\\System32\\schtasks.exe"}))
    check("wildcard rejects other path", not wildcard.matches({"Image": "C:\\schtasks.exe.bak"}))

    escaped = rule({"sel": {"CommandLine": "value\\*literal"}, "condition": "sel"})
    check("escaped asterisk is literal", escaped.matches({"CommandLine": "value*literal"}))
    check("escaped asterisk is not a wildcard", not escaped.matches({"CommandLine": "valueXliteral"}))

    listed = rule({"sel": {"EventID": [4728, 4732]}, "condition": "sel"})
    check("value list is an OR", listed.matches({"EventID": 4732}))
    check("value list rejects other values", not listed.matches({"EventID": 4740}))
    check("numeric values compare as strings too", listed.matches({"EventID": "4728"}))

    all_mod = rule({"sel": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "sel"})
    check("all modifier requires every value", all_mod.matches({"CommandLine": "pwsh -enc AAA -w hidden"}))
    check("all modifier fails on partial", not all_mod.matches({"CommandLine": "pwsh -enc AAA"}))

    negated = rule(
        {
            "sel": {"EventID": 4624},
            "filter": {"TargetUserName|endswith": "$"},
            "condition": "sel and not filter",
        }
    )
    check("negation filters machine accounts", not negated.matches({"EventID": 4624, "TargetUserName": "PC1$"}))
    check("negation keeps user accounts", negated.matches({"EventID": 4624, "TargetUserName": "alice"}))

    quantifier = rule(
        {
            "sel_a": {"A": "1"},
            "sel_b": {"B": "1"},
            "sel_c": {"C": "1"},
            "condition": "2 of sel_*",
        }
    )
    check("N of pattern needs N hits", quantifier.matches({"A": "1", "C": "1"}))
    check("N of pattern rejects one hit", not quantifier.matches({"A": "1"}))

    them = rule({"sel_a": {"A": "1"}, "sel_b": {"B": "1"}, "condition": "all of them"})
    check("all of them requires both", them.matches({"A": "1", "B": "1"}))
    check("all of them rejects one", not them.matches({"A": "1"}))

    regex = rule({"sel": {"CommandLine|re": r"-e(nc)?\s+[A-Za-z0-9+/]{20,}"}, "condition": "sel"})
    check("regex modifier matches", regex.matches({"CommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A"}))
    check("regex modifier rejects short", not regex.matches({"CommandLine": "powershell -enc AAA"}))

    cidr = rule({"sel": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "sel"})
    check("cidr matches inside range", cidr.matches({"SourceIp": "10.4.5.6"}))
    check("cidr rejects outside range", not cidr.matches({"SourceIp": "192.0.2.5"}))

    exists = rule({"sel": {"UserPrincipalName|exists": True}, "condition": "sel"})
    check("exists true when present", exists.matches({"UserPrincipalName": "a@b.c"}))
    check("exists false when absent", not exists.matches({"Other": 1}))

    nulled = rule({"sel": {"ParentImage": None}, "condition": "sel"})
    check("null matches missing field", nulled.matches({"Image": "x"}))
    check("null rejects present field", not nulled.matches({"ParentImage": "x"}))

    numeric = rule({"sel": {"Count|gte": 10}, "condition": "sel"})
    check("gte compares numerically", numeric.matches({"Count": 11}))
    check("gte rejects lower value", not numeric.matches({"Count": 9}))

    windash = rule({"sel": {"CommandLine|windash|contains": "-recurse"}, "condition": "sel"})
    check("windash accepts slash variant", windash.matches({"CommandLine": "cmd /recurse"}))

    dotted = rule({"sel": {"winlog.event_data.TargetUserName": "svc"}, "condition": "sel"})
    check("dotted path traverses nested events", dotted.matches({"winlog": {"event_data": {"TargetUserName": "svc"}}}))

    keywords = SigmaRule({"title": "t", "id": "x", "detection": {"keywords": ["mimikatz"], "condition": "keywords"}})
    check("keyword list searches all values", keywords.matches({"Message": "Invoke-Mimikatz ran"}))
    check("keyword list stays quiet otherwise", not keywords.matches({"Message": "nothing here"}))

    unsupported = False
    try:
        rule({"sel": {"Field|expand": "%x%"}, "condition": "sel"})
    except SigmaSyntaxError:
        unsupported = True
    check("unsupported modifiers raise instead of passing", unsupported)

    aggregation = False
    try:
        rule({"sel": {"A": 1}, "condition": "sel | count() > 5"})
    except SigmaSyntaxError:
        aggregation = True
    check("legacy aggregation is rejected", aggregation)

    check("timespan parsing", parse_timespan("15m").total_seconds() == 900)
    check("wildcard translation", wildcard_to_regex("a*b?c") == "a.*b.c")

    base = SigmaRule(
        {
            "title": "base",
            "name": "base_failed_logon",
            "id": "b",
            "detection": {"sel": {"EventID": 4625}, "condition": "sel"},
        }
    )
    value_count = CorrelationRule(
        {
            "title": "spray",
            "id": "c",
            "correlation": {
                "type": "value_count",
                "rules": ["base_failed_logon"],
                "group-by": ["SourceIp"],
                "timespan": "10m",
                "condition": {"field": "TargetUserName", "gte": 3},
            },
        }
    )
    spray_events = [
        {"timestamp": f"2026-09-01T10:0{index}:00Z", "EventID": 4625, "SourceIp": "198.51.100.9", "TargetUserName": f"user{index}"}
        for index in range(4)
    ]
    check("value_count fires on user fan-out", bool(evaluate_correlation(value_count, {"base_failed_logon": base}, spray_events)))

    repeated = [
        {"timestamp": f"2026-09-01T10:0{index}:00Z", "EventID": 4625, "SourceIp": "198.51.100.9", "TargetUserName": "same"}
        for index in range(6)
    ]
    check("value_count ignores repeats on one user", not evaluate_correlation(value_count, {"base_failed_logon": base}, repeated))

    slow = [
        {"timestamp": f"2026-09-01T{10 + index}:00:00Z", "EventID": 4625, "SourceIp": "198.51.100.9", "TargetUserName": f"user{index}"}
        for index in range(4)
    ]
    check("value_count respects the timespan", not evaluate_correlation(value_count, {"base_failed_logon": base}, slow))

    grouped = spray_events + [
        {"timestamp": "2026-09-01T10:05:00Z", "EventID": 4625, "SourceIp": "203.0.113.7", "TargetUserName": "solo"}
    ]
    hits = evaluate_correlation(value_count, {"base_failed_logon": base}, grouped)
    check("value_count groups by the group-by field", len(hits) == 1 and hits[0]["group"]["SourceIp"] == "198.51.100.9")

    ordered = CorrelationRule(
        {
            "title": "chain",
            "id": "d",
            "correlation": {
                "type": "temporal_ordered",
                "rules": ["first", "second"],
                "group-by": ["Host"],
                "timespan": "5m",
            },
        }
    )
    first = SigmaRule({"title": "1", "name": "first", "id": "1", "detection": {"sel": {"Stage": "one"}, "condition": "sel"}})
    second = SigmaRule({"title": "2", "name": "second", "id": "2", "detection": {"sel": {"Stage": "two"}, "condition": "sel"}})
    in_order = [
        {"timestamp": "2026-09-01T10:00:00Z", "Stage": "one", "Host": "h1"},
        {"timestamp": "2026-09-01T10:01:00Z", "Stage": "two", "Host": "h1"},
    ]
    reversed_order = [
        {"timestamp": "2026-09-01T10:00:00Z", "Stage": "two", "Host": "h1"},
        {"timestamp": "2026-09-01T10:01:00Z", "Stage": "one", "Host": "h1"},
    ]
    rules_map = {"first": first, "second": second}
    check("temporal_ordered honours order", bool(evaluate_correlation(ordered, rules_map, in_order)))
    check("temporal_ordered rejects wrong order", not evaluate_correlation(ordered, rules_map, reversed_order))

    failed = [label for label, ok in checks if not ok]
    for label, ok in checks:
        print(f"  {colour('pass', GREEN) if ok else colour('FAIL', RED)}   {label}")
    print()
    if failed:
        print(colour(f"Engine self-test FAILED: {len(failed)} of {len(checks)} checks", RED))
        return 1
    print(colour(f"Engine self-test passed: {len(checks)} checks", GREEN))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", help="only run fixtures whose filename contains this string")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every case")
    parser.add_argument("--selftest", action="store_true", help="test the evaluation engine itself")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    return run_suite(args.rule, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
