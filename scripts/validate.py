#!/usr/bin/env python3
"""Validate every structural and factual claim this repository makes.

What this checks
----------------
1. **Playbook frontmatter** against a schema: required keys, enumerated values, ID and filename
   consistency, and that declared surface files exist.
2. **ATT&CK correctness** against the pinned MITRE snapshot: every technique ID exists, is neither
   revoked nor deprecated, the declared primary tactic is one the technique actually belongs to,
   and every referenced Detection Strategy (DET) is genuinely linked to that technique upstream.
3. **Atomic Red Team GUIDs** against the pinned upstream index, including that the referenced test
   belongs to a technique the playbook claims.
4. **Sigma rules**: parseable by the evaluation engine, required fields present, valid UUIDs, unique
   IDs and correlation names, enumerated status and level, ISO dates, ATT&CK tags consistent with
   the playbook's frontmatter, non-empty false positives, and no unreferenced selections.
5. **KQL**: header block, bounded lookback, analyst-facing projection, ATT&CK reference, and no
   unbounded `search` scans.
6. **Tests**: a fixture exists for every rule file and points at the right rule.
7. **Documentation**: required sections in every playbook, resolvable relative links, and no
   personal contact details left in a public repository.

Usage
-----
    python3 scripts/validate.py           # full validation
    python3 scripts/validate.py --quiet   # errors only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sigma_eval import SigmaSyntaxError, load_rule_file  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"
KQL_DIR = ROOT / "queries" / "kql"
SIGMA_DIR = ROOT / "rules" / "sigma"
TEST_DIR = ROOT / "tests" / "rules"
ATTACK_SNAPSHOT = ROOT / "mappings" / "attack-reference.json"
ATOMIC_SNAPSHOT = ROOT / "validation" / "atomic-index.json"

REQUIRED_SECTIONS = (
    "## Hypothesis",
    "## Why this matters",
    "## ATT&CK alignment",
    "## Telemetry requirements",
    "## Analytic approach",
    "### Tunable parameters",
    "## Query surfaces",
    "## Unit tests",
    "## Triage workflow",
    "## Benign explanations",
    "## Escalation criteria",
    "## Response considerations",
    "## Purple-team validation",
    "## Limitations and blind spots",
    "## Related playbooks",
    "## Change log",
)
REQUIRED_FRONTMATTER = (
    "id", "name", "title", "summary", "status", "severity", "confidence", "version",
    "created", "updated", "review_cadence", "owner", "platforms", "attack", "telemetry",
    "surfaces", "related", "tags",
)
STATUS_VALUES = {"hunt", "production-candidate", "production"}
SEVERITY_VALUES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
SIGMA_LEVEL = {"informational", "low", "medium", "high", "critical"}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
# pySigma accepts only the quantifiers 1, any and all. Anything else is
# specification-legal and unconvertible.
UNPORTABLE_QUANTIFIER_RE = re.compile(r"(?<![\w.])(?!1\b)\d+\s+of\s+", re.I)
# Directory names that are never repository content. Everything the validator walks
# must be authored here, or the results depend on the machine rather than the repo.
IGNORED_TREES = frozenset(
    {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "site", "site-src", "dist", "templates"}
)
# Personal details that belong on a CV, not in a public repository.
CONTACT_PATTERNS = (
    (re.compile(r"\+\d{2,3}[\s-]?\d[\d\s-]{7,}"), "telephone number"),
    (re.compile(r"[\w.+-]+@(?:gmail|outlook|hotmail|yahoo|proton(?:mail)?)\.[a-z]{2,}", re.I), "personal email address"),
)
ALLOWED_CONTACT_FILES = {"CITATION.cff"}


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.checks = 0

    def check(self, condition: bool, message: str) -> bool:
        self.checks += 1
        if not condition:
            self.errors.append(message)
        return condition

    def warn(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            self.warnings.append(message)


def load_yaml(text: str) -> Any:
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:  # pragma: no cover - guidance path
        raise SystemExit("PyYAML is required: pip install -r requirements-dev.txt") from None
    return yaml.safe_load(text)


def parse_playbook(path: Path) -> tuple[dict[str, Any] | None, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None, text
    _, frontmatter, body = text.split("---", 2)
    data = load_yaml(frontmatter)
    return (data if isinstance(data, dict) else None), body


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def validate_playbooks(report: Report, reference: dict[str, Any], atomics: dict[str, Any]) -> dict[str, Any]:
    paths = sorted(PLAYBOOKS.glob("TH-*.md"))
    report.check(bool(paths), "no playbooks found")

    known_ids = {path.name[:6] for path in paths}
    collected: dict[str, Any] = {}
    guid_to_technique = {
        guid: tid
        for tid, tests in atomics.get("techniques", {}).items()
        for guid in tests
    }

    expected_ids = {f"TH-{index:03d}" for index in range(1, len(paths) + 1)}
    report.check(
        known_ids == expected_ids,
        f"playbook IDs are not contiguous: missing {sorted(expected_ids - known_ids)}, "
        f"unexpected {sorted(known_ids - expected_ids)}",
    )

    for path in paths:
        name = path.name
        data, body = parse_playbook(path)
        if not report.check(data is not None, f"{name}: missing or invalid YAML frontmatter"):
            continue
        collected[str(data.get("id"))] = data

        missing = [key for key in REQUIRED_FRONTMATTER if key not in data]
        report.check(not missing, f"{name}: frontmatter missing keys {missing}")
        if missing:
            continue

        playbook_id = str(data["id"])
        report.check(name.startswith(playbook_id), f"{name}: filename does not start with id {playbook_id}")
        report.check(
            name == f"{playbook_id}-{data['name']}.md",
            f"{name}: filename should be {playbook_id}-{data['name']}.md",
        )
        report.check(
            body.lstrip().startswith(f"# {playbook_id} —"),
            f"{name}: body must start with '# {playbook_id} —'",
        )
        report.check(str(data["status"]) in STATUS_VALUES, f"{name}: invalid status {data['status']!r}")
        report.check(str(data["severity"]) in SEVERITY_VALUES, f"{name}: invalid severity {data['severity']!r}")
        report.check(
            str(data["confidence"]) in CONFIDENCE_VALUES, f"{name}: invalid confidence {data['confidence']!r}"
        )
        for key in ("created", "updated"):
            value = data[key]
            report.check(
                isinstance(value, date) or DATE_RE.match(str(value)) is not None,
                f"{name}: {key} must be an ISO date, got {value!r}",
            )
        report.check(
            isinstance(data["platforms"], list) and bool(data["platforms"]),
            f"{name}: platforms must be a non-empty list",
        )
        report.check(
            len(str(data["summary"])) <= 200, f"{name}: summary should be one line (<=200 chars)"
        )

        for section in REQUIRED_SECTIONS:
            report.check(section in body, f"{name}: missing section {section}")

        # Surfaces exist and follow the naming convention.
        surfaces = data["surfaces"]
        for key, expected_dir, suffix in (
            ("kql", "queries/kql", ".kql"),
            ("sigma", "rules/sigma", ".yml"),
            ("tests", "tests/rules", ".yml"),
        ):
            declared = str(surfaces.get(key, ""))
            target = ROOT / declared
            report.check(target.exists(), f"{name}: declared {key} surface missing: {declared}")
            report.check(
                declared == f"{expected_dir}/{path.stem}{suffix}",
                f"{name}: {key} surface should be {expected_dir}/{path.stem}{suffix}, got {declared}",
            )

        # Telemetry must state what is required.
        telemetry = data["telemetry"]
        report.check(
            isinstance(telemetry, dict) and bool(telemetry.get("required")),
            f"{name}: telemetry.required must list at least one source",
        )

        # ATT&CK correctness.
        attack = data["attack"]
        techniques = attack.get("techniques") or []
        primary = attack.get("primary_technique")
        report.check(bool(techniques), f"{name}: attack.techniques is empty")
        report.check(primary in techniques, f"{name}: primary_technique {primary!r} not in techniques")
        for tid in techniques:
            info = reference["techniques"].get(tid)
            if not report.check(info is not None, f"{name}: unknown ATT&CK technique {tid}"):
                continue
            report.check(not info["revoked"], f"{name}: technique {tid} is revoked in ATT&CK")
            report.check(not info["deprecated"], f"{name}: technique {tid} is deprecated in ATT&CK")
        primary_info = reference["techniques"].get(primary, {})
        primary_tactic = attack.get("primary_tactic")
        report.check(
            primary_tactic in (primary_info.get("tactic_shortnames") or []),
            f"{name}: primary_tactic {primary_tactic!r} is not a tactic of {primary} "
            f"({primary_info.get('tactic_shortnames')})",
        )
        valid_strategies = {
            strategy["id"]
            for tid in techniques
            for strategy in reference["techniques"].get(tid, {}).get("detection_strategies", [])
        }
        for det in attack.get("detection_strategies", []) or []:
            report.check(
                det in valid_strategies,
                f"{name}: detection strategy {det} is not linked to {techniques} in ATT&CK "
                f"(valid: {sorted(valid_strategies)})",
            )

        # Atomic Red Team GUIDs.
        for guid in (data.get("validation", {}) or {}).get("atomics") or []:
            tid = guid_to_technique.get(guid)
            if not report.check(tid is not None, f"{name}: unknown Atomic Red Team GUID {guid}"):
                continue
            report.warn(
                tid in techniques,
                f"{name}: atomic {guid} belongs to {tid}, which the playbook does not claim",
            )

        # Cross-references.
        for related in data.get("related") or []:
            report.check(related in known_ids, f"{name}: related playbook {related} does not exist")
        report.check(playbook_id not in (data.get("related") or []), f"{name}: playbook lists itself as related")

    return collected


def validate_kql(report: Report) -> None:
    for path in sorted(KQL_DIR.glob("TH-*.kql")):
        text = path.read_text(encoding="utf-8")
        name = path.name
        playbook_id = name[:6]
        report.check(text.startswith(f"// {playbook_id} | Surface:"), f"{name}: missing surface header")
        report.check("// Purpose:" in text, f"{name}: missing purpose comment")
        report.check("// Required data:" in text, f"{name}: missing required-data comment")
        report.check("// ATT&CK:" in text, f"{name}: missing ATT&CK reference comment")
        report.check("// Tunable:" in text, f"{name}: missing tunable-parameter comment")
        report.check(
            "ago(" in text or "starttime=" in text, f"{name}: query is not bounded by a lookback"
        )
        report.check("| project" in text, f"{name}: no analyst-facing projection")
        active = "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))
        report.check(
            not re.search(r"^\s*search\s+", active, re.MULTILINE),
            f"{name}: unbounded 'search' is not permitted; name the table explicitly",
        )
        report.warn(
            "| order by" in text, f"{name}: no ordering - results will be hard to triage"
        )
        for line_number, line in enumerate(text.splitlines(), start=1):
            report.warn(len(line) <= 120, f"{name}:{line_number}: line exceeds 120 characters")


def validate_sigma(report: Report, playbooks: dict[str, Any]) -> None:
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}

    for path in sorted(SIGMA_DIR.glob("TH-*.yml")):
        name = path.name
        playbook_id = name[:6]
        playbook = playbooks.get(playbook_id)
        try:
            detections, correlations = load_rule_file(path)
        except (SigmaSyntaxError, ValueError) as exc:
            report.check(False, f"{name}: rule does not parse: {exc}")
            continue

        report.check(bool(detections), f"{name}: contains no detection rule")

        declared_techniques = set((playbook or {}).get("attack", {}).get("techniques", []))
        for rule in detections + correlations:
            raw = rule.raw
            label = f"{name}::{rule.identifier}"
            for key in ("title", "id", "status", "description", "author", "date", "tags", "falsepositives", "level"):
                report.check(key in raw, f"{label}: missing Sigma field {key!r}")
            rule_id = str(raw.get("id", ""))
            report.check(bool(UUID_RE.match(rule_id)), f"{label}: id is not a valid UUID: {rule_id!r}")
            if rule_id in seen_ids:
                report.check(False, f"{label}: duplicate Sigma id, also used by {seen_ids[rule_id]}")
            seen_ids[rule_id] = label
            if "name" in raw:
                rule_name = str(raw["name"])
                if rule_name in seen_names:
                    report.check(False, f"{label}: duplicate rule name {rule_name!r} ({seen_names[rule_name]})")
                seen_names[rule_name] = label

            report.check(str(raw.get("status")) in SIGMA_STATUS, f"{label}: invalid status {raw.get('status')!r}")
            report.check(str(raw.get("level")) in SIGMA_LEVEL, f"{label}: invalid level {raw.get('level')!r}")
            for key in ("date", "modified"):
                if key in raw:
                    value = raw[key]
                    report.check(
                        isinstance(value, date) or DATE_RE.match(str(value)) is not None,
                        f"{label}: {key} must be an ISO date, got {value!r}",
                    )
            report.check(
                isinstance(raw.get("falsepositives"), list) and bool(raw["falsepositives"]),
                f"{label}: falsepositives must be a non-empty list",
            )
            report.check(
                len(str(raw.get("description", ""))) >= 80,
                f"{label}: description is too short to be useful",
            )
            references = raw.get("references") or []
            report.check(bool(references), f"{label}: no references")

            tags = [str(tag) for tag in raw.get("tags", [])]
            technique_tags = {tag for tag in tags if TECHNIQUE_TAG_RE.match(tag)}
            report.check(bool(technique_tags), f"{label}: no attack.tXXXX technique tag")
            for tag in technique_tags:
                tid = tag.replace("attack.t", "T").upper().replace("ATTACK.T", "T")
                tid = "T" + tag.split("attack.t")[1]
                report.check(
                    tid.upper() in {value.upper() for value in declared_techniques},
                    f"{label}: tag {tag} is not declared in {playbook_id} frontmatter "
                    f"({sorted(declared_techniques)})",
                )

            if isinstance(rule.raw.get("detection"), dict):
                report.warn(
                    not getattr(rule, "unused_selections", []),
                    f"{label}: detection blocks not referenced by the condition: "
                    f"{getattr(rule, 'unused_selections', [])}",
                )
                # The specification allows `N of <pattern>`, but pySigma's grammar is
                # quantifier = Keyword("1") | Keyword("any") | Keyword("all"), so any
                # other quantifier converts in no backend. The engine in this
                # repository is more permissive than the reference implementation, so
                # this is checked here rather than discovered at conversion time.
                condition = str(rule.raw["detection"].get("condition", ""))
                for quantifier in UNPORTABLE_QUANTIFIER_RE.findall(condition):
                    report.check(
                        False,
                        f"{label}: quantifier {quantifier.strip()!r} is valid Sigma but "
                        f"unsupported by pySigma; use 1 of / any of / all of, or expand "
                        f"the threshold into explicit terms",
                    )

        # Correlation rules must reference base rules that exist in the same file.
        base_names = {str(rule.raw.get("name")) for rule in detections if "name" in rule.raw}
        for correlation in correlations:
            for referenced in correlation.referenced_rules:
                report.check(
                    referenced in base_names,
                    f"{name}::{correlation.identifier}: correlation references unknown rule {referenced!r}",
                )
            report.check(
                "timespan" in correlation.spec, f"{name}::{correlation.identifier}: correlation needs a timespan"
            )


def validate_tests(report: Report) -> None:
    rule_files = {path.stem for path in SIGMA_DIR.glob("TH-*.yml")}
    fixture_files = {path.stem for path in TEST_DIR.glob("TH-*.yml")}
    for missing in sorted(rule_files - fixture_files):
        report.check(False, f"{missing}: Sigma rule has no test fixture")
    for orphan in sorted(fixture_files - rule_files):
        report.check(False, f"{orphan}: test fixture has no matching Sigma rule")

    for path in sorted(TEST_DIR.glob("TH-*.yml")):
        fixture = load_yaml(path.read_text(encoding="utf-8"))
        report.check(isinstance(fixture, dict), f"{path.name}: fixture is not a mapping")
        if not isinstance(fixture, dict):
            continue
        report.check(
            str(fixture.get("rule", path.stem)) == path.stem,
            f"{path.name}: 'rule' must match the fixture filename",
        )
        cases = fixture.get("cases") or []
        report.check(bool(cases), f"{path.name}: no cases defined")
        report.check(
            bool(str(fixture.get("description", "")).strip()),
            f"{path.name}: fixture needs a description explaining what the cases prove",
        )
        for case in cases:
            report.check("name" in case, f"{path.name}: a case has no name")
            report.check(
                ("event" in case) ^ ("events" in case),
                f"{path.name} [{case.get('name')}]: define exactly one of 'event' or 'events'",
            )


def validate_links_and_privacy(report: Report) -> None:
    for path in sorted(ROOT.rglob("*.md")):
        # templates/ contains deliberate TH-0NN placeholders, so its links cannot resolve.
        # The rest are not repository content: a virtualenv created in-tree (which this
        # repository's own quick start suggests) carries thousands of vendored package
        # READMEs, and scanning them makes the assertion count depend on which machine
        # ran the check and lets a third-party file fail the build for a contact string
        # that is not ours.
        if set(path.parts) & IGNORED_TREES:
            continue
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        for target in LINK_RE.findall(text):
            clean = target.split("#", 1)[0].strip()
            if not clean or clean.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (path.parent / clean).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                report.check(False, f"{relative}: link escapes the repository: {target}")
                continue
            report.check(resolved.exists(), f"{relative}: broken relative link: {target}")

        if relative.name in ALLOWED_CONTACT_FILES:
            continue
        for pattern, description in CONTACT_PATTERNS:
            match = pattern.search(text)
            report.check(
                match is None,
                f"{relative}: {description} found in a public file: {match.group(0) if match else ''}",
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="print errors only")
    args = parser.parse_args()

    report = Report()
    reference = json.loads(ATTACK_SNAPSHOT.read_text(encoding="utf-8"))
    atomics = json.loads(ATOMIC_SNAPSHOT.read_text(encoding="utf-8"))

    playbooks = validate_playbooks(report, reference, atomics)
    validate_kql(report)
    validate_sigma(report, playbooks)
    validate_tests(report)
    validate_links_and_privacy(report)

    if report.warnings and not args.quiet:
        print(f"{len(report.warnings)} warning(s):")
        for warning in report.warnings:
            print(f" - {warning}")
        print()

    if report.errors:
        print(f"Validation FAILED with {len(report.errors)} error(s):")
        for error in report.errors:
            print(f" - {error}")
        return 1

    print(
        f"Validation passed: {len(playbooks)} playbooks, "
        f"{len(list(KQL_DIR.glob('TH-*.kql')))} KQL hunts, "
        f"{len(list(SIGMA_DIR.glob('TH-*.yml')))} Sigma files, "
        f"{len(list(TEST_DIR.glob('TH-*.yml')))} fixtures, "
        f"{report.checks} assertions, ATT&CK v{reference['attack_version']}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
