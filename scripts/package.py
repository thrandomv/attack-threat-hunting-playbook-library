#!/usr/bin/env python3
"""Build a reproducible release archive with a checksum and release notes.

Refuses to package content that has not passed validation and the unit-test suite: a release that
skipped its own checks is not a release.

Usage
-----
    python3 scripts/package.py            # validate, then build dist/<name>-v<version>.zip
    python3 scripts/package.py --skip-checks
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
NAME = "attack-threat-hunting-playbook-library"
EXCLUDE_DIRS = {".git", ".github/workflows/__pycache__", "dist", "site", "site-src", "__pycache__", ".venv", ".ruff_cache", ".mypy_cache"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def run(command: list[str]) -> None:
    print(f"$ {' '.join(command)}")
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(f"check failed: {' '.join(command)}")


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDE_DIRS for part in relative.parts):
        return False
    return path.suffix not in EXCLUDE_SUFFIXES


def release_notes(version: str) -> str:
    reference = json.loads((ROOT / "mappings" / "attack-reference.json").read_text(encoding="utf-8"))
    playbooks = len(list((ROOT / "playbooks").glob("TH-*.md")))
    fixtures = list((ROOT / "tests" / "rules").glob("TH-*.yml"))
    try:
        import yaml  # noqa: PLC0415

        cases = sum(len(yaml.safe_load(path.read_text(encoding="utf-8")).get("cases", [])) for path in fixtures)
    except ModuleNotFoundError:
        cases = 0
    return f"""# v{version}

{playbooks} ATT&CK-aligned threat-hunting playbooks with Microsoft KQL hunts and portable Sigma
detection and correlation rules, pinned to Enterprise ATT&CK v{reference['attack_version']}.

- Every Sigma rule ships with synthetic true-positive and false-positive unit tests: {cases} cases,
  executed in CI by the included Sigma evaluation engine (standard library plus PyYAML).
- ATT&CK technique, tactic and Detection Strategy references are validated against a pinned snapshot
  of the MITRE STIX bundle; Atomic Red Team GUIDs against a pinned snapshot of the upstream index.
- Coverage tables, the ATT&CK Navigator layer, the coverage matrix and the legacy-ID migration table
  are generated from playbook frontmatter, and CI fails if they drift.

Queries, thresholds and allowlists require validation against local telemetry before operational use.
See `CHANGELOG.md` for the full list of changes, including the detection bugs fixed in this release.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-checks", action="store_true", help="package without running the checks")
    args = parser.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    if not args.skip_checks:
        run([sys.executable, "scripts/run_tests.py", "--selftest"])
        run([sys.executable, "scripts/run_tests.py"])
        run([sys.executable, "scripts/validate.py"])
        run([sys.executable, "scripts/build.py", "--check"])

    DIST.mkdir(exist_ok=True)
    archive = DIST / f"{NAME}-v{version}.zip"
    files = sorted(path for path in ROOT.rglob("*") if path.is_file() and included(path))

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            # Deterministic archive: fixed timestamps, stable order, single root directory.
            info = zipfile.ZipInfo(f"{NAME}/{path.relative_to(ROOT).as_posix()}", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (DIST / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    (DIST / "RELEASE_NOTES.md").write_text(release_notes(version), encoding="utf-8")

    print(f"\nArchive: {archive.relative_to(ROOT)} ({archive.stat().st_size / 1024:.0f} KiB, {len(files)} files)")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
