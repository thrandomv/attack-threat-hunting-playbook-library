#!/usr/bin/env python3
"""Generate the pinned ATT&CK reference snapshot used by this repository.

The snapshot (``mappings/attack-reference.json``) is the authority that
``scripts/validate.py`` uses to check every technique ID, tactic name, and
detection-strategy reference in the library. Pinning a snapshot means CI does
not depend on network access and content review is a reviewable diff.

Source data: the official MITRE ATT&CK STIX 2.1 bundle published at
https://github.com/mitre-attack/attack-stix-data

Usage
-----
    python3 scripts/fetch_attack_reference.py                       # download and rebuild
    python3 scripts/fetch_attack_reference.py --bundle /tmp/ea.json # rebuild from a local bundle
    python3 scripts/fetch_attack_reference.py --check               # fail if the snapshot is stale

Only techniques referenced by the playbook library are retained, plus the full
revoked/deprecated technique map (ATT&CK v19 renumbered several long-lived IDs,
so operators migrating old content need that table).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"
SNAPSHOT = ROOT / "mappings" / "attack-reference.json"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def attack_url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def load_bundle(path: Path | None) -> dict[str, Any]:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    print(f"Downloading {BUNDLE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(BUNDLE_URL, timeout=300) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def referenced_techniques() -> set[str]:
    """Collect every technique ID declared in playbook frontmatter."""
    found: set[str] = set()
    for path in sorted(PLAYBOOKS.glob("TH-*.md")):
        text = path.read_text(encoding="utf-8")
        if not text.startswith("---"):
            continue
        frontmatter = text.split("---", 2)[1]
        block = re.search(r"(?ms)^attack:\s*\n(.*?)(?=^\S|\Z)", frontmatter)
        if block:
            found.update(TECHNIQUE_RE.findall(block.group(1)))
    return found


def build_snapshot(bundle: dict[str, Any], technique_ids: set[str]) -> dict[str, Any]:
    objects = bundle["objects"]
    by_uuid = {obj["id"]: obj for obj in objects}

    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})
    tactics = {}
    for obj in objects:
        if obj["type"] == "x-mitre-tactic" and not obj.get("x_mitre_deprecated"):
            tactics[external_id(obj)] = {
                "name": obj["name"],
                "shortname": obj["x_mitre_shortname"],
                "url": attack_url(obj),
            }
    shortname_to_tactic = {value["shortname"]: key for key, value in tactics.items()}

    patterns = {}
    for obj in objects:
        if obj["type"] == "attack-pattern":
            tid = external_id(obj)
            if tid:
                patterns[tid] = obj

    # Detection strategies (ATT&CK v19 object model) linked to each technique.
    strategies_by_technique: dict[str, list[dict[str, Any]]] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
            continue
        source = by_uuid.get(rel["source_ref"], {})
        target = by_uuid.get(rel["target_ref"], {})
        if source.get("type") != "x-mitre-detection-strategy":
            continue
        tid = external_id(target)
        if tid not in technique_ids:
            continue
        analytics = []
        for analytic_ref in source.get("x_mitre_analytic_refs", []):
            analytic = by_uuid.get(analytic_ref)
            if not analytic:
                continue
            analytics.append(
                {
                    "id": external_id(analytic),
                    "platforms": analytic.get("x_mitre_platforms", []),
                    "description": analytic.get("description", "").strip(),
                    "log_sources": sorted(
                        {
                            f"{item.get('name')}"
                            + (f" ({item['channel']})" if item.get("channel") else "")
                            for item in analytic.get("x_mitre_log_source_references", [])
                            if item.get("name")
                        }
                    ),
                    "mutable_elements": [
                        {
                            "field": item.get("field"),
                            "description": item.get("description", "").strip(),
                        }
                        for item in analytic.get("x_mitre_mutable_elements", [])
                    ],
                }
            )
        strategies_by_technique.setdefault(tid, []).append(
            {
                "id": external_id(source),
                "name": source.get("name"),
                "url": attack_url(source),
                "analytics": sorted(analytics, key=lambda item: item["id"] or ""),
            }
        )

    techniques: dict[str, Any] = {}
    for tid in sorted(technique_ids):
        obj = patterns.get(tid)
        if obj is None:
            raise SystemExit(f"Technique {tid} is not present in the ATT&CK bundle")
        phases = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        techniques[tid] = {
            "name": obj["name"],
            "url": attack_url(obj),
            "tactic_shortnames": phases,
            "tactics": [shortname_to_tactic.get(phase) for phase in phases],
            "tactic_names": [tactics.get(shortname_to_tactic.get(phase), {}).get("name") for phase in phases],
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "revoked": bool(obj.get("revoked")),
            "detection_strategies": sorted(
                strategies_by_technique.get(tid, []), key=lambda item: item["id"] or ""
            ),
        }

    revoked: dict[str, dict[str, str]] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "revoked-by":
            continue
        source = by_uuid.get(rel["source_ref"], {})
        target = by_uuid.get(rel["target_ref"], {})
        old, new = external_id(source), external_id(target)
        if old and new and source.get("type") == "attack-pattern":
            revoked[old] = {
                "old_name": source.get("name"),
                "replacement": new,
                "replacement_name": target.get("name"),
            }

    return {
        "_comment": (
            "Generated by scripts/fetch_attack_reference.py from the MITRE ATT&CK STIX bundle. "
            "Do not edit by hand. MITRE ATT&CK(R) content is (c) The MITRE Corporation; see NOTICE.md."
        ),
        "source": BUNDLE_URL,
        "attack_version": collection.get("x_mitre_version"),
        "collection_name": collection.get("name"),
        "collection_modified": collection.get("modified"),
        "tactics": dict(sorted(tactics.items())),
        "techniques": techniques,
        "revoked_techniques": dict(sorted(revoked.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="path to a local enterprise-attack.json")
    parser.add_argument("--check", action="store_true", help="fail if the snapshot would change")
    parser.add_argument(
        "--techniques",
        nargs="*",
        help="explicit technique IDs (default: every ID declared in playbook frontmatter)",
    )
    args = parser.parse_args()

    technique_ids = set(args.techniques or []) or referenced_techniques()
    if not technique_ids:
        raise SystemExit("No technique IDs found. Pass --techniques or add playbook frontmatter.")

    snapshot = build_snapshot(load_bundle(args.bundle), technique_ids)
    rendered = json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        current = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.exists() else ""
        if current != rendered:
            print("ATT&CK snapshot is stale; re-run scripts/fetch_attack_reference.py", file=sys.stderr)
            return 1
        print(f"ATT&CK snapshot current (v{snapshot['attack_version']}, {len(snapshot['techniques'])} techniques)")
        return 0

    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(rendered, encoding="utf-8")
    print(
        f"Wrote {SNAPSHOT.relative_to(ROOT)}: ATT&CK v{snapshot['attack_version']}, "
        f"{len(snapshot['techniques'])} techniques, "
        f"{sum(len(t['detection_strategies']) for t in snapshot['techniques'].values())} detection strategies, "
        f"{len(snapshot['revoked_techniques'])} revoked IDs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
