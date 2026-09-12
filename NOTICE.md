# Notices and attribution

## Trademarks

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. This project uses
ATT&CK identifiers, tactic names, technique names and Detection Strategy identifiers for defensive
mapping. Use of the framework does not imply MITRE review, endorsement or affiliation.

Microsoft, Microsoft Sentinel, Microsoft Defender, Windows, Entra and Azure are trademarks of the
Microsoft group of companies. Splunk, Elastic, IBM QRadar and other product names are trademarks of
their respective owners. Product names appear only to describe compatible telemetry and query
surfaces.

## Third-party content included in this repository

| Content | Source | Licence | Where |
|---|---|---|---|
| ATT&CK technique, tactic, Detection Strategy and Analytic metadata | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | ATT&CK [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | `mappings/attack-reference.json` (generated) |
| Atomic Red Team test names, GUIDs and platform metadata | [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | MIT (© Red Canary) | `validation/atomic-index.json` (generated) |

Both files are **generated** subsets, produced by `scripts/fetch_attack_reference.py` and
`scripts/fetch_atomic_index.py` respectively, and are included so validation and CI work without
network access. Neither contains attack tooling or payloads — only identifiers, names, platform lists
and descriptive metadata. Refresh them from upstream rather than editing them.

The Sigma rule format is maintained by the [SigmaHQ](https://sigmahq.io/) community; this repository
follows the published specification but contains no SigmaHQ rule content.

## Authoritative references

- [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/)
- [MITRE ATT&CK detection strategies](https://attack.mitre.org/detectionstrategies/)
- [Microsoft Defender XDR advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft Sentinel ASIM overview](https://learn.microsoft.com/azure/sentinel/normalization)
- [Sigma specification](https://sigmahq.io/sigma-specification/)

A fuller list is in [`docs/REFERENCES.md`](docs/REFERENCES.md).

## Provenance and freshness

Mappings are pinned to **Enterprise ATT&CK v19.2** (collection modified 2026-08-05) and were last
regenerated on 2026-09-10. ATT&CK, product schemas and the Sigma specification all evolve; refresh
the snapshots with `make refresh` and review the resulting diff at each review cycle.

## Original content

Everything else in this repository — playbooks, KQL, Sigma rules, test fixtures, tooling and
documentation — is original work by Hamza Khella, released under the [MIT License](LICENSE). It
contains no employer, customer or production data, and no proprietary detection content.
