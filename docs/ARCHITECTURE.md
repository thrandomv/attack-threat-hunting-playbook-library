# Repository architecture

## The idea

Playbook frontmatter is the single source of truth. Everything else is either an implementation of a
playbook (a query, a rule, a fixture) or generated from it (tables, matrices, layers, navigation).
Two scripts enforce that: `build.py` regenerates the derived artefacts, and `validate.py` checks the
claims. CI runs both, so the repository cannot describe itself inaccurately for longer than one
commit.

```text
                       ┌──────────────────────────────┐
                       │  playbooks/TH-0NN-*.md       │
                       │  YAML frontmatter + workflow │  ← the source of truth
                       └───────────────┬──────────────┘
                                       │
        ┌──────────────────────────────┼───────────────────────────────┐
        │                              │                               │
        ▼                              ▼                               ▼
┌───────────────┐            ┌───────────────────┐          ┌────────────────────┐
│ queries/kql/  │            │  rules/sigma/     │          │  tests/rules/      │
│ KQL hunts     │            │  Sigma + correl.  │◀────────▶│  TP / FP fixtures  │
└───────┬───────┘            └─────────┬─────────┘          └─────────┬──────────┘
        │                              │                              │
        │ validate.py (lint)           │ sigma_eval.py                │ run_tests.py
        │                              │ (parse + evaluate)           │
        ▼                              ▼                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          scripts/validate.py                                 │
│  frontmatter schema · ATT&CK facts · Atomic GUIDs · Sigma hygiene · links    │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  checks against
                ┌───────────────┴────────────────┐
                ▼                                ▼
┌───────────────────────────┐      ┌────────────────────────────┐
│ mappings/                 │      │ validation/                │
│ attack-reference.json     │      │ atomic-index.json          │
│ (pinned MITRE STIX)       │      │ (pinned Atomic Red Team)   │
└───────────────────────────┘      └────────────────────────────┘
                ▲                                ▲
                │ fetch_attack_reference.py      │ fetch_atomic_index.py
                └────────────────────────────────┘
                              upstream sources

                       ┌──────────────────────────────┐
                       │      scripts/build.py        │
                       │  regenerates, --check in CI  │
                       └───────────────┬──────────────┘
                                       ▼
     README table · mappings/attack-coverage.md · attack-navigator-layer.json
     mappings/legacy-technique-ids.md · validation/atomic-coverage.md
     playbooks/README.md · mkdocs nav
```

## Components

| Path | Role | Hand-edited? |
|---|---|---|
| `playbooks/TH-*.md` | Analyst workflow plus machine-readable frontmatter | Yes — this is the source |
| `playbooks/README.md` | Playbook index | No — generated |
| `queries/kql/*.kql` | Sentinel and Defender XDR implementations, with baseline companions | Yes |
| `rules/sigma/*.yml` | Portable detection and correlation rules | Yes |
| `tests/rules/*.yml` | Synthetic true-positive and false-positive events | Yes |
| `scripts/sigma_eval.py` | Sigma parser and evaluation engine | Yes |
| `scripts/run_tests.py` | Test runner and engine self-test | Yes |
| `scripts/validate.py` | Schema, ATT&CK, Atomic, Sigma and KQL validation | Yes |
| `scripts/build.py` | Regenerates every derived artefact | Yes |
| `scripts/fetch_*.py` | Rebuild the pinned upstream snapshots | Yes |
| `mappings/attack-reference.json` | Pinned ATT&CK v19.2 subset | No — generated |
| `validation/atomic-index.json` | Pinned Atomic Red Team index subset | No — generated |
| `mappings/*.md`, `mappings/*.json` | Coverage matrix, Navigator layer, legacy IDs | No — generated |
| `docs/*.md` | Operating guidance | Yes |

## Naming contract

For a playbook with id `TH-0NN` and name `some-technique`:

```text
playbooks/TH-0NN-some-technique.md
queries/kql/TH-0NN-some-technique.kql
rules/sigma/TH-0NN-some-technique.yml
tests/rules/TH-0NN-some-technique.yml
```

`validate.py` enforces all four, plus that the frontmatter `surfaces` block points at exactly those
paths. Consistent naming is what allows every other tool here to be simple.

## Adding a playbook

```bash
cp templates/playbook-template.md playbooks/TH-026-your-technique.md
# write the playbook, the KQL, the Sigma rule and the fixtures

python3 scripts/fetch_attack_reference.py   # if the technique is new to the library
python3 scripts/build.py                    # regenerate derived artefacts
make check                                  # validate + test + freshness
```

`fetch_attack_reference.py` reads technique IDs straight from playbook frontmatter, so a new
technique pulls its own ATT&CK metadata — including detection strategies — into the snapshot.

## Continuous integration

`.github/workflows/ci.yml` runs, on every push and pull request:

1. `scripts/run_tests.py --selftest` — the engine's own 42 checks
2. `scripts/run_tests.py` — the full fixture suite
3. `scripts/validate.py` — structural, schema, ATT&CK and Atomic validation
4. `scripts/build.py --check` — generated artefacts are in sync
5. `yamllint` over the Sigma rules and fixtures
6. `sigma-cli` conversion smoke test (non-blocking: upstream backend availability changes)

The first four are hard gates. A pull request that changes a playbook without regenerating the
coverage table fails, which is the intended behaviour.
