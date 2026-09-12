# Contributing

Contributions are welcome when they improve defensive value, reproducibility, or clarity.

## Before you start

```bash
pip install -r requirements-dev.txt
make check      # selftest + tests + validation + generated-artefact freshness
```

If `make check` fails on a clean clone, that is a bug — please open an issue.

## What a new playbook needs

A playbook is not a query with a description. It is a hunt someone else can run, tune, and argue
with. A new `TH-NNN` must have:

1. **Frontmatter** following [`templates/playbook-template.md`](templates/playbook-template.md),
   with the next sequential ID and matching file names across all four artefacts:
   `playbooks/TH-NNN-name.md`, `queries/kql/TH-NNN-name.kql`, `rules/sigma/TH-NNN-name.yml`,
   `tests/rules/TH-NNN-name.yml`.
2. **A falsifiable hypothesis** — a statement about adversary behaviour that the query could fail to
   support.
3. **A telemetry contract**: what is required, what is optional, and a data-quality check that proves
   the data exists before a zero-result run is treated as good news.
4. **ATT&CK alignment** with a current technique ID, its detection strategy (DET), and a
   tunable-parameter table mapping ATT&CK's mutable elements to the parameters in your query.
5. **At least one query surface** (KQL) and a Sigma rule, or an explicit explanation of why one is
   not applicable.
6. **Unit tests**: at least one true positive *and* at least one false positive per rule document.
   The false positive should be drawn from your own `falsepositives` list — if you cannot construct
   one, the rule's false-positive claim is not yet real.
7. **A blind-spots section** that names the evasion that defeats the detection. A playbook with no
   limitations has not been thought through.
8. **Purple-team validation**: Atomic Red Team GUIDs where they exist, and an honest "no published
   tests" statement plus a manual procedure where they do not.

Then run `python3 scripts/fetch_attack_reference.py` if the technique is new to the library,
`python3 scripts/build.py`, and `make check`.

## Rule design conventions

- **Behaviour over tool names.** Tool-name matching may support an analytic; it must not define it.
- **Thresholds live in `let` blocks** at the top of the KQL, appear in the tunable-parameter table,
  and ship with a baseline companion query that derives them from local data.
- **Use the right KQL operator.** `has`/`has_any` for whole terms, `contains` for path fragments and
  switches, `=~`/`in~` for exact values. See [`docs/KQL_STYLE.md`](docs/KQL_STYLE.md) — v1 of this
  repository got this wrong and the fix is documented there.
- **Match identities by SID** where a name is localisable or renameable.
- **Sigma conditions stay portable**: `and`/`or`/`not`, parentheses, and `N of pattern` quantifiers.
  No in-condition aggregations; use correlation rules.
- **`level` reflects standalone confidence**, not the worst-case impact of the technique. Base rules
  used only inside correlations are `informational`.
- **Never claim zero false positives.**

## Pull-request checklist

- [ ] `make check` passes.
- [ ] Every new or changed Sigma rule has true-positive and false-positive test cases.
- [ ] ATT&CK mapping uses a current, non-revoked technique and a detection strategy that ATT&CK
      actually links to it (the validator enforces this).
- [ ] Atomic Red Team GUIDs exist upstream (the validator enforces this too).
- [ ] Generated artefacts were regenerated with `python3 scripts/build.py`.
- [ ] The changelog records the change.
- [ ] No secrets, private telemetry, customer or employer data, or real personal identifiers.

## Reporting a false positive

Open a "False positive report" issue with the benign event that matched. If it is reproducible,
the fix is a new negative test case in `tests/rules/` plus the rule change — so the same false
positive cannot silently return.

By contributing, you agree that your contribution is licensed under this repository's MIT License.
