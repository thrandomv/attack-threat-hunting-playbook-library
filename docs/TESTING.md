# Testing detection content

## The problem this solves

A published detection rule usually carries two claims: *this fires on the technique* and *this does
not fire on the benign lookalike*. In most public repositories neither claim has ever been executed.
The rule was written, read, and merged. Converting it with `sigma-cli` proves it compiles — not that
it behaves.

This repository executes both claims. Every Sigma rule ships with synthetic events that assert its
behaviour, and CI fails if a rule has no true-positive case, no false-positive case, or produces the
wrong verdict on either.

## Running the suite

```bash
make test                                  # run everything
python3 scripts/run_tests.py -v            # show every case
python3 scripts/run_tests.py --rule TH-018 # one playbook
python3 scripts/run_tests.py --selftest    # test the engine itself
```

The suite needs no SIEM, no licence, and no network. It runs in under a second.

## Fixture format

Fixtures live in `tests/rules/<same-name-as-the-rule>.yml`:

```yaml
rule: TH-001-lsass-memory-access
description: >
  What these cases prove, and which tuning note each negative case defends.
cases:
  - name: ProcDump full memory dump of lsass
    expect: match                    # or no_match
    event:                           # a single event, evaluated against a detection rule
      Image: 'C:\Tools\procdump64.exe'
      CommandLine: 'procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\out.dmp'

  - name: Twelve distinct SPNs in ten minutes
    expect: match
    target: 2bb7f103-43d0-4b03-8d03-7d6a1f030103   # required when the file has several rules
    events:                          # a sequence, evaluated against a correlation rule
      - {timestamp: '2026-09-01T09:00:00Z', EventID: 4769, ...}
      - {timestamp: '2026-09-01T09:00:05Z', EventID: 4769, ...}
```

`event` evaluates a detection rule; `events` evaluates a correlation rule and each entry needs a
`timestamp`. `target` selects a rule by `name`, `id` or `title` when the file contains more than one.

## What to write a case for

Three kinds of case earn their place:

| Kind | Purpose | Example |
|---|---|---|
| Canonical positive | The technique as it is normally executed | `vssadmin delete shadows /all /quiet` |
| Variant positive | A branch of the logic that a single positive would not exercise | `vssadmin resize shadowstorage /maxsize=401MB` |
| Regression negative | The benign lookalike named in the rule's `falsepositives` list | `vssadmin list shadows` |

The negatives matter more than the positives. A rule that fires on the technique is easy; a rule that
stays quiet on the thing that looks exactly like it is the whole job. Several negatives in this
repository exist because the v1 rule got them wrong:

- TH-008 fired on every `TXT` query, including DMARC lookups.
- TH-018 counted disabled accounts (`50057`) and Conditional Access blocks (`53003`) as failed
  passwords.
- TH-013 matched group names, which silently fails on a French-locale domain controller.

Each of those is now a permanent test case. That is the point of a regression suite: a fixed bug
cannot come back quietly.

## The evaluation engine

[`scripts/sigma_eval.py`](../scripts/sigma_eval.py) is a small Sigma engine written against the
Python standard library; PyYAML is used only to read the rule and fixture files.

**Implemented.** Field/value maps, value lists (OR), lists of maps (OR), keyword lists, `null`
values, wildcards (`*`, `?`, with backslash escaping), case-insensitive matching by default, dotted
field paths, and the modifiers `contains`, `startswith`, `endswith`, `all`, `re` (+ `i`/`m`/`s`),
`cased`, `cidr`, `exists`, `windash`, `lt`, `lte`, `gt`, `gte`, `base64offset|contains`. Condition
grammar: `and`, `or`, `not`, parentheses, `N of pattern`, `all of pattern`, `... of them`.
Correlations: `event_count`, `value_count`, `temporal`, `temporal_ordered` with `group-by` and
`timespan`.

**Deliberately not implemented.** `expand`, `fieldref`, standalone `base64`/`utf16` transformations,
backend-specific field mapping, and legacy in-condition aggregations. A rule using any of these
raises `UnsupportedSigmaFeature` rather than passing quietly — a test suite that reports green on
logic it did not evaluate is worse than no test suite.

The engine has its own tests: `python3 scripts/run_tests.py --selftest` runs 42 checks covering
wildcard escaping, modifier semantics, quantifiers, negation, correlation windows and grouping, and
the two rejection paths. It found a real bug during authoring: the TH-009 PowerShell rule used
`2 of (encoding, cradle, in_memory, hidden)`, which is not valid Sigma syntax. A repository without
an engine would have shipped it.

### Where the engine is not enough

The engine also found the limit of its own usefulness. The rewritten TH-009 condition —
`2 of sig_*` — is valid per the Sigma specification, and the engine implements it, so the whole
suite passed. pySigma does not implement it: its grammar allows only the quantifiers `1`, `any`
and `all`, so the rule parsed here and failed to convert in the reference implementation. The CI
conversion job caught it on the first public push.

An in-house engine can only prove a rule against its own reading of the specification. Wherever
that reading is more permissive than pySigma's, the gap is invisible to the tests, so it has to be
closed by an explicit rule in `scripts/validate.py` and by running the content through pySigma in
CI. Both are in place; the second one is why the conversion job exists at all.

## What the tests do not prove

They prove the **logic** is sound against events shaped the way the rule expects. They do not prove:

- that your SIEM's field mapping matches the rule's field names (that is a backend pipeline concern);
- that the telemetry exists in your environment (see [TELEMETRY.md](TELEMETRY.md));
- that the thresholds suit your population (see [TUNING.md](TUNING.md));
- that a real adversary's variant is covered (see each playbook's blind spots, and
  [ATOMIC_VALIDATION.md](ATOMIC_VALIDATION.md)).

Passing tests move a rule from "asserted" to "evaluated". Everything beyond that is earned in your
environment.

## Adding a rule

1. Write the Sigma rule.
2. Write the fixture: at least one true positive and one false positive, the false positive drawn
   from the rule's own `falsepositives` list.
3. `make test` — the run fails if either kind of case is missing.
4. `make validate` — checks the metadata, ATT&CK facts and tag consistency.
5. `make build` — regenerates the coverage artefacts.
