# ATT&CK Detection Strategies

## What changed in ATT&CK

Until v17, ATT&CK's detection guidance was a paragraph of prose attached to each technique and a list
of data sources. Version 18 replaced that with structured objects, and v19 extended them:

| Object | ID form | What it holds |
|---|---|---|
| Detection Strategy | `DET####` | A named behavioural approach for detecting a technique |
| Analytic | `AN####` | A platform-specific analytic under a strategy, with log sources and **mutable elements** |

`x_mitre_mutable_elements` is the part that matters for engineering. It names the parameters ATT&CK
expects an implementer to tune — `TimeWindow`, `CommandLinePattern`, `AccessMask`,
`PasswordReuseThreshold`, `ExecStartPathAllowlist`, and so on. It is, in effect, MITRE publishing the
tuning surface alongside the detection idea.

## How this library uses them

Every playbook does three things with its detection strategy:

1. **Names it** in the ATT&CK alignment table, with the DET and AN identifiers and a link.
2. **Maps the mutable elements to concrete parameters** in its own tunable-parameter table, so each
   knob in a query has an upstream justification rather than being an arbitrary number.
3. **Validates the reference in CI** — `scripts/validate.py` checks that every DET a playbook cites
   is genuinely linked to one of the techniques the playbook claims, against the pinned MITRE STIX
   snapshot. A copied-in-error DET fails the build.

Concretely, TH-001's tunable-parameter table reads:

| Parameter | Where | Default | ATT&CK mutable element |
|---|---|---|---|
| `Lookback` | KQL | 7d | `TimeWindow` |
| `ApprovedDumpTools` | KQL | empty | `ProcessNameExclusions` |
| `DumpFilePattern` | KQL | `.dmp`, `.dump` | `DumpFilePath` |
| Handle-access mask | Companion query | `0x1010`, `0x1410`, `0x1F0FFF` | `AccessMask` |

AN1030 lists exactly those elements for T1003.001. The mapping is not decoration: it means a reader
can check the library's choices against MITRE's model rather than against the author's taste.

## Strategies referenced by this library

Generated from the pinned snapshot; see [`mappings/attack-coverage.md`](../mappings/attack-coverage.md)
for the current list per playbook.

## Reading an analytic critically

ATT&CK analytics are a starting point, not a specification. They are written to be platform-agnostic
and consequently under-specify thresholds, which is precisely what `mutable elements` acknowledges.
Two habits keep them useful:

- **Take the elements, question the defaults.** ATT&CK does not know your population size. The
  element tells you *what* to tune; your baseline tells you *to what*.
- **Check the log sources against what you actually collect.** Several analytics assume Sysmon event
  IDs or `auditd` rules that many estates do not deploy. That gap is a telemetry finding, not a
  detection failure — record it as such.

## Refreshing the mapping

```bash
python3 scripts/fetch_attack_reference.py     # rebuild the snapshot from MITRE STIX
python3 scripts/build.py                      # regenerate coverage artefacts
make validate                                 # confirm every reference still resolves
git diff mappings/attack-reference.json       # review what MITRE changed
```

Run this on each ATT&CK release. The diff is the review: renamed techniques, new detection
strategies, and revoked IDs all show up as concrete changes rather than as a vague sense that the
content is aging.
