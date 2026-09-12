---
id: TH-0NN
name: short-kebab-case-name
title: Human-readable title
summary: One line, under 200 characters, describing the behaviour this hunt looks for.
status: hunt                      # hunt | production-candidate | production
severity: medium                  # informational | low | medium | high | critical
confidence: medium                # low | medium | high
version: 2.0.0
created: YYYY-MM-DD
updated: YYYY-MM-DD
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: TNNNN.NNN
  techniques: [TNNNN.NNN]
  primary_tactic: credential-access   # must be a tactic the primary technique actually belongs to
  detection_strategies: [DETNNNN]     # must be linked to one of the techniques above in ATT&CK
telemetry:
  required:
    - The source without which this hunt cannot run
  optional:
    - The source that turns a lead into a conclusion
surfaces:
  kql: queries/kql/TH-0NN-short-kebab-case-name.kql
  sigma: rules/sigma/TH-0NN-short-kebab-case-name.yml
  tests: tests/rules/TH-0NN-short-kebab-case-name.yml
validation:
  atomics:
    - 00000000-0000-0000-0000-000000000000   # verified against validation/atomic-index.json in CI
related: [TH-0NN]
tags: [tactic, platform, data-source]
---

# TH-0NN — Title

## Hypothesis

One falsifiable statement about adversary behaviour. It must be possible for the data to fail to
support it.

## Why this matters

Why an analyst should spend time on this, and what makes it hard to detect well. Name the signal that
actually discriminates, not just the technique.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [TNNNN.NNN — Name](https://attack.mitre.org/techniques/TNNNN/NNN/) |
| Tactic | Tactic name (TANNNN) |
| Detection strategy | [DETNNNN — Name](https://attack.mitre.org/detectionstrategies/DETNNNN) |
| Analytic | ANNNNN (platform) — what it measures |

## Telemetry requirements

**Required.** What must be collected, and any audit policy or sensor configuration it depends on.

**Optional.** What improves confidence or speeds triage.

**Data-quality check.** A concrete query or action that proves the data exists. A zero-result hunt is
only meaningful next to evidence that the telemetry was there.

## Analytic approach

How the detection reasons about the behaviour, and why that approach over the obvious alternative.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 7d | `TimeWindow` | How to choose a value from local data |

## Query surfaces

- KQL: [`queries/kql/TH-0NN-short-kebab-case-name.kql`](../queries/kql/TH-0NN-short-kebab-case-name.kql)
- Sigma: [`rules/sigma/TH-0NN-short-kebab-case-name.yml`](../rules/sigma/TH-0NN-short-kebab-case-name.yml)

## Unit tests

What [`tests/rules/TH-0NN-short-kebab-case-name.yml`](../tests/rules/TH-0NN-short-kebab-case-name.yml)
asserts, and which benign lookalike each negative case defends against.

## Triage workflow

1. Numbered steps an analyst can follow without the author present.

## Benign explanations

The activity that will account for most matches, and how to tell it apart — by attribute, not by
intuition.

## Escalation criteria

The conditions that make this an incident rather than a lead.

## Response considerations

What to preserve, what to contain, and what the durable fix is.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Test name | `guid` | Windows | What you should see if the detection path works |

Where no upstream test exists, say so and give a manual procedure.

## Limitations and blind spots

The evasion that defeats this detection. If this section is empty, the playbook is not finished.

## Tuning notes

How to baseline before deployment, and what to allowlist by (attributes, not populations).

## Related playbooks

- [TH-0NN Title](TH-0NN-other.md)

## Change log

- YYYY-MM-DD (v2.0.0): Initial version.
