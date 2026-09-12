# Threat-hunting operating model

## Purpose

This library supports a repeatable cycle from hypothesis to durable detection. It is not a list of indicators. A hunt asks whether a behavior is present, gathers evidence, and produces one of four outcomes: confirmed incident, benign explanation, telemetry gap, or detection opportunity.

## Lifecycle

| Phase | Primary question | Required output |
|---|---|---|
| Prepare | Can the available data answer the hypothesis? | Data-quality check and scoped population |
| Hunt | Is the behavior present, rare, or changing? | Reproducible query and evidence notebook |
| Triage | Is the activity expected for this identity, host, and time? | Disposition with supporting evidence |
| Scope | What preceded and followed the signal? | Entity timeline and affected-asset list |
| Respond | Does risk justify containment or escalation? | Incident record and approved actions |
| Engineer | Should the hunt become continuous detection? | Rule, threshold, runbook, owner, and test |
| Review | Is the content still accurate and useful? | Metrics, changes, and next review date |

## Roles

| Role | Accountability |
|---|---|
| Hunt lead | Defines hypothesis, scope, evidence standard, and final conclusion |
| Data owner | Confirms connector health, field semantics, retention, and collection gaps |
| Detection engineer | Converts repeatable behavior into a monitored analytic and tests deployment |
| Incident responder | Owns containment, eradication, recovery, and evidence preservation |
| Service owner | Validates expected administration, change windows, and business impact |
| Content reviewer | Challenges assumptions, false-positive handling, and ATT&CK mapping |

One person may perform several roles in a small SOC, but each accountability should still be explicit.

## Hunt intake

Every hunt record should capture:

- source: intelligence, incident lesson, ATT&CK gap, anomaly, purple-team test, or analyst observation;
- hypothesis: one falsifiable sentence;
- scope: tenants, networks, platforms, identities, and lookback period;
- prerequisites: sensors, audit policy, parsers, enrichment, and retention;
- priority: threat relevance, asset exposure, data confidence, and expected effort;
- owner and timebox;
- evidence standard for confirmed, benign, inconclusive, and telemetry-gap outcomes.

## Severity and confidence

Do not use ATT&CK tactic or potential impact as the alert severity by itself. Keep two measures:

- **Confidence**: strength and completeness of observed evidence.
- **Impact**: privilege, asset criticality, exposure, and likely consequence.

A rare `rundll32.exe` command can be low-confidence on a workstation yet high-impact on a domain controller. Conversely, a high-confidence scheduled task created by an approved deployment tool may require no incident response.

Suggested confidence scale:

| Confidence | Meaning |
|---|---|
| Low | One weak signal or significant missing telemetry |
| Medium | Multiple aligned signals, but benign administration remains plausible |
| High | Behavior, context, and sequence strongly support unauthorized activity |

## Promotion to continuous detection

Promote a hunt when the behavior is observable with acceptable latency, results can be triaged consistently, and a response owner exists. Before enabling alerts:

1. run over at least 14–30 representative days where retention permits;
2. review the highest-volume identities, hosts, parents, command lines, and destinations;
3. define narrow, attributable exclusions with owners and expiration dates;
4. perform one positive and one known-good negative test;
5. set entity mappings, severity, suppression, grouping, and response steps;
6. measure alert count, true-positive rate, analyst minutes, and data completeness.

## Review cadence

- High-risk or high-volume production rules: monthly.
- All other enabled analytics: quarterly.
- ATT&CK and schema mappings: after major upstream releases, at least twice yearly.
- Immediate review: missed incident, material false positive, sensor migration, audit-policy change, or detection bypass finding.

Retire content when its telemetry no longer exists, the threat hypothesis is obsolete, or another analytic supersedes it. Preserve the decision in the changelog rather than silently deleting institutional knowledge.
