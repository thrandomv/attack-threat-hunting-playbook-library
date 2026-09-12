---
id: TH-014
name: impair-defenses
title: Defence impairment and log tampering
summary: Security tooling disabled, exclusions added, audit policy weakened, or event logs cleared - now ATT&CK's own Defense Impairment tactic.
status: production-candidate
severity: high
confidence: high
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: T1685
  techniques: [T1685, T1685.005, T1112]
  primary_tactic: defense-impairment
  detection_strategies: [DET0497, DET0532, DET0280]
telemetry:
  required:
    - Process creation with command line
    - Security 1102 (audit log cleared) and System 104 (event log cleared)
  optional:
    - Registry writes under Windows Defender, ETW and AMSI keys (Sysmon 12/13/14)
    - Security 4719 (system audit policy changed)
    - Sensor-health telemetry from the EDR platform itself
    - System 7045/7040 for security service state changes
surfaces:
  kql: queries/kql/TH-014-impair-defenses.kql
  sigma: rules/sigma/TH-014-impair-defenses.yml
  tests: tests/rules/TH-014-impair-defenses.yml
validation:
  atomics:
    - 1b3e0146-a1e5-4c5c-89fb-1bb2ffe8fc45
    - 0b19f4ee-de90-4059-88cb-63c800c683ed
    - 13f09b91-c953-438e-845b-b585e51cac9b
    - 40075d5f-3a70-4c66-9125-f72bee87247d
    - e6abb60e-26b8-41da-8aae-0c35174b0967
    - b13e9306-3351-4b4b-a6e8-477358b0b498
related: [TH-009, TH-012, TH-024, TH-015]
tags: [defense-impairment, endpoint, windows, anti-forensics]
---

# TH-014 — Defence impairment and log tampering

## Hypothesis

An adversary is reducing visibility before or during their objective: stopping or reconfiguring
security services, adding exclusions, disabling AMSI or ETW providers, weakening audit policy, or
clearing event logs.

## Why this matters

Defence impairment is a high-confidence signal because there is almost no benign reason for it
outside a change window — and it is usually immediately followed by the activity it was meant to
hide. Log clearing in particular is both an impairment and a destruction of the evidence you need,
so the alert must be fast, not batched.

**ATT&CK v19 renumbering.** ATT&CK v19 split the old Defense Evasion tactic into **Stealth (TA0005)**
and **Defense Impairment (TA0112)**, and renumbered the techniques this playbook covers:

| Legacy ID | Legacy name | Current ID | Current name |
|---|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | **T1685** | Disable or Modify Tools |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | **T1685.005** | Clear Windows Event Logs |

Existing rules tagged `attack.t1562.001` still describe the same behaviour; the full revoked-ID table
is generated at [`mappings/legacy-technique-ids.md`](../mappings/legacy-technique-ids.md).

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/), [T1685.005 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/), [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/) |
| Tactic | Defense Impairment (TA0112) |
| Detection strategies | [DET0497](https://attack.mitre.org/detectionstrategies/DET0497), [DET0532](https://attack.mitre.org/detectionstrategies/DET0532), [DET0280](https://attack.mitre.org/detectionstrategies/DET0280) |
| Analytics | AN1369 (Windows tooling), AN1472 (log clearing chain), AN0781 (registry modification) |

## Telemetry requirements

**Required.** Process creation, plus the two log-clearing events (Security 1102, System 104). These
two events are generated *by the clearing itself* and are the last record written — collect them
centrally or they are lost with the log.

**Optional but important.** Registry telemetry catches tampering that never spawns a process:
Defender policy keys, AMSI provider keys, ETW provider keys. Sensor-health telemetry catches the
case where the agent is killed rather than reconfigured — a silent sensor is itself a detection.

**Data-quality check.** Verify that 1102 arrives centrally within seconds. Test it: clearing a log on
a test host should produce an alert, and if it does not, this playbook cannot work.

## Analytic approach

Classify each command into an impairment category — log clearing, defender configuration, service
disabling, firewall change, audit-policy change, AMSI/ETW tampering — and treat any single category
as sufficient to review. Unlike behavioural hunts, this content is not scored: one clear signal is
enough, because the benign rate is genuinely low.

Recovery deletion (`vssadmin delete shadows`) is deliberately **not** here: ATT&CK classifies it as
Impact / T1490, and it is covered by [TH-024](TH-024-inhibit-system-recovery.md).

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `SecurityServiceNames` | KQL / Sigma | Defender, Sysmon, EventLog | `ServiceNames` | Add your EDR's service and driver names — that omission is the most common gap. |
| `ApprovedMaintenanceAccounts` | KQL | empty | `ProcessNameExclusions` | Patching and imaging accounts; scope to change windows if your platform supports it. |
| `Lookback` | KQL | 7d | `TimeWindow` | Alert in near-real-time; hunt at 7d for missed events. |
| Registry key list | Companion | Defender/AMSI/ETW | `RegistryKeyPathPatterns` | Extend with your EDR's configuration keys. |

## Query surfaces

- KQL: [`queries/kql/TH-014-impair-defenses.kql`](../queries/kql/TH-014-impair-defenses.kql)
- Sigma: [`rules/sigma/TH-014-impair-defenses.yml`](../rules/sigma/TH-014-impair-defenses.yml)

## Unit tests

[`tests/rules/TH-014-impair-defenses.yml`](../tests/rules/TH-014-impair-defenses.yml) covers
`wevtutil cl`, a Defender exclusion, a service stop targeting the EDR, an audit-policy clear, and an
AMSI provider registry deletion; negatives cover `wevtutil qe` (querying logs) and a legitimate
firewall rule addition.

## Triage workflow

1. Determine what was impaired and for how long: is the control still disabled right now?
2. Identify the actor and whether a change record exists.
3. Assume the impairment window contains the activity you cannot see — hunt the same host for the
   period around it using telemetry that was *not* impaired.
4. For log clearing, reconstruct from other sources: EDR telemetry, forwarded logs already in the
   SIEM, network data, and other hosts.
5. Check for parallel persistence and credential access on the host.
6. Scope: the same command pattern estate-wide, and the same actor's other sessions.

## Benign explanations

Imaging and provisioning, troubleshooting by IT staff, software installs that add exclusions, and
maintenance scripts. Genuine cases are attributable to a build process or a ticket — and if an
installer adds a Defender exclusion, that is a security decision worth reviewing regardless of intent.

## Escalation criteria

Escalate on any log clearing, any AMSI or ETW tampering, any EDR service stop, exclusions added for
broad paths (`C:\`, `C:\Users`), audit-policy clears, and any impairment performed by an account that
does not administer that host.

## Response considerations

Restore the control and verify it is actually running, not just started. Treat the impairment window
as an evidence gap and document it in the incident record. Where logs were cleared, preserve what
remains immediately and pull equivalent telemetry from the SIEM before it ages out. Consider
tamper-protection features and alerting on sensor-health changes as the durable fix.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Tamper with Windows Defender Registry | `1b3e0146-a1e5-4c5c-89fb-1bb2ffe8fc45` | Windows | Registry writes under the Defender policy key |
| Tamper with Windows Defender Evade Scanning - Folder | `0b19f4ee-de90-4059-88cb-63c800c683ed` | Windows | Exclusion added via `Set-MpPreference` |
| AMSI Bypass - Remove AMSI Provider Reg Key | `13f09b91-c953-438e-845b-b585e51cac9b` | Windows | Provider key deletion — process-only detection will miss it |
| Windows Disable LSA Protection | `40075d5f-3a70-4c66-9125-f72bee87247d` | Windows | RunAsPPL registry change, enabling TH-001 |
| Clear Logs | `e6abb60e-26b8-41da-8aae-0c35174b0967` | Windows | `wevtutil cl` plus Security 1102 |
| Delete System Logs Using Clear-EventLog | `b13e9306-3351-4b4b-a6e8-477358b0b498` | Windows | Same outcome with no `wevtutil.exe` process |

## Limitations and blind spots

Direct API and driver-level tampering leaves no command line. An adversary who kills the sensor
process removes the very telemetry this hunt depends on — sensor-health monitoring is the only
coverage there. Registry-only tampering requires registry telemetry. Log clearing performed after
disabling forwarding is invisible unless forwarding health is itself monitored.

## Tuning notes

Enumerate legitimate exclusion and service-change sources over 30 days. Expect provisioning and a
small number of installers; everything else deserves a ticket. Alert on *new* exclusions rather than
on the existing set.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-012 Windows service creation](TH-012-windows-service-creation.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-024 Inhibit system recovery](TH-024-inhibit-system-recovery.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, T1685 / T1685.005 renumbering documented, recovery deletion moved
  to TH-024, AMSI/ETW branch added, registry companion, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
