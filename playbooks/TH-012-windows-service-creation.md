---
id: TH-012
name: windows-service-creation
title: Windows service creation and modification
summary: New or reconfigured services whose binary path points at an interpreter, a writable directory, or a remote host.
status: production-candidate
severity: high
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: T1543.003
  techniques: [T1543.003]
  primary_tactic: persistence
  detection_strategies: [DET0552]
telemetry:
  required:
    - Process creation with command line (sc.exe, PowerShell New-Service / Set-Service)
    - System 7045 service installation, or Security 4697 where audit policy allows
  optional:
    - Registry writes under HKLM\SYSTEM\CurrentControlSet\Services (Sysmon 12/13/14)
    - Sysmon Event ID 6 for driver loads
    - File creation events for the service binary
surfaces:
  kql: queries/kql/TH-012-windows-service-creation.kql
  sigma: rules/sigma/TH-012-windows-service-creation.yml
  tests: tests/rules/TH-012-windows-service-creation.yml
validation:
  atomics:
    - 981e2942-e433-44e9-afc1-8c957a1496b6
    - 491a4af6-a521-4b74-b23b-f7b3f1ee9e77
    - fb4151a2-db33-4f8c-b7f8-78ea8790f961
    - 1f896ce4-8070-4959-8a25-2658856a70c9
related: [TH-005, TH-011, TH-014, TH-024]
tags: [persistence, privilege-escalation, endpoint, windows]
---

# TH-012 — Windows service creation and modification

## Hypothesis

An adversary is installing a new service, or reconfiguring an existing one, so that a payload runs as
SYSTEM at boot — pointing the binary path at a command interpreter, a user-writable directory, or a
remote share.

## Why this matters

Services are the most reliable SYSTEM-level persistence on Windows and double as a lateral-movement
mechanism (TH-005) and a defence-tampering vector (TH-014, where an existing security service is
reconfigured or disabled). Service *modification* is the branch most deployments forget: changing the
`ImagePath` of a dormant service is quieter than creating a new one and produces no 7045.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| Tactics | Persistence (TA0003), Privilege Escalation (TA0004) |
| Detection strategy | [DET0552 — Detection of Windows Service Creation or Modification](https://attack.mitre.org/detectionstrategies/DET0552) |
| Analytic | AN1527 (Windows) — 4697/7045, registry writes, driver loads, unsigned binary alerting |

AN1527 lists `ServiceNamePattern`, `ImagePathFilter`, `DriverExtensionList`, `StartupTypeChangeWindow`
and `UnsignedBinaryAlert`. The last is worth implementing directly: an unsigned service binary is a
better discriminator than any path list.

## Telemetry requirements

**Required.** Both the process view (`sc.exe`, PowerShell cmdlets) and the platform view (7045 or
4697). Tools that use the Service Control Manager API directly — most malware does — generate 7045
but no `sc.exe` process.

**Optional.** Registry telemetry catches modification of `ImagePath` and `Start` without any service
API call. Driver-load events (Sysmon 6) matter because kernel drivers are installed as services and
are the entry point for bring-your-own-vulnerable-driver attacks.

**Data-quality check.** Confirm the System log is forwarded from servers and workstations, not just
Security. In many estates 7045 collection is the single missing piece for this technique.

## Analytic approach

Match service creation and configuration where the binary path is an interpreter, sits in a writable
or UNC path, or where the change targets a security service. Report the start type: `auto` plus an
interpreter is persistence, `demand` plus an interpreter is usually lateral movement.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| Path fragments | KQL / Sigma | temp, public, appdata, UNC | `ImagePathFilter` | Add deployment staging paths only with a signer check in place. |
| `SecurityServiceNames` | KQL | Defender, EventLog, Sysmon | `ServiceNamePattern` | Extend with your EDR's service names — this is the TH-014 overlap. |
| Signature check | Companion | manual | `UnsignedBinaryAlert` | Where the sensor exposes signer, prefer "unsigned service binary" over path lists. |
| `Lookback` | KQL | 7d | `StartupTypeChangeWindow` | 7d for hunting, 24h for scheduled alerting. |

## Query surfaces

- KQL: [`queries/kql/TH-012-windows-service-creation.kql`](../queries/kql/TH-012-windows-service-creation.kql)
- Sigma: [`rules/sigma/TH-012-windows-service-creation.yml`](../rules/sigma/TH-012-windows-service-creation.yml)

## Unit tests

[`tests/rules/TH-012-windows-service-creation.yml`](../tests/rules/TH-012-windows-service-creation.yml)
covers service creation with a `cmd.exe` binary path, a remote `sc \\host create`, and reconfiguration
of a Defender service to disabled; negatives cover `sc query` and a legitimate installer creating a
service in `Program Files`.

## Triage workflow

1. Get the service definition: name, display name, `ImagePath`, account, start type, and whether it
   is still installed.
2. Hash and check the binary: signer, path, prevalence, and creation time relative to the service.
3. Identify the creator: process, account, and whether the session was local or remote.
4. Check for the boot-persistence pair — a service plus a scheduled task is a common redundancy.
5. If the change disabled or reconfigured a security service, escalate through TH-014 as well.
6. Scope by service name and binary hash across the estate; adversaries reuse both.

## Benign explanations

Software installation, agent updates, driver installs, and administrators reconfiguring services
during maintenance. Legitimate service binaries live in `Program Files` or `System32`, are signed,
and are created by an installer process.

## Escalation criteria

Escalate on interpreter binary paths, unsigned binaries, writable or UNC paths, remote service
creation, any change to a security service, and any service created by an interactive user session
outside a change window.

## Response considerations

Preserve the service configuration and binary before removal. Check for driver installation
separately — a malicious driver is a kernel-level problem, not an application one. After removal,
verify the service key is gone rather than just the service being stopped.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Service Installation CMD | `981e2942-e433-44e9-afc1-8c957a1496b6` | Windows | `sc create` plus 7045 |
| Service Installation PowerShell | `491a4af6-a521-4b74-b23b-f7b3f1ee9e77` | Windows | `New-Service` with no `sc.exe` process |
| Remote Service Installation CMD | `fb4151a2-db33-4f8c-b7f8-78ea8790f961` | Windows | `sc \\host create` — the lateral-movement branch |
| Modify Service to Run Arbitrary Binary (Powershell) | `1f896ce4-8070-4959-8a25-2658856a70c9` | Windows | Modification without creation — the branch 7045-only deployments miss |

## Limitations and blind spots

Direct SCM API use leaves no command line. Registry-only modification leaves no service event.
Services created by an installer that is itself malicious look entirely legitimate at this layer.
Path heuristics fail against binaries staged in `Program Files` — signer and prevalence are the
durable answers.

## Tuning notes

Inventory installed services estate-wide and keep the list; new service names are then inherently
interesting. Where the sensor exposes signature status, make "unsigned service binary" the primary
rule and treat path matching as a fallback.

## Related playbooks

- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-011 Scheduled task persistence](TH-011-scheduled-task-persistence.md)
- [TH-014 Impair defenses](TH-014-impair-defenses.md)
- [TH-024 Inhibit system recovery](TH-024-inhibit-system-recovery.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0552 alignment, PowerShell cmdlet coverage, service-modification
  branch, security-service overlap with TH-014, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
