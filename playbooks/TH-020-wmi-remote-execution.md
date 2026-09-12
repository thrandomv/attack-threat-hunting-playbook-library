---
id: TH-020
name: wmi-remote-execution
title: WMI execution and remote process creation
summary: Payloads spawned by the WMI provider host, the fileless lateral-movement path that leaves no service and no scheduled task.
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
  primary_technique: T1047
  techniques: [T1047]
  primary_tactic: execution
  detection_strategies: [DET0364]
telemetry:
  required:
    - Process creation with parent image (wmiprvse.exe children)
  optional:
    - Microsoft-Windows-WMI-Activity/Operational events 5857, 5858, 5860, 5861
    - Security 4624 type 3 for the session behind the remote WMI call
    - Network telemetry for DCOM/RPC (135 plus the ephemeral range)
surfaces:
  kql: queries/kql/TH-020-wmi-remote-execution.kql
  sigma: rules/sigma/TH-020-wmi-remote-execution.yml
  tests: tests/rules/TH-020-wmi-remote-execution.yml
validation:
  atomics:
    - 9c8ef159-c666-472f-9874-90c8d60d136b
    - 00738d2a-4651-4d76-adf2-c43a41dfb243
    - 7db7a7f9-9531-4840-9b30-46220135441c
    - 10447c83-fc38-462a-a936-5102363b1c43
related: [TH-004, TH-005, TH-007, TH-009]
tags: [execution, lateral-movement, endpoint, windows, fileless]
---

# TH-020 — WMI execution and remote process creation

## Hypothesis

An adversary is executing commands locally or on remote hosts through WMI — typically
`Win32_Process.Create` — producing child processes of `wmiprvse.exe` with no service installation and
no file written to disk.

## Why this matters

WMI is the fileless option: it needs no binary on the target, leaves no service, and is available on
every Windows host with administrative credentials. It is also used constantly by legitimate
management tooling, so the discriminator is *what* the provider host spawns, not that it spawned
anything.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) |
| Tactic | Execution (TA0002) |
| Detection strategy | [DET0364 — Behavioral Detection Strategy for WMI Execution Abuse on Windows](https://attack.mitre.org/detectionstrategies/DET0364) |
| Analytic | AN1031 (Windows) — provider-host children, WMI operational events, remote destination thresholds |

AN1031's `RemoteDestinationThreshold` is worth implementing as a second-order rule: one host issuing
remote WMI to many destinations is lateral movement regardless of what it executes.

## Telemetry requirements

**Required.** Process creation with parent image. `wmiprvse.exe` as parent is the anchor for the whole
detection.

**Optional.** The WMI-Activity operational log records the query and the calling user, which is the
only way to see WMI operations that do not spawn a process (event subscriptions, class modification).
Enable it on tier-0 hosts at minimum.

**Data-quality check.** Confirm `wmiprvse.exe` appears as a parent in your telemetry and that WMI
event subscriptions are visible somewhere — persistent event subscriptions are a separate persistence
technique that this playbook does not cover but that the same log exposes.

## Analytic approach

Take every child of `wmiprvse.exe`, filter to interpreters and tooling, and score for encoding,
transfer, persistence creation, and writable paths. Because legitimate management platforms use WMI
heavily, the practical deployment step is enumerating those platforms first and allowlisting them by
account and parent command line.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `SuspiciousChildren` | KQL / Sigma | interpreters and tooling | `SuspiciousCommandPatterns` | Keep `net.exe`, `sc.exe` and `schtasks.exe` — those are what an operator runs after landing. |
| `ApprovedWmiAccounts` | KQL | empty | `UserContext` | Management platform accounts, paired with the expected child. |
| Remote destination count | Companion | 3 | `RemoteDestinationThreshold` | One source issuing WMI to many hosts is lateral movement. |
| `Lookback` | KQL | 7d | `TimeWindow` | Daily scheduling is realistic. |

## Query surfaces

- KQL: [`queries/kql/TH-020-wmi-remote-execution.kql`](../queries/kql/TH-020-wmi-remote-execution.kql)
- Sigma: [`rules/sigma/TH-020-wmi-remote-execution.yml`](../rules/sigma/TH-020-wmi-remote-execution.yml)

## Unit tests

[`tests/rules/TH-020-wmi-remote-execution.yml`](../tests/rules/TH-020-wmi-remote-execution.yml)
covers encoded PowerShell, `rundll32`, and `schtasks` under `wmiprvse.exe`; negatives cover an
inventory binary under the same parent and an encoded PowerShell command under an ordinary parent.

## Triage workflow

1. Identify the account and whether the call was local or remote (WMI operational log, or a 4624
   type 3 immediately preceding).
2. Read the payload; decode where encoded.
3. Identify the source host for remote calls and investigate it as the origin.
4. Check for follow-on persistence, credential access, or further movement.
5. Look for WMI event subscriptions on the host — adversaries who use WMI for execution often use it
   for persistence too.
6. Scope the same account and payload shape across the estate.

## Benign explanations

SCCM/Configuration Manager, monitoring and inventory agents, backup software, and administrative
scripting all use WMI routinely. They are identifiable by a small set of service accounts and
repeated identical command shapes.

## Escalation criteria

Escalate on encoded payloads, transfers, persistence creation, execution from a workstation source,
service accounts performing WMI they have never performed before, and any WMI execution on tier-0
assets outside the approved platform.

## Response considerations

Preserve the WMI operational log and the process tree. Check for and remove WMI event subscriptions.
Treat the credential used as compromised and review where else it has been used.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| WMI Execute Remote Process | `9c8ef159-c666-472f-9874-90c8d60d136b` | Windows | `wmiprvse.exe` child on the remote host |
| WMI Execute rundll32 | `00738d2a-4651-4d76-adf2-c43a41dfb243` | Windows | LOLBin under the provider host — overlaps TH-010 |
| Create a Process using WMI Query and an Encoded Command | `7db7a7f9-9531-4840-9b30-46220135441c` | Windows | Encoded payload under `wmiprvse.exe` |
| Create a Process using obfuscated Win32_Process | `10447c83-fc38-462a-a936-5102363b1c43` | Windows | Obfuscated invocation — tests the TH-015 overlap |

## Limitations and blind spots

WMI operations that do not spawn a process — event subscriptions, class creation, remote queries for
discovery — are invisible to process telemetry and require the WMI operational log. Management
platforms generate high volumes that can bury a single malicious call. The source of a remote call
is not visible in the child process event alone.

## Tuning notes

Enumerate every account that legitimately triggers `wmiprvse.exe` children over 30 days. The list is
short in most estates. Allowlist by account *and* child image, so that a compromised management
account executing something unusual still alerts.

## Related playbooks

- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-007 WinRM and PowerShell remoting](TH-007-winrm-powershell-remoting.md)
- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0364 alignment, WMI operational log guidance, remote-destination
  companion, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
