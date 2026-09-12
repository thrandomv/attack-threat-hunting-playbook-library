---
id: TH-007
name: winrm-powershell-remoting
title: WinRM and PowerShell remoting abuse
summary: Suspicious children of the WinRM host processes, where remote command execution lands on the destination.
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
  primary_technique: T1021.006
  techniques: [T1021.006]
  primary_tactic: lateral-movement
  detection_strategies: [DET0477]
telemetry:
  required:
    - Microsoft Defender XDR DeviceProcessEvents (or Security 4688 with command line)
  optional:
    - PowerShell 4103/4104 script block logging on the destination
    - Microsoft-Windows-WinRM operational log (event 6, 91, 168)
    - Security 4624 type 3 with LogonProcess Kerberos/NTLM for session attribution
    - Network telemetry for TCP 5985/5986
surfaces:
  kql: queries/kql/TH-007-winrm-powershell-remoting.kql
  sigma: rules/sigma/TH-007-winrm-powershell-remoting.yml
  tests: tests/rules/TH-007-winrm-powershell-remoting.yml
validation:
  atomics:
    - 9059e8de-3d7d-4954-a322-46161880b9cf
    - 5295bd61-bd7e-4744-9d52-85962a4cf2d6
    - efe86d95-44c4-4509-ae42-7bfd9d1f5b3d
related: [TH-005, TH-009, TH-015, TH-020]
tags: [lateral-movement, execution, windows, powershell]
---

# TH-007 — WinRM and PowerShell remoting abuse

## Hypothesis

An adversary is executing commands on remote hosts through WinRM, so the payload appears as a child
of `wsmprovhost.exe` (PowerShell remoting) or `winrshost.exe` (WinRS) rather than of a user shell.

## Why this matters

WinRM is enabled by default on Windows Server, encrypted, and firewall-friendly, which makes it the
quietest of the built-in lateral movement paths. On the destination it produces a distinctive parent
process that almost nothing else uses, so the false-positive rate is genuinely low — provided you
know which management platforms in your estate use remoting legitimately.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1021.006 — Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) |
| Tactic | Lateral Movement (TA0008) |
| Detection strategy | [DET0477 — Behavioral Detection of WinRM-Based Remote Access](https://attack.mitre.org/detectionstrategies/DET0477) |
| Analytic | AN1313 (Windows) — inbound 5985/5986, WinRM event 6, and child-process anomaly scoring |

`KnownAdminHosts` and `CommandLineAnomalyScore` from AN1313 map to the approved-origin list and the
signal-count scoring below.

## Telemetry requirements

**Required.** Process creation with parent image on all servers. Without `ParentImage` this hunt
cannot run at all.

**Optional.** Script block logging turns "PowerShell ran" into "here is what it ran" and is the
single highest-value addition for this technique. WinRM operational logs and 5985/5986 flow data
provide the source attribution that process events lack.

**Data-quality check.** Confirm `wsmprovhost.exe` appears in your process telemetry at all — run one
authorised `Invoke-Command` and look for it. If your management platform uses remoting constantly,
measure that volume before setting thresholds.

## Analytic approach

Select every child of the WinRM host processes, then score the command line for download,
encoding, in-memory execution, and writable-path indicators. Report everything, but rank by score:
in most estates the unscored population is small enough to review, and that review is what builds
the allowlist.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 7d | `TimeWindow` | Daily scheduled execution is realistic given the low volume. |
| `SuspiciousChildren` | KQL / Sigma | interpreters and transfer tools | `CommandLineAnomalyScore` | Extend with tooling seen in your incidents. |
| `ApprovedRemotingAccounts` | KQL | empty | `UserContext` | Management platform service accounts; pair with source host where possible. |
| `MinSignalCount` | KQL | 1 | `CommandLineAnomalyScore` | Raise to 2 only after the unscored population has been reviewed and allowlisted. |

## Query surfaces

- KQL: [`queries/kql/TH-007-winrm-powershell-remoting.kql`](../queries/kql/TH-007-winrm-powershell-remoting.kql)
- Sigma: [`rules/sigma/TH-007-winrm-powershell-remoting.yml`](../rules/sigma/TH-007-winrm-powershell-remoting.yml)

## Unit tests

[`tests/rules/TH-007-winrm-powershell-remoting.yml`](../tests/rules/TH-007-winrm-powershell-remoting.yml)
covers an encoded PowerShell payload under `wsmprovhost.exe`, a `certutil` download under
`winrshost.exe`, and — as negatives — a benign inventory command under WinRM and an identical
encoded command under a normal interactive parent, which belongs to TH-009 rather than here.

## Triage workflow

1. Identify the account and the source of the remoting session (WinRM operational log, 4624 type 3,
   or network flow to 5985/5986).
2. Decode and read the payload. Script block logs on the destination usually contain it verbatim.
3. Determine whether the source host is an approved management origin.
4. Look for what the payload did: file writes, outbound connections, new services or tasks.
5. Scope the same session account across other destinations in the window (see TH-004 for the
   authentication view of the same movement).

## Benign explanations

Configuration management (DSC, Ansible over WinRM, SCCM), monitoring agents, and administrators
running `Invoke-Command`. These are recognisable by a stable source, a service account, and repeated
identical command shapes.

## Escalation criteria

Escalate on encoded commands, downloads, in-memory execution, or defence tampering under a WinRM
parent; on remoting from a workstation; on a service account performing remoting it has never done;
or on any WinRM child on a tier-0 host that is not from an approved platform.

## Response considerations

Preserve the script block logs before they roll — they are often the only record of the payload.
Treat the credential as compromised, review WinRM `TrustedHosts` and listener configuration on the
destination, and confirm no persistence was left behind.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Enable Windows Remote Management | `9059e8de-3d7d-4954-a322-46161880b9cf` | Windows | Listener creation — a configuration change worth alerting on by itself |
| Remote Code Execution with PS Credentials Using Invoke-Command | `5295bd61-bd7e-4744-9d52-85962a4cf2d6` | Windows | `wsmprovhost.exe` parent with the payload as child |
| WinRM Access with Evil-WinRM | `efe86d95-44c4-4509-ae42-7bfd9d1f5b3d` | Windows | Same parent, plus interactive-shell behaviour and file upload artefacts |

## Limitations and blind spots

Payloads that stay inside PowerShell (no child process) are invisible to process telemetry — script
block logging is the only answer. WinRM over 5986 with client certificates changes attribution. If
your configuration-management platform uses remoting continuously, the signal-to-noise ratio here
collapses and the hunt should be scoped to tier-0 assets instead.

## Tuning notes

Enumerate every legitimate remoting origin before deployment. In most estates that is between one and
five platforms; anything else originating WinRM is worth a look, which makes origin allowlisting far
more effective than command-line tuning.

## Related playbooks

- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-020 WMI remote execution](TH-020-wmi-remote-execution.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0477 alignment, substring matching for switches and paths,
  unit tests including the wrong-parent negative case.
- 2026-08-31 (v1.0.0): Initial version.
