---
id: TH-011
name: scheduled-task-persistence
title: Scheduled task persistence and remote task creation
summary: Tasks created or modified to run interpreters, encoded payloads or content from writable paths, locally or against a remote host.
status: production-candidate
severity: medium
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: T1053.005
  techniques: [T1053.005]
  primary_tactic: persistence
  detection_strategies: [DET0441]
telemetry:
  required:
    - Process creation with command line (schtasks.exe, powershell.exe scheduled-task cmdlets)
  optional:
    - Security 4698 (task created), 4702 (task updated), 4699 (task deleted)
    - Microsoft-Windows-TaskScheduler/Operational events 106, 140, 141
    - File creation under C:\Windows\System32\Tasks
surfaces:
  kql: queries/kql/TH-011-scheduled-task-persistence.kql
  sigma: rules/sigma/TH-011-scheduled-task-persistence.yml
  tests: tests/rules/TH-011-scheduled-task-persistence.yml
validation:
  atomics:
    - 42f53695-ad4a-4546-abb6-7d837f644a71
    - 2e5eac3e-327b-4a88-a0c0-c4057039a8dd
    - af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd
    - fec27f65-db86-4c2d-b66c-61945aee87c2
related: [TH-012, TH-009, TH-005, TH-024]
tags: [persistence, execution, endpoint, windows]
---

# TH-011 — Scheduled task persistence and remote task creation

## Hypothesis

An adversary is creating or modifying a scheduled task to re-execute a payload — running as SYSTEM,
at logon or boot, pointing at an interpreter or at content in a user-writable directory, and
sometimes created remotely with `schtasks /s`.

## Why this matters

Scheduled tasks survive reboots, run with chosen privilege, and blend into an estate that already has
hundreds of legitimate tasks. They are also a lateral-movement primitive: `schtasks /s <host>` runs
code on a remote machine with no service creation at all. The observable is the *creation* event —
once the task exists, the execution looks like Task Scheduler doing its job.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tactics | Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004) |
| Detection strategy | [DET0441 — Detection of Suspicious Scheduled Task Creation and Execution on Windows](https://attack.mitre.org/detectionstrategies/DET0441) |
| Analytic | AN1221 (Windows) — 4698/4702 with task-name patterns and command-line entropy |

## Telemetry requirements

**Required.** Process creation with command line, covering both `schtasks.exe` and the PowerShell
scheduled-task cmdlets (`Register-ScheduledTask`, `New-ScheduledTaskAction`), which produce no
`schtasks.exe` process at all.

**Optional but strongly recommended.** Security 4698 records the full task XML, including the action
and principal — it is the only source that survives a deleted task and the only one that catches
tasks created through the COM API or WMI. Enable *Audit Other Object Access Events* to get it.

**Data-quality check.** Create a benign task in a test window and confirm both the process event and
4698 appear. Many estates collect neither.

## Analytic approach

Two branches: command-line evidence from `schtasks.exe` and the PowerShell cmdlets, and (in the
companion query) the task XML from 4698 parsed for its action. Score on remote target, elevated
principal, interpreter action, encoded or remote content, and writable payload paths.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 7d | `TimeWindow` | Persistence is patient; retro-hunt at 30d after any incident. |
| Task-name filters | Sigma / KQL | none | `TaskNamePattern` | Suppress known deployment task names *by full name*, never by prefix wildcard. |
| Writable paths | KQL / Sigma | temp, public, appdata | `CommandLineEntropyThreshold` | Adding a path here is a decision to stop looking at it; record why. |
| `ApprovedTaskCreators` | KQL | empty | `UserContext` | Deployment service accounts, paired with the parent process. |

## Query surfaces

- KQL: [`queries/kql/TH-011-scheduled-task-persistence.kql`](../queries/kql/TH-011-scheduled-task-persistence.kql)
- Sigma: [`rules/sigma/TH-011-scheduled-task-persistence.yml`](../rules/sigma/TH-011-scheduled-task-persistence.yml)

## Unit tests

[`tests/rules/TH-011-scheduled-task-persistence.yml`](../tests/rules/TH-011-scheduled-task-persistence.yml)
covers a SYSTEM task running encoded PowerShell, a remote task creation with `/s`, and a task action
in a public directory; negatives cover a plain task query (`/query`) and a vendor updater task
registered from `Program Files`.

## Triage workflow

1. Retrieve the task definition: name, path in the task tree, principal, trigger, and action.
   Tasks hidden in unusual subfolders or with names imitating Microsoft tasks are a strong signal.
2. Identify who created it and from which session — remote creation means investigating two hosts.
3. Analyse the action: decode encoded commands, hash the referenced binary, check its path and
   signer.
4. Check the trigger: at logon, at boot, on an interval, or on an event subscription.
5. Look for the same task name or action across the estate — persistence is usually deployed widely.
6. Check what the task has already executed (Task Scheduler operational log 129/200/201).

## Benign explanations

Software updaters, backup jobs, monitoring agents, and administrative maintenance scripts. These are
recognisable by consistent names, signed binaries in `Program Files`, and creation by an installer
process rather than by an interactive shell.

## Escalation criteria

Escalate on remote task creation, on SYSTEM principals created by non-installer processes, on encoded
or remote actions, on payloads in writable paths, and on task names that imitate Microsoft tasks.

## Response considerations

Export the task XML before deletion — it is the evidence. Remove the task and the payload together,
then confirm no other persistence remains (services, run keys, WMI subscriptions). Where the task was
created remotely, treat the source host as compromised too.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Scheduled task Local | `42f53695-ad4a-4546-abb6-7d837f644a71` | Windows | `schtasks /create` with an action, plus 4698 |
| Scheduled task Remote | `2e5eac3e-327b-4a88-a0c0-c4057039a8dd` | Windows | `/s <host>` — the lateral-movement branch |
| Powershell Cmdlet Scheduled Task | `af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd` | Windows | No `schtasks.exe` process; only the cmdlet and 4698 |
| Scheduled Task Startup Script | `fec27f65-db86-4c2d-b66c-61945aee87c2` | Windows | Boot-trigger persistence |

The PowerShell cmdlet test is the one that exposes deployments relying on `schtasks.exe` alone.

## Limitations and blind spots

Tasks created through the COM scheduler API or WMI produce no command line — 4698 is the only
coverage. Task modification (4702) is easy to miss if only creation is monitored. Legitimate
deployment tooling creates tasks constantly, so name-based suppression tends to grow until it hides
the technique; prefer principal- and path-based reasoning.

## Tuning notes

Inventory existing tasks estate-wide once, classify them by publisher, and keep that inventory. New
task names then stand out on their own, which is a far better detection than any keyword list.

## Related playbooks

- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-012 Windows service creation](TH-012-windows-service-creation.md)
- [TH-024 Inhibit system recovery](TH-024-inhibit-system-recovery.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0441 alignment, PowerShell cmdlet coverage, 4698 companion,
  substring switch matching, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
