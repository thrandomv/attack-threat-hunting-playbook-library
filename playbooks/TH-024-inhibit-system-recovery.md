---
id: TH-024
name: inhibit-system-recovery
title: Inhibit system recovery (ransomware precursor)
summary: Shadow copies deleted, backup catalogs removed and recovery disabled - the last reversible moment before encryption.
status: production-candidate
severity: critical
confidence: high
version: 2.0.0
created: 2026-09-10
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Incident response
platforms: [Windows, Linux]
attack:
  primary_technique: T1490
  techniques: [T1490]
  primary_tactic: impact
  detection_strategies: [DET0329]
telemetry:
  required:
    - Process creation with command line
  optional:
    - Registry writes to System Restore and recovery keys
    - System log service events for backup and VSS services
    - Windows Backup operational log for catalog deletion
    - Cloud provider audit logs for snapshot deletion (IaaS equivalent)
surfaces:
  kql: queries/kql/TH-024-inhibit-system-recovery.kql
  sigma: rules/sigma/TH-024-inhibit-system-recovery.yml
  tests: tests/rules/TH-024-inhibit-system-recovery.yml
validation:
  atomics:
    - 43819286-91a9-4369-90ed-d31fb4da2c01
    - 6a3ff8dd-f49c-4272-a658-11c2fe58bd88
    - 263ba6cb-ea2b-41c9-9d4e-b652dadd002c
    - 42111a6f-7e7f-482c-9b1b-3cfd090b999c
    - 584331dd-75bc-4c02-9e0b-17f5fd81c748
    - 66e647d1-8741-4e43-b7c1-334760c2047f
related: [TH-014, TH-012, TH-019, TH-011]
tags: [impact, ransomware, endpoint, windows, high-value]
---

# TH-024 — Inhibit system recovery (ransomware precursor)

## Hypothesis

An adversary is removing the ability to restore systems — deleting volume shadow copies, wiping the
backup catalog, disabling Windows recovery, or turning off System Restore — immediately before
deploying encryption or destructive tooling.

## Why this matters

This is the highest-value alert in a ransomware chain because it sits at the last point where the
outcome is still reversible. It is also unusually precise: outside of a maintenance script, nothing
legitimate deletes every shadow copy on a production server. Minutes matter here, so this content
belongs in a real-time alert path, not a daily hunt.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) |
| Tactic | Impact (TA0040) |
| Detection strategy | [DET0329 — Behavioral Detection for T1490 Inhibit System Recovery](https://attack.mitre.org/detectionstrategies/DET0329) |
| Analytics | AN0933 (Windows utilities), AN0934 (Linux), AN0935 (ESXi snapshots), AN0937 (IaaS snapshot deletion) |

AN0933's mutable elements are `TimeWindow`, `CommandLinePattern` and `ParentProcessContext`. The
parent context matters: `vssadmin` invoked by a backup product differs from `vssadmin` invoked by a
PowerShell one-liner three minutes after a service was disabled.

## Telemetry requirements

**Required.** Process creation with command line, on servers and workstations alike — ransomware
operators frequently start on a workstation.

**Optional.** Registry telemetry catches System Restore being disabled without a process. The Windows
Backup operational log records catalog deletion. In cloud environments, snapshot deletion appears only
in the provider's audit log, not on the host.

**Data-quality check.** Confirm `wmic.exe`, `vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe` and
`diskshadow.exe` are all visible in your process telemetry, including on servers with restricted
agents.

## Analytic approach

Match the recovery-destruction verbs directly. Each pattern below is independently sufficient — there
is no scoring, because a single confirmed match warrants immediate response:

- `vssadmin delete shadows` / `vssadmin resize shadowstorage` (resizing to a tiny value silently
  discards copies — a quieter variant than deletion)
- `wmic shadowcopy delete` and its PowerShell equivalent
- `wbadmin delete catalog` / `delete systemstatebackup` / `delete backup`
- `bcdedit /set recoveryenabled no` and `bootstatuspolicy ignoreallfailures`
- `diskshadow` scripts performing deletion
- `reagentc /disable`, System Restore disabled through the registry, and deletion of restore points

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `ApprovedBackupParents` | KQL | empty | `ParentProcessContext` | Backup product executables, by full path. This is the only allowlist worth having here. |
| `Lookback` | KQL | 7d | `TimeWindow` | Alert in real time; the hunt window is for retro-analysis only. |
| Command patterns | KQL / Sigma | six families | `CommandLinePattern` | Add variants as new tooling appears; do not remove any to reduce noise. |
| Registry keys | Companion | SystemRestore, WinRE | — | Catches the process-free path. |

## Query surfaces

- KQL: [`queries/kql/TH-024-inhibit-system-recovery.kql`](../queries/kql/TH-024-inhibit-system-recovery.kql)
- Sigma: [`rules/sigma/TH-024-inhibit-system-recovery.yml`](../rules/sigma/TH-024-inhibit-system-recovery.yml)

## Unit tests

[`tests/rules/TH-024-inhibit-system-recovery.yml`](../tests/rules/TH-024-inhibit-system-recovery.yml)
covers `vssadmin delete shadows /all`, the WMI variant, `wbadmin delete catalog`, `bcdedit
recoveryenabled No`, and the shadow-storage resize variant; negatives cover `vssadmin list shadows`
and a backup product creating a shadow copy — the two operations that use the same binaries
legitimately.

## Triage workflow

1. Treat as an incident on first match. Do not batch, do not wait for a second signal.
2. Identify the host, account, parent process, and whether the command succeeded.
3. Check for the rest of the chain: defence impairment (TH-014), service stops, mass file
   modification, ransom notes, and lateral movement to other hosts.
4. Determine deployment scope immediately — the same command usually runs across many hosts within
   minutes, often via GPO, PsExec (TH-005), or WMI (TH-020).
5. Verify backup integrity from the backup system's own console, not from the affected host.

## Benign explanations

Backup products managing their own shadow copies, disk-space maintenance scripts, and imaging
workflows. These run from a backup product's install path or a scheduled maintenance task and are
attributable to a known parent — which is exactly what the allowlist should encode.

## Escalation criteria

Any confirmed deletion of shadow copies or backup catalogs on a production system is an incident.
Escalate with maximum urgency when the parent is a shell or script host, when it follows defence
impairment, when it appears on several hosts at once, or when it runs outside a maintenance window.

## Response considerations

Speed dominates. Isolate affected hosts immediately, block the deployment mechanism (disable the
account, block the share, remove the GPO or scheduled task), and confirm offline or immutable backups
are intact. Preserve evidence where possible, but containment takes priority over collection at this
stage of the chain.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Windows - Delete Volume Shadow Copies | `43819286-91a9-4369-90ed-d31fb4da2c01` | Windows | `vssadmin delete shadows /all /quiet` |
| Windows - Delete Volume Shadow Copies via WMI | `6a3ff8dd-f49c-4272-a658-11c2fe58bd88` | Windows | `wmic shadowcopy delete` |
| Windows - wbadmin Delete Windows Backup Catalog | `263ba6cb-ea2b-41c9-9d4e-b652dadd002c` | Windows | `wbadmin delete catalog -quiet` |
| Windows - Delete Volume Shadow Copies via Diskshadow | `42111a6f-7e7f-482c-9b1b-3cfd090b999c` | Windows | `diskshadow` script execution |
| Windows - wbadmin Delete systemstatebackup | `584331dd-75bc-4c02-9e0b-17f5fd81c748` | Windows | System state backup deletion |
| Disable System Restore Through Registry | `66e647d1-8741-4e43-b7c1-334760c2047f` | Windows | Registry-only path with no recovery utility involved |

Run these on a disposable lab host with no data you need. They destroy real recovery points.

## Limitations and blind spots

Ransomware families increasingly call the VSS COM API directly, deleting shadow copies with no
command line at all — EDR behavioural detection is the only coverage there. Cloud snapshot deletion
appears in the provider's audit log, not on the host. Linux and ESXi equivalents (removing recovery
partitions, `snapshot.removeall`) need separate content per ATT&CK's AN0934 and AN0935. Deletion via
GPO or a management platform can look like administration.

## Tuning notes

Enumerate the parents that legitimately touch these utilities over 30 days — typically one backup
product and one maintenance script. Allowlist those by full path and treat every other invocation as
an incident. Resist the temptation to tune out `vssadmin` entirely because a backup agent is noisy;
scope the allowlist to that agent instead.

## Related playbooks

- [TH-011 Scheduled task persistence](TH-011-scheduled-task-persistence.md)
- [TH-012 Windows service creation](TH-012-windows-service-creation.md)
- [TH-014 Impair defenses](TH-014-impair-defenses.md)
- [TH-019 Archive and stage data](TH-019-archive-stage-data.md)

## Change log

- 2026-09-10 (v2.0.0): New playbook; takes over the recovery-deletion branch previously mixed into
  TH-014, which ATT&CK classifies as Impact / T1490 rather than Defense Impairment.
