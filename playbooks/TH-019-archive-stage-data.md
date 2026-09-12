---
id: TH-019
name: archive-stage-data
title: Data archiving and local staging before exfiltration
summary: Archive utilities used with encryption, splitting or recursion against sensitive paths, and payloads staged in temp directories.
status: hunt
severity: high
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows, Linux, macOS]
attack:
  primary_technique: T1560.001
  techniques: [T1560.001, T1074.001]
  primary_tactic: collection
  detection_strategies: [DET0298, DET0261]
telemetry:
  required:
    - Process creation with command line
  optional:
    - File creation events with size, for archive artefacts
    - File access auditing on sensitive shares (Security 4663)
    - Outbound network and cloud-storage telemetry for the transfer that follows
surfaces:
  kql: queries/kql/TH-019-archive-stage-data.kql
  sigma: rules/sigma/TH-019-archive-stage-data.yml
  tests: tests/rules/TH-019-archive-stage-data.yml
validation:
  atomics:
    - 02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0
    - d1334303-59cb-4a03-8313-b3e24d02c198
    - 2a7bc405-9555-4f49-ace2-b2ae2941d629
    - a57fbe4b-3440-452a-88a7-943531ac872a
    - 107706a5-6f9f-451a-adae-bab8c667829f
related: [TH-016, TH-017, TH-008, TH-024]
tags: [collection, exfiltration, endpoint]
---

# TH-019 — Data archiving and local staging before exfiltration

## Hypothesis

An adversary is collecting data for exfiltration: compressing directories with an archive utility,
often password-protected or split into volumes, and staging the result in a temporary directory.

## Why this matters

Archiving is the last quiet step before exfiltration, and it is the last opportunity to intervene
before data leaves. It is also one of the few techniques where the *content* of the command line
reveals the impact: the paths being archived tell you what was taken.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1560.001 — Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/), [T1074.001 — Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) |
| Tactic | Collection (TA0009) |
| Detection strategies | [DET0298](https://attack.mitre.org/detectionstrategies/DET0298), [DET0261](https://attack.mitre.org/detectionstrategies/DET0261) |
| Analytics | AN0831 (Windows archive), AN0832 (Linux), AN0724 (Windows staging) |

AN0831 names `SuspiciousExtensions`, `ProcessAllowlist` and `FileSizeThresholdMB`; AN0724 adds
`StagingDirList`. File size is the element most deployments skip and the one that best separates a
backup from an exfiltration set.

## Telemetry requirements

**Required.** Process creation with command line.

**Optional but valuable.** File-creation events with size turn "an archive was made" into "a 4 GB
archive was made in a temp directory" — a far stronger lead. File-access auditing on sensitive shares
identifies the source data.

**Data-quality check.** Confirm that archive utilities bundled with applications (7-Zip inside a
vendor directory, `tar.exe` in System32) are visible in your process telemetry.

## Analytic approach

Match archive utilities, then score: password protection or encryption, volume splitting, recursion
over sensitive paths, and output into a staging directory. Password protection and splitting are the
strongest signals — both exist to defeat inspection and size limits.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `ArchiveTools` | KQL / Sigma | 7z, rar, tar, makecab, PowerShell | `ArchiveCommands` | Add any archiver bundled with your line-of-business software. |
| `SensitiveTerms` | KQL | user, share, finance, hr, legal, backup, mail | `MonitoredDirectories` | Replace with your own sensitive share names — this list is a placeholder, not a recommendation. |
| `StagingPaths` | KQL / Sigma | temp, public, programdata | `StagingDirList` | Include any directory writable by ordinary users. |
| File size | Companion query | 100 MB | `FileSizeThresholdMB` | The best single discriminator once file telemetry is available. |

## Query surfaces

- KQL: [`queries/kql/TH-019-archive-stage-data.kql`](../queries/kql/TH-019-archive-stage-data.kql)
- Sigma: [`rules/sigma/TH-019-archive-stage-data.yml`](../rules/sigma/TH-019-archive-stage-data.yml)

## Unit tests

[`tests/rules/TH-019-archive-stage-data.yml`](../tests/rules/TH-019-archive-stage-data.yml) covers a
password-protected RAR of a user profile, a split 7-Zip archive into a temp directory, and
`Compress-Archive` staging; negatives cover a scheduled backup job archiving into a backup volume and
a developer building a release artefact.

## Triage workflow

1. Read the command line: what was archived, from where, to where, and with what protection?
2. Establish the size of the archive and whether it still exists.
3. Check the actor and whether they normally access those paths at all.
4. Look forward for the transfer: cloud storage uploads, large outbound sessions, removable media,
   DNS or web anomalies (TH-008, TH-016).
5. Look backward for the collection: file-access auditing on the source shares.
6. Scope by archive name, actor, and source paths estate-wide.

## Benign explanations

Backups, log rotation and collection, software packaging, migration projects, and users compressing
files to email. These target predictable directories, run on schedule, and rarely use password
protection or volume splitting.

## Escalation criteria

Escalate on password-protected or split archives, on archives of sensitive shares or mail stores
(`.pst`, `.ost`, `.edb`), on staging into user-writable directories, on archives created by a service
account, and on any archive followed by a large outbound transfer.

## Response considerations

Preserve the archive — it is a precise inventory of what the adversary intended to take, which is
the core of any breach-notification assessment. Establish whether it left the environment before
deleting it. Where regulated data may be involved, engage legal and privacy functions early.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Compress Data for Exfiltration With Rar | `02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0` | Windows | `rar a` with recursion |
| Compress Data and lock with password for Exfiltration with 7zip | `d1334303-59cb-4a03-8313-b3e24d02c198` | Windows | `-p` switch — the strongest single signal |
| Compress a File for Exfiltration using Makecab | `2a7bc405-9555-4f49-ace2-b2ae2941d629` | Windows | A native utility most archive lists omit |
| Zip a Folder with PowerShell for Staging in Temp | `a57fbe4b-3440-452a-88a7-943531ac872a` | Windows | `Compress-Archive` into a temp path |
| Stage data from Discovery.bat | `107706a5-6f9f-451a-adae-bab8c667829f` | Windows | Local staging without archiving |

## Limitations and blind spots

Archiving performed by a custom binary or in-memory library produces no recognisable command line.
Cloud-native collection (downloading from SharePoint or a database directly to the adversary's
infrastructure) never touches an endpoint archiver. Small, targeted archives look exactly like
ordinary user activity. Encrypted archives cannot be inspected to confirm content.

## Tuning notes

Baseline which processes create archives and where they write, then focus the rule on password
protection, splitting, and staging directories. Volume alone will drown you; those three features
will not.

## Related playbooks

- [TH-008 DNS tunneling](TH-008-dns-tunneling.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-017 Web shell behavior](TH-017-web-shell-behavior.md)
- [TH-024 Inhibit system recovery](TH-024-inhibit-system-recovery.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0298/DET0261 alignment, file-size companion query, unit tests,
  Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
