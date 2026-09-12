---
id: TH-025
name: linux-cron-systemd-persistence
title: Linux cron and systemd persistence
summary: Scheduled jobs and service units created or modified to re-execute a payload on Linux hosts.
status: production-candidate
severity: high
confidence: medium
version: 2.0.0
created: 2026-09-10
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Linux]
attack:
  primary_technique: T1543.002
  techniques: [T1543.002, T1053.003]
  primary_tactic: persistence
  detection_strategies: [DET0253, DET0290]
telemetry:
  required:
    - Process creation on Linux (Microsoft Defender for Endpoint on Linux, Sysmon for Linux, or auditd execve)
    - File creation and modification events for cron and systemd unit paths
  optional:
    - auditd watches on /etc/cron*, /var/spool/cron, /etc/systemd/system and /usr/lib/systemd/system
    - syslog and journald entries for systemd unit reloads
    - Package manager logs, to separate installs from hand-edited units
surfaces:
  kql: queries/kql/TH-025-linux-cron-systemd-persistence.kql
  sigma: rules/sigma/TH-025-linux-cron-systemd-persistence.yml
  tests: tests/rules/TH-025-linux-cron-systemd-persistence.yml
validation:
  atomics:
    - 435057fb-74b1-410e-9403-d81baf194f75
    - 078e69eb-d9fb-450e-b9d0-2e118217c846
    - 2d943c18-e74a-44bf-936f-25ade6cccab4
    - d9e4f24f-aa67-4c6e-bcbf-85622b697a7c
    - c35ac4a8-19de-43af-b9f8-755da7e89c89
related: [TH-011, TH-012, TH-016, TH-017]
tags: [persistence, privilege-escalation, linux, endpoint]
---

# TH-025 — Linux cron and systemd persistence

## Hypothesis

An adversary is establishing persistence on a Linux host by installing a cron job or a systemd
service unit that re-executes a payload — often referencing a script in a world-writable directory,
or fetching and piping remote content to a shell.

## Why this matters

Linux persistence is under-monitored in most Windows-centric SOCs, and Linux hosts are exactly where
internet-facing applications, container hosts, and build infrastructure live. Both mechanisms are
simple, documented, and survive reboots; systemd units additionally run as root by default. The
observable is the write or the command, not the later execution, which looks like normal scheduling.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1543.002 — Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/), [T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) |
| Tactics | Persistence (TA0003), Privilege Escalation (TA0004), Execution (TA0002) |
| Detection strategies | [DET0253](https://attack.mitre.org/detectionstrategies/DET0253), [DET0290](https://attack.mitre.org/detectionstrategies/DET0290) |
| Analytics | AN0701 (systemd unit creation and modification), AN0805 (cron file writes and execution) |

AN0701's mutable elements — `ServicePathRegex`, `ExecStartPathAllowlist`, `UserContextFilter`,
`SystemctlOperationSet` — map directly to the unit-path and `ExecStart` checks below.

## Telemetry requirements

**Required.** Either process telemetry from a Linux EDR sensor, or `auditd` execve records. Without
one of these, only the file-write half of the technique is visible.

**Optional but strongly recommended.** File-integrity monitoring or `auditd` watches on the cron and
systemd directories. Many adversaries write the unit file directly rather than calling `systemctl`,
which makes the file event the only evidence.

**Data-quality check.** Confirm Linux telemetry is arriving at all, and that both root and
non-root process events are visible. Confirm that unit-file writes generate events — a watch rule
that is present but not loaded produces silence that looks like safety.

## Analytic approach

Two branches:

1. **Command evidence** — `crontab -e`/`crontab <file>`, `systemctl enable|start`, `systemd-run`, and
   writes into cron or unit directories performed with `tee`, `cp`, `mv` or a redirect.
2. **Content evidence** — a unit or cron entry whose action references `/tmp`, `/dev/shm`, `/var/tmp`,
   a user home directory, a download-and-pipe-to-shell chain, or a base64 decode.

The content branch is what distinguishes an adversary's unit from the dozens that a package manager
installs legitimately.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `SuspiciousPaths` | KQL / Sigma | /tmp, /dev/shm, /var/tmp, home dirs | `ExecStartPathAllowlist` | Invert where possible: allowlist `/usr/bin`, `/usr/sbin`, `/opt/<vendor>` and alert on everything else. |
| `UnitDirectories` | KQL / Sigma | systemd system and user paths | `ServicePathRegex` | Include `~/.config/systemd/user` — user units need no root. |
| `ApprovedActors` | KQL | package managers | `UserContextFilter` | apt, dpkg, yum, dnf, rpm, and your configuration-management agent. |
| `Lookback` | KQL | 7d | — | 30d for retro-hunting after any Linux-facing incident. |

## Query surfaces

- KQL: [`queries/kql/TH-025-linux-cron-systemd-persistence.kql`](../queries/kql/TH-025-linux-cron-systemd-persistence.kql)
- Sigma: [`rules/sigma/TH-025-linux-cron-systemd-persistence.yml`](../rules/sigma/TH-025-linux-cron-systemd-persistence.yml)
  — process-based and file-based rules, because either half can occur alone.

## Unit tests

[`tests/rules/TH-025-linux-cron-systemd-persistence.yml`](../tests/rules/TH-025-linux-cron-systemd-persistence.yml)
covers a cron entry written into `/etc/cron.d` with a curl-to-shell payload, `systemctl enable` of a
unit staged in `/tmp`, and a unit file written to `/etc/systemd/system`; negatives cover `crontab -l`
and a package manager installing a unit file.

## Triage workflow

1. Read the job or unit: schedule or trigger, the user it runs as, and the exact command.
2. Locate and hash the referenced payload; check its creation time and owner.
3. Identify who created it: process, parent, session, and whether the session arrived over SSH from an
   expected source.
4. Check whether it has already executed — journald and cron logs record it.
5. Look for parallel persistence: `~/.bashrc`, `/etc/rc.local`, `ld.so.preload`, SSH
   `authorized_keys`, and user-level systemd units.
6. Scope the same unit name, payload hash, or command across the Linux estate.

## Benign explanations

Package installation, configuration management (Ansible, Puppet, Chef, Salt), container and
orchestration tooling, and administrators scheduling maintenance. These write to standard paths, run
as a package manager or automation account, and reference binaries under `/usr` or `/opt`.

## Escalation criteria

Escalate on payloads in world-writable directories, on download-and-execute chains, on units created
by a web server or application account, on user-level units created for a service account, and on any
persistence created outside a change window on an internet-facing host.

## Response considerations

Capture the unit or cron file and the payload before removal, and check whether the payload has
already run. Remember `systemctl daemon-reload` and `systemctl disable` both matter — removing the
file alone may leave a running service. Verify no user-level units remain under user home
directories, which a root-focused review will miss.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Cron - Replace crontab with referenced file | `435057fb-74b1-410e-9403-d81baf194f75` | Linux, macOS | `crontab <file>` execution |
| Cron - Add script to /etc/cron.d folder | `078e69eb-d9fb-450e-b9d0-2e118217c846` | Linux | File write into `/etc/cron.d` |
| Cron - Add script to /var/spool/cron/crontabs/ folder | `2d943c18-e74a-44bf-936f-25ade6cccab4` | Linux | Direct spool write, bypassing `crontab` |
| Create Systemd Service | `d9e4f24f-aa67-4c6e-bcbf-85622b697a7c` | Linux | Unit file creation |
| Create Systemd Service file, enable, modify and reload | `c35ac4a8-19de-43af-b9f8-755da7e89c89` | Linux | Full lifecycle including `daemon-reload` |

The spool-write test is the one that proves whether your deployment sees direct file writes or only
`crontab` invocations.

## Limitations and blind spots

Persistence mechanisms outside cron and systemd — shell profile files, `ld.so.preload`, SSH keys,
init scripts, container image modification — are not covered here and deserve their own content.
User-level systemd units under home directories are frequently missed by monitoring scoped to
`/etc`. Containers restart from images, so persistence inside a running container may vanish before
it is investigated while the compromised image persists.

## Tuning notes

Inventory the existing units and cron entries per host role once; the legitimate set is stable and
mostly package-installed. After that, alert on *new* entries whose `ExecStart` or command falls
outside `/usr`, `/opt` and your agent paths.

## Related playbooks

- [TH-011 Scheduled task persistence](TH-011-scheduled-task-persistence.md)
- [TH-012 Windows service creation](TH-012-windows-service-creation.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-017 Web shell behavior](TH-017-web-shell-behavior.md)

## Change log

- 2026-09-10 (v2.0.0): New playbook; first Linux-native content in the library.
