---
id: TH-017
name: web-shell-behavior
title: Web shell behaviour on internet-facing servers
summary: Web server processes spawning shells, discovery commands or transfer utilities - the behavioural signature of an active web shell.
status: production-candidate
severity: critical
confidence: high
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows, Linux]
attack:
  primary_technique: T1505.003
  techniques: [T1505.003]
  primary_tactic: persistence
  detection_strategies: [DET0394]
telemetry:
  required:
    - Process creation with parent image on web servers
  optional:
    - Web server access logs (POST requests, unusual user agents, response sizes)
    - File creation events in web root directories
    - Outbound network events from the web server process
surfaces:
  kql: queries/kql/TH-017-web-shell-behavior.kql
  sigma: rules/sigma/TH-017-web-shell-behavior.yml
  tests: tests/rules/TH-017-web-shell-behavior.yml
validation:
  atomics:
    - 0a2ce662-1efa-496f-a472-2fe7b080db16
related: [TH-013, TH-016, TH-009, TH-019]
tags: [persistence, initial-access, web, endpoint, high-value]
---

# TH-017 — Web shell behaviour on internet-facing servers

## Hypothesis

An adversary has placed a web shell on an internet-facing application server and is executing
commands through it, causing the web server process to spawn command interpreters, discovery
utilities, or transfer tools.

## Why this matters

Web shells are the most common entry point into internet-facing infrastructure and among the highest
severity findings in any SOC: they mean an external attacker already has command execution inside the
perimeter. The behavioural detection is unusually reliable — a web server process has almost no
legitimate reason to spawn `cmd.exe`, `whoami`, or `certutil` — which makes this one of the few
playbooks that can be deployed as a high-confidence alert with minimal tuning.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| Tactic | Persistence (TA0003) |
| Detection strategy | [DET0394 — Web Shell Detection via Server Behavior and File Execution Chains](https://attack.mitre.org/detectionstrategies/DET0394) |
| Analytics | AN1108 (Windows/IIS), AN1109 (Linux/Apache/nginx), AN1110 (macOS) |

## Telemetry requirements

**Required.** Process creation with parent image on every internet-facing server. Coverage gaps here
are common: DMZ hosts are often the last to get an EDR agent, which is precisely backwards.

**Optional.** Web access logs let you find the request that triggered the command — the single most
useful artefact for scoping. File-creation events in the web root find the shell itself, including
dormant ones that have not executed yet.

**Data-quality check.** Confirm agents are installed and reporting on DMZ and application servers,
and that the application-pool identity is visible in the `User` field.

## Analytic approach

Match any child of a web server process against three families — shells and script interpreters,
discovery commands, and transfer utilities — and score the result. Because the false-positive rate is
low, the query reports everything and expects analysts to allowlist specific application behaviours
rather than tune the technique away.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `WebParents` | KQL / Sigma | IIS, Apache, nginx, PHP, Tomcat, Node | `ParentProcess` | Add your application's runtime process names. |
| `SuspiciousChildren` | KQL / Sigma | shells, discovery, transfer | `WebRootPath` (adjacent) | Keep discovery commands in the list — they are the first thing an operator runs. |
| `ApprovedChildProcesses` | KQL | empty | — | Legitimate CGI or build behaviour, allowlisted by full path and argument shape. |
| `Lookback` | KQL | 7d | `TimeWindow` | Alert in near-real-time; hunt over 30d after any web vulnerability disclosure. |

## Query surfaces

- KQL: [`queries/kql/TH-017-web-shell-behavior.kql`](../queries/kql/TH-017-web-shell-behavior.kql)
- Sigma: [`rules/sigma/TH-017-web-shell-behavior.yml`](../rules/sigma/TH-017-web-shell-behavior.yml)

## Unit tests

[`tests/rules/TH-017-web-shell-behavior.yml`](../tests/rules/TH-017-web-shell-behavior.yml) covers
`w3wp.exe` spawning `cmd.exe`, an Apache process spawning `whoami`, and `php-cgi.exe` running
`certutil`; negatives cover an IIS worker starting a legitimate application binary and a shell spawned
by a normal interactive parent.

## Triage workflow

1. Identify the web server process, the application pool or site, and the identity it runs as.
2. Find the request that caused it in the access logs — timestamp, URL, source IP, user agent, and
   body size. That URL is usually the shell.
3. Locate the shell file on disk: recent writes into the web root, unusual extensions, files with
   mismatched ownership or timestamps.
4. Determine what the operator did: the child commands are a transcript of their session.
5. Check for privilege escalation, credential access, and lateral movement from the server.
6. Scope: other files written in the same window, other servers with the same file or URL pattern,
   and the source IPs across your estate.

## Benign explanations

Legitimate CGI applications, build and deployment jobs running on the web server, and monitoring
scripts invoked through the application. These are stable, documented, and generally do not run
`whoami` or `certutil`.

## Escalation criteria

Any confirmed match on an internet-facing server is an incident. Escalate immediately when discovery
commands appear, when a transfer utility downloads a file, when new accounts are created (TH-013), or
when the process identity is a privileged application-pool account.

## Response considerations

Preserve the shell file, the web logs, and the process history before removing anything — the shell
is evidence and often reveals the initial vulnerability. Assume the server is fully compromised: patch
the underlying vulnerability, rebuild rather than clean where practical, rotate any credential or key
stored on the host, and check for additional shells before declaring closure.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Web Shell Written to Disk | `0a2ce662-1efa-496f-a472-2fe7b080db16` | Windows | File creation in the web root — the *file* half of the technique |

Atomic Red Team currently ships one test for T1505.003, and it only covers shell placement, not
execution. To exercise the behavioural rule, run a benign command through a test page in a lab
(for example a page that executes `whoami`) and confirm the `w3wp.exe` → `cmd.exe` chain is captured.
Never place a functional shell on a production or internet-reachable server.

## Limitations and blind spots

Shells that only read or write files, or that proxy traffic, never spawn a child process. In-memory
or module-based shells (IIS modules, servlet filters) leave no file in the web root. Applications
that legitimately shell out create a persistent tuning burden. Container workloads need the same
detection at the container runtime layer, which this content does not cover.

## Tuning notes

Enumerate the legitimate children of every web server process over 30 days per application. The list
is usually very short. Anything new should be treated as an alert rather than tuned away.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-019 Archive and stage data](TH-019-archive-stage-data.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0394 alignment, Linux parent coverage, unit tests, honest
  Atomic coverage note plus a manual behavioural validation procedure.
- 2026-08-31 (v1.0.0): Initial version.
