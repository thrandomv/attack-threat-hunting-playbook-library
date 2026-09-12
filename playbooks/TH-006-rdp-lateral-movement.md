---
id: TH-006
name: rdp-lateral-movement
title: RDP lateral movement and session fan-out
summary: Interactive remote-desktop sessions spreading from one source across multiple hosts, or arriving from places administrators never connect from.
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
  primary_technique: T1021.001
  techniques: [T1021.001]
  primary_tactic: lateral-movement
  detection_strategies: [DET0327]
telemetry:
  required:
    - Security 4624 with LogonType 10 (or 7 for reconnect) from destination systems
  optional:
    - Security 4778/4779 session connect and disconnect
    - TerminalServices-LocalSessionManager operational log
    - Network telemetry for TCP 3389 and RDP gateway logs
surfaces:
  kql: queries/kql/TH-006-rdp-lateral-movement.kql
  sigma: rules/sigma/TH-006-rdp-lateral-movement.yml
  tests: tests/rules/TH-006-rdp-lateral-movement.yml
validation:
  atomics:
    - 355d4632-8cb9-449d-91ce-b566d0253d3e
    - 2f840dd4-8a2e-4f44-beb3-6b2399ea3771
    - 01d1c6c0-faf0-408e-b368-752a02285cb2
related: [TH-004, TH-005, TH-007, TH-018]
tags: [lateral-movement, identity, windows, rdp]
---

# TH-006 — RDP lateral movement and session fan-out

## Hypothesis

An adversary with valid credentials is using Remote Desktop to move between hosts, producing
interactive logons from a source that does not normally originate them, or reaching more systems in
one window than any legitimate administrative workflow requires.

## Why this matters

RDP is the most operator-friendly lateral movement there is: full interactive access, native
tooling, and traffic that looks exactly like administration. In estates without a jump-host
architecture the benign baseline is wide, so the useful signals are *fan-out*, *direction* (server to
workstation is unusual), and *source anomaly* (a workstation originating RDP to servers).

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) |
| Tactic | Lateral Movement (TA0008) |
| Detection strategy | [DET0327 — Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity](https://attack.mitre.org/detectionstrategies/DET0327) |
| Analytic | AN0931 (Windows) — 4624/4648 with 4778/4779 session events and post-access process context |

AN0931 exposes `TimeWindow`, `UserContext`, `ProcessList` and `HostAccessPatterns`; the last is the
important one — this detection is only as good as the host-to-host access pattern you consider
normal.

## Telemetry requirements

**Required.** Security 4624 LogonType 10 from destination systems with `IpAddress` populated.
LogonType 7 (reconnect to an existing session) matters when an adversary resumes a disconnected
admin session, and is included as an option.

**Optional.** 4778/4779 give session-level connect/disconnect with client names; the
TerminalServices operational log gives the same detail where Security auditing is thin. RDP gateway
logs are the only reliable source when connections traverse a gateway that rewrites the source.

**Data-quality check.** Confirm that `IpAddress` is not `-` for RDP logons and that servers behind a
gateway are not all reporting the gateway address; if they are, this hunt must run on gateway logs
instead.

## Analytic approach

Aggregate LogonType 10 logons by account and source address, count distinct destinations in a
sliding window, and expose the direction of travel. The KQL additionally flags first-seen
source-to-destination pairs, which is usually a stronger signal than raw counts in environments where
administrators legitimately touch many hosts.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Window` | KQL / correlation | 30m | `TimeWindow` | 30m matches a working session; shorten for tighter alerting. |
| `MinDistinctTargets` | KQL / correlation | 3 | `HostAccessPatterns` | Derive from the 95th percentile of your admins' real behaviour. |
| `LogonTypes` | KQL | 10 | `UserContext` | Add 7 to catch session hijack and reconnect. |
| `ApprovedJumpHosts` | KQL / Sigma | placeholder | `HostAccessPatterns` | Allowlist the jump hosts, then alert on *anything else* originating RDP — that inversion is the highest-value tuning move available here. |

## Query surfaces

- KQL: [`queries/kql/TH-006-rdp-lateral-movement.kql`](../queries/kql/TH-006-rdp-lateral-movement.kql)
- Sigma: [`rules/sigma/TH-006-rdp-lateral-movement.yml`](../rules/sigma/TH-006-rdp-lateral-movement.yml)

## Unit tests

[`tests/rules/TH-006-rdp-lateral-movement.yml`](../tests/rules/TH-006-rdp-lateral-movement.yml)
proves the base rule ignores network logons and machine accounts, and that the correlation fires on
three destinations inside the window while staying silent for repeated reconnects to one host.

## Triage workflow

1. Confirm the account, source, and whether the source is an approved administrative origin.
2. Check the direction: workstation-to-server, server-to-workstation, or cross-tier. Cross-tier RDP
   is a policy violation regardless of intent.
3. Review what happened inside the session: process creation under the session's logon ID, clipboard
   and drive redirection, and files written.
4. Correlate with authentication anomalies before the session — password spraying (TH-018), NTLM
   fan-out (TH-004), or a fresh credential dump (TH-001).
5. Scope other destinations reached by the same account or source in the surrounding hours.

## Benign explanations

Administrators, helpdesk staff, jump hosts, RDP-based remote support tools, and automated session
brokers. The stable ones can be allowlisted by source and account; the transient ones (helpdesk
staff reaching many workstations) are better handled with an asset-tier rule than with a threshold.

## Escalation criteria

Escalate when the source is not an approved administrative origin, when the account is a service
account (service accounts should not have interactive rights), when the destination is tier-0, when
sessions fan out faster than a human workflow, or when RDP follows a credential-access hit on the
source.

## Response considerations

Terminate the session only after capturing what it did — an active RDP session is live evidence.
Reset the account, review Remote Desktop Users membership on the destinations, and check for
persistence created inside the session (TH-011, TH-012). Restricting RDP to jump hosts with
network-level authentication removes most of the attack surface.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| RDP to Remote Host | `355d4632-8cb9-449d-91ce-b566d0253d3e` | Windows | 4624 type 10 with the source address, 4778 session connect |
| Changing RDP Port to Non Standard Port via PowerShell | `2f840dd4-8a2e-4f44-beb3-6b2399ea3771` | Windows | Registry change under Terminal Server WinStations — port-based detection blind spot |
| Disable NLA for RDP via Command Prompt | `01d1c6c0-faf0-408e-b368-752a02285cb2` | Windows | Registry change weakening authentication; a hardening regression worth alerting on |

The last two tests are in this table to make a point: detections that key on TCP 3389 or on NLA being
present are trivially defeated by configuration changes that are themselves detectable.

## Limitations and blind spots

Gateways and jump hosts collapse the true source. Restored or hijacked sessions (LogonType 7) look
different from new logons. RDP over a non-standard port defeats network-based detection but not
4624-based detection. Single-hop movement produces no fan-out. Nothing here proves *what* the
operator did inside the session — that requires process telemetry correlated by logon ID.

## Tuning notes

Model normal source-to-destination pairs for 30 days and alert on new pairs involving privileged
accounts. Pair-novelty beats volume thresholds in almost every environment tested.

## Related playbooks

- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-007 WinRM and PowerShell remoting](TH-007-winrm-powershell-remoting.md)
- [TH-018 Password spraying](TH-018-password-spraying.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0327 alignment, Sigma correlation for destination fan-out,
  machine-account exclusion, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
