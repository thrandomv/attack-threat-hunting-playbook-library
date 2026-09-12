---
id: TH-004
name: pass-the-hash
title: Pass the Hash and NTLM credential reuse
summary: NTLM network logon fan-out from one source, consistent with reuse of stolen hashes rather than interactive authentication.
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
  primary_technique: T1550.002
  techniques: [T1550.002]
  primary_tactic: lateral-movement
  detection_strategies: [DET0409]
telemetry:
  required:
    - Security 4624 from destination systems, including LogonType, AuthenticationPackageName and IpAddress
  optional:
    - Security 4648 (explicit credential use) from the source host
    - Security 4776 (NTLM validation) from domain controllers
    - Process and network telemetry on the source host
surfaces:
  kql: queries/kql/TH-004-pass-the-hash.kql
  sigma: rules/sigma/TH-004-pass-the-hash.yml
  tests: tests/rules/TH-004-pass-the-hash.yml
validation:
  atomics:
    - ec23cef9-27d9-46e4-a68d-6f75f7b86908
    - eb05b028-16c8-4ad8-adea-6f5b219da9a9
    - f8757545-b00a-4e4e-8cfb-8cfb961ee713
related: [TH-001, TH-005, TH-006, TH-020]
tags: [lateral-movement, identity, windows, ntlm]
---

# TH-004 — Pass the Hash and NTLM credential reuse

## Hypothesis

An adversary holding a stolen NTLM hash is authenticating to multiple systems from a single source
in a short interval, producing network logons that carry no interactive session and no preceding
Kerberos activity for that account.

## Why this matters

Pass-the-Hash produces protocol-legal authentication: nothing fails, nothing is malformed. The only
reliable signal is behavioural — one source, one account, many destinations, in minutes, over NTLM
in an estate that mostly speaks Kerberos. Detecting it early is what separates a contained endpoint
compromise from an estate-wide incident.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1550.002 — Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) |
| Tactic | Lateral Movement (TA0008) |
| Detection strategy | [DET0409 — Detection Strategy for T1550.002 Pass the Hash](https://attack.mitre.org/detectionstrategies/DET0409) |
| Analytic | AN1144 (Windows) — 4624/4648 correlation with logon-type and source-anomaly thresholds |

AN1144's mutable elements are `TimeWindow`, `SourceAccountAnomalyThreshold`, and `LogonTypeFilter`,
which map to the window, destination-count threshold, and logon-type list below.

## Telemetry requirements

**Required.** Security 4624 collected from destination systems — not only domain controllers. NTLM
network logons authenticate against the destination, so DC-only collection will show 4776 but not
the fan-out. `AuthenticationPackageName`, `LogonProcessName`, `LogonType`, `IpAddress` and
`WorkstationName` must all be present.

**Optional.** 4648 on the source host names the process performing explicit credential use — the
strongest corroboration available. 4776 gives domain-wide NTLM visibility when endpoint collection
is incomplete.

**Data-quality check.** Confirm 4624 events arrive from member servers and workstations, not just
DCs, and that `IpAddress` is populated rather than `-`. Sample one known-good admin session and
trace it end to end before trusting the analytic.

## Analytic approach

Count distinct destination systems per source address and account inside a sliding window, restricted
to NTLM network logons (LogonType 3) and, optionally, LogonType 9 (`NewCredentials` — the
`runas /netonly` pattern used by over-pass-the-hash tooling). Exclude machine accounts and
`ANONYMOUS LOGON`, which produce constant benign NTLM traffic, and exclude documented scanners by
source address plus account.

Fan-out is the signal. A single NTLM logon is unremarkable; the same account reaching five systems in
ten minutes from a workstation is not.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Window` | KQL / correlation | 30m | `TimeWindow` | Shorter windows favour precision; longer windows catch paced movement. |
| `MinDistinctTargets` | KQL / correlation | 3 | `SourceAccountAnomalyThreshold` | Raise in estates with legitimate management fan-out, and pair with an asset-tier filter instead. |
| `LogonTypes` | KQL | 3, 9 | `LogonTypeFilter` | Drop 9 if `runas /netonly` is common in your admin workflow, and document why. |
| `ApprovedSources` | KQL / Sigma | placeholder | — | Vulnerability scanners and management servers; allowlist by source **and** account. |

## Query surfaces

- KQL: [`queries/kql/TH-004-pass-the-hash.kql`](../queries/kql/TH-004-pass-the-hash.kql)
- Sigma: [`rules/sigma/TH-004-pass-the-hash.yml`](../rules/sigma/TH-004-pass-the-hash.yml) — base
  NTLM network-logon event plus a `value_count` correlation on destination breadth.

## Unit tests

[`tests/rules/TH-004-pass-the-hash.yml`](../tests/rules/TH-004-pass-the-hash.yml) proves the base
rule ignores machine accounts, `ANONYMOUS LOGON`, and Kerberos logons, and that the correlation fires
on three destinations in one window but not on repeated logons to a single destination.

## Triage workflow

1. Identify the account and whether NTLM is expected for it at all. Service accounts pinned to
   Kerberos that suddenly authenticate over NTLM are a strong lead.
2. Identify the source host and its owner. A workstation reaching servers it has never touched is
   different from a jump host doing its job.
3. Pull 4648 from the source host to name the process that used the credentials.
4. Check for a preceding credential-access event on the source (TH-001, TH-003).
5. Map the destinations: are they a random spread, or a targeted path toward tier-0?
6. Look for what happened *after* the logon on each destination — service creation (TH-005, TH-012),
   scheduled tasks (TH-011), WMI (TH-020).

## Benign explanations

Vulnerability scanners, backup and inventory agents, legacy applications that cannot use Kerberos,
IP-literal connections (which force NTLM), and administrators using `runas /netonly`. Each has a
stable source and account pairing; that pairing, not the account alone, is what belongs on an
allowlist.

## Escalation criteria

Escalate when the account is privileged, when the source is a user workstation, when destinations
include domain controllers or tier-0 assets, when the fan-out is faster than a human could type, or
when the same account authenticates from two sources in overlapping windows.

## Response considerations

Reset the account's credentials and, if the hash may be cached elsewhere, treat every host with a
recent session for that account as exposed. Preserve the source host for forensics before reimaging.
Consider enforcing SMB signing, LDAP channel binding, and NTLM restriction as the durable fix —
detection alone does not remove the primitive.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Mimikatz Pass the Hash | `ec23cef9-27d9-46e4-a68d-6f75f7b86908` | Windows | 4624 type 9/3 with NTLM, plus 4648 on the source |
| crackmapexec Pass the Hash | `eb05b028-16c8-4ad8-adea-6f5b219da9a9` | Windows | NTLM network logons across many destinations from one source |
| Invoke-WMIExec Pass the Hash | `f8757545-b00a-4e4e-8cfb-8cfb961ee713` | Windows | NTLM logon followed by WMI process creation (see TH-020) |

Run against isolated lab hosts. These tests use real credential material; never execute them with
production accounts.

## Limitations and blind spots

Single-destination movement produces no fan-out and will not alert. Over-pass-the-hash converts the
hash to a Kerberos ticket and can leave NTLM out of the picture entirely — the LogonType 9 branch is
a partial answer, not a complete one. NAT and VPN concentrators collapse many sources into one
address, both hiding attackers and creating false positives. Destination-side collection gaps are
invisible to the analytic itself.

## Tuning notes

Baseline distinct-destination counts per account and source over 30 days. The right threshold is
environment-specific and usually sits just above the busiest legitimate admin workflow. Where the
noise is a management platform, allowlist the source-and-account pair rather than raising the
threshold for everyone.

## Related playbooks

- [TH-001 LSASS memory access](TH-001-lsass-memory-access.md)
- [TH-005 PsExec and remote services](TH-005-psexec-remote-services.md)
- [TH-006 RDP lateral movement](TH-006-rdp-lateral-movement.md)
- [TH-020 WMI remote execution](TH-020-wmi-remote-execution.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0409 alignment, LogonType 9 branch, machine-account and
  anonymous-logon exclusions, Sigma correlation, unit tests.
- 2026-08-31 (v1.0.0): Initial version.
