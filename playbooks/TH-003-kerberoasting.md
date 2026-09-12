---
id: TH-003
name: kerberoasting
title: Kerberoasting service ticket harvesting
summary: Bursts of service-ticket requests for user-backed SPNs, especially with RC4 encryption, used to crack service-account passwords offline.
status: production-candidate
severity: high
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Windows]
attack:
  primary_technique: T1558.003
  techniques: [T1558.003]
  primary_tactic: credential-access
  detection_strategies: [DET0157]
telemetry:
  required:
    - Security 4769 (Kerberos service ticket request) from every domain controller
  optional:
    - Security 4768 for the preceding TGT request
    - Security 4624/4648 to place the requester on a host
    - LDAP query telemetry for SPN enumeration that precedes the roast
surfaces:
  kql: queries/kql/TH-003-kerberoasting.kql
  sigma: rules/sigma/TH-003-kerberoasting.yml
  tests: tests/rules/TH-003-kerberoasting.yml
validation:
  atomics:
    - 3f987809-3681-43c8-bcd8-b3ff3a28533a
    - 14625569-6def-4497-99ac-8e7817105b55
    - e6f4affd-d826-4871-9a62-6c9004b8fe06
    - 902f4ed2-1aba-4133-90f2-cff6d299d6da
related: [TH-002, TH-004, TH-013, TH-021]
tags: [credential-access, active-directory, identity, kerberos]
---

# TH-003 — Kerberoasting service ticket harvesting

## Hypothesis

An authenticated principal is requesting service tickets for many user-backed service principal
names in a short interval — often forcing RC4 encryption — in order to crack the service account
passwords offline.

## Why this matters

Kerberoasting needs no special privilege: any domain account can request a service ticket for any
SPN. The attack is entirely legitimate protocol behaviour, so detection depends on *shape* — how
many distinct services, how fast, from where, with what encryption type — rather than on any single
malicious event. Service accounts frequently have weak, long-lived passwords and excessive rights,
which is why this is a favourite early move after initial access.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| Tactic | Credential Access (TA0006) |
| Detection strategy | [DET0157 — Detect Kerberoasting Attempts](https://attack.mitre.org/detectionstrategies/DET0157) |
| Analytic | AN0444 (Windows) — 4769 volume and encryption-type analysis with service-account baselining |

AN0444's mutable elements — `TGSRequestThreshold`, `AllowedEncryptionTypes`, `ServiceAccountBaselines`,
`TimeWindow` — map one-to-one onto the four parameters exposed below.

## Telemetry requirements

**Required.** Security 4769 from all domain controllers, including `TicketEncryptionType`,
`ServiceName`, `TargetUserName` (the requester), `IpAddress`, and `Status`. Kerberos audit policy
must be enabled domain-wide; a DC that does not log 4769 is a hole an adversary can request through.

**Optional.** 4768 for the TGT that preceded the burst, session data to attribute the request to a
host and process, and LDAP telemetry — SPN enumeration (`setspn -q`, `GetUserSPNs`) usually precedes
the ticket burst by seconds.

**Data-quality check.** Confirm that `TicketEncryptionType` is populated and that the value format
matches what the query expects (`0x17` for RC4-HMAC, `0x12` for AES256). Some parsers normalise this
field; adjust the comparison rather than assuming.

## Analytic approach

Aggregate successful 4769 events by requester and source address over a sliding window, then alert
on breadth (distinct SPNs) rather than volume alone — an adversary enumerating twenty services once
each is far more interesting than an application requesting one ticket a thousand times.

RC4 is treated as a strong but not required signal. In an AES-only estate an RC4 request is an
anomaly worth alerting on by itself; in a mixed estate, filtering on RC4 alone will miss tooling that
requests AES tickets, which is why the encryption type is exposed as a parameter and the companion
baseline query drops it entirely.

Machine accounts and `krbtgt` are excluded because they generate constant legitimate traffic; the
exclusion is on the *service*, not the requester, so a compromised computer account performing the
roast is still visible.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `MinDistinctServices` | KQL / correlation | 10 | `TGSRequestThreshold` | Set from your 95th percentile of legitimate per-user SPN breadth over 30 days. |
| `Window` | KQL / correlation | 15m | `TimeWindow` | Lengthen to catch low-and-slow roasting; expect more baseline noise. |
| `EncryptionTypes` | KQL | `0x17` | `AllowedEncryptionTypes` | Invert in an AES-only estate: alert on anything that is *not* AES. |
| `ExcludedServices` | KQL / Sigma | `krbtgt`, machine SPNs | `ServiceAccountBaselines` | Add heavy-traffic application SPNs only after confirming their normal requester set. |

## Query surfaces

- KQL: [`queries/kql/TH-003-kerberoasting.kql`](../queries/kql/TH-003-kerberoasting.kql)
- Sigma: [`rules/sigma/TH-003-kerberoasting.yml`](../rules/sigma/TH-003-kerberoasting.yml) — a base
  event rule plus a `value_count` correlation, because a single ticket request is not a detection.

## Unit tests

[`tests/rules/TH-003-kerberoasting.yml`](../tests/rules/TH-003-kerberoasting.yml) covers the base
rule (RC4 ticket for a user-backed SPN fires; AES ticket, machine SPN and failed request do not) and
the correlation (twelve distinct SPNs in ten minutes fires; twelve requests for one SPN, and the
same breadth spread across two hours, do not).

## Triage workflow

1. Identify the requester and whether the account has any business reason to enumerate services.
2. Locate the source host from `IpAddress`, then pivot to process telemetry on that host for
   `Rubeus`, `GetUserSPNs`, PowerShell, or `setspn` execution in the same minute.
3. List the SPNs requested. Targeting of high-value service accounts (SQL, backup, ADFS, ADCS)
   raises severity immediately.
4. Check what preceded it: LDAP enumeration, a fresh logon, or a lateral movement event.
5. Assess crackability: password age, length policy, and whether the account is a member of
   privileged groups. That determines urgency, not the ticket request itself.
6. Scope the same requester and source across the full lookback, and check whether other accounts
   performed the same pattern.

## Benign explanations

Vulnerability scanners and AD assessment tools (BloodHound-style collection, PingCastle, Purple
Knight), backup and monitoring agents that enumerate services, and legitimate administrative
scripting. All of these are schedulable and originate from known hosts; the differentiator is the
combination of source host, account, and time of day.

## Escalation criteria

Escalate when the requester is a user account with no administrative function, when the source host
is a workstation, when tooling strings appear on the source host, when RC4 is requested in an
AES-only environment, or when the targeted SPNs belong to tier-0 services.

## Response considerations

Rotate the passwords of every targeted service account, prioritising those with privileged group
membership, and treat offline cracking as already successful for weak passwords. Move service
accounts to group-managed service accounts (gMSA) where possible — that removes the technique's
value rather than detecting it repeatedly. Preserve the DC logs and the source host's process
history before remediation.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Request for service tickets | `3f987809-3681-43c8-bcd8-b3ff3a28533a` | Windows | 4769 burst across many SPNs from one requester |
| Rubeus kerberoast | `14625569-6def-4497-99ac-8e7817105b55` | Windows | Same 4769 shape plus tooling on the source host |
| Extract all accounts in use as SPN using setspn | `e6f4affd-d826-4871-9a62-6c9004b8fe06` | Windows | SPN enumeration without ticket requests — the reconnaissance half |
| Request All Tickets via PowerShell | `902f4ed2-1aba-4133-90f2-cff6d299d6da` | Windows | 4769 breadth with no third-party binary on disk |

The `setspn` test is included to demonstrate a deliberate gap: enumeration alone produces no 4769
events, so if enumeration matters to you, LDAP telemetry is a separate control.

## Limitations and blind spots

Low-and-slow roasting under the threshold is invisible by design; the window and threshold are a
trade, not a solution. AES-only requests bypass the encryption filter. Requests routed through a
proxy or a NAT boundary lose source attribution. Accounts with a single high-value SPN can be roasted
in one request, producing no burst at all — accept this and compensate with password policy and gMSA
migration rather than pretending the detection covers it.

## Tuning notes

Baseline per-requester SPN breadth for 30 days before setting `MinDistinctServices`. Applications
that legitimately request many tickets (monitoring, backup) should be allowlisted by requester *and*
source host, so that stolen credentials used from elsewhere still alert.

## Related playbooks

- [TH-002 DCSync replication abuse](TH-002-dcsync-replication-abuse.md)
- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-021 AD CS certificate abuse](TH-021-adcs-certificate-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0157 alignment, Sigma correlation rule replacing the
  single-event approximation, unit tests including a low-and-slow negative case.
- 2026-08-31 (v1.0.0): Initial version.
