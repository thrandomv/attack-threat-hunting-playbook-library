---
id: TH-002
name: dcsync-replication-abuse
title: DCSync directory replication abuse
summary: Non-domain-controller principals exercising directory replication rights to pull secrets from Active Directory.
status: production-candidate
severity: critical
confidence: high
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Windows]
attack:
  primary_technique: T1003.006
  techniques: [T1003.006]
  primary_tactic: credential-access
  detection_strategies: [DET0594]
telemetry:
  required:
    - Security 4662 from every domain controller, with Directory Service Access auditing enabled
    - A SACL on the domain naming context that audits control-access rights
  optional:
    - Security 4624/4648 for the source session behind the replication request
    - Network telemetry for DRSUAPI (RPC) traffic to domain controllers
    - Security 4929 for replica destination changes
surfaces:
  kql: queries/kql/TH-002-dcsync-replication-abuse.kql
  sigma: rules/sigma/TH-002-dcsync-replication-abuse.yml
  tests: tests/rules/TH-002-dcsync-replication-abuse.yml
validation:
  atomics:
    - 129efd28-8497-4c87-a1b0-73b9a870ca3e
    - a0bced08-3fc5-4d8b-93b7-e8344739376e
related: [TH-001, TH-003, TH-013, TH-021]
tags: [credential-access, active-directory, identity, high-value]
---

# TH-002 — DCSync directory replication abuse

## Hypothesis

A principal that is not a domain controller is using the directory replication service to request
account secrets — the `krbtgt` key, service-account hashes, or an entire domain — by exercising the
*Replicating Directory Changes* rights from an ordinary workstation or server.

## Why this matters

DCSync converts one over-privileged account into complete domain compromise without touching a
domain controller's disk or memory. It is quiet, fast, and indistinguishable from replication unless
you audit the right control-access rights. Because the legitimate population of replicating
principals is tiny and well known (domain controllers, and a handful of sync services), this is one
of the rare hunts where a near-complete allowlist is achievable and precision can be very high.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1003.006 — OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/) |
| Tactic | Credential Access (TA0006) |
| Detection strategy | [DET0594 — Detection of Unauthorized DCSync Operations via Replication API Abuse](https://attack.mitre.org/detectionstrategies/DET0594) |
| Analytic | AN1632 (Windows) — 4662 control-access-right use correlated with source context |

AN1632 names `TimeWindow`, `UserContext`, and `SourceIP` as the tunable elements; `UserContext` is
the one that carries this detection, and it is expressed here as an explicit allowlist of
replication principals held as reference data rather than inline strings.

## Telemetry requirements

**Required.** Security event 4662 from *all* domain controllers. This event is not produced by
default: `Audit Directory Service Access` must be enabled and the domain object needs a SACL that
audits the control-access rights below. Verify on each DC individually — a single unaudited DC is a
blind spot an adversary only needs once.

| Right | GUID |
|---|---|
| Replicating Directory Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| Replicating Directory Changes All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| Replicating Directory Changes In Filtered Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

**Optional.** Logon events that identify the session behind the request, and network telemetry for
DRSUAPI traffic from non-DC sources — useful when audit policy is incomplete.

**Data-quality check.** Generate one authorised replication (or observe normal DC-to-DC traffic) and
confirm 4662 events arrive with the `Properties` field populated. If `Properties` is empty, the SACL
is not auditing the control-access right and this hunt cannot work.

## Analytic approach

Select 4662 events that reference a replication GUID, then subtract the known-good population:
domain controller computer accounts, the Azure AD Connect / Entra Connect sync account, and any
documented backup or migration identity. Everything left is either a misconfiguration worth fixing
or an attack. Because the expected result set is near-empty, this content is suitable for a
production alert rather than a periodic hunt.

Machine accounts are excluded *by identity, not by pattern*: an account ending in `$` is not
automatically a domain controller, and an adversary who compromises a workstation account would
otherwise be invisible. The query resolves domain controllers from a maintained list.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 14d | `TimeWindow` | Keep long; DCSync is rare and retro-hunting is cheap. |
| `ApprovedReplicationAccounts` | KQL / Sigma filter | placeholders | `UserContext` | Replace with your real DC and sync accounts, ideally by SID. Review quarterly. |
| `DomainControllerAccounts` | KQL | placeholders | `UserContext` | Maintain as a watchlist or reference table, not inline. |
| `SourceIp` projection | KQL | reported | `SourceIP` | Alert on replication from a subnet that holds no DC. |

## Query surfaces

- KQL: [`queries/kql/TH-002-dcsync-replication-abuse.kql`](../queries/kql/TH-002-dcsync-replication-abuse.kql)
- Sigma: [`rules/sigma/TH-002-dcsync-replication-abuse.yml`](../rules/sigma/TH-002-dcsync-replication-abuse.yml)

## Unit tests

[`tests/rules/TH-002-dcsync-replication-abuse.yml`](../tests/rules/TH-002-dcsync-replication-abuse.yml)
asserts a hit for a user account exercising *Replicating Directory Changes All*, and silence for
domain-controller computer accounts and the documented sync account — the two allowlist branches
that make this rule usable in production.

## Triage workflow

1. Identify the principal and its rights: does it legitimately hold replication rights, and who
   granted them? Compare with the ACL on the domain object.
2. Identify the source host and session (4624/4648 near the same timestamp) and whether the account
   was used interactively or through a tool.
3. Determine scope of the pull: a single object, a targeted account such as `krbtgt`, or the whole
   naming context.
4. Look backwards for how the rights were obtained — recent ACL changes, group membership additions
   (TH-013), or delegation changes.
5. Look forwards for use of the recovered material: golden tickets, Pass-the-Hash (TH-004), new
   privileged sessions.

## Benign explanations

Azure AD / Entra Connect synchronisation, some backup and migration products, password-audit tooling
run by the identity team, and legitimate DC promotion. All of them are schedulable, documented, and
tied to specific accounts — an unexplained replication from a workstation is not one of them.

## Escalation criteria

Treat any non-allowlisted replication as a domain-compromise incident. Escalate immediately when the
source is a workstation, when the account is an ordinary user or a recently modified service account,
or when the request targets `krbtgt`. Do not wait for confirmation of hash use.

## Response considerations

Assume full domain credential exposure. Plan a `krbtgt` reset (twice, with the replication interval
respected between resets), tiered credential rotation, and review of every replication-capable ACL.
Preserve DC security logs before rotation. Coordinate with identity owners before disabling the
account — a shared service identity may be load-bearing.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| DCSync (Active Directory) | `129efd28-8497-4c87-a1b0-73b9a870ca3e` | Windows | 4662 referencing a replication GUID from a non-DC principal |
| Run DSInternals Get-ADReplAccount | `a0bced08-3fc5-4d8b-93b7-e8344739376e` | Windows | Same 4662 signature via a different tool, proving the detection is behavioural not tool-specific |

Run against a lab domain only. Never run credential-replication tests against production Active
Directory, even with approval — the recovered material is real.

## Limitations and blind spots

If auditing is not configured the technique is invisible; verify per DC. An adversary operating from
a compromised domain controller produces expected events. Replication rights granted to a group
rather than an account can make the allowlist drift silently, so review the ACL, not just the
alerts. Network-only detection (DRSUAPI) needs east-west visibility most environments lack.

## Tuning notes

Build the allowlist from Active Directory itself (query the domain object ACL for principals holding
the replication rights) rather than from memory. Store it as a watchlist; hard-coding it in the query
guarantees drift. Re-verify after every identity-platform change.

## Related playbooks

- [TH-001 LSASS memory access](TH-001-lsass-memory-access.md)
- [TH-003 Kerberoasting](TH-003-kerberoasting.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-021 AD CS certificate abuse](TH-021-adcs-certificate-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0594 alignment, explicit DC-account handling instead of `$`
  pattern matching, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
