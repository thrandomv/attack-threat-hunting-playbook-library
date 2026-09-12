---
id: TH-013
name: account-group-manipulation
title: Account creation and privileged group manipulation
summary: New accounts and additions to privileged groups, matched by well-known SID rather than by localised group name.
status: production-candidate
severity: high
confidence: high
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Windows]
attack:
  primary_technique: T1098
  techniques: [T1098, T1136.001]
  primary_tactic: persistence
  detection_strategies: [DET0096, DET0447]
telemetry:
  required:
    - Security 4720, 4722, 4728, 4732, 4756 from domain controllers and member servers
  optional:
    - Security 4738 (account changed), 4767 (unlocked), 4724 (password reset)
    - Process creation for net.exe / Add-LocalGroupMember, to attribute the change to a session
    - Identity platform audit logs for the cloud equivalent (see TH-023)
surfaces:
  kql: queries/kql/TH-013-account-group-manipulation.kql
  sigma: rules/sigma/TH-013-account-group-manipulation.yml
  tests: tests/rules/TH-013-account-group-manipulation.yml
validation:
  atomics:
    - 6657864e-0323-4206-9344-ac9cd7265a4f
    - bc8be0ac-475c-4fbf-9b1d-9fffd77afbde
    - fda74566-a604-4581-a4cc-fbbe21d66559
    - a55a22e9-a3d3-42ce-bd48-2653adb8f7a9
    - 5598f7cb-cf43-455e-883a-f6008c5d46af
related: [TH-002, TH-003, TH-017, TH-023]
tags: [persistence, privilege-escalation, identity, active-directory]
---

# TH-013 — Account creation and privileged group manipulation

## Hypothesis

An adversary is establishing durable access by creating an account, re-enabling a dormant one, or
adding a principal to a privileged group — locally or in the domain.

## Why this matters

Group membership is the quietest privilege escalation available: no exploit, no malware, one event.
It is also frequently the last step before objectives (data access, ransomware deployment) and the
first thing an adversary re-establishes after eviction. The detection is cheap and precise if the
matching is done properly.

**The v2 change that matters:** matching on group *names* ("Domain Admins", "Administrators") fails
on any non-English Windows installation — a French domain shows *Admins du domaine*, a Spanish one
*Administradores*. This content matches on **well-known SIDs and RIDs**, which are identical in every
locale and survive group renaming. In a multi-region estate this is not a refinement; it is the
difference between a working detection and a silent one.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/), [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| Tactics | Persistence (TA0003), Privilege Escalation (TA0004) |
| Detection strategies | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096), [DET0447](https://attack.mitre.org/detectionstrategies/DET0447) |
| Analytics | AN0265 (Windows account-manipulation chain), AN1235 (local account creation) |

AN0265 names `HighPrivilegeGroupList` and `SubjectTargetMismatch` as tunable elements. The SID list
below is the `HighPrivilegeGroupList`; the mismatch check — actor differs from target, and the actor
is not a delegated identity-management service — is the highest-value enrichment to add locally.

## Telemetry requirements

**Required.** Account-management events from domain controllers *and* member servers. Local group
additions on a member server never reach a DC, and local administrator persistence is exactly what
an adversary wants after lateral movement.

**Optional.** Process telemetry links the change to a session and a tool (`net localgroup`,
`Add-LocalGroupMember`, `dsadd`), which speeds triage considerably.

**Data-quality check.** Confirm that `TargetSid` (the group SID for 4728/4732/4756) is present in
your parsed events. If your pipeline drops it, the SID-based matching cannot work and you are back to
locale-dependent names.

## Analytic approach

Two rules. The first matches privileged group additions by SID: domain RIDs `-512` (Domain Admins),
`-518` (Schema Admins), `-519` (Enterprise Admins), `-520` (Group Policy Creator Owners), and the
built-in local SIDs `S-1-5-32-544` (Administrators), `-548` (Account Operators), `-549` (Server
Operators), `-551` (Backup Operators). The second matches account creation and re-enablement, which
is lower severity but essential context.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `PrivilegedGroupSids` | KQL / Sigma | 8 well-known SIDs | `HighPrivilegeGroupList` | Add your own tier-0 group SIDs (DnsAdmins, backup operators equivalents) — those RIDs are environment-specific. |
| `ApprovedIdentityActors` | KQL | empty | `SubjectTargetMismatch` | Identity-management service accounts (IAM/PAM platforms) that legitimately change membership. |
| `Lookback` | KQL | 7d | `TimeWindow` | 30d is reasonable — this event volume is low. |
| Account-creation branch | Sigma doc 2 | level medium | — | Raise to high on domain controllers and tier-0 servers. |

## Query surfaces

- KQL: [`queries/kql/TH-013-account-group-manipulation.kql`](../queries/kql/TH-013-account-group-manipulation.kql)
- Sigma: [`rules/sigma/TH-013-account-group-manipulation.yml`](../rules/sigma/TH-013-account-group-manipulation.yml)

## Unit tests

[`tests/rules/TH-013-account-group-manipulation.yml`](../tests/rules/TH-013-account-group-manipulation.yml)
includes the case that justifies the whole approach: a **French-locale** Domain Admins addition where
`TargetUserName` is `Admins du domaine` and only the SID identifies the group. It fires. A name-based
rule would not.

## Triage workflow

1. Identify actor, target, group, and source host. An actor adding *themselves* is a strong signal.
2. Check whether a change record exists and whether the actor is authorised to modify that group.
3. Check the target account: when was it created, when did it last log on, does it have an owner?
4. Look backwards: how did the actor obtain the rights to make this change (TH-002, TH-003, TH-021)?
5. Look forwards: what did the target account do after the change?
6. Scope other membership changes by the same actor in the surrounding period.

## Benign explanations

Onboarding, break-glass procedures, identity-management platforms, and delegated administration.
All of these are attributable to a service account or a documented process — a privileged group
change made by an interactive user at 02:00 without a ticket is not one of them.

## Escalation criteria

Escalate on any tier-0 group addition without a change record, on self-addition, on changes made by
a service account that does not manage identity, on account creation on a domain controller, and on
re-enablement of a long-dormant privileged account.

## Response considerations

Reverse the change only after capturing the evidence and understanding how the rights were obtained
— removing the membership without closing the path invites an immediate repeat. Review the actor's
own access, rotate affected credentials, and check for parallel persistence (TH-011, TH-012).

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Create a new user in a command prompt | `6657864e-0323-4206-9344-ac9cd7265a4f` | Windows | 4720 plus `net user` process evidence |
| Create a new user in PowerShell | `bc8be0ac-475c-4fbf-9b1d-9fffd77afbde` | Windows | 4720 with no `net.exe` process |
| Create a new Windows admin user | `fda74566-a604-4581-a4cc-fbbe21d66559` | Windows | 4720 followed by 4732 with SID `S-1-5-32-544` |
| Domain Account and Group Manipulate | `a55a22e9-a3d3-42ce-bd48-2653adb8f7a9` | Windows | 4728 with a domain group SID |
| Admin Account Manipulate | `5598f7cb-cf43-455e-883a-f6008c5d46af` | Windows | Account modification chain |

## Limitations and blind spots

Nested groups hide privilege: adding an account to an innocuous group that is itself a member of
Domain Admins produces an event with a non-privileged SID. Enumerate nested membership and add those
SIDs. Delegated ACL changes (granting rights directly on an OU) grant privilege with no group event
at all. Cloud-only identity changes are covered by TH-023, not here.

## Tuning notes

Extract your true tier-0 group SIDs — including nested ones — from Active Directory and maintain them
as reference data. Review after every organisational change; group structures drift faster than
detection content.

## Related playbooks

- [TH-002 DCSync replication abuse](TH-002-dcsync-replication-abuse.md)
- [TH-003 Kerberoasting](TH-003-kerberoasting.md)
- [TH-017 Web shell behavior](TH-017-web-shell-behavior.md)
- [TH-023 Entra application and consent abuse](TH-023-entra-oauth-consent-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0096/DET0447 alignment, **SID-based group matching replacing
  locale-dependent name matching**, split creation and privilege branches, unit tests including a
  French-locale regression case.
- 2026-08-31 (v1.0.0): Initial version.
