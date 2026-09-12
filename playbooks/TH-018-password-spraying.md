---
id: TH-018
name: password-spraying
title: Password spraying against Entra ID
summary: One source attempting a small number of passwords against many accounts, with explicit separation of "wrong password" from "right password, MFA blocked".
status: production-candidate
severity: high
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Entra ID, Windows]
attack:
  primary_technique: T1110.003
  techniques: [T1110.003]
  primary_tactic: credential-access
  detection_strategies: [DET0487]
telemetry:
  required:
    - Entra ID SigninLogs (interactive and non-interactive) with ResultType
  optional:
    - AADNonInteractiveUserSignInLogs - legacy-protocol spraying often appears only here
    - Security 4625 for the on-premises equivalent
    - Identity Protection risk detections and named-location reference data
surfaces:
  kql: queries/kql/TH-018-password-spraying.kql
  sigma: rules/sigma/TH-018-password-spraying.yml
  tests: tests/rules/TH-018-password-spraying.yml
validation:
  atomics:
    - a8aa2d3e-1c52-4016-bc73-0f8854cfa80a
    - 90bc2e54-6c84-47a5-9439-0a2a92b4b175
    - f14d956a-5b6e-4a93-847f-0c415142f07d
related: [TH-004, TH-006, TH-023, TH-013]
tags: [credential-access, identity, cloud, entra]
---

# TH-018 — Password spraying against Entra ID

## Hypothesis

An adversary is attempting a small number of common passwords against a large number of accounts from
one source, staying under per-account lockout thresholds, and will convert any success into access.

## Why this matters

Spraying is the highest-volume credential attack against cloud identity, it defeats lockout policy by
design, and its success is often invisible in the failure data — the interesting event is the one
sign-in that *stops failing*. Detection quality depends almost entirely on interpreting result codes
correctly.

**The v2 correction.** The v1 content treated *every* non-zero `ResultType` as a failed password. That
is wrong in a way that matters twice over:

- It **over-counts**: account-disabled (50057), Conditional Access block (53003) and expired-password
  (50055) results are not password guesses, so tenants with disabled accounts or strict CA policies
  generate constant phantom "sprays".
- It **under-reports severity**: `50074`, `50076`, `50079` and `500121` mean the first factor was
  accepted and the sign-in stopped at MFA. Those are not failures — they are **credential
  compromises that MFA contained**, and they deserve a higher severity than the spray itself.

v2 classifies result codes explicitly and adds a temporal correlation that fires when a spraying
source produces any credential-valid outcome.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| Tactic | Credential Access (TA0006) |
| Detection strategy | [DET0487 — Distributed Password Spraying via Authentication Failures Across Multiple Accounts](https://attack.mitre.org/detectionstrategies/DET0487) |
| Analytics | AN1339 (Identity Provider), AN1336 (Windows), AN1343 (SaaS) and five more |

AN1339's mutable elements are `GeoIPAnomalyCheck` and `FailedUserRatio`; AN1336 adds
`PasswordReuseThreshold`, `TimeWindow` and `TargetGroupFilter`.

## Telemetry requirements

**Required.** `SigninLogs` with `ResultType`, `UserPrincipalName`, `IPAddress`, `AppDisplayName`, and
`ClientAppUsed`.

**Optional but frequently decisive.** `AADNonInteractiveUserSignInLogs` — spraying against legacy
authentication endpoints (SMTP AUTH, IMAP, EWS, ActiveSync) often never appears in the interactive
log. If you only monitor `SigninLogs`, you are watching the front door while the side door is open.

**Data-quality check.** Confirm both sign-in log types are ingested, and confirm which `ResultType`
values actually occur in your tenant before setting the classification lists — code usage varies with
tenant configuration.

## Analytic approach

Three layers:

1. **Failure classification.** Only genuine credential-guess results count toward the spray
   threshold (50126, 50053, 50055, 50056).
2. **Spray shape.** One source, many distinct users, few attempts per user, inside a short window.
   Attempts-per-user is the discriminator that separates spraying from brute force.
3. **Outcome correlation.** Any success (0) or credential-valid-but-MFA outcome
   (50074, 50076, 50079, 500121, 53003) from the same source in the same window escalates the alert
   to critical, because the password guess worked.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `MinDistinctUsers` | KQL / correlation | 10 | `FailedUserRatio` | Scale to tenant size; 10 is right for a few thousand accounts. |
| `Window` | KQL / correlation | 20m / 10m | `TimeWindow` | Slow sprays need hours — run a second pass at 24h with a higher user count. |
| `MaxAttemptsPerUser` | KQL | 3.0 | `PasswordReuseThreshold` | Above ~5 the behaviour is brute force, not spraying. |
| `PasswordFailureCodes` | KQL / Sigma | 50126, 50053, 50055, 50056 | — | Verify against your tenant's observed codes. |
| `CredentialValidCodes` | KQL / Sigma | 0, 50074, 50076, 50079, 500121, 53003 | — | These are the escalation triggers, not noise. |
| `KnownEgressIps` | KQL | placeholder | `GeoIPAnomalyCheck` | Corporate NAT and VPN egress; maintain as reference data, and prefer named locations. |

## Query surfaces

- KQL: [`queries/kql/TH-018-password-spraying.kql`](../queries/kql/TH-018-password-spraying.kql)
- Sigma: [`rules/sigma/TH-018-password-spraying.yml`](../rules/sigma/TH-018-password-spraying.yml) —
  four documents: two base events, a `value_count` spray correlation, and a `temporal` correlation
  that pairs spraying with a credential-valid outcome.

## Unit tests

[`tests/rules/TH-018-password-spraying.yml`](../tests/rules/TH-018-password-spraying.yml) locks in the
v2 correction: `50057` (account disabled) and `53003` (Conditional Access block) must **not** count as
password failures, `50074` must be recognised as credential-valid, the spray correlation must fire on
twelve users in ten minutes, and the temporal correlation must fire only when a spray is followed by a
credential-valid result from the same source.

## Triage workflow

1. Classify the source: corporate egress, known VPN, residential proxy, hosting provider, or Tor.
   Named locations and ASN enrichment answer this in seconds.
2. Determine whether any account succeeded, and whether any produced an MFA-blocked result — those
   passwords are compromised regardless of the eventual outcome.
3. Check what the successful sessions did afterwards: token issuance, app consent (TH-023), mailbox
   rule creation, or enterprise application access.
4. Look for pattern: alphabetical user lists suggest enumeration from a harvested directory; targeted
   lists suggest reconnaissance.
5. Check the non-interactive log for the same source — legacy protocols often carry the real attempt.
6. Scope other sources exhibiting the same user list or user-agent within the period.

## Benign explanations

Corporate NAT and VPN egress concentrating many users behind one address, stale credentials on
mobile devices and mail clients after a password change, misconfigured service accounts, identity
migrations, and authorised security testing. All of these are identifiable by result-code profile:
stale clients repeat against *one* user, not many.

## Escalation criteria

Escalate to incident on any success or credential-valid result from a spraying source; on sources
from hosting or anonymising infrastructure; on targeting of privileged or executive accounts; and on
spraying that continues after credential resets.

## Response considerations

Reset the credentials of every account with a credential-valid result, not only those that fully
signed in. Revoke refresh tokens — a password reset alone does not end an existing session. Block or
challenge the source, apply Conditional Access to the affected users, and confirm legacy
authentication is disabled, which removes the most common spraying path outright.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Password spray all Azure AD users with a single password | `a8aa2d3e-1c52-4016-bc73-0f8854cfa80a` | Entra ID | `SigninLogs` 50126 across many UPNs from one source |
| Password Spray all Domain Users | `90bc2e54-6c84-47a5-9439-0a2a92b4b175` | Windows | On-premises 4625 equivalent |
| Password spray all AD domain users with a single password | `f14d956a-5b6e-4a93-847f-0c415142f07d` | Windows | Same, different tooling |

Run only against a lab tenant or a directory you own, with prior written approval. Spraying a
production tenant causes lockouts and is indistinguishable from an attack to anyone watching.

## Limitations and blind spots

Distributed spraying from many source addresses defeats source-based aggregation — aggregate by
password-attempt pattern or by user-agent instead. Slow sprays under the window are invisible by
design. Attacks against legacy endpoints may appear only in the non-interactive log. Federated
tenants may authenticate on-premises, so the evidence lives in ADFS or domain controller logs
instead.

## Tuning notes

Measure the distinct-failed-user distribution per source over 30 days and set `MinDistinctUsers` above
your largest legitimate NAT egress. Prefer named locations over raw IP allowlists, and never allowlist
a source without also excluding it from the credential-valid correlation — a spray from behind
corporate NAT is still a spray.

## Related playbooks

- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-006 RDP lateral movement](TH-006-rdp-lateral-movement.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-023 Entra application and consent abuse](TH-023-entra-oauth-consent-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): **Result-code classification replacing "everything non-zero is a failure"**,
  credential-valid escalation path, temporal correlation, non-interactive log guidance, unit tests
  covering the 50057 and 53003 regressions.
- 2026-08-31 (v1.0.0): Initial version.
