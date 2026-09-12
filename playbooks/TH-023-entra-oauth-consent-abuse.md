---
id: TH-023
name: entra-oauth-consent-abuse
title: Entra application consent and credential abuse
summary: OAuth consent grants to attacker-controlled applications, and credentials added to existing service principals for token-based persistence.
status: production-candidate
severity: high
confidence: medium
version: 2.0.0
created: 2026-09-10
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Entra ID, Microsoft 365]
attack:
  primary_technique: T1528
  techniques: [T1528, T1098.001]
  primary_tactic: credential-access
  detection_strategies: [DET0515, DET0531]
telemetry:
  required:
    - Entra ID AuditLogs (application management and directory management categories)
  optional:
    - SigninLogs for service principal sign-ins and the token use that follows
    - Microsoft 365 unified audit log for mailbox and file access by the consented application
    - Identity Protection risk detections
surfaces:
  kql: queries/kql/TH-023-entra-oauth-consent-abuse.kql
  sigma: rules/sigma/TH-023-entra-oauth-consent-abuse.yml
  tests: tests/rules/TH-023-entra-oauth-consent-abuse.yml
validation:
  atomics:
    - b8e747c3-bdf7-4d71-bce2-f1df2a057406
    - a12b5531-acab-4618-a470-0dafb294a87a
    - 9a5352e4-56e5-45c2-9b3f-41a46d3b3a43
related: [TH-018, TH-013, TH-021, TH-019]
tags: [credential-access, persistence, identity, cloud, entra, oauth]
---

# TH-023 — Entra application consent and credential abuse

## Hypothesis

An adversary is obtaining durable access to cloud data without a password: either by persuading a
user (or an administrator) to consent to an application that requests sensitive Graph permissions, or
by adding a secret or certificate to an existing service principal they can already modify.

## Why this matters

Token-based access is the cloud equivalent of a golden ticket. It survives password resets, is not
challenged by MFA, and is frequently invisible to teams that monitor only user sign-ins. Adding a
credential to an existing, already-consented service principal is quieter still — no consent prompt,
no new application, just one audit event that most SOCs do not alert on.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/), [T1098.001 — Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) |
| Tactics | Credential Access (TA0006), Persistence (TA0003) |
| Detection strategies | [DET0515](https://attack.mitre.org/detectionstrategies/DET0515), [DET0531](https://attack.mitre.org/detectionstrategies/DET0531) |
| Analytics | AN1425 (consent grants by abnormal users or at unusual times), AN1469 (service principal credential addition) |

AN1469's mutable elements — `MFABypassMechanism`, `SourceIPAllowlist`, `ApplicationCredentialType` —
say plainly what makes this technique valuable to an adversary: the credential bypasses interactive
authentication entirely.

## Telemetry requirements

**Required.** `AuditLogs` with the application-management operations: *Consent to application*,
*Add delegated permission grant*, *Add app role assignment to service principal*, *Add service
principal credentials*, and *Update application – Certificates and secrets management*.

**Optional.** `SigninLogs` filtered to service principal sign-ins shows the token actually being used
and from where. The Microsoft 365 unified audit log shows what the application then read.

**Data-quality check.** Confirm `AuditLogs` ingestion includes the `TargetResources` structure with
`modifiedProperties`, since the granted scopes live there. Without it you can see that consent
happened but not what was granted.

## Analytic approach

Two branches, deliberately kept separate because their response differs:

1. **Consent grants**, scored by the sensitivity of the scopes requested. `Mail.Read`,
   `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `Application.ReadWrite.All`
   and `full_access_as_user` are the ones that matter; application-type (app-only) grants outrank
   delegated grants because they carry no user context at all.
2. **Credential additions** to existing service principals, especially where the actor is not an
   application administrator by role.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `HighRiskScopes` | KQL / Sigma | mail, files, directory, app write | `OAuthScopeSensitivity` | Add scopes specific to your line-of-business data. |
| `ApprovedAppPublishers` | KQL | empty | `ClientAppIDAllowList` | Allowlist by application ID, never by display name — names are attacker-controlled. |
| `ApprovedCredentialActors` | KQL | empty | `CallerIdentityContext` | Your application lifecycle platform, if you have one. |
| `Lookback` | KQL | 30d | `TimeWindow` | Long: consent persistence is discovered late, and retro-hunting is cheap. |

## Query surfaces

- KQL: [`queries/kql/TH-023-entra-oauth-consent-abuse.kql`](../queries/kql/TH-023-entra-oauth-consent-abuse.kql)
- Sigma: [`rules/sigma/TH-023-entra-oauth-consent-abuse.yml`](../rules/sigma/TH-023-entra-oauth-consent-abuse.yml)

## Unit tests

[`tests/rules/TH-023-entra-oauth-consent-abuse.yml`](../tests/rules/TH-023-entra-oauth-consent-abuse.yml)
covers consent involving mail scopes, a credential added to a service principal, and an app role
assignment; negatives cover consent to low-risk scopes (`User.Read`) and an ordinary user-management
audit event.

## Triage workflow

1. Identify the application: application ID, publisher, verification status, reply URLs, and creation
   date. A recently registered application with a generic name is a strong signal.
2. Read the granted scopes and whether the grant is delegated or application-type.
3. Identify who consented and whether they could consent for the whole tenant.
4. Check what the application did next: service principal sign-ins, mailbox access, file access,
   directory reads.
5. For credential additions, identify who added the credential and whether they should be able to.
6. Scope: other tenants' users who consented to the same application ID, and other credentials on the
   same service principal.

## Benign explanations

Legitimate SaaS integrations, in-house applications, and IT-driven onboarding of new tools. These have
verified publishers, recognisable reply URLs, and a change record. A user-consented application with
mail scopes and no publisher verification rarely does.

## Escalation criteria

Escalate on mail, file or directory write scopes; on application-type permissions granted without a
change record; on credentials added to a service principal by an account that is not an application
administrator; on consent immediately following a suspicious sign-in (TH-018); and on any application
that begins reading mailboxes at volume.

## Response considerations

Revoke the service principal's credentials and delete the consent grant, then revoke refresh tokens —
existing tokens survive consent removal until they expire. Review what the application accessed while
it held the grant; for mailbox access this determines breach notification scope. Restrict user consent
to verified publishers and low-impact scopes, and require admin consent workflows — that removes the
technique's easiest path.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Azure AD Application Hijacking - Service Principal | `b8e747c3-bdf7-4d71-bce2-f1df2a057406` | Entra ID | *Add service principal credentials* audit event |
| Azure AD Application Hijacking - App Registration | `a12b5531-acab-4618-a470-0dafb294a87a` | Entra ID | Credential added to an app registration |
| Azure - Functions code upload via Blob upload | `9a5352e4-56e5-45c2-9b3f-41a46d3b3a43` | Azure | Token abuse in an IaaS context |

Run only against a lab tenant. Consent and credential changes in production tenants are real grants
with real data access.

## Limitations and blind spots

Tokens already issued keep working after the grant is removed, so detection is not containment.
Consent performed through a phishing flow may look identical to legitimate consent — the application
identity, not the event shape, distinguishes them. Application permissions granted directly by an
administrator through the portal produce the same events as an attack. Access performed by the
application is only visible if the workload's audit log is ingested.

## Tuning notes

Inventory existing consent grants once — most tenants find surprises immediately — and build the
allowlist from application IDs, not names. Alert on new application IDs rather than on scopes alone;
the scope list changes far less often than the application population.

## Related playbooks

- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-018 Password spraying](TH-018-password-spraying.md)
- [TH-019 Archive and stage data](TH-019-archive-stage-data.md)
- [TH-021 AD CS certificate abuse](TH-021-adcs-certificate-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): New playbook.
