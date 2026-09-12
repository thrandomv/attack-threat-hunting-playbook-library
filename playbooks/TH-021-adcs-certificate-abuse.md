---
id: TH-021
name: adcs-certificate-abuse
title: AD CS certificate abuse (ESC1-style misissuance)
summary: Certificate requests that specify an arbitrary subject alternative name, and the tooling that turns a certificate into a Kerberos ticket.
status: hunt
severity: critical
confidence: medium
version: 2.0.0
created: 2026-09-10
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering / Identity
platforms: [Windows]
attack:
  primary_technique: T1649
  techniques: [T1649]
  primary_tactic: credential-access
  detection_strategies: [DET0240]
telemetry:
  required:
    - Certification Authority audit events 4886 (request) and 4887 (issued) from every enterprise CA
    - Certificate Services auditing enabled ("Issue and manage certificate requests")
  optional:
    - Security 4768 with certificate information, for the ticket request that follows
    - Security 4624/4768 correlation to spot a certificate used by a different principal
    - Process creation for Certify, Certipy, Rubeus and PowerShell certificate cmdlets
surfaces:
  kql: queries/kql/TH-021-adcs-certificate-abuse.kql
  sigma: rules/sigma/TH-021-adcs-certificate-abuse.yml
  tests: tests/rules/TH-021-adcs-certificate-abuse.yml
validation:
  atomics:
    - eb121494-82d1-4148-9e2b-e624e03fbf3d
related: [TH-002, TH-003, TH-013, TH-004]
tags: [credential-access, active-directory, pki, identity, high-value]
---

# TH-021 — AD CS certificate abuse (ESC1-style misissuance)

## Hypothesis

An adversary is requesting a certificate from an Active Directory Certificate Services template that
permits a requester-supplied subject alternative name, obtaining a certificate that authenticates as
a different — usually privileged — principal, and exchanging it for a Kerberos ticket.

## Why this matters

A misconfigured certificate template converts any domain user into any other identity, including
Domain Admins, with no password and no exploit. The resulting certificate remains valid for its
lifetime, survives password resets, and authenticates cleanly — so a missed detection here creates a
persistent, credential-reset-proof foothold. This is the highest-impact Active Directory
misconfiguration class currently in wide exploitation, and it is absent from most detection libraries.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1649 — Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| Tactic | Credential Access (TA0006) |
| Detection strategy | [DET0240 — Detection Strategy for Steal or Forge Authentication Certificates](https://attack.mitre.org/detectionstrategies/DET0240) |
| Analytics | AN0671 (Windows: 4657, 4768), AN0674 (Identity Provider: certificate credential added) |

AN0671's mutable elements are `EKU_Thresholds`, `TimeWindow` and `LogonContext` — the last being the
key enrichment: a certificate whose subject does not match the requester's own identity.

## Telemetry requirements

**Required.** CA audit events 4886 and 4887 from every enterprise CA, with Certificate Services
auditing enabled (`certutil -setreg CA\AuditFilter 127` plus the corresponding audit policy). Without
these, certificate misissuance is invisible on the CA side.

**Optional.** Security 4768 with certificate serial and issuer identifies the ticket request that
uses the certificate. Endpoint process telemetry catches the tooling before the request lands.

**Data-quality check.** Request a certificate from a test template and confirm both 4886 and 4887
arrive with the `Attributes` field populated. Many deployments enable auditing but never verify that
the request attributes — where the subject alternative name appears — are actually recorded.

## Analytic approach

Three complementary signals:

1. **Requester-supplied SAN.** A request whose attributes contain `san:` (or `SubjectAltName`) on a
   template that is not explicitly expected to allow it. This is the ESC1 signature.
2. **Identity mismatch.** The certificate subject or SAN names a principal different from the
   requesting account.
3. **Tooling.** Certify, Certipy, and Rubeus certificate operations on endpoints, plus PowerShell
   certificate export cmdlets.

Because enterprise CAs are few and request volume is modest, this content can be deployed as an alert
after a short baseline of which templates legitimately allow SAN specification (web server templates
frequently do — those belong on the allowlist, not in the alert).

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `SanAllowedTemplates` | KQL / Sigma filter | placeholders | `EKU_Thresholds` | Populate from your CA's template inventory: web-server templates legitimately take a SAN. |
| `PrivilegedNamePatterns` | KQL | admin, adm-, svc- | `LogonContext` | Replace with your own privileged naming convention; better still, resolve against group membership. |
| `Lookback` | KQL | 14d | `TimeWindow` | Long — certificates are used well after issuance. |
| Tooling list | KQL / Sigma | Certify, Certipy, Rubeus | — | Renaming defeats it; keep the CA-side signals primary. |

## Query surfaces

- KQL: [`queries/kql/TH-021-adcs-certificate-abuse.kql`](../queries/kql/TH-021-adcs-certificate-abuse.kql)
- Sigma: [`rules/sigma/TH-021-adcs-certificate-abuse.yml`](../rules/sigma/TH-021-adcs-certificate-abuse.yml)
  — two documents: CA-side misissuance and endpoint-side tooling.

## Unit tests

[`tests/rules/TH-021-adcs-certificate-abuse.yml`](../tests/rules/TH-021-adcs-certificate-abuse.yml)
covers a user template request carrying a SAN for an administrator, an ESC1-style issuance, and
Certipy execution; negatives cover a web-server template request that legitimately carries a SAN and
an ordinary user certificate request with no SAN attribute.

## Triage workflow

1. Read the request: template, requester, and the full attribute string. The SAN value is the
   identity the adversary intends to become.
2. Check the template configuration: does it allow requester-supplied subjects, does it have a client
   authentication EKU, and does it require manager approval? A template with the first two and not the
   third is ESC1.
3. Determine whether the certificate was issued (4887) and retrieve its serial number.
4. Look for use: 4768 requests referencing that certificate, and sessions authenticating as the
   impersonated principal.
5. Assess blast radius by the impersonated identity, not by the requester.
6. Scope other requests from the same requester and other requests against the same template.

## Benign explanations

Web-server and SAN-enabled templates used by infrastructure teams, automated certificate enrolment
for services, and PKI administrators testing templates. All are attributable to specific templates and
service accounts, which is exactly why the template allowlist is the primary tuning lever.

## Escalation criteria

Escalate immediately when a SAN naming a privileged principal is requested on a client-authentication
template, when the requester and the SAN identity differ, when certificate tooling appears on an
endpoint, or when a certificate is used to obtain a ticket for a different account.

## Response considerations

Revoke the certificate *and* publish an updated CRL — revocation alone does not stop use until clients
refresh. Fix the template (disable requester-supplied subjects, require manager approval, restrict
enrolment rights). Certificates already issued survive password resets, so enumerate all certificates
issued from the affected template, not just the one you found. Where domain-level impersonation was
possible, treat the domain as compromised and follow the TH-002 response.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Staging Local Certificates via Export-Certificate | `eb121494-82d1-4148-9e2b-e624e03fbf3d` | Windows | Certificate export from the local store |

Atomic Red Team currently ships one test for T1649 and it covers local certificate theft, not template
abuse. Validate misissuance manually in a lab: create a deliberately vulnerable template (client
authentication EKU, requester-supplied subject, no manager approval), request a certificate with a SAN
for a test administrator, and confirm the 4886/4887 pair is captured with the attribute string intact.
Then fix the template. Never create such a template in production, even temporarily.

## Limitations and blind spots

CA auditing that is enabled but not fully configured records the request without the attributes,
which removes the SAN signal. Other AD CS abuse paths (ESC8 relay to the web enrolment endpoint,
ESC4 template ACL modification, CA certificate theft) produce different evidence and are not covered
here — ESC8 in particular overlaps with [TH-022](TH-022-ntlm-coercion-relay.md). Certificates
requested before detection was enabled remain valid and invisible.

## Tuning notes

Start from a template inventory: list every published template, its EKUs, whether it allows
requester-supplied subjects, and who may enrol. That inventory is both the tuning input and, usually,
the finding that fixes the problem outright.

## Related playbooks

- [TH-002 DCSync replication abuse](TH-002-dcsync-replication-abuse.md)
- [TH-003 Kerberoasting](TH-003-kerberoasting.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-022 NTLM coercion and relay](TH-022-ntlm-coercion-relay.md)

## Change log

- 2026-09-10 (v2.0.0): New playbook.
