---
id: TH-022
name: ntlm-coercion-relay
title: NTLM authentication coercion and relay
summary: Machine accounts coerced into authenticating to an attacker-controlled host, then relayed to a service that accepts NTLM.
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
  primary_technique: T1187
  techniques: [T1187, T1557.001]
  primary_tactic: credential-access
  detection_strategies: [DET0022, DET0462]
telemetry:
  required:
    - Security 5145 (detailed file share access) on domain controllers and servers, for named-pipe access
    - Security 4624 type 3 with NTLM, including machine accounts
  optional:
    - Security 4768/4769 for the ticket activity that follows a successful relay
    - Network telemetry for SMB (445), LLMNR (UDP 5355), NBT-NS (UDP 137) and HTTP with NTLMSSP
    - Endpoint process telemetry for Responder, Inveigh, ntlmrelayx, PetitPotam and Coercer
surfaces:
  kql: queries/kql/TH-022-ntlm-coercion-relay.kql
  sigma: rules/sigma/TH-022-ntlm-coercion-relay.yml
  tests: tests/rules/TH-022-ntlm-coercion-relay.yml
validation:
  atomics:
    - 485ce873-2e65-4706-9c7e-ae3ab9e14213
    - 81cfdd7f-1f41-4cc5-9845-bb5149438e37
    - 7f06b25c-799e-40f1-89db-999c9cc84317
    - deecd55f-afe0-4a62-9fba-4d1ba2deb321
related: [TH-004, TH-021, TH-013, TH-002]
tags: [credential-access, active-directory, network, identity, high-value]
---

# TH-022 — NTLM authentication coercion and relay

## Hypothesis

An adversary is forcing a Windows host — often a domain controller — to authenticate to a machine
they control, using an RPC method that triggers outbound authentication (`EfsRpcOpenFileRaw`,
`SpoolSample`, `DFSCoerce`, `ShadowCoerce`), or is poisoning name resolution to capture
authentication, and then relaying that authentication to a service that has not enforced signing or
channel binding.

## Why this matters

Coercion plus relay is a full domain-compromise chain that requires no credentials at all: coerce a
domain controller's machine account, relay it to AD CS web enrolment (ESC8) or to LDAP, and obtain a
certificate or a privileged object modification. The individual protocol operations are legitimate,
which is why detection concentrates on *which* named pipes are reached and *from where*.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/), [T1557.001 — Name Resolution Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) |
| Tactics | Credential Access (TA0006), Collection (TA0009) |
| Detection strategies | [DET0022](https://attack.mitre.org/detectionstrategies/DET0022), [DET0462](https://attack.mitre.org/detectionstrategies/DET0462) |
| Analytics | AN0065 (lure files and outbound NTLM), AN1274 (poisoning correlated with SMB authentication) |

Note that ATT&CK v19 renamed T1557.001 from *LLMNR/NBT-NS Poisoning and SMB Relay* to
**Name Resolution Poisoning and SMB Relay**, broadening it beyond the two legacy protocols.

## Telemetry requirements

**Required.** Security 5145 with `ShareName` `\\*\IPC$` and `RelativeTargetName` populated — this is
what shows the named pipe being reached (`efsrpc`, `lsarpc`, `netdfs`, `spoolss`, `samr`). It is
disabled by default: enable *Audit Detailed File Share* on domain controllers and file servers.
Volume is significant, so scope deliberately.

**Optional.** Network telemetry for LLMNR and NBT-NS responses from a non-authoritative host is the
cleanest poisoning signal. Machine-account NTLM logons from workstation subnets indicate a successful
coercion.

**Data-quality check.** Confirm 5145 events include `RelativeTargetName`; some pipelines drop it,
which removes the entire signal. Validate with a benign pipe access.

## Analytic approach

Three signals, each independently actionable:

1. **Coercion pipes** — 5145 access to `efsrpc`, `netdfs`, `spoolss`, `lsarpc` or `samr` from a source
   that is not a domain controller or an approved management host.
2. **Machine-account authentication anomaly** — a computer account authenticating over NTLM from an
   address that is not its own, which is what a coerced-and-relayed machine account looks like.
3. **Tooling** — Responder, Inveigh, ntlmrelayx, PetitPotam, Coercer, and PowerShell equivalents on
   endpoints.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `CoercionPipes` | KQL / Sigma | efsrpc, netdfs, spoolss, lsarpc, samr | `LureExtensions` | Keep `spoolss` even if the print spooler is disabled — the attempt is still evidence. |
| `ApprovedSources` | KQL | DC and management subnets | `UntrustedCIDR/DNS` | Express as subnets; per-host lists rot quickly. |
| `Window` | KQL | 10m | `TimeWindow` | Coercion and relay are seconds apart; a short window keeps precision high. |
| `TrustedResponders` | Companion | DNS/WINS servers | `TrustedResponderList` | For the poisoning branch, if you have name-resolution telemetry. |

## Query surfaces

- KQL: [`queries/kql/TH-022-ntlm-coercion-relay.kql`](../queries/kql/TH-022-ntlm-coercion-relay.kql)
- Sigma: [`rules/sigma/TH-022-ntlm-coercion-relay.yml`](../rules/sigma/TH-022-ntlm-coercion-relay.yml)
  — coercion-pipe access and relay tooling.

## Unit tests

[`tests/rules/TH-022-ntlm-coercion-relay.yml`](../tests/rules/TH-022-ntlm-coercion-relay.yml) covers
`efsrpc` and `spoolss` pipe access, and Responder/ntlmrelayx execution; negatives cover ordinary
`srvsvc` pipe access (routine SMB session enumeration) and a legitimate share connection.

## Triage workflow

1. Identify the source of the pipe access. If it is not a domain controller, a print server, or an
   approved management host, treat it as attacker-controlled until proven otherwise.
2. Identify the coerced account — usually a machine account — and where it authenticated to next.
3. Check the relay destination: AD CS web enrolment (`/certsrv`), LDAP, or SMB on another host. An
   AD CS relay produces a certificate; pivot to [TH-021](TH-021-adcs-certificate-abuse.md).
4. Check whether the relay succeeded: new certificates, LDAP object modifications, new sessions as
   the machine account.
5. Investigate the source host as compromised infrastructure.
6. Scope other coercion attempts and other machine accounts authenticating anomalously.

## Benign explanations

Legitimate EFS operations, DFS management, print server communication, and backup or management
platforms that enumerate shares. These originate from a small, stable set of servers — the source is
the discriminator, not the pipe.

## Escalation criteria

Escalate immediately when coercion pipes are reached from a workstation or an unknown address, when a
domain controller machine account authenticates from a subnet it does not belong to, when relay
tooling is observed, or when a certificate is issued to a machine account shortly after coercion.

## Response considerations

Contain the source host. Then close the primitive rather than only the incident: enforce SMB signing
and LDAP channel binding and signing, enable Extended Protection for Authentication on AD CS web
enrolment, restrict NTLM where possible, and disable the print spooler on domain controllers.
Coercion is not patchable in the general case — relay hardening is the control that matters.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| PetitPotam | `485ce873-2e65-4706-9c7e-ae3ab9e14213` | Windows | 5145 on `efsrpc`, outbound machine-account authentication |
| Trigger an authenticated RPC call to a target server with no Sign flag | `81cfdd7f-1f41-4cc5-9845-bb5149438e37` | Windows | Unsigned RPC authentication — the relayable condition |
| WinPwn - PowerSharpPack - Retrieving NTLM Hashes without Touching LSASS | `7f06b25c-799e-40f1-89db-999c9cc84317` | Windows | Coercion tooling on an endpoint |
| LLMNR Poisoning with Inveigh (PowerShell) | `deecd55f-afe0-4a62-9fba-4d1ba2deb321` | Windows | Name-resolution poisoning half of T1557.001 |

Run only in a lab. Coercion against production domain controllers can disrupt authentication and
generates real credential material.

## Limitations and blind spots

5145 auditing is expensive and often unavailable; without it the coercion half is invisible. New
coercion methods appear regularly and the pipe list will always lag. Relays that terminate at services
you do not log (a third-party appliance, for example) leave only the coercion side. Poisoning
detection needs network telemetry that most estates do not collect.

## Tuning notes

Baseline which hosts legitimately reach each coercion pipe over 30 days — the list is short and
stable. Express the allowlist as source subnets plus expected account, and revisit after any DFS,
EFS or printing change.

## Related playbooks

- [TH-002 DCSync replication abuse](TH-002-dcsync-replication-abuse.md)
- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-013 Account and group manipulation](TH-013-account-group-manipulation.md)
- [TH-021 AD CS certificate abuse](TH-021-adcs-certificate-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): New playbook.
