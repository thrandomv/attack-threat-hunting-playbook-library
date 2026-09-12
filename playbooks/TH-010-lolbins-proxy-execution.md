---
id: TH-010
name: lolbins-proxy-execution
title: LOLBin system binary proxy execution
summary: Signed Microsoft binaries used to execute attacker-controlled code, bypassing application control and signature-based prevention.
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
  primary_technique: T1218
  techniques: [T1218]
  primary_tactic: stealth
  detection_strategies: [DET0081]
telemetry:
  required:
    - Process creation with full command line and parent image
  optional:
    - DeviceNetworkEvents / Sysmon Event ID 3 and 22 for the fetch that follows
    - Sysmon Event ID 7 image loads for the DLL or COM object actually executed
    - Application control (WDAC/AppLocker) audit events
surfaces:
  kql: queries/kql/TH-010-lolbins-proxy-execution.kql
  sigma: rules/sigma/TH-010-lolbins-proxy-execution.yml
  tests: tests/rules/TH-010-lolbins-proxy-execution.yml
validation:
  atomics:
    - c426dacf-575d-4937-8611-a148a86a5e61
    - ad2c17ed-f626-4061-b21e-b9804a6f3655
    - db020456-125b-4c8b-a4a7-487df8afb5a2
    - 7cbb0f26-a4c1-4f77-b180-a009aa05637e
related: [TH-009, TH-015, TH-016, TH-020]
tags: [stealth, execution, endpoint, windows, lolbin]
---

# TH-010 — LOLBin system binary proxy execution

## Hypothesis

An adversary is executing code through a signed Microsoft binary — `mshta`, `regsvr32`, `rundll32`,
`msiexec`, `cmstp`, `installutil` and relatives — so that the executing image is trusted and the
payload never needs to be a signed executable of its own.

## Why this matters

Proxy execution is the standard answer to application control and to "block unsigned binaries"
policies. The binaries involved are present on every Windows host, are used legitimately, and cannot
be removed. Detection therefore keys on *argument shape*: remote content, script protocols, unusual
DLL exports, and payload paths in user-writable directories.

Note the ATT&CK v19 change: this technique now sits under the **Stealth** tactic (TA0005), which
replaced the old Defense Evasion tactic together with Defense Impairment (TA0112). Existing content
tagged `attack.defense-evasion` still refers to the same behaviour; see
[`mappings/legacy-technique-ids.md`](../mappings/legacy-technique-ids.md).

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |
| Tactic | Stealth (TA0005) |
| Detection strategy | [DET0081 — Detection of Proxy Execution via Trusted Signed Binaries Across Platforms](https://attack.mitre.org/detectionstrategies/DET0081) |
| Analytics | AN0226 (Windows), AN0227 (Linux), AN0228 (macOS) |

## Telemetry requirements

**Required.** Process creation with the full command line and the parent image. The command line is
where the payload reference lives; without it this technique is invisible.

**Optional.** Network events tie the execution to the fetch; image-load events show which DLL or
scriptlet actually ran, which is what an investigation ultimately needs.

**Data-quality check.** Confirm that command lines for `rundll32.exe` are captured intact — long
export strings are a frequent truncation victim.

## Analytic approach

Restrict to the known proxy-execution binaries, then require at least one argument-shape signal:
remote or UNC content, a script protocol or scriptlet reference, a suspicious export, or a payload
staged in a writable path. Report the signal breakdown so an analyst can judge quickly rather than
re-reading the command line.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `ProxyBinaries` | KQL / Sigma | 11 binaries | `SignedBinaryList` | Extend from the LOLBAS project as new abuse is published. |
| `RemoteContent` patterns | KQL / Sigma | http, https, ftp, UNC | `RemoteDomainAllowlist` | Allowlist internal deployment shares by full path, not by scheme. |
| `WritablePayload` paths | KQL | temp, public, appdata | `CommandLineRegex` | Add your software staging directories after confirming the publisher. |
| `SuspiciousParent` | KQL | Office and script hosts | `ParentProcessName` | The strongest single discriminator; keep it. |

## Query surfaces

- KQL: [`queries/kql/TH-010-lolbins-proxy-execution.kql`](../queries/kql/TH-010-lolbins-proxy-execution.kql)
- Sigma: [`rules/sigma/TH-010-lolbins-proxy-execution.yml`](../rules/sigma/TH-010-lolbins-proxy-execution.yml)

## Unit tests

[`tests/rules/TH-010-lolbins-proxy-execution.yml`](../tests/rules/TH-010-lolbins-proxy-execution.yml)
covers `mshta` executing remote HTA content, `regsvr32` fetching a remote scriptlet (the
"Squiblydoo" shape), and `rundll32` running from a temp path; negatives cover `rundll32` opening a
Control Panel applet and `msiexec` installing from a signed local package.

## Triage workflow

1. Read the argument: what content is being executed, and from where?
2. Identify the parent. An Office or browser parent moves this straight to incident handling.
3. Retrieve the referenced content if it is still reachable, and hash it.
4. Check the network events around the execution for the actual fetch and any follow-on beacon.
5. Look for persistence or credential access created in the same session.
6. Scope by URL, hash, and command-line shape across the estate.

## Benign explanations

Installers and updaters use `msiexec`, `rundll32` and `installutil` constantly; management tooling
runs scriptlets; some line-of-business applications register COM components at launch. Legitimate use
is characterised by local, signed content and a stable parent — remote content is the exception, not
the rule.

## Escalation criteria

Escalate on remote content of any kind, on script protocols (`javascript:`, `vbscript:`), on
scriptlet registration from a URL, on execution from a writable path, and on any Office, browser, or
web-server parent.

## Response considerations

Preserve the referenced payload before it disappears from the server. Where WDAC or AppLocker is
deployed, verify whether the policy actually blocks the observed path — proxy execution is often the
first thing to reveal a policy gap. Consider ASR rules that block Office child processes and
obfuscated script execution.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| mavinject - Inject DLL into running process | `c426dacf-575d-4937-8611-a148a86a5e61` | Windows | Signed binary used for injection |
| Register-CimProvider - Execute evil dll | `ad2c17ed-f626-4061-b21e-b9804a6f3655` | Windows | Less common LOLBin; tests list completeness |
| ProtocolHandler.exe Downloaded a Suspicious File | `db020456-125b-4c8b-a4a7-487df8afb5a2` | Windows | Remote content through a signed handler |
| Microsoft.Workflow.Compiler.exe Payload Execution | `7cbb0f26-a4c1-4f77-b180-a009aa05637e` | Windows | Compilation-based execution — a known gap in image-name lists |

## Limitations and blind spots

The binary list is a moving target: LOLBAS grows continuously and any list ages. Local-only payloads
with plausible paths defeat the argument heuristics. Renamed copies of the binaries defeat image-name
matching unless original file name is available. COM hijacking and DLL side-loading achieve the same
outcome without any of these binaries.

## Tuning notes

Baseline each binary separately — `msiexec` and `rundll32` have completely different benign profiles.
Allowlist by full command-line shape plus parent, and re-derive quarterly; software updates change
these shapes more often than most tuning cycles assume.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-020 WMI remote execution](TH-020-wmi-remote-execution.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0081 alignment, Stealth tactic note for the ATT&CK v19
  restructure, substring path matching, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
