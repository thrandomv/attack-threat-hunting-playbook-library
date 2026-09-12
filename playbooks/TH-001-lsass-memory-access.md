---
id: TH-001
name: lsass-memory-access
title: LSASS memory access and credential dumping
summary: Process-creation and handle-access evidence of credential material being read out of the LSASS process.
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
  primary_technique: T1003.001
  techniques: [T1003.001]
  primary_tactic: credential-access
  detection_strategies: [DET0363]
telemetry:
  required:
    - Microsoft Defender XDR DeviceProcessEvents (or Security 4688 with command line auditing)
    - Sysmon Event ID 10 (ProcessAccess) filtered to lsass.exe, or Security 4656/4663 with a SACL on LSASS
  optional:
    - Sysmon Event ID 11 (FileCreate) for dump artefacts
    - Sysmon Event ID 7 (ImageLoad) for comsvcs.dll / dbghelp.dll / dbgcore.dll
    - EDR sensitive-process-access alerts and ASR rule telemetry
surfaces:
  kql: queries/kql/TH-001-lsass-memory-access.kql
  sigma: rules/sigma/TH-001-lsass-memory-access.yml
  tests: tests/rules/TH-001-lsass-memory-access.yml
validation:
  atomics:
    - 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8
    - 2536dee2-12fb-459a-8c37-971844fa73be
    - dea6c349-f1c6-44f3-87a1-1ed33a59a607
    - dddd4aca-bbed-46f0-984d-e4c5971c51ea
related: [TH-002, TH-004, TH-014, TH-021]
tags: [credential-access, endpoint, windows, active-directory]
---

# TH-001 — LSASS memory access and credential dumping

## Hypothesis

An adversary with local administrator or SYSTEM rights on a Windows host is reading the memory of
`lsass.exe` to recover plaintext credentials, NT hashes, or Kerberos tickets, using either a
signed dumping utility, a living-off-the-land export path, or direct API calls followed by offline
parsing.

## Why this matters

LSASS is the shortest path from one compromised endpoint to domain-wide credentials. A successful
dump usually precedes Pass-the-Hash (TH-004), Kerberos abuse (TH-003), or DCSync (TH-002), so the
hunt is worth running even when its precision is imperfect. Command-line evidence alone is weak:
attacker tooling renames binaries, uses direct syscalls, or dumps through legitimate processes.
Handle-access telemetry (Sysmon Event ID 10) is the higher-fidelity source, and the two together
produce a defensible chain: *who opened LSASS with dump-capable rights, and what did they write to
disk immediately afterwards*.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Tactic | Credential Access (TA0006) |
| Detection strategy | [DET0363 — Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence](https://attack.mitre.org/detectionstrategies/DET0363) |
| Analytic | AN1030 (Windows) — access-mask plus dump-sequence behaviour chain |

ATT&CK's own analytic for this technique names `AccessMask`, `TimeWindow`, `ParentProcessName`,
`DumpFilePath`, and `CommandLinePattern` as the elements an implementer is expected to tune. The
parameter table below maps each of those to a concrete knob in this repository's content, which is
how the two stay in sync.

## Telemetry requirements

**Required.** Process creation with full command line (`DeviceProcessEvents`, or Security 4688 with
`Include command line in process creation events` enabled), plus one source of LSASS handle access:
Sysmon Event ID 10 scoped to `lsass.exe`, or Security 4656/4663 with an audit SACL on the process
object. Without the second source this hunt sees only the noisiest half of the technique.

**Optional but valuable.** File-creation events for `.dmp` artefacts, image loads of
`comsvcs.dll` / `dbgcore.dll` / `dbghelp.dll` into unusual processes, and EDR sensitive-process
telemetry.

**Data-quality check.** Confirm that command lines are populated (not truncated or redacted), that
Sysmon's `ProcessAccess` section is not filtered to exclude the very tools you care about, and that
coverage includes servers and jump hosts, not only workstations. Run
`DeviceProcessEvents | summarize count() by bin(Timestamp, 1d), DeviceName` over a week to confirm
sensor continuity before trusting a negative result.

## Analytic approach

The query treats a match as an accumulation of independent signals rather than a single keyword:

1. **Tool identity** — known dumper images and renamed copies (matched on original file name where
   the sensor supplies it).
2. **LSASS reference** — the target process named on the command line.
3. **Dump semantics** — switches and API names that only make sense when writing memory to disk.
4. **Credential semantics** — module or function names specific to credential parsing.

A single signal is a lead; two or more is an investigation. The `comsvcs.dll` MiniDump export is
promoted on its own because there is no benign reason to call it interactively.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 7d | `TimeWindow` | Shorten to 24h for scheduled execution, lengthen for retro-hunts after an incident. |
| `ApprovedDumpTools` | KQL | empty | `ProcessNameExclusions` | Add crash-handling agents only after confirming their signer and install path. |
| `DumpFilePattern` | KQL | `.dmp`, `.dump` | `DumpFilePath` | Extend with the extensions your backup or crash tooling produces. |
| `selection_credential_tooling` | Sigma | Mimikatz/nanodump strings | `CommandLinePattern` | Strings are a floor, not a ceiling; renamed tooling defeats them by design. |
| Handle-access mask | Companion query | `0x1010`, `0x1410`, `0x1F0FFF` | `AccessMask` | `0x1010` (VM_READ + QUERY_INFORMATION) is the classic dump mask; keep it even when noisy. |

## Query surfaces

- KQL: [`queries/kql/TH-001-lsass-memory-access.kql`](../queries/kql/TH-001-lsass-memory-access.kql)
  (Microsoft Defender XDR advanced hunting, with a Sentinel/Sysmon companion block).
- Sigma: [`rules/sigma/TH-001-lsass-memory-access.yml`](../rules/sigma/TH-001-lsass-memory-access.yml)
  (`process_creation`, portable to any backend).

## Unit tests

[`tests/rules/TH-001-lsass-memory-access.yml`](../tests/rules/TH-001-lsass-memory-access.yml)
asserts that the rule fires on ProcDump against LSASS, on the `comsvcs.dll` MiniDump export, and on
Mimikatz `sekurlsa` syntax, and that it stays silent on ProcDump against a non-LSASS process and on
`rundll32.exe` running a normal Control Panel applet. Run `make test` or
`python3 scripts/run_tests.py --rule TH-001`.

## Triage workflow

1. Establish the actor: user, logon session, logon type, and whether the session is interactive,
   remote, or a service context.
2. Reconstruct the process tree upward to the initial access vector — a dump launched by a web
   server or an Office application is a different incident from one launched by an admin console.
3. Check the binary: signer, original file name, hash prevalence in the estate, and install path.
4. Look for the output: `.dmp` files created in the same second range, on local disk, in a temp
   directory, or on a share. No artefact on disk does not clear the host; the dump may be streamed.
5. Correlate the timeline forward — new logons using accounts that had sessions on that host,
   remote service creation, or authentication from the host to systems it never talks to.
6. Scope: same tool hash, same command-line pattern, same actor across the estate over 30 days.

## Benign explanations

Crash-diagnostic collection by support staff, vendor performance tools, memory-forensics training,
security-team validation runs, and backup agents that snapshot process memory. Each of these should
be explainable by a ticket, a documented tool path, and a stable population of hosts. "It is our
software" is only an answer when the signer and path match the software's known deployment.

## Escalation criteria

Escalate immediately when the dump is initiated by a non-administrative or service account, when the
tool is renamed or unsigned, when the parent is a browser, Office application, or web server, when a
dump file appears on a network share, or when credential-parsing strings are present. Any hit on a
domain controller, PKI host, or privileged-access workstation is an incident until proven otherwise.

## Response considerations

Preserve volatile evidence before containment where the process is still running. Assume every
credential with a session on that host is exposed: build the exposure list from logon sessions and
cached-credential policy, then reset in tiers (service accounts and privileged accounts first,
`krbtgt` twice if domain-level compromise is plausible). Coordinate isolation with the incident lead
so that visibility is not traded away too early.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Dump LSASS.exe Memory using ProcDump | `0be2230c-9ab3-4ac2-8826-3199b9a0ebf8` | Windows | Process creation with `-ma lsass.exe`, Sysmon 10 handle open, `.dmp` file write |
| Dump LSASS.exe Memory using comsvcs.dll | `2536dee2-12fb-459a-8c37-971844fa73be` | Windows | `rundll32.exe comsvcs.dll, MiniDump`, image load of `comsvcs.dll`, dump artefact |
| Dump LSASS.exe Memory using Windows Task Manager | `dea6c349-f1c6-44f3-87a1-1ed33a59a607` | Windows | Sysmon 10 from `taskmgr.exe` only — **no** command-line evidence |
| Dump LSASS.exe Memory using NanoDump | `dddd4aca-bbed-46f0-984d-e4c5971c51ea` | Windows | Handle access with an unusual mask; command line may be absent |

Run in a lab or an approved test window only, with the change record referenced in the hunt log. The
Task Manager and NanoDump cases exist in this table specifically to demonstrate the command-line
blind spot: if only the first two tests are detected, the deployment is missing Sysmon Event ID 10.

## Limitations and blind spots

Direct syscalls, API unhooking, and process forking (`PssCaptureSnapshot`) avoid the classic access
mask. Renamed binaries defeat image-name matching. Dumping through Task Manager or a signed vendor
tool produces no distinguishing command line. Protected Process Light and Credential Guard change
what is recoverable but do not stop the access attempt from being logged, so absence of a dump file
is not absence of an attempt.

## Tuning notes

Baseline for 14 days before enabling as a scheduled rule. Expect the recurring noise to come from a
small set of support and telemetry tools; allowlist them by signer plus path plus parent, never by
image name alone — image name is the one attribute an adversary controls for free.

## Related playbooks

- [TH-002 DCSync replication abuse](TH-002-dcsync-replication-abuse.md)
- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-014 Impair defenses](TH-014-impair-defenses.md)
- [TH-021 AD CS certificate abuse](TH-021-adcs-certificate-abuse.md)

## Change log

- 2026-09-10 (v2.0.0): Added frontmatter, ATT&CK detection-strategy alignment, tunable-parameter
  table, unit tests, and Atomic Red Team validation mapping. Replaced term-based `has` matching with
  substring matching for path and switch fragments, and added the Sysmon handle-access companion.
- 2026-08-31 (v1.0.0): Initial version.
