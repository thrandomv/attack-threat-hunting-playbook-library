---
id: TH-016
name: ingress-tool-transfer
title: Ingress tool transfer with native utilities
summary: Built-in Windows utilities used to pull attacker tooling onto a host, avoiding the need to drop a downloader.
status: production-candidate
severity: medium
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: T1105
  techniques: [T1105]
  primary_tactic: command-and-control
  detection_strategies: [DET0060]
telemetry:
  required:
    - Process creation with command line
  optional:
    - DeviceNetworkEvents / Sysmon Event ID 3 for the connection that follows
    - DeviceFileEvents / Sysmon Event ID 11 for the file that lands
    - Proxy logs with user agent and destination reputation
surfaces:
  kql: queries/kql/TH-016-ingress-tool-transfer.kql
  sigma: rules/sigma/TH-016-ingress-tool-transfer.yml
  tests: tests/rules/TH-016-ingress-tool-transfer.yml
validation:
  atomics:
    - 2b080b99-0deb-4d51-af0f-833d37c4ca6a
    - 1a02df58-09af-4064-a765-0babe1a0d1e2
    - 2ca61766-b456-4fcf-a35a-1233685e1cad
    - 3dd6a6cf-9c78-462c-bd75-e9b54fc8925b
related: [TH-009, TH-010, TH-015, TH-017]
tags: [command-and-control, execution, endpoint, windows]
---

# TH-016 — Ingress tool transfer with native utilities

## Hypothesis

An adversary is downloading tooling onto a compromised host using utilities already present on the
system — `certutil`, `bitsadmin`, `curl`, PowerShell cradles, script hosts — rather than dropping a
dedicated downloader that antimalware would inspect.

## Why this matters

The transfer is the moment the adversary's toolkit becomes visible. It is also one of the few points
where a single command line contains both the destination and the local path, giving triage a full
lead in one event. Native utilities are used legitimately, so the discriminators are the destination
(external, raw IP, non-standard port), the output path (writable directory), and the parent.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| Tactic | Command and Control (TA0011) |
| Detection strategy | [DET0060 — Detect Ingress Tool Transfers via Behavioral Chain](https://attack.mitre.org/detectionstrategies/DET0060) |
| Analytics | AN0165 (Windows), AN0166 (Linux), AN0167 (macOS), AN0168 (ESXi), AN0169 (network devices) |

AN0165 names `ParentProcessName`, `DestinationIPCategory` and `FilePathRegex` — the three
discriminators used below, in that order of value.

## Telemetry requirements

**Required.** Process creation with command line.

**Optional but valuable.** Network events confirm the transfer actually happened and reveal the true
destination when the command line contains a redirector. File events confirm what landed and where,
which is what containment needs.

**Data-quality check.** Confirm `curl.exe` and `tar.exe` are visible (both ship with modern Windows
and are frequently overlooked in older rule sets).

## Analytic approach

Match the known transfer utilities with their transfer-specific switches, then amplify on
destination and output characteristics: raw IPv4 destinations, non-standard ports, writable output
paths, and archive or executable extensions. Every match is a lead, and the score orders the queue.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `DownloadTools` | KQL / Sigma | 10 utilities | `ToolName` | Add `tar.exe`, `ssh.exe`, `sftp.exe`, `scp.exe` if present in your estate. |
| Writable output paths | KQL | temp, public, appdata | `FilePathRegex` | Keep tight; the value is in "downloaded to a staging directory". |
| Raw-IP regex | KQL | IPv4 literal | `DestinationIPCategory` | Extend to IPv6 literals if relevant. |
| `ApprovedDownloadSources` | KQL | empty | — | Internal repositories and update endpoints, matched by full host. |

## Query surfaces

- KQL: [`queries/kql/TH-016-ingress-tool-transfer.kql`](../queries/kql/TH-016-ingress-tool-transfer.kql)
- Sigma: [`rules/sigma/TH-016-ingress-tool-transfer.yml`](../rules/sigma/TH-016-ingress-tool-transfer.yml)

## Unit tests

[`tests/rules/TH-016-ingress-tool-transfer.yml`](../tests/rules/TH-016-ingress-tool-transfer.yml)
covers `certutil -urlcache`, `bitsadmin /transfer`, and a `curl` download to a public directory;
negatives cover `certutil -hashfile` (a legitimate local hashing use of the same binary) and a `curl`
call to an internal API without a file output.

## Triage workflow

1. Extract the URL and the output path. Check the destination's reputation, age, and whether other
   hosts contacted it.
2. Hash and analyse the downloaded file if it is still present.
3. Read the parent chain — what caused the download?
4. Check whether the downloaded file executed, and what it did afterwards.
5. Scope by URL, hash, and command shape estate-wide; ingress usually repeats across hosts.

## Benign explanations

Software updates, package managers, deployment scripts, and administrators fetching tools from an
internal repository. These usually target internal or well-known vendor hosts and write into
`Program Files` or a package cache.

## Escalation criteria

Escalate on raw-IP destinations, non-standard ports, output into writable directories, downloads
initiated by Office or web-server parents, and any download followed by execution of the same file.

## Response considerations

Preserve the downloaded artefact and the network evidence. Block the destination only after
collection. If the file executed, treat this as the start of the intrusion timeline rather than the
whole of it.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Curl Download File | `2b080b99-0deb-4d51-af0f-833d37c4ca6a` | Windows | `curl.exe` with `-o` and a URL |
| Download a file with IMEWDBLD.exe | `1a02df58-09af-4064-a765-0babe1a0d1e2` | Windows | A LOLBin downloader that image-name lists usually miss |
| OSTAP Worming Activity | `2ca61766-b456-4fcf-a35a-1233685e1cad` | Windows | Script-host download chain |
| Download a file with OneDrive Standalone Updater | `3dd6a6cf-9c78-462c-bd75-e9b54fc8925b` | Windows | Signed-updater abuse; a deliberate gap in this rule |

The last test is included to show the boundary: a download performed by a signed vendor updater is
not covered by a utility-name list, and needs network-side detection instead.

## Limitations and blind spots

Downloads inside a PowerShell session with no new process leave no command line. Encrypted or
domain-fronted destinations hide the true endpoint. Signed updaters used as downloaders bypass the
utility list entirely. Transfers over SMB or through a browser are out of scope here.

## Tuning notes

Baseline which utilities perform downloads in your estate and from where. Most environments have a
short list of legitimate sources; allowlist those by full host, and treat everything else as a lead.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-010 LOLBin proxy execution](TH-010-lolbins-proxy-execution.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-017 Web shell behavior](TH-017-web-shell-behavior.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0060 alignment, substring switch matching, `certutil -hashfile`
  negative case, unit tests, Atomic validation table with an explicit coverage boundary.
- 2026-08-31 (v1.0.0): Initial version.
