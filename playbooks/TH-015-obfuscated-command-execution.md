---
id: TH-015
name: obfuscated-command-execution
title: Obfuscated and encoded command execution
summary: Command lines built to defeat string matching - encoding, escape-character density, variable indirection and concatenation.
status: hunt
severity: medium
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows, Linux, macOS]
attack:
  primary_technique: T1027.010
  techniques: [T1027.010]
  primary_tactic: stealth
  detection_strategies: [DET0505]
telemetry:
  required:
    - Process creation with full, untruncated command line
  optional:
    - PowerShell 4104 script block logging (post-deobfuscation content)
    - auditd execve on Linux, EndpointSecurity exec events on macOS
    - Parent process and file-origin telemetry
surfaces:
  kql: queries/kql/TH-015-obfuscated-command-execution.kql
  sigma: rules/sigma/TH-015-obfuscated-command-execution.yml
  tests: tests/rules/TH-015-obfuscated-command-execution.yml
validation:
  atomics: []
related: [TH-009, TH-010, TH-016, TH-020]
tags: [stealth, execution, endpoint, obfuscation]
---

# TH-015 — Obfuscated and encoded command execution

## Hypothesis

An adversary is obscuring command-line content — base64 encoding, caret or backtick escaping, string
concatenation, environment-variable indirection, character casting — specifically so that
keyword-based detections do not match.

## Why this matters

Obfuscation is the counter-detection layer that sits on top of every other technique in this library.
Hunting for *structure* rather than *content* is what keeps detection viable when the adversary knows
your keywords. The trade is precision: legitimate software also produces ugly command lines, so this
content is a hunt, not an alert, and it is scored rather than binary.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1027.010 — Obfuscated Files or Information: Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/) |
| Tactic | Stealth (TA0005) |
| Detection strategy | [DET0505 — Detection Strategy for Command Obfuscation](https://attack.mitre.org/detectionstrategies/DET0505) |
| Analytics | AN1394 (Windows), AN1395 (Linux), AN1396 (macOS) |

ATT&CK's own analytics name `CommandLineEntropyThreshold`, `SuspiciousCharacterCount`,
`EncodedExecRegex` and `ScriptEntropyThreshold` — an explicit acknowledgement that this technique is
detected statistically, not by signature.

## Telemetry requirements

**Required.** Untruncated command lines. This is the one hunt where truncation is fatal: obfuscated
commands are long by nature, and a 4096-character cut-off removes exactly the evidence being measured.

**Optional.** Script block logging shows the deobfuscated result, which is what triage actually needs.
On Linux and macOS the equivalent is `auditd` execve records and EndpointSecurity exec events.

**Data-quality check.** Measure your command-line length distribution. If the maximum observed length
is a round number, you are being truncated.

## Analytic approach

Score structural features independently:

1. **Explicit encoding** — `-EncodedCommand` with a base64 payload, `FromBase64String`, `base64 -d`.
2. **Long base64-like tokens** — 100+ characters of base64 alphabet anywhere in the line.
3. **Escape-character density** — carets or backticks well above normal usage.
4. **Variable indirection** — `%COMSPEC%`, `${env:...}`, `[char]`, `substring(`, `-join`.
5. **Suspicious parent** — Office, script hosts, web servers.

Two or more signals, or one signal with a suspicious parent, is worth review. The character-density
counts are exposed in the output so an analyst can judge the shape without reading the whole line.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| Caret/backtick density | KQL | 8 | `SuspiciousCharacterCount` | Measure your own distribution; batch-heavy estates run higher. |
| Base64 token length | KQL / Sigma | 100 / 50 | `EncodedExecRegex` | Lower catches more, at a cost paid in installer noise. |
| `MinSignalCount` | KQL | 2 | `CommandLineEntropyThreshold` | 2 is the practical floor; 1 is unusable outside a small estate. |
| Interpreter list | KQL / Sigma | shells and script hosts | `InterpreterParentFilter` | Add language runtimes present in your estate (python, node, perl). |

## Query surfaces

- KQL: [`queries/kql/TH-015-obfuscated-command-execution.kql`](../queries/kql/TH-015-obfuscated-command-execution.kql)
- Sigma: [`rules/sigma/TH-015-obfuscated-command-execution.yml`](../rules/sigma/TH-015-obfuscated-command-execution.yml)

## Unit tests

[`tests/rules/TH-015-obfuscated-command-execution.yml`](../tests/rules/TH-015-obfuscated-command-execution.yml)
covers an encoded PowerShell payload, caret-escaped `cmd.exe` obfuscation, and `[char]`-based
concatenation; negatives cover a long but structured MSI installer command line and a normal
`robocopy` invocation — the two shapes that most often trip naive length heuristics.

## Triage workflow

1. Deobfuscate. Base64 in `-EncodedCommand` is UTF-16LE; strip carets and backticks for `cmd.exe`
   obfuscation; resolve `[char]` and `-join` constructs.
2. Judge the deobfuscated content, not the wrapper. Obfuscation itself is the signal; the payload is
   the verdict.
3. Read the parent chain and the origin of the script or document that produced it.
4. Correlate with network and file activity in the same minute.
5. Scope by normalised command shape across the estate.

## Benign explanations

Installers with long encoded arguments, deployment tooling passing serialised parameters, developer
tooling, and administrators using encoding to avoid quoting problems. These repeat identically and are
safe to allowlist by full shape.

## Escalation criteria

Escalate when deobfuscation reveals a download cradle, credential access, defence tampering, or
persistence; when the parent is Office or a browser; or when the same obfuscated shape appears on
multiple hosts within a short period.

## Response considerations

Preserve the original, un-deobfuscated command line as evidence — normalising it destroys the very
structure that justified the detection. Where the payload resolved to a download or in-memory
execution, treat the host as compromised and follow the response guidance of the technique the
payload actually performed. Enabling script block logging estate-wide is the durable fix: it moves
the investigation from guessing at wrappers to reading what ran.

## Purple-team validation

Atomic Red Team currently ships **no** tests mapped to T1027.010 — verified against the pinned index
in [`validation/atomic-index.json`](../validation/atomic-index.json), which is generated from the
upstream project rather than asserted here. Validate manually instead:

1. Run a benign encoded command: `powershell.exe -EncodedCommand <base64 of "Get-Date">` and confirm
   it is scored.
2. Run a caret-obfuscated equivalent: `c^m^d.exe /c e^c^h^o test` and confirm the density branch
   fires.
3. Run a `[char]`-concatenated string that resolves to a harmless cmdlet and confirm the indirection
   branch fires.
4. Run a long legitimate installer command line and confirm it does **not** fire.

Record the four results in the hunt log; they are the evidence that the scoring is calibrated for
your estate.

## Limitations and blind spots

Obfuscation inside a script file never reaches the command line. Short obfuscated commands score
below threshold by design. Legitimate encoded arguments are indistinguishable structurally — only
content resolves them. Non-Windows obfuscation (shell variable expansion, `eval`, `base64 -d | sh`)
needs the Linux and macOS analytics, which are noted in the ATT&CK alignment but not implemented in
the KQL here.

## Tuning notes

Compute percentiles for command-line length, caret density, and base64 token length over 30 days per
platform tier. Set thresholds at the 99th percentile, and re-measure after major software rollouts.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-010 LOLBin proxy execution](TH-010-lolbins-proxy-execution.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-020 WMI remote execution](TH-020-wmi-remote-execution.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0505 alignment, honest "no atomics exist" validation section
  with a manual procedure, unit tests, tuning percentile guidance.
- 2026-08-31 (v1.0.0): Initial version.
