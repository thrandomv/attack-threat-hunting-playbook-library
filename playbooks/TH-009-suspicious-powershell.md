---
id: TH-009
name: suspicious-powershell
title: Suspicious PowerShell execution
summary: PowerShell invoked with encoding, download cradles, in-memory execution or defence tampering, especially from an unusual parent.
status: production-candidate
severity: high
confidence: medium
version: 2.0.1
created: 2026-08-31
updated: 2026-09-12
review_cadence: monthly
owner: SOC detection engineering
platforms: [Windows]
attack:
  primary_technique: T1059.001
  techniques: [T1059.001]
  primary_tactic: execution
  detection_strategies: [DET0455]
telemetry:
  required:
    - Process creation with full command line (DeviceProcessEvents or Security 4688)
  optional:
    - PowerShell 4104 script block logging (the only view of in-session behaviour)
    - PowerShell 400/403 engine lifecycle and 4103 module logging
    - Sysmon Event ID 7 for System.Management.Automation.dll loaded by non-PowerShell hosts
surfaces:
  kql: queries/kql/TH-009-suspicious-powershell.kql
  sigma: rules/sigma/TH-009-suspicious-powershell.yml
  tests: tests/rules/TH-009-suspicious-powershell.yml
validation:
  atomics:
    - bf8c1441-4674-4dab-8e4e-39d93d08f9b7
    - af1800cf-9f9d-4fd1-a709-14b1e6de020d
    - a21bb23e-e677-4ee7-af90-6931b57b6350
    - 388a7340-dbc1-4c9d-8e59-b75ad8c6d5da
related: [TH-007, TH-015, TH-016, TH-014]
tags: [execution, endpoint, windows, powershell]
---

# TH-009 — Suspicious PowerShell execution

## Hypothesis

An adversary is using PowerShell to download and execute code in memory, obscure the command with
encoding, or disable local defences — typically launched by a process that has no business starting
a shell.

## Why this matters

PowerShell is signed, present everywhere, and deeply integrated, which makes it the default execution
layer for both commodity and targeted intrusions. Blocking it is rarely realistic, so detection has
to separate the small set of adversary-typical behaviours from the very large set of legitimate
administrative usage. Parent process is the strongest single discriminator available.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Tactic | Execution (TA0002) |
| Detection strategy | [DET0455 — Abuse of PowerShell for Arbitrary Execution](https://attack.mitre.org/detectionstrategies/DET0455) |
| Analytic | AN1252 (Windows) — command-line patterns, parent process, module loads, script block length |

AN1252's `ScriptBlockLengthThreshold` and `LoadedModuleList` are reminders that command-line-only
detection is the shallow end of this technique; both are addressed in the telemetry notes.

## Telemetry requirements

**Required.** Process creation with command line. Note that `-EncodedCommand` payloads appear in the
command line but the *decoded* content does not — that requires script block logging.

**Optional but decisive.** Script block logging (4104) captures what actually ran, including
in-memory content that never touches a command line. Module load telemetry catches custom hosts that
load the automation DLL without ever launching `powershell.exe`.

**Data-quality check.** Confirm command lines are not truncated at 4096 characters (a common
truncation point that silently cuts off encoded payloads) and that both `powershell.exe` and
`pwsh.exe` are covered.

## Analytic approach

Score independent behaviours — encoding, hidden execution, download cradles, in-memory execution,
defence tampering, suspicious parent — and require either two signals, or one high-value signal
(defence tampering) on its own. Scoring rather than listing keeps the rule maintainable: a new
download cradle syntax adds one string, not a new rule.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `MinSignalCount` | KQL | 2 | `CommandLinePattern` | Lower to 1 on servers where PowerShell use is rare and scripted. |
| `SuspiciousParents` | KQL / Sigma | Office, script hosts, web servers | `ParentProcessName` | Add line-of-business apps that spawn shells only after reviewing why they do. |
| `Lookback` | KQL | 7d | `TimeWindow` | Daily execution is realistic; keep 7d for hunting. |
| Script block length | Telemetry note | n/a | `ScriptBlockLengthThreshold` | With 4104 enabled, unusually long single blocks are a strong secondary signal. |

## Query surfaces

- KQL: [`queries/kql/TH-009-suspicious-powershell.kql`](../queries/kql/TH-009-suspicious-powershell.kql)
- Sigma: [`rules/sigma/TH-009-suspicious-powershell.yml`](../rules/sigma/TH-009-suspicious-powershell.yml)

## Unit tests

[`tests/rules/TH-009-suspicious-powershell.yml`](../tests/rules/TH-009-suspicious-powershell.yml)
covers an encoded hidden-window invocation, a download cradle piped to `IEX`, a Defender exclusion
added from PowerShell, and — as negatives — an ordinary administrative one-liner and a signed
management agent running a script from `Program Files`.

Two further cases pin the two-signal threshold itself: exactly two signals under an ordinary parent
must match, exactly one must not. The Sigma condition expresses that threshold as six explicit pairs
rather than `2 of sig_*`, because pySigma implements only the quantifiers `1`, `any` and `all` — see
[SIGMA_STYLE](../docs/SIGMA_STYLE.md#condition-grammar). Those two cases are what keep the expansion
honest if anyone edits it.

## Triage workflow

1. Decode the payload. Base64 in `-EncodedCommand` is UTF-16LE; decode it before judging severity.
2. Read the parent chain. Office, browser, `mshta`, `wscript`, or `w3wp` as parent is an intrusion
   pattern, not an administration pattern.
3. Pull the script block logs for the session and read what actually executed.
4. Check the network: where did the cradle download from, and did the payload land on disk?
5. Check for follow-on activity: persistence, credential access, lateral movement.
6. Scope by command-line hash and by parent pattern across the estate.

## Benign explanations

Software deployment, configuration management, monitoring agents, installers, and administrators
using encoded commands for quoting convenience. All of these are stable and repeat identically —
that repetition is what makes them safe to allowlist by full command-line shape rather than by
keyword.

## Escalation criteria

Escalate on any defence tampering, on encoded commands from an interactive user session, on a
download cradle to an unknown host, on Office or browser parents, and on execution as SYSTEM from a
non-service parent.

## Response considerations

Capture the decoded payload and any downloaded artefacts before containment. Enable script block
logging estate-wide if this hunt is repeatedly blind. Consider Constrained Language Mode and WDAC
for the long-term fix; AMSI-bypass attempts should themselves be an alert (see TH-014).

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Run Bloodhound from Memory using Download Cradle | `bf8c1441-4674-4dab-8e4e-39d93d08f9b7` | Windows | Download cradle plus in-memory execution markers |
| Mimikatz - Cradlecraft PsSendKeys | `af1800cf-9f9d-4fd1-a709-14b1e6de020d` | Windows | Obfuscated cradle; tests the scoring rather than a single string |
| Run BloodHound from local disk | `a21bb23e-e677-4ee7-af90-6931b57b6350` | Windows | Script execution without a cradle — a deliberate lower-signal case |
| Powershell MsXml COM object - with prompt | `388a7340-dbc1-4c9d-8e59-b75ad8c6d5da` | Windows | COM-based download that avoids common cradle keywords |

The last two exist to show where command-line scoring degrades and script block logging takes over.

## Limitations and blind spots

Payloads executed inside an existing session leave no new command line. Custom hosts that load
`System.Management.Automation.dll` never launch `powershell.exe`. Obfuscation defeats string
matching by design (see TH-015 for the complementary approach). Command-line truncation silently
removes the evidence.

## Tuning notes

Cluster PowerShell command lines by normalised shape over 30 days; a handful of shapes will account
for most volume. Allowlist those by full shape and parent, and review the long tail — that tail is
where both the interesting administration and the intrusions live.

## Related playbooks

- [TH-007 WinRM and PowerShell remoting](TH-007-winrm-powershell-remoting.md)
- [TH-014 Impair defenses](TH-014-impair-defenses.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)

## Change log

- 2026-09-12 (v2.0.1): Two-signal threshold expanded from `2 of sig_*` into explicit pairs. The
  original is valid Sigma but pySigma implements only the quantifiers `1`, `any` and `all`, so the
  rule converted in no backend. Logic is unchanged; two test cases now pin the boundary at exactly
  one and exactly two signals.
- 2026-09-10 (v2.0.0): Frontmatter, DET0455 alignment, substring matching for switches, `pwsh.exe`
  coverage, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
