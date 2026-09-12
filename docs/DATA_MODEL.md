# Data model and field mapping

## Why this matters

The same behaviour has a different field name in every product. A rule written against Sysmon's
`Image` does not fire against a backend that calls it `process.executable`, and the failure is
silent: the rule converts, deploys, and never matches. Field mapping is where portable detection
content actually breaks.

Sigma solves this with backend pipelines. This document records the mapping this library assumes, so
you can verify your pipeline rather than discover the gap during an incident.

## Process creation

| Concept | Sigma (this library) | Sysmon EID 1 | Windows 4688 | Defender XDR | Elastic ECS | Splunk CIM |
|---|---|---|---|---|---|---|
| Executed image | `Image` | `Image` | `NewProcessName` | `FolderPath` + `FileName` | `process.executable` | `Processes.process_path` |
| Command line | `CommandLine` | `CommandLine` | `CommandLine` | `ProcessCommandLine` | `process.command_line` | `Processes.process` |
| Parent image | `ParentImage` | `ParentImage` | `ParentProcessName` | `InitiatingProcessFolderPath` + `InitiatingProcessFileName` | `process.parent.executable` | `Processes.parent_process_path` |
| Parent command line | `ParentCommandLine` | `ParentCommandLine` | — | `InitiatingProcessCommandLine` | `process.parent.command_line` | `Processes.parent_process` |
| User | `User` | `User` | `SubjectUserName` | `AccountName` (+ `AccountDomain`) | `user.name` | `Processes.user` |
| Hash | `Hashes` | `Hashes` | — | `SHA256` / `SHA1` / `MD5` | `process.hash.*` | `Processes.process_hash` |
| Original file name | `OriginalFileName` | `OriginalFileName` | — | `ProcessVersionInfoOriginalFileName` | `process.pe.original_file_name` | — |
| Host | `Computer` | `Computer` | `Computer` | `DeviceName` | `host.name` | `Processes.dest` |

Two traps worth naming. Windows 4688 does **not** include the parent command line, so any rule that
depends on parent arguments degrades on 4688-only telemetry. And `OriginalFileName` is the field that
survives an adversary renaming a binary — where the sensor provides it, prefer it over the image name.

## File events

| Concept | Sigma | Sysmon EID 11 | Defender XDR | ECS |
|---|---|---|---|---|
| Target path | `TargetFilename` | `TargetFilename` | `FolderPath` + `FileName` | `file.path` |
| Writing process | `Image` | `Image` | `InitiatingProcessFileName` | `process.executable` |
| Hash | `Hashes` | `Hashes` | `SHA256` | `file.hash.sha256` |

## Windows Security events

| Concept | Sigma | Sentinel `SecurityEvent` |
|---|---|---|
| Event ID | `EventID` | `EventID` |
| Acting principal | `SubjectUserName` / `SubjectUserSid` | `SubjectUserName`, `SubjectAccount`, `SubjectUserSid` |
| Target principal | `TargetUserName` / `TargetSid` | `TargetUserName`, `TargetAccount`, `TargetSid` |
| Source address | `IpAddress` | `IpAddress` (sometimes `ClientAddress`) |
| Logon type | `LogonType` | `LogonType` (string in some parsers — cast it) |

`SecurityEvent` field availability depends on the connector and the event. This library uses
`column_ifexists(...)` in KQL for fields that are not present on every event shape, which keeps a
query from failing outright when one field is missing.

## Entra ID

| Concept | Sigma | Sentinel |
|---|---|---|
| Sign-in result | `ResultType` | `ResultType` (string — cast with `toint`) |
| User | `UserPrincipalName` | `UserPrincipalName` |
| Source address | `IPAddress` | `IPAddress` |
| Audit operation | `OperationName` | `OperationName` |
| Audit detail | `Properties` | `TargetResources[0].modifiedProperties` |

Interactive and non-interactive sign-ins live in **different tables** (`SigninLogs` and
`AADNonInteractiveUserSignInLogs`). Legacy-protocol password spraying frequently appears only in the
second one. A tenant that ingests only the first has a blind spot, not a clean bill of health.

## DNS

| Concept | Sigma `dns` | Sentinel ASIM `_Im_Dns` | Zeek |
|---|---|---|---|
| Query | `query` | `DnsQuery` | `query` |
| Record type | `query_type` | `DnsQueryTypeName` | `qtype_name` |
| Client | `src_ip` | `SrcIpAddr` / `SrcHostname` | `id.orig_h` |
| Response code | — | `EventResultDetails` | `rcode_name` |

## Linux

| Concept | Sigma | Defender for Endpoint on Linux | auditd |
|---|---|---|---|
| Executed image | `Image` | `FolderPath` + `FileName` | `exe` |
| Command line | `CommandLine` | `ProcessCommandLine` | `proctitle` (reassembled) |
| Parent | `ParentImage` | `InitiatingProcessFileName` | `ppid` → lookup |
| File write target | `TargetFilename` | `FolderPath` + `FileName` | `PATH.name` |

auditd does not give you a command line directly: `proctitle` is a hex-encoded, argument-joined
approximation. Rules that depend on precise argument boundaries behave differently there.

## Verifying your pipeline

Do not assume the mapping. Prove it once per backend:

1. Generate one known event (an Atomic test, or a benign command).
2. Retrieve the raw event from the backend.
3. Confirm each field the rule references is present and holds what you expect.
4. Convert the rule and read the emitted query — the field names in the output are the truth.

Record the result. A pipeline verification is worth more than a dozen untested rules.
