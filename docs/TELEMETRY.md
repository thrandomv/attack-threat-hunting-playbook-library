# Telemetry requirements

## Data contract

Each analytic depends on a data contract: event meaning, producer, required fields, expected latency, retention, and failure mode. A query that returns zero rows does not prove the environment is clean until collection is verified.

## Core sources

| Source | Example table / category | Essential fields | Primary hunts |
|---|---|---|---|
| Endpoint process creation | `DeviceProcessEvents`; Sigma `process_creation` | time, host, image, command line, parent image/command line, user, hash | TH-001, 005, 007, 009–012, 014–017, 019–020 |
| Endpoint file events | `DeviceFileEvents` | time, host, path, name, hash, origin URL, initiator | TH-001, 016, 017, 019 |
| Windows Security log | `SecurityEvent`; Sigma `windows/security` | event ID, host, subject, target, logon type, source IP, service, ticket encryption | TH-002–006, 013, 018 |
| Microsoft Entra sign-ins | `SigninLogs` | time, user, IP, result type, application, user agent, location, risk | TH-018 |
| Normalized DNS | Sentinel `_Im_Dns`; Sigma `dns` | query, query type, response, client IP/host, timestamp | TH-008 |
| Network connections | `DeviceNetworkEvents` or normalized network session | time, source process/host, destination host/IP/port, direction | TH-007–010, 016–017, 020 |
| Registry activity | `DeviceRegistryEvents`; Sysmon EID 12–14 | key, value, old/new data, process, user | TH-014 and investigation pivots |
| PowerShell logs | Script Block 4104, Module 4103, transcription | script text, host, user, runspace, engine version | TH-007, 009, 015 |
| Web/proxy/WAF | vendor table or ASIM web session | URI, method, response, client, server, user agent | TH-016–017 |
| AD CS certification authority | `SecurityEvent` 4886/4887 | requester, template, request attributes (SAN), serial | TH-021 |
| Detailed file share (named pipes) | `SecurityEvent` 5145 | share name, relative target, source IP, subject | TH-022 |
| Microsoft Entra audit | `AuditLogs` | operation, initiator, target resource, modified properties | TH-023 |
| Linux endpoint | `DeviceProcessEvents`, `DeviceFileEvents` (Defender for Endpoint on Linux), Sysmon for Linux, auditd | image, command line, parent, target filename, user | TH-025 |

## Windows audit prerequisites

Use centrally managed policy and verify success events arrive before relying on these hunts.

| Event IDs | Audit area | Use |
|---|---|---|
| 4624, 4625 | Logon / Logoff | Network, RDP, and failed authentication analysis |
| 4648 | Logon with explicit credentials | Credential-use investigation pivot |
| 4662 | Directory Service Access | DCSync; requires appropriate SACLs on domain objects |
| 4688 | Process Creation | Process lineage when EDR is unavailable; enable command-line inclusion |
| 4698 | Other Object Access Events | Scheduled-task creation |
| 4720, 4722, 4728, 4732, 4756 | Account Management | User creation, enablement, and group membership changes |
| 4768, 4769, 4771 | Kerberos Authentication Service | Kerberos behavior and Kerberoasting |
| 5140, 5145 | Detailed File Share | SMB share access and lateral-movement pivots |
| 1102 | System audit policy / Security log | Security log cleared |
| 4886, 4887 | Certification Services | Certificate requested and issued; requires `certutil -setreg CA\\AuditFilter` |
| 5145 | Detailed File Share | Named-pipe access used by authentication coercion (TH-022) |
| 4697, 7045 | Service installation | Service creation (Security and System channels respectively) |

Event 7045 is in the Windows System channel, not the Security channel. Collect it through a `WindowsEvent`/event-log connector or rely on endpoint process and service telemetry.

## Endpoint sensor expectations

For process-based hunts, preserve the original process command line, initiating process, user context, and hashes. If using Sysmon, process creation is Event ID 1, network connection is Event ID 3, DNS query is Event ID 22, process access is Event ID 10, and file creation is Event ID 11. Sysmon configuration determines what is included or excluded; validate the deployed configuration rather than assuming event IDs are sufficient.

Sensitive-process access such as LSASS is best detected with EDR behavioral telemetry or carefully configured Sysmon Event ID 10. Process-creation data alone observes dump utilities and commands but may miss custom or injected access.

## Microsoft data surfaces

`DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` are Defender XDR advanced hunting tables populated by the relevant Defender services. Sentinel `SecurityEvent`, `WindowsEvent`, `SigninLogs`, and ASIM parsers are Log Analytics surfaces. KQL syntax is shared, but table availability and cross-workspace joins differ.

For source-independent DNS content, Microsoft recommends the ASIM unifying parser `_Im_Dns`, which combines supported query-time and ingest-time normalized data. Confirm that `DnsQuery`, `SrcIpAddr`, `SrcHostname`, `DnsQueryTypeName`, and `EventResultDetails` are populated by your parsers.

## Data-quality checks

Run these before a hunt and save the result with the hunt record:

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize Events=count(),
            Hosts=dcount(DeviceId),
            MissingCommandLine=countif(isempty(ProcessCommandLine)),
            MissingParent=countif(isempty(InitiatingProcessFileName)),
            LastEvent=max(Timestamp)
```

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Events=count(), Hosts=dcount(Computer), LastEvent=max(TimeGenerated) by EventID
| order by Events desc
```

```kusto
_Im_Dns(starttime=ago(24h))
| summarize Events=count(), Clients=dcount(SrcIpAddr),
            MissingQuery=countif(isempty(DnsQuery)), LastEvent=max(EventStartTime)
```

Investigate ingestion delay, abrupt volume changes, missing hosts, duplicated events, parser errors, clock skew, and retention boundaries. Record data gaps as findings; do not silently narrow the conclusion.

## Privacy and minimization

Command lines, DNS names, URLs, and sign-in metadata can contain personal or sensitive data. Apply role-based access, retention limits, query auditing, and redaction in exported evidence. Never commit raw production telemetry to this repository.

## Coverage self-assessment

Before claiming a technique is covered, answer three questions for its **required** sources:

1. **Is it collected?** Not "is the connector enabled" — is the event arriving, from every host class
   in scope, right now? The data-quality queries above answer this.
2. **Are the fields populated?** Command lines get truncated, `Properties` blobs get dropped by
   parsers, `RelativeTargetName` disappears in some pipelines. A field that is absent turns a
   detection into a rule that can never fire.
3. **Is the audit policy actually applied?** Several playbooks (TH-002, TH-021, TH-022) depend on
   auditing that is off by default. Verify per host, not per policy object: one unaudited domain
   controller is a complete bypass.

Record the answers with the hunt. A negative result is only meaningful next to evidence that the
telemetry existed.
