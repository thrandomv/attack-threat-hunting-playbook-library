---
id: TH-005
name: psexec-remote-services
title: PsExec-style remote service execution
summary: Remote command execution through admin shares and temporary Windows services, the classic PsExec pattern and its clones.
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
  primary_technique: T1021.002
  techniques: [T1021.002, T1569.002]
  primary_tactic: lateral-movement
  detection_strategies: [DET0530, DET0421]
telemetry:
  required:
    - Microsoft Defender XDR DeviceProcessEvents (or Security 4688 with command line)
    - System 7045 / Security 4697 service installation events
  optional:
    - Security 5145 (detailed file share access) for ADMIN$ and IPC$
    - Security 4624 type 3 to attribute the remote session
    - DeviceFileEvents for the service binary written to disk
surfaces:
  kql: queries/kql/TH-005-psexec-remote-services.kql
  sigma: rules/sigma/TH-005-psexec-remote-services.yml
  tests: tests/rules/TH-005-psexec-remote-services.yml
validation:
  atomics:
    - 0eb03d41-79e4-4393-8e57-6344856be1cf
    - 873106b7-cfed-454b-8680-fa9f6400431c
    - 2382dee2-a75f-49aa-9378-f52df6ed3fb1
    - a5d8cdeb-be90-43a9-8b26-cc618deac1e0
related: [TH-004, TH-012, TH-020, TH-016]
tags: [lateral-movement, execution, windows, endpoint]
---

# TH-005 — PsExec-style remote service execution

## Hypothesis

An adversary is executing commands on remote Windows hosts by writing a payload to an administrative
share and registering it as a temporary service, producing a short-lived service and an unusual
child of `services.exe`.

## Why this matters

This is the most durable lateral-movement pattern in Windows: it works with any admin credential, it
is implemented by dozens of tools (PsExec, PAExec, RemCom, CSExec, Impacket's `smbexec` and
`psexec.py`), and administrators use the original constantly. Detection therefore cannot rely on the
tool name — it has to key on the *shape*: a service created from a non-standard path, executing a
command interpreter, minutes after a network logon from another host.

## ATT&CK alignment

| Item | Value |
|---|---|
| Techniques | [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/), [T1569.002 — System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/) |
| Tactic | Lateral Movement (TA0008); Execution (TA0002) for the service half |
| Detection strategies | [DET0530](https://attack.mitre.org/detectionstrategies/DET0530), [DET0421](https://attack.mitre.org/detectionstrategies/DET0421) |
| Analytics | AN1468 (share + logon + process chain), AN1185 (service binary allowlist, parent correlation window) |

## Telemetry requirements

**Required.** Process creation with parent image and command line, plus service installation events
(System 7045 on the destination, or Security 4697 where audit policy allows). Either source alone
leaves half the technique invisible: 7045 without process data cannot show what the service ran, and
process data without 7045 misses tools that delete the service immediately.

**Optional.** 5145 share-access auditing shows the payload copy to `ADMIN$`; it is expensive to
collect and worth enabling only on tier-0 and high-value hosts.

**Data-quality check.** Confirm 7045 is being collected from member servers — many deployments
forward Security but not System. Verify by installing a benign service in a test window.

## Analytic approach

Two independent branches, either of which is sufficient to review:

1. **Known service images** — the binary names shipped by PsExec-family tools, matched on image and
   original file name so a rename is still caught by one of the two.
2. **Anomalous service children** — any child of `services.exe` that is a command interpreter, or
   whose image lives in a user-writable or administrative-share path.

The second branch is what survives contact with an adversary who compiles their own service wrapper.
Its cost is that legitimate software installers occasionally look identical, which is why the
playbook expects an allowlist built from your own software-deployment baseline.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `Lookback` | KQL | 7d | `ParentProcessCorrelationWindow` | Keep long enough to see the paired 4624 on the destination. |
| `KnownServiceImages` | KQL / Sigma | PsExec family | `ServiceBinaryAllowlist` | Extend when new tooling appears in incidents; never shorten to suppress noise. |
| `SuspiciousRoots` | KQL | temp, public, share paths | `ImagePathFilter` | Add any path your software deployment tool stages into, then verify the signer instead. |
| `ApprovedDeploymentParents` | KQL | empty | `ServiceBinaryAllowlist` | SCCM/Intune/agent installers, matched by full path. |

## Query surfaces

- KQL: [`queries/kql/TH-005-psexec-remote-services.kql`](../queries/kql/TH-005-psexec-remote-services.kql)
- Sigma: [`rules/sigma/TH-005-psexec-remote-services.yml`](../rules/sigma/TH-005-psexec-remote-services.yml)

## Unit tests

[`tests/rules/TH-005-psexec-remote-services.yml`](../tests/rules/TH-005-psexec-remote-services.yml)
covers the PsExec service binary, a renamed service binary running `cmd.exe` from `C:\Windows`, and
an Impacket-style `smbexec` command line; the negative cases cover a normal service starting its own
binary from `Program Files` and a legitimate installer child.

## Triage workflow

1. On the destination, establish the service: name, image path, account, and whether it still exists.
   PsExec-family services are created and deleted within seconds.
2. Correlate the network logon (4624 type 3) immediately preceding the service creation to identify
   the source host and account.
3. On the source host, look for the tool: process creation, file writes, and the credential it used
   (4648).
4. Determine what the service actually executed — the child process tree is the payload.
5. Scope: the same source account or service name across the estate, and any other destination
   contacted from that source in the same window.

## Benign explanations

Administrators using Sysinternals PsExec, software deployment agents, remote support tooling, and
monitoring products that install temporary services. All are attributable to a known source host and
a change record; the pattern that is never benign is a service image staged in `C:\Windows\Temp` by
an interactive user account.

## Escalation criteria

Escalate when the service image sits in a writable path, when the service is deleted within a minute
of creation, when the source is a workstation, when the executing account is not an approved admin,
or when the same pattern repeats across multiple destinations (see TH-004).

## Response considerations

Capture the service binary before it is deleted; it is often the only copy of the payload. Preserve
both hosts, review what the payload did, and treat the credentials used as compromised. Restricting
`ADMIN$` reachability and enforcing SMB signing reduces the primitive's availability.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| Copy and Execute File with PsExec | `0eb03d41-79e4-4393-8e57-6344856be1cf` | Windows | PSEXESVC service creation, `services.exe` child, 4624 type 3 |
| Use PsExec to execute a command on a remote host | `873106b7-cfed-454b-8680-fa9f6400431c` | Windows | Same, with the command interpreter as the payload |
| Execute a Command as a Service | `2382dee2-a75f-49aa-9378-f52df6ed3fb1` | Windows | 7045 with a `cmd.exe` binary path — the local half of the technique |
| Use RemCom to execute a command on a remote host | `a5d8cdeb-be90-43a9-8b26-cc618deac1e0` | Windows | A non-PsExec service image, proving the second analytic branch works |

## Limitations and blind spots

Tools that use WMI (TH-020), WinRM (TH-007), or scheduled tasks (TH-011) instead of services are out
of scope here by design. Services deleted before the 7045 event is forwarded leave only process
evidence. An adversary who names their service binary like a real product and stages it in
`Program Files` defeats the path heuristic — signer and prevalence checks are the answer, not more
path strings.

## Tuning notes

Build the allowlist from what actually installs services in your estate over 30 days, grouped by
image path and signer. Expect fewer than twenty distinct legitimate publishers in most environments.

## Related playbooks

- [TH-004 Pass the Hash](TH-004-pass-the-hash.md)
- [TH-012 Windows service creation](TH-012-windows-service-creation.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-020 WMI remote execution](TH-020-wmi-remote-execution.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0530/DET0421 alignment, original-file-name matching, substring
  path matching instead of term matching, unit tests, Atomic validation table.
- 2026-08-31 (v1.0.0): Initial version.
