# Roadmap

Honest scope, in priority order. Items move up when someone needs them, not on a schedule.

## Planned

| Item | Why | Notes |
|---|---|---|
| Splunk SPL and Elastic ES|QL surfaces | Sigma conversion is not the same as a well-written native query; aggregation-heavy hunts convert badly | Would follow the same file-naming contract, one file per playbook |
| QRadar AQL surfaces | Widely deployed in the MSSP world, poorly served by public detection content | AQL's aggregation model differs enough to need hand-written queries |
| Container and Kubernetes coverage | Runtime persistence and service-account token abuse are unaddressed here | Needs a telemetry model (`kubernetes:audit`, eBPF) before content |
| macOS coverage | Currently referenced only through ATT&CK analytics, never implemented | Requires EndpointSecurity or Defender for macOS telemetry |
| ESXi and hypervisor coverage | ATT&CK v19 added ESXi analytics for several techniques already in scope (T1490, T1074.001, T1685) | High value in ransomware scenarios |
| Sigma backend conversion matrix | Prove which rules survive conversion to which backends, in CI | Currently a non-blocking smoke test only |
| Detection-as-code deployment examples | Terraform or Bicep for Sentinel analytic rules generated from frontmatter | The metadata already exists; the deployment layer does not |

## Considered and rejected

| Item | Why not |
|---|---|
| A rule for every ATT&CK technique | Coverage counted in techniques is a vanity metric. Depth on techniques that matter beats breadth that nobody tunes. |
| Machine-learning anomaly content | Not reproducible in a public repository without the data it learned from, and unfalsifiable for a reader. |
| Bundling a Sysmon configuration | Excellent ones already exist (SwiftOnSecurity, Olaf Hartong). Forking one here would add maintenance burden and no value. |
| IOC feeds | Different lifecycle, different failure mode, different repository. |
| `production` status on any rule | That status is earned in one environment against its own baseline. Claiming it here would be dishonest. |

## Known limitations that are not going away

Some gaps are structural rather than unfinished:

- **KQL cannot be executed in CI.** It is linted, not run. No public repository can execute KQL
  without a workspace and data.
- **The Sigma engine models the specification, not a backend.** Passing tests prove logic, not
  behaviour in your SIEM.
- **Synthetic events are shaped by the author's assumptions.** They test the rule's logic, not the
  messiness of real telemetry. That is what the Atomic validation layer is for.
- **Thresholds cannot be right by default.** Every one is documented as a starting point with a
  baseline query attached.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md). The short version: a new playbook needs a hypothesis, a
telemetry contract, at least one query surface, a Sigma rule, true-positive *and* false-positive
tests, an honest blind-spot section, and `make check` passing.
