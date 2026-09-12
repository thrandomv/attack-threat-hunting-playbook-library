# ATT&CK Threat Hunting Playbook Library

Twenty-five hypothesis-driven threat hunts for Microsoft Sentinel, Defender XDR and any
Sigma-compatible SIEM. Every rule ships with unit tests, ATT&CK v19 detection-strategy alignment, and
a documented list of what it cannot see.

## Start here

| If you want to… | Read |
|---|---|
| Understand what makes this different from a query dump | [Testing detection content](TESTING.md) |
| Deploy a hunt | [Deployment guide](DEPLOYMENT.md) |
| Know what telemetry you need first | [Telemetry requirements](TELEMETRY.md) |
| Map fields to your own SIEM | [Data model](DATA_MODEL.md) |
| Tune thresholds honestly | [Tuning methodology](TUNING.md) |
| Prove a detection actually works | [Atomic Red Team validation](ATOMIC_VALIDATION.md) |
| Run a hunt as an analyst | [Triage workflow](TRIAGE.md) |
| Operate the content over time | [Operating model](OPERATING_MODEL.md) |
| Understand the repository itself | [Architecture](ARCHITECTURE.md) |

## The short version

Most public detection libraries publish queries nobody has executed. This one executes every Sigma
rule against synthetic true-positive and false-positive events in CI, validates every ATT&CK
technique and Atomic Red Team GUID against pinned snapshots of the upstream sources, and generates
every coverage artefact from playbook frontmatter so the documentation cannot drift from the content.

Each playbook states its hypothesis, the telemetry it requires (and how to verify you have it), the
analytic approach with each tunable parameter mapped to an ATT&CK mutable element, a triage workflow,
the benign explanations that will account for most matches, purple-team validation steps, and — the
section that matters most — what the detection cannot see.

## Coverage

See the [ATT&CK coverage matrix](../mappings/attack-coverage.md) and the
[playbook index](../playbooks/README.md).
