---
id: TH-008
name: dns-tunneling
title: DNS tunneling and encoded DNS traffic
summary: Clients encoding command-and-control or exfiltration data in DNS labels, visible as long, unique, high-entropy queries to a narrow domain set.
status: hunt
severity: high
confidence: medium
version: 2.0.0
created: 2026-08-31
updated: 2026-09-10
review_cadence: monthly
owner: SOC / Network security
platforms: [Windows, Linux, macOS, Network]
attack:
  primary_technique: T1071.004
  techniques: [T1071.004]
  primary_tactic: command-and-control
  detection_strategies: [DET0400]
telemetry:
  required:
    - Normalised DNS query logs with client attribution (Sentinel ASIM _Im_Dns, Zeek dns.log, or resolver logs)
  optional:
    - Endpoint process-to-DNS mapping (Sysmon Event ID 22, DeviceNetworkEvents)
    - Passive DNS, domain age and reputation enrichment
    - Proxy and firewall logs for the same client
surfaces:
  kql: queries/kql/TH-008-dns-tunneling.kql
  sigma: rules/sigma/TH-008-dns-tunneling.yml
  tests: tests/rules/TH-008-dns-tunneling.yml
validation:
  atomics:
    - 1700f5d6-5a44-487b-84de-bc66f507b0a6
    - 3efc144e-1af8-46bb-8ca2-1376bb6db8b6
    - fef31710-223a-40ee-8462-a396d6b66978
    - e7bf9802-2e78-4db9-93b5-181b7bcd37d7
related: [TH-009, TH-015, TH-016, TH-017]
tags: [command-and-control, network, dns, exfiltration]
---

# TH-008 — DNS tunneling and encoded DNS traffic

## Hypothesis

A client is encoding commands or data in DNS queries, producing unusually long or high-entropy
labels, a high ratio of unique subdomains to total queries, uncommon record types, periodic timing,
or an elevated NXDOMAIN rate against a small number of parent domains.

## Why this matters

DNS is allowed almost everywhere, including from segments with no other egress. It carries both
command-and-control and slow exfiltration. No single feature is decisive — CDNs, endpoint security
products, telemetry agents, and anti-spam lookups all generate long, unique labels — so a defensible
hunt combines label length, character distribution, query volume, uniqueness ratio, record type,
failure rate, periodicity, domain age, and the originating process.

## ATT&CK alignment

| Item | Value |
|---|---|
| Technique | [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) |
| Tactic | Command and Control (TA0011) |
| Detection strategy | [DET0400 — Behavioral Detection of DNS Tunneling and Application Layer Abuse](https://attack.mitre.org/detectionstrategies/DET0400) |
| Analytics | AN1121 (Windows), AN1122 (Linux), AN1123 (macOS), AN1124 (network devices), AN1125 (ESXi) |

ATT&CK's analytics name `QueryLengthThreshold`, `SubdomainEntropyScore`, `DomainReputationFeed`,
`QueryRatePerClient` and `ProcessImageFilter` as the tunable elements — the same five levers the
query below exposes.

## Telemetry requirements

**Required.** DNS query logs that identify the *original* client, not the forwarder. In Sentinel the
ASIM `_Im_Dns` parser normalises `DnsQuery`, `DnsQueryTypeName`, `EventResultDetails`, `SrcIpAddr`
and (where available) `SrcHostname`.

**Optional.** Endpoint DNS events map the query to a process, which converts a medium-confidence
network lead into a high-confidence endpoint investigation. Domain registration and reputation data
separate a new adversary domain from a fifteen-year-old CDN.

**Data-quality check.** Confirm queries are not truncated, that the client identity is the endpoint
rather than the resolver, that NXDOMAIN responses are represented, and that internal-only clients are
covered. Where DNS over HTTPS is permitted, document that gap explicitly — it is a coverage hole, not
a tuning problem.

## Analytic approach

Aggregate by client and registrable-domain approximation over a short window, then require
*sustained* behaviour: enough queries to be a channel rather than an accident, and at least one of
high uniqueness ratio, extreme label length, or a large count of encoded-looking labels. Because
reliable public-suffix parsing is environment-specific, the query uses a documented last-two-label
approximation and exposes `BaseDomain` so the approximation can be replaced with a managed function.

The Sigma rule intentionally does **not** alert on record type alone. TXT queries are ubiquitous
(SPF, DKIM, DMARC, domain verification); alerting on them produces noise that trains analysts to
ignore the rule. The rule requires an encoded-looking label, and treats unusual record types as an
amplifier.

### Tunable parameters

| Parameter | Where | Default | ATT&CK mutable element | Tuning guidance |
|---|---|---|---|---|
| `MinQueries` / `MinUniqueQueries` | KQL | 100 / 50 | `QueryRatePerClient` | Set from per-client percentiles; laptops and servers differ by an order of magnitude. |
| `MinUniqueRatio` | KQL | 0.70 | `SubdomainEntropyScore` | Below 0.5 the ratio stops discriminating. |
| `MinMaxLabelLength` | KQL / Sigma regex | 45 | `QueryLengthThreshold` | 45 is conservative; CDNs regularly reach 40. |
| `KnownGoodSuffixes` | KQL / Sigma filter | vendor domains | `DomainReputationFeed` | Maintain as reference data, reviewed quarterly. |
| Window | KQL | 15m | `TimeWindow` | Longer windows catch low-and-slow at the cost of dilution. |

## Query surfaces

- KQL: [`queries/kql/TH-008-dns-tunneling.kql`](../queries/kql/TH-008-dns-tunneling.kql)
- Sigma: [`rules/sigma/TH-008-dns-tunneling.yml`](../rules/sigma/TH-008-dns-tunneling.yml) — a
  single-query heuristic; the volume, uniqueness and periodicity analytics stay in the SIEM.

## Unit tests

[`tests/rules/TH-008-dns-tunneling.yml`](../tests/rules/TH-008-dns-tunneling.yml) proves the rule
fires on a long encoded label and on an encoded TXT lookup, and — the regression that motivated the
v2 rewrite — that it stays silent on ordinary TXT queries such as DMARC lookups and on long but
allowlisted CDN and endpoint-security labels.

## Triage workflow

1. Resolve the original client, base domain, sample queries, record types, response codes, and
   first/last seen.
2. Check domain ownership, registration age, reputation, and prevalence across peers. A domain used
   by exactly one host is far more interesting than one used by four hundred.
3. Identify the originating process and its tree; check signer, path, and hash prevalence.
4. Plot query timing and lengths. Automated update and tracking traffic is regular but low-entropy;
   data-bearing labels are long and unique.
5. Review the client's other egress: proxy, firewall, downloads, execution, persistence.
6. Scope other clients querying the same base domain or infrastructure.

## Benign explanations

Endpoint security and anti-spam lookups (which encode hashes into labels by design), CDNs, telemetry
and analytics agents, certificate validation, dynamic DNS, service discovery, and DKIM. Validate by
vendor ownership, process identity, and a stable deployment population.

## Escalation criteria

Escalate when the originating process is unusual, the domain is newly registered or unknown, the
unique-subdomain ratio is high, labels look encoded, TXT or NULL records carry payload-sized data,
timing is regular, or the client shows correlated execution or persistence.

## Response considerations

Preserve query samples, process evidence, and domain intelligence before blocking — sinkholing a
domain ends your visibility of the channel. Hunt historical traffic first where time allows, then
coordinate host isolation and resolver blocking with the incident lead.

## Purple-team validation

| Atomic Red Team test | GUID | Platform | Expected evidence |
|---|---|---|---|
| DNS Long Domain Query | `fef31710-223a-40ee-8462-a396d6b66978` | Windows | Single very long label — should trip the Sigma rule |
| DNS Large Query Volume | `1700f5d6-5a44-487b-84de-bc66f507b0a6` | Windows | High volume of unique labels — should trip the KQL aggregation |
| DNS Regular Beaconing | `3efc144e-1af8-46bb-8ca2-1376bb6db8b6` | Windows | Periodic low-rate queries — deliberately *not* covered by either surface |
| DNS C2 | `e7bf9802-2e78-4db9-93b5-181b7bcd37d7` | Windows | Full channel behaviour |

Run in an isolated lab against a domain you control. Do not build a functional covert channel on a
production network, and remove any test records afterwards.

## Limitations and blind spots

DNS over HTTPS or TLS bypasses resolver visibility entirely. Public-suffix approximation
mis-groups multi-part TLDs. Low-and-slow tunnels stay under volume thresholds by design — the
beaconing atomic above is included precisely to demonstrate that gap. Encrypted or hashed legitimate
labels resemble encoded data. NAT and forwarding obscure the client.

## Tuning notes

Build the allowlist from observed vendor suffixes over 30 days, and record *why* each entry is there.
Prefer suffix allowlisting over raising thresholds: thresholds hide adversaries as well as vendors.

## Related playbooks

- [TH-009 Suspicious PowerShell](TH-009-suspicious-powershell.md)
- [TH-015 Obfuscated command execution](TH-015-obfuscated-command-execution.md)
- [TH-016 Ingress tool transfer](TH-016-ingress-tool-transfer.md)
- [TH-017 Web shell behavior](TH-017-web-shell-behavior.md)

## Change log

- 2026-09-10 (v2.0.0): Frontmatter, DET0400 alignment, Sigma rewritten so record type alone can no
  longer fire the rule, allowlist filters, unit tests including the DMARC regression case.
- 2026-08-31 (v1.0.0): Initial version.
