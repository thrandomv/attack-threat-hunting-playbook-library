# Authoritative references

These sources define the framework, schemas, and rule format used by the repository. ATT&CK mappings target Enterprise ATT&CK v19.2 as reviewed on 2026-08-31. Vendor and framework content changes over time; links are preferred over copied field lists.

## MITRE ATT&CK

- [Enterprise techniques](https://attack.mitre.org/techniques/)
- [Enterprise tactics](https://attack.mitre.org/tactics/enterprise/) — including Stealth (TA0005) and Defense Impairment (TA0112)
- [Detection strategies](https://attack.mitre.org/detectionstrategies/) — the DET/AN model introduced in ATT&CK v18 and used throughout this library
- [ATT&CK release notes and updates](https://attack.mitre.org/resources/updates/)
- [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) — the STIX bundle `scripts/fetch_attack_reference.py` pins
- [Data sources](https://attack.mitre.org/datasources/)
- [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [DNS](https://attack.mitre.org/techniques/T1071/004/)
- [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)

## Microsoft hunting and normalization

- [Defender XDR advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
- [DeviceProcessEvents schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [SecurityEvent table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityevent)
- [SigninLogs table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Sentinel ASIM normalization](https://learn.microsoft.com/azure/sentinel/normalization)
- [ASIM DNS schema](https://learn.microsoft.com/azure/sentinel/normalization-schema-dns)
- [ASIM parser list](https://learn.microsoft.com/azure/sentinel/normalization-parsers-list)

## Detection format

- [Sigma specification](https://sigmahq.io/sigma-specification/)
- [Sigma rule specification](https://sigmahq.io/docs/basics/rules.html)
- [Sigma correlations](https://sigmahq.io/docs/meta/correlations.html)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and [pySigma](https://github.com/SigmaHQ/pySigma)

## Validation

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — the index `scripts/fetch_atomic_index.py` pins
- [Atomic Red Team execution framework](https://github.com/redcanaryco/invoke-atomicredteam)

## Identity and Windows internals

- [Well-known security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers) — why this library matches groups by SID
- [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes) — the AADSTS result codes TH-018 classifies
- [Microsoft Entra sign-in log schema](https://learn.microsoft.com/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema)
- [Microsoft Entra audit log schema](https://learn.microsoft.com/entra/identity/monitoring-health/reference-azure-monitor-audit-log-schema)

## Local validation responsibility

Documentation confirms intended field semantics, not local availability. Connector versions, audit policy, tenant licensing, sensor configuration, normalization, and backend conversion determine what actually works. Validate every query and rule in the target environment.
