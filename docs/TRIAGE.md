# Analyst triage field guide

## First five minutes

1. Confirm the event is real, recent enough to act on, and not duplicated.
2. Identify the primary entities: account, host, source IP, process, destination, and time.
3. Check asset role and criticality, identity privilege, and active change records.
4. Build a short timeline: 15 minutes before through 30 minutes after the signal.
5. Decide whether immediate escalation criteria are met; do not wait for perfect certainty when privileged assets or active compromise are involved.

## Evidence hierarchy

| Evidence | Questions |
|---|---|
| Identity | Is the account expected here? Privileged? Interactive, service, or machine identity? Recent resets or MFA changes? |
| Process | What created it? Is the lineage coherent? Signed? Common in this environment? First seen? |
| Host | Server role? Internet-facing? Domain controller? Jump host? Existing alerts or vulnerabilities? |
| Network | Source zone, destination ownership, protocol, volume, periodicity, and peer prevalence? |
| File | Origin, signer, hash prevalence, reputation, creation path, alternate data streams? |
| Change | Approved ticket, deployment, troubleshooting session, backup, scan, or exercise? |
| Sequence | Does the event align with discovery, credential access, lateral movement, persistence, or exfiltration? |

## Common dispositions

- **True positive — malicious:** unauthorized activity with evidence of compromise.
- **True positive — policy violation:** behavior occurred but intent may not be malicious; still requires action.
- **Benign positive:** analytic correctly observed the behavior, which was approved and understood.
- **False positive:** implementation or field mapping did not represent the intended behavior.
- **Inconclusive:** evidence is insufficient; document what is missing.
- **Test:** authorized validation or exercise, linked to its change record.

“Expected” is not enough for closure. Record who confirmed it, why it is expected, what evidence supports the claim, and whether a scoped tuning change is warranted.

## Cross-playbook pivots

| Starting signal | Immediate pivots |
|---|---|
| Credential access | TH-004–007 lateral movement; TH-013 account changes; privileged sign-ins |
| Lateral movement | Source-host process tree; TH-001–003 credential access; TH-011–012 persistence |
| DNS tunneling | TH-009/015 execution; TH-016 transfer; process-to-DNS correlation |
| LOLBin / PowerShell | File origin, network destinations, TH-014 defense impairment, TH-011 persistence |
| Password spray | Successful sign-ins from same IP; targeted privileged users; inbox/application changes |
| Web shell | Parent web worker, new files, outbound C2, spawned shells, account changes, lateral movement |
| Data staging | Preceding discovery; destination connections; cloud uploads; deletion or log clearing |

## Escalate immediately when

- credential-dumping or replication behavior involves a domain controller;
- a privileged account authenticates from an unexpected host after failures or credential access;
- a public-facing server spawns a command shell or scripting engine;
- security controls are disabled alongside suspicious execution;
- multiple hosts show the same unexplained remote execution or C2 pattern;
- evidence suggests ongoing exfiltration, ransomware preparation, or destructive action.

Containment must follow organizational authority. Preserve volatile evidence, avoid tipping off an active adversary without a response plan, and coordinate identity, endpoint, network, and legal/privacy stakeholders as required.

## Minimum case notes

- UTC time range and query version;
- all affected entities and identifiers;
- raw event references or secure evidence location;
- observed process/network/authentication timeline;
- ATT&CK mapping as context, not attribution;
- benign checks performed and people consulted;
- disposition, confidence, impact, and rationale;
- containment or monitoring actions with approvals;
- gaps, follow-up tasks, detection changes, and owner.
