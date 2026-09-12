# Deployment guide

## Choose the correct query surface

Every KQL file begins with a `Surface` comment.

- **Defender XDR advanced hunting**: files using `DeviceProcessEvents`, `DeviceFileEvents`, or `DeviceNetworkEvents`.
- **Microsoft Sentinel / Log Analytics**: files using `SecurityEvent`, `SigninLogs`, `WindowsEvent`, or `_Im_Dns`.

If Microsoft Defender data is connected to Sentinel, table access still depends on the configured integration and portal. Do not assume a query that runs in Defender automatically runs unchanged in a Log Analytics workspace.

## KQL deployment workflow

1. Copy the standalone `.kql` query into the stated portal.
2. Set the lookback and thresholds in the `let` block.
3. Run the data-quality check from the playbook.
4. Inspect unfiltered raw events for several expected benign cases.
5. Apply environment-specific exclusions after the main detection logic.
6. Preserve `Timestamp`/`TimeGenerated`, host, account, IP, process, and hash fields for entity mapping.
7. Run in hunting mode before creating a scheduled analytic.
8. For scheduled rules, align query lookback, schedule frequency, ingestion delay, and alert grouping so events are neither missed nor repeatedly alerted.

## Sigma deployment workflow

Sigma rules describe detection logic independently of a SIEM backend. They are not directly executable alerts.

1. Validate rule syntax with the Sigma tooling used by your organization.
2. Convert the rule with a backend and pipeline that match the target data model.
3. Review every field mapping. For example, `Image`, `CommandLine`, and `ParentImage` may map differently across EDR, Sysmon, and Windows event backends.
4. Compare converted logic with the playbook hypothesis; conversion warnings require review.
5. Add local filters in a separate managed layer where possible so upstream updates remain mergeable.
6. Test against a safe positive event and a representative benign event.

Example with a locally installed Sigma CLI and an appropriate backend:

```text
sigma check rules/sigma/
sigma convert -t <backend> -p <pipeline> rules/sigma/TH-010-lolbins-proxy-execution.yml
```

**Correlation rules.** Files such as `TH-003`, `TH-004`, `TH-006` and `TH-018` contain a base rule
plus one or more correlation documents. Backend support for Sigma correlations varies; check that
your conversion emits the aggregation rather than silently dropping it. If it does, deploy the KQL
companion instead — it performs the same aggregation natively — and never deploy the base rule alone
as an alert. Base rules are `level: informational` for exactly this reason.

Backend names and pipelines change; consult the installed tooling rather than copying an old command uncritically.

## Sentinel analytic settings

Recommended starting points, subject to local baselining:

| Property | Guidance |
|---|---|
| Frequency | 5–15 minutes for high-value identity/endpoint signals; longer for aggregate hunts |
| Lookback | At least frequency plus expected ingestion delay |
| Suppression | Only for understood duplicate patterns; never to hide untriaged volume |
| Grouping | Group by incident chain when host/account/destination align; avoid one giant tenant incident |
| Entity mapping | Account, Host, IP, URL/DNS, File hash, Process where supported |
| Alert details | Playbook ID, ATT&CK technique, key entity, observed count, threshold |
| Automation | Enrichment first; containment requires organizational authorization and guardrails |

## Versioning and rollback

Treat detection content like code. Record rule ID, repository version, converted query hash, owner, deployment timestamp, local exceptions, and prior version. Roll back when a change causes unacceptable noise or performance, then diagnose rather than permanently suppressing the signal.

## Post-deployment observation

For the first seven days, review daily:

- result count and alert count;
- top entities and recurring benign explanations;
- query duration and resource consumption;
- missing/late data and connector health;
- analyst disposition and time-to-triage;
- any event pattern the logic unexpectedly drops.

After stabilization, move the rule to the review cadence defined in [OPERATING_MODEL.md](OPERATING_MODEL.md).

## Before you deploy anything from this repository

```bash
make check
```

That runs the same validation CI runs: structural and ATT&CK checks, the Sigma unit-test suite, and
a generated-artefact freshness check. If it fails on a clean clone, do not deploy the content —
open an issue.

Then, per rule, in order:

1. Confirm the **required** telemetry exists using the playbook's data-quality check.
2. Run the KQL over a short lookback in hunting mode and read the raw results.
3. Run the baseline companion query at the bottom of the `.kql` file and set thresholds from *your*
   distribution.
4. Record the tuning decisions in the register described in [TUNING.md](TUNING.md).
5. Validate with the mapped Atomic Red Team tests in a lab.
6. Only then create the scheduled rule.
