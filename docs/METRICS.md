# Detection and hunting metrics

Metrics should improve decisions, not reward alert volume. Track quality, coverage, effort, and data health separately.

## Hunt metrics

| Metric | Definition | Caution |
|---|---|---|
| Hypotheses completed | Hunts reaching a documented conclusion | Count does not measure depth or value |
| Lead yield | Hunts producing at least one triageable lead | A low yield can still validate absence or a data gap |
| Detection conversion | Hunts promoted to recurring analytics | Not every valuable hunt should alert continuously |
| Telemetry-gap rate | Hunts blocked or qualified by missing data | Treat as an engineering backlog, not analyst failure |
| Time to conclusion | Analyst time from start to disposition | Segment by hunt complexity |
| Repeatability | Another analyst can reproduce result and conclusion | Requires versioned query and evidence notes |

## Detection metrics

| Metric | Formula / meaning |
|---|---|
| Precision | True malicious/policy-positive alerts ÷ alerts investigated; report benign positives separately |
| Recall proxy | Approved validation cases detected ÷ cases executed, plus known incidents detected ÷ relevant incidents |
| Mean time to triage | Alert creation to initial defensible disposition |
| Analyst minutes per alert | Active investigation effort, not elapsed queue time |
| Alert recurrence | Repeat alerts for the same behavior/entity/incident |
| Exclusion ratio | Events removed by allowlists ÷ pre-filter matches |
| Data completeness | Required fields populated and expected assets reporting |
| Rule health | Successful scheduled runs, latency, errors, and result-volume drift |

“Zero alerts” is not a success metric unless telemetry health and authorized validation demonstrate the rule can fire.

## Review dashboard fields

For each deployed analytic record:

- repository/version and local query hash;
- owner, severity, confidence, ATT&CK mapping, and response route;
- enabled date, last validation, next review, and last change;
- required connectors/tables and 24-hour data health;
- pre-filter matches, post-filter matches, alerts, incidents, dispositions, and analyst minutes;
- top included and excluded entities;
- allowlist entries with owner and expiry;
- test pass/fail and known blind spots.

## Interpreting change

An alert-volume drop can mean successful tuning, reduced adversary activity, broken ingestion, a schema change, or a new blind spot. A volume increase can mean deployment churn, an incident, duplicated ingestion, or a changed upstream product. Pair volume with data health, top-entity changes, and validation status before concluding.
