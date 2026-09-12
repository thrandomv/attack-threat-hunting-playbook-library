# Tuning methodology

## Principle

Tune with evidence, not discomfort. The goal is to remove explained, stable, and attributable benign activity while preserving suspicious variation. Broad exclusions make dashboards quiet and blind spots permanent.

## Baseline dimensions

Before changing logic, summarize at least 14–30 representative days by:

- initiating and target account;
- host role, operating system, criticality, and management group;
- parent/child process pair and signer;
- normalized command-line pattern;
- source and destination network zone;
- time of day and change window;
- software publisher, hash prevalence, and first/last seen;
- DNS registered domain, query type, label length, and client;
- authentication result, application, user agent, and location.

## Safe exclusion pattern

An exclusion should have all of these properties:

1. **Specific**: at least two stable attributes, such as managed parent plus signed hash, or service account plus management subnet.
2. **Owned**: a team can confirm and revalidate the activity.
3. **Bounded**: limited to the relevant systems, command pattern, and purpose.
4. **Expiring**: includes a review or end date.
5. **Observable**: exclusion hits remain measurable.

Prefer:

```kusto
| where not(
    InitiatingProcessFileName =~ "approved-agent.exe"
    and InitiatingProcessFolderPath startswith @"C:\Program Files\ApprovedVendor\"
    and DeviceName in~ (ManagedServers)
)
```

Avoid:

```kusto
| where AccountName !contains "admin"
| where ProcessCommandLine !contains "Program Files"
```

The broad examples suppress attacker-controlled strings and entire populations.

## Threshold tuning

Static thresholds are transparent and easy to operate, but should reflect population size and normal variance. For count-based analytics:

1. calculate per-entity distributions over a representative baseline;
2. compare median, 95th, 99th percentiles, and maximum;
3. examine seasonal peaks such as patching, backup, and month-end;
4. choose an initial threshold that analysts can review;
5. retain low-and-slow visibility through longer-window hunts.

For anomaly functions, keep a minimum event floor. Very sparse series produce misleading scores. Always expose the raw count and baseline alongside the score.

## Command-line normalization

Paths, GUIDs, temporary filenames, and version numbers can make identical administrative actions look unique. Normalize only for grouping; retain the original command line in output. Useful transformations include lowercase, slash normalization, removal of repeated whitespace, and replacement of high-entropy temporary tokens with placeholders.

Do not decode or execute captured content in the query. If encoded material is evidence, export it through approved malware-analysis procedures.

## Tuning register

Record exclusions outside the query when your platform supports watchlists or reference tables.

| Field | Example |
|---|---|
| Rule | TH-005 |
| Match | service account + management subnet + approved deployment parent |
| Business reason | Endpoint software distribution |
| Evidence | Change record and 30-day baseline |
| Owner | Workplace engineering |
| Added | 2026-08-31 |
| Expires/review | 2026-11-30 |
| Residual risk | Stolen service account could reuse approved path |

Measure both pre-filter and post-filter counts. A sudden increase in excluded activity can itself be a useful signal.
