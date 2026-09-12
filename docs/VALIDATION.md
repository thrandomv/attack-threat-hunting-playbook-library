# Validation strategy

## Safety boundary

Validate only in an isolated lab or an explicitly authorized test scope. Prefer benign simulations that produce the expected telemetry without extracting credentials, evading controls, contacting external infrastructure, or accessing real sensitive data.

## Five-layer validation

1. **Static content:** file naming, frontmatter schema, ATT&CK facts checked against the pinned MITRE
   snapshot, Atomic GUIDs checked against the pinned upstream index, link integrity.
   (`scripts/validate.py`)
2. **Rule logic:** every Sigma rule executed against synthetic true-positive and false-positive
   events, offline, in CI. (`scripts/run_tests.py` — see [TESTING.md](TESTING.md))
3. **Schema:** referenced tables and fields exist in the intended workspace; Sigma conversion produces
   the intended target fields. (local, per environment)
4. **Telemetry:** an approved test action reaches the sensor, connector, parser, and query with
   acceptable latency.
5. **Analytic behaviour:** expected positive matches, the known-good case does not, enrichment is
   correct, and the analyst workflow is usable.

Layers 1 and 2 run in this repository and prove the content is internally sound. Layers 3 to 5 can
only run in your environment and are what prove it *works*. Nothing in CI substitutes for them.

## Test case format

| Field | Description |
|---|---|
| Test ID | Stable identifier linked to playbook |
| Objective | Behavior and analytic branch being validated |
| Authorization | Owner, scope, date/time, and change record |
| Preconditions | Host, user, sensor, audit policy, expected table |
| Action | Safe test or replayed synthetic event |
| Expected telemetry | Event IDs/tables, required fields, and latency |
| Expected analytic result | Match count and key entity values |
| Negative control | Similar approved behavior that should not match |
| Cleanup | Files, tasks, accounts, or settings to remove/restore |
| Result | Pass, fail, inconclusive, evidence link, and defects |

## Safe validation examples

- Use built-in, approved administrative actions on a disposable Windows lab host to exercise process, task, service, RDP, WinRM, and account-management telemetry.
- Use synthetic DNS events or an internal test domain to validate long-label and high-volume features. Do not operate a covert tunnel.
- Use failed sign-ins against dedicated test accounts within lockout and authorization controls to validate password-spray aggregation.
- Create harmless text archives in a temporary lab directory to validate archive-tool telemetry; do not stage sensitive files.
- Use signed internal test binaries or harmless scripts to validate parent/child relationships.
- Replay sanitized, schema-correct JSON into a non-production test table when endpoint behavior is unsafe or hard to reproduce.

## Regression cases

For every tuned rule, retain:

- one minimal positive;
- one positive for each important logic branch;
- one common benign case;
- one case matching every allowlist;
- one missing-field case;
- one high-volume case for performance;
- the incident pattern that originally motivated the detection, when sanitized data is legally retainable.

## Failure diagnosis

If a test does not alert, check in order:

1. Did the endpoint or identity provider generate the event?
2. Did the sensor record the required fields?
3. Did the connector ingest it into the expected table?
4. Did normalization preserve the semantics?
5. Did time zone, lookback, or ingestion delay exclude it?
6. Did a filter, threshold, or allowlist suppress it?
7. Did scheduled-rule grouping or suppression hide the alert?
8. Did automation close or merge it?

Record telemetry failures separately from analytic failures.

## Repository validation

Run:

```text
make check        # everything CI runs
make validate     # structural, schema, ATT&CK and Atomic validation
make test         # Sigma unit tests
make selftest     # the evaluation engine's own tests
make build-check  # generated artefacts are in sync
```

`scripts/validate.py` confirms frontmatter schema, ID and filename consistency, required sections,
ATT&CK technique/tactic/detection-strategy correctness against the pinned MITRE snapshot, Atomic Red
Team GUID existence, Sigma field and UUID hygiene, tag-to-frontmatter consistency, KQL lint rules,
fixture coverage, link integrity, and the absence of personal contact details. It does not compile
KQL against a live workspace and does not prove detection efficacy — use platform-native tooling and
the Atomic tests for that.
