# Design decisions and limitations

## Behavior-first content

The library focuses on observable behavior and context. Tool names appear as supporting indicators because adversaries can rename tools and legitimate administrators can use the same utilities.

## Separate playbook, KQL, and Sigma artifacts

The Markdown playbook is the source of analyst intent. KQL is a deployable implementation for Microsoft data. Sigma expresses portable event logic. Keeping them separate makes each usable while allowing reviewers to compare implementation with intent.

## KQL table choices

Endpoint hunts use Defender XDR `Device*` tables because they offer consistent parent process, identity, hash, and network context. Identity and Windows audit hunts use Sentinel `SecurityEvent`/`SigninLogs`. DNS uses `_Im_Dns` so supported sources share normalized semantics.

These surfaces cannot always be joined in one portal. Companion pivots are described even when the standalone query cannot perform the join.

## Thresholds are starting points

Values are intentionally explicit. They are neither universal baselines nor vendor defaults. Tenant size, workstation/server mix, resolver architecture, automation, and retention materially change result distributions.

## Sigma portability limits

Sigma rules depend on backend field mappings and product pipelines. Aggregate behavior such as “one source failed against many accounts” may require Sigma correlation support or a SIEM-native query. In those cases, the Sigma file detects a useful event primitive while the KQL file performs the full aggregation. The difference is stated in the playbook.

## Known gaps

- Memory-only and kernel-level behavior may be invisible without suitable EDR telemetry.
- Encrypted network traffic limits payload inspection; metadata remains useful.
- Cloud, Linux, macOS, container, and OT coverage is not yet comprehensive.
- Process command lines can be truncated, absent, or manipulated.
- ATT&CK mapping explains behavior; it does not identify an actor or prove malicious intent.
- The repository validator checks structure, schema, ATT&CK facts and rule logic — not live table
  schemas in your workspace, and not detection efficacy against a real adversary.
- The Sigma engine models the specification, not any particular backend's execution. Passing tests
  mean the logic is sound; they do not replace validation in the target platform.
- KQL is linted, not executed. No public repository can execute KQL without a workspace.

## Version 2 decisions

### Unit tests over assertions

Every Sigma rule is executed against synthetic events in CI. The alternative — publishing rules that
have never been evaluated — makes false-positive guidance unverifiable. The cost is a Sigma engine
that must be maintained (standard library only, apart from PyYAML for parsing); the benefit is that a
tuning claim in a playbook is testable rather than rhetorical.

### Pinned upstream snapshots instead of live lookups

ATT&CK and Atomic Red Team data are committed as generated snapshots
(`mappings/attack-reference.json`, `validation/atomic-index.json`). CI then needs no network access,
upstream changes appear as reviewable diffs, and a renumbered technique or withdrawn test becomes a
build failure. The cost is that snapshots must be refreshed deliberately; the scripts that produce
them are in `scripts/`.

### Frontmatter as the single source of truth

Playbook frontmatter drives the README table, coverage matrix, Navigator layer, legacy-ID map and
documentation navigation. Nothing derived is hand-maintained, and `scripts/build.py --check` fails CI
if it drifts. A repository that claims twenty-five playbooks in one place and twenty in another has
already lost the reader's trust.

### SIDs instead of group names

Privileged group detection matches well-known SIDs and RIDs, not names. Group names are localised
(`Domain Admins` is `Admins du domaine` on a French installation) and renameable. Name matching fails
silently in exactly the multi-region estates that most need the detection.

### Result-code classification instead of "non-zero means failure"

Entra sign-in analytics classify result codes explicitly. Treating every non-zero `ResultType` as a
failed password both over-counts (disabled accounts, Conditional Access blocks) and hides the finding
that matters: `50074`/`50076`/`50079`/`500121` mean the password was correct and MFA stopped the
session. That is a contained credential compromise, not a failure.

### Recovery destruction separated from defence impairment

`vssadmin delete shadows` moved out of TH-014 into TH-024. ATT&CK classifies it as Impact (T1490),
its response is different (containment speed over evidence collection), and its severity is not the
same as an exclusion being added. Mixing them made one alert that meant two very different things.

## Content freshness

ATT&CK pages and Microsoft schemas are linked rather than copied. Technique mappings are pinned to the ATT&CK v19.2 snapshot in `mappings/attack-reference.json`
(collection modified 2026-08-05) and were last regenerated on 2026-09-10. Refresh with
`python3 scripts/fetch_attack_reference.py` on each ATT&CK release and review the resulting diff.
