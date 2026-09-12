# Portfolio walkthrough

How to present this project honestly in a SOC, detection-engineering, or CTI interview. The goal is
not to claim more than the repository does — it is to show that you know exactly what it proves and
what it does not.

## The ninety-second version

> It is a library of 25 ATT&CK v19.2 threat hunts with KQL and Sigma. What makes it different from
> the usual public rule dump is that the detection content is tested: every Sigma rule ships with
> synthetic events asserting that it fires on the technique and stays quiet on the benign lookalike,
> and that suite runs in CI using a Sigma evaluation engine I wrote, with no SIEM involved. The ATT&CK
> and Atomic Red Team references are validated against pinned snapshots of the upstream data, so a
> renumbered technique or a withdrawn test is a build failure. And every coverage artefact is
> generated from playbook frontmatter, so the documentation cannot drift from the content.
>
> The part I would point at first is the v2 changelog. It lists the detection bugs I found in my own
> v1 — KQL term-matching that did not mean what it read as, an Entra result-code classification that
> hid confirmed credential compromises, a DNS rule that fired on every DMARC lookup. Each one is now a
> permanent regression test.

That last paragraph is what separates a portfolio project from a portfolio. Anyone can publish
content; fewer people can show the review that found their own mistakes.

## Ten-minute demonstration

Run it in this order. Each step answers a question an interviewer is actually going to ask.

1. **`make check`** — runs the engine self-test (42 checks), the rule suite (158 cases), validation
   (4,600+ assertions), and the generated-artefact freshness check. Start here: it shows the content
   is verifiable, not just written.
2. **`tests/rules/TH-018-password-spraying.yml`** — open it and read the negative cases. `50057`
   (account disabled) and `53003` (Conditional Access block) must not count as failed passwords.
   Explain why: counting them inflates spray detections in any tenant with disabled accounts, and it
   hides the finding that matters — `50074`/`50076` mean the password was **correct** and MFA stopped
   the session. That is a contained credential compromise, not a failure.
3. **`rules/sigma/TH-013-account-group-manipulation.yml`** — SID-based group matching. Then open the
   French-locale test case: `TargetUserName` is `Admins du domaine` and only the SID identifies it as
   Domain Admins. A name-based rule fails silently in exactly the multi-region estates that need it.
   This is a good moment to mention that you work in a Francophone environment.
4. **`playbooks/TH-021-adcs-certificate-abuse.md`** — show the ATT&CK alignment table (DET0240 /
   AN0671) and the tunable-parameter table mapping ATT&CK's own mutable elements to concrete knobs in
   the query. Then show the "Limitations and blind spots" section. The willingness to document what a
   detection misses is the signal.
5. **`scripts/sigma_eval.py`** — explain what it implements and, more importantly, what it refuses to
   implement: unsupported modifiers raise instead of passing. Mention that it caught a real bug —
   `2 of (encoding, cradle, in_memory, hidden)` in TH-009 is not valid Sigma syntax.
6. **`mappings/legacy-technique-ids.md`** — generated from the MITRE STIX bundle. Use it to explain
   the ATT&CK v19 restructure: Defense Evasion split into Stealth (TA0005) and Defense Impairment
   (TA0112), `T1562.001` → `T1685`, `T1070.001` → `T1685.005`. This is current enough that most
   interviewers will not have absorbed it yet.
7. **The Navigator layer** — and immediately say that score reflects the playbook's declared
   severity, not detection confidence, and that `mappings/attack-coverage.md` has a "Deliberate gaps"
   section naming the tactics the library does not claim.

## Questions you should expect

### Why both KQL and Sigma?

KQL is where aggregation, joins and normalised ASIM data actually work, so the hunts that depend on
breadth or fan-out live there. Sigma is portable event logic that converts to other backends. They are
not equivalent: a single Sigma event rule is often a primitive, which is why the aggregate analytics
are written as Sigma correlation rules and the playbook states explicitly when a backend cannot
express one.

### How do you know any of this works?

Five layers, and I am clear about which two the repository can prove. Structural and ATT&CK
validation, and rule-logic unit tests, run in CI — they prove the content is internally sound. Schema
validation, telemetry-path validation and analytic behaviour can only happen in a real environment,
and that is what the Atomic Red Team mapping is for. Passing tests move a rule from "asserted" to
"evaluated". They do not make it effective.

### How do you control false positives?

I baseline by account, host role, parent/child pair, signer, normalised command pattern, network zone
and time of day, then exclude only activity that is attributable, stable, and bounded by at least two
attributes — with an owner and a review date. Pre-filter counts stay visible so allowlisted activity
remains observable. And when a false positive is found, the fix is a permanent negative test case, not
just a looser rule.

### Why is nothing marked `production`?

Because that status is earned in one environment against its own baseline, with an owner and a review
cadence. Shipping content labelled production-ready from a public repository would be claiming
something I cannot know.

### What would you do next?

Native Splunk SPL, Elastic ES|QL and QRadar AQL surfaces — Sigma conversion is not the same as a
well-written native query, especially for the aggregation-heavy hunts. Then container and ESXi
coverage, since ATT&CK v19 already publishes ESXi analytics for several techniques the library
covers. `docs/ROADMAP.md` also lists what I decided *not* to build and why.

### What is the weakest part?

KQL is linted, not executed — no public repository can run KQL without a workspace and data. The
synthetic test events are shaped by my assumptions about telemetry, so they test logic rather than
real-world messiness. And the Sigma engine models the specification, not any particular backend's
execution. All three are documented in `docs/DESIGN_DECISIONS.md` under known limitations.

## What to show as evidence

- terminal output of `make check`;
- one playbook open at its blind-spots section;
- a test fixture, with the negative case explained;
- the generated coverage matrix next to the Navigator layer;
- a short lab note: one Atomic test executed, the telemetry observed, and the gap it revealed.

Never use employer, customer, or production telemetry in a public portfolio — and say so when you show
the repository. The absence of real data is itself a professional signal.
