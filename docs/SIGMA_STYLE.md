# Sigma style guide

Rules follow the Sigma specification structure: `title`, `id`, `status`, `description`, `references`, `author`, dates, `tags`, `logsource`, `detection`, `falsepositives`, and `level`.

## Conventions

- One UUID remains stable for the life of a rule.
- `date` is creation; `modified` changes only with material logic or metadata changes.
- ATT&CK tags use lowercase technique identifiers, including sub-technique: `attack.t1003.001`.
- Selections describe observable events. The `condition` is readable and avoids backend-specific syntax.
- Use modifiers such as `|endswith`, `|contains`, `|startswith`, and `|all` intentionally.
- False positives name concrete administrative workflows.
- Severity reflects standalone signal confidence.

## Portability review

Before deployment, confirm:

1. the backend supports the log source and modifiers;
2. field mappings point to the intended event values;
3. lists use OR semantics unless `|all` is specified;
4. command-line case behavior matches the backend;
5. correlation or aggregation requirements survived conversion;
6. local exclusions do not overwrite the upstream rule.

Full behavior analytics may exceed a single event. When the KQL hunt aggregates entities but the Sigma rule represents an event primitive, the playbook explicitly marks that limitation.

## Correlation rules

Aggregate behaviour — "one source against many accounts", "one account to many destinations" — is
expressed with Sigma correlation rules rather than left to the SIEM. A correlation file contains one
or more named base rules plus the correlation document:

```yaml
title: Base event
name: th018_password_failure_signin      # the handle the correlation references
...
---
correlation:
  type: value_count                      # or event_count, temporal, temporal_ordered
  rules:
    - th018_password_failure_signin
  group-by: [IPAddress]
  timespan: 10m
  condition:
    field: UserPrincipalName
    gte: 10
```

Base rules used only inside a correlation are `level: informational` and say so in their description.
A base rule that alerts on its own defeats the purpose of the correlation.

Backend support for correlations varies. Where a backend cannot express one, the KQL companion
performs the aggregation and the playbook states the difference explicitly.

## Condition grammar

Conditions use only portable Sigma syntax: `and`, `or`, `not`, parentheses, and the quantifiers
`N of <pattern>`, `all of <pattern>`, `... of them`. Selection names are chosen so quantifiers work
naturally (`sig_*` for scoring signals, `filter_*` for exclusions, `selection_*` for anchors).

Two constructs are forbidden: in-condition aggregations (`| count() > 5`), which are deprecated in
favour of correlations, and explicit lists inside a quantifier (`2 of (a, b, c)`), which is not
Sigma syntax at all. The evaluation engine rejects both — it caught the second one in this
repository's own PowerShell rule during authoring.

## Every rule ships with tests

A rule is not finished until `tests/rules/<rule>.yml` proves it fires on the behaviour and stays
silent on the benign lookalike named in its `falsepositives` list. The test suite fails if any rule
document lacks either a true-positive or a false-positive case. See [TESTING.md](TESTING.md).
