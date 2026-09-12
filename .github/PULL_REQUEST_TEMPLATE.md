## Summary

What defensive behaviour does this change address, and why?

## Type of change

- [ ] New playbook
- [ ] Detection logic change (rule or query)
- [ ] False-positive fix
- [ ] Tooling or documentation
- [ ] Upstream snapshot refresh (ATT&CK / Atomic Red Team)

## Validation

- [ ] `make check` passes (`selftest`, `test`, `validate`, `build-check`).
- [ ] New or changed rules have **both** a true-positive and a false-positive test case.
- [ ] A false-positive fix added a permanent negative test case rather than only loosening the rule.
- [ ] ATT&CK mapping reviewed against the pinned snapshot; detection strategy is genuinely linked to
      the technique.
- [ ] Atomic Red Team GUIDs verified.
- [ ] KQL ran in the stated surface, or the limitation is documented.
- [ ] Sigma conversion checked for the intended backend (note if correlations do not survive).
- [ ] Generated artefacts regenerated (`python3 scripts/build.py`).

## Operational impact

Expected volume, performance cost, entity mappings, response owner, rollback plan, and any audit
policy or sensor change the content depends on.

## Blind spots

What does this detection still miss? If the answer is "nothing", reconsider.

## Privacy

- [ ] No secrets, tokens, private telemetry, customer or employer data, or real personal identifiers.
