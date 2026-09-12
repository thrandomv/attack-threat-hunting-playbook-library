# Defensive lab guide

## Goal

Build a small, disposable environment where telemetry and detection behavior can be observed without touching production data. The lab is for detection validation, not exploitation practice.

## Suggested topology

- one identity/domain service when Windows domain events are required;
- one Windows client and one Windows server;
- one Linux web server for web-shell parent/child telemetry if relevant;
- an endpoint sensor or Sysmon on test hosts;
- Windows event forwarding or an agent to a non-production SIEM workspace;
- a DNS resolver whose test logs can be collected;
- dedicated, non-privileged test users plus one carefully controlled administrative test account;
- snapshots or infrastructure automation for reliable reset.

Keep the network isolated from sensitive environments. Use internal-only names and RFC 5737 example addresses in documentation and screenshots.

## Build checklist

1. Record host names, roles, time synchronization, and sensor versions.
2. Configure required Windows audit policy and, where needed, object SACLs.
3. Enable PowerShell Script Block Logging in the lab according to organizational policy.
4. Install and configure endpoint monitoring; document exclusions.
5. Connect logs to a dedicated workspace and confirm field completeness.
6. Create a baseline by operating the systems normally.
7. Snapshot before each test batch.
8. Execute only approved benign test cases from the playbooks.
9. Export query screenshots or event identifiers without secrets.
10. Revert, confirm cleanup, and compare results with expected evidence.

## Evidence notebook

For portfolio-quality demonstrations, capture:

- architecture diagram and data flow;
- audit/sensor configuration summary;
- hypothesis and expected ATT&CK behavior;
- data-quality result before the test;
- sanitized raw event showing key fields;
- KQL result and Sigma conversion result;
- triage narrative, benign alternative, and limitations;
- tuning decision and regression result;
- cleanup confirmation.

Do not publish real tenant IDs, public IPs, user principal names, hostnames, tokens, or production screenshots.

## Reset and cleanup

Use snapshots where possible. Otherwise remove temporary tasks, services, test users/groups, archives, scripts, and DNS records; restore audit or security settings; rotate any test credentials exposed to logs; and verify that no listener, tunnel, scheduled job, or persistence remains.
