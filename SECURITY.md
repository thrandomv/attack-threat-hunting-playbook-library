# Security policy

## Reporting a problem

Do not open a public issue for secrets, private telemetry, bypasses caused by a published detection, or a vulnerability in supporting automation. Use GitHub's private vulnerability reporting feature after the repository is published.

Include the affected file, impact, a minimal reproduction, and a suggested mitigation when possible. Remove tenant IDs, hostnames, usernames, tokens, and real indicators from evidence.

## Supported content

The latest release is the supported version. Detection content is reviewed on a best-effort basis and should be revalidated locally after sensor, schema, operating-system, or ATT&CK changes.

## Secrets policy

This repository must never contain API keys, access tokens, customer identifiers, raw event exports, or proprietary intelligence. Use placeholders such as `TENANT_ID`, `example.org`, and RFC 5737 test IP ranges.
