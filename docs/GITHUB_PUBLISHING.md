# GitHub publishing checklist

## Repository settings

- **Name**: `attack-threat-hunting-playbook-library`
- **Description**: `25 ATT&CK v19.2 threat-hunting playbooks with KQL and Sigma, unit-tested detection logic, and purple-team validation mapping.`
- **Topics**: `threat-hunting`, `detection-engineering`, `mitre-attack`, `sigma`, `sigma-rules`, `kql`,
  `microsoft-sentinel`, `defender-xdr`, `soc`, `blue-team`, `purple-team`, `detection-as-code`,
  `incident-response`, `atomic-red-team`
- **License**: MIT (already present)
- **Visibility**: public only after the privacy review below
- **Branch protection** on `main`: require the CI check, require a pull request, require conversation
  resolution
- **Enable**: private vulnerability reporting, Dependabot alerts, secret scanning
- **Pages**: Settings → Pages → Source: *GitHub Actions* (the `pages.yml` workflow publishes the
  MkDocs site)

## Before the first push

1. **Replace the placeholder owner.** Several files assume the GitHub owner `thrandomv`. If your
   account differs, update: the badge URLs in `README.md`, `repo_url` in `mkdocs.yml`,
   `repository-code` in `CITATION.cff`, and `.github/CODEOWNERS`.
   ```bash
   grep -rn "thrandomv" --include="*.md" --include="*.yml" --include="*.cff" .
   ```
2. **Run the full check.**
   ```bash
   pip install -r requirements-dev.txt
   make check
   ```
   All four gates must pass: engine self-test, rule suite, validation, generated-artefact freshness.
3. **Privacy sweep.** `scripts/validate.py` already fails on telephone numbers and personal email
   addresses in markdown, but sweep manually too:
   ```bash
   grep -rniE "(@gmail|@outlook|\+212|\+33|\+1[0-9]{10})" . --exclude-dir=.git
   grep -rnE "([0-9]{1,3}\.){3}[0-9]{1,3}" queries rules tests playbooks | grep -vE "(10\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1|0\.0\.0\.0)"
   ```
   Every example address in this repository is RFC 5737 documentation space (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918 private space, and every domain is
   `contoso.local` / `contoso.com`. Keep it that way.
4. **Confirm no employer content.** No client names, no QRadar/FortiSIEM/LogRhythm rule exports, no
   internal hostnames, no tenant IDs, no real SIDs, no sanitised-but-recognisable incident detail.
   A portfolio that leaks an employer's detection logic is a liability, not a credential.
5. **Check the ATT&CK snapshot is current.** `mappings/attack-reference.json` records the ATT&CK
   version and collection date. If a newer release exists, run `make refresh` and review the diff
   before publishing.
6. **Import the Navigator layer** at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
   and confirm it renders.
7. **Read one playbook end to end as a stranger would.** If any section assumes knowledge you have and
   a reader does not, fix it.

## Publishing

```bash
git init
git add .
git commit -m "ATT&CK Threat Hunting Playbook Library v2.0.0"
git branch -M main
git remote add origin git@github.com:<you>/attack-threat-hunting-playbook-library.git
git push -u origin main

git tag -a v2.0.0 -m "v2.0.0"
git push origin v2.0.0     # triggers the release workflow: validates, then attaches the archive
```

Then:

1. Confirm the **CI** workflow passes. A red badge on the front page undoes the impression the
   repository is trying to make.
2. Confirm the **Documentation site** workflow publishes, and add the Pages URL to the repository
   description.
3. Confirm the **Release** workflow attached `dist/*.zip` and its `.sha256`.
4. Add the topics and description.

## After publishing

Worth adding once the URL is known:

- the real Actions badge (already wired to `ci.yml` — verify it resolves);
- a link to the Pages site in the repository description;
- one Navigator screenshot, checked for identifiers before upload;
- a short lab write-up: one Atomic test run, the telemetry observed, the gap it exposed. That single
  artefact does more for credibility than ten more rules.

Avoid badge walls, "production-ready" claims, and coverage percentages. The repository's argument is
that it tests what it claims — adding unverifiable claims on top works against it.

## Keeping it alive

| Cadence | Action |
|---|---|
| Each ATT&CK release | `make refresh`, review the diff, update affected playbooks and the changelog |
| Monthly | Dependabot pull requests; re-run `make check` |
| Quarterly | Re-read the tuning notes: are the defaults still defensible? |
| When you find a false positive anywhere | Add the negative test case here too |

A repository with a thoughtful commit history over six months reads very differently from one pushed
complete in a single commit. Small, explained changes are part of the portfolio.
