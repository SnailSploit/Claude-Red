# Security Policy

`skills-red` is an offensive security tooling library. Its content describes attack methodologies for use by authorized red team operators, penetration testers, and security researchers.

## Intended Use

These skills are intended for:

- Authorized penetration testing engagements with documented scope and rules of engagement
- Bug bounty programs with explicit written permission for the techniques described
- CTF competitions and security training environments
- Independent vulnerability research with responsible disclosure

These skills are **not** intended for unauthorized access to systems you do not own or do not have explicit, written permission to test. Misuse may violate computer-misuse laws in your jurisdiction (CFAA in the US, Computer Misuse Act in the UK, equivalent statutes elsewhere).

## Reporting a Vulnerability in skills-red Itself

If you discover a security issue in this repository — for example a malicious payload accidentally committed, a credential leaked in an example, a typosquat-prone install path, or an unsafe shell command in `install.sh` — please report it privately rather than opening a public issue.

**Contact:** security@snailsploit.com

Please include:

- Affected file(s) and commit hash
- A description of the issue and its impact
- Reproduction steps if applicable
- Any suggested remediation

We aim to acknowledge reports within 72 hours and resolve confirmed issues within 14 days.

## Reporting a Vulnerability Found Using This Library

If you discover a vulnerability in a third-party product or service while using `skills-red`'s methodologies, follow that vendor's responsible disclosure process. The [`offensive-reporting`](Skills/utility/offensive-reporting/SKILL.md) skill includes guidance on responsible disclosure, evidence handling, and report writing.

If the vendor has no published security contact:

- Try `security@<vendor-domain>`, then their PSIRT page, then `report` mailing addresses
- For ICS/OT vendors, escalate via [CISA ICS-CERT](https://www.cisa.gov/uscert/ics)
- For broad-impact bugs, request a CVE via [MITRE CNAs](https://www.cve.org/PartnerInformation/ListofPartners)
- Allow at least 90 days before public disclosure unless the vulnerability is being actively exploited

## Supply Chain Integrity

This repository is signed by SnailSploit. Verify commit signatures with:

```bash
git log --show-signature
```

If you receive a `skills-red` archive from a third party (mirror, pastebin, package manager), verify it against the upstream repository before using.

## Scope

| In scope | Out of scope |
|---|---|
| Issues in repository content (skills, scripts, install logic) | Vulnerabilities in third-party tools mentioned in skills |
| Malicious payloads in examples | The Claude platform itself (report to Anthropic) |
| Unsafe installation defaults | Bugs in tools you find using this library |
| Leaked credentials in example traffic | Bugs in your own implementation of techniques described |

## Acknowledgements

We credit researchers who report security issues responsibly in the project [CHANGELOG](CHANGELOG.md). Let us know if you'd prefer to remain anonymous.
