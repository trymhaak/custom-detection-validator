# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Custom Detection Validator, please report it privately by email to [trymhaak2@icloud.com](mailto:trymhaak2@icloud.com). Please do not open a public GitHub issue for security reports.

The disclosure policy that applies to reports is published at [trym.cloud/security/disclosure](https://trym.cloud/security/disclosure/).

A useful report includes:

- **Affected version or commit** — the release version or the Git commit SHA you tested against.
- **Steps to reproduce** — the exact input (for example the KQL query, CLI flags or HTTP request) and the steps needed to trigger the issue.
- **Impact** — what an attacker could achieve and under which conditions.

Reports made in good faith are welcome. Please give the maintainer a reasonable opportunity to investigate and address the issue before disclosing it publicly.

## Supported versions

Only the latest version on the default branch (`main`) is supported with security fixes. Older commits and forks are not maintained.

## Scope

This project consists of:

- the Python package `cdv` (CLI and the local web server started with `cdv --web`, which binds to `127.0.0.1`), and
- the static, browser-only web version published from `docs/` to GitHub Pages.

This project does not offer a bug bounty.
