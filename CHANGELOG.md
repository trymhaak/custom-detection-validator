# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SECURITY.md` with vulnerability reporting instructions, a Maintainer section in
  the README, and this changelog.

### Fixed

- Package metadata (`pyproject.toml`, `src/cdv/__init__.py`) and the web version
  reported `0.2.0` after the v1.0.0 release. They now report `1.0.0`.
- LICENSE spells the maintainer's name Trym Håkansson.
- README: the number of covered Defender XDR tables is 61, not 55.
- README: the CLI options table now lists `--verbose` and `-v/--version`,
  documents reading the query from stdin, and notes that `-f` and `-q`
  cannot be combined.

## [1.0.0] - 2026-07-23

First stable release, tagged on commit `8839c9c` (2026-02-18).

### Added

- Python package `cdv` that pre-validates KQL queries for Microsoft Defender XDR
  custom detection rules, using only the Python standard library (Python 3.9+).
- KQL tokenizer and extractor that identify source tables, operators
  (`join`, `union`, `externaldata`, `summarize`, `project`, `project-away`,
  `extend` and others), projected and referenced columns, and comment lines.
- Table rules (TBL001–TBL003): table recognition, classification
  (Defender for Endpoint, Alert, other Defender XDR, Microsoft Sentinel, unknown)
  and Scheduled/NRT (Continuous) frequency support. Covers 61 Defender XDR
  tables, 20 NRT-capable XDR tables, 19 NRT-capable Sentinel tables, known
  Sentinel tables and custom `_CL` tables.
- Required column rules (RC001–RC007): required timestamp column, timestamp
  manipulation, event ID columns, impacted asset columns, and columns lost
  through `summarize`, `project` or `project-away`.
- Non-supported column rules (NSC001–NSC003): NRT-excluded columns, a note on
  preview-only columns in NRT mode, and EmailEvents columns that are not
  available in the Streaming API.
- NRT eligibility rules (NRT001–NRT007): single table, no `join`, no `union`,
  no `externaldata`, no comment lines, table NRT support and EmailEvents
  column exclusions.
- Response action rules (ACT001–ACT005): availability of device, file,
  user (mark as compromised; disable user / force password reset) and email
  actions based on the query output, with the least-privileged RBAC and Entra
  role for each action.
- Table-aware action filtering across 12 product categories, and
  product-specific column hints when an action is not available (MDO, MDI,
  MDA and Entra ID).
- Best practice rules (BP001–BP005): timestamp filtering, `ingestion_time()`
  suggestion, `summarize` with `arg_max()`, the 150-alerts-per-run limit, and
  EmailEvents NRT column exclusions.
- CLI `cdv` with `-q/--query`, `-f/--file`, stdin input, `--json`,
  `--no-color`, `--verbose`, `--web`, `--port` and `-v/--version`. Exit code
  `0` when all checks pass, `1` on errors and `2` on warnings or usage errors.
- Local web UI (`cdv --web`) served by the standard-library HTTP server on
  `127.0.0.1`, with a `POST /api/validate` JSON endpoint, a 1 MB request
  limit and no CORS wildcard.
- Browser-only web version in `docs/index.html`, published on GitHub Pages,
  that runs all validation in JavaScript without sending data anywhere.
- Privacy notice in both web interfaces describing how query data is handled.
- Test suite (pytest) covering the tokenizer, extractor, table rules, every
  validator, the engine and the web server.
- MIT license and README.

[Unreleased]: https://github.com/trymhaak/custom-detection-validator/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/trymhaak/custom-detection-validator/releases/tag/v1.0.0
