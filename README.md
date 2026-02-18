# Custom Detection Validator

Pre-validate KQL queries for [Microsoft Defender XDR custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules) before deploying them.

Catches common issues like missing required columns, NRT eligibility problems, and unavailable response actions — before you hit "Create rule" and get a cryptic error.

## Use it now

**No install needed** — open the web version:

**[trymhaak.github.io/custom-detection-validator](https://trymhaak.github.io/custom-detection-validator/)**

Everything runs in your browser. No data is sent anywhere.

## What it checks

| Category | Rules | What it validates |
|----------|-------|-------------------|
| Table | TBL001–003 | Table recognition, classification, frequency support |
| Required Columns | RC001–007 | Timestamp, event IDs, impacted assets, project/project-away |
| Non-Supported Columns | NSC001–003 | NRT-excluded columns, preview columns, streaming API |
| NRT Eligibility | NRT001–007 | Single table, no join/union/externaldata/comments |
| Response Actions | ACT001–005 | Device, file, user, and email action availability + RBAC |
| Best Practices | BP001–005 | Timestamp filtering, ingestion_time, summarize, alert limits |

Covers 55 XDR tables, 20 NRT XDR tables, 19 NRT Sentinel tables, and table-aware action filtering across 12 product categories.

## CLI usage (optional)

If you prefer a terminal workflow:

```bash
pip install .
cdv -q "DeviceProcessEvents | where FileName == 'cmd.exe' | project Timestamp, DeviceId, ReportId"
```

Or without installing:

```bash
PYTHONPATH=src python3 -m cdv.cli -q "DeviceEvents | project Timestamp, DeviceId, ReportId"
```

Local web server:

```bash
cdv --web
```

### CLI options

| Flag | Description |
|------|-------------|
| `-q`, `--query` | KQL query string to validate |
| `-f`, `--file` | Read query from file |
| `--json` | Output results as JSON |
| `--web` | Start local web GUI |
| `--port` | Port for web server (default: 8471) |
| `--no-color` | Disable terminal colors |

## Requirements

- Python 3.9+ (CLI only)
- Zero external dependencies — stdlib only

## License

MIT
