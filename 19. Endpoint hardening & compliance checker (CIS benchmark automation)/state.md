# Application State Documentation

## Overview
The Endpoint Hardening & Compliance Checker is a PySide6 desktop application that evaluates system configurations against CIS Benchmarks and generates compliance reports with remediation scripts.

## Current State
- **Version**: 1.0.0
- **Status**: Ready for deployment
- **Last Updated**: 2026-09-21

## State Variables

### Assessment State
| Variable | Type | Description |
|----------|------|-------------|
| `_findings` | `list[dict]` | Current assessment findings (50+ CIS controls) |
| `_exceptions` | `list[dict]` | Approved exceptions (control_id, reason, expiry, approved_by) |
| `_history` | `list[dict]` | Historical assessment records (12 monthly entries) |
| `_benchmark` | `str` | Active benchmark name (e.g., "CIS Windows 11 v3.0") |

### UI State
| Tab | Description |
|-----|-------------|
| Dashboard | Gauge widget, pass/fail counts, category table, recent findings |
| Findings | Full findings table with filter by status/severity |
| Remediation Guide | PowerShell/Bash script generation with preview |
| History | Trend table + bar chart visualization |
| Reports | Export to HTML/JSON/CSV/PDF via file dialog |

## Assessment Flow

1. User selects benchmark from dropdown (Windows 11, Server 2022, Ubuntu 22.04, RHEL 9)
2. User selects target system (Local, Remote Windows, Remote Linux)
3. User clicks "Run Assessment" or "Load Demo Data"
4. System evaluates findings against expected values
5. Compliance score calculated: `(passed / total) * 100`
6. Dashboard gauge animates to score value
7. Category breakdown updated with per-category compliance %
8. User can export reports or generate remediation scripts

## Finding Structure

```json
{
  "finding_id": 1,
  "control_id": "1.1.1",
  "title": "Ensure password complexity requirements are enforced",
  "category": "1 - Identity and Access Management",
  "param_name": "password must meet complexity requirements",
  "expected_value": "1",
  "actual_value": "1",
  "status": "Pass|Fail",
  "severity": "Critical|High|Medium|Low|Informational",
  "check_command": "net accounts",
  "remediation": "net accounts /pwreq:8 yes",
  "description": "Control 1.1.1 check: ...",
  "benchmark": "CIS Windows 11 v3.0",
  "timestamp": "2026-09-21T00:00:00"
}
```

## History Record Structure

```json
{
  "date": "2026-01-15",
  "score": 72,
  "passed": 42,
  "failed": 16,
  "total": 58,
  "benchmark": "CIS Windows 11 v3.0",
  "host": "DESKTOP-TEST01"
}
```

## Score Color Coding
- **80-100%**: Green (#00c864) - Compliant
- **50-79%**: Amber (#ffb400) - Partially Compliant
- **0-49%**: Red (#ff3c3c) - Non-Compliant

## Severity Mapping
| Severity | Color | Usage |
|----------|-------|-------|
| Critical | #ff3c3c | Immediate risk |
| High | #ff8c00 | Significant risk |
| Medium | #ffb400 | Moderate risk |
| Low | #6ec6ff | Minimal risk |
| Informational | #888888 | Passed controls |

## Export Formats
- **HTML**: Full styled report with charts, tables, and trend data
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible tabular data
- **PDF**: HTML-based (browser print to PDF)

## Demo Data Scope
- **Total Controls**: 58 CIS benchmark findings
- **Categories**: 10 security domains
- **Historical Records**: 12 monthly snapshots
- **Exception Items**: 2 pre-configured exceptions
