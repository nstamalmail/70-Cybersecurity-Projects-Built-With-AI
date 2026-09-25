# Memory - Forensic Report Generator

## Architecture Notes

### Design Decisions
- Court-ready report format with proper sections and headers
- Evidence references linking findings to physical/digital evidence
- Chain of custody with hash linking for tamper evidence
- Executive summary separate from detailed findings
- Exhibit index for physical evidence reference

### Data Model
```
ReportMeta: { title, case_number, examiner, organization, date, classification, version }
Finding: { id, title, severity, category, narrative, evidence_refs, created }
Evidence: { id, description, type, source, hash, custodian, date }
Exhibit: { number, title, description, ref }
CustodyEntry: { timestamp, eid, action, from, to, notes, hash }
```

### Report Structure (Court-Ready)
1. Title Page / Header
2. Case Information
3. Executive Summary
4. Findings (numbered, with severity/category)
5. Evidence Log
6. Exhibit Index
7. Chain of Custody
8. Examiner Statement

### Export Formats
- **JSON**: Full structured data for programmatic access
- **CSV**: Tabular format for spreadsheet analysis
- **TXT**: Plain text formatted for printing
- **HTML**: Styled web report with severity color coding

### Severity Levels
- Critical: Immediate threat to life or critical infrastructure
- High: Significant impact, requires urgent action
- Medium: Moderate impact, scheduled remediation
- Low: Minimal impact, informational
- Informational: No security impact, documentation only
