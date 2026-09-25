# Firewall Rule Auditor — Technical Memory

## Architecture Decisions

### Single-File Application
The entire application is contained in `main_app.py` (~2500 lines). This design choice was made to:
- Enable easy distribution as a single file
- Simplify PyInstaller packaging
- Allow quick modifications without navigating a package structure
- Maintain all logic in one auditable location

### Data Model
```python
@dataclass
class NormalizedRule:
    rule_id: str           # Vendor-prefixed unique ID
    vendor: str            # 'paloalto' | 'checkpoint' | 'fortinet'
    rule_number: int       # Sequential position
    name: str | None
    description: str | None
    source_zones: list[str]
    dest_zones: list[str]
    source_addresses: list[str]
    dest_addresses: list[str]
    services: list[str]
    applications: list[str]
    action: str            # 'allow' | 'deny' | 'drop'
    logging_enabled: bool
    disabled: bool
    hit_count: int | None
    raw: dict              # Original vendor data

@dataclass
class AuditFinding:
    finding_id: str
    rule_id: str
    finding_type: str      # Check identifier
    severity: str          # 'critical' | 'high' | 'medium' | 'low'
    description: str
    evidence: str
    remediation: str
    compliance_refs: list[str]
```

### Vendor Parser Architecture

Each vendor parser implements a common interface:
1. Parse raw config file (XML/CSV/CLI)
2. Extract rules with vendor-specific fields
3. Normalize to `NormalizedRule` dataclass
4. Return list of normalized rules

**Palo Alto (XML):**
- Uses `lxml.etree` for XML parsing
- Extracts from `<rulebase><security><rules>` hierarchy
- Maps zones, addresses, applications, services
- Handles `<member>` elements for multi-value fields

**Check Point (CSV):**
- Uses Python `csv` module
- Standard column mapping: rule_number, name, source, destination, service, action, track, enabled
- Handles quoted fields and multi-value services (HTTP/HTTPS)

**Fortinet (CLI):**
- Custom line-by-line parser for FortiGate CLI config format
- Parses `edit <id>` ... `next` blocks
- Extracts `set` commands for each policy field
- Maps interface names, addresses, services, actions

### Shadowing Detection Algorithm
- O(n²) pairwise comparison of rules
- Rule B is shadowed by Rule A if:
  - A appears before B
  - A's source addresses are a superset or match of B's
  - A's destination addresses are a superset or match of B's
  - A's services are a superset or match of B's
  - A's action permits traffic that B would also match
- Simplified: uses "any" matching and exact string comparison
- For production: would use IP address range analysis

### Compliance Mapping Strategy
- NIST SP 800-53: AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection)
- PCI DSS: Req 1.1 (Firewall configuration), Req 1.2 (Firewall rules)
- CIS Controls: 4.1 (Firewall rules), 4.2 (Secure network services)
- Findings mapped based on finding type and severity

### Color Scheme
| Severity | Hex Color | Usage |
|----------|-----------|-------|
| Critical | #FF4444 | Rule rows, severity badges |
| High | #FF8C00 | Rule rows, severity badges |
| Medium | #FFD700 | Rule rows, severity badges |
| Low | #4488FF | Rule rows, severity badges |
| Compliant | #44BB44 | Compliance heatmap |
| Non-compliant | #FF4444 | Compliance heatmap |

### Report Generation
- **HTML**: Jinja2 template with embedded CSS, responsive layout
- **JSON**: Direct serialization of findings and rules
- **CSV**: Flat export of findings with all fields
- All reports include: executive summary, findings detail, rule inventory

### Threading Model
- Main thread: GUI event loop (PySide6/Qt)
- Config parsing: synchronous (configs are small)
- Report generation: synchronous with progress updates
- All UI updates via Qt signal/slot mechanism

## Key Algorithms

### Best-Practice Check Execution
```
for each rule:
    for each check in CHECK_REGISTRY:
        if check.rule_matches(rule):
            emit finding with severity, evidence, remediation
```

### Compliance Score Calculation
```
score = 100 - (critical*10 + high*5 + medium*2 + low*1)
score = max(0, min(100, score))
```

### Rule Table Filtering
```
filter_text applied to: name, source, destination, service, action
severity filter: checkbox selection
vendor filter: dropdown selection
```

## File Structure
```
14. Firewall rule auditor & misconfiguration checker/
├── main_app.py              # Complete application (~2500 lines)
├── requirements.txt         # Python dependencies
├── state.md                 # This file - application state
├── memory.md                # This file - technical memory
├── build_exe.bat            # PyInstaller build script
└── sample_data/
    ├── sample_paloalto.xml  # PAN-OS config (15 rules)
    ├── sample_checkpoint.csv # Check Point rules (20 rules)
    └── sample_fortinet.conf  # FortiGate config (15 rules)
```
