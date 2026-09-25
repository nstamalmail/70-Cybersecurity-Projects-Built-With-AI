# Technical Memory

## CIS Benchmark Structure

### Standard Format
CIS Benchmarks follow a hierarchical structure:
```
Section 1 - Section 1.1 - Control 1.1.1
Section 2 - Section 2.1 - Control 2.1.1
...
```

### Control Object Model
```yaml
control:
  id: "1.1.1"           # Unique control identifier
  title: "Ensure X"     # Human-readable title
  description: "..."    # Full description
  section: "1.1"        # Parent section
  severity: "medium"    # Critical/High/Medium/Low
  status: "manual"      # manual|automated
  check:
    type: "registry"    # registry|command|auditpol|service
    command: "reg query ..."
    expected: "value"
  fix:
    type: "powershell"  # powershell|bash|gpo
    command: "reg add ..."
  references:
    - url: "https://..."
    - nist: "SI-1.1"
```

## Benchmark Variants

| Benchmark | Controls | Target |
|-----------|----------|--------|
| CIS Windows 11 v3.0 | 200+ | Workstation |
| CIS Windows Server 2022 v2.0 | 300+ | Server |
| CIS Ubuntu 22.04 LTS v1.0 | 250+ | Linux Desktop/Server |
| CIS RHEL 9 v1.0 | 200+ | Enterprise Linux |

## Scoring Algorithm

### Per-Control Scoring
```
For each control:
  if actual_value matches expected_value:
    score = 100
  else:
    score = 0
```

### Overall Compliance Score
```
compliance_score = (sum(passed_controls) / total_controls) * 100
```

### Category Score
```
category_score = (category_passed / category_total) * 100
```

### Weighted Scoring (Enterprise)
```
weights = {
  "Identity": 0.20,
  "Audit Policy": 0.15,
  "Firewall": 0.15,
  "Windows Update": 0.10,
  "Account Policies": 0.15,
  "Security Options": 0.10,
  "Remote Access": 0.10,
  "Logging": 0.05
}
weighted_score = sum(category_score * weight for each category)
```

## OVAL Evaluation (Open Vulnerability Assessment Language)

### Structure
```xml
<oval_definitions>
  <definitions>
    <definition id="..." class="compliance">
      <metadata>
        <title>Ensure X</title>
      </metadata>
    </definition>
  </definitions>
  <tests>
    <registry_test id="..." check="at least one">
      <object object_ref="..."/>
      <state state_ref="..."/>
    </registry_test>
  </tests>
  <objects>
    <registry_object id="..." hive="HKEY_LOCAL_MACHINE" key="..." name="..."/>
  </objects>
  <states>
    <registry_state id="..." operator="equals">
      <value>1</value>
    </registry_state>
  </states>
</oval_definitions>
```

### Evaluation Logic
1. Collect OVAL definitions for target platform
2. Execute tests against system state
3. Compare actual vs expected values
4. Generate compliance results
5. Calculate scores per control/category

## Check Command Categories

### Windows Commands
| Type | Example | Purpose |
|------|---------|---------|
| Registry | `reg query HKLM\...\Key` | Check configuration values |
| Security Policy | `secedit /export /cfg` | Export security settings |
| Audit Policy | `auditpol /get /subcategory` | Check audit settings |
| Service | `sc query ServiceName` | Check service status |
| Net | `net accounts` | Check account policies |
| PowerShell | `Get-MpPreference` | Modern config checks |

### Linux Commands
| Type | Example | Purpose |
|------|---------|---------|
| File | `cat /etc/config` | Check file contents |
| Service | `systemctl status service` | Check service status |
| Package | `dpkg -l package` | Check installed packages |
| Kernel | `sysctl kernel.param` | Check kernel parameters |
| Permissions | `stat /etc/file` | Check file permissions |

## Remediation Script Generation

### PowerShell Script Template
```powershell
#Requires -RunAsAdministrator
param([switch]$WhatIf = $true)

# For each failed control:
Write-Host "Remediating {control_id}: {title}"
if ($WhatIf) {
    Write-Host "  [WhatIf] Would execute: {command}"
} else {
    Invoke-Expression "{command}"
    # Log result
}
```

### Bash Script Template
```bash
#!/bin/bash
set -euo pipefail
LOGFILE="/var/log/cis_remediation.log"

# For each failed control:
log "Applying control {control_id}"
if $WHATIF; then echo "  [WhatIf] Would apply {control_id}"; fi
{remediation_command}
```

## Report Generation

### HTML Report Structure
1. Header with metadata (date, benchmark, system)
2. Score badge with color-coded percentage
3. Category breakdown with progress bars
4. Detailed findings table (sortable)
5. Historical trend chart
6. Remediation summary

### Data Export Formats
| Format | Content | Use Case |
|--------|---------|----------|
| HTML | Full styled report | Human review |
| JSON | Complete data structure | Integration |
| CSV | Tabular findings only | Spreadsheet analysis |
| PDF | Browser print of HTML | Formal documentation |

## Exception Management

### Exception Record
```json
{
  "control_id": "1.4.1",
  "reason": "Already handled via GPO deployment",
  "expiry": "2026-12-31",
  "approved_by": "IT Security Team"
}
```

### Exception Rules
1. Exceptions must have expiry date
2. Approved by designated authority
3. Excluded from compliance score calculation
4. Tracked in audit logs

## Historical Trend Analysis

### Data Points
- Monthly assessment snapshots (12 months)
- Score progression over time
- Pass/fail ratio changes
- Category-level trends

### Visualization
- Bar chart: Monthly scores with color coding
- Table: Detailed historical records
- Trend line: Visual score progression

## Platform Support

### Windows (Primary)
- PowerShell 5.1+ for remediation
- Registry-based configuration checks
- Group Policy analysis
- Windows Event Log integration

### Linux (Secondary)
- Bash for remediation
- File-based configuration checks
- Systemd service analysis
- Package manager integration
