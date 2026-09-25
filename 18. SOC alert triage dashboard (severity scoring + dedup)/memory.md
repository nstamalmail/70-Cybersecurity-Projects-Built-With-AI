# SOC Alert Triage Dashboard - Technical Memory

## Severity Scoring Algorithm

### Base Severity Mapping (Source-reported → Numeric Score)
| Severity | Score |
|----------|-------|
| Critical | 4     |
| High     | 3     |
| Medium   | 2     |
| Low      | 1     |
| Info     | 0     |

### Recalibration Formula
```
calibrated_score = base_score * source_reliability * cti_multiplier * dedup_factor
```

Where:
- **source_reliability**: Factor (0.5–1.5) based on source trust level:
  - EDR (CrowdStrike, SentinelOne, Defender): 1.3
  - SIEM (Splunk): 1.2
  - Vulnerability Scanner (Qualys, Nessus): 1.1
  - Firewall (Palo Alto): 1.2
  - HIDS (OSSEC): 1.0
  - Unknown: 0.8

- **cti_multiplier**: Factor (1.0–2.0) based on CTI enrichment:
  - If IOC matches known campaign: 1.5
  - If IOC matches known threat actor: 1.8
  - If CVE with CVSS >= 9.0: 1.4
  - If IOC is malicious (no campaign): 1.2
  - If IOC is suspicious: 1.1
  - If no CTI match: 1.0

- **dedup_factor**: Factor (0.5–1.0) for deduplicated alerts:
  - Primary alert in group: 1.0
  - Duplicate in group: 0.5 + (0.5 / group_size)
  - Each additional duplicate reduces by 10%

### Calibrated Score → Final Severity
```
if score >= 3.5: Critical
elif score >= 2.5: High
elif score >= 1.5: Medium
elif score >= 0.5: Low
else: Info
```

### Promotion/Demotion Tracking
- **Promotion**: calibrated_severity > original_severity
- **Demotion**: calibrated_severity < original_severity
- Stored in alert metadata: `calibrated_severity`, `severity_change`

## Deduplication Logic

### Alert Normalization Pipeline
1. **Normalize title**: lowercase, strip whitespace, remove timestamps/IDs
2. **Normalize entities**: sort, deduplicate
3. **Fingerprint generation**: SHA256 of (normalized_title + sorted_entities + source_category)

### Grouping Algorithm
```python
def generate_group_key(alert):
    title_norm = re.sub(r'[\d\-:T]+Z?', '', alert['title'].lower().strip())
    entities_sorted = '|'.join(sorted(alert['entities']))
    return sha256(f"{title_norm}:{entities_sorted}")
```

### Dedup Statistics
- **Total alerts**: Count of all loaded alerts
- **Unique groups**: Count of distinct group_ids
- **Dedup ratio**: (total - unique_groups) / total * 100
- **Top patterns**: Most frequent alert title patterns (after normalization)

## Alert Normalization

### Standard Fields
Every alert, regardless of source, is normalized to:
```python
{
    "id": str,              # Original or generated ID
    "timestamp": ISO8601,   # Standardized timestamp
    "source": str,          # Originating system
    "severity": str,        # Critical/High/Medium/Low/Info
    "title": str,           # Alert title/description
    "description": str,     # Extended description
    "entities": list[str],  # IPs, hosts, users, files
    "ioc_matches": list[str],  # Matched IOCs (typed prefix)
    "status": str,          # New/Triage/Assigned/Escalated/Resolved/Suppressed
    "group_id": str,        # Dedup group membership
    "calibrated_severity": str,  # After scoring
    "severity_change": str,      # Promoted/Demoted/Unchanged
    "triage_notes": str,    # Analyst notes
    "assigned_to": str,     # Assigned analyst
    "created_at": ISO8601,  # When loaded into dashboard
    "updated_at": ISO8601   # Last modification time
}
```

### Source Normalization
- Microsoft Defender → source: "Microsoft Defender", category: "EDR"
- CrowdStrike → source: "CrowdStrike", category: "EDR"
- SentinelOne → source: "SentinelOne", category: "EDR"
- Splunk → source: "Splunk", category: "SIEM"
- Palo Alto FW → source: "Palo Alto FW", category: "Firewall"
- OSSEC → source: "OSSEC", category: "HIDS"
- Qualys → source: "Qualys", category: "VulnScanner"
- Nessus → source: "Nessus", category: "VulnScanner"

## Export Formats

### JSON Export
Full alert objects with all metadata, suitable for import into other tools.

### CSV Export
Flattened columns: id, timestamp, source, severity, calibrated_severity, title, status, group_id, assigned_to, triage_notes.

### HTML Export
Formatted report with summary statistics, severity breakdown, and alert table.

### PDF Export
Uses HTML template rendered to PDF (via QPrinter in Qt).

## Suppression Rules

### Rule Matching
1. Rules evaluated against all alerts on load and on import
2. Each rule has conditions (source, title_contains, severity, entity_contains)
3. Matching alerts are suppressed (status = Suppressed)
4. Rules can override severity
5. Rules can have expiry (hours)

### Rule Actions
- **suppress**: Set status to Suppressed, severity to override
- **escalate**: Set severity to override value
- **assign**: Auto-assign to analyst
