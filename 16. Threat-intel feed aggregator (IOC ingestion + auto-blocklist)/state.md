# Application State - Threat-Intel Feed Aggregator

## Current State

### Loaded Feeds
- **OTX AlienVault**: Active, 250 IOCs, last sync 2024-01-15
- **URLhaus**: Active, 180 IOCs, last sync 2024-01-15
- **MISP Instance**: Active, 320 IOCs, last sync 2024-01-15
- **Custom CSV**: Active, 100 IOCs, last sync 2024-01-15
- **Manual Import**: Active, 45 IOCs, last sync 2024-01-15

### IOC Database
| Type | Count | Confidence Avg |
|------|-------|----------------|
| IPv4 | 245 | 72.5 |
| Domain | 312 | 68.3 |
| URL | 156 | 71.2 |
| SHA256 | 89 | 78.4 |
| MD5 | 67 | 65.1 |
| SHA1 | 34 | 70.2 |
| Email | 22 | 55.8 |
| **Total** | **925** | **70.1** |

### Confidence Distribution
- Critical (90-100): 45 IOCs
- High (70-89): 312 IOCs
- Medium (50-69): 423 IOCs
- Low (30-49): 112 IOCs
- Info (0-29): 33 IOCs

### Blocklist Generation
- Palo Alto EDL: Last generated 2024-01-15
- FortiGate EBL: Last generated 2024-01-15
- Nginx deny.conf: Last generated 2024-01-15
- iptables: Last generated 2024-01-15
- DNS RPZ: Last generated 2024-01-15
- Plain Text: Last generated 2024-01-15

### Source Health
| Source | Status | Uptime | Last Error |
|--------|--------|--------|------------|
| OTX AlienVault | Healthy | 99.9% | None |
| URLhaus | Healthy | 99.5% | None |
| MISP Instance | Healthy | 98.8% | Timeout 2024-01-14 |
| Custom CSV | Healthy | 100% | None |

### Recent Activity
- 2024-01-15 10:30:00 - Imported 15 new IOCs from OTX
- 2024-01-15 10:25:00 - Generated Palo Alto EDL (250 entries)
- 2024-01-15 10:20:00 - Updated confidence scores for 89 IOCs
- 2024-01-15 10:15:00 - Detected 12 new high-confidence IOCs

### User Preferences
- Default blocklist format: Palo Alto EDL
- Confidence threshold for auto-block: 70
- Export format: JSON
- Dark mode: Disabled
- Auto-refresh feeds: Enabled (60 min interval)

## State Transitions

### Feed Synchronization States
```
IDLE -> SYNCING -> SUCCESS -> IDLE
IDLE -> SYNCING -> ERROR -> RETRYING -> SYNCING
IDLE -> SYNCING -> ERROR -> IDLE (manual abort)
```

### IOC Processing Pipeline
```
INGEST -> NORMALIZE -> DEDUPLICATE -> ENRICH -> SCORE -> STORE
```

### Blocklist Generation Pipeline
```
SELECT FORMAT -> FILTER IOCs -> VALIDATE -> GENERATE -> EXPORT
```

## Persistent State

### Configuration File (config.json)
- Feed configurations
- User preferences
- API keys (encrypted)
- Export settings

### Database Schema (SQLite)
- `iocs` - IOC records
- `feeds` - Feed configurations
- `sync_logs` - Synchronization history
- `blocklist_history` - Generated blocklists

### Cache
- Feed response cache (TTL: 1 hour)
- Enrichment cache (TTL: 24 hours)
- Confidence score cache (TTL: 1 hour)
