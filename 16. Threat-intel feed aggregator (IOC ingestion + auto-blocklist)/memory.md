# Technical Memory - Threat-Intel Feed Aggregator

## IOC Normalization

### IOC Types Supported
- **IPv4**: Normalized to dotted decimal (e.g., `192.168.1.1`)
- **IPv6**: Normalized to full form
- **Domain**: Lowercased, stripped of trailing dots
- **URL**: Normalized scheme, lowercased host, preserved path
- **MD5**: Lowercased, 32 hex chars
- **SHA1**: Lowercased, 40 hex chars
- **SHA256**: Lowercased, 64 hex chars
- **Email**: Lowercased, stripped of display name

### Normalization Rules
1. Strip whitespace from all values
2. Convert to lowercase
3. Validate format with regex
4. Remove duplicates by value + type combination
5. Preserve original value in `raw_value` field

## Confidence Scoring Algorithm

### Base Confidence (0-100 scale)

#### Source Reliability (0-40 points)
| Source Type | Points |
|-------------|--------|
| MISP (verified) | 40 |
| TAXII/STIX | 35 |
| OTX AlienVault | 30 |
| URLhaus | 30 |
| Custom CSV/JSON | 20 |
| Manual Import | 15 |

#### Enrichment Boost (0-30 points)
| Factor | Points |
|--------|--------|
| Seen in 3+ sources | +15 |
| Seen in 2 sources | +10 |
| Has threat type tag | +5 |
| Has malware family tag | +5 |
| Active (last 7 days) | +5 |

#### Age Decay (0-30 points)
| Age | Points |
|-----|--------|
| 0-24 hours | 30 |
| 1-7 days | 25 |
| 8-30 days | 20 |
| 31-90 days | 10 |
| 91-365 days | 5 |
| 365+ days | 0 |

### Final Confidence Formula
```
confidence = source_reliability + enrichment_boost + age_decay
confidence = max(0, min(100, confidence))
```

### Confidence Levels
- **Critical (90-100)**: Immediately actionable
- **High (70-89)**: Strong candidate for blocking
- **Medium (50-69)**: Investigate further
- **Low (30-49)**: Corroborate with other sources
- **Info (0-29)**: Reference only

## Blocklist Formats

### Palo Alto EDL (External Dynamic List)
```
# Palo Alto EDL Format
# Generated: 2024-01-15T10:30:00Z
# Total IOCs: 250
192.168.1.100
evil-domain.com
malware.exe
```

### FortiGate EBL (External Block List)
```
# FortiGate EBL Format
#IPs
192.168.1.100
#Domains
evil-domain.com
#URLs
http://malware.com/payload
```

### Nginx deny.conf
```
# Nginx Deny Configuration
# Generated: 2024-01-15
deny 192.168.1.100;
deny evil-domain.com;
```

### iptables
```
# iptables rules
# Generated: 2024-01-15
iptables -A INPUT -s 192.168.1.100 -j DROP
iptables -A OUTPUT -d 192.168.1.100 -j DROP
```

### DNS RPZ (Response Policy Zone)
```
; DNS RPZ Zone
$TTL 300
@ IN SOA ns.example.com. admin.example.com. (
    2024011501 ; Serial
    3600       ; Refresh
    600        ; Retry
    86400      ; Expire
    300        ; Minimum
)
evil-domain.com CNAME .
*.evil-domain.com CNAME .
```

### Plain Text (one per line)
```
# Blocklist
# Generated: 2024-01-15T10:30:00Z
192.168.1.100
evil-domain.com
```

## Data Structures

### IOC Record
```json
{
  "id": "uuid",
  "type": "ipv4|domain|url|md5|sha1|sha256|email",
  "value": "normalized_value",
  "raw_value": "original_value",
  "source": "feed_name",
  "confidence": 75,
  "first_seen": "2024-01-15T10:00:00Z",
  "last_seen": "2024-01-15T10:30:00Z",
  "tags": ["malware", "c2"],
  "threat_type": "malware|phishing|c2|scanner|spam",
  "malware_family": "emotet|trickbot|cobalt_strike",
  "tlp": "WHITE|GREEN|AMBER|RED"
}
```

### Feed Configuration
```json
{
  "name": "OTX AlienVault",
  "type": "otx",
  "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
  "api_key": "xxx",
  "enabled": true,
  "interval_minutes": 60,
  "last_sync": "2024-01-15T10:00:00Z",
  "ioc_types": ["ipv4", "domain", "url", "sha256"],
  "tags": ["threat-intel"]
}
```
