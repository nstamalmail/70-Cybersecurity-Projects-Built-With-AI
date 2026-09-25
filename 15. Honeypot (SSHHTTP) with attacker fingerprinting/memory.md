# Technical Architecture & Memory

## HASSH Algorithm (SSH Fingerprinting)

HASSH computes a fingerprint from SSH client KEX_INIT message fields:
1. Extract kex_algorithms, server_host_key_algorithms, encryption_algorithms_client_to_server, mac_algorithms_client_to_server, compression_algorithms_client_to_server
2. Join each list with semicolons
3. Concatenate fields with semicolons
4. Compute MD5 hash of the result
5. Format as 32-character hex string

```
hassh = md5(kex_algs + ";" + server_host_key_algs + ";" + enc_algs_c2s + ";" + mac_algs_c2s + ";" + comp_algs_c2s)
```

## JA3 Algorithm (TLS Fingerprinting)

JA3 computes a fingerprint from TLS ClientHello:
1. Extract TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
2. Join each field list with hyphens
3. Concatenate all fields with commas
4. Compute MD5 hash of the result

```
ja3 = md5(TLSVersion + "," + Ciphers + "," + Extensions + "," + EllipticCurves + "," + EllipticCurvePointFormats)
```

## HTTP Fingerprinting
- Parse User-Agent, Accept, Accept-Language, Accept-Encoding headers
- Hash the normalized header set
- Track cookie patterns and header ordering

## Data Models

### Session
```json
{
  "session_id": "uuid",
  "timestamp": "ISO8601",
  "source_ip": "x.x.x.x",
  "source_port": 12345,
  "protocol": "SSH|HTTP",
  "hassh": "md5hex (SSH)",
  "ja3": "md5hex (TLS)",
  "http_fp": "sha256hex (HTTP)",
  "username": "admin",
  "password": "password123",
  "commands": ["ls", "whoami"],
  "user_agent": "...",
  "headers": {},
  "risk_score": 0-100,
  "campaign_id": "uuid"
}
```

### Campaign
```json
{
  "campaign_id": "uuid",
  "name": "Campaign Name",
  "fingerprint": "hassh or ja3",
  "source_ips": ["x.x.x.x"],
  "session_ids": ["uuid"],
  "first_seen": "ISO8601",
  "last_seen": "ISO8601",
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL"
}
```

### ThreatIntel
```json
{
  "ip": "x.x.x.x",
  "abuseipdb": {"score": 85, "reports": 42},
  "virustotal": {"score": 15, "malicious": 8},
  "greynoise": {"classification": "malicious", "noise": true}
}
```

## Risk Scoring
- Known scanner IP: +30
- HASSH matches known botnet: +40
- Repeated login failures: +20
- Suspicious commands: +25
- Known malicious IP: +35
- Base score: 10

## Color Coding
- **Red** (risk >= 70): High-risk IPs
- **Orange** (risk >= 40): Known scanners / medium risk
- **Yellow** (risk >= 20): Suspicious activity
- **Green** (risk < 20): Low risk / unknown

## Dependencies
- PySide6: GUI framework
- Standard library: hashlib, json, uuid, datetime, csv, random
