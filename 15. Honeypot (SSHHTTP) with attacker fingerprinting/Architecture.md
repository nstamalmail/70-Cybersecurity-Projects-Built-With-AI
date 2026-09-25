# Architecture: Honeypot (SSH/HTTP) with Attacker Fingerprinting — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS) with deployment to Linux VPS for live operation
**Core Capability:** Multi-protocol honeypot (SSH/HTTP) with attacker fingerprinting (HASSH, JA3, header analysis), enrichment, and report generation
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Honeypot & Attacker Fingerprinting Platform (HAFP)** is a GUI-driven desktop application for security researchers, SOC analysts, and threat intelligence teams who need to **deploy, monitor, and analyze attacker activity** from SSH and HTTP honeypots. It combines low-interaction deception with **advanced attacker fingerprinting** — HASSH for SSH client identification, JA3 for TLS clients, and HTTP header analysis for web-based attackers — to enable attribution and campaign tracking.

Honeypots are a cornerstone of proactive threat intelligence. A well-deployed SSH honeypot captures brute-force credentials, attacker commands, and downloaded payloads in real time . HTTP honeypots capture web scanner behavior, exploitation attempts, and API probing . The key differentiator of this tool is **fingerprinting**: HASSH fingerprints SSH clients based on key-exchange negotiation patterns, enabling identification of specific attack tools like Hydra, Nmap, or custom botnets . HTTP header analysis reveals distinctive patterns — MuddyWater's ETag hashes and Cobalt Strike's `C5-Bid` header are documented examples of attribution via HTTP response metadata .

The tool is designed around four principles:

1. **Fingerprint-first attribution** — beyond IP addresses, identify attacker tools and campaigns via HASSH (SSH), JA3 (TLS/HTTPS), and HTTP header signatures .
2. **Safe by design** — low-interaction honeypots that never execute attacker input on the host; all commands are parsed and answered with fake persona-scoped data .
3. **Real-time enrichment** — IP reputation lookup (AbuseIPDB, VirusTotal, GreyNoise) and geolocation enrichment .
4. **Report-ready** — structured export (JSON, CSV, STIX 2.1, HTML, PDF) with attacker fingerprints, session timelines, and MITRE ATT&CK mapping.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Honeypot  │ │ Session   │ │ Attacker  │ │ IP        │ │ Report  │ │
│  │ Control   │ │ Monitor   │ │ Fingerpr. │ │ Enrichment│ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Live      │ │ Payload   │ │ Campaign  │ │ Threat    │ │ Console │ │
│  │ Traffic   │ │ Inspector │ │ Tracker   │ │ Feed      │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Honeypot   │ │ Session    │ │ Enrichment │ │ Event Bus / Log    │ │
│  │ Controller │ │ Aggregator │ │ Pipeline   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Honeypot Core Layer                              │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ SSH Honeypot   │ │ HTTP Honeypot  │ │ Attacker Fingerprinter   │  │
│  │ (async SSH)    │ │ (Twisted/      │ │ (HASSH, JA3, Headers)    │  │
│  │                │ │  Flask)        │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Session Recorder (credentials, commands, payloads, TTY)        │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Session    │ │ Fingerprint│ │ Payload    │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `HoneypotControlView` | Start/stop SSH and HTTP honeypot listeners. Configure bind addresses, ports, SSH banner string, HTTP server signature. Display listener status. |
| `SessionMonitorView` | **Primary view.** Real-time table of honeypot sessions: timestamp, source IP, protocol, session ID, fingerprint (HASSH/JA3), credential count, payload count. Sortable, filterable. |
| `AttackerFingerprintView` | Drill-down for a selected session: HASSH fingerprint, SSH version exchange details (KEX algorithms, ciphers, MACs), HTTP headers, User-Agent, TLS JA3 (if HTTPS), unique header combinations . |
| `IpEnrichmentView` | IP reputation and geolocation: AbuseIPDB score, VirusTotal detections, GreyNoise classification, ASN, country, city. Cached results . |
| `LiveTrafficView` | Raw event stream: connection events, credential attempts, HTTP requests, payload downloads. Color-coded by event type. |
| `PayloadInspectorView` | Captured payloads (files downloaded by attackers): filename, hash, size, source URL, VirusTotal verdict, MalwareBazaar upload button . |
| `CampaignTrackerView` | Group sessions by fingerprint, IP, or payload hash to identify campaigns. Track first/last seen, session count, unique IPs. |
| `ThreatFeedView` | Export threat feeds in multiple formats: plain text IP list, STIX 2.1, MISP event, iptables rules, Nginx deny rules . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, STIX 2.1, HTML, PDF), date range, sections to include (sessions, fingerprints, credentials, payloads, enrichment). |
| `ConsoleView` | Live honeypot log: connection events, protocol errors, enrichment failures. |

**Key UI Patterns:**
- **Session-first layout**: sessions are the primary unit; fingerprint and enrichment data are attached to sessions.
- **Fingerprint badges**: HASSH hash displayed as a compact identifier; click to see full KEX details.
- **Color coding**: High-risk IPs (red), known scanners (orange), unknown (gray).
- **Click-to-pivot**: click a fingerprint → show all sessions with that fingerprint; click a payload hash → show VirusTotal results.
- **Real-time streaming**: sessions and events appear as they occur.

### 3.2 Orchestration Layer

**Honeypot Controller**
- Manages listener lifecycle: start, stop, restart.
- Binds SSH and HTTP listeners to configured ports.
- Enforces safety: no real command execution, no filesystem access .

**Session Aggregator**
- Collects session events from SSH and HTTP handlers.
- Merges related events (connection → auth → commands → payload download) into a unified session record.
- Tracks session state and duration.

**Enrichment Pipeline**
- Asynchronously enriches source IPs with reputation data.
- Caches results (24h TTL) to avoid redundant API calls.
- Gracefully degrades if APIs unavailable.

### 3.3 Honeypot Core Layer

**SSH Honeypot**

Low-interaction SSH server that emulates OpenSSH behavior without providing a real shell .

**Core behaviors:**
- **Version exchange**: Sends configurable SSH banner (e.g., `SSH-2.0-OpenSSH_8.9p1`); captures client banner .
- **KEXINIT parsing**: Records offered key-exchange algorithms, ciphers, MACs, compression .
- **Authentication**: Logs username/password attempts; logs publickey attempts (algorithm, fingerprint, signature presence) .
- **Fake shell**: Responds to commands with persona-scoped fake output; never executes real commands .
- **Session recording**: Records TTY session for replay; captures downloaded payloads (wget/curl URLs) .

**HASSH Fingerprinting**

HASSH is a method for fingerprinting SSH clients based on the algorithm lists they offer during key exchange . The HASSH value is computed from the client's KEXINIT message:

```
HASSH = MD5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
HASSHServer = MD5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms) (server side)
```

Attack tools like Hydra, Nmap's ssh-brute, and custom botnets have distinctive HASSH fingerprints, enabling tool identification even when IPs rotate .

**HTTP Honeypot**

Low-interaction HTTP server emulating a web application .

**Core behaviors:**
- **Catch-all route**: Accepts any URI, any HTTP method .
- **Request logging**: Captures source IP, method, path, query, headers, body, User-Agent .
- **Fake responses**: Returns configurable error pages, fake admin panels, or cloned site content .
- **Payload capture**: Captures uploaded files and POST bodies.

**HTTP Header Fingerprinting**

HTTP headers reveal attacker tooling and intent :
- **User-Agent analysis**: Detect spoofed or unusual user-agents (e.g., `python-requests`, `curl`, custom bot strings).
- **Header combination analysis**: Some attack tools send distinctive header combinations.
- **Custom header detection**: Cobalt Strike's `C5-Bid` header, MuddyWater's ETag patterns .
- **Cookie analysis**: Irregular cookie patterns may indicate session manipulation.

### 3.4 Attacker Fingerprinter

**SSH Fingerprinting (HASSH)**

Extracts from KEXINIT:
- KEX algorithms offered
- Encryption algorithms offered
- MAC algorithms offered
- Compression algorithms offered
- Client version string (from banner exchange)

Computes HASSH fingerprint and matches against known tool fingerprints .

**TLS Fingerprinting (JA3)**

For HTTPS connections (if configured):
- Extracts Client Hello fields: TLS version, cipher suites, extensions, elliptic curves, EC point formats.
- Computes JA3 fingerprint .
- Matches against known malicious JA3 values (Cobalt Strike, Meterpreter).

**HTTP Fingerprinting**

- User-Agent string analysis.
- Header ordering and presence patterns.
- Custom header detection.
- Request path patterns (scanner signatures).

### 3.5 Enrichment Layer

**IP Reputation**
- **AbuseIPDB**: Abuse confidence score, report count, last reported .
- **VirusTotal**: Detection ratio, ASN, country.
- **GreyNoise**: Classification (malicious, benign, unknown), RIOT (benign service).
- **Shodan**: Open ports, services, vulnerabilities.

**Geolocation**
- MaxMind GeoLite2 (local, private) or HTTP-based lookup .
- Country, city, ASN, organization.

**Payload Analysis**
- **VirusTotal**: Hash lookup (never upload without explicit action) .
- **MalwareBazaar**: One-click upload of captured payloads .
- **URLhaus**: Submit URLs from which payloads were served .

### 3.6 Storage Layer

**Data directory:**
```
~/.hafp/
├── sessions/
│   └── <session_id>/
│       ├── session.json          # Full session record
│       ├── tty.log               # TTY recording (SSH)
│       ├── payloads/             # Downloaded files
│       └── fingerprint.json      # HASSH/JA3/HTTP fingerprint
├── enrichment/
│   └── <ip>.json                 # Cached enrichment results
├── campaigns/
│   └── <campaign_id>.json        # Campaign tracking data
├── reports/
│   └── <report_id>.pdf
└── logs/
    └── hafp.log
```

**Session record model:**
```python
@dataclass
class HoneypotSession:
    session_id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    protocol: str                    # 'ssh', 'http'
    duration_seconds: float

    # SSH-specific
    ssh_client_version: str | None
    hassh: str | None
    hassh_server: str | None
    kex_algorithms: list[str]
    encryption_algorithms: list[str]
    mac_algorithms: list[str]
    credentials_attempted: list[CredentialAttempt]
    commands_executed: list[str]

    # HTTP-specific
    ja3: str | None                  # if HTTPS
    user_agent: str | None
    http_methods: list[str]
    request_paths: list[str]
    headers: dict[str, str]
    custom_headers: list[str]

    # Payloads
    payloads: list[PayloadInfo]

    # Enrichment
    enrichment: IpEnrichment | None

@dataclass
class CredentialAttempt:
    username: str
    password: str
    timestamp: datetime
    success: bool                    # always False (honeypot)

@dataclass
class PayloadInfo:
    filename: str
    sha256: str
    size: int
    source_url: str | None
    virus_total_ratio: str | None
    malware_bazaar_uploaded: bool

@dataclass
class IpEnrichment:
    ip: str
    abuseipdb_score: int | None
    virus_total_detections: int | None
    greynoise_classification: str | None
    country: str | None
    city: str | None
    asn: str | None
    org: str | None
```

### 3.7 Canonical Data Model

See `HoneypotSession`, `CredentialAttempt`, `PayloadInfo`, and `IpEnrichment` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, session table updates, fingerprint display
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

SSH Listener Thread (single, asyncio)
  ├── Accept connections
  ├── Version exchange
  ├── KEXINIT parsing
  ├── Authentication loop
  └── Emit session events

HTTP Listener Thread (single, Twisted/Flask)
  ├── Accept requests
  ├── Header parsing
  ├── Response generation
  └── Emit session events

Enrichment Pool (QThreadPool, 4 workers)
  ├── AbuseIPDB lookup
  ├── VirusTotal lookup
  ├── GreyNoise lookup
  └── GeoIP lookup
```

**Rules:**
- Honeypot listeners run in dedicated threads with their own event loops.
- Session events marshalled to GUI via Qt signals.
- Enrichment lookups parallelized; cached to avoid rate limits.
- Payload capture limited in size (default: 10 MB) to prevent disk exhaustion.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Honeypots** → set SSH banner, HTTP server signature, bind ports, enable/disable protocols.
2. **Start Listeners** → honeypot begins accepting connections.
3. **Monitor Sessions** → real-time session table populates as attackers connect.
4. **Fingerprint Attackers** → HASSH (SSH), JA3 (HTTPS), HTTP headers displayed per session .
5. **Enrich IPs** → reputation and geolocation data attached to sessions.
6. **Inspect Payloads** → captured files with VirusTotal verdicts; upload to MalwareBazaar .
7. **Track Campaigns** → group sessions by fingerprint to identify coordinated activity.
8. **Export Threat Feed** → STIX 2.1, MISP, iptables rules, Nginx deny rules .
9. **Generate Report** → JSON/CSV/STIX/HTML/PDF with sessions, fingerprints, credentials, payloads.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Attacker escape** | Low-interaction honeypot; no real shell, no command execution, no filesystem access . |
| **Payload malware** | Captured payloads quarantined; never executed; VirusTotal hash lookup only (no upload) . |
| **Honeypot fingerprinting** | Honeypots themselves can be fingerprinted via protocol deviations . Use realistic banners and personas. |
| **Legal compliance** | Honeypot deployment may have legal implications; document that tool is for authorized research only. |
| **API key exposure** | Enrichment API keys stored in OS keychain; never logged. |
| **Report leakage** | Reports contain attacker IPs and fingerprints; redaction profile for external sharing. |

---

## 7. Extensibility Points

1. **New protocol honeypot** — implement `HoneypotProtocol` ABC (SSH, HTTP, FTP, Telnet) .
2. **New fingerprinting method** — implement `Fingerprinter` ABC (HASSH, JA3, HTTP headers, RDFP) .
3. **New enrichment source** — implement `Enricher` ABC (AbuseIPDB, VirusTotal, GreyNoise).
4. **New export format** — `Exporter` ABC (JSON, CSV, STIX 2.1, MISP, HTML, PDF).
5. **LLM-based command analysis** — optional: use LLM to derive TTPs from attacker commands .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 3 s |
| Connection acceptance | < 100 ms |
| Session event latency | < 1 s |
| Enrichment latency | < 3 s per IP |
| Memory footprint | < 500 MB RSS |
| Concurrent sessions | 1,000+ |
| Payload capture size limit | 10 MB (configurable) |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| SSH honeypot | `asyncssh` or custom asyncio | Low-interaction, no real shell  |
| HTTP honeypot | `Flask` or `Twisted` | Catch-all routing  |
| HASSH computation | Custom (MD5 of KEXINIT fields) | Standard fingerprinting  |
| JA3 computation | Custom or `tshark` | TLS fingerprinting  |
| Enrichment | `requests` (AbuseIPDB, VT, GreyNoise APIs) | Standard  |
| GeoIP | `geoip2fast` or MaxMind GeoLite2 | Local lookup  |
| DB | JSONL + SQLite | Lightweight, queryable |
| Report export | `json`, `csv`, `stix2`, `Jinja2`, `WeasyPrint` | Multi-format  |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
hafp/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── hafp/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── honeypot_control.py
│       │   │   ├── session_monitor.py
│       │   │   ├── attacker_fingerprint.py
│       │   │   ├── ip_enrichment.py
│       │   │   ├── live_traffic.py
│       │   │   ├── payload_inspector.py
│       │   │   ├── campaign_tracker.py
│       │   │   ├── threat_feed.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── sessions_table_model.py
│       │   │   └── fingerprints_table_model.py
│       │   └── widgets/
│       │       ├── hassh_badge.py
│       │       ├── risk_indicator.py
│       │       └── session_card.py
│       ├── core/
│       │   ├── honeypots/
│       │   │   ├── base.py
│       │   │   ├── ssh_honeypot.py
│       │   │   └── http_honeypot.py
│       │   ├── fingerprinting/
│       │   │   ├── hassh.py
│       │   │   ├── ja3.py
│       │   │   └── http_headers.py
│       │   ├── enrichment/
│       │   │   ├── abuseipdb.py
│       │   │   ├── virustotal.py
│       │   │   ├── greynoise.py
│       │   │   └── geoip.py
│       │   ├── sessions/
│       │   │   └── aggregator.py
│       │   └── campaigns/
│       │       └── tracker.py
│       ├── storage/
│       │   ├── session_store.py
│       │   ├── fingerprint_store.py
│       │   └── payload_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── stix_exporter.py
│       │   │   ├── misp_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── net.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── personas/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, SSH honeypot listener, credential logging | 2 weeks |
| **P1 — HTTP Honeypot** | HTTP listener, request logging, catch-all routing | 2 weeks |
| **P2 — HASSH Fingerprinting** | KEXINIT parsing, HASSH computation, fingerprint display | 2 weeks |
| **P3 — Enrichment** | AbuseIPDB, VirusTotal, GreyNoise, GeoIP integration | 2 weeks |
| **P4 — Payload Capture** | File download capture, hash computation, quarantine | 1 week |
| **P5 — Session Monitor** | Session aggregation, real-time table, detail views | 2 weeks |
| **P6 — Campaign Tracking** | Fingerprint-based grouping, campaign view | 1 week |
| **P7 — Threat Feed Export** | STIX 2.1, MISP, iptables, Nginx formats  | 1 week |
| **P8 — Reporting** | JSON/CSV/HTML/PDF report generation | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~18 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: HASSH computation, JA3 extraction, header parsing, credential logging.
- **Integration**: full honeypot flow with simulated attackers (Hydra, Nmap, curl).
- **GUI**: `pytest-qt` for session monitor, fingerprint display, report builder.
- **Cross-validation**: compare HASSH fingerprints against known tool values .
- **Security**: verify no command execution, no filesystem access, payload quarantine.

---

## 13. Open Questions / Decisions Pending

1. **SSH library** — `asyncssh` (full protocol) vs custom asyncio (lighter). Recommend: custom asyncio for low-interaction control .
2. **HTTP framework** — Flask (simple) vs Twisted (async). Recommend: Flask for v1; Twisted optional .
3. **Honeypot fingerprinting** — honeypots can be detected via protocol deviations . Recommend: use realistic banners; document limitation.
4. **Enrichment rate limits** — AbuseIPDB/VirusTotal have free-tier limits. Recommend: caching + configurable lookup frequency .
5. **LLM command analysis** — optional feature for deriving TTPs from attacker commands . Recommend: v2 feature.

---

## 14. Glossary

- **Honeypot** — Decoy system designed to attract and observe attackers .
- **Low-interaction** — Honeypot that emulates services without real command execution .
- **HASSH** — SSH client/server fingerprint based on KEXINIT algorithm lists .
- **JA3** — TLS client fingerprint based on Client Hello fields .
- **KEXINIT** — SSH key exchange initialization message containing algorithm offers .
- **TTY recording** — Session recording for attacker command replay .
- **AbuseIPDB** — IP reputation service .
- **GreyNoise** — Service classifying internet background noise vs targeted attacks.
- **STIX 2.1** — Structured Threat Information Expression .
- **MISP** — Malware Information Sharing Platform.
- **Payload** — File downloaded by attacker during honeypot session .

---

*End of document.*