# Architecture: Threat-Intel Feed Aggregator (IOC Ingestion + Auto-Blocklist) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Multi-source threat-intel ingestion, IOC normalization, deduplication, enrichment, auto-blocklist generation, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Threat-Intel Feed Aggregator (TIFA)** is a GUI-driven desktop application for SOC analysts, threat intelligence teams, and security engineers who need to **aggregate IOCs from multiple threat-intel sources**, normalize them into a common format, and **automatically generate blocklists** for firewalls, proxies, and EDR platforms. It addresses the operational gap between raw threat feeds and actionable enforcement: feeds produce IOCs in heterogeneous formats (STIX, CSV, JSON, MISP attributes), and security teams need unified, deduplicated, enriched blocklists that can be consumed by Palo Alto EDLs, FortiGate threat feeds, Nginx deny rules, or iptables .

The tool is designed around four principles:

1. **Multi-source ingestion** — support AlienVault OTX, Abuse.ch (URLhaus, MalwareBazaar), MISP, STIX/TAXII feeds, and custom CSV/JSON sources in a single pipeline .
2. **Normalization and deduplication** — every IOC is normalized to a unified schema (IP, domain, URL, hash) and deduplicated across sources .
3. **Enrichment before enforcement** — IOCs are enriched with confidence scores, first/last seen timestamps, and source metadata before inclusion in blocklists .
4. **Auto-blocklist generation** — output blocklists in formats directly consumable by security infrastructure (Palo Alto EDL, FortiGate EBL, Nginx, iptables, DNS RPZ) .

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Feed      │ │ Ingestion │ │ IOC       │ │ Blocklist │ │ Report  │ │
│  │ Manager   │ │ Progress  │ │ Inspector │ │ Generator │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Source    │ │ IOC       │ │ Confidence│ │ Export    │ │ Console │ │
│  │ Dashboard │ │ Table     │ │ Dashboard │ │ Formats   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Ingestion  │ │ IOC        │ │ Enrichment │ │ Event Bus / Log    │ │
│  │ Scheduler  │ │ Normalizer │ │ Pipeline   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Feed Adapter Layer                               │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ AlienVault OTX │ │ Abuse.ch       │ │ MISP Client              │  │
│  │ Adapter        │ │ Adapter        │ │ (PyMISP)                 │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ STIX/TAXII     │ │ Generic CSV/   │ │ Custom Feed              │  │
│  │ Client         │ │ JSON Adapter   │ │ Adapter                  │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Processing Layer                                 │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Normalizer     │ │ Deduplicator   │ │ Confidence Scorer        │  │
│  │ (STIX 2.1)     │ │ (value+type)   │ │ (source + enrichment)    │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Blocklist Generator (EDL, EBL, Nginx, iptables, DNS RPZ)       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ IOC Store  │ │ Feed       │ │ Blocklist  │ │ Report Store       │ │
│  │ (SQLite)   │ │ Registry   │ │ History    │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `FeedManagerView` | Add/remove/configure feed sources: AlienVault OTX (API key), Abuse.ch (URLhaus, MalwareBazaar), MISP (URL + API key), STIX/TAXII (collection URL), custom CSV/JSON . |
| `SourceDashboardView` | Per-source status: last sync, IOC count, errors, health indicator. |
| `IngestionProgressView` | Live progress per feed: IOCs fetched, normalized, deduplicated. Cancel/pause controls. |
| `IocInspectorView` | **Primary view.** Table of aggregated IOCs: type, value, source(s), confidence, first seen, last seen, TLP, tags. Sortable, filterable, searchable. |
| `ConfidenceDashboardView` | Confidence score breakdown: source reliability, enrichment signals, age decay. |
| `BlocklistGeneratorView` | **Export interface.** Select target format (Palo Alto EDL, FortiGate EBL, Nginx deny, iptables, DNS RPZ, plain text), IOC types to include, confidence threshold. Preview blocklist before export. |
| `ExportFormatsView` | Configure format-specific options (e.g., FortiGate EBL server URL, EDL filename). |
| `ReportBuilderView` | Export aggregation report (JSON, CSV, HTML, PDF) with source summary, IOC statistics, blocklist metadata. |
| `ConsoleView` | Live log: feed errors, API rate limits, normalization warnings. |

**Key UI Patterns:**
- **Source health indicators**: Green (healthy), yellow (stale), red (error).
- **Confidence color coding**: High (green), medium (yellow), low (gray).
- **Click-to-drill**: click IOC → show source attribution and enrichment details.
- **Blocklist preview**: show the exact lines that will be written to the blocklist file.
- **One-click export**: generate all blocklist formats simultaneously.

### 3.2 Orchestration Layer

**Ingestion Scheduler**
- Periodic feed sync (configurable per source; default: hourly for OTX, every 5 min for URLhaus) .
- Manual sync trigger.
- Incremental sync where supported (OTX uses `modified_since`) .

**IOC Normalizer**
- Converts heterogeneous feed formats to unified IOC model.
- Maps source-specific fields to canonical schema.
- Validates IOC format (IP address validation, domain syntax, hash length).

**Enrichment Pipeline**
- Optional enrichment with VirusTotal, AbuseIPDB, GreyNoise.
- Confidence scoring based on source reliability and enrichment signals.

### 3.3 Feed Adapter Layer

**AlienVault OTX Adapter**
- Uses OTX DirectConnect API (`X-OTX-API-KEY` header) .
- Fetches subscribed pulses and inline indicators .
- Supports incremental sync via `modified_since` parameter.
- Rate limit: 10,000 requests/hour .

**Abuse.ch Adapter**
- **URLhaus**: Downloads CSV feed (`/downloads/csv_recent/`); filters for active threats .
- **MalwareBazaar**: Queries by hash, tag, signature, file type . Requires API key from auth.abuse.ch .
- **ThreatFox**: IP/domain/URL IOCs associated with malware families.

**MISP Adapter**
- Uses PyMISP library to query MISP instance .
- Extracts attributes of types `ip-src`, `ip-dst`, `domain`, `hostname`, `url`, `md5`, `sha1`, `sha256` .
- Excludes known-safe indicators using MISP Warning Lists .
- Filters by timestamp (e.g., last 7 days).

**STIX/TAXII Adapter**
- Uses `taxii2-client` and `stix2` libraries .
- Connects to TAXII 2.1 servers (CISA AIS, commercial feeds).
- Parses STIX `indicator` objects with patterns .

**Generic CSV/JSON Adapter**
- Configurable column mapping for custom feeds.
- Supports plain text lists (one IOC per line) .

### 3.4 Processing Layer

**Normalizer**
- Unified IOC model:
```python
@dataclass
class NormalizedIOC:
    ioc_id: str
    ioc_type: str              # 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'
    value: str
    sources: list[str]         # ['otx', 'urlhaus', 'misp']
    confidence: float          # 0.0-1.0
    first_seen: datetime | None
    last_seen: datetime | None
    tlp: str                   # 'white', 'green', 'amber', 'red'
    tags: list[str]
    enriched: dict | None      # VT, AbuseIPDB, GreyNoise results
```

**Deduplicator**
- Composite key: `(ioc_type, value)`.
- Merges sources when duplicate found.
- Aggregates confidence (higher confidence source wins; multiple sources boost).

**Confidence Scorer**
- Base score per source (OTX: 0.6, URLhaus: 0.7, MISP: 0.8, commercial: 0.9) .
- Enrichment boost: VirusTotal detections > 5 → +0.2; GreyNoise malicious → +0.15.
- Age decay: IOCs older than 30 days get -0.1; older than 90 days get -0.3.

**Blocklist Generator**

| Target | Format | Reference |
|---|---|---|
| **Palo Alto EDL** | Plain text IP/URL list | Exposed via HTTP for EDL subscription  |
| **FortiGate EBL** | Plain text IP/domain/hash lists | External Block List format  |
| **Nginx** | `deny <ip>;` directives | Standard Nginx config |
| **iptables** | `iptables -A INPUT -s <ip> -j DROP` | Shell script output |
| **DNS RPZ** | Zone file format | Response Policy Zone |
| **Plain text** | One IOC per line | Generic consumption  |

### 3.5 Storage Layer

**Data directory:**
```
~/.tifa/
├── feeds/
│   └── <feed_id>.json           # Feed configuration
├── iocs/
│   └── iocs.db                  # SQLite IOC store
├── blocklists/
│   ├── ip_blocklist.txt
│   ├── domain_blocklist.txt
│   ├── url_blocklist.txt
│   └── hash_blocklist.txt
├── reports/
│   └── <report_id>.pdf
└── logs/
    └── tifa.log
```

**SQLite Schema (abridged):**
```sql
CREATE TABLE iocs (
  id INTEGER PRIMARY KEY,
  ioc_type TEXT NOT NULL,
  value TEXT NOT NULL,
  confidence REAL,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  tlp TEXT,
  tags_json TEXT,
  sources_json TEXT,
  UNIQUE(ioc_type, value)
);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_confidence ON iocs(confidence);
CREATE TABLE feed_registry (
  id TEXT PRIMARY KEY,
  name TEXT,
  adapter TEXT,
  config_json TEXT,
  last_sync TIMESTAMP,
  ioc_count INTEGER,
  status TEXT
);
CREATE TABLE sync_history (
  id INTEGER PRIMARY KEY,
  feed_id TEXT,
  sync_ts TIMESTAMP,
  iocs_fetched INTEGER,
  iocs_new INTEGER,
  error TEXT
);
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, IOC table, blocklist preview
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Ingestion Pool (QThreadPool, N workers)
  ├── OTX fetch thread
  ├── URLhaus fetch thread
  ├── MISP query thread
  └── STIX/TAXII fetch thread

Processing Worker (single thread)
  ├── Normalize → Deduplicate → Score → Store

Enrichment Pool (QThreadPool, 4 workers)
  ├── VirusTotal lookup
  ├── AbuseIPDB lookup
  └── GreyNoise lookup
```

**Rules:**
- Feed fetches parallelized across sources.
- Enrichment lookups parallelized and rate-limited per source.
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between feed operations.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Feeds** → add AlienVault OTX, URLhaus, MISP sources with credentials .
2. **Initial Sync** → fetch IOCs from all sources; normalize; deduplicate.
3. **Review IOCs** → table shows aggregated IOCs with source attribution and confidence.
4. **Enrich** (optional) → run enrichment for higher-confidence IOCs.
5. **Configure Blocklists** → select target formats (Palo Alto EDL, FortiGate EBL) .
6. **Set Thresholds** → minimum confidence, IOC types, age limit.
7. **Generate Blocklists** → preview and export in all selected formats.
8. **Export Report** → JSON/CSV/HTML/PDF with source summary and IOC statistics.
9. **Schedule Auto-Sync** → periodic refresh keeps blocklists current.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Feed API key exposure** | Keys stored in OS keychain; never logged or exported. |
| **Malicious feed content** | IOCs are data, not code; validated format; no execution. |
| **False positive blocking** | Confidence threshold enforced; preview before export; allowlist exclusion . |
| **Blocklist staleness** | Age-based decay; configurable TTL per IOC type (IP: 30d, domain: 90d, hash: 1y) . |
| **Feed poisoning** | Multi-source corroboration raises confidence; single-source low-confidence IOCs excluded by default. |
| **Rate limit compliance** | Per-source rate limiting (OTX: 10k/hr) ; exponential backoff on 429. |

---

## 7. Extensibility Points

1. **New feed adapter** — implement `FeedAdapter` ABC (OTX, Abuse.ch, MISP, STIX/TAXII, custom).
2. **New blocklist format** — implement `BlocklistFormatter` ABC (EDL, EBL, Nginx, iptables, DNS RPZ).
3. **New enrichment source** — implement `Enricher` ABC (VirusTotal, AbuseIPDB, GreyNoise, Shodan).
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, STIX 2.1).
5. **MISP auto-publish** — optional: publish high-confidence IOCs back to MISP .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Feed sync (10k IOCs) | < 30 s |
| Deduplication (100k IOCs) | < 5 s |
| Blocklist generation | < 2 s |
| Report generation | < 5 s |
| Memory footprint | < 300 MB RSS |
| IOC capacity | Up to 1M IOCs |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| OTX client | `OTXv2` | Official Python library  |
| MISP client | `pymisp` | Official Python library  |
| STIX/TAXII | `stix2`, `taxii2-client` | OASIS standard  |
| Abuse.ch | `requests` | Direct API/CSV  |
| DB | SQLite (WAL) | Embedded, ACID |
| Enrichment | `requests` (VT, AbuseIPDB, GreyNoise) | Standard APIs |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
tifa/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── tifa/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── feed_manager.py
│       │   │   ├── source_dashboard.py
│       │   │   ├── ingestion_progress.py
│       │   │   ├── ioc_inspector.py
│       │   │   ├── confidence_dashboard.py
│       │   │   ├── blocklist_generator.py
│       │   │   ├── export_formats.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── iocs_table_model.py
│       │   └── widgets/
│       │       ├── source_health.py
│       │       ├── confidence_badge.py
│       │       └── blocklist_preview.py
│       ├── core/
│       │   ├── adapters/
│       │   │   ├── base.py
│       │   │   ├── otx.py
│       │   │   ├── urlhaus.py
│       │   │   ├── malwarebazaar.py
│       │   │   ├── misp.py
│       │   │   ├── stix_taxii.py
│       │   │   └── generic.py
│       │   ├── processing/
│       │   │   ├── normalizer.py
│       │   │   ├── deduplicator.py
│       │   │   └── scorer.py
│       │   ├── enrichment/
│       │   │   ├── virustotal.py
│       │   │   ├── abuseipdb.py
│       │   │   └── greynoise.py
│       │   └── blocklist/
│       │       ├── generator.py
│       │       └── formatters/
│       │           ├── edl.py
│       │           ├── ebl.py
│       │           ├── nginx.py
│       │           ├── iptables.py
│       │           └── rpz.py
│       ├── storage/
│       │   ├── ioc_store.py
│       │   ├── feed_store.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── validation.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── default_feeds.yaml
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, feed manager, OTX adapter | 2 weeks |
| **P1 — URLhaus + MISP** | URLhaus CSV adapter, PyMISP integration  | 2 weeks |
| **P2 — Normalization** | Unified IOC model, deduplication, SQLite store | 2 weeks |
| **P3 — Blocklist Generation** | EDL, EBL, Nginx, iptables formatters  | 2 weeks |
| **P4 — Confidence Scoring** | Source reliability, age decay, multi-source boost | 1 week |
| **P5 — STIX/TAXII** | TAXII 2.1 client, STIX parsing  | 2 weeks |
| **P6 — Enrichment** | VirusTotal, AbuseIPDB, GreyNoise integration | 2 weeks |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~18 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: IOC validation, normalization, deduplication, confidence scoring, blocklist formatting.
- **Integration**: full pipeline with mock feed APIs; validate output against expected blocklists.
- **GUI**: `pytest-qt` for feed manager, IOC table, blocklist preview.
- **Cross-validation**: compare aggregated IOCs against source counts; verify deduplication.

---

## 13. Open Questions / Decisions Pending

1. **MISP requirement** — MISP instance is optional; the tool can operate with OTX/URLhaus only . Recommend: MISP support optional.
2. **Enrichment rate limits** — VT/AbuseIPDB free tiers have strict limits . Recommend: caching + configurable enrichment scope.
3. **Blocklist delivery** — file export vs embedded HTTP server for EDL subscription . Recommend: file export for v1; HTTP server for v2.
4. **STIX 2.1 output** — export aggregated IOCs as STIX bundle for TIP ingestion . Recommend: v2 feature.

---

## 14. Glossary

- **IOC** — Indicator of Compromise (IP, domain, URL, hash) .
- **STIX 2.1** — Structured Threat Information Expression standard .
- **TAXII 2.1** — Trusted Automated eXchange of Intelligence Information protocol .
- **MISP** — Malware Information Sharing Platform .
- **OTX** — AlienVault Open Threat Exchange .
- **URLhaus** — Abuse.ch feed of malicious URLs .
- **MalwareBazaar** — Abuse.ch malware sample repository .
- **EDL** — External Dynamic List (Palo Alto firewall feature) .
- **EBL** — External Block List (FortiGate feature) .
- **TLP** — Traffic Light Protocol for information sharing .
- **Confidence Score** — 0-100 value reflecting IOC reliability .

---

*End of document.*