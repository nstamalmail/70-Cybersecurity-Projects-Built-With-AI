# Architecture: SOC Alert Triage Dashboard (Severity Scoring + Dedup) — GUI-Based Solution

**Document Version:** 1.0  
**Author:** Senior Security Developer  
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)  
**Core Capability:** Ingest alerts from multiple SIEM/EDR sources, apply contextual severity scoring, deduplicate and group related alerts, and provide triage workflow with multi-format report export  
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)  
**Status:** Design Specification

---

## 1. Executive Summary

The **SOC Alert Triage Dashboard (SATD)** is a GUI-driven desktop application for SOC analysts and security managers who need to **cut through alert noise** and focus on genuine threats. It addresses the well-documented crisis in Security Operations: 62% of SOC alerts are disregarded because teams can't prioritize effectively, 55% of teams admit missing critical alerts due to poor prioritization, and 84% of security professionals report burnout from alert volume .

The tool consolidates proven noise-reduction techniques into a single workflow: **real-time CTI correlation** to suppress alerts with negative or stale threat intelligence, **alert grouping** to collapse recurrent identical alerts across sensors within configurable time windows, and **dynamic severity recalibration** where low-severity alerts corroborated by high-confidence CTI are promoted . Graph-based alert contextualisation enables analysis at a higher abstraction level by grouping related alerts into graph-based alert groups, capturing attack steps more effectively than individual alerts .

The tool is designed around four principles:

1. **Context over count** — every alert is enriched with asset, threat-intel, and historical context before scoring.
2. **Deduplication first** — repeated, identical alerts are collapsed into grouped events before reaching the analyst .
3. **Dynamic severity** — initial vendor severity is a starting signal, not a verdict; CTI and recurrence recalibrate priority .
4. **Report-ready** — export triage decisions, suppression statistics, and SOC performance metrics in JSON, CSV, HTML, and PDF formats.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Alert     │ │ Triage    │ │ Group     │ │ CTI       │ │ Report  │ │
│  │ Inbox     │ │ Queue     │ │ Viewer    │ │ Context   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Severity  │ │ Dedup     │ │ SOC       │ │ Suppress  │ │ Console │ │
│  │ Dashboard │ │ Statistics│ │ Metrics   │ │ Rules     │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Ingestion  │ │ Scoring    │ │ Dedup      │ │ Event Bus / Log    │ │
│  │ Scheduler  │ │ Engine     │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Processing Layer                                 │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Alert Normalizer│ │ CTI Correlator │ │ Graph Grouping           │  │
│  │ (STIX/ECS)     │ │ (IOC matching) │ │ (time-window edges)      │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Severity       │ │ Deduplication  │ │ Suppression              │  │
│  │ Recalibrator   │ │ (hash + window)│ │ (FP patterns)            │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Ingestion Adapter Layer                          │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Splunk         │ │ Microsoft      │ │ Generic Syslog/          │  │
│  │ Adapter        │ │ Sentinel       │ │ Webhook Adapter          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ CrowdStrike    │ │ Suricata       │ │ STIX/TAXII Consumer      │  │
│  │ Falcon         │ │ EVE JSON       │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Alert Store│ │ Group Store│ │ Suppression│ │ Report Store       │ │
│  │ (SQLite)   │ │            │ │ Rules      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `AlertInboxView` | **Primary triage view.** Table of scored, deduplicated alerts: timestamp, source, severity (recalibrated), group ID, CTI context, asset, status. Sortable, filterable. Color-coded by recalibrated severity. |
| `TriageQueueView` | Active triage queue: alerts assigned to the current analyst, with SLA timers and escalation indicators. |
| `GroupViewerView` | Expanded view of an alert group: all constituent alerts, graph edges (shared entities), attack step progression. |
| `CtiContextView` | CTI enrichment details for a selected alert: matched IOCs, campaign attribution, indicator freshness, confidence score. |
| `SeverityDashboardView` | Aggregated severity distribution: original vs. recalibrated severity, promotion/demotion counts, suppression statistics. |
| `DedupStatisticsView` | Deduplication metrics: total alerts ingested, unique groups, dedup ratio, top duplicate patterns. |
| `SocMetricsView` | SOC performance metrics: mean time to triage (MTTT), mean time to resolve (MTTR), alert backlog, per-analyst workload. |
| `SuppressionRulesView` | Configure suppression rules: known false-positive patterns, stale IOC thresholds, asset-based exclusions. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), date range, sections to include (triage summary, dedup stats, SOC metrics, suppressed alerts). |
| `ConsoleView` | Live log: ingestion errors, CTI lookup failures, scoring anomalies. |

**Key UI Patterns:**
- **Triage-first layout**: the inbox is the dominant view; context panels are collapsible sidebars.
- **Severity color coding**: Critical (red), High (orange), Medium (yellow), Low (blue), Suppressed (gray).
- **Group indicators**: alert rows belonging to the same group share a group ID badge.
- **Click-to-drill**: click a group → show all constituent alerts and shared entities; click an IOC → show CTI details.
- **Real-time streaming**: alerts appear as they are ingested and scored.

### 3.2 Orchestration Layer

**Ingestion Scheduler**
- Periodic polling of configured sources (Splunk API, Sentinel SecurityIncident table, generic webhooks) .
- Webhook receiver for push-based sources (Suricata EVE JSON, CrowdStrike detections) .
- Incremental sync using `modified_since` or `createdDateTime` filters .

**Scoring Engine**
- Applies contextual severity scoring to each alert.
- Computes recalibrated severity based on CTI correlation, recurrence, and asset criticality .
- Flags alerts for suppression if they match known false-positive patterns.

**Dedup Engine**
- Groups alerts by entity overlap (shared IP, hash, username, hostname) within configurable time windows .
- Collapses identical alerts across sensors into a single group .
- Computes dedup ratio and tracks group evolution over time.

### 3.3 Ingestion Adapter Layer

**Splunk Adapter**
- Uses `splunkctl` or `splunk-sdk-python` to query notable events .
- Maps Splunk `notable` fields to normalized alert model.
- Supports ES notables list/get/update for triage loop integration.

**Microsoft Sentinel Adapter**
- Queries `SecurityIncident` table via KQL .
- Uses `arg_max()` to retrieve latest state per incident .
- Maps Sentinel severity, status, and MITRE tactics to normalized model.

**CrowdStrike Falcon Adapter**
- Uses `falcon-mcp` or Falcon REST API for detections .
- Maps Falcon severity and tactic fields to normalized model.

**Suricata EVE JSON Adapter**
- Consumes EVE JSON from Suricata sensors .
- Maps signature severity (1-3) to normalized severity (3 = low).

**Generic Webhook Adapter**
- Accepts JSON payloads via HTTP POST.
- Configurable field mapping for custom sources.

### 3.4 Processing Layer

**Alert Normalizer**
- Converts heterogeneous alert formats to a unified model.
- Maps source-specific severity to normalized scale.

**CTI Correlator**
- Matches alert indicators (IP, domain, URL, hash) against curated threat intelligence feeds .
- Retrieves indicator freshness, campaign attribution, and confidence score.
- Suppresses alerts with negative or stale CTI evidence .

**Graph Grouping Engine**
- Builds alert graphs where nodes represent alerts and edges denote shared entities within time-windows .
- Groups related alerts into graph-based alert groups .
- Enables analysis at higher abstraction level, capturing attack steps .

**Severity Recalibrator**
- Adjusts severity based on CTI context: alerts with high-confidence CTI promoted; alerts with negative/stale CTI suppressed .
- Adds recurrence bonus: alerts observed across multiple sensors promoted .
- Applies asset criticality weighting.

**Deduplication Engine**
- Groups alerts by composite key: `(entity, signature, time_window)`.
- Collapses duplicates across sensors .
- Reports dedup ratio: industry data shows 60-80% reduction .

**Suppression Engine**
- Matches alerts against false-positive patterns.
- Suppresses known benign activity (e.g., quarantined malware, patched vulnerabilities) .
- Logs all suppressions for audit.

### 3.5 Storage Layer

**Data directory:**
```
~/.satd/
├── alerts/
│   └── alerts.db              # SQLite: alerts, groups, triage state
├── cti/
│   └── cti_cache.json         # Cached CTI lookup results
├── suppression/
│   └── rules.yaml             # Suppression rules
├── reports/
│   └── <report_id>.pdf
└── logs/
    └── satd.log
```

**SQLite Schema (abridged):**
```sql
CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  source TEXT,
  original_severity TEXT,
  recalibrated_severity TEXT,
  cti_confidence REAL,
  group_id TEXT,
  status TEXT,          -- 'new', 'triaging', 'resolved', 'suppressed'
  assigned_to TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  raw_json TEXT
);
CREATE INDEX idx_alerts_group ON alerts(group_id);
CREATE INDEX idx_alerts_severity ON alerts(recalibrated_severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE TABLE alert_groups (
  id TEXT PRIMARY KEY,
  entity_key TEXT,      -- shared entity (IP, hash, user)
  alert_count INTEGER,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  created_at TIMESTAMP
);
CREATE TABLE triage_metrics (
  id INTEGER PRIMARY KEY,
  alert_id TEXT,
  analyst TEXT,
  action TEXT,          -- 'triaged', 'escalated', 'resolved', 'suppressed'
  action_ts TIMESTAMP
);
```

### 3.6 Canonical Data Model

```python
@dataclass
class NormalizedAlert:
    alert_id: str
    source: str                    # 'splunk', 'sentinel', 'falcon', 'suricata'
    timestamp: datetime
    title: str
    description: str
    original_severity: str         # vendor severity
    recalibrated_severity: str     # adjusted by scoring engine
    cti_confidence: float | None
    cti_context: dict | None       # campaign, indicator freshness
    entities: list[str]            # IPs, hashes, users, hosts
    group_id: str | None
    status: str                    # 'new', 'triaging', 'resolved', 'suppressed'
    suppression_reason: str | None
    raw: dict

@dataclass
class AlertGroup:
    group_id: str
    entity_key: str
    alerts: list[NormalizedAlert]
    first_seen: datetime
    last_seen: datetime
    attack_steps: list[str]        # inferred progression
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, alert inbox, triage actions
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Ingestion Pool (QThreadPool, N workers)
  ├── Splunk query thread
  ├── Sentinel query thread
  ├── Falcon query thread
  └── Webhook receiver thread

Processing Worker (single thread)
  ├── Normalize → Score → Dedup → Group → Store

CTI Enrichment Pool (QThreadPool, 4 workers)
  ├── IOC lookup threads
  └── Campaign correlation
```

**Rules:**
- Source polling parallelized across adapters.
- CTI lookups parallelized and rate-limited.
- Scoring and dedup are serialized (global state).
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between processing batches.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Sources** → add Splunk, Sentinel, Falcon, webhook sources .
2. **Initial Ingest** → fetch alerts, normalize, score, deduplicate.
3. **Review Inbox** → scored, deduplicated alerts sorted by recalibrated severity.
4. **Inspect Groups** → click group → view constituent alerts and shared entities .
5. **Review CTI Context** → matched IOCs, campaign attribution, confidence .
6. **Triage** → assign, escalate, resolve, or suppress alerts.
7. **Track Metrics** → MTTT, MTTR, dedup ratio, suppression count .
8. **Export Report** → JSON/CSV/HTML/PDF with triage summary and metrics.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **SIEM API credentials** | Stored in OS keychain; never logged. |
| **CTI API rate limits** | Caching; configurable lookup frequency. |
| **Suppression abuse** | All suppressions logged with reason; audit trail. |
| **Alert data sensitivity** | Local-only storage; optional encryption at rest. |
| **False suppression** | Suppression rules require confidence threshold; preview before enabling. |

---

## 7. Extensibility Points

1. **New source adapter** — implement `AlertSource` ABC (Splunk, Sentinel, Falcon, Suricata, custom).
2. **New CTI provider** — implement `CtiProvider` ABC (MISP, OTX, commercial feeds).
3. **New scoring factor** — extend `SeverityScorer` (asset criticality, UEBA baseline).
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, STIX).
5. **SOAR integration** — optional: push triaged alerts to SOAR playbooks .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Alert ingestion (1000 alerts) | < 10 s |
| Dedup processing | < 5 s per 1000 alerts |
| CTI lookup latency | < 3 s per IOC |
| Report generation | < 5 s |
| Memory footprint | < 500 MB RSS |
| Alert capacity | Up to 1M alerts |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly  |
| Splunk | `splunkctl` or `splunk-sdk-python` | Python CLI/SDK  |
| Sentinel | `azure-monitor-query` or REST | KQL queries  |
| CrowdStrike | `falcon-mcp` or REST | Detections API  |
| CTI | `pymisp`, `OTXv2` | Standard libraries |
| DB | SQLite (WAL) | Embedded, ACID |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format  |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
satd/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── satd/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── alert_inbox.py
│       │   │   ├── triage_queue.py
│       │   │   ├── group_viewer.py
│       │   │   ├── cti_context.py
│       │   │   ├── severity_dashboard.py
│       │   │   ├── dedup_statistics.py
│       │   │   ├── soc_metrics.py
│       │   │   ├── suppression_rules.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── alerts_table_model.py
│       │   │   └── groups_table_model.py
│       │   └── widgets/
│       │       ├── severity_badge.py
│       │       ├── group_badge.py
│       │       └── cti_indicator.py
│       ├── core/
│       │   ├── adapters/
│       │   │   ├── base.py
│       │   │   ├── splunk.py
│       │   │   ├── sentinel.py
│       │   │   ├── falcon.py
│       │   │   ├── suricata.py
│       │   │   └── webhook.py
│       │   ├── processing/
│       │   │   ├── normalizer.py
│       │   │   ├── scorer.py
│       │   │   ├── deduplicator.py
│       │   │   └── grouper.py
│       │   ├── cti/
│       │   │   ├── correlator.py
│       │   │   └── providers/
│       │   └── suppression/
│       │       └── engine.py
│       ├── storage/
│       │   ├── alert_store.py
│       │   ├── group_store.py
│       │   └── metrics_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── hashing.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── suppression_patterns.yaml
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, alert inbox, Splunk adapter, basic table | 2 weeks |
| **P1 — Normalization** | Unified alert model, severity mapping | 2 weeks |
| **P2 — Deduplication** | Hash + window grouping, dedup ratio reporting | 2 weeks |
| **P3 — CTI Correlation** | IOC matching, confidence scoring, suppression  | 2 weeks |
| **P4 — Severity Recalibration** | Dynamic promotion/demotion, dashboard | 2 weeks |
| **P5 — Graph Grouping** | Entity-overlap graph, group viewer  | 2 weeks |
| **P6 — SOC Metrics** | MTTT, MTTR, backlog tracking  | 1 week |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~18 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: normalization, scoring recalibration, dedup key matching, CTI correlation.
- **Integration**: full pipeline with mock sources; validate dedup ratio and severity changes.
- **GUI**: `pytest-qt` for inbox, group viewer, CTI context.
- **Cross-validation**: compare dedup ratio against industry benchmark (60-80% reduction) .

---

## 13. Open Questions / Decisions Pending

1. **SIEM requirement** — Splunk vs Sentinel vs both? Recommend: configurable adapters; start with one .
2. **CTI feed** — MISP, OTX, or commercial? Recommend: MISP/OTX for v1; commercial optional.
3. **Graph grouping algorithm** — time-window edges vs. ML-based? Recommend: time-window for v1; ML optional .
4. **SOAR integration** — push triaged alerts to SOAR playbooks? Recommend: v2 feature .

---

## 14. Glossary

- **Alert Fatigue** — Analyst burnout from overwhelming alert volume .
- **Deduplication** — Collapsing identical alerts across sensors .
- **Graph Grouping** — Grouping related alerts into graph-based groups .
- **CTI** — Cyber Threat Intelligence; IOC enrichment .
- **Severity Recalibration** — Adjusting vendor severity based on CTI and context .
- **MTTT** — Mean Time to Triage .
- **MTTR** — Mean Time to Resolve .
- **Suppression** — Filtering known false positives .
- **Splunk ES Notables** — Splunk Enterprise Security alerts .
- **SecurityIncident** — Microsoft Sentinel incident table .

---

*End of document.*